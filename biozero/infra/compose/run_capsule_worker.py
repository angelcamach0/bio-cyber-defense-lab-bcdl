#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Opt-in three-service Compose acceptance with a fixed native host broker.

Uses existing pinned Go binaries and one exact cached image. No build/pull,
reviewer/browser, external network, model, historical reset or object removal.
All runtime configuration, payloads, PKI, logs and reports remain private.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import signal
import ssl
import stat
import subprocess
import sys
import time
import urllib.error

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT / "biozero/infra/native"
sys.path.insert(0, str(NATIVE))
from run_experiment import context, free_port, request

IMAGE = "sha256:1ca8e95c2f5679ab2001f856549c634f0b9daeeeb1492b8610814b96cf30fa7d"
SELECTORS = ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")
DOCKER = ["/usr/bin/sudo", "-n", "/usr/bin/env"] + [item for key in SELECTORS for item in ("-u", key)] + ["/usr/bin/docker", "--host=unix:///var/run/docker.sock"]
SERVICES = ("upload", "results", "worker")
BINARIES = ("upload-api", "results-api", "enclave-runner", "uploader-cli", "artifact-broker", "capsule-analysis")
ARTIFACTS = {"execution_receipt", "normalized_vcf", "variants_vcf", "variants_vcf_index"}
FIXTURE = ROOT / "biozero/bio/fixtures/variant-smoke"


class Failure(Exception):
    """Only fixed safe error codes; private command output never goes to stdout."""


def write_private(path, value):
    with path.open("w", encoding="utf-8") as out:
        json.dump(value, out, indent=2)
        out.write("\n")
    path.chmod(0o600)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            value.update(chunk)
    return value.hexdigest()


def copy_binary(source, target):
    """Copy one configured ELF through a no-follow descriptor traversal."""
    source = source.absolute()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for name in source.parts[1:-1]:
            next_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        binary = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    finally:
        os.close(fd)
    with os.fdopen(binary, "rb") as incoming:
        info = os.fstat(incoming.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o022 or not info.st_mode & 0o111 or not 20 <= info.st_size <= 32 << 20:
            raise Failure("binary_source_unsafe")
        header = incoming.read(20)
        if header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != 183:
            raise Failure("binary_not_linux_arm64_elf")
        incoming.seek(0)
        total = 0
        with target.open("xb") as outgoing:
            while True:
                chunk = incoming.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > 32 << 20:
                    raise Failure("binary_source_oversized")
                outgoing.write(chunk)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        if total != info.st_size:
            raise Failure("binary_source_changed")
    target.chmod(0o700)
    return {"sha256": digest(target), "bytes": total}


def snp_keys(path):
    # Import only the root-owned pure fixture comparator; its main never runs.
    spec = importlib.util.spec_from_file_location("biozero_native_capsule_checks", NATIVE / "run_capsule_worker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.synthetic_snp_keys(path)


def mount(source, target, readonly):
    return {"type": "bind", "source": str(source), "target": target, "read_only": readonly,
            "bind": {"create_host_path": False}}


def children(pid):
    found = set()
    for thread in Path(f"/proc/{pid}/task").iterdir():
        found.update(int(value) for value in (thread / "children").read_text().split())
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path, help="New private ignored .biozero path or a path outside the repository")
    parser.add_argument("--binaries-dir", required=True, type=Path, help="Existing current-UID ARM64 Go executable directory; never built here")
    parser.add_argument("--tools-prefix", required=True, type=Path, help="Existing native broker minimap2/samtools/bcftools/fastp prefix")
    args = parser.parse_args()
    if os.getuid() != 1000 or os.getgid() != 1000:
        parser.error("this acceptance requires host UID/GID1000")
    os.umask(0o077)
    run = args.run_dir.resolve()
    if run.is_relative_to(ROOT) and not run.is_relative_to(ROOT / ".biozero"):
        parser.error("run-dir inside source must be under ignored .biozero")
    run.mkdir(mode=0o700, parents=True, exist_ok=False)
    runtime = Path("/tmp") / ("bz-cw-" + secrets.token_hex(6))
    runtime.mkdir(mode=0o700)
    bin_dir, pki, data, host = [runtime / name for name in ("bin", "pki", "data", "host")]
    bin_dir.mkdir(mode=0o700)
    host.mkdir(mode=0o700)
    env = dict(os.environ)
    tools = args.tools_prefix.resolve()
    env["PATH"] = str(tools / "bin") + os.pathsep + env.get("PATH", "")
    report = {"schema_version": 1, "started_at": datetime.now(timezone.utc).isoformat(), "status": "failed",
              "scope": "three-service Compose upload/results/protected worker, individual mTLS, signature/encryption and host native v2 FD broker; no reviewer/browser, Docker capsule provider, biological model or image-build reproducibility claim",
              "runtime_root": str(runtime), "image_id": IMAGE, "provider": "native", "cases": [], "source_hashes": {}, "containers": {}}
    project = "bz-cw-" + secrets.token_hex(6)
    ownership_nonce = secrets.token_hex(16)
    owned_ids = {}
    compose_prefix = None
    started = False
    broker = None
    broker_log = None
    commands = 0
    complete = False

    def persist():
        write_private(run / "report.json", report)

    def record(name, passed, observed=None):
        report["cases"].append({"case": name, "passed": bool(passed), "observed": observed or {}})
        persist()
        print(("PASS " if passed else "FAIL ") + name, flush=True)
        if not passed:
            raise Failure("acceptance_case_failed")

    def command(argv, label, timeout=30, check=True):
        nonlocal commands
        commands += 1
        stem = f"{commands:03d}-{label}"
        try:
            proc = subprocess.run([str(x) for x in argv], cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            write_private(run / (stem + ".json"), {"timeout": True})
            raise Failure("command_deadline_exceeded") from exc
        write_private(run / (stem + ".json"), {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr})
        if check and proc.returncode:
            raise Failure("local_command_failed")
        return proc

    def compose(argv, label, timeout=60, check=True):
        return command(compose_prefix + argv, label, timeout, check)

    def inspect(service, missing_ok=False):
        identifier = compose(["ps", "--all", "--quiet", service], "id-" + service).stdout.strip()
        if not identifier and missing_ok:
            return None
        if not re.fullmatch("[0-9a-f]{12,64}", identifier):
            raise Failure("container_id_invalid")
        fmt = '{"id":{{json .Id}},"image":{{json .Image}},"state":{{json .State}},"user":{{json .Config.User}},"ownership":{{json (index .Config.Labels "org.biozero.acceptance_nonce")}},"host":{{json .HostConfig}},"mounts":{{json .Mounts}},"ports":{{json .NetworkSettings.Ports}}}'
        observed = json.loads(command(DOCKER + ["inspect", "--format", fmt, identifier], "inspect-" + service).stdout)
        if observed.get("ownership") != ownership_nonce or (service in owned_ids and owned_ids[service] != observed["id"]):
            raise Failure("container_ownership_changed")
        owned_ids[service] = observed["id"]
        report["containers"][service] = observed
        persist()
        return observed

    def source_pins():
        paths = command(["git", "ls-files", "-z", "-co", "--exclude-standard"], "source-enumeration", timeout=30).stdout.split("\0")
        return {name: digest(ROOT / name) for name in sorted(set(paths)) if (ROOT / name).is_file()}

    def await_result(job):
        if not re.fullmatch("[0-9a-f]{16}", job):
            raise Failure("job_id_invalid")
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            code, raw = request(results_base + "/results/" + job, client_a)
            value = json.loads(raw)
            if code == 200 and value.get("status") in {"succeeded", "failed", "incomplete", "rejected", "timed_out"}:
                return value
            if broker.poll() is not None:
                raise Failure("broker_exited_before_result")
            time.sleep(0.1)
        raise Failure("result_deadline_exceeded")

    try:
        # Explicit local Docker selectors; inherited DOCKER_CONFIG/proxy/CA/auth
        # variables are preserved. No daemon restart, pull or build is attempted.
        command(DOCKER + ["info", "--format", "{{.ServerVersion}} {{.OSType}}/{{.Architecture}}"], "local-daemon")
        report["compose_version"] = command(DOCKER + ["compose", "version", "--short"], "compose-version").stdout.strip()
        actual_image = command(DOCKER + ["image", "inspect", IMAGE, "--format", "{{.Id}}"], "cached-image").stdout.strip()
        record("exact_cached_image_without_build_or_pull", actual_image == IMAGE)
        report["source_hashes"] = source_pins()
        report["commit"] = command(["git", "rev-parse", "HEAD"], "commit").stdout.strip()
        report["dirty"] = bool(command(["git", "status", "--porcelain"], "dirty").stdout.strip())
        source_binary_pins = {}
        for name in BINARIES:
            source_binary_pins[name] = copy_binary(args.binaries_dir / name, bin_dir / name)
        report["binary_pins"] = source_binary_pins
        command(["bash", ROOT / "biozero/infra/PKI/gen-pki.sh", pki], "prepare-pki")
        command(["bash", ROOT / "biozero/infra/PKI/prepare-runtime.sh", data], "prepare-data")
        (data / "worker-custody").mkdir(mode=0o700)
        capsule = ROOT / "biozero/services/artifact-executor/capsule"
        assets = {"native_helper": capsule / "native_capsule.py", "pipeline": ROOT / "biozero/bio/pipeline/pipeline.py",
                  "resource_budget": ROOT / "biozero/bio/pipeline/resource_budget.py", "reference": FIXTURE / "reference.fa",
                  "evaluator": ROOT / "biozero/bio/benchmarks/evaluate_variants.py", "truth": FIXTURE / "expected.vcf",
                  "analysis_executable": bin_dir / "capsule-analysis", "analysis_rules": ROOT / "biozero/bio/reference-db/rules.json",
                  "analysis_panel": FIXTURE / "reference.fa"}
        config = {"schema_version": 1, "provider": "native", "mode": "variants", "store_root": str(host / "store"),
                  "journal_root": str(host / "journal"), "workspace_root": str(host / "workspace"), "socket_path": str(host / "channel/b.sock"),
                  "allowed_uid": 1000, "timeout_seconds": 60, "python_path": str(Path("/usr/bin/python3").resolve()),
                  "tool_path": str(tools / "bin") + ":/usr/bin", "docker_command": [], "image_id": "", "container_helper": {"path": "", "sha256": ""}}
        config.update({name: {"path": str(path), "sha256": digest(path)} for name, path in assets.items()})
        config_path = runtime / "broker.json"
        write_private(config_path, config)
        profile = command([bin_dir / "artifact-broker", "--config", config_path, "--print-profile"], "print-profile").stdout.strip()
        record("profile_without_store_or_provider_creation", bool(re.fullmatch("[0-9a-f]{64}", profile)) and not (host / "store").exists())
        pins = {name: {"sha256": digest(path), "bytes": path.stat().st_size} for name, path in assets.items() if name != "native_helper"}
        policy = runtime / "worker-policy.json"
        write_private(policy, {"schema_version": 1, "profile_sha256": profile, "pipeline_mode": "variants", "capsule_kind": "native", "source_pins": pins})
        report["profile_sha256"] = profile
        broker_log = (run / "broker.log").open("xb")
        broker = subprocess.Popen([str(bin_dir / "artifact-broker"), "--config", str(config_path)], env=env,
                                  stdout=broker_log, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 15
        while not Path(config["socket_path"]).is_socket():
            if broker.poll() is not None or time.monotonic() > deadline:
                raise Failure("broker_socket_readiness_failed")
            time.sleep(0.05)
        upload_port, results_port = free_port(), free_port()
        upload_base, results_base = f"https://127.0.0.1:{upload_port}", f"https://127.0.0.1:{results_port}"
        client_a, client_b = context(pki, "researcher-a"), context(pki, "researcher-b")
        base = {"image": IMAGE, "pull_policy": "never", "user": "1000:1000", "read_only": True, "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"], "init": True, "pids_limit": 128, "cpus": 1.0, "mem_limit": "512m",
                "labels": {"org.biozero.acceptance_nonce": ownership_nonce},
                "stop_grace_period": "40s", "logging": {"driver": "json-file", "options": {"max-size": "5m", "max-file": "2"}}}
        common = {"BIOZERO_DATA_DIR": "/data", "BIOZERO_SECURITY_MODE": "protected"}
        services = {}
        mount_sets = {}
        for service, executable, port, address in (("upload", "upload-api", upload_port, "BIOZERO_UPLOAD_ADDR"), ("results", "results-api", results_port, "BIOZERO_RESULTS_ADDR")):
            volumes = [mount(bin_dir / executable, "/run/bin/service", True), mount(pki / ("runtime/" + service), "/pki", True), mount(data / "jobs", "/data/jobs", service == "results")]
            if service == "upload":
                volumes.extend([mount(data / "uploads", "/data/uploads", False), mount(data / "admission", "/data/admission", False)])
            else:
                volumes.append(mount(data / "results", "/data/results", True))
            services[service] = {**base, "entrypoint": ["/run/bin/service"], "networks": ["local"], "ports": [f"127.0.0.1:{port}:{port}"],
                                 "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777"], "volumes": volumes,
                                 "environment": {**common, address: f"0.0.0.0:{port}", "BIOZERO_TLS_CERT": "/pki/server.crt", "BIOZERO_TLS_KEY": "/pki/server.key", "BIOZERO_TLS_CA": "/pki/ca.crt"}}
            mount_sets[service] = volumes
        volumes = [mount(bin_dir / "enclave-runner", "/run/bin/enclave-runner", True), mount(data / "uploads", "/data/uploads", True),
                   mount(pki / "runtime/worker", "/pki", True), mount(host / "channel", "/channel", True), mount(policy, "/config/worker-policy.json", True)]
        volumes.extend(mount(data / name, "/data/" + name, False) for name in ("jobs", "results", "worker-custody", "security-events"))
        services["worker"] = {**base, "entrypoint": ["/run/bin/enclave-runner"], "network_mode": "none", "volumes": volumes,
                              "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777", "/data/decrypted:rw,noexec,nosuid,nodev,size=32m,nr_inodes=4096,uid=1000,gid=1000,mode=0700"],
                              "environment": {**common, "BIOZERO_EXECUTION_BACKEND": "capsule", "BIOZERO_PIPELINE_MODE": "variants", "BIOZERO_POLL_SECONDS": "0.05", "BIOZERO_PIPELINE_TIMEOUT": "90s",
                                              "BIOZERO_PRIVATE_KEY": "/pki/decrypt.key", "BIOZERO_SIGNER_CERT": "/pki/signer.crt", "BIOZERO_DECRYPT_DIR": "/data/decrypted",
                                              "BIOZERO_ARTIFACT_SOCKET": "/channel/b.sock", "BIOZERO_ARTIFACT_PROFILE_SHA256": profile, "BIOZERO_ARTIFACT_PROJECTION_POLICY": "/config/worker-policy.json",
                                              "BIOZERO_WORKER_CUSTODY_DIR": "/data/worker-custody", "BIOZERO_SECURITY_EVENTS_DIR": "/data/security-events"}}
        mount_sets["worker"] = volumes
        compose_path = runtime / "compose.json"
        write_private(compose_path, {"services": services, "networks": {"local": {
            "driver": "bridge", "driver_opts": {"com.docker.network.bridge.host_binding_ipv4": "127.0.0.1"}}}})
        compose_prefix = DOCKER + ["compose", "--project-name", project, "--file", str(compose_path)]
        compose(["config", "--quiet"], "compose-config")
        if compose(["ps", "--all", "--quiet"], "fresh-project-preflight").stdout.strip():
            raise Failure("compose_project_not_empty")
        started = True
        compose(["up", "--detach", "--no-build", "--pull", "never", *SERVICES], "compose-up", timeout=120)
        network_format = '{"name":{{json .Name}},"driver":{{json .Driver}},"internal":{{json .Internal}},"options":{{json .Options}}}'
        network = json.loads(command(DOCKER + ["network", "inspect", project + "_local", "--format", network_format], "api-network-inspect").stdout)
        record("api_project_bridge_with_loopback_default", network.get("name") == project + "_local" and network.get("driver") == "bridge"
               and network.get("internal") is False and network.get("options", {}).get("com.docker.network.bridge.host_binding_ipv4") == "127.0.0.1")
        service_ports = {"upload": upload_port, "results": results_port}
        for service in SERVICES:
            observed = inspect(service)
            h = observed["host"]
            actual_binds = {row["Destination"]: (row["Source"], row["RW"]) for row in observed["mounts"] if row["Type"] == "bind"}
            expected_binds = {row["target"]: (row["source"], not row["read_only"]) for row in mount_sets[service]}
            expected_tmpfs = {"/tmp"} | ({"/data/decrypted"} if service == "worker" else set())
            unexpected_mount = any(row["Type"] not in {"bind", "tmpfs"} or (row["Type"] == "tmpfs" and row["Destination"] not in expected_tmpfs) for row in observed["mounts"])
            expected_ports = {} if service == "worker" else {f"{service_ports[service]}/tcp": [
                {"HostIp": "127.0.0.1", "HostPort": str(service_ports[service])}]}
            # API maps must be nonempty and exact. Docker29's sole internal
            # bridge can retain PortBindings while actual Ports is null.
            ports_match = (observed["ports"] or {}) == expected_ports and (h.get("PortBindings") or {}) == expected_ports
            record("container_controls_and_exact_mounts_" + service, observed["image"] == IMAGE and observed["user"] == "1000:1000"
                   and h.get("ReadonlyRootfs") is True and h.get("Init") is True and h.get("CapDrop") == ["ALL"]
                   and h.get("Privileged") is False and not h.get("CapAdd") and h.get("PidMode", "") == ""
                   and any(x in ("no-new-privileges:true", "no-new-privileges") for x in h.get("SecurityOpt", []))
                   and h.get("Memory") == 512 << 20 and h.get("PidsLimit") == 128 and h.get("NanoCpus") == 1000000000
                   and actual_binds == expected_binds and not unexpected_mount and set(h.get("Tmpfs", {})) == expected_tmpfs
                   and ports_match and h.get("NetworkMode") == ("none" if service == "worker" else project + "_local"))
        for base_url in (upload_base, results_base):
            deadline = time.monotonic() + 20
            while True:
                try:
                    code, raw = request(base_url + "/health", client_a)
                    if code == 200 and raw == b"ok":
                        break
                except (OSError, urllib.error.URLError):
                    pass
                if time.monotonic() > deadline:
                    raise Failure("tls_service_readiness_failed")
                time.sleep(0.1)
        deadline = time.monotonic() + 15
        while not (data / "worker-custody/journal.json").is_file():
            if time.monotonic() > deadline:
                raise Failure("worker_custody_readiness_failed")
            time.sleep(0.05)
        worker_state = inspect("worker")
        init_pid = worker_state["state"]["Pid"]
        worker_children = children(init_pid)
        if len(worker_children) != 1:
            raise Failure("worker_child_identity_ambiguous")
        worker_pid = next(iter(worker_children))
        stage_path = Path(f"/proc/{worker_pid}/root/data/decrypted")
        filesystem = os.statvfs(stage_path)
        status = dict(line.split(":", 1) for line in Path(f"/proc/{worker_pid}/status").read_text().splitlines() if ":" in line)
        mounts = [line for line in Path(f"/proc/{worker_pid}/mountinfo").read_text().splitlines() if line.split()[4] == "/data/decrypted"]
        record("worker_plaintext_tmpfs_actual_kernel_guards", len(mounts) == 1 and " - tmpfs " in mounts[0] and filesystem.f_blocks * filesystem.f_frsize == 32 << 20
               and filesystem.f_files == 4096 and filesystem.f_flag & 14 == 14 and status.get("NoNewPrivs", "").strip() == "1"
               and digest(Path(f"/proc/{worker_pid}/exe")) == source_binary_pins["enclave-runner"]["sha256"]
               and all(status.get(name, "").strip() == "0000000000000000" for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")),
               {"capacity_bytes": filesystem.f_blocks * filesystem.f_frsize, "inode_units": filesystem.f_files})

        def submit(path, label):
            argv = [bin_dir / "uploader-cli", "--file", path, "--client-id", "researcher-a", "--upload-url", upload_base + "/upload", "--results-url", results_base + "/results",
                    "--mtls-cert", pki / "clients/researcher-a.crt", "--mtls-key", pki / "clients/researcher-a.key", "--ca-cert", pki / "clients/ca.crt",
                    "--server-cert", pki / "clients/decrypt.crt", "--sign-key", pki / "clients/signer.key", "--wait-timeout", "110s", "--poll-seconds", "1"]
            uploaded = command(argv, "submit-" + label, timeout=120, check=False)
            match = re.search(r"uploaded job ([0-9a-f]{16})", uploaded.stdout)
            if not match:
                raise Failure("protected_upload_job_missing")
            job = match.group(1)
            result = await_result(job)
            write_private(run / (label + "-result.json"), result)
            return job, result, uploaded.returncode

        jobs, leases, callsets = [], [], []
        for number in (1, 2):
            job, payload, exit_code = submit(FIXTURE / "reads.fastq", "valid-" + str(number))
            jobs.append(job)
            result = payload.get("data", {})
            evaluation, binding = result.get("scientific_evaluation", {}), result.get("artifact_execution", {})
            record("protected_three_snp_" + str(number), exit_code == 0 and payload.get("status") == "succeeded" and result.get("release_status") == "evaluated_passed"
                   and evaluation.get("evaluation_status") == "passed" and evaluation.get("tp") == 3 and evaluation.get("fp") == 0 and evaluation.get("fn") == 0
                   and evaluation.get("precision") == 1 and evaluation.get("recall") == 1)
            job_meta = json.loads((data / "jobs" / (job + ".json")).read_text())
            record("ciphertext_and_plaintext_hashes_" + str(number), result.get("signature_valid") is True and result.get("decrypted") is True
                   and result.get("upload_sha256") == job_meta["sha256"] and result.get("processed_sha256") == digest(FIXTURE / "reads.fastq")
                   and result.get("size_bytes") == (FIXTURE / "reads.fastq").stat().st_size and job_meta["size_bytes"] != result.get("size_bytes"))
            lease = binding.get("lease_id", "")
            if not re.fullmatch("[0-9a-f]{32}", lease):
                raise Failure("retained_lease_invalid")
            objects = host / "store/objects" / lease
            manifest_raw, receipt_raw, proof_raw = [(objects / name).read_bytes() for name in ("manifest.json", "execution_receipt", "proof.json")]
            manifest, receipt, proof = [json.loads(raw) for raw in (manifest_raw, receipt_raw, proof_raw)]
            receipt_science = receipt.get("evaluation", {}).get("payload", {})
            record("receipt_context_science_and_pins_" + str(number), receipt.get("source_pins") == pins
                   and receipt.get("input_sha256") == result.get("processed_sha256") and receipt.get("input_bytes") == result.get("size_bytes")
                   and receipt.get("analysis_context", {}).get("original_name") == job_meta.get("original_name")
                   and receipt.get("analysis_context", {}).get("processed_size_bytes") == result.get("size_bytes")
                   and all(evaluation.get(key) == receipt_science.get(key) for key in ("evaluation_status", "tp", "fp", "fn", "precision", "recall")))
            alignment = result.get("detection", {}).get("signals", {}).get("alignment", {})
            detection = result.get("detection", {})
            record("actual_detection_and_1171_mapped_reads_" + str(number), detection.get("score") == 0.7 and detection.get("verdict") == "medium"
                   and "threat_panel_hit" in detection.get("reasons", []) and alignment.get("mapped_reads") == 1171 and alignment.get("total_reads") == 1171
                   and alignment.get("fraction") == 1 and len(alignment.get("targets", {})) == 1)
            retained = set(binding.get("files", {})) == ARTIFACTS
            for name, file in binding.get("files", {}).items():
                if name not in ARTIFACTS:
                    retained = False
                    continue
                path = objects / name
                retained = retained and path.is_file() and digest(path) == file.get("sha256") and path.stat().st_size == file.get("bytes")
                retained = retained and manifest.get("files", {}).get(name) == {"state": "verified", **file}
            record("four_artifacts_receipt_and_proof_" + str(number), retained and binding.get("profile_sha256") == profile
                   and hashlib.sha256(manifest_raw).hexdigest() == binding.get("manifest_sha256") and hashlib.sha256(receipt_raw).hexdigest() == binding.get("receipt_sha256")
                   and binding.get("receipt_bytes") == len(receipt_raw) and proof.get("capsule_wait_finished") is True and proof.get("export_authority_closed") is True
                   and proof.get("manifest_sha256") == binding.get("manifest_sha256")
                   and receipt.get("analysis_context", {}).get("signature_valid") is True and receipt.get("analysis_context", {}).get("decrypted") is True)
            record("observed_evaluated_retained_vcf_hash_" + str(number), manifest.get("observed_sha256") == manifest.get("evaluated_sha256") == digest(objects / "normalized_vcf"))
            record("worker_did_not_materialize_unbounded_outputs_" + str(number), not (data / "artifacts" / job).exists()
                   and result.get("pipeline_output", {}).get("outputs", {}).get("normalized_vcf") == "normalized_vcf"
                   and "raw_stdout" not in json.dumps(result) and "raw_stderr" not in json.dumps(result))
            code, _ = request(results_base + "/results/" + job, client_b, headers={"X-Client-Id": "researcher-a"})
            record("nonowner_cannot_spoof_header_" + str(number), code == 403)
            leases.append(lease)
            callsets.append(snp_keys(objects / "normalized_vcf"))
        record("repeat_exact_three_snp_callset", jobs[0] != jobs[1] and leases[0] != leases[1] and callsets[0] == callsets[1] == snp_keys(FIXTURE / "expected.vcf") and len(callsets[0]) == 3)
        _, invalid, invalid_exit = submit(FIXTURE / "invalid.fastq", "invalid")
        record("invalid_fastq_withheld_with_custody", invalid_exit != 0 and invalid.get("status") == "failed" and invalid.get("data", {}).get("release_status") == "withheld"
               and invalid.get("data", {}).get("artifact_execution") is not None)
        journals = {"store": host / "store/ledger.json", "broker": host / "journal/journal.json", "worker": data / "worker-custody/journal.json"}
        before = {key: digest(path) for key, path in journals.items()}
        boundary = "biozero-compose-capsule"
        unsigned = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="unsigned.fastq"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() + (FIXTURE / "reads.fastq").read_bytes() + f"\r\n--{boundary}--\r\n".encode()
        code, raw = request(upload_base + "/upload", client_a, unsigned, {"Content-Type": "multipart/form-data; boundary=" + boundary})
        record("unsigned_upload_reaches_verifier", code == 200)
        rejected = await_result(json.loads(raw)["job_id"])
        record("unsigned_rejected_before_any_custody", rejected.get("status") == "rejected" and rejected.get("data", {}).get("error_code") == "signature_required"
               and before == {key: digest(path) for key, path in journals.items()})
        anonymous_rejected = False
        try:
            request(upload_base + "/health", context(pki))
        except (ssl.SSLError, urllib.error.URLError) as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            anonymous_rejected = isinstance(reason, ssl.SSLError) and any(word in str(reason).lower() for word in ("certificate required", "certificate_required", "bad certificate", "handshake failure"))
        code, _ = request(upload_base + "/health", client_a)
        record("missing_client_certificate_rejected_with_live_tls", anonymous_rejected and code == 200)
        command(DOCKER + ["stop", "--time", "40", owned_ids["worker"]], "stop-worker-before-recovery", timeout=60)
        record("worker_clean_stop_before_recovery", inspect("worker")["state"]["ExitCode"] == 0)
        target = jobs[0]
        result_path = data / "results" / (target + ".json")
        original = result_path.read_bytes()
        with (run / "lost-publication-original.json").open("xb") as backup:
            backup.write(original)
        # Only this newly created synthetic fixture's confirmed result is removed;
        # original bytes are retained privately. No Store/broker/custody mutation.
        result_path.unlink()
        job_path = data / "jobs" / (target + ".json")
        job_meta = json.loads(job_path.read_text())
        job_meta["status"] = "running"
        write_private(job_path, job_meta)
        command(DOCKER + ["start", owned_ids["worker"]], "restart-same-worker-with-history")
        recovered = await_result(target)
        previous = json.loads(original)
        record("restart_lost_publication_same_lease_without_execution", recovered.get("status") == "succeeded"
               and recovered.get("data", {}).get("release_status") == "evaluated_passed"
               and all(recovered.get("data", {}).get(key) == previous.get(key) for key in ("detection", "artifact_execution", "scientific_evaluation"))
               and before == {key: digest(path) for key, path in journals.items()} and broker.poll() is None and inspect("worker")["state"]["Running"] is True)
        complete = True
    except Exception as exc:
        report["error_type"] = type(exc).__name__
        if isinstance(exc, Failure):
            report["error_code"] = str(exc)
        persist()
        raise Failure("compose_capsule_acceptance_failed") from None
    finally:
        cleanup_ok = True
        if started:
            try:
                compose(["logs", "--no-color", "--tail", "200", *SERVICES], "service-logs", check=False)
                # Discover partial-start objects only through the private nonce;
                # stop exact known IDs, never project-wide unknown objects.
                for name in SERVICES:
                    try:
                        row = inspect(name, missing_ok=True)
                        if row is None:
                            cleanup_ok = False
                    except Exception as exc:
                        cleanup_ok = False
                        report.setdefault("object_stop_errors", {})[name] = type(exc).__name__
                    if name in owned_ids:
                        try:
                            if command(DOCKER + ["stop", "--time", "40", owned_ids[name]], "stop-owned-" + name,
                                       timeout=60, check=False).returncode:
                                cleanup_ok = False
                        except Exception as exc:
                            cleanup_ok = False
                            report.setdefault("object_stop_errors", {})[name] = type(exc).__name__
                final = {name: inspect(name) for name in SERVICES if name in owned_ids}
                report["stopped_objects_preserved"] = all(not row["state"]["Running"] for row in final.values())
                report["expected_container_exits"] = all(row["state"]["ExitCode"] in ({0} if name == "worker" else {0, 143}) for name, row in final.items())
                cleanup_ok = cleanup_ok and report["stopped_objects_preserved"] and report["expected_container_exits"]
            except Exception as exc:
                cleanup_ok = False
                report["container_stop_error_type"] = type(exc).__name__
        if broker is not None:
            if broker.poll() is None:
                broker.send_signal(signal.SIGTERM)
            try:
                broker.wait(timeout=45)
            except subprocess.TimeoutExpired:
                # Only the host session started by this harness; forced exit is
                # a failure, never proof of completion or permission to refund.
                os.killpg(broker.pid, signal.SIGKILL)
                broker.wait(timeout=5)
                cleanup_ok = False
            report["broker_returncode"] = broker.returncode
            cleanup_ok = cleanup_ok and broker.returncode == 0
        if broker_log is not None:
            broker_log.close()
        try:
            report["source_hashes_after"] = source_pins()
            report["source_unchanged"] = report["source_hashes_after"] == report["source_hashes"]
            report["binary_sources_unchanged"] = all(digest(args.binaries_dir / name) == pin["sha256"] for name, pin in report.get("binary_pins", {}).items())
            report["copied_binaries_unchanged"] = all(digest(bin_dir / name) == pin["sha256"] for name, pin in report.get("binary_pins", {}).items())
            cleanup_ok = cleanup_ok and report["source_unchanged"] and report["binary_sources_unchanged"] and report["copied_binaries_unchanged"]
        except Exception as exc:
            cleanup_ok = False
            report["final_pin_error_type"] = type(exc).__name__
        report["status"] = "passed" if complete and cleanup_ok else "failed"
        report["ended_at"] = datetime.now(timezone.utc).isoformat()
        persist()
        if complete and not cleanup_ok:
            raise Failure("shutdown_or_pin_verification_failed")


if __name__ == "__main__":
    main()
