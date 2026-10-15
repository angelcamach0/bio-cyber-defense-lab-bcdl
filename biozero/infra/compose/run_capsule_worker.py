#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Opt-in three-service Compose acceptance with an explicit host broker provider.

Uses existing pinned Go binaries and one exact cached image. No build/pull,
reviewer/browser, external network, model or historical reset. Successful Docker
capsules are removed by their provider only after authoritative wait/inspection.
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
import selectors
import signal
import ssl
import stat
import subprocess
import sys
import threading
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
CAPSULE_TMPFS = "rw,noexec,nosuid,nodev,size=134217728,nr_inodes=4096,mode=0700,uid=1000,gid=1000"


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


class CapsuleObserver:
    """Read-only, bounded daemon evidence, not quiescence/export authority.

    The upload service is an explicit subscription barrier. Only its exact ID
    may be excluded from the three capsule actors after service inspection.
    """

    def __init__(self, store, nonce, run, env):
        self.store, self.nonce, self.run, self.env = store, nonce, run, env
        self.lock, self.stop = threading.Lock(), threading.Event()
        self.actors, self.barrier, self.events = {}, {}, []
        self.error, self.bytes, self.exit_code = None, 0, None
        self.stderr = (run / "capsule-observer-stderr.log").open("xb")
        since = str(int(time.time()) - 1)
        self.proc = subprocess.Popen(DOCKER + ["events", "--since", since, "--filter", "type=container",
                                    "--filter", "label=biozero.artifact.store=" + store,
                                    *[item for action in ("create", "start", "die", "destroy") for item in ("--filter", "event=" + action)],
                                    "--format", "{{json .}}"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     start_new_session=True)
        self.thread = threading.Thread(target=self._read, name="capsule-events", daemon=True)
        self.thread.start()

    def _inspect(self, actor):
        fmt = '{"id":{{json .Id}},"image":{{json .Image}},"state":{{json .State}},"config":{{json .Config}},"host":{{json .HostConfig}},"mounts":{{json .Mounts}}}'
        proc = subprocess.Popen(DOCKER + ["inspect", "--format", fmt, actor], env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
        selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + 5
        try:
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise Failure("capsule_inspect_deadline_exceeded")
                for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    limit = 1 << 20 if key.data == "stdout" else 65536
                    if len(buffers[key.data]) + len(chunk) > limit:
                        raise Failure("capsule_inspect_output_limit")
                    buffers[key.data].extend(chunk)
            code = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
            return json.loads(buffers["stdout"]) if code == 0 else None
        finally:
            selector.close()
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
            proc.stdout.close()
            proc.stderr.close()

    def _event(self, raw):
        event = json.loads(raw)
        if event.get("Type") != "container" or not isinstance(event.get("Actor"), dict):
            raise Failure("capsule_event_shape_invalid")
        actor = event["Actor"].get("ID", "")
        attrs = event["Actor"].get("Attributes", {})
        if not re.fullmatch("[0-9a-f]{64}", actor) or attrs.get("biozero.artifact.store") != self.store:
            raise Failure("capsule_event_identity_invalid")
        action = event.get("Action")
        with self.lock:
            self.events.append(event)
            if len(self.events) > 128:
                raise Failure("capsule_event_count_limit")
            if attrs.get("org.biozero.acceptance_observer") is not None:
                if (attrs.get("org.biozero.acceptance_observer") != self.nonce
                        or attrs.get("org.biozero.acceptance_nonce") != self.nonce
                        or "biozero.artifact.lease" in attrs or "biozero.artifact.nonce" in attrs
                        or (self.barrier and self.barrier["id"] != actor)):
                    raise Failure("capsule_event_barrier_invalid")
                self.barrier.setdefault("id", actor)
                self.barrier.setdefault("actions", []).append(action)
                return
            lease, nonce = attrs.get("biozero.artifact.lease", ""), attrs.get("biozero.artifact.nonce", "")
            if not re.fullmatch("[0-9a-f]{32}", lease) or not re.fullmatch("[0-9a-f]{32}", nonce):
                raise Failure("capsule_event_identity_invalid")
            row = self.actors.setdefault(actor, {"id": actor, "store": self.store, "lease": lease,
                                                "nonce": nonce, "actions": [], "snapshot": None})
            if row["lease"] != lease or row["nonce"] != nonce:
                raise Failure("capsule_event_identity_changed")
            if action not in {"create", "start", "die", "destroy"}:
                raise Failure("capsule_event_action_unexpected")
            order = ["create", "start", "die", "destroy"]
            if len(row["actions"]) >= 4 or order[len(row["actions"])] != action:
                raise Failure("capsule_event_order_invalid")
            if type(event.get("timeNano")) is not int or event["timeNano"] <= row.get("last_time", 0):
                raise Failure("capsule_event_time_invalid")
            row["actions"].append(action)
            row["last_time"] = event["timeNano"]
            if action == "die":
                row["exit_code"] = attrs.get("exitCode")
            needs_inspect = action in {"create", "start"} and row["snapshot"] is None
        if needs_inspect:
            snapshot = self._inspect(actor)
            if snapshot is not None and snapshot.get("state", {}).get("Status") in {"created", "running"}:
                with self.lock:
                    row["snapshot"] = snapshot

    def _read(self):
        pending = b""
        selector = selectors.DefaultSelector()
        selector.register(self.proc.stdout, selectors.EVENT_READ, "events")
        selector.register(self.proc.stderr, selectors.EVENT_READ, "stderr")
        stderr_bytes = 0
        try:
            while not self.stop.is_set():
                selected = selector.select(0.1)
                if not selected:
                    if self.proc.poll() is not None:
                        raise Failure("capsule_event_stream_ended")
                    continue
                for key, _ in selected:
                    raw = os.read(key.fileobj.fileno(), 65536)
                    if not raw:
                        raise Failure("capsule_event_stream_ended")
                    self.bytes += len(raw)
                    if self.bytes > 1 << 20:
                        raise Failure("capsule_event_total_limit")
                    if key.data == "stderr":
                        stderr_bytes += len(raw)
                        if stderr_bytes > 65536:
                            raise Failure("capsule_event_stderr_limit")
                        self.stderr.write(raw)
                        self.stderr.flush()
                        continue
                    pending += raw
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        if not line or len(line) > 65536:
                            raise Failure("capsule_event_frame_limit")
                        self._event(line)
                    if len(pending) > 65536:
                        raise Failure("capsule_event_frame_limit")
        except Exception as exc:
            with self.lock:
                self.error = str(exc) if isinstance(exc, Failure) else "capsule_event_observer_failed"
        finally:
            selector.close()

    def ready(self, upload_id):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with self.lock:
                if self.error:
                    raise Failure(self.error)
                if self.barrier.get("id") == upload_id and "start" in self.barrier.get("actions", []):
                    return
            time.sleep(0.05)
        raise Failure("capsule_event_subscription_not_observed")

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps({"store_id": self.store, "barrier": self.barrier,
                                         "actors": self.actors, "events": self.events, "error_code": self.error}))

    def finish(self):
        # Terminate only the observer CLI. No signal reaches a capsule/container.
        with self.lock:
            if (not self.thread.is_alive() or self.proc.poll() is not None) and self.error is None:
                self.error = "capsule_event_observer_ended_before_shutdown"
        self.stop.set()
        self.thread.join(timeout=12)
        # The thread's deliberate stop never asks Docker events to exit. An
        # already-finished CLI here is unexpected even if its exit code is 0.
        if self.proc.poll() is not None and self.error is None:
            self.error = "capsule_event_observer_ended_before_shutdown"
        if self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGTERM)
        try:
            self.exit_code = self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait(timeout=5)
            self.error = "capsule_event_observer_forced_exit"
        self.proc.stdout.close()
        self.proc.stderr.close()
        self.stderr.close()
        if self.thread.is_alive():
            self.error = "capsule_event_observer_not_joined"
        value = self.snapshot()
        value.update(bytes_read=self.bytes, returncode=self.exit_code, joined=not self.thread.is_alive(),
                     expected_exit=self.exit_code in (0, -signal.SIGTERM, 128 + signal.SIGTERM))
        write_private(self.run / "capsule-observer.json", value)
        return value


def covering_mount(mounts, path):
    rows = [row for row in mounts if row.get("mountpoint") == "/" or path == row.get("mountpoint")
            or path.startswith(row.get("mountpoint", "") + "/")]
    if not rows:
        raise Failure("receipt_covering_mount_missing")
    longest = max(len(row["mountpoint"]) for row in rows)
    rows = [row for row in rows if len(row["mountpoint"]) == longest]
    if len(rows) != 1:
        raise Failure("receipt_covering_mount_ambiguous")
    return rows[0]


def docker_receipt_checks(receipt, config):
    """Independent receipt predicates, without importing provider validators."""
    state = receipt.get("capsule_state", {})
    mounts = state.get("mounts", [])
    root, work, cgroup_mount = [covering_mount(mounts, path) for path in ("/", "/workspace", "/sys/fs/cgroup")]
    fs = state.get("workspace_statfs", {})
    group = state.get("cgroup", {})
    cpu = group.get("cpu.max", "").split()
    paths = ["/run/biozero/helpers/container_capsule.py", "/run/biozero/helpers/native_capsule.py",
             "/run/biozero/pipeline/pipeline.py", "/run/biozero/pipeline/resource_budget.py",
             "/run/biozero/reference.fa", "/run/biozero/truth.vcf", "/run/biozero/evaluator/evaluate_variants.py",
             "/run/biozero/analysis/capsule-analysis", "/run/biozero/analysis/rules.json", "/run/biozero/analysis/panel.fa",
             "/run/biozero/channel", "/usr/bin/python3.12", "/usr/bin"]
    return {
        "docker_receipt_schema_helper_and_keeper": receipt.get("schema_version") == 2 and receipt.get("capsule_kind") == "docker"
            and receipt.get("native_helper_sha256") == config["native_helper"]["sha256"]
            and receipt.get("keeper_monitor") == "active; EOF/error is cancellation, never proof"
            and receipt.get("workspace_policy") == {"filesystem": "tmpfs", "bytes": 128 << 20, "nr_inodes": 4096, "file_bytes": 64 << 20},
        "docker_receipt_identity_caps_network_and_fsize": all(type(state.get(k)) is int and state[k] == v for k, v in
            (("pid", 1), ("uid", 1000), ("euid", 1000), ("gid", 1000), ("egid", 1000)))
            and all(state.get(k) == "0000000000000000" for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
            and state.get("NoNewPrivs") == "1" and state.get("interfaces") == ["lo"] and state.get("rlimit_fsize") == [64 << 20, 64 << 20]
            and all(re.fullmatch(name + r":\[\d+\]", state.get("namespaces", {}).get(name, "")) for name in ("user", "mnt", "pid", "net")),
        "docker_receipt_actual_workspace_and_readonly_sources": "ro" in root["options"] and "rw" not in root["options"]
            and state.get("root_statfs", {}).get("flags", 0) & 1 == 1
            and work["mountpoint"] == "/workspace" and work["filesystem"] == "tmpfs"
            and {"rw", "noexec", "nosuid", "nodev"}.issubset(work["options"])
            and not any(x.startswith(("shared:", "master:")) for x in work["optional"])
            and fs.get("filesystem_magic") == 0x1021994 and fs.get("capacity_bytes") == 128 << 20
            and fs.get("inode_units") == 4096 and fs.get("flags", 0) & 14 == 14 and fs.get("flags", 0) & 1 == 0
            and state.get("workspace_directory") == {"uid": 1000, "gid": 1000, "mode": 0o700, "empty": True}
            and all("ro" in covering_mount(mounts, path)["options"] for path in paths),
        "docker_receipt_actual_cgroup_limits": cgroup_mount["filesystem"] == "cgroup2" and "ro" in cgroup_mount["options"]
            and group.get("membership") == "0::/" and bool(re.fullmatch(r"cgroup:\[\d+\]", group.get("namespace", "")))
            and group.get("memory.max") == "536870912" and group.get("memory.swap.max") == "0" and group.get("pids.max") == "128"
            and len(cpu) == 2 and all(x.isascii() and x.isdecimal() for x in cpu) and int(cpu[0]) == int(cpu[1]) > 0,
    }


def docker_snapshot_matches(row, config):
    observed = row.get("snapshot") or {}
    c, h = observed.get("config", {}), observed.get("host", {})
    labels = c.get("Labels") or {}
    assets = {"container_helper": "/run/biozero/helpers/container_capsule.py", "native_helper": "/run/biozero/helpers/native_capsule.py",
              "pipeline": "/run/biozero/pipeline/pipeline.py", "resource_budget": "/run/biozero/pipeline/resource_budget.py",
              "reference": "/run/biozero/reference.fa", "truth": "/run/biozero/truth.vcf", "evaluator": "/run/biozero/evaluator/evaluate_variants.py",
              "analysis_executable": "/run/biozero/analysis/capsule-analysis", "analysis_rules": "/run/biozero/analysis/rules.json", "analysis_panel": "/run/biozero/analysis/panel.fa"}
    expected = {target: (config[key]["path"], False, "rprivate") for key, target in assets.items()}
    expected["/run/biozero/channel"] = (str(Path(config["workspace_root"]) / ("capsule-" + row["nonce"])), False, "rprivate")
    binds = {x["Destination"]: (x["Source"], x["RW"], x.get("Propagation")) for x in observed.get("mounts", []) if x["Type"] == "bind"}
    mounts_ok = len(binds) == len(expected) and binds == expected and all(x["Type"] == "bind" or
                 (x["Type"] == "tmpfs" and x["Destination"] == "/workspace") for x in observed.get("mounts", []))
    offline = ["PATH=/usr/bin", "LANG=C", "LC_ALL=C", "PYTHONDONTWRITEBYTECODE=1"] + [name + "=" for name in
               ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy")]
    return (observed.get("id") == row["id"] and observed.get("image") == IMAGE
            and all(labels.get("biozero.artifact." + k) == row[k] for k in ("store", "lease", "nonce"))
            and c.get("User") == "1000:1000" and c.get("WorkingDir") == "/workspace"
            and c.get("Entrypoint") == ["/usr/bin/python3.12"] and c.get("Cmd") == ["-I", "-B", "-S", "/run/biozero/helpers/container_capsule.py"]
            and sorted(c.get("Env") or []) == sorted(offline) and not c.get("Volumes")
            and h.get("ReadonlyRootfs") is True and h.get("Privileged") is False and h.get("CapDrop") == ["ALL"] and not h.get("CapAdd")
            and h.get("SecurityOpt") == ["no-new-privileges"] and h.get("NetworkMode") == "none"
            and h.get("PidMode", "") == "" and h.get("UsernsMode", "") == "" and h.get("IpcMode") == "private" and h.get("CgroupnsMode") == "private"
            and h.get("RestartPolicy", {}).get("Name") == "no" and h.get("Memory") == 512 << 20 and h.get("MemorySwap") == 512 << 20
            and h.get("PidsLimit") == 128 and h.get("NanoCpus") == 1000000000 and h.get("ShmSize") == 65536
            and h.get("Init") is False and not h.get("Devices") and not h.get("PortBindings") and h.get("LogConfig", {}).get("Type") == "none"
            and h.get("Tmpfs") == {"/workspace": CAPSULE_TMPFS}
            and [x for x in h.get("Ulimits", []) if x.get("Name") == "fsize"] == [{"Name": "fsize", "Soft": 64 << 20, "Hard": 64 << 20}]
            and mounts_ok)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path, help="New private ignored .biozero path or a path outside the repository")
    parser.add_argument("--binaries-dir", required=True, type=Path, help="Existing current-UID ARM64 Go executable directory; never built here")
    parser.add_argument("--capsule-provider", choices=("native", "docker"), default="native", help="Actual broker capsule provider; app containers alone do not select it")
    parser.add_argument("--tools-prefix", type=Path, help="Existing native broker tool prefix; required only for native capsules")
    args = parser.parse_args()
    if args.capsule_provider == "native" and args.tools_prefix is None:
        parser.error("native capsules require --tools-prefix")
    if args.capsule_provider == "docker" and args.tools_prefix is not None:
        parser.error("docker capsules use image tools; omit --tools-prefix")
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
    tools = args.tools_prefix.resolve() if args.tools_prefix is not None else None
    if tools is not None:
        env["PATH"] = str(tools / "bin") + os.pathsep + env.get("PATH", "")
    provider = args.capsule_provider
    report = {"schema_version": 1, "started_at": datetime.now(timezone.utc).isoformat(), "status": "failed",
              "scope": "three-service Compose upload/results/protected worker, individual mTLS, signature/encryption and host " + provider + " v2 FD broker; no reviewer/browser, biological model or image-build reproducibility claim",
              "runtime_root": str(runtime), "image_id": IMAGE, "provider": provider, "cases": [], "source_hashes": {}, "containers": {}}
    project = "bz-cw-" + secrets.token_hex(6)
    ownership_nonce = secrets.token_hex(16)
    owned_ids = {}
    compose_prefix = None
    started = False
    broker = None
    broker_log = None
    observer = None
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
        fmt = '{"id":{{json .Id}},"image":{{json .Image}},"state":{{json .State}},"user":{{json .Config.User}},"ownership":{{json (index .Config.Labels "org.biozero.acceptance_nonce")}},"observer":{{json (index .Config.Labels "org.biozero.acceptance_observer")}},"store":{{json (index .Config.Labels "biozero.artifact.store")}},"host":{{json .HostConfig}},"mounts":{{json .Mounts}},"ports":{{json .NetworkSettings.Ports}}}'
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
        config = {"schema_version": 1, "provider": provider, "mode": "variants", "store_root": str(host / "store"),
                  "journal_root": str(host / "journal"), "workspace_root": str(host / "workspace"), "socket_path": str(host / "channel/b.sock"),
                  "allowed_uid": 1000, "timeout_seconds": 60, "python_path": str(Path("/usr/bin/python3").resolve()) if provider == "native" else "",
                  "tool_path": str(tools / "bin") + ":/usr/bin" if provider == "native" else "", "docker_command": [], "image_id": "", "container_helper": {"path": "", "sha256": ""}}
        config.update({name: {"path": str(path), "sha256": digest(path)} for name, path in assets.items()})
        if provider == "docker":
            config.update(docker_command=["/usr/bin/sudo", "-n", "/usr/bin/docker", "--host=unix:///var/run/docker.sock"],
                          image_id=IMAGE, container_helper={"path": str(capsule / "container_capsule.py"), "sha256": digest(capsule / "container_capsule.py")})
        config_path = runtime / "broker.json"
        write_private(config_path, config)
        profile = command([bin_dir / "artifact-broker", "--config", config_path, "--print-profile"], "print-profile").stdout.strip()
        record("profile_without_store_or_provider_creation", bool(re.fullmatch("[0-9a-f]{64}", profile)) and not (host / "store").exists())
        pins = {name: {"sha256": digest(path), "bytes": path.stat().st_size} for name, path in assets.items() if name != "native_helper"}
        policy = runtime / "worker-policy.json"
        write_private(policy, {"schema_version": 1, "profile_sha256": profile, "pipeline_mode": "variants", "capsule_kind": provider, "source_pins": pins})
        report["profile_sha256"] = profile
        broker_log = (run / "broker.log").open("xb")
        broker = subprocess.Popen([str(bin_dir / "artifact-broker"), "--config", str(config_path)], env=env,
                                  stdout=broker_log, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 15
        while not Path(config["socket_path"]).is_socket():
            if broker.poll() is not None or time.monotonic() > deadline:
                raise Failure("broker_socket_readiness_failed")
            time.sleep(0.05)
        if provider == "docker":
            store_id = json.loads((host / "store/ledger.json").read_bytes()).get("store_id", "")
            if not re.fullmatch("[0-9a-f]{32}", store_id):
                raise Failure("observer_store_identity_invalid")
            observer = CapsuleObserver(store_id, ownership_nonce, run, env)
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
            if service == "upload" and observer is not None:
                services[service]["labels"] = {**base["labels"], "biozero.artifact.store": store_id,
                                               "org.biozero.acceptance_observer": ownership_nonce}
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
        if observer is not None:
            upload_state = inspect("upload")
            observer.ready(upload_state["id"])
            record("docker_observer_subscription_real_upload_barrier", upload_state["store"] == store_id
                   and upload_state["observer"] == ownership_nonce and observer.snapshot()["barrier"]["id"] == upload_state["id"])
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

        def docker_retained(job, payload, label):
            if observer is None:
                return
            result = payload.get("data", {})
            binding = result.get("artifact_execution", {})
            lease = binding.get("lease_id", "")
            if not re.fullmatch("[0-9a-f]{32}", lease):
                raise Failure("docker_retained_lease_invalid")
            objects = host / "store/objects" / lease
            manifest_raw, receipt_raw, proof_raw = [(objects / name).read_bytes() for name in ("manifest.json", "execution_receipt", "proof.json")]
            manifest, receipt, proof = [json.loads(raw) for raw in (manifest_raw, receipt_raw, proof_raw)]
            for name, passed in docker_receipt_checks(receipt, config).items():
                record(name + "_" + label, passed)
            ledger = json.loads((host / "store/ledger.json").read_bytes())
            custody = json.loads((data / "worker-custody/journal.json").read_bytes())
            journal = json.loads((host / "journal/journal.json").read_bytes())
            stored, linked, local = ledger["records"][lease], journal["records"][job], custody["records"][job]
            context_facts = receipt.get("analysis_context")
            record("docker_receipt_exact_context_and_custody_" + label, receipt.get("source_pins") == pins
                   and receipt.get("mode") == "variants" and binding.get("store_id") == store_id
                   and receipt.get("input_sha256") == result.get("processed_sha256") == linked["processed_sha256"] == local["processed_sha256"]
                   and receipt.get("input_bytes") == result.get("size_bytes") == linked["processed_bytes"] == local["processed_bytes"]
                   and result.get("upload_sha256") == stored["input_sha256"] == linked["upload_sha256"] == local["upload_sha256"]
                   and context_facts == journal["analysis_contexts"][job] == local["analysis_context"]
                   and stored["job_id"] == linked["job_id"] == local["job_id"] == job and linked["lease_id"] == lease
                   and linked["stage"] == stored["state"] == "committed" and journal["profile_sha256"] == custody["profile_sha256"] == profile)
            retained = binding.get("files", {})
            expected_files = ARTIFACTS if payload.get("status") == "succeeded" else {"execution_receipt"}
            files_ok = set(retained) == set(stored["files"]) == set(manifest.get("files", {})) == expected_files
            for name, file in retained.items():
                if name not in ARTIFACTS:
                    files_ok = False
                    continue
                path = objects / name
                files_ok = (files_ok and file == {"sha256": digest(path), "bytes": path.stat().st_size}
                            and stored["files"][name] == manifest["files"][name] == {"state": "verified", **file})
            expected_identity = {"store_id": store_id, "lease_id": lease, "job_id": job, "input_sha256": result.get("upload_sha256")}
            outcome = receipt.get("outcome", {})
            record("docker_retained_proof_manifest_and_artifacts_" + label, files_ok
                   and all(manifest.get(key) == proof.get(key) == value for key, value in expected_identity.items())
                   and manifest.get("policy_sha256") == proof.get("policy_sha256") == journal["policy_sha256"]
                   and all(manifest.get(key) == outcome.get(key) for key in ("execution_status", "release_status", "error_code", "observed_sha256", "evaluated_sha256"))
                   and manifest.get("execution_status") == payload.get("status") and manifest.get("release_status") == result.get("release_status")
                   and hashlib.sha256(manifest_raw).hexdigest() == proof.get("manifest_sha256") == binding.get("manifest_sha256") == linked["manifest_sha256"] == stored["manifest_sha256"]
                   and hashlib.sha256(proof_raw).hexdigest() == stored["proof_sha256"]
                   and hashlib.sha256(receipt_raw).hexdigest() == binding.get("receipt_sha256") == linked["receipt_sha256"]
                   and len(receipt_raw) == binding.get("receipt_bytes") == linked["receipt_bytes"]
                   and proof.get("capsule_wait_finished") is True and proof.get("export_authority_closed") is True
                   and (payload.get("status") == "succeeded" or (receipt.get("evaluation") is None and result.get("scientific_evaluation") is None)))

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
            docker_retained(job, payload, "valid_" + str(number))
            leases.append(lease)
            callsets.append(snp_keys(objects / "normalized_vcf"))
        record("repeat_exact_three_snp_callset", jobs[0] != jobs[1] and leases[0] != leases[1] and callsets[0] == callsets[1] == snp_keys(FIXTURE / "expected.vcf") and len(callsets[0]) == 3)
        invalid_job, invalid, invalid_exit = submit(FIXTURE / "invalid.fastq", "invalid")
        record("invalid_fastq_withheld_with_custody", invalid_exit != 0 and invalid.get("status") == "failed" and invalid.get("data", {}).get("release_status") == "withheld"
               and invalid.get("data", {}).get("artifact_execution") is not None)
        docker_retained(invalid_job, invalid, "invalid")
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
        if observer is not None:
            ledger = json.loads(journals["store"].read_bytes())
            records = ledger["records"]
            expected_leases = set(leases + [invalid["data"]["artifact_execution"]["lease_id"]])
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                evidence = observer.snapshot()
                if evidence["error_code"]:
                    raise Failure(evidence["error_code"])
                if len(evidence["actors"]) == 3 and all(row["actions"] == ["create", "start", "die", "destroy"] for row in evidence["actors"].values()):
                    break
                time.sleep(0.05)
            actors = evidence["actors"]
            report["capsule_observation"] = evidence
            record("docker_exact_three_capsules_order_and_no_restart_execution", observer.proc.poll() is None
                   and evidence["barrier"].get("id") == owned_ids["upload"] and len(actors) == 3
                   and len({row["nonce"] for row in actors.values()}) == 3 and {row["lease"] for row in actors.values()} == expected_leases
                   and set(records) == expected_leases and all(row["actions"] == ["create", "start", "die", "destroy"] for row in actors.values()))
            for row in sorted(actors.values(), key=lambda x: x["lease"]):
                label = "invalid" if row["lease"] == invalid["data"]["artifact_execution"]["lease_id"] else "valid_" + str(leases.index(row["lease"]) + 1)
                record("docker_live_image_mounts_and_host_controls_" + label, docker_snapshot_matches(row, config),
                       {"snapshot_state": (row.get("snapshot") or {}).get("state", {}).get("Status")})
                record("docker_die_destroy_and_retained_quiescence_" + label, row.get("exit_code") == ("1" if label == "invalid" else "0")
                       and records[row["lease"]]["state"] == "committed"
                       and not any(Path(config["workspace_root"]).iterdir()))
            charges, charges_ok = {}, True
            for lease, stored in records.items():
                objects = host / "store/objects" / lease
                # Match Go struct/map serialization in actualCharge exactly;
                # record fields and hashes are fixed ASCII, map keys sorted.
                serialized = {key: stored[key] for key in ("job_id", "input_sha256", "state", "charge", "files", "manifest_sha256", "proof_sha256")}
                serialized["files"] = {key: {field: stored["files"][key][field] for field in ("state", "sha256", "bytes")}
                                       for key in sorted(stored["files"])}
                computed = sum(file["bytes"] for file in stored["files"].values())
                computed += sum((objects / name).stat().st_size for name in ("manifest.json", "proof.json"))
                computed += 2 * len(json.dumps(serialized, separators=(",", ":"), ensure_ascii=True).encode("ascii")) + 72
                charges[lease] = computed
                charges_ok = charges_ok and computed == stored["charge"] and stored["state"] == "committed"
            report["retained_accounting"] = {"header_reserve": 4096, "record_charges": charges, "total_charged_bytes": 4096 + sum(charges.values())}
            record("docker_retained_charge_exact_three_commits", charges_ok and len(records) == 3
                   and 4096 + sum(charges.values()) <= ledger["policy"]["global_bytes"])
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
        if observer is not None:
            try:
                observation = observer.finish()
                report["capsule_observer_final"] = observation
                cleanup_ok = cleanup_ok and observation["error_code"] is None and observation["joined"] and observation["expected_exit"]
                if complete:
                    cleanup_ok = cleanup_ok and observation["actors"] == report["capsule_observation"]["actors"]
            except Exception as exc:
                cleanup_ok = False
                report["observer_shutdown_error_type"] = type(exc).__name__
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
