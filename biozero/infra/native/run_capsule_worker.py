#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Opt-in real protected-entry acceptance for the native capsule worker route.

Keeps private runtime history and failed attempts. Does not run models, build or
download images, expose services outside loopback, or publish raw result data.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import signal
import ssl
import subprocess
import time
import urllib.error
from datetime import datetime, timezone

from run_experiment import ROOT, FIXTURE, command, context, free_port, request, sha, stop_processes


def write_private(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def synthetic_snp_keys(path):
    """Compare this fixture's normalized SNP presence, excluding VCF headers.

    File hashes remain separately verified. Tool headers can contain per-run
    paths, so equality of complete VCF bytes is a different reproducibility claim.
    """
    keys = set()
    for line in path.read_text(encoding="ascii").splitlines():
        if not line or line.startswith("#"): continue
        fields = line.split("\t")
        if len(fields) < 8 or len(fields[3]) != 1 or len(fields[4]) != 1:
            raise ValueError("fixture is not a normalized single-SNP callset")
        keys.add((fields[0], int(fields[1]), fields[3], fields[4]))
    return keys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=pathlib.Path, required=True)
    parser.add_argument("--tools-prefix", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if os.getuid() != 1000 or os.getgid() != 1000:
        parser.error("native worker launcher requires host UID/GID 1000")
    os.umask(0o077)
    run = args.run_dir.resolve()
    run.mkdir(mode=0o700, parents=True, exist_ok=False)
    runtime = pathlib.Path("/tmp") / ("bz-worker-" + secrets.token_hex(6))
    runtime.mkdir(mode=0o700)
    binaries, pki, data, host = [runtime / name for name in ("bin", "pki", "data", "host")]
    binaries.mkdir(mode=0o700)
    host.mkdir(mode=0o700)
    env = {**os.environ, "GOPROXY": "off", "GOSUMDB": "off", "CGO_ENABLED": "0", "GOMAXPROCS": "1", "GOFLAGS": "-p=1"}
    env["PATH"] = str(args.tools_prefix.resolve() / "bin") + os.pathsep + env.get("PATH", "")
    required = ["go", "openssl", "python3", "fastp", "minimap2", "samtools", "bcftools"]
    missing = [name for name in required if not shutil.which(name, path=env["PATH"])]
    if missing:
        parser.error("missing required tools: " + ", ".join(missing))
    report = {"schema_version": 1, "started_at": datetime.now(timezone.utc).isoformat(), "status": "failed",
              "scope": "actual native worker, mTLS, signature/decryption, v2 FD broker and bounded native pipeline/evaluation/detection; no Compose/browser/OCI or biological-model claim",
              "runtime_root": str(runtime), "cases": [], "processes": [], "source_hashes": {}}
    processes, logs, process_names = [], [], {}
    checks_complete = False

    def record(name, passed, observed=None):
        report["cases"].append({"case": name, "passed": bool(passed), "observed": observed or {}})
        write_private(run / "report.json", report)
        print(("PASS " if passed else "FAIL ") + name, flush=True)
        if not passed:
            raise RuntimeError("acceptance failed: " + name)

    def start(name, argv, settings=None):
        log = (run / (name + "-" + secrets.token_hex(3) + ".log")).open("xb")
        logs.append(log)
        proc = subprocess.Popen([str(a) for a in argv], env={**env, **(settings or {})}, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(proc)
        process_names[proc.pid] = name
        return proc

    def await_result(job, client, base):
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            code, raw = request(base + "/results/" + job, client)
            value = json.loads(raw)
            if code == 200 and value.get("status") not in ("uploaded", "running", "pending", "queued"):
                return value
            if worker.poll() is not None or broker.poll() is not None:
                raise RuntimeError("worker or broker exited before result")
            time.sleep(0.1)
        raise RuntimeError("protected capsule result deadline expired")

    try:
        source_paths = command(["git", "ls-files", "-z", "-co", "--exclude-standard"], env, ROOT).stdout.split("\0")
        report["source_hashes"] = {name: sha(ROOT / name) for name in sorted(set(source_paths)) if (ROOT / name).is_file()}
        report["commit"] = command(["git", "rev-parse", "HEAD"], env, ROOT).stdout.strip()
        report["dirty"] = bool(command(["git", "status", "--porcelain"], env, ROOT).stdout.strip())
        command(["bash", str(ROOT / "biozero/infra/PKI/gen-pki.sh"), str(pki)], env)
        command(["bash", str(ROOT / "biozero/infra/PKI/prepare-runtime.sh"), str(data)], env)
        services = ROOT / "biozero/services"
        for name in ("upload-api", "results-api", "enclave-runner", "uploader-cli"):
            command(["go", "build", "-o", str(binaries / name), "."], env, services / name)
        for name, module, package in (("artifact-broker", "artifact-executor", "./cmd/artifact-broker"),
                                      ("capsule-analysis", "enclave-runner", "./cmd/capsule-analysis"),
                                      ("worker-scope", "enclave-runner", "./cmd/worker-scope")):
            command(["go", "build", "-o", str(binaries / name), package], env, services / module)
        report["binary_pins"] = {p.name: {"sha256": sha(p), "bytes": p.stat().st_size} for p in binaries.iterdir()}
        capsule = services / "artifact-executor/capsule"
        assets = {"native_helper": capsule / "native_capsule.py", "pipeline": ROOT / "biozero/bio/pipeline/pipeline.py",
                  "resource_budget": ROOT / "biozero/bio/pipeline/resource_budget.py", "reference": FIXTURE / "reference.fa",
                  "evaluator": ROOT / "biozero/bio/benchmarks/evaluate_variants.py", "truth": FIXTURE / "expected.vcf",
                  "analysis_executable": binaries / "capsule-analysis", "analysis_rules": ROOT / "biozero/bio/reference-db/rules.json",
                  "analysis_panel": FIXTURE / "reference.fa"}
        config = {"schema_version": 1, "provider": "native", "mode": "variants", "store_root": str(host / "store"),
                  "journal_root": str(host / "journal"), "workspace_root": str(host / "workspace"),
                  "socket_path": str(host / "channel/b.sock"), "allowed_uid": os.getuid(), "timeout_seconds": 60,
                  "python_path": str(pathlib.Path("/usr/bin/python3").resolve()),
                  "tool_path": str(args.tools_prefix.resolve() / "bin") + ":/usr/bin", "docker_command": [], "image_id": "",
                  "container_helper": {"path": "", "sha256": ""}}
        config.update({name: {"path": str(path), "sha256": sha(path)} for name, path in assets.items()})
        config_path = runtime / "broker.json"
        write_private(config_path, config)
        profile = command([str(binaries / "artifact-broker"), "--config", str(config_path), "--print-profile"], env).stdout.strip()
        record("profile_is_bounded_hex_without_state", bool(re.fullmatch("[0-9a-f]{64}", profile)) and not (host / "store").exists())
        pins = {name: {"sha256": sha(path), "bytes": path.stat().st_size} for name, path in assets.items() if name != "native_helper"}
        policy_path = runtime / "worker-policy.json"
        write_private(policy_path, {"schema_version": 1, "profile_sha256": profile, "pipeline_mode": "variants", "capsule_kind": "native", "source_pins": pins})
        report["profile_sha256"] = profile
        broker = start("broker", [binaries / "artifact-broker", "--config", config_path])
        deadline = time.monotonic() + 10
        while not pathlib.Path(config["socket_path"]).exists():
            if broker.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("broker socket readiness failed")
            time.sleep(0.05)
        upload_port, results_port = free_port(), free_port()
        upload_base, results_base = f"https://127.0.0.1:{upload_port}", f"https://127.0.0.1:{results_port}"
        for name, role, port, addr in (("upload-api", "upload", upload_port, "BIOZERO_UPLOAD_ADDR"),
                                       ("results-api", "results", results_port, "BIOZERO_RESULTS_ADDR")):
            start(role, [binaries / name], {"BIOZERO_DATA_DIR": str(data), "BIOZERO_SECURITY_MODE": "protected", addr: f"127.0.0.1:{port}",
                  "BIOZERO_TLS_CERT": str(pki / f"runtime/{role}/server.crt"), "BIOZERO_TLS_KEY": str(pki / f"runtime/{role}/server.key"),
                  "BIOZERO_TLS_CA": str(pki / f"runtime/{role}/ca.crt")})
        client_a, client_b = context(pki, "researcher-a"), context(pki, "researcher-b")
        for base in (upload_base, results_base):
            deadline = time.monotonic() + 15
            while True:
                try:
                    code, raw = request(base + "/health", client_a)
                    if code == 200 and raw == b"ok": break
                except OSError:
                    pass
                if time.monotonic() > deadline: raise RuntimeError("TLS service readiness failed")
                time.sleep(0.1)
        settings = {"BIOZERO_DATA_DIR": str(data), "BIOZERO_SECURITY_MODE": "protected", "BIOZERO_EXECUTION_BACKEND": "capsule",
                    "BIOZERO_PIPELINE_MODE": "variants", "BIOZERO_POLL_SECONDS": "0.05", "BIOZERO_PIPELINE_TIMEOUT": "90s",
                    "BIOZERO_PRIVATE_KEY": str(pki / "runtime/worker/decrypt.key"), "BIOZERO_SIGNER_CERT": str(pki / "runtime/worker/signer.crt"),
                    "BIOZERO_ARTIFACT_SOCKET": config["socket_path"], "BIOZERO_ARTIFACT_PROFILE_SHA256": profile,
                    "BIOZERO_ARTIFACT_PROJECTION_POLICY": str(policy_path), "BIOZERO_WORKER_CUSTODY_DIR": str(data / "worker-custody")}
        worker_argv = [binaries / "worker-scope", "--worker", binaries / "enclave-runner", "--worker-sha256", sha(binaries / "enclave-runner"), "--tmpfs", data / "decrypted"]
        worker = start("worker", worker_argv, settings)
        deadline = time.monotonic() + 10
        while not (data / "worker-custody/journal.json").is_file():
            if worker.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("protected worker readiness failed")
            time.sleep(0.05)
        children = set()
        for thread in pathlib.Path(f"/proc/{worker.pid}/task").iterdir():
            children.update(int(pid) for pid in (thread / "children").read_text().split())
        if len(children) != 1: raise RuntimeError("worker process custody is ambiguous")
        worker_pid = next(iter(children))
        status = dict(line.split(":", 1) for line in pathlib.Path(f"/proc/{worker_pid}/status").read_text().splitlines() if ":" in line)
        stage_view = pathlib.Path(f"/proc/{worker_pid}/root") / str(data / "decrypted").lstrip("/")
        filesystem = os.statvfs(stage_view)
        mount_lines = pathlib.Path(f"/proc/{worker_pid}/mountinfo").read_text().splitlines()
        stage_mounts = [line for line in mount_lines if line.split()[4] == str(data / "decrypted")]
        record("worker_tmpfs_and_privilege_guards_observed", len(stage_mounts) == 1 and " - tmpfs " in stage_mounts[0]
               and filesystem.f_blocks * filesystem.f_frsize == 32 << 20 and filesystem.f_files == 4096 and filesystem.f_flag & 14 == 14
               and status.get("NoNewPrivs", "").strip() == "1"
               and all(status.get(name, "").strip() == "0000000000000000" for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")),
               {"capacity_bytes": filesystem.f_blocks * filesystem.f_frsize, "inode_units": filesystem.f_files})

        def submit(path, label):
            argv = [str(binaries / "uploader-cli"), "--protocol", "legacy", "--file", str(path), "--client-id", "researcher-a", "--upload-url", upload_base + "/upload",
                    "--results-url", results_base + "/results", "--mtls-cert", str(pki / "clients/researcher-a.crt"), "--mtls-key", str(pki / "clients/researcher-a.key"),
                    "--ca-cert", str(pki / "clients/ca.crt"), "--server-cert", str(pki / "clients/decrypt.crt"), "--sign-key", str(pki / "clients/signer.key"),
                    "--wait-timeout", "90s", "--poll-seconds", "1"]
            uploaded = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=100)
            write_private(run / (label + "-cli.json"), {"returncode": uploaded.returncode, "stdout": uploaded.stdout, "stderr": uploaded.stderr})
            match = re.search(r"uploaded job ([0-9a-f]{16})", uploaded.stdout)
            if not match: raise RuntimeError("protected upload did not return a job")
            job = match.group(1)
            payload = await_result(job, client_a, results_base)
            write_private(run / (label + "-result.json"), payload)
            return job, payload, uploaded.returncode

        callsets, leases = [], []
        jobs = []
        for number in (1, 2):
            job, payload, cli_exit = submit(FIXTURE / "reads.fastq", "valid-" + str(number))
            jobs.append(job)
            result = payload.get("data", {})
            evaluation, binding = result.get("scientific_evaluation", {}), result.get("artifact_execution", {})
            record("protected_three_snp_" + str(number), cli_exit == 0 and payload.get("status") == "succeeded" and result.get("release_status") == "evaluated_passed"
                   and evaluation.get("evaluation_status") == "passed" and evaluation.get("tp") == 3 and evaluation.get("fp") == 0
                   and evaluation.get("fn") == 0 and evaluation.get("precision") == 1 and evaluation.get("recall") == 1)
            stored = json.loads((data / "jobs" / (job + ".json")).read_text())
            record("immutable_ciphertext_and_verified_plaintext_" + str(number), result.get("signature_valid") is True and result.get("decrypted") is True
                   and result.get("upload_sha256") == stored["sha256"] and result.get("processed_sha256") == sha(FIXTURE / "reads.fastq")
                   and stored["size_bytes"] != result.get("size_bytes") and result.get("size_bytes") == (FIXTURE / "reads.fastq").stat().st_size)
            objects = host / "store/objects" / binding.get("lease_id", "missing")
            manifest_raw = (objects / "manifest.json").read_bytes()
            manifest = json.loads(manifest_raw)
            receipt_raw = (objects / "execution_receipt").read_bytes()
            receipt = json.loads(receipt_raw)
            proof_raw = (objects / "proof.json").read_bytes()
            proof = json.loads(proof_raw)
            receipt_evaluation = receipt.get("evaluation", {}).get("payload", {})
            receipt_context = receipt.get("analysis_context", {})
            record("receipt_science_input_and_policy_match_" + str(number), receipt.get("input_sha256") == result.get("processed_sha256")
                   and receipt.get("input_bytes") == result.get("size_bytes") and receipt.get("source_pins") == pins
                   and receipt_context.get("processed_size_bytes") == result.get("size_bytes")
                   and receipt_context.get("original_name") == stored.get("original_name")
                   and all(evaluation.get(name) == receipt_evaluation.get(name) for name in ("evaluation_status", "tp", "fp", "fn", "precision", "recall")))
            detection = result.get("detection", {})
            alignment = detection.get("signals", {}).get("alignment", {})
            record("actual_alignment_and_detection_" + str(number), detection.get("score") == 0.7 and detection.get("verdict") == "medium"
                   and "threat_panel_hit" in detection.get("reasons", []) and alignment.get("mapped_reads") == 1171
                   and alignment.get("total_reads") == 1171 and alignment.get("fraction") == 1 and len(alignment.get("targets", {})) == 1)
            retained_files_match = set(binding.get("files", {})) == {"execution_receipt", "normalized_vcf", "variants_vcf", "variants_vcf_index"}
            for name, file in binding.get("files", {}).items():
                if name not in {"execution_receipt", "normalized_vcf", "variants_vcf", "variants_vcf_index"}:
                    retained_files_match = False
                    continue
                retained = objects / name
                retained_files_match = retained_files_match and retained.is_file() and sha(retained) == file.get("sha256")
                retained_files_match = retained_files_match and retained.stat().st_size == file.get("bytes")
                retained_files_match = retained_files_match and manifest.get("files", {}).get(name) == {"state": "verified", **file}
            record("retained_receipt_and_proof_" + str(number), binding.get("profile_sha256") == profile
                   and hashlib.sha256(manifest_raw).hexdigest() == binding.get("manifest_sha256")
                   and hashlib.sha256(receipt_raw).hexdigest() == binding.get("receipt_sha256")
                   and proof.get("capsule_wait_finished") is True and proof.get("export_authority_closed") is True
                   and proof.get("manifest_sha256") == binding.get("manifest_sha256") and receipt.get("analysis_context", {}).get("signature_valid") is True
                   and receipt.get("analysis_context", {}).get("decrypted") is True
                   and binding.get("receipt_bytes") == len(receipt_raw) and retained_files_match)
            leases.append(binding["lease_id"])
            callsets.append(synthetic_snp_keys(objects / "normalized_vcf"))
            record("observed_evaluated_retained_hash_" + str(number), manifest.get("observed_sha256") == manifest.get("evaluated_sha256") == sha(objects / "normalized_vcf"))
            record("worker_has_no_unbounded_artifacts_" + str(number), not (data / "artifacts" / job).exists()
                   and result.get("pipeline_output", {}).get("outputs", {}).get("normalized_vcf") == "normalized_vcf"
                   and "raw_stdout" not in json.dumps(result) and "raw_stderr" not in json.dumps(result))
            code, _ = request(results_base + "/results/" + job, client_b, headers={"X-Client-Id": "researcher-a"})
            record("nonowner_denied_" + str(number), code == 403)
        record("repeat_callset_identical", jobs[0] != jobs[1] and leases[0] != leases[1] and len(callsets[0]) == 3
               and callsets[0] == callsets[1] == synthetic_snp_keys(FIXTURE / "expected.vcf"))
        _, bad, invalid_exit = submit(FIXTURE / "invalid.fastq", "invalid")
        record("invalid_fastq_failed_withheld", invalid_exit != 0 and bad.get("status") == "failed" and bad.get("data", {}).get("release_status") == "withheld"
               and bad.get("data", {}).get("artifact_execution") is not None)
        before = {"ledger": sha(host / "store/ledger.json"), "broker": sha(host / "journal/journal.json"), "worker": sha(data / "worker-custody/journal.json")}
        boundary = "biozero-protected-capsule"
        unsigned = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="unsigned.fastq"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() + (FIXTURE / "reads.fastq").read_bytes() + f"\r\n--{boundary}--\r\n".encode()
        code, raw = request(upload_base + "/upload", client_a, unsigned, {"Content-Type": "multipart/form-data; boundary=" + boundary})
        record("unsigned_upload_admitted_for_verification", code == 200)
        rejected = await_result(json.loads(raw)["job_id"], client_a, results_base)
        after = {"ledger": sha(host / "store/ledger.json"), "broker": sha(host / "journal/journal.json"), "worker": sha(data / "worker-custody/journal.json")}
        record("unsigned_rejected_without_custody", rejected.get("status") == "rejected" and rejected.get("data", {}).get("error_code") == "signature_required" and before == after)
        authenticated_before, _ = request(upload_base + "/health", client_a)
        anon_rejected = False
        try: request(upload_base + "/health", context(pki))
        except (ssl.SSLError, urllib.error.URLError) as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            anon_rejected = isinstance(reason, ssl.SSLError) and any(token in str(reason).lower() for token in ("certificate required", "certificate_required", "bad certificate", "handshake failure"))
        authenticated_after, _ = request(upload_base + "/health", client_a)
        record("mtls_rejects_missing_client_certificate", anon_rejected and authenticated_before == 200 and authenticated_after == 200
               and all(proc.poll() is None for proc in processes))
        # Simulate only lost result publication in this fresh fixture: preserve
        # the exact bytes, remove that synthetic result, and restore running.
        # Broker/worker custody, manifests, proof and charges remain unchanged.
        stop_processes([worker]); processes.remove(worker)
        record("worker_clean_shutdown", worker.returncode == 0)
        target = jobs[0]
        saved = (data / "results" / (target + ".json")).read_bytes()
        (run / "lost-publication-original.json").write_bytes(saved)
        (data / "results" / (target + ".json")).unlink()
        job_path = data / "jobs" / (target + ".json")
        job_record = json.loads(job_path.read_text()); job_record["status"] = "running"; write_private(job_path, job_record)
        worker = start("worker-restart", worker_argv, settings)
        recovered = await_result(target, client_a, results_base)
        previous = json.loads(saved)
        record("restart_recovers_same_artifacts_without_execution", recovered.get("status") == "succeeded"
               and recovered.get("data", {}).get("release_status") == "evaluated_passed"
               and recovered.get("data", {}).get("detection") == previous.get("detection")
               and recovered.get("data", {}).get("artifact_execution") is not None
               and recovered.get("data", {}).get("artifact_execution") == previous.get("artifact_execution")
               and recovered.get("data", {}).get("scientific_evaluation") == previous.get("scientific_evaluation")
               and sha(host / "store/ledger.json") == before["ledger"] and sha(host / "journal/journal.json") == before["broker"]
               and sha(data / "worker-custody/journal.json") == before["worker"] and worker.poll() is None and broker.poll() is None)
        checks_complete = True
    except Exception as exc:
        report["error_type"] = type(exc).__name__
        write_private(run / "report.json", report)
        raise
    finally:
        cleanup_error = None
        try: stop_processes(processes)
        except Exception as exc: cleanup_error = type(exc).__name__
        report["processes"] = [{"name": process_names[proc.pid], "pid": proc.pid, "returncode": proc.returncode} for proc in processes]
        report["all_processes_waited"] = all(proc.returncode is not None for proc in processes)
        # API mains have the default SIGTERM disposition; worker and broker have
        # explicit graceful shutdown. SIGKILL is never accepted as clean shutdown.
        expected_exits = all(proc.returncode == (-signal.SIGTERM if process_names[proc.pid] in ("upload", "results") else 0) for proc in processes)
        report["expected_process_exits"] = expected_exits
        final_paths = command(["git", "ls-files", "-z", "-co", "--exclude-standard"], env, ROOT).stdout.split("\0")
        report["source_hashes_after"] = {name: sha(ROOT / name) for name in sorted(set(final_paths)) if (ROOT / name).is_file()}
        report["source_unchanged"] = report["source_hashes_after"] == report["source_hashes"]
        if cleanup_error: report["cleanup_error_type"] = cleanup_error
        if checks_complete and cleanup_error is None and expected_exits and report["all_processes_waited"] and report["source_unchanged"]:
            report["status"] = "passed"
        for log in logs: log.close()
        report["ended_at"] = datetime.now(timezone.utc).isoformat()
        write_private(run / "report.json", report)
        if checks_complete and report["status"] != "passed": raise RuntimeError("cleanup or source stability verification failed")


if __name__ == "__main__":
    main()
