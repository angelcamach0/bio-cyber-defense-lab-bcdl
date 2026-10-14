#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Run the local synthetic milestone with mTLS, real tools, and retained evidence."""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import signal
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from public_vcf import export_alleles

ROOT = pathlib.Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "biozero/bio/fixtures/variant-smoke"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def context(pki, principal=None):
    ctx = ssl.create_default_context(cafile=str(pki / "clients/ca.crt"))
    if principal:
        ctx.load_cert_chain(str(pki / f"clients/{principal}.crt"), str(pki / f"clients/{principal}.key"))
    return ctx


def request(url, ctx, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    # Local services use the loopback interface, not an external proxy route.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def command(argv, env, cwd=None, timeout=120):
    proc = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    if proc.returncode:
        raise RuntimeError(f"Command failed ({proc.returncode}): {argv[0]}\n{proc.stderr[-3000:]}")
    return proc


def stop_processes(processes):
    """Signal only sessions created by this run, including separate child groups."""
    sessions = {proc.pid for proc in processes}
    groups = set(sessions)
    for stat in pathlib.Path('/proc').glob('[0-9]*/stat'):
        try:
            fields = stat.read_text().rsplit(')', 1)[1].split()
            if int(fields[3]) in sessions:
                groups.add(int(fields[2]))
        except (OSError, ValueError, IndexError):
            continue
    for group in groups:
        try:
            os.killpg(group, signal.SIGTERM)
        except ProcessLookupError:
            pass
    for proc in processes:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    for group in groups:
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass
    for proc in processes:
        proc.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=pathlib.Path)
    parser.add_argument("--tools-prefix", type=pathlib.Path)
    parser.add_argument("--mode", choices=["stats", "variants"], default="variants")
    args = parser.parse_args()
    env = dict(os.environ)
    if args.tools_prefix:
        env["PATH"] = str(args.tools_prefix.resolve() / "bin") + os.pathsep + env["PATH"]
    required = ["go", "openssl", "python3"] + (["samtools", "bcftools", "minimap2"] if args.mode == "variants" else [])
    missing = [name for name in required if not shutil.which(name, path=env["PATH"])]
    if missing:
        parser.error("Required tools unavailable: " + ", ".join(missing))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S-%fZ")
    run_dir = (args.run_dir or ROOT / "biozero/docs/evidence" / stamp).resolve()
    run_dir.mkdir(parents=True, exist_ok=False)
    run_dir.chmod(0o700)
    public = run_dir / 'public'
    public.mkdir()
    pki, data, binaries = run_dir / "private/pki", run_dir / "private/data", run_dir / "private/bin"
    binaries.mkdir(parents=True)
    manifest = {"schema_version": 1, "started_at": stamp, "mode": args.mode,
                "architecture": platform.machine(), "platform": platform.platform(), "cpu_count": os.cpu_count(),
                "scope": "local native single-worker synthetic experiment; container isolation and browser users not verified",
                "fixture_hashes": {name: sha(FIXTURE / name) for name in ["reference.fa", "reads.fastq", "expected.vcf", "invalid.fastq"]},
                "cases": [], "status": "failed"}
    processes, logs = [], []

    def record(name, passed, observed):
        manifest["cases"].append({"case": name, "verdict": "PASS" if passed else "FAIL", "observed": observed})
        print(f"{'PASS' if passed else 'FAIL'} {name}", flush=True)
        if not passed:
            raise RuntimeError(f"Acceptance failed: {name}")

    def start(name, settings):
        log = (run_dir / f"{name}.log").open("wb")
        logs.append(log)
        proc = subprocess.Popen([str(binaries / name)], env={**env, **settings}, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(proc)
        return proc

    try:
        manifest["commit"] = command(["git", "rev-parse", "HEAD"], env, ROOT).stdout.strip()
        manifest["dirty"] = bool(command(["git", "status", "--porcelain"], env, ROOT).stdout.strip())
        paths = command(["git", "ls-files", "-z", "-co", "--exclude-standard"], env, ROOT).stdout.split('\0')
        manifest["source_hashes"] = {name: sha(ROOT / name) for name in sorted(set(paths)) if (ROOT / name).is_file()}
        manifest["tool_versions"] = {}
        for name, flags in [("go", ["version"]), ("openssl", ["version"]), ("samtools", ["--version"]),
                            ("bcftools", ["--version"]), ("minimap2", ["--version"]), ("fastp", ["--version"])]:
            if shutil.which(name, path=env["PATH"]):
                proc = subprocess.run([name, *flags], env=env, capture_output=True, text=True, timeout=10)
                manifest["tool_versions"][name] = (proc.stdout + proc.stderr).splitlines()[0]
        command(["bash", str(ROOT / "biozero/infra/PKI/gen-pki.sh"), str(pki)], env)
        command(["bash", str(ROOT / "biozero/infra/PKI/prepare-runtime.sh"), str(data)], env)
        for name in ["upload-api", "results-api", "enclave-runner", "uploader-cli"]:
            command(["go", "build", "-o", str(binaries / name), "./..."], env, ROOT / "biozero/services" / name)
        upload_port, results_port = free_port(), free_port()
        upload_url, results_url = f"https://127.0.0.1:{upload_port}", f"https://127.0.0.1:{results_port}"
        shared = {"BIOZERO_DATA_DIR": str(data), "BIOZERO_SECURITY_MODE": "protected"}
        manifest["configuration"] = {"security_mode": "protected", "pipeline_mode": args.mode,
                                     "single_worker": True, "bound_address": "127.0.0.1"}
        for name, short, addr_var, port in [("upload-api", "upload", "BIOZERO_UPLOAD_ADDR", upload_port),
                                           ("results-api", "results", "BIOZERO_RESULTS_ADDR", results_port)]:
            start(name, {**shared, addr_var: f"127.0.0.1:{port}",
                         "BIOZERO_TLS_CERT": str(pki / f"runtime/{short}/server.crt"),
                         "BIOZERO_TLS_KEY": str(pki / f"runtime/{short}/server.key"),
                         "BIOZERO_TLS_CA": str(pki / f"runtime/{short}/ca.crt")})
        client_a, client_b = context(pki, "researcher-a"), context(pki, "researcher-b")
        for base in [upload_url, results_url]:
            deadline = time.monotonic() + 20
            while True:
                try:
                    code, body = request(base + "/health", client_a)
                    if code == 200 and body == b"ok":
                        break
                except (OSError, urllib.error.URLError):
                    pass
                if time.monotonic() > deadline:
                    raise RuntimeError("Service readiness deadline expired")
                time.sleep(0.2)
        start("enclave-runner", {**shared, "BIOZERO_RULES_PATH": str(ROOT / "biozero/bio/reference-db/rules.json"),
              "BIOZERO_PRIVATE_KEY": str(pki / "runtime/worker/decrypt.key"),
              "BIOZERO_SIGNER_CERT": str(pki / "runtime/worker/signer.crt"),
              "BIOZERO_PIPELINE_PATH": str(ROOT / "biozero/bio/pipeline/pipeline.py"),
              "BIOZERO_REFERENCE_PATH": str(FIXTURE / "reference.fa"), "BIOZERO_PIPELINE_MODE": args.mode,
              "BIOZERO_PIPELINE_TIMEOUT": "60s"})

        def submit(path, label):
            argv = [str(binaries / "uploader-cli"), "--file", str(path), "--client-id", "researcher-a",
                    "--upload-url", upload_url + "/upload", "--results-url", results_url + "/results",
                    "--mtls-cert", str(pki / "clients/researcher-a.crt"), "--mtls-key", str(pki / "clients/researcher-a.key"),
                    "--ca-cert", str(pki / "clients/ca.crt"), "--server-cert", str(pki / "clients/decrypt.crt"),
                    "--sign-key", str(pki / "clients/signer.key"), "--wait-timeout", "90s", "--poll-seconds", "1"]
            proc = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=100)
            # Keep keys/signatures/ciphertext metadata outside the reviewable bundle.
            match = re.search(r"uploaded job ([0-9a-f]+)", proc.stdout)
            if not match:
                raise RuntimeError(f"Upload failed: {proc.stderr[-2000:]}")
            job_id = match.group(1)
            code, raw = request(results_url + "/results/" + job_id, client_a)
            payload = json.loads(raw)
            (run_dir / f"{label}.json").write_text(json.dumps(payload, indent=2) + "\n")
            return proc.returncode, job_id, payload

        vcfs = []
        for number in [1, 2]:
            exit_code, job, payload = submit(FIXTURE / "reads.fastq", f"valid-{number}")
            record(f"valid-run-{number}", exit_code == 0 and payload["status"] == "succeeded", {"status": payload["status"], "exit_code": exit_code})
            output = payload["data"]["pipeline_output"]
            if args.mode == "variants":
                vcfs.append(output["outputs"]["normalized_vcf"])
            code, _ = request(results_url + "/results/" + job, client_b, headers={"X-Client-Id": "researcher-a"})
            record(f"client-b-denied-{number}", code == 403, {"http_status": code})
            stored = json.loads((data / "jobs" / f"{job}.json").read_text())
            record(f"upload-digest-preserved-{number}", stored["sha256"] == payload["data"]["upload_sha256"], {})
        if args.mode == "variants":
            evaluated = command(["python3", str(ROOT / "biozero/bio/benchmarks/evaluate_variants.py"),
                "--reference", str(FIXTURE / "reference.fa"), "--expected", str(FIXTURE / "expected.vcf"),
                "--observed", vcfs[0], "--repeat", vcfs[1]], env)
            metrics = json.loads(evaluated.stdout)
            (run_dir / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
            record("synthetic-variants-and-repeat", metrics["tp"] == 3 and metrics["fp"] == 0 and metrics["fn"] == 0 and metrics["reproducible_callset"], metrics)
            for index, vcf in enumerate(vcfs, 1):
                suffix = ".vcf.gz" if str(vcf).endswith(".gz") else ".vcf"
                shutil.copyfile(vcf, run_dir / f"run-{index}{suffix}")
                derivation = export_alleles(vcf, FIXTURE / "reference.fa", public / f"run-{index}.vcf")
                (public / f"run-{index}-derivation.json").write_text(json.dumps(derivation, indent=2) + "\n")
        exit_code, _, payload = submit(FIXTURE / "invalid.fastq", "invalid-fastq")
        errors = payload.get("data", {}).get("pipeline_output", {}).get("errors", [])
        format_error = any(error.get("stage") == "validate_fastq" and error.get("code") == "invalid_input" for error in errors)
        record("invalid-fastq-rejected-for-format", exit_code != 0 and payload["status"] == "failed" and format_error,
               {"status": payload["status"], "exit_code": exit_code, "format_error": format_error})
        anon_rejected = False
        try:
            request(upload_url + "/health", context(pki))
        except (OSError, urllib.error.URLError):
            anon_rejected = True
        record("mtls-requires-client-certificate", anon_rejected, {})
        # Direct unsigned multipart input must be accepted for queueing, then rejected before analysis.
        boundary = "biozero-milestone-boundary"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"client_id\"\r\n\r\nresearcher-a\r\n"
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"unsigned.fastq\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n").encode() + (FIXTURE / "reads.fastq").read_bytes() + f"\r\n--{boundary}--\r\n".encode()
        code, raw = request(upload_url + "/upload", client_a, body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        if code != 200:
            raise RuntimeError(f"Unsigned test submission unexpectedly returned {code}")
        unsigned_id = json.loads(raw)["job_id"]
        deadline = time.monotonic() + 20
        while True:
            _, raw = request(results_url + "/results/" + unsigned_id, client_a)
            unsigned_result = json.loads(raw)
            if unsigned_result["status"] not in ["uploaded", "queued", "pending", "running"]:
                break
            if time.monotonic() > deadline:
                raise RuntimeError("Unsigned rejection deadline expired")
            time.sleep(0.2)
        record("unsigned-input-rejected-before-analysis", unsigned_result["status"] == "rejected" and not (data / "artifacts" / unsigned_id).exists(), {"status": unsigned_result["status"]})
        manifest["status"] = "passed"
    except Exception as exc:
        manifest["error"] = str(exc)
        print(str(exc), flush=True)
    finally:
        stop_processes(processes)
        for log in logs:
            log.close()
        manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        # Publish only the known-answer synthetic review artifacts, never private/ or logs.
        public_manifest = dict(manifest)
        if "error" in public_manifest:
            public_manifest["error"] = "Experiment failed; detailed diagnostics retained privately."
        (public / 'manifest.json').write_text(json.dumps(public_manifest, indent=2) + '\n')
        for path in [run_dir / 'metrics.json']:
            if path.is_file():
                shutil.copyfile(path, public / path.name)
        (public / 'SHA256SUMS.json').write_text(json.dumps({p.name: sha(p) for p in sorted(public.iterdir()) if p.is_file()}, indent=2) + '\n')
        print(f"Evidence: {run_dir}", flush=True)
        print(f"Shareable synthetic evidence: {public}", flush=True)
        print("Private credentials and data remain in private/; do not publish that directory.", flush=True)
    return 0 if manifest["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
