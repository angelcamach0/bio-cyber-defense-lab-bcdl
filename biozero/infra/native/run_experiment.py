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
import secrets
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


def request(url, ctx, data=None, headers=None, timeout=5):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    # Local services use the loopback interface, not an external proxy route.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=timeout) as response:
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
    parser.add_argument("--soc", action="store_true", help="Verify worker outbox and authenticated simulated response")
    parser.add_argument("--metadata-faults", action="store_true", help="Verify unsafe metadata rejection and live worker progress")
    parser.add_argument("--output-cases", action="store_true", help="Verify protected command-output failures and scientific withholding")
    parser.add_argument("--admission-cases", action="store_true", help="Verify durable input quotas in separate fresh private runtimes")
    args = parser.parse_args()
    if args.output_cases and args.mode != "variants":
        parser.error("--output-cases requires variants mode for the scientific evaluator check")
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
        number = 1
        log_path = run_dir / f"{name}.log"
        while log_path.exists():
            number += 1
            log_path = run_dir / f"{name}-{number}.log"
        log = log_path.open("xb")
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
        for name in ["upload-api", "results-api", "enclave-runner", "uploader-cli"] + (["zeroresponder"] if args.soc else []):
            # One service executable per destination; modules may also contain
            # libraries and separate commands. check_go.py tests/vets all packages.
            command(["go", "build", "-o", str(binaries / name), "."], env, ROOT / "biozero/services" / name)
        upload_port, results_port = free_port(), free_port()
        upload_url, results_url = f"https://127.0.0.1:{upload_port}", f"https://127.0.0.1:{results_port}"
        shared = {"BIOZERO_DATA_DIR": str(data), "BIOZERO_SECURITY_MODE": "protected"}
        manifest["configuration"] = {"security_mode": "protected", "pipeline_mode": args.mode,
                                     "single_worker": True, "bound_address": "127.0.0.1",
                                     "soc_simulation": args.soc, "metadata_faults": args.metadata_faults,
                                     "output_cases": args.output_cases, "admission_cases": args.admission_cases}
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
        worker_settings = {**shared, "BIOZERO_EXECUTION_BACKEND": "legacy", "BIOZERO_RULES_PATH": str(ROOT / "biozero/bio/reference-db/rules.json"),
              "BIOZERO_PRIVATE_KEY": str(pki / "runtime/worker/decrypt.key"),
              "BIOZERO_SIGNER_CERT": str(pki / "runtime/worker/signer.crt"),
              "BIOZERO_PIPELINE_PATH": str(ROOT / "biozero/bio/pipeline/pipeline.py"),
              "BIOZERO_REFERENCE_PATH": str(FIXTURE / "reference.fa"), "BIOZERO_PIPELINE_MODE": args.mode,
              "BIOZERO_PIPELINE_TIMEOUT": "60s"}
        if args.soc:
            worker_settings['BIOZERO_SECURITY_EVENTS_DIR'] = str(data / 'security-events')
        worker_process = start("enclave-runner", worker_settings)

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
        def new_unsigned_job():
            code, raw = request(upload_url + "/upload", client_a, body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
            if code != 200:
                raise RuntimeError(f"Unsigned test submission unexpectedly returned {code}")
            return json.loads(raw)["job_id"]

        unsigned_id = new_unsigned_job()
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
        if args.soc:
            sys_path = str(ROOT / 'biozero/infra/soc')
            import sys
            sys.path.insert(0, sys_path)
            import relay
            event_id = 'evt-' + hashlib.sha256(f'enclave-runner/{unsigned_id}/signature_required'.encode()).hexdigest()
            event_path = data / 'security-events' / (event_id + '.json')

            def await_event():
                deadline = time.monotonic() + 15
                while not event_path.is_file():
                    if time.monotonic() > deadline:
                        raise RuntimeError('SOC outbox deadline expired')
                    time.sleep(0.1)
                return relay.decode(relay.private_read(event_path))

            event = await_event()
            wire = relay.canonical_event(event)
            event_digest = hashlib.sha256(wire).hexdigest()
            record('soc-real-security-rejection-event', event['event_code'] == 'signature_required'
                   and event['timestamp'] == unsigned_result['data']['processed_at']
                   and event['indicators'] == {'job_id': unsigned_id}, {'event_code': event['event_code']})
            # A persisted terminal result must recover a lost outbox event without execution.
            stop_processes([worker_process])
            processes.remove(worker_process)
            event_path.unlink()
            worker_process = start('enclave-runner', worker_settings)
            recovered = await_event()
            record('soc-terminal-result-recovers-outbox', recovered == event
                   and not (data / 'artifacts' / unsigned_id).exists(), {})

            responder_port = free_port()
            responder_base = f'https://127.0.0.1:{responder_port}'
            secret = secrets.token_hex(32)
            responder_settings = {'BIOZERO_DATA_DIR': str(data),
                'BIOZERO_RESPONDER_ADDR': f'127.0.0.1:{responder_port}',
                'BIOZERO_WEBHOOK_SECRET': secret,
                'BIOZERO_TLS_CERT': str(pki / 'runtime/responder/server.crt'),
                'BIOZERO_TLS_KEY': str(pki / 'runtime/responder/server.key')}

            def start_responder():
                proc = start('zeroresponder', responder_settings)
                deadline = time.monotonic() + 15
                while True:
                    try:
                        code, raw = request(responder_base + '/health', context(pki))
                        health = json.loads(raw)
                        if code == 200 and health.get('healthy') is True:
                            return proc
                    except (OSError, ValueError, urllib.error.URLError):
                        pass
                    if proc.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError('SOC responder readiness failed')
                    time.sleep(0.1)

            responder_process = start_responder()
            untrusted = False
            try:
                request(responder_base + '/health', ssl.create_default_context())
            except ssl.SSLCertVerificationError:
                untrusted = True
            except urllib.error.URLError as exc:
                untrusted = isinstance(exc.reason, ssl.SSLCertVerificationError)
            trusted_code, _ = request(responder_base + '/health', context(pki))
            record('soc-untrusted-tls-rejected', untrusted and trusted_code == 200, {})
            for label, supplied in [('missing', None), ('wrong', 'x' * 64)]:
                headers = {'Content-Type': 'application/json'}
                if supplied is not None:
                    headers['X-Webhook-Secret'] = supplied
                code, _ = request(responder_base + '/alert', context(pki), wire, headers)
                record('soc-' + label + '-secret-rejected', code == 403, {'http_status': code})
            first = relay.deliver(event_path, responder_base + '/alert', pki / 'clients/ca.crt',
                                  secret, data / 'security-deliveries')
            record('soc-durable-simulation-ack', first['replay'] is False
                   and first['enforced'] is False, {'mode': first['mode'], 'enforced': False})
            server_receipts = list((data / 'actions').glob('*.json'))
            record('soc-single-private-receipt', len(server_receipts) == 1
                   and (server_receipts[0].stat().st_mode & 0o777) == 0o600, {})
            receipt_bytes = server_receipts[0].read_bytes()
            stop_processes([responder_process])
            processes.remove(responder_process)
            responder_process = start_responder()
            replay = relay.deliver(event_path, responder_base + '/alert', pki / 'clients/ca.crt',
                                   secret, data / 'security-deliveries')
            record('soc-restart-idempotent-redelivery', replay['replay'] is True
                   and server_receipts[0].read_bytes() == receipt_bytes
                   and len(list((data / 'actions').glob('*.json'))) == 1, {})
            changed = dict(event)
            changed['timestamp'] = '2026-01-01T00:00:00Z'
            headers = {'Content-Type': 'application/json', 'X-Webhook-Secret': secret}
            code, _ = request(responder_base + '/alert', context(pki), relay.canonical_event(changed), headers)
            record('soc-changed-payload-conflict', code == 409
                   and server_receipts[0].read_bytes() == receipt_bytes, {'http_status': code})
            code, _ = request(responder_base + '/alert', context(pki), wire + b'{}', headers)
            record('soc-trailing-json-rejected', code == 400, {'http_status': code})
            code, _ = request(responder_base + '/alert', context(pki), b' ' * 65537, headers)
            record('soc-oversized-body-rejected', code == 413, {'http_status': code})
            record('soc-no-effective-action-artifacts',
                   not any((data / 'actions' / name).exists() for name in
                           ['blocklist.txt', 'revocations.txt', 'quarantine.txt', 'actions.log']), {})
            (public / 'soc-summary.json').write_text(json.dumps({'schema_version': 1,
                'scope': 'native local protected worker -> private outbox -> verified HTTPS relay -> simulated response',
                'source': event['source'], 'event_code': event['event_code'],
                'payload_sha256': event_digest, 'mode': 'simulation', 'enforced': False,
                'delivery': 'at least once with durable idempotent response',
                'worker_network_isolation_verified_here': False,
                'real_containment_verified': False}, indent=2) + '\n')
        if args.metadata_faults:
            from metadata_checks import run_checks

            existing_uploads = {entry.name for entry in (data / 'uploads').iterdir()}
            existing_jobs = {entry.name for entry in (data / 'jobs').iterdir()}
            oversized_metadata = (f'--{boundary}\r\nContent-Disposition: form-data; name="sig"\r\n\r\n'.encode()
                                  + b'x' * 65536 + b'\r\n' + body)
            code, raw = request(upload_url + '/upload', client_a, oversized_metadata,
                                {'Content-Type': f'multipart/form-data; boundary={boundary}'})
            error = json.loads(raw)
            clean = ({entry.name for entry in (data / 'uploads').iterdir()} == existing_uploads
                     and {entry.name for entry in (data / 'jobs').iterdir()} == existing_jobs)
            record('metadata_upload_rejects_oversized_job_before_publication',
                   code == 413 and error.get('code') == 'metadata_too_large' and clean,
                   {'http_status': code, 'error_code': 'metadata_too_large' if error.get('code') == 'metadata_too_large' else 'unexpected',
                    'no_new_job_or_payload': clean})

            # Calibrate against the actual retained upload fields, then reserve
            # worst-case mutable state using the independently frozen contract.
            template_for_budget = json.loads((data / 'jobs' / (unsigned_id + '.json')).read_text())
            for field in ('started_at', 'error_code', 'error_message'):
                template_for_budget.pop(field, None)
            template_for_budget.update(status='incomplete', started_at='2000-01-01T00:00:00Z',
                error_code='\x00' * 64, error_message='\x00' * 512, sig='x')
            projected_base = len(json.dumps(template_for_budget, ensure_ascii=False, indent=2).encode()) - 1
            boundary_sig_size = 65536 - projected_base
            if boundary_sig_size < 1:
                raise RuntimeError('Metadata boundary calibration invalid')
            boundary_body = (f'--{boundary}\r\nContent-Disposition: form-data; name="sig"\r\n\r\n'.encode()
                             + b'x' * boundary_sig_size + b'\r\n' + body)
            code, raw = request(upload_url + '/upload', client_a, boundary_body,
                                {'Content-Type': f'multipart/form-data; boundary={boundary}'})
            if code != 200:
                raise RuntimeError('Metadata projected-boundary upload was not admitted')
            boundary_job = json.loads(raw)['job_id']
            stop_at = time.monotonic() + 20
            boundary_result = None
            while time.monotonic() < stop_at:
                code, raw = request(results_url + '/results/' + boundary_job, client_a)
                if code != 200:
                    raise RuntimeError('Admitted metadata boundary job became unreadable')
                boundary_result = json.loads(raw)
                if boundary_result.get('status') == 'rejected':
                    break
                time.sleep(0.1)
            boundary_result = boundary_result or {}
            saved_boundary = json.loads((data / 'jobs' / (boundary_job + '.json')).read_text())
            denial, _ = request(results_url + '/results/' + boundary_job, client_b)
            readable = (boundary_result and boundary_result.get('status') == 'rejected'
                and boundary_result.get('data', {}).get('error_code') == 'signature_algorithm_invalid'
                and saved_boundary['sig'] == 'x' * boundary_sig_size
                and saved_boundary['sha256'] == template_for_budget['sha256']
                and saved_boundary['size_bytes'] == template_for_budget['size_bytes']
                and saved_boundary['client_id'] == template_for_budget['client_id']
                and saved_boundary['client_cert_serial'] == template_for_budget['client_cert_serial']
                and (data / 'jobs' / (boundary_job + '.json')).stat().st_size <= 65536
                and not (data / 'artifacts' / boundary_job).exists() and denial == 403)
            record('metadata_max_admitted_budget_stays_readable_after_processing', readable,
                {'projected_budget_bytes': 65536, 'terminal_rejected': boundary_result.get('status') == 'rejected',
                 'immutable_fields_preserved': bool(readable), 'owner_b_http_status': denial,
                 'saved_job_bytes': (data / 'jobs' / (boundary_job + '.json')).stat().st_size})

            one_over_body = (f'--{boundary}\r\nContent-Disposition: form-data; name="sig"\r\n\r\n'.encode()
                             + b'x' * (boundary_sig_size + 1) + b'\r\n' + body)
            before_jobs = {entry.name for entry in (data / 'jobs').iterdir()}
            before_uploads = {entry.name for entry in (data / 'uploads').iterdir()}
            code, raw = request(upload_url + '/upload', client_a, one_over_body,
                                {'Content-Type': f'multipart/form-data; boundary={boundary}'})
            refused = (code == 413 and json.loads(raw).get('code') == 'metadata_too_large'
                and {entry.name for entry in (data / 'jobs').iterdir()} == before_jobs
                and {entry.name for entry in (data / 'uploads').iterdir()} == before_uploads)
            record('metadata_one_over_lifecycle_budget_rejected_without_orphan', refused,
                   {'http_status': code, 'projected_budget_bytes': 65537, 'no_new_job_or_payload': refused})

            def request_as(actor, path, timeout=2):
                return request(results_url + path, client_a if actor == 'a' else client_b, timeout=timeout)

            def verify_worker_progress(deadline=20):
                job = new_unsigned_job()
                stop_at = time.monotonic() + deadline
                while time.monotonic() < stop_at:
                    code, raw = request_as('a', '/results/' + job)
                    result = json.loads(raw)
                    if code == 200 and result.get('status') == 'rejected':
                        return {'terminal_rejected': result.get('data', {}).get('error_code') == 'signature_required',
                                'pipeline_not_called': not (data / 'artifacts' / job).exists()}
                    time.sleep(0.1)
                return {'terminal_rejected': False, 'pipeline_not_called': False}

            metadata_private = run_dir / 'private/metadata-faults'
            metadata_private.mkdir(mode=0o700)
            template = json.loads((data / 'jobs' / (unsigned_id + '.json')).read_text())
            summary = run_checks(data_dir=data, private_dir=metadata_private,
                job_template=template, result_template=unsigned_result['data'],
                request_as=request_as, verify_worker_progress=verify_worker_progress,
                record=record)
            (public / 'metadata-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        if args.output_cases:
            output_private = run_dir / 'private/output-faults'
            output_private.mkdir(mode=0o700)
            output_observations = []

            def output_case(name, passed, observed):
                output_observations.append({'case': name, 'passed': bool(passed), 'observed': observed})
                record(name, passed, observed)

            def replace_worker(settings):
                nonlocal worker_process
                stop_processes([worker_process])
                processes.remove(worker_process)
                worker_process = start('enclave-runner', settings)

            def overflowing_command(filename, marker, prefix):
                child = "import time; from pathlib import Path; time.sleep(1); Path(" + repr(str(marker)) + ").touch()"
                script = ("#!/usr/bin/env python3\nimport subprocess, sys\n"
                          + "subprocess.Popen([sys.executable, '-c', " + repr(child) + "])\n"
                          + "sys.stdout.write(" + repr(json.dumps(prefix)) + "); sys.stdout.flush()\n"
                          + "sys.stdout.write(' ' * 1048577); sys.stdout.flush()\n")
                path = output_private / filename
                path.write_text(script)
                path.chmod(0o700)
                return path

            marker = output_private / 'pipeline-descendant-marker'
            command_path = overflowing_command('pipeline.py', marker,
                {'schema_version': 1, 'mode': 'variants', 'pipeline_status': 'succeeded'})
            replace_worker({**worker_settings, 'BIOZERO_PIPELINE_PATH': str(command_path)})
            _, output_job, output_payload = submit(FIXTURE / 'reads.fastq', 'output-pipeline-limit')
            output_data = output_payload.get('data', {})
            output_job_record = json.loads((data / 'jobs' / (output_job + '.json')).read_text())
            output_case('output_pipeline_limit_is_failed_and_withheld',
                output_payload.get('status') == 'failed' and output_data.get('release_status') == 'withheld'
                and output_data.get('error_code') == 'pipeline_output_limit',
                {'failed': output_payload.get('status') == 'failed', 'withheld': output_data.get('release_status') == 'withheld'})
            output_case('output_pipeline_crypto_and_original_hash_preserved',
                output_data.get('decrypted') is True and output_data.get('signature_valid') is True
                and output_data.get('upload_sha256') == output_job_record['sha256']
                and output_data.get('processed_sha256') == sha(FIXTURE / 'reads.fastq'),
                {'crypto_verified_before_output_failure': output_data.get('decrypted') is True and output_data.get('signature_valid') is True,
                 'original_hash_preserved': output_data.get('upload_sha256') == output_job_record['sha256']})
            result_size = (data / 'results' / (output_job + '.json')).stat().st_size
            output_case('output_pipeline_valid_json_prefix_not_released',
                not output_data.get('pipeline_output') and result_size <= 16777216,
                {'partial_json_released': bool(output_data.get('pipeline_output')), 'result_bytes': result_size})
            time.sleep(1.1)
            cleaned = not marker.exists() and not (data / 'decrypted' / (output_job + '_decrypted.bin')).exists()
            output_case('output_pipeline_descendant_and_plaintext_cleaned', cleaned,
                        {'descendant_marker_absent': not marker.exists(),
                         'plaintext_absent': not (data / 'decrypted' / (output_job + '_decrypted.bin')).exists()})
            denied, _ = request(results_url + '/results/' + output_job, client_b)
            output_case('output_pipeline_failure_nonowner_denied', denied == 403, {'http_status': denied})

            marker = output_private / 'evaluator-descendant-marker'
            evaluator = overflowing_command('evaluator.py', marker,
                {'evaluation_status': 'passed', 'tp': 3, 'fp': 0, 'fn': 0, 'precision': 1, 'recall': 1})
            replace_worker({**worker_settings, 'BIOZERO_EVALUATOR_PATH': str(evaluator),
                            'BIOZERO_TRUTH_PATH': str(FIXTURE / 'expected.vcf')})
            _, science_job, science_payload = submit(FIXTURE / 'reads.fastq', 'output-evaluator-limit')
            science_data = science_payload.get('data', {})
            evaluation = science_data.get('scientific_evaluation', {})
            science_job_record = json.loads((data / 'jobs' / (science_job + '.json')).read_text())
            output_case('output_evaluator_limit_withholds_successful_execution',
                science_payload.get('status') == 'succeeded' and science_data.get('release_status') == 'withheld'
                and evaluation.get('evaluation_error_code') == 'evaluation_output_limit',
                {'execution_succeeded': science_payload.get('status') == 'succeeded', 'science_withheld': science_data.get('release_status') == 'withheld'})
            output_case('output_evaluator_crypto_and_original_hash_preserved',
                science_data.get('decrypted') is True and science_data.get('signature_valid') is True
                and science_data.get('upload_sha256') == science_job_record['sha256']
                and science_data.get('processed_sha256') == sha(FIXTURE / 'reads.fastq'),
                {'crypto_verified': science_data.get('decrypted') is True and science_data.get('signature_valid') is True,
                 'original_hash_preserved': science_data.get('upload_sha256') == science_job_record['sha256']})
            output_case('output_evaluator_passed_json_prefix_not_accepted',
                evaluation.get('evaluation_status') == 'failed' and 'tp' not in evaluation,
                {'evaluation_failed': evaluation.get('evaluation_status') == 'failed', 'passed_metrics_released': 'tp' in evaluation})
            time.sleep(1.1)
            cleaned = not marker.exists() and not (data / 'decrypted' / (science_job + '_decrypted.bin')).exists()
            output_case('output_evaluator_descendant_and_plaintext_cleaned', cleaned,
                        {'descendant_marker_absent': not marker.exists(),
                         'plaintext_absent': not (data / 'decrypted' / (science_job + '_decrypted.bin')).exists()})
            denied, _ = request(results_url + '/results/' + science_job, client_b)
            output_case('output_evaluator_withheld_nonowner_denied', denied == 403, {'http_status': denied})
            replace_worker(worker_settings)
            (public / 'output-summary.json').write_text(json.dumps({'schema_version': 1,
                'scope': 'actual protected native uploads with intentionally excessive pipeline/evaluator output; no biological model',
                'case_count': len(output_observations), 'cases': output_observations,
                'artifact_or_total_disk_quota_verified': False}, indent=2) + '\n')
        if args.admission_cases:
            from admission_checks import run_checks as admission_checks
            admission_summary = admission_checks(run_dir=run_dir, binaries=binaries, pki=pki,
                                                  env=env, record=record)
            (public / 'admission-summary.json').write_text(json.dumps(admission_summary, indent=2) + '\n')
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
