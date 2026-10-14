#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the real Compose reviewer HTTPS/session flow with synthetic inputs.

Only public/ is reviewable. Invitations, cookies, configuration, raw results,
Docker/build logs and private keys remain in private/. Browser rendering is a
separate opt-in --browser check. This harness never prints raw responses.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import re
import shlex
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "biozero/infra/compose/docker-compose.yml"
FIXTURE = ROOT / "biozero/bio/fixtures/variant-smoke"
SERVICES = ("upload-api", "results-api", "enclave-runner", "reviewer-gateway")
SELECTORS = ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")
TERMINAL = {"succeeded", "failed", "incomplete", "rejected", "timed_out"}


class Failure(Exception):
    """A safe, fixed diagnostic code; never include response or credentials."""


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value, public=False):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o644 if public else 0o600)


def available_port(preferred):
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", preferred))
        except OSError:
            if preferred:
                sock.bind(("127.0.0.1", 0))
            else:
                raise Failure("loopback_port_unavailable")
        return sock.getsockname()[1]


class Browser:
    def __init__(self, origin, ca, certificate=None, key=None):
        self.origin = origin
        self.cookies = http.cookiejar.CookieJar()
        context = ssl.create_default_context(cafile=str(ca))
        if certificate:
            context.load_cert_chain(str(certificate), str(key))
        # These endpoints are local loopback services; do not route through egress.
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(self.cookies))
        self.csrf = None

    def call(self, path, method="GET", payload=None, headers=None, csrf=True):
        request_headers = {"Accept": "application/json"}
        if method != "GET":
            request_headers["Origin"] = self.origin
            if csrf and self.csrf:
                request_headers["X-CSRF-Token"] = self.csrf
        request_headers.update(headers or {})
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.origin + path, data=data,
                                         headers=request_headers, method=method)
        try:
            with self.opener.open(request, timeout=10) as response:
                status, raw = response.status, response.read(2 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise Failure("http_response_limit_exceeded")
        try:
            value = json.loads(raw) if raw else None
        except (ValueError, UnicodeError):
            value = "ok" if raw == b"ok" else None
        return status, value, raw


def safe_report(payload):
    """Export allowlisted scalar metrics; no backend paths or free text errors."""
    data = payload.get("data", {})
    safe = {name: payload[name] for name in ("job_id", "experiment_id", "status", "error_code") if name in payload}
    safe["data"] = {name: data[name] for name in (
        "status", "upload_sha256", "processed_sha256", "signature_valid", "decrypted",
        "release_status", "error_code") if name in data}
    pipeline = data.get("pipeline_output", {})
    safe["data"]["pipeline_output"] = {name: pipeline[name] for name in (
        "schema_version", "mode", "pipeline_status", "read_count", "avg_read_length", "line_count",
        "reference_sha256", "input_sha256") if name in pipeline}
    safe["data"]["pipeline_output"]["errors"] = [
        {field: row[field] for field in ("stage", "code") if field in row}
        for row in pipeline.get("errors", [])]
    evaluation = data.get("scientific_evaluation", {})
    safe["data"]["scientific_evaluation"] = {name: evaluation[name] for name in (
        "evaluation_status", "tp", "fp", "fn", "precision", "recall", "reproducible_callset",
        "truth_sha256", "reference_sha256", "observed_sha256", "evaluator_sha256") if name in evaluation}
    return safe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-command", default="docker --host=unix:///var/run/docker.sock",
                        help="Docker CLI prefix, parsed with shlex, including optional sudo -n env")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--browser", action="store_true", help="Also run real Firefox UI/TLS/session-race acceptance; requires Playwright and certutil")
    parser.add_argument("--image-prefix", default="biozero-review",
                        help="Existing <prefix>-<service> images when --skip-build is used")
    parser.add_argument("--port", type=int, default=8083, help="Preferred loopback gateway port; 0 chooses a free port")
    args = parser.parse_args()
    if args.browser:
        from browser_checks import run_browser_checks
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    docker = shlex.split(args.docker_command)
    if not docker:
        parser.error("--docker-command must not be empty")
    local_socket = "--host=unix:///var/run/docker.sock" in docker or any(
        item in ("--host", "-H") and index + 1 < len(docker)
        and docker[index + 1] == "unix:///var/run/docker.sock" for index, item in enumerate(docker))
    if not local_socket:
        parser.error("--docker-command must explicitly select unix:///var/run/docker.sock")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", args.image_prefix):
        parser.error("--image-prefix must be a lowercase image-name prefix")
    os.umask(0o077)
    env = dict(os.environ)
    for key in SELECTORS:
        env.pop(key, None)
    # The experiment selects its own BIOZERO settings, while retaining proxy/auth.
    for key in list(env):
        if key.startswith("BIOZERO_") or key in ("COMPOSE_FILE", "COMPOSE_PROJECT_NAME", "COMPOSE_PROFILES", "COMPOSE_ENV_FILES"):
            env.pop(key, None)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S-%fZ")
    run_dir = ROOT / "biozero/docs/evidence" / (stamp + "-reviewer-compose")
    run_dir.mkdir(parents=True, exist_ok=False)
    run_dir.chmod(0o700)
    private, public = run_dir / "private", run_dir / "public"
    private.mkdir(mode=0o700)
    public.mkdir(mode=0o755)
    pki, data, config = private / "pki", private / "data", private / "reviewer-config"
    project = "bz-review-" + stamp.lower().replace("t", "-").replace("z", "")
    manifest = {"schema_version": 1, "started_at": datetime.now(timezone.utc).isoformat(),
                "project": project, "status": "failed", "cases": [], "architecture": platform.machine(),
                "scope": "real Compose containers; HTTPS HTTP session flow and synthetic allele presence",
                "browser_rendering": "pending: HTTP flow does not verify browser rendering", "cleanup": "pending"}
    compose_prefix = None
    started = False
    counter = 0

    def command(argv, label, timeout=120, check=True):
        nonlocal counter
        counter += 1
        try:
            result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True,
                                    timeout=timeout, text=True, encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired as exc:
            for suffix, raw in (("out", exc.stdout), ("err", exc.stderr)):
                (private / f"{counter:03}-{label}.{suffix}").write_bytes(
                    raw if isinstance(raw, bytes) else (raw or "").encode())
            raise Failure(label + "_timeout") from None
        except OSError:
            raise Failure(label + "_unavailable") from None
        for suffix, raw in (("out", result.stdout), ("err", result.stderr)):
            (private / f"{counter:03}-{label}.{suffix}").write_text(raw, encoding="utf-8")
        if check and result.returncode:
            raise Failure(label + "_failed")
        return result

    def compose(argv, label, timeout=120, check=True):
        return command(compose_prefix + argv, label, timeout, check)

    def record(name, passed, observed=None):
        manifest["cases"].append({"case": name, "verdict": "PASS" if passed else "FAIL", "observed": observed or {}})
        print(("PASS " if passed else "FAIL ") + name, flush=True)
        if not passed:
            raise Failure("assertion_" + name)

    def poll(browser, path, expected, label, deadline_seconds=60):
        deadline = time.monotonic() + deadline_seconds
        while time.monotonic() < deadline:
            try:
                code, value, _ = browser.call(path)
                if expected(code, value):
                    return value
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.5)
        raise Failure(label + "_deadline")

    def signin(browser, invitation):
        code, _, _ = browser.call("/api/sign-in", "POST", {
            "id": invitation["id"], "access_code": invitation["access_code"]}, csrf=False)
        if code != 200:
            raise Failure("sign_in_failed")
        code, session, _ = browser.call("/api/session")
        if code != 200 or not isinstance(session, dict) or not session.get("csrf_token"):
            raise Failure("session_csrf_missing")
        browser.csrf = session["csrf_token"]

    def start_run(browser, experiment):
        code, payload, _ = browser.call("/api/experiments/" + experiment + "/runs", "POST", {})
        if code != 202 or not isinstance(payload, dict) or not re.fullmatch(r"[0-9a-f]{16}", payload.get("job_id", "")):
            raise Failure("prepared_run_submission_failed")
        job = payload["job_id"]
        result = poll(browser, "/api/results/" + job,
                      lambda code, value: code == 200 and isinstance(value, dict) and value.get("status") in TERMINAL,
                      "prepared_run_terminal", deadline_seconds=240)
        return job, result

    def inspect_containers():
        summaries = {}
        pki_scopes = {"upload-api": "upload", "results-api": "results", "enclave-runner": "worker", "reviewer-gateway": "gateway"}
        allowed_targets = {
            "upload-api": {"/data/uploads", "/data/jobs", "/pki"},
            "results-api": {"/data/jobs", "/data/results", "/pki"},
            "enclave-runner": {"/data/uploads", "/data/jobs", "/data/results", "/data/artifacts", "/data/security-events", "/pki", "/rules", "/pipeline", "/reference", "/benchmarks"},
            "reviewer-gateway": {"/pki", "/config", "/state", "/fixtures", "/ui"}}
        scoped_pki_files = {"upload-api": {"server.key", "server.crt", "ca.crt"},
                            "results-api": {"server.key", "server.crt", "ca.crt"},
                            "enclave-runner": {"decrypt.key", "signer.crt"},
                            "reviewer-gateway": {"server.key", "server.crt", "ca.crt", "decrypt.crt", "signer.key",
                                                 "researcher-a.crt", "researcher-a.key", "researcher-b.crt", "researcher-b.key"}}
        readonly_targets = {
            "upload-api": {"/pki"}, "results-api": allowed_targets["results-api"],
            "enclave-runner": {"/data/uploads", "/pki", "/rules", "/pipeline", "/reference", "/benchmarks"},
            "reviewer-gateway": {"/pki", "/config", "/fixtures", "/ui"}}
        expected_sources = {
            "upload-api": {"/data/uploads": data / "uploads", "/data/jobs": data / "jobs"},
            "results-api": {"/data/jobs": data / "jobs", "/data/results": data / "results"},
            "enclave-runner": {"/data/" + name: data / name for name in ("uploads", "jobs", "results", "artifacts", "security-events")},
            "reviewer-gateway": {"/config": config, "/state": data / "reviewer", "/fixtures": FIXTURE, "/ui": ROOT / "biozero/ui"}}
        expected_sources["enclave-runner"].update({"/rules": ROOT / "biozero/bio/reference-db", "/pipeline": ROOT / "biozero/bio/pipeline",
                                                   "/reference": FIXTURE, "/benchmarks": ROOT / "biozero/bio/benchmarks"})
        fmt = '{"id":{{json .Id}},"image":{{json .Image}},"user":{{json .Config.User}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"cap_drop":{{json .HostConfig.CapDrop}},"security_opt":{{json .HostConfig.SecurityOpt}},"network":{{json .HostConfig.NetworkMode}},"pids":{{json .HostConfig.PidsLimit}},"memory":{{json .HostConfig.Memory}},"cpu":{{json .HostConfig.NanoCpus}},"mounts":{{json .Mounts}}}'
        for service in SERVICES:
            identifier = compose(["ps", "-q", service], "container_id_" + service).stdout.strip()
            if not re.fullmatch(r"[0-9a-f]{12,64}", identifier):
                raise Failure("container_id_invalid")
            observed = json.loads(command(docker + ["inspect", "--format", fmt, identifier], "inspect_" + service).stdout)
            mounts = [m for m in observed["mounts"] if m["Type"] == "bind"]
            scopes = [m for m in mounts if m["Destination"] == "/pki"]
            safe_mounts = [{"target": m["Destination"], "readonly": not m["RW"]} for m in mounts]
            bounded = (observed["readonly"] is True and observed["privileged"] is False
                       and observed["user"] == f"{os.getuid()}:{os.getgid()}" and os.getuid() != 0
                       and "ALL" in (observed["cap_drop"] or [])
                       and any(str(item).startswith("no-new-privileges") for item in (observed["security_opt"] or []))
                       and isinstance(observed["pids"], int) and 0 < observed["pids"] <= 128
                       and 0 < observed["memory"] <= 512 * 1024 * 1024 and 0 < observed["cpu"] <= 1_000_000_000)
            scoped = (len(scopes) == 1 and Path(scopes[0]["Source"]).resolve() == (pki / "runtime" / pki_scopes[service]).resolve()
                      and not scopes[0]["RW"] and {m["Destination"] for m in mounts} == allowed_targets[service]
                      and len(mounts) == len(allowed_targets[service])
                      and all(not m["RW"] if m["Destination"] in readonly_targets[service] else m["RW"] for m in mounts)
                      and all(Path(m["Source"]).resolve() == expected_sources[service][m["Destination"]].resolve()
                              for m in mounts if m["Destination"] != "/pki")
                      and {path.name for path in (pki / "runtime" / pki_scopes[service]).iterdir()} == scoped_pki_files[service])
            summary = {key: observed[key] for key in ("id", "image", "user", "readonly", "privileged", "cap_drop", "security_opt", "network", "pids", "memory", "cpu")}
            summary["mounts"] = safe_mounts
            summaries[service] = summary
            record("container_controls_" + service, bounded and scoped and (service != "enclave-runner" or observed["network"] == "none"), summary)
        manifest["containers"] = summaries
        # Version-only commands; do not inspect container environment or keys.
        versions = {}
        for tool in ("python3", "minimap2", "samtools", "bcftools"):
            result = compose(["exec", "-T", "enclave-runner", tool, "--version"], "version_" + tool)
            rows = (result.stdout + result.stderr).splitlines()
            if not rows:
                raise Failure("tool_version_missing")
            versions[tool] = rows[0][:200]
        manifest["worker_tool_versions"] = versions

    try:
        if os.getuid() == 0:
            raise Failure("nonroot_host_user_required")
        manifest["commit"] = command(["git", "rev-parse", "HEAD"], "git_commit").stdout.strip()
        manifest["dirty"] = bool(command(["git", "status", "--porcelain"], "git_dirty").stdout.strip())
        source_paths = [COMPOSE, Path(__file__).resolve(), ROOT / "biozero/infra/PKI/gen-pki.sh",
                        ROOT / "biozero/infra/PKI/prepare-runtime.sh", ROOT / "biozero/infra/compose/prepare-reviewers.py",
                        ROOT / "biozero/bio/pipeline/pipeline.py", ROOT / "biozero/bio/benchmarks/evaluate_variants.py"]
        source_paths += [ROOT / "biozero/services" / service / filename for service in SERVICES for filename in ("main.go", "Dockerfile", "go.mod")]
        source_paths.append(ROOT / "biozero/services/enclave-runner/security_events.go")
        source_paths.append(ROOT / "biozero/services/enclave-runner/job_lifecycle.go")
        source_paths += [ROOT / "biozero/services" / service / "metadata.go" for service in ("enclave-runner", "results-api")]
        source_paths += [FIXTURE / name for name in ("reference.fa", "reads.fastq", "expected.vcf", "invalid.fastq")]
        source_paths += [ROOT / "biozero/ui" / name for name in ("app.js", "index.html", "styles.css")]
        if args.browser:
            source_paths.append(Path(__file__).with_name("browser_checks.py"))
            source_paths.append(ROOT / "biozero/infra/bootstrap/browser-linux-aarch64-py311.requirements.txt")
        manifest["source_hashes"] = {str(path.relative_to(ROOT)): digest(path) for path in source_paths}
        manifest["compose_version"] = command(docker + ["compose", "version", "--short"], "compose_version").stdout.strip()
        gateway_port, upload_port, results_port = available_port(args.port), available_port(8081), available_port(8082)
        if len({gateway_port, upload_port, results_port}) != 3:
            raise Failure("selected_port_collision")
        origin = f"https://127.0.0.1:{gateway_port}"
        manifest["configuration"] = {"origin": origin, "loopback_ports": {"upload": upload_port, "results": results_port},
                                     "pipeline_mode": "variants", "security_mode": "protected", "single_worker": True}
        command(["bash", str(ROOT / "biozero/infra/PKI/gen-pki.sh"), str(pki)], "generate_pki")
        command(["bash", str(ROOT / "biozero/infra/PKI/prepare-runtime.sh"), str(data)], "prepare_runtime")
        command([sys.executable, str(ROOT / "biozero/infra/compose/prepare-reviewers.py"), "--out", str(config), "--origin", origin], "prepare_reviewers")
        settings = {"BIOZERO_UID": str(os.getuid()), "BIOZERO_GID": str(os.getgid()),
                    "BIOZERO_PKI_PATH": str(pki), "BIOZERO_DATA_PATH": str(data), "BIOZERO_REVIEWER_CONFIG_PATH": str(config),
                    "BIOZERO_REFERENCE_DATA_PATH": str(FIXTURE), "BIOZERO_PIPELINE_MODE": "variants",
                    "BIOZERO_REFERENCE_PATH": "/reference/reference.fa", "BIOZERO_EVALUATOR_PATH": "/benchmarks/evaluate_variants.py",
                    "BIOZERO_TRUTH_PATH": "/reference/expected.vcf", "BIOZERO_PIPELINE_TIMEOUT": "120s", "BIOZERO_JOB_KEY": ""}
        env_file = private / "compose.env"
        env_file.write_text("\n".join(key + "=" + json.dumps(value) for key, value in settings.items()) + "\n")
        override = private / "override.yml"
        override_lines = ["services:"]
        for service, host_port, container_port in (("upload-api", upload_port, 8081), ("results-api", results_port, 8082), ("reviewer-gateway", gateway_port, 8083)):
            override_lines.extend([f"  {service}:", "    ports: !override", f'      - "127.0.0.1:{host_port}:{container_port}"'])
            if args.skip_build:
                override_lines.append(f"    image: {args.image_prefix}-{service}")
        if args.skip_build:
            override_lines.extend(["  enclave-runner:", f"    image: {args.image_prefix}-enclave-runner"])
            for service in SERVICES:
                command(docker + ["image", "inspect", "--format", "{{.Id}}", args.image_prefix + "-" + service], "image_preflight_" + service)
        override.write_text("\n".join(override_lines) + "\n")
        compose_prefix = docker + ["compose", "--project-name", project, "--project-directory", str(COMPOSE.parent),
                                  "--env-file", str(env_file), "-f", str(COMPOSE), "-f", str(override)]
        compose(["config", "--quiet"], "compose_validation")
        if not args.skip_build:
            compose(["build", *SERVICES], "compose_build", timeout=1800)
        started = True  # Also clean partially-created projects when up fails.
        compose(["up", "-d", "--no-build", *SERVICES], "compose_up", timeout=180)
        ca = pki / "clients/ca.crt"
        client_a = Browser("https://127.0.0.1:" + str(upload_port), ca, pki / "clients/researcher-a.crt", pki / "clients/researcher-a.key")
        client_results_a = Browser("https://127.0.0.1:" + str(results_port), ca, pki / "clients/researcher-a.crt", pki / "clients/researcher-a.key")
        client_results_b = Browser("https://127.0.0.1:" + str(results_port), ca, pki / "clients/researcher-b.crt", pki / "clients/researcher-b.key")
        for client, label in ((client_a, "upload_health"), (client_results_a, "results_health")):
            poll(client, "/health", lambda code, value: code == 200 and value == "ok", label)
            record(label, True, {"http_status": 200})
        for url, authenticated, label in ((client_a.origin, client_a, "upload_mtls_certificate_required"),
                                           (client_results_a.origin, client_results_a, "results_mtls_certificate_required")):
            denied = False
            try:
                Browser(url, ca).call("/health")
            except ssl.SSLError:
                denied = True
            except urllib.error.URLError as exc:
                denied = isinstance(exc.reason, ssl.SSLError)
            # A refused connection or dead service never earns an mTLS PASS.
            code, value, _ = authenticated.call("/health")
            record(label, denied and code == 200 and value == "ok")
        browser_a, browser_b, anonymous = Browser(origin, ca), Browser(origin, ca), Browser(origin, ca)
        poll(anonymous, "/health", lambda code, value: code == 200 and isinstance(value, dict) and value.get("status") == "gateway_alive", "gateway_health")
        record("gateway_https_health", True, {"http_status": 200})
        record("anonymous_session_denied", anonymous.call("/api/session")[0] == 401)
        invitations = json.loads((config / "invitations.json").read_text())
        indexed = {row["id"]: row for row in invitations}
        signin(browser_a, indexed["reviewer-a"])
        signin(browser_b, indexed["reviewer-b"])
        record("two_distinct_reviewer_sessions", browser_a.csrf != browser_b.csrf)
        record("foreign_origin_denied", browser_a.call("/api/experiments/variant-smoke/runs", "POST", {}, headers={"Origin": "https://foreign.invalid"})[0] == 403)
        record("missing_csrf_denied", browser_a.call("/api/experiments/variant-smoke/runs", "POST", {}, csrf=False)[0] == 403)
        record("unknown_experiment_denied", browser_a.call("/api/experiments/unknown/runs", "POST", {})[0] == 404)
        jobs, worker_vcfs = [], []
        for number in (1, 2):
            job, payload = start_run(browser_a, "variant-smoke")
            jobs.append(job)
            write_json(private / f"raw-valid-{number}.json", payload)
            write_json(public / f"valid-{number}.json", safe_report(payload), public=True)
            report = payload.get("data", {})
            evaluation = report.get("scientific_evaluation", {})
            passed = (payload.get("status") == "succeeded" and report.get("release_status") == "evaluated_passed"
                      and report.get("signature_valid") is True and report.get("decrypted") is True
                      and evaluation.get("evaluation_status") == "passed"
                      and (evaluation.get("tp"), evaluation.get("fp"), evaluation.get("fn")) == (3, 0, 0))
            record(f"reviewer_a_valid_run_{number}", passed, {"status": payload.get("status"), "release_status": report.get("release_status"), "tp": evaluation.get("tp"), "fp": evaluation.get("fp"), "fn": evaluation.get("fn")})
            code, _, _ = browser_b.call("/api/results/" + job, headers={"X-Client-Id": "researcher-a", "X-Reviewer-Id": "reviewer-a"})
            record(f"reviewer_b_cannot_read_a_{number}", code == 404, {"http_status": code})
            code, _, _ = client_results_b.call("/results/" + job, headers={"X-Client-Id": "researcher-a"})
            record(f"api_certificate_b_cannot_read_a_{number}", code == 403, {"http_status": code})
            worker = json.loads((data / "results" / (job + ".json")).read_text())
            metadata = json.loads((data / "jobs" / (job + ".json")).read_text())
            uploads = list((data / "uploads").glob(job + "_*"))
            original_hash_preserved = (len(uploads) == 1 and digest(uploads[0]) == metadata.get("sha256")
                                       == worker.get("upload_sha256") == report.get("upload_sha256")
                                       and worker.get("processed_sha256") == report.get("processed_sha256")
                                       == digest(FIXTURE / "reads.fastq"))
            record(f"original_upload_hash_immutable_{number}", original_hash_preserved,
                   {"upload_sha256": worker.get("upload_sha256"), "processed_sha256": worker.get("processed_sha256")})
            observed = Path(worker["pipeline_output"]["outputs"]["normalized_vcf"])
            relative = observed.relative_to("/data/artifacts")
            local = (data / "artifacts" / relative).resolve()
            workspace = (data / "artifacts" / job).resolve()
            if not local.is_relative_to(workspace) or not local.is_file():
                raise Failure("worker_artifact_outside_job")
            worker_vcfs.append(local)
        evaluated = command([sys.executable, str(ROOT / "biozero/bio/benchmarks/evaluate_variants.py"),
                             "--reference", str(FIXTURE / "reference.fa"), "--expected", str(FIXTURE / "expected.vcf"),
                             "--observed", str(worker_vcfs[0]), "--repeat", str(worker_vcfs[1])], "repeat_evaluation")
        metrics = json.loads(evaluated.stdout)
        record("normalized_science_repeat", metrics.get("evaluation_status") == "passed" and metrics.get("reproducible_callset") is True and (metrics.get("tp"), metrics.get("fp"), metrics.get("fn")) == (3, 0, 0),
               {key: metrics.get(key) for key in ("evaluation_status", "tp", "fp", "fn", "reproducible_callset")})
        write_json(public / "repeat-metrics.json", {key: metrics.get(key) for key in ("evaluation_status", "tp", "fp", "fn", "precision", "recall", "reproducible_callset", "scope")}, public=True)
        _, invalid = start_run(browser_a, "invalid-fastq")
        write_json(private / "raw-invalid.json", invalid)
        write_json(public / "invalid-fastq.json", safe_report(invalid), public=True)
        invalid_data = invalid.get("data", {})
        errors = invalid_data.get("pipeline_output", {}).get("errors", [])
        record("malformed_fastq_failed_and_withheld", invalid.get("status") == "failed" and invalid_data.get("release_status") == "withheld"
               and invalid_data.get("scientific_evaluation", {}).get("evaluation_status") != "passed"
               and any(row.get("stage") == "validate_fastq" and row.get("code") == "invalid_input" for row in errors),
               {"status": invalid.get("status"), "release_status": invalid_data.get("release_status")})
        compose(["restart", "reviewer-gateway"], "restart_gateway")
        poll(anonymous, "/health", lambda code, value: code == 200, "gateway_restart_health")
        record("gateway_restart_invalidates_session", browser_a.call("/api/session")[0] == 401)
        signin(browser_a, indexed["reviewer-a"])
        signin(browser_b, indexed["reviewer-b"])
        code, rows, _ = browser_a.call("/api/runs")
        record("relogin_recovers_own_runs", code == 200 and isinstance(rows, list) and set(jobs).issubset({row.get("job_id") for row in rows}))
        code, recovered, _ = browser_a.call("/api/results/" + jobs[0])
        record("relogin_recovers_own_result", code == 200 and recovered.get("status") == "succeeded" and recovered.get("data", {}).get("release_status") == "evaluated_passed")
        code, _, _ = browser_b.call("/api/results/" + jobs[0], headers={"X-Client-Id": "researcher-a"})
        record("restart_preserves_owner_isolation", code == 404, {"http_status": code})
        code, rows, _ = browser_b.call("/api/runs")
        record("reviewer_b_run_history_isolated", code == 200 and isinstance(rows, list) and not rows)
        old_cookie = "; ".join(cookie.name + "=" + cookie.value for cookie in browser_a.cookies)
        code, _, _ = browser_a.call("/api/sign-out", "POST", {})
        replay = Browser(origin, ca)
        replay_status = replay.call("/api/session", headers={"Cookie": old_cookie})[0]
        record("logout_revokes_session", bool(old_cookie) and code == 200 and replay_status == 401
               and browser_a.call("/api/session")[0] == 401)
        inspect_containers()
        if args.browser:
            browser_report = run_browser_checks(origin, config / "invitations.json", ca, public, private)
            manifest["browser_rendering"] = browser_report.get("status", "failed")
            record("real_browser_ui_tls_and_session_isolation", browser_report.get("status") == "passed",
                   {"report_file": "browser-checks.json", "checks": len(browser_report.get("checks", [])),
                    "javascript_error_count": browser_report.get("javascript_error_count")})
        manifest["status"] = "passed"
    except Exception as exc:
        manifest["error_code"] = str(exc) if isinstance(exc, Failure) else type(exc).__name__
        print("FAIL " + manifest["error_code"], flush=True)
    finally:
        if started:
            try:
                compose(["logs", "--no-color", "--tail", "200", *SERVICES], "container_logs", check=False)
            except Exception:
                manifest["log_capture"] = "failed"
            try:
                stopped = compose(["down", "--timeout", "10", "--remove-orphans"], "compose_down", timeout=90, check=False)
                remaining = compose(["ps", "--all", "--quiet"], "cleanup_verification", check=False)
                cleaned = stopped.returncode == 0 and remaining.returncode == 0 and not remaining.stdout.strip()
                manifest["cleanup"] = "passed" if cleaned else "failed"
                if not cleaned:
                    manifest["status"] = "failed"
                    manifest["error_code"] = "own_project_cleanup_failed"
            except Exception:
                manifest.update(status="failed", cleanup="failed", error_code="own_project_cleanup_failed")
        else:
            manifest["cleanup"] = "not_started"
        manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        public_allowlist = ("valid-1.json", "valid-2.json", "repeat-metrics.json", "invalid-fastq.json", "manifest.json",
                            "browser-checks.json", "browser-valid-desktop.png", "browser-valid-mobile.png",
                            "browser-invalid-desktop.png", "browser-session-isolation.png", "browser-failure.png")
        manifest["public_files"] = [name for name in public_allowlist if name == "manifest.json" or (public / name).is_file()]
        write_json(public / "manifest.json", manifest, public=True)
        checksums = public / "SHA256SUMS"
        checksums.write_text("".join(digest(public / name) + "  " + name + "\n" for name in manifest["public_files"]))
        checksums.chmod(0o644)
        print("Reviewable evidence: " + str(public), flush=True)
        print("Private credentials and raw logs remain in private/; share only public/.", flush=True)
    return 0 if manifest["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
