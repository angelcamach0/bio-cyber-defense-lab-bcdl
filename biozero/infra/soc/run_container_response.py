#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Accept one retained real worker event using the optional Compose responder.

No pipeline/model is executed and no event is fabricated. Share only public/;
raw event, secret, source-run linkage, receipts and logs stay in private/.
This verifies simulated recording, never effective quarantine or containment.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import socket
import ssl
import stat
import subprocess
import time
import urllib.error
import urllib.request

import relay

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "biozero/infra/compose/docker-compose.yml"
SELECTORS = ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")


class Failure(Exception):
    """Only fixed diagnostic codes, never credentials or HTTP bodies."""


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save_json(path, value, public=False):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    path.chmod(0o644 if public else 0o600)


def reserve_port(preferred):
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", preferred))
        except OSError:
            sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def bounded_document(path, limit=2 * 1024 * 1024):
    """Read a bounded local document without following links or blocking on FIFO."""
    path = Path(path).absolute()
    if path.resolve() != path:
        raise Failure("source_manifest_path_invalid")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit or info.st_uid != os.getuid():
                raise Failure("source_manifest_invalid")
            raw = stream.read(limit + 1)
    except OSError:
        raise Failure("source_manifest_unreadable") from None
    if len(raw) > limit:
        raise Failure("source_manifest_too_large")
    value = relay.decode(raw)
    if not isinstance(value, dict):
        raise Failure("source_manifest_contract_invalid")
    return raw, value


def http_request(opener, url, wire=None, secret=None):
    headers = {"Accept": "application/json"}
    if wire is not None:
        headers["Content-Type"] = "application/json"
    if secret is not None:
        headers["X-Webhook-Secret"] = secret
    request = urllib.request.Request(url, data=wire, headers=headers,
                                     method="POST" if wire is not None else "GET")
    try:
        with opener.open(request, timeout=10) as response:
            status, raw = response.status, response.read(relay.LIMIT + 1)
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read(relay.LIMIT + 1)
        exc.close()
    if len(raw) > relay.LIMIT:
        raise Failure("response_too_large")
    try:
        value = relay.decode(raw)
    except relay.RelayError:
        value = None
    return status, value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", required=True, type=Path, help="Private mode-0600 real worker event")
    parser.add_argument("--source-manifest", required=True, type=Path,
                        help="Passed native --soc run's root manifest.json; retained privately")
    parser.add_argument("--run-dir", type=Path, help="New evidence directory; existing destinations are refused")
    parser.add_argument("--docker-command", default="docker --host=unix:///var/run/docker.sock")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--image", default="biozero-review-zeroresponder", help="Existing image for --skip-build")
    parser.add_argument("--port", type=int, default=8090, help="Preferred loopback HTTPS port; 0 selects a free port")
    args = parser.parse_args()
    docker = shlex.split(args.docker_command)
    selected_local = "--host=unix:///var/run/docker.sock" in docker or any(
        value in ("--host", "-H") and index + 1 < len(docker) and docker[index + 1] == "unix:///var/run/docker.sock"
        for index, value in enumerate(docker))
    if not docker or not selected_local:
        parser.error("Docker command must explicitly select unix:///var/run/docker.sock")
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.:/-]*", args.image):
        parser.error("--image must be a lowercase Docker image reference")
    os.umask(0o077)
    env = dict(os.environ)
    for selector in SELECTORS:
        env.pop(selector, None)
    # Preserve proxy/auth and all non-selector environment variables. Required
    # experiment values are explicitly selected below and in a private env file.
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S-%fZ")
    run_dir = (args.run_dir or ROOT / "biozero/docs/evidence" / (stamp + "-soc-container")).absolute()
    if run_dir.resolve() != run_dir:
        parser.error("--run-dir must not contain symlink paths")
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    run_dir.chmod(0o700)
    private, public = run_dir / "private", run_dir / "public"
    private.mkdir(mode=0o700)
    public.mkdir(mode=0o755)
    pki, data = private / "pki", private / "data"
    project = "bz-soc-" + stamp.lower().replace("t", "-").replace("z", "")
    manifest = {"schema_version": 1, "started_at": datetime.now(timezone.utc).isoformat(),
                "project": project, "status": "failed", "cases": [], "cleanup": "pending",
                "scope": "real optional Compose responder using a retained worker event; simulation only",
                "enforced": False, "pipeline_or_model_executed": False,
                "identity_limit": "shared secret possession; no independent attestation of event origin",
                "image_provenance": ("existing image; source-to-image provenance requires its separate build receipt"
                                     if args.skip_build else "Compose build from the recorded source snapshot")}
    prefix = None
    started = False
    count = 0
    def terminate_requested(signum, frame):
        raise Failure("experiment_cancelled")
    old_term_handler = signal.signal(signal.SIGTERM, terminate_requested)

    def command(argv, label, timeout=120, check=True):
        nonlocal count
        count += 1
        out_path, err_path = private / f"{count:03}-{label}.out", private / f"{count:03}-{label}.err"
        with out_path.open("xb") as out, err_path.open("xb") as err:
            try:
                proc = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=out, stderr=err, start_new_session=True)
            except OSError:
                raise Failure(label + "_unavailable") from None
            try:
                code = proc.wait(timeout=timeout)
            except BaseException as exc:
                # Only this new command session; no unrelated Docker daemon/process.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=10)
                if isinstance(exc, subprocess.TimeoutExpired):
                    raise Failure(label + "_timeout") from None
                raise
        if check and code:
            raise Failure(label + "_failed")
        with out_path.open("rb") as stream:
            preview = stream.read(1024 * 1024)
        return code, preview.decode("utf-8", errors="replace")

    def compose(argv, label, timeout=120, check=True):
        return command(prefix + argv, label, timeout, check)

    def record(name, passed, observed=None):
        manifest["cases"].append({"case": name, "verdict": "PASS" if passed else "FAIL", "observed": observed or {}})
        print(("PASS " if passed else "FAIL ") + name, flush=True)
        if not passed:
            raise Failure("assertion_" + name)

    def ready(opener, base):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                code, value = http_request(opener, base + "/health")
                if (code == 200 and isinstance(value, dict) and value.get("status") == "responder_alive"
                        and value.get("healthy") is True and value.get("mode") == "simulation" and value.get("enforced") is False):
                    return True
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.5)
        raise Failure("verified_https_health_deadline")

    try:
        if os.getuid() == 0:
            raise Failure("nonroot_host_required")
        event_raw = relay.private_read(args.event)
        event = relay.decode(event_raw)
        wire = relay.canonical_event(event)
        event_digest = hashlib.sha256(wire).hexdigest()
        copied_event = private / "worker-event.json"
        with copied_event.open("xb") as stream:
            stream.write(event_raw)
        record("retained_event_contract", True, {"canonical_sha256": event_digest})
        manifest["event_canonical_sha256"] = event_digest
        manifest["event_original_byte_sha256"] = hashlib.sha256(event_raw).hexdigest()
        source_manifest = args.source_manifest.absolute()
        source_raw, parent_manifest = bounded_document(source_manifest)
        source_run = source_manifest.parent
        if source_manifest.name != "manifest.json":
            raise Failure("source_manifest_location_invalid")
        job = event["indicators"]["job_id"]
        expected_event = source_run / "private/data/security-events" / (event["alert_id"] + ".json")
        if args.event.absolute() != expected_event:
            raise Failure("event_outside_source_run")
        summary_raw, parent_summary = bounded_document(source_run / "public/soc-summary.json", relay.LIMIT)
        result_raw, parent_result = bounded_document(source_run / "private/data/results" / (job + ".json"), 16 * 1024 * 1024)
        cases = parent_manifest.get("cases", [])
        real_event_case = [row for row in cases if isinstance(row, dict) and row.get("case") == "soc-real-security-rejection-event"]
        source_verified = (parent_manifest.get("status") == "passed" and len(real_event_case) == 1
                           and real_event_case[0].get("verdict") == "PASS"
                           and parent_summary.get("payload_sha256") == event_digest
                           and parent_summary.get("source") == event["source"]
                           and parent_summary.get("event_code") == event["event_code"]
                           and type(parent_summary.get("schema_version")) is int and parent_summary["schema_version"] == 1
                           and parent_summary.get("mode") == "simulation" and parent_summary.get("enforced") is False
                           and type(parent_result.get("schema_version")) is int and parent_result["schema_version"] == 1
                           and parent_result.get("security_mode") == "protected" and parent_result.get("status") == "rejected"
                           and parent_result.get("release_status") == "withheld"
                           and parent_result.get("job_id") == job and parent_result.get("error_code") == event["event_code"]
                           and parent_result.get("processed_at") == event["timestamp"])
        record("passed_native_parent_bound_to_real_worker_result", source_verified,
               {"parent_status": "passed" if parent_manifest.get("status") == "passed" else "not_passed",
                "result_status": "rejected" if parent_result.get("status") == "rejected" else "unexpected",
                "event_canonical_sha256": event_digest})
        for name, raw in (("source-run-manifest.json", source_raw), ("source-soc-summary.json", summary_raw), ("source-worker-result.json", result_raw)):
            with (private / name).open("xb") as stream:
                stream.write(raw)
        manifest["source_run_manifest_sha256"] = hashlib.sha256(source_raw).hexdigest()
        manifest["source_summary_sha256"] = hashlib.sha256(summary_raw).hexdigest()
        manifest["source_worker_result_sha256"] = hashlib.sha256(result_raw).hexdigest()
        source_hashes = parent_manifest.get("source_hashes", {})
        relevant_parent_sources = ("biozero/services/enclave-runner/main.go", "biozero/services/enclave-runner/security_events.go",
                                   "biozero/services/zeroresponder/main.go", "biozero/infra/soc/relay.py", "biozero/infra/native/run_experiment.py")
        if not isinstance(source_hashes, dict) or any(not isinstance(source_hashes.get(name), str)
                or not re.fullmatch(r"[a-f0-9]{64}", source_hashes[name]) for name in relevant_parent_sources):
            raise Failure("parent_source_hashes_missing")
        manifest["parent_run_code_hashes"] = {name: source_hashes[name] for name in relevant_parent_sources}
        linkage = {"event_path": str(args.event.absolute()), "source_manifest_path": str(source_manifest)}
        save_json(private / "source-linkage.json", linkage)
        _, commit = command(["git", "rev-parse", "HEAD"], "source_commit")
        _, status = command(["git", "status", "--porcelain"], "source_dirty")
        manifest["commit"], manifest["dirty"] = commit.strip(), bool(status.strip())
        sources = [Path(__file__).resolve(), COMPOSE, ROOT / "biozero/infra/PKI/gen-pki.sh",
                   ROOT / "biozero/infra/PKI/prepare-runtime.sh", ROOT / "biozero/infra/soc/relay.py",
                   ROOT / "biozero/infra/native/run_experiment.py", ROOT / "biozero/docs/security/event-contract.md"]
        for service in ("enclave-runner", "zeroresponder"):
            folder = ROOT / "biozero/services" / service
            sources.extend([folder / "go.mod", folder / "Dockerfile", *sorted(folder.glob("*.go"))])
        manifest["source_hashes"] = {str(path.relative_to(ROOT)): sha(path) for path in sources}
        _, version = command(docker + ["compose", "version", "--short"], "compose_version")
        manifest["compose_version"] = version.strip()
        command(["bash", str(ROOT / "biozero/infra/PKI/gen-pki.sh"), str(pki)], "generate_pki")
        command(["bash", str(ROOT / "biozero/infra/PKI/prepare-runtime.sh"), str(data)], "prepare_runtime")
        port = reserve_port(args.port)
        base = f"https://127.0.0.1:{port}"
        endpoint = base + "/alert"
        secret = secrets.token_urlsafe(48)
        with (private / "webhook-secret").open("x", encoding="ascii") as stream:
            stream.write(secret)
        settings = {"BIOZERO_UID": str(os.getuid()), "BIOZERO_GID": str(os.getgid()),
                    "BIOZERO_PKI_PATH": str(pki), "BIOZERO_DATA_PATH": str(data),
                    "BIOZERO_RESPONDER_PORT": str(port), "BIOZERO_WEBHOOK_SECRET": secret}
        env.update(settings)
        env_file = private / "compose.env"
        with env_file.open("x", encoding="utf-8") as stream:
            stream.write("\n".join(key + "=" + json.dumps(value) for key, value in settings.items()) + "\n")
        prefix = docker + ["compose", "--project-name", project, "--project-directory", str(COMPOSE.parent),
                           "--env-file", str(env_file), "-f", str(COMPOSE)]
        if args.skip_build:
            command(docker + ["image", "inspect", "--format", "{{.Id}}", args.image], "image_preflight")
            override = private / "override.yml"
            with override.open("x", encoding="utf-8") as stream:
                stream.write("services:\n  zeroresponder:\n    image: " + args.image + "\n")
            prefix.extend(["-f", str(override)])
        prefix.extend(["--profile", "simulation"])
        compose(["config", "--quiet"], "compose_validation")
        started = True
        if args.skip_build:
            compose(["up", "--no-deps", "--no-build", "-d", "zeroresponder"], "responder_up", timeout=180)
        else:
            compose(["up", "--no-deps", "--build", "-d", "zeroresponder"], "responder_build_up", timeout=1800)
        opener = relay.make_opener(endpoint, pki / "clients/ca.crt")
        ready(opener, base)
        record("verified_ca_https_health", True, {"http_status": 200, "enforced": False})
        untrusted = urllib.request.build_opener(urllib.request.ProxyHandler({}), relay.NoRedirect(),
                                               urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        rejected = False
        try:
            http_request(untrusted, base + "/health")
        except ssl.SSLCertVerificationError:
            rejected = True
        except urllib.error.URLError as exc:
            rejected = isinstance(exc.reason, ssl.SSLCertVerificationError)
        record("untrusted_certificate_rejected", rejected and ready(opener, base))
        for label, supplied in (("missing_secret", None), ("wrong_secret", secrets.token_urlsafe(48))):
            code, _ = http_request(opener, endpoint, wire, supplied)
            record(label + "_denied", code == 403, {"http_status": code})
        local_receipts = data / "security-deliveries"
        first = relay.deliver(copied_event, endpoint, pki / "clients/ca.crt", secret, local_receipts)
        record("durable_simulation_acknowledgment", first["status"] == "recorded" and first["mode"] == "simulation"
               and first["enforced"] is False and first["replay"] is False and first["payload_sha256"] == event_digest,
               {"mode": first["mode"], "enforced": False, "replay": first["replay"]})
        server_path = data / "actions" / (event["alert_id"] + ".json")
        local_path = local_receipts / (event["alert_id"] + ".json")
        server_before, local_before = relay.private_read(server_path), relay.private_read(local_path)
        server_record = relay.decode(server_before)
        stored_wire = relay.canonical_event(server_record["alert"])
        record("single_private_mode0600_receipts", len(list((data / "actions").iterdir())) == 1
               and len(list(local_receipts.iterdir())) == 1 and stored_wire == wire
               and server_record.get("enforced") is False and server_record.get("payload_sha256") == event_digest,
               {"server_receipt_count": 1, "relay_receipt_count": 1, "mode": "0600"})
        compose(["restart", "zeroresponder"], "responder_restart", timeout=120)
        ready(opener, base)
        replayed = relay.deliver(copied_event, endpoint, pki / "clients/ca.crt", secret, local_receipts)
        record("restart_replay_preserves_exact_receipts", replayed["replay"] is True and replayed["enforced"] is False
               and replayed["recorded_at"] == first["recorded_at"] and replayed["actions"] == first["actions"]
               and relay.private_read(server_path) == server_before and relay.private_read(local_path) == local_before
               and len(list((data / "actions").iterdir())) == 1 and len(list(local_receipts.iterdir())) == 1,
               {"replay": True, "server_receipt_count": 1, "relay_receipt_count": 1, "bytes_preserved": True})
        record("no_effective_action_artifacts", {path.name for path in (data / "actions").iterdir()} == {server_path.name},
               {"effective_action_files": 0, "enforced": False})
        _, identifier = compose(["ps", "--quiet", "zeroresponder"], "container_id")
        identifier = identifier.strip()
        if not re.fullmatch(r"[0-9a-f]{12,64}", identifier):
            raise Failure("container_id_invalid")
        fmt = '{"id":{{json .Id}},"image":{{json .Image}},"user":{{json .Config.User}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"cap_drop":{{json .HostConfig.CapDrop}},"security_opt":{{json .HostConfig.SecurityOpt}},"pids":{{json .HostConfig.PidsLimit}},"memory":{{json .HostConfig.Memory}},"cpu":{{json .HostConfig.NanoCpus}},"port_bindings":{{json .HostConfig.PortBindings}},"published_ports":{{json .NetworkSettings.Ports}},"mounts":{{json .Mounts}}}'
        _, raw_inspection = command(docker + ["inspect", "--format", fmt, identifier], "container_controls")
        inspected = json.loads(raw_inspection)
        mounts = [mount for mount in inspected["mounts"] if mount["Type"] == "bind"]
        expected = {"/pki": (pki / "runtime/responder", False), "/data/actions": (data / "actions", True)}
        scoped = len(mounts) == 2 and {row["Destination"] for row in mounts} == set(expected)
        scoped = scoped and all(Path(row["Source"]).resolve() == expected[row["Destination"]][0].resolve()
                                and row["RW"] is expected[row["Destination"]][1] for row in mounts)
        scoped = scoped and {path.name for path in (pki / "runtime/responder").iterdir()} == {"server.key", "server.crt"}
        bounded = (inspected["user"] == f"{os.getuid()}:{os.getgid()}" and inspected["readonly"] is True
                   and inspected["privileged"] is False and "ALL" in (inspected["cap_drop"] or [])
                   and any(str(value).startswith("no-new-privileges") for value in (inspected["security_opt"] or []))
                   and isinstance(inspected["pids"], int) and 0 < inspected["pids"] <= 64
                   and 0 < inspected["memory"] <= 128 * 1024 * 1024 and 0 < inspected["cpu"] <= 250000000)
        ports = inspected["port_bindings"] or {}
        published = inspected["published_ports"] or {}
        loopback = (set(ports) == {"8090/tcp"} and ports["8090/tcp"] == [{"HostIp": "127.0.0.1", "HostPort": str(port)}]
                    and published.get("8090/tcp") == [{"HostIp": "127.0.0.1", "HostPort": str(port)}])
        summary = {key: inspected[key] for key in ("id", "image", "user", "readonly", "privileged", "cap_drop", "security_opt", "pids", "memory", "cpu")}
        summary["mounts"] = [{"target": row["Destination"], "readonly": not row["RW"]} for row in mounts]
        summary["loopback_only"] = loopback
        record("container_scope_limits_and_loopback", scoped and bounded and loopback, summary)
        manifest["container"] = summary
        manifest["source_hashes_unchanged_at_completion"] = all(sha(ROOT / name) == value for name, value in manifest["source_hashes"].items())
        record("source_snapshot_unchanged", manifest["source_hashes_unchanged_at_completion"])
        record("input_event_bytes_unchanged", relay.private_read(args.event) == event_raw)
        manifest["status"] = "passed"
    except Exception as exc:
        manifest["error_code"] = str(exc) if isinstance(exc, Failure) else type(exc).__name__
        print("FAIL " + manifest["error_code"], flush=True)
    except KeyboardInterrupt:
        manifest["error_code"] = "experiment_cancelled"
        print("FAIL experiment_cancelled", flush=True)
    finally:
        if started:
            try:
                compose(["logs", "--no-color", "--tail", "100", "zeroresponder"], "private_container_logs", check=False)
            except Exception:
                manifest["log_capture"] = "failed"
            try:
                code, _ = compose(["down", "--timeout", "10", "--remove-orphans"], "own_project_down", timeout=90, check=False)
                remaining_code, remaining = compose(["ps", "--all", "--quiet"], "own_project_cleanup_check", check=False)
                cleaned = code == 0 and remaining_code == 0 and not remaining.strip()
                manifest["cleanup"] = "passed" if cleaned else "failed"
                if not cleaned:
                    manifest.update(status="failed", error_code="own_project_cleanup_failed")
            except Exception:
                manifest.update(status="failed", cleanup="failed", error_code="own_project_cleanup_failed")
        else:
            manifest["cleanup"] = "not_started"
        manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        save_json(public / "manifest.json", manifest, public=True)
        checksum = public / "SHA256SUMS"
        with checksum.open("x", encoding="ascii") as stream:
            stream.write(sha(public / "manifest.json") + "  manifest.json\n")
        checksum.chmod(0o644)
        print("Public simulation evidence: " + str(public), flush=True)
        print("Raw event, credentials, receipts and logs remain private; no enforcement was performed.", flush=True)
        signal.signal(signal.SIGTERM, old_term_handler)
    return 0 if manifest["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
