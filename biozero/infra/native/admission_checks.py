# SPDX-License-Identifier: AGPL-3.0-only
"""Real native acceptance of retained-input admission; no disk-quota claim.

This helper starts only supplied local binaries in fresh private runtimes. It
uses existing role PKI without modifying it and publishes fixed observations,
never response bodies, principal names, job IDs, ledger contents or local paths.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import time
import urllib.error
import urllib.request


_PAYLOAD = b"@r\nACGT\n+\nIIII"  # Fourteen bytes; crypto rejection precedes parsing.
_BOUNDARY = "biozero-admission-boundary"
_RESPONSE_LIMIT = 16 * 1024 * 1024
_STAGE_DIRECTORY = ".biozero-admission-staging"


class AdmissionCheckError(Exception):
    """Fixed diagnostics safe for the parent manifest."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AdmissionCheckError("admission_check_redirect_refused")


def _private_directory(path):
    path = Path(path).absolute()
    if path.resolve() != path:
        raise AdmissionCheckError("admission_check_directory_unsafe")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise AdmissionCheckError("admission_check_directory_unsafe")
    return path


def _write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)


def _free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _fingerprint_inputs(data):
    """Fingerprint retained files and the exact, empty post-terminal stages.

    Directories are descriptor anchored and no-follow. A stage with even an
    empty reservation directory is not clean; unknown directories/files cannot
    disappear behind the staging allowlist. This runs after completed uploads,
    terminal worker persistence or with isolated services stopped.
    """
    result = {}
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC

    def private_dir(name, parent=None):
        fd = os.open(name, flags, dir_fd=parent)
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(fd)
            raise AdmissionCheckError("admission_check_directory_unsafe")
        return fd, info

    data_fd, _ = private_dir(data)
    try:
        for directory in ("uploads", "jobs"):
            parent, _ = private_dir(directory, data_fd)
            try:
                names = sorted(os.listdir(parent))
                if _STAGE_DIRECTORY not in names:
                    raise AdmissionCheckError("admission_check_stage_missing")
                for name in names:
                    if name == _STAGE_DIRECTORY:
                        stage, info = private_dir(name, parent)
                        try:
                            children = os.listdir(stage)
                            if children:
                                raise AdmissionCheckError("admission_check_stage_not_empty")
                            result[(directory, name)] = (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode), ())
                        finally:
                            os.close(stage)
                        continue
                    pattern = r"[0-9a-f]{16}\.json" if directory == "jobs" else r"[0-9a-f]{16}_unsigned\.fastq"
                    if not re.fullmatch(pattern, name):
                        raise AdmissionCheckError("admission_check_input_name_unknown")
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
                    with os.fdopen(fd, "rb") as stream:
                        info = os.fstat(stream.fileno())
                        limit = 65536 if directory == "jobs" else 1024
                        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > limit):
                            raise AdmissionCheckError("admission_check_input_unsafe")
                        raw = stream.read(limit + 1)
                        if len(raw) > limit:
                            raise AdmissionCheckError("admission_check_input_unsafe")
                        result[(directory, name)] = (info.st_dev, info.st_ino, info.st_uid,
                                                   stat.S_IMODE(info.st_mode), hashlib.sha256(raw).hexdigest())
            finally:
                os.close(parent)
    finally:
        os.close(data_fd)
    return result


def run_checks(*, run_dir, binaries, pki, env, record):
    """Run real HTTPS admission checks after the runtime authors declare freeze.

    ``record(name, passed, observed)`` receives fixed case names and scalar safe
    metrics. This helper never supplies fake results, builds/downloads tools or
    runs a pipeline/model. Missing/corrupt-ledger cases alter only private copies
    of its own retained inputs. Processes/groups it creates are stopped on every
    path; retained inputs and private diagnostics are preserved.
    """
    run = _private_directory(run_dir)
    binaries, pki = Path(binaries).resolve(), Path(pki).resolve()
    private = run / "private/admission-checks"
    private.mkdir(mode=0o700, parents=True, exist_ok=False)
    _private_directory(private)
    observations, processes, logs, process_logs = [], [], [], {}
    response_number = 0
    log_number = 0
    contexts = {}
    for actor in ("a", "b"):
        ctx = ssl.create_default_context(cafile=str(pki / "clients/ca.crt"))
        ctx.load_cert_chain(str(pki / f"clients/researcher-{actor}.crt"),
                            str(pki / f"clients/researcher-{actor}.key"))
        contexts[actor] = ctx
    policy = {"BIOZERO_ADMISSION_GLOBAL_JOBS": "2", "BIOZERO_ADMISSION_PRINCIPAL_JOBS": "1",
              "BIOZERO_ADMISSION_GLOBAL_BYTES": str(1 << 20),
              "BIOZERO_ADMISSION_PRINCIPAL_BYTES": str(512 << 10),
              "BIOZERO_ADMISSION_ACTIVE_UPLOADS": "2",
              "BIOZERO_ADMISSION_PRINCIPAL_ACTIVE_UPLOADS": "1",
              "BIOZERO_ADMISSION_FREE_SPACE_FLOOR": str(128 << 20),
              "BIOZERO_MAX_UPLOAD_BYTES": "1024", "BIOZERO_RATE_LIMIT": "1000"}

    def emit(name, passed, observed):
        if any(type(value) not in (bool, int, float, str) for value in observed.values()):
            raise AdmissionCheckError("admission_check_observation_invalid")
        item = {"case": name, "passed": bool(passed), "observed": observed}
        observations.append(item)
        record(name, bool(passed), observed)
        if not passed:
            raise AdmissionCheckError("admission_check_acceptance_failed")

    def fresh(label):
        data = private / label / "data"
        data.mkdir(mode=0o700, parents=True)
        data.parent.chmod(0o700)
        for name in ("uploads", "jobs", "admission"):
            (data / name).mkdir(mode=0o700)
        return data

    def start(name, data, overrides=None):
        nonlocal log_number
        log_number += 1
        log_path = private / f"process-{log_number:03d}.log"
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        log = os.fdopen(fd, "wb")
        logs.append(log)
        settings = {**env, **policy, "BIOZERO_SECURITY_MODE": "protected", "BIOZERO_DATA_DIR": str(data)}
        if name in ("upload-api", "results-api"):
            role = "upload" if name == "upload-api" else "results"
            port = _free_port()
            settings.update({f"BIOZERO_{'UPLOAD' if role == 'upload' else 'RESULTS'}_ADDR": f"127.0.0.1:{port}",
                             "BIOZERO_TLS_CERT": str(pki / f"runtime/{role}/server.crt"),
                             "BIOZERO_TLS_KEY": str(pki / f"runtime/{role}/server.key"),
                             "BIOZERO_TLS_CA": str(pki / f"runtime/{role}/ca.crt")})
        else:
            port = None
            settings.update({"BIOZERO_PIPELINE_PATH": str(data / "pipeline-must-not-run"),
                             "BIOZERO_RULES_PATH": str(data / "absent-rules"),
                             "BIOZERO_DECRYPT_DIR": str(data / "decrypted"),
                             "BIOZERO_SECURITY_EVENTS_DIR": str(data / "security-events"),
                             "BIOZERO_POLL_SECONDS": "0.01", "BIOZERO_PIPELINE_MODE": "stats",
                             "BIOZERO_JOB_KEY": "", "BIOZERO_SIGNER_CERT": "", "BIOZERO_PRIVATE_KEY": ""})
        settings.update(overrides or {})
        try:
            proc = subprocess.Popen([str(binaries / name)], env=settings, stdout=log,
                                    stderr=subprocess.STDOUT, start_new_session=True)
        except OSError:
            raise AdmissionCheckError("admission_check_process_start_failed") from None
        processes.append(proc)
        process_logs[proc.pid] = log_path
        return proc, (f"https://127.0.0.1:{port}" if port is not None else None)

    def request(url, actor="a", body=None):
        nonlocal response_number
        headers = {"Content-Type": f"multipart/form-data; boundary={_BOUNDARY}"} if body is not None else {}
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                             urllib.request.HTTPSHandler(context=contexts[actor]))
        try:
            with opener.open(urllib.request.Request(url, data=body, headers=headers), timeout=2) as resp:
                code, raw = resp.status, resp.read(_RESPONSE_LIMIT + 1)
        except urllib.error.HTTPError as exc:
            with exc:
                code, raw = exc.code, exc.read(_RESPONSE_LIMIT + 1)
        if len(raw) > _RESPONSE_LIMIT:
            raise AdmissionCheckError("admission_check_response_oversized")
        response_number += 1
        _write_private(private / f"response-{response_number:03d}.bin", raw)
        return code, raw

    def ready(proc, url):
        stop = time.monotonic() + 10
        while time.monotonic() < stop:
            if proc.poll() is not None:
                raise AdmissionCheckError("admission_check_service_exited")
            try:
                code, raw = request(url + "/health")
                if code == 200 and raw == b"ok":
                    return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.05)
        raise AdmissionCheckError("admission_check_readiness_failed")

    def stop(proc):
        # Child commands may have their own group but inherit our new session.
        # Include only those exact sessions, even after their leader exited.
        groups = {proc.pid} if proc.poll() is None else set()
        for entry in Path("/proc").glob("[0-9]*/stat"):
            try:
                fields = entry.read_text().rsplit(")", 1)[1].split()
                if int(fields[3]) == proc.pid:
                    groups.add(int(fields[2]))
            except (OSError, ValueError, IndexError):
                continue
        for group in groups:
            try:
                os.killpg(group, signal.SIGTERM)
            except ProcessLookupError:
                continue
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        for group in groups:
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                continue
        proc.wait(timeout=5)

    def startup_failed(proc, expected_code):
        try:
            exited = proc.wait(timeout=5) != 0
        except subprocess.TimeoutExpired:
            stop(proc)
            return False
        # Reject generic startup failures: each negative case needs its own
        # stable diagnostic, rather than accidentally passing on bind/TLS error.
        with process_logs[proc.pid].open("rb") as stream:
            raw = stream.read((1 << 20) + 1)
        return exited and len(raw) <= 1 << 20 and expected_code.encode("ascii") in raw

    def upload(url, actor):
        body = (f'--{_BOUNDARY}\r\nContent-Disposition: form-data; name="client_id"\r\n\r\nresearcher-{actor}\r\n'
                f'--{_BOUNDARY}\r\nContent-Disposition: form-data; name="file"; filename="unsigned.fastq"\r\n'
                'Content-Type: application/octet-stream\r\n\r\n').encode() + _PAYLOAD + f'\r\n--{_BOUNDARY}--\r\n'.encode()
        code, raw = request(url + "/upload", actor, body)
        try:
            value = json.loads(raw)
            job = value.get("job_id", "")
        except (ValueError, AttributeError):
            job = ""
        if code != 200 or not isinstance(job, str) or not re.fullmatch(r"[0-9a-f]{8,64}", job):
            raise AdmissionCheckError("admission_check_upload_not_admitted")
        return job

    def quota_denied(url, actor):
        # A malformed body must still be rejected by quota before parsing. This
        # is process evidence of ordering, not a transport-level unread-body proof.
        code, raw = request(url + "/upload", actor, b"malformed-body")
        try:
            value = json.loads(raw)
        except ValueError:
            value = {}
        return code, code == 429 and isinstance(value, dict) and value.get("code") == "quota_exceeded"

    def terminal(results_url, actor, job, data):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            code, raw = request(results_url + "/results/" + job, actor)
            try:
                value = json.loads(raw)
            except ValueError:
                value = {}
            if code == 200 and isinstance(value, dict) and value.get("status") == "rejected":
                try:
                    stored = json.loads((data / "jobs" / (job + ".json")).read_bytes())
                except (OSError, ValueError):
                    stored = {}
                if stored.get("status") == "rejected":
                    return (value.get("data", {}).get("error_code") == "signature_required"
                            and stored.get("error_code") == "signature_required"
                            and stored.get("size_bytes") == len(_PAYLOAD)
                            and stored.get("sha256") == hashlib.sha256(_PAYLOAD).hexdigest()
                            and not (data / "artifacts" / job).exists())
            if code != 200:
                return False
            time.sleep(0.05)
        return False

    completed = False
    try:
        retained = fresh("retained")
        uploader, upload_url = start("upload-api", retained)
        ready(uploader, upload_url)
        api, results_url = start("results-api", retained)
        ready(api, results_url)
        worker, _ = start("enclave-runner", retained)
        job_a = upload(upload_url, "a")
        emit("admission_principal_a_first_upload_admitted", True, {"http_status": 200, "payload_bytes": len(_PAYLOAD)})
        emit("admission_a_terminal_rejection_keeps_readable_result", terminal(results_url, "a", job_a, retained),
             {"actual_worker": True, "pipeline_not_called": not (retained / "artifacts" / job_a).exists()})
        code, _ = request(results_url + "/results/" + job_a, "b")
        emit("admission_nonowner_b_cannot_read_a", code == 403, {"http_status": code})
        before = _fingerprint_inputs(retained)
        code, denied = quota_denied(upload_url, "a")
        emit("admission_a_retained_quota_precedes_malformed_parse", denied and _fingerprint_inputs(retained) == before,
             {"http_status": code, "safe_error_code": "quota_exceeded" if denied else "unexpected", "inputs_unchanged": _fingerprint_inputs(retained) == before})
        job_b = upload(upload_url, "b")
        emit("admission_principal_b_has_independent_slot", job_b != job_a, {"http_status": 200, "retained_jobs": 2})
        emit("admission_b_terminal_rejection_keeps_readable_result", terminal(results_url, "b", job_b, retained),
             {"actual_worker": True, "pipeline_not_called": not (retained / "artifacts" / job_b).exists()})
        code, _ = request(results_url + "/results/" + job_b, "a")
        emit("admission_nonowner_a_cannot_read_b", code == 403, {"http_status": code})
        second, _ = start("upload-api", retained)
        exited = startup_failed(second, "admission_instance_already_running")
        health, _ = request(upload_url + "/health")
        emit("admission_second_uploader_excluded", exited and health == 200,
             {"second_instance_exited": exited, "first_health_http_status": health})
        before = _fingerprint_inputs(retained)
        stop(uploader)
        uploader, upload_url = start("upload-api", retained)
        ready(uploader, upload_url)
        code, denied = quota_denied(upload_url, "a")
        unchanged = _fingerprint_inputs(retained) == before
        emit("admission_restart_preserves_terminal_retained_charge", denied and unchanged,
             {"http_status": code, "retained_jobs": 2, "inputs_unchanged": unchanged})
        readable = terminal(results_url, "a", job_a, retained)
        emit("admission_restart_preserves_original_result_access", readable,
             {"original_rejection_readable": readable})
        stop(worker)
        stop(api)
        stop(uploader)

        global_data = fresh("global")
        global_policy = {"BIOZERO_ADMISSION_GLOBAL_JOBS": "1", "BIOZERO_ADMISSION_ACTIVE_UPLOADS": "1"}
        global_uploader, global_url = start("upload-api", global_data, global_policy)
        ready(global_uploader, global_url)
        upload(global_url, "a")
        emit("admission_global_first_upload_admitted", True, {"http_status": 200, "global_job_cap": 1})
        before = _fingerprint_inputs(global_data)
        code, denied = quota_denied(global_url, "b")
        emit("admission_global_cap_denies_other_principal", denied and _fingerprint_inputs(global_data) == before,
             {"http_status": code, "safe_error_code": "quota_exceeded" if denied else "unexpected", "inputs_unchanged": _fingerprint_inputs(global_data) == before})
        stop(global_uploader)

        # Snapshot only the helper's own stopped data; source policy is unchanged.
        for cause in ("missing", "corrupt"):
            child = private / ("ledger-" + cause)
            child.mkdir(mode=0o700)
            cloned = child / "data"
            shutil.copytree(global_data, cloned, symlinks=True)
            cloned.chmod(0o700)
            ledger = cloned / "admission/ledger.json"
            if not ledger.is_file() or ledger.is_symlink():
                raise AdmissionCheckError("admission_check_ledger_missing_from_snapshot")
            if cause == "missing":
                ledger.unlink()
            else:
                ledger.unlink()
                _write_private(ledger, b'{"schema_version":')
            # This snapshot was created with global cap one, including its ledger
            # policy; maintain that exact policy for negative startup.
            before = _fingerprint_inputs(cloned)
            bad, _ = start("upload-api", cloned, global_policy)
            expected = "admission_existing_data_requires_ledger" if cause == "missing" else "admission_state_invalid"
            failed = startup_failed(bad, expected)
            baseline_created = cause == "missing" and ledger.exists()
            emit("admission_" + cause + "_ledger_startup_failclosed", failed and _fingerprint_inputs(cloned) == before and not baseline_created,
                 {"startup_failed": failed, "retained_inputs_unchanged": _fingerprint_inputs(cloned) == before,
                  "empty_baseline_created": baseline_created})
        completed = True
    finally:
        # Only process sessions created above; never scan or signal other runs.
        cleanup_ok = True
        for proc in reversed(processes):
            try:
                stop(proc)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_ok = False
            if proc.poll() is None:
                cleanup_ok = False
        for log in logs:
            log.close()
        if completed:
            emit("admission_created_processes_stopped", cleanup_ok, {"created_processes_stopped": cleanup_ok})
        elif not cleanup_ok:
            raise AdmissionCheckError("admission_check_cleanup_failed")
    return {"schema_version": 1,
            "scope": "real native HTTPS retained-input admission; no pipeline, model or full-disk quota",
            "case_count": len(observations), "cases": observations,
            "body_limit_bytes": 1024, "global_job_cap": 2, "principal_job_cap": 1,
            "principal_names_ids_paths_and_raw_responses_public": False}
