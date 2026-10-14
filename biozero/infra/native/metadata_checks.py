# SPDX-License-Identifier: AGPL-3.0-only
"""Real native-process acceptance of corrupted metadata files, not host attacks.

Root owns the integration and live Go processes. This module only creates new
private fixtures, invokes bounded HTTPS/progress callbacks, and removes the exact
files it created. No pipeline, model, Docker or fake success result is executed.
"""
import copy
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time

JOB_LIMIT = 64 * 1024
RESULT_LIMIT = 16 * 1024 * 1024
_MARKER = "TM03_METADATA_PRIVATE_SENTINEL"
_ERROR_FIELDS = frozenset(("error", "code", "error_code", "message"))


class MetadataCheckError(Exception):
    """Fixed diagnostics suitable for an overall manifest; never raw responses."""


def _directory(path, *, private=False):
    path = Path(path).absolute()
    if path.resolve() != path:
        raise MetadataCheckError("metadata_check_directory_invalid")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise MetadataCheckError("metadata_check_directory_invalid")
    if private and stat.S_IMODE(info.st_mode) != 0o700:
        raise MetadataCheckError("metadata_check_directory_invalid")
    return path


def _json_bytes(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _safe_error(status, raw, forbidden):
    if status != 500 or not isinstance(raw, bytes) or len(raw) > 4096:
        return False
    if any(word in raw for word in forbidden):
        return False
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        return False
    return (isinstance(value, dict) and bool(value) and set(value).issubset(_ERROR_FIELDS)
            and any(field in value for field in ("error", "code", "error_code"))
            and all(isinstance(item, str) and len(item) <= 512 and "/" not in item
                    for item in value.values()))


def run_checks(*, data_dir, private_dir, job_template, result_template,
               request_as, verify_worker_progress, record):
    """Exercise Go readers with nine private faults while a real worker runs.

    ``job_template`` and ``result_template`` are dictionaries read by the parent
    from a legitimate retained owner-A job/result. Their schema, owner, signing
    and encryption fields remain private; original files are never changed.

    ``request_as(actor, path, timeout=2.0)`` returns ``(status, bytes)`` using the
    parent's verified HTTPS client for actor ``"a"`` or ``"b"``. Paths are
    relative API paths. Raw responses are retained only under ``private_dir``.

    ``verify_worker_progress(deadline=20.0)`` uploads a NEW actual unsigned job
    to the protected API, waits for its rejected result, and proves its pipeline
    was not called. Return ``{"terminal_rejected": bool, "pipeline_not_called":
    bool}``; a legacy bool may represent the conjunction of both verified facts.
    The callback must not simulate a worker response or delete these faults.

    ``record(name, passed, observed)`` accepts fixed names and safe metrics. A
    failed record may raise; this module still cleans up. Recovery reads the
    ORIGINAL real retained job after every fault is removed, without cloning its
    terminal result into the spool or creating additional synthetic outbox events.

    No live spool directory is renamed/replaced. Ancestor-symlink protection is
    covered by Go unit tests, not by moving the running service's directories.
    """
    data = _directory(data_dir, private=True)
    private = _directory(private_dir, private=True)
    jobs, results = _directory(data / "jobs", private=True), _directory(data / "results", private=True)
    if not isinstance(job_template, dict) or not isinstance(result_template, dict):
        raise MetadataCheckError("metadata_check_templates_invalid")
    owner = job_template.get("client_id")
    serial = job_template.get("client_cert_serial")
    if not isinstance(owner, str) or not owner or not isinstance(serial, str) or not serial:
        raise MetadataCheckError("metadata_check_owner_missing")
    if result_template.get("status") != "rejected" or result_template.get("security_mode") != "protected":
        raise MetadataCheckError("metadata_check_requires_actual_protected_rejection")
    original_job = job_template.get("job_id")
    if (not isinstance(original_job, str) or not re.fullmatch(r"[0-9a-f]{8,64}", original_job)
            or result_template.get("job_id") != original_job):
        raise MetadataCheckError("metadata_check_template_job_mismatch")
    work = Path(tempfile.mkdtemp(prefix="metadata-faults-", dir=private))
    work.chmod(0o700)
    created = {}
    used_ids = set()
    observations = []
    sequence = 0
    response_sequence = 0

    def emit(name, passed, observed):
        observations.append({"case": name, "passed": bool(passed), "observed": observed})
        record(name, bool(passed), observed)
        if not passed:
            raise MetadataCheckError("metadata_check_acceptance_failed")

    def identifier():
        nonlocal sequence
        # Low lexical IDs put the FIFO early in the worker's directory scan.
        # Both spools are checked; existing paths, including broken links, win.
        for _ in range(100000):
            candidate = f"{sequence:016x}"
            sequence += 1
            if candidate in used_ids:
                continue
            if os.path.lexists(jobs / (candidate + ".json")) or os.path.lexists(results / (candidate + ".json")):
                continue
            used_ids.add(candidate)
            return candidate
        raise MetadataCheckError("metadata_check_id_space_unavailable")

    def remember(path):
        info = path.lstat()
        created[path] = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))

    def regular(path, raw=None, sparse_size=None):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            remember(path)
            if sparse_size is not None:
                os.ftruncate(fd, sparse_size)
            if raw is not None:
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(fd)
        finally:
            os.close(fd)

    def fixture_job(job, uploaded=False):
        value = copy.deepcopy(job_template)
        value["job_id"] = job
        if uploaded:
            value["status"] = "uploaded"
            for field in ("started_at", "error_code", "error_message"):
                value.pop(field, None)
        return value

    def fixture_result(job):
        value = copy.deepcopy(result_template)
        value["job_id"] = job
        return value

    def fault(path, category, value):
        if category == "fifo":
            os.mkfifo(path, 0o600)
            remember(path)
        elif category == "outside_symlink":
            outside = work / (path.parent.name + "-outside-" + path.name)
            external = copy.deepcopy(value)
            external["error_message"] = _MARKER
            regular(outside, _json_bytes(external))
            path.symlink_to(outside)
            remember(path)
        elif category == "oversized":
            limit = JOB_LIMIT if path.parent == jobs else RESULT_LIMIT
            regular(path, sparse_size=limit + 1)
        elif category in ("duplicate_owner", "duplicate_status"):
            key = "client_id" if category == "duplicate_owner" else "status"
            raw = _json_bytes(value)
            # Duplicate a real retained value; no invented owner or success.
            duplicate = _json_bytes({key: value[key]})[1:-1]
            regular(path, raw[:-1] + b"," + duplicate + b"}")
        else:
            raise MetadataCheckError("metadata_check_fault_unknown")

    def request(actor, path, label):
        nonlocal response_sequence
        response_sequence += 1
        started = time.monotonic()
        try:
            status, raw = request_as(actor, path, timeout=2.0)
        except Exception:
            emit(label, False, {"bounded_request_returned": False})
            raise MetadataCheckError("metadata_check_request_failed") from None
        if not isinstance(status, int) or not isinstance(raw, bytes):
            raise MetadataCheckError("metadata_check_request_contract_invalid")
        # No identity, IDs, paths or raw body in returned/public observations.
        regular(work / f"response-{response_sequence:03d}.bin", raw)
        elapsed_ms = round((time.monotonic() - started) * 1000, 3)
        return status, raw, elapsed_ms

    def health(label):
        status, body, elapsed = request("a", "/health", label)
        emit(label, status == 200 and body == b"ok", {"http_status": status, "health_ok": body == b"ok", "elapsed_ms": elapsed})

    def cleanup_spool():
        removed, retained = 0, 0
        for path, expected in list(created.items()):
            if path.parent not in (jobs, results):
                continue  # Private diagnostics/sentinel are intentionally retained.
            try:
                info = path.lstat()
            except FileNotFoundError:
                retained += 1
                continue
            current = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
            if current != expected:
                retained += 1
                continue  # Never delete a file a service replaced.
            path.unlink()
            removed += 1
            del created[path]
        return removed, retained

    fault_jobs = []
    fault_results = []
    forbidden = (_MARKER.encode(), str(work).encode(), str(data).encode(), b"enc_key", b"pipeline_output", b"client_id")
    completed = False
    try:
        for category in ("fifo", "outside_symlink", "oversized", "duplicate_owner", "duplicate_status"):
            job = identifier()
            fault(jobs / (job + ".json"), category, fixture_job(job))
            fault_jobs.append((category, job))
        for category in ("fifo", "outside_symlink", "oversized", "duplicate_status"):
            job = identifier()
            # Result exists before its job becomes visible to the live worker.
            fault(results / (job + ".json"), category, fixture_result(job))
            regular(jobs / (job + ".json"), _json_bytes(fixture_job(job, uploaded=True)))
            fault_results.append((category, job))
        for category, job in fault_jobs:
            name = "metadata_job_" + category + "_safe_error"
            status, body, elapsed = request("a", "/results/" + job, name)
            emit(name, _safe_error(status, body, forbidden), {"http_status": status, "safe_error": _safe_error(status, body, forbidden), "elapsed_ms": elapsed})
            health("metadata_job_" + category + "_health")
        for category, job in fault_results:
            name = "metadata_result_" + category
            status, body, elapsed = request("b", "/results/" + job, name + "_owner_b_denied")
            emit(name + "_owner_b_denied", status == 403 and all(word not in body for word in forbidden),
                 {"http_status": status, "elapsed_ms": elapsed})
            status, body, elapsed = request("a", "/results/" + job, name + "_safe_error")
            emit(name + "_safe_error", _safe_error(status, body, forbidden),
                 {"http_status": status, "safe_error": _safe_error(status, body, forbidden), "elapsed_ms": elapsed})
            health(name + "_health")
        progress = verify_worker_progress(deadline=20.0)
        if isinstance(progress, dict):
            terminal_rejected = progress.get("terminal_rejected") is True
            pipeline_not_called = progress.get("pipeline_not_called") is True
        elif type(progress) is bool:
            terminal_rejected = pipeline_not_called = progress
        else:
            raise MetadataCheckError("metadata_check_progress_contract_invalid")
        emit("metadata_worker_progress_with_faults_present", terminal_rejected and pipeline_not_called,
             {"terminal_rejected": terminal_rejected, "pipeline_not_called": pipeline_not_called})
        removed, retained = cleanup_spool()
        emit("metadata_fault_files_removed_exactly", retained == 0 and removed == 13,
             {"crafted_spool_files_removed": removed, "unexpected_replacements": retained})
        # Read the untouched real job. No cloned terminal result that a live SOC
        # reconciler could mistake for a new worker-produced rejection event.
        status, raw, elapsed = request("a", "/results/" + original_job, "metadata_owner_a_recovers_after_faults")
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeError):
            payload = {}
        recovered = (status == 200 and payload.get("status") == result_template["status"]
                     and payload.get("data", {}).get("job_id") == original_job)
        emit("metadata_owner_a_recovers_after_faults", recovered, {"http_status": status, "retained_rejection_readable": recovered, "elapsed_ms": elapsed})
        status, _, elapsed = request("b", "/results/" + original_job, "metadata_owner_b_still_denied_after_recovery")
        emit("metadata_owner_b_still_denied_after_recovery", status == 403, {"http_status": status, "elapsed_ms": elapsed})
        health("metadata_recovery_health")
        completed = True
    finally:
        removed, retained = cleanup_spool()
        if retained:
            emit("metadata_final_cleanup", False, {"unexpected_replacements": retained})
        elif completed:
            emit("metadata_final_cleanup", removed == 0, {"additional_spool_files_removed": removed, "remaining_crafted_spool_files": 0})
    return {"schema_version": 1, "scope": "live native Go filename-corruption fixtures; no live spool-directory replacement",
            "fault_case_count": 9, "worker_progress_verified": True, "original_template_files_changed": False,
            "public_observations_contain_ids_paths_or_raw_bodies": False, "cases": observations}
