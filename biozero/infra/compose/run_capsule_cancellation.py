#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Opt-in protected Docker active cancellation with a pinned lifecycle fixture.

Local operator V2 Cancel, not a public/client cancellation API. No scientific
accuracy claim, image build/pull, model, Submit retry or history reset.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import time

import capsule_fault_proxy as codec
import run_capsule_worker as fixture


MARKER = "cancellation-ready.json"
INSPECT_FORMAT = '{"id":{{json .Id}},"image":{{json .Image}},"state":{{json .State}},"labels":{{json .Config.Labels}}}'
CHECKPOINT_LIMIT = 1 << 20


def metadata(info):
    return {key: getattr(info, key) for key in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                                               "st_size", "st_mtime_ns", "st_ctime_ns")}


def read_private_checkpoint(path):
    """Read bounded regular metadata through anchored no-follow ancestors."""
    path = Path(path)
    if not path.is_absolute():
        raise fixture.Failure("cancel_checkpoint_path_invalid")
    opened = []
    try:
        parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        opened.append(parent)
        for name in path.parts[1:-1]:
            parent = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            opened.append(parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        opened.append(fd)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid()
                or before.st_nlink != 1 or not 0 < before.st_size <= CHECKPOINT_LIMIT):
            raise fixture.Failure("cancel_checkpoint_file_unsafe")
        raw = bytearray()
        while True:
            chunk = os.read(fd, min(65536, CHECKPOINT_LIMIT + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > CHECKPOINT_LIMIT:
                raise fixture.Failure("cancel_checkpoint_oversized")
        after = os.fstat(fd)
        if metadata(before) != metadata(after) or len(raw) != before.st_size:
            raise fixture.Failure("cancel_checkpoint_changed_during_read")
        return bytes(raw), metadata(after)
    finally:
        for fd in reversed(opened):
            os.close(fd)


def save_active_checkpoint(ctx, validated):
    paths = {"store_ledger": ctx.host / "store/ledger.json", "broker_journal": ctx.host / "journal/journal.json",
             "worker_custody": ctx.data / "worker-custody/journal.json"}
    directory = ctx.run / "before-cancel"
    directory.mkdir(mode=0o700)
    control, report = {}, {"schema_version": 1, "files": {}, "directory_synced": False}
    for key, path in paths.items():
        raw, source_metadata = read_private_checkpoint(path)
        if codec._json(raw) != validated[key]:
            raise fixture.Failure("cancel_checkpoint_differs_from_validated_state")
        copy = directory / (key + ".json")
        fd = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        copied, copy_metadata = read_private_checkpoint(copy)
        if copied != raw or codec._json(copied) != validated[key]:
            raise fixture.Failure("cancel_checkpoint_copy_mismatch")
        control[key] = {"path": path, "raw": raw, "metadata": source_metadata}
        report["files"][key] = {"copy": "before-cancel/" + copy.name, "sha256": hashlib.sha256(raw).hexdigest(),
                                 "bytes": len(raw), "source_metadata": source_metadata, "copy_metadata": copy_metadata,
                                 "matches_validated_state": True, "file_synced": True}
    for path in (directory, ctx.run):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    report["directory_synced"] = True
    return control, report


def verify_active_checkpoint(control):
    for expected in control.values():
        raw, current_metadata = read_private_checkpoint(expected["path"])
        if raw != expected["raw"] or current_metadata != expected["metadata"]:
            raise fixture.Failure("cancel_checkpoint_changed_before_send")


def assets_factory(runtime):
    destination = runtime / "lifecycle-assets"
    destination.mkdir(mode=0o700)
    sources = {"pipeline": Path(__file__).parent / "fixtures/cancellation_pipeline.py",
               "resource_budget": fixture.ROOT / "biozero/bio/pipeline/resource_budget.py"}
    paths = {"pipeline": destination / "pipeline.py", "resource_budget": destination / "resource_budget.py"}
    for key, source in sources.items():
        with paths[key].open("xb") as out:
            out.write(source.read_bytes())
            out.flush()
            os.fsync(out.fileno())
        paths[key].chmod(0o600)
    return paths


def read_marker(pid):
    """Traverse the exact inspected PID; only its kernel root link is followed."""
    opened = []
    try:
        proc = os.open("/proc", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        opened.append(proc)
        process = os.open(str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=proc)
        opened.append(process)
        if os.fstat(process).st_uid != 1000:
            raise fixture.Failure("cancel_marker_process_unsafe")
        root = os.open("root", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=process)
        opened.append(root)
        work = os.open("workspace", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        opened.append(work)
        fd = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=work)
        opened.append(fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 1000
                or info.st_nlink != 1 or not 0 <= info.st_size <= 1024):
            raise fixture.Failure("cancel_marker_unsafe")
        if info.st_size == 0:
            return None
        raw = os.read(fd, 1025)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_size", "st_uid", "st_mode", "st_nlink", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != info.st_size or any(getattr(info, key) != getattr(after, key) for key in fields):
            raise fixture.Failure("cancel_marker_changed")
        return codec._json(raw)
    finally:
        for fd in reversed(opened):
            os.close(fd)


def live_actor(ctx, row):
    result = ctx.command(fixture.DOCKER + ["inspect", "--format", INSPECT_FORMAT, row["id"]], "cancel-live-capsule", timeout=5)
    value = json.loads(result.stdout)
    labels, state = value.get("labels", {}), value.get("state", {})
    if (value.get("id") != row["id"] or value.get("image") != fixture.IMAGE
            or any(labels.get("biozero.artifact." + key) != row[key] for key in ("store", "lease", "nonce"))
            or state.get("Status") != "running" or state.get("Running") is not True or type(state.get("Pid")) is not int or state["Pid"] <= 0):
        raise fixture.Failure("cancel_live_capsule_identity_invalid")
    return value


def active_marker(ctx, client):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        events = ctx.observer.snapshot()
        if events["error_code"]:
            raise fixture.Failure(events["error_code"])
        if len(events["actors"]) > 1:
            raise fixture.Failure("cancel_multiple_capsules")
        if len(events["actors"]) == 1:
            row = next(iter(events["actors"].values()))
            if row["actions"][:2] == ["create", "start"]:
                before = live_actor(ctx, row)
                try:
                    marker = read_marker(before["state"]["Pid"])
                except FileNotFoundError:
                    marker = None
                after = live_actor(ctx, row)
                if before["state"]["Pid"] != after["state"]["Pid"]:
                    raise fixture.Failure("cancel_capsule_pid_changed")
                if marker is not None:
                    ctx.record("actual_pinned_lifecycle_input_read_and_active_marker", marker.get("schema_version") == 1
                               and marker.get("phase") == "waiting_for_cancellation" and type(marker.get("pid")) is int and marker["pid"] > 1
                               and marker.get("input_sha256") == fixture.digest(fixture.FIXTURE / "reads.fastq")
                               and marker.get("input_bytes") == (fixture.FIXTURE / "reads.fastq").stat().st_size
                               and marker.get("status", {}).get("NoNewPrivs") == "1"
                               and all(marker.get("status", {}).get(key) == "0000000000000000" for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
                               and client.poll() is None)
                    ctx.report["active_capsule_before_cancel"] = {"identity": row, "before": before, "after": after, "marker": marker}
                    return row, marker
        if client.poll() is not None or ctx.get_broker().poll() is not None:
            raise fixture.Failure("cancel_fixture_exited_before_marker")
        time.sleep(0.1)
    raise fixture.Failure("cancel_active_marker_timeout")


def send_cancel(ctx, job, upload_sha256, checkpoint):
    query = {"schema_version": 2, "operation": "cancel", "job_id": job, "upload_sha256": upload_sha256,
             "expected_profile_sha256": ctx.profile, "processed_sha256": "", "processed_bytes": 0, "original_name": "",
             "analysis_context": {"original_name": "", "processed_size_bytes": 0, "decrypted": False,
                                  "decryption_error": "", "signature_valid": False, "signature_error": ""}}
    directory = codec._directory(Path(ctx.config["socket_path"]).parent)
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    state = {"request_sent": False, "response": None, "upstream_eof": False, "transport_error": None}
    try:
        name = Path(ctx.config["socket_path"]).name
        before = codec._socket_info(directory, name)
        channel.settimeout(5)
        channel.connect(f"/proc/self/fd/{directory}/{name}")
        codec._peer(channel)
        if before != codec._socket_info(directory, name):
            raise fixture.Failure("cancel_broker_socket_changed")
        verify_active_checkpoint(checkpoint)
        state["checkpoint_revalidated_before_send"] = True
        codec.write_frame(channel, json.dumps(query, separators=(",", ":")).encode("ascii"))
        state["request_sent"] = True
        # Keep the request open. EOF is read only from the real broker response.
        raw, fd = codec.read_frame(channel)
        if fd is not None:
            os.close(fd)
            raise fixture.Failure("cancel_unexpected_fd")
        state["response"] = codec._json(raw)
        codec.read_end(channel)
        state["upstream_eof"] = True
    except (OSError, codec.ProxyFailure) as exc:
        state["transport_error"] = type(exc).__name__
        if not state["request_sent"]:
            raise fixture.Failure("cancel_request_not_sent") from None
    finally:
        channel.close()
        os.close(directory)
    return state


def cancellation_scenario(ctx):
    ctx.report["scope"] = "protected Docker active cancellation of pinned lifecycle fixture; local operator Cancel, no scientific validation or public cancellation API claim"
    log = (ctx.run / "cancel-uploader.log").open("xb")
    client = None
    try:
        client = subprocess.Popen([str(x) for x in ctx.upload_argv(fixture.FIXTURE / "reads.fastq")], cwd=fixture.ROOT,
                                  env=ctx.env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        actor, marker = active_marker(ctx, client)
        store = ctx.host / "store"
        ledger = json.loads((store / "ledger.json").read_bytes())
        lease = actor["lease"]
        record = ledger["records"][lease]
        job = record["job_id"]
        journal = json.loads((ctx.host / "journal/journal.json").read_bytes())
        custody = json.loads((ctx.data / "worker-custody/journal.json").read_bytes())
        binding = journal["records"][job]
        ctx.record("submit_open_executing_full_reservation_before_cancel", len(ledger["records"]) == 1 and record["state"] == "executing"
                   and record["charge"] == ledger["policy"]["export_bytes"] + ledger["policy"]["publication_headroom"]
                   and record["manifest_sha256"] == record["proof_sha256"] == "" and binding["stage"] == "linked"
                   and binding["lease_id"] == lease and binding["processed_sha256"] == custody["records"][job]["processed_sha256"] == marker["input_sha256"]
                   and binding["upload_sha256"] == record["input_sha256"] == custody["records"][job]["upload_sha256"]
                   and custody["records"][job]["analysis_context"]["signature_valid"] is True
                   and custody["records"][job]["analysis_context"]["decrypted"] is True
                   and not (ctx.data / "results" / (job + ".json")).exists() and client.poll() is None)
        checkpoint, checkpoint_report = save_active_checkpoint(ctx, {"store_ledger": ledger, "broker_journal": journal, "worker_custody": custody})
        ctx.report["before_cancel_checkpoint"] = checkpoint_report
        ctx.record("durable_original_checkpoint_matches_executing_state", checkpoint_report["directory_synced"]
                   and all(value["matches_validated_state"] and value["file_synced"] for value in checkpoint_report["files"].values()))
        custody_before = checkpoint_report["files"]["worker_custody"]["sha256"]
        cancel_started = time.monotonic()
        cancel = send_cancel(ctx, job, binding["upload_sha256"], checkpoint)
        ctx.report["cancel_rpc"] = cancel
        response = cancel["response"]
        acknowledged = (isinstance(response, dict) and cancel["upstream_eof"] and response.get("schema_version") == 2
                        and response.get("job_id") == job and response.get("upload_sha256") == binding["upload_sha256"]
                        and response.get("profile_sha256") == ctx.profile and response.get("store_id") == ledger["store_id"]
                        and response.get("lease_id") == lease and response.get("cancel_requested") is True and response.get("error_code") == "")
        ctx.report["cancel_acknowledged"] = acknowledged
        ctx.record("real_cancel_sent_with_submit_still_open", cancel["request_sent"] is True and cancel.get("checkpoint_revalidated_before_send") is True)
        payload = ctx.await_result(job)
        elapsed = time.monotonic() - cancel_started
        code = client.wait(timeout=120)
        fixture.write_private(ctx.run / "cancellation-result.json", payload)
        result = payload.get("data", {})
        execution = result.get("artifact_execution", {})
        ctx.record("cancelled_result_failed_withheld_without_science", code == 3 and elapsed < 30 and payload.get("status") == "failed"
                   and result.get("release_status") == "withheld" and result.get("error_code") == "artifact_cancelled"
                   and result.get("scientific_evaluation") is None and result.get("pipeline_output") is None
                   and result.get("detection", {}).get("reason") == "detection_unavailable"
                   and result.get("signature_valid") is True and result.get("decrypted") is True)
        ctx.report["cancel_to_terminal_seconds"] = elapsed
        objects = store / "objects" / lease
        manifest_raw, proof_raw = [(objects / name).read_bytes() for name in ("manifest.json", "proof.json")]
        manifest, proof = [json.loads(raw) for raw in (manifest_raw, proof_raw)]
        after = json.loads((store / "ledger.json").read_bytes())
        committed = after["records"][lease]
        current_journal = json.loads((ctx.host / "journal/journal.json").read_bytes())
        identity = {"store_id": ledger["store_id"], "lease_id": lease, "job_id": job, "input_sha256": record["input_sha256"]}
        ctx.record("cancel_commit_has_zero_exports_and_postwait_proof", set(p.name for p in objects.iterdir()) == {"manifest.json", "proof.json"}
                   and manifest.get("files") == execution.get("files") == committed["files"] == {}
                   and manifest.get("execution_status") == "failed" and manifest.get("release_status") == "withheld" and manifest.get("error_code") == "artifact_cancelled"
                   and manifest.get("observed_sha256") == manifest.get("evaluated_sha256") == ""
                   and all(manifest.get(key) == proof.get(key) == value for key, value in identity.items())
                   and manifest.get("policy_sha256") == proof.get("policy_sha256") == journal["policy_sha256"]
                   and fixture.digest(objects / "manifest.json") == proof.get("manifest_sha256") == committed["manifest_sha256"] == execution.get("manifest_sha256")
                   and fixture.digest(objects / "proof.json") == committed["proof_sha256"]
                   and proof.get("capsule_wait_finished") is True and proof.get("export_authority_closed") is True
                   and execution.get("lease_id") == lease and execution.get("store_id") == ledger["store_id"]
                   and execution.get("receipt_sha256") == "" and execution.get("receipt_bytes") == 0
                   and current_journal["records"][job]["stage"] == committed["state"] == "committed")
        accounting, _, matches = fixture.retained_accounting(store)
        ctx.report["retained_accounting"] = accounting
        ctx.record("cancel_retains_slot_and_exact_metadata_charge", matches and len(after["records"]) == 1 and committed["charge"] > 0
                   and custody_before == fixture.digest(ctx.data / "worker-custody/journal.json"))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            events = ctx.observer.snapshot()
            if events["error_code"]:
                raise fixture.Failure(events["error_code"])
            if len(events["actors"]) == 1 and next(iter(events["actors"].values()))["actions"] == ["create", "start", "die", "destroy"]:
                break
            time.sleep(0.05)
        ctx.report["capsule_observation"] = events
        final = next(iter(events["actors"].values())) if len(events["actors"]) == 1 else {}
        ctx.record("one_capsule_cancelled_without_retry_and_control_history_clean", len(events["actors"]) == 1 and final.get("id") == actor["id"]
                   and final.get("lease") == lease and final.get("actions") == ["create", "start", "die", "destroy"]
                   and final.get("exit_code") in {"1", "137"} and fixture.docker_snapshot_matches(final, ctx.config)
                   and not any(Path(ctx.config["workspace_root"]).iterdir()))
        denied, _ = fixture.request(ctx.results_base + "/results/" + job, ctx.client_b, headers={"X-Client-Id": "researcher-a"})
        ctx.record("nonowner_denied_cancelled_result", denied == 403)
    finally:
        if client is not None:
            if client.poll() is None:
                os.killpg(client.pid, signal.SIGTERM)
                try:
                    client.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(client.pid, signal.SIGKILL)
                    client.wait(timeout=5)
            ctx.report["cancellation_uploader_returncode"] = client.returncode
        log.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--binaries-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    fixture.main(["--run-dir", str(args.run_dir), "--binaries-dir", str(args.binaries_dir), "--capsule-provider", "docker"],
                 scenario=cancellation_scenario, assets_factory=assets_factory)


if __name__ == "__main__":
    main()
