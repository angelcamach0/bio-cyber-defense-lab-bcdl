#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Opt-in broker SIGKILL and explicit own committed-socket recovery.

The worker response remains held during the operator procedure. This proves
same-profile committed recovery, not pending execution reconciliation or worker
query retries throughout an outage. No history or quota is reset or adopted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import time

from broker_socket_reconcile import CommittedSocketFixture
from capsule_fault_proxy import FixedBridgeProxy, _directory
import run_capsule_faults as faults
import run_capsule_worker as fixture


def private_bytes(path, limit):
    directory = _directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 1000 or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1 or not 0 <= before.st_size <= limit):
            raise fixture.Failure("broker_history_file_unsafe")
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
            raise fixture.Failure("broker_history_file_changed")
        return bytes(raw)
    finally:
        os.close(fd)


def exact_directory(path, expected):
    fd = _directory(path)
    try:
        if set(os.listdir(fd)) != set(expected):
            raise fixture.Failure("broker_history_unaccounted")
    finally:
        os.close(fd)


def committed_history(ctx, job, lease):
    """Complete one-job fixture guard; invoked again immediately before unlink."""
    store = ctx.host / "store"
    exact_directory(store, {"instance.lock", "ledger.json", "objects"})
    exact_directory(store / "objects", {lease})
    exact_directory(ctx.host / "journal", {"instance.lock", "journal.json"})
    exact_directory(ctx.data / "worker-custody", {"instance.lock", "journal.json"})
    exact_directory(Path(ctx.config["workspace_root"]), set())
    for value in ctx.config.values():
        if isinstance(value, dict) and set(value) == {"path", "sha256"} and value["path"]:
            source = Path(value["path"])
            info = source.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 1000 or info.st_nlink != 1
                    or info.st_mode & 0o022 or info.st_size > 16 << 20 or fixture.digest(source) != value["sha256"]):
                raise fixture.Failure("broker_profile_asset_changed")
    ledger = json.loads(private_bytes(store / "ledger.json", 1 << 20))
    journal = json.loads(private_bytes(ctx.host / "journal/journal.json", 1 << 20))
    custody = json.loads(private_bytes(ctx.data / "worker-custody/journal.json", 1 << 20))
    policy = {"global_bytes": 1 << 30, "jobs": 64, "export_bytes": 64 << 20,
              "publication_headroom": 128 << 10, "artifact_ids": sorted(fixture.ARTIFACTS)}
    if (ledger.get("schema_version") != 1 or journal.get("schema_version") != 2 or custody.get("schema_version") != 1
            or ledger.get("policy") != policy or set(ledger["records"]) != {lease}
            or set(journal["records"]) != {job} or set(journal["analysis_contexts"]) != {job}
            or set(custody["records"]) != {job}
            or journal["profile_sha256"] != ctx.profile or custody["profile_sha256"] != ctx.profile):
        raise fixture.Failure("broker_history_not_complete")
    stored, linked, local = ledger["records"][lease], journal["records"][job], custody["records"][job]
    if stored["state"] != linked["stage"] or stored["state"] != "committed" or linked["lease_id"] != lease:
        raise fixture.Failure("broker_history_not_committed")
    objects = store / "objects" / lease
    exact_directory(objects, fixture.ARTIFACTS | {"manifest.json", "proof.json"})
    raw = {name: private_bytes(objects / name, 16 << 20) for name in fixture.ARTIFACTS | {"manifest.json", "proof.json"}}
    manifest, proof, receipt = [json.loads(raw[name]) for name in ("manifest.json", "proof.json", "execution_receipt")]
    digest = lambda data: hashlib.sha256(data).hexdigest()
    policy_sha = digest(json.dumps(policy, separators=(",", ":")).encode("ascii"))
    identity = {"store_id": ledger["store_id"], "lease_id": lease, "job_id": job, "input_sha256": stored["input_sha256"]}
    if (manifest.get("schema_version") != 1 or proof.get("schema_version") != 1
            or any(manifest.get(key) != value or proof.get(key) != value for key, value in identity.items())
            or manifest.get("policy_sha256") != policy_sha or proof.get("policy_sha256") != policy_sha
            or journal.get("policy_sha256") != policy_sha or journal.get("store_id") != ledger["store_id"]
            or digest(raw["manifest.json"]) != proof["manifest_sha256"] or proof["manifest_sha256"] != stored["manifest_sha256"]
            or stored["manifest_sha256"] != linked["manifest_sha256"] or digest(raw["proof.json"]) != stored["proof_sha256"]
            or proof.get("capsule_wait_finished") is not True or proof.get("export_authority_closed") is not True
            or set(manifest["files"]) != fixture.ARTIFACTS or manifest["files"] != stored["files"]
            or manifest["execution_status"] != "succeeded" or manifest["release_status"] != "evaluated_passed" or manifest["error_code"] != ""):
        raise fixture.Failure("broker_history_proof_invalid")
    for name, metadata in manifest["files"].items():
        if metadata != {"state": "verified", "sha256": digest(raw[name]), "bytes": len(raw[name])}:
            raise fixture.Failure("broker_history_artifact_invalid")
    facts = journal["analysis_contexts"][job]
    if (receipt.get("schema_version") != 2 or receipt.get("capsule_kind") != "docker" or receipt.get("source_pins") != ctx.pins
            or receipt.get("analysis_context") != facts or local["analysis_context"] != facts
            or facts.get("signature_valid") is not True or facts.get("decrypted") is not True
            or linked["job_id"] != job or local["job_id"] != job
            or linked["upload_sha256"] != stored["input_sha256"] or local["upload_sha256"] != stored["input_sha256"]
            or receipt["input_sha256"] != linked["processed_sha256"] or receipt["input_sha256"] != local["processed_sha256"]
            or receipt["input_sha256"] != fixture.digest(fixture.FIXTURE / "reads.fastq")
            or receipt["input_bytes"] != linked["processed_bytes"] or receipt["input_bytes"] != local["processed_bytes"]
            or receipt["input_bytes"] != facts["processed_size_bytes"]
            or digest(raw["execution_receipt"]) != linked["receipt_sha256"] or len(raw["execution_receipt"]) != linked["receipt_bytes"]
            or any(receipt.get("outcome", {}).get(key) != manifest.get(key) for key in
                   ("execution_status", "release_status", "error_code", "observed_sha256", "evaluated_sha256"))
            or manifest["observed_sha256"] != manifest["evaluated_sha256"] or manifest["observed_sha256"] != digest(raw["normalized_vcf"])
            or not all(fixture.docker_receipt_checks(receipt, ctx.config).values())):
        raise fixture.Failure("broker_history_receipt_invalid")
    snapshot = faults.history_snapshot(ctx, job, lease)
    snapshot.update(all_committed=True, policy_sha256=policy_sha, workspace_empty=True)
    return snapshot


def broker_interruption(ctx, job, lease, before):
    original = ctx.get_broker()
    guard = lambda: committed_history(ctx, job, lease)
    pin = CommittedSocketFixture(original, ctx.config["socket_path"], ctx.config_path,
                                 ctx.binary_pins["artifact-broker"]["sha256"], ctx.profile, guard)
    ctx.report["broker_socket_operator"] = pin.receipt
    try:
        ctx.record("known_broker_socket_and_committed_history_pinned_while_alive", original.poll() is None
                   and ctx.proxy.snapshot()["held_response"] and pin.baseline["hashes"] == before["hashes"])
        started = time.monotonic()
        original.send_signal(signal.SIGKILL)
        killed = original.wait(timeout=5)
        ctx.record("broker_exact_owned_sigkill_wait_minus9", killed == -9)
        ctx.report.setdefault("expected_broker_exits", {})["initial"] = -9
        rejected = ctx.start_broker("stale-rejected")
        rejected_code = rejected.wait(timeout=10)
        rejected_log = private_bytes(ctx.run / "broker-stale-rejected.log", 65536)
        ctx.record("same_profile_restart_rejected_before_socket_reconciliation", rejected_code == 1
                   and rejected_log == b"artifact_service_start_failed\n" and guard() == pin.baseline
                   and not (ctx.data / "results" / (job + ".json")).exists() and ctx.proxy.snapshot()["held_response"])
        ctx.report["expected_broker_exits"]["stale-rejected"] = 1
        pin.retire(rejected, rejected_log)
        ctx.record("only_known_dead_socket_unlinked_and_directory_fsynced", pin.retired and pin.receipt["socket_unlinked"]
                   and pin.receipt["directory_fsynced"] and guard() == pin.baseline)
        replacement = ctx.start_broker("reconciled")
        deadline = time.monotonic() + 10
        while not Path(ctx.config["socket_path"]).is_socket():
            if replacement.poll() is not None or time.monotonic() >= deadline:
                raise fixture.Failure("broker_replacement_socket_not_ready")
            time.sleep(0.02)
        pin.verify_replacement(replacement)
        repeated_profile = ctx.command([ctx.bin_dir / "artifact-broker", "--config", ctx.config_path, "--print-profile"],
                                       "restarted-print-profile", timeout=10).stdout.strip()
        ctx.record("same_binary_config_profile_new_live_socket_and_history", pin.receipt["replacement_verified"]
                   and repeated_profile == ctx.profile and guard() == pin.baseline and replacement.poll() is None)
        ctx.report["broker_recovery_seconds"] = time.monotonic() - started
        ctx.proxy.release(drop=True)
    finally:
        pin.close()
        ctx.report["broker_socket_operator"] = pin.receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--binaries-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    fixture.main(["--run-dir", str(args.run_dir), "--binaries-dir", str(args.binaries_dir), "--capsule-provider", "docker"],
                 scenario=lambda ctx: faults.postcommit_scenario(ctx, "broker-sigkill-postcommit", after_commit=broker_interruption),
                 bridge_proxy_factory=lambda path, upstream, profile: FixedBridgeProxy(path, upstream, profile, mode="hold_submit_response"))


if __name__ == "__main__":
    main()
