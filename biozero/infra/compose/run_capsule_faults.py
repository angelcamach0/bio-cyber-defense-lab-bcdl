#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Opt-in protected Docker acceptance for two postcommit downstream faults.

Each invocation creates a new private fixture through run_capsule_worker. It
never modifies job/result metadata, retries Submit, builds/pulls images, resets
history or removes containers. Broker death and active cancellation are separate
unimplemented gates; this runner does not claim them.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

import run_capsule_worker as fixture
from capsule_fault_proxy import FixedBridgeProxy


SCENARIOS = ("downstream-response-loss", "worker-sigkill-postcommit")


class WorkerKernelPins:
    """Finite measurement references, never namespace entry or plaintext reads.

    Keep the old nsfs and tmpfs objects alive until both generations are observed
    simultaneously. Namespace inode and mount numbers can otherwise be reused.
    Only the kernel's fixed proc namespace/root links are followed intentionally.
    """

    def __init__(self, observation, executable_sha256):
        self.ns_fd = self.stage_fd = None
        self.closed = False
        pid = observation.get("worker_pid")
        expected_ns = observation.get("mount_namespace", "")
        if type(pid) is not int or pid <= 0 or not re.fullmatch(r"mnt:\[\d+\]", expected_ns):
            raise fixture.Failure("worker_pin_identity_invalid")
        ancestors = []
        try:
            proc = os.open("/proc", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            ancestors.append(proc)
            process = os.open(str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=proc)
            ancestors.append(process)
            if os.fstat(process).st_uid != os.getuid() or fixture.digest(Path(f"/proc/{pid}/exe")) != executable_sha256:
                raise fixture.Failure("worker_pin_process_changed")
            namespaces = os.open("ns", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=process)
            ancestors.append(namespaces)
            if os.readlink("mnt", dir_fd=namespaces) != expected_ns:
                raise fixture.Failure("worker_pin_namespace_changed")
            # O_NOFOLLOW here would pin/reject the proc symlink, not retain nsfs.
            self.ns_fd = os.open("mnt", os.O_RDONLY | os.O_CLOEXEC, dir_fd=namespaces)
            root = os.open("root", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=process)
            ancestors.append(root)
            data = os.open("data", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
            ancestors.append(data)
            self.stage_fd = os.open("decrypted", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=data)
            value = self.snapshot()
            if (value["namespace"]["inode"] != int(expected_ns[5:-1]) or value["namespace"]["name"] != expected_ns
                    or value["stage"]["dev"] != observation.get("stage_dev") or value["stage"]["inode"] != observation.get("stage_inode")
                    or value["stage"]["filesystem_id"] != observation.get("filesystem_id")
                    or os.readlink("mnt", dir_fd=namespaces) != expected_ns
                    or fixture.digest(Path(f"/proc/{pid}/exe")) != executable_sha256):
                raise fixture.Failure("worker_pin_observation_changed")
        except BaseException:
            self.close()
            raise
        finally:
            for fd in reversed(ancestors):
                os.close(fd)

    def snapshot(self):
        if self.closed or self.ns_fd is None or self.stage_fd is None:
            raise fixture.Failure("worker_pin_closed")
        ns, stage = os.fstat(self.ns_fd), os.fstat(self.stage_fd)
        # O_PATH may reject fstatvfs; this kernel FD reference retains the exact
        # directory without opening or reading any plaintext beneath it.
        filesystem = os.statvfs(f"/proc/self/fd/{self.stage_fd}")
        if (not stat.S_ISREG(ns.st_mode) or not stat.S_ISDIR(stage.st_mode) or stage.st_uid != os.getuid()
                or stat.S_IMODE(stage.st_mode) != 0o700
                or not fcntl.fcntl(self.stage_fd, fcntl.F_GETFL) & os.O_PATH
                or not all(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC for fd in (self.ns_fd, self.stage_fd))
                or filesystem.f_blocks * filesystem.f_frsize != 32 << 20 or filesystem.f_files != 4096 or filesystem.f_flag & 14 != 14):
            raise fixture.Failure("worker_pin_kernel_metadata_invalid")
        return {"namespace": {"dev": ns.st_dev, "inode": ns.st_ino, "name": os.readlink(f"/proc/self/fd/{self.ns_fd}")},
                "stage": {"dev": stage.st_dev, "inode": stage.st_ino, "filesystem_id": filesystem.f_fsid,
                          "capacity_bytes": filesystem.f_blocks * filesystem.f_frsize, "inode_units": filesystem.f_files},
                "cloexec": True, "closed": False}

    def close(self):
        failed = False
        for name in ("ns_fd", "stage_fd"):
            fd = getattr(self, name)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    failed = True
                setattr(self, name, None)
        self.closed = True
        if failed:
            raise fixture.Failure("worker_pin_close_failed")


def history_snapshot(ctx, job, lease):
    if not re.fullmatch("[0-9a-f]{16}", job) or not re.fullmatch("[0-9a-f]{32}", lease):
        raise fixture.Failure("fault_history_identity_invalid")
    store = ctx.host / "store"
    accounting, ledger, matches = fixture.retained_accounting(store)
    journal = json.loads((ctx.host / "journal/journal.json").read_bytes())
    custody = json.loads((ctx.data / "worker-custody/journal.json").read_bytes())
    if (not matches or set(ledger["records"]) != {lease} or set(journal["records"]) != {job}
            or set(custody["records"]) != {job} or ledger["records"][lease]["job_id"] != job
            or ledger["records"][lease]["state"] != "committed" or journal["records"][job]["stage"] != "committed"
            or journal["records"][job]["lease_id"] != lease or journal["profile_sha256"] != ctx.profile
            or custody["profile_sha256"] != ctx.profile):
        raise fixture.Failure("fault_history_not_one_committed_execution")
    objects = store / "objects" / lease
    expected = fixture.ARTIFACTS | {"manifest.json", "proof.json"}
    if {path.name for path in objects.iterdir()} != expected or {path.name for path in (store / "objects").iterdir()} != {lease}:
        raise fixture.Failure("fault_history_artifact_set_invalid")
    paths = {"store_ledger": store / "ledger.json", "broker_journal": ctx.host / "journal/journal.json",
             "worker_custody": ctx.data / "worker-custody/journal.json"}
    paths.update({"object_" + name: objects / name for name in sorted(expected)})
    for path in paths.values():
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or info.st_size > 16 << 20):
            raise fixture.Failure("fault_history_file_unsafe")
    return {"hashes": {key: fixture.digest(path) for key, path in paths.items()}, "accounting": accounting,
            "store_id": ledger["store_id"], "lease_id": lease, "job_id": job}


def assert_one_capsule(ctx, lease):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        evidence = ctx.observer.snapshot()
        if evidence["error_code"]:
            raise fixture.Failure(evidence["error_code"])
        actors = evidence["actors"]
        if len(actors) == 1 and next(iter(actors.values()))["actions"] == ["create", "start", "die", "destroy"]:
            break
        time.sleep(0.05)
    actors = evidence["actors"]
    ctx.report["capsule_observation"] = evidence
    ctx.record("one_real_docker_capsule_and_no_reexecution", ctx.observer.proc.poll() is None and len(actors) == 1
               and evidence["barrier"].get("id") == ctx.owned_ids["upload"]
               and next(iter(actors.values()))["lease"] == lease
               and next(iter(actors.values()))["actions"] == ["create", "start", "die", "destroy"])
    actor = next(iter(actors.values()))
    ctx.record("fault_capsule_live_image_mounts_and_limits", fixture.docker_snapshot_matches(actor, ctx.config))
    ctx.record("fault_capsule_die_destroy_and_quiescent_commit", actor.get("exit_code") == "0"
               and not any(Path(ctx.config["workspace_root"]).iterdir()))


def wait_for_drop(proxy):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        state = proxy.snapshot()
        if state.get("error_code") is not None:
            raise fixture.Failure("fault_proxy_failed")
        if state.get("dropped_submit_responses") == 1 and not state.get("held_response"):
            return state
        time.sleep(0.02)
    raise fixture.Failure("fault_submit_response_not_dropped")


def postcommit_scenario(ctx, scenario, *, after_commit=None):
    if ((scenario == "broker-sigkill-postcommit") != callable(after_commit)
            or scenario not in {*SCENARIOS, "broker-sigkill-postcommit"}):
        raise fixture.Failure("fault_scenario_invalid")
    ctx.report["fault_scenario"] = scenario
    ctx.report["scope"] = ("three-service protected Compose and real Docker capsule; " + scenario
                           + "; one signed encrypted synthetic execution with query-only recovery; "
                           + ("explicit committed-only broker socket recovery; no general pending reconciliation, "
                            if after_commit is not None else "no broker-death, ")
                           + "active-cancel, browser, biological model or full lifecycle-gate claim")
    if ctx.proxy is None or ctx.observer is None or ctx.config["provider"] != "docker":
        raise fixture.Failure("fault_fixture_configuration_invalid")
    log = (ctx.run / "fault-uploader.log").open("xb")
    client = None
    kernel_pins = []
    try:
        client = subprocess.Popen([str(value) for value in ctx.upload_argv(fixture.FIXTURE / "reads.fastq")], env=ctx.env,
                                  cwd=fixture.ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        if not ctx.proxy.barrier.wait(90):
            raise fixture.Failure("fault_postcommit_barrier_timeout")
        barrier = ctx.proxy.snapshot()
        fixture.write_private(ctx.run / "proxy-postcommit-barrier.json", barrier)
        sent, upstream = barrier.get("submit_request", {}), barrier.get("submit_response", {})
        job, lease = sent.get("job_id", ""), upstream.get("lease_id", "")
        expected_mode = "hold_submit_response" if scenario in {"worker-sigkill-postcommit", "broker-sigkill-postcommit"} else "drop_submit_response_once"
        ctx.record("real_submit_response_and_eof_before_fault", barrier.get("error_code") is None
                   and barrier.get("mode") == expected_mode and barrier.get("barrier_reached") is True
                   and barrier.get("upstream_submit_response_complete") is True and barrier.get("upstream_submit_eof") is True
                   and barrier.get("submit_requests") == 1 and upstream.get("state") == "committed"
                   and upstream.get("error_code") == "" and upstream.get("job_id") == job
                   and upstream.get("profile_sha256") == sent.get("expected_profile_sha256") == ctx.profile
                   and upstream.get("upload_sha256") == sent.get("upload_sha256")
                   and sent.get("processed_sha256") == fixture.digest(fixture.FIXTURE / "reads.fastq")
                   and sent.get("processed_bytes") == (fixture.FIXTURE / "reads.fastq").stat().st_size)
        before = history_snapshot(ctx, job, lease)
        ctx.report["fault_postcommit_history"] = before
        ctx.record("postcommit_store_and_custody_before_fault", before["store_id"] == upstream.get("store_id")
                   and before["hashes"]["object_manifest.json"] == upstream.get("manifest_sha256")
                   and before["hashes"]["object_execution_receipt"] == upstream.get("receipt_sha256"))

        if after_commit is not None:
            after_commit(ctx, job, lease, before)

        if scenario == "worker-sigkill-postcommit":
            previous = ctx.inspect("worker")
            worker_id = ctx.owned_ids["worker"]
            ctx.record("worker_alive_with_response_held_and_no_result", barrier.get("held_response") is True
                       and previous["id"] == worker_id and previous["state"]["Running"] is True
                       and not (ctx.data / "results" / (job + ".json")).exists() and client.poll() is None)
            valid_stage, staged = fixture.worker_plaintext_observation(previous, ctx.binary_pins["enclave-runner"]["sha256"])
            old_pin = WorkerKernelPins(staged, ctx.binary_pins["enclave-runner"]["sha256"])
            kernel_pins.append(old_pin)
            ctx.report["worker_kernel_identity_measurement"] = {
                "scope": "old/new namespace and plaintext tmpfs references held simultaneously; no setns, old plaintext reads or secure-erasure claim",
                "old_before_kill": old_pin.snapshot(), "fds_closed": False}
            ctx.record("verified_plaintext_still_staged_immediately_before_sigkill", valid_stage and staged["stage_empty"] is False
                       and staged["mount_namespace"] == ctx.stage_observation["mount_namespace"], staged)
            ctx.command(fixture.DOCKER + ["kill", "--signal", "KILL", worker_id], "kill-exact-worker-postcommit", timeout=10)
            waited = ctx.command(fixture.DOCKER + ["wait", worker_id], "wait-killed-worker", timeout=15).stdout.strip()
            stopped = ctx.inspect("worker")
            ctx.report["worker_sigkill"] = {"id": worker_id, "previous_pid": previous["state"]["Pid"],
                                          "wait_exit": waited, "stopped_state": stopped["state"]}
            ctx.record("worker_sigkill_causal_wait137", waited == "137" and stopped["id"] == worker_id
                       and stopped["state"]["Status"] == "exited" and stopped["state"]["ExitCode"] == 137
                       and stopped["state"]["Pid"] == 0 and stopped["state"]["Running"] is False)
            ctx.record("worker_death_preserves_committed_history", history_snapshot(ctx, job, lease) == before
                       and not (ctx.data / "results" / (job + ".json")).exists())
            ctx.proxy.release(drop=True)
            wait_for_drop(ctx.proxy)
            ctx.command(fixture.DOCKER + ["start", worker_id], "restart-exact-worker-after-sigkill", timeout=15)
            restarted = ctx.inspect("worker")
            ctx.record("same_worker_container_restarted", restarted["id"] == worker_id and restarted["state"]["Running"] is True
                       and restarted["state"]["Pid"] > 0 and restarted["state"]["StartedAt"] != previous["state"]["StartedAt"])
        else:
            wait_for_drop(ctx.proxy)

        payload = ctx.await_result(job)
        code = client.wait(timeout=120)
        log.flush()
        if (ctx.run / "fault-uploader.log").stat().st_size > 16 << 20:
            raise fixture.Failure("fault_uploader_log_oversized")
        uploaded_job = re.search(rb"uploaded job ([0-9a-f]{16})", (ctx.run / "fault-uploader.log").read_bytes())
        fixture.write_private(ctx.run / "fault-recovered-result.json", payload)
        result = payload.get("data", {})
        evaluation, binding = result.get("scientific_evaluation", {}), result.get("artifact_execution", {})
        ctx.record("protected_three_snp_science_recovers_after_fault", code == 0 and uploaded_job is not None
                   and uploaded_job.group(1).decode("ascii") == job and payload.get("status") == "succeeded"
                   and result.get("release_status") == "evaluated_passed" and evaluation.get("evaluation_status") == "passed"
                   and evaluation.get("tp") == 3 and evaluation.get("fp") == 0 and evaluation.get("fn") == 0
                   and evaluation.get("precision") == evaluation.get("recall") == 1)
        if scenario == "worker-sigkill-postcommit":
            valid_stage, stage = fixture.worker_plaintext_observation(ctx.inspect("worker"), ctx.binary_pins["enclave-runner"]["sha256"])
            new_pin = WorkerKernelPins(stage, ctx.binary_pins["enclave-runner"]["sha256"])
            kernel_pins.append(new_pin)
            old, new = old_pin.snapshot(), new_pin.snapshot()
            ctx.report["worker_kernel_identity_measurement"].update(old_after_restart=old, new_after_restart=new)
            ctx.record("restarted_worker_verified_new_empty_plaintext_tmpfs", valid_stage and stage["stage_empty"]
                       and (old["namespace"]["dev"], old["namespace"]["inode"]) != (new["namespace"]["dev"], new["namespace"]["inode"])
                       and old["stage"]["dev"] != new["stage"]["dev"]
                       and old["stage"]["filesystem_id"] != new["stage"]["filesystem_id"], stage)
        ctx.record("ciphertext_plaintext_and_same_committed_binding", result.get("signature_valid") is True and result.get("decrypted") is True
                   and result.get("upload_sha256") == sent["upload_sha256"] and result.get("processed_sha256") == sent["processed_sha256"]
                   and result.get("upload_sha256") != result.get("processed_sha256") and result.get("size_bytes") == sent["processed_bytes"]
                   and binding.get("store_id") == upstream["store_id"] and binding.get("lease_id") == lease
                   and binding.get("profile_sha256") == ctx.profile and binding.get("manifest_sha256") == upstream["manifest_sha256"]
                   and binding.get("receipt_sha256") == upstream["receipt_sha256"] and binding.get("receipt_bytes") == upstream["receipt_bytes"])
        ctx.docker_retained(job, payload, "fault_recovery")
        objects = ctx.host / "store/objects" / lease
        manifest = json.loads((objects / "manifest.json").read_bytes())
        ctx.record("science_observed_evaluated_retained_same_vcf", manifest.get("observed_sha256") == manifest.get("evaluated_sha256") == fixture.digest(objects / "normalized_vcf")
                   and fixture.snp_keys(objects / "normalized_vcf") == fixture.snp_keys(fixture.FIXTURE / "expected.vcf"))
        detection = result.get("detection", {})
        alignment = detection.get("signals", {}).get("alignment", {})
        ctx.record("actual_detection_recovers_1171_mapped_reads", detection.get("score") == 0.7 and detection.get("verdict") == "medium"
                   and "threat_panel_hit" in detection.get("reasons", []) and alignment.get("mapped_reads") == alignment.get("total_reads") == 1171
                   and alignment.get("fraction") == 1 and len(alignment.get("targets", {})) == 1)
        denied, _ = fixture.request(ctx.results_base + "/results/" + job, ctx.client_b, headers={"X-Client-Id": "researcher-a"})
        ctx.record("nonowner_denied_after_fault_recovery", denied == 403)
        recovered_history = history_snapshot(ctx, job, lease)
        ctx.report["fault_recovered_history"] = recovered_history
        ctx.report["retained_accounting"] = recovered_history["accounting"]
        ctx.record("same_artifacts_proof_and_exact_charge_after_recovery", before == recovered_history)
        state = ctx.proxy.snapshot()
        fixture.write_private(ctx.run / "proxy-after-recovery.json", state)
        ctx.record("one_submit_then_real_status_and_receipt_queries", state.get("error_code") is None and state.get("submit_requests") == 1
                   and state.get("dropped_submit_responses") == 1 and not state.get("held_response")
                   and state.get("query_requests", {}).get("status", 0) >= 1 and state.get("query_requests", {}).get("receipt", 0) >= 1
                   and state.get("query_requests", {}).get("cancel", 0) == 0)
        ctx.report["fault_proxy_required_final"] = {"submit_requests": 1, "dropped_submit_responses": 1,
                                                   "held_response": False, "mode": expected_mode}
        assert_one_capsule(ctx, lease)
    finally:
        try:
            if client is not None:
                if client.poll() is None:
                    os.killpg(client.pid, signal.SIGTERM)
                    try:
                        client.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(client.pid, signal.SIGKILL)
                        client.wait(timeout=5)
                ctx.report["fault_uploader_returncode"] = client.returncode
        finally:
            close_failed = False
            for pin in reversed(kernel_pins):
                try:
                    pin.close()
                except fixture.Failure:
                    close_failed = True
            if kernel_pins:
                ctx.report["worker_kernel_identity_measurement"].update(
                    fds_closed=all(pin.closed for pin in kernel_pins) and not close_failed,
                    measurement_references_created=2 * len(kernel_pins),
                    measurement_references_closed=2 * sum(pin.closed for pin in kernel_pins) if not close_failed else None)
            log.close()
            if close_failed:
                raise fixture.Failure("worker_pin_close_failed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path, help="New private root for exactly one fault scenario")
    parser.add_argument("--binaries-dir", required=True, type=Path, help="Existing verified ARM64 service binaries; never built here")
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    args = parser.parse_args(argv)
    mode = "hold_submit_response" if args.scenario == "worker-sigkill-postcommit" else "drop_submit_response_once"

    def proxy_factory(socket_path, upstream_path, profile):
        return FixedBridgeProxy(socket_path, upstream_path, profile, mode=mode)

    fixture.main(["--run-dir", str(args.run_dir), "--binaries-dir", str(args.binaries_dir), "--capsule-provider", "docker"],
                 scenario=lambda ctx: postcommit_scenario(ctx, args.scenario), bridge_proxy_factory=proxy_factory)


if __name__ == "__main__":
    main()
