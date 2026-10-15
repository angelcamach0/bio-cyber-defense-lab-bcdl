# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic tests; authored only while the biological measurement is active.

Namespace tests are opt-in, MUST run only after that measurement ends, and require
host uid1000/native unshare support. They cannot replace Go keeper/lifecycle tests.
No model, real biological records, network requests or Docker are used.
"""
import array
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("native_capsule", Path(__file__).with_name("native_capsule.py"))
capsule = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capsule)


def digest(data):
    return hashlib.sha256(data).hexdigest()


# Popen close_fds may run AFTER preexec_fn. Remapping there to new numbers can
# discard fd3/fd4, since pass_fds protects only the original numbers. This fixed
# launcher remaps after the first exec and closes originals before the next one.
FD_LAUNCHER = '''import os, sys
source_channel, source_input = int(sys.argv[1]), int(sys.argv[2])
saved_channel, saved_input = os.dup(source_channel), os.dup(source_input)
os.dup2(saved_channel, 3, inheritable=True)
os.dup2(saved_input, 4, inheritable=True)
# dup2(fd, fd) can preserve CLOEXEC even with inheritable=True. os.dup may
# return3/4 when both were free; explicitly clear CLOEXEC in that case too.
os.set_inheritable(3, True)
os.set_inheritable(4, True)
for fd in {source_channel, source_input, saved_channel, saved_input} - {3, 4}:
    os.close(fd)
command = sys.argv[3:]
os.execv(command[0], command)
'''


def config_fixture(root="/fixture"):
    return {"schema_version": 1, "workspace": root + "/work", "input_bytes": 8,
            "input_sha256": "a" * 64, "mode": "stats", "pipeline_path": root + "/assets/pipeline.py",
            "pipeline_sha256": "b" * 64, "resource_budget_sha256": "c" * 64,
            "reference_path": "", "reference_sha256": "", "evaluator_path": "",
            "evaluator_sha256": "", "truth_path": "", "truth_sha256": "",
            "python_path": "/usr/bin/python3.9", "tool_path": "/usr/bin", "timeout_seconds": 10}


def outcome_fixture():
    return {"execution_status": "succeeded", "release_status": "unassessed", "error_code": "",
            "observed_sha256": "", "evaluated_sha256": ""}


def analysis_fixture(root="/fixture", size=8):
    return {"executable_path": root + "/analysis/capsule-analysis", "executable_sha256": "1" * 64,
            "rules_path": root + "/analysis/rules.json", "rules_sha256": "2" * 64,
            "panel_path": "", "panel_sha256": "",
            "context": {"original_name": "private-synthetic.fastq", "processed_size_bytes": size,
                        "decrypted": True, "decryption_error": "", "signature_valid": True, "signature_error": ""}}


def analysis_capture_fixture(panel=False):
    signals = {"warnings": {"critical": 0, "warn": 0, "info": 0},
               "integrity": {"signature_valid": True, "decrypted": True},
               "pipeline": {"read_count": 3, "avg_read_length": 10}}
    if panel:
        signals["alignment"] = {"mapped_reads": 1, "total_reads": 3, "fraction": 1 / 3,
                                "targets": {"private-synthetic-target": 1}}
    payload = {"schema_version": 1, "status": "succeeded", "error_code": "", "warnings": [],
               "detection": {"score": .1, "reason": "no suspicious indicators", "verdict": "low", "signals": signals}}
    return {"returncode": 0, "payload": payload, "raw_stdout": json.dumps(payload), "raw_stderr": ""}


def receive_frame(channel):
    raw, ancillary, flags, _ = channel.recvmsg(capsule.FRAME_LIMIT + 4,
                                              socket.CMSG_SPACE(4 * array.array("i").itemsize))
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise AssertionError("truncated frame/rights")
    descriptors = []
    for level, kind, data in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            raise AssertionError("unexpected ancillary message")
        rights = array.array("i")
        rights.frombytes(data)
        descriptors.extend(rights)
    while len(raw) < 4:
        chunk = channel.recv(4 - len(raw))
        if not chunk:
            raise AssertionError("early channel close")
        raw += chunk
    length = struct.unpack("!I", raw[:4])[0]
    if length > capsule.FRAME_LIMIT:
        raise AssertionError("oversized frame")
    while len(raw) < length + 4:
        chunk = channel.recv(length + 4 - len(raw))
        if not chunk:
            raise AssertionError("early channel close")
        raw += chunk
    if len(raw) != length + 4:
        raise AssertionError("trailing frame bytes")
    return json.loads(raw[4:]), descriptors


class NativeCapsuleUnitTests(unittest.TestCase):
    def test_strict_config_and_optional_science_pair(self):
        self.assertEqual(capsule.validate_config(config_fixture()), config_fixture())
        variants = config_fixture()
        variants.update(mode="variants", reference_path="/ref/ref.fa", reference_sha256="d" * 64)
        capsule.validate_config(variants)  # Deliberately unassessed without evaluator.
        for key, value in (("schema_version", True), ("input_bytes", True),
                           ("input_bytes", capsule.INPUT_LIMIT + 1), ("timeout_seconds", 601),
                           ("input_sha256", "A" * 64), ("tool_path", "/usr/bin:"),
                           ("workspace", "/proc/job"), ("pipeline_path", "/fixture/work/tool.py"),
                           ("tool_path", "/fixture"), ("mode", "shell")):
            value_config = config_fixture()
            value_config[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(capsule.CapsuleError):
                capsule.validate_config(value_config)
        for modification in ({"evaluator_path": "/eval.py", "evaluator_sha256": "f" * 64},
                             {"reference_sha256": "f" * 64}, {"unexpected": "value"}):
            invalid = config_fixture()
            invalid.update(modification)
            with self.assertRaises(capsule.CapsuleError):
                capsule.validate_config(invalid)
        missing = config_fixture()
        missing.pop("resource_budget_sha256")
        with self.assertRaises(capsule.CapsuleError):
            capsule.validate_config(missing)

    def test_duplicate_nan_overflow_and_deep_json_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}',
                    b"[" * 66 + b"0" + b"]" * 66):
            with self.subTest(raw=raw[:30]), self.assertRaises(capsule.CapsuleError):
                capsule.parse_json(raw)

    def test_input_exact_hash_length_and_source_unchanged(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "source"
            original = b"\x1f\x8bsynthetic compressed bytes"
            source.write_bytes(original)
            fd = os.open(source, os.O_RDONLY)
            try:
                actual = capsule.copy_exact(fd, Path(root) / "copy", len(original),
                                            len(original), digest(original))
                self.assertEqual(actual, (digest(original), len(original)))
                for name, count, sha in (("too-short", len(original) - 1, digest(original)),
                                         ("too-long", len(original) + 1, digest(original)),
                                         ("wrong-digest", len(original), "0" * 64)):
                    with self.subTest(name=name), self.assertRaises(capsule.CapsuleError):
                        capsule.copy_exact(fd, Path(root) / name, len(original), count, sha)
                self.assertEqual(source.read_bytes(), original)
            finally:
                os.close(fd)

    def test_source_pins_include_resource_budget_and_no_changes(self):
        with tempfile.TemporaryDirectory() as root:
            assets = Path(root) / "assets"
            assets.mkdir()
            pipeline, budget = assets / "pipeline.py", assets / "resource_budget.py"
            pipeline.write_bytes(b"# synthetic pipeline\n")
            budget.write_bytes(b"# synthetic resource budget\n")
            config = config_fixture(root)
            config.update(python_path=os.path.realpath(sys.executable),
                          tool_path=os.path.realpath(os.path.dirname(sys.executable)),
                          pipeline_sha256=digest(pipeline.read_bytes()),
                          resource_budget_sha256=digest(budget.read_bytes()))
            pins = capsule.verify_sources(config)
            self.assertEqual(pins["resource_budget"]["sha256"], config["resource_budget_sha256"])
            budget.write_bytes(b"# mutated source\n")
            with self.assertRaises(capsule.CapsuleError) as caught:
                capsule.verify_sources(config)
            self.assertEqual(caught.exception.code, "capsule_source_pin_mismatch")

    def test_no_follow_regular_private_single_link_exports(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "export"
            path.write_bytes(b"private synthetic receipt")
            path.chmod(0o600)
            # Unit tests may run as host uid1000; helper sees its mapped uid0.
            actual_fstat = os.fstat
            class MappedStat:
                st_uid = 0
                def __init__(self, fd):
                    self.info = actual_fstat(fd)
                def __getattr__(self, name):
                    return getattr(self.info, name)
            # Test ownership independently through explicit failure first.
            if os.getuid() != 0:
                with self.assertRaises(capsule.CapsuleError):
                    capsule.export_file(str(path))
            with mock.patch.object(capsule.os, "fstat", side_effect=MappedStat):
                fd, metadata = capsule.export_file(str(path))
                try:
                    self.assertEqual(metadata["sha256"], digest(path.read_bytes()))
                    self.assertEqual(os.read(fd, 100), path.read_bytes())
                finally:
                    os.close(fd)
            # open_anchored tests avoid fabricating stat nanosecond attributes.
            fd = capsule.open_anchored(str(path))
            try:
                self.assertEqual(capsule.hash_fd(fd, 100), (digest(path.read_bytes()), path.stat().st_size))
            finally:
                os.close(fd)
            os.symlink(path, Path(root) / "link")
            with self.assertRaises(capsule.CapsuleError):
                capsule.open_anchored(str(Path(root) / "link"))
            os.symlink(root, Path(root) / "dir-link")
            with self.assertRaises(capsule.CapsuleError):
                capsule.open_anchored(str(Path(root) / "dir-link/export"))
            os.mkfifo(Path(root) / "fifo", 0o600)
            with self.assertRaises(capsule.CapsuleError):
                capsule.open_anchored(str(Path(root) / "fifo"))
            os.link(path, Path(root) / "second-name")
            with mock.patch.object(capsule.os, "fstat", side_effect=MappedStat), \
                    self.assertRaises(capsule.CapsuleError):
                capsule.export_file(str(path))
            (Path(root) / "second-name").unlink()
            path.chmod(0o644)
            with mock.patch.object(capsule.os, "fstat", side_effect=MappedStat), \
                    self.assertRaises(capsule.CapsuleError):
                capsule.export_file(str(path))

    def test_pipeline_exit_status_agreement_and_stats_unassessed(self):
        payload = {"schema_version": 1, "mode": "stats", "pipeline_status": "succeeded"}
        outcome = capsule.pipeline_outcome({"returncode": 0, "payload": payload}, "stats")
        self.assertEqual(outcome["release_status"], "unassessed")
        for status, code in (("succeeded", 1), ("failed", 0), ("incomplete", 0)):
            changed = dict(payload, pipeline_status=status)
            with self.assertRaises(capsule.CapsuleError):
                capsule.pipeline_outcome({"returncode": code, "payload": changed}, "stats")
        with self.assertRaises(capsule.CapsuleError):
            capsule.pipeline_outcome({"returncode": False, "payload": payload}, "stats")
        pending = dict(payload, pipeline_status="incomplete")
        self.assertEqual(capsule.pipeline_outcome({"returncode": 2, "payload": pending}, "stats")
                         ["release_status"], "withheld")

    def test_evaluator_pass_requires_positive_truth_and_consistent_metrics(self):
        passed = {"evaluation_status": "passed", "tp": 3, "fp": 0, "fn": 0,
                  "precision": 1.0, "recall": 1.0, "unexpected": [], "missing": []}
        self.assertTrue(capsule.evaluation_passed({"returncode": 0, "payload": passed}))
        for key, value in (("tp", 0), ("tp", True), ("fp", 1), ("fn", 1),
                           ("precision", True), ("precision", float("nan")),
                           ("recall", 0.5), ("unexpected", ["private-locus"])):
            changed = dict(passed)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(capsule.CapsuleError):
                capsule.evaluation_passed({"returncode": 0, "payload": changed})
        with self.assertRaises(capsule.CapsuleError):
            capsule.evaluation_passed({"returncode": 1, "payload": passed})
        self.assertFalse(capsule.evaluation_passed({"returncode": 1,
                                                   "payload": {"evaluation_status": "failed"}}))

    def test_fixed_environment_omits_credentials_and_keeps_shared_mode(self):
        with mock.patch.dict(os.environ, {"SECRET_CANARY": "never-export", "LD_PRELOAD": "/bad.so",
                                          "PYTHONPATH": "/bad", "BIOZERO_PIPELINE_GROUP_MODE": "owned"}):
            environment = capsule.fixed_environment(config_fixture(), "/fixture/work")
        self.assertNotIn("SECRET_CANARY", environment)
        self.assertNotIn("LD_PRELOAD", environment)
        self.assertNotIn("PYTHONPATH", environment)
        self.assertEqual(environment["BIOZERO_PIPELINE_GROUP_MODE"], "shared")
        self.assertEqual(environment["TMPDIR"], "/fixture/work")
        self.assertEqual(environment["BIOZERO_TOOL_STDOUT_BYTES"], str(64 << 10))

    def test_single_sendmsg_and_partial_stream_without_duplicate_rights(self):
        class PartialSocket:
            def __init__(self):
                self.data, self.calls, self.ancillary = bytearray(), 0, None
            def sendmsg(self, buffers, ancillary):
                self.calls += 1
                self.ancillary = ancillary
                self.data.extend(buffers[0][:7])
                return 7
            def send(self, data):
                count = min(11, len(data))
                self.data.extend(data[:count])
                return count
        channel = PartialSocket()
        capsule.send_frame(channel, outcome_fixture(), [("execution_receipt", 42,
                                                         {"sha256": "d" * 64, "bytes": 2})])
        self.assertEqual(channel.calls, 1)
        length = struct.unpack("!I", channel.data[:4])[0]
        self.assertEqual(length, len(channel.data) - 4)
        self.assertEqual(list(channel.ancillary[0][2]), [42])
        payload = json.loads(channel.data[4:])
        self.assertEqual(set(payload), {"schema_version", "outcome", "files"})
        self.assertEqual(set(payload["files"][0]), {"id", "sha256", "bytes"})
        self.assertNotIn("path", bytes(channel.data).decode())

    def test_partial_wire_failure_never_attempts_second_frame(self):
        channel = mock.MagicMock()
        channel.family, channel.type = socket.AF_UNIX, socket.SOCK_STREAM
        stdin = mock.Mock(buffer=io.BytesIO(capsule.json_bytes(config_fixture())))
        with mock.patch.object(capsule.os, "getpid", return_value=1), \
                mock.patch.object(capsule.os, "set_inheritable"), \
                mock.patch.object(capsule.socket, "socket", return_value=channel), \
                mock.patch.object(capsule.signal, "signal"), \
                mock.patch.object(capsule.signal, "setitimer"), \
                mock.patch.object(capsule.sys, "argv", ["native_capsule.py"]), \
                mock.patch.object(capsule.sys, "stdin", stdin), \
                mock.patch.object(capsule.sys, "stderr", io.StringIO()), \
                mock.patch.object(capsule.os, "umask"), \
                mock.patch.object(capsule, "execute", return_value=(outcome_fixture(), [])), \
                mock.patch.object(capsule, "send_frame", side_effect=OSError("private exception")) as send:
            self.assertEqual(capsule.main(), 1)
            self.assertEqual(send.call_count, 1)

    def test_capture_stdout_stderr_overflow_timeout_and_nonfinite(self):
        environment = {"PATH": os.path.dirname(sys.executable), "LANG": "C"}
        with tempfile.TemporaryDirectory() as root:
            for body, expected in (("import sys; sys.stdout.write('x'*1048577)", "capsule_capture_limit"),
                                   ("import sys; sys.stderr.write('x'*65537)", "capsule_capture_limit"),
                                   ("import time; time.sleep(2)", "capsule_timeout"),
                                   ("print('{\\\"x\\\":1e999}')", "capsule_json_invalid")):
                duration = 0.05 if "sleep" in body else 2
                with self.subTest(expected=expected), self.assertRaises(capsule.CapsuleError) as caught:
                    capsule.capture_command([sys.executable, "-I", "-B", "-S", "-c", body],
                                            environment, root, time.monotonic() + duration)
                self.assertEqual(caught.exception.code, expected)

    def test_drop_all_capabilities_and_require_actual_zero_observation(self):
        libc = mock.Mock()
        libc.prctl.return_value = 0
        libc.capset.return_value = 0
        state = {key: "0000000000000000" for key in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb")}
        state["NoNewPrivs"] = "1"
        with mock.patch.object(capsule.ctypes, "CDLL", return_value=libc), \
                mock.patch.object(capsule, "process_state", return_value=state):
            self.assertEqual(capsule.drop_capabilities(), state)
        self.assertEqual(libc.prctl.call_args_list[:64],
                         [mock.call(24, capability, 0, 0, 0) for capability in range(64)])
        self.assertEqual(libc.prctl.call_args_list[-1], mock.call(38, 1, 0, 0, 0))
        changed = dict(state, CapBnd="1")
        with mock.patch.object(capsule.ctypes, "CDLL", return_value=libc), \
                mock.patch.object(capsule, "process_state", return_value=changed), \
                self.assertRaises(capsule.CapsuleError):
            capsule.drop_capabilities()

    def test_rights_readonly_survive_sender_close_and_source_unchanged(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "private-path-canary"
            data = b"synthetic private bytes"
            path.write_bytes(data)
            fd = os.open(path, os.O_RDONLY)
            sender, receiver = socket.socketpair()
            received = []
            try:
                capsule.send_frame(sender, outcome_fixture(), [("execution_receipt", fd,
                                                                {"sha256": digest(data), "bytes": len(data)})])
                sender.close()
                os.close(fd)
                fd = -1
                payload, received = receive_frame(receiver)
                self.assertEqual(len(received), 1)
                self.assertEqual(os.read(received[0], len(data) + 1), data)
                with self.assertRaises(OSError):
                    os.write(received[0], b"alteration")
                self.assertEqual(path.read_bytes(), data)
                self.assertNotIn(root, json.dumps(payload))
            finally:
                if fd >= 0:
                    os.close(fd)
                for received_fd in received:
                    os.close(received_fd)
                sender.close()
                receiver.close()

    def test_post_exec_launcher_remaps_high_original_fds_and_closes_them(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "synthetic-input"
            path.write_bytes(b"synthetic input")
            sender, receiver = socket.socketpair()
            input_fd = os.open(path, os.O_RDONLY)
            # Force original FD numbers away from3/4: pass_fds must preserve
            # these through Popen, then the fixed launcher remaps and closes.
            channel_fd = capsule.fcntl.fcntl(sender.fileno(), capsule.fcntl.F_DUPFD_CLOEXEC, 20)
            source_fd = capsule.fcntl.fcntl(input_fd, capsule.fcntl.F_DUPFD_CLOEXEC, 20)
            probe = '''import fcntl,json,os,socket,stat,sys
closed=[]
for fd in map(int,sys.argv[1:]):
    try: os.fstat(fd)
    except OSError: closed.append(fd)
facts={'fd3_socket':stat.S_ISSOCK(os.fstat(3).st_mode),
       'fd4_readonly':fcntl.fcntl(4,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY,
       'original_fds_closed':closed,'input_bytes':len(os.read(4,100))}
channel=socket.socket(fileno=3)
channel.sendall(json.dumps(facts).encode('ascii'))
'''
            command = [sys.executable, "-I", "-B", "-S", "-c", FD_LAUNCHER,
                       str(channel_fd), str(source_fd), sys.executable, "-I", "-B", "-S", "-c",
                       probe, str(channel_fd), str(source_fd)]
            process = None
            try:
                process = subprocess.Popen(command, pass_fds=(channel_fd, source_fd),
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                sender.close()
                receiver.settimeout(5)
                facts = json.loads(receiver.recv(4096))
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0)
                self.assertEqual(stdout, b"")
                self.assertEqual(stderr, b"")
                self.assertEqual(facts, {"fd3_socket": True, "fd4_readonly": True,
                                         "original_fds_closed": [channel_fd, source_fd], "input_bytes": 15})
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
                if process is not None:
                    process.stdout.close()
                    process.stderr.close()
                for fd in (input_fd, channel_fd, source_fd):
                    os.close(fd)
                sender.close()
                receiver.close()

    def test_pid1_guard_before_mount_or_kill(self):
        with mock.patch.object(capsule.os, "getpid", return_value=999), \
                mock.patch.object(capsule, "mount") as mount, \
                mock.patch.object(capsule.os, "kill") as kill:
            with self.assertRaises(capsule.CapsuleError):
                capsule.prepare_mounts(config_fixture())
            with self.assertRaises(capsule.CapsuleError):
                capsule.stop_namespace_children()
            mount.assert_not_called()
            kill.assert_not_called()

    def test_output_directory_and_fixed_filenames_not_payload_authority(self):
        with tempfile.TemporaryDirectory() as root:
            config = config_fixture(root)
            work = Path(config["workspace"])
            work.mkdir()
            output = work / "biozero-run-fixture"
            output.mkdir()
            payload = {"output_dir": str(output), "outputs": {
                name: str(output / filename) for name, filename in capsule.EXPORT_NAMES[1:]}}
            self.assertEqual(capsule.pipeline_directory(config, payload), str(output))
            changed = copy.deepcopy(payload)
            changed["outputs"]["normalized_vcf"] = root + "/outside.vcf"
            with self.assertRaises(capsule.CapsuleError):
                capsule.pipeline_directory(config, changed)
            linked = work / "biozero-run-link"
            linked.symlink_to(output)
            changed = copy.deepcopy(payload)
            changed["output_dir"] = str(linked)
            with self.assertRaises(capsule.CapsuleError):
                capsule.pipeline_directory(config, changed)

    def _fake_execute(self, root, evaluation=None, pipeline_status="succeeded", mutate=False, analysis_result=None):
        work = Path(root) / "work"
        work.mkdir(mode=0o700)
        reference = Path(root) / "source-reference.fa"
        reference.write_bytes(b">synthetic\nACGT\n")
        config = config_fixture(root)
        config.update(mode="variants", reference_path=str(reference),
                      reference_sha256=digest(reference.read_bytes()),
                      evaluator_path=root + "/assets/evaluator.py", evaluator_sha256="e" * 64,
                      truth_path=root + "/truth.vcf", truth_sha256="f" * 64)
        if analysis_result is not None:
            config.update(schema_version=2, analysis=analysis_fixture(root))
        commands = []
        observed = work / "biozero-run-fixture" / "variants.vcf"
        def capture(command, environment, directory, deadline, **options):
            commands.append(command)
            if options:
                self.assertEqual(command, [config["analysis"]["executable_path"], "--rules", config["analysis"]["rules_path"],
                                            "--panel", "", "--content", str(work / "input.fastq")])
                self.assertEqual(options["stdout_limit"], 64 << 10)
                request = json.loads(options["stdin_bytes"])
                self.assertEqual(request["schema_version"], 1)
                self.assertEqual(request["context"], config["analysis"]["context"])
                self.assertEqual(request["pipeline"]["pipeline_status"], pipeline_status)
                if isinstance(analysis_result, BaseException):
                    raise analysis_result
                return analysis_result
            if "--observed" in command:
                self.assertEqual(command[command.index("--observed") + 1], str(observed))
                self.assertEqual(command[command.index("--reference") + 1], str(work / "reference.fa"))
                if mutate:
                    observed.write_bytes(b"mutated evaluated file")
                return evaluation
            output = observed.parent
            output.mkdir(mode=0o700)
            for _, filename in capsule.EXPORT_NAMES[1:]:
                (output / filename).write_bytes(b"synthetic VCF " + filename.encode())
            return {"returncode": {"succeeded": 0, "incomplete": 2, "failed": 1}[pipeline_status],
                    "payload": {"schema_version": 1, "mode": "variants", "pipeline_status": pipeline_status,
                                "output_dir": str(output), "outputs": {
                                    name: str(output / filename) for name, filename in capsule.EXPORT_NAMES[1:]}},
                    "raw_stdout": "private pipeline JSON", "raw_stderr": "private-stderr-canary"}
        real_fstat = os.fstat
        class MappedStat:
            st_uid = 0
            def __init__(self, fd):
                self.info = real_fstat(fd)
            def __getattr__(self, name):
                return getattr(self.info, name)
        input_checked = False
        def fstat(fd):
            nonlocal input_checked
            if fd == 4 and not input_checked:
                input_checked = True
                return mock.Mock(st_mode=stat.S_IFREG | 0o600)
            return MappedStat(fd)
        def copy(fd, destination, maximum, expected_bytes=None, expected_sha=None):
            Path(destination).write_bytes(b"synthetic copied source")
            return expected_sha, expected_bytes
        previous_umask = os.umask(0o077)
        try:
            with contextlib.ExitStack() as stack:
                for target, name, kwargs in (
                    (capsule, "verify_sources", {"return_value": {"pipeline": {"sha256": "b" * 64}}}),
                    (capsule, "prepare_mounts", {}), (capsule, "drop_capabilities", {"return_value": {"NoNewPrivs": "1"}}),
                    (capsule, "stop_namespace_children", {}), (capsule, "capture_command", {"side_effect": capture}),
                    (capsule, "copy_exact", {"side_effect": copy}),
                    (capsule.fcntl, "fcntl", {"return_value": os.O_RDONLY}),
                    (capsule.os, "fstat", {"side_effect": fstat}),
                    (capsule.os, "pread", {"return_value": b"@s"}),
                    (capsule.os, "chdir", {})):
                    stack.enter_context(mock.patch.object(target, name, **kwargs))
                outcome, files = capsule.execute(config, time.monotonic() + 10)
                return outcome, files, commands
        finally:
            os.umask(previous_umask)

    def test_fake_complete_variants_evaluator_exact_hash_and_private_receipt(self):
        evaluation = {"returncode": 0, "payload": {"evaluation_status": "passed", "tp": 3,
                      "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0, "unexpected": [], "missing": []},
                      "raw_stdout": "private evaluation JSON", "raw_stderr": "private canary"}
        with tempfile.TemporaryDirectory() as root:
            outcome, files, commands = self._fake_execute(root, evaluation=evaluation)
            try:
                self.assertEqual(outcome["release_status"], "evaluated_passed")
                self.assertEqual(outcome["observed_sha256"], outcome["evaluated_sha256"])
                self.assertEqual([name for name, _, _ in files], [name for name, _ in capsule.EXPORT_NAMES])
                self.assertEqual(files[1][2]["sha256"], outcome["observed_sha256"])
                self.assertEqual(len(commands), 2)
                receipt = json.loads(os.read(files[0][1], files[0][2]["bytes"]))
                self.assertEqual(receipt["schema_version"], 1)
                self.assertNotIn("analysis_capture", receipt)
                self.assertNotIn("analysis_context", receipt)
                self.assertEqual(receipt["evaluation"]["raw_stderr"], "private canary")
                self.assertEqual(receipt["input_sha256"], "a" * 64)
            finally:
                for _, fd, _ in files:
                    os.close(fd)

    def test_fake_incomplete_never_evaluates_or_releases_variants(self):
        with tempfile.TemporaryDirectory() as root:
            outcome, files, commands = self._fake_execute(root, pipeline_status="incomplete")
            try:
                self.assertEqual(outcome["execution_status"], "incomplete")
                self.assertEqual(outcome["release_status"], "withheld")
                self.assertEqual([name for name, _, _ in files], ["execution_receipt"])
                self.assertEqual(len(commands), 1)
            finally:
                for _, fd, _ in files:
                    os.close(fd)

    def test_fake_evaluator_mutation_of_observed_file_fails_before_exports(self):
        evaluation = {"returncode": 0, "payload": {"evaluation_status": "passed", "tp": 3,
                      "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0, "unexpected": [], "missing": []},
                      "raw_stdout": "private", "raw_stderr": ""}
        with tempfile.TemporaryDirectory() as root, self.assertRaises(capsule.CapsuleError) as caught:
            self._fake_execute(root, evaluation=evaluation, mutate=True)
        self.assertEqual(caught.exception.code, "capsule_observed_changed")


class NativeAnalysisUnitTests(unittest.TestCase):
    def _capture_unread_large_stdin(self, payload, exit_code):
        # Force less pipe capacity than the request before the helper writes.
        # The child deliberately emits a complete response without reading stdin.
        real_popen = subprocess.Popen
        def small_input_pipe(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            try:
                # Linux UAPI: F_LINUX_SPECIFIC_BASE(1024)+7. Python3.9 may
                # omit the named constant even though the kernel supports it.
                command = getattr(capsule.fcntl, "F_SETPIPE_SZ", 1031)
                actual = capsule.fcntl.fcntl(process.stdin.fileno(), command, 4096)
                self.assertLess(actual, 60000)
            except BaseException:
                process.kill()
                process.wait(timeout=1)
                for stream in (process.stdin, process.stdout, process.stderr): stream.close()
                raise
            return process
        body = "import sys;sys.stdout.write(%r);sys.stdout.flush();sys.exit(%d)" % (json.dumps(payload), exit_code)
        with tempfile.TemporaryDirectory() as root, mock.patch.object(capsule.subprocess, "Popen", side_effect=small_input_pipe):
            return capsule.capture_command([sys.executable, "-I", "-B", "-S", "-c", body],
                {"PATH": "/usr/bin", "LANG": "C"}, root, time.monotonic() + 2,
                stdin_bytes=b"s" * 60000, stdout_limit=64 << 10)

    def test_early_cli_failure_preserves_complete_response_after_stdin_epipe(self):
        payload = {"schema_version": 1, "status": "failed", "error_code": "rules_parse_error", "warnings": [], "detection": None}
        capture = self._capture_unread_large_stdin(payload, 1)
        self.assertEqual(set(capture), {"returncode", "payload", "raw_stdout", "raw_stderr"})
        self.assertEqual(capture["returncode"], 1)
        self.assertEqual(capture["payload"], payload)
        self.assertEqual(json.loads(capture["raw_stdout"]), payload)
        config = config_fixture(); config.update(schema_version=2, analysis=analysis_fixture())
        self.assertFalse(capsule.analysis_passed(capture, config))
        # The transport exception does not bypass strict validation of failures.
        malformed = copy.deepcopy(capture)
        malformed["payload"]["detection"] = {"invented": True}
        with self.assertRaises(capsule.CapsuleError): capsule.analysis_passed(malformed, config)

    def test_unread_stdin_never_accepts_success_or_exit_schema_disagreement(self):
        success = analysis_capture_fixture()["payload"]
        failed = {"schema_version": 1, "status": "failed", "error_code": "rules_parse_error", "warnings": [], "detection": None}
        alias = dict(failed, schema_version=True)
        for payload, exit_code in ((success, 0), (failed, 0), (alias, 1)):
            with self.subTest(status=payload["status"], exit=exit_code):
                with self.assertRaises(capsule.CapsuleError) as caught:
                    self._capture_unread_large_stdin(payload, exit_code)
                self.assertEqual(caught.exception.code, "capsule_analysis_stdin_failed")

    def test_v2_exact_fields_context_and_v1_no_analysis(self):
        valid = config_fixture()
        valid.update(schema_version=2, analysis=analysis_fixture())
        self.assertEqual(capsule.validate_config(valid), valid)
        mutations = [dict(valid, schema_version=1), config_fixture(), copy.deepcopy(valid)]
        mutations[1]["schema_version"] = 2
        mutations[2]["analysis"]["command"] = "forbidden"
        for key, value in (("processed_size_bytes", True), ("processed_size_bytes", 7),
                           ("signature_valid", 1), ("decryption_error", "private error"),
                           ("original_name", "é" * 2049), ("signature_error", "é" * 65)):
            wrong = copy.deepcopy(valid)
            wrong["analysis"]["context"][key] = value
            mutations.append(wrong)
        for key, value in (("panel_path", "/assets/panel.fa"), ("rules_sha256", "A" * 64),
                           ("executable_path", "/fixture/work/executable")):
            wrong = copy.deepcopy(valid)
            wrong["analysis"][key] = value
            mutations.append(wrong)
        for wrong in mutations:
            with self.assertRaises(capsule.CapsuleError):
                capsule.validate_config(wrong)

    def test_analysis_asset_pins_executable_metadata_and_mutation(self):
        with tempfile.TemporaryDirectory() as root:
            assets = Path(root) / "assets"
            analysis = Path(root) / "analysis"
            assets.mkdir(); analysis.mkdir()
            (assets / "pipeline.py").write_bytes(b"# pipeline\n")
            (assets / "resource_budget.py").write_bytes(b"# budget\n")
            exe, rules = analysis / "capsule-analysis", analysis / "rules.json"
            exe.write_bytes(b"#!/bin/sh\nexit 0\n"); exe.chmod(0o755)
            rules.write_bytes(b"{}")
            config = config_fixture(root)
            config.update(schema_version=2, analysis=analysis_fixture(root),
                          python_path=os.path.realpath(sys.executable), tool_path=os.path.realpath(os.path.dirname(sys.executable)),
                          pipeline_sha256=digest((assets / "pipeline.py").read_bytes()),
                          resource_budget_sha256=digest((assets / "resource_budget.py").read_bytes()))
            config["analysis"].update(executable_sha256=digest(exe.read_bytes()), rules_sha256=digest(rules.read_bytes()))
            pins = capsule.verify_sources(config)
            self.assertEqual(pins["analysis_executable"]["sha256"], digest(exe.read_bytes()))
            self.assertEqual(pins["analysis_rules"]["sha256"], digest(rules.read_bytes()))
            self.assertNotIn("analysis_panel", pins)
            for mode in (0o644, 0o775, 0o4755):
                exe.chmod(mode)
                with self.assertRaises(capsule.CapsuleError): capsule.verify_sources(config)
            exe.chmod(0o755)
            rules.write_bytes(b'{"mutated":true}')
            with self.assertRaises(capsule.CapsuleError) as caught: capsule.verify_sources(config)
            self.assertEqual(caught.exception.code, "capsule_source_pin_mismatch")

    def test_analysis_response_is_typed_context_bound_and_panel_required(self):
        config = config_fixture(); config.update(schema_version=2, analysis=analysis_fixture())
        good = analysis_capture_fixture()
        self.assertTrue(capsule.analysis_passed(good, config))
        for section, key, value in ((None, "score", True), ("integrity", "decrypted", 1),
                                     ("integrity", "signature_valid", False), ("pipeline", "read_count", True),
                                     ("warnings", "critical", True)):
            wrong = copy.deepcopy(good)
            target = wrong["payload"]["detection"] if section is None else wrong["payload"]["detection"]["signals"][section]
            target[key] = value
            with self.assertRaises(capsule.CapsuleError): capsule.analysis_passed(wrong, config)
        configured = copy.deepcopy(config)
        configured["analysis"].update(panel_path="/panel.fa", panel_sha256="3" * 64)
        with self.assertRaises(capsule.CapsuleError): capsule.analysis_passed(good, configured)
        self.assertTrue(capsule.analysis_passed(analysis_capture_fixture(panel=True), configured))
        bad_exit = copy.deepcopy(good); bad_exit["returncode"] = 1
        with self.assertRaises(capsule.CapsuleError): capsule.analysis_passed(bad_exit, config)

    def test_selector_stdin_and_stdout_share_deadline_without_pipe_deadlock(self):
        body = "import sys,json;sys.stdout.write(' '*20000);sys.stdout.flush();b=sys.stdin.buffer.read();print(json.dumps({'received':len(b)}))"
        with tempfile.TemporaryDirectory() as root:
            fd = os.open(Path(root) / "private-descriptor", os.O_RDWR | os.O_CREAT, 0o600)
            os.set_inheritable(fd, True)
            try:
                capture = capsule.capture_command([sys.executable, "-I", "-B", "-S", "-c", body],
                    {"PATH": "/usr/bin", "LANG": "C"}, root, time.monotonic() + 2,
                    stdin_bytes=b"s" * 60000, stdout_limit=64 << 10)
                self.assertEqual(capture["payload"], {"received": 60000})
                descriptor_body = "import os,json,sys;sys.stdin.buffer.read()\ntry:os.fstat(%d);present=True\nexcept OSError:present=False\nprint(json.dumps({'present':present}))" % fd
                capture = capsule.capture_command([sys.executable, "-I", "-B", "-S", "-c", descriptor_body],
                    {"PATH": "/usr/bin"}, root, time.monotonic() + 2, stdin_bytes=b"{}", stdout_limit=64 << 10)
                self.assertFalse(capture["payload"]["present"])
            finally:
                os.close(fd)

    def test_analysis_request_and_capture_fail_without_truncated_success(self):
        config = config_fixture(); config.update(schema_version=2, analysis=analysis_fixture())
        with mock.patch.object(capsule, "capture_command") as command:
            capture, error = capsule.run_analysis(config, {"payload": {"large": "x" * 65536}}, "/work/input", {}, "/work", time.monotonic() + 1)
            self.assertEqual(error, "capsule_analysis_request_limit")
            self.assertIsNone(capture["returncode"]); self.assertIsNone(capture["payload"])
            command.assert_not_called()
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(capsule.CapsuleError) as caught:
                capsule.capture_command([sys.executable, "-I", "-B", "-S", "-c", "import sys;sys.stdin.buffer.read();print('x'*65537)"],
                    {"PATH": "/usr/bin"}, root, time.monotonic() + 1, stdin_bytes=b"{}", stdout_limit=64 << 10)
            self.assertEqual(caught.exception.code, "capsule_capture_limit")

    def test_v2_private_receipt_failed_analysis_revokes_passed_science(self):
        evaluation = {"returncode": 0, "payload": {"evaluation_status": "passed", "tp": 3, "fp": 0, "fn": 0,
                      "precision": 1.0, "recall": 1.0, "unexpected": [], "missing": []}}
        failed = {"returncode": 1, "payload": {"schema_version": 1, "status": "failed", "error_code": "rules_parse_error", "warnings": [], "detection": None},
                  "raw_stdout": "private failed response", "raw_stderr": "private stderr"}
        for result, expected in ((analysis_capture_fixture(), "evaluated_passed"), (failed, "withheld"),
                                 (capsule.CapsuleError("capsule_capture_limit"), "withheld")):
            with tempfile.TemporaryDirectory() as root:
                outcome, files, commands = NativeCapsuleUnitTests._fake_execute(self, root, evaluation=evaluation, analysis_result=result)
                try:
                    receipt = json.loads(os.read(files[0][1], files[0][2]["bytes"]))
                    self.assertEqual(receipt["schema_version"], 2)
                    self.assertEqual(receipt["analysis_context"], analysis_fixture(root)["context"])
                    self.assertEqual(outcome["release_status"], expected)
                    self.assertEqual(len(commands), 3)
                    if expected == "withheld": self.assertEqual(outcome["execution_status"], "failed")
                    if result is failed: self.assertEqual(receipt["analysis_capture"], failed)
                    self.assertEqual(outcome["observed_sha256"], outcome["evaluated_sha256"])
                finally:
                    for _, fd, _ in files: os.close(fd)

    def test_failed_pipeline_still_analyzes_without_promotion(self):
        with tempfile.TemporaryDirectory() as root:
            outcome, files, commands = NativeCapsuleUnitTests._fake_execute(self, root, pipeline_status="failed", analysis_result=analysis_capture_fixture())
            try:
                receipt = json.loads(os.read(files[0][1], files[0][2]["bytes"]))
                self.assertEqual(outcome["execution_status"], "failed")
                self.assertEqual(outcome["release_status"], "withheld")
                self.assertEqual(len(commands), 2)
                self.assertEqual([name for name, _, _ in files], ["execution_receipt"])
                self.assertEqual(receipt["analysis_capture"]["returncode"], 0)
            finally:
                for _, fd, _ in files: os.close(fd)


@unittest.skipUnless(os.environ.get("BIOZERO_NATIVE_CAPSULE_ACCEPTANCE") == "1",
                     "PENDING: explicit native acceptance after biological100 terminal only")
class NativeNamespaceAcceptance(unittest.TestCase):
    """Opt-in actual helper boundary. Unavailable namespaces FAIL, not fallback.

    This uses unshare only to create the same four namespaces/map expected from
    Go. It does not certify the Go keeper's crash ordering or storage integration.
    """
    def _run(self, pipeline_body):
        self.assertEqual(os.getuid(), 1000, "acceptance requires host uid1000")
        unshare = shutil.which("unshare")
        self.assertIsNotNone(unshare)
        with tempfile.TemporaryDirectory(prefix="biozero-native-acceptance-") as root:
            assets = Path(root) / "assets"
            assets.mkdir(mode=0o700)
            work = Path(root) / "work"
            work.mkdir(mode=0o700)
            pipeline = assets / "pipeline.py"
            pipeline.write_text(pipeline_body)
            budget = assets / "resource_budget.py"
            budget.write_text("# pinned synthetic dependency\n")
            upload = Path(root) / "input.fastq"
            content = b"@synthetic\nACGT\n+\nIIII\n"
            upload.write_bytes(content)
            config = config_fixture(root)
            config.update(input_bytes=len(content), input_sha256=digest(content),
                          pipeline_sha256=digest(pipeline.read_bytes()),
                          resource_budget_sha256=digest(budget.read_bytes()),
                          python_path=os.path.realpath(sys.executable),
                          tool_path=os.path.realpath(os.path.dirname(sys.executable)),
                          timeout_seconds=20)
            sender, receiver = socket.socketpair()
            input_fd = os.open(upload, os.O_RDONLY)
            child_fd = sender.fileno()
            command = [config["python_path"], "-I", "-B", "-S", "-c", FD_LAUNCHER,
                       str(child_fd), str(input_fd), unshare, "--user", "--map-root-user",
                       "--mount", "--pid", "--fork", "--net", config["python_path"], "-I", "-B", "-S",
                       str(Path(__file__).with_name("native_capsule.py").resolve())]
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, pass_fds=(child_fd, input_fd),
                                       env={"PATH": "/usr/bin", "LANG": "C", "LC_ALL": "C"})
            sender.close()
            os.close(input_fd)
            receiver.settimeout(25)
            received = []
            try:
                process.stdin.write(capsule.json_bytes(config))
                process.stdin.close()
                try:
                    payload, received = receive_frame(receiver)
                except (AssertionError, OSError) as exc:
                    try:
                        code = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        code = process.wait(timeout=5)
                    stderr = process.stderr.read(capsule.STDERR_LIMIT + 1)
                    stable = stderr.decode("ascii", errors="replace").strip()
                    if not capsule.CODE.fullmatch(stable):
                        stable = "capsule_harness_start_failed"
                    # Stable diagnostics only: never echo an exception, command,
                    # source path, environment or unshare's arbitrary stderr.
                    raise AssertionError("capsule_harness_channel_failed: exit=%s code=%s "
                                         "stderr_bytes=%s stderr_sha256=%s" %
                                         (code, stable, len(stderr), digest(stderr))) from None
                self.assertEqual(process.wait(timeout=25),
                                 0 if payload["outcome"]["execution_status"] == "succeeded" else 1)
                self.assertEqual(process.stdout.read(), b"")
                retained = {}
                for metadata, fd in zip(payload["files"], received):
                    info = os.fstat(fd)
                    self.assertTrue(stat.S_ISREG(info.st_mode))
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                    self.assertEqual(info.st_nlink, 1)
                    data = os.read(fd, metadata["bytes"] + 1)
                    self.assertEqual(len(data), metadata["bytes"])
                    self.assertEqual(digest(data), metadata["sha256"])
                    retained[metadata["id"]] = data
                self.assertEqual(len(received), len(payload["files"]))
                self.assertEqual(upload.read_bytes(), content)
                evidence_root = os.environ.get("BIOZERO_NATIVE_CAPSULE_EVIDENCE_DIR")
                if evidence_root:
                    # Optional test evidence only; never forwarded to capsule.
                    # New directories/files avoid replacing previous failures.
                    evidence = Path(evidence_root) / self._testMethodName
                    evidence.mkdir(mode=0o700)
                    def preserve(name, data):
                        fd = os.open(evidence / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with os.fdopen(fd, "wb") as output:
                            output.write(data)
                    preserve("frame.json", capsule.json_bytes(payload))
                    for name, data in retained.items():
                        preserve(name + ".json", data)
                    metadata = {"schema_version": 1, "exit_code": process.returncode,
                                "helper_sha256": digest(Path(__file__).with_name("native_capsule.py").read_bytes()),
                                "test_sha256": digest(Path(__file__).read_bytes()),
                                "exports": payload["files"], "keeper_or_go_acceptance": False}
                    preserve("metadata.json", capsule.json_bytes(metadata))
                return payload, retained
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                for fd in received:
                    os.close(fd)
                receiver.close()
                process.stdout.close()
                process.stderr.close()

    def test_actual_caps_zero_fd_closure_and_stats_receipt_after_namespace_exit(self):
        body = '''import json, os
facts = {}
for line in open('/proc/self/status'):
    key, _, value = line.partition(':')
    if key in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb','NoNewPrivs'):
        facts[key] = value.strip()
facts['closed_fds'] = []
for fd in (3,4):
    try: os.fstat(fd)
    except OSError: facts['closed_fds'].append(fd)
print(json.dumps({'schema_version':1,'mode':'stats','pipeline_status':'succeeded','facts':facts}))
'''
        payload, retained = self._run(body)
        self.assertEqual(payload["outcome"]["release_status"], "unassessed")
        self.assertEqual(set(retained), {"execution_receipt"})
        receipt = json.loads(retained["execution_receipt"])
        facts = receipt["pipeline"]["payload"]["facts"]
        self.assertEqual(facts["closed_fds"], [3, 4])
        self.assertEqual(facts["NoNewPrivs"], "1")
        for key in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"):
            self.assertEqual(int(facts[key], 16), 0)

    def test_actual_many_file_aggregate_quota_fails_without_fsize_fallback(self):
        body = '''import json, os, errno
hit = False
try:
    for i in range(3):
        with open('aggregate-'+str(i), 'xb') as stream:
            for j in range(63): stream.write(b'x' * (1<<20))
except OSError as exc:
    hit = exc.errno == errno.ENOSPC
if not hit: raise RuntimeError('aggregate tmpfs boundary absent')
print(json.dumps({'schema_version':1,'mode':'stats','pipeline_status':'failed'}))
raise SystemExit(1)
'''
        payload, _ = self._run(body)
        self.assertEqual(payload["outcome"]["execution_status"], "failed")
        self.assertEqual(payload["outcome"]["release_status"], "withheld")
        self.assertEqual(payload["outcome"]["error_code"], "capsule_workspace_full")


if __name__ == "__main__":
    unittest.main()
