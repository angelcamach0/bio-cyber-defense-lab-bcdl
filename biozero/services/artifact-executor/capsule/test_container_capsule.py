# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic stdlib/Unix-IPC tests, never Docker/kernel acceptance or models.

Kernel predicates receive fabricated observations. Actual Docker mount/resource,
peerPID/keeper lifecycle and quota acceptance require the host provider separately.
The native module is imported unchanged; none of its guards are monkeypatched.
"""
import array
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest


def import_file(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


container = import_file("test_container_module", "container_capsule.py")
native = import_file("test_container_pinned_native", "native_capsule.py")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def execution_fixture():
    config = {"schema_version": 1, "input_bytes": 10, "input_sha256": "a" * 64, "mode": "variants",
              "pipeline_sha256": "b" * 64, "resource_budget_sha256": "c" * 64,
              "reference_sha256": "d" * 64, "evaluator_sha256": "e" * 64,
              "truth_sha256": "f" * 64, "timeout_seconds": 10}
    config.update(container.FIXED_PATHS)
    return config


def wrapper_fixture():
    return {"schema_version": 1, "native_helper_sha256": "a" * 64, "execution": execution_fixture()}


def kernel_fixture():
    return {"pid": 1, "uid": 1000, "euid": 1000, "gid": 1000, "egid": 1000,
            "CapInh": "0", "CapPrm": "0", "CapEff": "0", "CapBnd": "0", "CapAmb": "0",
            "NoNewPrivs": "1", "interfaces": ["lo"], "rlimit_fsize": [64 << 20, 64 << 20],
            "namespaces": {"pid": "pid:[12345]"},
            "root_statfs": {"flags": 1},
            "workspace_statfs": {"filesystem_magic": container.TMPFS_MAGIC, "capacity_bytes": 128 << 20,
                                  "inode_units": 4096, "free_inode_units": 4095, "flags": 0},
            "workspace_directory": {"uid": 1000, "gid": 1000, "mode": 0o700, "empty": True},
            "cgroup": {"membership": "0::/", "namespace": "cgroup:[12346]", "memory.max": "536870912",
                       "memory.swap.max": "0", "pids.max": "128", "cpu.max": "100000 100000"},
            "mounts": [{"mountpoint": "/", "filesystem": "overlay", "options": ["ro", "relatime"],
                        "super_options": ["rw"], "optional": []},
                       {"mountpoint": "/workspace", "filesystem": "tmpfs",
                        "options": ["rw", "nosuid", "nodev", "noexec"],
                        "super_options": ["rw", "size=131072k", "nr_inodes=4096"], "optional": []},
                       {"mountpoint": "/sys/fs/cgroup", "filesystem": "cgroup2", "options": ["ro"],
                        "super_options": ["rw"], "optional": []}]}


class ContainerCapsuleTests(unittest.TestCase):
    def test_strict_wrapper_rejects_alias_duplicate_nonfinite_and_oversize(self):
        raw = native.json_bytes(wrapper_fixture())
        self.assertEqual(container.bootstrap_json(raw), wrapper_fixture())
        for wrong in (dict(wrapper_fixture(), schema_version=True),
                      dict(wrapper_fixture(), native_helper_sha256="A" * 64),
                      dict(wrapper_fixture(), execution=[]), dict(wrapper_fixture(), command="arbitrary")):
            with self.assertRaises(container.ContainerError):
                container.bootstrap_json(native.json_bytes(wrong))
        for wrong in (b'{"schema_version":1,"schema_version":1}', b'{"x":NaN}', b'{"x":1e999}',
                      b"[" * 66 + b"0" + b"]" * 66, b" " * (container.CONFIG_LIMIT + 1)):
            with self.assertRaises(container.ContainerError):
                container.bootstrap_json(wrong)

    def test_native_spec_fixed_paths_and_optional_science_are_preserved(self):
        self.assertEqual(container.validate_execution(native, wrapper_fixture()), execution_fixture())
        for key, value in (("workspace", "/tmp/job"), ("pipeline_path", "/run/other.py"),
                           ("python_path", "/usr/bin/python3"), ("tool_path", "/usr/bin:/tmp"),
                           ("evaluator_path", "/run/other/evaluate.py")):
            wrapper = wrapper_fixture()
            wrapper["execution"][key] = value
            with self.subTest(key=key), self.assertRaises((container.ContainerError, native.CapsuleError)):
                container.validate_execution(native, wrapper)
        for name in ("evaluator", "truth"):
            wrapper = wrapper_fixture()
            wrapper["execution"][name + "_path"] = ""
            wrapper["execution"][name + "_sha256"] = ""
            with self.assertRaises(native.CapsuleError):
                container.validate_execution(native, wrapper)
        wrapper = wrapper_fixture()
        for name in ("evaluator", "truth"):
            wrapper["execution"][name + "_path"] = ""
            wrapper["execution"][name + "_sha256"] = ""
        container.validate_execution(native, wrapper)  # variants deliberately unassessed.
        wrapper["execution"]["mode"] = "stats"
        wrapper["execution"]["reference_path"] = wrapper["execution"]["reference_sha256"] = ""
        container.validate_execution(native, wrapper)

    def test_pinned_module_bytes_checked_before_code_and_source_unchanged(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "module.py"
            raw = b"raise RuntimeError('must never execute in byte verification')\n"
            path.write_bytes(raw)
            fd = os.open(path, os.O_RDONLY)
            try:
                self.assertEqual(container.read_pinned(fd, digest(raw)), raw)
            finally:
                os.close(fd)
            fd = os.open(path, os.O_RDONLY)
            try:
                with self.assertRaises(container.ContainerError) as caught:
                    container.read_pinned(fd, "0" * 64)
                self.assertEqual(caught.exception.code, "capsule_source_pin_mismatch")
            finally:
                os.close(fd)
            self.assertEqual(path.read_bytes(), raw)

    def test_mountinfo_parser_escaped_paths_and_covering_mount(self):
        raw = "1 0 0:1 / / ro,relatime - overlay overlay rw\n2 1 0:2 / /private\\040dir rw - tmpfs tmpfs rw,size=128m\n"
        mounts = container.parse_mountinfo(raw)
        self.assertEqual(container.covering_mount(mounts, "/private dir/child")["filesystem"], "tmpfs")
        self.assertEqual(container.covering_mount(mounts, "/private-other")["mountpoint"], "/")
        for bad in ("invalid", "1 0 0:1 / / ro - overlay\n", "x" * ((2 << 20) + 1)):
            with self.assertRaises(container.ContainerError):
                container.parse_mountinfo(bad)
        with self.assertRaises(container.ContainerError):
            container.covering_mount(mounts + [mounts[1]], "/private dir/child")

    def test_kernel_predicates_accept_only_the_exact_container_profile(self):
        state = kernel_fixture()
        self.assertEqual(container.validate_kernel(state, execution_fixture()), "pid:[12345]")
        for key, value in (("pid", 999), ("pid", True), ("uid", 0), ("euid", 0), ("gid", 0),
                           ("egid", 0), ("CapBnd", "1"), ("CapPrm", "1"), ("CapEff", "1"),
                           ("CapInh", "1"), ("CapAmb", "1"), ("NoNewPrivs", "0"),
                           ("interfaces", ["lo", "eth0"]), ("rlimit_fsize", [-1, -1]),
                           ("rlimit_fsize", [32 << 20, 64 << 20])):
            altered = copy.deepcopy(state)
            altered[key] = value
            with self.subTest(key=key), self.assertRaises(container.ContainerError):
                container.validate_kernel(altered, execution_fixture())

    def test_fsize_never_substitutes_for_aggregate_byte_or_inode_quota(self):
        for key, value in (("filesystem_magic", 0xEF53), ("capacity_bytes", 64 << 20),
                           ("capacity_bytes", (128 << 20) + 4096), ("inode_units", 4097), ("flags", 1)):
            altered = kernel_fixture()
            altered["workspace_statfs"][key] = value
            with self.subTest(key=key), self.assertRaises(container.ContainerError) as caught:
                container.validate_kernel(altered, execution_fixture())
            self.assertEqual(caught.exception.code, "capsule_workspace_quota_unavailable")
        altered = kernel_fixture()
        altered["mounts"][1]["filesystem"] = "ext4"
        with self.assertRaises(container.ContainerError):
            container.validate_kernel(altered, execution_fixture())
        # Free inode units differ from configured total units; do not assert4095
        # regular files or fake acceptance from a count alone.
        altered = kernel_fixture()
        altered["workspace_statfs"]["free_inode_units"] = 4094
        container.validate_kernel(altered, execution_fixture())

    def test_root_sources_workspace_permissions_and_propagation_fail_closed(self):
        for mutation in ("root_rw", "root_statfs_rw", "source_rw", "workspace_nonempty", "workspace_owner",
                         "workspace_mode", "workspace_exec", "workspace_shared", "namespace_missing"):
            state = kernel_fixture()
            if mutation == "root_rw": state["mounts"][0]["options"] = ["rw"]
            elif mutation == "root_statfs_rw": state["root_statfs"]["flags"] = 0
            elif mutation == "source_rw":
                state["mounts"].append({"mountpoint": "/run/biozero/pipeline", "filesystem": "ext4",
                                        "options": ["rw"], "super_options": ["rw"], "optional": []})
            elif mutation == "workspace_nonempty": state["workspace_directory"]["empty"] = False
            elif mutation == "workspace_owner": state["workspace_directory"]["uid"] = 0
            elif mutation == "workspace_mode": state["workspace_directory"]["mode"] = 0o755
            elif mutation == "workspace_exec": state["mounts"][1]["options"].remove("noexec")
            elif mutation == "workspace_shared": state["mounts"][1]["optional"] = ["shared:123"]
            else: state["namespaces"]["pid"] = ""
            with self.subTest(mutation=mutation), self.assertRaises(container.ContainerError):
                container.validate_kernel(state, execution_fixture())

    def test_actual_cgroup_values_not_hostconfig_claims_are_required(self):
        state = kernel_fixture()
        container.validate_cgroup(state["cgroup"], state["mounts"])
        for key, value in (("membership", "0::/host/docker"), ("memory.max", "max"),
                           ("memory.max", "1073741824"), ("memory.swap.max", "536870912"),
                           ("pids.max", "max"), ("pids.max", "129"), ("cpu.max", "max 100000"),
                           ("cpu.max", "200000 100000"), ("cpu.max", "0 0")):
            altered = copy.deepcopy(state)
            altered["cgroup"][key] = value
            with self.subTest(key=key), self.assertRaises(container.ContainerError):
                container.validate_kernel(altered, execution_fixture())
        altered = copy.deepcopy(state)
        altered["mounts"][2]["filesystem"] = "cgroup"
        with self.assertRaises(container.ContainerError):
            container.validate_kernel(altered, execution_fixture())
        altered = copy.deepcopy(state)
        altered["cgroup"]["cpu.max"] = "10000 10000"
        container.validate_kernel(altered, execution_fixture())  # one CPU, another valid period.

    def test_readonly_input_metadata_requires_uid_private_single_link_and_cloexec(self):
        valid = {"regular": True, "uid": 1000, "nlink": 1, "mode": 0o600,
                 "bytes": 10, "readonly": True, "cloexec": True}
        container.validate_input_metadata(valid, 10)
        for key, value in (("regular", False), ("regular", 1), ("uid", 0), ("nlink", 2), ("nlink", True),
                           ("mode", 0o644), ("bytes", 11), ("bytes", 10.0), ("readonly", False), ("cloexec", False)):
            invalid = dict(valid)
            invalid[key] = value
            with self.subTest(key=key), self.assertRaises(container.ContainerError):
                container.validate_input_metadata(invalid, 10)

    def test_control_peer_requires_exact_UID1000_without_namespace_PID_assumptions(self):
        # The host keeper may have pid0 as seen from the container PID namespace.
        # Host checks the connecting helper PID against Docker inspect separately.
        container.validate_peer_credentials(struct.pack("3i", 0, 1000, 1000))
        for raw in (struct.pack("3i", 123, 0, 0), b"short"):
            with self.assertRaises(container.ContainerError):
                container.validate_peer_credentials(raw)

    def test_exact_I_rights_handoff_cloexec_and_readonly_transport(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "input"
            data = b"synthetic input bytes"
            path.write_bytes(data)
            path.chmod(0o600)
            source = os.open(path, os.O_RDONLY)
            sender, receiver = socket.socketpair()
            received = -1
            try:
                sender.sendmsg([b"I"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [source]))])
                received = container.receive_input_descriptor(receiver)
                metadata = container.input_metadata(received)
                self.assertTrue(metadata["readonly"])
                self.assertTrue(metadata["cloexec"])
                self.assertEqual(os.read(received, 100), data)
                with self.assertRaises(OSError): os.write(received, b"changed")
                self.assertEqual(path.read_bytes(), data)
            finally:
                if received >= 0: os.close(received)
                os.close(source)
                sender.close()
                receiver.close()

    def test_input_transport_rejects_extra_bytes_rights_and_truncation(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "input"
            path.write_bytes(b"synthetic")
            source = os.open(path, os.O_RDONLY)
            try:
                for data, fd_count in ((b"X", 1), (b"II", 1), (b"I", 0), (b"I", 2), (b"I", 8)):
                    sender, receiver = socket.socketpair()
                    try:
                        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [source] * fd_count))] if fd_count else []
                        sender.sendmsg([data], ancillary)
                        with self.subTest(data=data, count=fd_count), self.assertRaises(container.ContainerError):
                            container.receive_input_descriptor(receiver)
                    finally:
                        sender.close()
                        receiver.close()
            finally:
                os.close(source)

    def test_input_hash_mismatch_prevents_tools_and_leaves_original_unchanged(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "source"
            raw = b"synthetic plaintext fixture"
            path.write_bytes(raw)
            source = os.open(path, os.O_RDONLY)
            try:
                with self.assertRaises(native.CapsuleError):
                    native.copy_exact(source, Path(root) / "copy", native.INPUT_LIMIT, len(raw), "0" * 64)
                self.assertEqual(path.read_bytes(), raw)
            finally:
                os.close(source)

    def test_keeper_monitor_eof_and_unexpected_data_request_exit_once(self):
        for data, expected in ((None, "capsule_keeper_closed"), (b"untrusted", "capsule_keeper_unexpected_data")):
            sender, receiver = socket.socketpair()
            event, reasons = threading.Event(), []
            def loss(reason): reasons.append(reason); event.set()
            monitor = container.KeeperMonitor(receiver, loss)
            monitor.start()
            try:
                if data is None: sender.close()
                else: sender.sendall(data)
                self.assertTrue(event.wait(2))
                monitor.thread.join(timeout=1)
                self.assertEqual(reasons, [expected])
            finally:
                monitor.stop()
                sender.close()
                receiver.close()

    def test_monitor_disarmed_before_normal_close_does_not_signal_loss(self):
        sender, receiver = socket.socketpair()
        reasons = []
        monitor = container.KeeperMonitor(receiver, reasons.append)
        monitor.start()
        monitor.stop()
        sender.close()
        receiver.close()
        self.assertFalse(monitor.thread.is_alive())
        self.assertEqual(reasons, [])

    def test_keeper_monitor_read_error_fails_closed_without_echoing_exception(self):
        sender, receiver = socket.socketpair()
        event, reasons = threading.Event(), []
        class FailingReceive:
            def fileno(self): return receiver.fileno()
            def recv(self, *args): raise PermissionError("private-exception-canary")
        def loss(reason): reasons.append(reason); event.set()
        monitor = container.KeeperMonitor(FailingReceive(), loss)
        monitor.start()
        try:
            sender.sendall(b"ready")
            self.assertTrue(event.wait(2))
            self.assertEqual(reasons, ["capsule_keeper_channel_error"])
        finally:
            monitor.stop()
            sender.close()
            receiver.close()

    def test_keeper_loss_unconditionally_exits_its_own_process_without_signal(self):
        path = str(Path(__file__).with_name("container_capsule.py").resolve())
        code = "import importlib.util,sys; s=importlib.util.spec_from_file_location('c',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.keeper_lost('already-validated-pidns','EOF'); print('continued')"
        result = subprocess.run([sys.executable, "-I", "-B", "-S", "-c", code, path],
                                capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def test_reused_capture_bounds_and_timeout(self):
        with tempfile.TemporaryDirectory() as root:
            for code, deadline, expected in (("import sys;sys.stdout.write('x'*1048577)", 2, "capsule_capture_limit"),
                                            ("import sys;sys.stderr.write('x'*65537)", 2, "capsule_capture_limit"),
                                            ("import time;time.sleep(2)", 0.05, "capsule_timeout")):
                with self.subTest(code=expected), self.assertRaises(native.CapsuleError) as caught:
                    native.capture_command([sys.executable, "-I", "-B", "-S", "-c", code],
                                           {"PATH": "/usr/bin", "LANG": "C"}, root, time.monotonic() + deadline)
                self.assertEqual(caught.exception.code, expected)

    def test_scientific_pass_requires_positive_TP_and_exact_exit_metric_agreement(self):
        report = {"returncode": 0, "payload": {"evaluation_status": "passed", "tp": 3, "fp": 0,
                  "fn": 0, "precision": 1.0, "recall": 1.0, "unexpected": [], "missing": []}}
        self.assertTrue(native.evaluation_passed(report))
        for key, value in (("tp", 0), ("tp", True), ("fp", 1), ("fn", 1), ("precision", True), ("recall", 0.5)):
            changed = copy.deepcopy(report)
            changed["payload"][key] = value
            with self.subTest(key=key), self.assertRaises(native.CapsuleError):
                native.evaluation_passed(changed)
        changed = copy.deepcopy(report)
        changed["returncode"] = 1
        with self.assertRaises(native.CapsuleError): native.evaluation_passed(changed)

    def test_failure_frame_has_no_source_paths_private_data_or_exports(self):
        sender, receiver = socket.socketpair()
        try:
            container.send_bootstrap_failure(sender, "capsule_source_pin_mismatch")
            raw = receiver.recv(4096)
            size = struct.unpack("!I", raw[:4])[0]
            self.assertEqual(size, len(raw) - 4)
            response = json.loads(raw[4:])
            self.assertEqual(set(response), {"schema_version", "outcome", "files"})
            self.assertEqual(response["files"], [])
            self.assertEqual(response["outcome"]["release_status"], "withheld")
            self.assertNotIn("/run", raw[4:].decode())
            self.assertNotIn("/workspace", raw[4:].decode())
        finally:
            sender.close()
            receiver.close()

    def test_source_metadata_and_native_module_remain_unchanged(self):
        path = Path(__file__).with_name("native_capsule.py")
        before = path.read_bytes()
        native.validate_config(execution_fixture())
        container.validate_kernel(kernel_fixture(), execution_fixture())
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(native.EXPORT_NAMES[0], ("execution_receipt", "execution_receipt.json"))
        self.assertEqual(native.FILE_LIMIT, 64 << 20)
        self.assertEqual(native.WORKSPACE_LIMIT, 128 << 20)


if __name__ == "__main__":
    unittest.main()
