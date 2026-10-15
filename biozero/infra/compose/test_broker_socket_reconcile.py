# SPDX-License-Identifier: AGPL-3.0-only
"""Real owned processes/sockets for the explicit fixture-only procedure."""
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import broker_socket_reconcile as reconcile


SERVER = '''import json,os,socket,sys
cfg=json.load(open(sys.argv[sys.argv.index('--config')+1]))
path=cfg['socket_path']
if os.path.lexists(path):
 print('artifact_service_start_failed',flush=True)
 sys.exit(1)
s=socket.socket(socket.AF_UNIX)
s.bind(path);os.chmod(path,0o600);s.listen(8)
print('broker_fixture_ready',flush=True)
while True:
 c,_=s.accept();c.close()
'''


@unittest.skipUnless(os.getuid() == 1000 and os.geteuid() == 1000, "owned broker fixture requires UID1000")
class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bz-reconcile-unit-")
        self.root = Path(self.temp.name)
        self.channel = self.root / "channel"
        self.channel.mkdir(mode=0o700)
        self.path = self.channel / "b.sock"
        self.config = self.root / "broker.json"
        self.config.write_text(json.dumps({"socket_path": str(self.path), "provider": "docker", "allowed_uid": 1000}))
        self.config.chmod(0o600)
        self.binary = self.root / "python"
        self.binary.write_bytes(Path(sys.executable).read_bytes())
        self.binary.chmod(0o700)
        self.sha = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.script = self.root / "server.py"
        self.script.write_text(SERVER)
        self.script.chmod(0o600)
        self.argv = [str(self.binary), str(self.script), "--config", str(self.config)]
        self.processes, self.pins = [], []
        self.history = {"all_committed": True, "artifacts_sha256": "a" * 64, "charge": 12345, "slots": 1}

    def tearDown(self):
        for pin in self.pins:
            pin.close()
        for proc in self.processes:
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=2)
        self.temp.cleanup()

    def start(self, ready=True):
        proc = subprocess.Popen(self.argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.processes.append(proc)
        if ready:
            # bind/chmod expose the node before listen accepts connections.
            # Only this fixture's successful child emits the post-listen marker;
            # rejected startups retain their exact, unread rejection stdout.
            marker = b"broker_fixture_ready\n"
            observed = b""
            until = time.monotonic() + 3
            while len(observed) < len(marker):
                remaining = until - time.monotonic()
                if remaining <= 0:
                    self.fail("test server readiness timed out")
                if proc.poll() is not None:
                    self.fail("test server did not start")
                readable, _, _ = select.select([proc.stdout], [], [], remaining)
                if not readable:
                    self.fail("test server readiness timed out")
                chunk = os.read(proc.stdout.fileno(), len(marker) - len(observed))
                if not chunk:
                    self.fail("test server exited before readiness")
                observed += chunk
                if not marker.startswith(observed):
                    self.fail("test server readiness marker invalid")
            if proc.poll() is not None or not self.path.is_socket() or self.path.stat().st_mode & 0o777 != 0o600:
                self.fail("test server not ready after listen")
        return proc

    def pin(self, proc=None):
        proc = self.start() if proc is None else proc
        value = reconcile.CommittedSocketFixture(proc, self.path, self.config, self.sha, "b" * 64,
                                                lambda: dict(self.history))
        self.pins.append(value)
        return value

    def killed_and_rejected(self):
        pin = self.pin()
        pin.proc.kill()
        self.assertEqual(pin.proc.wait(timeout=2), -9)
        rejected = self.start(ready=False)
        raw, _ = rejected.communicate(timeout=2)
        self.assertEqual(rejected.returncode, 1)
        self.assertEqual(raw, b"artifact_service_start_failed\n")
        return pin, rejected, raw

    def assert_preserved(self, pin, rejected, raw):
        before = self.config.read_bytes(), dict(self.history)
        with self.assertRaises((reconcile.ReconcileFailure, OSError)):
            pin.retire(rejected, raw)
        self.assertTrue(os.path.lexists(self.path))
        self.assertFalse(pin.receipt["socket_unlink_attempted"])
        self.assertEqual(before, (self.config.read_bytes(), dict(self.history)))

    def test_owned_dead_socket_retired_once_then_same_process_config_restarts(self):
        pin, rejected, raw = self.killed_and_rejected()
        original = os.fstat(pin.socket_fd)
        result = pin.retire(rejected, raw)
        self.assertTrue(result["directory_fsynced"])
        self.assertFalse(self.path.exists())
        self.assertEqual(os.fstat(pin.socket_fd).st_nlink, 0)
        replacement = self.start()
        result = pin.verify_replacement(replacement)
        self.assertTrue(result["replacement_verified"])
        self.assertNotEqual((original.st_dev, original.st_ino), tuple(result["replacement_socket_identity"][:2]))
        pin.close()
        self.assertTrue(pin.receipt["references_closed"])
        with self.assertRaises(reconcile.ReconcileFailure):
            pin.retire(rejected, raw)

    def test_live_original_never_removed(self):
        pin = self.pin()
        rejected = self.start(ready=False)
        raw, _ = rejected.communicate(timeout=2)
        self.assert_preserved(pin, rejected, raw)

    def test_nonkill_original_exit_never_authorizes_retirement(self):
        pin = self.pin()
        pin.proc.terminate()
        self.assertEqual(pin.proc.wait(timeout=2), -15)
        rejected = self.start(ready=False)
        raw, _ = rejected.communicate(timeout=2)
        self.assert_preserved(pin, rejected, raw)

    def test_wrong_rejection_text_or_nonterminal_rejection_never_removes(self):
        pin, rejected, raw = self.killed_and_rejected()
        self.assert_preserved(pin, rejected, b"some_other_failure\n")
        # Every attempt is final even if all preconditions later become true.
        with self.assertRaises(reconcile.ReconcileFailure):
            pin.retire(rejected, raw)

    def test_pending_or_changed_complete_history_never_removed(self):
        for field, value in (("all_committed", False), ("charge", 9), ("slots", 2), ("artifacts_sha256", "f" * 64)):
            with self.subTest(field=field):
                pin, rejected, raw = self.killed_and_rejected()
                self.history[field] = value
                self.assert_preserved(pin, rejected, raw)
                self.history = {"all_committed": True, "artifacts_sha256": "a" * 64, "charge": 12345, "slots": 1}
                # Only this test fixture creates/removes its own old node between cases.
                pin.close()
                self.path.unlink()

    def test_history_guard_exception_aborts_before_unlink(self):
        pin, rejected, raw = self.killed_and_rejected()
        def failing():
            raise reconcile.ReconcileFailure("reconcile_history_pending")
        pin.guard = failing
        self.assert_preserved(pin, rejected, raw)

    def test_source_configuration_drift_never_removed(self):
        pin, rejected, raw = self.killed_and_rejected()
        self.config.write_text(json.dumps({"socket_path": str(self.path), "provider": "docker", "changed": True}))
        self.assert_preserved(pin, rejected, raw)

    def test_unknown_directory_entry_never_removed(self):
        pin, rejected, raw = self.killed_and_rejected()
        (self.channel / "unknown").write_bytes(b"preserve")
        self.assert_preserved(pin, rejected, raw)
        self.assertEqual((self.channel / "unknown").read_bytes(), b"preserve")

    def test_replaced_symlink_or_socket_never_removed(self):
        for kind in ("symlink", "socket"):
            with self.subTest(kind=kind):
                pin, rejected, raw = self.killed_and_rejected()
                self.path.unlink()
                if kind == "symlink":
                    self.path.symlink_to(self.config)
                else:
                    other = socket.socket(socket.AF_UNIX)
                    other.bind(str(self.path))
                    self.path.chmod(0o600)
                    other.listen(1)
                    self.addCleanup(other.close)
                self.assert_preserved(pin, rejected, raw)
                pin.close()
                self.path.unlink()

    def test_mode_change_never_removed(self):
        pin, rejected, raw = self.killed_and_rejected()
        self.path.chmod(0o660)
        self.assert_preserved(pin, rejected, raw)

    def test_missing_socket_never_authorizes_retirement_or_retry(self):
        pin, rejected, raw = self.killed_and_rejected()
        self.path.unlink()
        with self.assertRaises((reconcile.ReconcileFailure, OSError)):
            pin.retire(rejected, raw)
        self.assertFalse(pin.receipt["socket_unlink_attempted"])
        with self.assertRaises(reconcile.ReconcileFailure):
            pin.retire(rejected, raw)

    def test_fsync_failure_after_unlink_blocks_replacement_verification(self):
        pin, rejected, raw = self.killed_and_rejected()
        with mock.patch.object(reconcile.os, "fsync", side_effect=OSError("test sync failure")):
            with self.assertRaises(OSError):
                pin.retire(rejected, raw)
        self.assertTrue(pin.receipt["socket_unlinked"])
        self.assertFalse(pin.receipt["directory_fsynced"])
        self.assertFalse(pin.retired)
        with self.assertRaises(reconcile.ReconcileFailure):
            pin.verify_replacement(rejected)
        with self.assertRaises(reconcile.ReconcileFailure):
            pin.retire(rejected, raw)

    def test_replaced_ancestor_refused_before_pin(self):
        proc = self.start()
        actual = self.root / "actual-channel"
        self.channel.rename(actual)
        self.channel.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(OSError):
            self.pin(proc)

    def test_configured_peer_uid_must_be_exact_int1000(self):
        proc = self.start()
        self.config.write_text(json.dumps({"socket_path": str(self.path), "provider": "docker", "allowed_uid": True}))
        with self.assertRaises(reconcile.ReconcileFailure):
            self.pin(proc)

    def test_other_uid_rejected_before_any_socket_adoption(self):
        proc = self.start()
        with mock.patch.object(reconcile.os, "geteuid", return_value=1001):
            with self.assertRaises(reconcile.ReconcileFailure):
                self.pin(proc)
        self.assertTrue(self.path.is_socket())


if __name__ == "__main__":
    unittest.main()
