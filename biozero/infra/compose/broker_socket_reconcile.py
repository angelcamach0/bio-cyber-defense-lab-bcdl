# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit committed-only socket procedure for a fresh, owned test fixture.

This is not a production reconciler or stale-socket cleanup utility. A trusted
exclusive supervisor supplies its own live child and complete history guard.
No ledger, plaintext, workspace, anchor, charge or execution is modified here.
unlinkat is not conditional by inode: cooperative host/same-UID writers remain
required even with directory/socket descriptors and immediate identity checks.
"""
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct

from capsule_fault_proxy import _directory


class ReconcileFailure(Exception):
    """Fixed codes only; callers retain detailed receipts privately."""


def _hex(value):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink, info.st_ctime_ns)


def _socket(info):
    return (stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1)


def _file_sha(path, limit, executable=False):
    path = Path(path).absolute()
    directory = _directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        before = os.fstat(fd)
        expected_mode = 0o700 if executable else 0o600
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != expected_mode or not 0 < before.st_size <= limit):
            raise ReconcileFailure("reconcile_source_unsafe")
        digest, raw = hashlib.sha256(), bytearray()
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not chunk:
                break
            digest.update(chunk)
            raw.extend(chunk)
            if len(raw) > limit:
                raise ReconcileFailure("reconcile_source_oversized")
        if len(raw) != before.st_size or _identity(os.fstat(fd)) != _identity(before):
            raise ReconcileFailure("reconcile_source_changed")
        return digest.hexdigest(), bytes(raw)
    finally:
        os.close(fd)


class CommittedSocketFixture:
    """Pin while alive; retire once after verified death; verify replacement.

    history_guard must independently require the fixture's complete matching
    Store/journal/custody, committed proofs/artifacts/charges and empty workspace.
    It returns a bounded JSON snapshot with all_committed=True. Equality alone
    is not validation; production custody authority remains in the real broker.
    """

    def __init__(self, proc, socket_path, config_path, executable_sha256, profile_sha256, history_guard):
        self.directory = self.socket_fd = self.pid_fd = None
        self.closed, self.attempted, self.retired = False, False, False
        self.proc, self.path, self.config = proc, Path(socket_path).absolute(), Path(config_path).absolute()
        self.profile, self.binary_sha, self.guard = profile_sha256, executable_sha256, history_guard
        self.receipt = {"socket_unlink_attempted": False, "socket_unlinked": False, "directory_fsynced": False,
                        "replacement_verified": False, "references_closed": False,
                        "scope": "exclusive own committed fixture; cooperative host/same-UID; no pending-state authority"}
        if (os.getuid() != 1000 or os.geteuid() != 1000 or not _hex(executable_sha256)
                or not _hex(profile_sha256) or not callable(history_guard) or proc.poll() is not None):
            raise ReconcileFailure("reconcile_config_invalid")
        if not isinstance(proc.args, (list, tuple)) or not all(isinstance(x, str) for x in proc.args):
            raise ReconcileFailure("reconcile_process_invalid")
        self.argv = tuple(proc.args)
        if self.argv.count("--config") != 1 or self.argv.index("--config") + 1 >= len(self.argv) or self.argv[self.argv.index("--config") + 1] != str(self.config):
            raise ReconcileFailure("reconcile_process_invalid")
        self.executable = Path(self.argv[0]).absolute()
        try:
            self.directory = _directory(self.path.parent)
            self.directory_identity = _identity(os.fstat(self.directory))
            if os.listdir(self.directory) != [self.path.name]:
                raise ReconcileFailure("reconcile_socket_directory_unknown")
            self.socket_fd = os.open(self.path.name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.directory)
            value = os.fstat(self.socket_fd)
            if not _socket(value):
                raise ReconcileFailure("reconcile_socket_unsafe")
            self.socket_identity = _identity(value)
            self.pid_fd = os.pidfd_open(proc.pid, 0)
            if not fcntl.fcntl(self.pid_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
                raise ReconcileFailure("reconcile_process_invalid")
            self._alive(proc)
            self.config_sha, raw = _file_sha(self.config, 65536)
            cfg = json.loads(raw)
            if (cfg.get("socket_path") != str(self.path) or cfg.get("provider") != "docker"
                    or type(cfg.get("allowed_uid")) is not int or cfg["allowed_uid"] != 1000):
                raise ReconcileFailure("reconcile_config_invalid")
            self._source_check()
            self._same_socket()
            self._peer(proc.pid)
            self.baseline = self._history()
            self.receipt.update(original_pid=proc.pid, socket_identity=list(self.socket_identity),
                                config_sha256=self.config_sha, binary_sha256=self.binary_sha,
                                profile_sha256=self.profile, original_history=self.baseline)
        except BaseException:
            self.close()
            raise

    def _alive(self, proc):
        if proc.poll() is not None or tuple(proc.args) != self.argv:
            raise ReconcileFailure("reconcile_process_not_alive")
        actual = Path(f"/proc/{proc.pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")
        if actual != [x.encode() for x in self.argv] or os.stat(f"/proc/{proc.pid}").st_uid != os.getuid():
            raise ReconcileFailure("reconcile_process_changed")
        # The source path and live executable must both match the pinned bytes.
        with open(f"/proc/{proc.pid}/exe", "rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else self._hash_stream(source)
        if digest != self.binary_sha:
            raise ReconcileFailure("reconcile_executable_changed")

    @staticmethod
    def _hash_stream(source):
        digest = hashlib.sha256()
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
        return digest.hexdigest()

    def _source_check(self):
        if _file_sha(self.executable, 32 << 20, executable=True)[0] != self.binary_sha or _file_sha(self.config, 65536)[0] != self.config_sha:
            raise ReconcileFailure("reconcile_source_changed")

    def _history(self):
        value = self.guard()
        if not isinstance(value, dict) or value.get("all_committed") is not True:
            raise ReconcileFailure("reconcile_history_pending")
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if len(raw) > 128 << 10:
            raise ReconcileFailure("reconcile_history_oversized")
        return json.loads(raw)

    def _same_socket(self):
        if self.directory is None or self.socket_fd is None:
            raise ReconcileFailure("reconcile_closed")
        directory = os.fstat(self.directory)
        # Directory ctime/mtime may change only at the explicit unlink below.
        if _identity(directory) != self.directory_identity:
            raise ReconcileFailure("reconcile_directory_changed")
        check = _directory(self.path.parent)
        try:
            if _identity(os.fstat(check)) != self.directory_identity or os.listdir(self.directory) != [self.path.name]:
                raise ReconcileFailure("reconcile_directory_changed")
        finally:
            os.close(check)
        current = os.stat(self.path.name, dir_fd=self.directory, follow_symlinks=False)
        if not _socket(current) or _identity(current) != self.socket_identity or _identity(os.fstat(self.socket_fd)) != self.socket_identity:
            raise ReconcileFailure("reconcile_socket_changed")

    def _peer(self, expected_pid):
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        try:
            conn.settimeout(1)
            conn.connect(f"/proc/self/fd/{self.directory}/{self.path.name}")
            pid, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if pid != expected_pid or uid != os.getuid():
                raise ReconcileFailure("reconcile_peer_changed")
        finally:
            conn.close()

    def retire(self, rejected_proc, rejection_bytes):
        """No implicit retry, including failures after unlink or directory fsync."""
        if self.closed or self.attempted:
            raise ReconcileFailure("reconcile_attempt_invalid")
        self.attempted = True
        if (self.proc.returncode != -9 or self.proc.poll() != -9 or not select.select([self.pid_fd], [], [], 0)[0]
                or rejected_proc is self.proc or rejected_proc.pid == self.proc.pid
                or rejected_proc.returncode != 1 or rejected_proc.poll() != 1 or tuple(rejected_proc.args) != self.argv
                or rejection_bytes != b"artifact_service_start_failed\n"):
            raise ReconcileFailure("reconcile_process_death_unproven")
        self._source_check()
        self._same_socket()
        if self._history() != self.baseline:
            raise ReconcileFailure("reconcile_history_changed")
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        try:
            conn.settimeout(1)
            try:
                conn.connect(f"/proc/self/fd/{self.directory}/{self.path.name}")
            except OSError as exc:
                if exc.errno != errno.ECONNREFUSED:
                    raise ReconcileFailure("reconcile_stale_unproven") from exc
            else:
                raise ReconcileFailure("reconcile_socket_still_active")
        finally:
            conn.close()
        # A successful connection check never authorizes removal of history.
        self._source_check()
        if self._history() != self.baseline:
            raise ReconcileFailure("reconcile_history_changed")
        self._same_socket()
        self.receipt["socket_unlink_attempted"] = True
        os.unlink(self.path.name, dir_fd=self.directory)
        self.receipt["socket_unlinked"] = True
        os.fsync(self.directory)
        self.receipt["directory_fsynced"] = True
        if os.listdir(self.directory) or os.fstat(self.socket_fd).st_nlink != 0:
            raise ReconcileFailure("reconcile_unlink_unproven")
        self.retired = True
        return dict(self.receipt)

    def verify_replacement(self, proc):
        if self.closed or not self.retired or self.receipt["replacement_verified"]:
            raise ReconcileFailure("reconcile_attempt_invalid")
        self._source_check()
        self._alive(proc)
        current_directory = _directory(self.path.parent)
        try:
            current = os.fstat(current_directory)
            original = os.fstat(self.directory)
            if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                raise ReconcileFailure("reconcile_directory_changed")
        finally:
            os.close(current_directory)
        if os.listdir(self.directory) != [self.path.name]:
            raise ReconcileFailure("reconcile_directory_changed")
        replacement = os.open(self.path.name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.directory)
        try:
            new, old = os.fstat(replacement), os.fstat(self.socket_fd)
            if not _socket(new) or old.st_nlink != 0 or (new.st_dev, new.st_ino) == (old.st_dev, old.st_ino):
                raise ReconcileFailure("reconcile_replacement_invalid")
            self._peer(proc.pid)
            if self._history() != self.baseline:
                raise ReconcileFailure("reconcile_history_changed")
            self._alive(proc)
            if (_identity(os.stat(self.path.name, dir_fd=self.directory, follow_symlinks=False)) != _identity(new)
                    or _identity(os.fstat(replacement)) != _identity(new)):
                raise ReconcileFailure("reconcile_replacement_changed")
            self.receipt.update(replacement_verified=True, replacement_pid=proc.pid,
                                replacement_socket_identity=list(_identity(new)))
        finally:
            os.close(replacement)
        return dict(self.receipt)

    def close(self):
        if self.closed:
            return
        self.closed = True
        failures = []
        for name in ("pid_fd", "socket_fd", "directory"):
            fd = getattr(self, name)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    failures.append(name)
                setattr(self, name, None)
        self.receipt["references_closed"] = not failures
        if failures:
            raise ReconcileFailure("reconcile_reference_close_failed")
