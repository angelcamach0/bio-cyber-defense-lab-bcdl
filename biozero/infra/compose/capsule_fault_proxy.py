# SPDX-License-Identifier: AGPL-3.0-only
"""Opt-in local fault fixture for the real v2 broker, never a service backend.

Relay exact frames and descriptor rights to one fixed, private host socket. A
barrier after the complete upstream Submit response AND EOF permits downstream
response loss or worker death. This proves upstream response delivery to this
fixture, not a failed broker ACK write. No response or scientific fact is forged.
"""
import array
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
import threading
import time

FRAME_LIMIT = 65536
REQUEST_KEYS = {"schema_version", "operation", "job_id", "upload_sha256",
                "expected_profile_sha256", "processed_sha256", "processed_bytes",
                "original_name", "analysis_context"}
CONTEXT_KEYS = {"original_name", "processed_size_bytes", "decrypted", "decryption_error",
                "signature_valid", "signature_error"}
RESPONSE_FIELDS = ("job_id", "upload_sha256", "profile_sha256", "store_id", "lease_id",
                   "manifest_sha256", "receipt_sha256", "receipt_bytes", "state", "error_code")


class ProxyFailure(Exception):
    """Fixed codes only; never print request bodies or operating-system paths."""


def _close_fds(fds):
    for fd in fds:
        os.close(fd)


def _remaining(conn, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProxyFailure("proxy_deadline_exceeded")
    conn.settimeout(remaining)


def _deadline(conn):
    timeout = conn.gettimeout()
    if timeout is None or timeout <= 0:
        raise ProxyFailure("proxy_deadline_missing")
    return time.monotonic() + timeout


def _receive(conn, count, deadline=None):
    if deadline is not None:
        _remaining(conn, deadline)
    data, ancillary, flags, _ = conn.recvmsg(count, socket.CMSG_SPACE(4 * 4), socket.MSG_CMSG_CLOEXEC)
    fds, invalid = [], False
    for level, kind, raw in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            invalid = True
            continue
        values = array.array("i")
        values.frombytes(raw[:len(raw) - len(raw) % values.itemsize])
        fds.extend(values)
        invalid |= len(raw) % values.itemsize != 0
    if invalid or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC):
        _close_fds(fds)
        raise ProxyFailure("proxy_rights_invalid")
    return data, fds


def read_frame(conn, deadline=None):
    """recvmsg for every byte; rights only with the first received frame byte."""
    fds, first = [], True
    deadline = _deadline(conn) if deadline is None else deadline
    try:
        def exact(count):
            nonlocal first
            out = bytearray()
            while len(out) < count:
                data, received = _receive(conn, 1 if first else count - len(out), deadline)
                fds.extend(received)
                allowed = first
                first = False
                if not data or len(fds) > 1 or (received and not allowed):
                    raise ProxyFailure("proxy_frame_invalid")
                out.extend(data)
            return bytes(out)
        length = struct.unpack("!I", exact(4))[0]
        if not 0 < length <= FRAME_LIMIT:
            raise ProxyFailure("proxy_frame_size_invalid")
        raw = exact(length)
        raw.decode("utf-8", errors="strict")
        return raw, fds.pop() if fds else None
    finally:
        _close_fds(fds)


def read_end(conn, deadline=None):
    data, fds = _receive(conn, 1, _deadline(conn) if deadline is None else deadline)
    try:
        if data or fds:
            raise ProxyFailure("proxy_response_trailing")
    finally:
        _close_fds(fds)


def write_frame(conn, raw, fd=None, deadline=None):
    if not 0 < len(raw) <= FRAME_LIMIT:
        raise ProxyFailure("proxy_frame_size_invalid")
    frame = struct.pack("!I", len(raw)) + raw
    rights = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))] if fd is not None else []
    deadline = _deadline(conn) if deadline is None else deadline
    _remaining(conn, deadline)
    count = conn.sendmsg([frame], rights)
    if count <= 0:
        raise ProxyFailure("proxy_frame_write_failed")
    # A partial write must not send SCM_RIGHTS twice.
    if count < len(frame):
        _remaining(conn, deadline)
        conn.sendall(frame[count:])


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ProxyFailure("proxy_json_duplicate")
            result[key] = value
        return result
    def constant(_):
        raise ProxyFailure("proxy_json_constant")
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProxyFailure("proxy_json_invalid") from exc
    if not isinstance(value, dict):
        raise ProxyFailure("proxy_json_invalid")
    return value


def _hex(value, size):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{" + str(size) + "}", value) is not None


def _file(fd, size, limit):
    if fd is None or type(size) is not int or not 0 <= size <= limit:
        raise ProxyFailure("proxy_file_invalid")
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != size
            or fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
            or not fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC):
        raise ProxyFailure("proxy_file_invalid")


def _peer(conn):
    _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != os.getuid():
        raise ProxyFailure("proxy_peer_forbidden")


def _request_open(conn):
    # Reject already queued trailing bytes/rights or EOF before upstream dispatch.
    # A later peer close races execution legitimately and cancels via the monitor.
    if select.select([conn], [], [], 0)[0]:
        _, fds = _receive(conn, 1)
        _close_fds(fds)
        raise ProxyFailure("proxy_request_not_open")


def _directory(path):
    path = Path(path).absolute()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ProxyFailure("proxy_directory_unsafe")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _socket_info(fd, name):
    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise ProxyFailure("proxy_socket_unsafe")
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_ctime_ns, info.st_nlink)


class FixedBridgeProxy:
    """Bounded one-shot fault; all later requests use the same real upstream."""

    def __init__(self, socket_path, upstream_path, profile_sha256,
                 mode="drop_submit_response_once", *, request_timeout=5, submit_timeout=90, hold_timeout=30):
        if mode not in {"drop_submit_response_once", "hold_submit_response"} or not _hex(profile_sha256, 64):
            raise ProxyFailure("proxy_config_invalid")
        if not (0 < request_timeout <= 5 and 0 < submit_timeout <= 120 and 0 < hold_timeout <= 30):
            raise ProxyFailure("proxy_config_invalid")
        self.path, self.upstream = Path(socket_path).absolute(), Path(upstream_path).absolute()
        if self.path == self.upstream:
            raise ProxyFailure("proxy_config_invalid")
        self.profile, self.mode = profile_sha256, mode
        self.request_timeout, self.submit_timeout, self.hold_timeout = request_timeout, submit_timeout, hold_timeout
        self.barrier, self._release, self._stop = threading.Event(), threading.Event(), threading.Event()
        self._lock = threading.Lock()
        self._listener, self._directory, self._identity, self._thread = None, None, None, None
        self._connections, self._workers = set(), []
        self._claimed, self._drop, self._closed = False, True, False
        self._state = {"mode": mode, "barrier_reached": False, "upstream_submit_response_complete": False,
                       "upstream_submit_eof": False, "submit_requests": 0, "query_requests": {"status": 0, "receipt": 0, "cancel": 0},
                       "dropped_submit_responses": 0, "held_response": False, "error_code": None,
                       "requests": 0, "events": [], "client_disconnects": 0, "joined": False}

    def _error(self, code):
        with self._lock:
            if self._state["error_code"] is None:
                self._state["error_code"] = code

    def snapshot(self):
        with self._lock:
            return json.loads(json.dumps(self._state))

    def start(self):
        if self._thread is not None or self._closed:
            raise ProxyFailure("proxy_start_invalid")
        self._directory = _directory(self.path.parent)
        try:
            try:
                os.stat(self.path.name, dir_fd=self._directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ProxyFailure("proxy_socket_exists")
            self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
            self._listener.bind(f"/proc/self/fd/{self._directory}/{self.path.name}")
            os.chmod(self.path.name, 0o600, dir_fd=self._directory, follow_symlinks=False)
            self._identity = _socket_info(self._directory, self.path.name)
            self._listener.listen(8)
            self._listener.settimeout(0.1)
            self._thread = threading.Thread(target=self._accept, name="capsule-fault-relay", daemon=True)
            self._thread.start()
            return self
        except BaseException:
            self.close()
            raise

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop.is_set():
                    self._error("proxy_accept_failed")
                break
            with self._lock:
                allowed = not self._stop.is_set() and len(self._connections) < 8 and self._state["requests"] < 256
                if allowed:
                    self._state["requests"] += 1
                    self._connections.add(conn)
                    worker = threading.Thread(target=self._serve, args=(conn,), name="capsule-fault-request", daemon=True)
                    self._workers.append(worker)
            if allowed:
                worker.start()
            else:
                conn.close()
                if not self._stop.is_set():
                    self._error("proxy_connection_limit")

    def _request(self, raw, fd):
        q = _json(raw)
        if (set(q) != REQUEST_KEYS or type(q["schema_version"]) is not int or q["schema_version"] != 2
                or not _hex(q["job_id"], 16) or not _hex(q["upload_sha256"], 64)
                or q["expected_profile_sha256"] != self.profile or not isinstance(q["operation"], str)
                or q["operation"] not in {"submit", "status", "receipt", "cancel"}
                or not isinstance(q["analysis_context"], dict) or set(q["analysis_context"]) != CONTEXT_KEYS):
            raise ProxyFailure("proxy_request_invalid")
        if q["operation"] == "submit":
            _file(fd, q["processed_bytes"], 25 << 20)
            if not _hex(q["processed_sha256"], 64) or not isinstance(q["original_name"], str) or len(q["original_name"].encode()) > 4096:
                raise ProxyFailure("proxy_request_invalid")
        elif fd is not None or q["processed_sha256"] != "" or type(q["processed_bytes"]) is not int or q["processed_bytes"] != 0 or q["original_name"] != "":
            raise ProxyFailure("proxy_request_invalid")
        # The fixed real broker remains the authority for full context/manifest validation.
        return q

    def _connect(self):
        directory = _directory(self.upstream.parent)
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        try:
            before = _socket_info(directory, self.upstream.name)
            conn.settimeout(self.request_timeout)
            conn.connect(f"/proc/self/fd/{directory}/{self.upstream.name}")
            _peer(conn)
            if before != _socket_info(directory, self.upstream.name):
                raise ProxyFailure("proxy_upstream_changed")
            return conn
        except BaseException:
            conn.close()
            raise
        finally:
            os.close(directory)

    def _serve(self, downstream):
        input_fd = output_fd = upstream = monitor = None
        event, phase = None, "receive_request"
        monitor_stop = threading.Event()
        disconnected = threading.Event()
        def watch():
            try:
                while not monitor_stop.is_set() and not self._stop.is_set():
                    if not select.select([downstream], [], [], 0.05)[0]:
                        continue
                    data, fds = _receive(downstream, 1)
                    try:
                        if data or fds:
                            self._error("proxy_request_trailing")
                        else:
                            with self._lock:
                                self._state["client_disconnects"] += 1
                        disconnected.set()
                        upstream.shutdown(socket.SHUT_RDWR)
                    finally:
                        _close_fds(fds)
                    return
            except (OSError, ProxyFailure):
                if not monitor_stop.is_set() and not self._stop.is_set():
                    self._error("proxy_monitor_failed")
                    disconnected.set()
                    try:
                        upstream.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
        try:
            if self._stop.is_set():
                return
            _peer(downstream)
            downstream.settimeout(self.request_timeout)
            raw, input_fd = read_frame(downstream)
            q = self._request(raw, input_fd)
            operation = q["operation"]
            with self._lock:
                if operation == "submit":
                    self._state["submit_requests"] += 1
                else:
                    self._state["query_requests"][operation] += 1
                inject = operation == "submit" and not self._claimed
                if inject:
                    self._claimed = True
                    self._state["submit_request"] = {k: q[k] for k in ("job_id", "upload_sha256", "expected_profile_sha256", "processed_sha256", "processed_bytes")}
                event = {"operation": operation, "request_sha256": hashlib.sha256(raw).hexdigest()}
                self._state["events"].append(event)
            phase = "before_connect"
            _request_open(downstream)
            phase = "connect_upstream"
            upstream = self._connect()
            with self._lock:
                if self._stop.is_set():
                    return
                self._connections.add(upstream)
            phase = "before_forward"
            _request_open(downstream)
            monitor = threading.Thread(target=watch, name="capsule-fault-disconnect", daemon=True)
            monitor.start()
            if disconnected.is_set() or self._stop.is_set():
                return
            phase = "forward_request"
            write_frame(upstream, raw, input_fd)
            with self._lock:
                event["forwarded"] = True
            if input_fd is not None:
                os.close(input_fd)
                input_fd = None
            upstream.settimeout(self.submit_timeout if operation == "submit" else self.request_timeout)
            response_deadline = _deadline(upstream)
            phase = "read_upstream_response"
            response_raw, output_fd = read_frame(upstream, response_deadline)
            response = _json(response_raw)
            if response.get("schema_version") != 2:
                raise ProxyFailure("proxy_response_invalid")
            if operation == "receipt" and response.get("error_code") == "":
                _file(output_fd, response.get("receipt_bytes"), 16 << 20)
            elif output_fd is not None:
                raise ProxyFailure("proxy_unexpected_response_fd")
            phase = "read_upstream_eof"
            read_end(upstream, response_deadline)
            monitor_stop.set()
            monitor.join(timeout=1)
            if monitor.is_alive():
                raise ProxyFailure("proxy_monitor_not_joined")
            with self._lock:
                event["response_sha256"] = hashlib.sha256(response_raw).hexdigest()
                event["upstream_eof"] = True
            if disconnected.is_set():
                return
            if inject:
                if (response.get("error_code") != "" or response.get("state") != "committed"
                        or response.get("job_id") != q["job_id"] or response.get("upload_sha256") != q["upload_sha256"]
                        or response.get("profile_sha256") != self.profile or not _hex(response.get("lease_id"), 32)):
                    raise ProxyFailure("proxy_submit_barrier_invalid")
                with self._lock:
                    self._state.update(barrier_reached=True, upstream_submit_response_complete=True, upstream_submit_eof=True,
                                       held_response=self.mode == "hold_submit_response")
                    self._state["submit_response"] = {key: response.get(key) for key in RESPONSE_FIELDS}
                self.barrier.set()
                if self.mode == "hold_submit_response":
                    if not self._release.wait(self.hold_timeout):
                        raise ProxyFailure("proxy_hold_timeout")
                    with self._lock:
                        self._state["held_response"] = False
                if self.mode == "drop_submit_response_once" or self._drop:
                    with self._lock:
                        self._state["dropped_submit_responses"] += 1
                    return
            phase = "write_downstream_response"
            downstream.settimeout(self.request_timeout)
            write_frame(downstream, response_raw, output_fd)
        except Exception as exc:
            if not self._stop.is_set() and not disconnected.is_set():
                if event is not None:
                    with self._lock:
                        event["failure"] = {"phase": phase, "exception_type": type(exc).__name__,
                                            "errno": exc.errno if isinstance(exc, OSError) else None}
                self._error(str(exc) if isinstance(exc, ProxyFailure) else "proxy_transport_failed")
        finally:
            monitor_stop.set()
            if monitor is not None:
                monitor.join(timeout=1)
                if monitor.is_alive():
                    self._error("proxy_monitor_not_joined")
            _close_fds([fd for fd in (input_fd, output_fd) if fd is not None])
            with self._lock:
                self._connections.discard(downstream)
                if upstream is not None:
                    self._connections.discard(upstream)
            downstream.close()
            if upstream is not None:
                upstream.close()

    def release(self, drop=True):
        self._drop = bool(drop)
        self._release.set()

    def close(self):
        if self._closed:
            return self.snapshot()
        self._closed = True
        self._stop.set()
        self.release(drop=True)
        if self._listener is not None:
            self._listener.close()
        with self._lock:
            connections = list(self._connections)
        for conn in connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        deadline = time.monotonic() + 3
        if self._thread is not None:
            self._thread.join(timeout=max(0, deadline - time.monotonic()))
        # Accept loop is now terminal; its worker list cannot grow.
        for worker in self._workers:
            worker.join(timeout=max(0, deadline - time.monotonic()))
        joined = (self._thread is None or not self._thread.is_alive()) and all(not w.is_alive() for w in self._workers)
        with self._lock:
            self._state["joined"] = joined
        if not joined:
            self._error("proxy_shutdown_not_joined")
        if self._directory is not None:
            try:
                if self._identity is not None:
                    if _socket_info(self._directory, self.path.name) != self._identity:
                        raise ProxyFailure("proxy_socket_changed")
                    os.unlink(self.path.name, dir_fd=self._directory)
                    os.fsync(self._directory)
            except (OSError, ProxyFailure):
                self._error("proxy_socket_cleanup_failed")
            finally:
                os.close(self._directory)
                self._directory = None
        return self.snapshot()
