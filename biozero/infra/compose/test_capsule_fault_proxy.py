# SPDX-License-Identifier: AGPL-3.0-only
"""Actual Unix/SCM_RIGHTS tests; these are not capsule/scientific acceptance."""
import array
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest

import capsule_fault_proxy as proxy

PROFILE = "a" * 64
JOB = "b" * 16
UPLOAD = "c" * 64


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode()


def request(operation="submit", payload=b"synthetic fixture"):
    submit = operation == "submit"
    return {"schema_version": 2, "operation": operation, "job_id": JOB, "upload_sha256": UPLOAD,
            "expected_profile_sha256": PROFILE, "processed_sha256": hashlib.sha256(payload).hexdigest() if submit else "",
            "processed_bytes": len(payload) if submit else 0, "original_name": "reads.fastq" if submit else "",
            "analysis_context": {"original_name": "reads.fastq" if submit else "", "processed_size_bytes": len(payload) if submit else 0,
                                 "decrypted": submit, "decryption_error": "", "signature_valid": submit, "signature_error": ""}}


def response():
    return {"schema_version": 2, "job_id": JOB, "upload_sha256": UPLOAD, "profile_sha256": PROFILE,
            "store_id": "d" * 32, "lease_id": "e" * 32, "manifest_sha256": "f" * 64,
            "receipt_sha256": hashlib.sha256(b"real receipt bytes").hexdigest(), "receipt_bytes": len(b"real receipt bytes"),
            "state": "committed", "error_code": ""}


class SocketFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bz-fault-unit-")
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.handles = []

    def tearDown(self):
        for fd in self.handles:
            os.close(fd)
        self.temp.cleanup()

    def readonly(self, data=b"synthetic fixture", name="input"):
        path = self.root / name
        path.write_bytes(data)
        path.chmod(0o600)
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        self.handles.append(fd)
        return fd

    def pair(self):
        a, b = socket.socketpair()
        a.settimeout(1)
        b.settimeout(1)
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        return a, b


class FrameTests(SocketFixture):
    def test_fragmented_first_header_descriptor_has_cloexec(self):
        incoming, outgoing = self.pair()
        original = self.readonly()
        raw = encode(request())
        frame = struct.pack("!I", len(raw)) + raw
        outgoing.sendmsg([frame[:1]], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [original]))])
        for chunk in (frame[1:2], frame[2:4], frame[4:37], frame[37:]):
            outgoing.sendall(chunk)
        received, fd = proxy.read_frame(incoming)
        try:
            self.assertEqual(raw, received)
            proxy._file(fd, len(b"synthetic fixture"), 25 << 20)
            self.assertFalse(os.get_inheritable(fd))
            self.assertEqual(os.pread(fd, 99, 0), b"synthetic fixture")
        finally:
            os.close(fd)

    def test_late_header_and_body_rights_rejected_without_leak(self):
        for split in (1, 4, 7):
            with self.subTest(split=split):
                incoming, outgoing = self.pair()
                fd = self.readonly(name="input" + str(split))
                frame = struct.pack("!I", 4) + b"null"
                outgoing.sendall(frame[:split])
                outgoing.sendmsg([frame[split:]], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
                before = len(os.listdir("/proc/self/fd"))
                with self.assertRaises(proxy.ProxyFailure):
                    proxy.read_frame(incoming)
                self.assertEqual(before, len(os.listdir("/proc/self/fd")))

    def test_extra_and_truncated_rights_rejected_without_leak(self):
        fd = self.readonly()
        for count in (2, 30):
            with self.subTest(count=count):
                incoming, outgoing = self.pair()
                outgoing.sendmsg([struct.pack("!I", 4) + b"null"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd] * count))])
                before = len(os.listdir("/proc/self/fd"))
                with self.assertRaises(proxy.ProxyFailure):
                    proxy.read_frame(incoming)
                self.assertEqual(before, len(os.listdir("/proc/self/fd")))

    def test_oversize_and_bad_utf8_close_rights(self):
        fd = self.readonly()
        for wire in (struct.pack("!I", 65537), struct.pack("!I", 1) + b"\xff"):
            with self.subTest(wire=wire):
                incoming, outgoing = self.pair()
                outgoing.sendmsg([wire], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
                before = len(os.listdir("/proc/self/fd"))
                with self.assertRaises((proxy.ProxyFailure, UnicodeError)):
                    proxy.read_frame(incoming)
                self.assertEqual(before, len(os.listdir("/proc/self/fd")))

    def test_partial_write_sends_rights_once(self):
        class Partial:
            def __init__(self):
                self.sent, self.rights, self.rest = [], [], None
            def gettimeout(self):
                return 1
            def settimeout(self, _):
                pass
            def sendmsg(self, pieces, rights):
                self.sent.append(pieces[0][:1])
                self.rights.append(rights)
                return 1
            def sendall(self, data):
                self.sent.append(data)
        conn = Partial()
        fd = self.readonly()
        proxy.write_frame(conn, b"{}", fd)
        self.assertEqual(b"".join(conn.sent), struct.pack("!I", 2) + b"{}")
        self.assertEqual(len(conn.rights), 1)
        self.assertEqual(list(conn.rights[0][0][2]), [fd])

    def test_absolute_frame_deadline_stops_slow_fragments(self):
        incoming, outgoing = self.pair()
        incoming.settimeout(0.12)
        stop = threading.Event()
        def trickle():
            for byte in struct.pack("!I", 20) + b" " * 20:
                if stop.wait(0.025):
                    return
                outgoing.sendall(bytes([byte]))
        thread = threading.Thread(target=trickle)
        thread.start()
        start = time.monotonic()
        try:
            with self.assertRaises((proxy.ProxyFailure, socket.timeout)):
                proxy.read_frame(incoming)
            self.assertLess(time.monotonic() - start, 0.3)
        finally:
            stop.set()
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())

    def test_complete_write_accepts_peer_closing_immediately_after_frame(self):
        incoming, outgoing = self.pair()
        closed, observed = threading.Event(), []
        def peer():
            try:
                raw, fd = proxy.read_frame(incoming)
                observed.append(raw)
                if fd is not None:
                    os.close(fd)
            finally:
                incoming.close()
                closed.set()
        reader = threading.Thread(target=peer)
        reader.start()
        class ClosingPeer:
            def gettimeout(self):
                return outgoing.gettimeout()
            def settimeout(self, timeout):
                outgoing.settimeout(timeout)
            def sendmsg(self, pieces, rights):
                count = outgoing.sendmsg(pieces, rights)
                if count != sum(map(len, pieces)) or not closed.wait(1):
                    raise AssertionError("complete-write test barrier failed")
                return count
            def sendall(self, raw):
                outgoing.sendall(raw)
        try:
            proxy.write_frame(ClosingPeer(), b"{}")
            self.assertEqual(observed, [b"{}"])
        finally:
            reader.join(timeout=1)
            self.assertFalse(reader.is_alive())

    def test_trailing_response_rights_closed(self):
        incoming, outgoing = self.pair()
        fd = self.readonly()
        outgoing.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
        before = len(os.listdir("/proc/self/fd"))
        with self.assertRaises(proxy.ProxyFailure):
            proxy.read_end(incoming)
        self.assertEqual(before, len(os.listdir("/proc/self/fd")))


class RelayTests(SocketFixture):
    def broker(self, handler):
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(self.root / "b.sock"))
        os.chmod(self.root / "b.sock", 0o600)
        listener.listen(8)
        listener.settimeout(0.05)
        stop, errors = threading.Event(), []
        def serve():
            try:
                while not stop.is_set():
                    try:
                        conn, _ = listener.accept()
                    except socket.timeout:
                        continue
                    with conn:
                        conn.settimeout(2)
                        handler(conn)
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=serve)
        thread.start()
        def finish():
            stop.set()
            thread.join(timeout=3)
            listener.close()
            self.assertFalse(thread.is_alive())
            if errors:
                raise errors[0]
        self.addCleanup(finish)
        return errors

    def relay(self, **kwargs):
        relay = proxy.FixedBridgeProxy(self.root / "p.sock", self.root / "b.sock", PROFILE, **kwargs).start()
        self.addCleanup(relay.close)
        return relay

    def client(self, q, fd=None):
        conn = socket.socket(socket.AF_UNIX)
        self.addCleanup(conn.close)
        conn.settimeout(2)
        conn.connect(str(self.root / "p.sock"))
        proxy.write_frame(conn, encode(q), fd)
        return conn

    def test_drop_once_then_exact_queries_and_receipt_fd(self):
        observed = []
        receipt_fd = self.readonly(b"real receipt bytes", "receipt")
        def handle(conn):
            raw, fd = proxy.read_frame(conn)
            q = json.loads(raw)
            observed.append(raw)
            # The proxy must keep the request write side open throughout dispatch.
            self.assertFalse(select_ready(conn, 0.01))
            if fd is not None:
                try:
                    self.assertEqual(os.pread(fd, 99, 0), b"synthetic fixture")
                finally:
                    os.close(fd)
            proxy.write_frame(conn, encode(response()), receipt_fd if q["operation"] == "receipt" else None)
        self.broker(handle)
        relay = self.relay()
        submit = self.client(request(), self.readonly())
        self.assertTrue(relay.barrier.wait(2))
        with self.assertRaises(proxy.ProxyFailure):
            proxy.read_frame(submit)
        for operation in ("status", "receipt"):
            conn = self.client(request(operation))
            raw, fd = proxy.read_frame(conn)
            try:
                self.assertEqual(raw, encode(response()))
                proxy.read_end(conn)
                if operation == "receipt":
                    proxy._file(fd, len(b"real receipt bytes"), 16 << 20)
                    self.assertEqual(os.pread(fd, 99, 0), b"real receipt bytes")
                else:
                    self.assertIsNone(fd)
            finally:
                if fd is not None:
                    os.close(fd)
        final = relay.close()
        self.assertEqual(observed, [encode(request(op)) for op in ("submit", "status", "receipt")])
        self.assertEqual(final["submit_requests"], 1)
        self.assertEqual(final["query_requests"], {"status": 1, "receipt": 1, "cancel": 0})
        self.assertEqual(final["dropped_submit_responses"], 1)
        self.assertTrue(final["joined"])
        self.assertIsNone(final["error_code"])

    def test_barrier_requires_upstream_eof_then_held_response_can_be_dropped(self):
        sent, allow_eof = threading.Event(), threading.Event()
        self.addCleanup(allow_eof.set)
        def handle(conn):
            _, fd = proxy.read_frame(conn)
            os.close(fd)
            proxy.write_frame(conn, encode(response()))
            sent.set()
            self.assertTrue(allow_eof.wait(2))
        self.broker(handle)
        relay = self.relay(mode="hold_submit_response")
        client = self.client(request(), self.readonly())
        self.assertTrue(sent.wait(2))
        self.assertFalse(relay.barrier.wait(0.08))
        allow_eof.set()
        self.assertTrue(relay.barrier.wait(2))
        self.assertTrue(relay.snapshot()["held_response"])
        self.assertFalse(select_ready(client, 0.03))
        client.close()  # The real worker-death fixture uses Docker Wait instead.
        relay.release(drop=True)
        final = relay.close()
        self.assertTrue(final["upstream_submit_eof"])
        self.assertIsNone(final["error_code"])

    def test_disconnect_propagates_upstream_cancellation(self):
        active, eof = threading.Event(), threading.Event()
        def handle(conn):
            _, fd = proxy.read_frame(conn)
            os.close(fd)
            active.set()
            self.assertEqual(conn.recv(1), b"")
            eof.set()
        self.broker(handle)
        relay = self.relay()
        client = self.client(request(), self.readonly())
        self.assertTrue(active.wait(2))
        client.close()
        self.assertTrue(eof.wait(2))
        final = relay.close()
        self.assertFalse(final["barrier_reached"])
        self.assertEqual(final["client_disconnects"], 1)
        self.assertTrue(final["joined"])
        self.assertIsNone(final["error_code"])

    def test_half_closed_request_and_trailing_data_never_dispatch(self):
        for trailing in (b"", b"extra"):
            with self.subTest(trailing=trailing):
                relay = self.relay()
                # Send frame and trailing/half-close before handing server the bytes.
                conn, other = self.pair()
                raw = encode(request())
                proxy.write_frame(other, raw, self.readonly(name="in" + str(len(trailing))))
                other.sendall(trailing)
                other.shutdown(socket.SHUT_WR)
                relay._serve(conn)
                state = relay.close()
                self.assertEqual(state["error_code"], "proxy_request_not_open")
                self.assertFalse(any(row.get("forwarded") for row in state["events"]))

    def test_close_interrupts_blocked_upstream_and_joins(self):
        active, eof = threading.Event(), threading.Event()
        def handle(conn):
            _, fd = proxy.read_frame(conn)
            os.close(fd)
            active.set()
            self.assertEqual(conn.recv(1), b"")
            eof.set()
        self.broker(handle)
        relay = self.relay()
        self.client(request(), self.readonly())
        self.assertTrue(active.wait(2))
        final = relay.close()
        self.assertTrue(eof.wait(2))
        self.assertTrue(final["joined"])
        self.assertIsNone(final["error_code"])
        self.assertEqual(final, relay.close())

    def test_unexpected_upstream_trailing_prevents_barrier(self):
        def handle(conn):
            _, fd = proxy.read_frame(conn)
            os.close(fd)
            proxy.write_frame(conn, encode(response()))
            conn.sendall(b"extra")
        self.broker(handle)
        relay = self.relay()
        conn = self.client(request(), self.readonly())
        with self.assertRaises(proxy.ProxyFailure):
            proxy.read_frame(conn)
        final = relay.close()
        self.assertFalse(final["barrier_reached"])
        self.assertEqual(final["error_code"], "proxy_response_trailing")

    def test_shutdown_during_connect_never_forwards_and_joins(self):
        connected, release_connect, no_frame = threading.Event(), threading.Event(), threading.Event()
        def handle(conn):
            self.assertEqual(conn.recv(1), b"")
            no_frame.set()
        self.broker(handle)
        relay = self.relay()
        original = relay._connect
        def delayed():
            upstream = original()
            connected.set()
            if not release_connect.wait(2):
                upstream.close()
                raise AssertionError("test connect barrier expired")
            return upstream
        relay._connect = delayed
        self.client(request(), self.readonly())
        self.assertTrue(connected.wait(2))
        result = []
        closer = threading.Thread(target=lambda: result.append(relay.close()))
        closer.start()
        self.assertTrue(relay._stop.wait(1))
        release_connect.set()
        closer.join(timeout=3)
        self.assertFalse(closer.is_alive())
        self.assertTrue(no_frame.wait(1))
        self.assertTrue(result[0]["joined"])
        self.assertIsNone(result[0]["error_code"])
        self.assertFalse(any(event.get("forwarded") for event in result[0]["events"]))

    def test_existing_or_replaced_node_is_preserved(self):
        path = self.root / "p.sock"
        path.write_bytes(b"existing")
        path.chmod(0o600)
        with self.assertRaises(proxy.ProxyFailure):
            self.relay()
        self.assertEqual(path.read_bytes(), b"existing")
        path.unlink()
        relay = self.relay()
        path.unlink()
        path.write_bytes(b"replacement")
        path.chmod(0o600)
        final = relay.close()
        self.assertEqual(path.read_bytes(), b"replacement")
        self.assertEqual(final["error_code"], "proxy_socket_cleanup_failed")


def select_ready(conn, timeout):
    import select
    return bool(select.select([conn], [], [], timeout)[0])


if __name__ == "__main__":
    unittest.main()
