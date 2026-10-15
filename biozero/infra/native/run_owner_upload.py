#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Opt-in native owner-v1 authority/CLI/upload transport acceptance.

Builds three real service/client executables plus an independent payload inspector
offline and retains every private attempt. The actual CLI ciphertext must decrypt
under its signed canonical AAD and reject a changed AAD. No worker, broker,
scientific tools, Docker, download, deployment or release gate is exercised. A
delivered receipt establishes transport only. The TLS relay is owned test
instrumentation holding the synthetic owner's TLS credential; optional loss cuts
the downstream response after receiving the complete upstream response.
"""

import argparse
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import threading
import time
import traceback
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[3]
LIMIT = 25 << 20
RECEIPT_FIELDS = {"schema_version", "job_id", "acceptance_sha256", "credential_sha256",
                  "ciphertext_sha256", "ciphertext_bytes", "key_envelope_sha256", "state"}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sha(path):
    return digest(path.read_bytes())


def compact(value):
    # This fixture uses ASCII keys/values. Preserve the Go struct field order
    # from its original JSON; sorting would change the signed representation.
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def exact_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_bytes(path, raw, replace=False):
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
    flags |= os.O_TRUNC if replace else os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as out:
        os.fchmod(out.fileno(), 0o600)
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    sync_dir(path.parent)


def private_json(path, value, replace=False):
    private_bytes(path, json.dumps(value, indent=2).encode() + b"\n", replace)


def tree_hashes(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("unexpected private symlink")
        if path.is_file():
            result[str(path.relative_to(root))] = sha(path)
    return result


def physical_file_totals(root):
    """Observed retained files, separate from the policy's logical promises."""
    info = [path.stat() for path in root.rglob("*") if path.is_file()]
    return {"regular_files": len(info), "file_bytes": sum(item.st_size for item in info),
            "allocated_file_bytes": sum(item.st_blocks * 512 for item in info)}


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def client_context(pki, role):
    ctx = ssl.create_default_context(cafile=str(pki / "ca.crt"))
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["http/1.1"])
    ctx.load_cert_chain(pki / (role + ".crt"), pki / (role + ".key"))
    return ctx


def request(port, context, method, route, body=None, headers=None):
    # http.client does not consult external proxy settings or follow redirects.
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=15)
    try:
        conn.connect()
        version = conn.sock.version()
        conn.request(method, route, body=body, headers=headers or {})
        response = conn.getresponse()
        raw = response.read((96 << 10) + 1)
        if len(raw) > 96 << 10:
            raise ValueError("response exceeds fixture bound")
        return response.status, raw, version
    finally:
        conn.close()


class ReceiptRelay:
    """Observed real HTTP/mTLS hop, optionally losing one downstream receipt."""

    def __init__(self, pki, upstream_port, evidence, lose_receipt):
        self.events, self.errors = [], []
        self.lock = threading.Lock()
        self.upstream = upstream_port
        self.context = client_context(pki, "owner-a")
        self.evidence = evidence
        self.lose_receipt = lose_receipt
        self.lost = threading.Event()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def forward(self):
                try:
                    self.connection.settimeout(30)
                    leaf = self.connection.getpeercert(binary_form=True)
                    if digest(leaf) != outer.owner_sha:
                        self.send_error(403)
                        self.close_connection = True
                        return
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 0 or length > LIMIT + (65 << 10):
                        raise ValueError("relay frame exceeds fixture bound")
                    body = self.rfile.read(length)
                    if len(body) != length:
                        raise ValueError("relay truncated body")
                    headers = {"Content-Type": self.headers["Content-Type"]} if "Content-Type" in self.headers else {}
                    status, raw, version = request(outer.upstream, outer.context, self.command,
                                                   self.path, body if length else None, headers)
                    with outer.lock:
                        number = len(outer.events)
                        event = {"method": self.command, "route": self.path, "body_bytes": length,
                                 "body_sha256": digest(body), "status": status, "tls": version,
                                 "incoming_credential_sha256": digest(leaf),
                                 "upstream_client_credential_sha256": outer.owner_sha,
                                 "upstream_response_sha256": digest(raw)}
                        outer.events.append(event)
                        private_json(outer.evidence / ("relay-event-%02d.json" % number), event)
                        private_bytes(outer.evidence / ("relay-response-%02d.bin" % number), raw)
                        if outer.lose_receipt and self.command == "POST" and self.path == "/v1/uploads" and not outer.lost.is_set():
                            receipt = exact_json(raw)
                            if status != 200 or set(receipt) != RECEIPT_FIELDS or receipt["state"] != "delivered":
                                raise ValueError("no committed upstream receipt to interrupt")
                            # Above evidence is fsynced before the first downstream
                            # status/header/body write. TLS-layer failure is real;
                            # no upstream ACK-write failure is claimed.
                            private_json(outer.evidence / "relay-ack-barrier.json",
                                         {"upstream_complete": True, "downstream_http_bytes_written": 0,
                                          "receipt_sha256": digest(raw)})
                            outer.lost.set()
                            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                            self.close_connection = True
                            self.connection.close()
                            return
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(raw)
                    self.wfile.flush()
                    self.close_connection = True
                except Exception:
                    with outer.lock:
                        outer.errors.append(traceback.format_exc())
                    self.close_connection = True

        der = ssl.PEM_cert_to_DER_cert((pki / "owner-a.crt").read_text())
        self.owner_sha = digest(der)
        class PrivateServer(http.server.ThreadingHTTPServer):
            def handle_error(self, *_):
                # The standard server prints tracebacks and peer addresses to
                # stderr. Keep unexpected handler failures private as well.
                with outer.lock:
                    outer.errors.append(traceback.format_exc())

        self.server = PrivateServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = False
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols(["http/1.1"])
        ctx.load_cert_chain(pki / "upload.crt", pki / "upload.key")
        ctx.load_verify_locations(pki / "ca.crt")
        ctx.verify_mode = ssl.CERT_REQUIRED
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, name="owner-upload-fixture-relay")
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise RuntimeError("relay did not drain")
        private_json(self.evidence / "relay-summary.json", {"events": self.events, "errors": self.errors})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path, help="new absolute private evidence root; never reuse")
    parser.add_argument("--ack-loss", action="store_true", help="interrupt downstream reply after complete upstream receipt")
    args = parser.parse_args()
    if not args.run_dir.is_absolute() or args.run_dir != Path(os.path.abspath(args.run_dir)):
        parser.error("run directory must be an absolute normalized new path")
    if os.name != "posix" or not Path("/proc/self").exists():
        parser.error("Linux is required")
    os.umask(0o077)
    # Resolve the existing parent only; never adopt an existing final component.
    run = args.run_dir.parent.resolve(strict=True) / args.run_dir.name
    run.mkdir(mode=0o700, exist_ok=False)
    sync_dir(run.parent)
    for name in ("bin", "pki", "config", "evidence", "logs", "state"):
        (run / name).mkdir(mode=0o700)
    logs, evidence, pki, binaries = [run / n for n in ("logs", "evidence", "pki", "bin")]
    env = {**os.environ, "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local",
           "CGO_ENABLED": "0", "GOMAXPROCS": "1", "GOFLAGS": "-p=1"}
    report = {"schema_version": 1, "status": "failed", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "real owner-v1 authority, CLI, upload transport and independent real-payload OAEP/GCM-AAD inspection; no worker/broker/Results or scientific release",
              "ack_loss": args.ack_loss, "cases": [], "commands": [], "processes": []}
    children, handles, relay = [], [], None
    durable_before_shutdown = None
    command_number = 0

    def save():
        private_json(run / "report.json", report, replace=(run / "report.json").exists())

    def check(name, passed, observed=None):
        report["cases"].append({"case": name, "passed": bool(passed), "observed": observed or {}})
        save()
        if not passed:
            raise RuntimeError("acceptance assertion failed: " + name)

    def command(name, argv, cwd=None, settings=None, expected=0, timeout=120):
        nonlocal command_number
        number = command_number
        command_number += 1
        prefix = logs / ("%03d-%s" % (number, name))
        out = prefix.with_suffix(".stdout").open("xb")
        err = prefix.with_suffix(".stderr").open("xb")
        entry = {"name": name, "argv": [str(x) for x in argv], "cwd": str(cwd or ROOT),
                 "stdout": str(out.name), "stderr": str(err.name), "returncode": None}
        report["commands"].append(entry)
        save()
        try:
            result = subprocess.run([str(x) for x in argv], cwd=cwd or ROOT,
                                    env={**env, **(settings or {})}, stdout=out, stderr=err, timeout=timeout)
            entry["returncode"] = result.returncode
        except BaseException:
            entry["exception"] = traceback.format_exc()
            raise
        finally:
            out.flush(); err.flush()
            os.fsync(out.fileno()); os.fsync(err.fileno())
            out.close(); err.close()
            save()
        raw = Path(entry["stdout"]).read_bytes()
        if expected is not None and result.returncode != expected:
            raise RuntimeError("fixture command failed: " + name)
        return result.returncode, raw

    def start(name, argv, settings=None):
        out = (logs / (name + ".stdout")).open("xb")
        err = (logs / (name + ".stderr")).open("xb")
        handles.extend((out, err))
        proc = subprocess.Popen([str(x) for x in argv], cwd=ROOT, env={**env, **(settings or {})},
                                stdout=out, stderr=err, start_new_session=True)
        children.append(proc)
        report["processes"].append({"name": name, "pid": proc.pid, "argv": [str(x) for x in argv], "returncode": None})
        save()
        return proc

    def wait_ready(proc, port, ctx, route):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("owned service exited before readiness")
            try:
                status, raw, version = request(port, ctx, "GET", route)
                if status == 200:
                    if version != "TLSv1.3":
                        raise RuntimeError("unexpected TLS version")
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        raise RuntimeError("owned service readiness deadline expired")

    def source_inventory():
        _, raw = command("source-list", ["git", "ls-files", "-z", "-co", "--exclude-standard"])
        paths = [ROOT / os.fsdecode(x) for x in raw.split(b"\0") if x]
        return {str(p.relative_to(ROOT)): sha(p) for p in sorted(set(paths))
                if p.is_file() and not p.is_relative_to(run)}

    def asset(path):
        return {"path": str(path), "sha256": sha(path)}

    def openssl(name, *argv):
        return command(name, ["openssl", *argv])

    try:
        for tool in ("go", "openssl"):
            if shutil.which(tool, path=env.get("PATH")) is None:
                raise RuntimeError("required local tool unavailable")
        _, gov = command("go-version", ["go", "version"])
        _, opensslv = openssl("openssl-version", "version")
        _, commit = command("commit", ["git", "rev-parse", "HEAD"])
        _, dirty = command("worktree", ["git", "status", "--porcelain"])
        report.update({"go_version": gov.decode().strip(), "openssl_version": opensslv.decode().strip(),
                       "commit": commit.decode().strip(), "dirty": bool(dirty), "source_hashes": source_inventory()})
        inputs = {name: value for name, value in report["source_hashes"].items()
                  if name.endswith(".go") or Path(name).name in ("go.mod", "go.sum", "go.work", "go.work.sum")}
        report["complete_go_module_inputs"] = inputs
        private_json(evidence / "build-inputs-before.json", inputs)
        services = ROOT / "biozero/services"
        for name, module, package in (("uploader-cli", "uploader-cli", "."),
                                      ("ownership-authority", "ownership-authority", "./cmd/ownership-authority"),
                                      ("upload-api", "upload-api", ".")):
            command("build-" + name, ["go", "build", "-o", binaries / name, package], cwd=services / module)
            command("build-info-" + name, ["go", "version", "-m", binaries / name])
        inspector_source = ROOT / "biozero/infra/native/owner_upload_verify/main.go"
        command("build-owner-upload-verify", ["go", "build", "-o", binaries / "owner-upload-verify", inspector_source])
        command("build-info-owner-upload-verify", ["go", "version", "-m", binaries / "owner-upload-verify"])
        report["independent_inspector_source_sha256"] = sha(inspector_source)
        report["binary_pins"] = {p.name: {"sha256": sha(p), "bytes": p.stat().st_size} for p in binaries.iterdir()}
        current = source_inventory()
        check("build_source_snapshot_unchanged", current == report["source_hashes"])
        # All keys are synthetic and exclusive to this retained fixture. Separate
        # client/server EKUs and a separate RSA recipient avoid the older dual-EKU
        # and signing-key-as-recipient shortcuts.
        openssl("ca-key", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", pki / "ca.key")
        openssl("ca-cert", "req", "-new", "-x509", "-sha256", "-key", pki / "ca.key", "-out", pki / "ca.crt",
                "-days", "2", "-subj", "/CN=owner-upload-fixture-ca", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        for index, role in enumerate(("authority", "upload", "owner-a", "owner-b"), start=2):
            server = role in ("authority", "upload")
            openssl(role + "-key", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", pki / (role + ".key"))
            openssl(role + "-csr", "req", "-new", "-sha256", "-key", pki / (role + ".key"), "-out", pki / (role + ".csr"), "-subj", "/CN=" + role)
            extension = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage="
            extension += "serverAuth\nsubjectAltName=IP:127.0.0.1\n" if server else "clientAuth\n"
            private_bytes(pki / (role + ".ext"), extension.encode())
            openssl(role + "-cert", "x509", "-req", "-sha256", "-in", pki / (role + ".csr"), "-CA", pki / "ca.crt",
                    "-CAkey", pki / "ca.key", "-set_serial", str(index), "-days", "2", "-extfile", pki / (role + ".ext"), "-out", pki / (role + ".crt"))
            openssl(role + "-verify", "verify", "-CAfile", pki / "ca.crt", "-purpose", "sslserver" if server else "sslclient", pki / (role + ".crt"))
            wrong, _ = command(role + "-reject-other-purpose", ["openssl", "verify", "-CAfile", pki / "ca.crt",
                                  "-purpose", "sslclient" if server else "sslserver", pki / (role + ".crt")], expected=None)
            check("tls_eku_role_separation_" + role, wrong != 0)
        openssl("worker-key", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", pki / "worker.key")
        openssl("worker-public", "pkey", "-in", pki / "worker.key", "-pubout", "-out", pki / "worker.pub")
        openssl("authority-ed-key", "genpkey", "-algorithm", "ED25519", "-out", pki / "authority-ed.pem")
        openssl("authority-ed-der", "pkey", "-in", pki / "authority-ed.pem", "-outform", "DER", "-out", pki / "authority-ed.der")
        openssl("authority-ed-public", "pkey", "-in", pki / "authority-ed.pem", "-pubout", "-out", pki / "authority-ed.pub")
        openssl("authority-ed-public-der", "pkey", "-in", pki / "authority-ed.pem", "-pubout", "-outform", "DER", "-out", pki / "authority-ed-public.der")
        edprivate, edpublic = (pki / "authority-ed.der").read_bytes(), (pki / "authority-ed-public.der").read_bytes()
        check("ed25519_key_encoding_is_exact", len(edprivate) == 48 and edprivate[:16].hex() == "302e020100300506032b657004220420"
              and len(edpublic) == 44 and edpublic[:12].hex() == "302a300506032b6570032100")
        private_bytes(pki / "authority-signing.raw", edprivate[-32:] + edpublic[-32:])
        for path in pki.iterdir():
            path.chmod(0o600)
        report["pki_pins"] = tree_hashes(pki)
        authority_id = os.urandom(16).hex()
        profile = digest(compact({"domain": "biozero.owner-upload.synthetic-profile.v1", "pipeline_mode": "stats",
                                  "recipient_public_sha256": sha(pki / "worker.pub"), "binary_pins": report["binary_pins"]}))
        # Profile predates authority genesis. Scope is obtained only from its real
        # initializer, and is not folded back into this profile (no hash cycle).
        report["profile_sha256"] = profile
        report["profile_scope"] = "fixture transport profile; no executing broker/attestation claim"
        authority_port, upload_port = free_port(), free_port()
        while upload_port == authority_port:
            upload_port = free_port()
        policy = {"max_jobs": 64, "max_principal_jobs": 16, "max_bytes": 512 << 20,
                  "max_principal_bytes": 128 << 20, "max_active": 2, "max_principal_active": 1,
                  "max_body_bytes": LIMIT, "free_space_floor_bytes": 0, "challenge_ttl_seconds": 300}
        authority_store, upload_store = run / "state/authority", run / "state/upload"
        authority_config = {"schema_version": 1, "listen_address": "127.0.0.1:" + str(authority_port),
                            "store_root": str(authority_store), "namespace": "owner-upload-fixture",
                            "authority_id": authority_id, "public_key_hex": edpublic[-32:].hex(),
                            "pipeline_mode": "stats", "execution_profile_sha256": profile,
                            "signing_key": asset(pki / "authority-signing.raw"), "tls_certificate": asset(pki / "authority.crt"),
                            "tls_private_key": asset(pki / "authority.key"), "client_ca": asset(pki / "ca.crt"),
                            "policy": policy, "expected_scope": {"store_id": "", "policy_sha256": ""}}
        authority_path = run / "config/authority.json"
        private_json(authority_path, authority_config)
        _, raw_scope = command("authority-genesis", [binaries / "ownership-authority", "--config", authority_path, "--init-store"])
        scope = exact_json(raw_scope)
        check("genesis_supplies_external_scope", set(scope) == {"store_id", "policy_sha256"}
              and re.fullmatch("[0-9a-f]{32}", scope["store_id"]) and re.fullmatch("[0-9a-f]{64}", scope["policy_sha256"]))
        private_bytes(evidence / "authority-genesis-scope.json", raw_scope)
        authority_config["expected_scope"] = scope
        private_json(authority_path, authority_config, replace=True)
        upload_config = {"schema_version": 1, "listen_address": "127.0.0.1:" + str(upload_port),
                         "store_root": str(upload_store), "namespace": "owner-upload-transport",
                         "authority_id": authority_id, "public_key_hex": edpublic[-32:].hex(),
                         "pipeline_mode": "stats", "execution_profile_sha256": profile,
                         "expected_scope": scope, "policy": {k: v for k, v in policy.items() if k != "challenge_ttl_seconds"},
                         "tls_certificate": asset(pki / "upload.crt"), "tls_private_key": asset(pki / "upload.key"),
                         "client_ca": asset(pki / "ca.crt")}
        upload_path = run / "config/upload.json"
        private_json(upload_path, upload_config)
        upload_env = {"BIOZERO_UPLOAD_PROTOCOL": "owner-v1", "BIOZERO_OWNER_UPLOAD_CONFIG": str(upload_path)}
        command("upload-genesis", [binaries / "upload-api", "--init-owner-ingress"], settings=upload_env)
        authority = start("authority", [binaries / "ownership-authority", "--config", authority_path])
        upload = start("upload", [binaries / "upload-api"], upload_env)
        ctx_a, ctx_b = client_context(pki, "owner-a"), client_context(pki, "owner-b")
        wait_ready(authority, authority_port, ctx_a, "/healthz")
        wait_ready(upload, upload_port, ctx_a, "/healthz")
        # Observe every CLI delivery/recovery request in both modes. Direct
        # owner-A/B GET controls below use the service itself, bypassing this hop.
        relay = ReceiptRelay(pki, upload_port, evidence, args.ack_loss)
        endpoint_port = relay.port
        client_config = {"schema_version": 1, "authority_url": "https://127.0.0.1:" + str(authority_port),
                         "authority_server_name": "127.0.0.1", "upload_url": "https://127.0.0.1:" + str(endpoint_port),
                         "upload_server_name": "127.0.0.1", "tls_certificate": asset(pki / "owner-a.crt"),
                         "tls_private_key": asset(pki / "owner-a.key"), "authority_ca": asset(pki / "ca.crt"),
                         "upload_ca": asset(pki / "ca.crt"), "encryption_public_key": asset(pki / "worker.pub"),
                         "authority_id": authority_id, "public_key_hex": edpublic[-32:].hex(), "pipeline_mode": "stats",
                         "execution_profile_sha256": profile, "expected_scope": scope, "original_name": "synthetic.fastq"}
        client_path = run / "config/client.json"
        private_json(client_path, client_config)
        plaintext_path = run / "synthetic.fastq"
        private_bytes(plaintext_path, b"@synthetic-owner-upload\nACGTACGTACGTACGT\n+\nIIIIIIIIIIIIIIII\n")
        client_run = run / "state/client"

        def cli(action, expected=0):
            argv = [binaries / "uploader-cli", "--protocol", "owner-v1", "--config", client_path,
                    "--run-dir", client_run, "--action", action]
            if action == "submit":
                argv += ["--file", plaintext_path]
            return command("cli-" + action, argv, expected=expected)

        code, submitted = cli("submit", expected=None if args.ack_loss else 0)
        if args.ack_loss:
            check("causal_ack_loss_after_upstream_receipt", code != 0 and relay.lost.is_set()
                  and len(relay.events) == 1 and relay.events[0]["method"] == "POST" and not relay.errors)
            check("client_intent_retained_before_response_loss", (client_run / "delivery/01-delivering.json").is_file()
                  and not (client_run / "delivery/02-delivered.json").exists())
        else:
            response = exact_json(submitted)
            check("cli_reports_delivered_transport_only", response.get("protocol") == "owner-v1" and response.get("phase") == "delivered")
        operation = exact_json((client_run / "operation/04-accepted.json").read_bytes())
        acceptance_raw = operation["acceptance_json"].encode()
        acceptance = exact_json(acceptance_raw)
        record, binding = acceptance["record"], acceptance["record"]["binding"]
        job = binding["job_id"]
        check("signed_job_is_original_challenge_job", re.fullmatch("[0-9a-f]{16}", job) is not None
              and job == record["challenge"]["claim"]["job_id"]
              and (args.ack_loss or response.get("job_id") == job))
        for name, obj, signature in (("accepted", record, acceptance["signature"]),
                                      ("challenge", record["challenge"]["claim"], record["challenge"]["signature"])):
            private_bytes(evidence / (name + "-signed.bin"), compact(obj))
            private_bytes(evidence / (name + ".sig"), bytes.fromhex(signature))
            openssl("verify-" + name, "pkeyutl", "-verify", "-pubin", "-inkey", pki / "authority-ed.pub", "-rawin",
                    "-in", evidence / (name + "-signed.bin"), "-sigfile", evidence / (name + ".sig"))
        openssl("owner-signing-public", "x509", "-in", pki / "owner-a.crt", "-pubkey", "-noout", "-out", evidence / "owner-signing.pub")
        private_bytes(evidence / "manifest-signed.bin", compact(record["manifest"]["manifest"]))
        private_bytes(evidence / "manifest.sig", bytes.fromhex(record["manifest"]["signature"]))
        openssl("verify-manifest", "dgst", "-sha256", "-verify", evidence / "owner-signing.pub", "-signature", evidence / "manifest.sig",
                "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", evidence / "manifest-signed.bin")
        canonical_acceptance = compact(acceptance)
        acceptance_sha = digest(canonical_acceptance)
        leaf_sha = digest(ssl.PEM_cert_to_DER_cert((pki / "owner-a.crt").read_text()))
        ciphertext = (client_run / "operation/ciphertext.bin").read_bytes()
        envelope = bytes.fromhex(operation["envelope_hex"])
        framed = struct.pack(">I", len(canonical_acceptance)) + canonical_acceptance
        framed += struct.pack(">I", len(envelope)) + envelope + ciphertext
        check("observed_post_is_exact_accepted_bundle", len(relay.events) == 1
              and relay.events[0]["body_sha256"] == digest(framed) and relay.events[0]["body_bytes"] == len(framed))
        check("accepted_external_scope_and_owner_are_pinned", record["authority_id"] == authority_id and record["store_id"] == scope["store_id"]
              and record["policy_sha256"] == scope["policy_sha256"] and binding["credential_sha256"] == leaf_sha
              and binding["execution_profile_sha256"] == profile and binding["pipeline_mode"] == "stats")
        check("exact_original_ciphertext_and_envelope_preserved", ciphertext == (client_run / "delivery/ciphertext.bin").read_bytes()
              and ciphertext == (upload_store / "uploads" / (job + "_synthetic.fastq")).read_bytes()
              and binding["ciphertext_sha256"] == digest(ciphertext) and binding["ciphertext_bytes"] == len(ciphertext)
              and binding["key_envelope_sha256"] == digest(envelope) and len(envelope) == 256)
        # Reconstruct independently from the signed challenge in the exact order
        # of protocol.go CanonicalAAD. This inspects CLI-generated payload bytes;
        # it does not establish that a running worker enforces ownership/AAD.
        claim = record["challenge"]["claim"]
        aad = compact({"schema_version": 1, "domain": "biozero.ownership.aad.v1",
                       "authority_id": claim["authority_id"], "job_id": claim["job_id"],
                       "nonce": claim["nonce"], "credential_sha256": claim["credential_sha256"],
                       "original_name": claim["original_name"], "enc_alg": claim["enc_alg"],
                       "pipeline_mode": claim["pipeline_mode"],
                       "execution_profile_sha256": claim["execution_profile_sha256"]})
        check("canonical_aad_matches_both_signed_digests", digest(aad) == binding["aad_sha256"]
              and digest(aad) == record["manifest"]["manifest"]["aad_sha256"])
        private_bytes(evidence / "accepted-canonical.json", canonical_acceptance)
        private_bytes(evidence / "envelope.bin", envelope)
        private_bytes(evidence / "aad.bin", aad)
        _, inspection = command("inspect-real-cli-payload", [binaries / "owner-upload-verify", "--key", pki / "worker.key",
                                "--ciphertext", client_run / "operation/ciphertext.bin", "--plaintext", plaintext_path,
                                "--aad", evidence / "aad.bin", "--envelope", evidence / "envelope.bin"])
        check("real_cli_payload_decrypts_only_with_signed_aad", inspection == b'{"plaintext_matches":true,"changed_aad_rejected":true}\n')
        stored_job = exact_json((upload_store / "jobs" / (job + ".json")).read_bytes())
        ledger = exact_json((upload_store / "ledger.json").read_bytes())
        ledger_record = ledger["records"][0]
        check("ingress_keeps_authority_job_without_relabel", stored_job["job_id"] == job and stored_job["enc_key"] == envelope.hex()
              and stored_job["ownership_version"] == 1 and stored_job["ownership_acceptance_sha256"] == acceptance_sha
              and ledger_record["job_id"] == job and ledger_record["acceptance_sha256"] == acceptance_sha
              and ledger_record["state"] == "delivered" and ledger_record["envelope_hex"] == envelope.hex()
              and compact(exact_json((upload_store / "acceptances" / (job + ".json")).read_bytes())) == canonical_acceptance
              and len(ledger["records"]) == 1)
        expected_receipt = {"schema_version": 1, "job_id": job, "acceptance_sha256": acceptance_sha,
                            "credential_sha256": leaf_sha, "ciphertext_sha256": digest(ciphertext),
                            "ciphertext_bytes": len(ciphertext), "key_envelope_sha256": digest(envelope), "state": "delivered"}
        before = {"authority": tree_hashes(authority_store), "upload": tree_hashes(upload_store)}
        private_json(evidence / "retained-before-recovery.json", before)
        a_status, a_raw, tls_version = request(upload_port, ctx_a, "GET", "/v1/uploads/" + job)
        b_status, b_raw, _ = request(upload_port, ctx_b, "GET", "/v1/uploads/" + job)
        private_bytes(evidence / "owner-upload-get.json", a_raw)
        private_bytes(evidence / "other-owner-upload-denial.json", b_raw)
        check("upload_owner_a_allowed_owner_b_denied", a_status == 200 and exact_json(a_raw) == expected_receipt
              and set(exact_json(a_raw)) == RECEIPT_FIELDS and b_status == 403 and tls_version == "TLSv1.3")
        a_authority, a_accepted, _ = request(authority_port, ctx_a, "GET", "/v1/jobs/" + job)
        b_authority, b_denied, _ = request(authority_port, ctx_b, "GET", "/v1/jobs/" + job)
        private_bytes(evidence / "owner-authority-get.json", a_accepted)
        private_bytes(evidence / "other-owner-authority-denial.json", b_denied)
        check("authority_owner_a_allowed_owner_b_denied", a_authority == 200 and b_authority == 403
              and compact(exact_json(a_accepted)["acceptance"]) == canonical_acceptance)
        _, status_raw = cli("status", expected=2 if args.ack_loss else 0)
        status_response = exact_json(status_raw)
        check("cold_cli_status_retains_original_job", status_response.get("job_id") == job
              and status_response.get("phase") == ("delivery_pending" if args.ack_loss else "delivered"))
        check("cold_cli_status_performs_no_network", [event["method"] for event in relay.events] == ["POST"])
        # Both explicit cold recovery invocations operate on the same directory.
        # In the loss case only the first may append its observed GET receipt.
        _, recovered_raw = cli("recover-delivery")
        recovered = exact_json(recovered_raw)
        check("cold_cli_recovers_same_delivery", recovered.get("job_id") == job and recovered.get("phase") == "delivered"
              and recovered.get("acceptance_sha256") == acceptance_sha)
        local_before_repeat = tree_hashes(client_run)
        cli("recover-delivery")
        cli("status")
        check("completed_cli_recovery_is_local_and_immutable", tree_hashes(client_run) == local_before_repeat)
        phase2 = exact_json((client_run / "delivery/02-delivered.json").read_bytes())
        check("local_receipt_is_exact_transport_schema", phase2["receipt"] == expected_receipt and set(phase2["receipt"]) == RECEIPT_FIELDS)
        after = {"authority": tree_hashes(authority_store), "upload": tree_hashes(upload_store)}
        private_json(evidence / "retained-after-recovery.json", after)
        check("server_history_and_full_charges_unchanged_by_get", before == after)
        durable_before_shutdown = after
        authority_ledger = exact_json((authority_store / "ledger.json").read_bytes())
        authority_rows = authority_ledger["ledger"]["records"]
        promised_charge = policy["max_body_bytes"] + (128 << 10)
        authority_total = sum(row["charge_bytes"] for row in authority_rows)
        transport_total = sum(row["charge_bytes"] for row in ledger["records"])
        check("one_exact_full_authority_and_transport_charge", len(authority_rows) == 1 and authority_rows[0]["state"] == "accepted"
              and authority_rows[0]["charge_bytes"] == promised_charge and ledger_record["charge_bytes"] == promised_charge
              and authority_total == promised_charge and transport_total == promised_charge)
        report["retained_accounting"] = {"authority_records": len(authority_rows), "authority_charged_bytes": authority_total,
                                         "transport_records": len(ledger["records"]), "transport_charged_bytes": transport_total,
                                         "per_record_full_promise": promised_charge,
                                         "authority_physical_files": physical_file_totals(authority_store),
                                         "transport_physical_files": physical_file_totals(upload_store)}
        check("recovery_only_get_without_ciphertext_repost", not relay.errors
              and [event["method"] for event in relay.events] == (["POST", "GET"] if args.ack_loss else ["POST"])
              and all(event["incoming_credential_sha256"] == leaf_sha
                      and event["upstream_client_credential_sha256"] == leaf_sha for event in relay.events))
        check("runtime_source_snapshot_unchanged", source_inventory() == report["source_hashes"])
        report["config_hashes"] = tree_hashes(run / "config")
        report["final_client_hashes"] = tree_hashes(client_run)
        report["checks_completed"] = True
    except BaseException:
        private_bytes(evidence / "failure.txt", traceback.format_exc().encode())
        report["checks_completed"] = False
    finally:
        cleanup_ok = True
        if relay:
            try:
                relay.close()
            except BaseException:
                cleanup_ok = False
                private_bytes(evidence / "relay-cleanup-failure.txt", traceback.format_exc().encode())
        # Only exact Popen children from this invocation receive signals. Never
        # use names, stale PID files, pkill, port owners, or unrelated sessions.
        for proc in reversed(children):
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
        for proc, entry in zip(children, report["processes"]):
            try:
                code = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cleanup_ok = False
                proc.kill()
                code = proc.wait(timeout=5)
                entry["forced_kill"] = True
            entry["returncode"] = code
            if code != 0:
                cleanup_ok = False
        for handle in handles:
            handle.flush(); os.fsync(handle.fileno()); handle.close()
        try:
            # Capture final source pins even when build/startup/assertion fails.
            # Never relabel an attempt after another agent changes its sources.
            final_source = source_inventory()
            private_json(evidence / "source-hashes-final.json", final_source)
            report["final_source_hashes"] = final_source
            report["source_unchanged_through_cleanup"] = final_source == report.get("source_hashes")
            cleanup_ok = cleanup_ok and report["source_unchanged_through_cleanup"]
        except BaseException:
            cleanup_ok = False
            private_bytes(evidence / "final-source-pin-failure.txt", traceback.format_exc().encode())
        if durable_before_shutdown is not None:
            try:
                stopped_history = {"authority": tree_hashes(run / "state/authority"),
                                   "upload": tree_hashes(run / "state/upload")}
                private_json(evidence / "retained-after-wait.json", stopped_history)
                report["history_unchanged_after_shutdown"] = stopped_history == durable_before_shutdown
                cleanup_ok = cleanup_ok and report["history_unchanged_after_shutdown"]
            except BaseException:
                cleanup_ok = False
                private_bytes(evidence / "shutdown-history-failure.txt", traceback.format_exc().encode())
        report["cleanup_clean_wait"] = cleanup_ok
        report["status"] = "passed" if report.get("checks_completed") and cleanup_ok else "failed"
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        save()
        # No private identifier, credential, key, route, directory or body is
        # printed. Public documentation needs an independently reviewed export.
        print(json.dumps({"status": report["status"], "checks": len(report["cases"]),
                          "passed": sum(case["passed"] for case in report["cases"]),
                          "scope": "owner_upload_transport", "ack_loss": args.ack_loss}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # Failure before a private evidence root exists cannot retain a private
        # traceback. Do not print raw configuration paths or private identifiers.
        print('{"status":"failed","scope":"owner_upload_transport","setup_error":true}')
        raise SystemExit(1)
