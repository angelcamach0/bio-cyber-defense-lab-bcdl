#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Opt-in real native owner upload -> protected worker -> V3 broker -> capsule.

Uses cached local tools only. Builds fresh by default; explicit private build
receipt reuse verifies complete Go/module inputs and copies eight pinned binaries
without compilation, retaining their original provenance. Retains all private
attempts, keys, workspaces and logs. No Results service, gateway, Docker, download or biological model is run.
The private worker cache is observability, never result authorization. This is
same-host synthetic acceptance, not deployment isolation or clinical accuracy.
"""

import argparse
import array
import ctypes
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import time
import traceback

from run_owner_upload import (ROOT, client_context, compact, digest, exact_json,
                              free_port, private_bytes, private_json, request,
                              sha, sync_dir, tree_hashes)


FIXTURE = ROOT / "biozero/bio/fixtures/variant-smoke"
ARTIFACT_IDS = {"execution_receipt", "normalized_vcf", "variants_vcf", "variants_vcf_index"}
BUILD_NAMES = {"ownership-authority", "upload-api", "uploader-cli", "artifact-owner-broker",
               "enclave-runner", "worker-scope", "capsule-analysis", "payload-inspector"}


def stable_stat(value):
    # Reading may update atime; it must not change identity/content metadata.
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def anchored_directory(path, private=False):
    if not path.is_absolute() or path != Path(os.path.abspath(path)) or path == Path("/"):
        raise ValueError("reuse path is not absolute and normalized")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = next_fd
        info = os.fstat(fd)
        if private and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("reuse directory is not private")
        return fd
    except BaseException:
        os.close(fd)
        raise


def private_snapshot(path, limit):
    parent = anchored_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.geteuid()
                or before.st_nlink != 1 or not 0 <= before.st_size <= limit):
            raise ValueError("reuse evidence is not a bounded private regular file")
        chunks, count = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - count))
            if not chunk:
                break
            chunks.append(chunk); count += len(chunk)
            if count > limit:
                raise ValueError("reuse evidence exceeds bound")
        if count != before.st_size or stable_stat(before) != stable_stat(os.fstat(fd)):
            raise ValueError("reuse evidence changed while reading")
        return b"".join(chunks)
    finally:
        os.close(fd)


def reuse_builds(report_path, current_inputs, bins, evidence):
    """Explicit verified copy only; failure never falls back to compilation."""
    raw_report = private_snapshot(report_path, 16 << 20)
    previous = exact_json(raw_report)
    if (previous.get("schema_version") != 1 or previous.get("go_module_inputs") != current_inputs
            or previous.get("source_unchanged") is not True or set(previous.get("binary_pins", {})) != BUILD_NAMES):
        raise ValueError("reuse source inventory or binary set differs")
    final_inputs = {name: value for name, value in previous.get("final_source_hashes", {}).items()
                    if name.endswith(".go") or Path(name).name in ("go.mod", "go.sum", "go.work", "go.work.sum")}
    if final_inputs != current_inputs:
        raise ValueError("original build ended with changed Go/module sources")
    runtime_path = Path(previous["runtime_root"])
    root_fd = anchored_directory(runtime_path, private=True)
    try:
        source_fd = os.open("bin", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=root_fd)
    finally:
        os.close(root_fd)
    copies = {}
    try:
        directory_before = os.fstat(source_fd)
        if (directory_before.st_uid != os.geteuid() or stat.S_IMODE(directory_before.st_mode) != 0o700
                or set(os.listdir(source_fd)) != BUILD_NAMES or list(bins.iterdir())):
            raise ValueError("reuse binary directory has unexpected metadata or names")
        for name in sorted(BUILD_NAMES):
            pin = previous["binary_pins"][name]
            if (set(pin) != {"sha256", "bytes"} or not isinstance(pin["sha256"], str)
                    or re.fullmatch("[0-9a-f]{64}", pin["sha256"]) is None or type(pin["bytes"]) is not int or pin["bytes"] < 1):
                raise ValueError("reuse binary pin is invalid")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=source_fd)
            try:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o700 or before.st_uid != os.geteuid()
                        or before.st_nlink != 1 or before.st_size != pin["bytes"]):
                    raise ValueError("reuse executable metadata differs")

                def source_hash():
                    os.lseek(fd, 0, os.SEEK_SET)
                    hashed, count = hashlib.sha256(), 0
                    while True:
                        chunk = os.read(fd, 65536)
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > pin["bytes"]:
                            raise ValueError("reuse executable grew")
                        hashed.update(chunk)
                    if count != pin["bytes"]:
                        raise ValueError("reuse executable is truncated")
                    return hashed.hexdigest()

                before_hash = source_hash()
                if before_hash != pin["sha256"] or stable_stat(before) != stable_stat(os.fstat(fd)):
                    raise ValueError("reuse executable source pin differs")
                target_fd = os.open(bins / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o700)
                try:
                    os.fchmod(target_fd, 0o700)
                    os.lseek(fd, 0, os.SEEK_SET)
                    copied, copied_hash = 0, hashlib.sha256()
                    while True:
                        chunk = os.read(fd, 65536)
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > pin["bytes"]:
                            raise ValueError("reuse source grew during copy")
                        copied_hash.update(chunk)
                        pending = memoryview(chunk)
                        while pending:
                            written = os.write(target_fd, pending)
                            if written <= 0:
                                raise ValueError("reuse copy write failed")
                            pending = pending[written:]
                    os.fsync(target_fd)
                    target = os.fstat(target_fd)
                    if (copied != pin["bytes"] or copied_hash.hexdigest() != pin["sha256"] or target.st_size != pin["bytes"]
                            or stat.S_IMODE(target.st_mode) != 0o700 or target.st_uid != os.geteuid() or target.st_nlink != 1):
                        raise ValueError("reuse copy does not match pin")
                finally:
                    os.close(target_fd)
                after_hash = source_hash()
                after = os.fstat(fd)
                if before_hash != after_hash or stable_stat(before) != stable_stat(after) or sha(bins / name) != pin["sha256"]:
                    raise ValueError("reuse executable changed during copy")
                copies[name] = {"sha256_before": before_hash, "sha256_after": after_hash,
                                "source_stat_before": stable_stat(before), "source_stat_after": stable_stat(after), "bytes": copied}
            finally:
                os.close(fd)
        if set(os.listdir(source_fd)) != BUILD_NAMES or stable_stat(directory_before) != stable_stat(os.fstat(source_fd)):
            raise ValueError("reuse binary directory changed")
        if {path.name for path in bins.iterdir()} != BUILD_NAMES:
            raise ValueError("copied executable set differs")
        sync_dir(bins)
    finally:
        os.close(source_fd)
    private_bytes(evidence / "original-build-report.json", raw_report)
    build_commands = [entry for entry in previous.get("commands", []) if entry["name"].startswith("build-info-")]
    if {entry["name"].removeprefix("build-info-") for entry in build_commands} != BUILD_NAMES or len(build_commands) != len(BUILD_NAMES):
        raise ValueError("original build metadata set is incomplete")
    metadata = {}
    for entry in build_commands:
        if entry.get("returncode") != 0:
            raise ValueError("original build metadata command failed")
        name = entry["name"].removeprefix("build-info-")
        metadata[name] = {}
        for stream in ("stdout", "stderr"):
            raw = private_snapshot(Path(entry[stream]), 1 << 20)
            private_bytes(evidence / ("original-build-info-" + name + "." + stream), raw)
            metadata[name][stream + "_sha256"] = digest(raw)
    return {"report_sha256": digest(raw_report), "report_path": str(report_path), "original_runtime_root": str(runtime_path),
            "original_commit": previous["commit"], "original_dirty": previous["dirty"], "original_status": previous["status"],
            "original_started_at": previous["started_at"], "original_binary_pins": previous["binary_pins"],
            "original_build_metadata": metadata, "copies": copies}


def canonical_aad(claim):
    return compact({"schema_version": 1, "domain": "biozero.ownership.aad.v1",
                    **{key: claim[key] for key in ("authority_id", "job_id", "nonce", "credential_sha256",
                                                   "original_name", "enc_alg", "pipeline_mode", "execution_profile_sha256")}})


def snps(raw):
    result = set()
    for line in raw.decode("ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) < 8 or len(fields[3]) != 1 or len(fields[4]) != 1:
            raise ValueError("synthetic truth must contain normalized single SNPs")
        result.add((fields[0], int(fields[1]), fields[3], fields[4]))
    return result


class StageWatch:
    """Real inotify over the worker's mounted tmpfs, with positive controls."""

    def __init__(self, path):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.inotify_init1.argtypes = [ctypes.c_int]
        self.libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self.fd = self.libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify initialization failed")
        # Mutations only: observer reads must not look like staging activity.
        self.mask = 0x00000002 | 0x00000004 | 0x00000008 | 0x00000040 | 0x00000080 | 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800
        self.watch = self.libc.inotify_add_watch(self.fd, os.fsencode(path), self.mask)
        if self.watch < 0:
            os.close(self.fd)
            raise OSError(ctypes.get_errno(), "inotify watch failed")

    def drain(self):
        result = []
        while True:
            try:
                raw = os.read(self.fd, 65536)
            except BlockingIOError:
                break
            offset = 0
            while offset < len(raw):
                if len(raw) - offset < 16:
                    raise ValueError("inotify event is truncated")
                watch, mask, cookie, length = struct.unpack_from("iIII", raw, offset)
                if offset + 16 + length > len(raw) or mask & 0x00004000 or mask & 0x00008000:
                    raise ValueError("inotify overflow or lost watch")
                name = os.fsdecode(raw[offset + 16:offset + 16 + length].split(b"\0", 1)[0])
                result.append({"watch": watch, "mask": mask, "cookie": cookie, "name": name})
                offset += 16 + length
        return result

    def close(self):
        os.close(self.fd)


def broker_read(socket_path, broker_pid, query):
    """Independent bounded V3 query/receipt FD reader. Never submits/cancels."""
    if query["operation"] not in ("status", "receipt"):
        raise ValueError("fixture reader cannot mutate broker")
    received = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(20)
        conn.connect(str(socket_path))
        pid, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid != broker_pid or uid != os.geteuid():
            raise ValueError("unexpected broker peer")
        raw = compact(query)
        conn.sendall(struct.pack(">I", len(raw)) + raw)
        first = True

        def read_exact(length):
            nonlocal first
            chunks = []
            while length:
                data, controls, flags, _ = conn.recvmsg(min(length, 65536), socket.CMSG_SPACE(16), socket.MSG_CMSG_CLOEXEC)
                rights = []
                invalid_control = False
                for level, kind, value in controls:
                    if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                        invalid_control = True
                        continue
                    values = array.array("i")
                    values.frombytes(value[:len(value) - len(value) % values.itemsize])
                    rights.extend(values)
                received.extend(rights)
                if invalid_control or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) or not data or len(received) > 1 or (not first and rights):
                    raise ValueError("invalid broker frame/FD placement")
                first = False
                chunks.append(data)
                length -= len(data)
            return b"".join(chunks)

        try:
            header = read_exact(1) + read_exact(3)
            length, = struct.unpack(">I", header)
            if not 1 <= length <= 65536:
                raise ValueError("broker frame exceeds64KiB")
            wire = read_exact(length)
            extra, controls, flags, _ = conn.recvmsg(1, socket.CMSG_SPACE(16), socket.MSG_CMSG_CLOEXEC)
            for level, kind, value in controls:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    values = array.array("i"); values.frombytes(value[:len(value) - len(value) % values.itemsize]); received.extend(values)
            if extra or controls or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC):
                raise ValueError("broker sent trailing bytes/rights")
            response = exact_json(wire)
            payload = None
            if query["operation"] == "receipt":
                if len(received) != 1:
                    raise ValueError("receipt descriptor is absent")
                fd = received[0]
                before = os.fstat(fd)
                size = response["execution"]["receipt_bytes"]
                if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.geteuid()
                        or before.st_nlink != 1 or before.st_size != size or not 0 <= size <= 16 << 20
                        or fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
                        or not fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC):
                    raise ValueError("unsafe receipt descriptor")
                chunks, offset = [], 0
                while offset < size:
                    chunk = os.pread(fd, min(65536, size - offset), offset)
                    if not chunk:
                        raise ValueError("short receipt descriptor")
                    chunks.append(chunk); offset += len(chunk)
                payload = b"".join(chunks)
                after = os.fstat(fd)
                if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                        or digest(payload) != response["execution"]["receipt_sha256"]):
                    raise ValueError("receipt changed or digest differs")
            elif received:
                raise ValueError("status returned descriptor")
            return response, payload
        finally:
            for fd in received:
                os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path, help="new private retained evidence root")
    parser.add_argument("--tools-prefix", required=True, type=Path, help="existing ARM tool installation; never installs")
    parser.add_argument("--reuse-build-report", type=Path, help="explicit private original build receipt; verify/copy eight binaries without rebuilding")
    args = parser.parse_args()
    if os.getuid() != 1000 or os.getgid() != 1000:
        parser.error("native worker scope requires UID/GID1000")
    if platform.machine() != "aarch64":
        parser.error("this acceptance requires the existing ARM64 tool installation")
    if not args.run_dir.is_absolute() or args.run_dir != Path(os.path.abspath(args.run_dir)):
        parser.error("run directory must be absolute and normalized")
    if args.reuse_build_report is not None and (not args.reuse_build_report.is_absolute()
                                              or args.reuse_build_report != Path(os.path.abspath(args.reuse_build_report))):
        parser.error("reuse report must be an absolute normalized private path")
    os.umask(0o077)
    run = args.run_dir.parent.resolve(strict=True) / args.run_dir.name
    run.mkdir(mode=0o700, exist_ok=False); sync_dir(run.parent)
    runtime = Path("/tmp") / ("bz-owner-" + secrets.token_hex(6))
    runtime.mkdir(mode=0o700, exist_ok=False); sync_dir(runtime.parent)
    for name in ("logs", "evidence"):
        (run / name).mkdir(mode=0o700)
    for name in ("bin", "pki", "config", "host", "worker", "client", "plaintext"):
        (runtime / name).mkdir(mode=0o700)
    bins, pki, host, worker_root = [runtime / name for name in ("bin", "pki", "host", "worker")]
    logs, evidence = run / "logs", run / "evidence"
    tools = args.tools_prefix.resolve(strict=True)
    env = {**os.environ, "GOMAXPROCS": "1", "GOFLAGS": "-p=1", "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "CGO_ENABLED": "0"}
    env["PATH"] = str(tools / "bin") + ":" + env.get("PATH", "")
    report = {"schema_version": 1, "status": "failed", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "native synthetic owner authority/upload/worker-v3/broker-v3/capsule; private cache only; no Results/gateway/deployment/clinical claim",
              "runtime_root": str(runtime), "cases": [], "commands": [], "processes": []}
    children, handles, watch = [], [], None
    counter, api_counter = 0, 0
    stable_history = None

    def save():
        private_json(run / "report.json", report, replace=(run / "report.json").exists())

    def check(name, passed, observed=None):
        report["cases"].append({"case": name, "passed": bool(passed), "observed": observed or {}})
        save()
        if not passed:
            raise RuntimeError("acceptance assertion failed: " + name)

    def command(name, argv, cwd=ROOT, settings=None, expected=0, timeout=180):
        nonlocal counter
        prefix = logs / ("%03d-%s" % (counter, name)); counter += 1
        stdout, stderr = prefix.with_suffix(".stdout").open("xb"), prefix.with_suffix(".stderr").open("xb")
        entry = {"name": name, "argv": [str(x) for x in argv], "cwd": str(cwd), "stdout": str(stdout.name), "stderr": str(stderr.name)}
        report["commands"].append(entry); save()
        try:
            completed = subprocess.run([str(x) for x in argv], cwd=cwd, env={**env, **(settings or {})}, stdout=stdout, stderr=stderr, timeout=timeout)
            entry["returncode"] = completed.returncode
        except BaseException:
            entry["exception"] = traceback.format_exc(); raise
        finally:
            stdout.flush(); stderr.flush(); os.fsync(stdout.fileno()); os.fsync(stderr.fileno()); stdout.close(); stderr.close(); save()
        if expected is not None and completed.returncode != expected:
            raise RuntimeError("fixture command failed: " + name)
        return completed.returncode, Path(entry["stdout"]).read_bytes()

    def openssl(name, *argv, expected=0):
        return command(name, ["openssl", *argv], expected=expected)

    def api(name, port, ctx, method, route, body=None, headers=None):
        nonlocal api_counter
        code, raw, version = request(port, ctx, method, route, body, headers)
        prefix = "%03d-%s" % (api_counter, name); api_counter += 1
        private_bytes(evidence / (prefix + ".body"), raw)
        private_json(evidence / (prefix + ".json"), {"method": method, "route": route, "status": code, "tls": version,
                                                     "request_bytes": len(body or b""), "request_sha256": digest(body or b""), "response_sha256": digest(raw)})
        if version != "TLSv1.3":
            raise ValueError("TLS1.3 required")
        return code, raw

    def start(name, argv, settings=None):
        stdout, stderr = (logs / (name + ".stdout")).open("xb"), (logs / (name + ".stderr")).open("xb")
        handles.extend((stdout, stderr))
        proc = subprocess.Popen([str(x) for x in argv], cwd=ROOT, env={**env, **(settings or {})}, stdout=stdout, stderr=stderr, start_new_session=True)
        children.append(proc); report["processes"].append({"name": name, "pid": proc.pid, "returncode": None}); save()
        return proc

    def wait_for(test, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(proc.poll() is not None for proc in children):
                raise RuntimeError("owned service exited before fixture completion")
            if test():
                return
            time.sleep(0.05)
        raise RuntimeError("fixture observation deadline expired")

    def inventory():
        _, raw = command("source-list", ["git", "ls-files", "-z", "-co", "--exclude-standard"])
        paths = [ROOT / os.fsdecode(value) for value in raw.split(b"\0") if value]
        return {str(path.relative_to(ROOT)): sha(path) for path in sorted(set(paths)) if path.is_file() and not path.is_relative_to(run)}

    def asset(path):
        return {"path": str(path), "sha256": sha(path)}

    def retained():
        return {name: tree_hashes(path) for name, path in (("store", host / "s"), ("broker", host / "j"), ("worker", worker_root / "custody"))}

    def verify_signed(label, signed, public, field):
        private_bytes(evidence / (label + ".signed"), compact(signed[field]))
        private_bytes(evidence / (label + ".sig"), bytes.fromhex(signed["signature"]))
        openssl("verify-" + label, "pkeyutl", "-verify", "-pubin", "-inkey", public, "-rawin", "-in", evidence / (label + ".signed"), "-sigfile", evidence / (label + ".sig"))

    try:
        for name in ("go", "openssl", "python3", "fastp", "minimap2", "samtools", "bcftools"):
            if shutil.which(name, path=env["PATH"]) is None:
                raise RuntimeError("required existing tool unavailable")
        for name in ("fastp", "minimap2", "samtools", "bcftools"):
            selected = Path(shutil.which(name, path=env["PATH"])).resolve()
            if not selected.is_relative_to(tools):
                raise RuntimeError("selected bioinformatics executable is outside the supplied tool prefix")
        _, raw = command("commit", ["git", "rev-parse", "HEAD"]); report["commit"] = raw.decode().strip()
        _, raw = command("worktree", ["git", "status", "--porcelain"]); report["dirty"] = bool(raw)
        report["source_hashes"] = inventory()
        report["go_module_inputs"] = {name: value for name, value in report["source_hashes"].items() if name.endswith(".go") or Path(name).name in ("go.mod", "go.sum", "go.work", "go.work.sum")}
        private_json(evidence / "go-module-inputs.json", report["go_module_inputs"])
        report["fixture_pins"] = {name: {"sha256": sha(FIXTURE / name), "bytes": (FIXTURE / name).stat().st_size} for name in ("reads.fastq", "invalid.fastq", "reference.fa", "expected.vcf")}
        report["tool_pins"] = {}
        for name, flags in (("go", ["version"]), ("openssl", ["version"]), ("fastp", ["--version"]), ("minimap2", ["--version"]), ("samtools", ["--version"]), ("bcftools", ["--version"])):
            path = Path(shutil.which(name, path=env["PATH"])).resolve()
            code, raw = command("version-" + name, [path, *flags], expected=None)
            report["tool_pins"][name] = {"path": str(path), "sha256": sha(path), "bytes": path.stat().st_size, "version_command_exit": code}
        services = ROOT / "biozero/services"
        if args.reuse_build_report is not None:
            report["build_mode"] = "explicit_verified_reuse"
            report["reused_builds"] = reuse_builds(args.reuse_build_report, report["go_module_inputs"], bins, evidence)
        else:
            report["build_mode"] = "fresh_compile"
            for name, module, package in (("ownership-authority", "ownership-authority", "./cmd/ownership-authority"), ("upload-api", "upload-api", "."),
                                          ("uploader-cli", "uploader-cli", "."), ("artifact-owner-broker", "artifact-executor", "./cmd/artifact-owner-broker"),
                                          ("enclave-runner", "enclave-runner", "."), ("worker-scope", "enclave-runner", "./cmd/worker-scope"),
                                          ("capsule-analysis", "enclave-runner", "./cmd/capsule-analysis")):
                command("build-" + name, ["go", "build", "-o", bins / name, package], cwd=services / module)
            command("build-payload-inspector", ["go", "build", "-o", bins / "payload-inspector", ROOT / "biozero/infra/native/owner_upload_verify/main.go"])
        report["binary_pins"] = {path.name: {"sha256": sha(path), "bytes": path.stat().st_size} for path in bins.iterdir()}
        for path in bins.iterdir():
            command("build-info-" + path.name, ["go", "version", "-m", path])
        check("build_snapshot_unchanged", inventory() == report["source_hashes"])

        openssl("ca-key", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", pki / "ca.key")
        openssl("ca-cert", "req", "-new", "-x509", "-sha256", "-key", pki / "ca.key", "-out", pki / "ca.crt", "-days", "2", "-subj", "/CN=owner-worker-fixture-ca", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        for serial, role in enumerate(("authority", "upload", "owner-a", "owner-b"), 2):
            server = role in ("authority", "upload")
            openssl(role + "-key", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", pki / (role + ".key"))
            openssl(role + "-csr", "req", "-new", "-sha256", "-key", pki / (role + ".key"), "-out", pki / (role + ".csr"), "-subj", "/CN=" + role)
            extension = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=" + ("serverAuth\nsubjectAltName=IP:127.0.0.1\n" if server else "clientAuth\n")
            private_bytes(pki / (role + ".ext"), extension.encode())
            openssl(role + "-cert", "x509", "-req", "-sha256", "-in", pki / (role + ".csr"), "-CA", pki / "ca.crt", "-CAkey", pki / "ca.key", "-set_serial", str(serial), "-days", "2", "-extfile", pki / (role + ".ext"), "-out", pki / (role + ".crt"))
            openssl(role + "-purpose", "verify", "-CAfile", pki / "ca.crt", "-purpose", "sslserver" if server else "sslclient", pki / (role + ".crt"))
            wrong, _ = openssl(role + "-reject-other-purpose", "verify", "-CAfile", pki / "ca.crt", "-purpose", "sslclient" if server else "sslserver", pki / (role + ".crt"), expected=None)
            check("separate_tls_eku_" + role, wrong != 0)
        openssl("recipient-key", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", pki / "recipient.key")
        openssl("recipient-public", "pkey", "-in", pki / "recipient.key", "-pubout", "-out", pki / "recipient.pub")
        openssl("authority-signing", "genpkey", "-algorithm", "ED25519", "-out", pki / "signing.pem")
        openssl("authority-signing-der", "pkey", "-in", pki / "signing.pem", "-outform", "DER", "-out", pki / "signing.der")
        openssl("authority-public-der", "pkey", "-in", pki / "signing.pem", "-pubout", "-outform", "DER", "-out", pki / "signing-public.der")
        openssl("authority-public", "pkey", "-in", pki / "signing.pem", "-pubout", "-out", pki / "signing.pub")
        private_der, public_der = (pki / "signing.der").read_bytes(), (pki / "signing-public.der").read_bytes()
        check("exact_ed25519_encoding", len(private_der) == 48 and private_der[:16].hex() == "302e020100300506032b657004220420" and len(public_der) == 44 and public_der[:12].hex() == "302a300506032b6570032100")
        private_bytes(pki / "signing.raw", private_der[-32:] + public_der[-32:])
        report["pki_pins"] = tree_hashes(pki)
        authority_id = secrets.token_hex(16)
        capsule = services / "artifact-executor/capsule"
        assets = {"native_helper": capsule / "native_capsule.py", "pipeline": ROOT / "biozero/bio/pipeline/pipeline.py", "resource_budget": ROOT / "biozero/bio/pipeline/resource_budget.py", "reference": FIXTURE / "reference.fa", "evaluator": ROOT / "biozero/bio/benchmarks/evaluate_variants.py", "truth": FIXTURE / "expected.vcf", "analysis_executable": bins / "capsule-analysis", "analysis_rules": ROOT / "biozero/bio/reference-db/rules.json", "analysis_panel": FIXTURE / "reference.fa"}
        execution = {"schema_version": 1, "provider": "native", "mode": "variants", "store_root": str(host / "s"), "journal_root": str(host / "j"), "workspace_root": str(host / "w"), "socket_path": str(host / "c/b.sock"), "allowed_uid": os.getuid(), "timeout_seconds": 60, "python_path": str(Path("/usr/bin/python3").resolve()), "tool_path": str(tools / "bin") + ":/usr/bin", "docker_command": [], "image_id": "", "container_helper": {"path": "", "sha256": ""}, **{name: asset(path) for name, path in assets.items()}}
        broker_config = {"schema_version": 1, "execution": execution, "authority_id": authority_id, "public_key_hex": public_der[-32:].hex(), "expected_scope": {"store_id": "", "policy_sha256": ""}}
        broker_path = runtime / "config/broker.json"; private_json(broker_path, broker_config)
        _, raw = command("owner-profile", [bins / "artifact-owner-broker", "--config", broker_path, "--print-profile"])
        profile = raw.decode().strip()
        check("profile_before_scope_without_state", bool(re.fullmatch("[0-9a-f]{64}", profile)) and raw == (profile + "\n").encode() and not (host / "s").exists() and not (host / "j").exists())
        report["profile_sha256"] = profile
        authority_port, upload_port = free_port(), free_port()
        while authority_port == upload_port:
            upload_port = free_port()
        policy = {"max_jobs": 64, "max_principal_jobs": 16, "max_bytes": 512 << 20, "max_principal_bytes": 128 << 20, "max_active": 2, "max_principal_active": 1, "max_body_bytes": 25 << 20, "free_space_floor_bytes": 0, "challenge_ttl_seconds": 300}
        authority_store, upload_store = runtime / "authority", runtime / "upload"
        authority_config = {"schema_version": 1, "listen_address": "127.0.0.1:" + str(authority_port), "store_root": str(authority_store), "namespace": "owner-worker-authority", "authority_id": authority_id, "public_key_hex": public_der[-32:].hex(), "pipeline_mode": "variants", "execution_profile_sha256": profile, "signing_key": asset(pki / "signing.raw"), "tls_certificate": asset(pki / "authority.crt"), "tls_private_key": asset(pki / "authority.key"), "client_ca": asset(pki / "ca.crt"), "policy": policy, "expected_scope": {"store_id": "", "policy_sha256": ""}}
        authority_path = runtime / "config/authority.json"; private_json(authority_path, authority_config)
        _, raw = command("authority-genesis", [bins / "ownership-authority", "--config", authority_path, "--init-store"])
        scope = exact_json(raw); private_bytes(evidence / "genesis-scope.json", raw)
        check("scope_from_real_authority_genesis", set(scope) == {"store_id", "policy_sha256"} and bool(re.fullmatch("[0-9a-f]{32}", scope["store_id"])) and bool(re.fullmatch("[0-9a-f]{64}", scope["policy_sha256"])))
        authority_config["expected_scope"] = scope; private_json(authority_path, authority_config, replace=True)
        broker_config["expected_scope"] = scope; private_json(broker_path, broker_config, replace=True)
        _, raw = command("owner-profile-after-scope", [bins / "artifact-owner-broker", "--config", broker_path, "--print-profile"])
        check("scope_does_not_change_execution_profile", raw == (profile + "\n").encode())
        command("broker-genesis", [bins / "artifact-owner-broker", "--config", broker_path, "--init-owner-broker"])
        upload_config = {"schema_version": 1, "listen_address": "127.0.0.1:" + str(upload_port), "store_root": str(upload_store), "namespace": "owner-worker-transport", "authority_id": authority_id, "public_key_hex": public_der[-32:].hex(), "pipeline_mode": "variants", "execution_profile_sha256": profile, "expected_scope": scope, "policy": {name: value for name, value in policy.items() if name != "challenge_ttl_seconds"}, "tls_certificate": asset(pki / "upload.crt"), "tls_private_key": asset(pki / "upload.key"), "client_ca": asset(pki / "ca.crt")}
        upload_path = runtime / "config/upload.json"; private_json(upload_path, upload_config)
        upload_env = {"BIOZERO_UPLOAD_PROTOCOL": "owner-v1", "BIOZERO_OWNER_UPLOAD_CONFIG": str(upload_path)}
        command("upload-genesis", [bins / "upload-api", "--init-owner-ingress"], settings=upload_env)
        (worker_root / "results").mkdir(mode=0o700); (worker_root / "stage").mkdir(mode=0o700)
        pins = {name: {"sha256": sha(path), "bytes": path.stat().st_size} for name, path in assets.items() if name != "native_helper"}
        projection_path = runtime / "config/projection.json"; private_json(projection_path, {"schema_version": 1, "profile_sha256": profile, "pipeline_mode": "variants", "capsule_kind": "native", "source_pins": pins})
        worker_config = {"schema_version": 1, "protocol": "owner-v1", "socket": execution["socket_path"], "jobs_directory": str(upload_store / "jobs"), "uploads_directory": str(upload_store / "uploads"), "acceptances_directory": str(upload_store / "acceptances"), "results_directory": str(worker_root / "results"), "stage_directory": str(worker_root / "stage"), "custody_directory": str(worker_root / "custody"), "authority_id": authority_id, "public_key_hex": public_der[-32:].hex(), "pipeline_mode": "variants", "execution_profile_sha256": profile, "expected_scope": scope, "decryption_key": asset(pki / "recipient.key"), "projection_policy": asset(projection_path), "poll_milliseconds": 100, "timeout_seconds": 90}
        worker_path = runtime / "config/worker.json"; private_json(worker_path, worker_config)
        worker_env = {"BIOZERO_WORKER_PROTOCOL": "owner-v1", "BIOZERO_OWNER_WORKER_CONFIG": str(worker_path), "BIOZERO_SECURITY_MODE": "protected", "BIOZERO_EXECUTION_BACKEND": "capsule"}
        command("worker-genesis", [bins / "enclave-runner", "--init-owner-worker"], settings=worker_env)
        authority = start("authority", [bins / "ownership-authority", "--config", authority_path])
        upload = start("upload", [bins / "upload-api"], upload_env)
        broker = start("broker", [bins / "artifact-owner-broker", "--config", broker_path])
        ctx_a, ctx_b = client_context(pki, "owner-a"), client_context(pki, "owner-b")
        for port in (authority_port, upload_port):
            def healthy(port=port):
                try:
                    return request(port, ctx_a, "GET", "/healthz")[0] == 200
                except (OSError, http.client.HTTPException):
                    return False
            wait_for(healthy)
        wait_for(lambda: Path(execution["socket_path"]).is_socket())
        launcher = start("worker", [bins / "worker-scope", "--worker", bins / "enclave-runner", "--worker-sha256", sha(bins / "enclave-runner"), "--tmpfs", worker_root / "stage"], worker_env)
        wait_for(lambda: b"owner_worker_ready\n" in (logs / "worker.stdout").read_bytes())
        descendants = set()
        for task in Path("/proc/%d/task" % launcher.pid).iterdir():
            descendants.update(int(pid) for pid in (task / "children").read_text().split())
        check("owned_worker_child_is_unambiguous", len(descendants) == 1)
        worker_pid = next(iter(descendants))
        stage_view = Path("/proc/%d/root" % worker_pid) / str(worker_root / "stage").lstrip("/")
        selected_environment = {}
        for pair in Path("/proc/%d/environ" % worker_pid).read_bytes().split(b"\0"):
            key, separator, value = pair.partition(b"=")
            if separator and key in (b"BIOZERO_DECRYPT_DIR", b"BIOZERO_WORKER_PROTOCOL", b"BIOZERO_OWNER_WORKER_CONFIG"):
                selected_environment[key.decode()] = os.fsdecode(value)
        stage_stat = stage_view.stat()
        selected_path = Path("/proc/%d/root" % worker_pid) / selected_environment.get("BIOZERO_DECRYPT_DIR", "missing").lstrip("/")
        selected_stat = selected_path.stat()
        check("launcher_stage_selection_matches_pinned_owner_config", selected_environment.get("BIOZERO_WORKER_PROTOCOL") == "owner-v1"
              and selected_environment.get("BIOZERO_OWNER_WORKER_CONFIG") == str(worker_path)
              and selected_environment.get("BIOZERO_DECRYPT_DIR") == worker_config["stage_directory"]
              and (selected_stat.st_dev, selected_stat.st_ino) == (stage_stat.st_dev, stage_stat.st_ino)
              and stat.S_IMODE(stage_stat.st_mode) == 0o700 and stage_stat.st_uid == os.getuid())
        filesystem = os.statvfs(stage_view)
        status = dict(line.split(":", 1) for line in Path("/proc/%d/status" % worker_pid).read_text().splitlines() if ":" in line)
        mounts = [line for line in Path("/proc/%d/mountinfo" % worker_pid).read_text().splitlines() if line.split()[4] == str(worker_root / "stage")]
        check("worker_stage_real_tmpfs_and_privilege_guards", len(mounts) == 1 and " - tmpfs " in mounts[0] and filesystem.f_blocks * filesystem.f_frsize == 32 << 20 and filesystem.f_files == 4096 and filesystem.f_flag & 14 == 14 and status["NoNewPrivs"].strip() == "1" and all(status[name].strip() == "0000000000000000" for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")))
        report["worker_stage_observation"] = {"pid": worker_pid, "capacity_bytes": filesystem.f_blocks * filesystem.f_frsize, "inode_units": filesystem.f_files, "mountinfo": mounts,
                                               "config_sha256": sha(worker_path), "selected_environment": selected_environment,
                                               "stat": {"device": stage_stat.st_dev, "inode": stage_stat.st_ino, "mode": stage_stat.st_mode, "uid": stage_stat.st_uid, "gid": stage_stat.st_gid},
                                               "namespace_ids": {name: os.readlink("/proc/%d/ns/%s" % (worker_pid, name)) for name in ("user", "mnt", "net")}}
        watch = StageWatch(stage_view)
        client_config = {"schema_version": 1, "authority_url": "https://127.0.0.1:" + str(authority_port), "authority_server_name": "127.0.0.1", "upload_url": "https://127.0.0.1:" + str(upload_port), "upload_server_name": "127.0.0.1", "tls_certificate": asset(pki / "owner-a.crt"), "tls_private_key": asset(pki / "owner-a.key"), "authority_ca": asset(pki / "ca.crt"), "upload_ca": asset(pki / "ca.crt"), "encryption_public_key": asset(pki / "recipient.pub"), "authority_id": authority_id, "public_key_hex": public_der[-32:].hex(), "pipeline_mode": "variants", "execution_profile_sha256": profile, "expected_scope": scope, "original_name": "synthetic.fastq"}
        client_path = runtime / "config/client.json"; private_json(client_path, client_config)
        original = {}
        for label, fixture_name in (("valid", "reads.fastq"), ("repeat", "reads.fastq"), ("invalid", "invalid.fastq")):
            plaintext = runtime / "plaintext" / (label + ".fastq"); private_bytes(plaintext, (FIXTURE / fixture_name).read_bytes())
            client_run = runtime / "client" / label
            _, raw = command("cli-" + label, [bins / "uploader-cli", "--protocol", "owner-v1", "--config", client_path, "--run-dir", client_run, "--action", "submit", "--file", plaintext])
            delivered = exact_json(raw); job = delivered["job_id"]
            op = exact_json((client_run / "operation/04-accepted.json").read_bytes()); accepted = exact_json(op["acceptance_json"])
            verify_signed(label + "-acceptance", accepted, pki / "signing.pub", "record")
            binding = accepted["record"]["binding"]; acceptance_sha = digest(compact(accepted))
            check(label + "_signed_job_and_delivery_preserved", delivered.get("phase") == "delivered" and delivered.get("acceptance_sha256") == acceptance_sha and binding["job_id"] == job and binding["execution_profile_sha256"] == profile and binding["credential_sha256"] == digest(ssl.PEM_cert_to_DER_cert((pki / "owner-a.crt").read_text())))
            cache_path = worker_root / "results" / (job + ".json")
            wait_for(cache_path.is_file, 120)
            cache = exact_json(cache_path.read_bytes()); private_json(evidence / (label + "-cache.json"), cache)
            check(label + "_cache_owner_binding", cache.get("protocol") == "owner-v1" and cache.get("job_id") == job and cache.get("acceptance_sha256") == acceptance_sha)
            query = {"schema_version": 3, "operation": "status", "job_id": job, "upload_sha256": binding["ciphertext_sha256"], "expected_profile_sha256": profile, "processed_sha256": "", "processed_bytes": 0, "original_name": "", "analysis_context": {"original_name": "", "processed_size_bytes": 0, "decrypted": False, "decryption_error": "", "signature_valid": False, "signature_error": ""}, "acceptance_sha256": acceptance_sha, "acceptance_bytes": 0}
            response, _ = broker_read(execution["socket_path"], broker.pid, query)
            private_json(evidence / (label + "-broker-status.json"), response)
            query["operation"] = "receipt"; receipt_response, receipt_raw = broker_read(execution["socket_path"], broker.pid, query)
            private_json(evidence / (label + "-broker-receipt.json"), receipt_response); private_bytes(evidence / (label + "-receipt.json"), receipt_raw)
            execution_result = response["execution"]; manifest = execution_result["manifest"]; receipt = exact_json(receipt_raw)
            check(label + "_trusted_broker_owner_and_receipt", response == receipt_response and response["schema_version"] == 3 and response["authority_scope"] == scope and response["credential_sha256"] == binding["credential_sha256"] and response["acceptance_sha256"] == acceptance_sha and response["processed_sha256"] == sha(plaintext) and response["processed_bytes"] == plaintext.stat().st_size and response["analysis_context"]["signature_valid"] is True and response["analysis_context"]["decrypted"] is True and execution_result["schema_version"] == 2 and execution_result["state"] == "committed" and execution_result["error_code"] == "")
            objects = host / "s/objects" / execution_result["lease_id"]
            check(label + "_actual_retained_artifacts_match", sha(objects / "manifest.json") == execution_result["manifest_sha256"] and exact_json((objects / "manifest.json").read_bytes()) == manifest and sha(objects / "execution_receipt") == digest(receipt_raw) and all(name in ARTIFACT_IDS and sha(objects / name) == entry["sha256"] and (objects / name).stat().st_size == entry["bytes"] and entry["state"] == "verified" for name, entry in manifest["files"].items()))
            proof = exact_json((objects / "proof.json").read_bytes())
            check(label + "_proof_input_and_source_pins", proof["capsule_wait_finished"] is True and proof["export_authority_closed"] is True and proof["manifest_sha256"] == execution_result["manifest_sha256"] and receipt["schema_version"] == 2 and receipt["input_sha256"] == sha(plaintext) and receipt["input_bytes"] == plaintext.stat().st_size and receipt["source_pins"] == pins and receipt["analysis_context"] == response["analysis_context"])
            if label != "invalid":
                evaluation = receipt["evaluation"]["payload"]; detection = cache["detection"]; alignment = detection["signals"]["alignment"]
                check(label + "_real_three_snp_scientific_release", cache["status"] == manifest["execution_status"] == "succeeded" and cache["release_status"] == manifest["release_status"] == "evaluated_passed" and set(manifest["files"]) == ARTIFACT_IDS and evaluation["evaluation_status"] == "passed" and evaluation["tp"] == 3 and evaluation["fp"] == 0 and evaluation["fn"] == 0 and evaluation["precision"] == evaluation["recall"] == 1 and snps((objects / "normalized_vcf").read_bytes()) == snps((FIXTURE / "expected.vcf").read_bytes()))
                check(label + "_actual_detection_and_same_observed_evaluated_hash", alignment["mapped_reads"] == alignment["total_reads"] == 1171 and alignment["fraction"] == 1 and len(alignment["targets"]) == 1 and "threat_panel_hit" in detection["reasons"] and manifest["observed_sha256"] == manifest["evaluated_sha256"] == sha(objects / "normalized_vcf")
                      and receipt["analysis_capture"]["payload"]["detection"] == detection
                      and all(cache["scientific_evaluation"][key] == evaluation[key] for key in ("evaluation_status", "tp", "fp", "fn", "precision", "recall")))
            else:
                check("real_invalid_fastq_failed_withheld", cache["status"] == manifest["execution_status"] == "failed" and cache["release_status"] == manifest["release_status"] == "withheld" and set(manifest["files"]) == {"execution_receipt"})
            events = watch.drain(); private_json(evidence / (label + "-stage-events.json"), events)
            check(label + "_inotify_positive_stage_control", any(event["mask"] & 0x100 and event["name"].startswith("verified-" + job + "-") for event in events) and not list(stage_view.iterdir()))
            a_code, _ = api(label + "-owner-get", upload_port, ctx_a, "GET", "/v1/uploads/" + job)
            b_code, _ = api(label + "-other-owner-get", upload_port, ctx_b, "GET", "/v1/uploads/" + job)
            check(label + "_transport_owner_a_allowed_b_denied", a_code == 200 and b_code == 403)
            original[label] = {"job": job, "operation": op, "accepted": accepted, "plaintext": plaintext, "client_run": client_run,
                               "lease_id": execution_result["lease_id"], "normalized_snps": snps((objects / "normalized_vcf").read_bytes()) if label != "invalid" else None}
        check("repeat_has_distinct_job_lease_and_equal_snp_callset", original["valid"]["job"] != original["repeat"]["job"]
              and original["valid"]["lease_id"] != original["repeat"]["lease_id"]
              and len(original["valid"]["normalized_snps"]) == 3 and original["valid"]["normalized_snps"] == original["repeat"]["normalized_snps"])

        # B legitimately obtains a fresh authority challenge/acceptance while
        # signing copied ciphertext/envelope with B's distinct actual TLS key.
        before_attack = retained(); private_json(evidence / "before-copy-attack.json", before_attack)
        before_rejections = (logs / "worker.stderr").read_bytes().count(b"owner_worker_input_rejected\n")
        watch.drain()
        reserve = compact({"schema_version": 1, "request_id": secrets.token_hex(16), "original_name": "synthetic.fastq"})
        code, raw_challenge = api("b-reserve", authority_port, ctx_b, "POST", "/v1/reservations", reserve, {"Content-Type": "application/json"})
        check("copy_attack_b_has_real_signed_challenge", code == 200)
        challenge = exact_json(raw_challenge); verify_signed("b-challenge", challenge, pki / "signing.pub", "claim")
        original_a = original["valid"]; copied_cipher = (original_a["client_run"] / "operation/ciphertext.bin").read_bytes(); copied_envelope = bytes.fromhex(original_a["operation"]["envelope_hex"])
        aad_b = canonical_aad(challenge["claim"])
        manifest_b = {"schema_version": 1, "domain": "biozero.ownership.manifest.v1", "sig_alg": "rsa-pss-sha256", "challenge_sha256": digest(compact(challenge)), "aad_sha256": digest(aad_b), "ciphertext_sha256": digest(copied_cipher), "ciphertext_bytes": len(copied_cipher), "key_envelope_sha256": digest(copied_envelope)}
        private_bytes(evidence / "b-manifest.signed", compact(manifest_b)); private_bytes(evidence / "b-aad.bin", aad_b); private_bytes(evidence / "copied-envelope.bin", copied_envelope)
        openssl("b-sign-manifest", "dgst", "-sha256", "-sign", pki / "owner-b.key", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", "-out", evidence / "b-manifest.sig", evidence / "b-manifest.signed")
        signed_manifest_b = compact({"manifest": manifest_b, "signature": (evidence / "b-manifest.sig").read_bytes().hex()})
        frame = struct.pack(">I", len(raw_challenge)) + raw_challenge + struct.pack(">I", len(signed_manifest_b)) + signed_manifest_b + copied_cipher
        code, raw_b = api("b-finalize-copy", authority_port, ctx_b, "POST", "/v1/finalizations", frame, {"Content-Type": "application/octet-stream"})
        check("copy_attack_authority_really_accepts_b_signature", code == 200)
        accepted_b = exact_json(raw_b); verify_signed("b-acceptance", accepted_b, pki / "signing.pub", "record")
        binding_b = accepted_b["record"]["binding"]; job_b = binding_b["job_id"]; acceptance_b = compact(accepted_b)
        expected_binding_b = {"authority_id": authority_id, "job_id": challenge["claim"]["job_id"], "nonce": challenge["claim"]["nonce"],
                              "credential_sha256": digest(ssl.PEM_cert_to_DER_cert((pki / "owner-b.crt").read_text())), "original_name": "synthetic.fastq",
                              "enc_alg": "aes-256-gcm+rsa-oaep-sha256+owner-v1", "pipeline_mode": "variants", "execution_profile_sha256": profile,
                              "challenge_sha256": digest(compact(challenge)), "aad_sha256": digest(aad_b), "manifest_sha256": digest(signed_manifest_b),
                              "ciphertext_sha256": digest(copied_cipher), "ciphertext_bytes": len(copied_cipher), "key_envelope_sha256": digest(copied_envelope)}
        check("copy_attack_acceptance_contains_exact_verified_b_challenge_manifest", binding_b == expected_binding_b
              and accepted_b["record"]["challenge"] == challenge and accepted_b["record"]["manifest"] == exact_json(signed_manifest_b)
              and accepted_b["record"]["credential_der"] == ssl.PEM_cert_to_DER_cert((pki / "owner-b.crt").read_text()).hex())
        check("copy_attack_signed_facts_are_distinct_owner_same_bytes", job_b != original_a["job"] and binding_b["credential_sha256"] == digest(ssl.PEM_cert_to_DER_cert((pki / "owner-b.crt").read_text())) and binding_b["credential_sha256"] != original_a["accepted"]["record"]["binding"]["credential_sha256"] and binding_b["ciphertext_sha256"] == digest(copied_cipher) and binding_b["ciphertext_bytes"] == len(copied_cipher) and binding_b["key_envelope_sha256"] == digest(copied_envelope) and binding_b["aad_sha256"] == digest(aad_b) and binding_b["execution_profile_sha256"] == profile and accepted_b["record"]["store_id"] == scope["store_id"] and accepted_b["record"]["policy_sha256"] == scope["policy_sha256"])
        aad_a = canonical_aad(original_a["accepted"]["record"]["challenge"]["claim"]); private_bytes(evidence / "a-aad.bin", aad_a)
        inspection_args = [bins / "payload-inspector", "--key", pki / "recipient.key", "--ciphertext", original_a["client_run"] / "operation/ciphertext.bin", "--envelope", evidence / "copied-envelope.bin", "--plaintext", original_a["plaintext"]]
        _, raw = command("inspect-copied-original-aad", [*inspection_args, "--aad", evidence / "a-aad.bin"])
        check("original_copied_bytes_decrypt_under_aad_a", raw == b'{"plaintext_matches":true,"changed_aad_rejected":true}\n')
        code, _ = command("inspect-identical-copy-wrong-owner-aad", [*inspection_args, "--aad", evidence / "b-aad.bin"], expected=1)
        check("only_changed_owner_aad_fails_actual_gcm", code == 1 and aad_a != aad_b)
        attack_frame = struct.pack(">I", len(acceptance_b)) + acceptance_b + struct.pack(">I", len(copied_envelope)) + copied_envelope + copied_cipher
        code, raw = api("b-upload-copy", upload_port, ctx_b, "POST", "/v1/uploads", attack_frame, {"Content-Type": "application/octet-stream"})
        delivered_b = exact_json(raw)
        check("copy_attack_transport_delivered_not_execution", code == 200 and delivered_b["state"] == "delivered" and delivered_b["job_id"] == job_b and delivered_b["acceptance_sha256"] == digest(acceptance_b))
        job_b_path = upload_store / "jobs" / (job_b + ".json")
        physical_job_b = exact_json(job_b_path.read_bytes())
        physical_cipher_b = upload_store / "uploads" / (job_b + "_synthetic.fastq")
        physical_acceptance_b = upload_store / "acceptances" / (job_b + ".json")
        check("copy_attack_worker_input_is_exact_owner_b_bundle", set(physical_job_b) == {"job_id", "status", "uploaded_at", "original_name", "size_bytes", "sha256", "client_id", "enc_alg", "enc_key", "ownership_version", "ownership_acceptance_sha256"}
              and physical_job_b["job_id"] == job_b and physical_job_b["status"] == "uploaded" and physical_job_b["original_name"] == "synthetic.fastq"
              and physical_job_b["client_id"] == "" and physical_job_b["ownership_version"] == 1 and physical_job_b["enc_alg"] == expected_binding_b["enc_alg"]
              and physical_job_b["ownership_acceptance_sha256"] == digest(acceptance_b) and physical_job_b["sha256"] == digest(copied_cipher)
              and physical_job_b["size_bytes"] == len(copied_cipher) and physical_job_b["enc_key"] == copied_envelope.hex()
              and physical_cipher_b.read_bytes() == copied_cipher and compact(exact_json(physical_acceptance_b.read_bytes())) == acceptance_b
              and all(stat.S_IMODE(path.stat().st_mode) == 0o600 and path.stat().st_uid == os.getuid() and path.stat().st_nlink == 1 for path in (job_b_path, physical_cipher_b, physical_acceptance_b)))
        wait_for(lambda: (logs / "worker.stderr").read_bytes().count(b"owner_worker_input_rejected\n") > before_rejections)
        time.sleep(0.3)
        events = watch.drain(); private_json(evidence / "copy-attack-stage-events.json", events)
        after_attack = retained(); private_json(evidence / "after-copy-attack.json", after_attack)
        check("worker_rejects_copy_before_stage_or_reserve", events == [] and before_attack == after_attack and not list(stage_view.iterdir()) and not (worker_root / "results" / (job_b + ".json")).exists())
        # The process log deliberately emits a generic classification. The
        # independently signed/validated input and isolated AAD control above
        # establish the fixture's cryptographic failure; no hidden log code or
        # fabricated result is attributed to the worker.
        report["copy_attack_observation"] = {"worker_log": "owner_worker_input_rejected", "stage_mutations": len(events), "custody_unchanged": before_attack == after_attack, "independent_aad_control": True}
        worker_journal = exact_json((worker_root / "custody/journal.json").read_bytes()); broker_journal = exact_json((host / "j/journal.json").read_bytes()); store_ledger = exact_json((host / "s/ledger.json").read_bytes())
        expected_jobs = {value["job"] for value in original.values()}
        check("only_three_a_jobs_occupy_execution_custody", set(worker_journal["records"]) == set(broker_journal["records"]) == set(broker_journal["owner_bindings"]) == expected_jobs and len(store_ledger["records"]) == 3 and all(row["state"] == "committed" for row in store_ledger["records"].values()))
        authority_rows = exact_json((authority_store / "ledger.json").read_bytes())["ledger"]["records"]
        upload_rows = exact_json((upload_store / "ledger.json").read_bytes())["records"]
        promise = (25 << 20) + (128 << 10)
        check("all_four_admitted_inputs_keep_full_transport_and_authority_charges", len(authority_rows) == len(upload_rows) == 4 and all(row["charge_bytes"] == promise and row["state"] == "accepted" for row in authority_rows) and all(row["charge_bytes"] == promise and row["state"] == "delivered" for row in upload_rows))
        for lease, row in store_ledger["records"].items():
            objects = host / "s/objects" / lease
            exact_charge = sum(file["bytes"] for file in row["files"].values()) + (objects / "manifest.json").stat().st_size + (objects / "proof.json").stat().st_size + 2 * len(compact(row)) + 72
            check("exact_retained_execution_charge_" + str(len(report.get("execution_charges", []))), row["charge"] == exact_charge)
            report.setdefault("execution_charges", []).append(row["charge"])
        report["accounting"] = {"authority_jobs": len(authority_rows), "authority_charge": sum(row["charge_bytes"] for row in authority_rows), "upload_jobs": len(upload_rows), "upload_charge": sum(row["charge_bytes"] for row in upload_rows), "execution_slots": len(store_ledger["records"]), "execution_record_charge": sum(row["charge"] for row in store_ledger["records"].values()), "store_header_reserve": 4096,
                                "execution_total_with_header": 4096 + sum(row["charge"] for row in store_ledger["records"].values())}
        report["native_workspace_hashes"] = tree_hashes(host / "w")
        stable_history = retained(); report["config_hashes"] = tree_hashes(runtime / "config"); report["checks_completed"] = True
    except BaseException:
        report["checks_completed"] = False
        private_bytes(evidence / "failure.txt", traceback.format_exc().encode())
    finally:
        cleanup_ok = True
        if watch:
            try:
                private_json(evidence / "final-stage-events.json", watch.drain()); watch.close()
            except BaseException:
                cleanup_ok = False; private_bytes(evidence / "stage-watch-cleanup-failure.txt", traceback.format_exc().encode())
        # Stop worker admission and await its own launcher first, while broker
        # remains available. Then stop broker and HTTPS services. Signal only
        # exact Popen children created by this fixture, never process names.
        for proc, entry in reversed(list(zip(children, report["processes"]))):
            try:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGTERM)
                try:
                    code = proc.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    cleanup_ok = False; proc.kill(); code = proc.wait(timeout=10); entry["forced_kill"] = True
                entry["returncode"] = code
                cleanup_ok = cleanup_ok and code == 0
            except BaseException:
                cleanup_ok = False; entry["cleanup_error"] = traceback.format_exc()
        for handle in handles:
            handle.flush(); os.fsync(handle.fileno()); handle.close()
        try:
            final_source = inventory(); report["final_source_hashes"] = final_source; report["source_unchanged"] = final_source == report.get("source_hashes")
            private_json(evidence / "final-source-hashes.json", final_source); cleanup_ok = cleanup_ok and report["source_unchanged"]
            if stable_history is not None:
                final_history = retained(); private_json(evidence / "history-after-wait.json", final_history)
                report["history_unchanged_after_wait"] = final_history == stable_history; cleanup_ok = cleanup_ok and report["history_unchanged_after_wait"]
        except BaseException:
            cleanup_ok = False; private_bytes(evidence / "final-readback-failure.txt", traceback.format_exc().encode())
        report["cleanup_clean_wait"] = cleanup_ok; report["status"] = "passed" if report.get("checks_completed") and cleanup_ok else "failed"
        report["finished_at"] = datetime.now(timezone.utc).isoformat(); save()
        print(json.dumps({"status": report["status"], "checks": len(report["cases"]), "passed": sum(case["passed"] for case in report["cases"]), "scope": "native_owner_worker_capsule"}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print('{"status":"failed","scope":"native_owner_worker_capsule","setup_error":true}')
        raise SystemExit(1)
