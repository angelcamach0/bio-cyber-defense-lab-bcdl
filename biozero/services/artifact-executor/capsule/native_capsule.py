#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Trusted Linux PID1 helper. Local stdin configuration is NOT an RPC surface.

Go creates NEWUSER/NEWNS/NEWPID/NEWNET, maps uid/gid0 to host1000, and gives
fd3=STREAM socket and fd4=read-only input. It pins this file before execution.
The only response is a BE32 length/JSON frame with ordered SCM_RIGHTS exports.
Successful storage and quiescence are the outside keeper's separate decisions.
Tests are authored, not runtime acceptance of namespaces or quota enforcement.
"""
import array
import ctypes
import errno
import fcntl
import hashlib
import json
import math
import os
import re
import resource
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

CONFIG_LIMIT = FRAME_LIMIT = 64 << 10
INPUT_LIMIT = 25 << 20
REFERENCE_LIMIT = 32 << 20
FILE_LIMIT = EXPORT_LIMIT = 64 << 20
WORKSPACE_LIMIT = 128 << 20
JSON_LIMIT = 1 << 20
STDERR_LIMIT = 64 << 10
PIN_LIMIT = 4 << 20
EXPORT_NAMES = (
    ("execution_receipt", "execution_receipt.json"),
    ("normalized_vcf", "variants.vcf"),
    ("variants_vcf", "variants.vcf.gz"),
    ("variants_vcf_index", "variants.vcf.gz.csi"),
)
KEYS = {
    "schema_version", "workspace", "input_bytes", "input_sha256", "mode",
    "pipeline_path", "pipeline_sha256", "resource_budget_sha256",
    "reference_path", "reference_sha256", "evaluator_path", "evaluator_sha256",
    "truth_path", "truth_sha256", "python_path", "tool_path", "timeout_seconds",
}
ANALYSIS_KEYS = {"executable_path", "executable_sha256", "rules_path", "rules_sha256",
                 "panel_path", "panel_sha256", "context"}
CONTEXT_KEYS = {"original_name", "processed_size_bytes", "decrypted", "decryption_error",
                "signature_valid", "signature_error"}
ANALYSIS_LIMIT = 64 << 10
HASH = re.compile(r"[0-9a-f]{64}\Z")
CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class CapsuleError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def fail(code):
    raise CapsuleError(code)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("capsule_json_invalid")
        result[key] = value
    return result


def parse_json(raw):
    try:
        result = json.loads(raw, object_pairs_hook=_pairs,
                            parse_constant=lambda _: fail("capsule_json_invalid"))
        check_json(result)
        return result
    except (ValueError, UnicodeError, RecursionError):
        fail("capsule_json_invalid")


def check_json(value, depth=0):
    if depth > 64 or (type(value) is float and not math.isfinite(value)):
        fail("capsule_json_invalid")
    if type(value) is dict:
        for item in value.values():
            check_json(item, depth + 1)
    elif type(value) is list:
        for item in value:
            check_json(item, depth + 1)


def json_bytes(value):
    try:
        return json.dumps(value, separators=(",", ":"), sort_keys=True,
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError):
        fail("capsule_json_invalid")


def canonical_path(value):
    return (type(value) is str and value.startswith("/") and "\x00" not in value
            and len(value.encode("utf-8")) <= 4096
            and value == os.path.normpath(value) and value != "/")


def validate_config(config):
    if type(config) is not dict:
        fail("capsule_config_invalid")
    version = config.get("schema_version")
    if type(version) is not int or version not in (1, 2):
        fail("capsule_config_invalid")
    if set(config) != (KEYS if version == 1 else KEYS | {"analysis"}):
        fail("capsule_config_invalid")
    for key, low, high in (("input_bytes", 0, INPUT_LIMIT), ("timeout_seconds", 1, 600)):
        if type(config[key]) is not int or not low <= config[key] <= high:
            fail("capsule_config_invalid")
    if config["mode"] not in ("stats", "variants"):
        fail("capsule_config_invalid")
    for key in ("workspace", "pipeline_path", "python_path"):
        if not canonical_path(config[key]):
            fail("capsule_config_invalid")
    for key in ("input_sha256", "pipeline_sha256", "resource_budget_sha256"):
        if type(config[key]) is not str or not HASH.fullmatch(config[key]):
            fail("capsule_config_invalid")
    if (type(config["tool_path"]) is not str or not config["tool_path"]
            or len(config["tool_path"].encode("utf-8")) > 8192):
        fail("capsule_config_invalid")
    tool_dirs = config["tool_path"].split(":")
    if len(tool_dirs) > 16 or len(set(tool_dirs)) != len(tool_dirs):
        fail("capsule_config_invalid")
    if any(not canonical_path(path) for path in tool_dirs):
        fail("capsule_config_invalid")
    for name in ("reference", "evaluator", "truth"):
        path, digest = config[name + "_path"], config[name + "_sha256"]
        if path == "" and digest == "":
            continue
        if not canonical_path(path) or type(digest) is not str or not HASH.fullmatch(digest):
            fail("capsule_config_invalid")
    if bool(config["evaluator_path"]) != bool(config["truth_path"]):
        fail("capsule_config_invalid")
    if config["evaluator_path"] and not config["reference_path"]:
        fail("capsule_config_invalid")
    if config["mode"] == "variants" and not config["reference_path"]:
        fail("capsule_config_invalid")
    workspace = config["workspace"]
    paths = [config[key] for key in ("pipeline_path", "python_path", "reference_path",
                                    "evaluator_path", "truth_path") if config[key]] + tool_dirs
    # A source under workspace would disappear at mount; a read-only source
    # parent must not cover workspace or proc. Require a separate caller-owned dir.
    if workspace == "/proc" or workspace.startswith("/proc/"):
        fail("capsule_config_invalid")
    for path in paths:
        if path == workspace or path.startswith(workspace + "/"):
            fail("capsule_config_invalid")
    if any(workspace.startswith(path + "/") or path.startswith("/proc") for path in tool_dirs):
        fail("capsule_config_invalid")
    for key in ("pipeline_path", "evaluator_path"):
        if config[key]:
            parent = os.path.dirname(config[key])
            if parent == "/" or workspace.startswith(parent + "/") or parent.startswith("/proc"):
                fail("capsule_config_invalid")
    if version == 2:
        validate_analysis_config(config)
    return config


def validate_analysis_config(config):
    analysis = config["analysis"]
    if type(analysis) is not dict or set(analysis) != ANALYSIS_KEYS:
        fail("capsule_analysis_config_invalid")
    for name in ("executable", "rules", "panel"):
        path, pin = analysis[name + "_path"], analysis[name + "_sha256"]
        if name == "panel" and path == pin == "":
            continue
        if (not canonical_path(path) or "\n" in path or "\r" in path
                or type(pin) is not str or not HASH.fullmatch(pin)
                or path == "/proc" or path.startswith("/proc/")
                or path == config["workspace"] or path.startswith(config["workspace"] + "/")):
            fail("capsule_analysis_config_invalid")
    facts = analysis["context"]
    if type(facts) is not dict or set(facts) != CONTEXT_KEYS:
        fail("capsule_analysis_context_invalid")
    if (type(facts["processed_size_bytes"]) is not int
            or facts["processed_size_bytes"] != config["input_bytes"]
            or type(facts["decrypted"]) is not bool or type(facts["signature_valid"]) is not bool):
        fail("capsule_analysis_context_invalid")
    for key, limit in (("original_name", 4096), ("decryption_error", 128), ("signature_error", 128)):
        try:
            valid = type(facts[key]) is str and len(facts[key].encode("utf-8")) <= limit
        except UnicodeError:
            valid = False
        if not valid:
            fail("capsule_analysis_context_invalid")
    if ((facts["decrypted"] and facts["decryption_error"])
            or (facts["signature_valid"] and facts["signature_error"])):
        fail("capsule_analysis_context_invalid")


def open_anchored(path, directory=False):
    """Reject symlinks in every component, including final regular files/FIFOs."""
    if not canonical_path(path):
        fail("capsule_source_unsafe")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        parts = path[1:].split("/")
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if not final or directory:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            fail("capsule_source_unsafe")
        result, fd = fd, -1
        return result
    except OSError:
        fail("capsule_source_unsafe")
    finally:
        if fd >= 0:
            os.close(fd)


def hash_fd(fd, maximum):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        fail("capsule_source_size")
    digest, count = hashlib.sha256(), 0
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, min(65536, maximum - count + 1))
        if not chunk:
            break
        count += len(chunk)
        if count > maximum:
            fail("capsule_source_size")
        digest.update(chunk)
    after = os.fstat(fd)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        fail("capsule_source_changed")
    if count != before.st_size:
        fail("capsule_source_changed")
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest(), count


def copy_exact(fd, destination, maximum, expected_bytes=None, expected_sha=None):
    digest, count = hashlib.sha256(), 0
    os.lseek(fd, 0, os.SEEK_SET)
    with open(destination, "xb") as output:
        while True:
            chunk = os.read(fd, min(65536, maximum - count + 1))
            if not chunk:
                break
            count += len(chunk)
            if count > maximum or (expected_bytes is not None and count > expected_bytes):
                fail("capsule_input_mismatch")
            output.write(chunk)
            digest.update(chunk)
        output.flush()
        os.fsync(output.fileno())
    actual = digest.hexdigest()
    if (expected_bytes is not None and count != expected_bytes) or (
            expected_sha is not None and actual != expected_sha):
        fail("capsule_input_mismatch")
    return actual, count


def mount(source, target, fs_type=None, flags=0, data=None):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                          ctypes.c_ulong, ctypes.c_char_p]
    libc.mount.restype = ctypes.c_int
    args = [None if item is None else os.fsencode(item) for item in (source, target, fs_type)]
    if libc.mount(*args, flags, None if data is None else os.fsencode(data)) != 0:
        fail("capsule_mount_unavailable")


def readonly_bind(path):
    # Mount propagation was made private first. This is a mountpoint remount,
    # not a global filesystem remount. No host mount flag is changed.
    mount(path, path, flags=4096)  # MS_BIND
    mount(None, path, flags=4096 | 32 | 1 | 2 | 4)  # BIND|REMOUNT|RDONLY|NOSUID|NODEV


def prepare_mounts(config):
    if os.getpid() != 1 or os.getuid() != 0 or os.geteuid() != 0:
        fail("capsule_namespace_required")
    # The initial proc belongs to the host: only use self records before replacing
    # it; UID mapping is checked again after mounting the capsule's own proc.
    workspace_fd = open_anchored(config["workspace"], directory=True)
    try:
        info = os.fstat(workspace_fd)
        if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != 0 or os.listdir(workspace_fd):
            fail("capsule_workspace_unsafe")
    finally:
        os.close(workspace_fd)
    # No tools/bytes have been copied before these mandatory kernel boundaries.
    mount(None, "/", flags=(1 << 14) | (1 << 18))  # MS_REC|MS_PRIVATE
    mount("tmpfs", config["workspace"], "tmpfs", flags=2 | 4 | 8,
          data="size=134217728,nr_inodes=4096,mode=0700")
    mount("proc", "/proc", "proc", flags=1 | 2 | 4 | 8)
    with open("/proc/self/uid_map", encoding="ascii") as stream:
        mapping = [line.split() for line in stream if line.strip()]
    if mapping != [["0", "1000", "1"]]:
        fail("capsule_namespace_required")
    with open("/proc/self/gid_map", encoding="ascii") as stream:
        mapping = [line.split() for line in stream if line.strip()]
    if mapping != [["0", "1000", "1"]] or os.getgid() != 0 or os.getegid() != 0:
        fail("capsule_namespace_required")
    with open("/proc/net/dev", encoding="ascii") as stream:
        interfaces = [line.split(":", 1)[0].strip() for line in stream if ":" in line]
    if interfaces != ["lo"]:
        fail("capsule_network_not_private")
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))
    dirs = {os.path.dirname(config["pipeline_path"]), *config["tool_path"].split(":")}
    if config["evaluator_path"]:
        dirs.add(os.path.dirname(config["evaluator_path"]))
    for path in sorted(dirs, key=len):
        fd = open_anchored(path, directory=True)
        os.close(fd)
        readonly_bind(path)
    for key in ("reference_path", "truth_path", "python_path"):
        if config[key]:
            readonly_bind(config[key])
    if config["schema_version"] == 2:
        for name in ("executable", "rules", "panel"):
            path = config["analysis"][name + "_path"]
            if path:
                readonly_bind(path)


class CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]


def process_state():
    result = {"pid": os.getpid(), "uid": os.getuid(), "gid": os.getgid(),
              "rlimit_fsize": list(resource.getrlimit(resource.RLIMIT_FSIZE))}
    with open("/proc/self/status", encoding="ascii") as stream:
        for line in stream:
            key, _, value = line.partition(":")
            if key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"):
                result[key] = value.strip()
    result["namespaces"] = {name: os.readlink("/proc/self/ns/" + name)
                            for name in ("user", "mnt", "pid", "net")}
    return result


def drop_capabilities():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    libc.prctl.restype = ctypes.c_int
    for cap in range(64):
        if libc.prctl(24, cap, 0, 0, 0) != 0 and ctypes.get_errno() != errno.EINVAL:
            fail("capsule_capability_drop_failed")
    data = (CapData * 2)()
    header = CapHeader(0x20080522, 0)
    libc.capset.argtypes = [ctypes.POINTER(CapHeader), ctypes.POINTER(CapData)]
    libc.capset.restype = ctypes.c_int
    if libc.capset(ctypes.byref(header), data) != 0 or libc.prctl(38, 1, 0, 0, 0) != 0:
        fail("capsule_capability_drop_failed")
    state = process_state()
    if state.get("NoNewPrivs") != "1" or any(
            int(state.get(key, "1"), 16) != 0
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")):
        fail("capsule_capability_drop_failed")
    return state


def fixed_environment(config, work):
    # No credentials, user-supplied environment, LD_PRELOAD or Python startup
    # hooks are inherited. Runtime/tool paths are trusted host configuration.
    return {"PATH": config["tool_path"], "HOME": work, "TMPDIR": work,
            "LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
            "BIOZERO_PIPELINE_GROUP_MODE": "shared",
            "BIOZERO_PIPELINE_MAX_FILE_BYTES": str(FILE_LIMIT),
            "BIOZERO_PIPELINE_MAX_REFERENCE_BYTES": str(REFERENCE_LIMIT),
            "BIOZERO_PIPELINE_MAX_BYTES": str(INPUT_LIMIT),
            "BIOZERO_TOOL_STDOUT_BYTES": str(STDERR_LIMIT),
            "BIOZERO_TOOL_STDERR_BYTES": str(STDERR_LIMIT),
            "BIOZERO_PIPELINE_TIMEOUT_SECONDS": str(config["timeout_seconds"])}


def stop_namespace_children():
    # Never call outside namespace PID1. Kernel teardown after PID1 exits is
    # still the keeper's authoritative boundary, not this best-effort reaping.
    if os.getpid() != 1:
        fail("capsule_namespace_required")
    try:
        os.kill(-1, signal.SIGKILL)
    except ProcessLookupError:
        pass
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
            if not pid:
                break
        except ChildProcessError:
            break


def capture_command(command, environment, work, deadline, stdin_bytes=None, stdout_limit=JSON_LIMIT):
    if (type(stdout_limit) is not int or not 0 < stdout_limit <= JSON_LIMIT
            or (stdin_bytes is not None and (type(stdin_bytes) is not bytes or len(stdin_bytes) > ANALYSIS_LIMIT))):
        fail("capsule_analysis_request_limit")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        fail("capsule_timeout")
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL if stdin_bytes is None else subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment, cwd=work,
                               close_fds=True)
    captures = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    try:
        for name, stream, maximum in (("stdout", process.stdout, stdout_limit),
                                      ("stderr", process.stderr, STDERR_LIMIT)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (name, maximum))
        written, stdin_incomplete = 0, False
        if stdin_bytes is not None:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, ("stdin", 0))
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail("capsule_timeout")
            for key, _ in selector.select(min(remaining, 0.1)):
                name, maximum = key.data
                if name == "stdin":
                    try:
                        written += os.write(process.stdin.fileno(), stdin_bytes[written:written + 65536])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        # The pinned CLI may reject rules before reading stdin.
                        # Preserve its bounded failure response, not a JSON prefix.
                        stdin_incomplete = True
                        selector.unregister(process.stdin)
                        process.stdin.close()
                        continue
                    if written == len(stdin_bytes):
                        selector.unregister(process.stdin)
                        process.stdin.close()
                    continue
                chunk = os.read(key.fileobj.fileno(), min(65536, maximum - len(captures[name]) + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(captures[name]) + len(chunk) > maximum:
                    fail("capsule_capture_limit")
                captures[name].extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail("capsule_timeout")
        try:
            code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            fail("capsule_timeout")
        raw_stdout = bytes(captures["stdout"])
        payload = parse_json(raw_stdout)
        if type(payload) is not dict:
            fail("capsule_json_invalid")
        if stdin_incomplete and not (type(code) is int and code == 1
                                     and type(payload.get("schema_version")) is int
                                     and payload["schema_version"] == 1
                                     and payload.get("status") == "failed"):
            fail("capsule_analysis_stdin_failed")
        return {"returncode": code, "payload": payload,
                "raw_stdout": raw_stdout.decode("utf-8", errors="strict"),
                "raw_stderr": bytes(captures["stderr"]).decode("utf-8", errors="replace")}
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        if process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass


def pipeline_outcome(capture, mode):
    payload, code = capture["payload"], capture["returncode"]
    status = payload.get("pipeline_status")
    if (type(code) is not int or type(payload.get("schema_version")) is not int
            or payload["schema_version"] != 1 or payload.get("mode") != mode
            or status not in ("succeeded", "incomplete", "failed")
            or code != {"succeeded": 0, "incomplete": 2, "failed": 1}[status]):
        fail("capsule_pipeline_disagreement")
    return {"execution_status": status,
            "release_status": "unassessed" if status == "succeeded" else "withheld",
            "error_code": "" if status == "succeeded" else "capsule_pipeline_" + status,
            "observed_sha256": "", "evaluated_sha256": ""}


def evaluation_passed(capture):
    payload, code = capture["payload"], capture["returncode"]
    status = payload.get("evaluation_status")
    if type(code) is not int or status not in ("passed", "failed"):
        fail("capsule_evaluator_disagreement")
    if code != (0 if status == "passed" else 1):
        fail("capsule_evaluator_disagreement")
    if status != "passed":
        return False
    if any(type(payload.get(key)) is not int for key in ("tp", "fp", "fn")):
        fail("capsule_evaluator_disagreement")
    if (payload["tp"] <= 0 or payload["fp"] != 0 or payload["fn"] != 0
            or any(type(payload.get(key)) not in (float, int)
                   or not math.isfinite(payload[key]) or payload[key] != 1
                   for key in ("precision", "recall"))
            or payload.get("unexpected") != [] or payload.get("missing") != []):
        fail("capsule_evaluator_disagreement")
    return True


def pipeline_directory(config, payload):
    work, path = config["workspace"], payload.get("output_dir")
    if (not canonical_path(path) or os.path.dirname(path) != work
            or not os.path.basename(path).startswith("biozero-run-")
            or os.path.basename(path) == "biozero-run-"):
        fail("capsule_output_unsafe")
    fd = open_anchored(path, directory=True)
    os.close(fd)
    outputs = payload.get("outputs")
    if type(outputs) is not dict:
        fail("capsule_output_unsafe")
    for name, filename in EXPORT_NAMES[1:]:
        if outputs.get(name) != os.path.join(path, filename):
            fail("capsule_output_unsafe")
    return path


def export_file(path):
    fd = open_anchored(path)
    try:
        info = os.fstat(fd)
        if stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_uid != 0:
            fail("capsule_output_unsafe")
        digest, size = hash_fd(fd, FILE_LIMIT)
        return fd, {"sha256": digest, "bytes": size}
    except BaseException:
        os.close(fd)
        raise


def send_frame(channel, outcome, files):
    # Exactly one sendmsg supplies rights; subsequent sends finish a partial
    # STREAM write without duplicating descriptors. The keeper orders by files.
    if set(outcome) != {"execution_status", "release_status", "error_code",
                        "observed_sha256", "evaluated_sha256"}:
        fail("capsule_protocol_invalid")
    public_files = [{"id": name, **metadata} for name, _, metadata in files]
    payload = json_bytes({"schema_version": 1, "outcome": outcome, "files": public_files})
    if len(payload) > FRAME_LIMIT:
        fail("capsule_frame_limit")
    data = struct.pack("!I", len(payload)) + payload
    rights = array.array("i", [fd for _, fd, _ in files])
    ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)] if files else []
    sent = channel.sendmsg([data], ancillary)
    if sent <= 0:
        fail("capsule_channel_failed")
    while sent < len(data):
        amount = channel.send(data[sent:])
        if amount <= 0:
            fail("capsule_channel_failed")
        sent += amount


def verify_sources(config):
    sources = {}
    for name, limit in (("pipeline", PIN_LIMIT), ("resource_budget", PIN_LIMIT),
                        ("reference", REFERENCE_LIMIT), ("evaluator", PIN_LIMIT),
                        ("truth", REFERENCE_LIMIT)):
        path = (os.path.join(os.path.dirname(config["pipeline_path"]), "resource_budget.py")
                if name == "resource_budget" else config[name + "_path"])
        if not path:
            continue
        fd = open_anchored(path)
        try:
            digest, size = hash_fd(fd, limit)
            if digest != config[name + "_sha256"]:
                fail("capsule_source_pin_mismatch")
            sources[name] = {"sha256": digest, "bytes": size}
        finally:
            os.close(fd)
    if config["schema_version"] == 2:
        analysis = config["analysis"]
        for name, limit in (("executable", PIN_LIMIT), ("rules", ANALYSIS_LIMIT), ("panel", REFERENCE_LIMIT)):
            path = analysis[name + "_path"]
            if not path:
                continue
            fd = open_anchored(path)
            try:
                info = os.fstat(fd)
                if name == "executable" and (not info.st_mode & 0o100 or info.st_mode & 0o7022
                                              or info.st_nlink != 1 or info.st_uid != os.geteuid()):
                    fail("capsule_source_unsafe")
                digest, size = hash_fd(fd, limit)
                if digest != analysis[name + "_sha256"]:
                    fail("capsule_source_pin_mismatch")
                sources["analysis_" + name] = {"sha256": digest, "bytes": size}
            finally:
                os.close(fd)
    fd = open_anchored(config["python_path"])
    try:
        if not os.fstat(fd).st_mode & 0o111:
            fail("capsule_source_unsafe")
    finally:
        os.close(fd)
    for path in config["tool_path"].split(":"):
        fd = open_anchored(path, directory=True)
        os.close(fd)
    return sources


def analysis_passed(capture, config):
    """Validate the pinned CLI's complete typed result, never its exit alone."""
    payload, code = capture["payload"], capture["returncode"]
    if (type(payload) is not dict or set(payload) != {"schema_version", "status", "error_code", "warnings", "detection"}
            or type(payload["schema_version"]) is not int or payload["schema_version"] != 1
            or payload["warnings"] != [] or type(code) is not int):
        fail("capsule_analysis_invalid")
    if payload["status"] == "failed":
        if (code != 1 or payload["detection"] is not None or type(payload["error_code"]) is not str
                or not CODE.fullmatch(payload["error_code"])):
            fail("capsule_analysis_invalid")
        return False
    if payload["status"] != "succeeded" or code != 0 or payload["error_code"] != "":
        fail("capsule_analysis_invalid")
    detection = payload["detection"]
    if (type(detection) is not dict or not {"score", "reason", "verdict", "signals"}.issubset(detection)
            or set(detection) - {"score", "reason", "verdict", "signals", "reasons"}):
        fail("capsule_analysis_invalid")
    def number(value):
        return type(value) in (int, float) and math.isfinite(value)
    def integer(value, maximum=(1 << 63) - 1):
        return type(value) is int and 0 <= value <= maximum
    reasons = detection.get("reasons", [])
    valid_reasons = {"suspicious_filename", "file_size_exceeded", "decryption_failed", "signature_invalid",
                     "critical_pipeline_warnings", "low_quality_reads", "threat_panel_hit"}
    if (not number(detection["score"]) or not 0 <= detection["score"] <= 1
            or detection["verdict"] not in ("low", "medium", "high") or type(reasons) is not list
            or any(type(item) is not str or item not in valid_reasons for item in reasons)
            or len(reasons) > 7 or len(set(reasons)) != len(reasons)
            or detection["reason"] != (reasons[0] if reasons else "no suspicious indicators")):
        fail("capsule_analysis_invalid")
    signals = detection["signals"]
    if (type(signals) is not dict or not {"warnings", "integrity", "pipeline"}.issubset(signals)
            or set(signals) - {"warnings", "integrity", "pipeline", "fastp", "alignment"}):
        fail("capsule_analysis_invalid")
    warnings, integrity, pipeline = signals["warnings"], signals["integrity"], signals["pipeline"]
    if (type(warnings) is not dict or set(warnings) != {"critical", "warn", "info"}
            or not all(integer(v, 1 << 20) for v in warnings.values())
            or type(integrity) is not dict or set(integrity) != {"signature_valid", "decrypted"}
            or not all(type(v) is bool for v in integrity.values())
            or integrity != {key: config["analysis"]["context"][key] for key in ("signature_valid", "decrypted")}
            or type(pipeline) is not dict or set(pipeline) != {"read_count", "avg_read_length"}
            or not all(integer(v) for v in pipeline.values())):
        fail("capsule_analysis_invalid")
    if "fastp" in signals:
        fastp = signals["fastp"]
        if type(fastp) is not dict or set(fastp) != {"q30_rate"} or not number(fastp["q30_rate"]):
            fail("capsule_analysis_invalid")
    if bool(config["analysis"]["panel_path"]) != ("alignment" in signals):
        fail("capsule_analysis_invalid")
    if "alignment" in signals:
        alignment = signals["alignment"]
        if (type(alignment) is not dict or not {"mapped_reads", "total_reads", "fraction"}.issubset(alignment)
                or set(alignment) - {"mapped_reads", "total_reads", "fraction", "targets"}):
            fail("capsule_analysis_invalid")
        mapped, total, fraction = alignment["mapped_reads"], alignment["total_reads"], alignment["fraction"]
        targets = alignment.get("targets", {})
        if (not integer(total, 1000000) or not integer(mapped, total) or not number(fraction)
                or fraction != (mapped / total if total else 0)
                or type(targets) is not dict or len(targets) > 128):
            fail("capsule_analysis_invalid")
        for target, count in targets.items():
            if (type(target) is not str or len(target) > 128 or any(not 33 <= ord(c) <= 126 for c in target)
                    or not integer(count, mapped) or count == 0):
                fail("capsule_analysis_invalid")
        if sum(targets.values()) != mapped:
            fail("capsule_analysis_invalid")
    return True


def run_analysis(config, pipeline, input_path, env, work, deadline):
    """No projection/truncation: unsupported large payloads remain explicit failure."""
    capture = None
    try:
        analysis = config["analysis"]
        request = json_bytes({"schema_version": 1, "context": analysis["context"], "pipeline": pipeline["payload"]})
        if len(request) > ANALYSIS_LIMIT:
            fail("capsule_analysis_request_limit")
        capture = capture_command([analysis["executable_path"], "--rules", analysis["rules_path"],
                                   "--panel", analysis["panel_path"], "--content", input_path],
                                  env, work, deadline, stdin_bytes=request, stdout_limit=ANALYSIS_LIMIT)
        return capture, "" if analysis_passed(capture, config) else "capsule_analysis_failed"
    except CapsuleError as exc:
        if exc.code in ("capsule_timeout", "capsule_cancelled"):
            raise
        code = exc.code
    except OSError:
        code = "capsule_analysis_start_failed"
    if capture is None:
        # No valid complete CLI result was observed; no exit/status is invented.
        capture = {"returncode": None, "payload": None, "raw_stdout": "", "raw_stderr": "", "error_code": code}
    return capture, code


def write_receipt(work, receipt):
    path = os.path.join(work, "execution_receipt.json")
    data = json_bytes(receipt)
    # Raw UTF-8 captures may expand when JSON-escaped, but the private receipt
    # remains explicitly bounded independently of FSIZE and aggregate tmpfs.
    if len(data) > 16 << 20:
        fail("capsule_receipt_limit")
    with open(path, "xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return path


def execute(config, deadline):
    sources = verify_sources(config)
    prepare_mounts(config)
    # Repeat pins after read-only mounts; changes during setup fail before tools.
    if verify_sources(config) != sources:
        fail("capsule_source_changed")
    work = config["workspace"]
    flags = fcntl.fcntl(4, fcntl.F_GETFL)
    if flags & os.O_ACCMODE != os.O_RDONLY or not stat.S_ISREG(os.fstat(4).st_mode):
        fail("capsule_input_unsafe")
    magic = os.pread(4, 2, 0)
    input_path = os.path.join(work, "input.fastq.gz" if magic == b"\x1f\x8b" else "input.fastq")
    input_sha, input_bytes = copy_exact(4, input_path, INPUT_LIMIT,
                                      config["input_bytes"], config["input_sha256"])
    reference = ""
    if config["reference_path"]:
        reference = os.path.join(work, "reference.fa")
        fd = open_anchored(config["reference_path"])
        try:
            copy_exact(fd, reference, REFERENCE_LIMIT, expected_sha=config["reference_sha256"])
        finally:
            os.close(fd)
    state = drop_capabilities()
    os.chdir(work)
    env = fixed_environment(config, work)
    # -S omits site/user startup hooks while keeping the pinned script sibling
    # import (resource_budget); -I would remove that required import directory.
    command = [config["python_path"], "-B", "-S", config["pipeline_path"], input_path,
               "--out-dir", work, "--mode", config["mode"]]
    if reference:
        command.extend(["--reference", reference])
    pipeline = capture_command(command, env, work, deadline)
    stop_namespace_children()
    outcome = pipeline_outcome(pipeline, config["mode"])
    files, directory, evaluated = [], None, None
    try:
        if outcome["execution_status"] == "succeeded" and config["mode"] == "variants":
            directory = pipeline_directory(config, pipeline["payload"])
            observed_path = os.path.join(directory, "variants.vcf")
            fd, metadata = export_file(observed_path)
            os.close(fd)
            outcome["observed_sha256"] = metadata["sha256"]
            if config["evaluator_path"]:
                evaluated = capture_command(
                    [config["python_path"], "-B", "-S", config["evaluator_path"],
                     "--reference", reference, "--expected", config["truth_path"],
                     "--observed", observed_path], env, work, deadline)
                stop_namespace_children()
                fd, after = export_file(observed_path)
                os.close(fd)
                if after != metadata:
                    fail("capsule_observed_changed")
                outcome["evaluated_sha256"] = metadata["sha256"]
                if evaluation_passed(evaluated):
                    outcome["release_status"] = "evaluated_passed"
                else:
                    outcome["release_status"] = "withheld"
                    outcome["error_code"] = "capsule_science_failed"
        analysis_capture = None
        if config["schema_version"] == 2:
            analysis_capture, analysis_error = run_analysis(config, pipeline, input_path, env, work, deadline)
            stop_namespace_children()
            if analysis_error:
                outcome.update(execution_status="failed", release_status="withheld", error_code=analysis_error)
        stop_namespace_children()
        receipt = {"schema_version": config["schema_version"], "input_sha256": input_sha, "input_bytes": input_bytes,
                   "source_pins": sources, "mode": config["mode"], "capsule_state": state,
                   "workspace_policy": {"filesystem": "tmpfs", "bytes": WORKSPACE_LIMIT,
                                        "nr_inodes": 4096, "file_bytes": FILE_LIMIT},
                   "outcome": outcome, "pipeline": pipeline, "evaluation": evaluated,
                   "scope": "synthetic normalized allele presence; no biological accuracy claim"}
        if config["schema_version"] == 2:
            receipt.update(analysis_capture=analysis_capture, analysis_context=config["analysis"]["context"])
        receipt_path = write_receipt(work, receipt)
        fd, metadata = export_file(receipt_path)
        files.append(("execution_receipt", fd, metadata))
        if directory:
            for name, filename in EXPORT_NAMES[1:]:
                fd, metadata = export_file(os.path.join(directory, filename))
                files.append((name, fd, metadata))
            if files[1][2]["sha256"] != outcome["observed_sha256"]:
                fail("capsule_observed_changed")
        if sum(metadata["bytes"] for _, _, metadata in files) > EXPORT_LIMIT:
            fail("capsule_export_limit")
        return outcome, files
    except BaseException:
        for _, fd, _ in files:
            os.close(fd)
        raise


def _interrupted(signum, frame):
    fail("capsule_timeout" if signum == signal.SIGALRM else "capsule_cancelled")


def main():
    os.umask(0o077)
    channel, files, wire_attempted = None, [], False
    started = time.monotonic()
    try:
        if len(sys.argv) != 1 or os.getpid() != 1:
            fail("capsule_namespace_required")
        for fd in (3, 4):
            os.set_inheritable(fd, False)
        channel = socket.socket(fileno=3)
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_STREAM:
            fail("capsule_channel_invalid")
        signal.signal(signal.SIGALRM, _interrupted)
        signal.signal(signal.SIGTERM, _interrupted)
        signal.signal(signal.SIGINT, _interrupted)
        signal.setitimer(signal.ITIMER_REAL, 600)
        raw = sys.stdin.buffer.read(CONFIG_LIMIT + 1)
        if len(raw) > CONFIG_LIMIT:
            fail("capsule_config_limit")
        config = validate_config(parse_json(raw))
        deadline = started + config["timeout_seconds"]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail("capsule_timeout")
        signal.setitimer(signal.ITIMER_REAL, remaining)
        channel.settimeout(remaining)
        outcome, files = execute(config, deadline)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail("capsule_timeout")
        channel.settimeout(remaining)
        wire_attempted = True
        send_frame(channel, outcome, files)
        return 0 if outcome["execution_status"] == "succeeded" else 1
    except BaseException as exc:
        code = exc.code if isinstance(exc, CapsuleError) else "capsule_internal_error"
        if isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
            code = "capsule_workspace_full"
        elif isinstance(exc, OSError) and exc.errno == errno.EFBIG:
            code = "capsule_file_limit"
        if not CODE.fullmatch(code):
            code = "capsule_internal_error"
        if not wire_attempted and channel is not None:
            try:
                stop_namespace_children()
                channel.settimeout(1)
                send_frame(channel, {"execution_status": "failed", "release_status": "withheld",
                                     "error_code": code, "observed_sha256": "",
                                     "evaluated_sha256": ""}, [])
            except BaseException:
                pass
        # Only a stable code, never exception text, source paths or tool output.
        print(code, file=sys.stderr)
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for _, fd, _ in files:
            os.close(fd)
        if channel is not None:
            channel.close()
        # Do not unlink exports or explicitly unmount: received readonly FDs
        # keep tmpfs file objects alive through PID1 exit and parent Wait.


if __name__ == "__main__":
    raise SystemExit(main())
