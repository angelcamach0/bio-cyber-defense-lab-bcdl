#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Pinned stdlib Docker PID1 helper; configuration is a trusted local API.

The host fixes image, mounts, user, namespaces and resource flags. This helper
observes those boundaries; it never creates mounts, raises limits or changes caps.
stdin <=64KiB: {schema_version:1,native_helper_sha256,execution:<nativeSpec>}.
The fixed Unix socket supplies byte I plus exactly one readonly SCM_RIGHTS input.
The response is the unchanged nativeResponse frame/ordered readonly export FDs.
Only Docker Wait outside the capsule establishes the provider completion boundary.
"""
import array
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
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
import sys
import threading
import time

CONFIG_LIMIT = 64 << 10
HELPER_LIMIT = 4 << 20
FILE_LIMIT = 64 << 20
WORKSPACE_LIMIT = 128 << 20
INODE_UNITS = 4096
TMPFS_MAGIC = 0x01021994
WORKSPACE = "/workspace"
NATIVE_PATH = "/run/biozero/helpers/native_capsule.py"
CONTROL_PATH = "/run/biozero/channel/control.sock"
FIXED_PATHS = {"workspace": WORKSPACE, "pipeline_path": "/run/biozero/pipeline/pipeline.py",
               "reference_path": "/run/biozero/reference.fa",
               "evaluator_path": "/run/biozero/evaluator/evaluate_variants.py",
               "truth_path": "/run/biozero/truth.vcf",
               "python_path": "/usr/bin/python3.12", "tool_path": "/usr/bin"}
HASH = re.compile(r"[0-9a-f]{64}\Z")
CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class ContainerError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def fail(code):
    raise ContainerError(code)


def bootstrap_json(raw):
    """Minimal strict bootstrap, before executing the pinned native module."""
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                fail("capsule_json_invalid")
            value[key] = item
        return value
    def finite(value, depth=0):
        if depth > 64 or (type(value) is float and not math.isfinite(value)):
            fail("capsule_json_invalid")
        if type(value) is dict:
            for child in value.values():
                finite(child, depth + 1)
        elif type(value) is list:
            for child in value:
                finite(child, depth + 1)
    if len(raw) > CONFIG_LIMIT:
        fail("capsule_config_limit")
    try:
        result = json.loads(raw, object_pairs_hook=pairs,
                            parse_constant=lambda _: fail("capsule_json_invalid"))
        finite(result)
    except (ValueError, UnicodeError, RecursionError):
        fail("capsule_json_invalid")
    if type(result) is not dict or set(result) != {"schema_version", "native_helper_sha256", "execution"}:
        fail("capsule_config_invalid")
    if type(result["schema_version"]) is not int or result["schema_version"] != 1:
        fail("capsule_config_invalid")
    pin = result["native_helper_sha256"]
    if type(pin) is not str or not HASH.fullmatch(pin) or type(result["execution"]) is not dict:
        fail("capsule_config_invalid")
    return result


def anchored_open(path, directory=False, socket_node=False):
    """Bootstrap no-follow traversal; no import of an unverified helper."""
    if not path.startswith("/") or os.path.normpath(path) != path or path == "/" or "\x00" in path:
        fail("capsule_source_unsafe")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        parts = path[1:].split("/")
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            flags = os.O_CLOEXEC | os.O_NOFOLLOW
            if final and socket_node:
                flags |= os.O_PATH
            else:
                flags |= os.O_RDONLY | os.O_NONBLOCK
            if not final or directory:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        valid = stat.S_ISSOCK(info.st_mode) if socket_node else (
            stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        if not valid:
            fail("capsule_source_unsafe")
        result, fd = fd, -1
        return result
    except OSError:
        fail("capsule_source_unsafe")
    finally:
        if fd >= 0:
            os.close(fd)


def read_pinned(fd, pin):
    """Read/hash one stable descriptor before any execution of its code."""
    try:
        before = os.fstat(fd)
        if before.st_size > HELPER_LIMIT:
            fail("capsule_source_size")
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, HELPER_LIMIT - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > HELPER_LIMIT:
                fail("capsule_source_size")
            chunks.append(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            fail("capsule_source_changed")
        raw = b"".join(chunks)
        if len(raw) != before.st_size or hashlib.sha256(raw).hexdigest() != pin:
            fail("capsule_source_pin_mismatch")
        return raw
    except OSError:
        fail("capsule_source_unsafe")


def load_native(pin):
    with open("/proc/self/mountinfo", encoding="ascii") as stream:
        mounts = parse_mountinfo(stream.read((2 << 20) + 1))
    if "ro" not in covering_mount(mounts, NATIVE_PATH)["options"]:
        fail("capsule_container_source_not_readonly")
    fd = anchored_open(NATIVE_PATH)
    try:
        raw = read_pinned(fd, pin)
    finally:
        os.close(fd)
    spec = importlib.util.spec_from_file_location("biozero_pinned_native_capsule", NATIVE_PATH)
    module = importlib.util.module_from_spec(spec)
    # Compile precisely the bytes checked above, avoiding a second path-based read.
    exec(compile(raw, NATIVE_PATH, "exec"), module.__dict__)
    return module


def validate_execution(native, wrapper):
    config = native.validate_config(wrapper["execution"])
    for key, expected in FIXED_PATHS.items():
        if key in ("reference_path", "evaluator_path", "truth_path") and config[key] == "":
            continue  # Native optional/pairing rules remain intact.
        if config[key] != expected:
            fail("capsule_container_path_invalid")
    return config


def parse_mountinfo(raw):
    if len(raw) > 2 << 20:
        fail("capsule_mountinfo_invalid")
    result = []
    def unescape(value):
        return re.sub(r"\\(040|011|012|134)", lambda m: chr(int(m[1], 8)), value)
    for line in raw.splitlines():
        parts = line.split(" - ")
        if len(parts) != 2:
            fail("capsule_mountinfo_invalid")
        left, right = parts[0].split(), parts[1].split()
        if len(left) < 6 or len(right) != 3:
            fail("capsule_mountinfo_invalid")
        result.append({"mountpoint": unescape(left[4]), "options": left[5].split(","),
                       "filesystem": right[0], "super_options": right[2].split(","),
                       "optional": left[6:]})
    return result


def covering_mount(mounts, path):
    candidates = [entry for entry in mounts if entry["mountpoint"] == "/"
                  or path == entry["mountpoint"] or path.startswith(entry["mountpoint"] + "/")]
    if not candidates:
        fail("capsule_mountinfo_invalid")
    maximum = max(len(entry["mountpoint"]) for entry in candidates)
    active = [entry for entry in candidates if len(entry["mountpoint"]) == maximum]
    if len(active) != 1:
        fail("capsule_mountinfo_invalid")
    return active[0]


class StatFS(ctypes.Structure):
    # Linux 64-bit statfs ABI on the approved arm64/amd64 container profiles.
    _fields_ = [("type", ctypes.c_long), ("bsize", ctypes.c_long),
                ("blocks", ctypes.c_ulong), ("bfree", ctypes.c_ulong), ("bavail", ctypes.c_ulong),
                ("files", ctypes.c_ulong), ("ffree", ctypes.c_ulong), ("fsid", ctypes.c_int * 2),
                ("namelen", ctypes.c_long), ("frsize", ctypes.c_long), ("flags", ctypes.c_long),
                ("spare", ctypes.c_long * 4)]


def statfs(path):
    if ctypes.sizeof(ctypes.c_long) != 8 or os.uname().machine not in ("aarch64", "x86_64"):
        fail("capsule_statfs_unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.statfs.argtypes = [ctypes.c_char_p, ctypes.POINTER(StatFS)]
    libc.statfs.restype = ctypes.c_int
    value = StatFS()
    if libc.statfs(os.fsencode(path), ctypes.byref(value)) != 0:
        fail("capsule_statfs_unavailable")
    return {"filesystem_magic": value.type, "block_bytes": value.frsize,
            "capacity_bytes": value.blocks * value.frsize, "inode_units": value.files,
            "free_inode_units": value.ffree, "flags": value.flags}


def observe_cgroup():
    def read_small(path):
        fd = anchored_open(path)
        try:
            raw = os.read(fd, 4097)
            if len(raw) > 4096:
                fail("capsule_cgroup_limits_unavailable")
            return raw.decode("ascii").strip()
        finally:
            os.close(fd)
    # /proc/self is intentionally a kernel symlink; the no-follow reader uses
    # this already-checked PID's numeric directory instead.
    return {"membership": read_small("/proc/%d/cgroup" % os.getpid()),
            "namespace": os.readlink("/proc/self/ns/cgroup"),
            **{name: read_small("/sys/fs/cgroup/" + name)
               for name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max")}}


def validate_cgroup(observation, mounts):
    def decimal(value):
        if type(value) is not str or not value or len(value) > 19 or not value.isascii() or not value.isdecimal():
            fail("capsule_cgroup_limits_unavailable")
        return int(value)
    mounted = covering_mount(mounts, "/sys/fs/cgroup")
    if (mounted["filesystem"] != "cgroup2" or "ro" not in mounted["options"]
            or observation.get("membership") != "0::/"
            or not re.fullmatch(r"cgroup:\[\d+\]", observation.get("namespace", ""))):
        fail("capsule_cgroup_limits_unavailable")
    if (decimal(observation.get("memory.max")) != 512 << 20
            or decimal(observation.get("memory.swap.max")) != 0
            or decimal(observation.get("pids.max")) != 128):
        fail("capsule_cgroup_limits_unavailable")
    cpu = observation.get("cpu.max")
    if type(cpu) is not str or len(cpu) > 41 or len(cpu.split()) != 2:
        fail("capsule_cgroup_limits_unavailable")
    quota, period = map(decimal, cpu.split())
    if quota != period or quota <= 0:
        fail("capsule_cgroup_limits_unavailable")


def observe_kernel(native):
    state = native.process_state()
    state.update(euid=os.geteuid(), egid=os.getegid())
    with open("/proc/self/mountinfo", encoding="ascii") as stream:
        mounts = parse_mountinfo(stream.read((2 << 20) + 1))
    with open("/proc/net/dev", encoding="ascii") as stream:
        interfaces = [line.split(":", 1)[0].strip() for line in stream if ":" in line]
    state.update(mounts=mounts, interfaces=interfaces, root_statfs=statfs("/"),
                 workspace_statfs=statfs(WORKSPACE), cgroup=observe_cgroup())
    fd = anchored_open(WORKSPACE, directory=True)
    try:
        info = os.fstat(fd)
        state["workspace_directory"] = {"uid": info.st_uid, "gid": info.st_gid,
                                         "mode": stat.S_IMODE(info.st_mode), "empty": not os.listdir(fd)}
    finally:
        os.close(fd)
    return state


def validate_kernel(state, config):
    """Pure predicates: tmpfs is aggregate enforcement; FSIZE is supplementary."""
    if any(type(state.get(key)) is not int or state[key] != value for key, value in (
            ("pid", 1), ("uid", 1000), ("euid", 1000), ("gid", 1000), ("egid", 1000))):
        fail("capsule_namespace_required")
    try:
        zero_caps = all(int(state[key], 16) == 0 for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
    except (KeyError, ValueError, TypeError):
        zero_caps = False
    if not zero_caps or state.get("NoNewPrivs") != "1":
        fail("capsule_container_capabilities_invalid")
    if state.get("interfaces") != ["lo"]:
        fail("capsule_network_not_private")
    if state.get("rlimit_fsize") != [FILE_LIMIT, FILE_LIMIT]:
        fail("capsule_file_limit_unavailable")
    mounts = state["mounts"]
    validate_cgroup(state.get("cgroup", {}), mounts)
    root, work = covering_mount(mounts, "/"), covering_mount(mounts, WORKSPACE)
    if "ro" not in root["options"] or "rw" in root["options"] or not state["root_statfs"]["flags"] & 1:
        fail("capsule_container_root_not_readonly")
    fs = state["workspace_statfs"]
    if (work["mountpoint"] != WORKSPACE or work["filesystem"] != "tmpfs"
            or not {"rw", "nosuid", "nodev", "noexec"}.issubset(work["options"])
            or any(option.startswith(("shared:", "master:")) for option in work["optional"])
            or fs["filesystem_magic"] != TMPFS_MAGIC or fs["capacity_bytes"] != WORKSPACE_LIMIT
            or fs["inode_units"] != INODE_UNITS or fs["flags"] & 1):
        fail("capsule_workspace_quota_unavailable")
    directory = state["workspace_directory"]
    if directory != {"uid": 1000, "gid": 1000, "mode": 0o700, "empty": True}:
        fail("capsule_workspace_unsafe")
    paths = [NATIVE_PATH, "/run/biozero/helpers/container_capsule.py", CONTROL_PATH, config["pipeline_path"],
             "/run/biozero/pipeline/resource_budget.py", config["python_path"]]
    paths += [config[key] for key in ("reference_path", "evaluator_path", "truth_path") if config[key]]
    paths += config["tool_path"].split(":")
    if any("ro" not in covering_mount(mounts, path)["options"] for path in paths):
        fail("capsule_container_source_not_readonly")
    namespace = state.get("namespaces", {}).get("pid", "")
    if not re.fullmatch(r"pid:\[\d+\]", namespace):
        fail("capsule_namespace_required")
    return namespace


def validate_peer_credentials(raw):
    if len(raw) != struct.calcsize("3i"):
        fail("capsule_channel_invalid")
    _, uid, _ = struct.unpack("3i", raw)
    if uid != 1000:
        fail("capsule_peer_forbidden")


def connect_control():
    directory_fd = anchored_open(os.path.dirname(CONTROL_PATH), directory=True)
    metadata_fd = anchored_open(CONTROL_PATH, socket_node=True)
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        directory, metadata = os.fstat(directory_fd), os.fstat(metadata_fd)
        if (directory.st_uid != 1000 or stat.S_IMODE(directory.st_mode) != 0o700
                or metadata.st_uid != 1000 or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1):
            fail("capsule_channel_invalid")
        # Keep the no-follow parent anchor through connect; host mutation remains
        # trusted, while source path aliases cannot redirect directory traversal.
        channel.settimeout(10)
        channel.connect("/proc/self/fd/%d/control.sock" % directory_fd)
        credentials = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        validate_peer_credentials(credentials)
        os.set_inheritable(channel.fileno(), False)
        return channel
    except BaseException:
        channel.close()
        raise
    finally:
        os.close(metadata_fd)
        os.close(directory_fd)


def receive_input_descriptor(channel):
    descriptors = []
    try:
        data, ancillary, flags, _ = channel.recvmsg(2, socket.CMSG_SPACE(2 * array.array("i").itemsize),
                                                   socket.MSG_CMSG_CLOEXEC)
        valid = True
        for level, kind, raw in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS or len(raw) % array.array("i").itemsize:
                valid = False
                continue
            rights = array.array("i")
            rights.frombytes(raw)
            descriptors.extend(rights)
        if (data != b"I" or not valid or len(descriptors) != 1
                or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)):
            fail("capsule_input_transport_invalid")
        return descriptors.pop()
    finally:
        for fd in descriptors:
            os.close(fd)


def input_metadata(fd):
    info = os.fstat(fd)
    return {"regular": stat.S_ISREG(info.st_mode), "uid": info.st_uid, "nlink": info.st_nlink,
            "mode": stat.S_IMODE(info.st_mode), "bytes": info.st_size,
            "readonly": fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY,
            "cloexec": bool(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)}


def validate_input_metadata(metadata, expected_bytes):
    if (type(metadata) is not dict or any(type(metadata.get(key)) is not int for key in ("uid", "nlink", "mode", "bytes"))
            or any(type(metadata.get(key)) is not bool for key in ("regular", "readonly", "cloexec"))
            or metadata != {"regular": True, "uid": 1000, "nlink": 1, "mode": 0o600,
                            "bytes": expected_bytes, "readonly": True, "cloexec": True}):
        fail("capsule_input_unsafe")


def receive_input(channel, config):
    fd = receive_input_descriptor(channel)
    try:
        validate_input_metadata(input_metadata(fd), config["input_bytes"])
        return fd
    except BaseException:
        os.close(fd)
        raise


class KeeperMonitor:
    """EOF is cancellation only. It is never a storage/quiescence proof."""
    def __init__(self, channel, on_loss):
        self.channel, self.on_loss = channel, on_loss
        self.lock = threading.Lock()
        self.stopping = False
        self.thread = threading.Thread(target=self._run, name="biozero-keeper-monitor", daemon=True)

    def start(self):
        self.thread.start()

    def _run(self):
        selector = selectors.DefaultSelector()
        try:
            selector.register(self.channel, selectors.EVENT_READ)
            while True:
                with self.lock:
                    if self.stopping:
                        return
                if not selector.select(0.05):
                    continue
                try:
                    data = self.channel.recv(1, socket.MSG_DONTWAIT)
                    reason = "capsule_keeper_closed" if not data else "capsule_keeper_unexpected_data"
                except BlockingIOError:
                    continue
                except OSError:
                    reason = "capsule_keeper_channel_error"
                with self.lock:
                    if not self.stopping:
                        self.on_loss(reason)
                    return
        except BaseException:
            with self.lock:
                if not self.stopping:
                    self.on_loss("capsule_keeper_monitor_error")
        finally:
            selector.close()

    def stop(self):
        # Main disarms only after the final transfer or a terminal failure. A
        # concurrent observed loss either wins first or is ignored on normal exit.
        with self.lock:
            self.stopping = True
        self.thread.join(timeout=1)


def identity_matches(namespace):
    return (os.getpid() == 1 and os.getuid() == os.geteuid() == 1000
            and os.getgid() == os.getegid() == 1000
            and os.readlink("/proc/self/ns/pid") == namespace)


def keeper_lost(namespace, reason):
    # The monitor is created only after PID1/caps/NNP verification. Direct exit
    # cannot be ignored by namespace PID1 signal rules. Kernel teardown kills its
    # descendants. This requests cancellation, never proof; host still Docker Waits.
    os._exit(1)


def stop_children(namespace):
    if not identity_matches(namespace):
        fail("capsule_namespace_required")
    try:
        os.kill(-1, signal.SIGKILL)
    except ProcessLookupError:
        pass
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
            if not pid:
                return
        except ChildProcessError:
            return


def export_file(native, path):
    fd = native.open_anchored(path)
    try:
        info = os.fstat(fd)
        if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 1000 or info.st_nlink != 1:
            fail("capsule_output_unsafe")
        digest, size = native.hash_fd(fd, FILE_LIMIT)
        return fd, {"sha256": digest, "bytes": size}
    except BaseException:
        os.close(fd)
        raise


def execute(native, config, input_fd, state, namespace, deadline, native_pin):
    sources = native.verify_sources(config)
    work = config["workspace"]
    magic = os.pread(input_fd, 2, 0)
    input_path = os.path.join(work, "input.fastq.gz" if magic == b"\x1f\x8b" else "input.fastq")
    input_sha, input_bytes = native.copy_exact(input_fd, input_path, native.INPUT_LIMIT,
                                              config["input_bytes"], config["input_sha256"])
    reference = ""
    if config["reference_path"]:
        reference = os.path.join(work, "reference.fa")
        fd = native.open_anchored(config["reference_path"])
        try:
            native.copy_exact(fd, reference, native.REFERENCE_LIMIT, expected_sha=config["reference_sha256"])
        finally:
            os.close(fd)
    os.chdir(work)
    env = native.fixed_environment(config, work)
    command = [config["python_path"], "-B", "-S", config["pipeline_path"], input_path,
               "--out-dir", work, "--mode", config["mode"]]
    if reference:
        command.extend(["--reference", reference])
    pipeline = native.capture_command(command, env, work, deadline)
    stop_children(namespace)
    outcome = native.pipeline_outcome(pipeline, config["mode"])
    files, directory, evaluated = [], None, None
    try:
        if outcome["execution_status"] == "succeeded" and config["mode"] == "variants":
            directory = native.pipeline_directory(config, pipeline["payload"])
            observed = os.path.join(directory, "variants.vcf")
            fd, metadata = export_file(native, observed)
            os.close(fd)
            outcome["observed_sha256"] = metadata["sha256"]
            if config["evaluator_path"]:
                evaluated = native.capture_command(
                    [config["python_path"], "-B", "-S", config["evaluator_path"],
                     "--reference", reference, "--expected", config["truth_path"], "--observed", observed],
                    env, work, deadline)
                stop_children(namespace)
                fd, after = export_file(native, observed)
                os.close(fd)
                if metadata != after:
                    fail("capsule_observed_changed")
                outcome["evaluated_sha256"] = metadata["sha256"]
                if native.evaluation_passed(evaluated):
                    outcome["release_status"] = "evaluated_passed"
                else:
                    outcome["release_status"], outcome["error_code"] = "withheld", "capsule_science_failed"
        stop_children(namespace)
        receipt = {"schema_version": 1, "capsule_kind": "docker", "input_sha256": input_sha,
                   "input_bytes": input_bytes, "native_helper_sha256": native_pin, "source_pins": sources,
                   "mode": config["mode"], "capsule_state": state, "outcome": outcome,
                   "workspace_policy": {"filesystem": "tmpfs", "bytes": WORKSPACE_LIMIT,
                                        "nr_inodes": INODE_UNITS, "file_bytes": FILE_LIMIT},
                   "pipeline": pipeline, "evaluation": evaluated,
                   "keeper_monitor": "active; EOF/error is cancellation, never proof",
                   "scope": "synthetic normalized allele presence; no biological accuracy claim"}
        fd, metadata = export_file(native, native.write_receipt(work, receipt))
        files.append(("execution_receipt", fd, metadata))
        if directory:
            for name, filename in native.EXPORT_NAMES[1:]:
                fd, metadata = export_file(native, os.path.join(directory, filename))
                files.append((name, fd, metadata))
            if files[1][2]["sha256"] != outcome["observed_sha256"]:
                fail("capsule_observed_changed")
        if sum(metadata["bytes"] for _, _, metadata in files) > native.EXPORT_LIMIT:
            fail("capsule_export_limit")
        return outcome, files
    except BaseException:
        for _, fd, _ in files:
            os.close(fd)
        raise


def send_bootstrap_failure(channel, code):
    payload = json.dumps({"schema_version": 1, "outcome": {"execution_status": "failed",
                         "release_status": "withheld", "error_code": code,
                         "observed_sha256": "", "evaluated_sha256": ""}, "files": []},
                         separators=(",", ":"), allow_nan=False).encode("ascii")
    channel.sendall(struct.pack("!I", len(payload)) + payload)


def interrupted(signum, frame):
    fail("capsule_timeout" if signum == signal.SIGALRM else "capsule_cancelled")


def main():
    os.umask(0o077)
    channel, native, monitor, input_fd, namespace = None, None, None, -1, None
    files, wire_attempted = [], False
    started = time.monotonic()
    try:
        if len(sys.argv) != 1 or os.getpid() != 1 or os.getuid() != 1000 or os.geteuid() != 1000:
            fail("capsule_namespace_required")
        signal.signal(signal.SIGALRM, interrupted)
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        signal.setitimer(signal.ITIMER_REAL, 600)
        channel = connect_control()
        raw = sys.stdin.buffer.read(CONFIG_LIMIT + 1)
        wrapper = bootstrap_json(raw)
        native = load_native(wrapper["native_helper_sha256"])
        # Recheck the complete bootstrap with the pinned implementation's parser.
        if native.parse_json(raw) != wrapper:
            fail("capsule_json_invalid")
        config = validate_execution(native, wrapper)
        deadline = started + config["timeout_seconds"]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail("capsule_timeout")
        signal.setitimer(signal.ITIMER_REAL, remaining)
        channel.settimeout(remaining)
        state = observe_kernel(native)
        namespace = validate_kernel(state, config)
        input_fd = receive_input(channel, config)
        monitor = KeeperMonitor(channel, lambda reason: keeper_lost(namespace, reason))
        monitor.start()
        outcome, files = execute(native, config, input_fd, state, namespace, deadline,
                                 wrapper["native_helper_sha256"])
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail("capsule_timeout")
        channel.settimeout(remaining)
        wire_attempted = True
        native.send_frame(channel, outcome, files)
        return 0 if outcome["execution_status"] == "succeeded" else 1
    except BaseException as exc:
        code = "capsule_internal_error"
        if isinstance(exc, ContainerError) or (native is not None and isinstance(exc, native.CapsuleError)):
            code = exc.code
        elif isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
            code = "capsule_workspace_full"
        elif isinstance(exc, OSError) and exc.errno == errno.EFBIG:
            code = "capsule_file_limit"
        if not CODE.fullmatch(code):
            code = "capsule_internal_error"
        if namespace is not None:
            try:
                stop_children(namespace)
            except BaseException:
                pass
        if channel is not None and not wire_attempted:
            try:
                channel.settimeout(1)
                wire_attempted = True
                send_bootstrap_failure(channel, code)
            except BaseException:
                pass
        print(code, file=sys.stderr)
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        if monitor is not None:
            monitor.stop()
        for _, fd, _ in files:
            os.close(fd)
        if input_fd >= 0:
            os.close(input_fd)
        if channel is not None:
            channel.close()
        # Never unlink exports or fabricate proof. Received FDs retain tmpfs file
        # objects after PID1 exit; host waits for Docker before trusting exports.


if __name__ == "__main__":
    raise SystemExit(main())
