# SPDX-License-Identifier: AGPL-3.0-only
"""Limits for the executable wrapper and its trusted tools, not filesystem quotas.

The CLI lowers its own hard FSIZE before copying or spawning. Tool children
inherit that limit and the job's existing process group. Library calls used by
unit tests do not lower the caller's irreversible process limit.
"""
from dataclasses import dataclass
import errno
import ctypes
import os
import math
from pathlib import Path
import selectors
import signal
import subprocess
import time


class BudgetError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Budget:
    file_bytes: int = 64 << 20
    reference_bytes: int = 32 << 20
    input_bytes: int = 25 << 20
    stdout_bytes: int = 64 << 10
    stderr_bytes: int = 64 << 10
    timeout_seconds: int = 600

    @classmethod
    def from_env(cls):
        defaults = cls()
        values = {}
        names = {"file_bytes": "BIOZERO_PIPELINE_MAX_FILE_BYTES",
                 "reference_bytes": "BIOZERO_PIPELINE_MAX_REFERENCE_BYTES",
                 "input_bytes": "BIOZERO_PIPELINE_MAX_BYTES",
                 "stdout_bytes": "BIOZERO_TOOL_STDOUT_BYTES",
                 "stderr_bytes": "BIOZERO_TOOL_STDERR_BYTES",
                 "timeout_seconds": "BIOZERO_PIPELINE_TIMEOUT_SECONDS"}
        for field, name in names.items():
            raw = os.environ.get(name)
            if raw is None:
                values[field] = getattr(defaults, field)
                continue
            if not raw.isascii() or not raw.isdecimal() or not raw or len(raw) > 19:
                raise BudgetError("resource_config_invalid")
            value = int(raw)
            if not 0 < value <= (1 << 63) - 1:
                raise BudgetError("resource_config_invalid")
            values[field] = value
        budget = cls(**values)
        if os.environ.get("BIOZERO_PIPELINE_GROUP_MODE", "owned") not in ("owned", "shared"):
            raise BudgetError("resource_config_invalid")
        if (budget.reference_bytes > budget.file_bytes or budget.stdout_bytes > (1 << 20)
                or budget.stderr_bytes > (1 << 20) or budget.timeout_seconds > 86400):
            raise BudgetError("resource_config_invalid")
        return budget


def apply_kernel_file_limit(budget):
    """Only the executable's private process lowers the hard kernel limit."""
    try:
        import resource
        # A privileged actor could raise a hard limit again; this is an
        # unprivileged/trusted-tool profile. Capsule cap-drop is a later gate.
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("CapPrm:") and int(line.split()[1], 16) & (1 << 24):
                raise BudgetError("resource_budget_unavailable")
        _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        if hard != resource.RLIM_INFINITY and hard < budget.file_bytes:
            raise BudgetError("resource_budget_unavailable")
        resource.setrlimit(resource.RLIMIT_FSIZE, (budget.file_bytes, budget.file_bytes))
    except BudgetError:
        raise
    except (ImportError, AttributeError, OSError, ValueError):
        raise BudgetError("resource_budget_unavailable") from None


_owns_tool_descendants = False


def own_job_group():
    """Explicit CLI scope; shared capsule mode preserves its owner's group."""
    global _owns_tool_descendants
    mode = os.environ.get("BIOZERO_PIPELINE_GROUP_MODE", "owned")
    if mode not in ("owned", "shared"):
        raise BudgetError("resource_config_invalid")
    try:
        if mode == "owned" and os.getpgrp() != os.getpid():
            os.setpgid(0, 0)
        # Subreaper adoption keeps orphan tool descendants in our tree, without
        # assigning ownership merely because they belong to a process group.
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
        libc.prctl.restype = ctypes.c_int
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), "subreaper unavailable")
        if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
            raise OSError(ctypes.get_errno(), "no-new-privs unavailable")
        fd = os.pidfd_open(os.getpid())
        try:
            signal.pidfd_send_signal(fd, 0)
        finally:
            os.close(fd)
        _owns_tool_descendants = True
    except (OSError, AttributeError):
        raise BudgetError("resource_budget_unavailable") from None


def descendant_pids(root):
    parents = {}
    for entry in os.scandir("/proc"):
        if not entry.name.isdecimal():
            continue
        try:
            with open(entry.path + "/stat", "rb") as stream:
                record = stream.read(16384)
            fields = record[record.rfind(b")") + 2:].split()
            parents[int(entry.name)] = int(fields[1])
        except (OSError, ValueError, IndexError):
            continue
    descendants = set()
    frontier = {root}
    while frontier:
        children = {pid for pid, parent in parents.items() if parent in frontier}
        children -= descendants
        descendants.update(children)
        frontier = children
    return descendants


def kill_job_members(process):
    """Only our tool tree, never another same-PGID process or the capsule owner.

    Executable CLI is a subreaper, so leader-exit descendants are adopted by us.
    Imported helper calls have authority over only their own child subtree.
    """
    if not _owns_tool_descendants and process.returncode is not None:
        return set()
    root = os.getpid() if _owns_tool_descendants else process.pid
    known = set()
    for _ in range(4):
        known.update(descendant_pids(root))
        if process.returncode is None:
            known.add(process.pid)
        for pid in known:
            try:
                fd = os.pidfd_open(pid)
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                finally:
                    os.close(fd)
            except (ProcessLookupError, PermissionError):
                continue
    return known


def reap_adopted(known, leader):
    if not _owns_tool_descendants:
        return
    deadline = time.monotonic() + 1
    pending = known - {leader}
    while pending and time.monotonic() < deadline:
        for pid in tuple(pending):
            try:
                child, _ = os.waitpid(pid, os.WNOHANG)
                if child:
                    pending.remove(pid)
            except ChildProcessError:
                pending.remove(pid)
        if pending:
            time.sleep(0.005)


def bounded_command(cmd, stdout_path=None, timeout_seconds=None, budget=None, cwd=None):
    budget = budget or Budget.from_env()
    timeout_seconds = budget.timeout_seconds if timeout_seconds is None else timeout_seconds
    if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 86400:
        raise BudgetError("resource_config_invalid")
    deadline = time.monotonic() + timeout_seconds
    captures = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": budget.stdout_bytes, "stderr": budget.stderr_bytes}
    failure = ""
    process = None
    output = None
    phase = "open"
    environment = dict(os.environ)
    if cwd is not None:
        environment["TMPDIR"] = str(cwd)
        environment["TMP"] = str(cwd)
        environment["TEMP"] = str(cwd)
    try:
        if stdout_path is not None:
            fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            output = os.fdopen(fd, "wb")
        # No shell, setsid or new child group: Go's cancellation reaches tools.
        phase = "start"
        process = subprocess.Popen(cmd, stdout=output or subprocess.PIPE,
                                   stderr=subprocess.PIPE, cwd=cwd, env=environment)
        phase = "capture"
        with selectors.DefaultSelector() as selector:
            streams = [("stderr", process.stderr)]
            if output is None:
                streams.append(("stdout", process.stdout))
            for name, stream in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = "timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.05)):
                    chunk = os.read(key.fd, 16384)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    name = key.data
                    available = limits[name] - len(captures[name])
                    captures[name].extend(chunk[:available])
                    if len(chunk) > available:
                        failure = "tool_output_limit"
                        break
                if failure:
                    break
        killed = set()
        if failure:
            killed.update(kill_job_members(process))
        # EOF alone does not establish leader exit; it may close both streams
        # while remaining alive. The same total stage deadline covers that wait.
        try:
            returncode = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            failure = failure or "timeout"
            killed.update(kill_job_members(process))
            returncode = process.wait(timeout=2)
        killed.update(kill_job_members(process))
        reap_adopted(killed, process.pid)
        if returncode == -signal.SIGXFSZ and not failure:
            failure = "artifact_file_limit"
        if output is not None:
            phase = "sync"
            output.flush()
            os.fsync(output.fileno())
        if failure:
            returncode = 124 if failure == "timeout" else 125
    except OSError as exc:
        if process is not None:
            killed = kill_job_members(process)
            process.wait(timeout=2)
            reap_adopted(killed, process.pid)
        failure = "artifact_file_limit" if exc.errno == errno.EFBIG else ("tool_start_failed" if phase == "start" else "tool_io_failed")
        returncode = 125 if failure == "artifact_file_limit" else 127
    finally:
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        if output is not None:
            output.close()
    result = subprocess.CompletedProcess(cmd, returncode,
        captures["stdout"].decode("utf-8", errors="replace"),
        captures["stderr"].decode("utf-8", errors="replace"))
    result.error_code = failure
    return result
