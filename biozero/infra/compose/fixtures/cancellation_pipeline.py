#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fixed lifecycle fixture: read the protected input, publish readiness, wait.

This intentionally produces no scientific output. The capsule/provider, rather
than this marker, remains the resource, termination and export authority.
"""
import hashlib
import json
import os
import stat
import sys
import time


def main():
    if len(sys.argv) < 2:
        return 1
    descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= 25 << 20:
            return 1
        sha, total = hashlib.sha256(), 0
        while True:
            raw = os.read(descriptor, 65536)
            if not raw:
                break
            total += len(raw)
            if total > 25 << 20:
                return 1
            sha.update(raw)
        if total != info.st_size:
            return 1
    finally:
        os.close(descriptor)
    status = {}
    with open("/proc/self/status", encoding="ascii") as stream:
        for line in stream:
            key, _, value = line.partition(":")
            if key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"):
                status[key] = value.strip()
    marker = {"schema_version": 1, "phase": "waiting_for_cancellation", "pid": os.getpid(),
              "input_sha256": sha.hexdigest(), "input_bytes": total, "status": status}
    raw = json.dumps(marker, separators=(",", ":")).encode("ascii")
    if len(raw) > 1024:
        return 1
    marker_fd = os.open("/workspace/cancellation-ready.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        if os.write(marker_fd, raw) != len(raw):
            return 1
        os.fsync(marker_fd)
    finally:
        os.close(marker_fd)
    # Finite even if the test fails to send Cancel; the provider's own60second
    # deadline should fire first. Neither exit path can approve science.
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        time.sleep(0.05)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
