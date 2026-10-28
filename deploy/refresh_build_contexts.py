#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Refresh local BuildKit metadata after extracting reproducible source archives.

Archive timestamps remain deterministic. Only installed regular-file mtimes in
the two fixed build contexts change; contents, permissions and atimes do not.
BuildKit's incremental local transfer can otherwise mistake equal-size files
with equal epoch timestamps for unchanged input.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import time

CONTEXTS = ("sovagrid-hub", "sovagrid-web")
EXCLUDED = frozenset((".git", ".venv", "__pycache__"))
MAX_ENTRIES = 4096
MAX_BYTES = 256 * 1024 * 1024
MAX_DEPTH = 32


class BuildContextError(RuntimeError):
    pass


def directory(info):
    if not stat.S_ISDIR(info.st_mode):
        raise BuildContextError("INVALID_CONTEXT")


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns)


def refresh(source_root: Path) -> int:
    """Validate both complete walks before changing any file metadata."""
    source_root = Path(source_root)
    if not source_root.is_absolute():
        raise BuildContextError("INVALID_CONTEXT")
    directory(source_root.lstat())  # Reject a linked root, without following it.
    source_root = source_root.resolve(strict=True)
    files = []
    entries = total_bytes = 0
    for name in CONTEXTS:
        root = source_root / name
        directory(root.lstat())
        pending = [(root, 0)]
        while pending:
            parent, depth = pending.pop()
            if depth > MAX_DEPTH:
                raise BuildContextError("CONTEXT_TOO_LARGE")
            with os.scandir(parent) as children:
                for child in children:
                    # Never inspect or follow local VCS/runtime cache entries.
                    if child.name in EXCLUDED:
                        continue
                    entries += 1
                    if entries > MAX_ENTRIES:
                        raise BuildContextError("CONTEXT_TOO_LARGE")
                    info = child.stat(follow_symlinks=False)
                    path = parent / child.name
                    if stat.S_ISDIR(info.st_mode):
                        pending.append((path, depth + 1))
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                        total_bytes += info.st_size
                        if total_bytes > MAX_BYTES:
                            raise BuildContextError("CONTEXT_TOO_LARGE")
                        files.append((path, info))
                    else:
                        raise BuildContextError("INVALID_CONTEXT")
    # Use a common fresh nanosecond value, including on filesystems where the
    # current clock happens to equal a previous timestamp exactly.
    stamp = time.time_ns()
    old_stamps = {info.st_mtime_ns for _path, info in files}
    while stamp in old_stamps:
        stamp += 1
    if not 0 < stamp < 2**63:
        raise BuildContextError("INVALID_CLOCK")
    for path, expected in files:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            actual = os.fstat(descriptor)
            if identity(actual) != identity(expected):
                raise BuildContextError("CONTEXT_CHANGED")
            os.utime(descriptor, ns=(expected.st_atime_ns, stamp))
            if os.fstat(descriptor).st_mtime_ns == expected.st_mtime_ns:
                raise BuildContextError("REFRESH_FAILED")
        finally:
            os.close(descriptor)
    return len(files)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        return 2
    try:
        refresh(Path(args[0]))
    except (BuildContextError, OSError, ValueError, OverflowError):
        print("SovaGrid: build context metadata could not be refreshed safely", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
