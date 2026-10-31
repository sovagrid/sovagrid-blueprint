#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Prepare two fixed locks before the broker enters its mount sandbox.

Existing inodes and contents are never replaced, truncated or repaired.
After reboot /run is empty, so this also runs as a fixed ExecStartPre command.
"""

import os
from pathlib import Path
import stat


NAMES = ("sovagrid-installation.lock", "sovagrid-promotion.lock")


def ensure(directory: Path = Path("/run"), *, uid: int = 0, gid: int = 0) -> None:
    def checked(value):
        if (not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or
                (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) != (uid, gid, 0o600)):
            raise ValueError("UNSAFE_RUNTIME_LOCK")

    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(parent)
        if ((info.st_uid, info.st_gid) != (uid, gid) or not stat.S_ISDIR(info.st_mode) or
                info.st_mode & 0o022):
            raise ValueError("UNSAFE_RUNTIME_DIRECTORY")
        for name in NAMES:
            created = False
            try:
                descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                created = True
            except FileExistsError:
                checked(os.stat(name, dir_fd=parent, follow_symlinks=False))
                descriptor = os.open(name, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW |
                                     os.O_CLOEXEC, dir_fd=parent)
            try:
                value = os.fstat(descriptor)
                checked(value)
                observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (observed.st_dev, observed.st_ino) != (value.st_dev, value.st_ino):
                    raise ValueError("RUNTIME_LOCK_CHANGED")
                if created:
                    os.fsync(descriptor)
                    os.fsync(parent)
            finally:
                os.close(descriptor)
    finally:
        os.close(parent)


if __name__ == "__main__":
    try:
        if os.geteuid() != 0:
            raise ValueError("ROOT_REQUIRED")
        ensure()
    except (OSError, ValueError):
        raise SystemExit("SovaGrid: runtime locks are missing or unsafe")
