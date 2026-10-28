#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Root-only, opt-in, one-candidate server update timer.

This never discovers or downloads a release. A trusted SSH client must first
stage a bundle under its exact SHA-256 and explicitly arm that one digest.
The vendored transaction worker performs the same backup and rollback checks
as Connect's manual updater and independently checks the archive again.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time


POLICY = Path("/etc/sovagrid/auto-update.json")
STATUS = Path("/var/lib/sovagrid/auto-update-status.json")
LOCK = Path("/var/lib/sovagrid/.auto-update.lock")
WORKER = Path(__file__).with_name("remote_update_worker.py")
TIMER = "sovagrid-auto-update.timer"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
POLICY_LIFETIME = 14 * 86400
MAX_LIFETIME = 30 * 86400
ROOT_UID = 0


class Refused(Exception):
    pass


def require_root() -> None:
    if os.geteuid() != 0:
        raise Refused("ROOT_REQUIRED")


def digest(value: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise Refused("INVALID_DIGEST")
    return value


def safe_directory(directory: Path) -> None:
    try:
        info = directory.lstat()
    except FileNotFoundError as exc:
        raise Refused("MISSING_DIRECTORY") from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
        raise Refused("UNSAFE_DIRECTORY")


def safe_file(path: Path, *, optional: bool = False) -> bytes | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        if optional:
            return None
        raise Refused("MISSING_FILE")
    except OSError as exc:
        raise Refused("UNSAFE_FILE") from exc
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or
                info.st_size > 4096):
            raise Refused("UNSAFE_FILE")
        return stream.read(4097)


def atomic_private(path: Path, payload: bytes) -> None:
    safe_directory(path.parent)
    if len(payload) > 4096:
        raise Refused("INVALID_STATE")
    if path.exists() or path.is_symlink():
        safe_file(path)
    descriptor, name = tempfile.mkstemp(prefix=".sovagrid-update-", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        temporary.unlink(missing_ok=True)


def json_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def load_policy() -> dict | None:
    safe_directory(POLICY.parent)
    raw = safe_file(POLICY, optional=True)
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise Refused("INVALID_POLICY") from exc
    if (not isinstance(value, dict) or set(value) != {
            "format", "archive_sha256", "expected_current_manifest", "created_at", "expires_at"
    } or type(value["format"]) is not int or value["format"] != 1 or
            type(value["created_at"]) is not int or type(value["expires_at"]) is not int):
        raise Refused("INVALID_POLICY")
    digest(value["archive_sha256"])
    digest(value["expected_current_manifest"])
    if not (0 < value["created_at"] < value["expires_at"] <= value["created_at"] + MAX_LIFETIME):
        raise Refused("INVALID_POLICY")
    return value


def remove_policy() -> None:
    if POLICY.exists() or POLICY.is_symlink():
        safe_file(POLICY)
        POLICY.unlink()
        parent_fd = os.open(POLICY.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)


@contextlib.contextmanager
def exclusive() -> object:
    require_root()
    safe_directory(LOCK.parent)
    try:
        descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as exc:
        raise Refused("UNSAFE_LOCK") from exc
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise Refused("UNSAFE_LOCK")
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield


def worker(*args: str) -> subprocess.CompletedProcess[str]:
    try:
        info = WORKER.lstat()
    except OSError as exc:
        raise Refused("UNSAFE_WORKER") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
        raise Refused("UNSAFE_WORKER")
    try:
        return subprocess.run([sys.executable, "-I", str(WORKER), *args],
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              errors="replace", check=False)
    except OSError as exc:
        raise Refused("WORKER_UNAVAILABLE") from exc


def save_status(state: str, *, policy: dict | None = None, detail: str = "") -> None:
    record = {"format": 1, "state": state, "updated_at": int(time.time()),
              "archive_sha256": policy["archive_sha256"] if policy else None,
              "expected_current_manifest": policy["expected_current_manifest"] if policy else None,
              "detail": detail[:160]}
    atomic_private(STATUS, json_bytes(record))


def arm(archive: str, current: str) -> None:
    archive, current = digest(archive), digest(current)
    with exclusive():
        previous = load_policy()
        # A timer may not have run since a policy expired. In particular,
        # reporting ALREADY_ARMED for an expired identical pin would promise
        # the GUI a live approval that no longer exists.
        if previous is not None and previous["expires_at"] <= int(time.time()):
            remove_policy()
            save_status("expired", policy=previous)
            previous = None
        if previous is not None:
            if (previous["archive_sha256"], previous["expected_current_manifest"]) == (archive, current):
                print("SG_AUTO_UPDATE:ALREADY_ARMED")
                return
            raise Refused("ALREADY_ARMED")
        result = worker("preflight", archive, current)
        if result.returncode != 0 or "SG_UPDATE_PREFLIGHT:OK" not in result.stdout.splitlines():
            raise Refused("PREFLIGHT_FAILED")
        now = int(time.time())
        policy = {"format": 1, "archive_sha256": archive,
                  "expected_current_manifest": current,
                  "created_at": now, "expires_at": now + POLICY_LIFETIME}
        atomic_private(POLICY, json_bytes(policy))
        try:
            subprocess.run(["systemctl", "enable", "--now", TIMER],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as exc:
            remove_policy()
            raise Refused("TIMER_UNAVAILABLE") from exc
        save_status("armed", policy=policy)
        print("SG_AUTO_UPDATE:ARMED")


def disarm() -> None:
    with exclusive():
        policy = load_policy()
        remove_policy()
        save_status("disabled", policy=policy)
        print("SG_AUTO_UPDATE:DISABLED")


def tick() -> None:
    with exclusive():
        policy = load_policy()
        if policy is None:
            return
        if policy["expires_at"] <= int(time.time()):
            remove_policy()
            save_status("expired", policy=policy)
            print("SG_AUTO_UPDATE:EXPIRED")
            return
        try:
            result = worker("apply-auto", policy["archive_sha256"],
                            policy["expected_current_manifest"])
        except Refused as exc:
            remove_policy()
            save_status("needs_attention", policy=policy, detail=str(exc))
            raise
        output = result.stdout.splitlines()
        for line in output:
            if line.startswith(("SG_APPLY_STAGE:", "SG_UPDATE_REFUSE:")):
                print(line, flush=True)
        if result.returncode == 0 and "SG_APPLY_STAGE:DONE" in output:
            remove_policy()
            save_status("applied", policy=policy)
            print("SG_AUTO_UPDATE:APPLIED")
            return
        if "SG_UPDATE_REFUSE:BUSY" in output:
            save_status("deferred_busy", policy=policy)
            print("SG_AUTO_UPDATE:DEFERRED_BUSY")
            return
        # Only BUSY may retry automatically. A failed update, including one
        # whose rollback needs recovery, must be examined before another run.
        remove_policy()
        marker = next((line for line in reversed(output)
                       if line.startswith(("SG_APPLY_STAGE:", "SG_UPDATE_REFUSE:"))), "")
        save_status("needs_attention", policy=policy, detail=marker)
        raise Refused("UPDATE_FAILED")


def status() -> None:
    with exclusive():
        policy = load_policy()
        raw = safe_file(STATUS, optional=True)
        report = {"policy": policy, "last": json.loads(raw) if raw else None}
        print(json.dumps(report, sort_keys=True))


def main(args: list[str]) -> int:
    try:
        if len(args) == 3 and args[0] == "arm":
            arm(args[1], args[2])
        elif args == ["disarm"]:
            disarm()
        elif args == ["run"]:
            tick()
        elif args == ["status"]:
            status()
        else:
            raise Refused("ARGS")
    except Refused as exc:
        print("SG_AUTO_UPDATE_REFUSE:" + str(exc), flush=True)
        return 40
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
