#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Sync or verify the exact Connect Python package carried by the server bundle.

No network fetch is performed. ``sync`` reads committed Git blobs from the
pinned Connect revision in a separate checkout, even when its HEAD has moved.
``check`` verifies the vendored bytes offline and, when --source is supplied,
compares every byte with that exact upstream commit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor/connect"
PACKAGE = VENDOR / "sovagrid_connect"
LOCK = VENDOR / "SOURCE.json"
UPSTREAM = "https://github.com/sovagrid/sovagrid-connect"
UPSTREAM_COMMIT = "7353ffc880fcb3b3202187f1bff01731b12400f9"
# Runtime-only Ubuntu closure for AgentEnrollment, EnrollmentAPI and AgentRPC.
# core.ssh_grant and enrollment_journal.keygen are used only by the desktop UI
# and Windows branches; the server worker never invokes those paths.
SELECTED_FILES = frozenset("sovagrid_connect/" + name for name in (
    "__init__.py", "agent_enrollment.py", "agent_rpc.py", "askpass.py", "core.py",
    "enrollment_api.py", "enrollment_journal.py", "enrollment_protocol.py",
    "installer.py", "remote_update.py", "server_status.py", "server_timer.py",
    "theme.py", "legal/LICENSE", "legal/ATTRIBUTION.md", "legal/NOTICE",
))
_SAFE_PART = re.compile(r"[A-Za-z0-9_.-]+\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class VendorError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VendorError(message)


def safe_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    require(path.parts and path.parts[0] == "sovagrid_connect" and
            len(path.parts) >= 2 and not path.is_absolute() and
            all(_SAFE_PART.fullmatch(part) and part not in (".", "..") for part in path.parts) and
            path.as_posix() == value, "Unexpected upstream package path")
    return path


def git(repo: Path, *args: str) -> bytes:
    try:
        return subprocess.check_output(("git", "-C", str(repo), *args), stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        raise VendorError("Cannot read the pinned Connect Git checkout") from None


def source_files(repo: Path) -> dict[str, tuple[int, bytes]]:
    require(repo.is_dir() and not repo.is_symlink(), "Connect checkout is missing")
    raw = git(repo, "ls-tree", "-r", "-z", "--full-tree", UPSTREAM_COMMIT, "--", "sovagrid_connect")
    result: dict[str, tuple[int, bytes]] = {}
    for item in raw.split(b"\0"):
        if not item:
            continue
        metadata, separator, name = item.partition(b"\t")
        fields = metadata.split()
        require(separator == b"\t" and len(fields) == 3 and fields[1] == b"blob" and
                fields[0] in (b"100644", b"100755") and
                re.fullmatch(rb"[0-9a-f]{40,64}", fields[2]) is not None,
                "Unsupported upstream Git entry")
        path = os.fsdecode(name)
        safe_path(path)
        require(path not in result, "Duplicate upstream Git path")
        if path in SELECTED_FILES:
            result[path] = (0o755 if fields[0] == b"100755" else 0o644,
                            git(repo, "cat-file", "blob", fields[2].decode("ascii")))
    require(set(result) == SELECTED_FILES, "Pinned Connect runtime closure is incomplete")
    return result


def tree_sha256(files: dict[str, tuple[int, bytes]]) -> str:
    digest = hashlib.sha256()
    for name, (mode, contents) in sorted(files.items()):
        safe_path(name)
        require(mode in (0o644, 0o755), "Unexpected package file mode")
        digest.update(name.encode("utf-8") + b"\0" + format(mode, "o").encode("ascii") + b"\0" +
                      hashlib.sha256(contents).hexdigest().encode("ascii") + b"\n")
    return digest.hexdigest()


def vendor_files(package: Path = PACKAGE, *, exact: bool = True) -> dict[str, tuple[int, bytes]]:
    require(package.is_dir() and not package.is_symlink(), "Vendored Connect package is missing")
    result = {}
    for path in package.rglob("*"):
        relative = path.relative_to(package.parent).as_posix()
        safe_path(relative)
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode), "Vendored Connect contains a symlink")
        if stat.S_ISDIR(info.st_mode):
            continue
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "Vendored Connect contains an unsupported file")
        mode = stat.S_IMODE(info.st_mode)
        require(mode in (0o644, 0o755), "Vendored Connect file has an unexpected mode")
        result[relative] = (mode, path.read_bytes())
    if exact:
        require(set(result) == SELECTED_FILES, "Vendored Connect runtime closure changed")
    return result


def lock_payload(files: dict[str, tuple[int, bytes]]) -> dict[str, object]:
    return {"format": 1, "repository": UPSTREAM, "commit": UPSTREAM_COMMIT,
            "file_count": len(files), "tree_sha256": tree_sha256(files)}


def verify_vendored(package: Path = PACKAGE, lock: Path = LOCK) -> dict[str, tuple[int, bytes]]:
    require(lock.is_file() and not lock.is_symlink(), "Vendored Connect source lock is missing")
    try:
        recorded = json.loads(lock.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise VendorError("Vendored Connect source lock is invalid") from None
    require(isinstance(recorded, dict) and set(recorded) ==
            {"format", "repository", "commit", "file_count", "tree_sha256"} and
            recorded["format"] == 1 and recorded["repository"] == UPSTREAM and
            recorded["commit"] == UPSTREAM_COMMIT and type(recorded["file_count"]) is int and
            recorded["file_count"] == len(SELECTED_FILES) and
            isinstance(recorded["tree_sha256"], str) and
            _SHA.fullmatch(recorded["tree_sha256"]) is not None,
            "Vendored Connect source lock does not match the pinned upstream")
    files = vendor_files(package)
    require(len(files) == recorded["file_count"] and
            tree_sha256(files) == recorded["tree_sha256"],
            "Vendored Connect differs from its source lock")
    return files


def sync(repo: Path) -> None:
    files = source_files(repo)
    require(not VENDOR.is_symlink() and (not PACKAGE.exists() or
            PACKAGE.is_dir() and not PACKAGE.is_symlink()), "Unsafe vendored Connect directory")
    PACKAGE.mkdir(parents=True, exist_ok=True)
    existing = vendor_files(PACKAGE, exact=False)
    for stale in set(existing) - set(files):
        (VENDOR / stale).unlink()
    for name, (mode, contents) in sorted(files.items()):
        destination = VENDOR / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        require(not destination.is_symlink(), "Refusing a vendored Connect symlink")
        destination.write_bytes(contents)
        destination.chmod(mode)
    for directory in sorted((path for path in PACKAGE.rglob("*") if path.is_dir()),
                            key=lambda path: len(path.parts), reverse=True):
        if not any(directory.iterdir()):
            directory.rmdir()
    LOCK.write_text(json.dumps(lock_payload(files), sort_keys=True, indent=2) + "\n", encoding="utf-8")
    LOCK.chmod(0o644)
    verify_vendored()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "sync"))
    parser.add_argument("--source", type=Path, help="local Connect Git checkout at the pinned commit")
    args = parser.parse_args()
    if args.action == "sync":
        require(args.source is not None, "sync needs --source")
        sync(args.source.resolve())
    else:
        vendored = verify_vendored()
        if args.source is not None:
            upstream = source_files(args.source.resolve())
            require(vendored == upstream, "Vendored Connect differs byte-for-byte from upstream")
    print(f"Vendored Connect verified: {UPSTREAM_COMMIT}")


if __name__ == "__main__":
    try:
        main()
    except VendorError as error:
        raise SystemExit(str(error)) from None
