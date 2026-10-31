#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Build a reproducible, private Connect source bundle from the installed tree.

The installed run.sh source tree has no original tarball. This module verifies
its five-component manifest and bytes, then creates the exact tar.gz expected
by Connect AgentEnrollment. It does not download code or run an installer.
"""

from __future__ import annotations

import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tempfile


SOURCE_ROOT = Path("/opt/sovagrid-src")
OUTPUT_PATH = Path("/var/lib/sovagrid/web-agent/source.tar.gz")  # Selects the private archive directory.
COMPONENTS = frozenset(("sovagrid-blueprint", "sovagrid-hub", "sovagrid-web",
                        "sovagrid-agent", "sovagrid-vpn"))
REQUIRED = frozenset(("sovagrid-blueprint/run.sh", "sovagrid-blueprint/deploy/compose.yaml",
    "sovagrid-blueprint/deploy/remote_agent.py", "sovagrid-hub/Dockerfile",
    "sovagrid-blueprint/deploy/vpn_source_install.py",
    "sovagrid-web/Dockerfile", "sovagrid-web/deploy/Caddyfile.container",
    "sovagrid-agent/deploy/sovagrid-agent.service",
    "sovagrid-vpn/deploy/sovagrid-vpn-status.service",
    "sovagrid-vpn/deploy/install-wireguard-control.py",
    "sovagrid-vpn/sovagrid_vpn/wireguard_install.py",
    "sovagrid-vpn/deploy/sovagrid-amnezia-provision",
    "sovagrid-vpn/sovagrid_vpn/amnezia_provision.py"))
_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_GENERATED = re.compile(
    r"sovagrid-[a-z]+/(?:[A-Za-z0-9_.-]+/)*__pycache__/[A-Za-z0-9_.-]+\.cpython-[0-9]+\.pyc\Z")
_MAX_MANIFEST = 512 * 1024
_MAX_FILE = 32 * 1024 * 1024
_MAX_EXPANDED = 256 * 1024 * 1024
_MAX_ARCHIVE = 64 * 1024 * 1024
_MAX_FILES = 4096


class BundleError(RuntimeError):
    """Fixed code only; paths, file contents and subprocess output stay private."""


def _need(condition: bool, code: str = "SOURCE_UNTRUSTED") -> None:
    if not condition:
        raise BundleError(code)


def _name(path: str) -> str:
    _need(isinstance(path, str) and path.isascii() and 1 <= len(path) <= 255)
    parts = path.split("/")
    _need(all(part not in ("", ".", "..") and _NAME.fullmatch(part) for part in parts))
    _need(len(parts) >= 2 and parts[0] in COMPONENTS)
    return path


def _safe_parent(path: Path, uid: int) -> None:
    """Reject symlink ancestors and writable untrusted parents."""
    _need(path.is_absolute() and ".." not in path.parts)
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            raise BundleError("SOURCE_UNTRUSTED") from None
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        _need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
              and info.st_uid in (0, uid)
              and (not info.st_mode & 0o022 or sticky_root))


def _private_dir(path: Path, uid: int) -> None:
    """Create only the leaf private directory; ancestors must already exist."""
    _safe_parent(path.parent, uid)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == uid
          and stat.S_IMODE(info.st_mode) == 0o700)


def _read_regular(path: Path, uid: int, limit: int) -> tuple[bytes, int]:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        _need((before.st_dev, before.st_ino) == (info.st_dev, info.st_ino)
              and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
              and info.st_uid == uid and not info.st_mode & 0o022
              and 0 <= info.st_size <= limit)
        data = stream.read(limit + 1)
        _need(len(data) == info.st_size)
        return data, stat.S_IMODE(info.st_mode)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result)
        result[key] = value
    return result


def _manifest(source: Path, uid: int) -> tuple[bytes, dict[str, str]]:
    _safe_parent(source, uid)
    source_info = source.lstat()
    _need(stat.S_ISDIR(source_info.st_mode) and source_info.st_uid == uid
          and not source_info.st_mode & 0o022)
    raw, _ = _read_regular(source / "sovagrid-bundle.json", uid, _MAX_MANIFEST)
    try:
        data = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise BundleError("SOURCE_UNTRUSTED") from None
    _need(type(data) is dict and set(data) == {"format", "components", "sha256"}
          and type(data["format"]) is int and data["format"] == 1)
    components, hashes = data["components"], data["sha256"]
    _need(type(components) is dict and set(components) == COMPONENTS
          and type(hashes) is dict and REQUIRED <= set(hashes)
          and 1 <= len(hashes) <= _MAX_FILES)
    for name, digest in hashes.items():
        _name(name)
        _need(type(digest) is str and _SHA.fullmatch(digest) is not None)
    for component, value in components.items():
        _need(type(value) is dict and set(value) == {"commit", "file_count"}
              and type(value["commit"]) is str and _COMMIT.fullmatch(value["commit"])
              and type(value["file_count"]) is int and value["file_count"] >= 1
              and value["file_count"] == sum(name.startswith(component + "/") for name in hashes))
    _need({item.name for item in source.iterdir()} == COMPONENTS | {"sovagrid-bundle.json"})
    seen = set()
    count = 0
    for parent, dirs, files in os.walk(source, followlinks=False):
        for name in dirs + files:
            count += 1
            _need(count <= _MAX_FILES + 4096)
            path = Path(parent) / name
            relative = path.relative_to(source).as_posix()
            if name in dirs:
                info = path.lstat()
                _need(stat.S_ISDIR(info.st_mode) and info.st_uid == uid
                      and not info.st_mode & 0o022)
            elif relative == "sovagrid-bundle.json":
                continue
            elif relative in hashes:
                data_bytes, _ = _read_regular(path, uid, _MAX_FILE)
                _need(hashlib.sha256(data_bytes).hexdigest() == hashes[relative])
                seen.add(relative)
            else:
                _need(_GENERATED.fullmatch(relative) is not None)
                _read_regular(path, uid, _MAX_FILE)
    _need(seen == set(hashes))
    return raw, hashes


def _entry(name: str, mode: int, *, directory: bool = False, size: int = 0) -> tarfile.TarInfo:
    item = tarfile.TarInfo(name + "/" if directory else name)
    item.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    item.mode = mode
    item.size = size
    item.uid = item.gid = item.mtime = 0
    item.uname = item.gname = ""
    return item


def _build(stream, source: Path, raw: bytes, hashes: dict[str, str], uid: int) -> None:
    files = sorted(hashes)
    directories = set(COMPONENTS)
    for name in files:
        parts = name.split("/")
        for end in range(2, len(parts)):
            directories.add("/".join(parts[:end]))
    with gzip.GzipFile(filename="", mode="wb", fileobj=stream, compresslevel=9, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name in sorted(directories):
                archive.addfile(_entry(name, 0o755, directory=True))
            archive.addfile(_entry("sovagrid-bundle.json", 0o644, size=len(raw)), io.BytesIO(raw))
            total = len(raw)
            for name in files:
                data, mode = _read_regular(source / name, uid, _MAX_FILE)
                _need(hashlib.sha256(data).hexdigest() == hashes[name])
                total += len(data)
                _need(total <= _MAX_EXPANDED)
                canonical_mode = 0o755 if mode & 0o111 else 0o644
                if name == "sovagrid-web/deploy/Caddyfile.container":
                    canonical_mode = 0o644
                archive.addfile(_entry(name, canonical_mode, size=len(data)), io.BytesIO(data))


def _verify_connect_bundle(path: Path, manifest: bytes) -> None:
    vendor = Path(__file__).resolve().parents[1] / "vendor/connect"
    _need((vendor / "sovagrid_connect/agent_enrollment.py").is_file(), "RUNTIME_UNAVAILABLE")
    if str(vendor) not in sys.path:
        sys.path.insert(0, str(vendor))
    try:
        from sovagrid_connect.agent_enrollment import EnrollmentError, source_bundle
        from sovagrid_connect.installer import InstallError
        for module in (sys.modules["sovagrid_connect.agent_enrollment"],
                       sys.modules["sovagrid_connect.installer"]):
            Path(module.__file__).resolve().relative_to(vendor)
    except (ImportError, KeyError, ValueError, TypeError, AttributeError):
        raise BundleError("RUNTIME_UNAVAILABLE") from None
    try:
        selected, _ = source_bundle(path)
        _need(selected["path"] == str(path.resolve()))
        with tarfile.open(path, "r:gz") as archive:
            item = archive.extractfile("sovagrid-bundle.json")
            _need(item is not None and item.read(_MAX_MANIFEST + 1) == manifest)
    except (EnrollmentError, InstallError, OSError, tarfile.TarError, KeyError, ValueError):
        raise BundleError("BUNDLE_INVALID") from None


def _prune_unused(directory: Path, current: Path, uid: int, jobs_root: Path) -> None:
    """Retire unreferenced archives under the same OS lock as job mutation.

    A busy or unreadable journal leaves all archives intact. Completed active
    records do not need their source archive for resume; pending and active
    cleanup records do. The journal's own 128-record cap bounds retained pins.
    """
    from sovagrid_connect.enrollment_journal import EnrollmentJournal, EnrollmentJournalError

    _private_dir(jobs_root, uid)
    lock_path = jobs_root / ".enrollment-web-mutation"
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        descriptor = os.open(lock_path, flags)
    with os.fdopen(descriptor, "rb+") as lock:
        info = os.fstat(lock.fileno())
        path_info = lock_path.lstat()
        _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
              and info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o600
              and (info.st_dev, info.st_ino) == (path_info.st_dev, path_info.st_ino),
              "JOURNAL_UNAVAILABLE")
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        try:
            records = EnrollmentJournal(jobs_root).list()
        except EnrollmentJournalError:
            return
        protected = {current}
        for record in records:
            if record["phase"] != "active" or record["cleanup_required"]:
                saved = record["bundle"]
                path = Path(saved["path"])
                if path.parent == directory and path.name == f"source-{saved['sha256']}.tar.gz":
                    protected.add(path)
        removed = False
        with os.scandir(directory) as entries:
            for index, entry in enumerate(entries):
                if index >= _MAX_FILES + 4096:
                    return
                match = re.fullmatch(r"source-([0-9a-f]{64})\.tar\.gz", entry.name)
                if match is None:
                    continue
                path = directory / entry.name
                if path in protected:
                    continue
                info = path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                        info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o600):
                    return
                path.unlink()
                removed = True
        if removed:
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


def _best_effort_prune(directory: Path, current: Path, uid: int, jobs_root: Path) -> None:
    try:
        _prune_unused(directory, current, uid, jobs_root)
    except (BundleError, OSError, ValueError, ImportError):
        # Recovery has priority: a damaged or busy journal must never cause
        # deletion or prevent the service from starting so it can be repaired.
        pass


def ensure_managed_bundle(*, source_root: Path = SOURCE_ROOT, output_path: Path = OUTPUT_PATH,
                          expected_uid: int = 0, require_root: bool = True,
                          journal_root: Path | None = None) -> tuple[Path, str]:
    """Return the pinned archive path and SHA-256; build atomically when needed.

    Production callers use defaults. The explicit paths/UID allow isolated unit
    tests without changing anything under /opt or /var/lib.
    """
    source = Path(source_root)
    output = Path(output_path)
    jobs_root = Path(journal_root) if journal_root is not None else output.parent / "jobs"
    if require_root:
        _need(os.geteuid() == 0 and expected_uid == 0, "ROOT_REQUIRED")
    _need(source.is_absolute() and output.is_absolute()
          and output.name == "source.tar.gz" and ".." not in source.parts + output.parts,
          "INVALID_PATH")
    try:
        _private_dir(output.parent, expected_uid)
        lock_path = output.parent / ".bundle.lock"
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            descriptor = os.open(lock_path, flags)
        with os.fdopen(descriptor, "rb+") as lock:
            info = os.fstat(lock.fileno())
            path_info = lock_path.lstat()
            _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                  and info.st_uid == expected_uid and stat.S_IMODE(info.st_mode) == 0o600
                  and (info.st_dev, info.st_ino) == (path_info.st_dev, path_info.st_ino))
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise BundleError("BUSY") from None
            raw, hashes = _manifest(source, expected_uid)
            temporary = None
            try:
                descriptor, temporary = tempfile.mkstemp(prefix=".source-", dir=output.parent)
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    _build(stream, source, raw, hashes, expected_uid)
                    stream.flush(); os.fsync(stream.fileno())
                temporary_path = Path(temporary)
                info = temporary_path.lstat()
                _need(info.st_size <= _MAX_ARCHIVE, "BUNDLE_TOO_LARGE")
                _verify_connect_bundle(temporary_path, raw)
                digest = hashlib.sha256(temporary_path.read_bytes()).hexdigest()
                archive_path = output.parent / f"source-{digest}.tar.gz"
                if archive_path.exists() or archive_path.is_symlink():
                    old_info = archive_path.lstat()
                    _need(stat.S_ISREG(old_info.st_mode) and old_info.st_nlink == 1
                          and old_info.st_uid == expected_uid
                          and stat.S_IMODE(old_info.st_mode) == 0o600
                          and old_info.st_size <= _MAX_ARCHIVE, "OUTPUT_UNSAFE")
                    _need(hashlib.sha256(archive_path.read_bytes()).hexdigest() == digest,
                          "OUTPUT_UNSAFE")
                    _best_effort_prune(output.parent, archive_path, expected_uid, jobs_root)
                    return archive_path, digest
                # Old versioned archives remain available to incomplete
                # enrollment journals after upgrades. The private directory
                # and lock serialize all cooperative builders.
                os.rename(temporary_path, archive_path)
                temporary = None
                directory_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                _best_effort_prune(output.parent, archive_path, expected_uid, jobs_root)
                return archive_path, digest
            finally:
                if temporary is not None:
                    try:
                        os.unlink(temporary)
                    except FileNotFoundError:
                        pass
    except BundleError:
        raise
    except (OSError, ValueError, TypeError, tarfile.TarError):
        raise BundleError("SOURCE_UNTRUSTED") from None
