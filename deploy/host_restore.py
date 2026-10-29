#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Validation and private staging for SovaGrid host archives.

This module deliberately has no apply entry point. Staging writes only to a
private directory and never installs files or starts services. Docker images,
writer fencing, durable recovery, and rollback remain prerequisites to apply.
"""

from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import time
import uuid
from types import SimpleNamespace
from typing import Any


sys.dont_write_bytecode = True


def _sibling(filename: str, name: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise RuntimeError("SovaGrid archive validator unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


backup = _sibling("host_backup.py", "_sovagrid_host_restore_backup")
PROTOCOL = "sovagrid-host-restore-plan-v1"
STAGE_PROTOCOL = "sovagrid-host-restore-stage-v1"
STAGING = Path("/var/lib/.sovagrid-host-restore-staging")
ID = re.compile(r"[0-9a-f]{32}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
GENERATED = re.compile(
    r"sovagrid-[a-z]+/(?:[A-Za-z0-9_.-]+/)*__pycache__/"
    r"[A-Za-z0-9_.-]+\.cpython-[0-9]+\.pyc\Z"
)
COMPONENTS = frozenset(("sovagrid-blueprint", "sovagrid-hub", "sovagrid-web",
                        "sovagrid-agent", "sovagrid-vpn"))
# Check the managed namespaces as well as the exact archived sources. The
# private archive directory is deliberately absent: a clean target can hold a
# copied archive pair there without being mistaken for an installed SovaGrid.
TARGET_NAMESPACES = frozenset((
    "/etc/sovagrid", "/etc/sovagrid-hub", "/etc/sovagrid-local",
    "/etc/sovagrid-vpn", "/etc/sovagrid-vpn-routing",
    "/etc/sovagrid-service", "/etc/sovagrid-service-local",
    "/etc/sovagrid-journal", "/var/lib/sovagrid",
    "/var/lib/sovagrid-vpn", "/var/lib/sovagrid-containers",
    "/var/lib/sovagrid-containers-local",
    "/var/lib/sovagrid-promotion", "/var/lib/sovagrid-agent",
    "/var/lib/sovagrid-agent-local",
    "/var/lib/sovagrid-host-backup-operations",
    "/opt/sovagrid-src", "/opt/sovagrid-vpn", "/opt/sovagrid-agent",
    "/opt/sovagrid-agent-local",
))
SCAN_NAMESPACES = (
    "/etc", "/etc/systemd/system", "/opt", "/usr/local/bin",
    "/usr/local/libexec", "/var/lib",
)
REQUIRED_BUNDLE = frozenset((
    "sovagrid-blueprint/run.sh",
    "sovagrid-blueprint/deploy/compose.yaml",
    "sovagrid-hub/Dockerfile",
    "sovagrid-web/Dockerfile",
    "sovagrid-web/deploy/Caddyfile.container",
    "sovagrid-agent/deploy/sovagrid-agent.service",
    "sovagrid-vpn/deploy/sovagrid-vpn-status.service",
))
DIRECT_FILES = {
    "/var/lib/sovagrid/hub": frozenset(
        ("hub.sqlite", "hub.sqlite-wal", "hub.sqlite-shm", "telegram-bot-token")),
    "/etc/sovagrid-hub": frozenset(("bot.token", "hub-only-auto-update.json")),
    "/etc/sovagrid-vpn": frozenset(("amnezia-control.enabled",
                                   "amnezia-wireguard-control.enabled",
                                   "amnezia-install.lock")),
    "/etc/sovagrid-service": frozenset(("enabled", "units.json")),
    "/etc/sovagrid-service-local": frozenset(("enabled", "units.json")),
    "/etc/sovagrid-journal": frozenset(("units.json",)),
    "/etc/sovagrid-local": frozenset(("agent.json", "agent.token", "hub-ca.pem")),
    "/etc/sovagrid-vpn-routing": frozenset(("policy.json",)),
    "/var/lib/sovagrid/vpn": frozenset(("status.json",)),
    "/var/lib/sovagrid-containers": frozenset(("snapshot.json",)),
    "/var/lib/sovagrid-containers-local": frozenset(("snapshot.json",)),
}
# These groups are created by the installer. A clean target has neither group,
# so archive inspection must validate the archived numeric identity instead of
# resolving group names against the target's /etc/group.
DYNAMIC_GROUPS = (
    frozenset(("/etc/sovagrid/agent.json", "/etc/sovagrid/agent.token")),
    frozenset(("/etc/sovagrid-local/agent.json", "/etc/sovagrid-local/agent.token",
               "/etc/sovagrid-local/hub-ca.pem",
               "/var/lib/sovagrid-containers-local",
               "/var/lib/sovagrid-containers-local/snapshot.json")),
)
DYNAMIC_GROUP_PATHS = frozenset().union(*DYNAMIC_GROUPS)
MAX_BUNDLE_MANIFEST = 512 * 1024
MAX_BUNDLE_FILES = backup.MAX_FILES


class Refused(RuntimeError):
    """Stable machine-readable refusal without names of private files."""


def _require_root() -> None:
    if os.geteuid() != 0:
        raise Refused("ROOT_REQUIRED")


def _id(value: Any) -> str:
    if not isinstance(value, str) or ID.fullmatch(value) is None:
        raise Refused("INVALID_ID")
    return value


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise Refused("INVALID_BUNDLE")
        value[key] = item
    return value


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid,
            info.st_gid, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)


def _archive_fd(identity: str) -> tuple[int, dict]:
    manifest = backup._record(identity)
    if manifest["source_manifest_sha256"] is None:
        raise Refused("SOURCE_UNPINNED")
    output = backup._output(create=False)
    target = output / (identity + ".tar.gz")
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != backup.ROOT_UID or
                info.st_gid != backup.ROOT_GID or stat.S_IMODE(info.st_mode) != 0o600 or
                info.st_nlink != 1 or info.st_size != manifest["bytes"]):
            raise Refused("UNSAFE_ARCHIVE")
        return fd, manifest
    except BaseException:
        os.close(fd)
        raise


def _hash_archive(fd: int, manifest: dict, *, deadline: float) -> tuple[int, ...]:
    before = os.fstat(fd)
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while True:
        if time.monotonic() > deadline:
            raise Refused("TIME_LIMIT")
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        total += len(block)
        if total > backup.MAX_BYTES:
            raise Refused("SIZE_LIMIT")
        digest.update(block)
    if (total != manifest["bytes"] or digest.hexdigest() != manifest["sha256"] or
            _fingerprint(os.fstat(fd)) != _fingerprint(before)):
        raise Refused("ARCHIVE_CHANGED")
    return _fingerprint(before)


def _member_path(member: tarfile.TarInfo) -> tuple[str, bool]:
    if member.type not in (tarfile.REGTYPE, tarfile.DIRTYPE) or member.linkname:
        raise Refused("INVALID_ARCHIVE")
    name = member.name.rstrip("/")
    if (member.type == tarfile.REGTYPE and name != member.name) or member.name.endswith("//"):
        raise Refused("INVALID_ARCHIVE")
    try:
        raw = name.encode("utf-8")
    except UnicodeError as exc:
        raise Refused("INVALID_ARCHIVE") from exc
    parts = name.split("/")
    if (not name or name.startswith("/") or len(raw) > 4096 or
            any(part in ("", ".", "..") or len(part.encode("utf-8")) > 255
                for part in parts)):
        raise Refused("INVALID_ARCHIVE")
    if (type(member.uid) is not int or type(member.gid) is not int or
            not 0 <= member.uid <= 65535 or not 0 <= member.gid <= 65535 or
            type(member.mode) is not int or member.mode & ~0o777 or
            type(member.mtime) is not int or not 0 <= member.mtime <= 253402300799 or
            type(member.size) is not int or member.size < 0 or
            member.size > backup.MAX_FILE_BYTES or
            (member.isdir() and member.size != 0)):
        raise Refused("INVALID_ARCHIVE")
    return "/" + name, member.isdir()


def _source_for(path: str, sources: tuple) -> Any:
    matches = [source for source in sources if path == source.path or
               (source.kind == "dir" and path.startswith(source.path + "/"))]
    if len(matches) != 1:
        raise Refused("UNEXPECTED_PATH")
    return matches[0]


def _check_member(path: str, member: tarfile.TarInfo, directory: bool,
                  sources: tuple, directories: set[str]) -> None:
    source = _source_for(path, sources)
    if path == source.path:
        if (source.kind == "dir") != directory:
            raise Refused("INVALID_ARCHIVE")
        selected = source
    else:
        remainder = path[len(source.path) + 1:]
        parent = path.rsplit("/", 1)[0]
        if parent not in directories:
            raise Refused("INVALID_ARCHIVE")
        child = remainder.split("/", 1)[0]
        if child in source.excluded:
            raise Refused("UNEXPECTED_PATH")
        if source.path == "/opt/sovagrid-src":
            if child not in COMPONENTS | {"sovagrid-bundle.json"}:
                raise Refused("UNEXPECTED_PATH")
            if child == "sovagrid-bundle.json" and "/" in remainder:
                raise Refused("UNEXPECTED_PATH")
        fixed = DIRECT_FILES.get(source.path)
        if fixed is not None and (child not in fixed or "/" in remainder or directory):
            raise Refused("UNEXPECTED_PATH")
        try:
            selected = backup._web_agent_source(path) or backup.Source(path, source.owner)
        except backup.Refused as exc:
            raise Refused("UNEXPECTED_PATH") from exc
        if (path.startswith(backup.WEB_AGENT_DIR + "/") and
                directory != (selected.kind == "dir")):
            raise Refused("INVALID_ARCHIVE")
        limit = backup._web_agent_limit(path)
        if limit is not None and member.size > limit:
            raise Refused("INVALID_ARCHIVE")
        if backup._web_agent_nonempty(path) and member.size == 0:
            raise Refused("INVALID_ARCHIVE")
    info = SimpleNamespace(st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) |
                          member.mode, st_uid=member.uid, st_gid=member.gid, st_nlink=1)
    if path in DYNAMIC_GROUP_PATHS:
        local_snapshot_dir = path == "/var/lib/sovagrid-containers-local"
        if (directory != local_snapshot_dir or member.uid != backup.ROOT_UID or
                member.gid == 0 or member.mode != (0o750 if local_snapshot_dir else 0o640)):
            raise Refused("INVALID_ARCHIVE")
        return
    try:
        backup._check(info, selected, directory=directory)
    except (backup.Refused, KeyError) as exc:
        raise Refused("INVALID_ARCHIVE") from exc


def _bundle(raw: bytes, files: dict[str, str], generated: set[str],
            directories: set[str]) -> None:
    if not 0 < len(raw) <= MAX_BUNDLE_MANIFEST:
        raise Refused("INVALID_BUNDLE")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise Refused("INVALID_BUNDLE") from exc
    if (not isinstance(value, dict) or set(value) != {"format", "components", "sha256"} or
            type(value["format"]) is not int or value["format"] != 1 or
            not isinstance(value["components"], dict) or
            set(value["components"]) != COMPONENTS or
            not isinstance(value["sha256"], dict) or
            not 1 <= len(value["sha256"]) <= MAX_BUNDLE_FILES):
        raise Refused("INVALID_BUNDLE")
    hashes = value["sha256"]
    if not REQUIRED_BUNDLE <= set(hashes) or set(hashes) != set(files):
        raise Refused("INVALID_BUNDLE")
    try:
        invalid_hashes = any(
            not isinstance(name, str) or
            len(name.encode("utf-8")) > 4096 or
            name.split("/", 1)[0] not in COMPONENTS or
            not isinstance(digest, str) or SHA.fullmatch(digest) is None or
            files[name] != digest for name, digest in hashes.items())
    except UnicodeError as exc:
        raise Refused("INVALID_BUNDLE") from exc
    if invalid_hashes:
        raise Refused("INVALID_BUNDLE")
    for component, record in value["components"].items():
        if (not isinstance(record, dict) or set(record) != {"commit", "file_count"} or
                not isinstance(record["commit"], str) or
                COMMIT.fullmatch(record["commit"]) is None or
                type(record["file_count"]) is not int or
                record["file_count"] != sum(name.startswith(component + "/")
                                            for name in hashes)):
            raise Refused("INVALID_BUNDLE")
    if any(GENERATED.fullmatch(name) is None or
           name.split("/", 1)[0] not in COMPONENTS for name in generated):
        raise Refused("INVALID_BUNDLE")
    expected_directories: set[str] = set()
    for name in set(files) | generated | {"sovagrid-bundle.json"}:
        parts = name.split("/")
        expected_directories.update("/".join(parts[:depth])
                                    for depth in range(1, len(parts)))
    if directories != expected_directories:
        raise Refused("INVALID_BUNDLE")


def _required(layout: str, present: set[str]) -> set[str]:
    chosen = backup.CORE + (backup.FULL if layout == "full" else backup.HUB_ONLY)
    required = {source.path for source in chosen if source.required}
    required.update((
        "/var/lib/sovagrid/hub/hub.sqlite",
        "/var/lib/sovagrid/caddy/caddy/pki/authorities/local/root.crt",
        "/var/lib/sovagrid/caddy/caddy/pki/authorities/local/root.key",
        "/opt/sovagrid-src/sovagrid-bundle.json",
    ))
    if layout == "full":
        required.update(("/etc/sovagrid/agent.json", "/etc/sovagrid/agent.token",
                         "/etc/sovagrid/hub-ca.pem", "/opt/sovagrid-agent"))
    elif "/etc/sovagrid-local/agent.json" in present:
        required.update(("/etc/sovagrid-local/agent.token",
                         "/etc/sovagrid-local/hub-ca.pem",
                         "/opt/sovagrid-agent-local"))
        if "/var/lib/sovagrid-promotion/local-container-inventory.json" in present:
            required.update((
                "/var/lib/sovagrid-containers-local",
                "/var/lib/sovagrid-containers-local/snapshot.json",
                "/etc/systemd/system/sovagrid-container-inventory-local.service",
                "/etc/systemd/system/sovagrid-container-inventory-local.timer",
            ))
    try:
        required.update(backup._web_agent_required(present))
    except backup.Refused as exc:
        raise Refused("INVALID_ARCHIVE") from exc
    return required


def _inspect_tar(fd: int, manifest: dict, sources: tuple, *, deadline: float) -> dict:
    os.lseek(fd, 0, os.SEEK_SET)
    seen: set[str] = set()
    directories: set[str] = set()
    source_hashes: dict[str, str] = {}
    generated: set[str] = set()
    source_directories: set[str] = set()
    bundle_raw = b""
    total = 0
    count = 0
    dynamic_gids: dict[str, int] = {}
    try:
        with os.fdopen(os.dup(fd), "rb") as archive_file:
            with tarfile.open(fileobj=archive_file, mode="r|gz") as archive:
                for member in archive:
                    if time.monotonic() > deadline:
                        raise Refused("TIME_LIMIT")
                    path, directory = _member_path(member)
                    if path in seen or count >= backup.MAX_FILES:
                        raise Refused("INVALID_ARCHIVE")
                    _check_member(path, member, directory, sources, directories)
                    if path in DYNAMIC_GROUP_PATHS:
                        dynamic_gids[path] = member.gid
                    seen.add(path)
                    count += 1
                    if directory:
                        directories.add(path)
                        if path.startswith("/opt/sovagrid-src/"):
                            source_directories.add(path[len("/opt/sovagrid-src/"):])
                        continue
                    total += member.size
                    if total > backup.MAX_BYTES:
                        raise Refused("SIZE_LIMIT")
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise Refused("INVALID_ARCHIVE")
                    digest = hashlib.sha256()
                    remaining = member.size
                    bundle_path = "/opt/sovagrid-src/sovagrid-bundle.json"
                    marker_path = backup.SSH_GATEWAY_MARKER
                    web_marker_path = backup.WEB_AGENT_MARKER
                    capture = (bytearray() if path in
                               (bundle_path, marker_path, web_marker_path) else None)
                    if path == bundle_path and member.size > MAX_BUNDLE_MANIFEST:
                        raise Refused("INVALID_BUNDLE")
                    if path == marker_path and member.size != len(
                            backup.SSH_GATEWAY_MARKER_CONTENT):
                        raise Refused("INVALID_ARCHIVE")
                    if path == web_marker_path and member.size != len(
                            backup.WEB_AGENT_MARKER_CONTENT):
                        raise Refused("INVALID_ARCHIVE")
                    while remaining:
                        if time.monotonic() > deadline:
                            raise Refused("TIME_LIMIT")
                        block = stream.read(min(1024 * 1024, remaining))
                        if not block:
                            raise Refused("INVALID_ARCHIVE")
                        digest.update(block)
                        if capture is not None:
                            capture.extend(block)
                        remaining -= len(block)
                    if capture is not None:
                        if path == marker_path:
                            if bytes(capture) != backup.SSH_GATEWAY_MARKER_CONTENT:
                                raise Refused("INVALID_ARCHIVE")
                        elif path == web_marker_path:
                            if bytes(capture) != backup.WEB_AGENT_MARKER_CONTENT:
                                raise Refused("INVALID_ARCHIVE")
                        else:
                            bundle_raw = bytes(capture)
                    elif path.startswith(backup.WEB_AGENT_DIR + "/"):
                        bundle = backup.WEB_AGENT_BUNDLE.fullmatch(path.rsplit("/", 1)[1])
                        if bundle is not None and digest.hexdigest() != bundle.group(1):
                            raise Refused("INVALID_ARCHIVE")
                    elif path.startswith("/opt/sovagrid-src/"):
                        relative = path[len("/opt/sovagrid-src/"):]
                        if GENERATED.fullmatch(relative):
                            generated.add(relative)
                        else:
                            source_hashes[relative] = digest.hexdigest()
    except (tarfile.TarError, EOFError, OSError, ValueError, OverflowError) as exc:
        raise Refused("INVALID_ARCHIVE") from exc
    if count != manifest["files"] or not _required(manifest["layout"], seen) <= seen:
        raise Refused("INVALID_ARCHIVE")
    for group in DYNAMIC_GROUPS:
        if len({dynamic_gids[path] for path in group if path in dynamic_gids}) > 1:
            raise Refused("INVALID_ARCHIVE")
    if not bundle_raw or hashlib.sha256(bundle_raw).hexdigest() != manifest[
            "source_manifest_sha256"]:
        raise Refused("INVALID_BUNDLE")
    _bundle(bundle_raw, source_hashes, generated, source_directories)
    return {"archive": backup._summary(manifest), "source_manifest_sha256": manifest[
                "source_manifest_sha256"], "uncompressed_bytes": total,
            "entries": count, "generated_bytecode_files": len(generated)}


def verify(identity: str) -> dict:
    """Validate a private archive and every member without extracting it."""
    _require_root()
    identity = _id(identity)
    deadline = time.monotonic() + 2 * backup.MAX_SECONDS
    fd, manifest = _archive_fd(identity)
    try:
        before = _hash_archive(fd, manifest, deadline=deadline)
        sources = backup._sources(manifest["layout"])
        result = _inspect_tar(fd, manifest, sources, deadline=deadline)
        if _fingerprint(os.fstat(fd)) != before:
            raise Refused("ARCHIVE_CHANGED")
    finally:
        os.close(fd)
    return {"ok": True, "protocol": PROTOCOL, "verified": True, **result}


def plan(identity: str) -> dict:
    """Show compatibility only; no write path or restore authority exists."""
    result = verify(identity)
    target = backup.plan()
    target_layout = target["layout"]
    target_manifest = backup._source_manifest()
    blockers = ["APPLY_NOT_IMPLEMENTED"]
    if target_layout != result["archive"]["layout"]:
        blockers.append("LAYOUT_MISMATCH")
    if target_manifest != result["source_manifest_sha256"]:
        blockers.append("SOURCE_MISMATCH")
    if target["running_containers"] not in ([], list(backup.COMPOSE_SERVICES[:2]),
                                            list(backup.COMPOSE_SERVICES)):
        blockers.append("TARGET_STACK_DEGRADED")
    return {**result, "target_layout": target_layout,
            "target_manifest_sha256": target_manifest,
            "target_running_containers": target["running_containers"],
            "target_active_units": target["active_units"],
            "target_offline_ready": target["offline_ready"],
            "same_layout": target_layout == result["archive"]["layout"],
            "same_source": target_manifest == result["source_manifest_sha256"],
            "apply_available": False, "blockers": blockers}


def _target_path(path: str) -> tuple[bool, bool]:
    """Read a target path without following symlinks in any component.

    The result is an advisory snapshot only; there is intentionally no write
    operation that could rely on this check across a race.
    """
    current = backup.ROOT
    parts = Path(path).parts
    if not path.startswith("/") or len(parts) < 2:
        raise Refused("INVALID_TARGET")
    for index, part in enumerate(parts[1:]):
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return False, False
        if index + 1 < len(parts) - 1:
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != backup.ROOT_UID or
                    stat.S_IMODE(info.st_mode) & 0o022):
                return False, True
        else:
            return True, stat.S_ISLNK(info.st_mode)
    raise Refused("INVALID_TARGET")


def clean_plan(identity: str) -> dict:
    """Validate a copied archive and inspect a target without installed state.

    The archive still lives in the private backup directory. No member is
    extracted, no systemd unit is stopped, and no Docker image is installed.
    """
    result = verify(identity)
    sources = backup._sources(result["archive"]["layout"])
    paths = set(TARGET_NAMESPACES) | {source.path for source in sources}
    unsafe = 0
    # Include SovaGrid-named units and helper files unknown to this release.
    # A clean target must not silently adopt a newer or foreign installation.
    for namespace in SCAN_NAMESPACES:
        present, unsafe_path = _target_path(namespace)
        if unsafe_path:
            unsafe += 1
            continue
        if not present:
            continue
        parent = backup._host(namespace)
        parent_info = os.lstat(parent)
        if (not stat.S_ISDIR(parent_info.st_mode) or
                parent_info.st_uid != backup.ROOT_UID or
                stat.S_IMODE(parent_info.st_mode) & 0o022):
            unsafe += 1
            continue
        try:
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY |
                                 os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                with os.scandir(descriptor) as entries:
                    paths.update(namespace + "/" + entry.name for entry in entries
                                 if entry.name.startswith("sovagrid-") and
                                 (namespace, entry.name) != (
                                     "/var/lib", "sovagrid-host-backups") and
                                 (namespace, entry.name) != (
                                     "/var/lib", "sovagrid-host-image-exports"))
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise Refused("TARGET_CHECK_UNAVAILABLE") from exc
    conflicts = 0
    for path in sorted(paths):
        present, unsafe_path = _target_path(path)
        conflicts += int(present)
        unsafe += int(unsafe_path)
    blockers = ["APPLY_NOT_IMPLEMENTED", "DOCKER_IMAGES_NOT_INCLUDED"]
    if conflicts:
        blockers.append("TARGET_STATE_PRESENT")
    if unsafe:
        blockers.append("TARGET_PATH_UNSAFE")
    return {**result, "target_kind": "clean", "target_empty": not conflicts and not unsafe,
            "target_conflicts": conflicts, "target_unsafe_paths": unsafe,
            "apply_available": False, "blockers": blockers}


def _staging_root() -> tuple[Path, int]:
    """Create/open the one root-only staging namespace without following links."""
    present, unsafe = _target_path("/var/lib")
    if not present or unsafe:
        raise Refused("UNSAFE_STAGE")
    parent_fd = backup._safe_open(Path("/var/lib"), directory=True)
    try:
        parent_info = os.fstat(parent_fd)
        if (parent_info.st_uid != backup.ROOT_UID or
                stat.S_IMODE(parent_info.st_mode) & 0o022):
            raise Refused("UNSAFE_STAGE")
        name = STAGING.name
        created = False
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            created = True
            os.fsync(parent_fd)
        except FileExistsError:
            pass
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                     os.O_CLOEXEC, dir_fd=parent_fd)
        if created:
            info = os.fstat(fd)
            if (info.st_uid, info.st_gid) != (backup.ROOT_UID, backup.ROOT_GID):
                os.fchown(fd, backup.ROOT_UID, backup.ROOT_GID)
            os.fchmod(fd, 0o700)
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or
                (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) !=
                (backup.ROOT_UID, backup.ROOT_GID, 0o700)):
            os.close(fd)
            raise Refused("UNSAFE_STAGE")
        return backup._host(STAGING), fd
    finally:
        os.close(parent_fd)


def _stage_parent(root_fd: int, components: list[str]) -> int:
    """Open a private destination directory, creating only root:root 0700 dirs."""
    fd = os.dup(root_fd)
    try:
        for name in components:
            created = False
            try:
                os.mkdir(name, 0o700, dir_fd=fd)
                created = True
            except FileExistsError:
                pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC, dir_fd=fd)
            if created:
                info = os.fstat(child)
                if (info.st_uid, info.st_gid) != (backup.ROOT_UID, backup.ROOT_GID):
                    os.fchown(child, backup.ROOT_UID, backup.ROOT_GID)
                os.fchmod(child, 0o700)
            info = os.fstat(child)
            if (not stat.S_ISDIR(info.st_mode) or
                    (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) !=
                    (backup.ROOT_UID, backup.ROOT_GID, 0o700)):
                os.close(child)
                raise Refused("UNSAFE_STAGE")
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _materialize(fd: int, root_fd: int, manifest: dict, sources: tuple,
                 expected: dict, *, deadline: float) -> None:
    """Copy only already-validated regular members into the private tree."""
    os.lseek(fd, 0, os.SEEK_SET)
    seen: set[str] = set()
    directories: set[str] = set()
    total = 0
    try:
        with os.fdopen(os.dup(fd), "rb") as archive_file:
            with tarfile.open(fileobj=archive_file, mode="r|gz") as archive:
                for member in archive:
                    if time.monotonic() > deadline:
                        raise Refused("TIME_LIMIT")
                    path, directory = _member_path(member)
                    if path in seen or len(seen) >= backup.MAX_FILES:
                        raise Refused("INVALID_ARCHIVE")
                    _check_member(path, member, directory, sources, directories)
                    seen.add(path)
                    if directory:
                        directories.add(path)
                    components = path.lstrip("/").split("/")
                    parent_fd = _stage_parent(root_fd, components[:-1])
                    try:
                        name = components[-1]
                        if directory:
                            child_fd = _stage_parent(parent_fd, [name])
                            os.close(child_fd)
                            continue
                        total += member.size
                        if total > backup.MAX_BYTES:
                            raise Refused("SIZE_LIMIT")
                        stream = archive.extractfile(member)
                        if stream is None:
                            raise Refused("INVALID_ARCHIVE")
                        file_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                          os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                                          dir_fd=parent_fd)
                        try:
                            info = os.fstat(file_fd)
                            if (info.st_uid, info.st_gid) != (backup.ROOT_UID,
                                                               backup.ROOT_GID):
                                os.fchown(file_fd, backup.ROOT_UID, backup.ROOT_GID)
                            os.fchmod(file_fd, 0o600)
                            info = os.fstat(file_fd)
                            if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (
                                    backup.ROOT_UID, backup.ROOT_GID, 0o600):
                                raise Refused("UNSAFE_STAGE")
                            remaining = member.size
                            while remaining:
                                if time.monotonic() > deadline:
                                    raise Refused("TIME_LIMIT")
                                block = stream.read(min(1024 * 1024, remaining))
                                if not block:
                                    raise Refused("INVALID_ARCHIVE")
                                view = memoryview(block)
                                while view:
                                    written = os.write(file_fd, view)
                                    if written <= 0:
                                        raise Refused("IO_ERROR")
                                    view = view[written:]
                                remaining -= len(block)
                            os.fsync(file_fd)
                        finally:
                            os.close(file_fd)
                    finally:
                        os.close(parent_fd)
    except (tarfile.TarError, EOFError, ValueError, OverflowError) as exc:
        raise Refused("INVALID_ARCHIVE") from exc
    if len(seen) != expected["entries"] or total != expected["uncompressed_bytes"]:
        raise Refused("ARCHIVE_CHANGED")


def _sync_stage_directories(path: Path) -> None:
    for directory, children, files in os.walk(path, topdown=False, followlinks=False):
        for name in children + files:
            item = Path(directory) / name
            if item.is_symlink():
                raise Refused("UNSAFE_STAGE")
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                     os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _stage_tree_digest(path: Path, *, deadline: float) -> str:
    """Hash every sealed staged item, including unexpected entries."""
    digest = hashlib.sha256()
    count = 0
    total = 0
    for directory, children, files in os.walk(path, topdown=True, followlinks=False):
        if time.monotonic() > deadline:
            raise Refused("TIME_LIMIT")
        children.sort()
        files.sort()
        root = Path(directory)
        for name in children + files:
            if root == path and name == "receipt.json":
                continue
            item = root / name
            info = os.lstat(item)
            relative = item.relative_to(path).as_posix()
            if (info.st_uid, info.st_gid) != (backup.ROOT_UID, backup.ROOT_GID):
                raise Refused("UNSAFE_STAGE")
            count += 1
            if count > backup.MAX_FILES * 32:
                raise Refused("FILE_LIMIT")
            if stat.S_ISDIR(info.st_mode):
                if stat.S_IMODE(info.st_mode) != 0o700:
                    raise Refused("UNSAFE_STAGE")
                digest.update(b"D\0" + relative.encode("utf-8") + b"\0")
            elif stat.S_ISREG(info.st_mode):
                if stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                    raise Refused("UNSAFE_STAGE")
                total += info.st_size
                if total > backup.MAX_BYTES:
                    raise Refused("SIZE_LIMIT")
                item_fd = os.open(item, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    before = _fingerprint(os.fstat(item_fd))
                    file_digest = hashlib.sha256()
                    remaining = info.st_size
                    while remaining:
                        if time.monotonic() > deadline:
                            raise Refused("TIME_LIMIT")
                        block = os.read(item_fd, min(1024 * 1024, remaining))
                        if not block:
                            raise Refused("STAGE_CHANGED")
                        file_digest.update(block)
                        remaining -= len(block)
                    if _fingerprint(os.fstat(item_fd)) != before:
                        raise Refused("STAGE_CHANGED")
                finally:
                    os.close(item_fd)
                digest.update(b"F\0" + relative.encode("utf-8") + b"\0" +
                              str(info.st_size).encode("ascii") + b"\0" +
                              file_digest.digest())
            else:
                raise Refused("UNSAFE_STAGE")
    return digest.hexdigest()


def stage_status(identity: str) -> dict:
    """Recheck the private tree and the original archive without changing it."""
    _require_root()
    identity = _id(identity)
    present, unsafe = _target_path("/var/lib")
    if not present or unsafe:
        raise Refused("UNSAFE_STAGE")
    try:
        root_fd = backup._safe_open(STAGING, directory=True)
    except FileNotFoundError as exc:
        raise Refused("STAGE_NOT_FOUND") from exc
    try:
        root_info = os.fstat(root_fd)
        if (root_info.st_uid, root_info.st_gid, stat.S_IMODE(root_info.st_mode)) != (
                backup.ROOT_UID, backup.ROOT_GID, 0o700):
            raise Refused("UNSAFE_STAGE")
        try:
            fcntl.flock(root_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused("BUSY") from exc
        try:
            stage_fd = os.open(identity, os.O_RDONLY | os.O_DIRECTORY |
                               os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
        except FileNotFoundError as exc:
            raise Refused("STAGE_NOT_FOUND") from exc
        try:
            info = os.fstat(stage_fd)
            if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (
                    backup.ROOT_UID, backup.ROOT_GID, 0o700):
                raise Refused("UNSAFE_STAGE")
            receipt_fd = os.open("receipt.json", os.O_RDONLY | os.O_NOFOLLOW |
                                 os.O_CLOEXEC, dir_fd=stage_fd)
            try:
                info = os.fstat(receipt_fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                        info.st_size > 2048 or
                        (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (
                            backup.ROOT_UID, backup.ROOT_GID, 0o600)):
                    raise Refused("UNSAFE_STAGE")
                raw = os.read(receipt_fd, 2049)
            finally:
                os.close(receipt_fd)
        finally:
            os.close(stage_fd)
        try:
            receipt = json.loads(raw, object_pairs_hook=_unique)
        except (Refused, ValueError, UnicodeError) as exc:
            raise Refused("INVALID_STAGE") from exc
        if (not isinstance(receipt, dict) or set(receipt) != {
                "protocol", "id", "archive_sha256", "source_manifest_sha256",
                "entries", "uncompressed_bytes", "tree_sha256", "staged_at"} or
                receipt["protocol"] != STAGE_PROTOCOL or receipt["id"] != identity or
                type(receipt["entries"]) is not int or
                not 0 < receipt["entries"] <= backup.MAX_FILES or
                type(receipt["uncompressed_bytes"]) is not int or
                not 0 <= receipt["uncompressed_bytes"] <= backup.MAX_BYTES or
                not isinstance(receipt["tree_sha256"], str) or
                SHA.fullmatch(receipt["tree_sha256"]) is None or
                not isinstance(receipt["staged_at"], str) or
                len(receipt["staged_at"]) > 40):
            raise Refused("INVALID_STAGE")
        verified = verify(identity)
        archive_fd, manifest = _archive_fd(identity)
        os.close(archive_fd)
        if (receipt["archive_sha256"] != manifest["sha256"] or
                receipt["source_manifest_sha256"] != verified["source_manifest_sha256"] or
                receipt["entries"] != verified["entries"] or
                receipt["uncompressed_bytes"] != verified["uncompressed_bytes"]):
            raise Refused("STAGE_CHANGED")
        if _stage_tree_digest(backup._host(STAGING) / identity,
                              deadline=time.monotonic() + backup.MAX_SECONDS) != receipt[
                                  "tree_sha256"]:
            raise Refused("STAGE_CHANGED")
        return {"ok": True, "protocol": STAGE_PROTOCOL, "id": identity,
                "staged": True, "verified": True, "entries": receipt["entries"],
                "uncompressed_bytes": receipt["uncompressed_bytes"],
                "apply_available": False,
                "blockers": ["APPLY_NOT_IMPLEMENTED", "DOCKER_IMAGES_NOT_INCLUDED"]}
    finally:
        os.close(root_fd)


def stage(identity: str) -> dict:
    """Atomically publish a sealed private copy; never touch live paths."""
    _require_root()
    identity = _id(identity)
    preview = clean_plan(identity)
    if not preview["target_empty"]:
        raise Refused("TARGET_NOT_CLEAN")
    stage_root, root_fd = _staging_root()
    temporary: Path | None = None
    try:
        try:
            fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused("BUSY") from exc
        if os.path.lexists(stage_root / identity):
            raise Refused("STAGE_EXISTS")
        deadline = time.monotonic() + 4 * backup.MAX_SECONDS
        archive_fd, manifest = _archive_fd(identity)
        try:
            before = _hash_archive(archive_fd, manifest, deadline=deadline)
            sources = backup._sources(manifest["layout"])
            inspected = _inspect_tar(archive_fd, manifest, sources, deadline=deadline)
            if shutil.disk_usage(stage_root).free < (inspected["uncompressed_bytes"] +
                                                    backup.MIN_FREE):
                raise Refused("DISK_SPACE")
            temp_name = "." + identity + "." + uuid.uuid4().hex + ".tmp"
            os.mkdir(temp_name, 0o700, dir_fd=root_fd)
            temporary = stage_root / temp_name
            temp_fd = os.open(temp_name, os.O_RDONLY | os.O_DIRECTORY |
                              os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
            try:
                info = os.fstat(temp_fd)
                if (info.st_uid, info.st_gid) != (backup.ROOT_UID, backup.ROOT_GID):
                    os.fchown(temp_fd, backup.ROOT_UID, backup.ROOT_GID)
                os.fchmod(temp_fd, 0o700)
                _materialize(archive_fd, temp_fd, manifest, sources, inspected,
                             deadline=deadline)
                _hash_archive(archive_fd, manifest, deadline=deadline)
                if _fingerprint(os.fstat(archive_fd)) != before:
                    raise Refused("ARCHIVE_CHANGED")
                tree_sha = _stage_tree_digest(temporary, deadline=deadline)
                receipt = {"protocol": STAGE_PROTOCOL, "id": identity,
                           "archive_sha256": manifest["sha256"],
                           "source_manifest_sha256": manifest["source_manifest_sha256"],
                           "entries": inspected["entries"],
                           "uncompressed_bytes": inspected["uncompressed_bytes"],
                           "tree_sha256": tree_sha,
                           "staged_at": datetime.now(timezone.utc).isoformat()}
                raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) +
                       "\n").encode()
                receipt_fd = os.open("receipt.json", os.O_WRONLY | os.O_CREAT |
                                     os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     0o600, dir_fd=temp_fd)
                try:
                    info = os.fstat(receipt_fd)
                    if (info.st_uid, info.st_gid) != (backup.ROOT_UID, backup.ROOT_GID):
                        os.fchown(receipt_fd, backup.ROOT_UID, backup.ROOT_GID)
                    os.fchmod(receipt_fd, 0o600)
                    view = memoryview(raw)
                    while view:
                        written = os.write(receipt_fd, view)
                        if written <= 0:
                            raise Refused("IO_ERROR")
                        view = view[written:]
                    os.fsync(receipt_fd)
                finally:
                    os.close(receipt_fd)
            finally:
                os.close(temp_fd)
            _sync_stage_directories(temporary)
            if os.path.lexists(stage_root / identity):
                raise Refused("STAGE_EXISTS")
            os.rename(temp_name, identity, src_dir_fd=root_fd, dst_dir_fd=root_fd)
            temporary = None
            os.fsync(root_fd)
            return {"ok": True, "protocol": STAGE_PROTOCOL, "id": identity,
                    "staged": True, "entries": inspected["entries"],
                    "uncompressed_bytes": inspected["uncompressed_bytes"],
                    "apply_available": False,
                    "blockers": ["APPLY_NOT_IMPLEMENTED", "DOCKER_IMAGES_NOT_INCLUDED"]}
        finally:
            os.close(archive_fd)
    finally:
        if temporary is not None:
            shutil.rmtree(temporary)
        os.close(root_fd)


def main(argv: list[str]) -> int:
    try:
        if len(argv) != 2 or argv[0] not in ("verify", "plan", "clean-plan", "stage",
                                              "stage-status"):
            raise Refused("USAGE")
        result = (verify(argv[1]) if argv[0] == "verify" else
                  clean_plan(argv[1]) if argv[0] == "clean-plan" else
                  stage(argv[1]) if argv[0] == "stage" else
                  stage_status(argv[1]) if argv[0] == "stage-status" else plan(argv[1]))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (Refused, backup.Refused, OSError, ValueError, TypeError) as exc:
        code = str(exc) if isinstance(exc, (Refused, backup.Refused)) else "IO_ERROR"
        print(json.dumps({"ok": False, "protocol": PROTOCOL, "error": code},
                         separators=(",", ":")))
        return 40


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
