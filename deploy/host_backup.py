#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Offline, root-only archive of the SovaGrid-managed part of one Ubuntu host.

This is deliberately a low-level export primitive. It never stops services,
downloads an archive, adopts an external Agent, or restores a host. A GUI can
later arrange a confirmed stop/create/restart sequence over its trusted SSH
connection. The archive is a secret and must remain on a root-only filesystem.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import grp
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import uuid


ROOT = Path("/")
OUTPUT = Path("/var/lib/sovagrid-host-backups")
CANDIDATE_LOCK = Path("/opt/sovagrid-candidates/.lock")
PUBLIC_LOCK = Path("/var/lib/sovagrid/.public-web.lock")
PROMOTION_LOCK = Path("/run/sovagrid-promotion.lock")
PROTOCOL = "sovagrid-host-backup-v1"
MAX_FILES = 20_000
MAX_BYTES = 8 * 1024**3
MAX_FILE_BYTES = 4 * 1024**3
MAX_SECONDS = 300
MIN_FREE = 256 * 1024**2
MAX_ARCHIVES = 100
# Keep the old Hub/Web pair in this order; the gateway is opt-in on 0.6 hosts.
COMPOSE_SERVICES = ("hub", "web", "ssh-gateway")
SSH_GATEWAY_MARKER = "/var/lib/sovagrid/.ssh-gateway-managed-by-run-sh"
SSH_GATEWAY_MARKER_CONTENT = b"SOVAGRID_SSH_GATEWAY_V1\n"
WEB_AGENT_MARKER = "/var/lib/sovagrid/.web-agent-installer-managed-by-run-sh"
WEB_AGENT_MARKER_CONTENT = b"SOVAGRID_WEB_AGENT_INSTALL_V1\n"
WEB_AGENT_DIR = "/var/lib/sovagrid/web-agent"
WEB_AGENT_JOBS = WEB_AGENT_DIR + "/jobs"
WEB_AGENT_MUTATION_LOCK = WEB_AGENT_JOBS + "/.enrollment-web-mutation"
WEB_AGENT_AUDIT = WEB_AGENT_DIR + "/completed-enrollments.jsonl"
WEB_AGENT_UNITS = ("sovagrid-web-agent-control.socket",
                   "sovagrid-web-agent-control.service")
WEB_AGENT_UNIT_PATHS = tuple("/etc/systemd/system/" + unit
                             for unit in WEB_AGENT_UNITS)
WEB_AGENT_BUNDLE = re.compile(r"source-([0-9a-f]{64})\.tar\.gz\Z")
WEB_AGENT_JOB = re.compile(r"[0-9a-f]{32}\.json\Z")
WEB_AGENT_SOURCE_TEMP = re.compile(r"\.source-[A-Za-z0-9_]{6,31}\Z")
WEB_AGENT_JOB_TEMP = re.compile(r"\.enrollment-[A-Za-z0-9_]{6,31}\Z")
WEB_AGENT_MAX_BUNDLE = 64 * 1024**2
WEB_AGENT_MAX_JOB = 32 * 1024
WEB_AGENT_MAX_LOCK = 128
ID = re.compile(r"[0-9a-f]{32}\Z")
ROOT_UID = 0
ROOT_GID = 0
HUB_UID = 10001
HUB_GID = 10001
WEB_UID = 10002
WEB_GID = 10002
WRITERS = {
    "full": frozenset((
        "sovagrid-vpn-status.service", "sovagrid-vpn-status.timer",
        "sovagrid-vpn-control.service", "sovagrid-vpn-control.socket",
        "sovagrid-auto-update.service", "sovagrid-auto-update.timer",
        "sovagrid-release-feed.service", "sovagrid-release-feed.timer",
        "sovagrid-container-inventory.service", "sovagrid-container-inventory.timer",
        "sovagrid-hub-backup-control.service", "sovagrid-hub-backup-control.socket",
        *WEB_AGENT_UNITS,
    )),
    "hub-only": frozenset((
        "sovagrid-vpn-status.service", "sovagrid-vpn-status.timer",
        "sovagrid-hub-only-update.service", "sovagrid-hub-only-update.timer",
        "sovagrid-release-feed.service", "sovagrid-release-feed.timer",
        "sovagrid-container-inventory-local.service",
        "sovagrid-container-inventory-local.timer",
        "sovagrid-hub-backup-control.service", "sovagrid-hub-backup-control.socket",
        *WEB_AGENT_UNITS,
    )),
}
AMNEZIA_WRITERS = frozenset(("sovagrid-amnezia-control.service",
                             "sovagrid-amnezia-control.socket"))
NON_WRITERS = {
    "full": frozenset((
        "sovagrid-agent.service", "sovagrid-agent-tunnel.service",
        "sovagrid-vpn-routing.service",
        "sovagrid-terminal-control.service", "sovagrid-terminal-control.socket",
        "sovagrid-journal-control.service", "sovagrid-journal-control.socket",
        "sovagrid-service-control.service", "sovagrid-service-control.socket",
    )),
    "hub-only": frozenset((
        "sovagrid-agent.service", "sovagrid-agent-tunnel.service",
        "sovagrid-agent-local.service", "sovagrid-vpn-routing.service",
        "sovagrid-terminal-control.service", "sovagrid-terminal-control.socket",
        "sovagrid-terminal-local-control.service",
        "sovagrid-terminal-local-control.socket",
        "sovagrid-journal-control.service", "sovagrid-journal-control.socket",
        "sovagrid-service-control.service", "sovagrid-service-control.socket",
        "sovagrid-service-local-control.service",
        "sovagrid-service-local-control.socket",
        "sovagrid-vpn-control.service", "sovagrid-vpn-control.socket",
        "sovagrid-amnezia-control.service", "sovagrid-amnezia-control.socket",
        "sovagrid-auto-update.service", "sovagrid-auto-update.timer",
        "sovagrid-container-inventory.service",
        "sovagrid-container-inventory.timer",
    )),
}


class Refused(RuntimeError):
    """Stable public code, never a filename or secret value."""


@dataclass(frozen=True)
class Source:
    path: str
    owner: int = ROOT_UID
    kind: str = "file"
    required: bool = False
    private: bool = False
    exact_mode: int | None = None
    gid: int | None = None
    excluded: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Entry:
    path: str
    info: os.stat_result


# These are state/configuration roots created by SovaGrid, not a filesystem
# walk of /etc, /root, /home, arbitrary Docker volumes, or SSH key stores.
CORE = (
    Source("/var/lib/sovagrid/hub", HUB_UID, "dir", True, True, 0o700, HUB_UID),
    Source("/var/lib/sovagrid/caddy", WEB_UID, "dir", True, True, 0o700, WEB_UID),
    Source("/var/lib/sovagrid/backups", kind="dir", private=True, exact_mode=0o700,
           gid=0),
    Source("/var/lib/sovagrid/vpn", kind="dir", exact_mode=0o750, gid=HUB_GID),
    Source("/etc/sovagrid/deploy.env", required=True, private=True,
           exact_mode=0o600, gid=0),
    Source("/etc/sovagrid/local-web", kind="dir", private=True, exact_mode=0o700, gid=0),
    Source("/etc/sovagrid/admin-password", required=True, private=True,
           exact_mode=0o600, gid=0),
    Source("/var/lib/sovagrid/.managed-by-run-sh", required=True, private=True,
           exact_mode=0o600),
    Source("/var/lib/sovagrid/.hub-backup-broker-managed-by-run-sh", private=True,
           exact_mode=0o600),
    Source("/var/lib/sovagrid/.release-feed-units-managed-by-run-sh", private=True,
           exact_mode=0o600),
    Source(SSH_GATEWAY_MARKER, private=True, exact_mode=0o600, gid=ROOT_GID),
    Source(WEB_AGENT_MARKER, private=True, exact_mode=0o600, gid=ROOT_GID),
    Source(WEB_AGENT_DIR, kind="dir", private=True, exact_mode=0o700,
           gid=ROOT_GID),
    Source("/var/lib/sovagrid/release-feed-state.json", private=True),
    Source("/var/lib/sovagrid/auto-update-status.json", private=True),
    Source("/etc/sovagrid/release-feed.json", private=True),
    Source("/etc/sovagrid/.vpn-unit-managed-by-run-sh", private=True,
           exact_mode=0o600),
    Source("/etc/sovagrid-vpn-routing", kind="dir", private=True),
    Source("/etc/sysctl.d/70-sovagrid-vpn-routing.conf"),
    Source("/opt/sovagrid-vpn", kind="dir"),
    Source("/opt/sovagrid-src", kind="dir"),
)

FULL = (
    Source("/var/lib/sovagrid-vpn", kind="dir", private=True, exact_mode=0o700,
           gid=0),
    Source("/etc/sovagrid-vpn", kind="dir", private=True),
    Source("/etc/systemd/system/sovagrid-amnezia-control.service",
           exact_mode=0o644, gid=0),
    Source("/etc/systemd/system/sovagrid-amnezia-control.socket",
           exact_mode=0o644, gid=0),
    Source("/etc/sovagrid-hub", kind="dir", private=True, exact_mode=0o750,
           gid=HUB_GID, excluded=frozenset({"hub-only-auto-update.json"})),
    Source("/etc/sovagrid/auto-update.json", private=True, exact_mode=0o600),
    Source("/etc/sovagrid/.vpn-control-managed-by-run-sh", private=True,
           exact_mode=0o600),
    Source("/usr/local/bin/sovagrid-vpn-ctl"),
    Source("/usr/local/libexec/sovagrid-vpn-broker"),
    Source("/opt/sovagrid-agent", kind="dir"),
    Source("/etc/sovagrid/agent.json", private=True, exact_mode=0o640),
    Source("/etc/sovagrid/agent.token", private=True, exact_mode=0o640),
    Source("/etc/sovagrid/hub-ca.pem"),
    Source("/etc/sovagrid/.agent-unit-managed-by-run-sh", required=True,
           private=True, exact_mode=0o600),
    Source("/etc/sovagrid/.terminal-unit-managed-by-run-sh", private=True,
           exact_mode=0o600),
    Source("/etc/sovagrid/.journal-managed-by-run-sh", private=True,
           exact_mode=0o600),
    Source("/etc/sovagrid/.containers-managed-by-run-sh", private=True,
           exact_mode=0o600),
    Source("/etc/sovagrid/public-web", kind="dir", private=True),
    Source("/etc/sovagrid-journal", kind="dir", private=True),
    Source("/etc/sovagrid-service", kind="dir", private=True),
    Source("/var/lib/sovagrid-containers", kind="dir", private=True),
)

HUB_ONLY = (
    Source("/etc/sovagrid-hub", kind="dir", private=True, exact_mode=0o750,
           gid=HUB_GID, excluded=frozenset({"bot.token"})),
    Source("/etc/sovagrid/.external-agent-recovery-managed-by-run-sh", private=True,
           exact_mode=0o600, gid=ROOT_GID),
    Source("/opt/sovagrid-agent-local", kind="dir"),
    Source("/etc/sovagrid-local", kind="dir", private=True),
    # Local Agent's /files workspace, and the independent external Agent,
    # remain outside this Hub-only archive.
    Source("/var/lib/sovagrid/local-hub-ca.pem"),
    Source("/var/lib/sovagrid/hub-only-update-status.json", private=True),
    Source("/etc/sovagrid-service-local", kind="dir", private=True),
    Source("/var/lib/sovagrid-promotion/bundle-pin.json", private=True),
    Source("/var/lib/sovagrid-promotion/local-agent.json", private=True),
    Source("/var/lib/sovagrid-promotion/local-operations.json", private=True),
    Source("/var/lib/sovagrid-promotion/local-operations-pending.json", private=True),
    Source("/var/lib/sovagrid-promotion/local-container-inventory.json", private=True,
           exact_mode=0o600, gid=0),
    Source("/var/lib/sovagrid-promotion/local-container-inventory-pending.json", private=True,
           exact_mode=0o600, gid=0),
    Source("/var/lib/sovagrid-containers-local", kind="dir", private=True,
           exact_mode=0o750),
)


def _host(path: str | Path) -> Path:
    return ROOT / str(path).lstrip("/")


def _present(path: str | Path) -> bool:
    return os.path.lexists(_host(path))


def _require_root() -> None:
    if os.geteuid() != ROOT_UID:
        raise Refused("ROOT_REQUIRED")


def _safe_open(path: Path, *, directory: bool = False) -> int:
    """Open each component relative to a pinned fd, rejecting every symlink."""
    if not path.is_absolute() or path == Path("/"):
        raise Refused("INVALID_PATH")
    root = ROOT
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        base = os.fstat(fd)
        if base.st_uid != ROOT_UID or not stat.S_ISDIR(base.st_mode) or base.st_mode & 0o022:
            raise Refused("UNSAFE_PATH")
        parts = path.parts[1:]
        for position, part in enumerate(parts):
            if part in ("", ".", ".."):
                raise Refused("INVALID_PATH")
            last = position == len(parts) - 1
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            if not last or directory:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            if not last:
                info = os.fstat(fd)
                if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
                    raise Refused("UNSAFE_PATH")
        return fd
    except Exception:
        os.close(fd)
        raise


def _check(info: os.stat_result, source: Source, *, directory: bool) -> None:
    if source.path in ("/etc/sovagrid/agent.json", "/etc/sovagrid/agent.token"):
        try:
            agent_gid = grp.getgrnam("sovagrid").gr_gid
        except KeyError as exc:
            raise Refused("UNSAFE_SOURCE") from exc
        source = Source(source.path, ROOT_UID, private=True, exact_mode=0o640,
                        gid=agent_gid)
    if source.path in ("/etc/sovagrid-local/agent.json",
                       "/etc/sovagrid-local/agent.token",
                       "/etc/sovagrid-local/hub-ca.pem"):
        try:
            agent_gid = grp.getgrnam("sovagrid-local").gr_gid
        except KeyError as exc:
            raise Refused("UNSAFE_SOURCE") from exc
        source = Source(source.path, ROOT_UID, private=True, exact_mode=0o640,
                        gid=agent_gid)
    if source.path in ("/var/lib/sovagrid-containers-local",
                       "/var/lib/sovagrid-containers-local/snapshot.json"):
        try:
            local_gid = grp.getgrnam("sovagrid-local").gr_gid
        except KeyError as exc:
            raise Refused("UNSAFE_SOURCE") from exc
        source = Source(source.path, ROOT_UID, kind="dir" if directory else "file",
                        private=True, exact_mode=0o750 if directory else 0o640,
                        gid=local_gid)
    if source.path == "/etc/sovagrid-hub/bot.token":
        source = Source(source.path, ROOT_UID, private=True, exact_mode=0o640,
                        gid=HUB_GID)
    if source.path == "/etc/sovagrid-hub/hub-only-auto-update.json":
        source = Source(source.path, ROOT_UID, private=True, exact_mode=0o600,
                        gid=ROOT_GID)
    if source.path in ("/var/lib/sovagrid/hub/hub.sqlite",
                       "/var/lib/sovagrid/hub/telegram-bot-token"):
        source = Source(source.path, HUB_UID, private=True, exact_mode=0o600,
                        gid=HUB_GID)
    if source.path in (
            "/var/lib/sovagrid/caddy/caddy/pki/authorities/local/root.crt",
            "/var/lib/sovagrid/caddy/caddy/pki/authorities/local/root.key"):
        source = Source(source.path, WEB_UID, private=True, exact_mode=0o600,
                        gid=WEB_GID)
    if info.st_uid != source.owner or info.st_mode & 0o022:
        raise Refused("UNSAFE_SOURCE")
    if source.gid is not None and info.st_gid != source.gid:
        raise Refused("UNSAFE_SOURCE")
    if source.exact_mode is not None and stat.S_IMODE(info.st_mode) != source.exact_mode:
        raise Refused("UNSAFE_SOURCE")
    if source.private and info.st_mode & 0o007:
        raise Refused("UNSAFE_SOURCE")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise Refused("UNSAFE_SOURCE")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Refused("UNSAFE_SOURCE")


def _skip_container_temp(path: str, name: str, info: os.stat_result) -> bool:
    """Ignore only a collector's verified interrupted atomic-write file."""
    groups = {"/var/lib/sovagrid-containers": "sovagrid",
              "/var/lib/sovagrid-containers-local": "sovagrid-local"}
    if path not in groups or not name.startswith(".snapshot-"):
        return False
    if (len(name) > 40 or re.fullmatch(r"\.snapshot-[A-Za-z0-9_]{6,31}", name) is None or
            not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_gid != grp.getgrnam(groups[path]).gr_gid or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) not in (0o600, 0o640) or
            not 0 <= info.st_size <= 10000):
        raise Refused("UNSAFE_SOURCE")
    return True


def _web_agent_source(path: str) -> Source | None:
    """Accept only the installer's private bundle and journal inventory."""
    if path == WEB_AGENT_DIR or path == WEB_AGENT_JOBS:
        return Source(path, ROOT_UID, kind="dir", private=True, exact_mode=0o700,
                      gid=ROOT_GID)
    if path.startswith(WEB_AGENT_DIR + "/"):
        relative = path[len(WEB_AGENT_DIR) + 1:]
        if (relative in (".bundle.lock", "completed-enrollments.jsonl") or
                WEB_AGENT_BUNDLE.fullmatch(relative) or
                relative in ("jobs/.lock", "jobs/.enrollment-web-mutation") or
                relative.startswith("jobs/") and
                WEB_AGENT_JOB.fullmatch(relative[5:])):
            return Source(path, ROOT_UID, private=True, exact_mode=0o600,
                          gid=ROOT_GID)
        raise Refused("UNSAFE_SOURCE")
    return None


def _web_agent_limit(path: str) -> int | None:
    if path == WEB_AGENT_AUDIT:
        return WEB_AGENT_MAX_BUNDLE
    if path.startswith(WEB_AGENT_DIR + "/source-"):
        return WEB_AGENT_MAX_BUNDLE
    if path.startswith(WEB_AGENT_JOBS + "/"):
        return (WEB_AGENT_MAX_JOB if WEB_AGENT_JOB.fullmatch(path.rsplit("/", 1)[1])
                else WEB_AGENT_MAX_LOCK)
    if path == WEB_AGENT_DIR + "/.bundle.lock":
        return WEB_AGENT_MAX_LOCK
    return None


def _web_agent_nonempty(path: str) -> bool:
    name = path.rsplit("/", 1)[1]
    return bool((path.startswith(WEB_AGENT_DIR + "/") and
                 WEB_AGENT_BUNDLE.fullmatch(name)) or
                (path.startswith(WEB_AGENT_JOBS + "/") and
                 WEB_AGENT_JOB.fullmatch(name)))


def _skip_web_agent_temp(path: str, name: str, info: os.stat_result) -> bool:
    """Ignore only interrupted atomic writes that can never be journal state."""
    limit = (WEB_AGENT_MAX_BUNDLE if path == WEB_AGENT_DIR and
             WEB_AGENT_SOURCE_TEMP.fullmatch(name) else
             WEB_AGENT_MAX_JOB if path == WEB_AGENT_JOBS and
             WEB_AGENT_JOB_TEMP.fullmatch(name) else None)
    if limit is None:
        return False
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or
            info.st_gid != ROOT_GID or stat.S_IMODE(info.st_mode) != 0o600 or
            info.st_nlink != 1 or not 0 <= info.st_size <= limit):
        raise Refused("UNSAFE_SOURCE")
    return True


def _web_agent_required(present: set[str]) -> set[str]:
    """A marker must carry a usable recovery snapshot, never a partial one."""
    state = {WEB_AGENT_DIR, WEB_AGENT_JOBS, *WEB_AGENT_UNIT_PATHS}
    if WEB_AGENT_MARKER not in present:
        if state & present:
            raise Refused("UNMANAGED_WEB_AGENT")
        return set()
    required = state | {WEB_AGENT_MARKER}
    if not required <= present or not any(
            path.startswith(WEB_AGENT_DIR + "/") and
            WEB_AGENT_BUNDLE.fullmatch(path.rsplit("/", 1)[1])
            for path in present):
        raise Refused("MISSING_SOURCE")
    return required


def _scan(sources: tuple[Source, ...], *, deadline: float) -> tuple[list[Entry], int]:
    entries: list[Entry] = []
    total = 0
    seen: set[str] = set()

    def add(path: str, source: Source, depth: int) -> None:
        nonlocal total
        if time.monotonic() > deadline:
            raise Refused("TIME_LIMIT")
        if depth > 32 or len(entries) >= MAX_FILES:
            raise Refused("FILE_LIMIT")
        if path in seen:
            raise Refused("DUPLICATE_SOURCE")
        seen.add(path)
        dir_required = path == source.path and source.kind == "dir"
        fd = _safe_open(Path(path), directory=dir_required)
        try:
            info = os.fstat(fd)
            directory = stat.S_ISDIR(info.st_mode)
            if not directory and not stat.S_ISREG(info.st_mode):
                raise Refused("UNSAFE_SOURCE")
            if source.kind == "file" and directory:
                raise Refused("UNSAFE_SOURCE")
            web_agent = _web_agent_source(path)
            selected = (web_agent if web_agent is not None else
                        source if path == source.path else Source(path, source.owner))
            if web_agent is not None and directory != (web_agent.kind == "dir"):
                raise Refused("UNSAFE_SOURCE")
            _check(info, selected, directory=directory)
            if not directory:
                if info.st_size < 0 or info.st_size > MAX_FILE_BYTES:
                    raise Refused("SIZE_LIMIT")
                web_limit = _web_agent_limit(path)
                if web_limit is not None and info.st_size > web_limit:
                    raise Refused("SIZE_LIMIT")
                if _web_agent_nonempty(path) and info.st_size == 0:
                    raise Refused("UNSAFE_SOURCE")
                bundle = (WEB_AGENT_BUNDLE.fullmatch(path.rsplit("/", 1)[1])
                          if path.startswith(WEB_AGENT_DIR + "/") else None)
                if bundle is not None:
                    digest = hashlib.sha256()
                    while block := os.read(fd, 1024 * 1024):
                        if time.monotonic() > deadline:
                            raise Refused("TIME_LIMIT")
                        digest.update(block)
                    if (digest.hexdigest() != bundle.group(1) or
                            _fingerprint(os.fstat(fd)) != _fingerprint(info)):
                        raise Refused("UNSAFE_SOURCE")
                total += info.st_size
                if total > MAX_BYTES:
                    raise Refused("SIZE_LIMIT")
            entries.append(Entry(path, info))
            if directory:
                with os.scandir(fd) as children:
                    names = sorted(item.name for item in children)
                for name in names:
                    if name in source.excluded:
                        continue
                    if path in ("/var/lib/sovagrid-containers",
                                "/var/lib/sovagrid-containers-local") and name.startswith(".snapshot-"):
                        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        if _skip_container_temp(path, name, info):
                            continue
                    if path in (WEB_AGENT_DIR, WEB_AGENT_JOBS) and name.startswith(
                            ".source-" if path == WEB_AGENT_DIR else ".enrollment-"):
                        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        if _skip_web_agent_temp(path, name, info):
                            continue
                    allowed = {
                        "/var/lib/sovagrid/hub": {"hub.sqlite", "hub.sqlite-wal",
                                                  "hub.sqlite-shm", "telegram-bot-token"},
                        "/etc/sovagrid-hub": {"bot.token", "hub-only-auto-update.json"},
                        "/etc/sovagrid-vpn": {"amnezia-control.enabled",
                                               "amnezia-wireguard-control.enabled",
                                               "amnezia-install.lock"},
                        "/etc/sovagrid-service": {"enabled", "units.json"},
                        "/etc/sovagrid-service-local": {"enabled", "units.json"},
                        "/etc/sovagrid-journal": {"units.json"},
                        "/etc/sovagrid-local": {"agent.json", "agent.token", "hub-ca.pem"},
                        "/etc/sovagrid-vpn-routing": {"policy.json"},
                        "/var/lib/sovagrid/vpn": {"status.json"},
                        "/var/lib/sovagrid-containers": {"snapshot.json"},
                        "/var/lib/sovagrid-containers-local": {"snapshot.json"},
                    }.get(path)
                    if (name in (".", "..") or "/" in name or
                            len(name.encode("utf-8")) > 255 or
                            len((path + "/" + name).encode("utf-8")) > 4096 or
                            (allowed is not None and name not in allowed)):
                        raise Refused("UNSAFE_SOURCE")
                    add(path + "/" + name, source, depth + 1)
        finally:
            os.close(fd)

    for source in sources:
        if _present(source.path):
            add(source.path, source, 0)
        elif source.required:
            raise Refused("MISSING_SOURCE")
    return entries, total


def _layout() -> str:
    full = _present("/etc/sovagrid/.agent-unit-managed-by-run-sh")
    local = _present("/etc/sovagrid-local/agent.json")
    if full and local:
        raise Refused("AMBIGUOUS_LAYOUT")
    return "full" if full else "hub-only"


def _unit_paths(layout: str) -> tuple[Source, ...]:
    # The updater owns the exact systemd units. Importing constants only does
    # not execute its updater. Do not add a wildcard over /etc/systemd/system.
    sys.dont_write_bytecode = True
    import importlib.util
    module = "remote_update_worker.py" if layout == "full" else "hub_only_update.py"
    target = Path(__file__).with_name(module)
    spec = importlib.util.spec_from_file_location("_sovagrid_host_backup_units", target)
    if spec is None or spec.loader is None:
        raise Refused("SOURCE_UNAVAILABLE")
    loaded = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(loaded)
    except (ImportError, OSError, AttributeError) as exc:
        raise Refused("SOURCE_UNAVAILABLE") from exc
    return tuple(Source(path, exact_mode=0o644, gid=ROOT_GID) for path in loaded.SNAPSHOT
                 if path.startswith("/etc/systemd/system/") and
                 path.rsplit("/", 1)[1].startswith("sovagrid-"))


def _sources(layout: str) -> tuple[Source, ...]:
    chosen = CORE + (FULL if layout == "full" else HUB_ONLY) + _unit_paths(layout)
    paths = [source.path for source in chosen]
    if len(paths) != len(set(paths)):
        raise Refused("DUPLICATE_SOURCE")
    return chosen


def _run(args: list[str]) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10,
                                check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused("OFFLINE_CHECK_UNAVAILABLE") from exc
    if result.returncode:
        raise Refused("OFFLINE_CHECK_UNAVAILABLE")
    return result.stdout


def _sealed_marker(path: str, contents: bytes, error: str) -> bool:
    if not _present(path):
        return False
    try:
        fd = _safe_open(Path(path))
    except (OSError, Refused) as exc:
        raise Refused(error) from exc
    try:
        before = os.fstat(fd)
        _check(before, Source(path, ROOT_UID, private=True, exact_mode=0o600,
                              gid=ROOT_GID), directory=False)
        if (before.st_size != len(contents) or
                os.read(fd, len(contents) + 1) != contents or
                _fingerprint(os.fstat(fd)) != _fingerprint(before)):
            raise Refused(error)
        return True
    except (OSError, Refused) as exc:
        raise Refused(error) from exc
    finally:
        os.close(fd)


def _gateway_marker() -> bool:
    """Only a sealed installer marker makes the optional gateway managed."""
    return _sealed_marker(SSH_GATEWAY_MARKER, SSH_GATEWAY_MARKER_CONTENT,
                          "UNSAFE_GATEWAY_MARKER")


def _web_agent_marker() -> bool:
    return _sealed_marker(WEB_AGENT_MARKER, WEB_AGENT_MARKER_CONTENT,
                          "UNSAFE_WEB_AGENT_MARKER")


def _active_writers(layout: str) -> tuple[list[str], list[str]]:
    if layout == "hub-only" and _present(
            "/etc/systemd/system/sovagrid-agent.service.requires/"
            "sovagrid-external-agent-recovery.service"):
        raise Refused("EXTERNAL_AGENT_UPDATE_BUSY")
    expected = WRITERS[layout]
    gateway_managed = _gateway_marker()
    web_agent_managed = _web_agent_marker()
    if (layout == "full" and
            (_present("/etc/sovagrid-vpn/amnezia-control.enabled") or
             _present("/etc/sovagrid-vpn/amnezia-wireguard-control.enabled"))):
        expected = expected | AMNEZIA_WRITERS
    units = _run(["systemctl", "list-units", "--all", "--plain", "--no-legend",
                  "--no-pager", "sovagrid-*.service", "sovagrid-*.socket",
                  "sovagrid-*.timer"])
    active = []
    for line in units.splitlines():
        fields = line.lstrip("● ").split()
        if len(fields) < 3 or not fields[0].startswith("sovagrid-") or fields[2] != "active":
            continue
        if fields[0] not in expected and fields[0] not in NON_WRITERS[layout]:
            raise Refused("UNKNOWN_ACTIVE_UNIT")
        if fields[0] in expected:
            if fields[0] in WEB_AGENT_UNITS and not web_agent_managed:
                raise Refused("UNMANAGED_WEB_AGENT")
            unit_path = Path("/etc/systemd/system") / fields[0]
            try:
                fd = _safe_open(unit_path)
            except OSError as exc:
                raise Refused("UNMANAGED_UNIT") from exc
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or
                        stat.S_IMODE(info.st_mode) != 0o644 or info.st_nlink != 1):
                    raise Refused("UNMANAGED_UNIT")
            finally:
                os.close(fd)
            active.append(fields[0])
    all_ids = _run(["docker", "ps", "--quiet", "--filter",
                    "label=com.docker.compose.project=sovagrid"]).splitlines()
    containers = []
    selected = []
    for service in COMPOSE_SERVICES:
        ids = _run(["docker", "ps", "--quiet", "--filter",
                    "label=com.docker.compose.project=sovagrid", "--filter",
                    "label=com.docker.compose.service=" + service]).splitlines()
        if len(ids) > 1:
            raise Refused("CONTAINER_AMBIGUOUS")
        if ids:
            if service == "ssh-gateway" and not gateway_managed:
                raise Refused("UNMANAGED_GATEWAY")
            selected.extend(ids)
            containers.append(service)
    if len(all_ids) != len(set(all_ids)) or set(all_ids) != set(selected):
        raise Refused("CONTAINER_AMBIGUOUS")
    return sorted(active), containers


def _require_offline(layout: str) -> None:
    active, containers = _active_writers(layout)
    if active:
        raise Refused("SERVICES_RUNNING")
    if containers:
        raise Refused("CONTAINERS_RUNNING")


def plan() -> dict:
    _require_root()
    layout = _layout()
    active, containers = _active_writers(layout)
    return {"ok": True, "protocol": PROTOCOL, "layout": layout,
            "active_units": active, "running_containers": containers,
            "offline_ready": not active and not containers}


@contextmanager
def _promotion_lock():
    """Serialize a direct Hub-only archive with local collector changes.

    Acquire this before candidate/public locks, matching the Hub-only updater's
    order. The orchestrator holds the same lock around its offline phase.
    """
    if _layout() != "hub-only":
        yield
        return
    path = _host(PROMOTION_LOCK)
    if path.is_symlink():
        raise Refused("LOCK_UNAVAILABLE")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or
                info.st_gid != ROOT_GID or stat.S_IMODE(info.st_mode) != 0o600 or
                info.st_nlink != 1):
            raise Refused("LOCK_UNAVAILABLE")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused("BUSY") from exc
        if _layout() != "hub-only":
            raise Refused("LAYOUT_CHANGED")
        yield
    finally:
        os.close(fd)


@contextmanager
def _locks():
    locks = []
    try:
        for path in (CANDIDATE_LOCK, PUBLIC_LOCK):
            target = _host(path)
            if not target.exists() or target.is_symlink():
                raise Refused("LOCK_UNAVAILABLE")
            fd = _safe_open(path)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                os.close(fd)
                raise Refused("LOCK_UNAVAILABLE")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                os.close(fd)
                raise Refused("BUSY") from exc
            locks.append(fd)
        yield
    finally:
        for fd in reversed(locks):
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _output(*, create: bool) -> Path:
    target = _host(OUTPUT)
    if create and not os.path.lexists(target):
        target.mkdir(mode=0o700)
        info = target.lstat()
        if (info.st_uid, info.st_gid) != (ROOT_UID, ROOT_GID):
            os.chown(target, ROOT_UID, ROOT_GID, follow_symlinks=False)
        os.chmod(target, 0o700, follow_symlinks=False)
    fd = _safe_open(OUTPUT, directory=True)
    try:
        info = os.fstat(fd)
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (ROOT_UID, ROOT_GID, 0o700):
            raise Refused("UNSAFE_OUTPUT")
    finally:
        os.close(fd)
    return target


def _inventory(output: Path) -> list[str]:
    manifests: set[str] = set()
    archives: set[str] = set()
    for item in output.iterdir():
        name = item.name
        if name.endswith(".manifest.json") and ID.fullmatch(name[:-14]):
            manifests.add(name[:-14])
        elif name.endswith(".tar.gz") and ID.fullmatch(name[:-7]):
            archives.add(name[:-7])
        elif name.startswith(".") and name.endswith(".tmp"):
            raise Refused("INCOMPLETE_ARCHIVE")
        else:
            raise Refused("UNSAFE_OUTPUT")
        if len(manifests) > MAX_ARCHIVES or len(archives) > MAX_ARCHIVES:
            raise Refused("ARCHIVE_LIMIT")
    if manifests != archives:
        raise Refused("INCOMPLETE_ARCHIVE")
    return sorted(manifests)


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _source_manifest() -> str | None:
    if not _present("/opt/sovagrid-src"):
        return None
    # The updater's signed-off inventory rejects extras and altered sources.
    # ROOT is fixed to / in production; tests can omit this optional tree.
    if ROOT != Path("/"):
        return None
    target = Path(__file__).with_name("remote_update_worker.py")
    script = ("import importlib.util,pathlib,sys; sys.dont_write_bytecode=True; "
              "p=" + repr(str(target)) + "; "
              "s=importlib.util.spec_from_file_location('sg_host_source',p); "
              "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
              "print(m.source_manifest(pathlib.Path('/opt/sovagrid-src'),"
              "allow_generated=True)[0])")
    try:
        result = subprocess.run([sys.executable, "-I", "-B", "-c", script],
                                capture_output=True, text=True, timeout=60,
                                check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused("SOURCE_UNSAFE") from exc
    digest = result.stdout.strip()
    if result.returncode or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise Refused("SOURCE_UNSAFE")
    return digest


def source() -> dict:
    """Return the installed source generation for compare-and-set requests."""
    _require_root()
    digest = _source_manifest()
    if digest is None:
        raise Refused("SOURCE_UNAVAILABLE")
    return {"ok": True, "protocol": PROTOCOL, "manifest_sha256": digest}


class _LimitedReader(io.RawIOBase):
    def __init__(self, fd: int, size: int, deadline: float):
        self.fd, self.remaining, self.deadline = fd, size, deadline
        self.digest = hashlib.sha256()

    def readable(self) -> bool:
        return True

    def read(self, amount: int = -1) -> bytes:
        if time.monotonic() > self.deadline:
            raise Refused("TIME_LIMIT")
        if self.remaining == 0:
            return b""
        amount = self.remaining if amount < 0 else min(amount, self.remaining)
        block = os.read(self.fd, min(amount, 1024 * 1024))
        if not block:
            raise Refused("SOURCE_CHANGED")
        self.remaining -= len(block)
        self.digest.update(block)
        return block


def _write_archive(path: Path, entries: list[Entry], deadline: float) -> tuple[int, str]:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    try:
        info = os.fstat(fd)
        if (info.st_uid, info.st_gid) != (ROOT_UID, ROOT_GID):
            os.fchown(fd, ROOT_UID, ROOT_GID)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            fd = -1
            with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
                for entry in entries:
                    if time.monotonic() > deadline:
                        raise Refused("TIME_LIMIT")
                    directory = stat.S_ISDIR(entry.info.st_mode)
                    source_fd = _safe_open(Path(entry.path), directory=directory)
                    try:
                        before = os.fstat(source_fd)
                        if _fingerprint(before) != _fingerprint(entry.info):
                            raise Refused("SOURCE_CHANGED")
                        name = entry.path.lstrip("/")
                        member = tarfile.TarInfo(name + ("/" if directory else ""))
                        member.uid, member.gid = before.st_uid, before.st_gid
                        member.mode = stat.S_IMODE(before.st_mode)
                        member.mtime = int(before.st_mtime)
                        member.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
                        member.size = 0 if directory else before.st_size
                        reader = None if directory else _LimitedReader(source_fd,
                                                                        before.st_size, deadline)
                        archive.addfile(member, reader)
                        after = os.fstat(source_fd)
                        if (_fingerprint(after) != _fingerprint(before) or
                                (reader is not None and reader.remaining != 0)):
                            raise Refused("SOURCE_CHANGED")
                        bundle = (WEB_AGENT_BUNDLE.fullmatch(name.rsplit("/", 1)[1])
                                  if entry.path.startswith(WEB_AGENT_DIR + "/") else None)
                        if bundle is not None and (reader is None or
                                                   reader.digest.hexdigest() !=
                                                   bundle.group(1)):
                            raise Refused("SOURCE_CHANGED")
                    finally:
                        os.close(source_fd)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if fd >= 0:
            os.close(fd)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_BYTES:
        raise Refused("SIZE_LIMIT")
    return info.st_size, _hash(path, deadline=deadline)


def _hash(path: Path, *, deadline: float | None = None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            if deadline is not None and time.monotonic() > deadline:
                raise Refused("TIME_LIMIT")
            digest.update(chunk)
    return digest.hexdigest()


def _sync(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _summary(manifest: dict) -> dict:
    return {key: manifest[key] for key in ("id", "created_at", "layout", "bytes", "files")}


def _create_locked(identity: str | None = None) -> dict:
    """Create while the caller holds candidate and public-Web locks."""
    _require_root()
    layout = _layout()
    _require_offline(layout)
    if layout == "hub-only" and _present(
            "/var/lib/sovagrid-promotion/local-container-inventory-pending.json"):
        raise Refused("LOCAL_CONTAINERS_RECOVERY")
    deadline = time.monotonic() + MAX_SECONDS
    source_digest = _source_manifest()
    sources = _sources(layout)
    entries, total = _scan(sources, deadline=deadline)
    present = {item.path for item in entries}
    required = {
        "/var/lib/sovagrid/hub/hub.sqlite",
        "/var/lib/sovagrid/caddy/caddy/pki/authorities/local/root.crt",
        "/var/lib/sovagrid/caddy/caddy/pki/authorities/local/root.key",
    }
    if layout == "full":
        required.update(("/etc/sovagrid/agent.json", "/etc/sovagrid/agent.token",
                         "/etc/sovagrid/hub-ca.pem", "/opt/sovagrid-agent"))
    elif _present("/etc/sovagrid-local/agent.json"):
        required.update(("/etc/sovagrid-local/agent.json",
                         "/etc/sovagrid-local/agent.token",
                         "/etc/sovagrid-local/hub-ca.pem",
                         "/opt/sovagrid-agent-local"))
        if _present("/var/lib/sovagrid-promotion/local-container-inventory.json"):
            required.update((
                "/var/lib/sovagrid-promotion/local-container-inventory.json",
                "/var/lib/sovagrid-containers-local",
                "/var/lib/sovagrid-containers-local/snapshot.json",
                "/etc/systemd/system/sovagrid-container-inventory-local.service",
                "/etc/systemd/system/sovagrid-container-inventory-local.timer",
            ))
    if len(entries) < 3 or not required <= present:
        raise Refused("MISSING_SOURCE")
    _web_agent_required(present)
    output = _output(create=True)
    if len(_inventory(output)) >= MAX_ARCHIVES:
        raise Refused("ARCHIVE_LIMIT")
    # gzip may expand incompressible input. Reserve the full input bytes,
    # tar overhead, and a fixed safety margin on the destination filesystem.
    available = shutil.disk_usage(output).free
    if available < total + len(entries) * 1024 + MIN_FREE:
        raise Refused("DISK_SPACE")
    identity = uuid.uuid4().hex if identity is None else identity
    if not isinstance(identity, str) or ID.fullmatch(identity) is None:
        raise Refused("INVALID_ID")
    archive_path = output / (identity + ".tar.gz")
    manifest_path = output / (identity + ".manifest.json")
    temporary_archive = output / ("." + identity + ".tar.gz.tmp")
    temporary_manifest = output / ("." + identity + ".manifest.json.tmp")
    if any(os.path.lexists(item) for item in
           (archive_path, manifest_path, temporary_archive, temporary_manifest)):
        raise Refused("ID_CONFLICT")
    published = False
    try:
        size, digest = _write_archive(temporary_archive, entries, deadline)
        after, _after_total = _scan(sources, deadline=deadline)
        if ([(item.path, _fingerprint(item.info)) for item in after] !=
                [(item.path, _fingerprint(item.info)) for item in entries]):
            raise Refused("SOURCE_CHANGED")
        _require_offline(layout)
        if time.monotonic() > deadline:
            raise Refused("TIME_LIMIT")
        manifest = {"protocol": PROTOCOL, "id": identity,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "layout": layout, "bytes": size, "files": len(entries),
                    "sha256": digest, "source_manifest_sha256": source_digest}
        raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        fd = os.open(temporary_manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        if (info.st_uid, info.st_gid) != (ROOT_UID, ROOT_GID):
            os.fchown(fd, ROOT_UID, ROOT_GID)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_archive, archive_path)
        os.replace(temporary_manifest, manifest_path)
        _sync(output)
        published = True
    finally:
        temporary_archive.unlink(missing_ok=True)
        temporary_manifest.unlink(missing_ok=True)
        if not published:
            archive_path.unlink(missing_ok=True)
            manifest_path.unlink(missing_ok=True)
            _sync(output)
    return {"ok": True, "protocol": PROTOCOL, "archive": _summary(manifest)}


def create() -> dict:
    _require_root()
    with _promotion_lock(), _locks():
        return _create_locked()


def _record(identity: str) -> dict:
    if not ID.fullmatch(identity):
        raise Refused("INVALID_ID")
    if not _present(OUTPUT):
        raise Refused("NOT_FOUND")
    output = _output(create=False)
    archive = output / (identity + ".tar.gz")
    manifest = output / (identity + ".manifest.json")
    for path in (archive, manifest):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError as exc:
            raise Refused("NOT_FOUND") from exc
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or
                    info.st_gid != ROOT_GID or stat.S_IMODE(info.st_mode) != 0o600 or
                    info.st_nlink != 1):
                raise Refused("UNSAFE_ARCHIVE")
            if path == manifest:
                if info.st_size > 2048:
                    raise Refused("UNSAFE_ARCHIVE")
                raw = os.read(fd, 2049)
        finally:
            os.close(fd)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise Refused("INVALID_MANIFEST") from exc
    if (not isinstance(value, dict) or set(value) != {"protocol", "id", "created_at",
            "layout", "bytes", "files", "sha256", "source_manifest_sha256"} or
            value["protocol"] != PROTOCOL or value["id"] != identity or
            value["layout"] not in ("full", "hub-only") or
            type(value["bytes"]) is not int or not 0 < value["bytes"] <= MAX_BYTES or
            type(value["files"]) is not int or not 0 < value["files"] <= MAX_FILES or
            not isinstance(value["created_at"], str) or
            len(value["created_at"]) > 40 or
            not value["created_at"].endswith("+00:00") or
            not re.fullmatch(r"[0-9a-f]{64}", str(value["sha256"])) or
            (value["source_manifest_sha256"] is not None and
             not re.fullmatch(r"[0-9a-f]{64}", str(value["source_manifest_sha256"])))):
        raise Refused("INVALID_MANIFEST")
    try:
        datetime.fromisoformat(value["created_at"])
    except ValueError as exc:
        raise Refused("INVALID_MANIFEST") from exc
    if archive.stat().st_size != value["bytes"]:
        raise Refused("ARCHIVE_CHANGED")
    return value


def list_archives() -> dict:
    _require_root()
    if not _present(OUTPUT):
        return {"ok": True, "protocol": PROTOCOL, "archives": []}
    output = _output(create=False)
    names = _inventory(output)
    records = [_summary(_record(identity)) for identity in names]
    records.sort(key=lambda item: (item["created_at"], item["id"]), reverse=True)
    return {"ok": True, "protocol": PROTOCOL, "archives": records}


def verify(identity: str) -> dict:
    _require_root()
    deadline = time.monotonic() + MAX_SECONDS
    manifest = _record(identity)
    output = _output(create=False)
    archive = output / (identity + ".tar.gz")
    if _hash(archive, deadline=deadline) != manifest["sha256"]:
        raise Refused("ARCHIVE_CHANGED")
    # The whole-file digest protects the private archive; structural checks
    # make malformed paths and duplicate members visible before any restore
    # design can consume it.
    try:
        with tarfile.open(archive, "r:gz") as stream:
            seen = set()
            total = 0
            for member in stream:
                if time.monotonic() > deadline:
                    raise Refused("TIME_LIMIT")
                name = member.name.rstrip("/")
                total += member.size
                if (name in seen or len(seen) >= MAX_FILES or not name or
                        name.startswith("/") or any(part in ("", ".", "..")
                        for part in name.split("/")) or
                        not (member.isfile() or member.isdir()) or
                        member.size > MAX_FILE_BYTES or total > MAX_BYTES):
                    raise Refused("INVALID_ARCHIVE")
                seen.add(name)
            if len(seen) != manifest["files"]:
                raise Refused("INVALID_ARCHIVE")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise Refused("INVALID_ARCHIVE") from exc
    return {"ok": True, "protocol": PROTOCOL, "archive": _summary(manifest),
            "verified": True}


def main(argv: list[str]) -> int:
    try:
        if argv == ["create"]:
            result = create()
        elif argv == ["plan"]:
            result = plan()
        elif argv == ["source"]:
            result = source()
        elif argv == ["list"]:
            result = list_archives()
        elif len(argv) == 2 and argv[0] == "verify":
            result = verify(argv[1])
        else:
            raise Refused("USAGE")
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except (Refused, OSError, tarfile.TarError, ValueError, EOFError) as exc:
        code = str(exc) if isinstance(exc, Refused) else "IO_ERROR"
        print(json.dumps({"ok": False, "protocol": PROTOCOL, "error": code},
                         separators=(",", ":")))
        return 40


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
