#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in, two-phase promotion of an Agent-only host to its own local Hub.

``prepare`` records the exact external Agent/tunnel state before run.sh
--hub-only. ``activate`` checks that state before creating an *additional*
local Agent service. The original Agent, enrollment and SSH tunnels are never
rewritten by this helper. This is a host-root helper for a future GUI wizard,
not an automatic migration or a release downloader.
"""

from __future__ import annotations

import hashlib
import fcntl
import grp
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
import uuid


STATE_DIR = Path("/var/lib/sovagrid-promotion")
BASELINE = STATE_DIR / "baseline.json"
PIN = STATE_DIR / "bundle-pin.json"
LOCAL = STATE_DIR / "local-agent.json"
LOCAL_OPERATIONS = STATE_DIR / "local-operations.json"
LOCAL_OPERATIONS_PENDING = STATE_DIR / "local-operations-pending.json"
SOURCE = Path("/opt/sovagrid-src")
LOCAL_SOURCE = Path("/opt/sovagrid-agent-local")
MANAGED_MARKER = Path("/var/lib/sovagrid/.managed-by-run-sh")
AGENT_MARKER = Path("/etc/sovagrid/.agent-unit-managed-by-run-sh")
LOCAL_USER = "sovagrid-local"
LOCAL_ETC = Path("/etc/sovagrid-local")
LOCAL_DATA = Path("/var/lib/sovagrid-agent-local")
LOCAL_CONFIG = LOCAL_ETC / "agent.json"
LOCAL_TOKEN = LOCAL_ETC / "agent.token"
LOCAL_CA = LOCAL_ETC / "hub-ca.pem"
LOCAL_HUB_CA_STAGING = Path("/var/lib/sovagrid/local-hub-ca.pem")
LOCAL_UNIT = Path("/etc/systemd/system/sovagrid-agent-local.service")
LOCAL_FILE_WORKSPACE = LOCAL_DATA / "files"
LOCAL_SHELL = "sovagrid-local-shell"
LOCAL_SHELL_HOME = Path("/var/lib/sovagrid-local-shell")
LOCAL_TERMINAL_SOCKET = "/run/sovagrid-terminal-local/control.sock"
LOCAL_SERVICE_SOCKET = "/run/sovagrid-service-local/control.sock"
SERVICE_SETUP_LOCK = Path("/etc/sovagrid-service-setup.lock")
LOCAL_TERMINAL_UNITS = ("sovagrid-terminal-local-control.socket",
                        "sovagrid-terminal-local-control.service")
CRITICAL = (
    "/etc/sovagrid/agent.json",
    "/etc/sovagrid/agent.token",
    "/etc/systemd/system/sovagrid-agent.service",
    "/etc/systemd/system/sovagrid-agent-tunnel.service",
    "/opt/sovagrid-agent-installer/source-manifest.json",
    "/var/lib/sovagrid-agent-enrollment/state.json",
)
OPTIONAL_CRITICAL = ("/etc/sovagrid/hub-ca.pem",)
UNITS = ("sovagrid-agent.service", "sovagrid-agent-tunnel.service")
MAX_ADDITIONAL_TUNNELS = 16
UNIT_NAME = re.compile(r"[A-Za-z0-9_.@-]+\.service\Z")
UNIT_TEXT = """[Unit]
Description=SovaGrid local Agent for the independent local Hub
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=sovagrid-local
Group=sovagrid-local
WorkingDirectory=/opt/sovagrid-agent-local
ExecStart=/usr/bin/python3 -m sovagrid_agent --config /etc/sovagrid-local/agent.json
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sovagrid-agent-local
CapabilityBoundingSet=
TasksMax=64
MemoryMax=256M

[Install]
WantedBy=multi-user.target
"""
ROOT_UID = 0
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMPONENTS = {"sovagrid-blueprint", "sovagrid-hub", "sovagrid-web", "sovagrid-agent", "sovagrid-vpn"}


class PromotionError(RuntimeError):
    pass


def need(ok: bool, why: str) -> None:
    if not ok:
        raise PromotionError(why)


def _read_regular(path: Path, limit: int = 1024 * 1024) -> bytes:
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and
         not info.st_mode & 0o022 and 0 < info.st_size <= limit,
         f"Unsafe or missing file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        need((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino),
             f"File changed during inspection: {path}")
        value = stream.read(limit + 1)
    need(len(value) <= limit, f"File exceeds limit: {path}")
    return value


def _unit_active(unit: str) -> bool:
    result = subprocess.run(["systemctl", "is-active", "--quiet", unit], timeout=10, check=False)
    return result.returncode == 0


def _unit_enabled(unit: str) -> bool:
    result = subprocess.run(["systemctl", "is-enabled", "--quiet", unit], timeout=10, check=False)
    return result.returncode == 0


def _additional_reverse_tunnels(systemd_dir: Path = Path("/etc/systemd/system")) -> dict[str, bytes]:
    """Find independent reverse SSH transports without naming a particular host.

    Only root-owned regular unit files in the local systemd directory qualify.
    The original Agent transport is already a required, separately guarded unit.
    """
    info = systemd_dir.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and
         not info.st_mode & 0o022, "Systemd unit directory is unsafe")
    found = {}
    for path in sorted(systemd_dir.glob("*.service")):
        if path.is_symlink():
            continue
        need(UNIT_NAME.fullmatch(path.name) is not None, "Systemd unit name is unsafe")
        if path.name in UNITS:
            continue
        raw = _read_regular(path, 65536)
        lines = raw.decode("utf-8", errors="replace").replace("\\\n", " ").splitlines()
        if any(re.match(r"\s*ExecStart\s*=", line) and
               re.search(r"(?:^|/)(?:auto)?ssh\b", line) and
               re.search(r"(?<!\S)-R", line)
               for line in lines):
            found[path.name] = raw
            need(len(found) <= MAX_ADDITIONAL_TUNNELS, "Too many reverse SSH units")
    return found


def capture_external() -> dict:
    """Snapshot public hashes/metadata only; never serialize a token."""
    need(os.geteuid() == 0, "Root authority is required")
    release_path = Path("/etc/os-release")
    if release_path.is_symlink():
        need(release_path.resolve(strict=True) == Path("/usr/lib/os-release"),
             "Unexpected OS release link")
        release_path = Path("/usr/lib/os-release")
    release = _read_regular(release_path, 8192).decode("utf-8")
    need(re.search(r"(?m)^ID=ubuntu$", release) is not None, "Ubuntu is required")
    files = {}
    tracked = CRITICAL + tuple(name for name in OPTIONAL_CRITICAL
                               if Path(name).exists() or Path(name).is_symlink())
    for name in tracked:
        path = Path(name)
        raw = _read_regular(path, 4 * 1024 * 1024 if name.endswith("state.json") else 1024 * 1024)
        info = path.lstat()
        files[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "uid": info.st_uid,
                       "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}
    agent_dir = Path("/var/lib/sovagrid-agent")
    info = agent_dir.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and
         not info.st_mode & 0o022, "External Agent data directory is unsafe")
    additional = _additional_reverse_tunnels()
    units = {name: _unit_active(name) for name in (*UNITS, *additional)}
    need(units["sovagrid-agent.service"] and units["sovagrid-agent-tunnel.service"],
         "External Agent and its transport must be active")
    for name, raw in additional.items():
        need(units[name], "Existing reverse SSH tunnel must be active")
        path = Path("/etc/systemd/system") / name
        extra = path.lstat()
        files[str(path)] = {"sha256": hashlib.sha256(raw).hexdigest(), "uid": extra.st_uid,
                            "gid": extra.st_gid, "mode": stat.S_IMODE(extra.st_mode)}
    return {"protocol": 1, "files": files,
            "agent_data": {"uid": info.st_uid, "gid": info.st_gid,
                           "mode": stat.S_IMODE(info.st_mode)}, "units": units}


def _external_matches(current: dict, baseline: dict) -> bool:
    """Accept legacy absent optional units without weakening active guards."""
    if current == baseline:
        return True
    if not isinstance(current, dict) or not isinstance(baseline, dict):
        return False
    old_units, new_units = baseline.get("units"), current.get("units")
    old_files = baseline.get("files")
    if not isinstance(old_units, dict) or not isinstance(new_units, dict) or not isinstance(old_files, dict):
        return False
    absent = set(old_units) - set(new_units)
    if any(name in UNITS or old_units[name] is not False or
           "/etc/systemd/system/" + name in old_files for name in absent):
        return False
    return {**baseline, "units": {name: active for name, active in old_units.items()
                                    if name not in absent}} == current


def _private_json(path: Path) -> dict:
    raw = _read_regular(path, 32768)
    info = path.lstat()
    need(stat.S_IMODE(info.st_mode) == 0o600, "Promotion journal must be root-only")
    value = json.loads(raw)
    need(isinstance(value, dict), "Promotion journal is invalid")
    return value


def _save_private(path: Path, value: dict) -> None:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    need(len(raw) <= 32768, "Promotion journal is too large")
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    info = STATE_DIR.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and stat.S_IMODE(info.st_mode) == 0o700,
         "Promotion journal directory is unsafe")
    temporary = STATE_DIR / ("." + secrets.token_hex(12) + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _pin() -> str | None:
    need(not PIN.is_symlink(), "Promotion package pin is unsafe")
    if not PIN.exists():
        return None
    value = _private_json(PIN)
    digest = value.get("manifest_sha256")
    need(set(value) == {"protocol", "manifest_sha256"} and type(value["protocol"]) is int and
         value["protocol"] == 1 and
         isinstance(digest, str) and HEX_SHA256.fullmatch(digest) is not None,
         "Promotion package pin is invalid")
    return digest


def prepare(*, manifest_sha256: str | None = None) -> dict:
    if manifest_sha256 is not None:
        need(isinstance(manifest_sha256, str) and HEX_SHA256.fullmatch(manifest_sha256) is not None,
             "A canonical manifest SHA-256 is required")
    need(not SOURCE.exists() and not SOURCE.is_symlink(), "Local Hub source already exists")
    need(not MANAGED_MARKER.exists() and not MANAGED_MARKER.is_symlink(), "Local Hub already exists")
    need(not LOCAL.exists() and not LOCAL.is_symlink(), "Promotion is already in progress")
    need(not BASELINE.is_symlink(), "Promotion baseline is unsafe")
    current = capture_external()
    if BASELINE.exists():
        need(_external_matches(current, _private_json(BASELINE)),
             "External Agent changed since preparation")
    else:
        _save_private(BASELINE, current)
    old_pin = _pin()
    if manifest_sha256 is not None:
        need(old_pin is None or old_pin == manifest_sha256, "A different package is already pinned")
        if old_pin is None:
            _save_private(PIN, {"protocol": 1, "manifest_sha256": manifest_sha256})
    return {"protocol": 1, "prepared": True, "external_agent_preserved": True}


def _source_manifest_sha256() -> str:
    """Bounded, read-only verification of every file in a candidate bundle."""
    info = SOURCE.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and
         not info.st_mode & 0o022, "Local Hub source directory is unsafe")
    manifest_raw = _read_regular(SOURCE / "sovagrid-bundle.json")
    manifest = json.loads(manifest_raw)
    hashes = manifest.get("sha256") if isinstance(manifest, dict) else None
    need(isinstance(manifest, dict) and type(manifest.get("format")) is int and
         manifest.get("format") == 1 and isinstance(hashes, dict) and
         1 <= len(hashes) <= 1024, "Candidate bundle manifest is invalid")
    expected = set()
    for name, digest in hashes.items():
        need(isinstance(name, str) and len(name) <= 255 and not name.startswith("/") and
             len(name.split("/")) >= 2 and name.split("/")[0] in COMPONENTS and
             all(part not in ("", ".", "..") for part in name.split("/")) and
             isinstance(digest, str) and HEX_SHA256.fullmatch(digest) is not None,
             "Candidate bundle manifest path or digest is invalid")
        expected.add(name)
    actual = set()
    total = 0
    def walk_error(exc):
        raise PromotionError("Candidate bundle tree is unreadable") from exc
    directory_count = 0
    for parent, directories, files in os.walk(SOURCE, topdown=True, followlinks=False, onerror=walk_error):
        directory_count += len(directories)
        need(directory_count <= 2048 and len(Path(parent).relative_to(SOURCE).parts) <= 16,
             "Candidate bundle tree is too large")
        for name in directories:
            child = Path(parent) / name
            info = child.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and
                 not info.st_mode & 0o022, "Candidate bundle directory is unsafe")
        for name in files:
            child = Path(parent) / name
            relative = child.relative_to(SOURCE).as_posix()
            if relative == "sovagrid-bundle.json":
                continue
            need(relative in expected and relative not in actual,
                 "Candidate bundle has an unexpected file")
            raw = _read_regular(child, 8 * 1024 * 1024)
            total += len(raw)
            need(total <= 256 * 1024 * 1024 and
                 hashlib.sha256(raw).hexdigest() == hashes[relative],
                 "Candidate bundle file changed")
            actual.add(relative)
    need(actual == expected, "Candidate bundle is incomplete")
    return hashlib.sha256(manifest_raw).hexdigest()


def _hub_footprint() -> bool:
    return any(path.exists() or path.is_symlink() for path in (
        Path("/etc/sovagrid/deploy.env"), Path("/etc/sovagrid/admin-password"),
        Path("/etc/sovagrid-hub"), Path("/var/lib/sovagrid"),
        Path("/etc/systemd/system/sovagrid-vpn-status.timer")))


def _local_artifacts() -> bool:
    return any(path.exists() or path.is_symlink() for path in (
        LOCAL, LOCAL_UNIT, LOCAL_CONFIG, LOCAL_TOKEN, LOCAL_CA,
        LOCAL_SOURCE, LOCAL_ETC, LOCAL_DATA, LOCAL_OPERATIONS,
        LOCAL_OPERATIONS_PENDING, LOCAL_SHELL_HOME,
        *(Path("/etc/systemd/system") / name for name in LOCAL_TERMINAL_UNITS)))


def _operations_record() -> dict:
    need(not LOCAL_OPERATIONS_PENDING.exists() and not LOCAL_OPERATIONS_PENDING.is_symlink(),
         "Local operations change needs recovery")
    need(not LOCAL_OPERATIONS.is_symlink(), "Local operations state is unsafe")
    if not LOCAL_OPERATIONS.exists():
        return {"protocol": 1, "terminal": False, "files": False}
    value = _private_json(LOCAL_OPERATIONS)
    need(set(value) == {"protocol", "terminal", "files"} and
         type(value["protocol"]) is int and value["protocol"] == 1 and
         type(value["terminal"]) is bool and type(value["files"]) is bool,
         "Local operations state is invalid")
    return value


def _local_hub_ready() -> bool:
    ca_info = LOCAL_HUB_CA_STAGING.lstat()
    need(stat.S_ISREG(ca_info.st_mode) and ca_info.st_uid == ROOT_UID and
         ca_info.st_gid == 0 and stat.S_IMODE(ca_info.st_mode) == 0o600,
         "Local Hub CA staging file is unsafe")
    _read_regular(LOCAL_HUB_CA_STAGING, 16384)
    context = ssl.create_default_context(cafile=str(LOCAL_HUB_CA_STAGING))
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    with opener.open("https://localhost:8767/healthz", timeout=3) as response:
        return response.status == 200


def _local_record() -> str:
    saved = _private_json(LOCAL)
    operations = _operations_record()
    server_id = saved.get("server_id")
    digest = saved.get("token_sha256")
    need(set(saved) == {"protocol", "server_id", "token_sha256", "commands"} and
         type(saved["protocol"]) is int and saved["protocol"] == 1 and isinstance(server_id, str) and
         str(uuid.UUID(server_id)) == server_id and isinstance(digest, str) and
         HEX_SHA256.fullmatch(digest) is not None and type(saved["commands"]) is bool,
         "Local Agent journal is invalid")
    group = grp.getgrnam(LOCAL_USER)
    user = pwd.getpwnam(LOCAL_USER)
    external = pwd.getpwnam("sovagrid")
    external_group = grp.getgrnam("sovagrid")
    need(user.pw_uid != external.pw_uid and user.pw_gid == group.gr_gid and
         group.gr_gid != external_group.gr_gid and
         os.getgrouplist(LOCAL_USER, user.pw_gid) == [user.pw_gid],
         "Local Agent identity is unsafe")
    for path, uid, gid, mode in ((LOCAL_ETC, 0, group.gr_gid, 0o750),
                                 (LOCAL_DATA, user.pw_uid, group.gr_gid, 0o700)):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
             (uid, gid, mode), "Local Agent directory is unsafe")
    for path in (LOCAL_TOKEN, LOCAL_CONFIG, LOCAL_CA):
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
             (0, group.gr_gid, 0o640), "Local Agent file is unsafe")
    config = _read_regular(LOCAL_CONFIG, 8192)
    need(hashlib.sha256(_read_regular(LOCAL_TOKEN, 256).strip()).hexdigest() == digest and
         config in (_config_bytes(saved, operations=operations),
                    _config_bytes(saved, operations=operations, service_socket=True)) and
         _read_regular(LOCAL_CA, 16384) == _read_regular(LOCAL_HUB_CA_STAGING, 16384) and
         _read_regular(LOCAL_UNIT, 8192) == UNIT_TEXT.encode(),
         "Local Agent files changed")
    files, hashes = _agent_source_files()
    _verify_local_source(files, hashes)
    if operations["files"]:
        workspace = LOCAL_FILE_WORKSPACE.lstat()
        need(stat.S_ISDIR(workspace.st_mode) and
             (workspace.st_uid, workspace.st_gid, stat.S_IMODE(workspace.st_mode)) ==
             (user.pw_uid, group.gr_gid, 0o700), "Local file workspace is unsafe")
    if operations["terminal"]:
        shell = pwd.getpwnam(LOCAL_SHELL)
        shell_group = grp.getgrnam(LOCAL_SHELL)
        need(shell.pw_uid != 0 and shell.pw_uid not in (user.pw_uid, external.pw_uid) and
             shell.pw_gid == shell_group.gr_gid and shell.pw_dir == str(LOCAL_SHELL_HOME) and
             shell.pw_shell == "/usr/sbin/nologin" and
             os.getgrouplist(LOCAL_SHELL, shell.pw_gid) == [shell.pw_gid],
             "Local PTY shell identity is unsafe")
        shell_home = LOCAL_SHELL_HOME.lstat()
        need(stat.S_ISDIR(shell_home.st_mode) and
             (shell_home.st_uid, shell_home.st_gid, stat.S_IMODE(shell_home.st_mode)) ==
             (shell.pw_uid, shell_group.gr_gid, 0o700), "Local PTY shell home is unsafe")
        for name in LOCAL_TERMINAL_UNITS:
            unit = Path("/etc/systemd/system") / name
            source_unit = SOURCE / "sovagrid-agent/deploy" / name
            info = unit.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
                 stat.S_IMODE(info.st_mode) == 0o644 and
                 _read_regular(unit, 8192) == _read_regular(source_unit, 8192) and
                 _unit_active(name) and _unit_enabled(name),
                 "Local PTY broker unit is unsafe or inactive")
    elif any(_unit_active(name) or _unit_enabled(name) for name in LOCAL_TERMINAL_UNITS):
        raise PromotionError("Local PTY broker is active without permission")
    need(_unit_active(LOCAL_UNIT.name), "Local Agent service is inactive")
    return server_id


def inspect() -> dict:
    """Return a fixed, secret-free resume state without changing host files."""
    result = {"protocol": 1, "phase": "unknown", "external_agent_preserved": False,
              "baseline_sha256": None, "pinned_manifest_sha256": None,
              "source_manifest_sha256": None, "local_server_id": None,
              "reason_code": "UNSAFE_STATE"}
    if os.geteuid() != ROOT_UID:
        result["reason_code"] = "ROOT_REQUIRED"
        return result
    has_baseline = BASELINE.exists() or BASELINE.is_symlink()
    try:
        baseline = _private_json(BASELINE) if has_baseline else None
        if baseline is not None:
            result["baseline_sha256"] = hashlib.sha256(_read_regular(BASELINE, 32768)).hexdigest()
        result["pinned_manifest_sha256"] = _pin()
    except (OSError, ValueError, PromotionError, json.JSONDecodeError):
        result["reason_code"] = "BASELINE_INVALID"
        return result
    try:
        external = capture_external()
    except (OSError, ValueError, PromotionError, subprocess.SubprocessError):
        result["phase"] = "external_changed" if baseline is not None else "unknown"
        result["reason_code"] = "EXTERNAL_UNAVAILABLE"
        return result
    if baseline is not None and not _external_matches(external, baseline):
        result["phase"] = "external_changed"
        result["reason_code"] = "EXTERNAL_CHANGED"
        return result
    if AGENT_MARKER.exists() or AGENT_MARKER.is_symlink():
        result["reason_code"] = "EXTERNAL_ADOPTED"
        return result
    has_source = SOURCE.exists() or SOURCE.is_symlink()
    has_hub = MANAGED_MARKER.exists() or MANAGED_MARKER.is_symlink()
    if not has_baseline and (has_source or has_hub or _hub_footprint() or _local_artifacts() or PIN.exists()):
        result["reason_code"] = "UNOWNED_HUB_STATE"
        return result
    if not has_source:
        if has_hub or _hub_footprint() or _local_artifacts():
            return result
        result.update(phase="prepared" if baseline is not None else "eligible",
                      external_agent_preserved=True, reason_code=None)
        return result
    if baseline is None:
        return result
    try:
        result["source_manifest_sha256"] = _source_manifest_sha256()
    except (OSError, ValueError, PromotionError, json.JSONDecodeError):
        result["reason_code"] = "SOURCE_INVALID"
        return result
    if result["pinned_manifest_sha256"] != result["source_manifest_sha256"]:
        result["reason_code"] = "SOURCE_MISMATCH"
        return result
    if not has_hub:
        if _hub_footprint() or _local_artifacts():
            result["reason_code"] = "HUB_PARTIAL"
            return result
        result.update(phase="source_staged", external_agent_preserved=True, reason_code=None)
        return result
    try:
        info = MANAGED_MARKER.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and
             stat.S_IMODE(info.st_mode) == 0o600 and _local_hub_ready(),
             "Local Hub is incomplete")
    except (OSError, ValueError, PromotionError, ssl.SSLError):
        result["reason_code"] = "HUB_PARTIAL"
        return result
    if not LOCAL.exists() and not LOCAL.is_symlink():
        if _local_artifacts():
            result["reason_code"] = "LOCAL_PARTIAL"
            return result
        result.update(phase="hub_installed", external_agent_preserved=True, reason_code=None)
        return result
    try:
        result["local_server_id"] = _local_record()
    except (OSError, ValueError, KeyError, PromotionError, subprocess.SubprocessError):
        result["reason_code"] = "LOCAL_PARTIAL"
        return result
    result.update(phase="activated", external_agent_preserved=True, reason_code=None)
    return result


def _http(method: str, path: str, *, bearer: str | None = None, body: dict | None = None) -> tuple[int, dict]:
    need(path.startswith("/api/v1/") and "?" not in path and "#" not in path, "Invalid Hub API path")
    data = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if bearer is not None:
        headers["Authorization"] = "Bearer " + bearer
    message = Request("http://127.0.0.1:8766" + path, method=method, headers=headers, data=data)
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(message, timeout=10) as reply:
            return reply.status, json.loads(reply.read(16384))
    except HTTPError as exc:
        raise PromotionError(f"Local Hub API refused {method} {path}: HTTP {exc.code}") from None


def _with_admin(operation):
    # A host-root one-shot container mints a 60-second, single-use local Hub
    # grant. Neither an admin password nor the grant enters argv or a log.
    command = ["docker", "compose", "--env-file", "/etc/sovagrid/deploy.env", "-f",
               "/opt/sovagrid-src/sovagrid-blueprint/deploy/compose.yaml", "run", "--rm",
               "--no-deps", "-T", "--entrypoint", "python3", "hub", "-m",
               "sovagrid_hub", "--db", "/data/hub.sqlite", "ssh-grant"]
    issued = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, check=False, timeout=45)
    need(issued.returncode == 0 and 0 < len(issued.stdout) <= 512,
         "Local Hub could not issue a root SSH grant")
    grant = json.loads(issued.stdout)
    need(isinstance(grant, dict) and set(grant) == {"protocol", "grant", "expires_at", "username"}
         and grant["protocol"] == 1 and isinstance(grant["grant"], str)
         and re.fullmatch(r"[A-Za-z0-9_-]{43}", grant["grant"]) is not None,
         "Local Hub grant response is invalid")
    status, login = _http("POST", "/api/v1/session/ssh-grant", body={"grant": grant["grant"]})
    need(status == 200 and isinstance(login.get("token"), str), "Local admin grant failed")
    bearer = login["token"]
    try:
        return operation(bearer)
    finally:
        try:
            _http("DELETE", "/api/v1/session", bearer=bearer)
        except PromotionError:
            pass


def _write_group_file(path: Path, data: bytes, gid: int) -> None:
    need(not path.exists() and not path.is_symlink(), f"Destination already exists: {path}")
    temporary = path.parent / ("." + path.name + "." + secrets.token_hex(12))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchown(fd, 0, gid)
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _replace_group_file(path: Path, old: bytes, new: bytes, gid: int) -> None:
    need(_read_regular(path) == old, f"Owned file changed: {path}")
    info = path.lstat()
    need(info.st_gid == gid and stat.S_IMODE(info.st_mode) == 0o640,
         f"Owned file permissions changed: {path}")
    temporary = path.parent / ("." + path.name + "." + secrets.token_hex(12))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchown(fd, 0, gid)
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "wb") as stream:
            stream.write(new)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _agent_source_files() -> tuple[list[Path], dict]:
    manifest = json.loads(_read_regular(SOURCE / "sovagrid-bundle.json", 1024 * 1024))
    hashes = manifest.get("sha256")
    need(isinstance(hashes, dict), "Server source manifest is invalid")
    entries = sorted((SOURCE / "sovagrid-agent/sovagrid_agent").glob("*.py"))
    need(len(entries) >= 8, "Agent source is incomplete")
    files = entries + [SOURCE / "sovagrid-agent" / name for name in ("LICENSE", "ATTRIBUTION.md", "NOTICE")]
    for path in files:
        name = str(path.relative_to(SOURCE))
        need(hashlib.sha256(_read_regular(path)).hexdigest() == hashes.get(name),
             "Agent source does not match the pinned manifest")
    return files, hashes


def _verify_local_source(files: list[Path], hashes: dict) -> None:
    for directory in (LOCAL_SOURCE, LOCAL_SOURCE / "sovagrid_agent"):
        info = directory.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and
             stat.S_IMODE(info.st_mode) == 0o755, "Local Agent source directory changed")
    expected = {"sovagrid_agent"} | {p.name for p in files if p.suffix != ".py"}
    need({p.name for p in LOCAL_SOURCE.iterdir()} == expected,
         "Local Agent source has unexpected files")
    expected_python = {p.name for p in files if p.suffix == ".py"}
    need({p.name for p in (LOCAL_SOURCE / "sovagrid_agent").iterdir()} == expected_python,
         "Local Agent Python source has unexpected files")
    for original in files:
        name = str(original.relative_to(SOURCE))
        destination = (LOCAL_SOURCE / "sovagrid_agent" / original.name) if original.suffix == ".py" else LOCAL_SOURCE / original.name
        need(hashlib.sha256(_read_regular(destination)).hexdigest() == hashes[name],
             "Local Agent source no longer matches its bundle")


def _install_agent_source(files: list[Path], hashes: dict) -> None:
    need(not LOCAL_SOURCE.exists() and not LOCAL_SOURCE.is_symlink(), "Local Agent source already exists")
    temporary = LOCAL_SOURCE.parent / (".sovagrid-agent-local-" + secrets.token_hex(10))
    temporary.mkdir(mode=0o755)
    try:
        temporary.chmod(0o755)
        (temporary / "sovagrid_agent").mkdir(mode=0o755)
        (temporary / "sovagrid_agent").chmod(0o755)
        for path in files:
            destination = (temporary / "sovagrid_agent" / path.name) if path.suffix == ".py" else temporary / path.name
            shutil.copyfile(path, destination)
            destination.chmod(0o644)
        os.rename(temporary, LOCAL_SOURCE)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    _verify_local_source(files, hashes)


def _local_identity() -> tuple[int, int]:
    """Create a separate unprivileged identity without external Agent groups."""
    try:
        group = grp.getgrnam(LOCAL_USER)
    except KeyError:
        subprocess.run(["groupadd", "--system", LOCAL_USER], check=True, timeout=20)
        group = grp.getgrnam(LOCAL_USER)
    need(not group.gr_mem, "Local Agent group has unexpected members")
    try:
        user = pwd.getpwnam(LOCAL_USER)
    except KeyError:
        subprocess.run(["useradd", "--system", "--gid", LOCAL_USER, "--home-dir",
                        str(LOCAL_DATA), "--shell", "/usr/sbin/nologin", LOCAL_USER],
                       check=True, timeout=20)
        user = pwd.getpwnam(LOCAL_USER)
    need(user.pw_uid != 0 and user.pw_gid == group.gr_gid and
         user.pw_dir == str(LOCAL_DATA) and user.pw_shell == "/usr/sbin/nologin" and
         os.getgrouplist(LOCAL_USER, user.pw_gid) == [user.pw_gid],
         "Local Agent account is not isolated")
    external_user = pwd.getpwnam("sovagrid")
    external_group = grp.getgrnam("sovagrid")
    need(user.pw_uid != external_user.pw_uid and group.gr_gid != external_group.gr_gid,
         "Local Agent reused the external Agent UID or GID")
    return user.pw_uid, group.gr_gid


def _local_directory(path: Path, *, uid: int, gid: int, mode: int) -> None:
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=mode)
        os.chown(path, uid, gid)
        path.chmod(mode)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and
         info.st_gid == gid and stat.S_IMODE(info.st_mode) == mode,
         f"Local Agent directory is unsafe: {path}")


def _ensure_local_private_paths() -> int:
    uid, gid = _local_identity()
    _local_directory(LOCAL_ETC, uid=0, gid=gid, mode=0o750)
    _local_directory(LOCAL_DATA, uid=uid, gid=gid, mode=0o700)
    ca_info = LOCAL_HUB_CA_STAGING.lstat()
    need(ca_info.st_gid == 0 and stat.S_IMODE(ca_info.st_mode) == 0o600,
         "Local Hub CA staging file is unsafe")
    local_ca = _read_regular(LOCAL_HUB_CA_STAGING, 16384)
    if LOCAL_CA.exists() or LOCAL_CA.is_symlink():
        info = LOCAL_CA.lstat()
        need(info.st_gid == gid and stat.S_IMODE(info.st_mode) == 0o640 and
             _read_regular(LOCAL_CA, 16384) == local_ca,
             "Local Hub CA copy is unsafe or changed")
    else:
        _write_group_file(LOCAL_CA, local_ca, gid)
    return gid


def _ensure_local_record() -> dict:
    need(not LOCAL.is_symlink(), "Local Agent journal is unsafe")
    if LOCAL.exists():
        saved = _private_json(LOCAL)
        server_id = saved.get("server_id")
        digest = saved.get("token_sha256")
        need(isinstance(server_id, str) and str(uuid.UUID(server_id)) == server_id and
             isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest),
             "Local Agent journal is invalid")
        token_info = LOCAL_TOKEN.lstat()
        need(token_info.st_gid == grp.getgrnam(LOCAL_USER).gr_gid and
             stat.S_IMODE(token_info.st_mode) == 0o640,
             "Local Agent token permissions changed")
        need(hashlib.sha256(_read_regular(LOCAL_TOKEN, 256).strip()).hexdigest() == digest,
             "Local Agent token changed")
        return saved
    need(not LOCAL_TOKEN.exists() and not LOCAL_CONFIG.exists() and not LOCAL_UNIT.exists(),
         "Unowned local Agent files already exist")
    status, created = _with_admin(lambda bearer: _http(
        "POST", "/api/v1/servers", bearer=bearer, body={"name": "Local " + os.uname().nodename[:60]}))
    need(status == 201 and isinstance(created.get("id"), str) and
         isinstance(created.get("agent_token"), str), "Local server registration failed")
    server_id = str(uuid.UUID(created["id"]))
    need(server_id == created["id"], "Local server ID is invalid")
    token = created["agent_token"]
    need(re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is not None, "Local Agent token is invalid")
    gid = grp.getgrnam(LOCAL_USER).gr_gid
    _write_group_file(LOCAL_TOKEN, (token + "\n").encode(), gid)
    saved = {"protocol": 1, "server_id": server_id,
             "token_sha256": hashlib.sha256(token.encode()).hexdigest(), "commands": False}
    _save_private(LOCAL, saved)
    return saved


def _config_bytes(saved: dict, *, operations: dict | None = None,
                  service_socket: bool = False) -> bytes:
    operations = _operations_record() if operations is None else operations
    value = {"hub_url": "https://localhost:8767", "server_id": saved["server_id"],
             "token_file": str(LOCAL_TOKEN), "ca_file": str(LOCAL_CA),
             "interval_seconds": 30, "allow_remote_commands": bool(saved["commands"]),
             "allow_interactive_terminal": bool(operations["terminal"]),
             "allow_file_manager": bool(operations["files"])}
    if operations["terminal"]:
        value["terminal_socket"] = LOCAL_TERMINAL_SOCKET
    if operations["files"]:
        value["file_roots"] = {"workspace": str(LOCAL_FILE_WORKSPACE)}
    if service_socket:
        value["service_socket"] = LOCAL_SERVICE_SOCKET
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _config_service_socket(raw: bytes, saved: dict, *, operations: dict | None = None) -> bool:
    """Accept only the two exact local-Agent config forms we own."""
    if raw == _config_bytes(saved, operations=operations):
        return False
    if raw == _config_bytes(saved, operations=operations, service_socket=True):
        return True
    raise PromotionError("Local Agent config changed")


def _service_setup_lock(timeout: float = 30) -> int:
    """Serialize local config writes with the root service broker setup."""
    need(os.geteuid() == 0 and not SERVICE_SETUP_LOCK.is_symlink(), "Service setup lock is unsafe")
    fd = os.open(SERVICE_SETUP_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid,
             stat.S_IMODE(info.st_mode), info.st_nlink) == (0, 0, 0o600, 1),
             "Service setup lock is unsafe")
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except BlockingIOError:
                need(time.monotonic() < deadline, "Service setup is busy")
                time.sleep(0.1)
    except BaseException:
        os.close(fd)
        raise


def _write_config(saved: dict, *, commands_pending: bool = False) -> None:
    data = _config_bytes(saved)
    if LOCAL_CONFIG.exists():
        current = _read_regular(LOCAL_CONFIG)
        if current not in (data, _config_bytes(saved, service_socket=True)):
            need(commands_pending and not saved["commands"] and
                 current in (_config_bytes({**saved, "commands": True}),
                             _config_bytes({**saved, "commands": True}, service_socket=True)),
                 "Local Agent config changed")
    else:
        _write_group_file(LOCAL_CONFIG, data, grp.getgrnam(LOCAL_USER).gr_gid)


def _wait_local_metric(server_id: str, timeout: float = 100, *, since: int = 0) -> None:
    def wait(bearer):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                status, data = _http("GET", "/api/v1/servers", bearer=bearer)
                servers = data.get("servers", []) if status == 200 else []
                if any(item.get("id") == server_id and item.get("online") is True and
                       isinstance(item.get("last_seen"), int) and item["last_seen"] >= since
                       for item in servers):
                    return
            except PromotionError:
                pass
            time.sleep(5)
        raise PromotionError("Local Agent did not report a fresh metric")
    _with_admin(wait)


def activate(*, enable_commands: bool = False) -> dict:
    need(BASELINE.exists() and not BASELINE.is_symlink(), "Run prepare before installing the local Hub")
    need(_external_matches(capture_external(), _private_json(BASELINE)),
         "External Agent or SSH tunnel changed")
    info = MANAGED_MARKER.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and
         stat.S_IMODE(info.st_mode) == 0o600,
         "Local Hub is not managed by run.sh")
    source_info = SOURCE.lstat()
    need(stat.S_ISDIR(source_info.st_mode) and source_info.st_uid == ROOT_UID and
         not source_info.st_mode & 0o022 and (SOURCE / "sovagrid-bundle.json").is_file(),
         "Local Hub source is missing or unsafe")
    source_digest = _source_manifest_sha256()
    pinned_digest = _pin()
    need(pinned_digest is None or pinned_digest == source_digest,
         "Local Hub source differs from the prepared package")
    need(not AGENT_MARKER.exists() and not AGENT_MARKER.is_symlink(),
         "The external Agent was unexpectedly adopted by run.sh")
    lock = _service_setup_lock()
    try:
        return _activate_local(enable_commands=enable_commands)
    finally:
        os.close(lock)


def _activate_local(*, enable_commands: bool) -> dict:
    # An authenticated local API call below confirms the running Hub.
    local_gid = _ensure_local_private_paths()
    saved = _ensure_local_record()
    files, hashes = _agent_source_files()
    if not LOCAL_SOURCE.exists():
        _install_agent_source(files, hashes)
    else:
        _verify_local_source(files, hashes)
    _write_config(saved, commands_pending=enable_commands)
    if LOCAL_UNIT.exists():
        need(_read_regular(LOCAL_UNIT) == UNIT_TEXT.encode(), "Local Agent unit changed")
    else:
        _write_group_file(LOCAL_UNIT, UNIT_TEXT.encode(), 0)
        LOCAL_UNIT.chmod(0o644)
    subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=30)
    subprocess.run(["systemctl", "enable", "--now", LOCAL_UNIT.name], check=True, timeout=40)
    _wait_local_metric(saved["server_id"])
    if enable_commands and not saved["commands"]:
        def gate(bearer):
            return _http("POST", f"/api/v1/servers/{saved['server_id']}/commands",
                         bearer=bearer, body={"enabled": True})
        status, result = _with_admin(gate)
        need(status == 200 and result.get("remote_commands_enabled") is True,
             "Local commands gate was not enabled")
        current = {**saved, "commands": True}
        raw = _read_regular(LOCAL_CONFIG)
        try:
            service_socket = _config_service_socket(raw, saved)
        except PromotionError:
            service_socket = _config_service_socket(raw, current)
        old = _config_bytes(saved, service_socket=service_socket)
        new = _config_bytes(current, service_socket=service_socket)
        if raw == old:
            _replace_group_file(LOCAL_CONFIG, old, new, local_gid)
        restarted_at = int(time.time())
        subprocess.run(["systemctl", "restart", LOCAL_UNIT.name], check=True, timeout=40)
        _wait_local_metric(saved["server_id"], since=restarted_at)
        saved = current
        _save_private(LOCAL, saved)
    need(_external_matches(capture_external(), _private_json(BASELINE)),
         "External Agent or SSH tunnel changed")
    return {"protocol": 1, "activated": True, "local_server_id": saved["server_id"],
            "local_commands": saved["commands"], "external_agent_preserved": True}


def main(argv: list[str]) -> int:
    os.umask(0o077)
    if argv == ["inspect"]:
        result = inspect()
    elif argv == ["prepare"]:
        result = prepare()
    elif len(argv) == 3 and argv[:2] == ["prepare", "--manifest-sha256"]:
        result = prepare(manifest_sha256=argv[2])
    elif argv == ["activate"]:
        result = activate()
    elif argv == ["activate", "--enable-commands"]:
        result = activate(enable_commands=True)
    else:
        raise PromotionError("Usage: promote_agent_only.py inspect | prepare [--manifest-sha256 SHA256] | activate [--enable-commands]")
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, subprocess.SubprocessError, PromotionError) as exc:
        print(f"SovaGrid promotion refused: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
