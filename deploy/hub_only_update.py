#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Transactional update of a promoted Hub without adopting its external Agent.

This is a separate host-root worker. It accepts only an already staged,
content-addressed server bundle and a pinned current manifest. The external
Agent, its enrollment, data and SSH tunnels are read to enforce invariants;
they are never in the mutable snapshot or restarted by this worker.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import sqlite3
import ssl
import stat
import subprocess
import sys
import time
import urllib.request
import uuid

# A first update may execute this helper directly from an immutable staged
# candidate. Dynamic imports must not create __pycache__ beside signed files.
sys.dont_write_bytecode = True


ROOT = Path("/")
SOURCE = Path("/opt/sovagrid-src")
CANDIDATES = Path("/opt/sovagrid-candidates")
TRANSACTIONS = CANDIDATES / "hub-only-transactions"
PROMOTION_LOCK = Path("/run/sovagrid-promotion.lock")
SYSTEMD = Path("/etc/systemd/system")
MAX_BACKUP = 4 * 1024**3
SHA = re.compile(r"[0-9a-f]{64}\Z")
TRANSACTION_NAME = re.compile(r"[0-9]{17,25}-[0-9a-f]{12}\Z")
WEB_AGENT_MARKER = "/var/lib/sovagrid/.web-agent-installer-managed-by-run-sh"
WEB_AGENT_DIR = "/var/lib/sovagrid/web-agent"
WEB_AGENT_UNITS = ("sovagrid-web-agent-control.socket",
                   "sovagrid-web-agent-control.service")
EXTERNAL_APPLY_MARKER = "/etc/sovagrid/.external-agent-apply-managed-by-run-sh"
EXTERNAL_APPLY_UNIT = "/etc/systemd/system/sovagrid-external-agent-apply@.service"
EXTERNAL_APPLY_LEDGER = "/var/lib/sovagrid/external-agent-operations"

# These paths belong to the local Hub, including its private Web Agent job
# journal. External Agent data and SSH transport remain outside this snapshot.
# New run.sh features need reviewed snapshot expansion before acceptance.
LEGACY_SNAPSHOT = (
    "/opt/sovagrid-agent-local",
    "/opt/sovagrid-vpn",
    "/etc/sovagrid-local",
    "/var/lib/sovagrid-agent-local",
    "/var/lib/sovagrid/hub",
    "/var/lib/sovagrid/caddy",
    "/var/lib/sovagrid/vpn",
    "/var/lib/sovagrid/local-hub-ca.pem",
    "/var/lib/sovagrid/hub-only-update-status.json",
    "/var/lib/sovagrid/.managed-by-run-sh",
    "/etc/sovagrid/deploy.env",
    "/etc/sovagrid/admin-password",
    "/etc/sovagrid/.vpn-unit-managed-by-run-sh",
    "/etc/sovagrid-hub",
    "/var/lib/sovagrid-promotion/bundle-pin.json",
    "/var/lib/sovagrid-promotion/local-agent.json",
    "/var/lib/sovagrid-promotion/local-operations.json",
    "/var/lib/sovagrid-promotion/local-operations-pending.json",
    "/var/lib/sovagrid-local-shell",
    "/etc/systemd/system/sovagrid-agent-local.service",
    "/etc/systemd/system/sovagrid-terminal-local-control.socket",
    "/etc/systemd/system/sovagrid-terminal-local-control.service",
    "/etc/systemd/system/sovagrid-vpn-status.service",
    "/etc/systemd/system/sovagrid-vpn-status.timer",
    "/etc/systemd/system/sovagrid-hub-only-update.service",
    "/etc/systemd/system/sovagrid-hub-only-update.timer",
)
RELEASE_FEED_SNAPSHOT = LEGACY_SNAPSHOT + (
    "/etc/sovagrid/release-feed.json",
    "/var/lib/sovagrid/.release-feed-units-managed-by-run-sh",
    "/var/lib/sovagrid/release-feed-state.json",
    "/etc/systemd/system/sovagrid-release-feed.service",
    "/etc/systemd/system/sovagrid-release-feed.timer",
)
SERVICE_SNAPSHOT = RELEASE_FEED_SNAPSHOT + (
    "/etc/sovagrid-service-local",
    "/etc/systemd/system/sovagrid-service-local-control.socket",
    "/etc/systemd/system/sovagrid-service-local-control.service",
)
ROUTING_SNAPSHOT = SERVICE_SNAPSHOT + (
    "/etc/sovagrid-vpn-routing/policy.json",
    "/etc/sysctl.d/70-sovagrid-vpn-routing.conf",
    "/etc/systemd/system/sovagrid-vpn-routing.service",
)
HUB_BACKUP_SNAPSHOT = ROUTING_SNAPSHOT + (
    "/var/lib/sovagrid/.hub-backup-broker-managed-by-run-sh",
    "/var/lib/sovagrid/backups/.broker-requests",
    "/etc/systemd/system/sovagrid-hub-backup-control.socket",
    "/etc/systemd/system/sovagrid-hub-backup-control.service",
)
SSH_GATEWAY_SNAPSHOT = HUB_BACKUP_SNAPSHOT + (
    "/var/lib/sovagrid/.ssh-gateway-managed-by-run-sh",
)
LOCAL_WEB_SNAPSHOT = SSH_GATEWAY_SNAPSHOT + ("/etc/sovagrid/local-web",)
LOCAL_CONTAINERS_SNAPSHOT = LOCAL_WEB_SNAPSHOT + (
    "/var/lib/sovagrid-promotion/local-container-inventory.json",
    "/var/lib/sovagrid-promotion/local-container-inventory-pending.json",
    "/var/lib/sovagrid-containers-local",
    "/etc/systemd/system/sovagrid-container-inventory-local.service",
    "/etc/systemd/system/sovagrid-container-inventory-local.timer",
)
WEB_AGENT_SNAPSHOT = LOCAL_CONTAINERS_SNAPSHOT + (
    WEB_AGENT_MARKER,
    WEB_AGENT_DIR,
    *(f"/etc/systemd/system/{unit}" for unit in WEB_AGENT_UNITS),
    "/etc/sovagrid/.external-agent-recovery-managed-by-run-sh",
    "/etc/systemd/system/sovagrid-external-agent-recovery.service",
)
SNAPSHOT = WEB_AGENT_SNAPSHOT + (
    EXTERNAL_APPLY_MARKER, EXTERNAL_APPLY_UNIT, EXTERNAL_APPLY_LEDGER,
)
LEGACY_UNITS = ("sovagrid-agent-local.service", "sovagrid-terminal-local-control.socket",
         "sovagrid-terminal-local-control.service", "sovagrid-vpn-status.service",
         "sovagrid-vpn-status.timer",
         "sovagrid-hub-only-update.timer")
RELEASE_FEED_UNITS = LEGACY_UNITS + ("sovagrid-release-feed.timer",)
SERVICE_ALL_UNITS = RELEASE_FEED_UNITS + ("sovagrid-service-local-control.socket",
                                          "sovagrid-service-local-control.service")
ROUTING_UNIT = "sovagrid-vpn-routing.service"
ROUTING_ALL_UNITS = SERVICE_ALL_UNITS + (ROUTING_UNIT,)
BACKUP_BROKER_UNITS = ("sovagrid-hub-backup-control.socket",
                       "sovagrid-hub-backup-control.service")
LOCAL_WEB_UNITS = ROUTING_ALL_UNITS + BACKUP_BROKER_UNITS
LOCAL_CONTAINER_UNITS = ("sovagrid-container-inventory-local.service",
                         "sovagrid-container-inventory-local.timer")
LOCAL_CONTAINERS_ALL_UNITS = LOCAL_WEB_UNITS + LOCAL_CONTAINER_UNITS
UNITS = LOCAL_CONTAINERS_ALL_UNITS + WEB_AGENT_UNITS
LOCAL_SERVICE_UNITS = ("sovagrid-service-local-control.socket",
                       "sovagrid-service-local-control.service")
REQUIRED_CANDIDATE = (
    "sovagrid-blueprint/deploy/promote_agent_only.py",
    "sovagrid-blueprint/deploy/hub_only_update.py",
    "sovagrid-blueprint/deploy/hub_only_auto_update.py",
    "sovagrid-blueprint/deploy/local_operations.py",
    "sovagrid-blueprint/deploy/local_container_inventory.py",
    "sovagrid-blueprint/deploy/sovagrid-hub-only-update.service",
    "sovagrid-blueprint/deploy/sovagrid-hub-only-update.timer",
    "sovagrid-blueprint/deploy/remote_update_worker.py",
    "sovagrid-blueprint/deploy/release_feed.py",
    "sovagrid-blueprint/deploy/sovagrid-release-feed.service",
    "sovagrid-blueprint/deploy/sovagrid-release-feed.timer",
    "sovagrid-blueprint/run.sh",
)
FORBIDDEN_MARKERS = (
    "/etc/sovagrid/.agent-unit-managed-by-run-sh",
    "/etc/sovagrid/.vpn-control-managed-by-run-sh",
    "/etc/sovagrid/.terminal-unit-managed-by-run-sh",
    "/etc/sovagrid/.journal-managed-by-run-sh",
    "/etc/sovagrid/.containers-managed-by-run-sh",
    "/etc/sovagrid/public-web",
    "/etc/sovagrid-hub/bot.token",
)


def _module(name: str, filename: str):
    file = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, file)
    if spec is None or spec.loader is None:
        raise RuntimeError("missing installed update dependency")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


common = _module("sovagrid_common_update", "remote_update_worker.py")
promotion = _module("sovagrid_promotion_update", "promote_agent_only.py")
local_inventory = _module("sovagrid_local_inventory_update", "local_container_inventory.py")


class Refused(Exception):
    pass


def need(ok: bool, code: str) -> None:
    if not ok:
        raise Refused(code)


def emit(value: str) -> None:
    print(value, flush=True)


def _hash_file(file: Path) -> str:
    return hashlib.sha256(promotion._read_regular(file, 32768)).hexdigest()


def _external() -> str:
    baseline = promotion._private_json(promotion.BASELINE)
    need(promotion.capture_external() == baseline, "EXTERNAL_CHANGED")
    return _hash_file(promotion.BASELINE)


def _unit_state(unit: str) -> dict:
    return {
        "active": common.command(["systemctl", "is-active", "--quiet", unit], timeout=10,
                                 check=False) == 0,
        "enabled": common.command(["systemctl", "is-enabled", "--quiet", unit], timeout=10,
                                  check=False) == 0,
    }


def _external_runtime() -> dict[str, dict]:
    result = {}
    for unit in promotion.UNITS:
        status = _unit_state(unit)
        pid = subprocess.run(["systemctl", "show", "-P", "MainPID", unit],
                             capture_output=True, text=True, timeout=10, check=True).stdout.strip()
        need(pid.isdecimal(), "EXTERNAL_RUNTIME")
        current_pid = int(pid)
        # Every active external Agent/SSH unit must still have a running main
        # process. A zero PID with "active" is insufficient for a tunnel.
        need(not status["active"] or current_pid > 1, "EXTERNAL_RUNTIME")
        result[unit] = {**status, "pid": current_pid}
    return result


def _external_apply_idle() -> None:
    """An independent Agent writer cannot overlap a local Hub source swap."""
    def active_state(name: str) -> str:
        try:
            result = subprocess.run(
                ["systemctl", "show", "-P", "ActiveState", name],
                capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Refused("EXTERNAL_APPLY_BUSY") from None
        need(result.returncode == 0 and result.stdout.strip() in
             ("inactive", "failed", "active", "activating", "deactivating", "reloading"),
             "EXTERNAL_APPLY_BUSY")
        return result.stdout.strip()

    marker, unit, ledger = (Path(EXTERNAL_APPLY_MARKER), Path(EXTERNAL_APPLY_UNIT),
                            Path(EXTERNAL_APPLY_LEDGER))
    if not marker.exists() and not marker.is_symlink():
        need(not any(item.exists() or item.is_symlink() for item in (unit, ledger)),
             "EXTERNAL_APPLY_STATE")
        return
    need(common.public_path(str(marker), private=True, limit=128) ==
         b"SOVAGRID_EXTERNAL_AGENT_APPLY_UNIT_V1\n", "EXTERNAL_APPLY_STATE")
    common.public_path(str(unit), limit=8192)
    _private_dir(ledger)
    need(active_state("sovagrid-external-agent-recovery.service") == "inactive",
         "EXTERNAL_APPLY_BUSY")
    entries = list(ledger.iterdir())
    need(len(entries) <= 129, "EXTERNAL_APPLY_STATE")
    for item in entries:
        if item.name == ".lock":
            info = item.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
                 stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
                 info.st_size == 0, "EXTERNAL_APPLY_STATE")
            continue
        try:
            request_id = str(uuid.UUID(item.name))
        except (ValueError, AttributeError):
            raise Refused("EXTERNAL_APPLY_STATE") from None
        need(request_id == item.name, "EXTERNAL_APPLY_STATE")
        _private_dir(item)
        try:
            raw = common.public_path(str(item / "status.json"), private=True, limit=1024)
            status = json.loads(raw)
        except (OSError, ValueError):
            raise Refused("EXTERNAL_APPLY_STATE") from None
        need(isinstance(status, dict) and set(status) == {
             "format", "request_id", "phase", "created_at", "updated_at", "error"} and
             raw == (json.dumps(status, sort_keys=True, separators=(",", ":")) + "\n").encode() and
             type(status["format"]) is int and status["format"] == 1 and
             status["request_id"] == request_id and
             status["phase"] in ("complete", "failed") and
             type(status["created_at"]) is int and
             type(status["updated_at"]) is int and
             1 <= status["created_at"] <= status["updated_at"] <= 253402300799 and
             (status["error"] is None if status["phase"] == "complete" else
              isinstance(status["error"], str) and
              re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", status["error"]) is not None),
             "EXTERNAL_APPLY_BUSY")
        need(active_state("sovagrid-external-agent-apply@" + request_id + ".service")
             in ("inactive", "failed"), "EXTERNAL_APPLY_BUSY")


def _check_external_runtime(expected: dict[str, dict]) -> None:
    """Require the same unit policy and liveness, allowing independent restarts.

    The external processes belong to a different installation and can restart
    themselves while a local Hub update is running. Their pinned unit/config
    files are checked separately by inspect() against the promotion baseline.
    """
    current = _external_runtime()
    need(set(current) == set(expected), "EXTERNAL_RUNTIME")
    for unit in promotion.UNITS:
        before, after = expected[unit], current[unit]
        need((before["active"], before["enabled"]) ==
             (after["active"], after["enabled"]), "EXTERNAL_RUNTIME")
        if before["pid"] != after["pid"]:
            emit("SG_HUB_ONLY_EXTERNAL_PID_CHANGED:" + unit)


def _container_health() -> None:
    for service in common.compose_services():
        result = subprocess.run(
            ["docker", "ps", "--filter", "label=com.docker.compose.project=sovagrid",
             "--filter", "label=com.docker.compose.service=" + service, "--format", "{{.ID}}"],
            capture_output=True, text=True, timeout=10, check=True,
        )
        ids = result.stdout.splitlines()
        need(len(ids) == 1, "HUB_UNHEALTHY")
        image = subprocess.run(["docker", "inspect", "--format", "{{.Image}}", ids[0]],
                               capture_output=True, text=True, timeout=10, check=True).stdout.strip()
        expected = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}",
                                   "sovagrid-" + service + ":local"], capture_output=True,
                                  text=True, timeout=10, check=True).stdout.strip()
        need(image == expected, "HUB_UNHEALTHY")
        if service in ("hub", common.SSH_GATEWAY_SERVICE):
            state = subprocess.run(["docker", "inspect", "--format", "{{.State.Health.Status}}", ids[0]],
                                   capture_output=True, text=True, timeout=10, check=True).stdout.strip()
            need(state == "healthy", "HUB_UNHEALTHY")
    if common.SSH_GATEWAY_SERVICE not in common.compose_services():
        stray = subprocess.run(
            ["docker", "ps", "--filter", "label=com.docker.compose.project=sovagrid",
             "--filter", "label=com.docker.compose.service=" + common.SSH_GATEWAY_SERVICE,
             "--format", "{{.ID}}"], capture_output=True, text=True,
            timeout=10, check=True).stdout.strip()
        need(not stray, "HUB_UNHEALTHY")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open("http://127.0.0.1:8766/healthz", timeout=5) as response:
        need(response.status == 200, "HUB_UNHEALTHY")
    if common.SSH_GATEWAY_SERVICE in common.compose_services():
        common.browser_ssh_route_health()
    context = ssl.create_default_context(cafile=str(promotion.LOCAL_HUB_CA_STAGING))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    with opener.open("https://localhost:8767/healthz", timeout=5) as response:
        need(response.status == 200, "HUB_UNHEALTHY")
    inventory = Path("/var/lib/sovagrid/vpn/status.json")
    need(inventory.is_file() and not inventory.is_symlink(), "VPN_INVENTORY")


def inspect() -> tuple[str, dict, dict[str, str], str]:
    need(os.geteuid() == 0, "ROOT")
    release = Path("/etc/os-release").read_text()
    need(re.search(r"(?m)^ID=ubuntu$", release) is not None, "UBUNTU")
    external_recovery_dependency = Path(
        "/etc/systemd/system/sovagrid-agent.service.requires/"
        "sovagrid-external-agent-recovery.service")
    need(not external_recovery_dependency.exists() and
         not external_recovery_dependency.is_symlink(),
         "EXTERNAL_AGENT_RECOVERY_PENDING")
    if common.managed_routing_enabled():
        need(_unit_state(ROUTING_UNIT)["active"], "ROUTING")
    for marker in FORBIDDEN_MARKERS:
        item = Path(marker)
        need(not item.exists() and not item.is_symlink(), "UNSUPPORTED_FEATURE")
    feed_marker = Path("/var/lib/sovagrid/.release-feed-units-managed-by-run-sh")
    feed_config = Path("/etc/sovagrid/release-feed.json")
    feed_state = Path("/var/lib/sovagrid/release-feed-state.json")
    feed_units = (Path("/etc/systemd/system/sovagrid-release-feed.service"),
                  Path("/etc/systemd/system/sovagrid-release-feed.timer"))
    if feed_marker.exists() or feed_marker.is_symlink():
        need(common.public_path(str(feed_marker), private=True, limit=128) ==
             b"SOVAGRID_RELEASE_FEED_UNITS_V1\n", "FEED_STATE")
        for unit in feed_units:
            common.public_path(str(unit), limit=8192)
        if feed_config.exists() or feed_config.is_symlink():
            common.public_path(str(feed_config), private=True)
            need(_unit_state("sovagrid-release-feed.timer")["active"], "FEED_TIMER")
        if feed_state.exists() or feed_state.is_symlink():
            common.public_path(str(feed_state), private=True)
    else:
        need(not any(item.exists() or item.is_symlink() for item in
                     (feed_config, feed_state, *feed_units)), "FEED_STATE")
    if common.backup_broker_enabled():
        need(_unit_state(BACKUP_BROKER_UNITS[0])["active"], "BACKUP_BROKER")
        common.backup_broker_socket_ready()
    if common.web_agent_managed():
        need(all(_unit_state(unit)["active"] for unit in WEB_AGENT_UNITS), "WEB_AGENT")
        common.web_agent_socket_ready()
    _external_apply_idle()
    state = promotion.inspect()
    need(state.get("phase") == "activated" and state.get("external_agent_preserved") is True,
         "PROMOTION_STATE")
    manifest, commits = common.source_manifest(SOURCE, allow_generated=True)
    need(manifest == state.get("source_manifest_sha256") == state.get("pinned_manifest_sha256"),
         "PROMOTION_PIN")
    need(_external() == state["baseline_sha256"], "EXTERNAL_CHANGED")
    for unit in ("sovagrid-agent-local.service", "sovagrid-vpn-status.timer"):
        need(_unit_state(unit)["active"], "LOCAL_SERVICE")
    _container_health()
    local = promotion._private_json(promotion.LOCAL)
    uri = "file:/var/lib/sovagrid/hub/hub.sqlite?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=2) as db:
        db.execute("PRAGMA query_only=ON")
        row = db.execute("SELECT remote_commands_enabled FROM servers WHERE id=?",
                         (state["local_server_id"],)).fetchone()
    need(row is not None and row[0] in (0, 1) and
         bool(row[0]) == local["commands"], "LOCAL_COMMANDS_GATE")
    return manifest, state, commits, _hash_file(promotion.BASELINE)


def _candidate(archive_sha: str, old_commits: dict[str, str]):
    need(SHA.fullmatch(archive_sha) is not None, "HASH")
    need(CANDIDATES.stat().st_dev == SOURCE.stat().st_dev, "FILESYSTEM")
    source, commits = common.candidate_source(archive_sha)
    need(commits != old_commits, "SAME_VERSION")
    for name in REQUIRED_CANDIDATE:
        need((source / name).is_file(), "CANDIDATE_INCOMPATIBLE")
    script = (source / "sovagrid-blueprint/run.sh").read_bytes()
    need(b"--hub-only" in script and b"local-hub-ca.pem" in script,
         "CANDIDATE_INCOMPATIBLE")
    if Path("/var/lib/sovagrid/.release-feed-units-managed-by-run-sh").is_file():
        need(b"# SOVAGRID_RELEASE_FEED_UNITS_V1" in script,
             "CANDIDATE_INCOMPATIBLE")
    if common.backup_broker_enabled():
        need(b"# SOVAGRID_HUB_BACKUP_BROKER_V1" in script,
             "CANDIDATE_INCOMPATIBLE")
        for name in ("sovagrid-blueprint/deploy/compose.backup.yaml",
                     "sovagrid-blueprint/deploy/sovagrid-hub-backup-control.socket",
                     "sovagrid-blueprint/deploy/sovagrid-hub-backup-control.service",
                     "sovagrid-hub/sovagrid_hub/backup_broker.py"):
            need((source / name).is_file(), "CANDIDATE_INCOMPATIBLE")
    if Path(EXTERNAL_APPLY_MARKER).is_file():
        need(b"# SOVAGRID_EXTERNAL_AGENT_APPLY_UNIT_V1" in script,
             "CANDIDATE_INCOMPATIBLE")
        for name in ("sovagrid-blueprint/deploy/external_agent_operation.py",
                     "sovagrid-blueprint/deploy/sovagrid-external-agent-apply@.service"):
            need((source / name).is_file(), "CANDIDATE_INCOMPATIBLE")
    if common.web_agent_managed():
        need(b"# SOVAGRID_WEB_AGENT_INSTALL_V1" in script,
             "CANDIDATE_INCOMPATIBLE")
        for name in ("compose.web-agent.yaml", "web_agent_bundle.py",
                     "web_agent_jobs.py", "web_agent_service.py",
                     "web_wireguard_control.py", "web_amnezia_provision.py",
                     *WEB_AGENT_UNITS):
            need((source / "sovagrid-blueprint/deploy" / name).is_file(),
                 "CANDIDATE_INCOMPATIBLE")
        for name in ("deploy/sovagrid-amnezia-provision",
                     "sovagrid_vpn/amnezia_provision.py"):
            need((source / "sovagrid-vpn" / name).is_file(),
                 "CANDIDATE_INCOMPATIBLE")
    if common.ssh_gateway_managed():
        need(b"# SOVAGRID_SSH_GATEWAY_INSTALL_V1" in script,
             "CANDIDATE_INCOMPATIBLE")
        need(b"# SOVAGRID_PUBLIC_SSH_REFRESH_V1" in script,
             "CANDIDATE_INCOMPATIBLE")
        for name in ("sovagrid-web/Dockerfile.ssh-gateway",
                     "sovagrid-web/gateway/package.json",
                     "sovagrid-web/gateway/package-lock.json",
                     "sovagrid-web/gateway/server.js"):
            need((source / name).is_file(), "CANDIDATE_INCOMPATIBLE")
        need(b"/api/v1/browser-ssh/" in
             (source / "sovagrid-web/deploy/Caddyfile.container").read_bytes(),
             "CANDIDATE_INCOMPATIBLE")
    if Path("/etc/sovagrid/local-web").exists() or Path("/etc/sovagrid/local-web").is_symlink():
        common.local_web_overlay()
        need(b"# SOVAGRID_LOCAL_WEB_V1" in script, "CANDIDATE_INCOMPATIBLE")
        for name in ("sovagrid-blueprint/deploy/local_web.py",
                     "sovagrid-blueprint/deploy/compose.local-web.template"):
            need((source / name).is_file(), "CANDIDATE_INCOMPATIBLE")
        need(b"import /etc/caddy/local/*.caddy" in
             (source / "sovagrid-web/deploy/Caddyfile.container").read_bytes(),
             "CANDIDATE_INCOMPATIBLE")
    if common.managed_routing_enabled():
        need((source / "sovagrid-vpn/sovagrid_vpn/routing.py").is_file(),
             "CANDIDATE_INCOMPATIBLE")
    operations = promotion._operations_record()
    if operations["files"]:
        need((source / "sovagrid-agent/sovagrid_agent/files.py").is_file(),
             "CANDIDATE_INCOMPATIBLE")
    for name in promotion.LOCAL_TERMINAL_UNITS:
        installed = Path("/etc/systemd/system") / name
        if operations["terminal"] or installed.exists() or installed.is_symlink():
            need((source / "sovagrid-agent/deploy" / name).is_file() and
                 (source / "sovagrid-agent/sovagrid_agent/terminal_broker.py").is_file(),
                 "CANDIDATE_INCOMPATIBLE")
    local_inventory = Path("/var/lib/sovagrid-promotion/local-container-inventory.json")
    if (local_inventory.exists() or local_inventory.is_symlink() or
            any((Path("/etc/systemd/system") / name).exists() or
                (Path("/etc/systemd/system") / name).is_symlink()
                for name in LOCAL_CONTAINER_UNITS)):
        need(local_inventory.is_file() and not local_inventory.is_symlink(),
             "LOCAL_CONTAINERS_UNMANAGED")
        for name in LOCAL_CONTAINER_UNITS:
            need((source / "sovagrid-agent/deploy" / name).is_file(),
                 "CANDIDATE_INCOMPATIBLE")
        need((source / "sovagrid-agent/sovagrid_agent/container_collector.py").is_file() and
             (source / "sovagrid-agent/sovagrid_agent/containers.py").is_file(),
             "CANDIDATE_INCOMPATIBLE")
    return source, commits


def preview() -> None:
    manifest, state, commits, _ = inspect()
    emit("SG_HUB_ONLY_CURRENT_MANIFEST:" + manifest)
    emit("SG_HUB_ONLY_LOCAL_SERVER:" + state["local_server_id"])
    for component in sorted(commits):
        emit("SG_HUB_ONLY_CURRENT_COMMIT:" + component + ":" + commits[component])
    emit("SG_HUB_ONLY_PREFLIGHT:OK")


def preflight(archive_sha: str, current_manifest: str) -> None:
    manifest, _state, commits, _ = inspect()
    need(manifest == current_manifest, "VERSION")
    _candidate(archive_sha, commits)
    emit("SG_HUB_ONLY_CANDIDATE:OK")


def _private_dir(path: Path, *, create: bool = False) -> None:
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
         "UNSAFE_DIRECTORY")


def _lock(path: Path) -> int:
    need(not path.is_symlink(), "LOCK")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        common.validate_lock(os.fstat(fd))
        fcntl.flock(fd, fcntl.LOCK_EX)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _snapshot_size() -> int:
    return sum(common.safe_snapshot_item(Path(item)) for item in SNAPSHOT)


def _local_inventory_healthy() -> bool:
    try:
        status = local_inventory.preview()
    except (OSError, ValueError, KeyError, local_inventory.Refused,
            local_inventory.operations.Refused,
            promotion.PromotionError):
        return False
    return (status.get("phase") == "ready" and status.get("enabled") is True and
            status.get("collector_active") is True and status.get("snapshot_fresh") is True)


def _state(folder: Path, value: dict) -> None:
    common.state_write(folder, value)


def _restore(folder: Path, state: dict) -> bool:
    """Restore only local managed paths; never write external Agent paths."""
    errors = []
    layout = state.get("snapshot_layout", "legacy")
    need(layout in ("legacy", "release_feed_v1", "service_control_v1", "routing_v1",
                    "hub_backup_broker_v1", "ssh_gateway_v1", "local_web_v1",
                    "local_containers_v1", "web_agent_v1", "external_apply_v1"), "TRANSACTION_STATE")
    snapshot = (LEGACY_SNAPSHOT if layout == "legacy" else
                RELEASE_FEED_SNAPSHOT if layout == "release_feed_v1" else
                SERVICE_SNAPSHOT if layout == "service_control_v1" else
                ROUTING_SNAPSHOT if layout == "routing_v1" else
                HUB_BACKUP_SNAPSHOT if layout == "hub_backup_broker_v1" else
                SSH_GATEWAY_SNAPSHOT if layout == "ssh_gateway_v1" else
                LOCAL_WEB_SNAPSHOT if layout == "local_web_v1" else
                LOCAL_CONTAINERS_SNAPSHOT if layout == "local_containers_v1" else
                WEB_AGENT_SNAPSHOT if layout == "web_agent_v1" else SNAPSHOT)
    units = (LEGACY_UNITS if layout == "legacy" else
             RELEASE_FEED_UNITS if layout == "release_feed_v1" else
             SERVICE_ALL_UNITS if layout == "service_control_v1" else
             ROUTING_ALL_UNITS if layout == "routing_v1" else
             LOCAL_WEB_UNITS if layout in ("hub_backup_broker_v1", "ssh_gateway_v1",
                                           "local_web_v1") else
             LOCAL_CONTAINERS_ALL_UNITS if layout == "local_containers_v1" else UNITS)
    old_source = folder / "source-before"
    try:
        if old_source.exists():
            if SOURCE.exists() or SOURCE.is_symlink():
                if (folder / "source-failed").exists():
                    common.remove_item(folder / "source-failed")
                os.replace(SOURCE, folder / "source-failed")
            os.replace(old_source, SOURCE)
    except Exception as exc:
        errors.append("source: " + str(exc))
    try:
        if layout in ("web_agent_v1", "external_apply_v1"):
            common.command(["systemctl", "stop", *reversed(WEB_AGENT_UNITS)], timeout=40,
                           check=False)
        if layout in ("local_containers_v1", "web_agent_v1", "external_apply_v1"):
            common.command(["systemctl", "stop", *LOCAL_CONTAINER_UNITS], timeout=40, check=False)
        if layout in ("hub_backup_broker_v1", "ssh_gateway_v1", "local_web_v1",
                      "local_containers_v1", "web_agent_v1", "external_apply_v1"):
            common.command(["systemctl", "stop", *BACKUP_BROKER_UNITS], timeout=40, check=False)
        if layout in ("service_control_v1", "routing_v1", "hub_backup_broker_v1",
                      "ssh_gateway_v1", "local_web_v1", "local_containers_v1", "web_agent_v1", "external_apply_v1"):
            common.command(["systemctl", "stop", *reversed(LOCAL_SERVICE_UNITS)],
                           timeout=40, check=False)
        common.command(["systemctl", "stop", "sovagrid-terminal-local-control.service",
                        "sovagrid-terminal-local-control.socket"], timeout=40, check=False)
        common.command(["systemctl", "stop", "sovagrid-vpn-status.timer",
                        "sovagrid-vpn-status.service"], timeout=40, check=False)
        common.command(["systemctl", "stop", "sovagrid-agent-local.service"], timeout=40, check=False)
        args, env = common.rollback_stop_compose_args(SOURCE, folder, snapshot, state["phase"])
        common.command(args + ["stop"], timeout=120, check=False, env=env)
        if (layout in ("ssh_gateway_v1", "local_web_v1", "local_containers_v1", "web_agent_v1", "external_apply_v1") and state["phase"] != "preparing" and
                common.SSH_GATEWAY_SERVICE not in state["images"] and
                "gateway_before" in state):
            common.remove_new_gateway_on_rollback(state["gateway_before"]["container_ids"])
    except Exception as exc:
        errors.append("stop: " + str(exc))
    if state["phase"] != "preparing":
        for index, name in enumerate(snapshot):
            item = Path(name)
            saved = folder / "snapshot" / str(index)
            try:
                common.remove_item(item)
                if saved.exists():
                    common.copy_item(saved, item)
            except Exception as exc:
                errors.append(name + ": " + str(exc))
    try:
        for service in state["images"]:
            common.command(["docker", "image", "tag", state["images"][service],
                            "sovagrid-" + service + ":local"])
        if (layout in ("ssh_gateway_v1", "local_web_v1", "local_containers_v1", "web_agent_v1", "external_apply_v1") and state["phase"] != "preparing" and
                common.SSH_GATEWAY_SERVICE not in state["images"] and
                "gateway_before" in state):
            old_gateway_image = state["gateway_before"]["image"]
            if old_gateway_image:
                common.command(["docker", "image", "tag", old_gateway_image,
                                "sovagrid-" + common.SSH_GATEWAY_SERVICE + ":local"])
            else:
                common.command(["docker", "image", "rm",
                                "sovagrid-" + common.SSH_GATEWAY_SERVICE + ":local"],
                               check=False)
        common.command(["systemctl", "daemon-reload"])
        for unit in units:
            old = state["units"][unit]
            common.command(["systemctl", "enable" if old["enabled"] else "disable", unit],
                           timeout=30, check=bool(old["enabled"]))
        if layout in ("hub_backup_broker_v1", "ssh_gateway_v1", "local_web_v1",
                      "local_containers_v1", "web_agent_v1", "external_apply_v1") and common.backup_broker_enabled() and \
                state["units"][BACKUP_BROKER_UNITS[0]]["active"]:
            common.command(["systemctl", "start", BACKUP_BROKER_UNITS[0]], timeout=30)
        if layout in ("hub_backup_broker_v1", "ssh_gateway_v1", "local_web_v1",
                      "local_containers_v1", "web_agent_v1", "external_apply_v1"):
            common.backup_broker_socket_ready()
        if (layout in ("web_agent_v1", "external_apply_v1") and common.web_agent_managed() and
                state["units"][WEB_AGENT_UNITS[0]]["active"]):
            common.command(["systemctl", "start", WEB_AGENT_UNITS[0]], timeout=30)
            common.web_agent_socket_ready()
        args, env = common.compose_args(SOURCE)
        common.command(args + ["up", "-d", "--no-build", "--force-recreate",
                              *state["images"]], timeout=240, env=env)
        common.wait_recreated_container_health(state["images"])
        for unit in units:
            old = state["units"][unit]
            if unit in (BACKUP_BROKER_UNITS[0], WEB_AGENT_UNITS[0]):
                continue  # Container socket mounts required them before Compose up.
            if unit == ROUTING_UNIT:
                # Routing sync takes the VPN locks held by this update. Keep
                # its oneshot running and verify it rather than restarting.
                if old["active"]:
                    need(_unit_state(unit)["active"], "ROUTING_RESTORE")
                else:
                    common.command(["systemctl", "stop", unit], timeout=30, check=False)
                continue
            if unit == "sovagrid-agent-local.service" and old["active"]:
                common.command(["systemctl", "reset-failed", unit], timeout=10)
            common.command(["systemctl", "restart" if old["active"] else "stop", unit],
                           timeout=60, check=bool(old["active"]))
        if layout in ("local_containers_v1", "web_agent_v1", "external_apply_v1") and state["units"][LOCAL_CONTAINER_UNITS[1]]["active"]:
            common.command(["systemctl", "start", LOCAL_CONTAINER_UNITS[0]], timeout=40)
        manifest, _promotion, _commits, baseline_sha = inspect()
        need(manifest == state["old_manifest"] and baseline_sha == state["baseline_sha256"],
             "ROLLBACK_HEALTH")
        _check_external_runtime(state["external_runtime"])
        need(_hash_file(promotion.LOCAL) == state["local_record_sha256"] and
             _hash_file(promotion.LOCAL_CONFIG) == state["local_config_sha256"],
             "ROLLBACK_LOCAL_CONFIG")
    except Exception as exc:
        errors.append("restart/health: " + str(exc))
    if errors:
        state["phase"] = "rollback_failed"
        state["errors"] = errors[:12]
        _state(folder, state)
        emit("SG_HUB_ONLY_STAGE:ROLLBACK_FAILED")
        return False
    state["phase"] = "rolled_back"
    _state(folder, state)
    emit("SG_HUB_ONLY_STAGE:ROLLED_BACK")
    return True


def _refresh_local_agent(new_manifest: str) -> None:
    """Replace only the second Agent's code and CA, then advance its pin."""
    files, hashes = promotion._agent_source_files()
    common.remove_item(promotion.LOCAL_SOURCE)
    promotion._install_agent_source(files, hashes)
    group = promotion.grp.getgrnam(promotion.LOCAL_USER).gr_gid
    old_ca = promotion._read_regular(promotion.LOCAL_CA, 16384)
    new_ca = promotion._read_regular(promotion.LOCAL_HUB_CA_STAGING, 16384)
    if old_ca != new_ca:
        promotion._replace_group_file(promotion.LOCAL_CA, old_ca, new_ca, group)
    promotion._save_private(promotion.PIN, {"protocol": 1, "manifest_sha256": new_manifest})


def _refresh_local_broker(old_source: Path, units: dict[str, dict]) -> None:
    """Update installed broker units only when they were already installed."""
    changed = False
    for name in (*promotion.LOCAL_TERMINAL_UNITS, *LOCAL_SERVICE_UNITS,
                 *LOCAL_CONTAINER_UNITS):
        target = SYSTEMD / name
        if not target.exists() and not target.is_symlink():
            need(not units[name]["active"] and not units[name]["enabled"], "BROKER_STATE")
            continue
        before = promotion._read_regular(old_source / "sovagrid-agent/deploy" / name, 8192)
        after = promotion._read_regular(SOURCE / "sovagrid-agent/deploy" / name, 8192)
        info = target.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
             stat.S_IMODE(info.st_mode) == 0o644 and
             promotion._read_regular(target, 8192) == before, "BROKER_CHANGED")
        if before == after:
            continue
        temporary = target.parent / ("." + name + "." + secrets.token_hex(12))
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o644)
            with os.fdopen(fd, "wb") as stream:
                stream.write(after)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        changed = True
    if changed:
        common.command(["systemctl", "daemon-reload"])
    for name in (*promotion.LOCAL_TERMINAL_UNITS, *LOCAL_SERVICE_UNITS,
                 *LOCAL_CONTAINER_UNITS):
        old = units[name]
        if old["active"]:
            if name.endswith(".socket") or name in promotion.LOCAL_TERMINAL_UNITS:
                need(old["enabled"], "BROKER_STATE")
                common.command(["systemctl", "enable", "--now", name], timeout=40)
            else:
                common.command(["systemctl", "restart", name], timeout=40)
            need(_unit_state(name) == old, "BROKER_STATE")


def _recover_pending() -> None:
    _private_dir(TRANSACTIONS, create=True)
    for folder in sorted(TRANSACTIONS.iterdir()):
        need(folder.is_dir() and not folder.is_symlink() and
             TRANSACTION_NAME.fullmatch(folder.name) is not None, "TRANSACTION_STATE")
        _private_dir(folder)
        info = (folder / "state.json").lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
             stat.S_IMODE(info.st_mode) == 0o600, "TRANSACTION_STATE")
        state = json.loads((folder / "state.json").read_bytes())
        layout = state.get("snapshot_layout", "legacy") if isinstance(state, dict) else None
        expected_units = (LEGACY_UNITS if layout == "legacy" else
                          RELEASE_FEED_UNITS if layout == "release_feed_v1" else
                          SERVICE_ALL_UNITS if layout == "service_control_v1" else
                          ROUTING_ALL_UNITS if layout == "routing_v1" else
                          LOCAL_WEB_UNITS if layout in ("hub_backup_broker_v1",
                                                        "ssh_gateway_v1", "local_web_v1") else
                          LOCAL_CONTAINERS_ALL_UNITS if layout == "local_containers_v1" else UNITS)
        required = {"phase", "old_manifest", "candidate", "images", "units", "baseline_sha256",
                    "local_record_sha256", "local_config_sha256", "local_server_id",
                    "external_runtime"}
        need(isinstance(state, dict) and required <= set(state) and
             state["phase"] in ("preparing", "backed_up", "running", "committed", "rolled_back", "rollback_failed") and
             all(isinstance(state[key], str) and SHA.fullmatch(state[key]) is not None
                 for key in ("old_manifest", "candidate", "baseline_sha256",
                             "local_record_sha256", "local_config_sha256")) and
             isinstance(state["local_server_id"], str) and
             isinstance(state["images"], dict) and
             set(state["images"]) in ({"hub", "web"}, {"hub", "web", "ssh-gateway"}) and
             ("ssh-gateway" not in state["images"] or layout in
              ("ssh_gateway_v1", "local_web_v1", "local_containers_v1",
               "web_agent_v1", "external_apply_v1")) and
             all(isinstance(value, str) and SHA.fullmatch(value.removeprefix("sha256:")) is not None
                 for value in state["images"].values()) and
             layout in ("legacy", "release_feed_v1", "service_control_v1", "routing_v1",
                        "hub_backup_broker_v1", "ssh_gateway_v1", "local_web_v1",
                        "local_containers_v1", "web_agent_v1", "external_apply_v1") and
             isinstance(state["units"], dict) and set(state["units"]) == set(expected_units) and
             all(isinstance(item, dict) and set(item) == {"active", "enabled"} and
                 type(item["active"]) is bool and type(item["enabled"]) is bool
                 for item in state["units"].values()) and
             isinstance(state["external_runtime"], dict) and
             set(state["external_runtime"]) == set(promotion.UNITS) and
             all(isinstance(item, dict) and set(item) == {"active", "enabled", "pid"} and
                 type(item["active"]) is bool and type(item["enabled"]) is bool and
                 type(item["pid"]) is int and item["pid"] >= 0
                 for item in state["external_runtime"].values()),
             "TRANSACTION_STATE")
        if state["phase"] in ("committed", "rolled_back"):
            shutil.rmtree(folder)
            continue
        emit("SG_HUB_ONLY_STAGE:RECOVERING")
        if not _restore(folder, state):
            raise Refused("RECOVERY")
        shutil.rmtree(folder)
        raise Refused("RECOVERED")


def _automatic_barrier(admission: contextlib.ExitStack):
    try:
        return admission.enter_context(common.automatic_idle_barrier())
    except common.UpdateFailure as exc:
        if str(exc) == "BUSY":
            raise Refused("BUSY") from exc
        raise


def apply(archive_sha: str, current_manifest: str, *, automatic: bool = False) -> None:
    need(os.geteuid() == 0 and SHA.fullmatch(archive_sha) is not None and
         SHA.fullmatch(current_manifest) is not None, "ARGS")
    _private_dir(CANDIDATES)
    with contextlib.ExitStack() as locks:
        # Promotion uses this lock before run.sh's public lock. Keep the same
        # order so an interrupted promotion cannot race an update.
        locks.callback(os.close, _lock(PROMOTION_LOCK))
        locks.callback(os.close, _lock(CANDIDATES / ".lock"))
        locks.enter_context(common.web_agent_snapshot_lock())
        locks.enter_context(common.public_web_lock())
        locks.callback(os.close, promotion._service_setup_lock())
        locks.enter_context(common.managed_vpn_locks())
        _recover_pending()
        manifest, state_before, old_commits, baseline_sha = inspect()
        need(manifest == current_manifest, "VERSION")
        local_inventory_pending = Path(
            "/var/lib/sovagrid-promotion/local-container-inventory-pending.json")
        need(not local_inventory_pending.exists() and not local_inventory_pending.is_symlink(),
             "LOCAL_CONTAINERS_RECOVERY")
        local_inventory_marker = Path(
            "/var/lib/sovagrid-promotion/local-container-inventory.json")
        if local_inventory_marker.exists() or local_inventory_marker.is_symlink():
            need(_local_inventory_healthy(), "LOCAL_CONTAINERS_UNHEALTHY")
        staged, new_commits = _candidate(archive_sha, old_commits)
        new_manifest = common.source_manifest(staged)[0]
        amount = _snapshot_size()
        need(amount <= MAX_BACKUP and shutil.disk_usage(CANDIDATES).free >=
             amount * 2 + 512 * 1024**2, "SPACE")
        gateway_before = common.gateway_prior_state()
        images = {}
        for service in common.compose_services():
            images[service] = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}",
                                              "sovagrid-" + service + ":local"], capture_output=True,
                                             text=True, timeout=10, check=True).stdout.strip()
        units = {name: _unit_state(name) for name in UNITS}
        external_runtime = _external_runtime()
        admission = contextlib.ExitStack()
        locks.callback(admission.close)
        barrier = _automatic_barrier(admission) if automatic else None
        folder = TRANSACTIONS / (str(time.time_ns()) + "-" + archive_sha[:12])
        created = False
        try:
            folder.mkdir(mode=0o700)
            created = True
            state = {"phase": "preparing", "old_manifest": manifest, "candidate": archive_sha,
                     "snapshot_layout": "external_apply_v1",
                     "images": images, "gateway_before": gateway_before,
                     "units": units, "baseline_sha256": baseline_sha,
                     "local_server_id": state_before["local_server_id"],
                     "local_record_sha256": _hash_file(promotion.LOCAL),
                     "local_config_sha256": _hash_file(promotion.LOCAL_CONFIG),
                     "external_runtime": external_runtime}
            _state(folder, state)
        except BaseException:
            admission.close()
            if created:
                with contextlib.suppress(OSError):
                    shutil.rmtree(folder)
            raise
        try:
            for service in images:
                common.command(["docker", "image", "tag", images[service],
                                "sovagrid-" + service + ":rollback-" + archive_sha[:12]])
            if automatic:
                args, env = common.compose_args(SOURCE)
                common.command(args + ["stop", "--timeout", "30", "hub"],
                               timeout=45, env=env)
                running = subprocess.run(
                    ["docker", "ps", "--quiet", "--filter", "label=com.docker.compose.project=sovagrid",
                     "--filter", "label=com.docker.compose.service=hub"],
                    capture_output=True, text=True, timeout=10, check=True).stdout.strip()
                need(not running, "CONTAINER_STOP")
                barrier.assert_held()
                admission.close()
            common.command(["systemctl", "stop", "sovagrid-vpn-status.timer",
                            "sovagrid-vpn-status.service"], timeout=40)
            common.command(["systemctl", "stop", "sovagrid-terminal-local-control.service",
                            "sovagrid-terminal-local-control.socket"], timeout=40, check=False)
            common.command(["systemctl", "stop", *reversed(WEB_AGENT_UNITS)], timeout=40,
                           check=False)
            common.command(["systemctl", "stop", *LOCAL_CONTAINER_UNITS], timeout=40,
                           check=False)
            common.command(["systemctl", "stop", *BACKUP_BROKER_UNITS], timeout=40, check=False)
            common.command(["systemctl", "stop", *reversed(LOCAL_SERVICE_UNITS)],
                           timeout=40, check=False)
            common.command(["systemctl", "stop", "sovagrid-agent-local.service"], timeout=40)
            if not automatic:
                args, env = common.compose_args(SOURCE)
            common.command(args + ["stop"], timeout=120, env=env)
            if automatic:
                for service in images:
                    running = subprocess.run(
                        ["docker", "ps", "--quiet", "--filter", "label=com.docker.compose.project=sovagrid",
                         "--filter", "label=com.docker.compose.service=" + service],
                        capture_output=True, text=True, timeout=10, check=True).stdout.strip()
                    need(not running, "CONTAINER_STOP")
            admission.close()
            (folder / "snapshot").mkdir(mode=0o700)
            for index, name in enumerate(SNAPSHOT):
                item = Path(name)
                if item.exists():
                    common.copy_item(item, folder / "snapshot" / str(index))
            new_source = folder / "source-new"
            common.copy_item(staged, new_source)
            need(common.source_manifest(new_source) == (new_manifest, new_commits), "CANDIDATE_CHANGED")
            need(common.source_manifest(SOURCE, allow_generated=True)[0] == manifest, "SOURCE_CHANGED")
            state["phase"] = "backed_up"
            _state(folder, state)
            os.replace(SOURCE, folder / "source-before")
            os.replace(new_source, SOURCE)
            state["phase"] = "running"
            _state(folder, state)
            emit("SG_HUB_ONLY_STAGE:INSTALLING")
            with (folder / "install.log").open("wb") as output:
                os.chmod(output.fileno(), 0o600)
                install_env = os.environ.copy()
                install_env.update(SOVAGRID_PUBLIC_WEB_LOCK_HELD="1", SOVAGRID_UPDATER_TIMER_SNAPSHOT="1",
                                   SOVAGRID_RELEASE_FEED_SNAPSHOT="1",
                                   SOVAGRID_HUB_BACKUP_BROKER_SNAPSHOT="1",
                                   SOVAGRID_EXTERNAL_APPLY_UNIT_SNAPSHOT="1",
                                   SOVAGRID_SSH_GATEWAY_SNAPSHOT="1",
                                   SOVAGRID_WEB_AGENT_SNAPSHOT="1")
                common.command(["bash", str(SOURCE / "sovagrid-blueprint/run.sh"), "--hub-only"],
                               timeout=2700, stdout=output, env=install_env)
            _refresh_local_agent(new_manifest)
            _refresh_local_broker(folder / "source-before", units)
            if units[LOCAL_CONTAINER_UNITS[1]]["active"]:
                common.command(["systemctl", "start", LOCAL_CONTAINER_UNITS[0]], timeout=40)
            restarted_at = int(time.time())
            common.command(["systemctl", "reset-failed", "sovagrid-agent-local.service"], timeout=10)
            common.command(["systemctl", "restart", "sovagrid-agent-local.service"], timeout=60)
            promotion._wait_local_metric(state_before["local_server_id"], timeout=100, since=restarted_at)
            if local_inventory_marker.exists() or local_inventory_marker.is_symlink():
                need(_local_inventory_healthy(), "LOCAL_CONTAINERS_POSTCHECK")
            after_manifest, after_state, after_commits, after_baseline = inspect()
            need(after_manifest == new_manifest and after_commits == new_commits and
                 after_baseline == baseline_sha and
                 after_state["local_server_id"] == state_before["local_server_id"] and
                 _hash_file(promotion.LOCAL) == state["local_record_sha256"] and
                 _hash_file(promotion.LOCAL_CONFIG) == state["local_config_sha256"], "POSTCHECK")
            _check_external_runtime(external_runtime)
            for unit in ("sovagrid-vpn-status.timer", "sovagrid-vpn-status.service"):
                common.command(["systemctl", "start" if units[unit]["active"] else "stop", unit],
                               timeout=40, check=units[unit]["active"])
            need(_unit_state(ROUTING_UNIT) == units[ROUTING_UNIT], "ROUTING_STATE")
            state["phase"] = "committed"
            _state(folder, state)
            emit("SG_HUB_ONLY_STAGE:DONE")
        except BaseException:
            # The DB has not been copied until after the confirmed stop. A
            # preparing rollback must be able to restart Hub and write to it.
            admission.close()
            emit("SG_HUB_ONLY_STAGE:ROLLBACK")
            if _restore(folder, state):
                try:
                    common.preserve_install_log(folder)
                except (OSError, common.UpdateFailure):
                    pass
                shutil.rmtree(folder)
                raise Refused("ROLLED_BACK")
            raise Refused("ROLLBACK_FAILED")
        try:
            shutil.rmtree(folder)
            for service in images:
                common.command(["docker", "image", "rm",
                                "sovagrid-" + service + ":rollback-" + archive_sha[:12]],
                               timeout=30, check=False)
        except (OSError, common.UpdateFailure):
            pass


def interrupted(_number, _frame):
    common.interrupted(_number, _frame)


def main(argv: list[str]) -> int:
    try:
        if argv == ["preview"]:
            preview()
        elif len(argv) == 3 and argv[0] == "preflight":
            preflight(argv[1], argv[2])
        elif len(argv) == 3 and argv[0] in ("apply", "apply-auto"):
            apply(argv[1], argv[2], automatic=argv[0] == "apply-auto")
        else:
            raise Refused("ARGS")
    except Refused as exc:
        emit("SG_HUB_ONLY_REFUSE:" + str(exc))
        return 40
    except (OSError, ValueError, subprocess.SubprocessError, sqlite3.Error,
            common.UpdateFailure,
            promotion.PromotionError):
        emit("SG_HUB_ONLY_REFUSE:UNEXPECTED")
        return 41
    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    raise SystemExit(main(sys.argv[1:]))
