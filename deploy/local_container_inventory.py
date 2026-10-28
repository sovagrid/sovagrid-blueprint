#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in Docker inventory for a promoted Hub's separate local Agent.

The root collector has one fixed Docker API reader and writes a sanitized
snapshot for ``sovagrid-local``. This transaction never changes the external
Agent, its credentials, the reverse tunnel, or the local Agent configuration.
"""

from __future__ import annotations

import contextlib
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location(
    "sovagrid_local_operations", Path(__file__).with_name("local_operations.py"))
assert _spec and _spec.loader
operations = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(operations)
promotion = operations.promotion

STATE = promotion.STATE_DIR / "local-container-inventory.json"
PENDING = promotion.STATE_DIR / "local-container-inventory-pending.json"
DIRECTORY = Path("/var/lib/sovagrid-containers-local")
SNAPSHOT = DIRECTORY / "snapshot.json"
UNITS = ("sovagrid-container-inventory-local.service",
         "sovagrid-container-inventory-local.timer")
TIMER = UNITS[1]
REVISION = re.compile(r"[0-9a-f]{64}\Z")
MAX_SNAPSHOT = 10000


class Refused(Exception):
    pass


def need(condition: bool, code: str) -> None:
    if not condition:
        raise Refused(code)


def _record(path: Path) -> bool:
    need(not path.is_symlink(), "STATE")
    if not path.exists():
        return False
    value = promotion._private_json(path)
    need(set(value) == {"protocol", "enabled"} and
         type(value["protocol"]) is int and value["protocol"] == 1 and
         value["enabled"] is True, "STATE")
    return True


def _pending() -> dict | None:
    need(not PENDING.is_symlink(), "PENDING")
    if not PENDING.exists():
        return None
    value = promotion._private_json(PENDING)
    need(set(value) == {"protocol", "previous", "target", "manifest_sha256"} and
         type(value["protocol"]) is int and value["protocol"] == 1 and
         type(value["previous"]) is bool and type(value["target"]) is bool and
         value["previous"] != value["target"] and
         isinstance(value["manifest_sha256"], str) and
         REVISION.fullmatch(value["manifest_sha256"]) is not None, "PENDING")
    return value


def _source() -> str:
    digest = promotion._source_manifest_sha256()
    need(digest == promotion._pin(), "SOURCE_PIN")
    files, hashes = promotion._agent_source_files()
    promotion._verify_local_source(files, hashes)
    need("sovagrid-agent/sovagrid_agent/container_collector.py" in hashes and
         "sovagrid-agent/sovagrid_agent/containers.py" in hashes,
         "SOURCE_AGENT")
    for unit in UNITS:
        need("sovagrid-agent/deploy/" + unit in hashes, "SOURCE_UNIT")
    return digest


def _identity() -> int:
    local = pwd.getpwnam(promotion.LOCAL_USER)
    group = grp.getgrnam(promotion.LOCAL_USER)
    external = pwd.getpwnam("sovagrid")
    docker_gid = grp.getgrnam("docker").gr_gid
    local_groups = set(os.getgrouplist(promotion.LOCAL_USER, local.pw_gid))
    external_groups = set(os.getgrouplist("sovagrid", external.pw_gid))
    need(local.pw_uid != 0 and local.pw_gid == group.gr_gid and
         local.pw_uid != external.pw_uid and group.gr_gid != external.pw_gid and
         local_groups == {local.pw_gid} and group.gr_gid not in external_groups,
         "LOCAL_IDENTITY")
    need(docker_gid not in local_groups and docker_gid not in external_groups,
         "DOCKER_GROUP")
    return group.gr_gid


def _preflight(*, pending: bool = False) -> tuple[dict, dict, str, int]:
    need(os.geteuid() == 0, "ROOT")
    baseline = promotion._private_json(promotion.BASELINE)
    need(promotion.capture_external() == baseline, "EXTERNAL_CHANGED")
    digest = _source()
    if not pending:
        state = promotion.inspect()
        need(state.get("phase") == "activated" and
             state.get("external_agent_preserved") is True, "PROMOTION_STATE")
    saved = promotion._private_json(promotion.LOCAL)
    need(set(saved) == {"protocol", "server_id", "token_sha256", "commands"} and
         type(saved["protocol"]) is int and saved["protocol"] == 1 and
         isinstance(saved["server_id"], str) and
         isinstance(saved["token_sha256"], str) and
         REVISION.fullmatch(saved["token_sha256"]) is not None and
         type(saved["commands"]) is bool, "LOCAL_IDENTITY")
    need(str(uuid.UUID(saved["server_id"])) == saved["server_id"] and
         hashlib.sha256(promotion._read_regular(promotion.LOCAL_TOKEN, 256).strip()).hexdigest() ==
         saved["token_sha256"], "LOCAL_IDENTITY")
    gid = _identity()
    if not pending:
        need(promotion._unit_active(promotion.LOCAL_UNIT.name), "LOCAL_AGENT_INACTIVE")
    return saved, baseline, digest, gid


def _unit_bytes() -> dict[str, bytes]:
    return {unit: operations._verified_unit(unit) for unit in UNITS}


def _directory(gid: int, *, allow_absent: bool) -> bool:
    need(not DIRECTORY.is_symlink(), "DIRECTORY")
    if not DIRECTORY.exists():
        need(allow_absent, "DIRECTORY")
        return False
    info = DIRECTORY.lstat()
    need(stat.S_ISDIR(info.st_mode) and
         (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, gid, 0o750),
         "DIRECTORY")
    for child in DIRECTORY.iterdir():
        need(child.name == SNAPSHOT.name or
             (child.name.startswith(".snapshot-") and len(child.name) <= 40),
             "DIRECTORY_CONTENT")
        record = child.lstat()
        need(stat.S_ISREG(record.st_mode) and record.st_uid == 0 and
             record.st_gid == gid and record.st_nlink == 1 and
             stat.S_IMODE(record.st_mode) in (0o600, 0o640) and
             record.st_size <= MAX_SNAPSHOT, "SNAPSHOT_FILE")
    return True


def _snapshot_fresh(gid: int) -> bool:
    try:
        _directory(gid, allow_absent=False)
        info = SNAPSHOT.lstat()
        if (not stat.S_ISREG(info.st_mode) or
                (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink) !=
                (0, gid, 0o640, 1) or not 1 <= info.st_size <= MAX_SNAPSHOT):
            return False
        fd = os.open(SNAPSHOT, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                return False
            value = json.loads(stream.read(MAX_SNAPSHOT + 1))
        docker = value["engines"][0]
        timestamp = value["collected_at"]
        return (value["version"] == 1 and docker["engine"] == "docker" and
                docker["source_status"] == "ok" and
                type(timestamp) is int and 0 <= time.time() - timestamp <= 120)
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        return False


def _physical(enabled: bool, gid: int) -> dict:
    marker = _record(STATE)
    need(marker == enabled, "STATE_CHANGED")
    paths = [operations.SYSTEMD / name for name in UNITS]
    present = [path.exists() or path.is_symlink() for path in paths]
    if enabled:
        need(all(present), "UNIT_MISSING")
        _unit_bytes()
        _directory(gid, allow_absent=False)
    else:
        need(not any(present) and not DIRECTORY.exists() and
             not DIRECTORY.is_symlink() and
             not promotion._unit_active(TIMER) and not promotion._unit_enabled(TIMER),
             "UNMANAGED_INVENTORY")
    active = promotion._unit_active(TIMER) and promotion._unit_enabled(TIMER)
    return {"collector_active": active, "snapshot_fresh": _snapshot_fresh(gid) if enabled else False}


def _revision(saved: dict, digest: str, enabled: bool) -> str:
    value = {"protocol": 1, "local_server_id": saved["server_id"],
             "manifest_sha256": digest, "enabled": enabled}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"))
                          .encode("ascii")).hexdigest()


def _state(saved: dict, digest: str, enabled: bool, health: dict) -> dict:
    return {"protocol": 1, "phase": "ready", "enabled": enabled,
            "manifest_sha256": digest, "local_server_id": saved["server_id"],
            "external_agent_preserved": True, "state_revision": _revision(saved, digest, enabled),
            **health}


def preview() -> dict:
    pending = _pending()
    if pending is not None:
        saved, baseline, digest, _ = _preflight(pending=True)
        need(promotion.capture_external() == baseline and
             digest == pending["manifest_sha256"], "RECOVERY_SOURCE")
        return {"protocol": 1, "phase": "recovery_required",
                "previous_enabled": pending["previous"], "requested_enabled": pending["target"],
                "manifest_sha256": digest, "local_server_id": saved["server_id"],
                "external_agent_preserved": True, "state_revision": None}
    saved, baseline, digest, gid = _preflight()
    enabled = _record(STATE)
    health = _physical(enabled, gid)
    need(promotion.capture_external() == baseline, "EXTERNAL_CHANGED")
    return _state(saved, digest, enabled, health)


def _command(*args: str) -> None:
    subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=50, check=True)


def _enable(gid: int) -> None:
    units = _unit_bytes()
    _command("systemd-analyze", "verify",
             *(str(operations.SOURCE_AGENT / name) for name in UNITS))
    need(not STATE.is_symlink(), "STATE")
    if not STATE.exists():
        promotion._save_private(STATE, {"protocol": 1, "enabled": True})
    promotion._local_directory(DIRECTORY, uid=0, gid=gid, mode=0o750)
    _directory(gid, allow_absent=False)
    for name, raw in units.items():
        operations._install_unit(name, raw)
    _command("systemctl", "daemon-reload")
    _command("systemctl", "enable", "--now", TIMER)
    _command("systemctl", "start", UNITS[0])
    need(promotion._unit_active(TIMER) and promotion._unit_enabled(TIMER), "TIMER_START")
    need(_snapshot_fresh(gid), "SNAPSHOT_UNAVAILABLE")


def _disable(gid: int) -> None:
    _unit_bytes()  # An existing unit must match this exact pinned source.
    if promotion._unit_active(TIMER):
        _command("systemctl", "stop", TIMER)
    if promotion._unit_enabled(TIMER):
        _command("systemctl", "disable", TIMER)
    if promotion._unit_active(UNITS[0]):
        _command("systemctl", "stop", UNITS[0])
    if _directory(gid, allow_absent=True):
        for child in DIRECTORY.iterdir():
            child.unlink()
        DIRECTORY.rmdir()
    for name in UNITS:
        path = operations.SYSTEMD / name
        if path.exists():
            path.unlink()
    _command("systemctl", "daemon-reload")
    STATE.unlink(missing_ok=True)
    need(not promotion._unit_active(TIMER) and not promotion._unit_enabled(TIMER), "TIMER_STOP")


def _apply(enabled: bool, gid: int) -> None:
    if enabled:
        _enable(gid)
    else:
        _disable(gid)


def _recover_locked() -> None:
    pending = _pending()
    if pending is None:
        return
    saved, baseline, digest, gid = _preflight(pending=True)
    need(digest == pending["manifest_sha256"], "RECOVERY_SOURCE")
    _apply(pending["previous"], gid)
    _physical(pending["previous"], gid)
    need(promotion.capture_external() == baseline and
         promotion.inspect().get("phase") == "activated", "RECOVERY_POSTCHECK")
    PENDING.unlink()


def change(enabled: bool, *, expected_state: str) -> dict:
    need(type(enabled) is bool and isinstance(expected_state, str) and
         REVISION.fullmatch(expected_state) is not None, "ARGS")
    with contextlib.ExitStack() as stack:
        stack.callback(os.close, operations._lock())
        stack.callback(os.close, promotion._service_setup_lock())
        need(_pending() is None, "RECOVERY_REQUIRED")
        saved, baseline, digest, gid = _preflight()
        previous = _record(STATE)
        health = _physical(previous, gid)
        need(_revision(saved, digest, previous) == expected_state, "STATE_CHANGED")
        if previous == enabled:
            return _state(saved, digest, enabled, health)
        promotion._save_private(PENDING, {"protocol": 1, "previous": previous,
                                          "target": enabled, "manifest_sha256": digest})
        try:
            _apply(enabled, gid)
            result = _physical(enabled, gid)
            need(promotion.capture_external() == baseline and
                 promotion.inspect().get("phase") == "activated", "POSTCHECK")
            PENDING.unlink()
            return _state(saved, digest, enabled, result)
        except BaseException as original:
            print("SG_LOCAL_CONTAINERS_STAGE:APPLY_FAILED:" +
                  (str(original) if isinstance(original, Refused) else type(original).__name__.upper()),
                  file=sys.stderr)
            try:
                _apply(previous, gid)
                _physical(previous, gid)
                need(promotion.capture_external() == baseline and
                     promotion.inspect().get("phase") == "activated", "ROLLBACK_POSTCHECK")
                PENDING.unlink()
            except BaseException as rollback:
                print("SG_LOCAL_CONTAINERS_STAGE:ROLLBACK_FAILED:" +
                      (str(rollback) if isinstance(rollback, Refused) else type(rollback).__name__.upper()),
                      file=sys.stderr)
                raise Refused("ROLLBACK_NEEDS_RECOVERY") from rollback
            raise Refused("ROLLED_BACK") from original


def recover() -> dict:
    with contextlib.ExitStack() as stack:
        stack.callback(os.close, operations._lock())
        stack.callback(os.close, promotion._service_setup_lock())
        _recover_locked()
        return preview()


def main(argv: list[str]) -> int:
    os.umask(0o077)
    if argv == ["preview"]:
        result = preview()
    elif argv == ["recover"]:
        result = recover()
    elif len(argv) == 3 and argv[0] in ("enable", "disable") and argv[1] == "--expected-state":
        result = change(argv[0] == "enable", expected_state=argv[2])
    else:
        raise Refused("ARGS")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError,
            promotion.PromotionError, operations.Refused, Refused) as exc:
        code = str(exc) if isinstance(exc, Refused) else type(exc).__name__.upper()
        print("SG_LOCAL_CONTAINERS_REFUSE:" + code, file=sys.stderr)
        raise SystemExit(40) from None
