#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Root-only opt-in PTY and file workspace for a promoted local Agent.

The external Agent and its SSH transport are checked, never written. A small
root-only pending journal makes an interrupted change recoverable. No command
from the caller is interpolated into a shell or systemd unit.
"""
from __future__ import annotations

import contextlib
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import sqlite3
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("sovagrid_local_promotion", Path(__file__).with_name("promote_agent_only.py"))
assert _spec and _spec.loader
promotion = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(promotion)

LOCK = Path("/run/sovagrid-promotion.lock")
SOURCE_AGENT = promotion.SOURCE / "sovagrid-agent/deploy"
SYSTEMD = Path("/etc/systemd/system")
FEATURES = {"terminal", "files"}
STATE_REVISION = re.compile(r"[0-9a-f]{64}\Z")


class Refused(Exception):
    pass


def need(condition: bool, code: str) -> None:
    if not condition:
        raise Refused(code)


def _operation(value: object) -> dict:
    need(isinstance(value, dict) and set(value) == {"protocol", "terminal", "files"} and
         type(value["protocol"]) is int and value["protocol"] == 1 and
         type(value["terminal"]) is bool and type(value["files"]) is bool,
         "STATE")
    return value


def _ready() -> dict:
    if not promotion.LOCAL_OPERATIONS.exists() and not promotion.LOCAL_OPERATIONS.is_symlink():
        return {"protocol": 1, "terminal": False, "files": False}
    return _operation(promotion._private_json(promotion.LOCAL_OPERATIONS))


def _revision(saved: dict, current: dict) -> str:
    """Opaque compare-and-swap value bound to the installed local Hub."""
    payload = {"protocol": 1, "server_id": saved["server_id"],
               "source_manifest_sha256": promotion._source_manifest_sha256(),
               "operations": _operation(current)}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"))
                          .encode("ascii")).hexdigest()


def _pending() -> dict | None:
    path = promotion.LOCAL_OPERATIONS_PENDING
    need(not path.is_symlink(), "STATE")
    if not path.exists():
        return None
    value = promotion._private_json(path)
    need(set(value) == {"protocol", "previous", "target"} and
         value["protocol"] == 1, "STATE")
    _operation(value["previous"])
    _operation(value["target"])
    return value


def _lock() -> int:
    need(os.geteuid() == 0 and not LOCK.is_symlink(), "ROOT_OR_LOCK")
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    try:
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "LOCK")
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _preflight(*, pending: bool = False) -> tuple[dict, dict]:
    need(os.geteuid() == 0, "ROOT")
    baseline = promotion._private_json(promotion.BASELINE)
    need(promotion.capture_external() == baseline, "EXTERNAL_CHANGED")
    need(promotion._source_manifest_sha256() == promotion._pin(), "SOURCE_PIN")
    if not pending:
        state = promotion.inspect()
        need(state.get("phase") == "activated" and state.get("external_agent_preserved") is True,
             "PROMOTION_STATE")
    saved = promotion._private_json(promotion.LOCAL)
    need(set(saved) == {"protocol", "server_id", "token_sha256", "commands"} and
         type(saved["protocol"]) is int and saved["protocol"] == 1 and
         isinstance(saved["server_id"], str) and
         isinstance(saved["token_sha256"], str) and
         re.fullmatch(r"[0-9a-f]{64}", saved["token_sha256"]) is not None and
         saved["commands"] is True,
         "COMMANDS_REQUIRED")
    need(str(uuid.UUID(saved["server_id"])) == saved["server_id"] and
         hashlib.sha256(promotion._read_regular(promotion.LOCAL_TOKEN, 256).strip()).hexdigest() ==
         saved["token_sha256"], "LOCAL_IDENTITY")
    with sqlite3.connect("file:/var/lib/sovagrid/hub/hub.sqlite?mode=ro", uri=True, timeout=2) as db:
        db.execute("PRAGMA query_only=ON")
        row = db.execute("SELECT remote_commands_enabled FROM servers WHERE id=?",
                         (saved["server_id"],)).fetchone()
    need(row == (1,), "COMMANDS_REQUIRED")
    return saved, baseline


def _verified_unit(name: str) -> bytes:
    source = SOURCE_AGENT / name
    manifest = json.loads(promotion._read_regular(promotion.SOURCE / "sovagrid-bundle.json", 1024 * 1024))
    raw = promotion._read_regular(source, 8192)
    need(hashlib.sha256(raw).hexdigest() == manifest.get("sha256", {}).get("sovagrid-agent/deploy/" + name),
         "UNIT_SOURCE")
    target = SYSTEMD / name
    if target.exists() or target.is_symlink():
        info = target.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
             stat.S_IMODE(info.st_mode) == 0o644 and
             promotion._read_regular(target, 8192) == raw, "UNIT_CONFLICT")
    return raw


def _install_unit(name: str, raw: bytes) -> None:
    target = SYSTEMD / name
    if target.exists():
        return
    temporary = SYSTEMD / ("." + name + "." + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _ensure_shell() -> None:
    name = promotion.LOCAL_SHELL
    try:
        group = grp.getgrnam(name)
    except KeyError:
        subprocess.run(["groupadd", "--system", name], check=True, timeout=20)
        group = grp.getgrnam(name)
    need(not group.gr_mem, "SHELL_IDENTITY")
    try:
        user = pwd.getpwnam(name)
    except KeyError:
        subprocess.run(["useradd", "--system", "--gid", name, "--home-dir",
                        str(promotion.LOCAL_SHELL_HOME), "--shell", "/usr/sbin/nologin", name],
                       check=True, timeout=20)
        user = pwd.getpwnam(name)
    local = pwd.getpwnam(promotion.LOCAL_USER)
    external = pwd.getpwnam("sovagrid")
    need(user.pw_uid != 0 and user.pw_uid not in (local.pw_uid, external.pw_uid) and
         user.pw_gid == group.gr_gid and group.gr_gid not in (local.pw_gid, external.pw_gid) and
         user.pw_dir == str(promotion.LOCAL_SHELL_HOME) and user.pw_shell == "/usr/sbin/nologin" and
         os.getgrouplist(name, group.gr_gid) == [group.gr_gid], "SHELL_IDENTITY")
    promotion._local_directory(promotion.LOCAL_SHELL_HOME, uid=user.pw_uid,
                               gid=group.gr_gid, mode=0o700)


def _ensure_workspace() -> None:
    user = pwd.getpwnam(promotion.LOCAL_USER)
    promotion._local_directory(promotion.LOCAL_FILE_WORKSPACE,
                               uid=user.pw_uid, gid=user.pw_gid, mode=0o700)


def _cmd(*args: str) -> None:
    subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True, timeout=50)


def _apply_target(saved: dict, previous: dict, target: dict) -> None:
    units = ({name: _verified_unit(name) for name in promotion.LOCAL_TERMINAL_UNITS}
             if target["terminal"] or previous["terminal"] or
             any((SYSTEMD / name).exists() or (SYSTEMD / name).is_symlink()
                 for name in promotion.LOCAL_TERMINAL_UNITS) else {})
    if target["terminal"]:
        _ensure_shell()
        for name, raw in units.items():
            _install_unit(name, raw)
        _cmd("systemctl", "daemon-reload")
        _cmd("systemctl", "enable", "--now", promotion.LOCAL_TERMINAL_UNITS[0])
        _cmd("systemctl", "enable", "--now", promotion.LOCAL_TERMINAL_UNITS[1])
        _cmd("systemctl", "restart", promotion.LOCAL_TERMINAL_UNITS[1])
        need(all(promotion._unit_active(name) and promotion._unit_enabled(name)
                 for name in promotion.LOCAL_TERMINAL_UNITS),
             "TERMINAL_START")
    if target["files"]:
        _ensure_workspace()
    current = promotion._read_regular(promotion.LOCAL_CONFIG, 8192)
    variants = [service_socket for service_socket in (False, True) if
                current in (promotion._config_bytes(saved, operations=previous,
                                                    service_socket=service_socket),
                            promotion._config_bytes(saved, operations=target,
                                                    service_socket=service_socket))]
    need(len(variants) == 1, "CONFIG_CHANGED")
    desired = promotion._config_bytes(saved, operations=target,
                                      service_socket=variants[0])
    if current != desired:
        promotion._replace_group_file(promotion.LOCAL_CONFIG, current, desired,
                                      grp.getgrnam(promotion.LOCAL_USER).gr_gid)
    restarted_at = int(time.time())
    # Several operator toggles may happen within systemd's default start-limit
    # window. Clear only this local Agent's counter before the deliberate restart.
    _cmd("systemctl", "reset-failed", promotion.LOCAL_UNIT.name)
    _cmd("systemctl", "restart", promotion.LOCAL_UNIT.name)
    promotion._wait_local_metric(saved["server_id"], since=restarted_at)
    if not target["terminal"]:
        for name in reversed(promotion.LOCAL_TERMINAL_UNITS):
            if (SYSTEMD / name).exists():
                if promotion._unit_active(name):
                    _cmd("systemctl", "stop", name)
                if promotion._unit_enabled(name):
                    _cmd("systemctl", "disable", name)
        need(not any(promotion._unit_active(name) or promotion._unit_enabled(name)
                     for name in promotion.LOCAL_TERMINAL_UNITS),
             "TERMINAL_STOP")
    if target["files"]:
        _ensure_workspace()


def _complete(saved: dict, baseline: dict, previous: dict, target: dict) -> None:
    try:
        _apply_target(saved, previous, target)
        need(promotion.capture_external() == baseline, "EXTERNAL_CHANGED")
        promotion._save_private(promotion.LOCAL_OPERATIONS, target)
        promotion.LOCAL_OPERATIONS_PENDING.unlink()
        state = promotion.inspect()
        need(state.get("phase") == "activated" and state.get("external_agent_preserved") is True,
             "POSTCHECK")
    except BaseException as original:
        code = str(original) if isinstance(original, Refused) else type(original).__name__.upper()
        print("SG_LOCAL_OPERATIONS_STAGE:APPLY_FAILED:" + code, file=sys.stderr)
        # Return the Agent and PTY broker to the last committed local state.
        # An interruption during rollback retains the pending file for recovery.
        try:
            _apply_target(saved, target, previous)
            promotion._save_private(promotion.LOCAL_OPERATIONS, previous)
            if promotion.LOCAL_OPERATIONS_PENDING.exists():
                promotion.LOCAL_OPERATIONS_PENDING.unlink()
            need(promotion.inspect().get("phase") == "activated" and
                 promotion.capture_external() == baseline, "ROLLBACK_POSTCHECK")
        except BaseException as exc:
            code = str(exc) if isinstance(exc, Refused) else type(exc).__name__.upper()
            print("SG_LOCAL_OPERATIONS_STAGE:ROLLBACK_FAILED:" + code, file=sys.stderr)
            raise Refused("ROLLBACK_NEEDS_RECOVERY") from exc
        raise Refused("ROLLED_BACK")


def _recover() -> None:
    pending = _pending()
    if pending is None:
        return
    saved, baseline = _preflight(pending=True)
    previous, target = pending["previous"], pending["target"]
    _apply_target(saved, target, previous)
    promotion._save_private(promotion.LOCAL_OPERATIONS, previous)
    promotion.LOCAL_OPERATIONS_PENDING.unlink()
    need(promotion.inspect().get("phase") == "activated" and
         promotion.capture_external() == baseline, "RECOVERY_POSTCHECK")


def preview() -> dict:
    pending = _pending()
    if pending is not None:
        return {"protocol": 1, "phase": "recovery_required", "current": pending["previous"],
                "requested": pending["target"], "external_agent_preserved": None,
                "state_revision": None}
    saved, baseline = _preflight()
    current = _ready()
    return {"protocol": 1, "phase": "ready", "current": current,
            "local_server_id": saved["server_id"],
            "external_agent_preserved": promotion.capture_external() == baseline,
            "state_revision": _revision(saved, current)}


def change(feature: str, enabled: bool, *, expected_state: str | None = None) -> dict:
    need(feature in FEATURES, "FEATURE")
    need(expected_state is None or (isinstance(expected_state, str) and
         STATE_REVISION.fullmatch(expected_state) is not None), "EXPECTED_STATE")
    with contextlib.ExitStack() as locks:
        locks.callback(os.close, _lock())
        locks.callback(os.close, promotion._service_setup_lock())
        if expected_state is None:
            _recover()
        else:
            need(_pending() is None, "STATE_CHANGED")
        saved, baseline = _preflight()
        previous = _ready()
        if expected_state is not None:
            need(_revision(saved, previous) == expected_state, "STATE_CHANGED")
        target = {**previous, feature: enabled}
        if target != previous:
            promotion._save_private(promotion.LOCAL_OPERATIONS_PENDING,
                                    {"protocol": 1, "previous": previous, "target": target})
            _complete(saved, baseline, previous, target)
        return {"protocol": 1, "phase": "ready", "current": target,
                "local_server_id": saved["server_id"], "external_agent_preserved": True,
                "state_revision": _revision(saved, target)}


def recover() -> dict:
    with contextlib.ExitStack() as locks:
        locks.callback(os.close, _lock())
        locks.callback(os.close, promotion._service_setup_lock())
        _recover()
        return preview()


def main(argv: list[str]) -> int:
    if argv == ["preview"]:
        result = preview()
    elif argv == ["recover"]:
        result = recover()
    elif len(argv) == 2 and argv[0] in ("enable", "disable"):
        result = change(argv[1], argv[0] == "enable")
    elif len(argv) == 4 and argv[0] in ("enable", "disable") and argv[2] == "--expected-state":
        result = change(argv[1], argv[0] == "enable", expected_state=argv[3])
    else:
        raise Refused("ARGS")
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError,
            promotion.PromotionError, Refused) as exc:
        code = str(exc) if isinstance(exc, Refused) else type(exc).__name__.upper()
        print("SG_LOCAL_OPERATIONS_REFUSE:" + code, file=sys.stderr)
        raise SystemExit(40) from None
