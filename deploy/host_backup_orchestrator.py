#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Journaled, root-only stop/snapshot/restart of one managed SovaGrid host.

The SSH command only creates an operation journal and starts an independent
systemd worker. Losing SSH never repeats a snapshot. An interrupted worker is
recovered explicitly, and recovery only restarts the previously active stack.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any
import uuid
import urllib.request


sys.dont_write_bytecode = True


def _sibling(filename: str, name: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise RuntimeError("SovaGrid backup source unavailable")
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves forward annotations through sys.modules while the
    # sibling executes (including on Ubuntu's Python 3.12).
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


backup = _sibling("host_backup.py", "_sovagrid_host_backup")
update = _sibling("remote_update_worker.py", "_sovagrid_backup_compose")

PROTOCOL = "sovagrid-host-backup-operation-v1"
DEFAULT_STATE_DIR = Path("/var/lib/sovagrid-host-backup-operations")
STATE_DIR = DEFAULT_STATE_DIR
SOURCE = Path("/opt/sovagrid-src")
SCRIPT = SOURCE / "sovagrid-blueprint/deploy/host_backup_orchestrator.py"
REQUEST = re.compile(r"[0-9a-f]{32}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
PHASES = frozenset(("accepted", "stopping", "archiving", "restarting",
                    "complete", "recovery_requested", "recovered", "failed",
                    "recovery_required"))
FINAL = frozenset(("complete", "recovered", "failed"))
MAX_OPERATIONS = 10_000
LIST_LIMIT = 100
MAX_STATE = 8192
MAX_COMMAND_SECONDS = 120
TRANSIENT_WRITERS = frozenset((
    "sovagrid-vpn-status.service", "sovagrid-auto-update.service",
    "sovagrid-release-feed.service", "sovagrid-container-inventory.service",
    "sovagrid-container-inventory-local.service",
    "sovagrid-hub-only-update.service",
))
PROMOTION_LOCK = Path("/run/sovagrid-promotion.lock")
RUNNING_STACKS = frozenset(((), backup.COMPOSE_SERVICES[:2], backup.COMPOSE_SERVICES))
START_ORDER = ("hub", "ssh-gateway", "web")


class Refused(RuntimeError):
    """Stable public error code without subprocess output or secret paths."""


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require_root() -> None:
    if os.geteuid() != 0:
        raise Refused("ROOT_REQUIRED")


def _id(value: str) -> str:
    if not isinstance(value, str) or REQUEST.fullmatch(value) is None:
        raise Refused("INVALID_ID")
    return value


def _hash(value: str) -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise Refused("INVALID_HASH")
    return value


def _state_dir(*, create: bool) -> Path:
    if create and not os.path.lexists(STATE_DIR):
        if STATE_DIR == DEFAULT_STATE_DIR:
            parent_fd = backup._safe_open(STATE_DIR.parent, directory=True)
            os.close(parent_fd)
        STATE_DIR.mkdir(mode=0o700)
    try:
        info = STATE_DIR.lstat()
    except FileNotFoundError as exc:
        raise Refused("NOT_FOUND") from exc
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
            info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise Refused("UNSAFE_STATE")
    if STATE_DIR == DEFAULT_STATE_DIR:
        fd = backup._safe_open(STATE_DIR, directory=True)
        os.close(fd)
    return STATE_DIR


def _sync(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _private_read(path: Path, *, maximum: int = MAX_STATE) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError as exc:
        raise Refused("NOT_FOUND") from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != 0o600 or
                info.st_nlink != 1 or not 0 < info.st_size <= maximum):
            raise Refused("UNSAFE_STATE")
        raw = os.read(fd, maximum + 1)
        if len(raw) != info.st_size:
            raise Refused("UNSAFE_STATE")
        return raw
    finally:
        os.close(fd)


def _private_write(path: Path, raw: bytes) -> None:
    if not 0 < len(raw) <= MAX_STATE:
        raise Refused("UNSAFE_STATE")
    directory = _state_dir(create=True)
    temporary = directory / ("." + path.name + "." + os.urandom(8).hex() + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync(directory)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def _record_path(identity: str) -> Path:
    return _state_dir(create=False) / (_id(identity) + ".json")


def _record(identity: str) -> dict[str, Any]:
    try:
        value = json.loads(_private_read(_record_path(identity)))
    except (UnicodeError, ValueError) as exc:
        raise Refused("INVALID_STATE") from exc
    keys = {"protocol", "request_id", "phase", "created_at", "updated_at",
            "expected_manifest_sha256", "layout", "active_units", "running_containers",
            "container_ids", "unit_hashes", "archive_id", "archive", "error"}
    if (not isinstance(value, dict) or set(value) != keys or value["protocol"] != PROTOCOL or
            value["request_id"] != identity or not isinstance(value["phase"], str) or
            value["phase"] not in PHASES or
            not isinstance(value["created_at"], str) or len(value["created_at"]) > 40 or
            not isinstance(value["updated_at"], str) or len(value["updated_at"]) > 40 or
            not isinstance(value["expected_manifest_sha256"], str) or
            SHA.fullmatch(value["expected_manifest_sha256"]) is None or
            value["layout"] not in ("full", "hub-only") or
            not isinstance(value["active_units"], list) or
            not isinstance(value["running_containers"], list) or
            any(not isinstance(item, str) for item in value["active_units"]) or
            any(not isinstance(item, str) for item in value["running_containers"]) or
            not isinstance(value["container_ids"], dict) or
            not isinstance(value["unit_hashes"], dict) or
            not isinstance(value["archive_id"], str) or
            REQUEST.fullmatch(value["archive_id"]) is None or
            set(value["container_ids"]) != set(value["running_containers"]) or
            any(not isinstance(item, str) or SHA.fullmatch(item) is None
                for item in value["container_ids"].values()) or
            set(value["unit_hashes"]) != set(value["active_units"]) or
            any(not isinstance(item, str) or SHA.fullmatch(item) is None
                for item in value["unit_hashes"].values()) or
            len(value["active_units"]) > 32 or
            len(value["running_containers"]) > len(backup.COMPOSE_SERVICES) or
            len(set(value["active_units"])) != len(value["active_units"]) or
            len(set(value["running_containers"])) != len(value["running_containers"]) or
            any(not isinstance(item, str) or item not in backup.WRITERS[value["layout"]] |
                (backup.AMNEZIA_WRITERS if value["layout"] == "full" else frozenset())
                for item in value["active_units"]) or
            any(not isinstance(item, str) or item not in backup.COMPOSE_SERVICES
                for item in value["running_containers"]) or
            tuple(value["running_containers"]) not in RUNNING_STACKS or
            (value["archive"] is not None and (not _valid_archive(value["archive"]) or
             value["archive"]["id"] != value["archive_id"])) or
            (value["error"] is not None and (not isinstance(value["error"], str) or
             re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", value["error"]) is None))):
        raise Refused("INVALID_STATE")
    return value


def _valid_archive(value: Any) -> bool:
    return (isinstance(value, dict) and set(value) == {"id", "created_at", "layout", "bytes", "files"} and
            isinstance(value["id"], str) and REQUEST.fullmatch(value["id"]) is not None and
            isinstance(value["created_at"], str) and len(value["created_at"]) <= 40 and
            value["layout"] in ("full", "hub-only") and type(value["bytes"]) is int and
            0 < value["bytes"] <= backup.MAX_BYTES and type(value["files"]) is int and
            0 < value["files"] <= backup.MAX_FILES)


def _write_record(value: dict[str, Any]) -> None:
    _private_write(_record_path(value["request_id"]),
                   (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))


def _phase(value: dict[str, Any], phase: str, *, error: str | None = None,
           archive: dict[str, Any] | None = None) -> None:
    if phase not in PHASES:
        raise Refused("INVALID_STATE")
    value["phase"] = phase
    value["updated_at"] = _utc()
    value["error"] = error
    if archive is not None:
        value["archive"] = archive
    _write_record(value)


def _public(value: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, "protocol": PROTOCOL, "request_id": value["request_id"],
            "phase": value["phase"], "archive": value["archive"],
            "error": value["error"], "created_at": value["created_at"]}


@contextmanager
def _global_lock(*, wait: bool = False):
    directory = _state_dir(create=True)
    target = directory / ".lock"
    fd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != 0o600 or
                info.st_nlink != 1):
            raise Refused("UNSAFE_STATE")
        deadline = time.monotonic() + 30 if wait else time.monotonic()
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise Refused("BUSY") from exc
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)


@contextmanager
def _promotion_lock(identity: str):
    """Serialize only promoted-Hub snapshots with local collector changes."""
    if _record(identity)["layout"] != "hub-only":
        yield
        return
    if PROMOTION_LOCK.is_symlink():
        raise Refused("BUSY")
    fd = os.open(PROMOTION_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise Refused("BUSY")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _active() -> str | None:
    target = _state_dir(create=True) / ".active"
    if not os.path.lexists(target):
        return None
    try:
        raw = _private_read(target, maximum=33).decode("ascii")
    except UnicodeError as exc:
        raise Refused("INVALID_STATE") from exc
    if not raw.endswith("\n") or REQUEST.fullmatch(raw[:-1]) is None:
        raise Refused("INVALID_STATE")
    return raw[:-1]


def _set_active(identity: str) -> None:
    _private_write(_state_dir(create=True) / ".active", (_id(identity) + "\n").encode("ascii"))


def _clear_active(identity: str) -> None:
    if _active() == identity:
        (_state_dir(create=False) / ".active").unlink()
        _sync(_state_dir(create=False))


def _capture(args: list[str], *, timeout: int = 10) -> str:
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused("COMMAND_FAILED") from exc
    if result.returncode or len(result.stdout) > 4096:
        raise Refused("COMMAND_FAILED")
    return result.stdout.strip()


def _command(args: list[str], *, timeout: int = MAX_COMMAND_SECONDS) -> None:
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused("COMMAND_FAILED") from exc
    if result.returncode:
        raise Refused("COMMAND_FAILED")


def _container_ids(services: list[str]) -> dict[str, str]:
    result = {}
    for service in services:
        ids = _capture(["docker", "ps", "--quiet", "--filter",
                        "label=com.docker.compose.project=sovagrid", "--filter",
                        "label=com.docker.compose.service=" + service]).splitlines()
        if len(ids) != 1:
            raise Refused("CONTAINER_CHANGED")
        identity = _capture(["docker", "inspect", "--format", "{{.Id}}", ids[0]])
        if SHA.fullmatch(identity) is None:
            raise Refused("CONTAINER_CHANGED")
        result[service] = identity
    return result


def _unit_hashes(units: list[str]) -> dict[str, str]:
    result = {}
    for unit in units:
        path = Path("/etc/systemd/system") / unit
        fd = backup._safe_open(path)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or
                    stat.S_IMODE(before.st_mode) != 0o644 or before.st_nlink != 1 or
                    before.st_size > 65536):
                raise Refused("UNMANAGED_UNIT")
            raw = os.read(fd, 65537)
            if len(raw) != before.st_size or os.fstat(fd) != before:
                raise Refused("UNMANAGED_UNIT")
            result[unit] = hashlib.sha256(raw).hexdigest()
        finally:
            os.close(fd)
    return result


def _compose_stop(services: list[str]) -> None:
    if not services:
        return
    args, env = update.compose_args(SOURCE, allow_missing_backup_overlay=True)
    try:
        result = subprocess.run(args + ["stop", *services], env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused("STOP_FAILED") from exc
    if result.returncode:
        raise Refused("STOP_FAILED")


def _stop(value: dict[str, Any]) -> None:
    units = value["active_units"]
    for suffix in (".timer", ".socket", ".service"):
        selected = [unit for unit in units if unit.endswith(suffix)]
        if selected:
            _command(["systemctl", "stop", *selected], timeout=40)
    _compose_stop(value["running_containers"])
    current = backup.plan()
    if not current["offline_ready"]:
        raise Refused("STOP_FAILED")


def _restart(value: dict[str, Any]) -> None:
    if backup._source_manifest() != value["expected_manifest_sha256"] or (
            _unit_hashes(value["active_units"]) != value["unit_hashes"]):
        raise Refused("STATE_CHANGED")
    # Inspect all compose services before starting any container; a replacement
    # instance must never be joined with the archived instance.
    before = backup.plan()
    if any(service not in value["running_containers"]
           for service in before["running_containers"]):
        raise Refused("CONTAINER_CHANGED")
    pending_start = []
    for service in START_ORDER:
        if service in value["running_containers"]:
            identity = value["container_ids"][service]
            current = _capture(["docker", "inspect", "--format", "{{.Id}}", identity])
            if current != identity:
                raise Refused("CONTAINER_CHANGED")
            running = _capture(["docker", "inspect", "--format", "{{.State.Running}}", identity])
            if running == "false":
                others = _capture(["docker", "ps", "--quiet", "--filter",
                                   "label=com.docker.compose.project=sovagrid", "--filter",
                                   "label=com.docker.compose.service=" + service])
                if others:
                    raise Refused("CONTAINER_CHANGED")
                pending_start.append(identity)
            elif running != "true":
                raise Refused("CONTAINER_CHANGED")
    for identity in pending_start:
        _command(["docker", "start", identity], timeout=90)
    for suffix in (".service", ".socket", ".timer"):
        selected = [unit for unit in value["active_units"] if unit.endswith(suffix)]
        if selected:
            _command(["systemctl", "start", *selected], timeout=60)
    current = backup.plan()
    if (current["running_containers"] != value["running_containers"] or
            _container_ids(value["running_containers"]) != value["container_ids"]):
        raise Refused("RESTART_INCOMPLETE")
    for unit in value["active_units"]:
        try:
            checked = subprocess.run(["systemctl", "is-active", "--quiet", unit],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Refused("RESTART_INCOMPLETE") from exc
        if checked.returncode:
            raise Refused("RESTART_INCOMPLETE")
    _ready(value)


def _ready(value: dict[str, Any]) -> None:
    if tuple(value["running_containers"]) not in (
            backup.COMPOSE_SERVICES[:2], backup.COMPOSE_SERVICES):
        return
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        try:
            health = _capture(["docker", "inspect", "--format", "{{.State.Health.Status}}",
                               value["container_ids"]["hub"]], timeout=5)
            gateway_healthy = True
            if "ssh-gateway" in value["running_containers"]:
                gateway_healthy = (_capture(["docker", "inspect", "--format",
                    "{{.State.Health.Status}}", value["container_ids"]["ssh-gateway"]],
                    timeout=5) == "healthy")
            if health == "healthy" and gateway_healthy:
                with opener.open("http://127.0.0.1:8766/healthz", timeout=3) as response:
                    if response.status == 200:
                        return
        except (Refused, OSError, TimeoutError):
            pass
        time.sleep(2)
    raise Refused("HUB_UNHEALTHY")


def _reconcile_archive(value: dict[str, Any]) -> dict[str, Any] | None:
    """Find the one pre-pinned archive; remove only its incomplete own files."""
    if not os.path.lexists(backup.OUTPUT):
        return None
    output = backup._output(create=False)
    identity = value["archive_id"]
    archive = output / (identity + ".tar.gz")
    manifest = output / (identity + ".manifest.json")
    partials = (output / ("." + identity + ".tar.gz.tmp"),
                output / ("." + identity + ".manifest.json.tmp"))
    for item in (*partials, archive, manifest):
        if not os.path.lexists(item):
            continue
        info = item.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_gid != os.getegid() or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise Refused("UNSAFE_ARCHIVE")
    for item in partials:
        if os.path.lexists(item):
            item.unlink()
    if os.path.lexists(archive) != os.path.lexists(manifest):
        archive.unlink(missing_ok=True)
        manifest.unlink(missing_ok=True)
        backup._sync(output)
        return None
    if not os.path.lexists(archive):
        backup._sync(output)
        return None
    backup._sync(output)
    return backup.verify(identity)["archive"]


def _worker(identity: str, *, recovery: bool) -> None:
    with _global_lock(wait=True), _promotion_lock(identity):
        value = _record(identity)
        if _active() != identity or (recovery and value["phase"] != "recovery_requested") or (
                not recovery and value["phase"] != "accepted"):
            raise Refused("INVALID_STATE")
        try:
            locks = backup._locks()
            locks.__enter__()
        except backup.Refused:
            _phase(value, "recovery_required" if recovery else "failed", error="BUSY")
            if not recovery:
                _clear_active(identity)
            return
        try:
            if recovery:
                try:
                    _phase(value, "restarting")
                except Exception:
                    pass  # Try to restore services even if journal storage failed.
                archive_error = None
                try:
                    value["archive"] = _reconcile_archive(value)
                except Exception:
                    archive_error = "ARCHIVE_UNSAFE"
                try:
                    _restart(value)
                except Exception:
                    _phase(value, "recovery_required", error="RECOVERY_FAILED")
                    return
                _phase(value, "recovered", error=archive_error or "INTERRUPTED",
                       archive=value["archive"])
                _clear_active(identity)
                return
            if backup._source_manifest() != value["expected_manifest_sha256"]:
                _phase(value, "failed", error="SOURCE_CHANGED")
                _clear_active(identity)
                return
            current = backup.plan()
            if (current["layout"] != value["layout"] or
                    current["active_units"] != value["active_units"] or
                    current["running_containers"] != value["running_containers"] or
                    _container_ids(value["running_containers"]) != value["container_ids"] or
                    _unit_hashes(value["active_units"]) != value["unit_hashes"]):
                _phase(value, "failed", error="STATE_CHANGED")
                _clear_active(identity)
                return
            error = None
            try:
                _phase(value, "stopping")
                _stop(value)
                _phase(value, "archiving")
                result = backup._create_locked(identity=value["archive_id"])
                if not isinstance(result, dict) or not _valid_archive(result.get("archive")):
                    raise Refused("ARCHIVE_FAILED")
                value["archive"] = result["archive"]
            except Exception:
                error = "ARCHIVE_FAILED"
            try:
                _phase(value, "restarting", error=error)
            except Exception:
                # Journal I/O must never suppress a best-effort restart.
                error = "JOURNAL_FAILED"
            try:
                if value["archive"] is None:
                    value["archive"] = _reconcile_archive(value)
            except Exception:
                error = "ARCHIVE_UNSAFE"
            try:
                _restart(value)
            except Exception:
                _phase(value, "recovery_required", error="RESTART_INCOMPLETE",
                       archive=value["archive"])
                return
            _phase(value, "complete" if error is None else "failed", error=error,
                   archive=value["archive"])
            _clear_active(identity)
        finally:
            locks.__exit__(None, None, None)


def _spawn(action: str, identity: str) -> None:
    unit = ("sg-host-backup-recover-" if action == "recover-run" else
            "sg-host-backup-") + identity
    args = ["systemd-run", "--quiet", "--collect", "--unit=" + unit,
            "--property=Type=exec", "--property=RuntimeMaxSec=900",
            "/usr/bin/python3", "-I", str(SCRIPT), action, identity]
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused("SPAWN_UNCERTAIN") from exc
    if result.returncode:
        raise Refused("SPAWN_FAILED")


def start(identity: str, expected_manifest: str) -> dict[str, Any]:
    _require_root()
    identity, expected_manifest = _id(identity), _hash(expected_manifest)
    with _global_lock():
        active = _active()
        if active is not None:
            previous = _record(active)
            if previous["phase"] in FINAL:
                _clear_active(active)
            elif active != identity:
                raise Refused("BUSY")
        if (_state_dir(create=True) / (identity + ".json")).exists():
            value = _record(identity)
            if value["expected_manifest_sha256"] != expected_manifest:
                raise Refused("ID_CONFLICT")
            return _public(value)
        if len(list(_state_dir(create=True).glob("*.json"))) >= MAX_OPERATIONS:
            raise Refused("OPERATION_LIMIT")
        if backup._source_manifest() != expected_manifest:
            raise Refused("SOURCE_CHANGED")
        plan = backup.plan()
        containers = plan["running_containers"]
        if any(unit in TRANSIENT_WRITERS for unit in plan["active_units"]):
            raise Refused("BUSY")
        if tuple(containers) not in RUNNING_STACKS:
            raise Refused("DEGRADED_CONTAINERS")
        backup.list_archives()  # Refuse incomplete or foreign files before downtime.
        value = {"protocol": PROTOCOL, "request_id": identity,
                 "phase": "accepted", "created_at": _utc(), "updated_at": _utc(),
                 "expected_manifest_sha256": expected_manifest,
                 "layout": plan["layout"], "active_units": plan["active_units"],
                 "running_containers": containers, "container_ids": _container_ids(containers),
                 "unit_hashes": _unit_hashes(plan["active_units"]),
                 "archive_id": uuid.uuid4().hex,
                 "archive": None, "error": None}
        _write_record(value)
        _set_active(identity)
        try:
            _spawn("run", identity)
        except Refused as exc:
            if str(exc) == "SPAWN_FAILED":
                _phase(value, "failed", error="SPAWN_FAILED")
                _clear_active(identity)
            else:
                _phase(value, "accepted", error="SPAWN_UNCERTAIN")
        return _public(value)


def status(identity: str) -> dict[str, Any]:
    _require_root()
    return _public(_record(_id(identity)))


def list_operations() -> dict[str, Any]:
    _require_root()
    if not os.path.lexists(STATE_DIR):
        return {"ok": True, "protocol": PROTOCOL, "operations": []}
    directory = _state_dir(create=False)
    names = sorted(item.name for item in directory.iterdir() if item.name.endswith(".json"))
    if len(names) > MAX_OPERATIONS or any(REQUEST.fullmatch(name[:-5]) is None
                                          for name in names):
        raise Refused("INVALID_STATE")
    records = [_public(_record(name[:-5])) for name in names]
    records.sort(key=lambda item: (item["created_at"], item["request_id"]), reverse=True)
    return {"ok": True, "protocol": PROTOCOL, "operations": records[:LIST_LIMIT]}


def recover(identity: str) -> dict[str, Any]:
    _require_root()
    identity = _id(identity)
    with _global_lock():
        value = _record(identity)
        if value["phase"] in FINAL:
            return _public(value)
        if _active() != identity:
            raise Refused("INVALID_STATE")
        units = ["sg-host-backup-" + identity + ".service",
                 "sg-host-backup-recover-" + identity + ".service"]
        for unit in units:
            try:
                active = subprocess.run(["systemctl", "is-active", "--quiet", unit],
                                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, timeout=10, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise Refused("STATUS_UNAVAILABLE") from exc
            if active.returncode == 0:
                raise Refused("BUSY")
        if value["phase"] != "recovery_requested":
            _phase(value, "recovery_requested", error="INTERRUPTED")
        try:
            _spawn("recover-run", identity)
        except Refused:
            # The operation remains fenced. Repeating recover can only spawn
            # another recovery worker; it never repeats the archive.
            _phase(value, "recovery_requested", error="SPAWN_UNCERTAIN")
        return _public(value)


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 3 and argv[0] == "start":
            result = start(argv[1], argv[2])
        elif argv == ["list"]:
            result = list_operations()
        elif len(argv) == 2 and argv[0] == "status":
            result = status(argv[1])
        elif len(argv) == 2 and argv[0] == "recover":
            result = recover(argv[1])
        elif len(argv) == 2 and argv[0] in ("run", "recover-run"):
            _require_root()
            _worker(_id(argv[1]), recovery=argv[0] == "recover-run")
            return 0
        else:
            raise Refused("USAGE")
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except (Refused, backup.Refused, OSError, subprocess.TimeoutExpired) as exc:
        code = str(exc) if isinstance(exc, (Refused, backup.Refused)) else "IO_ERROR"
        print(json.dumps({"ok": False, "protocol": PROTOCOL, "error": code},
                         separators=(",", ":")))
        return 40


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
