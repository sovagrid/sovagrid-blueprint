#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""One fixed systemd worker for a reviewed external-Agent update request.

The Hub backup broker may enqueue and start this unit, but its filesystem
sandbox must not perform the Agent tree exchange. This worker reads one
root-owned request and runs only the installed external_agent_update CLI.
"""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid


sys.dont_write_bytecode = True

OPERATIONS = Path("/var/lib/sovagrid/external-agent-operations")
UPDATE = Path("/opt/sovagrid-src/sovagrid-blueprint/deploy/external_agent_update.py")
SHA = re.compile(r"[0-9a-f]{64}\Z")
ERROR = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
PHASES = frozenset(("accepted", "running", "complete", "failed", "uncertain"))
MAX_DOCUMENT = 1024
MAX_OUTPUT = 4096
APPLY_TIMEOUT = 910


class Refused(RuntimeError):
    """Stable error code. Never include request bytes, paths or credentials."""


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise Refused(code)


def _id(value: str) -> str:
    try:
        _need(isinstance(value, str) and str(uuid.UUID(value)) == value,
              "INVALID_REQUEST")
    except (ValueError, AttributeError):
        raise Refused("INVALID_REQUEST") from None
    return value


def _directory(path: Path, mode: int) -> None:
    try:
        info = path.lstat()
    except OSError:
        raise Refused("UNSAFE_STATE") from None
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
          stat.S_IMODE(info.st_mode) == mode, "UNSAFE_STATE")


def _record_dir(request_id: str) -> Path:
    try:
        parent = OPERATIONS.parent.lstat()
    except OSError:
        raise Refused("UNSAFE_STATE") from None
    _need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and
          parent.st_gid == 0 and not stat.S_IMODE(parent.st_mode) & 0o022,
          "UNSAFE_STATE")
    _directory(OPERATIONS, 0o700)
    path = OPERATIONS / _id(request_id)
    _directory(path, 0o700)
    return path


def _read(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise Refused("UNSAFE_STATE") from None
    try:
        info = os.fstat(descriptor)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
              stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
              0 < info.st_size <= MAX_DOCUMENT, "UNSAFE_STATE")
        raw = os.read(descriptor, MAX_DOCUMENT + 1)
        _need(len(raw) == info.st_size, "UNSAFE_STATE")
        return raw
    finally:
        os.close(descriptor)


def _pairs(items):
    value = {}
    for key, item in items:
        _need(key not in value, "UNSAFE_STATE")
        value[key] = item
    return value


def _decode(raw: bytes) -> dict:
    _need(0 < len(raw) <= MAX_DOCUMENT, "UNSAFE_STATE")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeError, ValueError):
        raise Refused("UNSAFE_STATE") from None
    _need(type(value) is dict and
          (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode() == raw,
          "UNSAFE_STATE")
    return value


def _request(path: Path, request_id: str) -> dict:
    value = _decode(_read(path / "request.json"))
    _need(set(value) == {"format", "request_id", "archive_sha256",
                         "current_hub_manifest_sha256", "external_agent_manifest_sha256",
                         "review_sha256"} and type(value["format"]) is int and
          value["format"] == 1 and value["request_id"] == request_id and
          all(isinstance(value[key], str) and SHA.fullmatch(value[key]) is not None
              for key in ("archive_sha256", "current_hub_manifest_sha256",
                          "external_agent_manifest_sha256", "review_sha256")),
          "UNSAFE_STATE")
    return value


def _status(path: Path, request_id: str) -> dict:
    value = _decode(_read(path / "status.json"))
    _need(set(value) == {"format", "request_id", "phase", "created_at", "updated_at",
                         "error"} and type(value["format"]) is int and
          value["format"] == 1 and value["request_id"] == request_id and
          value["phase"] in PHASES and type(value["created_at"]) is int and
          type(value["updated_at"]) is int and
          1 <= value["created_at"] <= value["updated_at"] <= 253402300799 and
          ((value["error"] is None) == (value["phase"] in
            ("accepted", "running", "complete"))) and
          (value["error"] is None or isinstance(value["error"], str) and
           ERROR.fullmatch(value["error"]) is not None), "UNSAFE_STATE")
    return value


def _sync(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_status(path: Path, value: dict) -> None:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    _need(len(raw) <= MAX_DOCUMENT, "UNSAFE_STATE")
    temporary = path / (".status." + os.urandom(8).hex())
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path / "status.json")
        _sync(path)
    finally:
        temporary.unlink(missing_ok=True)


def _transition(path: Path, request_id: str, expected: frozenset[str], phase: str,
                error: str | None = None) -> dict:
    descriptor = os.open(path / "status.lock", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
              stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
              "UNSAFE_STATE")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        value = _status(path, request_id)
        _need(value["phase"] in expected, "OPERATION_ALREADY_STARTED")
        value["phase"] = phase
        value["updated_at"] = max(value["updated_at"], int(time.time()))
        value["error"] = error
        _write_status(path, value)
        return value
    finally:
        os.close(descriptor)


def _apply(request_id: str) -> int:
    _need(sys.platform.startswith("linux") and os.geteuid() == 0 and os.getegid() == 0,
          "ROOT_LINUX")
    path = _record_dir(request_id)
    request = _request(path, request_id)
    # An uncertain start may already have entered this worker. Never replay
    # the same request after a timeout, crash, or operator systemctl restart.
    _transition(path, request_id, frozenset(("accepted",)), "running")
    command = ["/usr/bin/python3", "-B", "-I", str(UPDATE), "apply",
               request["archive_sha256"], request["current_hub_manifest_sha256"],
               request["external_agent_manifest_sha256"], request["review_sha256"]]
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=APPLY_TIMEOUT, check=False,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        _transition(path, request_id, frozenset(("running",)), "uncertain", "APPLY_UNCERTAIN")
        return 40
    if result.returncode == 0:
        try:
            _need(0 < len(result.stdout) <= MAX_OUTPUT, "APPLY_UNCERTAIN")
            value = _decode(result.stdout)
            _need(set(value) == {"protocol", "applied", "external_agent_manifest_sha256",
                                 "review_sha256"} and type(value["protocol"]) is int and
                  value["protocol"] == 1 and value["applied"] is True and
                  value["external_agent_manifest_sha256"] ==
                  request["current_hub_manifest_sha256"] and
                  value["review_sha256"] == request["review_sha256"],
                  "APPLY_UNCERTAIN")
        except Refused:
            _transition(path, request_id, frozenset(("running",)), "uncertain", "APPLY_UNCERTAIN")
            return 40
        _transition(path, request_id, frozenset(("running",)), "complete")
        return 0
    refusal = re.fullmatch(rb"SG_EXTERNAL_AGENT_UPDATE_REFUSE:([A-Z][A-Z0-9_]{1,63})\n",
                           result.stderr[:MAX_OUTPUT])
    code = refusal.group(1).decode("ascii") if refusal and len(result.stderr) <= MAX_OUTPUT else "APPLY_UNCERTAIN"
    # Only checks completed before the transaction writer can touch the Agent
    # tree are definitely failed. A generic rollback refusal can also follow
    # a durable commit with a later health failure, so its outcome is unknown.
    phase = "failed" if code in {"LOCK_UNAVAILABLE", "LOCK_UNSAFE",
                                  "REVIEW_CHANGED", "PROMOTION_CHANGED",
                                  "CANDIDATE_NOT_LOCAL_HUB", "TRIAL_CAPABILITY_MISSING",
                                  "EXTERNAL_CHANGED"} else "uncertain"
    # The updater prints only a fixed uppercase refusal code on stderr.
    # Preserve that code even when the outcome is uncertain, so status remains
    # useful without exposing command output, paths, credentials or journals.
    _transition(path, request_id, frozenset(("running",)), phase, code)
    return 40


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2 or args[0] != "apply":
        return 2
    try:
        return _apply(_id(args[1]))
    except Refused as exc:
        print("SG_EXTERNAL_AGENT_OPERATION_REFUSE:" + str(exc), file=sys.stderr)
        return 40
    except Exception:
        print("SG_EXTERNAL_AGENT_OPERATION_REFUSE:UNSAFE_STATE", file=sys.stderr)
        return 40


if __name__ == "__main__":
    raise SystemExit(main())
