# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Explicit, resumable archival of fully rolled-back restore metadata."""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid


PROTOCOL = "sovagrid-portable-restore-retry-v1"
MAX_FILE = 8 * 1024**2


def _read(core, fd, name, uid, gid, maximum=MAX_FILE):
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    except FileNotFoundError:
        return None
    try:
        raw, _fingerprint = core._read_private_fd(descriptor, maximum=maximum, uid=uid, gid=gid)
        info = os.fstat(descriptor)
        return raw, {"device": info.st_dev, "inode": info.st_ino,
                     "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    finally:
        os.close(descriptor)


def _save(core, fd, name, value, uid, gid, *, initial):
    temporary = name + "." + uuid.uuid4().hex + ".tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        os.fchmod(descriptor, 0o600)
        core._private(os.fstat(descriptor), directory=False, uid=uid, gid=gid)
        core._write(descriptor, core._canonical(value) + b"\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        if initial:
            core._rename_noreplace(fd, temporary, name)
        else:
            os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass


def _validate(core, value, identity, expected):
    if (not isinstance(value, dict) or set(value) != {"protocol", "id", "terminal_sha256", "nonce", "phase", "files"} or
            value["protocol"] != PROTOCOL or value["id"] != identity or value["terminal_sha256"] != expected or
            not isinstance(expected, str) or core.SHA.fullmatch(expected) is None or
            not isinstance(value["nonce"], str) or core.ID.fullmatch(value["nonce"]) is None or
            value["phase"] not in ("archiving", "complete") or not isinstance(value["files"], list) or
            not 1 <= len(value["files"]) <= 3):
        raise core.Refused("INVALID_RESTORE_RETRY")
    sources = {"journal": ".apply-" + identity + ".json", "plan": ".apply-plan-" + identity + ".json",
               "compose": ".apply-compose-" + identity + ".json"}
    kinds = []
    for item in value["files"]:
        if not isinstance(item, dict) or set(item) != {"kind", "source", "destination", "proof"}:
            raise core.Refused("INVALID_RESTORE_RETRY")
        kind = item["kind"]
        proof = item["proof"]
        if (kind not in sources or item["source"] != sources[kind] or
                item["destination"] != ".history-" + identity + "-" + value["nonce"] + "-" + kind + ".json" or
                not isinstance(proof, dict) or set(proof) != {"device", "inode", "bytes", "sha256"} or
                any(type(proof[key]) is not int or proof[key] < 0 for key in ("device", "inode", "bytes")) or
                proof["bytes"] > MAX_FILE or not isinstance(proof["sha256"], str) or
                core.SHA.fullmatch(proof["sha256"]) is None):
            raise core.Refused("INVALID_RESTORE_RETRY")
        kinds.append(kind)
    if len(set(kinds)) != len(kinds) or "journal" not in kinds:
        raise core.Refused("INVALID_RESTORE_RETRY")


def inspect(restore, core, identity):
    """Read a partial retry even after its live journal has been archived."""
    restore._require_root()
    identity = core._id(identity)
    try:
        fd = restore.backup._safe_open(restore.STAGING, directory=True)
    except FileNotFoundError:
        return None
    try:
        saved = _read(core, fd, ".retry-" + identity + ".json",
                      restore.backup.ROOT_UID, restore.backup.ROOT_GID, 16384)
        if saved is None:
            return None
        value = json.loads(saved[0], object_pairs_hook=core._unique)
        _validate(core, value, identity, value.get("terminal_sha256") if isinstance(value, dict) else None)
        return {"phase": value["phase"], "terminal_sha256": value["terminal_sha256"],
                "history_id": value["nonce"]}
    finally:
        os.close(fd)


def retry(restore, core, identity, expected):
    restore._require_root()
    identity = core._id(identity)
    if not isinstance(expected, str) or core.SHA.fullmatch(expected) is None:
        raise core.Refused("INVALID_RESTORE_REVIEW")
    with core.transaction_locks(restore) as (fd, _exporter):
        uid, gid = restore.backup.ROOT_UID, restore.backup.ROOT_GID
        journal = core.Journal(fd, identity, uid=uid, gid=gid)
        live = journal.read()
        name = ".retry-" + identity + ".json"
        saved = _read(core, fd, name, uid, gid, 16384)
        previous = None if saved is None else json.loads(saved[0], object_pairs_hook=core._unique)
        if previous is not None:
            _validate(core, previous, identity,
                      previous.get("terminal_sha256") if isinstance(previous, dict) else None)
        if live is not None:
            if (live["phase"] != "rolled_back" or
                    hashlib.sha256(core._canonical(live)).hexdigest() != expected):
                raise core.Refused("RESTORE_RETRY_NOT_TERMINAL")
        elif previous is None or previous["terminal_sha256"] != expected:
            raise core.Refused("RESTORE_NOT_FOUND")
        # Recovery may have durably finished just before unlinking its fence.
        if live is not None:
            core.Fence(restore.backup.ROOT, uid=uid, gid=gid).release(identity, live["bindings"])
        else:
            core.Fence(restore.backup.ROOT, uid=uid, gid=gid).require_absent()
        clean = restore.portable_clean_plan(identity)
        if not clean["target_empty"] or clean.get("target_ready") is not True:
            raise core.Refused("RESTORE_TARGET_NOT_READY")
        # Never archive an operation while another restore is unfinished.
        for entry in os.listdir(fd):
            match = re.fullmatch(r"\.apply-([0-9a-f]{32})\.json", entry)
            if match and match[1] != identity:
                other = core.Journal(fd, match[1], uid=uid, gid=gid).read()
                if other["phase"] not in ("committed", "rolled_back"):
                    raise core.Refused("OTHER_RESTORE_RECOVERY_REQUIRED")
        continuing = previous is not None and previous["phase"] == "archiving"
        if continuing:
            if previous["terminal_sha256"] != expected:
                raise core.Refused("STALE_RESTORE_REVIEW")
            value = previous
        elif live is None:
            value = previous
        else:
            value = {"protocol": PROTOCOL, "id": identity, "terminal_sha256": expected,
                     "nonce": uuid.uuid4().hex, "phase": "archiving", "files": []}
            for kind, source in (("journal", journal.name), ("plan", ".apply-plan-" + identity + ".json"),
                                 ("compose", ".apply-compose-" + identity + ".json")):
                record = _read(core, fd, source, uid, gid)
                if record is not None:
                    value["files"].append({"kind": kind, "source": source,
                        "destination": ".history-" + identity + "-" + value["nonce"] + "-" + kind + ".json",
                        "proof": record[1]})
            _validate(core, value, identity, expected)
            _save(core, fd, name, value, uid, gid, initial=previous is None)
        for item in value["files"]:
            source = _read(core, fd, item["source"], uid, gid)
            destination = _read(core, fd, item["destination"], uid, gid)
            if source is not None and destination is None and source[1] == item["proof"]:
                core._rename_noreplace(fd, item["source"], item["destination"])
                os.fsync(fd)
            elif source is not None or destination is None or destination[1] != item["proof"]:
                raise core.Refused("RESTORE_RETRY_CHANGED")
        value["phase"] = "complete"
        _save(core, fd, name, value, uid, gid, initial=False)
        return {"ok": True, "protocol": PROTOCOL, "id": identity, "retry_ready": True,
                "terminal_sha256": expected, "history_id": value["nonce"], "requires_fresh_preview": True}
