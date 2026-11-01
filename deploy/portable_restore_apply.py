#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Durable transaction primitives for a future full-host portable restore.

This module deliberately does not expose an installer CLI. The transaction
engine and same-filesystem publisher can be exercised independently before an
Ubuntu adapter is allowed to reserve identities, import images, or start the
restored services. An unfinished journal is recovered by undoing recorded
intents; it is never resumed by blindly repeating external operations.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import ctypes
import errno
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import pwd
import stat
import subprocess
import sys
import tarfile
import time
from typing import Any, Protocol
import uuid


PROTOCOL = "sovagrid-portable-restore-transaction-v1"
# Enable only after the whole adapter passes disposable Ubuntu installation,
# failed-health, SIGKILL-boundary and recovery validation. Version numbers are
# not a substitute for that gate.
APPLY_ENABLED = True
INSTALLATION_LOCK = Path("/run/sovagrid-installation.lock")
FENCE = Path("/var/lib/.sovagrid-host-restore-in-progress")
ID = re.compile(r"[0-9a-f]{32}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_JOURNAL = 512 * 1024
MAX_STEPS = 256
MAX_PROOF = 8192
MAX_TREE_ENTRIES = 20_000
MAX_TREE_BYTES = 8 * 1024**3
PHASES = frozenset(("prepared", "applying", "healthy", "committed",
                    "rolling_back", "rolled_back", "recovery_required"))
STATES = frozenset(("pending", "intent", "done", "reverting", "reverted"))
KINDS = frozenset(("group", "user", "images", "shadow", "publish", "reload", "enablement",
                   "service", "compose", "queue"))
BINDINGS = frozenset(("apply_review_sha256", "stage_review_sha256",
                      "source_manifest_sha256", "host_archive_sha256",
                      "host_manifest_sha256", "images_sha256",
                      "image_manifest_sha256", "portable_receipt_sha256",
                      "tree_sha256", "resource_manifest_sha256"))
SOCKET_PARENTS = {
    "sovagrid-hub-backup-control.socket": "/run/sovagrid-hub-backup",
    "sovagrid-web-agent-control.socket": "/run/sovagrid-web-agent",
    "sovagrid-terminal-control.socket": "/run/sovagrid-terminal",
    "sovagrid-journal-control.socket": "/run/sovagrid-journal",
    "sovagrid-service-control.socket": "/run/sovagrid-service",
    "sovagrid-vpn-control.socket": "/run/sovagrid-vpn",
    "sovagrid-amnezia-control.socket": "/run/sovagrid-vpn",
}


class Refused(RuntimeError):
    """Stable refusal code, without subprocess output or private file names."""


def _unique(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused("INVALID_RESTORE_JOURNAL")
        result[key] = value
    return result


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (ValueError, TypeError, OverflowError) as exc:
        raise Refused("INVALID_RESTORE_JOURNAL") from exc


def _id(identity: str) -> str:
    if not isinstance(identity, str) or ID.fullmatch(identity) is None:
        raise Refused("INVALID_ID")
    return identity


def _private(info: os.stat_result, *, directory: bool, uid: int, gid: int) -> None:
    if ((not stat.S_ISDIR(info.st_mode) if directory else
         not stat.S_ISREG(info.st_mode) or info.st_nlink != 1) or
            (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) !=
            (uid, gid, 0o700 if directory else 0o600)):
        raise Refused("UNSAFE_RESTORE_JOURNAL")


def _write(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise Refused("RESTORE_IO_ERROR")
        view = view[written:]


def _validate_step(step: Any, index: int) -> None:
    if (not isinstance(step, dict) or
            set(step) != {"index", "kind", "resource", "desired", "state", "proof"} or
            type(step["index"]) is not int or step["index"] != index or
            step["kind"] not in KINDS or
            not isinstance(step["resource"], str) or
            not 1 <= len(step["resource"]) <= 512 or
            any(ord(character) < 32 or ord(character) > 126
                for character in step["resource"]) or
            not isinstance(step["desired"], dict) or
            len(_canonical(step["desired"])) > MAX_PROOF or
            step["state"] not in STATES or
            (step["proof"] is not None and not isinstance(step["proof"], dict)) or
            len(_canonical(step["proof"])) > MAX_PROOF or
            (step["state"] == "pending" and step["proof"] is not None) or
            (step["state"] != "pending" and step["proof"] is None)):
        raise Refused("INVALID_RESTORE_JOURNAL")


def _validate(value: Any, identity: str) -> None:
    if (not isinstance(value, dict) or set(value) != {
            "protocol", "id", "bindings", "layout", "phase", "generation",
            "steps", "error"} or value["protocol"] != PROTOCOL or
            value["id"] != identity or value["layout"] != "full" or
            not isinstance(value["bindings"], dict) or
            set(value["bindings"]) != BINDINGS or
            any(not isinstance(digest, str) or SHA.fullmatch(digest) is None
                for digest in value["bindings"].values()) or
            value["phase"] not in PHASES or type(value["generation"]) is not int or
            value["generation"] < 0 or not isinstance(value["steps"], list) or
            not 1 <= len(value["steps"]) <= MAX_STEPS or
            (value["error"] is not None and
             (not isinstance(value["error"], str) or
              re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value["error"]) is None))):
        raise Refused("INVALID_RESTORE_JOURNAL")
    resources = set()
    for index, step in enumerate(value["steps"]):
        _validate_step(step, index)
        key = (step["kind"], step["resource"])
        if key in resources:
            raise Refused("INVALID_RESTORE_JOURNAL")
        resources.add(key)
    if value["phase"] in ("healthy", "committed") and any(
            step["state"] != "done" for step in value["steps"]):
        raise Refused("INVALID_RESTORE_JOURNAL")
    if value["phase"] == "rolled_back" and any(
            step["state"] not in ("pending", "reverted") for step in value["steps"]):
        raise Refused("INVALID_RESTORE_JOURNAL")


class Journal:
    """A private atomic journal under the already exclusively locked stage FD.

    Callers retain the installation and staging locks for this object's entire
    lifetime. Root UID/GID overrides exist solely for unprivileged local tests.
    """

    def __init__(self, directory_fd: int, identity: str, *, uid: int = 0, gid: int = 0):
        self.fd = directory_fd
        self.identity = _id(identity)
        self.uid, self.gid = uid, gid
        _private(os.fstat(self.fd), directory=True, uid=uid, gid=gid)
        self.name = ".apply-" + self.identity + ".json"

    def read(self) -> dict | None:
        try:
            raw, _ = _read_atomic_private_at(self.fd, self.name, maximum=MAX_JOURNAL,
                uid=self.uid, gid=self.gid, changed_code="RESTORE_JOURNAL_CHANGED",
                limit_code="INVALID_RESTORE_JOURNAL")
        except FileNotFoundError:
            return None
        try:
            value = json.loads(raw, object_pairs_hook=_unique)
        except (ValueError, UnicodeError) as exc:
            raise Refused("INVALID_RESTORE_JOURNAL") from exc
        _validate(value, self.identity)
        return value

    def save(self, value: dict, *, initial: bool = False) -> None:
        _validate(value, self.identity)
        old = self.read()
        if initial:
            if old is not None or value["generation"] != 0:
                raise Refused("RESTORE_JOURNAL_EXISTS")
        elif (old is None or old["generation"] + 1 != value["generation"] or
              old["bindings"] != value["bindings"] or
              [{key: step[key] for key in ("index", "kind", "resource", "desired")}
               for step in old["steps"]] !=
              [{key: step[key] for key in ("index", "kind", "resource", "desired")}
               for step in value["steps"]] or
              any(before["proof"] is not None and before["proof"] != after["proof"]
                  for before, after in zip(old["steps"], value["steps"]))):
            raise Refused("RESTORE_JOURNAL_CHANGED")
        raw = _canonical(value) + b"\n"
        if len(raw) > MAX_JOURNAL:
            raise Refused("RESTORE_JOURNAL_LIMIT")
        temporary = ".apply-" + self.identity + "." + uuid.uuid4().hex + ".tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        try:
            os.fchmod(descriptor, 0o600)
            _private(os.fstat(descriptor), directory=False, uid=self.uid, gid=self.gid)
            _write(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            if initial:
                _rename_noreplace(self.fd, temporary, self.name)
            else:
                os.replace(temporary, self.name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass


class Driver(Protocol):
    def prepare(self, step: dict) -> dict:
        """Inspect only, returning the proof to persist BEFORE any mutation."""

    def execute(self, step: dict, proof: dict) -> None:
        """Perform one bounded operation using its already persisted intent."""

    def verify(self, step: dict, proof: dict) -> None:
        """Refuse unless the resource is exactly the one just requested."""

    def undo(self, step: dict, proof: dict) -> None:
        """Idempotently undo absent or proof-matching resources; refuse others."""

    def health(self, value: dict) -> None:
        """Check restored services; returning does not itself commit a restore."""


class Fence:
    """Persistent cross-installer fence, published after the durable journal.

    The caller retains the installation lock while acquiring/releasing it.
    Installers need only reject its no-follow presence, even without Python.
    """

    def __init__(self, root: Path = Path("/"), *, uid: int = 0, gid: int = 0):
        self.root, self.uid, self.gid = root, uid, gid

    @staticmethod
    def _raw(identity, bindings):
        return _canonical({"protocol": "sovagrid-host-restore-fence-v1", "id": identity,
                           "apply_review_sha256": bindings["apply_review_sha256"],
                           "resource_manifest_sha256": bindings["resource_manifest_sha256"]}) + b"\n"

    def _read(self, parent, name):
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError:
            return None
        try:
            raw, _fingerprint_value = _read_private_fd(descriptor, maximum=1024,
                                                      uid=self.uid, gid=self.gid)
            return raw
        finally:
            os.close(descriptor)

    def require_absent(self):
        parent, name = _safe_parent(self.root, str(FENCE), uid=self.uid)
        try:
            if self._read(parent, name) is not None:
                raise Refused("RESTORE_FENCE_PRESENT")
        finally:
            os.close(parent)

    def acquire(self, identity, bindings):
        raw = self._raw(_id(identity), bindings)
        parent, name = _safe_parent(self.root, str(FENCE), uid=self.uid)
        temporary = FENCE.name + "." + identity + "." + uuid.uuid4().hex + ".tmp"
        try:
            old = self._read(parent, name)
            if old is not None:
                if old != raw:
                    raise Refused("RESTORE_FENCE_FOREIGN")
                return
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            try:
                os.fchmod(descriptor, 0o600)
                _private(os.fstat(descriptor), directory=False, uid=self.uid, gid=self.gid)
                _write(descriptor, raw)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _rename_noreplace(parent, temporary, name)
            os.fsync(parent)
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)

    def release(self, identity, bindings):
        parent, name = _safe_parent(self.root, str(FENCE), uid=self.uid)
        try:
            old = self._read(parent, name)
            if old is None:
                return
            if old != self._raw(_id(identity), bindings):
                raise Refused("RESTORE_FENCE_FOREIGN")
            os.unlink(name, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)


def _advance(journal: Journal, value: dict) -> None:
    value["generation"] += 1
    journal.save(value)


def _public(value: dict) -> dict:
    return {"ok": value["phase"] == "committed",
            "protocol": PROTOCOL, "id": value["id"], "phase": value["phase"],
            "restored": value["phase"] == "committed",
            "apply_review_sha256": value["bindings"]["apply_review_sha256"],
            "steps_total": len(value["steps"]),
            "steps_done": sum(step["state"] == "done" for step in value["steps"]),
            "steps_reverted": sum(step["state"] == "reverted"
                                  for step in value["steps"]),
            "error": value["error"], "apply_available": False,
            "retry_available": value["phase"] == "rolled_back",
            "terminal_sha256": (hashlib.sha256(_canonical(value)).hexdigest()
                                if value["phase"] in ("committed", "rolled_back") else None)}


def status(journal: Journal) -> dict:
    value = journal.read()
    if value is None:
        raise Refused("RESTORE_NOT_FOUND")
    return _public(value)


def _refuse_other_journals(journal: Journal) -> None:
    # An interrupted explicit retry must finish archiving its exact terminal
    # metadata before a new forward transaction can create another journal.
    for name in os.listdir(journal.fd):
        match = re.fullmatch(r"\.retry-([0-9a-f]{32})\.json", name)
        if match:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=journal.fd)
            try:
                raw, _ = _read_private_fd(descriptor, maximum=16384, uid=journal.uid, gid=journal.gid)
                retry = json.loads(raw, object_pairs_hook=_unique)
            finally:
                os.close(descriptor)
            if (not isinstance(retry, dict) or retry.get("protocol") != "sovagrid-portable-restore-retry-v1" or
                    retry.get("id") != match[1] or retry.get("phase") != "complete"):
                raise Refused("RESTORE_RETRY_REQUIRED")
    with os.scandir(journal.fd) as entries:
        names = [entry.name for entry in entries if re.fullmatch(r"\.apply-[0-9a-f]{32}\.json", entry.name)]
    if len(names) > 1000:
        raise Refused("RESTORE_JOURNAL_LIMIT")
    for name in names:
        identity = name[len(".apply-"):-len(".json")]
        if identity == journal.identity:
            continue
        other = Journal(journal.fd, identity, uid=journal.uid, gid=journal.gid).read()
        if other is None or other["phase"] not in ("committed", "rolled_back"):
            raise Refused("RESTORE_OTHER_IN_PROGRESS")


def _recover(journal: Journal, driver: Driver, value: dict) -> dict:
    if value["phase"] in ("committed", "rolled_back"):
        return _public(value)
    value["phase"] = "rolling_back"
    _advance(journal, value)
    for step in reversed(value["steps"]):
        if step["state"] in ("pending", "reverted"):
            continue
        step["state"] = "reverting"
        _advance(journal, value)
        try:
            driver.undo(step, step["proof"])
        except Exception:
            # Lower steps may own prerequisites of this changed resource.
            # Stop here: deleting those prerequisites would damage it too.
            value["phase"] = "recovery_required"
            value["error"] = "RESTORE_RESOURCE_CHANGED"
            _advance(journal, value)
            return _public(value)
        step["state"] = "reverted"
        _advance(journal, value)
    finish = getattr(driver, "rollback_complete", None)
    if finish is not None:
        try:
            finish(value)
        except Exception:
            value["phase"] = "recovery_required"
            value["error"] = "RESTORE_RECOVERY_INCOMPLETE"
            _advance(journal, value)
            return _public(value)
    value["phase"] = "rolled_back"
    _advance(journal, value)
    return _public(value)


def recover(journal: Journal, driver: Driver, *, fence: Fence | None = None) -> dict:
    value = journal.read()
    if value is None:
        raise Refused("RESTORE_NOT_FOUND")
    if fence is not None and value["phase"] not in ("committed", "rolled_back"):
        fence.acquire(value["id"], value["bindings"])
    result = _recover(journal, driver, value)
    if fence is not None and value["phase"] in ("committed", "rolled_back"):
        fence.release(value["id"], value["bindings"])
    return result


def run(journal: Journal, driver: Driver, bindings: dict, steps: list[dict], *,
        fence: Fence | None = None) -> dict:
    """Execute a preflighted internal plan, persisting every effect's intent.

    This is not a public restore command: a production adapter must hold the
    shared installation/staging/export locks, retain verified input FDs, and
    produce the bounded steps. A repeated committed request is idempotent;
    every unfinished request requires explicit recovery, never replay.
    """
    old = journal.read()
    if old is not None:
        if old["bindings"] != bindings:
            raise Refused("STALE_RESTORE_REVIEW")
        if old["phase"] == "committed":
            if fence is not None:
                fence.release(old["id"], old["bindings"])
            return _public(old)
        raise Refused("RESTORE_RECOVERY_REQUIRED")
    _refuse_other_journals(journal)
    if fence is not None:
        fence.require_absent()
    value = {"protocol": PROTOCOL, "id": journal.identity, "bindings": bindings,
             "layout": "full", "phase": "prepared", "generation": 0,
             "steps": [{"index": index, "kind": step["kind"],
                        "resource": step["resource"], "desired": step["desired"],
                        "state": "pending", "proof": None}
                       for index, step in enumerate(steps)], "error": None}
    journal.save(value, initial=True)
    try:
        if fence is not None:
            fence.acquire(value["id"], bindings)
        value["phase"] = "applying"
        _advance(journal, value)
        for step in value["steps"]:
            proof = driver.prepare(step)
            if not isinstance(proof, dict) or len(_canonical(proof)) > MAX_PROOF:
                raise Refused("INVALID_RESTORE_PROOF")
            step["proof"] = proof
            step["state"] = "intent"
            _advance(journal, value)
            driver.execute(step, proof)
            driver.verify(step, proof)
            step["state"] = "done"
            _advance(journal, value)
        driver.health(value)
        value["phase"] = "healthy"
        _advance(journal, value)
        value["phase"] = "committed"
        _advance(journal, value)
        if fence is not None:
            fence.release(value["id"], bindings)
        return _public(value)
    except Exception as exc:
        # BaseException deliberately propagates: process death is recovered
        # from the durable intent, not caught as an ordinary operation failure.
        code = str(exc) if isinstance(exc, Refused) else "RESTORE_FAILED"
        value["error"] = (code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code)
                          else "RESTORE_FAILED")
        _advance(journal, value)
        result = _recover(journal, driver, value)
        if fence is not None and value["phase"] == "rolled_back":
            fence.release(value["id"], bindings)
        return result


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _rename_noreplace(parent_fd: int, source: str, target: str) -> None:
    if not sys.platform.startswith("linux"):
        raise Refused("UNSUPPORTED_PLATFORM")
    function = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if function is None:
        raise Refused("UNSUPPORTED_PLATFORM")
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                         ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    if function(parent_fd, os.fsencode(source), parent_fd, os.fsencode(target), 1):
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise Refused("RESTORE_TARGET_EXISTS")
        raise Refused("RESTORE_IO_ERROR")


def _safe_parent(root: Path, target: str, *, uid: int) -> tuple[int, str]:
    path = PurePosixPath(target)
    if (not path.is_absolute() or target != path.as_posix() or
            len(path.parts) < 2 or any(part in (".", "..") for part in path.parts)):
        raise Refused("INVALID_RESTORE_PATH")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                         os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            info = os.fstat(descriptor)
            if info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o022:
                raise Refused("UNSAFE_RESTORE_PARENT")
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o022:
            raise Refused("UNSAFE_RESTORE_PARENT")
        return descriptor, path.name
    except BaseException:
        os.close(descriptor)
        raise


def tree_proof(parent_fd: int, name: str) -> dict:
    """Hash file bytes and exact owners/modes, rejecting links and races.

    The root inode is recorded independently of the digest, so an equal-byte
    replacement created by another process is never adopted for deletion.
    """
    count, total = 0, 0
    deadline = time.monotonic() + 600
    digest = hashlib.sha256()

    def walk(directory_fd: int, leaf: str, relative: str) -> os.stat_result:
        nonlocal count, total
        if time.monotonic() > deadline:
            raise Refused("RESTORE_TIME_LIMIT")
        info = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
        is_directory = stat.S_ISDIR(info.st_mode)
        if (not is_directory and
                (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)):
            raise Refused("UNSAFE_RESTORE_RESOURCE")
        descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                             (os.O_DIRECTORY if is_directory else 0), dir_fd=directory_fd)
        try:
            before = os.fstat(descriptor)
            if _fingerprint(info) != _fingerprint(before):
                raise Refused("RESTORE_RESOURCE_CHANGED")
            count += 1
            if count > MAX_TREE_ENTRIES:
                raise Refused("RESTORE_FILE_LIMIT")
            entry = {"path": relative, "kind": "dir" if is_directory else "file",
                     "uid": info.st_uid, "gid": info.st_gid,
                     "mode": stat.S_IMODE(info.st_mode)}
            if is_directory:
                with os.scandir(descriptor) as iterator:
                    names = sorted(item.name for item in iterator)
                digest.update(_canonical(entry) + b"\0")
                for child in names:
                    walk(descriptor, child, relative + "/" + child if relative else child)
            else:
                total += info.st_size
                if total > MAX_TREE_BYTES:
                    raise Refused("RESTORE_SIZE_LIMIT")
                file_digest = hashlib.sha256()
                size = 0
                while True:
                    if time.monotonic() > deadline:
                        raise Refused("RESTORE_TIME_LIMIT")
                    block = os.read(descriptor, 1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    if size > info.st_size:
                        raise Refused("RESTORE_RESOURCE_CHANGED")
                    file_digest.update(block)
                if size != info.st_size:
                    raise Refused("RESTORE_RESOURCE_CHANGED")
                entry.update(size=size, sha256=file_digest.hexdigest())
                digest.update(_canonical(entry) + b"\0")
            if _fingerprint(os.fstat(descriptor)) != _fingerprint(before):
                raise Refused("RESTORE_RESOURCE_CHANGED")
            return info
        finally:
            os.close(descriptor)

    info = walk(parent_fd, name, "")
    return {"device": info.st_dev, "inode": info.st_ino,
            "sha256": digest.hexdigest(), "entries": count, "bytes": total}


class Publisher:
    """Publish verified shadow resources and undo only their exact inodes.

    The caller supplies the closed set of live roots derived from the verified
    archive/installer contract. A journal cannot expand that set. Shadow trees
    must already have restored numeric metadata and be fsynced on the target
    filesystem. Undo quarantines back to the original shadow name; it never
    recursively removes a live tree or unknown replacement.
    """

    def __init__(self, root: Path, identity: str, targets: set[str], *, uid: int = 0):
        self.root, self.identity, self.targets, self.uid = root, _id(identity), targets, uid

    def _open(self, step: dict) -> tuple[int, str, str]:
        if (step["kind"] != "publish" or step["resource"] not in self.targets or
                set(step["desired"]) != {"shadow", "sha256"} or
                not isinstance(step["desired"]["sha256"], str) or
                SHA.fullmatch(step["desired"]["sha256"]) is None):
            raise Refused("INVALID_RESTORE_PUBLICATION")
        shadow = step["desired"]["shadow"]
        if (not isinstance(shadow, str) or re.fullmatch(
                r"\.sovagrid-restore-" + self.identity + r"-[0-9]{1,3}", shadow) is None):
            raise Refused("INVALID_RESTORE_PUBLICATION")
        parent, name = _safe_parent(self.root, step["resource"], uid=self.uid)
        return parent, name, shadow

    @staticmethod
    def _exists(parent: int, name: str) -> bool:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def _check_parent(self, descriptor: int, proof: dict) -> None:
        info = os.fstat(descriptor)
        if [info.st_dev, info.st_ino] != proof["parent"]:
            raise Refused("RESTORE_PARENT_CHANGED")

    def prepare(self, step: dict) -> dict:
        parent, name, shadow = self._open(step)
        try:
            if self._exists(parent, name):
                raise Refused("RESTORE_TARGET_EXISTS")
            resource = tree_proof(parent, shadow)
            if resource["sha256"] != step["desired"]["sha256"]:
                raise Refused("RESTORE_SHADOW_CHANGED")
            info = os.fstat(parent)
            return {"parent": [info.st_dev, info.st_ino], "resource": resource}
        finally:
            os.close(parent)

    def execute(self, step: dict, proof: dict) -> None:
        parent, name, shadow = self._open(step)
        try:
            self._check_parent(parent, proof)
            if tree_proof(parent, shadow) != proof["resource"]:
                raise Refused("RESTORE_SHADOW_CHANGED")
            _rename_noreplace(parent, shadow, name)
            os.fsync(parent)
        finally:
            os.close(parent)

    def verify(self, step: dict, proof: dict) -> None:
        parent, name, _shadow = self._open(step)
        try:
            self._check_parent(parent, proof)
            if tree_proof(parent, name) != proof["resource"]:
                raise Refused("RESTORE_RESOURCE_CHANGED")
        finally:
            os.close(parent)

    def undo(self, step: dict, proof: dict) -> None:
        parent, name, shadow = self._open(step)
        try:
            self._check_parent(parent, proof)
            live = self._exists(parent, name)
            hidden = self._exists(parent, shadow)
            if hidden and not live:
                if tree_proof(parent, shadow) != proof["resource"]:
                    raise Refused("RESTORE_RESOURCE_CHANGED")
                return
            if not live or hidden or tree_proof(parent, name) != proof["resource"]:
                raise Refused("RESTORE_RESOURCE_CHANGED")
            _rename_noreplace(parent, name, shadow)
            os.fsync(parent)
            if tree_proof(parent, shadow) != proof["resource"]:
                raise Refused("RESTORE_RESOURCE_CHANGED")
        finally:
            os.close(parent)


class Identities:
    """Reserve only missing installer identities with a journal-specific GECOS.

    Adopting existing NSS identities is intentionally unsupported. User removal
    never uses --remove: restored directories have their own publication proofs.
    """

    USERS = {"sovagrid-hub": (10001, "/nonexistent"),
             "sovagrid-web": (10002, "/nonexistent"),
             "sovagrid-shell": (10003, "/nonexistent"),
             "sovagrid-journal": (10004, "/nonexistent"),
             "sovagrid": (None, "/var/lib/sovagrid-agent")}
    GROUPS = frozenset((*USERS, "sovagrid-web-agent"))

    def __init__(self, identity: str):
        self.identity = _id(identity)
        self.comment = "SovaGrid restore " + self.identity

    @staticmethod
    def _named_user(name):
        try:
            return pwd.getpwnam(name)
        except KeyError:
            return None

    @staticmethod
    def _named_group(name):
        try:
            return grp.getgrnam(name)
        except KeyError:
            return None

    @staticmethod
    def _locked_password(filename, name, *, group=False):
        """Do not delete an account/group whose password or admins changed."""
        descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or
                    before.st_nlink != 1 or before.st_mode & 0o027 or
                    before.st_size > 1024 * 1024):
                return False
            raw = os.read(descriptor, 1024 * 1024 + 1)
            if len(raw) != before.st_size or _fingerprint(before) != _fingerprint(os.fstat(descriptor)):
                return False
        finally:
            os.close(descriptor)
        try:
            rows = [line.split(":") for line in raw.decode("ascii").splitlines()
                    if line.partition(":")[0] == name]
        except UnicodeError:
            return False
        return (len(rows) == 1 and len(rows[0]) == (4 if group else 9) and
                rows[0][1] in ("!", "!!", "*") and
                (not group or rows[0][2:] == ["", ""]))

    @staticmethod
    def _command(args):
        try:
            result = subprocess.run(args, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=30, check=False,
                                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Refused("RESTORE_IDENTITY_FAILED") from exc
        if result.returncode:
            raise Refused("RESTORE_IDENTITY_FAILED")

    def _desired(self, step):
        name, desired = step["resource"], step["desired"]
        if step["kind"] == "group":
            if (name not in self.GROUPS or set(desired) != {"gid"} or
                    type(desired["gid"]) is not int or not 1 <= desired["gid"] <= 65535 or
                    (name != "sovagrid" and desired["gid"] !=
                     (10005 if name == "sovagrid-web-agent" else self.USERS[name][0]))):
                raise Refused("INVALID_RESTORE_IDENTITY")
        elif step["kind"] == "user":
            if (name not in self.USERS or set(desired) != {"uid", "gid"} or
                    any(type(desired[key]) is not int or not 1 <= desired[key] <= 65535
                        for key in ("uid", "gid")) or
                    (name != "sovagrid" and (desired["uid"] != self.USERS[name][0] or
                                              desired["gid"] != desired["uid"])) or
                    (name == "sovagrid" and not 100 <= desired["uid"] <= 999)):
                raise Refused("INVALID_RESTORE_IDENTITY")
        else:
            raise Refused("INVALID_RESTORE_IDENTITY")
        return name, desired

    def prepare(self, step):
        name, desired = self._desired(step)
        if step["kind"] == "group":
            named = self._named_group(name)
            try:
                numbered = grp.getgrgid(desired["gid"])
            except KeyError:
                numbered = None
        else:
            named = self._named_user(name)
            try:
                numbered = pwd.getpwuid(desired["uid"])
            except KeyError:
                numbered = None
            group = self._named_group(name)
            if group is None or group.gr_gid != desired["gid"]:
                raise Refused("RESTORE_IDENTITY_GROUP_MISMATCH")
        if named is not None or numbered is not None:
            raise Refused("RESTORE_IDENTITY_EXISTS")
        return {"absent": True, "marker": self.comment}

    def execute(self, step, proof):
        name, desired = self._desired(step)
        if proof != {"absent": True, "marker": self.comment}:
            raise Refused("INVALID_RESTORE_PROOF")
        # Repeat absence immediately before invoking the system account tool.
        self.prepare(step)
        if step["kind"] == "group":
            self._command(["/usr/sbin/groupadd", "--system", "--gid",
                           str(desired["gid"]), name])
        else:
            args = ["/usr/sbin/useradd", "--system", "--uid", str(desired["uid"]),
                    "--gid", str(desired["gid"]), "--home-dir", self.USERS[name][1],
                    "--shell", "/usr/sbin/nologin", "--comment", self.comment]
            if name == "sovagrid-journal":
                if self._named_group("systemd-journal") is None:
                    raise Refused("RESTORE_JOURNAL_GROUP_UNAVAILABLE")
                args += ["--groups", "systemd-journal"]
            self._command([*args, name])

    def _matches(self, step):
        name, desired = self._desired(step)
        if step["kind"] == "group":
            group = self._named_group(name)
            return (group is not None and group.gr_gid == desired["gid"] and
                    group.gr_passwd in ("x", "*", "!") and not group.gr_mem and
                    self._locked_password("/etc/gshadow", name, group=True))
        user = self._named_user(name)
        if user is None:
            return False
        expected_groups = {desired["gid"]}
        if name == "sovagrid-journal":
            group = self._named_group("systemd-journal")
            if group is None:
                return False
            expected_groups.add(group.gr_gid)
        return (user.pw_uid == desired["uid"] and user.pw_gid == desired["gid"] and
                user.pw_gecos == self.comment and user.pw_dir == self.USERS[name][1] and
                user.pw_shell == "/usr/sbin/nologin" and
                set(os.getgrouplist(name, desired["gid"])) == expected_groups and
                self._locked_password("/etc/shadow", name))

    def verify(self, step, proof):
        if proof != {"absent": True, "marker": self.comment} or not self._matches(step):
            raise Refused("RESTORE_IDENTITY_CHANGED")

    def undo(self, step, proof):
        name, desired = self._desired(step)
        existing = (self._named_group(name) if step["kind"] == "group" else
                    self._named_user(name))
        if existing is None:
            return
        self.verify(step, proof)
        if step["kind"] == "group":
            if any(user.pw_gid == desired["gid"] for user in pwd.getpwall()):
                raise Refused("RESTORE_IDENTITY_CHANGED")
            self._command(["/usr/sbin/groupdel", name])
        else:
            self._command(["/usr/sbin/userdel", name])
        if (self._named_group(name) if step["kind"] == "group" else
                self._named_user(name)) is not None:
            raise Refused("RESTORE_IDENTITY_CHANGED")


class Images:
    """Import from a retained verified tar FD and undo only matching local tags."""

    DOCKER = ("/usr/bin/docker", "--host", "unix:///var/run/docker.sock")
    SERVICES = frozenset(("hub", "web", "ssh-gateway"))
    CONFIG = re.compile(r"sha256:[0-9a-f]{64}\Z")

    def __init__(self, inputs: Any):
        self.inputs = inputs
        self._converted_cache = None

    @staticmethod
    def _environment():
        # A user's Docker context/config must never redirect restore operations.
        return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}

    def _capture(self, args):
        try:
            result = subprocess.run([*self.DOCKER, *args], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=20, check=False, env=self._environment())
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Refused("RESTORE_DOCKER_UNAVAILABLE") from exc
        if result.returncode or len(result.stdout) > 128 * 1024:
            raise Refused("RESTORE_DOCKER_UNAVAILABLE")
        try:
            return result.stdout.decode("ascii").strip()
        except UnicodeError as exc:
            raise Refused("RESTORE_DOCKER_UNAVAILABLE") from exc

    def _desired(self, step):
        if (step["kind"] != "images" or step["resource"] != "sovagrid-compose-images" or
                set(step["desired"]) != {"services"}):
            raise Refused("INVALID_RESTORE_IMAGES")
        services = step["desired"]["services"]
        if (not isinstance(services, dict) or set(services) not in (
                {"hub", "web"}, set(self.SERVICES)) or any(
                not isinstance(value, dict) or set(value) != {"config", "rootfs_sha256", "platform", "runtime_ids"} or
                not isinstance(value["config"], str) or self.CONFIG.fullmatch(value["config"]) is None or
                not isinstance(value["rootfs_sha256"], str) or SHA.fullmatch(value["rootfs_sha256"]) is None or
                value["platform"] not in ({"os": "linux", "architecture": "amd64"},
                                            {"os": "linux", "architecture": "arm64"}) or
                not isinstance(value["runtime_ids"], list) or not 1 <= len(value["runtime_ids"]) <= 3 or
                any(not isinstance(identity, str) or self.CONFIG.fullmatch(identity) is None
                    for identity in value["runtime_ids"]) or
                value["runtime_ids"] != sorted(set(value["runtime_ids"])) or
                value["config"] not in value["runtime_ids"]
                for value in services.values())):
            raise Refused("INVALID_RESTORE_IMAGES")
        expected = {service: {"config": digest,
                              "rootfs_sha256": self.inputs.images["rootfs_sha256"][service],
                              "platform": self.inputs.platforms[service],
                              "runtime_ids": self.inputs.runtime_ids[service]}
                    for service, digest in self.inputs.images["exported_configs"].items()}
        if services != expected:
            raise Refused("RESTORE_IMAGE_RECEIPT_MISMATCH")
        return services

    def _tags(self):
        raw = self._capture(["image", "ls", "--no-trunc", "--format",
                             "{{.Repository}}:{{.Tag}}|{{.ID}}"])
        found = {}
        for row in raw.splitlines():
            tag, separator, image = row.partition("|")
            if not separator or self.CONFIG.fullmatch(image) is None:
                raise Refused("RESTORE_DOCKER_UNAVAILABLE")
            if tag in {"sovagrid-" + service + ":local" for service in self.SERVICES}:
                if tag in found:
                    raise Refused("RESTORE_IMAGE_CHANGED")
                found[tag] = image
        return found

    def _inventory(self):
        values = self._capture(["image", "ls", "--all", "--no-trunc", "--quiet"]).splitlines()
        if (any(self.CONFIG.fullmatch(value) is None for value in values) or
                len(set(values)) > 96):
            raise Refused("RESTORE_IMAGE_INVENTORY_LIMIT")
        return sorted({value[7:] for value in values})

    def _proof(self, proof, services):
        if (not isinstance(proof, dict) or set(proof) != {"absent", "services", "preexisting_ids"} or
                proof["absent"] is not True or proof["services"] != services or
                not isinstance(proof["preexisting_ids"], list) or len(proof["preexisting_ids"]) > 96 or
                any(not isinstance(value, str) or SHA.fullmatch(value) is None for value in proof["preexisting_ids"]) or
                proof["preexisting_ids"] != sorted(set(proof["preexisting_ids"])) or
                len(_canonical(proof)) > MAX_PROOF):
            raise Refused("INVALID_RESTORE_PROOF")

    def _scratch(self):
        """An anonymous file cannot survive process death or replace any path."""
        if not getattr(os, "O_TMPFILE", 0):
            raise Refused("RESTORE_IMAGE_REEXPORT_UNAVAILABLE")
        uid, gid = self.inputs.root_uid, self.inputs.root_gid
        _private(os.fstat(self.inputs.stage_fd), directory=True, uid=uid, gid=gid)
        try:
            fd = os.open(".", os.O_RDWR | os.O_CLOEXEC | os.O_TMPFILE, 0o600,
                         dir_fd=self.inputs.stage_fd)
        except OSError as exc:
            raise Refused("RESTORE_IMAGE_REEXPORT_UNAVAILABLE") from exc
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 0 or
                    (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, 0o600)):
                raise Refused("UNSAFE_RESTORE_IMAGE_SCRATCH")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _space(self):
        try:
            info = os.fstatvfs(self.inputs.stage_fd)
        except OSError as exc:
            raise Refused("RESTORE_DISK_SPACE") from exc
        if info.f_bavail * info.f_frsize < self.inputs.exporter.MAX_IMAGE_BYTES + self.inputs.exporter.MIN_FREE:
            raise Refused("RESTORE_DISK_SPACE")

    def _converted_ids(self):
        tags = self._tags()
        key = tuple(sorted(tags.items()))
        if self._converted_cache is not None and self._converted_cache[0] == key:
            return self._converted_cache[1]
        services = {name: tags["sovagrid-" + name + ":local"]
                    for name in self.inputs.images["exported_configs"] if "sovagrid-" + name + ":local" in tags}
        if not services:
            raise Refused("RESTORE_IMAGE_CHANGED")
        self._space()
        descriptor = self._scratch()
        exporter = self.inputs.exporter
        try:
            deadline = time.monotonic() + exporter.MAX_IMAGE_SECONDS
            exporter._save_images(["sovagrid-" + name + ":local" for name in sorted(services)],
                                  descriptor, descriptor, deadline=deadline)
            exported, platforms, runtime_ids = {}, {}, {}
            exporter._inspect_image_tar(descriptor, services, deadline=deadline,
                source_rootfs={name: self.inputs.images["rootfs_sha256"][name] for name in services},
                exported_configs=exported, platforms=platforms, runtime_ids=runtime_ids)
            if (exported != {name: self.inputs.images["exported_configs"][name] for name in services} or
                    platforms != {name: self.inputs.platforms[name] for name in services} or
                    set(runtime_ids) != set(services) or
                    any(identity not in runtime_ids[name] for name, identity in services.items()) or self._tags() != tags):
                raise Refused("RESTORE_IMAGE_CHANGED")
        except (exporter.Refused, OSError) as exc:
            raise Refused("RESTORE_IMAGE_REEXPORT_FAILED") from exc
        finally:
            os.close(descriptor)
        self._converted_cache = key, runtime_ids
        return runtime_ids

    def _check(self, service, desired):
        tag = "sovagrid-" + service + ":local"
        projection = '{"id":{{json .Id}},"os":{{json .Os}},"arch":{{json .Architecture}},"layers":{{json .RootFS.Layers}}}'
        try:
            value = json.loads(self._capture(["image", "inspect", "--format", projection, tag]),
                               object_pairs_hook=_unique)
        except (ValueError, UnicodeError) as exc:
            raise Refused("RESTORE_IMAGE_CHANGED") from exc
        if not isinstance(value, dict):
            raise Refused("RESTORE_IMAGE_CHANGED")
        layers = value.get("layers")
        if (not isinstance(layers, list) or not 1 <= len(layers) <= 256 or
                any(not isinstance(layer, str) or self.CONFIG.fullmatch(layer) is None for layer in layers) or
                {"os": value.get("os"), "architecture": value.get("arch")} != desired["platform"] or
                hashlib.sha256("\n".join(layers).encode("ascii")).hexdigest() != desired["rootfs_sha256"]):
            raise Refused("RESTORE_IMAGE_CHANGED")
        if value.get("id") not in desired["runtime_ids"] and value.get("id") not in self._converted_ids().get(service, []):
            raise Refused("RESTORE_IMAGE_CHANGED")
        return value["id"]

    def resolved(self, services):
        """Return runnable daemon IDs after verifying their archive DAG binding."""
        tags = self._tags()
        if set(tags) != {"sovagrid-" + service + ":local" for service in services}:
            raise Refused("RESTORE_IMAGE_CHANGED")
        result = {}
        for service, desired in services.items():
            identity = self._check(service, desired)
            if tags["sovagrid-" + service + ":local"] != identity:
                raise Refused("RESTORE_IMAGE_CHANGED")
            result[service] = identity
        return result

    def _owned_references(self, identity, tag):
        projection = '{"id":{{json .Id}},"tags":{{json .RepoTags}},"digests":{{json .RepoDigests}}}'
        try:
            value = json.loads(self._capture(["image", "inspect", "--format", projection, identity]),
                               object_pairs_hook=_unique)
        except (ValueError, UnicodeError) as exc:
            raise Refused("RESTORE_IMAGE_CHANGED") from exc
        repository = tag.removesuffix(":local")
        expected = {name + "@" + identity for name in
                    (repository, tag, "docker.io/library/" + repository, "docker.io/library/" + tag)}
        digests = value.get("digests") if isinstance(value, dict) else None
        if digests is None:
            digests = []
        if (not isinstance(value, dict) or value.get("id") != identity or value.get("tags") != [tag] or
                not isinstance(digests, list) or len(digests) > len(expected) or
                any(not isinstance(ref, str) or ref not in expected for ref in digests) or
                len(set(digests)) != len(digests)):
            raise Refused("RESTORE_IMAGE_CHANGED")
        if self._capture(["ps", "-a", "--no-trunc", "--filter", "ancestor=" + identity,
                          "--format", "{{.ID}}"]):
            raise Refused("RESTORE_IMAGE_IN_USE")

    def prepare(self, step):
        services = self._desired(step)
        self.inputs.unchanged()
        if self._tags():
            raise Refused("RESTORE_IMAGE_EXISTS")
        self._space()
        descriptor = self._scratch()
        os.close(descriptor)
        proof = {"absent": True, "services": services, "preexisting_ids": self._inventory()}
        self._proof(proof, services)
        return proof

    def execute(self, step, proof):
        services = self._desired(step)
        self._proof(proof, services)
        if self.prepare(step) != proof:
            raise Refused("RESTORE_IMAGE_CHANGED")
        os.lseek(self.inputs.images_fd, 0, os.SEEK_SET)
        try:
            result = subprocess.run([*self.DOCKER, "image", "load"], stdin=self.inputs.images_fd,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=1200, check=False, env=self._environment())
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Refused("RESTORE_IMAGE_LOAD_FAILED") from exc
        self.inputs.unchanged()
        if result.returncode:
            raise Refused("RESTORE_IMAGE_LOAD_FAILED")

    def verify(self, step, proof):
        services = self._desired(step)
        self._proof(proof, services)
        self.resolved(services)

    def undo(self, step, proof):
        services = self._desired(step)
        self._proof(proof, services)
        tags = self._tags()
        # Inspect ALL matching tags before removing any: a foreign replacement
        # must not lose a prerequisite merely because another tag still matches.
        for service, desired in services.items():
            tag = "sovagrid-" + service + ":local"
            if tag in tags:
                if tags[tag] != self._check(service, desired):
                    raise Refused("RESTORE_IMAGE_CHANGED")
                if tags[tag][7:] in proof["preexisting_ids"]:
                    raise Refused("RESTORE_IMAGE_PREEXISTED")
                self._owned_references(tags[tag], tag)
        for service, desired in services.items():
            tag = "sovagrid-" + service + ":local"
            if tag in tags:
                identity = self._check(service, desired)
                if identity != tags[tag]:
                    raise Refused("RESTORE_IMAGE_CHANGED")
                if identity[7:] in proof["preexisting_ids"]:
                    raise Refused("RESTORE_IMAGE_PREEXISTED")
                self._owned_references(identity, tag)
                # A concurrent retag must never redirect deletion to a foreign
                # image. The daemon receives the proven newly imported ID;
                # new aliases or consumers cause refusal without --force.
                self._capture(["image", "rm", "--no-prune", identity])
        if any("sovagrid-" + service + ":local" in self._tags() for service in services):
            raise Refused("RESTORE_IMAGE_CHANGED")


class Services:
    """Exact unit-hash fencing for restored enablement and unit activation.

    The plan builder must restore all unit files and daemon-reload first, and
    schedule sockets before consumers and timers last. Enablement is confined
    to the three standard installer targets; aliases/Also/runtime links and
    missing target directories are rejected instead of delegated to systemctl.
    """

    TARGETS = frozenset(("multi-user.target", "sockets.target", "timers.target"))
    SYSTEMCTL = "/usr/bin/systemctl"
    LOAD_PATHS = ("/etc/systemd/system.control", "/run/systemd/system.control",
                  "/run/systemd/transient", "/run/systemd/generator.early",
                  "/etc/systemd/system", "/etc/systemd/system.attached",
                  "/run/systemd/system", "/run/systemd/system.attached",
                  "/run/systemd/generator", "/usr/local/lib/systemd/system",
                  "/usr/lib/systemd/system", "/lib/systemd/system", "/run/systemd/generator.late")

    def __init__(self, root: Path, states: dict, *, uid: int = 0, gid: int = 0):
        self.root, self.states, self.uid, self.gid = root, states, uid, gid

    def _command(self, args, *, accepted=(0,)):
        try:
            result = subprocess.run([self.SYSTEMCTL, "--no-pager", *args],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=60, check=False,
                                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Refused("RESTORE_SYSTEMD_FAILED") from exc
        if result.returncode not in accepted or len(result.stdout) > 4096:
            raise Refused("RESTORE_SYSTEMD_FAILED")
        try:
            return result.stdout.decode("ascii").strip()
        except UnicodeError as exc:
            raise Refused("RESTORE_SYSTEMD_FAILED") from exc

    def _unit(self, step):
        unit, desired = step["resource"], step["desired"]
        state = self.states.get(unit)
        if (not isinstance(unit, str) or re.fullmatch(
                r"sovagrid-[a-z0-9-]{1,80}\.(?:service|socket|timer)", unit) is None or
                not isinstance(state, dict) or step["kind"] not in ("enablement", "service") or
                set(desired) != ({"state", "sha256"} if step["kind"] == "enablement" else
                                 {"active", "sha256"}) or
                desired.get("sha256") != state.get("sha256") or
                (step["kind"] == "enablement" and (desired.get("state") != state.get("enablement") or
                 desired.get("state") not in ("enabled", "disabled", "static"))) or
                (step["kind"] == "service" and (desired.get("active") is not True or
                                                state.get("active") is not True))):
            raise Refused("INVALID_RESTORE_UNIT")
        parent, name = _safe_parent(self.root, "/etc/systemd/system/" + unit, uid=self.uid)
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                before = os.fstat(descriptor)
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                        before.st_uid != self.uid or before.st_gid != self.gid or
                        stat.S_IMODE(before.st_mode) != 0o644 or before.st_size > 128 * 1024):
                    raise Refused("RESTORE_UNIT_CHANGED")
                raw = bytearray()
                while len(raw) <= 128 * 1024:
                    block = os.read(descriptor, min(65536, 128 * 1024 + 1 - len(raw)))
                    if not block:
                        break
                    raw.extend(block)
                if (_fingerprint(before) != _fingerprint(os.fstat(descriptor)) or
                        len(raw) != before.st_size or
                        hashlib.sha256(raw).hexdigest() != desired["sha256"]):
                    raise Refused("RESTORE_UNIT_CHANGED")
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)
        return unit, bytes(raw)

    def _targets(self, raw):
        try:
            text = raw.decode("utf-8")
        except UnicodeError as exc:
            raise Refused("RESTORE_ENABLEMENT_UNSUPPORTED") from exc
        section = None
        targets = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line
            elif section == "[Install]":
                key, separator, value = line.partition("=")
                if not separator or key != "WantedBy" or "\\" in value:
                    raise Refused("RESTORE_ENABLEMENT_UNSUPPORTED")
                targets.extend(value.split())
        if len(targets) > 3 or len(set(targets)) != len(targets) or any(
                target not in self.TARGETS for target in targets):
            raise Refused("RESTORE_ENABLEMENT_UNSUPPORTED")
        return sorted(targets)

    def _link_parent(self, unit, target):
        return _safe_parent(self.root, "/etc/systemd/system/" + target + ".wants/" + unit,
                            uid=self.uid)

    def _links(self, unit, targets):
        result = []
        for target in targets:
            parent, name = self._link_parent(unit, target)
            try:
                info = os.fstat(parent)
                try:
                    link_info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    link_info = None
                if link_info is not None:
                    if (not stat.S_ISLNK(link_info.st_mode) or link_info.st_uid != self.uid or
                            os.readlink(name, dir_fd=parent) != "../" + unit):
                        raise Refused("RESTORE_ENABLEMENT_CHANGED")
                result.append({"target": target, "parent": [info.st_dev, info.st_ino],
                               "present": link_info is not None})
            finally:
                os.close(parent)
        return result

    def _active(self, unit):
        value = self._command(["is-active", unit], accepted=(0, 3, 4))
        if value not in ("active", "inactive", "failed", "unknown"):
            raise Refused("RESTORE_UNIT_STATE_CHANGED")
        return value == "active"

    def _fragment(self, unit):
        value = self._command(["show", "--property=FragmentPath", "--value", unit])
        if value != "/etc/systemd/system/" + unit:
            raise Refused("RESTORE_UNIT_CHANGED")
        if self._command(["show", "--property=DropInPaths", "--value", unit]):
            raise Refused("RESTORE_UNIT_OVERRIDE_PRESENT")
        self.audit(unit, allowed=self._declared_links(unit))

    def _declared_links(self, unit):
        state = self.states[unit]
        if state["enablement"] != "enabled":
            return set()
        step = {"kind": "enablement", "resource": unit,
                "desired": {"state": state["enablement"], "sha256": state["sha256"]}}
        _unit, raw = self._unit(step)
        return {"/etc/systemd/system/" + target + ".wants/" + unit for target in self._targets(raw)}

    def audit(self, unit, *, allowed=frozenset()):
        """Read the complete standard unit graph; never adopt foreign routes.

        Check full, dash-prefix and type-wide drop-ins before daemon-reload as
        well as the manager's effective DropInPaths immediately before actions.
        /lib is Ubuntu's standard alias for /usr/lib; no other link is followed.
        """
        stem, suffix = unit.rsplit(".", 1)
        dropins = {unit + ".d", suffix + ".d"}
        pieces = stem.split("-")
        dropins.update("-".join(pieces[:index]) + "-." + suffix + ".d"
                       for index in range(1, len(pieces)))
        seen = set()
        for absolute in self.LOAD_PATHS:
            root = self.root / absolute.lstrip("/")
            if not os.path.lexists(root):
                continue
            relative = root.relative_to(self.root)
            if any((self.root / Path(*relative.parts[:index])).is_symlink()
                   for index in range(1, len(relative.parts) + 1)):
                if absolute != "/lib/systemd/system" or root.resolve() != self.root / "usr/lib/systemd/system":
                    raise Refused("RESTORE_UNIT_OVERRIDE_PRESENT")
            info = root.stat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid or info.st_mode & 0o022):
                raise Refused("RESTORE_UNIT_OVERRIDE_PRESENT")
            if (info.st_dev, info.st_ino) in seen:
                continue
            seen.add((info.st_dev, info.st_ino))
            if any(os.path.lexists(root / name) for name in dropins):
                raise Refused("RESTORE_UNIT_OVERRIDE_PRESENT")
            entries = list(root.iterdir())
            if len(entries) > 20000:
                raise Refused("RESTORE_ENABLEMENT_CHANGED")
            for directory in entries:
                if directory.is_symlink() and (directory.name == unit or
                        PurePosixPath(os.readlink(directory)).name == unit):
                    raise Refused("RESTORE_ENABLEMENT_CHANGED")
                if not directory.name.endswith((".wants", ".requires", ".upholds")):
                    continue
                if directory.is_symlink() or not directory.is_dir():
                    raise Refused("RESTORE_ENABLEMENT_CHANGED")
                directory_info = directory.lstat()
                if directory_info.st_uid != self.uid or directory_info.st_mode & 0o022:
                    raise Refused("RESTORE_ENABLEMENT_CHANGED")
                children = list(directory.iterdir())
                if len(children) > 20000:
                    raise Refused("RESTORE_ENABLEMENT_CHANGED")
                for child in children:
                    targets_unit = child.name == unit
                    if child.is_symlink():
                        targets_unit |= PurePosixPath(os.readlink(child)).name == unit
                    if not targets_unit:
                        continue
                    route = absolute + "/" + directory.name + "/" + child.name
                    if (route not in allowed or not child.is_symlink() or
                            child.lstat().st_uid != self.uid or os.readlink(child) != "../" + unit):
                        raise Refused("RESTORE_ENABLEMENT_CHANGED")

    def _runtime_absence(self, unit):
        if unit != "sovagrid-agent.service":
            return
        parent, name = _safe_parent(self.root, "/run/sovagrid-agent-control", uid=self.uid)
        try:
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise Refused("RESTORE_RUNTIME_STATE_PRESENT")
        finally:
            os.close(parent)

    def prepare(self, step):
        unit, raw = self._unit(step)
        self._fragment(unit)
        if step["kind"] == "service":
            self._runtime_absence(unit)
            if self._active(unit):
                raise Refused("RESTORE_UNIT_ALREADY_ACTIVE")
            return {"inactive": True, "sha256": step["desired"]["sha256"]}
        targets = self._targets(raw)
        desired = step["desired"]["state"]
        if (desired == "static") != (not targets):
            raise Refused("RESTORE_ENABLEMENT_UNSUPPORTED")
        links = self._links(unit, targets)
        if any(link["present"] for link in links):
            raise Refused("RESTORE_ENABLEMENT_CHANGED")
        return {"links": links, "sha256": step["desired"]["sha256"]}

    def execute(self, step, proof):
        unit, raw = self._unit(step)
        self._fragment(unit)
        if step["kind"] == "service":
            self._runtime_absence(unit)
            if proof != {"inactive": True, "sha256": step["desired"]["sha256"]} or self._active(unit):
                raise Refused("RESTORE_UNIT_STATE_CHANGED")
            self._command(["start", unit])
            return
        expected = self.prepare(step)
        if proof != expected:
            raise Refused("RESTORE_ENABLEMENT_CHANGED")
        if step["desired"]["state"] != "enabled":
            return
        for link in proof["links"]:
            parent, name = self._link_parent(unit, link["target"])
            try:
                info = os.fstat(parent)
                if [info.st_dev, info.st_ino] != link["parent"]:
                    raise Refused("RESTORE_PARENT_CHANGED")
                os.symlink("../" + unit, name, dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)

    def verify(self, step, proof):
        unit, raw = self._unit(step)
        self._fragment(unit)
        if step["kind"] == "service":
            if proof != {"inactive": True, "sha256": step["desired"]["sha256"]} or not self._active(unit):
                raise Refused("RESTORE_UNIT_STATE_CHANGED")
            return
        links = self._links(unit, self._targets(raw))
        if (proof.get("sha256") != step["desired"]["sha256"] or
                [{**link, "present": False} for link in links] != proof.get("links") or
                any(link["present"] != (step["desired"]["state"] == "enabled") for link in links)):
            raise Refused("RESTORE_ENABLEMENT_CHANGED")
        observed = self._command(["is-enabled", unit], accepted=(0, 1))
        if observed != step["desired"]["state"]:
            raise Refused("RESTORE_ENABLEMENT_CHANGED")

    def undo(self, step, proof):
        unit, raw = self._unit(step)
        self._fragment(unit)
        if step["kind"] == "service":
            if proof != {"inactive": True, "sha256": step["desired"]["sha256"]}:
                raise Refused("INVALID_RESTORE_PROOF")
            if self._active(unit):
                self._command(["stop", unit])
            if self._active(unit):
                raise Refused("RESTORE_UNIT_STATE_CHANGED")
            return
        links = self._links(unit, self._targets(raw))
        if (proof.get("sha256") != step["desired"]["sha256"] or
                [{**link, "present": False} for link in links] != proof.get("links")):
            raise Refused("RESTORE_ENABLEMENT_CHANGED")
        if step["desired"]["state"] != "enabled":
            if any(link["present"] for link in links):
                raise Refused("RESTORE_ENABLEMENT_CHANGED")
            return
        # All links were checked before removing any. Each unlink is relative
        # to the pinned parent, after another exact readlink check.
        for link in links:
            if not link["present"]:
                continue
            parent, name = self._link_parent(unit, link["target"])
            try:
                info = os.fstat(parent)
                if [info.st_dev, info.st_ino] != link["parent"] or os.readlink(name, dir_fd=parent) != "../" + unit:
                    raise Refused("RESTORE_ENABLEMENT_CHANGED")
                os.unlink(name, dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)


@contextmanager
def transaction_locks(restore: Any, *, images: bool = False):
    """Installation -> staging -> image export, retained through the caller.

    Recovery only needs installation/staging locks: original archives may no
    longer exist. The inputs are required again for any fresh application.
    """
    backup = restore.backup
    with ExitStack() as stack:
        run_fd = backup._safe_open(Path("/run"), directory=True)
        stack.callback(os.close, run_fd)
        run_info = os.fstat(run_fd)
        if run_info.st_uid != backup.ROOT_UID or stat.S_IMODE(run_info.st_mode) & 0o022:
            raise Refused("UNSAFE_INSTALLATION_LOCK")
        installation_fd = os.open(INSTALLATION_LOCK.name,
                                  os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  0o600, dir_fd=run_fd)
        stack.callback(os.close, installation_fd)
        _private(os.fstat(installation_fd), directory=False,
                 uid=backup.ROOT_UID, gid=backup.ROOT_GID)
        try:
            fcntl.flock(installation_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused("BUSY") from exc
        _folder, stage_fd = restore._staging_root()
        stack.callback(os.close, stage_fd)
        try:
            fcntl.flock(stage_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused("BUSY") from exc
        exporter = None
        if images:
            exporter = restore._portable_export_module()
            _folder, image_fd = exporter._output(create=False)
            stack.callback(os.close, image_fd)
            try:
                fcntl.flock(image_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Refused("BUSY") from exc
        yield stage_fd, exporter


def _read_private_fd(descriptor: int, *, maximum: int, uid: int, gid: int) -> tuple[bytes, tuple]:
    before = os.fstat(descriptor)
    _private(before, directory=False, uid=uid, gid=gid)
    if before.st_size > maximum:
        raise Refused("RESTORE_INPUT_LIMIT")
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = bytearray()
    while len(raw) <= maximum:
        block = os.read(descriptor, min(65536, maximum + 1 - len(raw)))
        if not block:
            break
        raw.extend(block)
    if len(raw) != before.st_size or _fingerprint(before) != _fingerprint(os.fstat(descriptor)):
        raise Refused("RESTORE_INPUT_CHANGED")
    return bytes(raw), _fingerprint(before)


def _atomic_replacement(directory_fd: int, name: str, before: os.stat_result,
                        after: os.stat_result, *, uid: int, gid: int) -> bool:
    # Unlink changes ctime/nlink on an otherwise immutable held inode. Every
    # other ownership/content observation must agree; an in-place write,
    # permission change or a still-linked/hardlinked old file is not a retry.
    def stable(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_size, info.st_mtime_ns)
    if (before.st_nlink not in (0, 1) or after.st_nlink != 0 or
            not stat.S_ISREG(before.st_mode) or stable(before) != stable(after) or
            (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) != (uid, gid, 0o600)):
        return False
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        _private(named, directory=False, uid=uid, gid=gid)
    except (FileNotFoundError, Refused):
        return False
    return (named.st_dev, named.st_ino) != (after.st_dev, after.st_ino)


def _read_atomic_private_at(directory_fd: int, name: str, *, maximum: int, uid: int, gid: int,
                            changed_code: str = "RESTORE_INPUT_CHANGED",
                            limit_code: str = "RESTORE_INPUT_LIMIT") -> tuple[bytes, tuple]:
    """Read current atomic JSON; never accept bytes from a detected old inode."""
    for attempt in range(4):
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                 dir_fd=directory_fd)
        except FileNotFoundError:
            if attempt:
                raise Refused(changed_code) from None
            raise
        try:
            before = os.fstat(descriptor)
            if before.st_nlink == 0:
                # A replacement may win after open but before the first stat.
                # No bytes from this already detached inode are considered.
                if not _atomic_replacement(directory_fd, name, before, os.fstat(descriptor), uid=uid, gid=gid):
                    raise Refused("UNSAFE_RESTORE_JOURNAL")
            else:
                _private(before, directory=False, uid=uid, gid=gid)
                if before.st_size > maximum:
                    raise Refused(limit_code)
                raw = bytearray()
                while len(raw) <= maximum:
                    block = os.read(descriptor, min(65536, maximum + 1 - len(raw)))
                    if not block:
                        break
                    raw.extend(block)
                after = os.fstat(descriptor)
                if len(raw) != before.st_size:
                    raise Refused(changed_code)
                if _fingerprint(before) == _fingerprint(after):
                    try:
                        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        raise Refused(changed_code) from None
                    if _fingerprint(named) == _fingerprint(after):
                        return bytes(raw), _fingerprint(before)
                    if (named.st_dev, named.st_ino) == (after.st_dev, after.st_ino):
                        # Name lookup can resolve this inode immediately before
                        # replacement and report its now-unlinked metadata.
                        after = named
                    else:
                        # No mutation was observed on the held inode. A later
                        # replacement must now prove unlink; hardlinks refuse.
                        after = os.fstat(descriptor)
                if not _atomic_replacement(directory_fd, name, before, after, uid=uid, gid=gid):
                    raise Refused(changed_code)
            if attempt == 3:
                raise Refused(changed_code)
        finally:
            os.close(descriptor)
    raise Refused(changed_code)


class Inputs:
    """Verified FDs retained from final preflight until commit or rollback."""

    def __init__(self, restore: Any, identity: str, stage_fd: int, exporter: Any,
                 host_fd: int, host: dict, images_fd: int, images: dict,
                 metadata: dict[str, tuple[int, bytes, tuple]], preview: dict):
        self.restore, self.identity, self.stage_fd = restore, identity, stage_fd
        self.exporter, self.host_fd, self.host = exporter, host_fd, host
        self.images_fd, self.images, self.metadata = images_fd, images, metadata
        self.preview = preview
        self.root_uid, self.root_gid = restore.backup.ROOT_UID, restore.backup.ROOT_GID
        self.host_fingerprint = _fingerprint(os.fstat(host_fd))
        self.images_fingerprint = _fingerprint(os.fstat(images_fd))
        self.stage_fingerprint = (os.fstat(stage_fd).st_dev, os.fstat(stage_fd).st_ino)
        self.platforms = {}
        self.runtime_ids = {}
        exported = {}
        count = exporter._inspect_image_tar(
            images_fd, images["images"], deadline=time.monotonic() + 1200,
            platforms=self.platforms, source_rootfs=images["rootfs_sha256"],
            exported_configs=exported, runtime_ids=self.runtime_ids)
        if count != images["files"] or exported != images["exported_configs"]:
            raise Refused("RESTORE_INPUT_CHANGED")
        self.bindings = {
            "apply_review_sha256": preview["apply_review_sha256"],
            "stage_review_sha256": preview["stage_review_sha256"],
            "source_manifest_sha256": host["source_manifest_sha256"],
            "host_archive_sha256": host["sha256"],
            "host_manifest_sha256": hashlib.sha256(metadata["host_manifest"][1]).hexdigest(),
            "images_sha256": images["sha256"],
            "image_manifest_sha256": hashlib.sha256(metadata["image_manifest"][1]).hexdigest(),
            "portable_receipt_sha256": hashlib.sha256(metadata["portable_receipt"][1]).hexdigest(),
            "tree_sha256": restore._read_portable_marker(stage_fd, identity)["tree_sha256"],
        }

    def unchanged(self, *, hash_contents: bool = False) -> None:
        if (_fingerprint(os.fstat(self.host_fd)) != self.host_fingerprint or
                _fingerprint(os.fstat(self.images_fd)) != self.images_fingerprint):
            raise Refused("RESTORE_INPUT_CHANGED")
        for descriptor, expected_raw, before in self.metadata.values():
            if _fingerprint(os.fstat(descriptor)) != before:
                raise Refused("RESTORE_INPUT_CHANGED")
            raw, _ = _read_private_fd(descriptor, maximum=64 * 1024,
                                      uid=self.restore.backup.ROOT_UID,
                                      gid=self.restore.backup.ROOT_GID)
            if raw != expected_raw:
                raise Refused("RESTORE_INPUT_CHANGED")
        # Path-based stage readers must still refer to the pinned directory.
        current = self.restore.backup._safe_open(self.restore.STAGING, directory=True)
        try:
            info = os.fstat(current)
            if (info.st_dev, info.st_ino) != self.stage_fingerprint:
                raise Refused("RESTORE_STAGE_CHANGED")
        finally:
            os.close(current)
        if hash_contents:
            self.restore._hash_archive(self.host_fd, self.host,
                                       deadline=time.monotonic() + 600)
            self.exporter._hash_tar(self.images_fd, self.images,
                                    deadline=time.monotonic() + 1200)
            if self.restore._stage_tree_digest(
                    self.restore.backup._host(self.restore.STAGING) / self.identity,
                    deadline=time.monotonic() + 600) != self.bindings["tree_sha256"]:
                raise Refused("RESTORE_STAGE_CHANGED")


@contextmanager
def held_inputs(restore: Any, identity: str, expected_apply_review_sha256: str | None, *,
                _for_preview: bool = False):
    """Recheck a full v2 pair under locks and pin all five transferred files.

    No user, live directory, image, container, or service is changed. Consumers
    use these retained descriptors, never reopen a transfer path for mutation.
    """
    restore._require_root()
    identity = _id(identity)
    if not (_for_preview and expected_apply_review_sha256 is None) and (
            not isinstance(expected_apply_review_sha256, str) or SHA.fullmatch(expected_apply_review_sha256) is None):
        raise Refused("INVALID_RESTORE_REVIEW")
    with transaction_locks(restore, images=True) as (stage_fd, exporter), ExitStack() as stack:
        current_journal = Journal(stage_fd, identity, uid=restore.backup.ROOT_UID, gid=restore.backup.ROOT_GID)
        _refuse_other_journals(current_journal)
        current = current_journal.read()
        if current is not None:
            raise Refused("RESTORE_RETRY_REQUIRED" if current["phase"] == "rolled_back" else
                          "RESTORE_ALREADY_COMMITTED" if current["phase"] == "committed" else "RESTORE_RECOVERY_REQUIRED")
        host_fd, host = restore._archive_fd(identity)
        stack.callback(os.close, host_fd)
        _folder, image_directory, images_fd, images = exporter._artifact(identity)
        stack.callback(os.close, image_directory)
        stack.callback(os.close, images_fd)
        metadata = {}
        host_manifest_fd = restore.backup._safe_open(
            restore.backup.OUTPUT / (identity + ".manifest.json"))
        stack.callback(os.close, host_manifest_fd)
        for key, name, maximum in (
                ("host_manifest", None, 64 * 1024),
                ("image_manifest", "manifest.json", 64 * 1024),
                ("portable_receipt", "receipt.json", 8192)):
            if name is None:
                descriptor = host_manifest_fd
            else:
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                                     os.O_CLOEXEC, dir_fd=image_directory)
                stack.callback(os.close, descriptor)
            raw, fingerprint = _read_private_fd(
                descriptor, maximum=maximum, uid=restore.backup.ROOT_UID,
                gid=restore.backup.ROOT_GID)
            metadata[key] = (descriptor, raw, fingerprint)
        try:
            if (json.loads(metadata["host_manifest"][1], object_pairs_hook=_unique) != host or
                    json.loads(metadata["image_manifest"][1], object_pairs_hook=_unique) != images):
                raise Refused("RESTORE_INPUT_CHANGED")
            receipt = json.loads(metadata["portable_receipt"][1], object_pairs_hook=_unique)
        except (ValueError, UnicodeError) as exc:
            raise Refused("INVALID_RESTORE_INPUT") from exc
        if host["layout"] != "full":
            raise Refused("RESTORE_LAYOUT_UNSUPPORTED")
        if receipt.get("protocol") != restore.PORTABLE_RECEIPT_V2:
            raise Refused("RECEIPT_V1_UNSUPPORTED")
        states = receipt.get("unit_states")
        if (not isinstance(states, dict) or any(
                not isinstance(state, dict) or state.get("enablement") not in
                ("enabled", "disabled", "static") for state in states.values())):
            raise Refused("RESTORE_ENABLEMENT_UNSUPPORTED")
        # This path explicitly passes the owned stage FD. A second flock via a
        # separately opened FD would refuse the exclusive lock held above.
        preview = restore.portable_apply_preview(identity, _root_fd=stage_fd)
        retained = Inputs(restore, identity, stage_fd, exporter, host_fd, host,
                          images_fd, images, metadata, preview)
        retained.unchanged(hash_contents=True)
        if (retained.bindings["image_manifest_sha256"] !=
                restore._portable_metadata_hashes(exporter, identity)["image_manifest_sha256"] or
                retained.bindings["portable_receipt_sha256"] !=
                restore._portable_metadata_hashes(exporter, identity)["portable_receipt_sha256"]):
            raise Refused("RESTORE_INPUT_CHANGED")
        physical = [code for code in preview["blockers"] if code != "APPLY_NOT_IMPLEMENTED"]
        plan = None
        if not physical:
            try:
                plan = build_resource_plan(retained)
            except RuntimeError as exc:
                code = str(exc)
                if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code) is None:
                    raise Refused("RESTORE_PREVIEW_FAILED") from None
                physical.append(code)
        retry_name = ".retry-" + identity + ".json"
        attempt_revision = None
        try:
            descriptor = os.open(retry_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=stage_fd)
        except FileNotFoundError:
            pass
        else:
            try:
                raw, _ = _read_private_fd(descriptor, maximum=16384,
                    uid=restore.backup.ROOT_UID, gid=restore.backup.ROOT_GID)
                retry = json.loads(raw, object_pairs_hook=_unique)
                if (not isinstance(retry, dict) or retry.get("protocol") != "sovagrid-portable-restore-retry-v1" or retry.get("id") != identity or
                        retry.get("phase") != "complete" or not isinstance(retry.get("nonce"), str) or
                        ID.fullmatch(retry["nonce"]) is None):
                    raise Refused("RESTORE_RETRY_REQUIRED")
                attempt_revision = retry["nonce"]
            finally:
                os.close(descriptor)
        retained.public_preview = _full_preview(preview, plan, physical, attempt_revision=attempt_revision)
        retained.bindings["apply_review_sha256"] = retained.public_preview["apply_review_sha256"]
        if not _for_preview:
            if retained.public_preview["apply_review_sha256"] != expected_apply_review_sha256:
                raise Refused("STALE_RESTORE_REVIEW")
            if retained.public_preview["target_ready"] is not True:
                raise Refused("RESTORE_TARGET_NOT_READY")
        yield retained


def _full_preview(base, plan, blockers, *, attempt_revision=None):
    physical = list(dict.fromkeys(blockers))
    resource = None if plan is None else plan["bindings"]["resource_manifest_sha256"]
    policy = {"queued_jobs": "cancel", "telegram_confirmations": "cancel", "vpn": "restore_configuration_down",
              "public_address_override": False, "layout": "full", "receipt": "v2"}
    review = {"protocol": "sovagrid-portable-restore-apply-review-v2",
              "base_review_sha256": base["apply_review_sha256"], "resource_manifest_sha256": resource,
              "backend_supported": APPLY_ENABLED, "policy": policy, "blockers": physical,
              "attempt_revision": attempt_revision}
    return {**base, "protocol": review["protocol"], "backend_supported": APPLY_ENABLED,
            "target_ready": not physical, "apply_available": APPLY_ENABLED and not physical,
            "resource_manifest_sha256": resource, "policy": policy,
            "attempt_revision": attempt_revision,
            "blockers": ([] if APPLY_ENABLED else ["APPLY_NOT_IMPLEMENTED"]) + physical,
            "apply_review_sha256": hashlib.sha256(_canonical(review)).hexdigest()}


def preview_host(restore, identity):
    restore._require_root()
    identity = _id(identity)
    try:
        with held_inputs(restore, identity, None, _for_preview=True) as inputs:
            return inputs.public_preview
    except RuntimeError as exc:
        code = str(exc)
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code) is None:
            raise Refused("RESTORE_PREVIEW_FAILED") from None
        # Unsupported v1/layout/state is a reviewable blocker, not an opaque
        # failure after the administrator has already confirmed installation.
        base = restore._portable_apply_preview_base(identity)
        blockers = [item for item in base["blockers"] if item != "APPLY_NOT_IMPLEMENTED"]
        return _full_preview(base, None, [*blockers, code])


def _resource_root(path: str) -> str:
    parts = PurePosixPath(path).parts
    if (not path.startswith("/") or path != PurePosixPath(path).as_posix() or
            any(part in (".", "..") for part in parts)):
        raise Refused("INVALID_RESTORE_PATH")
    if len(parts) >= 3 and parts[1] == "etc" and re.fullmatch(
            r"sovagrid(?:-[a-z0-9-]{1,64})?", parts[2]):
        return "/" + "/".join(parts[1:3])
    if len(parts) >= 4 and parts[1:3] == ("var", "lib") and re.fullmatch(
            r"sovagrid(?:-[a-z0-9-]{1,64})?", parts[3]):
        return "/" + "/".join(parts[1:4])
    if len(parts) >= 3 and parts[1] == "opt" and re.fullmatch(
            r"sovagrid-[a-z0-9-]{1,64}", parts[2]):
        return "/" + "/".join(parts[1:3])
    if (len(parts) == 5 and parts[1:4] == ("etc", "systemd", "system") and
            re.fullmatch(r"sovagrid-[a-z0-9-]{1,80}\.(?:service|socket|timer)", parts[4])):
        return path
    if path in ("/var/cache/sovagrid-web-restores",
                "/etc/sysctl.d/70-sovagrid-vpn-routing.conf",
                "/usr/local/bin/sovagrid-vpn-ctl", "/usr/local/libexec/sovagrid-vpn-broker"):
        return path
    raise Refused("INVALID_RESTORE_PATH")


def _resource_digest(entries: dict[str, dict]) -> str:
    """The same closed traversal/metadata digest used by tree_proof()."""
    if "" not in entries:
        raise Refused("INVALID_RESTORE_RESOURCE_PLAN")
    children = {}
    for relative in entries:
        if not relative:
            continue
        parent = relative.rpartition("/")[0]
        if parent not in entries or entries[parent]["kind"] != "dir":
            raise Refused("INVALID_RESTORE_RESOURCE_PLAN")
        children.setdefault(parent, []).append(relative)
    digest = hashlib.sha256()

    def visit(relative):
        source = entries[relative]
        value = {"path": relative, "kind": source["kind"], "uid": source["uid"],
                 "gid": source["gid"], "mode": source["mode"]}
        if source["kind"] == "file":
            value.update(size=source["size"], sha256=source["sha256"])
        elif source["kind"] != "dir":
            raise Refused("INVALID_RESTORE_RESOURCE_PLAN")
        digest.update(_canonical(value) + b"\0")
        for child in sorted(children.get(relative, [])):
            visit(child)

    visit("")
    return digest.hexdigest()


def _unused_agent_uid() -> int:
    for candidate in range(999, 99, -1):
        try:
            pwd.getpwuid(candidate)
        except KeyError:
            return candidate
    raise Refused("RESTORE_AGENT_UID_UNAVAILABLE")


def _staged_json(inputs: Inputs, absolute: str, maximum: int) -> dict:
    descriptor = inputs.restore.backup._safe_open(
        inputs.restore.STAGING / inputs.identity / absolute.lstrip("/"))
    try:
        raw, _fingerprint_value = _read_private_fd(
            descriptor, maximum=maximum, uid=inputs.restore.backup.ROOT_UID,
            gid=inputs.restore.backup.ROOT_GID)
        value = json.loads(raw, object_pairs_hook=_unique)
        if not isinstance(value, dict):
            raise Refused("INVALID_RESTORE_CONFIGURATION")
        return value
    except (ValueError, UnicodeError) as exc:
        raise Refused("INVALID_RESTORE_CONFIGURATION") from exc
    finally:
        os.close(descriptor)


def _public_target_check(inputs: Inputs, present: set[str]) -> dict | None:
    if "/etc/sovagrid/public-web/state.json" not in present:
        return None
    # Validate generation files against the sealed stage before checking live
    # target interfaces/DNS. A response from the source server is never health.
    helper = inputs.restore._sibling("public_web.py", "_sovagrid_restore_public_check")
    staged = inputs.restore.backup._host(inputs.restore.STAGING) / inputs.identity
    public = helper.PublicWeb(root=staged, uid=inputs.restore.backup.ROOT_UID)
    try:
        state, _revision = public.state()
        if state is None:
            raise Refused("RESTORE_PUBLIC_CONFIGURATION_INVALID")
        public.address_check(state["config"])
        if state["config"]["acme_environment"] != "production":
            raise Refused("RESTORE_PUBLIC_STAGING_UNSUPPORTED")
        return state["config"]
    except helper.PublicWebError as exc:
        raise Refused("PUBLIC_ENDPOINT_MISMATCH" if exc.code in (
            "ADDRESS_NOT_LOCAL", "IPV6_UNAVAILABLE") else
            "RESTORE_PUBLIC_CONFIGURATION_INVALID") from exc


def _dependencies_check(present: set[str]) -> None:
    tools = []
    wireguard = "/etc/sovagrid/.vpn-control-managed-by-run-sh" in present
    if wireguard:
        tools.append("/usr/bin/wg")
    if "/etc/systemd/system/sovagrid-vpn-routing.service" in present:
        tools.append("/usr/sbin/nft")
    for tool in tools:
        try:
            info = os.lstat(tool)
        except OSError as exc:
            raise Refused("RESTORE_DEPENDENCIES_REQUIRED") from exc
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                stat.S_IMODE(info.st_mode) & 0o022 or not info.st_mode & stat.S_IXUSR):
            raise Refused("RESTORE_DEPENDENCIES_REQUIRED")
    if wireguard:
        try:
            command = subprocess.run(["/usr/bin/python3", "-I", "-c", "import cryptography"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=10, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Refused("RESTORE_DEPENDENCIES_REQUIRED") from exc
        if command.returncode:
            raise Refused("RESTORE_DEPENDENCIES_REQUIRED")


def build_resource_plan(inputs: Inputs, *, check_public: bool = True) -> dict:
    """Derive live metadata and runtime resources from the held verified tar.

    This function is read-only. In particular, stage parents' root:root0700
    metadata is NEVER copied into /etc/sovagrid or the running data namespaces.
    A production adapter must journal shadow construction before publishing
    any of these resources; this plan alone grants no mutation capability.
    """
    restore, backup = inputs.restore, inputs.restore.backup
    if inputs.host["layout"] != "full":
        raise Refused("RESTORE_LAYOUT_UNSUPPORTED")
    inputs.unchanged()
    inspected = restore._inspect_tar(inputs.host_fd, inputs.host, backup._sources("full"),
                                     deadline=time.monotonic() + 600)
    identities = inspected["identities"]
    if "sovagrid" not in identities["groups"]:
        raise Refused("RESTORE_AGENT_IDENTITY_MISSING")
    groups = dict(identities["groups"])
    users = {name: {"uid": uid, "gid": groups[name]}
             for name, uid in identities["users"].items()}
    users["sovagrid"] = {"uid": _unused_agent_uid(), "gid": groups["sovagrid"]}
    # Reusing a matching NSS entry is deliberately not enough: home/shell and
    # supplementary groups would need a separate adoption contract.
    for name, gid in groups.items():
        if Identities._named_group(name) is not None:
            raise Refused("RESTORE_IDENTITY_EXISTS")
        try:
            grp.getgrgid(gid)
        except KeyError:
            pass
        else:
            raise Refused("RESTORE_IDENTITY_EXISTS")
    for name, value in users.items():
        if Identities._named_user(name) is not None:
            raise Refused("RESTORE_IDENTITY_EXISTS")
        try:
            pwd.getpwuid(value["uid"])
        except KeyError:
            pass
        else:
            raise Refused("RESTORE_IDENTITY_EXISTS")
    if "sovagrid-journal" in users and Identities._named_group("systemd-journal") is None:
        raise Refused("RESTORE_JOURNAL_GROUP_UNAVAILABLE")
    resources = {}
    present = set()
    deadline = time.monotonic() + 600
    total_bytes = 0
    os.lseek(inputs.host_fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(inputs.host_fd), "rb") as stream:
        with tarfile.open(fileobj=stream, mode="r|gz") as archive:
            for member in archive:
                if time.monotonic() > deadline:
                    raise Refused("RESTORE_TIME_LIMIT")
                path, directory = restore._member_path(member)
                if path in present or len(present) >= MAX_TREE_ENTRIES:
                    raise Refused("RESTORE_FILE_LIMIT")
                total_bytes += member.size
                if member.size > 4 * 1024**3 or total_bytes > MAX_TREE_BYTES:
                    raise Refused("RESTORE_SIZE_LIMIT")
                root = _resource_root(path)
                relative = path[len(root):].lstrip("/")
                entries = resources.setdefault(root, {})
                if relative in entries:
                    raise Refused("INVALID_RESTORE_RESOURCE_PLAN")
                value = {"kind": "dir" if directory else "file", "uid": member.uid,
                         "gid": member.gid, "mode": member.mode, "mtime": member.mtime}
                if not directory:
                    reader = archive.extractfile(member)
                    if reader is None:
                        raise Refused("INVALID_RESTORE_RESOURCE_PLAN")
                    digest, size = hashlib.sha256(), 0
                    while True:
                        if time.monotonic() > deadline:
                            raise Refused("RESTORE_TIME_LIMIT")
                        block = reader.read(1024 * 1024)
                        if not block:
                            break
                        size += len(block)
                        if size > member.size:
                            raise Refused("RESTORE_INPUT_CHANGED")
                        digest.update(block)
                    if size != member.size:
                        raise Refused("RESTORE_INPUT_CHANGED")
                    value.update(size=size, sha256=digest.hexdigest(), source=path)
                entries[relative] = value
                present.add(path)
    for root, entries in resources.items():
        if "" in entries:
            continue
        if root == "/etc/sovagrid":
            entries[""] = {"kind": "dir", "uid": 0, "gid": groups["sovagrid"],
                           "mode": 0o750, "mtime": 0}
        elif root == "/var/lib/sovagrid":
            entries[""] = {"kind": "dir", "uid": 0, "gid": 0, "mode": 0o700, "mtime": 0}
        else:
            raise Refused("RESTORE_PARENT_METADATA_UNAVAILABLE")
    config = _staged_json(inputs, "/etc/sovagrid/agent.json", 256 * 1024)
    if config.get("allow_file_manager") is True:
        if config.get("file_roots") != {"workspace": "/var/lib/sovagrid-agent/files"}:
            raise Refused("RESTORE_FILE_ROOTS_UNSUPPORTED")
    agent = users["sovagrid"]
    resources["/var/lib/sovagrid-agent"] = {
        "": {"kind": "dir", "uid": agent["uid"], "gid": agent["gid"],
             "mode": 0o700, "mtime": 0}}
    if config.get("allow_file_manager") is True:
        resources["/var/lib/sovagrid-agent"]["files"] = dict(
            resources["/var/lib/sovagrid-agent"][""])
    if "/etc/sovagrid/.terminal-unit-managed-by-run-sh" in present:
        if "sovagrid-shell" not in users:
            raise Refused("RESTORE_TERMINAL_IDENTITY_MISSING")
        resources["/var/lib/sovagrid-shell"] = {
            "": {"kind": "dir", "uid": 10003, "gid": 10003, "mode": 0o700, "mtime": 0}}
    receipt = json.loads(inputs.metadata["portable_receipt"][1], object_pairs_hook=_unique)
    states = receipt["unit_states"]
    workspaces = []
    if "sovagrid-hub-backup-control.service" in states:
        # These empty installer workspaces are intentionally outside the
        # archive. The restored broker nevertheless requires their exact RW
        # mounts, including when a currently inactive socket starts later.
        workspaces.extend(("/opt/sovagrid-candidates", "/var/lib/sovagrid-host-backup-operations"))
    if "sovagrid-web-agent-control.service" in states:
        # Bulk restore-upload cache is excluded from archives. Claim a fresh
        # private directory before service activation instead of letting
        # systemd adopt or recursively chown an unrelated existing cache.
        workspaces.append("/var/cache/sovagrid-web-restores")
    for target in workspaces:
        descriptor, name = _safe_parent(backup.ROOT, target, uid=backup.ROOT_UID)
        try:
            try:
                os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refused("RESTORE_RUNTIME_STATE_PRESENT")
        finally:
            os.close(descriptor)
        resources[target] = {"": {"kind": "dir", "uid": 0, "gid": 0,
                                   "mode": 0o700, "mtime": 0}}
    for unit in states:
        Services(backup.ROOT, states, uid=backup.ROOT_UID, gid=backup.ROOT_GID).audit(unit)
    if any(state["enablement"] not in ("enabled", "disabled", "static")
           for state in states.values()):
        raise Refused("RESTORE_ENABLEMENT_UNSUPPORTED")
    # Routing changes kernel state outside the file/archive transaction. Its
    # previous sysctl/nft state needs a separate adapter before it can be used.
    routing = states.get("sovagrid-vpn-routing.service", {})
    if routing.get("active") is True or routing.get("enablement") == "enabled":
        raise Refused("RESTORE_ROUTING_STATE_UNSUPPORTED")
    _dependencies_check(present)
    public_config = _public_target_check(inputs, present) if check_public else None
    selected = {name for name, state in states.items() if state["active"]}
    before = sorted(name for name in selected if name.endswith(".socket"))
    # An Agent may immediately use a restored broker socket. Start every
    # originally active paired service before consumers, so its subsequent
    # plan step cannot accidentally adopt socket-triggered activation.
    paired = {name.removesuffix(".socket") + ".service" for name in before}
    before.extend(sorted(selected & paired))
    after = sorted(name for name in selected if name not in before and not name.endswith(".timer"))
    timers = sorted(name for name in selected if name.endswith(".timer"))
    parents = set()
    planned = []
    filesystem_bytes = {}
    for index, (root, entries) in enumerate(sorted(resources.items())):
        parent = str(PurePosixPath(root).parent)
        # Standard parent directories are read-only prerequisites for now;
        # missing /usr/local/libexec gets an explicit journaled-parent task.
        try:
            descriptor, _name = _safe_parent(backup.ROOT, root, uid=backup.ROOT_UID)
        except FileNotFoundError:
            if parent != "/usr/local/libexec":
                raise Refused("RESTORE_TARGET_PARENT_MISSING") from None
            parents.add(parent)
            descriptor, _name = _safe_parent(backup.ROOT, parent, uid=backup.ROOT_UID)
        try:
            info = os.fstat(descriptor)
            filesystem_bytes[info.st_dev] = filesystem_bytes.get(info.st_dev, 0) + sum(
                entry.get("size", 0) for entry in entries.values())
            if os.fstatvfs(descriptor).f_bavail * os.fstatvfs(descriptor).f_frsize < (
                    filesystem_bytes[info.st_dev] + 256 * 1024**2):
                raise Refused("RESTORE_DISK_SPACE")
        finally:
            os.close(descriptor)
        planned.append({"target": root, "shadow": ".sovagrid-restore-" + inputs.identity + "-" + str(index),
                        "sha256": _resource_digest(entries), "entries": entries})
    for unit, state in states.items():
        unit_resource = resources.get("/etc/systemd/system/" + unit, {})
        raw_entry = unit_resource.get("")
        if raw_entry is None or raw_entry["sha256"] != state["sha256"]:
            raise Refused("RESTORE_UNIT_CHANGED")
        descriptor = backup._safe_open(
            restore.STAGING / inputs.identity / "etc/systemd/system" / unit)
        try:
            raw, _fingerprint_value = _read_private_fd(
                descriptor, maximum=128 * 1024, uid=backup.ROOT_UID, gid=backup.ROOT_GID)
        finally:
            os.close(descriptor)
        if hashlib.sha256(raw).hexdigest() != state["sha256"]:
            raise Refused("RESTORE_UNIT_CHANGED")
        wanted = Services(backup.ROOT, states)._targets(raw)
        if (state["enablement"] == "static") != (not wanted):
            raise Refused("RESTORE_ENABLEMENT_UNSUPPORTED")
        for target in wanted:
            parents.add("/etc/systemd/system/" + target + ".wants")
    runtime_paths = {SOCKET_PARENTS[unit] for unit in selected if unit in SOCKET_PARENTS}
    if "sovagrid-agent.service" in selected:
        runtime_paths.add("/run/sovagrid-agent-control")
    for target in sorted(runtime_paths):
        descriptor, name = _safe_parent(backup.ROOT, target, uid=backup.ROOT_UID)
        try:
            try:
                os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refused("RESTORE_RUNTIME_STATE_PRESENT")
        finally:
            os.close(descriptor)
        if target != "/run/sovagrid-agent-control":
            parents.add(target)
    for target in sorted(parents):
        descriptor, name = _safe_parent(backup.ROOT, target, uid=backup.ROOT_UID)
        try:
            try:
                current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                current = None
            if current is not None:
                if (not stat.S_ISDIR(current.st_mode) or current.st_uid != backup.ROOT_UID or
                        current.st_gid != backup.ROOT_GID or stat.S_IMODE(current.st_mode) & 0o022):
                    raise Refused("UNSAFE_RESTORE_PARENT")
                continue
        finally:
            os.close(descriptor)
        entries = {"": {"kind": "dir", "uid": 0, "gid": 0, "mode": 0o755, "mtime": 0}}
        planned.append({"target": target,
                        "shadow": ".sovagrid-restore-" + inputs.identity + "-" + str(len(planned)),
                        "sha256": _resource_digest(entries), "entries": entries})
    plan = {"protocol": "sovagrid-portable-restore-resources-v1", "id": inputs.identity,
            "layout": "full", "identities": {"groups": groups, "users": users},
            "resources": planned, "parents": sorted(parents), "unit_states": states,
            "runtime_absent_paths": sorted(runtime_paths),
            "before_compose": before, "after_compose": after, "timers": timers,
            "public_config": public_config,
            "compose_services": sorted(inputs.images["exported_configs"]),
            "images": {service: {"config": digest,
                                  "rootfs_sha256": inputs.images["rootfs_sha256"][service],
                                  "platform": inputs.platforms[service],
                                  "runtime_ids": inputs.runtime_ids[service]}
                       for service, digest in inputs.images["exported_configs"].items()}}
    if len(_canonical(plan)) > 8 * 1024**2 or len(planned) > 100:
        raise Refused("RESTORE_RESOURCE_PLAN_LIMIT")
    inputs.unchanged()
    plan["bindings"] = {**inputs.bindings, "resource_manifest_sha256":
                        hashlib.sha256(_canonical(plan)).hexdigest()}
    return plan


def host_status(restore: Any, identity: str) -> dict:
    """Read the atomic journal while a worker holds its mutation locks."""
    restore._require_root()
    identity = _id(identity)
    try:
        stage_fd = restore.backup._safe_open(restore.STAGING, directory=True)
    except FileNotFoundError as exc:
        raise Refused("RESTORE_NOT_FOUND") from exc
    try:
        return status(Journal(stage_fd, identity, uid=restore.backup.ROOT_UID,
                              gid=restore.backup.ROOT_GID))
    finally:
        os.close(stage_fd)


def _host_runtime(restore):
    return restore._sibling("portable_restore_runtime.py", "_sovagrid_restore_runtime")


def recover_host(restore: Any, identity: str) -> dict:
    """Recover journal-owned effects; never repeat forward installation steps."""
    restore._require_root()
    identity = _id(identity)
    with transaction_locks(restore) as (stage_fd, _exporter):
        journal = Journal(stage_fd, identity, uid=restore.backup.ROOT_UID,
                          gid=restore.backup.ROOT_GID)
        value = journal.read()
        if value is None:
            raise Refused("RESTORE_NOT_FOUND")
        runtime = _host_runtime(restore)
        plan = runtime.load(restore, sys.modules[__name__], stage_fd, identity, value["bindings"])
        driver = runtime.Runtime(restore, sys.modules[__name__], plan, journal)
        fence = Fence(restore.backup.ROOT, uid=restore.backup.ROOT_UID, gid=restore.backup.ROOT_GID)
        result = recover(journal, driver, fence=fence)
        driver.cleanup_commit(journal.read())
        return result


def host_retry_status(restore: Any, identity: str) -> dict | None:
    helper = restore._sibling("portable_restore_retry.py", "_sovagrid_portable_restore_retry_status")
    return helper.inspect(restore, sys.modules[__name__], identity)


def retry_host(restore: Any, identity: str, expected_terminal_sha256: str) -> dict:
    helper = restore._sibling("portable_restore_retry.py", "_sovagrid_portable_restore_retry")
    return helper.retry(restore, sys.modules[__name__], identity, expected_terminal_sha256)


def _apply_host_checked(restore: Any, identity: str, expected_apply_review_sha256: str) -> dict:
    """Run the verified transaction after the public capability check."""
    restore._require_root()
    identity = _id(identity)
    if not isinstance(expected_apply_review_sha256, str) or SHA.fullmatch(expected_apply_review_sha256) is None:
        raise Refused("INVALID_RESTORE_REVIEW")
    # A committed request must remain idempotent even though its live files
    # correctly make a new clean-target preview fail.
    with transaction_locks(restore) as (stage_fd, _exporter):
        journal = Journal(stage_fd, identity, uid=restore.backup.ROOT_UID,
                          gid=restore.backup.ROOT_GID)
        _refuse_other_journals(journal)
        old = journal.read()
        if old is not None:
            if old["bindings"]["apply_review_sha256"] != expected_apply_review_sha256:
                raise Refused("STALE_RESTORE_REVIEW")
            if old["phase"] != "committed":
                raise Refused("RESTORE_RECOVERY_REQUIRED")
            runtime = _host_runtime(restore)
            plan = runtime.load(restore, sys.modules[__name__], stage_fd, identity, old["bindings"])
            driver = runtime.Runtime(restore, sys.modules[__name__], plan, journal)
            driver.cleanup_commit(old)
            Fence(restore.backup.ROOT, uid=restore.backup.ROOT_UID, gid=restore.backup.ROOT_GID).release(identity, old["bindings"])
            return _public(old)
    with held_inputs(restore, identity, expected_apply_review_sha256) as inputs:
        plan = build_resource_plan(inputs)
        if plan["bindings"]["resource_manifest_sha256"] != inputs.public_preview["resource_manifest_sha256"]:
            raise Refused("STALE_RESTORE_REVIEW")
        runtime = _host_runtime(restore)
        runtime.persist(restore, sys.modules[__name__], inputs.stage_fd, plan)
        journal = Journal(inputs.stage_fd, identity, uid=restore.backup.ROOT_UID,
                          gid=restore.backup.ROOT_GID)
        driver = runtime.Runtime(restore, sys.modules[__name__], plan, journal, inputs=inputs)
        result = run(journal, driver, plan["bindings"], driver.steps(),
                     fence=Fence(restore.backup.ROOT, uid=restore.backup.ROOT_UID, gid=restore.backup.ROOT_GID))
        driver.cleanup_commit(journal.read())
        return result


def apply_host(restore: Any, identity: str, expected_apply_review_sha256: str) -> dict:
    restore._require_root()
    _id(identity)
    if not APPLY_ENABLED:
        raise Refused("APPLY_NOT_IMPLEMENTED")
    return _apply_host_checked(restore, identity, expected_apply_review_sha256)
