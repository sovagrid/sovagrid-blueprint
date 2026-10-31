#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Quarantine executable Hub work before portable-restore activation.

The journal records an inspection-only intent first. A Hub-owned disk clone
consumes any archived WAL and cancels queued work using trusted host Python,
never archived application code. A private, fsynced result receipt precedes
moving any original inode or publishing the clone. Recovery restores original
inodes only after proving every surviving original and derived byte. A crash
before the result receipt deliberately requires manual recovery: unknown clone
bytes are preserved, and the transaction driver retains the installation fence.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import uuid


DATABASE = "/var/lib/sovagrid/hub/hub.sqlite"
POLICY = {"policy": "cancel-restored-queued-v1"}
HUB_UID, HUB_GID = 10001, 10001
MAX_DATABASE = 4 * 1024**3
MAX_SHM = 16 * 1024**2
TIME_LIMIT = 600
FILES = ("hub.sqlite", "hub.sqlite-wal", "hub.sqlite-shm")

# Imports run before the chroot; -I -S excludes archived cwd/PYTHONPATH/site code.
# SQLite canonicalizes paths, so chdir alone cannot cross a root-private parent
# after setuid. The root helper chroots into the already opened Hub-owned clone.
_HELPER = r'''
import json, os, resource, sqlite3, sys, time
try:
    descriptor, uid, gid, now, maximum = map(int, sys.argv[1:])
    os.fchdir(descriptor)
    if os.geteuid() == 0:
        os.chroot('.')
        os.chdir('/')
        os.setgroups([])
    if os.getegid() != gid:
        os.setgid(gid)
    if os.geteuid() != uid:
        os.setuid(uid)
    os.close(descriptor)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
    resource.setrlimit(resource.RLIMIT_CPU, (580, 580))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    if sys.platform.startswith('linux'):
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    deadline = time.monotonic() + 570
    db = sqlite3.connect('file:hub.sqlite?mode=rw', uri=True, timeout=0,
                         isolation_level=None)
    db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
    db.execute('PRAGMA trusted_schema=OFF')
    db.execute('PRAGMA temp_store=MEMORY')
    db.execute('PRAGMA cache_size=-8192')
    db.execute('PRAGMA mmap_size=0')
    db.execute('PRAGMA synchronous=FULL')
    # Record the persistent mode before consolidating the archived WAL.
    journal_mode = db.execute('PRAGMA journal_mode').fetchall()[0][0].lower()
    if journal_mode not in ('delete', 'wal'):
        raise ValueError()
    # Never use immutable=1: a valid committed WAL is part of the archive.
    if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
        raise ValueError()
    schema = list(db.execute("SELECT type,name,sql FROM sqlite_master"))
    if any(kind == 'trigger' or (sql and 'CREATE VIRTUAL TABLE' in sql.upper())
           for kind, name, sql in schema):
        raise ValueError()
    tables = {name for kind, name, sql in schema if kind == 'table'}
    if not {'jobs', 'pending_commands', 'audit_events'} <= tables:
        raise ValueError()
    required = {'jobs': {'state', 'command', 'completed_at'},
                'pending_commands': {'command'},
                'audit_events': {'at', 'actor', 'action', 'server_id', 'subject_id', 'details'}}
    for table, columns in required.items():
        if not columns <= {r[1] for r in db.execute('PRAGMA table_info(' + table + ')')}:
            raise ValueError()
    # Consolidation and rollback journaling touch only the disk clone.
    if db.execute('PRAGMA journal_mode=DELETE').fetchall()[0][0].lower() != 'delete':
        raise ValueError()
    db.execute('BEGIN IMMEDIATE')
    pending = db.execute('SELECT COUNT(*) FROM pending_commands').fetchall()[0][0]
    queued = db.execute("UPDATE jobs SET state='cancelled', command='', completed_at=? WHERE state='queued'",
                        (now,)).rowcount
    db.execute('DELETE FROM pending_commands')
    counts = {'queued_jobs_cancelled': queued, 'pending_commands_removed': pending}
    db.execute("INSERT INTO audit_events(at,actor,action,server_id,subject_id,details) VALUES (?, 'system', 'portable_restore_queue_quarantined', NULL, NULL, ?)",
               (now, json.dumps(counts, sort_keys=True, separators=(',', ':'))))
    if db.execute("SELECT COUNT(*) FROM jobs WHERE state='queued'").fetchall()[0][0] or db.execute('SELECT COUNT(*) FROM pending_commands').fetchall()[0][0]:
        raise ValueError()
    db.commit()
    # WAL is part of Hub's initialized state; ordinary startup does not reset
    # it. Restore the recorded mode before publication. This is the clone's
    # sole connection, so its final close checkpoints/removes private sidecars.
    if db.execute('PRAGMA journal_mode=' + journal_mode).fetchall()[0][0].lower() != journal_mode:
        raise ValueError()
    if db.execute('PRAGMA journal_mode').fetchall()[0][0].lower() != journal_mode:
        raise ValueError()
    db.close()
    print(json.dumps({'counts': counts, 'journal_mode': journal_mode},
                     sort_keys=True, separators=(',', ':')))
except BaseException:
    # Do not expose malformed database contents, SQL errors, commands or secrets.
    sys.exit(1)
'''


class Queue:
    def __init__(self, restore, core, plan, inputs=None):
        self.restore, self.core, self.inputs = restore, core, inputs
        self.identity = core._id(plan["id"])
        self.uid, self.gid = restore.backup.ROOT_UID, restore.backup.ROOT_GID

    def _check(self, step):
        if (step["kind"] != "queue" or step["resource"] != DATABASE or
                step["desired"] != POLICY):
            raise self.core.Refused("INVALID_RESTORE_QUEUE")

    @staticmethod
    def _exists(parent, name):
        try:
            return os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def _open(self, step):
        self._check(step)
        parent, name = self.core._safe_parent(self.restore.backup.ROOT,
                                             str(Path(DATABASE).parent), uid=self.uid)
        try:
            hub = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                          os.O_CLOEXEC, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            self.core._private(os.fstat(hub), directory=True, uid=HUB_UID, gid=HUB_GID)
            parent, _name = self.core._safe_parent(self.restore.backup.ROOT,
                                                  "/var/lib/.sovagrid-queue", uid=self.uid)
            if os.fstat(parent).st_dev != os.fstat(hub).st_dev:
                os.close(parent)
                raise self.core.Refused("RESTORE_QUEUE_FILESYSTEM")
            return hub, parent
        except BaseException:
            os.close(hub)
            raise

    def _file(self, parent, name, *, uid=HUB_UID, gid=HUB_GID, maximum=MAX_DATABASE):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            self.core._private(before, directory=False, uid=uid, gid=gid)
            if before.st_size > maximum:
                raise self.core.Refused("RESTORE_QUEUE_SIZE_LIMIT")
            digest, total, deadline = hashlib.sha256(), 0, time.monotonic() + TIME_LIMIT
            while True:
                if time.monotonic() > deadline:
                    raise self.core.Refused("RESTORE_TIME_LIMIT")
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
                total += len(block)
                if total > before.st_size:
                    raise self.core.Refused("RESTORE_QUEUE_CHANGED")
            if (total != before.st_size or self.core._fingerprint(before) !=
                    self.core._fingerprint(os.fstat(descriptor))):
                raise self.core.Refused("RESTORE_QUEUE_CHANGED")
            return {"device": before.st_dev, "inode": before.st_ino,
                    "size": total, "sha256": digest.hexdigest(),
                    "mtime_ns": before.st_mtime_ns, "uid": uid, "gid": gid, "mode": 0o600}
        finally:
            os.close(descriptor)

    def _files(self, parent):
        result = {}
        for name in FILES:
            if self._exists(parent, name) is not None:
                result[name] = self._file(parent, name, uid=HUB_UID, gid=HUB_GID,
                                        maximum=MAX_SHM if name.endswith('-shm') else MAX_DATABASE)
        if FILES[0] not in result:
            raise self.core.Refused("RESTORE_QUEUE_DATABASE_MISSING")
        return result

    def _name(self, proof):
        if (not isinstance(proof, dict) or set(proof) != {
                "parent", "hub", "hub_times", "nonce", "original", "at"} or
                not isinstance(proof["nonce"], str) or self.core.ID.fullmatch(proof["nonce"]) is None or
                type(proof["at"]) is not int or not isinstance(proof["original"], dict) or
                FILES[0] not in proof["original"] or set(proof["original"]) - set(FILES)):
            raise self.core.Refused("INVALID_RESTORE_PROOF")
        return ".sovagrid-restore-queue-" + self.identity + "-" + proof["nonce"]

    def _parents(self, hub, parent, proof):
        self._name(proof)
        for descriptor, key in ((hub, "hub"), (parent, "parent")):
            info = os.fstat(descriptor)
            if [info.st_dev, info.st_ino] != proof[key]:
                raise self.core.Refused("RESTORE_PARENT_CHANGED")

    def _marker(self, proof):
        return self.core._canonical({"protocol": "sovagrid-restore-queue-owner-v1",
                                     "id": self.identity, "intent": proof}) + b"\n"

    def _private_read(self, parent, name):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            raw, _fp = self.core._read_private_fd(descriptor, maximum=16384, uid=self.uid, gid=self.gid)
            return raw
        finally:
            os.close(descriptor)

    def _write(self, parent, name, raw):
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                             os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            os.fchmod(descriptor, 0o600)
            self.core._private(os.fstat(descriptor), directory=False, uid=self.uid, gid=self.gid)
            self.core._write(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent)

    def _directory(self, parent, name, uid, gid, *, create=False):
        if create:
            os.mkdir(name, 0o700, dir_fd=parent)
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                             os.O_CLOEXEC, dir_fd=parent)
        try:
            if create:
                os.fchown(descriptor, uid, gid)
                os.fchmod(descriptor, 0o700)
                os.fsync(descriptor)
                os.fsync(parent)
            self.core._private(os.fstat(descriptor), directory=True, uid=uid, gid=gid)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _receipt(self, work, proof):
        if self._private_read(work, "owner") != self._marker(proof):
            raise self.core.Refused("RESTORE_QUEUE_OWNER_CHANGED")
        try:
            result = json.loads(self._private_read(work, "result.json"), object_pairs_hook=self.core._unique)
        except (FileNotFoundError, ValueError, UnicodeError) as exc:
            raise self.core.Refused("RESTORE_QUEUE_PROOF_INCOMPLETE") from exc
        if (not isinstance(result, dict) or set(result) != {"intent", "output", "counts", "journal_mode"} or
                result["intent"] != proof or not isinstance(result["output"], dict) or
                result["journal_mode"] not in ("delete", "wal") or
                not isinstance(result["counts"], dict) or set(result["counts"]) != {
                    "queued_jobs_cancelled", "pending_commands_removed"} or
                any(type(value) is not int or value < 0 for value in result["counts"].values())):
            raise self.core.Refused("RESTORE_QUEUE_PROOF_CHANGED")
        return result

    def prepare(self, step):
        hub, parent = self._open(step)
        try:
            info, hub_info = os.fstat(parent), os.fstat(hub)
            proof = {"parent": [info.st_dev, info.st_ino], "hub": [hub_info.st_dev, hub_info.st_ino],
                     "hub_times": [hub_info.st_atime_ns, hub_info.st_mtime_ns],
                     "nonce": uuid.uuid4().hex, "original": self._files(hub), "at": int(time.time())}
            if self._exists(parent, self._name(proof)) is not None:
                raise self.core.Refused("RESTORE_QUEUE_EXISTS")
            return proof
        finally:
            os.close(hub)
            os.close(parent)

    def _move(self, source_parent, target_parent, name):
        """Atomic cross-directory rename that cannot overwrite an unknown inode."""
        if not sys.platform.startswith("linux"):
            raise self.core.Refused("UNSUPPORTED_PLATFORM")
        function = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
        if function is None:
            raise self.core.Refused("UNSUPPORTED_PLATFORM")
        function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                             ctypes.c_char_p, ctypes.c_uint)
        function.restype = ctypes.c_int
        if function(source_parent, os.fsencode(name), target_parent, os.fsencode(name), 1):
            code = ctypes.get_errno()
            if code == errno.EEXIST:
                raise self.core.Refused("RESTORE_QUEUE_CHANGED")
            raise self.core.Refused("RESTORE_IO_ERROR")

    def _copy(self, source_parent, target_parent, name, expected):
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=source_parent)
        target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                         os.O_CLOEXEC, 0o600, dir_fd=target_parent)
        try:
            os.fchown(target, HUB_UID, HUB_GID)
            os.fchmod(target, 0o600)
            total, digest, deadline = 0, hashlib.sha256(), time.monotonic() + TIME_LIMIT
            before = self.core._fingerprint(os.fstat(source))
            while True:
                if time.monotonic() > deadline:
                    raise self.core.Refused("RESTORE_TIME_LIMIT")
                block = os.read(source, 1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > expected["size"]:
                    raise self.core.Refused("RESTORE_QUEUE_CHANGED")
                digest.update(block)
                self.core._write(target, block)
            if (total != expected["size"] or digest.hexdigest() != expected["sha256"] or
                    before != self.core._fingerprint(os.fstat(source))):
                raise self.core.Refused("RESTORE_QUEUE_CHANGED")
            os.fsync(target)
        finally:
            os.close(target)
            os.close(source)
        os.fsync(target_parent)

    def _quarantine(self, derived, at):
        try:
            result = subprocess.run([sys.executable, "-I", "-S", "-c", _HELPER,
                str(derived), str(HUB_UID), str(HUB_GID), str(at), str(MAX_DATABASE)],
                pass_fds=(derived,), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=TIME_LIMIT, check=False, env={"PATH": "/usr/bin:/bin"})
            outcome = json.loads(result.stdout)
            if (result.returncode != 0 or not isinstance(outcome, dict) or
                    set(outcome) != {"counts", "journal_mode"} or
                    outcome["journal_mode"] not in ("delete", "wal") or
                    not isinstance(outcome["counts"], dict) or set(outcome["counts"]) != {
                        "queued_jobs_cancelled", "pending_commands_removed"} or
                    any(type(value) is not int or value < 0 for value in outcome["counts"].values())):
                raise self.core.Refused("RESTORE_QUEUE_QUARANTINE_FAILED")
            return outcome
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            raise self.core.Refused("RESTORE_QUEUE_QUARANTINE_FAILED") from exc

    def execute(self, step, proof):
        hub, parent = self._open(step)
        work = original = derived = None
        try:
            self._parents(hub, parent, proof)
            if self._files(hub) != proof["original"]:
                raise self.core.Refused("RESTORE_QUEUE_CHANGED")
            # Bound clone + potential full rollback journal + WAL consolidation.
            needed = 2 * sum(item["size"] for item in proof["original"].values()) + 64 * 1024**2
            space = os.fstatvfs(parent)
            if space.f_bavail * space.f_frsize < needed:
                raise self.core.Refused("RESTORE_QUEUE_SPACE_REQUIRED")
            work = self._directory(parent, self._name(proof), self.uid, self.gid, create=True)
            self._write(work, "owner", self._marker(proof))
            original = self._directory(work, "original", HUB_UID, HUB_GID, create=True)
            derived = self._directory(work, "derived", HUB_UID, HUB_GID, create=True)
            for name in (FILES[0], FILES[1]):
                if name in proof["original"] and (name == FILES[0] or proof["original"][name]["size"]):
                    self._copy(hub, derived, name, proof["original"][name])
            outcome = self._quarantine(derived, proof["at"])
            if sorted(os.listdir(derived)) != [FILES[0]]:
                raise self.core.Refused("RESTORE_QUEUE_SIDECAR_REMAINS")
            # Fsync both data and directory before the receipt can authorize publication.
            descriptor = os.open(FILES[0], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=derived)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(derived)
            output = self._file(derived, FILES[0], uid=HUB_UID, gid=HUB_GID)
            receipt = {"intent": proof, "output": output, **outcome}
            self._write(work, "result.tmp", self.core._canonical(receipt) + b"\n")
            self.core._rename_noreplace(work, "result.tmp", "result.json")
            os.fsync(work)
            if self._files(hub) != proof["original"]:
                raise self.core.Refused("RESTORE_QUEUE_CHANGED")
            # Move sidecars before replacing the database. Every prefix is recoverable.
            for name in (FILES[1], FILES[2], FILES[0]):
                if name in proof["original"]:
                    self._move(hub, original, name)
                    os.fsync(hub)
                    os.fsync(original)
            self._move(derived, hub, FILES[0])
            os.fsync(derived)
            os.fsync(hub)
        finally:
            for descriptor in (derived, original, work, parent, hub):
                if descriptor is not None:
                    os.close(descriptor)

    def verify(self, step, proof):
        hub, parent = self._open(step)
        work = original = derived = None
        try:
            self._parents(hub, parent, proof)
            work = self._directory(parent, self._name(proof), self.uid, self.gid)
            receipt = self._receipt(work, proof)
            original = self._directory(work, "original", HUB_UID, HUB_GID)
            derived = self._directory(work, "derived", HUB_UID, HUB_GID)
            if (self._files(hub) != {FILES[0]: receipt["output"]} or
                    self._files(original) != proof["original"] or os.listdir(derived) or
                    set(os.listdir(work)) != {"owner", "result.json", "original", "derived"}):
                raise self.core.Refused("RESTORE_QUEUE_CHANGED")
        finally:
            for descriptor in (derived, original, work, parent, hub):
                if descriptor is not None:
                    os.close(descriptor)

    def _remove_work(self, parent, work, name):
        for child in ("original", "derived"):
            os.rmdir(child, dir_fd=work)
        for child in ("result.json", "owner"):
            os.unlink(child, dir_fd=work)
        os.fsync(work)
        os.rmdir(name, dir_fd=parent)
        os.fsync(parent)

    def undo(self, step, proof):
        hub, parent = self._open(step)
        work = original = derived = None
        try:
            self._parents(hub, parent, proof)
            name = self._name(proof)
            if self._exists(parent, name) is None:
                if self._files(hub) != proof["original"]:
                    raise self.core.Refused("RESTORE_QUEUE_CHANGED")
                return
            work = self._directory(parent, name, self.uid, self.gid)
            receipt = self._receipt(work, proof)
            original = self._directory(work, "original", HUB_UID, HUB_GID)
            derived = self._directory(work, "derived", HUB_UID, HUB_GID)
            if (set(os.listdir(work)) != {"owner", "result.json", "original", "derived"} or
                    set(os.listdir(original)) - set(proof["original"]) or
                    set(os.listdir(derived)) - {FILES[0]}):
                raise self.core.Refused("RESTORE_QUEUE_CHANGED")
            # Prove every byte before the first destructive action. Unknown runtime
            # rows, replacement inodes and new WALs require fenced manual recovery.
            live = {item: self._file(hub, item, uid=HUB_UID, gid=HUB_GID,
                    maximum=MAX_SHM if item.endswith('-shm') else MAX_DATABASE)
                    for item in FILES if self._exists(hub, item) is not None}
            retained = {item: self._file(original, item, uid=HUB_UID, gid=HUB_GID,
                        maximum=MAX_SHM if item.endswith('-shm') else MAX_DATABASE)
                        for item in os.listdir(original)}
            clone = self._file(derived, FILES[0], uid=HUB_UID, gid=HUB_GID) if os.listdir(derived) else None
            output_live = live.get(FILES[0]) == receipt["output"]
            if clone is not None and (clone != receipt["output"] or output_live):
                raise self.core.Refused("RESTORE_QUEUE_CHANGED")
            originals_live = {key: value for key, value in live.items() if not (key == FILES[0] and output_live)}
            if (set(originals_live) & set(retained) or
                    {**originals_live, **retained} != proof["original"]):
                raise self.core.Refused("RESTORE_QUEUE_CHANGED")
            if output_live:
                os.unlink(FILES[0], dir_fd=hub)
                os.fsync(hub)
            elif clone is not None:
                os.unlink(FILES[0], dir_fd=derived)
                os.fsync(derived)
            for item in FILES:
                if item in retained:
                    self._move(original, hub, item)
                    os.fsync(original)
                    os.fsync(hub)
            os.utime(hub, ns=tuple(proof["hub_times"]))
            os.fsync(hub)
            if self._files(hub) != proof["original"]:
                raise self.core.Refused("RESTORE_QUEUE_CHANGED")
            self._remove_work(parent, work, name)
        finally:
            for descriptor in (derived, original, work, parent, hub):
                if descriptor is not None:
                    os.close(descriptor)

    def cleanup_commit(self, step, proof):
        """Remove proven retained plaintext originals after durable commit.

        Live data may legitimately change after activation; it is never read,
        overwritten or removed by this cleanup. Missing retained files permit
        retry after interruption; any surviving changed bytes are preserved.
        """
        hub, parent = self._open(step)
        work = original = derived = None
        try:
            self._parents(hub, parent, proof)
            name = self._name(proof)
            if self._exists(parent, name) is None:
                return
            work = self._directory(parent, name, self.uid, self.gid)
            self._receipt(work, proof)
            original = self._directory(work, "original", HUB_UID, HUB_GID)
            derived = self._directory(work, "derived", HUB_UID, HUB_GID)
            if (set(os.listdir(work)) != {"owner", "result.json", "original", "derived"} or
                    set(os.listdir(original)) - set(proof["original"]) or os.listdir(derived)):
                raise self.core.Refused("RESTORE_QUEUE_CHANGED")
            names = os.listdir(original)
            for item in names:
                if self._file(original, item, uid=HUB_UID, gid=HUB_GID,
                        maximum=MAX_SHM if item.endswith('-shm') else MAX_DATABASE) != proof["original"][item]:
                    raise self.core.Refused("RESTORE_QUEUE_CHANGED")
            for item in names:
                os.unlink(item, dir_fd=original)
                os.fsync(original)
            self._remove_work(parent, work, name)
        finally:
            for descriptor in (derived, original, work, parent, hub):
                if descriptor is not None:
                    os.close(descriptor)
