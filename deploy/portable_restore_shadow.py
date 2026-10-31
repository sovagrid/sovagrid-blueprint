#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Journal-intent-owned shadow trees for portable host restoration.

The core and restore APIs are passed explicitly so independently verified
standalone restore scripts do not import an unrelated installed Python package.
Only the sealed stage supplies bytes; archive metadata comes from the bounded
resource plan. Every created namespace has an immutable nonce-bound owner file.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time
import uuid
from typing import Any


PARENTS = frozenset(("/usr/local/libexec",
                     "/etc/systemd/system/multi-user.target.wants",
                     "/etc/systemd/system/sockets.target.wants",
                     "/etc/systemd/system/timers.target.wants",
                     "/run/sovagrid-hub-backup", "/run/sovagrid-web-agent",
                     "/run/sovagrid-terminal", "/run/sovagrid-journal",
                     "/run/sovagrid-service", "/run/sovagrid-vpn"))


class Shadows:
    def __init__(self, restore: Any, core: Any, identity: str, resources: list[dict], *,
                 uid: int = 0, gid: int = 0):
        self.restore, self.core, self.identity = restore, core, core._id(identity)
        self.uid, self.gid = uid, gid
        self.resources = {resource["target"]: resource for resource in resources}
        if len(self.resources) != len(resources):
            raise core.Refused("INVALID_RESTORE_RESOURCE_PLAN")
        for target, resource in self.resources.items():
            if target not in PARENTS and core._resource_root(target) != target:
                raise core.Refused("INVALID_RESTORE_RESOURCE_PLAN")
            if core._resource_digest(resource["entries"]) != resource["sha256"]:
                raise core.Refused("INVALID_RESTORE_RESOURCE_PLAN")
            for relative, entry in resource["entries"].items():
                if (relative and (relative.startswith("/") or
                        any(part in ("", ".", "..") for part in relative.split("/")))):
                    raise core.Refused("INVALID_RESTORE_RESOURCE_PLAN")
                if entry["kind"] == "file" and entry.get("source") != target + (
                        "/" + relative if relative else ""):
                    raise core.Refused("INVALID_RESTORE_RESOURCE_PLAN")

    def _open(self, step):
        resource = self.resources.get(step["resource"])
        if (step["kind"] != "shadow" or resource is None or step["desired"] != {
                "shadow": resource["shadow"], "sha256": resource["sha256"]} or
                re.fullmatch(r"\.sovagrid-restore-" + self.identity + r"-[0-9]{1,3}",
                             resource["shadow"]) is None):
            raise self.core.Refused("INVALID_RESTORE_SHADOW")
        parent, name = self.core._safe_parent(self.restore.backup.ROOT, resource["target"], uid=self.uid)
        return parent, name, resource

    def _marker(self, resource, proof):
        if (not isinstance(proof, dict) or set(proof) != {"parent", "nonce", "sha256"} or
                not isinstance(proof["nonce"], str) or
                self.core.ID.fullmatch(proof["nonce"]) is None or
                proof["sha256"] != resource["sha256"]):
            raise self.core.Refused("INVALID_RESTORE_PROOF")
        return self.core._canonical({"protocol": "sovagrid-restore-shadow-owner-v1",
                                     "id": self.identity, "nonce": proof["nonce"],
                                     "target": resource["target"],
                                     "sha256": resource["sha256"]}) + b"\n"

    def _parent(self, descriptor, proof):
        info = os.fstat(descriptor)
        if [info.st_dev, info.st_ino] != proof["parent"]:
            raise self.core.Refused("RESTORE_PARENT_CHANGED")

    @staticmethod
    def _exists(parent, name):
        try:
            return os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def _read_owner(self, parent, name, expected, *, partial=False):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            raw, _before = self.core._read_private_fd(descriptor, maximum=4096,
                                                     uid=self.uid, gid=self.gid)
            if (raw != expected if not partial else not expected.startswith(raw)):
                raise self.core.Refused("RESTORE_SHADOW_OWNER_CHANGED")
        finally:
            os.close(descriptor)

    def prepare(self, step):
        parent, name, resource = self._open(step)
        try:
            if any(self._exists(parent, item) is not None for item in (
                    name, resource["shadow"], resource["shadow"] + ".owner")):
                raise self.core.Refused("RESTORE_TARGET_EXISTS")
            info = os.fstat(parent)
            return {"parent": [info.st_dev, info.st_ino], "nonce": uuid.uuid4().hex,
                    "sha256": resource["sha256"]}
        finally:
            os.close(parent)

    def _source(self, entry):
        descriptor = self.restore.backup._safe_open(
            self.restore.STAGING / self.identity / entry["source"].lstrip("/"))
        try:
            info = os.fstat(descriptor)
            self.core._private(info, directory=False, uid=self.uid, gid=self.gid)
            if info.st_size != entry["size"]:
                raise self.core.Refused("RESTORE_STAGE_CHANGED")
            return descriptor, self.core._fingerprint(info)
        except BaseException:
            os.close(descriptor)
            raise

    def _relative(self, root_fd, relative, *, directory=False):
        if not relative:
            return os.dup(root_fd)
        parts = relative.split("/")
        descriptor = os.dup(root_fd)
        try:
            for position, part in enumerate(parts):
                child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                                (os.O_DIRECTORY if directory or position < len(parts) - 1 else 0),
                                dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _metadata(self, descriptor, entry):
        os.fchown(descriptor, entry["uid"], entry["gid"])
        os.fchmod(descriptor, entry["mode"])
        os.utime(descriptor, ns=(entry["mtime"] * 10**9, entry["mtime"] * 10**9))
        os.fsync(descriptor)

    def _copy(self, destination, entry):
        source, before = self._source(entry)
        digest, count = hashlib.sha256(), 0
        deadline = time.monotonic() + 600
        try:
            while True:
                if time.monotonic() > deadline:
                    raise self.core.Refused("RESTORE_TIME_LIMIT")
                block = os.read(source, 1024 * 1024)
                if not block:
                    break
                count += len(block)
                if count > entry["size"]:
                    raise self.core.Refused("RESTORE_STAGE_CHANGED")
                digest.update(block)
                self.core._write(destination, block)
            if (count != entry["size"] or digest.hexdigest() != entry["sha256"] or
                    self.core._fingerprint(os.fstat(source)) != before):
                raise self.core.Refused("RESTORE_STAGE_CHANGED")
            self._metadata(destination, entry)
        finally:
            os.close(source)

    def execute(self, step, proof):
        parent, _name, resource = self._open(step)
        temporary = resource["shadow"] + ".owner.tmp" + proof["nonce"]
        owner = resource["shadow"] + ".owner"
        marker = self._marker(resource, proof)
        try:
            self._parent(parent, proof)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            try:
                os.fchmod(descriptor, 0o600)
                self.core._private(os.fstat(descriptor), directory=False, uid=self.uid, gid=self.gid)
                self.core._write(descriptor, marker)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self.core._rename_noreplace(parent, temporary, owner)
            os.fsync(parent)
            entries = resource["entries"]
            directory = entries[""]["kind"] == "dir"
            if directory:
                os.mkdir(resource["shadow"], 0o700, dir_fd=parent)
                descriptor = os.open(resource["shadow"], os.O_RDONLY | os.O_NOFOLLOW |
                                     os.O_CLOEXEC | os.O_DIRECTORY, dir_fd=parent)
            else:
                descriptor = os.open(resource["shadow"], os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            os.fsync(parent)
            try:
                if not directory:
                    self._copy(descriptor, entries[""])
                else:
                    for relative, entry in sorted(entries.items(), key=lambda pair: (pair[0].count("/"), pair[0])):
                        if not relative:
                            continue
                        parent_relative, _, name = relative.rpartition("/")
                        output = self._relative(descriptor, parent_relative, directory=True)
                        try:
                            if entry["kind"] == "dir":
                                os.mkdir(name, 0o700, dir_fd=output)
                            else:
                                created = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                                  os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=output)
                                try:
                                    self._copy(created, entry)
                                finally:
                                    os.close(created)
                            os.fsync(output)
                        finally:
                            os.close(output)
                    for relative, entry in sorted(entries.items(), key=lambda pair: (-pair[0].count("/"), pair[0]), reverse=False):
                        if relative and entry["kind"] == "dir":
                            directory_fd = self._relative(descriptor, relative, directory=True)
                            try:
                                self._metadata(directory_fd, entry)
                            finally:
                                os.close(directory_fd)
                    # Root metadata must be last even when its depth ties a
                    # direct child; the namespace stays root-private to here.
                    self._metadata(descriptor, entries[""])
            finally:
                os.close(descriptor)
            os.fsync(parent)
        finally:
            os.close(parent)

    def verify(self, step, proof):
        parent, _name, resource = self._open(step)
        try:
            self._parent(parent, proof)
            self._read_owner(parent, resource["shadow"] + ".owner", self._marker(resource, proof))
            if self.core.tree_proof(parent, resource["shadow"])["sha256"] != resource["sha256"]:
                raise self.core.Refused("RESTORE_SHADOW_CHANGED")
        finally:
            os.close(parent)

    def _prefix(self, descriptor, entry):
        before = os.fstat(descriptor)
        if before.st_size > entry["size"]:
            raise self.core.Refused("RESTORE_SHADOW_CHANGED")
        source, source_before = self._source(entry)
        digest, total = hashlib.sha256(), 0
        deadline = time.monotonic() + 600
        try:
            while True:
                if time.monotonic() > deadline:
                    raise self.core.Refused("RESTORE_TIME_LIMIT")
                raw = os.read(source, 1024 * 1024)
                if not raw:
                    break
                digest.update(raw)
                compare = min(len(raw), max(0, before.st_size - total))
                if compare and os.read(descriptor, compare) != raw[:compare]:
                    raise self.core.Refused("RESTORE_SHADOW_CHANGED")
                total += len(raw)
                if total > entry["size"]:
                    raise self.core.Refused("RESTORE_STAGE_CHANGED")
            if (total != entry["size"] or digest.hexdigest() != entry["sha256"] or
                    self.core._fingerprint(os.fstat(source)) != source_before or
                    self.core._fingerprint(os.fstat(descriptor)) != self.core._fingerprint(before)):
                raise self.core.Refused("RESTORE_SHADOW_CHANGED")
        finally:
            os.close(source)

    def _partial(self, parent, name, entries):
        found = {}

        def visit(directory_fd, leaf, relative):
            entry = entries.get(relative)
            if entry is None:
                raise self.core.Refused("RESTORE_SHADOW_CHANGED")
            info = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
            directory = entry["kind"] == "dir"
            if ((directory and not stat.S_ISDIR(info.st_mode)) or
                    (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)) or
                    (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) not in {
                        (self.uid, self.gid, 0o700 if directory else 0o600),
                        (entry["uid"], entry["gid"], 0o700 if directory else 0o600),
                        (entry["uid"], entry["gid"], entry["mode"])}):
                raise self.core.Refused("RESTORE_SHADOW_CHANGED")
            descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                                 (os.O_DIRECTORY if directory else 0), dir_fd=directory_fd)
            try:
                if self.core._fingerprint(os.fstat(descriptor)) != self.core._fingerprint(info):
                    raise self.core.Refused("RESTORE_SHADOW_CHANGED")
                found[relative] = info
                if directory:
                    with os.scandir(descriptor) as iterator:
                        children = sorted(item.name for item in iterator)
                    for child in children:
                        visit(descriptor, child, relative + "/" + child if relative else child)
                else:
                    self._prefix(descriptor, entry)
            finally:
                os.close(descriptor)

        visit(parent, name, "")
        return found

    def undo(self, step, proof):
        parent, _name, resource = self._open(step)
        owner = resource["shadow"] + ".owner"
        temporary = owner + ".tmp" + proof["nonce"]
        marker = self._marker(resource, proof)
        try:
            self._parent(parent, proof)
            live = self._exists(parent, resource["shadow"])
            marker_exists = self._exists(parent, owner)
            temporary_exists = self._exists(parent, temporary)
            if temporary_exists is not None:
                if live is not None or marker_exists is not None:
                    raise self.core.Refused("RESTORE_SHADOW_OWNER_CHANGED")
                self._read_owner(parent, temporary, marker, partial=True)
                os.unlink(temporary, dir_fd=parent)
                os.fsync(parent)
                return
            if marker_exists is None:
                if live is not None:
                    raise self.core.Refused("RESTORE_SHADOW_OWNER_CHANGED")
                return
            self._read_owner(parent, owner, marker)
            if live is not None:
                found = self._partial(parent, resource["shadow"], resource["entries"])
                directory = resource["entries"][""]["kind"] == "dir"
                root = os.open(resource["shadow"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                               (os.O_DIRECTORY if directory else 0), dir_fd=parent)
                try:
                    for relative in sorted(found, key=lambda value: (value.count("/"), value), reverse=True):
                        if not relative:
                            continue
                        parent_relative, _, name = relative.rpartition("/")
                        container = self._relative(root, parent_relative, directory=True)
                        try:
                            before = found[relative]
                            current = os.stat(name, dir_fd=container, follow_symlinks=False)
                            if (current.st_dev, current.st_ino, current.st_uid, current.st_gid,
                                    stat.S_IMODE(current.st_mode)) != (
                                    before.st_dev, before.st_ino, before.st_uid, before.st_gid,
                                    stat.S_IMODE(before.st_mode)):
                                raise self.core.Refused("RESTORE_SHADOW_CHANGED")
                            if stat.S_ISDIR(before.st_mode):
                                os.rmdir(name, dir_fd=container)
                            else:
                                if self.core._fingerprint(before) != self.core._fingerprint(current):
                                    raise self.core.Refused("RESTORE_SHADOW_CHANGED")
                                os.unlink(name, dir_fd=container)
                            os.fsync(container)
                        finally:
                            os.close(container)
                finally:
                    os.close(root)
                current = os.stat(resource["shadow"], dir_fd=parent, follow_symlinks=False)
                before = found[""]
                if ((current.st_dev, current.st_ino, current.st_uid, current.st_gid,
                     stat.S_IMODE(current.st_mode)) != (
                        before.st_dev, before.st_ino, before.st_uid, before.st_gid,
                        stat.S_IMODE(before.st_mode)) or
                        (not directory and self.core._fingerprint(before) != self.core._fingerprint(current))):
                    raise self.core.Refused("RESTORE_SHADOW_CHANGED")
                if directory:
                    os.rmdir(resource["shadow"], dir_fd=parent)
                else:
                    os.unlink(resource["shadow"], dir_fd=parent)
                os.fsync(parent)
            self._read_owner(parent, owner, marker)
            os.unlink(owner, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)

    def cleanup_commit(self, step, proof):
        parent, _name, resource = self._open(step)
        try:
            self._parent(parent, proof)
            if self._exists(parent, resource["shadow"]) is not None:
                raise self.core.Refused("RESTORE_SHADOW_CHANGED")
            owner = resource["shadow"] + ".owner"
            if self._exists(parent, owner) is not None:
                self._read_owner(parent, owner, self._marker(resource, proof))
                os.unlink(owner, dir_fd=parent)
                os.fsync(parent)
        finally:
            os.close(parent)
