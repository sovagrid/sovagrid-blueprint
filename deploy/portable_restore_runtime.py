#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Private plan persistence and adapter ordering for portable restoration.

The public apply entry remains disabled until disposable Ubuntu validation.
Recovery is conservative: changed live database/runtime bytes are preserved and
leave the installation fence in place instead of deleting newly accepted work.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
from typing import Any
import uuid


MAX_PLAN = 8 * 1024**2


def _private_file(core, restore, stage_fd, name, raw):
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=stage_fd)
    except FileNotFoundError:
        descriptor = None
    if descriptor is not None:
        try:
            existing, _fingerprint = core._read_private_fd(descriptor, maximum=MAX_PLAN,
                uid=restore.backup.ROOT_UID, gid=restore.backup.ROOT_GID)
            if existing != raw:
                raise core.Refused("RESTORE_PLAN_EXISTS")
            return
        finally:
            os.close(descriptor)
    temporary = name + "." + uuid.uuid4().hex + ".tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                         os.O_CLOEXEC, 0o600, dir_fd=stage_fd)
    try:
        os.fchmod(descriptor, 0o600)
        core._private(os.fstat(descriptor), directory=False,
                      uid=restore.backup.ROOT_UID, gid=restore.backup.ROOT_GID)
        core._write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        core._rename_noreplace(stage_fd, temporary, name)
        os.fsync(stage_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=stage_fd)
        except FileNotFoundError:
            pass


def persist(restore, core, stage_fd, plan):
    raw = core._canonical(plan) + b"\n"
    if len(raw) > MAX_PLAN:
        raise core.Refused("RESTORE_RESOURCE_PLAN_LIMIT")
    _private_file(core, restore, stage_fd, ".apply-plan-" + plan["id"] + ".json", raw)
    compose = restore._sibling("portable_restore_compose.py", "_sovagrid_restore_compose")
    _private_file(core, restore, stage_fd, ".apply-compose-" + plan["id"] + ".json", compose.override(plan))


def load(restore, core, stage_fd, identity, bindings):
    descriptor = os.open(".apply-plan-" + core._id(identity) + ".json",
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=stage_fd)
    try:
        raw, _fingerprint = core._read_private_fd(descriptor, maximum=MAX_PLAN,
            uid=restore.backup.ROOT_UID, gid=restore.backup.ROOT_GID)
    finally:
        os.close(descriptor)
    try:
        plan = json.loads(raw, object_pairs_hook=core._unique)
        expected = plan.pop("bindings")
        if (plan.get("protocol") != "sovagrid-portable-restore-resources-v1" or
                plan.get("id") != identity or plan.get("layout") != "full" or
                expected != bindings or set(expected) != core.BINDINGS or
                hashlib.sha256(core._canonical(plan)).hexdigest() != expected["resource_manifest_sha256"]):
            raise core.Refused("RESTORE_PLAN_CHANGED")
        plan["bindings"] = expected
        return plan
    except (ValueError, UnicodeError, KeyError, TypeError, AttributeError) as exc:
        raise core.Refused("RESTORE_PLAN_CHANGED") from exc


class Reload:
    def __init__(self, core, services, states):
        self.core, self.services = core, services
        self.hashes = {unit: state["sha256"] for unit, state in states.items()}

    def _check(self, step):
        if (step["kind"] != "reload" or step["resource"] != "sovagrid-units" or
                step["desired"] != {"unit_hashes": self.hashes}):
            raise self.core.Refused("INVALID_RESTORE_UNIT")
        for unit, digest in self.hashes.items():
            self.services._unit({"kind": "enablement", "resource": unit,
                "desired": {"state": self.services.states[unit]["enablement"], "sha256": digest}})

    def prepare(self, step):
        self._check(step)
        return {"unit_hashes": self.hashes}

    def execute(self, step, proof):
        self._check(step)
        if proof != {"unit_hashes": self.hashes}:
            raise self.core.Refused("INVALID_RESTORE_PROOF")
        self.services._command(["daemon-reload"])

    def verify(self, step, proof):
        self._check(step)
        if proof != {"unit_hashes": self.hashes}:
            raise self.core.Refused("INVALID_RESTORE_PROOF")
        for unit in self.hashes:
            self.services._fragment(unit)

    def undo(self, step, proof):
        # Unit files must remain loaded until later service/enablement intents
        # are undone. A final reload runs after all file publications revert.
        if proof != {"unit_hashes": self.hashes}:
            raise self.core.Refused("INVALID_RESTORE_PROOF")


class Runtime:
    def __init__(self, restore: Any, core: Any, plan: dict, journal: Any, *, inputs=None):
        self.restore, self.core, self.plan, self.journal, self.inputs = restore, core, plan, journal, inputs
        shadows = restore._sibling("portable_restore_shadow.py", "_sovagrid_restore_shadows")
        compose = restore._sibling("portable_restore_compose.py", "_sovagrid_restore_compose")
        queue = restore._sibling("portable_restore_queue.py", "_sovagrid_restore_queue")
        self.shadow_api = shadows
        self.shadows = shadows.Shadows(restore, core, plan["id"], plan["resources"],
                                      uid=restore.backup.ROOT_UID, gid=restore.backup.ROOT_GID)
        self.publisher = core.Publisher(restore.backup.ROOT, plan["id"],
            {resource["target"] for resource in plan["resources"]}, uid=restore.backup.ROOT_UID)
        self.identities = core.Identities(plan["id"])
        self.queue = queue.Queue(restore, core, plan, inputs=inputs)
        image_inputs = inputs or SimpleNamespace(
            images={"exported_configs": {name: value["config"] for name, value in plan["images"].items()},
                    "rootfs_sha256": {name: value["rootfs_sha256"] for name, value in plan["images"].items()}},
            platforms={name: value["platform"] for name, value in plan["images"].items()})
        self.images = core.Images(image_inputs)
        self.services = core.Services(restore.backup.ROOT, plan["unit_states"],
                                      uid=restore.backup.ROOT_UID, gid=restore.backup.ROOT_GID)
        self.reload = Reload(core, self.services, plan["unit_states"])
        self.compose = compose.Compose(restore, core, plan,
            restore.STAGING / (".apply-compose-" + plan["id"] + ".json"))

    def _adapter(self, step):
        if step["kind"] in ("group", "user"):
            return self.identities
        if step["kind"] in ("enablement", "service"):
            return self.services
        adapters = {"images": self.images, "shadow": self.shadows, "publish": self.publisher,
                    "reload": self.reload, "compose": self.compose, "queue": self.queue}
        if step["kind"] not in adapters:
            raise self.core.Refused("INVALID_RESTORE_JOURNAL")
        return adapters[step["kind"]]

    def prepare(self, step):
        if self.inputs is None:
            raise self.core.Refused("RESTORE_INPUTS_REQUIRED")
        self.inputs.unchanged()
        return self._adapter(step).prepare(step)

    def execute(self, step, proof):
        if self.inputs is None:
            raise self.core.Refused("RESTORE_INPUTS_REQUIRED")
        self.inputs.unchanged()
        self._adapter(step).execute(step, proof)

    def verify(self, step, proof):
        self._adapter(step).verify(step, proof)

    def undo(self, step, proof):
        self._adapter(step).undo(step, proof)

    def rollback_complete(self, value):
        self.services._command(["daemon-reload"])

    def health(self, value):
        if self.inputs is None:
            raise self.core.Refused("RESTORE_INPUTS_REQUIRED")
        self.inputs.unchanged(hash_contents=True)
        compose = [step for step in value["steps"] if step["kind"] == "compose"]
        if len(compose) != 1 or compose[0]["state"] != "done":
            raise self.core.Refused("INVALID_RESTORE_JOURNAL")
        quarantine = [step for step in value["steps"] if step["kind"] == "queue"]
        if len(quarantine) != 1 or quarantine[0]["state"] != "done":
            raise self.core.Refused("RESTORE_QUEUE_NOT_QUARANTINED")
        self.compose.health(compose[0]["proof"])
        mutable = {"/var/lib/sovagrid", "/var/lib/sovagrid-vpn", "/var/lib/sovagrid-containers",
                   *self.shadow_api.PARENTS}
        for step in value["steps"]:
            if step["kind"] in ("service", "enablement"):
                self.services.verify(step, step["proof"])
            elif step["kind"] == "publish" and step["resource"] not in mutable:
                self.publisher.verify(step, step["proof"])
        self._socket_health()

    def _socket_health(self):
        for unit, socket_path, gid in (
                ("sovagrid-hub-backup-control.socket", "/run/sovagrid-hub-backup/control.sock", 10001),
                ("sovagrid-web-agent-control.socket", "/run/sovagrid-web-agent/control.sock", 10005)):
            if unit not in self.plan["unit_states"]:
                continue
            descriptor = self.restore.backup._safe_open(Path(socket_path).parent, directory=True)
            try:
                info = os.stat(Path(socket_path).name, dir_fd=descriptor, follow_symlinks=False)
                if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid != gid or
                        stat.S_IMODE(info.st_mode) != 0o660):
                    raise self.core.Refused("RESTORE_SOCKET_UNHEALTHY")
            finally:
                os.close(descriptor)

    def cleanup_commit(self, value):
        if value["phase"] != "committed":
            return
        for step in reversed(value["steps"]):
            if step["kind"] == "queue":
                self.queue.cleanup_commit(step, step["proof"])
            if step["kind"] == "shadow":
                self.shadows.cleanup_commit(step, step["proof"])

    def steps(self):
        result = []

        def add(kind, resource, desired):
            result.append({"kind": kind, "resource": resource, "desired": desired})

        for name, gid in sorted(self.plan["identities"]["groups"].items()):
            add("group", name, {"gid": gid})
        for name, desired in sorted(self.plan["identities"]["users"].items()):
            add("user", name, desired)
        add("images", "sovagrid-compose-images", {"services": self.plan["images"]})
        # Owned prerequisite parents are published before leaves beneath them.
        resources = sorted(self.plan["resources"], key=lambda resource: (
            resource["target"] not in self.shadow_api.PARENTS,
            resource["target"].count("/"), resource["target"]))
        for resource in resources:
            desired = {"shadow": resource["shadow"], "sha256": resource["sha256"]}
            add("shadow", resource["target"], desired)
            add("publish", resource["target"], desired)
        add("queue", "/var/lib/sovagrid/hub/hub.sqlite", {"policy": "cancel-restored-queued-v1"})
        add("reload", "sovagrid-units", {"unit_hashes": {
            name: state["sha256"] for name, state in self.plan["unit_states"].items()}})
        for name, state in sorted(self.plan["unit_states"].items()):
            add("enablement", name, {"state": state["enablement"], "sha256": state["sha256"]})
        for name in self.plan["before_compose"]:
            add("service", name, {"active": True, "sha256": self.plan["unit_states"][name]["sha256"]})
        add("compose", "sovagrid", {"services": self.plan["compose_services"], "images": self.plan["images"]})
        for name in self.plan["after_compose"] + self.plan["timers"]:
            add("service", name, {"active": True, "sha256": self.plan["unit_states"][name]["sha256"]})
        if len(result) > self.core.MAX_STEPS:
            raise self.core.Refused("RESTORE_JOURNAL_LIMIT")
        return result
