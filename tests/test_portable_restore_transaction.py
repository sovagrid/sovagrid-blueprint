# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Crash recovery may only undo resources owned by its durable intent."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deploy import portable_restore_apply as apply


IDENTITY = "a" * 32
BINDINGS = {key: hashlib.sha256(key.encode()).hexdigest() for key in apply.BINDINGS}
STEPS = [{"kind": "group", "resource": "sovagrid-test-group", "desired": {"gid": 123}},
         {"kind": "user", "resource": "sovagrid-test-user", "desired": {"uid": 123}}]


class PowerLoss(BaseException):
    pass


class FakeDriver:
    def __init__(self):
        self.resources = {}
        self.undone = []
        self.events = []
        self.fail_at = None
        self.crash_at = None
        self.unhealthy = False

    def prepare(self, step):
        resource = step["resource"]
        if resource in self.resources:
            raise apply.Refused("RESOURCE_EXISTS")
        self.events.append(("prepare", resource))
        return {"owned": resource, "value": step["desired"]}

    def execute(self, step, proof):
        resource = step["resource"]
        self.resources[resource] = copy.deepcopy(proof["value"])
        self.events.append(("execute", resource))
        if resource == self.fail_at:
            raise OSError("private command output must never escape")
        if resource == self.crash_at:
            raise PowerLoss()

    def verify(self, step, proof):
        if self.resources.get(step["resource"]) != proof["value"]:
            raise apply.Refused("RESOURCE_CHANGED")

    def undo(self, step, proof):
        resource = step["resource"]
        if resource in self.resources and self.resources[resource] != proof["value"]:
            raise apply.Refused("RESOURCE_CHANGED")
        self.resources.pop(resource, None)
        self.undone.append(resource)

    def health(self, value):
        self.events.append(("health", value["id"]))
        if self.unhealthy:
            raise apply.Refused("HUB_UNHEALTHY")


class TransactionFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.folder.chmod(0o700)
        self.fd = os.open(self.folder, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.driver = FakeDriver()
        self.journal = apply.Journal(self.fd, IDENTITY, uid=os.getuid(), gid=os.getgid())
        if not sys.platform.startswith("linux"):
            # Production requires Linux renameat2. These serial adapter tests
            # also run on development macOS without claiming its race safety.
            patcher = patch.object(apply, "_rename_noreplace", self.rename)
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def rename(fd, source, target):
        try:
            os.stat(target, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            os.rename(source, target, src_dir_fd=fd, dst_dir_fd=fd)
        else:
            raise apply.Refused("RESTORE_TARGET_EXISTS")


class TransactionTest(TransactionFixture):
    def test_health_and_exact_steps_precede_commit_and_repeat_is_idempotent(self):
        result = apply.run(self.journal, self.driver, BINDINGS, STEPS)
        self.assertEqual(result["phase"], "committed")
        self.assertEqual(self.driver.events[-1], ("health", IDENTITY))
        before = list(self.driver.events)
        self.assertEqual(apply.run(self.journal, self.driver, BINDINGS, STEPS), result)
        self.assertEqual(before, self.driver.events)
        self.assertEqual(stat.S_IMODE((self.folder / self.journal.name).stat().st_mode), 0o600)

    def test_failure_after_external_effect_rolls_back_in_reverse(self):
        self.driver.fail_at = STEPS[1]["resource"]
        result = apply.run(self.journal, self.driver, BINDINGS, STEPS)
        self.assertEqual(result["phase"], "rolled_back")
        self.assertEqual(result["error"], "RESTORE_FAILED")
        self.assertEqual(self.driver.resources, {})
        self.assertEqual(self.driver.undone, [STEPS[1]["resource"], STEPS[0]["resource"]])
        self.assertNotIn("private", json.dumps(result))

    def test_failed_health_never_commits(self):
        self.driver.unhealthy = True
        result = apply.run(self.journal, self.driver, BINDINGS, STEPS)
        self.assertEqual(result["phase"], "rolled_back")
        self.assertEqual(result["error"], "HUB_UNHEALTHY")
        self.assertFalse(self.driver.resources)

    def test_power_loss_after_effect_uses_intent_and_never_reexecutes(self):
        self.driver.crash_at = STEPS[1]["resource"]
        with self.assertRaises(PowerLoss):
            apply.run(self.journal, self.driver, BINDINGS, STEPS)
        value = self.journal.read()
        self.assertEqual([step["state"] for step in value["steps"]], ["done", "intent"])
        with self.assertRaisesRegex(apply.Refused, "RESTORE_RECOVERY_REQUIRED"):
            apply.run(self.journal, self.driver, BINDINGS, STEPS)
        executions = [event for event in self.driver.events if event[0] == "execute"]
        recovered = apply.recover(self.journal, self.driver)
        self.assertEqual(recovered["phase"], "rolled_back")
        self.assertFalse(self.driver.resources)
        self.assertEqual(executions, [event for event in self.driver.events if event[0] == "execute"])
        self.assertEqual(apply.recover(self.journal, self.driver), recovered)

    def test_every_durable_boundary_can_be_recovered_after_process_death(self):
        original_save = self.journal.save
        for boundary in range(8):
            with self.subTest(boundary=boundary):
                self.driver = FakeDriver()
                try:
                    os.unlink(self.journal.name, dir_fd=self.fd)
                except FileNotFoundError:
                    pass
                counter = 0

                def save(value, *, initial=False):
                    nonlocal counter
                    original_save(value, initial=initial)
                    current = counter
                    counter += 1
                    if current == boundary:
                        raise PowerLoss()

                with patch.object(self.journal, "save", side_effect=save):
                    with self.assertRaises(PowerLoss):
                        apply.run(self.journal, self.driver, BINDINGS, STEPS)
                result = apply.recover(self.journal, self.driver)
                if boundary == 7:
                    self.assertEqual(result["phase"], "committed")
                    self.assertEqual(len(self.driver.resources), 2)
                else:
                    self.assertEqual(result["phase"], "rolled_back")
                    self.assertFalse(self.driver.resources)

    def test_changed_resource_stops_rollback_before_deleting_its_prerequisite(self):
        self.driver.crash_at = STEPS[1]["resource"]
        with self.assertRaises(PowerLoss):
            apply.run(self.journal, self.driver, BINDINGS, STEPS)
        self.driver.resources[STEPS[1]["resource"]] = {"uid": 456}
        result = apply.recover(self.journal, self.driver)
        self.assertEqual(result["phase"], "recovery_required")
        self.assertEqual(result["error"], "RESTORE_RESOURCE_CHANGED")
        self.assertEqual(len(self.driver.resources), 2)
        self.assertEqual(self.driver.undone, [])

    def test_crash_after_undo_is_recoverable_without_repeating_other_effects(self):
        self.driver.crash_at = STEPS[1]["resource"]
        with self.assertRaises(PowerLoss):
            apply.run(self.journal, self.driver, BINDINGS, STEPS)
        original = self.driver.undo

        def undo(step, proof):
            original(step, proof)
            raise PowerLoss()

        with patch.object(self.driver, "undo", side_effect=undo):
            with self.assertRaises(PowerLoss):
                apply.recover(self.journal, self.driver)
        self.assertEqual(self.journal.read()["steps"][1]["state"], "reverting")
        self.assertEqual(apply.recover(self.journal, self.driver)["phase"], "rolled_back")
        self.assertFalse(self.driver.resources)

    def test_stale_binding_is_rejected_even_after_success(self):
        apply.run(self.journal, self.driver, BINDINGS, STEPS)
        changed = {**BINDINGS, "images_sha256": "0" * 64}
        with self.assertRaisesRegex(apply.Refused, "STALE_RESTORE_REVIEW"):
            apply.run(self.journal, self.driver, changed, STEPS)

    def test_other_unfinished_journal_blocks_a_new_restore_even_if_fence_is_missing(self):
        self.driver.crash_at = STEPS[1]["resource"]
        with self.assertRaises(PowerLoss):
            apply.run(self.journal, self.driver, BINDINGS, STEPS)
        other = apply.Journal(self.fd, "b" * 32, uid=os.getuid(), gid=os.getgid())
        fresh = FakeDriver()
        with self.assertRaisesRegex(apply.Refused, "RESTORE_OTHER_IN_PROGRESS"):
            apply.run(other, fresh, BINDINGS, STEPS)
        self.assertFalse(fresh.events)
        self.assertIsNone(other.read())

    def test_unsafe_duplicate_or_forged_journal_is_not_accepted(self):
        apply.run(self.journal, self.driver, BINDINGS, STEPS)
        target = self.folder / self.journal.name
        target.chmod(0o644)
        with self.assertRaisesRegex(apply.Refused, "UNSAFE_RESTORE_JOURNAL"):
            self.journal.read()
        target.chmod(0o600)
        value = self.journal.read()
        value["steps"][0]["state"] = "pending"
        value["steps"][0]["proof"] = None
        target.write_text(json.dumps(value))
        with self.assertRaisesRegex(apply.Refused, "INVALID_RESTORE_JOURNAL"):
            self.journal.read()
        target.write_text('{"id":"x","id":"y"}')
        with self.assertRaisesRegex(apply.Refused, "INVALID_RESTORE_JOURNAL"):
            self.journal.read()

    def test_unknown_state_after_replace_is_not_silently_adopted(self):
        apply.run(self.journal, self.driver, BINDINGS, STEPS)
        changed = self.journal.read()
        changed["generation"] += 2
        with self.assertRaisesRegex(apply.Refused, "RESTORE_JOURNAL_CHANGED"):
            self.journal.save(changed)

    def test_durable_resource_specification_and_intent_proof_are_immutable(self):
        self.driver.crash_at = STEPS[1]["resource"]
        with self.assertRaises(PowerLoss):
            apply.run(self.journal, self.driver, BINDINGS, STEPS)
        for mutate in (
                lambda value: value["steps"][0]["desired"].update(gid=456),
                lambda value: value["steps"][0].update(resource="somebody-else"),
                lambda value: value["steps"][0]["proof"].update(owned="somebody-else")):
            value = self.journal.read()
            value["generation"] += 1
            mutate(value)
            with self.assertRaisesRegex(apply.Refused, "RESTORE_JOURNAL_CHANGED"):
                self.journal.save(value)


class PublisherTest(TransactionFixture):
    def make_publisher(self, *, directory=False):
        (self.folder / "etc").mkdir(mode=0o755)
        shadow = ".sovagrid-restore-" + IDENTITY + "-0"
        source = self.folder / "etc" / shadow
        if directory:
            source.mkdir(mode=0o750)
            source.chmod(0o750)
            (source / "token").write_bytes(b"test-only-secret")
            (source / "token").chmod(0o640)
        else:
            source.write_bytes(b"test-only-config")
            source.chmod(0o600)
        parent_fd = os.open(self.folder / "etc", os.O_RDONLY | os.O_DIRECTORY)
        try:
            digest = apply.tree_proof(parent_fd, shadow)["sha256"]
        finally:
            os.close(parent_fd)
        step = {"index": 0, "kind": "publish", "resource": "/etc/sovagrid-test",
                "desired": {"shadow": shadow, "sha256": digest}}
        publisher = apply.Publisher(self.folder, IDENTITY, {step["resource"]}, uid=os.getuid())
        return source, step, publisher

    def test_actual_publication_and_idempotent_quarantine_undo_preserve_metadata(self):
        source, step, publisher = self.make_publisher(directory=True)
        original = source.stat()
        proof = publisher.prepare(step)
        publisher.execute(step, proof)
        target = self.folder / "etc/sovagrid-test"
        self.assertEqual(target.stat().st_ino, original.st_ino)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((target / "token").stat().st_mode), 0o640)
        publisher.verify(step, proof)
        publisher.undo(step, proof)
        publisher.undo(step, proof)
        self.assertFalse(target.exists())
        self.assertEqual((source / "token").read_bytes(), b"test-only-secret")

    def test_equal_bytes_replacement_is_never_removed(self):
        source, step, publisher = self.make_publisher()
        proof = publisher.prepare(step)
        publisher.execute(step, proof)
        target = self.folder / "etc/sovagrid-test"
        replacement = self.folder / "etc/replacement"
        replacement.write_bytes(target.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(target)
        with self.assertRaisesRegex(apply.Refused, "RESTORE_RESOURCE_CHANGED"):
            publisher.undo(step, proof)
        self.assertEqual(target.read_bytes(), b"test-only-config")

    def test_changed_nested_file_is_not_quarantined_or_deleted(self):
        source, step, publisher = self.make_publisher(directory=True)
        proof = publisher.prepare(step)
        publisher.execute(step, proof)
        target = self.folder / "etc/sovagrid-test"
        (target / "token").write_bytes(b"changed-by-someone-else")
        with self.assertRaisesRegex(apply.Refused, "RESTORE_RESOURCE_CHANGED"):
            publisher.undo(step, proof)
        self.assertTrue(target.exists())
        self.assertFalse(source.exists())

    def test_parent_replacement_blocks_both_publication_and_recovery(self):
        source, step, publisher = self.make_publisher()
        proof = publisher.prepare(step)
        (self.folder / "etc").rename(self.folder / "original-etc")
        (self.folder / "etc").mkdir()
        with self.assertRaisesRegex(apply.Refused, "RESTORE_PARENT_CHANGED"):
            publisher.execute(step, proof)
        with self.assertRaisesRegex(apply.Refused, "RESTORE_PARENT_CHANGED"):
            publisher.undo(step, proof)

    def test_symlink_hardlink_and_unapproved_path_are_rejected(self):
        source, step, publisher = self.make_publisher()
        source.unlink()
        source.symlink_to("/etc/passwd")
        with self.assertRaisesRegex(apply.Refused, "UNSAFE_RESTORE_RESOURCE"):
            publisher.prepare(step)
        source.unlink()
        other = self.folder / "other"
        other.write_bytes(b"test-only-config")
        os.link(other, source)
        with self.assertRaisesRegex(apply.Refused, "UNSAFE_RESTORE_RESOURCE"):
            publisher.prepare(step)
        step["resource"] = "/etc/passwd"
        with self.assertRaisesRegex(apply.Refused, "INVALID_RESTORE_PUBLICATION"):
            publisher.prepare(step)

    def test_target_created_after_preparation_is_preserved(self):
        source, step, publisher = self.make_publisher()
        proof = publisher.prepare(step)
        target = self.folder / "etc/sovagrid-test"
        target.write_bytes(b"external")
        with self.assertRaisesRegex(apply.Refused, "RESTORE_TARGET_EXISTS"):
            publisher.execute(step, proof)
        self.assertEqual(target.read_bytes(), b"external")
        self.assertTrue(source.exists())


class FenceTest(TransactionFixture):
    def setUp(self):
        super().setUp()
        self.host = self.folder / "host"
        (self.host / "var/lib").mkdir(parents=True)
        self.fence = apply.Fence(self.host, uid=os.getuid(), gid=os.getgid())
        self.fence_path = self.host / str(apply.FENCE).lstrip("/")

    def test_journal_precedes_fence_and_fence_precedes_every_external_effect(self):
        original = self.driver.execute

        def execute(step, proof):
            self.assertEqual(self.journal.read()["phase"], "applying")
            marker = json.loads(self.fence_path.read_bytes())
            self.assertEqual(marker["id"], IDENTITY)
            self.assertEqual(marker["resource_manifest_sha256"], BINDINGS["resource_manifest_sha256"])
            original(step, proof)

        with patch.object(self.driver, "execute", side_effect=execute):
            result = apply.run(self.journal, self.driver, BINDINGS, STEPS, fence=self.fence)
        self.assertEqual(result["phase"], "committed")
        self.assertFalse(self.fence_path.exists())

    def test_terminal_journal_recovery_cleans_fence_after_process_dies_before_unlink(self):
        original = self.journal.save

        def save(value, *, initial=False):
            original(value, initial=initial)
            if value["phase"] == "committed":
                raise PowerLoss()

        with patch.object(self.journal, "save", side_effect=save):
            with self.assertRaises(PowerLoss):
                apply.run(self.journal, self.driver, BINDINGS, STEPS, fence=self.fence)
        self.assertTrue(self.fence_path.exists())
        self.assertEqual(self.journal.read()["phase"], "committed")
        result = apply.recover(self.journal, self.driver, fence=self.fence)
        self.assertEqual(result["phase"], "committed")
        self.assertFalse(self.fence_path.exists())
        self.assertEqual(len(self.driver.resources), 2)

    def test_failed_restore_releases_fence_only_after_full_rollback(self):
        self.driver.unhealthy = True
        original = self.driver.undo

        def undo(step, proof):
            self.assertTrue(self.fence_path.exists())
            original(step, proof)

        with patch.object(self.driver, "undo", side_effect=undo):
            result = apply.run(self.journal, self.driver, BINDINGS, STEPS, fence=self.fence)
        self.assertEqual(result["phase"], "rolled_back")
        self.assertFalse(self.fence_path.exists())

    def test_foreign_fence_blocks_new_restore_before_its_journal_or_any_effect(self):
        self.fence.acquire("b" * 32, BINDINGS)
        with self.assertRaisesRegex(apply.Refused, "RESTORE_FENCE_PRESENT"):
            apply.run(self.journal, self.driver, BINDINGS, STEPS, fence=self.fence)
        self.assertIsNone(self.journal.read())
        self.assertFalse(self.driver.events)
        self.assertEqual(json.loads(self.fence_path.read_bytes())["id"], "b" * 32)

    def test_changed_resource_keeps_fence_until_operator_resolves_recovery(self):
        self.driver.crash_at = STEPS[1]["resource"]
        with self.assertRaises(PowerLoss):
            apply.run(self.journal, self.driver, BINDINGS, STEPS, fence=self.fence)
        self.driver.resources[STEPS[1]["resource"]] = {"uid": 456}
        self.assertEqual(apply.recover(self.journal, self.driver, fence=self.fence)["phase"], "recovery_required")
        self.assertTrue(self.fence_path.exists())

    def test_foreign_fence_is_not_removed_or_ignored_during_recovery(self):
        self.driver.crash_at = STEPS[1]["resource"]
        with self.assertRaises(PowerLoss):
            apply.run(self.journal, self.driver, BINDINGS, STEPS, fence=self.fence)
        self.fence_path.write_bytes(self.fence._raw("b" * 32, BINDINGS))
        with self.assertRaisesRegex(apply.Refused, "RESTORE_FENCE_FOREIGN"):
            apply.recover(self.journal, self.driver, fence=self.fence)
        self.assertEqual(len(self.driver.resources), 2)
        self.assertEqual(json.loads(self.fence_path.read_bytes())["id"], "b" * 32)


class IdentityAdapterTest(unittest.TestCase):
    def setUp(self):
        self.driver = apply.Identities(IDENTITY)
        self.groups = {}
        self.users = {}
        self.memberships = {}
        self.commands = []
        patchers = [
            patch.object(apply.grp, "getgrnam", side_effect=lambda name: self.lookup(self.groups, name)),
            patch.object(apply.pwd, "getpwnam", side_effect=lambda name: self.lookup(self.users, name)),
            patch.object(apply.grp, "getgrgid", side_effect=lambda gid: self.numeric(self.groups, "gr_gid", gid)),
            patch.object(apply.pwd, "getpwuid", side_effect=lambda uid: self.numeric(self.users, "pw_uid", uid)),
            patch.object(apply.pwd, "getpwall", side_effect=lambda: list(self.users.values())),
            patch.object(apply.os, "getgrouplist", side_effect=lambda name, gid: self.memberships.get(name, [gid])),
            patch.object(self.driver, "_command", side_effect=self.command),
            patch.object(self.driver, "_locked_password", return_value=True)]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def lookup(values, name):
        if name not in values:
            raise KeyError(name)
        return values[name]

    @staticmethod
    def numeric(values, attribute, number):
        for value in values.values():
            if getattr(value, attribute) == number:
                return value
        raise KeyError(number)

    def command(self, args):
        self.commands.append(args)
        name = args[-1]
        if args[0].endswith("groupadd"):
            self.groups[name] = SimpleNamespace(gr_name=name, gr_gid=int(args[args.index("--gid") + 1]),
                                                gr_passwd="x", gr_mem=[])
        elif args[0].endswith("useradd"):
            self.users[name] = SimpleNamespace(
                pw_name=name, pw_uid=int(args[args.index("--uid") + 1]),
                pw_gid=int(args[args.index("--gid") + 1]), pw_gecos=self.driver.comment,
                pw_dir=args[args.index("--home-dir") + 1], pw_shell="/usr/sbin/nologin")
        elif args[0].endswith("groupdel"):
            self.groups.pop(name)
        elif args[0].endswith("userdel"):
            self.users.pop(name)

    def test_missing_group_and_user_are_created_and_undone_without_home_deletion(self):
        group = {"kind": "group", "resource": "sovagrid-hub", "desired": {"gid": 10001}}
        user = {"kind": "user", "resource": "sovagrid-hub", "desired": {"gid": 10001, "uid": 10001}}
        group_proof = self.driver.prepare(group)
        self.driver.execute(group, group_proof)
        self.driver.verify(group, group_proof)
        user_proof = self.driver.prepare(user)
        self.driver.execute(user, user_proof)
        self.driver.verify(user, user_proof)
        self.assertEqual(self.users["sovagrid-hub"].pw_gecos, "SovaGrid restore " + IDENTITY)
        with self.assertRaisesRegex(apply.Refused, "RESTORE_IDENTITY_CHANGED"):
            self.driver.undo(group, group_proof)
        self.driver.undo(user, user_proof)
        self.driver.undo(group, group_proof)
        self.driver.undo(group, group_proof)
        self.assertFalse(self.groups)
        self.assertFalse(self.users)
        self.assertEqual(self.commands[-2:], [["/usr/sbin/userdel", "sovagrid-hub"],
                                             ["/usr/sbin/groupdel", "sovagrid-hub"]])

    def test_existing_same_numeric_identity_is_not_adopted(self):
        step = {"kind": "group", "resource": "sovagrid-hub", "desired": {"gid": 10001}}
        self.groups["other"] = SimpleNamespace(gr_name="other", gr_gid=10001)
        with self.assertRaisesRegex(apply.Refused, "RESTORE_IDENTITY_EXISTS"):
            self.driver.prepare(step)
        self.assertFalse(self.commands)

    def test_changed_account_marker_groups_or_password_blocks_deletion(self):
        self.groups["sovagrid"] = SimpleNamespace(gr_name="sovagrid", gr_gid=997)
        step = {"kind": "user", "resource": "sovagrid", "desired": {"gid": 997, "uid": 998}}
        proof = self.driver.prepare(step)
        self.driver.execute(step, proof)
        account = self.users["sovagrid"]
        account.pw_gecos = "changed"
        with self.assertRaisesRegex(apply.Refused, "RESTORE_IDENTITY_CHANGED"):
            self.driver.undo(step, proof)
        account.pw_gecos = self.driver.comment
        self.memberships["sovagrid"] = [997, 27]
        with self.assertRaisesRegex(apply.Refused, "RESTORE_IDENTITY_CHANGED"):
            self.driver.undo(step, proof)
        self.memberships["sovagrid"] = [997]
        with patch.object(self.driver, "_locked_password", return_value=False):
            with self.assertRaisesRegex(apply.Refused, "RESTORE_IDENTITY_CHANGED"):
                self.driver.undo(step, proof)
        self.assertIn("sovagrid", self.users)

    def test_unbounded_uid_name_or_foreign_identity_are_refused(self):
        for step in (
                {"kind": "user", "resource": "root", "desired": {"uid": 0, "gid": 0}},
                {"kind": "group", "resource": "docker", "desired": {"gid": 10}},
                {"kind": "user", "resource": "sovagrid", "desired": {"uid": 10001, "gid": 997}},
                {"kind": "user", "resource": "sovagrid-hub", "desired": {"uid": 123, "gid": 123}}):
            with self.subTest(step=step):
                with self.assertRaisesRegex(apply.Refused, "INVALID_RESTORE_IDENTITY"):
                    self.driver.prepare(step)


class ImageAdapterTest(unittest.TestCase):
    def setUp(self):
        self.layer = "sha256:" + "f" * 64
        self.services = {service: {"config": "sha256:" + digit * 64,
                                   "rootfs_sha256": hashlib.sha256(self.layer.encode()).hexdigest(),
                                   "platform": {"os": "linux", "architecture": "amd64"}}
                         for service, digit in (("hub", "a"), ("web", "b"))}
        self.inputs = SimpleNamespace(
            images={"exported_configs": {service: value["config"] for service, value in self.services.items()},
                    "rootfs_sha256": {service: value["rootfs_sha256"] for service, value in self.services.items()}},
            platforms={service: value["platform"] for service, value in self.services.items()},
            unchanged=lambda: None)
        self.driver = apply.Images(self.inputs)
        self.step = {"kind": "images", "resource": "sovagrid-compose-images", "desired": {"services": self.services}}
        self.tags = {}
        self.removed = []
        self.bad_layers = False
        patcher = patch.object(self.driver, "_capture", side_effect=self.capture)
        patcher.start()
        self.addCleanup(patcher.stop)

    def capture(self, args):
        if args[:2] == ["image", "ls"]:
            return "\n".join(tag + "|" + digest for tag, digest in self.tags.items())
        if args[:2] == ["image", "inspect"]:
            tag = args[-1]
            return json.dumps({"id": self.tags[tag], "os": "linux", "arch": "amd64",
                               "layers": ["sha256:" + "e" * 64 if self.bad_layers else self.layer]})
        if args[:2] == ["image", "rm"]:
            self.assertEqual(args[2], "--no-prune")
            self.removed.append(args[-1])
            self.tags.pop(args[-1])
            return ""
        raise AssertionError(args)

    def load(self):
        self.tags = {"sovagrid-" + service + ":local": value["config"]
                     for service, value in self.services.items()}

    def test_exported_config_and_rootfs_are_verified_and_only_exact_tags_untagged(self):
        proof = self.driver.prepare(self.step)
        self.load()
        self.driver.verify(self.step, proof)
        self.driver.undo(self.step, proof)
        self.driver.undo(self.step, proof)
        self.assertFalse(self.tags)
        self.assertEqual(set(self.removed), {"sovagrid-hub:local", "sovagrid-web:local"})

    def test_changed_tag_or_rootfs_prevents_removal_of_all_tags(self):
        proof = self.driver.prepare(self.step)
        self.load()
        self.tags["sovagrid-web:local"] = "sha256:" + "d" * 64
        with self.assertRaisesRegex(apply.Refused, "RESTORE_IMAGE_CHANGED"):
            self.driver.undo(self.step, proof)
        self.assertFalse(self.removed)
        self.load()
        self.bad_layers = True
        with self.assertRaisesRegex(apply.Refused, "RESTORE_IMAGE_CHANGED"):
            self.driver.undo(self.step, proof)
        self.assertFalse(self.removed)

    def test_partial_docker_load_can_be_recovered(self):
        proof = self.driver.prepare(self.step)
        self.load()
        self.tags.pop("sovagrid-web:local")
        self.driver.undo(self.step, proof)
        self.assertEqual(self.removed, ["sovagrid-hub:local"])

    def test_arbitrary_config_outside_retained_receipt_is_refused(self):
        step = copy.deepcopy(self.step)
        step["desired"]["services"]["hub"]["config"] = "sha256:" + "e" * 64
        with self.assertRaisesRegex(apply.Refused, "RESTORE_IMAGE_RECEIPT_MISMATCH"):
            self.driver.prepare(step)

    def test_docker_load_uses_held_fd_and_explicit_local_socket_without_user_context(self):
        proof = self.driver.prepare(self.step)
        with tempfile.TemporaryFile() as source:
            source.write(b"verified-image-tar")
            source.flush()
            self.inputs.images_fd = source.fileno()
            with patch.object(apply.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as command:
                self.driver.execute(self.step, proof)
                args, kwargs = command.call_args
                self.assertEqual(args[0], ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "image", "load"])
                self.assertEqual(kwargs["stdin"], source.fileno())
                self.assertEqual(os.read(source.fileno(), 32), b"verified-image-tar")
                self.assertNotIn("DOCKER_HOST", kwargs["env"])
                self.assertNotIn("DOCKER_CONTEXT", kwargs["env"])


class ServiceAdapterTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.system = self.root / "etc/systemd/system"
        self.system.mkdir(parents=True)
        self.unit = "sovagrid-test-control.socket"
        self.raw = b"[Socket]\nListenStream=/run/sovagrid-test.sock\n[Install]\nWantedBy=sockets.target\n"
        self.path = self.system / self.unit
        self.path.write_bytes(self.raw)
        self.path.chmod(0o644)
        (self.system / "sockets.target.wants").mkdir()
        self.sha = hashlib.sha256(self.raw).hexdigest()
        self.states = {self.unit: {"active": True, "enablement": "enabled", "sha256": self.sha}}
        self.driver = apply.Services(self.root, self.states, uid=os.getuid(), gid=os.getgid())
        self.enable = {"kind": "enablement", "resource": self.unit,
                       "desired": {"state": "enabled", "sha256": self.sha}}
        self.activate = {"kind": "service", "resource": self.unit,
                         "desired": {"active": True, "sha256": self.sha}}
        self.active = False
        self.commands = []
        self.foreign_fragment = False
        self.dropins = ""
        patcher = patch.object(self.driver, "_command", side_effect=self.command)
        patcher.start()
        self.addCleanup(patcher.stop)

    def command(self, args, **kwargs):
        self.commands.append(args)
        if args[0] == "show":
            if "--property=DropInPaths" in args:
                return self.dropins
            return "/usr/lib/systemd/system/foreign.socket" if self.foreign_fragment else "/etc/systemd/system/" + self.unit
        if args[0] == "is-active":
            return "active" if self.active else "inactive"
        if args[0] == "is-enabled":
            return "enabled" if (self.system / "sockets.target.wants" / self.unit).is_symlink() else "disabled"
        if args[0] in ("start", "stop"):
            self.active = args[0] == "start"
            return ""
        raise AssertionError(args)

    def test_enable_start_stop_and_disable_restore_exact_unit(self):
        enable_proof = self.driver.prepare(self.enable)
        self.driver.execute(self.enable, enable_proof)
        self.driver.verify(self.enable, enable_proof)
        link = self.system / "sockets.target.wants" / self.unit
        self.assertEqual(os.readlink(link), "../" + self.unit)
        start_proof = self.driver.prepare(self.activate)
        self.driver.execute(self.activate, start_proof)
        self.driver.verify(self.activate, start_proof)
        self.assertTrue(self.active)
        self.driver.undo(self.activate, start_proof)
        self.driver.undo(self.enable, enable_proof)
        self.driver.undo(self.enable, enable_proof)
        self.assertFalse(self.active)
        self.assertFalse(link.is_symlink())

    def test_changed_unit_or_loaded_fragment_is_never_stopped(self):
        proof = self.driver.prepare(self.activate)
        self.driver.execute(self.activate, proof)
        self.foreign_fragment = True
        with self.assertRaisesRegex(apply.Refused, "RESTORE_UNIT_CHANGED"):
            self.driver.undo(self.activate, proof)
        self.assertTrue(self.active)
        self.foreign_fragment = False
        self.path.write_bytes(self.raw + b"# changed\n")
        with self.assertRaisesRegex(apply.Refused, "RESTORE_UNIT_CHANGED"):
            self.driver.undo(self.activate, proof)
        self.assertTrue(self.active)

    def test_foreign_enablement_link_is_preserved(self):
        proof = self.driver.prepare(self.enable)
        self.driver.execute(self.enable, proof)
        link = self.system / "sockets.target.wants" / self.unit
        link.unlink()
        link.symlink_to("../foreign.socket")
        with self.assertRaisesRegex(apply.Refused, "RESTORE_ENABLEMENT_CHANGED"):
            self.driver.undo(self.enable, proof)
        self.assertEqual(os.readlink(link), "../foreign.socket")

    def test_alias_also_and_arbitrary_targets_are_not_delegated_to_systemctl(self):
        for install in ("Alias=other.socket", "Also=other.socket", "WantedBy=foreign.target"):
            self.raw = ("[Socket]\nListenStream=/run/sovagrid-test.sock\n[Install]\n" + install + "\n").encode()
            self.path.write_bytes(self.raw)
            self.sha = hashlib.sha256(self.raw).hexdigest()
            self.enable["desired"]["sha256"] = self.sha
            self.states[self.unit]["sha256"] = self.sha
            with self.subTest(install=install):
                with self.assertRaisesRegex(apply.Refused, "RESTORE_ENABLEMENT_UNSUPPORTED"):
                    self.driver.prepare(self.enable)
        self.assertFalse(any(args[0] in ("start", "enable", "disable") for args in self.commands))

    def test_already_active_unit_is_not_adopted(self):
        self.active = True
        with self.assertRaisesRegex(apply.Refused, "RESTORE_UNIT_ALREADY_ACTIVE"):
            self.driver.prepare(self.activate)

    def test_effective_foreign_dropin_blocks_start_and_recovery_stop(self):
        proof = self.driver.prepare(self.activate)
        self.dropins = "/run/systemd/system/socket.d/foreign.conf"
        for action in (self.driver.execute, self.driver.undo):
            with self.assertRaisesRegex(apply.Refused, "RESTORE_UNIT_OVERRIDE_PRESENT"):
                action(self.activate, proof)
        self.assertFalse(any(args[0] in ("start", "stop") for args in self.commands))

    def test_all_standard_paths_reject_unit_prefix_and_typewide_dropins(self):
        for base, name in (("run/systemd/system", self.unit + ".d"),
                           ("usr/lib/systemd/system", "sovagrid-.socket.d"),
                           ("etc/systemd/system", "socket.d")):
            target = self.root / base / name
            target.mkdir(parents=True)
            with self.subTest(path=base, name=name):
                with self.assertRaisesRegex(apply.Refused, "RESTORE_UNIT_OVERRIDE_PRESENT"):
                    self.driver.audit(self.unit)
            target.rmdir()

    def test_foreign_activation_route_prevents_prepare_and_commit(self):
        proof = self.driver.prepare(self.enable)
        self.driver.execute(self.enable, proof)
        directory = self.root / "run/systemd/system/foreign.target.requires"
        directory.mkdir(parents=True)
        foreign = directory / self.unit
        foreign.symlink_to("/etc/systemd/system/" + self.unit)
        with self.assertRaisesRegex(apply.Refused, "RESTORE_ENABLEMENT_CHANGED"):
            self.driver.verify(self.enable, proof)
        self.assertTrue(foreign.is_symlink())
        with self.assertRaisesRegex(apply.Refused, "RESTORE_ENABLEMENT_CHANGED"):
            self.driver.prepare(self.activate)

    def test_missing_enablement_parent_is_not_created_outside_journal(self):
        (self.system / "sockets.target.wants").rmdir()
        with self.assertRaises(FileNotFoundError):
            self.driver.prepare(self.enable)
        self.assertFalse((self.system / "sockets.target.wants").exists())


if __name__ == "__main__":
    unittest.main()
