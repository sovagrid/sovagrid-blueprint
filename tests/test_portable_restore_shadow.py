# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Interrupted shadow construction must clean only its nonce-bound namespace."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from deploy import host_restore as restore
from deploy import portable_restore_apply as core
from deploy import portable_restore_shadow as shadows


IDENTITY = "a" * 32


class PowerLoss(BaseException):
    pass


class ShadowTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "etc").mkdir()
        self.stage = self.root / "var/lib/.sovagrid-host-restore-staging" / IDENTITY
        source = self.stage / "etc/sovagrid-test/sub/token"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"test-only-source-content")
        source.chmod(0o600)
        entries = {
            "": {"kind": "dir", "uid": os.getuid(), "gid": os.getgid(), "mode": 0o750, "mtime": 1700000000},
            "sub": {"kind": "dir", "uid": os.getuid(), "gid": os.getgid(), "mode": 0o700, "mtime": 1700000001},
            "sub/token": {"kind": "file", "uid": os.getuid(), "gid": os.getgid(), "mode": 0o640,
                          "mtime": 1700000002, "size": len(source.read_bytes()),
                          "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                          "source": "/etc/sovagrid-test/sub/token"}}
        self.resource = {"target": "/etc/sovagrid-test", "shadow": ".sovagrid-restore-" + IDENTITY + "-0",
                         "sha256": core._resource_digest(entries), "entries": entries}
        self.step = {"kind": "shadow", "resource": self.resource["target"],
                     "desired": {"shadow": self.resource["shadow"], "sha256": self.resource["sha256"]}}
        self.shadow = self.root / "etc" / self.resource["shadow"]
        self.owner = self.shadow.with_name(self.shadow.name + ".owner")
        self.source = source
        patchers = [patch.object(restore.backup, "ROOT", self.root),
                    patch.object(restore.backup, "ROOT_UID", os.getuid()),
                    patch.object(restore.backup, "ROOT_GID", os.getgid())]
        if not sys.platform.startswith("linux"):
            patchers.append(patch.object(core, "_rename_noreplace", self.rename))
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.driver = shadows.Shadows(restore, core, IDENTITY, [self.resource],
                                      uid=os.getuid(), gid=os.getgid())

    @staticmethod
    def rename(fd, source, target):
        try:
            os.stat(target, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            os.rename(source, target, src_dir_fd=fd, dst_dir_fd=fd)
        else:
            raise core.Refused("RESTORE_TARGET_EXISTS")

    def test_copy_preserves_exact_archive_metadata_without_installing_live_path(self):
        proof = self.driver.prepare(self.step)
        self.driver.execute(self.step, proof)
        self.driver.verify(self.step, proof)
        self.assertEqual(stat.S_IMODE(self.shadow.stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((self.shadow / "sub/token").stat().st_mode), 0o640)
        self.assertEqual(int((self.shadow / "sub/token").stat().st_mtime), 1700000002)
        self.assertFalse((self.root / "etc/sovagrid-test").exists())
        self.driver.undo(self.step, proof)
        self.driver.undo(self.step, proof)
        self.assertFalse(self.shadow.exists())
        self.assertFalse(self.owner.exists())

    def test_partial_file_after_process_death_is_verified_as_source_prefix_and_removed(self):
        proof = self.driver.prepare(self.step)

        def copy(descriptor, entry):
            os.write(descriptor, b"test-only-source")
            raise PowerLoss()

        with patch.object(self.driver, "_copy", side_effect=copy):
            with self.assertRaises(PowerLoss):
                self.driver.execute(self.step, proof)
        self.assertTrue(self.owner.exists())
        self.driver.undo(self.step, proof)
        self.assertFalse(self.shadow.exists())
        self.assertFalse(self.owner.exists())

    def test_crash_after_owner_publication_before_resource_creation_is_recoverable(self):
        proof = self.driver.prepare(self.step)
        original = os.mkdir

        def mkdir(name, *args, **kwargs):
            if name == self.resource["shadow"]:
                raise PowerLoss()
            return original(name, *args, **kwargs)

        with patch.object(shadows.os, "mkdir", side_effect=mkdir):
            with self.assertRaises(PowerLoss):
                self.driver.execute(self.step, proof)
        self.assertTrue(self.owner.exists())
        self.assertFalse(self.shadow.exists())
        self.driver.undo(self.step, proof)
        self.assertFalse(self.owner.exists())

    def test_partial_private_owner_temporary_is_never_published_as_valid_ownership(self):
        proof = self.driver.prepare(self.step)

        def write(descriptor, raw):
            os.write(descriptor, raw[:20])
            raise PowerLoss()

        with patch.object(core, "_write", side_effect=write):
            with self.assertRaises(PowerLoss):
                self.driver.execute(self.step, proof)
        self.assertFalse(self.owner.exists())
        self.assertFalse(self.shadow.exists())
        temporary = self.owner.with_name(self.owner.name + ".tmp" + proof["nonce"])
        self.assertTrue(temporary.exists())
        self.driver.undo(self.step, proof)
        self.assertFalse(temporary.exists())

    def test_foreign_file_in_shadow_or_changed_prefix_is_preserved(self):
        proof = self.driver.prepare(self.step)
        self.driver.execute(self.step, proof)
        unexpected = self.shadow / "foreign"
        unexpected.write_bytes(b"someone-else")
        with self.assertRaisesRegex(core.Refused, "RESTORE_SHADOW_CHANGED"):
            self.driver.undo(self.step, proof)
        self.assertEqual((self.shadow / "sub/token").read_bytes(), self.source.read_bytes())
        unexpected.unlink()
        (self.shadow / "sub/token").write_bytes(b"changed")
        with self.assertRaisesRegex(core.Refused, "RESTORE_SHADOW_CHANGED"):
            self.driver.undo(self.step, proof)
        self.assertTrue(self.owner.exists())

    def test_changed_stage_cannot_authorize_deleting_changed_shadow_bytes(self):
        proof = self.driver.prepare(self.step)
        self.driver.execute(self.step, proof)
        changed = b"x" * len(self.source.read_bytes())
        self.source.write_bytes(changed)
        (self.shadow / "sub/token").write_bytes(changed[:4])
        with self.assertRaisesRegex(core.Refused, "RESTORE_SHADOW_CHANGED"):
            self.driver.undo(self.step, proof)
        self.assertTrue(self.shadow.exists())

    def test_unknown_owner_or_symlink_is_not_removed(self):
        proof = self.driver.prepare(self.step)
        self.driver.execute(self.step, proof)
        self.owner.write_bytes(b"unknown-owner")
        with self.assertRaisesRegex(core.Refused, "RESTORE_SHADOW_OWNER_CHANGED"):
            self.driver.undo(self.step, proof)
        self.assertTrue(self.shadow.exists())

    def test_published_tree_rolls_back_through_quarantine_before_shadow_cleanup(self):
        proof = self.driver.prepare(self.step)
        self.driver.execute(self.step, proof)
        publication = {**self.step, "kind": "publish"}
        publisher = core.Publisher(self.root, IDENTITY, {self.resource["target"]}, uid=os.getuid())
        published = publisher.prepare(publication)
        publisher.execute(publication, published)
        publisher.verify(publication, published)
        self.assertTrue((self.root / "etc/sovagrid-test").exists())
        self.assertFalse(self.shadow.exists())
        publisher.undo(publication, published)
        self.driver.undo(self.step, proof)
        self.assertFalse((self.root / "etc/sovagrid-test").exists())
        self.assertFalse(self.shadow.exists())
        self.assertFalse(self.owner.exists())


if __name__ == "__main__":
    unittest.main()
