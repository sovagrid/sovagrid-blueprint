# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The reboot initializer must preserve lock ownership and held file descriptions."""

import fcntl
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "deploy/runtime_locks.py"
spec = importlib.util.spec_from_file_location("runtime_lock_fixture", SOURCE)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class RuntimeLockTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)

    def ensure(self):
        runtime.ensure(self.root, uid=os.getuid(), gid=os.getgid())

    def test_fresh_boot_creates_only_two_private_regular_files(self):
        self.ensure()
        self.assertEqual({item.name for item in self.root.iterdir()}, set(runtime.NAMES))
        for item in self.root.iterdir():
            value = item.stat()
            self.assertEqual((value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode), value.st_nlink),
                             (os.getuid(), os.getgid(), 0o600, 1))
            self.assertEqual(item.read_bytes(), b"")

    def test_repeated_initialization_preserves_bytes_inode_and_held_lock(self):
        self.ensure()
        item = self.root / runtime.NAMES[0]
        item.write_bytes(b"existing diagnostic")
        before = item.stat()
        descriptor = os.open(item, os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.ensure()
            after = item.stat()
            self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
            self.assertEqual(item.read_bytes(), b"existing diagnostic")
            other = os.open(item, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(other)
        finally:
            os.close(descriptor)

    def test_existing_unsafe_entries_are_rejected_without_repair(self):
        for kind in ("symlink", "hardlink", "mode", "directory", "fifo"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                root.chmod(0o700)
                original = root / "original"
                original.write_bytes(b"unchanged")
                original.chmod(0o600)
                target = root / runtime.NAMES[0]
                if kind == "symlink":
                    target.symlink_to(original)
                elif kind == "hardlink":
                    os.link(original, target)
                elif kind == "directory":
                    target.mkdir()
                elif kind == "fifo":
                    os.mkfifo(target, 0o600)
                else:
                    target.write_bytes(b"keep")
                    target.chmod(0o644)
                before = target.lstat()
                with self.assertRaises((OSError, ValueError)):
                    runtime.ensure(root, uid=os.getuid(), gid=os.getgid())
                self.assertEqual(target.lstat(), before)
                self.assertEqual(original.read_bytes(), b"unchanged")

    def test_unsafe_parent_is_rejected_before_creating_files(self):
        self.root.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "UNSAFE_RUNTIME_DIRECTORY"):
            self.ensure()
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
