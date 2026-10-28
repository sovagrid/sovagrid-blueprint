# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Actual metadata and fail-before-mutation checks for extracted build inputs."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build_context_refresh", REPO / "deploy/refresh_build_contexts.py")
build_contexts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_contexts)


class BuildContextMetadata(unittest.TestCase):
    def fixture(self, root):
        paths = []
        for name in build_contexts.CONTEXTS:
            context = root / name
            context.mkdir()
            path = context / "input.txt"
            path.write_bytes(b"verified source bytes\n")
            path.chmod(0o644)
            os.utime(path, ns=(123456789, 0))
            paths.append(path)
        return paths

    def test_refresh_preserves_source_bytes_modes_atimes_and_skips_local_caches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self.fixture(root)
            excluded = []
            for name in build_contexts.EXCLUDED:
                cache = root / "sovagrid-web" / name
                cache.mkdir()
                entry = cache / "untouched"
                entry.write_bytes(b"local cache\n")
                os.utime(entry, ns=(0, 0))
                excluded.append(entry)
            outside = root / "outside.txt"
            outside.write_bytes(b"outside source\n")
            os.utime(outside, ns=(0, 0))
            (root / "sovagrid-hub/.git").symlink_to(outside)
            excluded.append(outside)
            original = {p: (p.read_bytes(), p.stat()) for p in paths}
            # Atime is captured after reading the original bytes.
            original = {p: (raw, p.stat()) for p, (raw, _info) in original.items()}
            with patch.object(build_contexts.time, "time_ns", return_value=0):
                self.assertEqual(build_contexts.refresh(root), len(paths))
            for path, (raw, before) in original.items():
                after = path.stat()
                self.assertEqual(after.st_mtime_ns, 1)
                self.assertEqual(after.st_atime_ns, before.st_atime_ns)
                self.assertEqual(stat.S_IMODE(after.st_mode), stat.S_IMODE(before.st_mode))
                self.assertEqual((after.st_uid, after.st_gid), (before.st_uid, before.st_gid))
                self.assertEqual(path.read_bytes(), raw)
            self.assertTrue(all(path.stat().st_mtime_ns == 0 for path in excluded))

    def test_linked_or_special_inputs_fail_before_any_source_file_is_touched(self):
        for kind in ("file-link", "directory-link", "hard-link", "fifo"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                paths = self.fixture(root)
                outside = root / "outside.txt"
                outside.write_bytes(b"outside source\n")
                os.utime(outside, ns=(0, 0))
                unexpected = root / "sovagrid-web" / "unexpected"
                if kind == "file-link":
                    unexpected.symlink_to(outside)
                elif kind == "directory-link":
                    unexpected.symlink_to(root, target_is_directory=True)
                elif kind == "hard-link":
                    os.link(outside, unexpected)
                else:
                    os.mkfifo(unexpected)
                with self.assertRaises(build_contexts.BuildContextError):
                    build_contexts.refresh(root)
                self.assertTrue(all(path.stat().st_mtime_ns == 0 for path in [*paths, outside]))

    def test_linked_root_or_context_cannot_refresh_an_outside_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.mkdir()
            paths = self.fixture(outside)
            root_link = root / "linked-root"
            root_link.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(build_contexts.BuildContextError):
                build_contexts.refresh(root_link)
            selected = root / "selected"
            selected.mkdir()
            (selected / "sovagrid-hub").mkdir()
            (selected / "sovagrid-web").symlink_to(outside / "sovagrid-web", target_is_directory=True)
            with self.assertRaises(build_contexts.BuildContextError):
                build_contexts.refresh(selected)
            self.assertTrue(all(path.stat().st_mtime_ns == 0 for path in paths))

    def test_walk_and_size_bounds_refuse_before_refresh(self):
        for limit, value in (("MAX_ENTRIES", 1), ("MAX_BYTES", 1), ("MAX_DEPTH", 0)):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                paths = self.fixture(root)
                (root / "sovagrid-web/nested").mkdir()
                with patch.object(build_contexts, limit, value), self.assertRaises(build_contexts.BuildContextError):
                    build_contexts.refresh(root)
                self.assertTrue(all(path.stat().st_mtime_ns == 0 for path in paths))


if __name__ == "__main__":
    unittest.main()
