# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""A package may have extra files, but Agent recovery gets an exact tree."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
spec = importlib.util.spec_from_file_location("sovagrid_external_projection_test",
                                              DEPLOY / "external_agent_update.py")
assert spec and spec.loader
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)


class ExactProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.parent = self.root / "private-candidates"
        self.parent.mkdir(mode=0o700)
        self.parent.chmod(0o700)
        self.candidate = self.root / "candidate"
        (self.candidate / "sovagrid-agent/sovagrid_agent").mkdir(parents=True)
        self.files = {
            "LICENSE": b"license\n",
            "sovagrid_agent/__main__.py": b"print('agent')\n",
        }
        for relative, value in self.files.items():
            (self.candidate / "sovagrid-agent" / relative).write_bytes(value)
        self.tree = {name: hashlib.sha256(value).hexdigest()
                     for name, value in self.files.items()}
        self.owner, self.group = os.geteuid(), os.getegid()

    def stage(self, verifier):
        return planner._projected_candidate_tree(
            self.candidate, self.tree, verifier, staging_parent=self.parent,
            owner=self.owner, group=self.group)

    def test_extra_package_files_never_enter_recovery_projection(self):
        (self.candidate / "sovagrid-agent/tests").mkdir()
        (self.candidate / "sovagrid-agent/tests/test_agent.py").write_text("extra\n")
        observed = []

        def verify(path, expected):
            root = Path(path)
            observed.append(root)
            self.assertEqual(expected, self.tree)
            self.assertEqual({item.relative_to(root).as_posix() for item in root.rglob("*")
                              if item.is_file()}, set(self.tree))
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)
            self.assertTrue(all(stat.S_IMODE((root / name).stat().st_mode) == 0o644
                                for name in self.tree))

        with self.stage(mock.Mock(_tree=verify)) as projected:
            self.assertEqual(projected, observed[0])
            self.assertFalse((projected / "tests").exists())
        self.assertFalse(observed[0].exists())
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_changed_or_symlinked_source_refuses_and_cleans_staging(self):
        source = self.candidate / "sovagrid-agent/LICENSE"
        source.write_bytes(b"changed\n")
        with self.assertRaisesRegex(planner.Refused, "CANDIDATE_CHANGED"):
            with self.stage(mock.Mock()):
                self.fail("changed candidate was staged")
        self.assertEqual(list(self.parent.iterdir()), [])

        source.unlink()
        source.symlink_to(self.root / "outside")
        (self.root / "outside").write_bytes(self.files["LICENSE"])
        with self.assertRaisesRegex(planner.Refused, "CANDIDATE_CHANGED"):
            with self.stage(mock.Mock()):
                self.fail("symlinked candidate was staged")
        self.assertEqual(list(self.parent.iterdir()), [])

        source.unlink()
        source.write_bytes(self.files["LICENSE"])
        nested = self.candidate / "sovagrid-agent/sovagrid_agent"
        outside_directory = self.root / "outside-directory"
        nested.rename(outside_directory)
        nested.symlink_to(outside_directory, target_is_directory=True)
        with self.assertRaisesRegex(planner.Refused, "CANDIDATE_CHANGED"):
            with self.stage(mock.Mock()):
                self.fail("symlinked parent was staged")
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_verification_exception_also_cleans_staging(self):
        verifier = mock.Mock()
        verifier._tree.side_effect = RuntimeError("strict tree rejected")
        with self.assertRaisesRegex(RuntimeError, "strict tree rejected"):
            with self.stage(verifier):
                self.fail("unverified projection was yielded")
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_unsafe_parent_and_path_traversal_refuse(self):
        alias = self.root / "candidate-alias"
        alias.symlink_to(self.parent, target_is_directory=True)
        with self.assertRaisesRegex(planner.Refused, "PROJECTION_STAGING_UNSAFE"):
            with planner._projected_candidate_tree(
                    self.candidate, self.tree, mock.Mock(), staging_parent=alias,
                    owner=self.owner, group=self.group):
                self.fail("unsafe staging parent was accepted")
        with self.assertRaisesRegex(planner.Refused, "PROJECTION_INVALID"):
            with planner._projected_candidate_tree(
                    self.candidate, {"../escape": "a" * 64}, mock.Mock(),
                    staging_parent=self.parent, owner=self.owner, group=self.group):
                self.fail("traversal was accepted")
        self.assertEqual(list(self.parent.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
