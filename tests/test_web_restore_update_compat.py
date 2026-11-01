# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Existing restore journals cannot be downgraded out of their runtime."""
from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.test_hub_only_update import update as hub

worker = hub.common
ROOT = Path(__file__).resolve().parents[1]


class WebRestoreUpdateCompatibility(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.namespace = self.root / worker.WEB_RESTORE_DIR.lstrip("/")
        self.namespace.mkdir(parents=True, mode=0o700)
        self.namespace.chmod(0o700)
        self.source = self.root / "candidate"
        self.script = self.source / "sovagrid-blueprint/run.sh"
        self.script.parent.mkdir(parents=True)
        self.script.write_bytes(b"#!/bin/bash\n# --hub-only\n# local-hub-ca.pem\n")
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in (("ROOT", self.root), ("PUBLIC_OWNER", os.getuid()),
                            ("web_agent_managed", lambda: False), ("backup_broker_enabled", lambda: False),
                            ("ssh_gateway_managed", lambda: False), ("managed_routing_enabled", lambda: False)):
            self.stack.enter_context(patch.object(worker, name, value))
        original = Path.lstat
        self.bad_gid = None

        def root_group(path):
            info = original(path)
            if path.is_relative_to(self.root):
                return SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid,
                    st_gid=1 if path == self.bad_gid else 0, st_nlink=info.st_nlink, st_size=info.st_size)
            return info

        self.stack.enter_context(patch.object(Path, "lstat", root_group))
        for name, value in (("CANDIDATES", self.root), ("SOURCE", self.root)):
            self.stack.enter_context(patch.object(hub, name, value))
        self.stack.enter_context(patch.object(worker, "candidate_source", return_value=(self.source, {"component": "new"})))
        for name in hub.REQUIRED_CANDIDATE:
            if name != "sovagrid-blueprint/run.sh":
                self.file(name)

    def file(self, name):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n")
        return path

    def check_full(self):
        return worker.candidate_features_compatible(self.source, [])

    def check_hub(self):
        return hub._candidate("a" * 64, {"component": "old"})

    def test_both_candidate_paths_require_marker_and_every_runtime_file(self):
        for check, error in ((self.check_full, worker.UpdateFailure), (self.check_hub, hub.Refused)):
            with self.assertRaises(error):
                check()
        self.script.write_bytes(self.script.read_bytes() + b"# SOVAGRID_WEB_RESTORE_V1\n")
        for name in worker.WEB_RESTORE_REQUIRED:
            self.file(name)
        self.check_full(); self.check_hub()
        for name in worker.WEB_RESTORE_REQUIRED:
            path = self.source / name
            path.unlink()
            for check, error in ((self.check_full, worker.UpdateFailure), (self.check_hub, hub.Refused)):
                with self.subTest(name=name, check=check.__name__), self.assertRaises(error):
                    check()
            self.file(name)
        # A file link is not preservation of the fixed runtime closure.
        path = self.source / worker.WEB_RESTORE_REQUIRED[0]
        path.unlink(); path.symlink_to(self.script)
        with self.assertRaises(worker.UpdateFailure): self.check_full()
        with self.assertRaises(hub.Refused): self.check_hub()

    def test_absent_namespace_allows_the_old_candidate_without_modifying_snapshot_layout(self):
        self.namespace.rmdir()
        self.check_full(); self.check_hub()
        self.assertNotIn(worker.WEB_RESTORE_DIR, worker.SNAPSHOT)
        self.assertNotIn("/var/cache/sovagrid-web-restores", worker.SNAPSHOT)
        self.assertIn(worker.WEB_AGENT_DIR, worker.SNAPSHOT)
        self.assertIn(worker.WEB_AGENT_DIR, hub.SNAPSHOT)

    def test_unsafe_present_namespace_is_never_adopted(self):
        self.namespace.chmod(0o755)
        with self.assertRaisesRegex(worker.UpdateFailure, "STATE"): worker.web_restore_managed()
        self.assertEqual(stat.S_IMODE(self.namespace.stat().st_mode), 0o755)
        self.namespace.chmod(0o700)
        self.bad_gid = self.namespace
        with self.assertRaisesRegex(worker.UpdateFailure, "STATE"): worker.web_restore_managed()
        self.bad_gid = None
        self.namespace.rmdir(); self.namespace.symlink_to(self.root / "missing", target_is_directory=True)
        with self.assertRaisesRegex(worker.UpdateFailure, "STATE"): worker.web_restore_managed()
        self.assertTrue(self.namespace.is_symlink())

    def test_recursive_existing_snapshot_copies_restore_records_and_excludes_cache(self):
        record = self.namespace / "operations" / ("a" * 32) / "state.json"
        record.parent.mkdir(parents=True)
        record.write_text('{"operation_id":"nonsecret-fixture"}\n')
        destination = self.root / "saved-agent"
        def local_copy(args, **kwargs):
            self.assertEqual(args[:4], ["cp", "-a", "--reflink=auto", "--"])
            shutil.copytree(args[-2], args[-1])
        with patch.object(worker, "command", side_effect=local_copy):
            worker.copy_item(self.namespace.parent, destination)
        self.assertEqual((destination / record.relative_to(self.namespace.parent)).read_bytes(), record.read_bytes())
        self.assertNotIn("/var/cache/sovagrid-web-restores", (*worker.SNAPSHOT, *hub.SNAPSHOT))

    def test_guard_covers_the_audited_vendored_python_closure(self):
        spec = importlib.util.spec_from_file_location("restore_vendor_closure_test", ROOT / "tools/sync_connect_vendor.py")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        expected = {"sovagrid-blueprint/vendor/connect/" + name for name in module.SELECTED_FILES if name.endswith(".py")}
        self.assertTrue(expected <= set(worker.WEB_RESTORE_REQUIRED), expected - set(worker.WEB_RESTORE_REQUIRED))


if __name__ == "__main__":
    unittest.main()
