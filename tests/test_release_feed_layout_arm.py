# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Layout-bound feed arm preserves legacy policy and policy-first lock order."""
import contextlib
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"


def load(filename):
    spec = importlib.util.spec_from_file_location("feed_arm_" + filename.replace(".", "_"), DEPLOY / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


feed = load("release_feed.py")
full = load("auto_update.py")
hub = load("hub_only_auto_update.py")
ARCHIVE, CURRENT = "a" * 64, "b" * 64


class LayoutArmTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, automatic, layout):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as changes:
            root = Path(directory)
            for module in (automatic, feed):
                changes.enter_context(mock.patch.object(module, "ROOT_UID", os.getuid()))
            changes.enter_context(mock.patch.object(automatic, "require_root"))
            for key, value in {"POLICY": root / "approval.json", "STATUS": root / "status.json",
                               "LOCK": root / "policy.lock"}.items():
                changes.enter_context(mock.patch.object(automatic, key, value))
            for key, value in {"INSTALLATION_LOCK": root / "installation.lock", "PROMOTION_LOCK": root / "promotion.lock",
                               "PROMOTION_STATE_DIR": root / "promotion", "HUB_ONLY_ARTIFACTS": (),
                               "HUB_ONLY_MANUAL_POLICY": root / "hub-manual.json",
                               "RESTORE_FENCE": root / "restore.pending"}.items():
                changes.enter_context(mock.patch.object(feed, key, value))
            if layout == "hub_only":
                feed.PROMOTION_STATE_DIR.mkdir(mode=0o700)
                for name in ("baseline.json", "bundle-pin.json", "local-agent.json"):
                    path = feed.PROMOTION_STATE_DIR / name
                    path.write_text("{}"); path.chmod(0o600)
            changes.enter_context(mock.patch.object(automatic, "_signed_layout_module", return_value=feed))
            yield root

    def assert_locked(self, path, locked):
        with path.open("a+") as stream:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.assertTrue(locked)
            else:
                self.assertFalse(locked)

    def test_fixed_backend_arms_under_policy_then_layout_and_releases_layout_before_systemctl(self):
        for automatic, layout, marker in ((full, "full", "SG_UPDATE_PREFLIGHT:OK"),
                                           (hub, "hub_only", "SG_HUB_ONLY_CANDIDATE:OK")):
            with self.subTest(layout=layout), self.fixture(automatic, layout):
                def preflight(*args):
                    self.assertEqual(args, ("preflight", ARCHIVE, CURRENT))
                    self.assert_locked(automatic.LOCK, True)
                    self.assert_locked(feed.INSTALLATION_LOCK, True)
                    self.assert_locked(feed.PROMOTION_LOCK, True)
                    return subprocess.CompletedProcess([], 0, marker + "\n", "")
                def systemctl(*_args, **_kwargs):
                    self.assert_locked(automatic.LOCK, True)
                    self.assert_locked(feed.INSTALLATION_LOCK, False)
                    self.assert_locked(feed.PROMOTION_LOCK, False)
                    return subprocess.CompletedProcess([], 0, "", "")
                with mock.patch.object(automatic, "worker", side_effect=preflight), \
                     mock.patch.object(automatic.subprocess, "run", side_effect=systemctl):
                    automatic.arm(ARCHIVE, CURRENT, layout=layout)
                policy = automatic.load_policy()
                self.assertEqual(set(policy), {"format", "archive_sha256", "expected_current_manifest", "created_at", "expires_at"})
                self.assertEqual(policy["archive_sha256"], ARCHIVE)

    def test_wrong_backend_or_changed_layout_cannot_create_a_policy(self):
        for automatic, bound, actual in ((full, "hub_only", "hub_only"), (hub, "full", "full"),
                                          (full, "full", "hub_only"), (hub, "hub_only", "full")):
            with self.subTest(bound=bound, actual=actual), self.fixture(automatic, actual):
                with mock.patch.object(automatic, "worker") as worker, \
                     mock.patch.object(automatic.subprocess, "run") as systemctl:
                    with self.assertRaisesRegex(automatic.Refused, "STATE_CHANGED"):
                        automatic.arm(ARCHIVE, CURRENT, layout=bound)
                worker.assert_not_called(); systemctl.assert_not_called()
                self.assertFalse(automatic.POLICY.exists())

    def test_layout_change_during_preflight_revokes_only_the_exact_new_policy(self):
        for automatic, layout, marker in ((full, "full", "SG_UPDATE_PREFLIGHT:OK"),
                                           (hub, "hub_only", "SG_HUB_ONLY_CANDIDATE:OK")):
            with self.subTest(layout=layout), self.fixture(automatic, layout):
                def preflight(*_args):
                    if layout == "full":
                        feed.PROMOTION_STATE_DIR.mkdir(mode=0o700)
                    else:
                        for path in feed.PROMOTION_STATE_DIR.iterdir(): path.unlink()
                        feed.PROMOTION_STATE_DIR.rmdir()
                    return subprocess.CompletedProcess([], 0, marker + "\n", "")
                with mock.patch.object(automatic, "worker", side_effect=preflight), \
                     mock.patch.object(automatic.subprocess, "run") as systemctl:
                    with self.assertRaises(automatic.Refused):
                        automatic.arm(ARCHIVE, CURRENT, layout=layout)
                systemctl.assert_not_called()
                self.assertFalse(automatic.POLICY.exists())

    def test_layout_guard_does_not_wait_on_installation_lock_while_holding_policy(self):
        with self.fixture(full, "full"):
            with feed.layout_guard("full"):
                with mock.patch.object(full, "worker") as worker:
                    with self.assertRaisesRegex(full.Refused, "BUSY"):
                        full.arm(ARCHIVE, CURRENT, layout="full")
            worker.assert_not_called()
            self.assertFalse(full.POLICY.exists())

    def test_unsafe_runtime_lock_cannot_reach_preflight_or_create_policy(self):
        for kind in ("symlink", "directory", "mode", "hardlink"):
            with self.subTest(kind=kind), self.fixture(hub, "hub_only") as root:
                lock = feed.INSTALLATION_LOCK
                target = root / "foreign"
                if kind == "symlink":
                    target.write_text("do not change"); lock.symlink_to(target)
                elif kind == "directory": lock.mkdir()
                elif kind == "mode": lock.touch(); lock.chmod(0o644)
                else:
                    target.touch(); target.chmod(0o600); os.link(target, lock)
                with mock.patch.object(hub, "worker") as worker:
                    with self.assertRaisesRegex(hub.Refused, "UNSAFE_LOCK"):
                        hub.arm(ARCHIVE, CURRENT, layout="hub_only")
                worker.assert_not_called()
                self.assertFalse(hub.POLICY.exists())
                if kind == "symlink": self.assertEqual(target.read_text(), "do not change")

    def test_new_cli_is_optional_and_rejects_another_backend(self):
        for automatic, layout in ((full, "full"), (hub, "hub_only")):
            with self.subTest(layout=layout), mock.patch.object(automatic, "arm") as arm:
                self.assertEqual(automatic.main(["arm", ARCHIVE, CURRENT]), 0)
                arm.assert_called_once_with(ARCHIVE, CURRENT)
                arm.reset_mock()
                self.assertEqual(automatic.main(["arm", ARCHIVE, CURRENT, "--layout", layout]), 0)
                arm.assert_called_once_with(ARCHIVE, CURRENT, layout=layout)
