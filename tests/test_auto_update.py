# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""One-candidate timer policy must fail closed and remain optional."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "auto_update.py"
spec = importlib.util.spec_from_file_location("sovagrid_server_auto_update", SCRIPT)
assert spec and spec.loader
auto = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auto)
ARCHIVE = "a" * 64
CURRENT = "b" * 64


class TimerPolicy(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.patchers = [
            mock.patch.object(auto, "POLICY", root / "auto-update.json"),
            mock.patch.object(auto, "STATUS", root / "auto-update-status.json"),
            mock.patch.object(auto, "LOCK", root / ".auto-update.lock"),
            mock.patch.object(auto, "ROOT_UID", os.geteuid()),
            mock.patch.object(auto, "require_root", return_value=None),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def success(marker: str, code: int = 0) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], code, marker + "\n", "")

    def arm(self) -> None:
        with mock.patch.object(auto, "worker", return_value=self.success("SG_UPDATE_PREFLIGHT:OK")) as worker, \
             mock.patch.object(auto.subprocess, "run", return_value=self.success("")) as systemctl:
            auto.arm(ARCHIVE, CURRENT)
        worker.assert_called_once_with("preflight", ARCHIVE, CURRENT)
        self.assertEqual(systemctl.call_args.args[0], ["systemctl", "enable", "--now", auto.TIMER])

    def test_arm_creates_only_one_exact_private_pin(self) -> None:
        self.arm()
        policy = auto.load_policy()
        assert policy is not None
        self.assertEqual(policy["archive_sha256"], ARCHIVE)
        self.assertEqual(policy["expected_current_manifest"], CURRENT)
        self.assertEqual(auto.POLICY.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(auto.Refused, "ALREADY_ARMED"):
            auto.arm("c" * 64, CURRENT)

    def test_bad_preflight_cannot_arm(self) -> None:
        with mock.patch.object(auto, "worker", return_value=self.success("SG_UPDATE_REFUSE:HASH", 40)):
            with self.assertRaisesRegex(auto.Refused, "PREFLIGHT_FAILED"):
                auto.arm(ARCHIVE, CURRENT)
        self.assertFalse(auto.POLICY.exists())

    def test_rearm_expired_identical_pin_revalidates(self) -> None:
        self.arm()
        data = auto.load_policy()
        assert data is not None
        data["created_at"] -= auto.POLICY_LIFETIME + 1
        data["expires_at"] -= auto.POLICY_LIFETIME + 1
        auto.atomic_private(auto.POLICY, auto.json_bytes(data))
        with mock.patch.object(auto, "worker", return_value=self.success("SG_UPDATE_REFUSE:VERSION", 40)) as worker:
            with self.assertRaisesRegex(auto.Refused, "PREFLIGHT_FAILED"):
                auto.arm(ARCHIVE, CURRENT)
        worker.assert_called_once_with("preflight", ARCHIVE, CURRENT)
        self.assertIsNone(auto.load_policy())
        self.assertEqual(json.loads(auto.STATUS.read_text())["state"], "expired")

    def test_timer_failure_revokes_new_policy(self) -> None:
        with mock.patch.object(auto, "worker", return_value=self.success("SG_UPDATE_PREFLIGHT:OK")), \
             mock.patch.object(auto.subprocess, "run", side_effect=OSError("systemd unavailable")):
            with self.assertRaisesRegex(auto.Refused, "TIMER_UNAVAILABLE"):
                auto.arm(ARCHIVE, CURRENT)
        self.assertIsNone(auto.load_policy())

    def test_timer_busy_defers_then_applies_once(self) -> None:
        self.arm()
        with mock.patch.object(auto, "worker", return_value=self.success("SG_UPDATE_REFUSE:BUSY", 40)):
            auto.tick()
        self.assertIsNotNone(auto.load_policy())
        self.assertEqual(json.loads(auto.STATUS.read_text())["state"], "deferred_busy")
        with mock.patch.object(auto, "worker", return_value=self.success("SG_APPLY_STAGE:DONE")) as worker:
            auto.tick()
        worker.assert_called_once_with("apply-auto", ARCHIVE, CURRENT)
        self.assertIsNone(auto.load_policy())
        self.assertEqual(json.loads(auto.STATUS.read_text())["state"], "applied")

    def test_failed_apply_disarms_to_prevent_repeated_downtime(self) -> None:
        self.arm()
        with mock.patch.object(auto, "worker", return_value=self.success(
                "SG_APPLY_STAGE:ROLLBACK_FAILED\nSG_UPDATE_REFUSE:RECOVERY", 40)):
            with self.assertRaisesRegex(auto.Refused, "UPDATE_FAILED"):
                auto.tick()
        self.assertIsNone(auto.load_policy())
        status = json.loads(auto.STATUS.read_text())
        self.assertEqual(status["state"], "needs_attention")
        self.assertNotIn("token", status)

    def test_expiry_disarms_without_invoking_worker(self) -> None:
        self.arm()
        data = auto.load_policy()
        assert data is not None
        data["created_at"] -= auto.POLICY_LIFETIME + 1
        data["expires_at"] -= auto.POLICY_LIFETIME + 1
        auto.atomic_private(auto.POLICY, auto.json_bytes(data))
        with mock.patch.object(auto, "worker") as worker:
            auto.tick()
        worker.assert_not_called()
        self.assertIsNone(auto.load_policy())
        self.assertEqual(json.loads(auto.STATUS.read_text())["state"], "expired")

    def test_symlink_and_weak_modes_are_rejected(self) -> None:
        target = auto.POLICY.parent / "target"
        target.write_text("{}")
        auto.POLICY.symlink_to(target)
        with self.assertRaisesRegex(auto.Refused, "UNSAFE_FILE"):
            auto.load_policy()
        auto.POLICY.unlink()
        auto.POLICY.write_text("{}")
        auto.POLICY.chmod(0o644)
        with self.assertRaisesRegex(auto.Refused, "UNSAFE_FILE"):
            auto.load_policy()

    def test_install_guard_precedes_mutation_and_timer_is_opt_in(self) -> None:
        source = (SCRIPT.parents[1] / "run.sh").read_text()
        self.assertLess(source.index("SOVAGRID_UPDATER_TIMER_SNAPSHOT"), source.index("apt_refresh()"))
        self.assertIn("systemctl enable --now sovagrid-auto-update.timer", source)
        service = (SCRIPT.parent / "sovagrid-auto-update.service").read_text()
        self.assertIn("ConditionPathExists=/etc/sovagrid/auto-update.json", service)
        self.assertNotIn("curl", service)


if __name__ == "__main__":
    unittest.main()
