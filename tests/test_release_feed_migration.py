# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Offline checks for the two-stage feed-unit migration and snapshot layouts."""

from __future__ import annotations

from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tests.test_hub_only_update import update as hub_only
from tests.test_release_feed import feed


ROOT = Path(__file__).resolve().parents[1]


class ReleaseFeedMigration(unittest.TestCase):
    def test_legacy_snapshot_indices_are_unchanged(self) -> None:
        common = hub_only.common
        self.assertEqual(common.SNAPSHOT[:len(common.LEGACY_SNAPSHOT)], common.LEGACY_SNAPSHOT)
        self.assertEqual(common.UNITS[:len(common.LEGACY_UNITS)], common.LEGACY_UNITS)
        self.assertEqual(hub_only.SNAPSHOT[:len(hub_only.LEGACY_SNAPSHOT)], hub_only.LEGACY_SNAPSHOT)
        self.assertEqual(hub_only.UNITS[:len(hub_only.LEGACY_UNITS)], hub_only.LEGACY_UNITS)
        for worker in (common, hub_only):
            self.assertIn("/var/lib/sovagrid/.release-feed-units-managed-by-run-sh", worker.SNAPSHOT)
            self.assertIn("/var/lib/sovagrid/release-feed-state.json", worker.SNAPSHOT)
            self.assertIn("/etc/systemd/system/sovagrid-release-feed.service", worker.SNAPSHOT)
            self.assertIn("/etc/systemd/system/sovagrid-release-feed.timer", worker.SNAPSHOT)
            self.assertIn("sovagrid-release-feed.timer", worker.UNITS)
        self.assertIn("/etc/sovagrid/release-feed.json", hub_only.SNAPSHOT)
        self.assertEqual(common.SNAPSHOT[:len(common.RELEASE_FEED_SNAPSHOT)],
                         common.RELEASE_FEED_SNAPSHOT)
        self.assertEqual(hub_only.SNAPSHOT[:len(hub_only.RELEASE_FEED_SNAPSHOT)],
                         hub_only.RELEASE_FEED_SNAPSHOT)
        self.assertIn("/etc/sovagrid-service", common.SNAPSHOT)
        self.assertIn("sovagrid-service-control.socket", common.UNITS)
        self.assertIn("/etc/sovagrid-service-local", hub_only.SNAPSHOT)
        self.assertIn("sovagrid-service-local-control.socket", hub_only.UNITS)
        self.assertNotIn("/etc/sovagrid-service", hub_only.SNAPSHOT)
        self.assertNotIn("/etc/sovagrid-service-local", common.SNAPSHOT)
        for worker in (common, hub_only):
            self.assertNotIn("/etc/sovagrid-service-setup.lock", worker.SNAPSHOT)
            self.assertEqual(worker.SNAPSHOT[:len(worker.SERVICE_SNAPSHOT)], worker.SERVICE_SNAPSHOT)
            self.assertEqual(worker.UNITS[:len(worker.SERVICE_ALL_UNITS)], worker.SERVICE_ALL_UNITS)
            self.assertIn("/etc/sovagrid-vpn-routing/policy.json", worker.SNAPSHOT)
            self.assertIn("/etc/systemd/system/sovagrid-vpn-routing.service", worker.SNAPSHOT)
            self.assertIn("sovagrid-vpn-routing.service", worker.UNITS)
            self.assertNotIn("/etc/sovagrid-vpn-routing", worker.SNAPSHOT)
        for external in ("/etc/sovagrid/agent.json", "/etc/sovagrid/agent.token",
                         "/etc/systemd/system/sovagrid-agent.service", "/opt/sovagrid-agent"):
            self.assertNotIn(external, hub_only.SNAPSHOT)

    def test_unreviewed_key_and_older_worker_cannot_enable_discovery(self) -> None:
        installer = (ROOT / "run.sh").read_text()
        self.assertLess(installer.index("SOVAGRID_RELEASE_FEED_SNAPSHOT"),
                        installer.index("apt_refresh()"))
        self.assertIn("release_feed_deferred=1", installer)
        self.assertIn("install_release_feed_units", installer)
        self.assertNotIn("systemctl enable --now sovagrid-release-feed.timer", installer)
        self.assertEqual(feed.TRUST_ANCHORS, {})
        self.assertIn("SOVAGRID_RELEASE_FEED_SNAPSHOT", (ROOT / "deploy/remote_update_worker.py").read_text())
        self.assertIn("SOVAGRID_RELEASE_FEED_SNAPSHOT", (ROOT / "deploy/hub_only_update.py").read_text())
        subprocess.run(["bash", "-n", str(ROOT / "run.sh")], check=True)

    def test_routing_policy_gate_rejects_partial_or_invalid_state(self) -> None:
        common = hub_only.common
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            policy_dir = root / "etc/sovagrid-vpn-routing"
            policy_dir.mkdir(parents=True, mode=0o700)
            policy_dir.chmod(0o700)
            policy = policy_dir / "policy.json"
            sysctl = root / "etc/sysctl.d/70-sovagrid-vpn-routing.conf"
            unit = root / "etc/systemd/system/sovagrid-vpn-routing.service"
            sysctl.parent.mkdir(parents=True)
            unit.parent.mkdir(parents=True)
            with patch.object(common, "ROOT", root), patch.object(common, "PUBLIC_OWNER", os.geteuid()):
                self.assertFalse(common.managed_routing_enabled())
                policy.write_text(json.dumps({"version": 1, "enabled": [], "pending_remove": []}))
                policy.chmod(0o600)
                self.assertFalse(common.managed_routing_enabled())
                policy.write_text(json.dumps({"version": 1, "enabled": ["phone-vpn"],
                                              "pending_remove": []}))
                with self.assertRaises(common.UpdateFailure):
                    common.managed_routing_enabled()
                sysctl.write_text("net.ipv4.ip_forward = 1\n")
                unit.write_text("[Unit]\nDescription=Routing\n")
                self.assertTrue(common.managed_routing_enabled())
                policy.write_text(json.dumps({"version": 1, "enabled": [["bad"]],
                                              "pending_remove": []}))
                with self.assertRaises(common.UpdateFailure):
                    common.managed_routing_enabled()


if __name__ == "__main__":
    unittest.main()
