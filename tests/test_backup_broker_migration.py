# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Offline checks for the optional root broker and rollback compatibility."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tests.test_hub_only_update import update as hub_only


ROOT = Path(__file__).resolve().parents[1]
common = hub_only.common


class BackupBrokerMigration(unittest.TestCase):
    def test_full_rollback_preserves_old_layout_and_starts_socket_before_hub(self) -> None:
        for layout, units, has_broker in (
            ("routing_v1", common.ROUTING_ALL_UNITS, False),
            ("hub_backup_broker_v1", common.UNITS, True),
        ):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                transaction = root / "transaction"
                transaction.mkdir()
                calls = []
                removed = []
                def command(args, **_kwargs):
                    calls.append(tuple(args))
                    return 0
                state = {
                    "phase": "running", "snapshot_layout": layout,
                    "old_manifest": "old", "images": {"hub": "image-h", "web": "image-w"},
                    "units": {name: {"active": has_broker and name == common.BACKUP_BROKER_UNITS[0],
                                     "enabled": False} for name in units},
                    "expected_units": [],
                }
                with patch.object(common, "ROOT", root), \
                     patch.object(common, "command", side_effect=command), \
                     patch.object(common, "compose_args", return_value=(["compose"], {})), \
                     patch.object(common, "backup_broker_enabled", return_value=has_broker), \
                     patch.object(common, "backup_broker_socket_ready"), \
                     patch.object(common, "remove_item", side_effect=removed.append), \
                     patch.object(common, "copy_item"), \
                     patch.object(common, "wait_recreated_container_health",
                                  side_effect=lambda _images: calls.append(("wait-health",))), \
                     patch.object(common, "health"), \
                     patch.object(common, "source_manifest", return_value=("old", {})), \
                     patch.object(common, "state_write"), \
                     patch.object(common, "emit"):
                    self.assertTrue(common.restore(transaction, state))
                self.assertEqual(any(str(item).endswith(common.BACKUP_BROKER_MARKER)
                                     for item in removed), has_broker)
                self.assertEqual(any(common.BACKUP_BROKER_UNITS[0] in call
                                     for call in calls), has_broker)
                if has_broker:
                    self.assertLess(calls.index(("systemctl", "start", common.BACKUP_BROKER_UNITS[0])),
                                    calls.index(("compose", "up", "-d", "--no-build", "--force-recreate",
                                                 "hub", "web")))
                self.assertLess(calls.index(("compose", "up", "-d", "--no-build", "--force-recreate",
                                             "hub", "web")), calls.index(("wait-health",)))

    def test_hub_only_rollback_preserves_old_layout_and_starts_socket_before_hub(self) -> None:
        for layout, units, has_broker in (
            ("routing_v1", hub_only.ROUTING_ALL_UNITS, False),
            ("hub_backup_broker_v1", hub_only.LOCAL_WEB_UNITS, True),
            ("local_containers_v1", hub_only.UNITS, True),
        ):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory() as folder:
                transaction = Path(folder) / "transaction"
                transaction.mkdir()
                calls = []
                removed = []
                def command(args, **_kwargs):
                    calls.append(tuple(args))
                    return 0
                state = {
                    "phase": "running", "snapshot_layout": layout,
                    "old_manifest": "old", "baseline_sha256": "baseline",
                    "local_record_sha256": "local", "local_config_sha256": "local",
                    "external_runtime": {name: {"active": True, "enabled": True, "pid": 101}
                                         for name in hub_only.promotion.UNITS},
                    "images": {"hub": "image-h", "web": "image-w"},
                    "units": {name: {"active": has_broker and name == hub_only.BACKUP_BROKER_UNITS[0],
                                     "enabled": False} for name in units},
                }
                with patch.object(hub_only.common, "command", side_effect=command), \
                     patch.object(hub_only.common, "compose_args", return_value=(["compose"], {})), \
                     patch.object(hub_only.common, "backup_broker_enabled", return_value=has_broker), \
                     patch.object(hub_only.common, "backup_broker_socket_ready"), \
                     patch.object(hub_only.common, "remove_item", side_effect=removed.append), \
                     patch.object(hub_only.common, "copy_item"), \
                     patch.object(hub_only.common, "wait_recreated_container_health",
                                  side_effect=lambda _images: calls.append(("wait-health",))), \
                     patch.object(hub_only, "inspect", return_value=("old", {}, {}, "baseline")), \
                     patch.object(hub_only, "_external_runtime",
                                  return_value=state["external_runtime"]), \
                     patch.object(hub_only, "_hash_file", return_value="local"), \
                     patch.object(hub_only, "_unit_state", return_value={"active": False, "enabled": False}), \
                     patch.object(hub_only, "_state"), \
                     patch.object(hub_only, "emit"):
                    self.assertTrue(hub_only._restore(transaction, state))
                self.assertEqual(any(str(item).endswith(common.BACKUP_BROKER_MARKER)
                                     for item in removed), has_broker)
                self.assertEqual(any(hub_only.BACKUP_BROKER_UNITS[0] in call
                                     for call in calls), has_broker)
                if has_broker:
                    self.assertLess(calls.index(("systemctl", "start", hub_only.BACKUP_BROKER_UNITS[0])),
                                    calls.index(("compose", "up", "-d", "--no-build", "--force-recreate",
                                                 "hub", "web")))
                self.assertLess(calls.index(("compose", "up", "-d", "--no-build", "--force-recreate",
                                             "hub", "web")), calls.index(("wait-health",)))

    def test_snapshot_appends_only_root_broker_state(self) -> None:
        for worker in (common, hub_only):
            self.assertEqual(worker.SNAPSHOT[:len(worker.ROUTING_SNAPSHOT)],
                             worker.ROUTING_SNAPSHOT)
            self.assertEqual(worker.UNITS[:len(worker.ROUTING_ALL_UNITS)],
                             worker.ROUTING_ALL_UNITS)
            for path in ("/var/lib/sovagrid/.hub-backup-broker-managed-by-run-sh",
                         "/var/lib/sovagrid/backups/.broker-requests",
                         "/etc/systemd/system/sovagrid-hub-backup-control.socket",
                         "/etc/systemd/system/sovagrid-hub-backup-control.service"):
                self.assertIn(path, worker.SNAPSHOT)
            self.assertNotIn("/var/lib/sovagrid/backups", worker.SNAPSHOT)
            self.assertIn(("sovagrid-hub-backup-control.socket",
                           "sovagrid-hub-backup-control.service"),
                          tuple(worker.UNITS[index:index + 2]
                                for index in range(len(worker.UNITS) - 1)))
        for path in ("/etc/sovagrid/agent.json", "/opt/sovagrid-agent"):
            self.assertNotIn(path, hub_only.SNAPSHOT)

    def test_installer_gates_old_updater_and_starts_socket_before_compose(self) -> None:
        installer = (ROOT / "run.sh").read_text()
        self.assertLess(installer.index("SOVAGRID_HUB_BACKUP_BROKER_SNAPSHOT"),
                        installer.index("apt_refresh()"))
        self.assertIn("backup_broker_deferred=1", installer)
        self.assertIn("$source_root/sovagrid-hub/sovagrid_hub/backup_broker.py", installer)
        self.assertIn("managed Hub backup broker source is missing", installer)
        self.assertLess(installer.index('exec 9>>"$candidate_root/.lock"'),
                        installer.index('exec 8>>"$public_lock"'))
        self.assertLess(installer.index("install_backup_broker\nif (( ! backup_broker_deferred ))"),
                        installer.index('"${compose[@]}" config --quiet'))
        self.assertLess(installer.index('"${compose[@]}" config --quiet'),
                        installer.index('"${compose[@]}" up -d --build --force-recreate'))
        for file in ("remote_update_worker.py", "hub_only_update.py"):
            source = (ROOT / "deploy" / file).read_text()
            self.assertIn('SOVAGRID_HUB_BACKUP_BROKER_SNAPSHOT', source)
            self.assertIn('hub_backup_broker_v1', source)
        subprocess.run(["bash", "-n", str(ROOT / "run.sh")], check=True)

    def test_unit_and_compose_expose_only_unix_socket(self) -> None:
        service = (ROOT / "deploy/sovagrid-hub-backup-control.service").read_text()
        socket = (ROOT / "deploy/sovagrid-hub-backup-control.socket").read_text()
        overlay = (ROOT / "deploy/compose.backup.yaml").read_text()
        self.assertIn("-m sovagrid_hub.backup_broker", service)
        self.assertIn("ReadWritePaths=/var/lib/sovagrid /opt/sovagrid-candidates", service)
        self.assertIn("/etc/sovagrid", service)
        self.assertIn("WorkingDirectory=/opt/sovagrid-src/sovagrid-hub", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK", service)
        for capability in ("CAP_CHOWN", "CAP_FOWNER", "CAP_DAC_OVERRIDE",
                           "CAP_SETUID", "CAP_SETGID", "CAP_SYS_CHROOT"):
            self.assertIn(capability, service)
        self.assertIn("CAP_NET_BIND_SERVICE", service)
        self.assertIn("SocketGroup=sovagrid-hub", socket)
        self.assertIn("SocketMode=0660", socket)
        self.assertIn("source: /run/sovagrid-hub-backup", overlay)
        self.assertIn("read_only: true", overlay)
        self.assertNotIn("/var/lib/sovagrid/backups", overlay)
        self.assertNotIn("docker.sock", overlay)

    def test_partial_state_refused_and_compose_overlay_is_conditional(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source"
            overlay = source / "sovagrid-blueprint/deploy/compose.backup.yaml"
            overlay.parent.mkdir(parents=True)
            marker = root / common.BACKUP_BROKER_MARKER.lstrip("/")
            ledger = root / common.BACKUP_BROKER_LEDGER.lstrip("/")
            units = [root / "etc/systemd/system" / name
                     for name in common.BACKUP_BROKER_UNITS]
            ledger.parent.mkdir(parents=True)
            ledger.parent.chmod(0o700)
            with patch.object(common, "ROOT", root), \
                 patch.object(common, "PUBLIC_OWNER", os.geteuid()), \
                 patch.object(common, "BROKER_OWNER_GID", os.getegid()), \
                 patch.object(common, "public_web_overlay", return_value=None):
                self.assertFalse(common.backup_broker_enabled())
                self.assertNotIn(str(overlay), common.compose_args(source)[0])
                ledger.mkdir(mode=0o700)
                with self.assertRaises(common.UpdateFailure):
                    common.backup_broker_enabled()
                marker.write_text("SOVAGRID_HUB_BACKUP_BROKER_V1\n")
                marker.chmod(0o600)
                with self.assertRaises(common.UpdateFailure):
                    common.backup_broker_enabled()
                for unit in units:
                    unit.parent.mkdir(parents=True, exist_ok=True)
                    unit.write_text("[Unit]\nDescription=Test\n")
                    unit.chmod(0o644)
                self.assertTrue(common.backup_broker_enabled())
                with self.assertRaises(common.UpdateFailure):
                    common.compose_args(source)
                self.assertNotIn(str(overlay), common.compose_args(
                    source, allow_missing_backup_overlay=True)[0])
                overlay.write_text("services: {}\n")
                self.assertIn(str(overlay), common.compose_args(source)[0])
                marker.write_text("INVALID\n")
                with self.assertRaises(common.UpdateFailure):
                    common.backup_broker_enabled()


if __name__ == "__main__":
    unittest.main()
