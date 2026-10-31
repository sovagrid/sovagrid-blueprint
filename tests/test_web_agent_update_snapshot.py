#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""The two update engines preserve Web Agent journal and Compose wiring."""

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests.test_hub_only_update import update as hub_only


worker = hub_only.common


class WebAgentUpdateSnapshotTest(unittest.TestCase):
    def test_new_layout_extends_both_prior_snapshots(self):
        expected = (
            "/var/lib/sovagrid/.web-agent-installer-managed-by-run-sh",
            "/var/lib/sovagrid/web-agent",
            "/etc/systemd/system/sovagrid-web-agent-control.socket",
            "/etc/systemd/system/sovagrid-web-agent-control.service",
        )
        self.assertEqual(worker.SNAPSHOT, worker.SSH_GATEWAY_SNAPSHOT + expected)
        self.assertEqual(hub_only.SNAPSHOT, hub_only.LOCAL_CONTAINERS_SNAPSHOT + expected + (
            "/etc/sovagrid/.external-agent-recovery-managed-by-run-sh",
            "/etc/systemd/system/sovagrid-external-agent-recovery.service",
        ))
        self.assertEqual(worker.UNITS, worker.SSH_GATEWAY_UNITS + worker.WEB_AGENT_UNITS)
        self.assertEqual(hub_only.UNITS,
                         hub_only.LOCAL_CONTAINERS_ALL_UNITS + hub_only.WEB_AGENT_UNITS)

    def test_compose_includes_installed_web_agent_overlay(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            overlay = source / "sovagrid-blueprint/deploy/compose.web-agent.yaml"
            overlay.parent.mkdir(parents=True)
            overlay.write_text("services: {}\n")
            with mock.patch.object(worker, "ROOT", source), \
                 mock.patch.object(worker, "web_agent_managed", return_value=True), \
                 mock.patch.object(worker, "backup_broker_enabled", return_value=False), \
                 mock.patch.object(worker, "public_web_overlay", return_value=None), \
                 mock.patch.object(worker, "local_web_overlay", return_value=None):
                args, _env = worker.compose_args(source)
                self.assertEqual(args[-2:], ["-f", str(overlay)])
                overlay.unlink()
                with self.assertRaises(worker.UpdateFailure):
                    worker.compose_args(source)

    def test_existing_installer_rejects_candidate_without_its_files(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            script = source / "sovagrid-blueprint/run.sh"
            script.parent.mkdir(parents=True)
            script.write_bytes(b"# SOVAGRID_WEB_AGENT_INSTALL_V1\n")
            required = ("compose.web-agent.yaml", "web_agent_bundle.py",
                        "web_agent_jobs.py", "web_agent_service.py",
                        "web_wireguard_control.py", "web_amnezia_provision.py",
                        *worker.WEB_AGENT_UNITS)
            for name in required:
                path = source / "sovagrid-blueprint/deploy" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n")
            for name in ("deploy/sovagrid-amnezia-provision",
                         "sovagrid_vpn/amnezia_provision.py"):
                path = source / "sovagrid-vpn" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n")
            with mock.patch.object(worker, "ROOT", source), \
                 mock.patch.object(worker, "web_agent_managed", return_value=True), \
                 mock.patch.object(worker, "backup_broker_enabled", return_value=False), \
                 mock.patch.object(worker, "ssh_gateway_managed", return_value=False), \
                 mock.patch.object(worker, "managed_routing_enabled", return_value=False):
                worker.candidate_features_compatible(source, [])
                (source / "sovagrid-blueprint/deploy/web_wireguard_control.py").unlink()
                with self.assertRaises(worker.UpdateFailure):
                    worker.candidate_features_compatible(source, [])

    def test_full_rollback_restores_journal_and_starts_socket_before_compose(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "transaction"
            saved = folder / "snapshot" / str(worker.SNAPSHOT.index(worker.WEB_AGENT_DIR))
            saved.mkdir(parents=True)
            (saved / "pending-job.json").write_text("fixture\n")
            state = {
                "phase": "running", "snapshot_layout": "web_agent_v1",
                "old_manifest": "a" * 64, "images": {}, "gateway_before": {"container_ids": [], "image": None},
                "units": {unit: {"active": unit in worker.WEB_AGENT_UNITS,
                                 "enabled": unit in worker.WEB_AGENT_UNITS}
                          for unit in worker.UNITS},
                "expected_units": [],
            }
            with mock.patch.object(worker, "ROOT", root), \
                 mock.patch.object(worker, "command", return_value=0) as command, \
                 mock.patch.object(worker, "remove_item"), \
                 mock.patch.object(worker, "copy_item") as copy_item, \
                 mock.patch.object(worker, "rollback_stop_compose_args",
                                   return_value=(["docker", "compose"], {})), \
                 mock.patch.object(worker, "compose_args",
                                   return_value=(["docker", "compose"], {})), \
                 mock.patch.object(worker, "backup_broker_enabled", return_value=False), \
                 mock.patch.object(worker, "web_agent_managed", return_value=True), \
                 mock.patch.object(worker, "web_agent_socket_ready"), \
                 mock.patch.object(worker, "remove_new_gateway_on_rollback"), \
                 mock.patch.object(worker, "wait_recreated_container_health"), \
                 mock.patch.object(worker, "health"), \
                 mock.patch.object(worker, "source_manifest", return_value=("a" * 64, {})), \
                 mock.patch.object(worker, "state_write"):
                self.assertTrue(worker.restore(folder, state))
            copy_item.assert_any_call(saved, root / worker.WEB_AGENT_DIR.lstrip("/"))
            calls = [call.args[0] for call in command.call_args_list]
            start_socket = calls.index(["systemctl", "start", worker.WEB_AGENT_UNITS[0]])
            compose_up = next(index for index, args in enumerate(calls)
                              if args[:2] == ["docker", "compose"] and "up" in args)
            restart_service = calls.index(["systemctl", "restart", worker.WEB_AGENT_UNITS[1]])
            self.assertLess(start_socket, compose_up)
            self.assertLess(compose_up, restart_service)

    def test_promoted_hub_rollback_restores_local_web_agent_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            saved = folder / "snapshot" / str(hub_only.SNAPSHOT.index(hub_only.WEB_AGENT_DIR))
            saved.mkdir(parents=True)
            (saved / "pending-job.json").write_text("fixture\n")
            digest = "b" * 64
            state = {
                "phase": "running", "snapshot_layout": "web_agent_v1",
                "old_manifest": digest, "baseline_sha256": digest,
                "local_record_sha256": digest, "local_config_sha256": digest,
                "external_runtime": {}, "images": {},
                "gateway_before": {"container_ids": [], "image": None},
                "units": {unit: {"active": unit in hub_only.WEB_AGENT_UNITS,
                                 "enabled": unit in hub_only.WEB_AGENT_UNITS}
                          for unit in hub_only.UNITS},
            }
            with mock.patch.object(worker, "command", return_value=0) as command, \
                 mock.patch.object(worker, "remove_item"), \
                 mock.patch.object(worker, "copy_item") as copy_item, \
                 mock.patch.object(worker, "rollback_stop_compose_args",
                                   return_value=(["docker", "compose"], {})), \
                 mock.patch.object(worker, "compose_args",
                                   return_value=(["docker", "compose"], {})), \
                 mock.patch.object(worker, "backup_broker_enabled", return_value=False), \
                 mock.patch.object(worker, "web_agent_managed", return_value=True), \
                 mock.patch.object(worker, "web_agent_socket_ready"), \
                 mock.patch.object(worker, "remove_new_gateway_on_rollback"), \
                 mock.patch.object(worker, "wait_recreated_container_health"), \
                 mock.patch.object(hub_only, "inspect", return_value=(digest, {}, {}, digest)), \
                 mock.patch.object(hub_only, "_check_external_runtime"), \
                 mock.patch.object(hub_only, "_hash_file", return_value=digest), \
                 mock.patch.object(hub_only, "_state"):
                self.assertTrue(hub_only._restore(folder, state))
            copy_item.assert_any_call(saved, Path(hub_only.WEB_AGENT_DIR))
            calls = [call.args[0] for call in command.call_args_list]
            start_socket = calls.index(["systemctl", "start", hub_only.WEB_AGENT_UNITS[0]])
            compose_up = next(index for index, args in enumerate(calls)
                              if args[:2] == ["docker", "compose"] and "up" in args)
            restart_service = calls.index(["systemctl", "restart", hub_only.WEB_AGENT_UNITS[1]])
            self.assertLess(start_socket, compose_up)
            self.assertLess(compose_up, restart_service)


if __name__ == "__main__":
    unittest.main()
