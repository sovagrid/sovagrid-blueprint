# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Permission boundaries for promoted local operations."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, DEPLOY / file)
    assert spec and spec.loader
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


promotion = module("sovagrid_promotion_local_operations_test", "promote_agent_only.py")
update = module("sovagrid_hub_only_local_operations_test", "hub_only_update.py")
operations = module("sovagrid_local_operations_test", "local_operations.py")


class LocalOperationsTests(unittest.TestCase):
    def test_local_config_uses_only_fixed_socket_and_workspace_after_opt_in(self):
        saved = {"server_id": "00000000-0000-4000-8000-000000000001", "commands": True}
        disabled = json.loads(promotion._config_bytes(saved, operations={
            "protocol": 1, "terminal": False, "files": False}))
        self.assertFalse(disabled["allow_interactive_terminal"])
        self.assertFalse(disabled["allow_file_manager"])
        self.assertNotIn("terminal_socket", disabled)
        self.assertNotIn("file_roots", disabled)
        enabled = json.loads(promotion._config_bytes(saved, operations={
            "protocol": 1, "terminal": True, "files": True}))
        self.assertEqual(enabled["terminal_socket"],
                         "/run/sovagrid-terminal-local/control.sock")
        self.assertEqual(enabled["file_roots"],
                         {"workspace": "/var/lib/sovagrid-agent-local/files"})
        self.assertEqual(enabled["token_file"], "/etc/sovagrid-local/agent.token")
        self.assertEqual(enabled["allow_remote_commands"], disabled["allow_remote_commands"])
        service = json.loads(promotion._config_bytes(saved, operations={
            "protocol": 1, "terminal": False, "files": False}, service_socket=True))
        self.assertEqual(service["service_socket"],
                         "/run/sovagrid-service-local/control.sock")

    def test_file_operation_preserves_exact_local_service_socket(self):
        saved = {"server_id": "00000000-0000-4000-8000-000000000001", "commands": True}
        before = {"protocol": 1, "terminal": False, "files": False}
        after = {**before, "files": True}
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "agent.json"
            config.write_bytes(promotion._config_bytes(saved, operations=before,
                                                       service_socket=True))
            with mock.patch.object(operations.promotion, "LOCAL_CONFIG", config), \
                 mock.patch.object(operations.promotion, "_read_regular",
                                   side_effect=lambda path, *args: path.read_bytes()), \
                 mock.patch.object(operations.promotion, "_replace_group_file",
                                   side_effect=lambda path, old, new, gid: path.write_bytes(new)), \
                 mock.patch.object(operations.grp, "getgrnam", return_value=type("G", (), {"gr_gid": 42})()), \
                 mock.patch.object(operations, "_ensure_workspace"), \
                 mock.patch.object(operations, "_cmd"), \
                 mock.patch.object(operations.promotion, "_wait_local_metric"), \
                 mock.patch.object(operations.promotion, "_unit_active", return_value=False), \
                 mock.patch.object(operations.promotion, "_unit_enabled", return_value=False):
                operations._apply_target(saved, before, after)
            self.assertEqual(config.read_bytes(), promotion._config_bytes(
                saved, operations=after, service_socket=True))

    def test_pending_journal_blocks_normal_promotion_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            pending = Path(directory) / "pending.json"
            pending.write_text("fixture")
            with mock.patch.object(promotion, "LOCAL_OPERATIONS_PENDING", pending):
                with self.assertRaisesRegex(promotion.PromotionError, "needs recovery"):
                    promotion._operations_record()

    def test_hub_only_snapshot_includes_broker_and_workspace_but_no_external_agent(self):
        for item in ("/var/lib/sovagrid-promotion/local-operations.json",
                     "/var/lib/sovagrid-promotion/local-operations-pending.json",
                     "/var/lib/sovagrid-local-shell",
                     "/etc/systemd/system/sovagrid-terminal-local-control.socket",
                     "/etc/systemd/system/sovagrid-terminal-local-control.service"):
            self.assertIn(item, update.SNAPSHOT)
        self.assertIn("sovagrid-terminal-local-control.socket", update.UNITS)
        self.assertIn("sovagrid-terminal-local-control.service", update.UNITS)
        for item in ("/var/lib/sovagrid-agent", "/etc/sovagrid/agent.token",
                     "/etc/systemd/system/sovagrid-agent-tunnel.service"):
            self.assertNotIn(item, update.SNAPSHOT)

    def test_operation_schema(self):
        valid = {"protocol": 1, "terminal": True, "files": False}
        self.assertEqual(operations._operation(valid), valid)
        for invalid in ({**valid, "terminal": 1}, {**valid, "extra": True},
                        {**valid, "protocol": 2}):
            with self.assertRaises(operations.Refused):
                operations._operation(invalid)

    def test_state_revision_binds_local_server_source_and_flags(self):
        off = {"protocol": 1, "terminal": False, "files": False}
        files = {**off, "files": True}
        with mock.patch.object(operations.promotion, "_source_manifest_sha256", return_value="a" * 64):
            first = operations._revision({"server_id": "server-one"}, off)
            self.assertEqual(len(first), 64)
            self.assertEqual(first, operations._revision({"server_id": "server-one"}, off))
            self.assertNotEqual(first, operations._revision({"server_id": "server-one"}, files))
            self.assertNotEqual(first, operations._revision({"server_id": "server-two"}, off))
        with mock.patch.object(operations.promotion, "_source_manifest_sha256", return_value="b" * 64):
            self.assertNotEqual(first, operations._revision({"server_id": "server-one"}, off))

    def test_expected_state_rechecked_inside_mutation_lock(self):
        off = {"protocol": 1, "terminal": False, "files": False}
        with tempfile.TemporaryFile() as temporary:
            descriptor = os.dup(temporary.fileno())
            service_descriptor = os.dup(temporary.fileno())
            with mock.patch.object(operations, "_lock", return_value=descriptor), \
                 mock.patch.object(operations.promotion, "_service_setup_lock",
                                   return_value=service_descriptor), \
                 mock.patch.object(operations, "_pending", return_value=None), \
                 mock.patch.object(operations, "_preflight", return_value=({"server_id": "server"}, {})), \
                 mock.patch.object(operations, "_ready", return_value=off), \
                 mock.patch.object(operations, "_revision", return_value="a" * 64), \
                 mock.patch.object(operations, "_complete") as complete, \
                 mock.patch.object(operations, "_recover") as recover:
                with self.assertRaisesRegex(operations.Refused, "STATE_CHANGED"):
                    operations.change("files", True, expected_state="b" * 64)
                complete.assert_not_called()
                recover.assert_not_called()

    def test_expected_state_refuses_pending_recovery(self):
        with tempfile.TemporaryFile() as temporary:
            descriptor = os.dup(temporary.fileno())
            service_descriptor = os.dup(temporary.fileno())
            with mock.patch.object(operations, "_lock", return_value=descriptor), \
                 mock.patch.object(operations.promotion, "_service_setup_lock",
                                   return_value=service_descriptor), \
                 mock.patch.object(operations, "_pending", return_value={"protocol": 1}), \
                 mock.patch.object(operations, "_preflight") as preflight:
                with self.assertRaisesRegex(operations.Refused, "STATE_CHANGED"):
                    operations.change("terminal", True, expected_state="a" * 64)
                preflight.assert_not_called()

    def test_matching_state_noop_returns_same_revision(self):
        off = {"protocol": 1, "terminal": False, "files": False}
        with tempfile.TemporaryFile() as temporary:
            descriptor = os.dup(temporary.fileno())
            service_descriptor = os.dup(temporary.fileno())
            with mock.patch.object(operations, "_lock", return_value=descriptor), \
                 mock.patch.object(operations.promotion, "_service_setup_lock",
                                   return_value=service_descriptor), \
                 mock.patch.object(operations, "_pending", return_value=None), \
                 mock.patch.object(operations, "_preflight", return_value=({"server_id": "server"}, {})), \
                 mock.patch.object(operations, "_ready", return_value=off), \
                 mock.patch.object(operations, "_revision", return_value="a" * 64), \
                 mock.patch.object(operations, "_complete") as complete:
                result = operations.change("files", False, expected_state="a" * 64)
                self.assertEqual(result["state_revision"], "a" * 64)
                self.assertEqual(result["current"], off)
                complete.assert_not_called()

    def test_invalid_expected_state_refuses_before_lock(self):
        with mock.patch.object(operations, "_lock") as lock:
            with self.assertRaisesRegex(operations.Refused, "EXPECTED_STATE"):
                operations.change("files", True, expected_state="invalid")
            lock.assert_not_called()

    def test_fixed_unit_source_when_agent_checkout_is_present(self):
        agent = DEPLOY.parent.parent / "sovagrid-agent"
        if not agent.is_dir():
            self.skipTest("Agent checkout is tested in its own repository and combined VM")
        for name in promotion.LOCAL_TERMINAL_UNITS:
            source = agent / "deploy" / name
            self.assertTrue(source.is_file())
            self.assertIn("sovagrid-local", source.read_text())


if __name__ == "__main__":
    unittest.main()
