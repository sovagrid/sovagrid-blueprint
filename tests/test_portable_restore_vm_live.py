# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Restored Hub verification includes all three rich enrollment records."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vm = load("portable_restore_vm_live_fixture", "portable_restore_apply_vm.py")
legacy = load("portable_restore_vm_live_legacy", "integrated_install_vm.py")


class Reply(io.BytesIO):
    status = 200

    def __init__(self, raw, reads):
        super().__init__(raw)
        self.reads = reads

    def read(self, size=-1):
        self.reads.append(size)
        return super().read(size)


class RestoredLiveHubTest(unittest.TestCase):
    def setUp(self):
        self.host = "11111111-1111-4111-8111-111111111111"
        self.rows = [{"id": identity, "online": True, "last_seen": 200,
            "remote_commands_enabled": False,
            "capabilities": {"metric_" + str(number): "bounded monitored capability " * 12
                             for number in range(12)}}
            for identity in (self.host, "22222222-2222-4222-8222-222222222222",
                             "33333333-3333-4333-8333-333333333333")]
        self.server_bytes = json.dumps({"servers": self.rows}).encode()
        self.assertGreater(len(self.server_bytes), 8192)
        self.assertLess(len(self.server_bytes), 65536)
        self.calls, self.reads = [], {}

    def open(self, request, timeout):
        method, path = request.method, request.full_url.removeprefix("http://127.0.0.1:8766")
        self.calls.append((method, path))
        raw = {
            ("POST", "/api/v1/session"): b'{"token":"fixture-session"}',
            ("GET", "/api/v1/servers"): self.server_bytes,
            ("GET", "/api/v1/servers/" + self.host + "/metrics?limit=1"): b'{"metrics":[{"timestamp":200}]}',
            ("DELETE", "/api/v1/session"): b'{}',
        }[(method, path)]
        if method != "POST":
            self.assertEqual(request.headers["Authorization"], "Bearer fixture-session")
        self.assertIn(timeout, (10, 20))
        reads = self.reads.setdefault((method, path), [])
        return Reply(raw, reads)

    @contextlib.contextmanager
    def live(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {"server_id": self.host, "allow_interactive_terminal": True, "allow_file_manager": True}
            root = Path(directory)
            (root / "agent.json").write_text(json.dumps(config))
            (root / "admin-password").write_text("fixture-password")
            mappings = {"/etc/sovagrid/agent.json": root / "agent.json",
                        "/etc/sovagrid/admin-password": root / "admin-password",
                        "/var/lib/sovagrid-agent/files": SimpleNamespace(stat=lambda: SimpleNamespace(st_uid=12345)),
                        "/var/lib/sovagrid-shell": SimpleNamespace(stat=lambda: SimpleNamespace(st_uid=10003))}
            def mapped(path):
                return mappings.get(str(path), Path(path))
            spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
            with (patch.object(vm.importlib.util, "spec_from_file_location", return_value=spec),
                  patch.object(vm.importlib.util, "module_from_spec", return_value=legacy),
                  patch.object(vm, "Path", side_effect=mapped),
                  patch.object(vm.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=12345)),
                  patch.object(legacy, "verify_agent_quiescence") as quiescence,
                  patch.object(legacy, "request", wraps=legacy.request) as request,
                  patch.object(vm, "verify_command_files_terminal") as terminal,
                  patch.object(vm.urllib.request, "build_opener", return_value=SimpleNamespace(open=self.open)),
                  contextlib.redirect_stdout(io.StringIO())):
                yield config, quiescence, request, terminal

    def test_restored_three_server_inventory_uses_bounded64k_request_and_continues_live_checks(self):
        with self.live() as (config, quiescence, request, terminal):
            vm.verify_live(Path("/verified/bundle"), 199)
            quiescence.assert_called_once_with()
            terminal.assert_called_once_with(config, self.rows[0], "fixture-session")
            self.assertEqual([(call.args[0], call.args[1]) for call in request.call_args_list],
                             [("POST", "/api/v1/session"), ("DELETE", "/api/v1/session")])
        self.assertEqual(self.reads[("GET", "/api/v1/servers")], [65537])
        self.assertEqual(self.calls[-1], ("DELETE", "/api/v1/session"))

    def test_legacy_install_helper_keeps_its8k_bound_for_other_callers(self):
        with patch.object(legacy.urllib.request, "build_opener", return_value=SimpleNamespace(open=self.open)):
            with self.assertRaisesRegex(RuntimeError, "Hub reply is unexpectedly large"):
                legacy.request("GET", "/api/v1/servers", token="fixture-session")
        self.assertEqual(self.reads[("GET", "/api/v1/servers")], [8193])

    def test_restore_inventory_over64k_still_refuses_and_logs_out_before_runtime_checks(self):
        self.server_bytes = json.dumps({"servers": self.rows, "oversized": "x" * 65536}).encode()
        with self.live() as (_config, quiescence, _request, terminal):
            with self.assertRaisesRegex(RuntimeError, "oversized Hub operation result"):
                vm.verify_live(Path("/verified/bundle"), 199)
            quiescence.assert_called_once_with()
            terminal.assert_not_called()
        self.assertEqual(self.reads[("GET", "/api/v1/servers")], [65537])
        self.assertEqual(self.calls[-1], ("DELETE", "/api/v1/session"))


if __name__ == "__main__":
    unittest.main()
