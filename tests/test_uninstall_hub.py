# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Uninstall preserves the local Hub until its complete Agent roster is reviewed."""

from contextlib import ExitStack, closing, redirect_stdout
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

from deploy import uninstall_hub as hub


ENROLLMENT_A = "10000000-0000-4000-8000-000000000001"
ENROLLMENT_B = "10000000-0000-4000-8000-000000000002"
SERVER_A = "20000000-0000-4000-8000-000000000001"
SERVER_B = "20000000-0000-4000-8000-000000000002"
LOCAL_SERVER = "20000000-0000-4000-8000-000000000003"
FOREIGN_SERVER = "20000000-0000-4000-8000-000000000004"
KEY = "SHA256:" + "h" * 43
REVISION = "a" * 64


class HubUninstallTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "sovagrid-bundle.json").write_text("{}")
        self.data = self.root / "data"
        self.data.mkdir()
        self.database = self.data / "hub.sqlite"
        with closing(sqlite3.connect(self.database)) as database:
            database.executescript("""
                CREATE TABLE servers(id TEXT PRIMARY KEY, last_seen INTEGER);
                CREATE TABLE agent_enrollments(id TEXT PRIMARY KEY, server_id TEXT,
                                               name TEXT, cancelled_at INTEGER);
            """)
            database.executemany("INSERT INTO servers VALUES (?,?)",
                                 [(SERVER_A, 100), (SERVER_B, 200), (LOCAL_SERVER, 300)])
            database.executemany("INSERT INTO agent_enrollments VALUES (?,?,?,NULL)",
                                 [(ENROLLMENT_A, SERVER_A, "First"), (ENROLLMENT_B, SERVER_B, "Second")])
            database.commit()
        self.entries = {
            ENROLLMENT_A: {"server_id": SERVER_A, "revoked": False, "ssh_key_fingerprint": KEY},
            ENROLLMENT_B: {"server_id": SERVER_B, "revoked": False, "ssh_key_fingerprint": KEY},
        }
        self.ledger = Mock()
        self.ledger.hub_state.return_value = {"enrollments": self.entries}
        self.routes = {SERVER_A: "first-profile", SERVER_B: "second-profile"}

    def inventory(self):
        with closing(sqlite3.connect(self.database)) as database:
            return hub.installed_agents(database, self.ledger, local_id=LOCAL_SERVER)

    def run_uninstall(self, *, events, fail=False, routes=None):
        terminal = MagicMock()
        terminal.__enter__.return_value = terminal
        terminal.readline.return_value = "REMOVE SOVAGRID\n"
        server_config = json.dumps({"server_id": LOCAL_SERVER}).encode()

        def rpc(agent, route, action, revision=None):
            self.assertEqual(route, self.routes[agent.server_id])
            events.append((action, agent.server_id))
            if action == "apply":
                self.assertEqual(revision, REVISION)
                with closing(sqlite3.connect(self.database, timeout=0)) as other:
                    with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                        other.execute("BEGIN IMMEDIATE")
                if fail and agent.server_id == SERVER_B:
                    raise hub.UninstallError("fixture target failure")
            return {"state": "ready" if action == "preview" else "removed",
                    "revision": REVISION, "server_id": agent.server_id, "enrollment_id": agent.enrollment_id}

        with ExitStack() as stack:
            for name, value in {"SOURCE": self.source, "DATA": self.data, "DB": self.database,
                                "WEB_JOBS": self.root / "jobs", "BACKUPS": self.data / "backups"}.items():
                stack.enter_context(patch.object(hub, name, value))
            stack.enter_context(redirect_stdout(io.StringIO()))
            stack.enter_context(patch.object(hub, "open", return_value=terminal, create=True))
            stack.enter_context(patch.object(hub.enrollment, "Enrollment", return_value=self.ledger))
            stack.enter_context(patch.object(hub, "runtime_roots", return_value=[self.data]))
            stack.enter_context(patch.object(hub, "reviewed_units", return_value=[]))
            stack.enter_context(patch.object(hub, "reviewed_containers", return_value=[]))
            stack.enter_context(patch.object(hub, "reviewed_network", return_value=None))
            stack.enter_context(patch.object(hub.installed, "public_path", return_value=server_config))
            stack.enter_context(patch.object(hub, "agent_rpc", side_effect=rpc))
            stack.enter_context(patch.object(hub, "stop_local", side_effect=lambda *_: events.append(("stop", "Hub"))))
            stack.enter_context(patch.object(hub, "remove_local", side_effect=lambda *_: events.append(("remove", "Hub"))))
            return hub.uninstall(False, self.routes if routes is None else routes)

    def test_roster_requires_matching_registration_and_tunnel_identity(self):
        self.assertEqual([agent.server_id for agent in self.inventory()], [SERVER_A, SERVER_B])
        self.entries[ENROLLMENT_B]["server_id"] = FOREIGN_SERVER
        with self.assertRaises(hub.UninstallError):
            self.inventory()
        self.entries.pop(ENROLLMENT_B)
        with self.assertRaises(hub.UninstallError):
            self.inventory()

    def test_roster_rejects_unclaimed_tunnel_and_unmanaged_telemetry_sender(self):
        self.entries[LOCAL_SERVER] = {"server_id": FOREIGN_SERVER, "revoked": False, "ssh_key_fingerprint": KEY}
        with self.assertRaises(hub.UninstallError):
            self.inventory()
        self.entries[LOCAL_SERVER]["revoked"] = True
        self.assertEqual(len(self.inventory()), 2)
        with closing(sqlite3.connect(self.database)) as database:
            database.execute("INSERT INTO servers VALUES (?,?)", (FOREIGN_SERVER, 500))
            database.commit()
        with self.assertRaises(hub.UninstallError):
            self.inventory()

    def test_every_agent_is_reviewed_and_removed_before_the_hub_is_stopped(self):
        events = []
        self.assertEqual(self.run_uninstall(events=events), 0)
        self.assertEqual(events, [("preview", SERVER_A), ("preview", SERVER_B),
                                  ("apply", SERVER_A), ("apply", SERVER_B),
                                  ("stop", "Hub"), ("remove", "Hub")])

    def test_failed_agent_apply_preserves_local_hub(self):
        events = []
        with self.assertRaisesRegex(hub.UninstallError, "fixture target failure"):
            self.run_uninstall(events=events, fail=True)
        self.assertEqual(events, [("preview", SERVER_A), ("preview", SERVER_B),
                                  ("apply", SERVER_A), ("apply", SERVER_B)])
        self.assertTrue((self.source / "sovagrid-bundle.json").is_file())
        self.assertTrue(self.database.is_file())
        self.assertEqual(len(self.inventory()), 2)

    def test_foreign_ssh_route_is_rejected_before_any_remote_work(self):
        events = []
        with self.assertRaises(hub.UninstallError):
            self.run_uninstall(events=events, routes={**self.routes, FOREIGN_SERVER: "foreign-profile"})
        self.assertEqual(events, [])

    def test_delete_preserves_backups_and_unrelated_directory(self):
        backup_folder = self.data / "backups"
        backup_folder.mkdir()
        archive = backup_folder / "backup.tar.gz"
        archive.write_bytes(b"existing backup")
        (backup_folder / ".broker-requests").mkdir()
        unrelated = self.root / "other-service.txt"
        unrelated.write_text("independent")
        service = self.root / "sovagrid-agent.service"
        service.write_text("own unit file")
        with patch.object(hub, "DATA", self.data), patch.object(hub, "BACKUPS", backup_folder), \
             patch.object(hub, "execute") as execute:
            hub.remove_local([service], [self.data, self.source])
        self.assertFalse(self.data.exists())
        retained, = self.root.glob("sovagrid-backups-retained-*")
        self.assertEqual((retained / "backups" / archive.name).read_bytes(), b"existing backup")
        self.assertTrue((retained / "backups/.broker-requests").is_dir())
        self.assertEqual(unrelated.read_text(), "independent")
        self.assertFalse(service.exists())
        self.assertFalse(self.source.exists())
        execute.assert_called_once_with("systemctl", "daemon-reload")

    def test_apply_only_trusts_the_confirmed_agent_id_and_revision(self):
        agent = hub.Agent(ENROLLMENT_A, SERVER_A, KEY, "First")
        valid = {"enrollment_id": ENROLLMENT_A, "server_id": SERVER_A, "state": "removed", "revision": REVISION}
        with patch.object(hub, "ssh_user", return_value={}), patch.object(hub.subprocess, "run") as run:
            for changed in ({"server_id": FOREIGN_SERVER}, {"state": "ready"}, {"revision": "b" * 64}):
                with self.subTest(changed=changed):
                    run.return_value = subprocess.CompletedProcess([], 0, json.dumps({**valid, **changed}).encode())
                    with self.assertRaises(hub.UninstallError):
                        hub.agent_rpc(agent, "first-profile", "apply", REVISION)
            run.return_value = subprocess.CompletedProcess([], 0, json.dumps(valid).encode())
            self.assertEqual(hub.agent_rpc(agent, "first-profile", "apply", REVISION), valid)
            self.assertIn("StrictHostKeyChecking=yes", run.call_args.args[0])
            self.assertEqual(run.call_args.kwargs["input"], Path(hub.__file__).with_name("uninstall_agent.py").read_bytes())


if __name__ == "__main__":
    unittest.main()
