# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Uninstall preserves the local Hub until its complete Agent roster is reviewed."""

from contextlib import ExitStack, closing, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
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
        mountinfo = self.root / "mountinfo"
        mountinfo.write_text("")
        mount_patch = patch.object(hub.recovery, "MOUNTINFO", mountinfo)
        mount_patch.start()
        self.addCleanup(mount_patch.stop)
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

    def run_uninstall(self, *, events, fail=False, routes=None, shared=False, vpn_programs=()):
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
            runtime_roots = stack.enter_context(patch.object(hub, "runtime_roots", return_value=[self.data]))
            if vpn_programs:
                stack.enter_context(patch.object(hub, "VPN_CONTROL_MARKER", str(self.database)))
                stack.enter_context(patch.object(hub, "reviewed_vpn_programs", return_value=vpn_programs))
            stack.enter_context(patch.object(hub, "reviewed_units", return_value=[]))
            stack.enter_context(patch.object(hub, "reviewed_containers", return_value=[]))
            stack.enter_context(patch.object(hub, "reviewed_network", return_value=None))
            stack.enter_context(patch.object(hub.installed, "public_path", return_value=server_config))
            stack.enter_context(patch.object(hub, "agent_rpc", side_effect=rpc))
            stack.enter_context(patch.object(hub, "stop_local", side_effect=lambda *_: events.append(("stop", "Hub"))))
            stack.enter_context(patch.object(hub, "remove_local", side_effect=lambda *_, **__: events.append(("remove", "Hub"))))
            layout = None
            if shared:
                layout = Mock(local_id=LOCAL_SERVER, retained_paths=())
                layout.recheck_external.side_effect = lambda: events.append(("external", "Agent"))
                stack.enter_context(patch.object(hub.hub_only, "inspect", return_value=layout))
            status = hub.uninstall(False, self.routes if routes is None else routes,
                                   manifest_digest="a" * 64 if shared else None)
            self.assertTrue(all(call.kwargs["vpn_programs"] == vpn_programs for call in runtime_roots.call_args_list))
            return status

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

    def test_full_hub_includes_verified_vpn_programs_in_cleanup_plan(self):
        program = self.root / 'sovagrid-vpn-ctl'
        program.write_text('verified tool')
        events = []
        self.assertEqual(self.run_uninstall(events=events, vpn_programs=(program,)), 0)
        self.assertEqual(events[-2:], [("stop", "Hub"), ("remove", "Hub")])

    def test_vpn_program_must_match_the_manifest_hash(self):
        program = self.root / 'sovagrid-vpn-ctl'
        program.write_bytes(b'verified tool')
        manifest = {'sha256': {'sovagrid-vpn/deploy/sovagrid-vpn-ctl':
                              hashlib.sha256(b'verified tool').hexdigest()}}
        with (patch.object(hub.hub_only, 'VPN_PROGRAMS', (program,)),
              patch.object(hub.installed, 'public_path', side_effect=lambda name, **_: Path(name).read_bytes())):
            self.assertEqual(hub.reviewed_vpn_programs(manifest), (program,))
            program.write_bytes(b'operator modified')
            with self.assertRaisesRegex(hub.UninstallError, 'отличается'):
                hub.reviewed_vpn_programs(manifest)

    def test_hub_only_rechecks_external_agent_without_using_its_local_config(self):
        events = []
        self.assertEqual(self.run_uninstall(events=events, shared=True), 0)
        self.assertEqual(events, [("preview", SERVER_A), ("preview", SERVER_B),
                                  ("apply", SERVER_A), ("apply", SERVER_B),
                                  ("stop", "Hub"), ("external", "Agent"),
                                  ("remove", "Hub"), ("external", "Agent")])

    def test_hub_only_skips_external_units_and_matches_generated_local_agent(self):
        own = self.root / hub.hub_only.promotion.LOCAL_UNIT.name
        own.write_text(hub.hub_only.promotion.UNIT_TEXT)
        external_names = ("sovagrid-agent.service", "sovagrid-agent-tunnel.service",
                          "sovagrid-terminal-control.socket")
        hashes = {}
        for name in external_names:
            (self.root / name).write_text(name)
            hashes["sovagrid-agent/deploy/" + name] = hashlib.sha256(name.encode()).hexdigest()
        actual_lstat = Path.lstat

        def lstat(path):
            self.assertEqual(path, own)
            return SimpleNamespace(st_mode=actual_lstat(path).st_mode, st_uid=0, st_nlink=1)

        layout = Mock(local_id=LOCAL_SERVER, allowed_units={own.name})
        with patch.object(hub, "UNITS", self.root), patch.object(Path, "lstat", lstat), \
             patch.object(hub, "execute", return_value=f"FragmentPath={own}\nDropInPaths=\n".encode()):
            self.assertEqual(hub.reviewed_units({"sha256": hashes}, layout), [own])

    def test_hub_only_selects_shared_hub_configuration_without_external_artifacts(self):
        policy = hub.hub_only
        standalone = self.root / "no-promotion-journal"
        with patch.object(policy.promotion, "STATE_DIR", standalone), \
             patch.object(policy.promotion, "_local_artifacts", return_value=False), \
             patch.object(policy.os.path, "lexists", return_value=False), \
             patch.object(policy, "_check_hub_only_units") as check_units, \
             patch.object(policy, "_shared_configuration", return_value=[Path("/etc/sovagrid/deploy.env")]), \
             patch.object(policy.updates, "_external_apply_idle"), \
             patch.object(policy.installed, "public_path"):
            layout = policy.inspect({"sha256": {}}, "a" * 64)
            check_units.assert_called_once()
        self.assertIsNone(layout.local_id)
        self.assertIn(Path("/etc/sovagrid/deploy.env"), layout.extra_paths)
        self.assertNotIn(Path("/etc/sovagrid"), layout.extra_paths)
        self.assertNotIn(Path("/etc/sovagrid/agent.json"), layout.extra_paths)
        self.assertNotIn(Path("/etc/sovagrid/agent.token"), layout.extra_paths)
        self.assertNotIn(Path("/etc/sovagrid/hub-ca.pem"), layout.extra_paths)
        self.assertNotIn("sovagrid-agent.service", layout.allowed_units)
        self.assertNotIn("sovagrid-agent-tunnel.service", layout.allowed_units)
        self.assertNotIn("sovagrid-terminal-control.service", layout.allowed_units)

    def test_hub_only_refuses_foreign_local_web_directory(self):
        policy = hub.hub_only
        foreign = self.root / "etc/sovagrid/local-web"
        foreign.mkdir(parents=True, mode=0o700)
        (foreign / "admin-file").write_text("keep")
        with patch.object(hub.installed, "ROOT", self.root), \
             patch.object(hub.installed, "PUBLIC_OWNER", foreign.stat().st_uid):
            with self.assertRaises(hub.installed.UpdateFailure):
                policy._web_directory(foreign, hub.installed.local_web_overlay)
        self.assertEqual((foreign / "admin-file").read_text(), "keep")

    def test_hub_routing_review_validates_generated_configuration_and_dependencies(self):
        unit = b"managed unit"
        sysctl = b"managed forwarding"
        code = {
            "routing.py": f"UNIT_CONTENT = {unit!r}\nSYSCTL_CONTENT = {sysctl!r}\n".encode(),
            **{name: b"module" for name in hub.ROUTING_MODULES if name != "routing.py"},
        }
        manifest = {"sha256": {"sovagrid-vpn/sovagrid_vpn/" + name: hashlib.sha256(raw).hexdigest()
                               for name, raw in code.items()}}
        policy = b'{"version":1,"enabled":["example"],"pending_remove":[]}'
        contents = {
            hub.ROUTING_POLICY: policy, hub.ROUTING_UNIT: unit, hub.ROUTING_SYSCTL: sysctl,
            **{str(hub.VPN_CODE / "sovagrid_vpn" / name): raw for name, raw in code.items()},
        }
        with patch.object(hub.os.path, "lexists", return_value=True), \
             patch.object(hub.installed, "public_path", side_effect=lambda filename, **_: contents[filename]), \
             patch.object(hub.installed, "managed_routing_enabled", return_value=True):
            self.assertEqual(hub.reviewed_routing(manifest), (policy, unit, sysctl))
            contents[hub.ROUTING_SYSCTL] = b"unknown override"
            with self.assertRaises(hub.UninstallError):
                hub.reviewed_routing(manifest)

    def test_hub_leaves_administrator_routing_without_managed_policy(self):
        policy_unit = self.root / hub.installed.ROUTING_UNIT
        policy_unit.write_text("administrator unit")
        with patch.object(hub, "UNITS", self.root), \
             patch.object(hub.os.path, "lexists", return_value=False), \
             patch.object(hub.installed, "managed_routing_enabled") as managed:
            self.assertIsNone(hub.reviewed_routing({"sha256": {}}))
            self.assertEqual(hub.reviewed_units({"sha256": {}}), [])
            managed.assert_not_called()

    def test_hub_removes_managed_prometheus_before_shared_network_owner(self):
        self.ledger.hub_state.return_value = None
        with patch.object(hub, "execute") as execute, \
             patch.object(hub.monitoring, "_token_hash"), \
             patch.object(hub.monitoring, "_collector_details", return_value={"Id": "collector"}):
            hub.stop_local([], ["hub", "collector", "web"], "network", self.ledger, [])
        self.assertEqual([call.args for call in execute.call_args_list], [
            (*hub.DOCKER, "rm", "--force", "collector"),
            (*hub.DOCKER, "rm", "--force", "hub", "web"),
            (*hub.DOCKER, "network", "rm", "network"),
        ])

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
             patch.object(hub.recovery, "STATE", self.root / "remove.json"), \
             patch.object(hub, "execute", return_value=b"inactive\n") as execute:
            hub.remove_local([service], [self.data, self.source])
        self.assertFalse(self.data.exists())
        retained, = self.root.glob("sovagrid-backups-retained-*")
        self.assertEqual((retained / "backups" / archive.name).read_bytes(), b"existing backup")
        self.assertTrue((retained / "backups/.broker-requests").is_dir())
        self.assertEqual(unrelated.read_text(), "independent")
        self.assertFalse(service.exists())
        self.assertFalse(self.source.exists())
        self.assertEqual(execute.call_args.args, ("systemctl", "daemon-reload"))

    def test_hub_only_relocation_leaves_a_clean_path_for_repromotion(self):
        workspace = self.root / "sovagrid-agent-local"
        workspace.mkdir()
        original = workspace / "file.txt"
        original.write_text("preserve")
        with (patch.object(hub, "DATA", self.data), patch.object(hub, "BACKUPS", self.data / "backups"),
              patch.object(hub.recovery, "STATE", self.root / "remove.json"), patch.object(hub, "execute")):
            hub.remove_local([], [], (workspace,))
        self.assertFalse(workspace.exists())
        retained, = self.root.glob("sovagrid-workspaces-retained-*")
        self.assertEqual((retained / workspace.name / original.name).read_text(), "preserve")

    def test_interrupted_local_cleanup_resumes_after_unit_already_disappeared(self):
        backup = self.data / "backups"
        backup.mkdir()
        (backup / "archive.tar.gz").write_bytes(b"preserve")
        unit = self.root / "sovagrid-hub-only-update.timer"
        unit.write_text("verified")
        pending = self.root / "remove.json"

        def fail_reload(*arguments):
            if arguments[1] == "daemon-reload":
                raise OSError("interrupted")
            return b"inactive\n"

        with patch.object(hub.recovery, "STATE", pending):
            state = hub.recovery.prepare([unit], [self.data], (), backup, None)
            with self.assertRaisesRegex(OSError, "interrupted"):
                hub.recovery.complete(state, fail_reload)
            self.assertTrue(pending.exists())
            self.assertFalse(unit.exists())
            self.assertTrue(self.data.exists())
            hub.recovery.complete(json.loads(pending.read_bytes()), Mock())
        self.assertFalse(self.data.exists())
        self.assertFalse(pending.exists())
        retained, = self.root.glob("sovagrid-backups-retained-*")
        self.assertEqual((retained / backup.name / "archive.tar.gz").read_bytes(), b"preserve")

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
            self.assertEqual(run.call_args.kwargs["input"], hub.agent_uninstall.ssh_program())


if __name__ == "__main__":
    unittest.main()
