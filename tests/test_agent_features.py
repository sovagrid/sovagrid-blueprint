# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Real source/config files with a fixed, bounded systemd/NSS command fixture."""
import copy
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock
import uuid
import socket
import subprocess
import grp
import pwd
import socketserver
import threading
import time

from test_remote_agent import helper

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("agent_feature_helper", REPO / "deploy/agent_features.py")
features = importlib.util.module_from_spec(spec)
spec.loader.exec_module(features)
TEMPLATES = {
    "sovagrid-terminal-control.service": b"[Unit]\nDescription=Disposable fixture PTY broker\n[Service]\nUser=sovagrid-shell\nGroup=sovagrid-shell\nExecStart=/usr/bin/true\n",
    "sovagrid-terminal-control.socket": b"[Socket]\nListenStream=/run/sovagrid-terminal/control.sock\nSocketUser=root\nSocketGroup=sovagrid\nSocketMode=0660\nDirectoryMode=0755\nRemoveOnStop=true\n",
}


class FeatureFixture:
    def __init__(self, root):
        self.root = root
        # Darwin inherits directory groups from /tmp (unlike the previous
        # per-user temporary directory). Model root's primary group exactly.
        os.chown(root, os.getuid(), os.getgid())
        self.f = helper.Files(root, owner=os.getuid())
        self.calls = []
        self.active = {"sovagrid-agent.service": True, "sovagrid-agent-tunnel.service": True}
        self.foreign_dropin = False
        self.unit_file_state = "enabled"
        self.interrupt_restart = False
        self.shadow_password = "*NP*"
        self.shadow_expiry = "1"
        self.agent = SimpleNamespace(pw_uid=os.getuid() or 10001, pw_gid=os.getgid(), pw_gecos="fixture-agent",
                                     pw_dir="/var/lib/sovagrid-agent", pw_shell="/usr/sbin/nologin")
        self.core = {"protocol": 1, "kind": "target", "identity": {field: str(uuid.uuid4()) for field in
                     ("request_id", "enrollment_id", "server_id")}, "phase": "active",
                     "agent_token_sha256": "a" * 64, "local_port": 18767,
                     "transport": {"hub_host": "198.51.100.1", "local_port": 18767},
                     "source_files": {}, "owned_files": {}, "file_metadata": {}, "pending_writes": {},
                     "owned_directories": {}, "accounts": {"sovagrid": {"uid": self.agent.pw_uid,
                         "gid": self.agent.pw_gid, "home": self.agent.pw_dir, "comment": self.agent.pw_gecos}}}
        for path, mode in (("/etc/sovagrid", 0o750), ("/etc/systemd/system", 0o755),
                           ("/opt/sovagrid-agent", 0o755), ("/opt/sovagrid-agent-installer", 0o755),
                           ("/var/lib/sovagrid-agent", 0o755), (helper.TARGET_STATE_DIR, 0o700)):
            self.f.mkdir(path, mode)
            self.core["owned_directories"][path] = mode
        old = {"format": 1, "components": {}, "sha256": {}}
        runtime = {"sovagrid_agent/__main__.py": b"# fixture unchanged runtime\n", "sovagrid_agent/terminal.py": b"# fixture PTY code\n",
                   "LICENSE": b"license\n", "NOTICE": b"notice\n", "ATTRIBUTION.md": b"author\n",
                   "deploy/sovagrid-agent.service": b"# fixture Agent unit\n"}
        for relative, data in runtime.items():
            old["sha256"]["sovagrid-agent/" + relative] = features.sha(data)
            self.write("/opt/sovagrid-agent/" + relative, data)
        old["sha256"][helper.SELF_NAME] = features.sha(b"# old verified helper\n")
        self.write(helper.TARGET_HELPER, b"# old verified helper\n")
        self.core["source_files"] = helper.Enrollment.installed_projection(old)
        raw = features.encode(old)
        self.write(features.MANIFEST, raw)
        self.core["source_manifest_sha256"] = features.sha(raw)
        self.config = {"hub_url": "https://localhost:18767", "server_id": self.core["identity"]["server_id"],
                       "token_file": "/etc/sovagrid/agent.token", "ca_file": "/etc/sovagrid/hub-ca.pem",
                       "interval_seconds": 30, "allow_remote_commands": False, "allow_interactive_terminal": False,
                       "allow_file_manager": False, "allow_systemd_journal": False, "journal_units": [], "file_roots": {}}
        config_bytes = features.encode(self.config) + b"\n"
        self.write(features.CONFIG, config_bytes, 0o640)
        self.owned(features.CONFIG, config_bytes, 0o640)
        for unit in ("sovagrid-agent.service", "sovagrid-agent-tunnel.service"):
            self.write("/etc/systemd/system/" + unit, b"# managed fixture unit\n")
            self.owned("/etc/systemd/system/" + unit, b"# managed fixture unit\n", 0o644)
        self.write(helper.TARGET_STATE, features.encode(self.core), 0o600)
        self.manifest = copy.deepcopy(old)
        for unit in features.UNITS:
            self.manifest["sha256"]["sovagrid-agent/deploy/" + unit] = features.sha(TEMPLATES[unit])
        self.source_root = "/var/tmp/sovagrid-agent-enroll.FEATURES1/source"
        for unit in features.UNITS:
            self.write(self.source_root + "/sovagrid-agent/deploy/" + unit, TEMPLATES[unit])
        module = (REPO / "deploy/agent_features.py").read_bytes()
        self.write(self.source_root + "/sovagrid-blueprint/deploy/agent_features.py", module)
        self.manifest["sha256"]["sovagrid-blueprint/deploy/agent_features.py"] = features.sha(module)
        self.e = helper.Enrollment(root=root, owner=os.getuid(), executable=self.source_root + "/" + helper.SELF_NAME,
                                   commands=SimpleNamespace(run=self.command))
        self.e.source = lambda _side: ("b" * 64, self.manifest)
        self.e.platform = lambda: {"ubuntu_version": "26.04", "systemd_version": "259"}
        self.e.verify_credentials = lambda state: self.assert_identity(state)
        self.e.tls_ready = lambda *_args, **_kwargs: True
        # Every active enrollment already created its private lock while
        # preparing. Feature status never creates a missing lock.
        with self.e.locked("target"):
            pass

    def assert_identity(self, state):
        assert state["agent_token_sha256"] == "a" * 64
        assert state["identity"] == self.core["identity"]

    def owned(self, path, data, mode):
        self.core["owned_files"][path] = features.sha(data)
        self.core["file_metadata"][path] = {"mode": mode, "gid": os.getgid()}

    def write(self, path, data, mode=0o644):
        parent = str(Path(path).parent)
        if not self.f.path(parent).exists():
            self.f.mkdir(parent, 0o755)
        self.f.write(path, data, mode=mode)

    def command(self, argv, **options):
        self.calls.append((list(argv), dict(options)))
        assert options.get("timeout", 20) <= 40
        if argv == ["/usr/bin/getent", "shadow", features.SHELL_NAME]:
            return 0, (features.SHELL_NAME + ":" + self.shadow_password + ":20000:0:99999:7::" + self.shadow_expiry + ":\n").encode()
        if argv[:2] == ["/usr/bin/systemctl", "is-active"]:
            return (0 if self.active.get(argv[-1], False) else 3), b""
        if argv[:2] == ["/usr/bin/systemctl", "show"]:
            unit = argv[2]
            exists = self.f.path("/etc/systemd/system/" + unit).exists()
            if not exists:
                return 1, b"LoadState=not-found\nDropInPaths=\n"
            user = "sovagrid-tunnel" if unit == "sovagrid-agent-tunnel.service" else "sovagrid-shell" if unit in features.UNITS else "sovagrid"
            dropin = "/etc/systemd/system/sovagrid-agent.service.d/10-tunnel.conf" if unit == "sovagrid-agent.service" else ""
            if self.foreign_dropin and unit == "sovagrid-agent.service":
                dropin += " /run/systemd/system/sovagrid-agent.service.d/foreign.conf"
            return 0, ("FragmentPath=/etc/systemd/system/" + unit + "\nLoadState=loaded\nDropInPaths=" + dropin
                       + "\nUser=" + user + "\nGroup=" + user + "\nUnitFileState=" + self.unit_file_state + "\n").encode()
        if argv[:2] == ["/usr/bin/systemctl", "restart"]:
            if self.interrupt_restart and argv[-1] == "sovagrid-agent.service":
                self.interrupt_restart = False
                raise helper.Refuse("SERVICE_FAILED")
            self.active[argv[-1]] = True
            return 0, b""
        if argv == ["/usr/bin/systemctl", "daemon-reload"]:
            return 0, b""
        raise AssertionError("Unexpected mutation/command: " + repr(argv))

    def lookup(self, name):
        if name == "sovagrid":
            return self.agent
        raise KeyError(name)

    def group(self, _name):
        raise KeyError(_name)

    def manager(self):
        return features.FeatureManager(self.e, "b" * 64, self.manifest, self.source_root)

    def request(self, desired, status=None):
        status = status or self.manager().dispatch("target-features-status", {"protocol": 1, "server_id": self.core["identity"]["server_id"]})
        return {"protocol": 1, "server_id": self.core["identity"]["server_id"], "enrollment_id": self.core["identity"]["enrollment_id"],
                "agent_token_sha256": "a" * 64, "features": desired, "expected": status["expected"]}


@unittest.skipIf(os.geteuid() == 0, "ordinary filesystem cases map the Agent to the current unprivileged UID")
class RemoteAgentFeatures(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sgfeatures-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.fixture = FeatureFixture(Path(self.temp.name))
        self.patches = [mock.patch.object(features.pwd, "getpwnam", side_effect=self.fixture.lookup),
                        mock.patch.object(features.grp, "getgrnam", side_effect=self.fixture.group),
                        mock.patch.object(features.os, "getgrouplist", side_effect=lambda _name, gid: [gid])]
        for item in self.patches:
            item.start(); self.addCleanup(item.stop)

    def test_protocol_rejects_extra_secrets_bool_coercion_and_implicit_commands(self):
        server = self.fixture.core["identity"]["server_id"]
        good = {"protocol": 1, "server_id": server}
        helper.validate_request("target-features-status", good)
        for value in (dict(good, request_id=str(uuid.uuid4())), dict(good, password="CANARY"), dict(good, protocol=True)):
            with self.assertRaises(helper.Refuse):
                helper.validate_request("target-features-status", value)
        for requested in ({"commands": False, "terminal": True, "files": False}, {"commands": 1, "terminal": False, "files": False}):
            with self.assertRaises(helper.Refuse):
                helper.validate_request("target-features-preview", dict(good, features=requested))

    def test_status_and_preview_are_read_only_and_never_export_secrets(self):
        f = self.fixture
        before = {p: p.read_bytes() for p in f.root.rglob("*") if p.is_file()}
        response = f.manager().dispatch("target-features-preview", {"protocol": 1, "server_id": f.core["identity"]["server_id"],
                                             "features": {"commands": True, "terminal": False, "files": True}})
        self.assertTrue(response["changed"])
        self.assertFalse(response["recovery_required"])
        self.assertEqual(before, {p: p.read_bytes() for p in f.root.rglob("*") if p.is_file()})
        self.assertFalse(f.f.path(features.STATE).exists())
        self.assertNotIn("password", json.dumps(response))
        self.assertTrue(all(argv[:2] in (["/usr/bin/systemctl", "show"], ["/usr/bin/systemctl", "is-active"]) for argv, _ in f.calls))

    def test_read_snapshots_share_the_existing_lock_and_exclude_an_inflight_apply(self):
        f = self.fixture
        request = {"protocol": 1, "server_id": f.core["identity"]["server_id"]}
        desired = {"commands": True, "terminal": False, "files": True}
        before = {p: p.read_bytes() for p in f.root.rglob("*") if p.is_file()}
        # Separate open file descriptions exercise the kernel flock, even
        # though this fixture models both concurrent RPCs in one process.
        with f.e.locked("target"):
            for action in ("target-features-status", "target-features-preview"):
                manager = f.manager()
                with mock.patch.object(manager, "snapshot", side_effect=AssertionError("must lock before snapshot")):
                    with self.assertRaises(helper.Refuse) as error:
                        manager.dispatch(action, dict(request, features=desired) if action.endswith("preview") else request)
                self.assertEqual(error.exception.code, "STATE_CONFLICT")
        with f.e.locked("target", readonly=True):
            status = f.manager().dispatch("target-features-status", request)
            preview = f.manager().dispatch("target-features-preview", dict(request, features=desired))
        self.assertEqual(status["expected"], preview["expected"])
        self.assertEqual(before, {p: p.read_bytes() for p in f.root.rglob("*") if p.is_file()})

    def test_readonly_status_refuses_a_missing_lock_without_creating_it(self):
        f = self.fixture
        f.f.path(helper.TARGET_STATE_DIR + "/lock").unlink()
        with self.assertRaises(helper.Refuse) as error:
            f.manager().dispatch("target-features-status", {"protocol": 1, "server_id": f.core["identity"]["server_id"]})
        self.assertEqual(error.exception.code, "STATE_CONFLICT")
        self.assertFalse(f.f.path(helper.TARGET_STATE_DIR + "/lock").exists())
        self.assertFalse(f.f.path(features.STATE).exists())

    def test_agent_home_must_keep_its_managed_traversable_mode(self):
        f = self.fixture
        f.f.path(features.AGENT_HOME).chmod(0o700)
        with self.assertRaises((features.FeatureError, helper.Refuse)) as error:
            f.manager().dispatch("target-features-status", {"protocol": 1, "server_id": f.core["identity"]["server_id"]})
        self.assertEqual(error.exception.code, "OWNERSHIP_CONFLICT")
        self.assertFalse(f.f.path(features.STATE).exists())

    def test_terminal_preview_refuses_foreign_numeric_uid_or_gid_before_changes(self):
        f = self.fixture
        request = {"protocol": 1, "server_id": f.core["identity"]["server_id"],
                   "features": {"commands": True, "terminal": True, "files": False}}
        before = {p: p.read_bytes() for p in f.root.rglob("*") if p.is_file()}
        for lookup in ("getpwuid", "getgrgid"):
            with mock.patch.object(features.pwd if lookup == "getpwuid" else features.grp, lookup,
                                   return_value=SimpleNamespace(pw_name="foreign-reserved-id", gr_name="foreign-reserved-id")):
                with self.assertRaises(features.FeatureError) as error:
                    f.manager().dispatch("target-features-preview", request)
            self.assertEqual(error.exception.code, "OWNERSHIP_CONFLICT")
        self.assertEqual(before, {p: p.read_bytes() for p in f.root.rglob("*") if p.is_file()})
        self.assertFalse(f.f.path(features.STATE).exists())
        self.assertTrue(all(argv[:2] in (["/usr/bin/systemctl", "show"], ["/usr/bin/systemctl", "is-active"]) for argv, _ in f.calls))

    def test_unit_and_socket_directory_metadata_are_enforced_and_bound_in_cas(self):
        f = self.fixture
        path = "/etc/systemd/system/sovagrid-terminal-control.socket"
        f.write(path, TEMPLATES["sovagrid-terminal-control.socket"])
        state = {"protocol": 1, "kind": "target-features", "identity": {**f.core["identity"], "agent_token_sha256": "a" * 64},
                 "phase": "ready", "pending_features": None, "owned_files": {path: features.sha(f.f.read(path))},
                 "pending_writes": {}, "data_directories": {}, "shell_account": None}
        f.f.write(features.STATE, features.encode(state))
        f.f.mkdir("/run/sovagrid-terminal", 0o755)
        listener = socket.socket(socket.AF_UNIX)
        self.addCleanup(listener.close)
        listener.bind(str(f.f.path(features.SOCKET)))
        f.f.path(features.SOCKET).chmod(0o660)
        manager = f.manager().load()
        snapshot = manager.socket_snapshot()
        self.assertEqual(snapshot["directory"]["mode"], 0o755)
        before = manager.snapshot()["expected"]
        f.f.path(features.SOCKET).unlink()
        replacement = socket.socket(socket.AF_UNIX)
        self.addCleanup(replacement.close)
        replacement.bind(str(f.f.path(features.SOCKET)))
        f.f.path(features.SOCKET).chmod(0o660)
        self.assertNotEqual(f.manager().snapshot()["expected"], before)
        f.f.path("/run/sovagrid-terminal").chmod(0o700)
        with self.assertRaises(features.FeatureError):
            f.manager().snapshot()
        f.f.path("/run/sovagrid-terminal").chmod(0o755)
        f.f.path(path).chmod(0o600)
        with self.assertRaises(features.FeatureError):
            f.manager().snapshot()

    def test_foreign_destination_after_staging_intent_is_never_adopted(self):
        f = self.fixture
        desired = {"commands": True, "terminal": False, "files": True}
        request = f.request(desired)
        with mock.patch.object(features, "publish_directory", side_effect=features.FeatureError("SERVICE_FAILED")):
            with self.assertRaises(features.FeatureError):
                f.manager().dispatch("target-features-apply", request)
        record = f.e.load_json(features.STATE)["data_directories"][features.WORKSPACE]
        self.assertTrue(f.f.path(record["publication"]["staging"]).is_dir())
        f.f.mkdir(features.WORKSPACE, 0o700)
        secret = f.f.path(features.WORKSPACE) / "foreign-private.txt"
        secret.write_bytes(b"previously private content\n")
        inode = f.f.path(features.WORKSPACE).stat().st_ino
        with mock.patch.object(features.os, "fchown") as chown:
            with self.assertRaises(features.FeatureError) as error:
                f.manager().dispatch("target-features-apply", request)
        self.assertEqual(error.exception.code, "OWNERSHIP_CONFLICT")
        chown.assert_not_called()
        self.assertEqual(f.f.path(features.WORKSPACE).stat().st_ino, inode)
        self.assertEqual(secret.read_bytes(), b"previously private content\n")
        self.assertEqual(f.f.path(features.WORKSPACE).stat().st_mode & 0o777, 0o700)

    def test_lost_atomic_publication_reply_reconciles_only_the_recorded_inode(self):
        f = self.fixture
        desired = {"commands": True, "terminal": False, "files": True}
        request = f.request(desired)
        publish = features.publish_directory
        def lost_reply(source, destination):
            publish(source, destination)
            raise OSError("lost reply after no-replace publication")
        with mock.patch.object(features, "publish_directory", side_effect=lost_reply):
            with self.assertRaises(OSError):
                f.manager().dispatch("target-features-apply", request)
        record = f.e.load_json(features.STATE)["data_directories"][features.WORKSPACE]
        self.assertEqual(f.f.path(features.WORKSPACE).stat().st_ino, record["publication"]["ino"])
        self.assertFalse(f.f.path(record["publication"]["staging"]).exists())
        status = f.manager().dispatch("target-features-status", {"protocol": 1, "server_id": f.core["identity"]["server_id"]})
        self.assertTrue(status["recovery_required"])
        with mock.patch.object(features, "publish_directory", side_effect=AssertionError("already published")):
            result = f.manager().dispatch("target-features-apply", f.request(desired, status))
        self.assertEqual(result["current"], desired)
        self.assertFalse(result["recovery_required"])

    @unittest.skipIf(os.geteuid() == 0, "non-root fixture uses its own current UID as the Agent; real root boundary has separate integration coverage")
    def test_enable_files_then_disable_preserves_data_and_old_source_identity(self):
        f = self.fixture
        old_helper = f.f.read(helper.TARGET_HELPER)
        old_manifest = f.f.read(features.MANIFEST)
        desired = {"commands": True, "terminal": False, "files": True}
        result = f.manager().dispatch("target-features-apply", f.request(desired))
        self.assertTrue(result["applied"])
        self.assertEqual(result["current"], desired)
        workspace = f.f.path(features.WORKSPACE)
        (workspace / "preserved.txt").write_bytes(b"user data\n")
        disabled = {"commands": False, "terminal": False, "files": False}
        result = f.manager().dispatch("target-features-apply", f.request(disabled))
        self.assertEqual(result["current"], disabled)
        self.assertEqual((workspace / "preserved.txt").read_bytes(), b"user data\n")
        self.assertEqual(f.f.read(helper.TARGET_HELPER), old_helper)
        self.assertEqual(f.f.read(features.MANIFEST), old_manifest)
        core = f.e.load_state("target")
        self.assertEqual(core["identity"], f.core["identity"])
        self.assertNotIn(features.WORKSPACE, core["owned_directories"])
        self.assertEqual(core["accounts"], f.core["accounts"])
        f.e.check_owned_files(core)
        self.assertFalse(any("sovagrid-agent-tunnel.service" in argv and "restart" in argv for argv, _ in f.calls))

    @unittest.skipIf(os.geteuid() == 0, "fixture maps Agent to its unprivileged test UID")
    def test_lost_restart_reply_requires_replay_and_then_becomes_idempotent(self):
        f = self.fixture
        desired = {"commands": True, "terminal": False, "files": True}
        request = f.request(desired)
        f.interrupt_restart = True
        with self.assertRaises(helper.Refuse):
            f.manager().dispatch("target-features-apply", request)
        status = f.manager().dispatch("target-features-status", {"protocol": 1, "server_id": f.core["identity"]["server_id"]})
        self.assertTrue(status["recovery_required"])
        self.assertEqual(status["pending_features"], desired)
        result = f.manager().dispatch("target-features-apply", f.request(desired, status))
        self.assertTrue(result["applied"])
        self.assertFalse(result["recovery_required"])
        f.calls.clear()
        result = f.manager().dispatch("target-features-apply", f.request(desired))
        self.assertFalse(result["changed"])
        self.assertFalse(any("restart" in argv for argv, _ in f.calls))

    def test_changed_config_or_service_policy_invalidates_preview_without_repair(self):
        f = self.fixture
        request = f.request({"commands": True, "terminal": False, "files": False})
        f.foreign_dropin = True
        with self.assertRaises(features.FeatureError) as error:
            f.manager().dispatch("target-features-apply", request)
        self.assertEqual(error.exception.code, "OWNERSHIP_CONFLICT")
        self.assertFalse(f.f.path(features.STATE).exists())

    def test_runtime_mismatch_refuses_without_replacing_installed_files(self):
        f = self.fixture
        f.manifest["sha256"]["sovagrid-agent/sovagrid_agent/__main__.py"] = "c" * 64
        before = f.f.read(helper.TARGET_HELPER)
        with self.assertRaises(features.FeatureError) as error:
            f.manager().snapshot()
        self.assertEqual(error.exception.code, "AGENT_UPDATE_REQUIRED")
        self.assertEqual(f.f.read(helper.TARGET_HELPER), before)
        self.assertFalse(f.f.path(features.STATE).exists())

    def test_foreign_workspace_and_shell_identity_are_never_adopted(self):
        f = self.fixture
        f.f.mkdir(features.WORKSPACE, 0o700)
        with self.assertRaises(features.FeatureError) as error:
            f.manager().snapshot()
        self.assertEqual(error.exception.code, "OWNERSHIP_CONFLICT")
        f.f.path(features.WORKSPACE).rmdir()
        shell = SimpleNamespace(pw_uid=f.agent.pw_uid, pw_gid=f.agent.pw_gid, pw_dir=features.SHELL_HOME,
                                pw_gecos="foreign", pw_shell="/usr/sbin/nologin")
        with mock.patch.object(features.pwd, "getpwnam", side_effect=lambda name: shell if name == features.SHELL_NAME else f.agent):
            with self.assertRaises(features.FeatureError):
                f.manager().snapshot()

    def test_wrong_server_identity_never_creates_feature_state(self):
        f = self.fixture
        request = f.request({"commands": True, "terminal": False, "files": False})
        request["server_id"] = str(uuid.uuid4())
        with self.assertRaises(features.FeatureError) as error:
            f.manager().dispatch("target-features-apply", request)
        self.assertEqual(error.exception.code, "STATE_CONFLICT")
        self.assertFalse(f.f.path(features.STATE).exists())

    def test_changed_unit_enable_policy_rejects_stale_cas_before_writes(self):
        f = self.fixture
        request = f.request({"commands": True, "terminal": False, "files": False})
        f.unit_file_state = "disabled"
        with self.assertRaises(features.FeatureError) as error:
            f.manager().dispatch("target-features-apply", request)
        self.assertEqual(error.exception.code, "STALE_PREVIEW")
        self.assertFalse(f.f.path(features.STATE).exists())

    def test_staged_module_hash_is_checked_before_execution(self):
        f = self.fixture
        path = f.source_root + "/sovagrid-blueprint/deploy/agent_features.py"
        f.f.write(path, b"raise RuntimeError('must never execute unverified helper')\n", mode=0o644)
        with self.assertRaises(helper.Refuse) as error:
            f.e.target_features("target-features-status", {"protocol": 1, "server_id": f.core["identity"]["server_id"]})
        self.assertEqual(error.exception.code, "SOURCE_CHANGED")
        self.assertFalse(f.f.path(features.STATE).exists())

    def test_config_write_disconnect_reconciles_old_enrollment_hash_intent(self):
        f = self.fixture
        desired = {"commands": True, "terminal": False, "files": False}
        request = f.request(desired)
        original = f.e.files.write
        failed = []
        def disconnect(path, data, **options):
            original(path, data, **options)
            if path == features.CONFIG and not failed:
                failed.append(True)
                raise OSError("fixture connection lost after atomic replacement")
        with mock.patch.object(f.e.files, "write", side_effect=disconnect):
            with self.assertRaises(OSError):
                f.manager().dispatch("target-features-apply", request)
        self.assertIn(features.CONFIG, f.e.load_state("target")["pending_writes"])
        status = f.manager().snapshot()
        self.assertTrue(status["recovery_required"])
        result = f.manager().dispatch("target-features-apply", f.request(desired, status))
        self.assertFalse(result["recovery_required"])
        self.assertFalse(f.e.load_state("target")["pending_writes"])
        f.e.check_owned_files(f.e.load_state("target"))

    def test_owned_shell_cannot_share_the_agent_group(self):
        f = self.fixture
        identity = {**f.core["identity"], "agent_token_sha256": f.core["agent_token_sha256"]}
        state = {"protocol": 1, "kind": "target-features", "identity": identity, "phase": "ready", "pending_features": None,
                 "owned_files": {}, "pending_writes": {}, "data_directories": {}, "shell_account": {
                     "uid": features.SHELL_UID, "gid": features.SHELL_UID,
                     "comment": "sovagrid-features-" + f.core["identity"]["enrollment_id"],
                     "group_started": True, "user_started": True}}
        f.f.write(features.STATE, features.encode(state))
        shell = SimpleNamespace(pw_uid=features.SHELL_UID, pw_gid=f.agent.pw_gid, pw_dir=features.SHELL_HOME,
                                pw_gecos=state["shell_account"]["comment"], pw_shell="/usr/sbin/nologin")
        group = SimpleNamespace(gr_gid=features.SHELL_UID, gr_mem=[])
        with mock.patch.object(features.pwd, "getpwnam", side_effect=lambda name: shell if name == features.SHELL_NAME else f.agent), \
             mock.patch.object(features.grp, "getgrnam", return_value=group):
            with self.assertRaises(features.FeatureError) as error:
                f.manager().snapshot()
        self.assertEqual(error.exception.code, "OWNERSHIP_CONFLICT")

    def test_owned_shell_requires_nonwritable_login_home_and_private_expiry_policy(self):
        f = self.fixture
        record = {"uid": features.SHELL_UID, "gid": features.SHELL_UID,
                  "comment": "sovagrid-features-" + f.core["identity"]["enrollment_id"],
                  "group_started": True, "user_started": True}
        state = {"protocol": 1, "kind": "target-features", "identity": {**f.core["identity"], "agent_token_sha256": "a" * 64},
                 "phase": "ready", "pending_features": None, "owned_files": {}, "pending_writes": {},
                 "data_directories": {}, "shell_account": record}
        f.f.write(features.STATE, features.encode(state))
        before = f.f.read(features.STATE)
        shell = SimpleNamespace(pw_uid=features.SHELL_UID, pw_gid=features.SHELL_UID, pw_dir=features.SHELL_LOGIN_HOME,
                                pw_gecos=record["comment"], pw_shell="/usr/sbin/nologin")
        group = SimpleNamespace(gr_gid=features.SHELL_UID, gr_mem=[])
        with mock.patch.object(features.pwd, "getpwnam", side_effect=lambda name: shell if name == features.SHELL_NAME else f.agent), \
             mock.patch.object(features.grp, "getgrnam", return_value=group):
            manager = f.manager().load()
            self.assertEqual(manager.account_snapshot()["user"]["login_policy"], {"password_disabled": True, "expiry_day": 1})
            response = manager.snapshot()
            self.assertNotIn("*NP*", json.dumps(response))
            shell.pw_dir = features.SHELL_HOME
            with self.assertRaises(features.FeatureError):
                f.manager().snapshot()
            shell.pw_dir = features.SHELL_LOGIN_HOME
            for expiry in ("", "99999"):
                f.shadow_expiry = expiry
                with self.assertRaises(features.FeatureError) as error:
                    f.manager().snapshot()
                self.assertEqual(error.exception.code, "OWNERSHIP_CONFLICT")
            f.shadow_expiry = "1"
            f.shadow_password = "$6$PRIVATE-HASH-CANARY"
            with self.assertRaises(features.FeatureError) as error:
                f.manager().snapshot()
            self.assertEqual(str(error.exception), "OWNERSHIP_CONFLICT")
            self.assertNotIn("PRIVATE-HASH-CANARY", repr(f.calls))
        self.assertEqual(f.f.read(features.STATE), before)

    def test_half_active_terminal_never_counts_as_fully_enabled_or_disabled(self):
        f = self.fixture
        f.active["sovagrid-terminal-control.service"] = True
        f.active["sovagrid-terminal-control.socket"] = False
        manager = f.manager()
        self.assertTrue(manager.services()["terminal"])
        self.assertFalse(manager.terminal_ready(True))
        self.assertFalse(manager.terminal_ready(False))


@unittest.skipUnless(os.geteuid() == 0 and os.environ.get("SOVAGRID_DISPOSABLE_FEATURE_FIXTURE") == "1" and Path("/.dockerenv").is_file(),
                     "actual UID creation only inside the explicit offline disposable container")
class KernelFeaturePermissions(unittest.TestCase):
    """Real chown/NSS/UID drops/SSH, with only systemd state modeled locally."""
    @classmethod
    def setUpClass(cls):
        if {path.name for path in Path("/sys/class/net").iterdir()} != {"lo"}:
            raise AssertionError("Only the offline disposable container is allowed")
        for name in ("sovagrid", features.SHELL_NAME):
            for lookup in (pwd.getpwnam, grp.getgrnam):
                try:
                    lookup(name)
                except KeyError:
                    pass
                else:
                    raise AssertionError("Nonempty disposable identity fixture")
        helper.Commands().run(["/usr/sbin/groupadd", "--system", "--gid", "10001", "sovagrid"], capture=False)
        helper.Commands().run(["/usr/sbin/useradd", "--system", "--uid", "10001", "--gid", "10001", "--no-create-home",
                               "--home-dir", "/var/lib/sovagrid-agent", "--shell", "/usr/sbin/nologin", "--comment", "fixture-agent", "sovagrid"], capture=False)

    @classmethod
    def tearDownClass(cls):
        cls.remove_user("sovagrid")

    @staticmethod
    def remove_user(name):
        real = helper.Commands()
        try:
            pwd.getpwnam(name)
        except KeyError:
            pass
        else:
            real.run(["/usr/sbin/userdel", name], capture=False)
        try:
            grp.getgrnam(name)
        except KeyError:
            pass
        else:
            real.run(["/usr/sbin/groupdel", name], capture=False)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        self.fixture = FeatureFixture(self.root)
        f = self.fixture
        f.agent = pwd.getpwnam("sovagrid")
        f.core["accounts"]["sovagrid"].update(uid=f.agent.pw_uid, gid=f.agent.pw_gid)
        os.chown(f.f.path("/etc/sovagrid"), 0, f.agent.pw_gid)
        os.chown(f.f.path(features.CONFIG), 0, f.agent.pw_gid)
        f.core["file_metadata"][features.CONFIG]["gid"] = f.agent.pw_gid
        token = b"kernel-permission-fixture-only\n"
        f.write("/etc/sovagrid/agent.token", token, 0o640)
        os.chown(f.f.path("/etc/sovagrid/agent.token"), 0, f.agent.pw_gid)
        f.core["agent_token_sha256"] = features.sha(token.rstrip(b"\n"))
        f.write(helper.TARGET_STATE, features.encode(f.core), 0o600)
        f.e.verify_credentials = lambda state: self.assertEqual(state["agent_token_sha256"], features.sha(token.rstrip(b"\n")))
        self.real = helper.Commands()
        self.listener = None
        self.lost_useradd = False
        original = f.command
        def command(argv, **options):
            if argv[0] in ("/usr/sbin/groupadd", "/usr/sbin/useradd", "/usr/bin/getent", "/usr/bin/systemd-analyze") \
                    or argv == ["/usr/bin/python3", "-I", "-B", "-c", features.TOKEN_DENIAL_PROBE]:
                f.calls.append((list(argv), dict(options)))
                actual = list(argv)
                if argv[0] == "/usr/bin/python3":
                    actual[-1] = features.TOKEN_DENIAL_PROBE.replace("/etc/sovagrid/agent.token", str(f.f.path("/etc/sovagrid/agent.token")))
                elif argv[0] == "/usr/bin/systemd-analyze":
                    actual[2:] = [str(f.f.path(path)) for path in argv[2:]]
                result = self.real.run(actual, **options)
                if argv[0] == "/usr/sbin/useradd" and self.lost_useradd:
                    self.lost_useradd = False
                    raise helper.Refuse("SERVICE_FAILED")
                return result
            if argv[:3] == ["/usr/bin/systemctl", "enable", "--now"]:
                f.active[argv[-1]] = True
                directory = f.f.path("/run/sovagrid-terminal")
                directory.mkdir(parents=True, exist_ok=True)
                directory.chmod(0o755)
                self.listener = socket.socket(socket.AF_UNIX)
                self.listener.bind(str(f.f.path(features.SOCKET)))
                os.chown(f.f.path(features.SOCKET), 0, f.agent.pw_gid)
                f.f.path(features.SOCKET).chmod(0o660)
                f.calls.append((list(argv), dict(options)))
                return 0, b""
            if argv[:3] == ["/usr/bin/systemctl", "disable", "--now"]:
                f.active[argv[-1]] = False
                if self.listener is not None:
                    self.listener.close(); self.listener = None
                f.f.path(features.SOCKET).unlink(missing_ok=True)
                f.calls.append((list(argv), dict(options)))
                return 0, b""
            if argv[:2] == ["/usr/bin/systemctl", "stop"]:
                f.active[argv[-1]] = False
                f.calls.append((list(argv), dict(options)))
                return 0, b""
            return original(argv, **options)
        f.e.commands = SimpleNamespace(run=command)

    def tearDown(self):
        if self.listener is not None:
            self.listener.close()
        self.remove_user(features.SHELL_NAME)
        self.temp.cleanup()

    def request(self, desired):
        request = self.fixture.request(desired)
        request["agent_token_sha256"] = self.fixture.core["agent_token_sha256"]
        return request

    def test_actual_distinct_uid_token_denial_and_disable_preserves_workspace(self):
        f = self.fixture
        enabled = {"commands": True, "terminal": True, "files": True}
        result = f.manager().dispatch("target-features-apply", self.request(enabled))
        self.assertEqual(result["current"], enabled)
        shell = pwd.getpwnam(features.SHELL_NAME)
        self.assertNotEqual(shell.pw_uid, f.agent.pw_uid)
        self.assertEqual(shell.pw_dir, features.SHELL_LOGIN_HOME)
        self.assertEqual(os.getgrouplist(features.SHELL_NAME, shell.pw_gid), [shell.pw_gid])
        account = f.manager().load().account_snapshot()["user"]
        self.assertEqual(account["login_policy"], {"password_disabled": True, "expiry_day": 1})
        creation = next(argv for argv, _ in f.calls if argv[0] == "/usr/sbin/useradd")
        self.assertNotIn("--system", creation)
        self.assertEqual(creation[creation.index("--expiredate") + 1], "1970-01-02")
        probe = features.TOKEN_DENIAL_PROBE.replace("/etc/sovagrid/agent.token", str(f.f.path("/etc/sovagrid/agent.token")))
        self.real.run(["/usr/bin/python3", "-I", "-B", "-c", probe], capture=False)
        self.real.run(["/usr/bin/test", "-r", str(f.f.path("/etc/sovagrid/agent.token"))], user=f.agent.pw_uid, group=f.agent.pw_gid)
        workspace = f.f.path(features.WORKSPACE)
        self.assertEqual(workspace.stat().st_uid, f.agent.pw_uid)
        self.real.run(["/usr/bin/test", "-w", str(workspace)], user=f.agent.pw_uid, group=f.agent.pw_gid)
        self.real.run(["/usr/bin/test", "-x", str(workspace)], user=f.agent.pw_uid, group=f.agent.pw_gid)
        (workspace / "preserve.txt").write_bytes(b"data survives feature disable\n")
        disabled = {"commands": False, "terminal": False, "files": False}
        result = f.manager().dispatch("target-features-apply", self.request(disabled))
        self.assertEqual(result["current"], disabled)
        self.assertEqual((workspace / "preserve.txt").read_bytes(), b"data survives feature disable\n")
        f.e.check_owned_files(f.e.load_state("target"))

    def test_actual_useradd_lost_reply_reuses_same_owned_identity(self):
        f = self.fixture
        desired = {"commands": True, "terminal": True, "files": False}
        self.lost_useradd = True
        with self.assertRaises(helper.Refuse):
            f.manager().dispatch("target-features-apply", self.request(desired))
        first = pwd.getpwnam(features.SHELL_NAME)
        status = f.manager().dispatch("target-features-status", {"protocol": 1, "server_id": f.core["identity"]["server_id"]})
        self.assertTrue(status["recovery_required"])
        f.manager().dispatch("target-features-apply", self.request(desired))
        self.assertEqual(pwd.getpwnam(features.SHELL_NAME).pw_uid, first.pw_uid)

    def test_actual_no_replace_publication_preserves_foreign_private_directory(self):
        f = self.fixture
        desired = {"commands": True, "terminal": False, "files": True}
        request = self.request(desired)
        publish = features.publish_directory
        foreign = []
        def competing_directory(source, destination):
            destination.mkdir(mode=0o700)
            secret = destination / "root-private.txt"
            secret.write_bytes(b"foreign root-private fixture\n")
            secret.chmod(0o600)
            foreign.append(destination.stat().st_ino)
            publish(source, destination)
        with mock.patch.object(features, "publish_directory", side_effect=competing_directory):
            with self.assertRaises(features.FeatureError) as error:
                f.manager().dispatch("target-features-apply", request)
        self.assertEqual(error.exception.code, "OWNERSHIP_CONFLICT")
        workspace = f.f.path(features.WORKSPACE)
        self.assertEqual(workspace.stat().st_ino, foreign[0])
        self.assertEqual(workspace.stat().st_uid, 0)
        self.assertEqual(workspace.stat().st_mode & 0o777, 0o700)
        self.real.run(["/usr/bin/test", "!", "-r", str(workspace / "root-private.txt")], user=f.agent.pw_uid, group=f.agent.pw_gid)
        with self.assertRaises(features.FeatureError):
            f.manager().dispatch("target-features-apply", request)
        self.assertEqual((workspace / "root-private.txt").read_bytes(), b"foreign root-private fixture\n")

    def test_actual_lost_publication_reply_reuses_exact_inode(self):
        f = self.fixture
        desired = {"commands": True, "terminal": False, "files": True}
        request = self.request(desired)
        publish = features.publish_directory
        def lost_reply(source, destination):
            publish(source, destination)
            raise OSError("lost successful Linux renameat2 reply")
        with mock.patch.object(features, "publish_directory", side_effect=lost_reply):
            with self.assertRaises(OSError):
                f.manager().dispatch("target-features-apply", request)
        record = f.e.load_json(features.STATE)["data_directories"][features.WORKSPACE]
        workspace = f.f.path(features.WORKSPACE)
        self.assertEqual(workspace.stat().st_ino, record["publication"]["ino"])
        self.assertEqual(workspace.stat().st_uid, 0)
        result = f.manager().dispatch("target-features-apply", self.request(desired))
        self.assertFalse(result["recovery_required"])
        self.assertEqual(workspace.stat().st_ino, record["publication"]["ino"])
        self.assertEqual(workspace.stat().st_uid, f.agent.pw_uid)

    def test_actual_expired_shell_rejects_valid_key_forwarding_after_disable_with_and_without_pam(self):
        f = self.fixture
        enabled = {"commands": True, "terminal": True, "files": False}
        f.manager().dispatch("target-features-apply", self.request(enabled))
        control = "sg-feature-login-control"
        for lookup, key in ((pwd.getpwnam, control), (grp.getgrnam, control), (pwd.getpwuid, 10004), (grp.getgrgid, 10004)):
            with self.assertRaises(KeyError):
                lookup(key)
        self.real.run(["/usr/sbin/groupadd", "--gid", "10004", control], capture=False)
        self.addCleanup(self.remove_user, control)
        self.real.run(["/usr/sbin/useradd", "--uid", "10004", "--gid", "10004", "--no-create-home",
                       "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "--password", "*NP*",
                       "--expiredate", "", control], capture=False)
        self.assertEqual(pwd.getpwnam(control).pw_shell, "/usr/sbin/nologin")
        Path("/run/sshd").mkdir(exist_ok=True)
        Path("/run/sshd").chmod(0o755)
        Path("/run/nologin").unlink(missing_ok=True)
        marker = b"SOVAGRID_EXPIRED_SHELL_FORWARDING_PROOF\n"
        class Backend(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(marker)
        backend = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Backend)
        backend.daemon_threads = True
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        try:
            # /run avoids an incidental StrictModes failure on /tmp. This
            # entire test is guarded by the offline disposable-container gate.
            with tempfile.TemporaryDirectory(prefix="sg-feature-ssh-", dir="/run") as directory:
                directory = Path(directory)
                directory.chmod(0o755)
                host_key, client_key = directory / "host-key", directory / "client-key"
                for key in (host_key, client_key):
                    self.real.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "fixture", "-f", str(key)], capture=False)
                public = " ".join(Path(str(client_key) + ".pub").read_text().split()[:2]) + "\n"
                keys = directory / "authorized_keys"
                keys.write_text(public)
                keys.chmod(0o644)
                runtime_home = f.f.path(features.SHELL_HOME)
                script = "from pathlib import Path; import sys; p=Path(sys.argv[1])/'.ssh'; p.mkdir(mode=0o700); (p/'authorized_keys').write_text(sys.argv[2])"
                self.real.run(["/usr/bin/python3", "-I", "-B", "-c", script, str(runtime_home), public],
                              user=features.SHELL_UID, group=features.SHELL_UID, capture=False)
                disabled = {"commands": False, "terminal": False, "files": False}
                f.manager().dispatch("target-features-apply", self.request(disabled))
                self.assertTrue((runtime_home / ".ssh/authorized_keys").is_file())
                self.assertEqual(f.manager().load().account_snapshot()["user"]["login_policy"], {"password_disabled": True, "expiry_day": 1})
                for pam in ("yes", "no"):
                    with socket.socket() as reservation:
                        reservation.bind(("127.0.0.1", 0))
                        port = reservation.getsockname()[1]
                    config = directory / ("sshd-" + pam + ".conf")
                    config.write_text("Port " + str(port) + "\nListenAddress 127.0.0.1\nHostKey " + str(host_key)
                        + "\nPidFile " + str(directory / ("sshd-" + pam + ".pid")) + "\nUsePAM " + pam
                        + "\nPermitRootLogin no\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no"
                        + "\nAuthenticationMethods publickey\nAuthorizedKeysFile " + str(keys)
                        + "\nAuthorizedKeysCommand none\nStrictModes yes\nAllowTcpForwarding yes\nPermitOpen 127.0.0.1:"
                        + str(backend.server_address[1]) + "\nPermitTTY no\nMaxSessions 0\nPrintMotd no\nLogLevel ERROR\n")
                    self.real.run(["/usr/sbin/sshd", "-t", "-f", str(config)], capture=False)
                    host_public = " ".join(Path(str(host_key) + ".pub").read_text().split()[:2])
                    known_hosts = directory / ("known-hosts-" + pam)
                    known_hosts.write_text("[127.0.0.1]:" + str(port) + " " + host_public + "\n")
                    server = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], stdin=subprocess.DEVNULL,
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                    try:
                        deadline = time.monotonic() + 3
                        ready = False
                        while time.monotonic() < deadline:
                            self.assertIsNone(server.poll(), "isolated fixture sshd exited")
                            try:
                                with socket.create_connection(("127.0.0.1", port), timeout=0.2) as connection:
                                    connection.settimeout(0.2)
                                    ready = connection.recv(64).startswith(b"SSH-2.0-")
                            except OSError:
                                time.sleep(0.05)
                            if ready:
                                break
                        self.assertTrue(ready, "isolated fixture sshd not ready")
                        def forward(name):
                            return subprocess.run(["/usr/bin/ssh", "-F", "/dev/null", "-i", str(client_key), "-p", str(port),
                                "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no",
                                "-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
                                "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UserKnownHostsFile=" + str(known_hosts),
                                "-o", "ConnectTimeout=2", "-o", "LogLevel=ERROR", "-W", "127.0.0.1:" + str(backend.server_address[1]),
                                name + "@127.0.0.1"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=5, close_fds=True)
                        accepted = forward(control)
                        self.assertEqual((accepted.returncode, accepted.stdout), (0, marker), "positive nologin forwarding control failed with UsePAM=" + pam)
                        denied = forward(features.SHELL_NAME)
                        self.assertEqual((denied.returncode, denied.stdout), (255, b""), "expired shell authenticated with UsePAM=" + pam)
                    finally:
                        server.terminate()
                        try:
                            server.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            server.kill()
                            server.wait(timeout=3)
        finally:
            backend.shutdown()
            backend.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
