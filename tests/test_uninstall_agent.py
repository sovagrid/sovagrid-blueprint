# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
import base64
import grp
import hashlib
import json
import os
import pwd
from pathlib import Path
from types import SimpleNamespace
import stat
import tempfile
import unittest
from unittest.mock import patch
import uuid

from deploy import agent_features
from deploy import uninstall_agent as removal


class AgentRemovalTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.worker = removal.AgentRemoval(self.root, owner=os.geteuid())
        self.identity = {key: str(uuid.uuid4()) for key in ("request_id", "enrollment_id", "server_id")}
        public_blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + b"a" * 32
        self.key = b"ssh-ed25519 " + base64.b64encode(public_blob)
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(public_blob).digest()).decode().rstrip("=")
        self.request = {key: self.identity[key] for key in ("enrollment_id", "server_id")}
        self.request["ssh_key_fingerprint"] = fingerprint
        source_paths = {
            "/opt/sovagrid-agent/sovagrid_agent/__main__.py": b"# agent fixture\n",
            "/opt/sovagrid-agent/sovagrid_agent/terminal_policy.py": b"# terminal policy fixture\n",
            "/opt/sovagrid-agent/LICENSE": b"license\n",
            "/opt/sovagrid-agent/NOTICE": b"notice\n",
            "/opt/sovagrid-agent/ATTRIBUTION.md": b"attribution\n",
            "/opt/sovagrid-agent/deploy/sovagrid-agent.service": b"# unit source fixture\n",
            removal.HELPER: (Path(removal.__file__).with_name("remote_agent.py")).read_bytes(),
        }
        digest_map = {("sovagrid-agent/" + path.removeprefix("/opt/sovagrid-agent/")
                       if path != removal.HELPER else removal.SOURCE_ENTRY): removal.digest(data)
                      for path, data in source_paths.items()}
        manifest = removal.encode({"sha256": digest_map})
        self.token = b"a" * 43
        data = {**source_paths, removal.MANIFEST: manifest,
                "/etc/sovagrid/agent.token": self.token + b"\n",
                "/etc/sovagrid-agent-tunnel/id_ed25519.pub": self.key + b" sovagrid:"
                + self.identity["enrollment_id"].encode() + b"\n"}
        owners = (set(removal.CORE_DIRECTORIES)
                  | {"/opt/sovagrid-agent/sovagrid_agent", "/opt/sovagrid-agent/deploy"})
        file_modes = {}
        for path in set(data) | removal.CORE_FILES:
            mode = (0o600 if path.endswith("/id_ed25519") else
                    0o640 if path.endswith("/agent.token") else 0o644)
            data.setdefault(path, b"fixture\n")
            self.write(path, data[path], mode)
            file_modes[path] = {"mode": mode, "gid": self.worker.path(path).stat().st_gid}
        token_path = "/etc/sovagrid/agent.token"
        agent_gid = file_modes[token_path]["gid"]
        if agent_gid == 0:
            agent_gid = 1
            os.chown(self.worker.path(token_path), -1, agent_gid)
            file_modes[token_path]["gid"] = agent_gid
        for path in owners:
            self.worker.path(path).mkdir(parents=True, exist_ok=True)
        state = {"protocol": 1, "kind": "target", "identity": self.identity, "phase": "active",
                 "source_manifest_sha256": removal.digest(manifest),
                 "source_files": {path: removal.digest(raw) for path, raw in source_paths.items()},
                 "owned_files": {path: removal.digest(raw) for path, raw in data.items()},
                 "file_metadata": file_modes, "owned_directories": {path: 0o755 for path in owners},
                 "pending_writes": {}, "accounts": {"sovagrid": {"uid": 64200, "gid": agent_gid},
                                                  "sovagrid-tunnel": {"uid": 64201, "gid": 64201}},
                 "agent_token_sha256": removal.digest(self.token), "ssh_public_key": self.key.decode(),
                 "ssh_key_fingerprint": fingerprint}
        self.write(removal.STATE, removal.encode(state), 0o600)
        self.worker.path(removal.JOURNAL).chmod(0o700)
        self.write(removal.JOURNAL + "/lock", b"", 0o600)
        self.other = self.write("/etc/application/private.txt", b"unrelated", 0o600)
        self.calls = []
        self.running = set(removal.UNITS)
        self.original_load_helper = self.worker.load_helper
        patcher = patch.object(self.worker, "load_helper", self.load_helper)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, path, data, mode):
        item = self.worker.path(path)
        item.parent.mkdir(parents=True, exist_ok=True)
        item.write_bytes(data)
        item.chmod(mode)
        return item

    def state(self):
        return json.loads(self.worker.path(removal.STATE).read_text())

    def load_helper(self, state):
        helper = self.original_load_helper(state)
        def command(_commands, args, **_kwargs):
            self.calls.append(args)
            if args[0] == "/usr/bin/ssh-keygen":
                return 0, self.key + b"\n"
            if args[0] == "/usr/bin/getent":
                return 0, b"sovagrid-shell:*NP*:20000:0:99999:7::1:\n"
            if args[0] == "/usr/sbin/userdel" and args[-1] == "sovagrid-shell":
                self.shell_account = False
            if args[0] == "/usr/sbin/groupdel" and args[-1] == "sovagrid-shell":
                self.shell_group = False
            if args[1] == "show":
                unit = args[2]
                path = "/etc/systemd/system/" + unit
                if not self.worker.path(path).exists():
                    return 1, b"LoadState=not-found\n"
                agent = unit == removal.UNITS[0]
                user = "sovagrid" if agent else "sovagrid-shell" if unit in removal.FEATURE_UNITS else "sovagrid-tunnel"
                dropin = "/etc/systemd/system/sovagrid-agent.service.d/10-tunnel.conf" if agent else ""
                return 0, (f"FragmentPath={path}\nDropInPaths={dropin}\n"
                           f"User={user}\nGroup={user}\nLoadState=loaded\n").encode()
            if args[1] == "disable":
                self.running.discard(args[-1])
            if args[1] == "is-active":
                return (0 if args[-1] in self.running else 3), b""
            return 0, b""
        helper.Commands.run = command
        helper.Enrollment.reconcile_account = lambda *_args: object()
        helper.Enrollment.process_snapshot = lambda *_args: {}
        return helper

    def preview(self):
        return self.worker.run("preview", self.request)

    def test_reviewed_cleanup_preserves_other_files_and_can_be_retried(self):
        before = self.worker.path(removal.STATE).read_bytes()
        preview = self.preview()
        self.assertEqual(preview["state"], "ready")
        self.assertEqual(self.worker.path(removal.STATE).read_bytes(), before)
        request = {**self.request, "expected_revision": preview["revision"]}
        result = self.worker.run("apply", request)
        self.assertEqual(result, {**preview, "state": "removed"})
        self.assertEqual(self.worker.run("apply", request), result)
        self.assertEqual(self.preview(), result)
        self.assertFalse(self.worker.path(removal.HELPER).exists())
        self.assertFalse(self.worker.path(removal.MANIFEST).exists())
        self.assertFalse(self.worker.path("/etc/sovagrid").exists())
        self.assertFalse(self.running)
        self.assertEqual(self.other.read_bytes(), b"unrelated")
        self.assertTrue(self.state()["removed"])
        self.assertNotIn(self.token, self.worker.path(removal.STATE).read_bytes())

    def test_target_and_review_revision_are_required_before_stopping_services(self):
        preview = self.preview()
        with self.assertRaisesRegex(removal.Refused, "STALE_PREVIEW"):
            self.worker.run("apply", {**self.request, "expected_revision": "a" * 64})
        with self.assertRaisesRegex(removal.Refused, "WRONG_AGENT"):
            self.worker.run("preview", {**self.request, "server_id": str(uuid.uuid4())})
        with self.assertRaisesRegex(removal.Refused, "WRONG_AGENT"):
            self.worker.run("preview", {**self.request, "ssh_key_fingerprint": "SHA256:" + "x" * 43})
        self.assertEqual(self.state()["phase"], "active")
        self.assertEqual(self.running, set(removal.UNITS))
        self.assertRegex(preview["revision"], r"^[a-f0-9]{64}$")

    def test_changed_helper_or_user_data_prevents_removal(self):
        helper = self.worker.path(removal.HELPER)
        original = helper.read_bytes()
        helper.write_bytes(b"raise Exception('unexpected code')\n")
        with self.assertRaisesRegex(removal.Refused, "SOURCE_CHANGED"):
            self.preview()
        helper.write_bytes(original)
        other = self.write("/var/lib/sovagrid-agent/custom-export", b"keep", 0o600)
        with self.assertRaisesRegex(removal.Refused, "UNOWNED_DATA"):
            self.preview()
        self.assertEqual(other.read_bytes(), b"keep")
        other.unlink()
        self.write(removal.JOURNAL + "/features.json", b"{}", 0o600)
        with self.assertRaisesRegex(removal.Refused, "FEATURES_NOT_READY"):
            self.preview()
        self.assertEqual(self.running, set(removal.UNITS))

    def enable_features(self, *, terminal=True, files=True, explicit=False):
        state = self.state()
        state["local_port"] = 18767
        state["accounts"]["sovagrid"].update(uid=os.getuid() or 10001, home=agent_features.AGENT_HOME,
                                            comment="fixture-agent")
        account = state["accounts"]["sovagrid"]
        self.shell_account = self.shell_group = terminal
        shell_comment = "sovagrid-features-" + self.identity["enrollment_id"]

        def getpwnam(name):
            if name == "sovagrid":
                return SimpleNamespace(pw_uid=account["uid"], pw_gid=account["gid"], pw_gecos=account["comment"],
                                       pw_dir=account["home"], pw_shell="/usr/sbin/nologin")
            if name == agent_features.SHELL_NAME and self.shell_account:
                return SimpleNamespace(pw_uid=agent_features.SHELL_UID, pw_gid=agent_features.SHELL_UID,
                                       pw_gecos=shell_comment, pw_dir=agent_features.SHELL_LOGIN_HOME,
                                       pw_shell="/usr/sbin/nologin")
            raise KeyError(name)

        def getgrnam(name):
            if name == agent_features.SHELL_NAME and self.shell_group:
                return SimpleNamespace(gr_gid=agent_features.SHELL_UID, gr_mem=[])
            raise KeyError(name)

        for patcher in (patch.object(pwd, "getpwnam", side_effect=getpwnam),
                        patch.object(grp, "getgrnam", side_effect=getgrnam),
                        patch.object(os, "getgrouplist", side_effect=lambda _name, group: [group])):
            patcher.start()
            self.addCleanup(patcher.stop)

        config_raw = {"hub_url": "https://localhost:18767", "server_id": self.identity["server_id"],
                      "token_file": "/etc/sovagrid/agent.token", "ca_file": "/etc/sovagrid/hub-ca.pem",
                      "interval_seconds": 30, "allow_remote_commands": files or not explicit,
                      "allow_interactive_terminal": terminal, "allow_file_manager": files,
                      "allow_systemd_journal": False, "journal_units": [],
                      "file_roots": {"workspace": agent_features.WORKSPACE} if files else {}}
        if explicit:
            config_raw["terminal_permission_mode"] = "explicit"
        raw = removal.encode(config_raw) + b"\n"
        config = self.write(agent_features.CONFIG, raw, 0o640)
        if os.getuid() == 0:
            os.chown(config, -1, account["gid"])
        state["owned_files"][agent_features.CONFIG] = removal.digest(raw)
        state["file_metadata"][agent_features.CONFIG] = {"mode": 0o640, "gid": account["gid"]}
        self.write(removal.STATE, removal.encode(state), 0o600)
        sidecar = {"protocol": 2 if explicit else 1, "kind": "target-features", "phase": "ready",
                   "identity": {**self.identity, "agent_token_sha256": state["agent_token_sha256"]},
                   "pending_features": None, "pending_writes": {}, "owned_files": {}, "data_directories": {},
                   "shell_account": None}
        if terminal:
            sidecar["shell_account"] = {"uid": agent_features.SHELL_UID, "gid": agent_features.SHELL_UID,
                                         "comment": shell_comment, "group_started": True, "user_started": True}
            for unit in removal.FEATURE_UNITS:
                path = "/etc/systemd/system/" + unit
                data = b"# terminal test unit\n"
                self.write(path, data, 0o644)
                sidecar["owned_files"][path] = removal.digest(data)
            self.running.update(removal.FEATURE_UNITS)

        saved_inode_owners = {}
        for name, wanted, enabled in ((agent_features.WORKSPACE, (account["uid"], account["gid"]), files),
                                      (agent_features.SHELL_HOME, (agent_features.SHELL_UID, agent_features.SHELL_UID), terminal)):
            if not enabled:
                continue
            item = self.worker.path(name)
            item.mkdir(mode=0o700)
            (item / "note").write_text("keep " + removal.FEATURE_DATA[name])
            info = item.lstat()
            device = (info.st_dev, info.st_ino)
            saved_inode_owners[device] = wanted
            sidecar["data_directories"][name] = {"uid": wanted[0], "gid": wanted[1], "mode": 0o700, "ready": True,
                                                 "publication": {"staging": str(Path(name).parent / ".sovagrid-feature-data.test0001"),
                                                                 "dev": device[0], "ino": device[1]}}

        native_lstat = Path.lstat

        def lstat(item):
            info = native_lstat(item)
            pair = (info.st_dev, info.st_ino)
            if pair not in saved_inode_owners:
                return info
            uid, gid = saved_inode_owners[pair]
            return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino, st_mode=info.st_mode,
                                   st_uid=uid, st_gid=gid)

        patcher = patch.object(Path, "lstat", lstat)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.write(removal.FEATURES, removal.encode(sidecar), 0o600)
        return self.worker.path(removal.JOURNAL + "/retained-" + self.identity["enrollment_id"])

    def test_featured_agent_preserves_data_and_removes_terminal_resources(self):
        retained = self.enable_features()
        request = {**self.request, "expected_revision": self.preview()["revision"]}
        self.assertFalse(retained.exists())
        self.assertEqual(self.worker.run("apply", request)["state"], "removed")
        for name in ("workspace", "terminal-home"):
            self.assertEqual((retained / name / "note").read_text(), "keep " + name)
        self.assertEqual(stat.S_IMODE(retained.stat().st_mode), 0o700)
        self.assertFalse(self.worker.path(removal.FEATURES).exists())
        self.assertFalse(self.running)
        self.assertFalse(self.shell_account)
        self.assertFalse(self.shell_group)
        self.assertTrue(all(not self.worker.path("/etc/systemd/system/" + unit).exists() for unit in removal.FEATURE_UNITS))
        self.assertEqual(self.worker.run("apply", request)["state"], "removed")

    def test_featured_agent_resumes_after_data_was_already_retained(self):
        retained = self.enable_features()
        request = {**self.request, "expected_revision": self.preview()["revision"]}
        preserve = removal.FeatureRemoval.preserve_data

        def interrupted(features, moves):
            preserve(features, moves)
            raise OSError("fixture interruption")

        with patch.object(removal.FeatureRemoval, "preserve_data", interrupted):
            with self.assertRaisesRegex(OSError, "fixture interruption"):
                self.worker.run("apply", request)
        self.assertEqual(self.state()["uninstallation"]["step"], "features")
        self.assertEqual(self.worker.run("apply", request)["state"], "removed")
        self.assertEqual((retained / "workspace/note").read_text(), "keep workspace")

    def test_feature_unit_changed_after_review_prevents_a_stop(self):
        self.enable_features(files=False, explicit=True)
        request = {**self.request, "expected_revision": self.preview()["revision"]}
        unit = "/etc/systemd/system/" + removal.FEATURE_UNITS[0]
        self.write(unit, b"foreign terminal socket", 0o644)
        original = set(self.running)
        with self.assertRaisesRegex(removal.Refused, "OWNERSHIP_CONFLICT"):
            self.worker.run("apply", request)
        self.assertEqual(self.running, original)
        self.assertTrue(self.shell_account)
        self.assertEqual(self.state()["phase"], "active")

    def test_retry_after_crash_deleting_helper_does_not_need_helper_source(self):
        preview = self.preview()
        request = {**self.request, "expected_revision": preview["revision"]}

        def partial(_state):
            self.worker.path(removal.HELPER).unlink()
            raise OSError("fixture interruption")

        with patch.object(self.worker, "finish", side_effect=partial):
            with self.assertRaisesRegex(OSError, "fixture interruption"):
                self.worker.run("apply", request)
        self.assertEqual(self.state()["uninstallation"]["step"], "installer")
        self.assertFalse(self.worker.path(removal.HELPER).exists())
        self.assertEqual(self.worker.run("apply", request)["state"], "removed")
        self.assertEqual(self.preview()["state"], "removed")


if __name__ == "__main__":
    unittest.main()
