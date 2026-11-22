# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

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
            if args[1] == "show":
                unit = args[2]
                agent = unit == removal.UNITS[0]
                user = "sovagrid" if agent else "sovagrid-tunnel"
                dropin = "/etc/systemd/system/sovagrid-agent.service.d/10-tunnel.conf" if agent else ""
                return 0, (f"FragmentPath={removal.UNIT_PATHS[unit]}\nDropInPaths={dropin}\n"
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
        with self.assertRaisesRegex(removal.Refused, "UNSUPPORTED_INSTALLATION"):
            self.preview()
        self.assertEqual(self.running, set(removal.UNITS))

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
