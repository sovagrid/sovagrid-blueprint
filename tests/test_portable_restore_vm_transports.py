# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""A CI transport ledger may authorize only the two actual enrollment producers."""

import base64
import contextlib
import copy
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid


spec = importlib.util.spec_from_file_location("portable_restore_transport_vm",
    Path(__file__).with_name("portable_restore_apply_vm.py"))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
fixture = vm.fixture_module()
spec = importlib.util.spec_from_file_location("portable_restore_transport_public_helper",
    Path(__file__).resolve().parents[1] / "deploy/remote_agent.py")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def record(kind, *, mode, raw=b""):
    result = {"kind": kind, "uid": 0, "gid": 0, "mode": mode, "dev": 1, "ino": 2}
    if kind == "file":
        result.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    return result


class TransportProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.expected, accounts, self.users, directories, self.files = {}, {}, {}, {}, {helper.POLICY_PATH: helper.POLICY}
        directories["/etc/ssh/sovagrid-tunnels"] = 0o755
        self.targets = []
        for index in range(2):
            identity = {key: str(uuid.UUID(int=10 * index + number + 1))
                        for number, key in enumerate(("request_id", "enrollment_id", "server_id"))}
            raw = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes([index]) * 32
            public, fingerprint = helper.public_key("ssh-ed25519 " + base64.b64encode(raw).decode())
            eid, sid = identity["enrollment_id"], identity["server_id"]
            name = helper.username(sid)
            self.expected[eid] = {"enrollment_id": eid, "server_id": sid, "username": name,
                "ssh_public_key": public, "ssh_key_fingerprint": fingerprint, "revoked": False}
            comment, home = "sovagrid-" + eid + "-hub-tunnel", "/var/empty/" + name
            accounts[name] = {"uid": 998 - index, "requested_uid": 998 - index,
                              "gid": 64200, "home": home, "comment": comment}
            self.users[name] = pwd.struct_passwd((name, "*", 998 - index, 64200, comment, home, "/usr/sbin/nologin"))
            directories[home] = 0o755
            self.files["/etc/ssh/sovagrid-tunnels/" + name] = (
                'restrict,port-forwarding,permitopen="127.0.0.1:8767",command="/bin/false" '
                + public + " sovagrid:" + sid + ":" + eid + "\n").encode()
            self.targets.append({"protocol": 1, "kind": "target", "identity": identity,
                "phase": "active", "source_manifest_sha256": "a" * 64, "pending_writes": {},
                "ssh_public_key": public, "ssh_key_fingerprint": fingerprint,
                "agent_token_sha256": "b" * 64, "local_port": 18767 + index})
        self.state = {"protocol": 1, "kind": "hub", "created_at": 1,
            "group": {"name": helper.HUB_GROUP, "gid": 64200}, "enrollments": self.expected,
            "accounts": accounts, "owned_files": {path: hashlib.sha256(raw).hexdigest() for path, raw in self.files.items()},
            "owned_directories": directories, "pending_writes": {},
            "file_metadata": {path: {"mode": 0o644, "gid": 0} for path in self.files}}
        self.inventory = {path: {"": record("dir", mode=0o755)} for path in directories}
        self.inventory["/etc/ssh/sovagrid-tunnels"].update({Path(path).name: record("file", mode=0o644, raw=raw)
            for path, raw in self.files.items() if path != helper.POLICY_PATH})
        self.inventory.update({path: {"": record("file", mode=0o644, raw=raw)} for path, raw in self.files.items()})
        self.inventory[helper.HUB_STATE_DIR] = {"": record("dir", mode=0o700),
            "lock": record("file", mode=0o600), "state.json": record("file", mode=0o600, raw=helper.encode(self.state) + b"\n")}
        self.runner = SimpleNamespace(locked=lambda *args, **kwargs: contextlib.nullcontext(),
            hub_state=lambda: self.state,
            files=SimpleNamespace(inspect=lambda *args, **kwargs: None, read=lambda path: self.files[path]))

    @contextlib.contextmanager
    def model(self):
        with (patch.object(helper, "Enrollment", return_value=self.runner),
              patch.object(vm.grp, "getgrnam", return_value=grp.struct_group((helper.HUB_GROUP, "*", 64200, []))),
              patch.object(vm.pwd, "getpwall", side_effect=lambda: list(self.users.values())),
              patch.object(vm.pwd, "getpwnam", side_effect=lambda name: self.users[name]),
              patch.object(vm.os, "getgrouplist", return_value=[64200]),
              patch.object(fixture, "inventory", side_effect=lambda path: copy.deepcopy(self.inventory[str(path)]))):
            yield

    def test_exact_two_enrollments_seal_only_closed_state_policy_keys_accounts(self):
        with self.model():
            sealed = vm.hub_transport_snapshot(fixture, helper, copy.deepcopy(self.expected))
        self.assertEqual(sealed["state"], self.state)
        self.assertEqual(set(sealed["users"]), set(self.users))
        self.assertEqual(set(sealed["trees"]), set(self.state["owned_directories"]) | {helper.HUB_STATE_DIR, helper.POLICY_PATH})

    def test_unknown_enrollment_account_state_leaf_key_home_policy_and_primary_member_refuse(self):
        cases = (
            lambda: self.state["enrollments"].update({str(uuid.uuid4()): {"foreign": True}}),
            lambda: self.state["accounts"].update({"foreign": {}}),
            lambda: self.inventory[helper.HUB_STATE_DIR].update({"foreign": record("file", mode=0o600)}),
            lambda: self.inventory["/etc/ssh/sovagrid-tunnels"].update({"foreign": record("file", mode=0o644)}),
            lambda: self.inventory[next(path for path in self.inventory if path.startswith("/var/empty/"))].update(
                {"foreign": record("file", mode=0o600)}),
            lambda: self.files.update({helper.POLICY_PATH: helper.POLICY + b"# foreign\n"}),
            lambda: self.users.update({"foreign": pwd.struct_passwd(("foreign", "*", 123, 64200, "", "/", "/bin/sh"))}),
            lambda: self.users.update({"alias": pwd.struct_passwd(("alias", "*", 998, 54321, "", "/", "/bin/sh"))}),
            lambda: self.state["pending_writes"].update({"foreign": {}}),
        )
        for index, mutate in enumerate(cases):
            with self.subTest(case=index):
                self.setUp()
                expected = copy.deepcopy(self.expected)
                mutate()
                with self.model(), self.assertRaises((RuntimeError, KeyError)):
                    vm.hub_transport_snapshot(fixture, helper, expected)

    def test_recorder_requires_both_guest_proofs_and_exact_web_journal(self):
        suffix = "012345abcdef"
        names = ("sovagrid-ci-target-" + suffix, "sovagrid-ci-web-target-" + suffix)
        provenance = {"manifest_sha256": "a" * 64, "trees": {}, "guests": dict.fromkeys(names, {"known": True})}
        state = {"container": names[0], "web_container": names[1]}
        journals = {}
        for name, target in zip(names, self.targets):
            identity = target["identity"]
            journals[identity["request_id"]] = {"request_id": identity["request_id"], "phase": "active",
                "cleanup_required": False, "hub_authorized": True,
                "target": helper.Enrollment.public_target(target),
                "registration": {"id": identity["enrollment_id"], "server_id": identity["server_id"], "state": "active"},
                "name": name if name == names[1] else "ci-remote-agent-" + suffix}
        def private(path, **kwargs):
            if str(path).endswith("sovagrid-remote-ci/state.json"):
                return state
            for name, target in zip(names, self.targets):
                if str(path) == "/var/lib/machines/" + name + "/var/lib/sovagrid-agent-enrollment/state.json":
                    return target
            return journals[path.stem]
        for wrong in (False, True):
            value = copy.deepcopy(provenance)
            with self.subTest(wrong_web_identity=wrong), patch.object(vm, "guard"), \
                    patch.object(vm, "fixture_module", return_value=fixture), \
                    patch.object(fixture, "ledger", return_value=value), patch.object(fixture, "source_pin"), \
                    patch.object(fixture, "save") as save, patch.object(vm, "load", return_value=helper), \
                    patch.object(vm, "private_json", side_effect=private), \
                    patch.object(vm, "guest_identity", return_value={"known": True}), \
                    patch.object(vm, "hub_transport_snapshot", return_value={"trees": {fixture.HUB_TRANSPORT: {"known": True}}}) as snapshot, \
                    patch.dict(os.environ, {"RUNNER_TEMP": "/unused"}):
                request = str(uuid.uuid4()) if wrong else self.targets[1]["identity"]["request_id"]
                if wrong:
                    with self.assertRaisesRegex(RuntimeError, "Web job differs"):
                        vm.record_hub_transports(request)
                    snapshot.assert_not_called()
                    save.assert_not_called()
                else:
                    vm.record_hub_transports(request)
                    self.assertEqual(snapshot.call_args.args[2], self.expected)
                    self.assertIn(fixture.HUB_TRANSPORT, value["trees"])
                    save.assert_called_once()

    def test_changed_or_interrupted_proof_refuses_before_any_revocation(self):
        for interrupted in (False, True):
            value = {"manifest_sha256": "a" * 64, "hub_transports": {"state": {"enrollments": self.expected}}}
            if interrupted:
                value["hub_transport_cleanup"] = {"phase": "revoking", "completed": []}
            with self.subTest(interrupted=interrupted), patch.object(vm, "fixture_module", return_value=fixture), \
                    patch.object(fixture, "ledger", return_value=value), patch.object(fixture, "save") as save, \
                    patch.object(fixture, "source_pin"), patch.object(vm, "verified_bundle"), \
                    patch.object(vm, "load", return_value=helper), \
                    patch.object(vm, "hub_transport_snapshot", return_value={"foreign": True}), \
                    patch.object(helper, "Enrollment") as enrollment, patch.object(vm, "command") as command:
                with self.assertRaises(RuntimeError):
                    vm.remove_hub_transports(Path("/unused"))
                enrollment.assert_not_called()
                command.assert_not_called()
                save.assert_not_called()

    def test_known_revoke_may_replace_only_state_and_remove_its_own_account_home_key(self):
        for tamper in (None, "unknown-key", "replaced-remaining-key", "replaced-lock", "wrong-state"):
            self.setUp()
            with self.subTest(tamper=tamper), self.model():
                proof = vm.hub_transport_snapshot(fixture, helper, copy.deepcopy(self.expected))
                after = copy.deepcopy(self.state)
                eid, entry = next(iter(self.expected.items()))
                name = entry["username"]
                after["enrollments"][eid]["revoked"] = True
                del after["accounts"][name]
                del after["owned_directories"]["/var/empty/" + name]
                del after["owned_files"]["/etc/ssh/sovagrid-tunnels/" + name]
                del after["file_metadata"]["/etc/ssh/sovagrid-tunnels/" + name]
                del self.users[name]
                del self.inventory["/etc/ssh/sovagrid-tunnels"][name]
                state = record("file", mode=0o600, raw=helper.encode(after) + b"\n")
                state["ino"] = 3  # The public helper atomically publishes the new state.
                self.inventory[helper.HUB_STATE_DIR]["state.json"] = state
                if tamper == "unknown-key":
                    self.inventory["/etc/ssh/sovagrid-tunnels"]["foreign"] = record("file", mode=0o644)
                if tamper == "replaced-remaining-key":
                    remaining = next(iter(self.users))
                    self.inventory["/etc/ssh/sovagrid-tunnels"][remaining]["ino"] += 1
                if tamper == "replaced-lock": self.inventory[helper.HUB_STATE_DIR]["lock"]["ino"] += 1
                if tamper == "wrong-state": state["sha256"] = "f" * 64
                if tamper:
                    with self.assertRaises(RuntimeError): vm.check_transport_remainder(fixture, helper, proof, after)
                else:
                    self.assertEqual(vm.check_transport_remainder(fixture, helper, proof, after)["state.json"], state)

    def test_expected_cleanup_transitions_match_real_public_revoke_on_temporary_root(self):
        """Real file/state mutations, fake NSS only; no host accounts or services."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for path in self.state["owned_directories"]:
                (root / path.lstrip("/")).mkdir(parents=True, mode=0o755)
            for path, raw in self.files.items():
                location = root / path.lstrip("/")
                location.parent.mkdir(parents=True, exist_ok=True)
                location.write_bytes(raw)
                location.chmod(0o644)
            location = root / helper.HUB_STATE.lstrip("/")
            location.parent.mkdir(parents=True, mode=0o700)
            location.write_text(json.dumps(self.state))
            location.chmod(0o600)
            calls = []
            def command(args, **kwargs):
                self.assertEqual(args[:1], ["/usr/sbin/userdel"])
                self.assertIn(args[1], self.users)
                calls.append(args[1])
                del self.users[args[1]]
                return 0, b""
            def user(name):
                if name not in self.users: raise KeyError(name)
                return self.users[name]
            runner = helper.Enrollment(root=root, owner=os.getuid(), commands=SimpleNamespace(run=command))
            after = copy.deepcopy(self.state)
            with (patch.object(helper.pwd, "getpwnam", side_effect=user),
                  patch.object(helper.grp, "getgrnam", return_value=grp.struct_group((helper.HUB_GROUP, "*", 64200, []))),
                  patch.object(helper.os, "getgrouplist", return_value=[64200]),
                  patch.object(runner, "check_cas"), patch.object(runner, "process_snapshot", return_value={})):
                for eid, entry in sorted(self.expected.items()):
                    result = runner.hub_revoke({"enrollment_id": eid, "server_id": entry["server_id"],
                        "ssh_key_fingerprint": entry["ssh_key_fingerprint"], "expected": {}})
                    self.assertEqual(result, {"revoked": True, "cleanup_required": False})
                    name = entry["username"]
                    after["enrollments"][eid]["revoked"] = True
                    del after["accounts"][name]
                    del after["owned_directories"]["/var/empty/" + name]
                    del after["owned_files"]["/etc/ssh/sovagrid-tunnels/" + name]
                    del after["file_metadata"]["/etc/ssh/sovagrid-tunnels/" + name]
                    self.assertEqual(runner.hub_state(), after)
                    self.assertFalse((root / "var/empty" / name).exists())
                self.assertEqual(set(calls), {entry["username"] for entry in self.expected.values()})
                self.assertEqual(list((root / "etc/ssh/sovagrid-tunnels").iterdir()), [])
                self.assertEqual((root / helper.POLICY_PATH.lstrip("/")).read_bytes(), helper.POLICY)
                self.assertEqual(runner.hub_state()["accounts"], {})

    def test_private_state_tree_never_adopts_extra_files_symlinks_hardlinks_or_nonempty_lock(self):
        original = fixture.inventory
        for kind in ("good", "extra", "symlink", "hardlink", "lock"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                root.chmod(0o700)
                for name in ("lock", "state.json"):
                    (root / name).write_bytes(b"" if name == "lock" else b"{}")
                    (root / name).chmod(0o600)
                if kind == "extra": (root / "foreign").write_bytes(b"keep")
                if kind == "symlink": (root / "foreign").symlink_to(root / "state.json")
                if kind == "hardlink": os.link(root / "state.json", root / "foreign")
                if kind == "lock": (root / "lock").write_bytes(b"foreign")
                def inventory(_path):
                    records = original(root)
                    for item in records.values(): item["uid"] = item["gid"] = 0
                    return records
                with patch.object(fixture, "inventory", side_effect=inventory):
                    if kind == "good": self.assertEqual(set(fixture.transport_inventory()), {"", "lock", "state.json"})
                    else:
                        with self.assertRaises(RuntimeError): fixture.transport_inventory()
                self.assertTrue((root / "state.json").exists())

    def test_final_shared_cleanup_cannot_adopt_same_byte_lock_or_state_replacement(self):
        original = fixture.inventory
        for changed in (None, "lock", "state.json"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for name in ("lock", "state.json"):
                    (root / name).write_bytes(b"" if name == "lock" else b"{}\n")
                    (root / name).chmod(0o600)
                sealed = original(root)
                if changed:
                    replacement = root / "replacement"
                    replacement.write_bytes((root / changed).read_bytes())
                    replacement.chmod(0o600)
                    os.replace(replacement, root / changed)
                value = {"trees": {fixture.HUB_TRANSPORT: sealed}, "hub_transports": {},
                         "hub_transport_cleanup": {"phase": "revoking"}}
                runner = SimpleNamespace(locked=lambda *args, **kwargs: contextlib.nullcontext(), hub_state=lambda: {})
                with (patch.object(fixture, "inventory", side_effect=lambda path: original(root)),
                      patch.object(fixture, "save") as save):
                    if changed:
                        with self.assertRaisesRegex(RuntimeError, "producer-owned fixture changed"):
                            vm.finish_hub_transport_cleanup(fixture, helper, runner, value, {})
                        save.assert_not_called()
                        self.assertNotIn("removed", value["hub_transports"])
                    else:
                        vm.finish_hub_transport_cleanup(fixture, helper, runner, value, {})
                        self.assertIs(value["hub_transports"]["removed"], True)
                        self.assertIs(value["trees"][fixture.HUB_TRANSPORT], sealed)
                        save.assert_called_once()


if __name__ == "__main__":
    unittest.main()
