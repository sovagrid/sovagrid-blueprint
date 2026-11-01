# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Live restoration metadata is derived from tar, never private-stage modes."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deploy import host_restore as restore
from deploy import portable_restore_apply as apply


IDENTITY = "a" * 32


class ResourcePlanTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.root = self.folder / "root"
        self.root.mkdir()
        for absolute in ("/etc/systemd/system", "/etc/sysctl.d", "/opt", "/var/lib", "/var/cache", "/run",
                         "/usr/local/bin", "/usr/local/libexec"):
            (self.root / absolute.lstrip("/")).mkdir(parents=True, exist_ok=True)
        self.staged = self.root / "var/lib/.sovagrid-host-restore-staging" / IDENTITY
        self.staged.mkdir(parents=True)
        self.entries = {
            "/etc/sovagrid/agent.json": {"raw": json.dumps({"allow_file_manager": True,
                "file_roots": {"workspace": "/var/lib/sovagrid-agent/files"}}).encode(),
                "uid": 0, "gid": 997, "mode": 0o640},
            "/etc/sovagrid/agent.token": {"raw": b"test-only-token", "uid": 0, "gid": 997, "mode": 0o640},
            "/etc/sovagrid/.terminal-unit-managed-by-run-sh": {"raw": b"test-only-marker", "uid": 0, "gid": 0, "mode": 0o600},
            "/var/lib/sovagrid/hub": {"raw": None, "uid": 10001, "gid": 10001, "mode": 0o700},
            "/var/lib/sovagrid/hub/hub.sqlite": {"raw": b"test-only-db", "uid": 10001, "gid": 10001, "mode": 0o600},
            "/opt/sovagrid-src": {"raw": None, "uid": 0, "gid": 0, "mode": 0o755},
            "/opt/sovagrid-src/sovagrid-bundle.json": {"raw": b"{}", "uid": 0, "gid": 0, "mode": 0o644},
        }
        self.states = {}
        self.add_unit("sovagrid-agent.service", "multi-user.target", active=True)
        self.add_unit("sovagrid-web-agent-control.socket", "sockets.target", active=True)
        self.add_unit("sovagrid-web-agent-control.service", None, active=True)
        self.add_unit("sovagrid-release-feed.timer", "timers.target", active=True)
        self.identities = {"groups": {"sovagrid": 997, "sovagrid-hub": 10001, "sovagrid-web": 10002,
                                      "sovagrid-shell": 10003, "sovagrid-web-agent": 10005},
                           "users": {"sovagrid-hub": 10001, "sovagrid-web": 10002, "sovagrid-shell": 10003}}
        patchers = [
            patch.object(restore.backup, "ROOT", self.root),
            patch.object(restore.backup, "ROOT_UID", os.getuid()),
            patch.object(restore.backup, "ROOT_GID", os.getgid()),
            patch.object(restore, "_inspect_tar", return_value={"identities": self.identities}),
            patch.object(apply.grp, "getgrnam", side_effect=KeyError),
            patch.object(apply.grp, "getgrgid", side_effect=KeyError),
            patch.object(apply.pwd, "getpwnam", side_effect=KeyError),
            patch.object(apply.pwd, "getpwuid", side_effect=KeyError)]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def add_unit(self, name, target, *, active):
        raw = b"[Service]\nExecStart=/bin/true\n" if name.endswith(".service") else b"[Socket]\nListenStream=/run/test.sock\n"
        if target is not None:
            raw += ("[Install]\nWantedBy=" + target + "\n").encode()
        self.entries["/etc/systemd/system/" + name] = {"raw": raw, "uid": 0, "gid": 0, "mode": 0o644}
        self.states[name] = {"active": active, "enablement": "enabled" if target else "static",
                             "sha256": hashlib.sha256(raw).hexdigest()}

    def inputs(self):
        archive = self.folder / "archive.tar.gz"
        with tarfile.open(archive, "w:gz") as stream:
            for absolute, entry in self.entries.items():
                path = self.staged / absolute.lstrip("/")
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = entry["raw"]
                if raw is None:
                    path.mkdir(exist_ok=True)
                    path.chmod(0o700)
                else:
                    path.write_bytes(raw)
                    path.chmod(0o600)
                member = tarfile.TarInfo(absolute.lstrip("/"))
                member.uid, member.gid, member.mode = entry["uid"], entry["gid"], entry["mode"]
                member.mtime = 1_700_000_000
                member.type = tarfile.DIRTYPE if raw is None else tarfile.REGTYPE
                member.size = len(raw) if raw is not None else 0
                stream.addfile(member, io.BytesIO(raw) if raw is not None else None)
        descriptor = os.open(archive, os.O_RDONLY)
        self.addCleanup(os.close, descriptor)
        return SimpleNamespace(
            identity=IDENTITY, restore=restore, host={"layout": "full"}, host_fd=descriptor,
            unchanged=lambda: None,
            bindings={key: "a" * 64 for key in apply.BINDINGS if key != "resource_manifest_sha256"},
            metadata={"portable_receipt": (None, json.dumps({"unit_states": self.states}).encode(), None)},
            images={"exported_configs": {"hub": "sha256:" + "a" * 64, "web": "sha256:" + "b" * 64},
                    "rootfs_sha256": {"hub": "c" * 64, "web": "d" * 64}},
            platforms={service: {"os": "linux", "architecture": "amd64"} for service in ("hub", "web")})

    def test_implicit_live_parents_and_runtime_paths_use_installer_contract(self):
        result = apply.build_resource_plan(self.inputs())
        resources = {resource["target"]: resource for resource in result["resources"]}
        etc = resources["/etc/sovagrid"]["entries"][""]
        self.assertEqual((etc["uid"], etc["gid"], etc["mode"]), (0, 997, 0o750))
        data = resources["/var/lib/sovagrid"]["entries"]
        self.assertEqual((data[""]["uid"], data[""]["gid"], data[""]["mode"]), (0, 0, 0o700))
        self.assertEqual((data["hub"]["uid"], data["hub"]["gid"], data["hub"]["mode"]), (10001, 10001, 0o700))
        agent = resources["/var/lib/sovagrid-agent"]["entries"]
        self.assertEqual((agent[""]["uid"], agent[""]["gid"], agent[""]["mode"]), (999, 997, 0o700))
        self.assertEqual(agent["files"], agent[""])
        self.assertEqual(resources["/var/lib/sovagrid-shell"]["entries"][""]["uid"], 10003)
        self.assertFalse((self.root / "etc/sovagrid").exists())
        self.assertFalse((self.root / "var/lib/sovagrid").exists())

    def test_backup_broker_workspaces_are_planned_empty_private_and_never_adopted(self):
        self.add_unit("sovagrid-hub-backup-control.service", None, active=False)
        result = apply.build_resource_plan(self.inputs())
        resources = {resource["target"]: resource for resource in result["resources"]}
        for absolute in ("/opt/sovagrid-candidates", "/var/lib/sovagrid-host-backup-operations"):
            self.assertEqual(resources[absolute]["entries"], {
                "": {"kind": "dir", "uid": 0, "gid": 0, "mode": 0o700, "mtime": 0}})
            path = self.root / absolute.lstrip("/")
            self.assertFalse(path.exists())
            path.mkdir(mode=0o700)
            (path / "foreign-data").write_bytes(b"preserve")
            with self.assertRaisesRegex(apply.Refused, "RESTORE_RUNTIME_STATE_PRESENT"):
                apply.build_resource_plan(self.inputs())
            self.assertEqual((path / "foreign-data").read_bytes(), b"preserve")
            (path / "foreign-data").unlink()
            path.rmdir()

    def test_web_restore_cache_is_fresh_journaled_and_existing_data_is_not_adopted(self):
        result = apply.build_resource_plan(self.inputs())
        resource = next(item for item in result["resources"] if item["target"] == "/var/cache/sovagrid-web-restores")
        self.assertEqual(resource["entries"], {"": {"kind": "dir", "uid": 0, "gid": 0,
                                                     "mode": 0o700, "mtime": 0}})
        cache = self.root / "var/cache/sovagrid-web-restores"
        self.assertFalse(cache.exists())
        cache.mkdir(mode=0o700)
        foreign = cache / "foreign-file"
        foreign.write_bytes(b"preserve")
        with self.assertRaisesRegex(apply.Refused, "RESTORE_RUNTIME_STATE_PRESENT"):
            apply.build_resource_plan(self.inputs())
        self.assertEqual(foreign.read_bytes(), b"preserve")

    def test_unit_order_is_socket_then_consumers_then_timers(self):
        result = apply.build_resource_plan(self.inputs())
        self.assertEqual(result["before_compose"], ["sovagrid-web-agent-control.socket", "sovagrid-web-agent-control.service"])
        self.assertEqual(result["after_compose"], ["sovagrid-agent.service"])
        self.assertEqual(result["timers"], ["sovagrid-release-feed.timer"])
        self.assertEqual(set(result["parents"]), {
            "/etc/systemd/system/multi-user.target.wants", "/etc/systemd/system/sockets.target.wants",
            "/etc/systemd/system/timers.target.wants", "/run/sovagrid-web-agent"})

    def test_resource_manifest_digest_binds_owners_file_hashes_and_unit_states(self):
        result = apply.build_resource_plan(self.inputs())
        bindings = result.pop("bindings")
        self.assertEqual(bindings["resource_manifest_sha256"], hashlib.sha256(apply._canonical(result)).hexdigest())
        result["resources"][0]["entries"][""]["gid"] += 1
        self.assertNotEqual(bindings["resource_manifest_sha256"], hashlib.sha256(apply._canonical(result)).hexdigest())

    def test_existing_matching_named_identity_is_not_adopted(self):
        inputs = self.inputs()
        with patch.object(apply.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=997)):
            with self.assertRaisesRegex(apply.Refused, "RESTORE_IDENTITY_EXISTS"):
                apply.build_resource_plan(inputs)

    def test_arbitrary_workspace_and_kernel_routing_state_are_blocked(self):
        entry = self.entries["/etc/sovagrid/agent.json"]
        entry["raw"] = json.dumps({"allow_file_manager": True, "file_roots": {"root": "/"}}).encode()
        with self.assertRaisesRegex(apply.Refused, "RESTORE_FILE_ROOTS_UNSUPPORTED"):
            apply.build_resource_plan(self.inputs())
        entry["raw"] = b"{}"
        self.add_unit("sovagrid-vpn-routing.service", "multi-user.target", active=True)
        with self.assertRaisesRegex(apply.Refused, "RESTORE_ROUTING_STATE_UNSUPPORTED"):
            apply.build_resource_plan(self.inputs())
        self.states["sovagrid-vpn-routing.service"]["active"] = False
        with self.assertRaisesRegex(apply.Refused, "RESTORE_ROUTING_STATE_UNSUPPORTED"):
            apply.build_resource_plan(self.inputs())

    def test_dropin_and_foreign_activation_route_block_readonly_plan_before_changes(self):
        for directory in ("run/systemd/system/service.d", "usr/lib/systemd/system/sovagrid-.service.d"):
            target = self.root / directory
            target.mkdir(parents=True)
            with self.assertRaisesRegex(apply.Refused, "RESTORE_UNIT_OVERRIDE_PRESENT"):
                apply.build_resource_plan(self.inputs())
            target.rmdir()
        target = self.root / "etc/systemd/system/foreign.target.wants"
        target.mkdir()
        (target / "sovagrid-agent.service").symlink_to("../sovagrid-agent.service")
        with self.assertRaisesRegex(apply.Refused, "RESTORE_ENABLEMENT_CHANGED"):
            apply.build_resource_plan(self.inputs())
        self.assertFalse((self.root / "etc/sovagrid").exists())

    def test_public_endpoint_failure_is_propagated_before_host_mutation(self):
        with patch.object(apply, "_public_target_check", side_effect=apply.Refused("PUBLIC_ENDPOINT_MISMATCH")):
            with self.assertRaisesRegex(apply.Refused, "PUBLIC_ENDPOINT_MISMATCH"):
                apply.build_resource_plan(self.inputs())
        self.assertFalse((self.root / "etc/sovagrid").exists())

    def test_resource_tree_digest_matches_actual_publisher_traversal(self):
        path = self.folder / "resource"
        path.mkdir(mode=0o700)
        (path / "sub").mkdir(mode=0o750)
        (path / "sub").chmod(0o750)
        (path / "sub/token").write_bytes(b"test")
        (path / "sub/token").chmod(0o600)
        entries = {"": {"kind": "dir", "uid": os.getuid(), "gid": os.getgid(), "mode": 0o700},
                   "sub": {"kind": "dir", "uid": os.getuid(), "gid": os.getgid(), "mode": 0o750},
                   "sub/token": {"kind": "file", "uid": os.getuid(), "gid": os.getgid(), "mode": 0o600,
                                 "size": 4, "sha256": hashlib.sha256(b"test").hexdigest()}}
        descriptor = os.open(self.folder, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.assertEqual(apply._resource_digest(entries), apply.tree_proof(descriptor, "resource")["sha256"])
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
