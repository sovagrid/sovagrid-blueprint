# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Fail-closed and rollback contracts for promoted Hub Docker inventory."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import time
import types
import unittest
from unittest import mock


DEPLOY = Path(__file__).resolve().parents[1] / "deploy"


def module(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, DEPLOY / file)
    assert spec and spec.loader
    result = importlib.util.module_from_spec(spec)
    # dataclasses resolves postponed annotations through sys.modules on 3.13.
    sys.modules[name] = result
    try:
        spec.loader.exec_module(result)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return result


inventory = module("sovagrid_local_container_inventory_test", "local_container_inventory.py")
update = module("sovagrid_hub_only_containers_test", "hub_only_update.py")
backup = module("sovagrid_host_backup_local_containers_test", "host_backup.py")
restore = module("sovagrid_host_restore_local_containers_test", "host_restore.py")


class LocalInventoryTests(unittest.TestCase):
    def test_external_agent_cannot_read_local_snapshot_or_docker_socket_by_group(self):
        users = {
            "sovagrid-local": types.SimpleNamespace(pw_uid=102, pw_gid=202),
            "sovagrid": types.SimpleNamespace(pw_uid=101, pw_gid=201),
        }
        groups = {"sovagrid-local": types.SimpleNamespace(gr_gid=202),
                  "docker": types.SimpleNamespace(gr_gid=999)}
        memberships = {"sovagrid-local": [202], "sovagrid": [201]}
        with mock.patch.object(inventory.pwd, "getpwnam", side_effect=users.__getitem__), \
             mock.patch.object(inventory.grp, "getgrnam", side_effect=groups.__getitem__), \
             mock.patch.object(inventory.os, "getgrouplist",
                               side_effect=lambda name, _primary: memberships[name]):
            self.assertEqual(inventory._identity(), 202)
            memberships["sovagrid"] = [201, 202]
            with self.assertRaisesRegex(inventory.Refused, "LOCAL_IDENTITY"):
                inventory._identity()
            memberships["sovagrid"] = [201, 999]
            with self.assertRaisesRegex(inventory.Refused, "DOCKER_GROUP"):
                inventory._identity()
            memberships["sovagrid"] = [201]
            memberships["sovagrid-local"] = [202, 999]
            with self.assertRaisesRegex(inventory.Refused, "LOCAL_IDENTITY|DOCKER_GROUP"):
                inventory._identity()

    def test_revision_binds_server_bundle_and_enabled_flag(self):
        first = inventory._revision({"server_id": "one"}, "a" * 64, False)
        self.assertEqual(first, inventory._revision({"server_id": "one"}, "a" * 64, False))
        self.assertNotEqual(first, inventory._revision({"server_id": "one"}, "a" * 64, True))
        self.assertNotEqual(first, inventory._revision({"server_id": "two"}, "a" * 64, False))
        self.assertNotEqual(first, inventory._revision({"server_id": "one"}, "b" * 64, False))

    def test_unowned_unit_refuses_even_when_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / inventory.UNITS[0]).write_text("unowned")
            with mock.patch.object(inventory.operations, "SYSTEMD", root), \
                 mock.patch.object(inventory, "DIRECTORY", root / "snapshot-dir"), \
                 mock.patch.object(inventory, "_record", return_value=False), \
                 mock.patch.object(inventory.promotion, "_unit_active", return_value=False), \
                 mock.patch.object(inventory.promotion, "_unit_enabled", return_value=False):
                with self.assertRaisesRegex(inventory.Refused, "UNMANAGED_INVENTORY"):
                    inventory._physical(False, 42)

    def test_pending_schema_rejects_tampered_or_equal_state(self):
        with tempfile.TemporaryDirectory() as directory:
            pending = Path(directory) / "pending.json"
            with mock.patch.object(inventory, "PENDING", pending), \
                 mock.patch.object(inventory.promotion, "_private_json",
                                   side_effect=lambda path: json.loads(path.read_text())):
                self.assertIsNone(inventory._pending())
                pending.write_text(json.dumps({"protocol": 1, "previous": False,
                                               "target": False,
                                               "manifest_sha256": "a" * 64}))
                with self.assertRaisesRegex(inventory.Refused, "PENDING"):
                    inventory._pending()
                pending.write_text(json.dumps({"protocol": 1, "previous": False,
                                               "target": True,
                                               "manifest_sha256": "a" * 64}))
                self.assertEqual(inventory._pending()["target"], True)

    def test_stale_cas_stops_before_writing_pending_or_systemd(self):
        with tempfile.TemporaryFile() as file:
            lock1, lock2 = os.dup(file.fileno()), os.dup(file.fileno())
            with mock.patch.object(inventory.operations, "_lock", return_value=lock1), \
                 mock.patch.object(inventory.promotion, "_service_setup_lock", return_value=lock2), \
                 mock.patch.object(inventory, "_pending", return_value=None), \
                 mock.patch.object(inventory, "_preflight",
                                   return_value=({"server_id": "server"}, {}, "a" * 64, 42)), \
                 mock.patch.object(inventory, "_record", return_value=False), \
                 mock.patch.object(inventory, "_physical", return_value={}), \
                 mock.patch.object(inventory.promotion, "_save_private") as save, \
                 mock.patch.object(inventory, "_apply") as apply:
                with self.assertRaisesRegex(inventory.Refused, "STATE_CHANGED"):
                    inventory.change(True, expected_state="b" * 64)
                save.assert_not_called()
                apply.assert_not_called()

    def test_failed_apply_and_failed_rollback_keep_private_recovery_record(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile() as file:
            pending = Path(directory) / "pending.json"
            lock1, lock2 = os.dup(file.fileno()), os.dup(file.fileno())
            saved, digest = {"server_id": "server"}, "a" * 64
            def save(path, value):
                path.write_text(json.dumps(value))
                path.chmod(0o600)
            with mock.patch.object(inventory, "PENDING", pending), \
                 mock.patch.object(inventory.operations, "_lock", return_value=lock1), \
                 mock.patch.object(inventory.promotion, "_service_setup_lock", return_value=lock2), \
                 mock.patch.object(inventory, "_preflight", return_value=(saved, {}, digest, 42)), \
                 mock.patch.object(inventory, "_record", return_value=False), \
                 mock.patch.object(inventory, "_physical", return_value={}), \
                 mock.patch.object(inventory.promotion, "_save_private", side_effect=save), \
                 mock.patch.object(inventory, "_apply", side_effect=OSError("fixture")):
                with self.assertRaisesRegex(inventory.Refused, "ROLLBACK_NEEDS_RECOVERY"):
                    inventory.change(True, expected_state=inventory._revision(saved, digest, False))
            self.assertEqual(json.loads(pending.read_text())["previous"], False)
            self.assertEqual(json.loads(pending.read_text())["target"], True)
            self.assertEqual(stat.S_IMODE(pending.stat().st_mode), 0o600)

    def test_snapshot_requires_fresh_successful_docker_sample(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "snapshot.json"
            now = int(time.time())
            value = {"version": 1, "collected_at": now,
                     "engines": [{"engine": "docker", "source_status": "ok"}]}
            snapshot.write_text(json.dumps(value))
            original = Path.lstat
            def lstat(path):
                info = original(path)
                if path != snapshot:
                    return info
                return types.SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_uid=0,
                                             st_gid=42, st_nlink=1, st_size=info.st_size,
                                             st_dev=info.st_dev, st_ino=info.st_ino)
            with mock.patch.object(inventory, "SNAPSHOT", snapshot), \
                 mock.patch.object(inventory, "_directory", return_value=True), \
                 mock.patch.object(Path, "lstat", lstat):
                self.assertTrue(inventory._snapshot_fresh(42))
                value["engines"][0]["source_status"] = "unavailable"
                snapshot.write_text(json.dumps(value))
                self.assertFalse(inventory._snapshot_fresh(42))
                value["engines"][0]["source_status"] = "ok"
                value["collected_at"] = now - 300
                snapshot.write_text(json.dumps(value))
                self.assertFalse(inventory._snapshot_fresh(42))

    def test_next_hub_update_and_backup_include_only_local_collector(self):
        self.assertIn("/var/lib/sovagrid-containers-local", update.SNAPSHOT)
        self.assertIn("/var/lib/sovagrid-promotion/local-container-inventory-pending.json",
                      update.SNAPSHOT)
        self.assertIn(inventory.TIMER, update.UNITS)
        self.assertNotIn("/var/lib/sovagrid-containers-local", update.LOCAL_WEB_SNAPSHOT)
        self.assertNotIn("/opt/sovagrid-agent", update.SNAPSHOT)
        self.assertIn(inventory.TIMER, backup.WRITERS["hub-only"])
        self.assertIn("/var/lib/sovagrid-containers-local", restore.TARGET_NAMESPACES)
        self.assertIn("/var/lib/sovagrid-containers-local/snapshot.json",
                      restore.DYNAMIC_GROUP_PATHS)

    def test_clean_host_restore_checks_local_snapshot_group_and_modes(self):
        path = "/var/lib/sovagrid-containers-local"
        self.assertTrue(any({path, path + "/snapshot.json",
                             "/etc/sovagrid-local/agent.json"} <= group
                            for group in restore.DYNAMIC_GROUPS))
        source = backup.Source(path, kind="dir", private=True, exact_mode=0o750)
        directory = tarfile.TarInfo(path.removeprefix("/") + "/")
        directory.type = tarfile.DIRTYPE
        directory.uid, directory.gid, directory.mode = 0, 123, 0o750
        restore._check_member(path, directory, True, (source,), set())
        file = tarfile.TarInfo(path.removeprefix("/") + "/snapshot.json")
        file.uid, file.gid, file.mode = 0, 123, 0o640
        restore._check_member(path + "/snapshot.json", file, False,
                              (source,), {path})
        file.gid = 0
        with self.assertRaisesRegex(restore.Refused, "INVALID_ARCHIVE"):
            restore._check_member(path + "/snapshot.json", file, False,
                                  (source,), {path})
        directory.mode = 0o770
        with self.assertRaisesRegex(restore.Refused, "INVALID_ARCHIVE"):
            restore._check_member(path, directory, True, (source,), set())

    def test_host_backup_ignores_only_safe_abandoned_collector_temp(self):
        path = "/var/lib/sovagrid-containers-local"
        info = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_uid=0,
                                     st_gid=202, st_nlink=1, st_size=100)
        with mock.patch.object(backup.grp, "getgrnam",
                               return_value=types.SimpleNamespace(gr_gid=202)):
            self.assertTrue(backup._skip_container_temp(path, ".snapshot-abcd1234", info))
            self.assertFalse(backup._skip_container_temp(path, "snapshot.json", info))
            for invalid in (types.SimpleNamespace(**{**vars(info), "st_mode": stat.S_IFLNK | 0o777}),
                            types.SimpleNamespace(**{**vars(info), "st_uid": 101}),
                            types.SimpleNamespace(**{**vars(info), "st_gid": 201}),
                            types.SimpleNamespace(**{**vars(info), "st_size": 10001})):
                with self.subTest(invalid=invalid), self.assertRaisesRegex(backup.Refused, "UNSAFE_SOURCE"):
                    backup._skip_container_temp(path, ".snapshot-abcd1234", invalid)


if __name__ == "__main__":
    unittest.main()
