# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Local fixture for interrupted collector and Hub-only unit refresh."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


DEPLOY = Path(__file__).resolve().parents[1] / "deploy"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, DEPLOY / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inventory = load("sovagrid_local_inventory_transactions", "local_container_inventory.py")
update = load("sovagrid_hub_update_local_inventory_transactions", "hub_only_update.py")


class TransactionTests(unittest.TestCase):
    def test_disable_refuses_modified_installed_unit_before_removing_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            deploy = source / "sovagrid-agent" / "deploy"
            systemd = root / "systemd"
            deploy.mkdir(parents=True)
            systemd.mkdir()
            manifest = {"sha256": {}}
            for name in inventory.UNITS:
                raw = ("managed:" + name).encode()
                (deploy / name).write_bytes(raw)
                (systemd / name).write_bytes(raw)
                manifest["sha256"]["sovagrid-agent/deploy/" + name] = hashlib.sha256(raw).hexdigest()
            (source / "sovagrid-bundle.json").write_text(json.dumps(manifest))
            (systemd / inventory.UNITS[0]).write_bytes(b"changed by another owner")
            marker = root / "state.json"
            marker.write_text(json.dumps({"protocol": 1, "enabled": True}))
            with mock.patch.object(inventory, "STATE", marker), \
                 mock.patch.object(inventory.operations, "SOURCE_AGENT", deploy), \
                 mock.patch.object(inventory.operations, "SYSTEMD", systemd), \
                 mock.patch.object(inventory.operations.promotion, "SOURCE", source), \
                 mock.patch.object(inventory.operations.promotion, "_read_regular",
                                   side_effect=lambda path, _limit: path.read_bytes()), \
                 mock.patch.object(inventory, "_command") as command:
                with self.assertRaisesRegex(inventory.operations.Refused, "UNIT_CONFLICT"):
                    inventory._disable(42)
            self.assertTrue(marker.exists())
            self.assertEqual((systemd / inventory.UNITS[0]).read_bytes(), b"changed by another owner")
            command.assert_not_called()

    @contextlib.contextmanager
    def fake_host(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            root = Path(directory)
            systemd = root / "systemd"
            source = root / "source"
            systemd.mkdir()
            source.mkdir()
            state = root / "state.json"
            pending = root / "pending.json"
            snapshot_dir = root / "containers"
            snapshot = snapshot_dir / "snapshot.json"
            raw = {name: ("unit:" + name).encode() for name in inventory.UNITS}
            for name, value in raw.items():
                (source / name).write_bytes(value)
            active = {}
            enabled = {}

            def checked_units():
                for name, value in raw.items():
                    target = systemd / name
                    if target.exists() and target.read_bytes() != value:
                        raise inventory.Refused("UNIT_CONFLICT")
                return raw

            def check_dir(_gid, *, allow_absent):
                if snapshot_dir.exists():
                    if not snapshot_dir.is_dir() or snapshot_dir.is_symlink():
                        raise inventory.Refused("DIRECTORY")
                    return True
                if not allow_absent:
                    raise inventory.Refused("DIRECTORY")
                return False

            def save(path, value):
                path.write_text(json.dumps(value))
                path.chmod(0o600)

            def command(*args):
                if args[:2] == ("systemctl", "enable"):
                    enabled[args[-1]] = True
                    active[args[-1]] = True
                elif args[:2] == ("systemctl", "disable"):
                    enabled[args[-1]] = False
                elif args[:2] == ("systemctl", "stop"):
                    active[args[-1]] = False
                elif args[:2] == ("systemctl", "start"):
                    snapshot.write_text("fresh")

            patches = (
                mock.patch.object(inventory, "STATE", state),
                mock.patch.object(inventory, "PENDING", pending),
                mock.patch.object(inventory, "DIRECTORY", snapshot_dir),
                mock.patch.object(inventory, "SNAPSHOT", snapshot),
                mock.patch.object(inventory.operations, "SYSTEMD", systemd),
                mock.patch.object(inventory.operations, "SOURCE_AGENT", source),
                mock.patch.object(inventory, "_preflight", return_value=(
                    {"server_id": "0d44742e-6317-46cb-8d91-2c807033745d"}, {}, "a" * 64, 42)),
                mock.patch.object(inventory, "_unit_bytes", side_effect=checked_units),
                mock.patch.object(inventory, "_directory", side_effect=check_dir),
                mock.patch.object(inventory, "_snapshot_fresh",
                                  side_effect=lambda _gid: snapshot.exists()),
                mock.patch.object(inventory, "_command", side_effect=command),
                mock.patch.object(inventory.promotion, "_private_json",
                                  side_effect=lambda path: json.loads(path.read_text())),
                mock.patch.object(inventory.promotion, "_save_private", side_effect=save),
                mock.patch.object(inventory.promotion, "_local_directory",
                                  side_effect=lambda path, **_kwargs: path.mkdir(exist_ok=True)),
                mock.patch.object(inventory.promotion, "_unit_active",
                                  side_effect=lambda name: active.get(name, False)),
                mock.patch.object(inventory.promotion, "_unit_enabled",
                                  side_effect=lambda name: enabled.get(name, False)),
                mock.patch.object(inventory.promotion, "capture_external", return_value={}),
                mock.patch.object(inventory.promotion, "inspect", return_value={"phase": "activated"}),
            )
            for patch in patches:
                stack.enter_context(patch)
            yield state, pending, snapshot_dir, snapshot, systemd, raw, active, enabled

    def test_recover_removes_partial_enable_and_snapshot(self):
        with self.fake_host() as (state, pending, directory, snapshot, systemd, raw, active, enabled):
            state.write_text(json.dumps({"protocol": 1, "enabled": True}))
            pending.write_text(json.dumps({"protocol": 1, "previous": False,
                                           "target": True, "manifest_sha256": "a" * 64}))
            directory.mkdir()
            snapshot.write_text("partial")
            (systemd / inventory.UNITS[0]).write_bytes(raw[inventory.UNITS[0]])
            active[inventory.TIMER] = enabled[inventory.TIMER] = True
            inventory._recover_locked()
            self.assertFalse(state.exists())
            self.assertFalse(pending.exists())
            self.assertFalse(directory.exists())
            self.assertFalse(any(systemd.iterdir()))
            self.assertFalse(active[inventory.TIMER])
            self.assertFalse(enabled[inventory.TIMER])

    def test_recover_recreates_collector_after_partial_disable(self):
        with self.fake_host() as (state, pending, directory, snapshot, systemd, raw, active, enabled):
            pending.write_text(json.dumps({"protocol": 1, "previous": True,
                                           "target": False, "manifest_sha256": "a" * 64}))
            (systemd / inventory.UNITS[0]).write_bytes(raw[inventory.UNITS[0]])
            inventory._recover_locked()
            self.assertTrue(state.exists())
            self.assertFalse(pending.exists())
            self.assertEqual({path.name: path.read_bytes() for path in systemd.iterdir()}, raw)
            self.assertTrue(directory.is_dir())
            self.assertTrue(snapshot.exists())
            self.assertTrue(active[inventory.TIMER])
            self.assertTrue(enabled[inventory.TIMER])

    def test_apply_failure_rolls_partial_enable_back(self):
        with self.fake_host() as (state, pending, directory, snapshot, systemd, _raw, _active, _enabled):
            saved = {"server_id": "0d44742e-6317-46cb-8d91-2c807033745d"}
            with tempfile.TemporaryFile() as file:
                lock1, lock2 = os.dup(file.fileno()), os.dup(file.fileno())
                original = inventory._command

                def fail_once(*args):
                    if args[:2] == ("systemctl", "enable"):
                        raise OSError("fixture")
                    return original(*args)

                with mock.patch.object(inventory.operations, "_lock", return_value=lock1), \
                     mock.patch.object(inventory.promotion, "_service_setup_lock", return_value=lock2), \
                     mock.patch.object(inventory, "_command", side_effect=fail_once):
                    with self.assertRaisesRegex(inventory.Refused, "ROLLED_BACK"):
                        inventory.change(True, expected_state=inventory._revision(saved, "a" * 64, False))
            self.assertFalse(state.exists())
            self.assertFalse(pending.exists())
            self.assertFalse(directory.exists())
            self.assertFalse(any(systemd.iterdir()))

    def test_hub_update_refreshes_enabled_collector_units(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / "old" / "sovagrid-agent" / "deploy"
            current = root / "current" / "sovagrid-agent" / "deploy"
            systemd = root / "systemd"
            for path in (previous, current, systemd):
                path.mkdir(parents=True)
            units = {name: {"active": False, "enabled": False}
                     for name in (*update.promotion.LOCAL_TERMINAL_UNITS,
                                  *update.LOCAL_SERVICE_UNITS, *update.LOCAL_CONTAINER_UNITS)}
            timer = update.LOCAL_CONTAINER_UNITS[1]
            units[timer] = {"active": True, "enabled": True}
            for name in update.LOCAL_CONTAINER_UNITS:
                (previous / name).write_bytes(("old:" + name).encode())
                (current / name).write_bytes(("new:" + name).encode())
                (systemd / name).write_bytes(("old:" + name).encode())
                (systemd / name).chmod(0o644)
            commands = []
            with mock.patch.object(update, "SOURCE", root / "current"), \
                 mock.patch.object(update, "SYSTEMD", systemd), \
                 mock.patch.object(update.promotion, "_read_regular",
                                   side_effect=lambda path, _limit: path.read_bytes()), \
                 mock.patch.object(update.common, "command", side_effect=lambda args, **_kw: commands.append(args)), \
                 mock.patch.object(update, "_unit_state", side_effect=lambda name: units[name]), \
                 mock.patch.object(update.os, "getuid", return_value=0):
                # lstat ownership is supplied by the real root process in CI; locally
                # patch only the check's source of uid/gid.
                original = Path.lstat
                def root_lstat(path):
                    info = original(path)
                    if path.parent != systemd:
                        return info
                    import types
                    return types.SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=0)
                with mock.patch.object(Path, "lstat", root_lstat):
                    update._refresh_local_broker(root / "old", units)
            for name in update.LOCAL_CONTAINER_UNITS:
                self.assertEqual((systemd / name).read_bytes(), ("new:" + name).encode())
            self.assertIn(["systemctl", "daemon-reload"], commands)
            self.assertIn(["systemctl", "restart", timer], commands)


if __name__ == "__main__":
    unittest.main()
