# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Disposable filesystem/fake systemd: source upgrade, rollback and recovery."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
from vpn_source_install import Installer, Refuse, SOURCE_DEST, PACKAGE_DEST
from vpn_source_maintenance import AMNEZIA, WIREGUARD, LOCKS, JOURNAL, WG_MARKER, UNIT_ORDER


class PowerLoss(BaseException):
    pass


class Systemd:
    def __init__(self):
        self.units = {}
        self.calls = []
        self.fail_import = False
        self.fail_start_once = False

    def run(self, args, **kwargs):
        self.calls.append(args)
        stdout = b""
        code = 0
        if args[:2] == ["/usr/bin/systemctl", "show"]:
            name = args[2]
            state = self.units[name]
            stdout = ("ActiveState=" + ("active" if state["active"] else "inactive") + "\n" +
                "UnitFileState=" + state["enablement"] + "\nLoadState=loaded\nFragmentPath=/etc/systemd/system/" +
                name + "\nDropInPaths=" + state.get("dropins", "") + "\n").encode()
        elif args[:2] == ["/usr/bin/systemctl", "stop"]:
            self.units[args[2]]["active"] = False
        elif args[:2] == ["/usr/bin/systemctl", "start"]:
            if self.fail_start_once:
                self.fail_start_once = False
                code = 1
            else:
                self.units[args[2]]["active"] = True
        elif args[0] == "/usr/bin/python3" and self.fail_import:
            self.fail_import = False
            code = 1
        return subprocess.CompletedProcess(args, code, stdout=stdout, stderr=b"")


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.systemd = Systemd()
        self.installer = Installer(root=self.root, owner=os.getuid(), run=self.systemd.run)
        self.source = {"sovagrid_vpn/__init__.py": b"# source\n",
                       "sovagrid_vpn/amnezia_install.py": b"# old module\n"}
        for name, _, _ in AMNEZIA + WIREGUARD:
            self.source["deploy/" + name] = ("# old " + name + "\n").encode()
        self.package = {"__init__.py": b"# source\n", "amnezia_install.py": b"# old module\n"}
        preview = self.installer.preview("a" * 64, self.source, self.package)
        self.installer.apply("a" * 64, self.source, self.package, preview["expected"])
        for name, absolute, mode in AMNEZIA + WIREGUARD:
            self.write(absolute, self.source["deploy/" + name], mode)
            if absolute.startswith("/etc/systemd/system/"):
                self.systemd.units[Path(absolute).name] = {"active": not name.endswith("status-agent.service"),
                    "enablement": "static" if name.endswith("status-agent.service") else "enabled"}
        self.write(WG_MARKER, json.dumps({"schema_version": 2, "files": {
            absolute: self.installer._hashmap({"x": self.source["deploy/" + name]})["x"]
            for name, absolute, _ in WIREGUARD}}).encode(), 0o600)
        self.write("/etc/sovagrid-vpn/amnezia-control.enabled", b"enabled\n", 0o600)
        self.write("/etc/wireguard/sg-test.conf", b"PrivateKey=fixture-secret\n", 0o600)
        self.write("/var/lib/sovagrid-vpn/amnezia-provision/state.json", b'{"schema_version":1}', 0o600)
        self.write("/var/lib/sovagrid-vpn/amnezia-admin/awg2.json", b'{"generation":7}', 0o600)
        self.new_source = {key: value + b"# candidate\n" for key, value in self.source.items()}
        self.new_package = {key: value + b"# candidate\n" for key, value in self.package.items()}
        self.original_units = json.loads(json.dumps(self.systemd.units))

    def write(self, absolute, raw, mode):
        target = self.root / absolute.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        # Product private control roots use 0700; system directories stay 0755.
        for private in ("/etc/sovagrid-vpn", "/etc/wireguard", "/var/lib/sovagrid-vpn",
                        "/var/lib/sovagrid-vpn/amnezia-admin", "/var/lib/sovagrid-vpn/amnezia-provision"):
            path = self.root / private.lstrip("/")
            if path.exists(): path.chmod(0o700)
        target.write_bytes(raw); target.chmod(mode)

    def preview(self):
        return self.installer.preview("b" * 64, self.new_source, self.new_package)

    def apply(self, expected=None):
        return self.installer.apply("b" * 64, self.new_source, self.new_package,
            expected or self.preview()["expected"], maintenance=True)

    def assert_old(self):
        self.assertEqual(self.installer._tree(SOURCE_DEST), self.installer._hashmap(self.source))
        self.assertEqual(self.installer._tree(PACKAGE_DEST), self.installer._hashmap(self.package))
        for name, absolute, _ in AMNEZIA + WIREGUARD:
            self.assertEqual(self.installer._read(absolute), self.source["deploy/" + name])
        self.assertEqual(self.systemd.units, self.original_units)
        self.assertFalse((self.root / JOURNAL.lstrip("/")).exists())
        self.assertFalse((self.root / "var/lib/sovagrid/vpn-source/maintenance.blocked").exists())
        self.assertFalse(list((self.root / "etc/systemd/system").glob("*.d")))
        self.assertEqual(self.installer._read("/etc/wireguard/sg-test.conf"), b"PrivateKey=fixture-secret\n")

    def test_explicit_upgrade_drains_only_brokers_and_preserves_all_vpn_state(self):
        before = self.installer._maintenance().protected()
        preview = self.preview()
        self.assertTrue(preview["maintenance_required"])
        with self.assertRaisesRegex(Refuse, "CONTROL_ACTIVE"):
            self.installer.apply("b" * 64, self.new_source, self.new_package, preview["expected"])
        self.assertFalse(any(call[1:2] == ["stop"] for call in self.systemd.calls))
        result = self.apply(preview["expected"])
        self.assertTrue(result["changed"])
        self.assertFalse(result["cleanup_required"])
        self.assertEqual(self.installer._maintenance().protected(), before)
        self.assertEqual(self.systemd.units, self.original_units)
        self.assertEqual(self.installer._tree(SOURCE_DEST), self.installer._hashmap(self.new_source))
        self.assertFalse((self.root / JOURNAL.lstrip("/")).exists())
        self.assertFalse(self.installer.recover()["recovered"])
        self.assertFalse(any("docker" in call[0] or "wg" == call[0] for call in self.systemd.calls))

    def test_active_wireguard_configuration_symlink_is_preserved_without_following_foreign_links(self):
        self.write("/var/lib/sovagrid-vpn/phone-vpn/server.conf", b"PrivateKey=fixture-server-key\n", 0o600)
        link = self.root / "etc/wireguard/sg-owned.conf"
        # Use a host-absolute link, as the real managed interface does. The
        # isolated test root has no such host file; following it would fail.
        link.symlink_to("/var/lib/sovagrid-vpn/phone-vpn/server.conf")
        foreign = self.root / "etc/wireguard/other.conf"
        foreign.symlink_to("/a/foreign/private/path")
        before = self.installer._maintenance().protected()
        self.apply()
        self.assertEqual(self.installer._maintenance().protected(), before)
        self.assertEqual(os.readlink(link), "/var/lib/sovagrid-vpn/phone-vpn/server.conf")
        self.assertEqual(os.readlink(foreign), "/a/foreign/private/path")

    def test_changed_runtime_or_peer_state_invalidates_review_before_stop(self):
        for mutation in ("runtime", "peer", "mode"):
            with self.subTest(mutation=mutation):
                preview = self.preview()
                if mutation == "runtime":
                    self.systemd.units[UNIT_ORDER[0]]["active"] = False
                elif mutation == "peer":
                    self.write("/var/lib/sovagrid-vpn/amnezia-admin/awg2.json", b'{"generation":8}', 0o600)
                else:
                    (self.root / "etc/wireguard/sg-test.conf").chmod(0o640)
                with self.assertRaisesRegex(Refuse, "STALE_PREVIEW"):
                    self.apply(preview["expected"])
        self.assertFalse(any(call[1:2] == ["stop"] for call in self.systemd.calls))

    def test_disk_full_refuses_before_journal_or_stopping_units(self):
        expected = self.preview()["expected"]
        with mock.patch("vpn_source_install.os.statvfs", return_value=SimpleNamespace(f_bavail=1, f_frsize=4096)):
            with self.assertRaisesRegex(Refuse, "INSUFFICIENT_SPACE"):
                self.apply(expected)
        self.assertFalse((self.root / JOURNAL.lstrip("/")).exists())
        self.assertFalse(any(call[1:2] == ["stop"] for call in self.systemd.calls))
        self.assert_old()

    def test_full_host_restore_fence_blocks_vpn_apply_and_recover(self):
        expected = self.preview()["expected"]
        self.write("/var/lib/.sovagrid-host-restore-in-progress", b"host restore pending\n", 0o600)
        with self.assertRaisesRegex(Refuse, "RESTORE_RECOVERY"):
            self.apply(expected)
        with self.assertRaisesRegex(Refuse, "RESTORE_RECOVERY"):
            self.installer.recover()
        self.assertFalse(any(call[1:2] == ["stop"] for call in self.systemd.calls))

    def test_shared_installation_lock_blocks_source_update_before_service_mutation(self):
        preview = self.preview()
        with self.installer._installation_guard():
            with self.assertRaisesRegex(Refuse, "BUSY"):
                self.apply(preview["expected"])
        self.assertFalse(any(call[1:2] == ["stop"] for call in self.systemd.calls))

    def test_in_use_resource_lock_refuses_without_stopping_a_unit(self):
        preview = self.preview()
        with self.installer._maintenance().locks():
            with self.assertRaisesRegex(Refuse, "BUSY"):
                self.apply(preview["expected"])
        self.assertFalse(any(call[1:2] == ["stop"] for call in self.systemd.calls))

    def test_new_runtime_import_or_service_failure_rolls_back_old_files_and_activity(self):
        for failure in ("fail_import", "fail_start_once"):
            with self.subTest(failure=failure):
                setattr(self.systemd, failure, True)
                with self.assertRaisesRegex(Refuse, "OPERATION_FAILED"):
                    self.apply()
                self.assert_old()

    def test_power_loss_during_each_durable_phase_recovers_idempotently(self):
        phases = ["maintenance:prepared", "maintenance:stopped", "source_switched", "package_switched",
                  "maintenance:file:sovagrid-amnezia-broker", "maintenance:files_switched",
                  "maintenance:guard:sovagrid-amnezia-control.service", "maintenance:unblocked",
                  "maintenance:runtime_started", "source_committed"]
        for phase in phases:
            with self.subTest(phase=phase):
                def crash(current):
                    if phase == current: raise PowerLoss()
                self.installer.checkpoint = crash
                with self.assertRaises(PowerLoss): self.apply()
                self.installer.checkpoint = lambda _phase: None
                with self.assertRaisesRegex(Refuse, "RECOVERY_REQUIRED"): self.preview()
                self.assertTrue(self.installer.recover()["recovered"])
                self.assert_old()
                self.assertFalse(self.installer.recover()["recovered"])

    def _candidate_variant(self, kind):
        self.new_source = {key: value + b"# candidate\n" for key, value in self.source.items()
                           } if kind == "both" else dict(self.source)
        self.new_package = {key: value + b"# candidate\n" for key, value in self.package.items()
                            } if kind != "source_only" else dict(self.package)
        if kind == "source_only":
            self.new_source.update({key: value + b"# deploy-only candidate\n"
                                    for key, value in self.source.items() if key.startswith("deploy/")})

    def _restore_original_candidate(self):
        preview = self.installer.preview("a" * 64, self.source, self.package)
        self.installer.apply("a" * 64, self.source, self.package,
                             preview["expected"], maintenance=True)
        self.assert_old()

    def _interrupt_apply(self, checkpoint=None, rename=None):
        original = self.installer._rename
        calls = 0
        def changed(old, new):
            nonlocal calls
            calls += 1
            if rename == (calls, "before"): raise PowerLoss()
            original(old, new)
            if rename == (calls, "after"): raise PowerLoss()
        def reached(point):
            if point == checkpoint: raise PowerLoss()
        self.installer._rename = changed
        self.installer.checkpoint = reached
        try:
            with self.assertRaises(PowerLoss): self.apply()
        finally:
            self.installer._rename = original
            self.installer.checkpoint = lambda _phase: None

    def test_source_only_and_package_only_apply_recover_at_every_rename_and_checkpoint(self):
        for kind in ("source_only", "package_only", "both"):
            self._candidate_variant(kind)
            checkpoints, renames = [], []
            original = self.installer._rename
            def renamed(old, new):
                renames.append((old, new))
                original(old, new)
            self.installer.checkpoint = checkpoints.append
            self.installer._rename = renamed
            try:
                self.apply()
            finally:
                self.installer.checkpoint = lambda _phase: None
                self.installer._rename = original
            self._restore_original_candidate()
            boundaries = [("checkpoint", point) for point in dict.fromkeys(checkpoints)]
            boundaries += [("rename", (index, when)) for index in range(1, len(renames) + 1)
                           for when in ("before", "after")]
            self.assertTrue(renames)
            for category, point in boundaries:
                with self.subTest(candidate=kind, boundary=category, point=point):
                    self._interrupt_apply(**{category: point})
                    self.assertTrue(self.installer.recover()["recovered"])
                    if category == "checkpoint" and point == "maintenance:committed":
                        self.assertEqual(self.installer._tree(SOURCE_DEST), self.installer._hashmap(self.new_source))
                        self.assertEqual(self.installer._tree(PACKAGE_DEST), self.installer._hashmap(self.new_package))
                        self._restore_original_candidate()
                    else:
                        self.assert_old()
                    self.assertFalse(self.installer.recover()["recovered"])

    def test_partial_component_recovery_itself_can_be_interrupted_at_each_boundary(self):
        for kind in ("source_only", "package_only", "both"):
            self._candidate_variant(kind)
            for interrupted_at in ("source_switched", "package_switched"):
                self._interrupt_apply(checkpoint=interrupted_at)
                checkpoints, renames = [], []
                original = self.installer._rename
                def renamed(old, new):
                    renames.append((old, new))
                    original(old, new)
                self.installer.checkpoint = checkpoints.append
                self.installer._rename = renamed
                try:
                    self.assertTrue(self.installer.recover()["recovered"])
                finally:
                    self.installer.checkpoint = lambda _phase: None
                    self.installer._rename = original
                self.assert_old()
                boundaries = [("checkpoint", point) for point in dict.fromkeys(checkpoints)]
                boundaries += [("rename", (index, when)) for index in range(1, len(renames) + 1)
                               for when in ("before", "after")]
                self.assertTrue(renames)
                for category, point in boundaries:
                    with self.subTest(candidate=kind, apply_boundary=interrupted_at,
                                      recovery_boundary=category, point=point):
                        self._interrupt_apply(checkpoint=interrupted_at)
                        calls = 0
                        def changed(old, new):
                            nonlocal calls
                            calls += 1
                            if category == "rename" and point == (calls, "before"): raise PowerLoss()
                            original(old, new)
                            if category == "rename" and point == (calls, "after"): raise PowerLoss()
                        def reached(current):
                            if category == "checkpoint" and current == point: raise PowerLoss()
                        self.installer._rename = changed
                        self.installer.checkpoint = reached
                        try:
                            with self.assertRaises(PowerLoss): self.installer.recover()
                        finally:
                            self.installer._rename = original
                            self.installer.checkpoint = lambda _phase: None
                        self.assertTrue(self.installer.recover()["recovered"])
                        self.assert_old()
                        self.assertFalse(self.installer.recover()["recovered"])

    def test_recover_repairs_unchanged_package_moved_to_discard_by_older_bug(self):
        self._candidate_variant("source_only")
        self._interrupt_apply(checkpoint="source_switched")
        journal = self.installer._maintenance().read()
        stage = journal["pending"]["stage"]
        # Reproduce the previous recovery's failure exactly: source had moved,
        # but package still had no old backup. Its bytes equal both manifests.
        self.installer._rename(PACKAGE_DEST, stage + "/discard_package")
        self.assertFalse(self.installer.at(PACKAGE_DEST).exists())
        self.assertTrue(self.installer.recover()["recovered"])
        self.assert_old()

    def test_missing_changed_backup_refuses_before_moving_another_component(self):
        self._candidate_variant("both")
        self._interrupt_apply(checkpoint="package_switched")
        journal = self.installer._maintenance().read()
        stage = journal["pending"]["stage"]
        # A foreign removal of the only changed-component backup cannot be
        # repaired by discarding the remaining live candidate.
        self.installer.at(stage + "/old_package").rename(self.root / "externally-moved-package")
        before_source = self.installer._tree(SOURCE_DEST)
        before_package = self.installer._tree(PACKAGE_DEST)
        with self.assertRaisesRegex(Refuse, "STATE_CONFLICT"): self.installer.recover()
        self.assertEqual(self.installer._tree(SOURCE_DEST), before_source)
        self.assertEqual(self.installer._tree(PACKAGE_DEST), before_package)
        self.assertTrue(self.installer.at(JOURNAL).is_file())

    def test_committed_interruption_finishes_cleanup_and_keeps_new_version(self):
        def crash(phase):
            if phase == "maintenance:committed": raise PowerLoss()
        self.installer.checkpoint = crash
        with self.assertRaises(PowerLoss): self.apply()
        self.installer.checkpoint = lambda _phase: None
        self.assertTrue(self.installer.recover()["recovered"])
        self.assertEqual(self.installer._tree(SOURCE_DEST), self.installer._hashmap(self.new_source))
        self.assertEqual(self.systemd.units, self.original_units)
        self.assertFalse(self.installer.recover()["recovered"])

    def test_recovery_does_not_touch_a_file_changed_by_another_administrator(self):
        def crash(phase):
            if phase == "maintenance:files_switched": raise PowerLoss()
        self.installer.checkpoint = crash
        with self.assertRaises(PowerLoss): self.apply()
        self.installer.checkpoint = lambda _phase: None
        absolute = AMNEZIA[0][1]
        self.write(absolute, b"external administrator edit\n", 0o755)
        self.systemd.calls.clear()
        with self.assertRaisesRegex(Refuse, "STATE_CONFLICT"): self.installer.recover()
        self.assertEqual(self.installer._read(absolute), b"external administrator edit\n")
        self.assertTrue((self.root / JOURNAL.lstrip("/")).exists())
        self.assertFalse(any(call[1:2] == ["stop"] for call in self.systemd.calls))

    def test_recovery_checks_external_source_edits_before_stopping_any_unit(self):
        def crash(phase):
            if phase == "package_switched": raise PowerLoss()
        self.installer.checkpoint = crash
        with self.assertRaises(PowerLoss): self.apply()
        self.installer.checkpoint = lambda _phase: None
        self.write(SOURCE_DEST + "/sovagrid_vpn/amnezia_install.py", b"# external edit\n", 0o644)
        self.systemd.calls.clear()
        with self.assertRaisesRegex(Refuse, "STATE_CONFLICT"): self.installer.recover()
        self.assertEqual(self.installer._read(SOURCE_DEST + "/sovagrid_vpn/amnezia_install.py"), b"# external edit\n")
        self.assertFalse(any(call[1:2] == ["stop"] for call in self.systemd.calls))

    def test_unknown_unit_override_or_pending_peer_transaction_is_refused(self):
        self.systemd.units[UNIT_ORDER[0]]["dropins"] = "/etc/systemd/system/other.conf"
        with self.assertRaisesRegex(Refuse, "CONTROL_ACTIVE"): self.preview()
        self.systemd.units[UNIT_ORDER[0]].pop("dropins")
        self.write("/var/lib/sovagrid-vpn/amnezia-admin/awg2.pending", b"{}", 0o600)
        with self.assertRaisesRegex(Refuse, "RECOVERY_REQUIRED"): self.preview()

    @unittest.skipUnless(hasattr(os, "fork"), "requires a local fork-capable test host")
    def test_uncatchable_process_exit_preserves_startup_barrier_and_recovers(self):
        for phase in ("source_switched", "maintenance:file:sovagrid-amnezia-broker", "maintenance:committed"):
            with self.subTest(phase=phase):
                pid = os.fork()
                if pid == 0:
                    self.installer.checkpoint = lambda point: os._exit(23) if point == phase else None
                    try:
                        self.apply()
                    except BaseException:
                        os._exit(24)
                    os._exit(25)
                _, result = os.waitpid(pid, 0)
                self.assertEqual(os.waitstatus_to_exitcode(result), 23)
                blocker = self.root / "var/lib/sovagrid/vpn-source/maintenance.blocked"
                if phase != "maintenance:committed":
                    self.assertTrue(blocker.is_file())
                    guards = list((self.root / "etc/systemd/system").glob("*.d/*.conf"))
                    self.assertEqual(len(guards), 6)
                    for guard in guards:
                        self.assertIn(b"ConditionPathExists=!/var/lib/sovagrid/vpn-source/maintenance.blocked", guard.read_bytes())
                self.assertTrue(self.installer.recover()["recovered"])
                if phase != "maintenance:committed":
                    self.assert_old()
                else:
                    self.assertEqual(self.installer._tree(SOURCE_DEST), self.installer._hashmap(self.new_source))
                self.assertFalse(blocker.exists())

    def test_recovery_does_not_replace_an_externally_modified_startup_guard(self):
        def crash(phase):
            if phase == "source_switched": raise PowerLoss()
        self.installer.checkpoint = crash
        with self.assertRaises(PowerLoss): self.apply()
        self.installer.checkpoint = lambda _phase: None
        guard = next((self.root / "etc/systemd/system").glob("*.d/*.conf"))
        guard.write_text("external admin edit\n")
        self.systemd.calls.clear()
        with self.assertRaisesRegex(Refuse, "STATE_CONFLICT"): self.installer.recover()
        self.assertEqual(guard.read_text(), "external admin edit\n")
        self.assertTrue((self.root / JOURNAL.lstrip("/")).exists())
        self.assertFalse(any(call[1:2] == ["stop"] for call in self.systemd.calls))

    def test_candidate_syntax_error_is_refused_before_mutation(self):
        self.new_package["amnezia_install.py"] = b"if missing colon\n"
        with self.assertRaisesRegex(Refuse, "SOURCE_UNTRUSTED"): self.preview()
        self.assertFalse(any(call[1:2] == ["stop"] for call in self.systemd.calls))


if __name__ == "__main__": unittest.main()
