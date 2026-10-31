# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""No network or root privileges: exact source transaction and recovery."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
from vpn_source_install import Installer, Refuse, STATE_FILE


class SourceInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.installer = Installer(root=self.root, owner=os.getuid())
        self.source = {"sovagrid_vpn/amnezia_install.py": b"old module\n",
                       "deploy/install-amnezia-control.py": b"old launcher\n"}
        self.package = {"amnezia_install.py": b"old module\n"}

    def _install(self):
        preview = self.installer.preview("a" * 64, self.source, self.package)
        return self.installer.apply("a" * 64, self.source, self.package, preview["expected"])

    def test_first_install_is_idempotent_and_keeps_two_trees_equal(self):
        preview = self.installer.preview("a" * 64, self.source, self.package)
        self.assertEqual(preview["change"], "install")
        self.assertEqual(preview["installed_sha256"], "0" * 64)
        result = self._install()
        self.assertTrue(result["changed"])
        self.assertEqual((self.root / "opt/sovagrid-src/sovagrid-vpn/sovagrid_vpn/amnezia_install.py").read_bytes(),
                         (self.root / "opt/sovagrid-vpn/sovagrid_vpn/amnezia_install.py").read_bytes())
        current = self.installer.preview("a" * 64, self.source, self.package)
        self.assertEqual(current["change"], "current")
        self.assertFalse(self.installer.apply("a" * 64, self.source, self.package,
                                              current["expected"])["changed"])

    def test_update_uses_cas_and_refuses_drift(self):
        self._install()
        source = {**self.source, "sovagrid_vpn/amnezia_install.py": b"new module\n"}
        package = {"amnezia_install.py": b"new module\n"}
        preview = self.installer.preview("b" * 64, source, package)
        self.assertEqual(preview["change"], "update")
        with self.assertRaises(Refuse) as stale:
            self.installer.apply("b" * 64, source, package,
                                 {**preview["expected"], "state_sha256": "0" * 64})
        self.assertEqual(stale.exception.code, "STALE_PREVIEW")
        self.assertTrue(self.installer.apply("b" * 64, source, package,
                                             preview["expected"])["changed"])
        (self.root / "opt/sovagrid-vpn/sovagrid_vpn/amnezia_install.py").write_bytes(b"tampered")
        with self.assertRaises(Refuse) as drift:
            self.installer.preview("b" * 64, source, package)
        self.assertEqual(drift.exception.code, "STATE_CONFLICT")

    def test_unmanaged_path_and_symlink_are_never_adopted(self):
        foreign = self.root / "opt/sovagrid-src/sovagrid-vpn"
        foreign.mkdir(parents=True)
        (foreign / "foreign.py").write_text("leave me", encoding="utf-8")
        with self.assertRaises(Refuse) as conflict:
            self.installer.preview("a" * 64, self.source, self.package)
        self.assertEqual(conflict.exception.code, "OWNERSHIP_CONFLICT")
        self.assertEqual((foreign / "foreign.py").read_text(), "leave me")
        foreign.rename(foreign.with_name("moved"))
        foreign.symlink_to(foreign.with_name("moved"))
        with self.assertRaises(Refuse):
            self.installer.preview("a" * 64, self.source, self.package)

    def test_foreign_private_state_file_is_not_adopted(self):
        state = self.root / "var/lib/sovagrid/vpn-source"
        state.mkdir(parents=True, mode=0o700)
        state.chmod(0o700)
        (state / "foreign.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(Refuse) as error:
            self.installer.preview("a" * 64, self.source, self.package)
        self.assertEqual(error.exception.code, "OWNERSHIP_CONFLICT")

    def test_failed_swap_rolls_back_owned_files(self):
        self._install()
        original = self.installer._rename
        calls = 0

        def interrupted(old, new):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError("simulated rename failure")
            return original(old, new)

        self.installer._rename = interrupted
        new_source = {**self.source, "sovagrid_vpn/amnezia_install.py": b"new module\n"}
        new_package = {"amnezia_install.py": b"new module\n"}
        preview = self.installer.preview("b" * 64, new_source, new_package)
        with self.assertRaises(OSError):
            self.installer.apply("b" * 64, new_source, new_package, preview["expected"])
        self.installer._rename = original
        self.assertEqual(self.installer.preview("a" * 64, self.source, self.package)["change"], "current")
        self.assertEqual((self.root / "opt/sovagrid-vpn/sovagrid_vpn/amnezia_install.py").read_bytes(),
                         b"old module\n")

    def test_recover_pending_after_interrupted_swap(self):
        self._install()
        prior, _ = self.installer._state()
        new_source = {**self.source, "sovagrid_vpn/amnezia_install.py": b"new module\n"}
        new_package = {"amnezia_install.py": b"new module\n"}
        stage = "/opt/.sovagrid-vpn-source-" + "a" * 32
        pending = {"protocol": 1, "phase": "pending", "stage": stage,
                   "source_manifest_sha256": "b" * 64,
                   "source_files": self.installer._hashmap(new_source),
                   "package_files": self.installer._hashmap(new_package), "previous": prior}
        self.installer._save_state(pending)
        self.installer._mkdir(stage, 0o700)
        self.installer._write_tree(stage + "/new_source", new_source)
        self.installer._write_tree(stage + "/new_package", new_package)
        self.installer._rename("/opt/sovagrid-src/sovagrid-vpn", stage + "/old_source")
        self.installer._rename(stage + "/new_source", "/opt/sovagrid-src/sovagrid-vpn")
        with self.assertRaises(Refuse) as pending_error:
            self.installer.preview("b" * 64, new_source, new_package)
        self.assertEqual(pending_error.exception.code, "RECOVERY_REQUIRED")
        self.assertTrue(self.installer.recover()["recovered"])
        self.assertEqual(self.installer.preview("a" * 64, self.source, self.package)["change"], "current")
        self.assertFalse((self.root / stage.lstrip("/")).exists())

    def test_control_unit_blocks_source_update(self):
        self._install()
        unit = self.root / "etc/systemd/system/sovagrid-amnezia-control.service"
        unit.parent.mkdir(parents=True)
        unit.write_bytes(b"managed")
        source = {**self.source, "sovagrid_vpn/amnezia_install.py": b"new module\n"}
        with self.assertRaises(Refuse) as error:
            self.installer.preview("b" * 64, source, {"amnezia_install.py": b"new module\n"})
        self.assertEqual(error.exception.code, "CONTROL_ACTIVE")

    def test_python_bytecode_does_not_change_managed_source_hash(self):
        self._install()
        cache = self.root / "opt/sovagrid-vpn/sovagrid_vpn/__pycache__"
        cache.mkdir()
        (cache / "amnezia_install.cpython-311.pyc").write_bytes(b"compiled cache")
        self.assertEqual(self.installer.preview("a" * 64, self.source,
                                                self.package)["change"], "current")
        (cache / "foreign.txt").write_text("foreign", encoding="utf-8")
        with self.assertRaises(Refuse) as error:
            self.installer.preview("a" * 64, self.source, self.package)
        self.assertEqual(error.exception.code, "STATE_CONFLICT")


if __name__ == "__main__":
    unittest.main()
