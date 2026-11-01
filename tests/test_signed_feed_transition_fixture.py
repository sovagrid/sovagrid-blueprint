# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Offline check of the disposable VM's faithful broker-sandbox copy."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("signed_vm_fixture", Path(__file__).with_name("signed_feed_transition_vm.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class SandboxFixtureTests(unittest.TestCase):
    def test_pinned_legacy_full_uses_the_old_zero_argument_api(self):
        class LegacyFeed:
            def current_manifest(self):
                return fixture.LEGACY_FULL_MANIFEST
        with patch.object(fixture.os.path, "lexists", return_value=False):
            self.assertEqual(fixture.transition_current(LegacyFeed(), "full", legacy_full=True),
                             fixture.LEGACY_FULL_MANIFEST)

    def test_current_api_keeps_explicit_layout_and_default_portable_mode(self):
        seen = []
        class CurrentFeed:
            def current_manifest(self, layout):
                seen.append(layout)
                return "a" * 64
        self.assertEqual(fixture.transition_current(CurrentFeed(), "hub_only"), "a" * 64)
        self.assertEqual(seen, ["hub_only"])

    def test_legacy_mode_refuses_other_source_layout_or_existing_restore_provenance(self):
        class WrongFeed:
            def current_manifest(self): return "a" * 64
        with self.assertRaisesRegex(SystemExit, "published 0.14.1"):
            fixture.transition_current(WrongFeed(), "full", legacy_full=True)
        with self.assertRaisesRegex(SystemExit, "only.*full baseline"):
            fixture.transition_current(WrongFeed(), "hub_only", legacy_full=True)
        class LegacyFeed:
            def current_manifest(self): return fixture.LEGACY_FULL_MANIFEST
        with patch.object(fixture.os.path, "lexists", return_value=True), \
             self.assertRaisesRegex(SystemExit, "provenance ledger"):
            fixture.transition_current(LegacyFeed(), "full", legacy_full=True)

    def test_installed_unit_repeated_write_paths_are_all_preserved(self):
        text = (ROOT / "deploy/sovagrid-hub-backup-control.service").read_text()
        properties = fixture.sandbox_properties(text)
        writable = properties["ReadWritePaths"].split()
        self.assertIn("/var/lib/sovagrid", writable)
        self.assertIn("/opt/sovagrid-candidates", writable)
        self.assertIn("/etc/sovagrid-hub", writable)
        self.assertIn("-/run/sovagrid-installation.lock", writable)
        self.assertIn("-/run/sovagrid-promotion.lock", writable)
        self.assertNotIn("/run", writable)
        self.assertEqual(properties["ProtectSystem"], "strict")
        self.assertEqual(properties["NoNewPrivileges"], "true")
        self.assertEqual(properties["AmbientCapabilities"], "")

    def test_reset_of_a_systemd_list_does_not_reintroduce_earlier_mounts(self):
        text = """[Service]
ProtectSystem=strict
ReadWritePaths=/run
ReadWritePaths=
ReadWritePaths=/etc/sovagrid-hub
ReadWritePaths=/run/sovagrid-installation.lock /run/sovagrid-promotion.lock
"""
        self.assertNotIn("/run", fixture.sandbox_properties(text)["ReadWritePaths"].split())

    def test_missing_or_broadened_sandbox_refuses_the_gate(self):
        text = (ROOT / "deploy/sovagrid-hub-backup-control.service").read_text()
        for changed in (text.replace("ProtectSystem=strict", "ProtectSystem=false"),
                        text.replace("/etc/sovagrid-hub", ""),
                        text + "\nReadWritePaths=/run\n",
                        text + "\nReadWritePaths=-/run\n",
                        text + "\nReadWritePaths=-/\n"):
            with self.subTest(changed=changed[-80:]), self.assertRaises(SystemExit):
                fixture.sandbox_properties(changed)
