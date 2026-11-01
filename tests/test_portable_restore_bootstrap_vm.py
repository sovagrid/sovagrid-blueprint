# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The hosted bootstrap smoke must never run on an unselected local host."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("sovagrid_bootstrap_vm_guard",
    Path(__file__).with_name("portable_restore_bootstrap_vm.py"))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class BootstrapVmGuardTest(unittest.TestCase):
    def test_every_hosted_selection_and_manifest_pin_precedes_source_reads_or_execution(self):
        good = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                "SOVAGRID_PORTABLE_RESTORE_DISPOSABLE": "1", "SOVAGRID_RESTORE_EXPECTED_MANIFEST": "a" * 64}
        for missing in (*good, "root"):
            environment = dict(good)
            if missing != "root": environment.pop(missing)
            with (self.subTest(missing=missing), patch.dict(os.environ, environment, clear=True),
                  patch.object(vm.os, "geteuid", return_value=1000 if missing == "root" else 0),
                  patch.object(vm.Path, "read_text") as read, patch.object(vm, "smoke") as smoke):
                with self.assertRaisesRegex(RuntimeError, "requires (explicit fresh|the artifact-pinned)"):
                    vm.main(["/private/source.tar.gz"])
                read.assert_not_called()
                smoke.assert_not_called()

    def test_self_hosted_runner_is_refused_even_with_explicit_disposable_flag(self):
        environment = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted", "RUNNER_OS": "Linux",
                       "SOVAGRID_PORTABLE_RESTORE_DISPOSABLE": "1", "SOVAGRID_RESTORE_EXPECTED_MANIFEST": "a" * 64}
        with patch.dict(os.environ, environment, clear=True), patch.object(vm.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "explicit fresh"):
                vm.guard()

    def test_source_pin_mismatch_never_imports_verifier(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            manifest = bundle / "sovagrid-bundle.json"
            manifest.write_bytes(b"untrusted source map")
            manifest.chmod(0o644)
            real_lstat = vm.Path.lstat
            def root_owned(path):
                info = real_lstat(path)
                values = list(info)
                values[4] = values[5] = 0
                values[0] = (values[0] & ~0o022) if path == manifest else stat.S_IFDIR | 0o755
                return os.stat_result(values)
            with (patch.object(vm.Path, "is_relative_to", return_value=True),
                  patch.object(vm.Path, "lstat", root_owned), patch.object(vm.importlib.util, "spec_from_file_location") as load):
                with self.assertRaisesRegex(RuntimeError, "source manifest pin mismatch"):
                    vm.source_verifier(bundle, "a" * 64)
                load.assert_not_called()

    def test_helper_output_is_bounded_and_failures_do_not_expose_private_stderr(self):
        expected = {"ok": True, "protocol": vm.PROTOCOL}
        self.assertEqual(vm.command([sys.executable, "-c", "print(" + repr(json.dumps(expected)) + ")"], b"", timeout=5), [expected])
        for script in ("print('x'*65537)",
                       "import sys; print('private credential',file=sys.stderr); sys.exit(40)"):
            with self.subTest(script=script):
                with self.assertRaisesRegex(RuntimeError, "fixed bootstrap/receiver command") as error:
                    vm.command([sys.executable, "-c", script], b"", timeout=5)
                self.assertNotIn("private credential", str(error.exception))


if __name__ == "__main__": unittest.main()
