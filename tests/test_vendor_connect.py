# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""The server bundle carries an exact and usable Connect enrollment runtime."""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/sync_connect_vendor.py"
VENDOR = ROOT / "vendor/connect"


def load_sync():
    spec = importlib.util.spec_from_file_location("sync_connect_vendor", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class VendoredConnectTests(unittest.TestCase):
    def test_locked_bytes_and_optional_exact_upstream_comparison(self):
        sync = load_sync()
        files = sync.verify_vendored()
        self.assertEqual(set(files), sync.SELECTED_FILES)
        source = ROOT.parent / "sovagrid-connect"
        if source.is_dir():
            self.assertEqual(files, sync.source_files(source))

    def test_one_changed_file_breaks_offline_lock(self):
        sync = load_sync()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "sovagrid_connect"
            shutil.copytree(VENDOR / "sovagrid_connect", package)
            lock = root / "SOURCE.json"
            shutil.copy2(VENDOR / "SOURCE.json", lock)
            sync.verify_vendored(package, lock)
            key = package / "__init__.py"
            key.write_bytes(key.read_bytes() + b"# unexpected edit\n")
            with self.assertRaises(sync.VendorError):
                sync.verify_vendored(package, lock)

    def test_enrollment_runtime_imports_without_tk(self):
        script = """
import sys
sys.path.insert(0, sys.argv[1])
from sovagrid_connect.agent_enrollment import AgentEnrollment
from sovagrid_connect.enrollment_api import EnrollmentAPI
from sovagrid_connect.agent_rpc import AgentRPC
from sovagrid_connect.enrollment_journal import EnrollmentJournal
assert AgentEnrollment and EnrollmentAPI and AgentRPC and EnrollmentJournal
assert 'tkinter' not in sys.modules
assert 'sovagrid_connect.gui' not in sys.modules
assert sys.modules['sovagrid_connect.agent_enrollment'].__file__.startswith(sys.argv[1])
"""
        result = subprocess.run((sys.executable, "-B", "-I", "-c", script, str(VENDOR)),
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr[-1000:])

    def test_ubuntu_relative_import_closure_stays_explicit(self):
        sync = load_sync()
        selected_modules = {Path(name).stem for name in sync.SELECTED_FILES if name.endswith('.py')}
        optional_desktop_only = {('core', 'ssh_grant'), ('enrollment_journal', 'keygen')}
        for name in sync.SELECTED_FILES:
            if not name.endswith('.py'):
                continue
            module = Path(name).stem
            tree = ast.parse((VENDOR / name).read_text(encoding='utf-8'), filename=name)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
                    self.assertTrue(node.module in selected_modules or
                        (module, node.module) in optional_desktop_only,
                        f'{module} imports an unvendored runtime module {node.module}')


if __name__ == "__main__":
    unittest.main()
