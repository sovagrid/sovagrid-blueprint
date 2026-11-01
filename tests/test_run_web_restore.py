# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Run the installer's actual restore preflight without touching host paths."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from tests.test_web_restore_update_compat import worker

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "run.sh").read_text()


class WebRestoreInstallSafety(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        start = SOURCE.index("web_restore_preflight() {")
        end = SOURCE.index("\n}\nweb_restore_preflight\n", start) + 3
        self.preflight = SOURCE[start:end].replace("/var", '"$fixture/var"')
        self.shim = '''
stat() { python3 -c 'import os,stat,sys; i=os.lstat(sys.argv[-1]); u=1 if sys.argv[-1]==os.environ.get("BAD_UID") else 0; g=1 if sys.argv[-1]==os.environ.get("BAD_GID") else 0; print(str(u) if sys.argv[2]=="%u" else f"{u}:{g}:{stat.S_IMODE(i.st_mode):o}")' "$@"; }
find() { python3 -c 'import os,sys; print(sys.argv[1] if os.lstat(sys.argv[1]).st_mode & 0o022 else "",end="")' "$@"; }
die() { printf '%s\\n' "$*" >&2; exit 1; }
'''
        self.namespaces = [self.root / "var/lib/sovagrid/web-agent/restores", self.root / "var/cache/sovagrid-web-restores"]
        for path in self.namespaces:
            path.parent.mkdir(parents=True, exist_ok=True)

    def invoke(self, **env):
        script = 'set -euo pipefail\nfixture=$1\n' + self.shim + self.preflight + '\nweb_restore_preflight\n'
        return subprocess.run(["bash", "-c", script, "preflight", str(self.root)], text=True,
            capture_output=True, env={**os.environ, **env})

    def test_fresh_install_does_not_create_namespaces_and_checks_before_systemd(self):
        self.assertEqual(self.invoke().returncode, 0)
        self.assertTrue(all(not path.exists() for path in self.namespaces))
        install = SOURCE[SOURCE.index("install_web_agent_service() {"):SOURCE.index("reserve_identity() {")]
        self.assertLess(install.index("web_restore_preflight"), install.index("systemctl daemon-reload"))
        self.assertIn("# SOVAGRID_WEB_RESTORE_V1\n", SOURCE)
        subprocess.run(["bash", "-n", str(ROOT / "run.sh")], check=True)

    def test_existing_private_directories_are_accepted_without_repairs(self):
        for path in self.namespaces: path.mkdir(mode=0o700)
        self.assertEqual(self.invoke().returncode, 0)
        for path in self.namespaces: self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_unsafe_existing_mode_identity_link_and_ancestor_refuse_without_changing_them(self):
        for path in self.namespaces:
            path.mkdir(mode=0o755)
            path.chmod(0o755)
            self.assertNotEqual(self.invoke().returncode, 0)
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
            path.chmod(0o700)
            for variable in ("BAD_UID", "BAD_GID"):
                self.assertNotEqual(self.invoke(**{variable: str(path)}).returncode, 0)
            path.rmdir(); path.write_text("foreign data")
            self.assertNotEqual(self.invoke().returncode, 0)
            self.assertEqual(path.read_text(), "foreign data")
            path.unlink(); path.symlink_to(self.root / "missing", target_is_directory=True)
            self.assertNotEqual(self.invoke().returncode, 0)
            self.assertTrue(path.is_symlink()); path.unlink()
        parent = self.namespaces[0].parent
        parent.rmdir(); parent.symlink_to(self.root / "outside", target_is_directory=True)
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertTrue(parent.is_symlink())

    def test_actual_required_closure_rejects_a_missing_or_linked_restore_runtime(self):
        start = SOURCE.index("for web_restore_file in ")
        end = SOURCE.index("\ndone\n", start) + len("\ndone\n")
        closure = SOURCE[start:end]
        for name in worker.WEB_RESTORE_REQUIRED:
            self.assertIn(name, closure)
            self.assertTrue((ROOT.parent / name).is_file(), name)
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("fixture")
        script = 'set -euo pipefail\nsource_root=$1\n' + self.shim + closure
        def check():
            return subprocess.run(["bash", "-c", script, "closure", str(self.root)], capture_output=True, text=True)
        self.assertEqual(check().returncode, 0)
        for name in worker.WEB_RESTORE_REQUIRED:
            path = self.root / name; path.unlink()
            self.assertNotEqual(check().returncode, 0, name)
            path.symlink_to(ROOT / "run.sh")
            self.assertNotEqual(check().returncode, 0, name)
            path.unlink(); path.write_text("fixture")


if __name__ == "__main__":
    unittest.main()
