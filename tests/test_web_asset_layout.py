# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Gate modular Web archives while preserving legacy updater compatibility."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from deploy import web_assets
from package_server import web_compatibility_files


class ModularAssetsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.web = Path(temporary.name) / "sovagrid-web"
        self.web.mkdir()
        self.manifest = self.web / web_assets.ENTRYPOINTS
        self.paths = {
            name: f"assets/{name.rsplit('.', 1)[1]}/features/{name}"
            for name in web_assets.RESTORE_ASSETS
        }

    def regular(self, relative: str) -> Path:
        file = self.web / relative
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(f"{relative}\n")
        return file

    def legacy(self) -> None:
        for name in self.paths:
            self.regular(name)

    def modular(self) -> None:
        for relative in self.paths.values():
            self.regular(relative)
        self.manifest.write_text(json.dumps({"assets": self.paths}))

    def installer_check(self) -> subprocess.CompletedProcess:
        """Use the same isolated CLI as run.sh before service mutations."""
        return subprocess.run(
            [sys.executable, "-B", "-I", web_assets.__file__, str(self.web)],
            capture_output=True, text=True, check=False,
        )

    def test_install_accepts_both_complete_layouts(self):
        self.legacy()
        self.assertEqual(self.installer_check().returncode, 0)
        for name in self.paths:
            (self.web / name).unlink()
        self.modular()
        self.assertEqual(self.installer_check().returncode, 0)

    def test_modular_tree_never_falls_back_to_legacy_aliases(self):
        self.legacy()
        self.modular()
        live = self.web / self.paths["host-restore.js"]
        live.unlink()
        result = self.installer_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn(self.paths["host-restore.js"], result.stderr)
        self.manifest.unlink()
        self.assertEqual(self.installer_check().returncode, 1)

    def test_modular_paths_cannot_point_outside_the_asset_tree(self):
        self.modular()
        for bad in ("../host-restore.js", "/assets/js/host-restore.js",
                    "assets/js/../host-restore.js", "assets/css/host-restore.js"):
            with self.subTest(value=bad):
                self.manifest.write_text(json.dumps({"assets": {**self.paths, "host-restore.js": bad}}))
                self.assertEqual(self.installer_check().returncode, 1)
        self.modular()
        original = self.web / "assets/js/features"
        moved = self.web / "outside"
        original.rename(moved)
        original.symlink_to(moved)
        self.assertEqual(self.installer_check().returncode, 1)

    def test_archive_aliases_use_only_tracked_modular_assets(self):
        self.modular()
        entries = [(Path(name), 0o100644)
                   for name in [web_assets.ENTRYPOINTS, *self.paths.values()]]
        aliases = web_compatibility_files(self.web, entries)
        self.assertEqual(
            {name: (path.relative_to(self.web).as_posix(), mode) for path, name, mode in aliases},
            {f"sovagrid-web/{name}": (relative, 0o100644) for name, relative in self.paths.items()},
        )
        with self.assertRaisesRegex(SystemExit, "must be tracked"):
            web_compatibility_files(self.web, entries[:-1])
        self.regular("host-restore.js")
        with self.assertRaisesRegex(SystemExit, "conflicts"):
            web_compatibility_files(self.web, [*entries, (Path("host-restore.js"), 0o100644)])


if __name__ == "__main__":
    unittest.main()
