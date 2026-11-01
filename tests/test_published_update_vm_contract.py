# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Offline contracts for the manually selected published-baseline VM gates."""
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("published_hub_candidate_test", ROOT / "tests/hub_only_candidate.py")
candidate = importlib.util.module_from_spec(spec); spec.loader.exec_module(candidate)


class PublishedUpdateVMContract(unittest.TestCase):
    def test_candidate_requires_four_exact_component_refs(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(SystemExit, "exact reviewed"):
            candidate.candidate_commits()
        selected = {key + "_REF": chr(ord("a") + index) * 40 for index, key in enumerate(("HUB", "WEB", "AGENT", "VPN"))}
        with patch.dict(os.environ, selected, clear=True):
            self.assertEqual(len(candidate.candidate_commits()), 4)
            with patch.dict(os.environ, {"WEB_REF": "main"}), self.assertRaises(SystemExit):
                candidate.candidate_commits()

    def test_full_gate_uses_installed_published_upgrader_and_hub_gate_keeps_manual_then_signed(self):
        full = (ROOT / ".github/workflows/release-feed-migration-vm.yml").read_text()
        hub = (ROOT / ".github/workflows/hub-only-update-vm.yml").read_text()
        for source in (full, hub):
            self.assertIn("server-v0.14.1/SovaGrid-server-source.tar.gz", source)
            self.assertIn("c5786bb64467063196046144e665a98e347f40713facb37809b65a03eb70f347", source)
            self.assertIn("ec6f567b0292916dd3f104f1441451708a955b79d02ef91f82237a8cf8603f1f", source)
            self.assertIn('test "$GITHUB_ACTIONS" = true', source)
            self.assertIn('("/usr/local", "/usr/local/bin", "/usr/local/libexec")', source)
            self.assertNotIn("rm -rf", source)
        self.assertIn("source.tar.gz full legacy-full", full)
        self.assertLess(full.index("run.sh\n"), full.index("source.tar.gz full legacy-full"))
        self.assertNotIn("VM fixture: full Hub upgrade", full)
        self.assertLess(hub.index("Update local Hub and second Agent"), hub.index("Build the next signed Hub-only"))
        self.assertNotIn("0.11.0", hub)

    def test_embedded_workflow_shell_and_python_syntax(self):
        for filename in ("release-feed-migration-vm.yml", "hub-only-update-vm.yml"):
            source = (ROOT / ".github/workflows" / filename).read_text()
            # Workflow literal run blocks have ten-space indentation. Check
            # their real Bash/heredocs; no commands in these blocks execute.
            for index, match in enumerate(re.finditer(r"        run: \|\n((?:          .*\n|\n)+)", source)):
                body = "\n".join(line[10:] if line.startswith("          ") else line for line in match[1].splitlines())
                result = subprocess.run(["bash", "-n"], input=body, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, f"{filename} block {index}: {result.stderr}")
                for code in re.finditer(r"<<'(PY|PYTHON)'\n(.*?)\n\1(?:\n|$)", body, re.DOTALL):
                    compile(code[2], f"{filename}:block-{index}", "exec")


if __name__ == "__main__":
    unittest.main()
