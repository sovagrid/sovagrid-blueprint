# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Exercise the real run.sh argument parser without touching a server."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "run.sh"


class JournalInstallSafety(unittest.TestCase):
    def test_disable_revokes_agent_before_stopping_broker(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertLess(source.index('value["allow_systemd_journal"] = False'),
                        source.index('systemctl disable --now sovagrid-journal-control.socket'))
        self.assertIn('if (( journal_disable_requested )); then', source)
        self.assertIn('if (( with_journal )); then', source)
        self.assertNotIn('usermod -aG systemd-journal sovagrid', source)


class JournalInstallArguments(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("bash") is None:
            raise unittest.SkipTest("Bash is unavailable")
        version = subprocess.check_output(["bash", "-c", "printf '%s' \"${BASH_VERSINFO[0]}\""])
        if int(version) < 4:
            raise unittest.SkipTest("run.sh targets Ubuntu Bash 4+")
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("hub_only=0\n")
        end = source.index("if (( ! hub_only )) && [[ -f /etc/sovagrid/.terminal-unit-managed-by-run-sh ]]", start)
        cls.parser = (
            "set -euo pipefail\n"
            "die() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
            + source[start:end]
            + "printf 'OK:%s:%s\\n' \"$journal_requested\" \"${#journal_units[@]}\"\n"
        )

    def invoke(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["bash", "-c", self.parser, "sovagrid", *args],
                              capture_output=True, text=True)

    def test_explicit_allowlist(self) -> None:
        result = self.invoke("--journal-unit", "ssh.service", "--with-journal",
                             "--journal-unit", "nginx@site-1.service")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OK:1:2", result.stdout)
        disabled = self.invoke("--disable-journal")
        self.assertEqual(disabled.returncode, 0, disabled.stderr)
        self.assertIn("OK:0:0", disabled.stdout)

    def test_unsafe_or_missing_options_fail_before_install(self) -> None:
        cases = [
            ("--with-journal",),
            ("--journal-unit", "ssh.service"),
            ("--with-journal", "--journal-unit"),
            ("--with-journal", "--journal-unit", "ssh.service;id"),
            ("--with-journal", "--journal-unit", "ssh.service", "--journal-unit", "ssh.service"),
            ("--with-journal", "--with-journal", "--journal-unit", "ssh.service"),
            ("--disable-journal", "--with-journal", "--journal-unit", "ssh.service"),
            ("--disable-journal", "--journal-unit", "ssh.service"),
            ("--with-journal", *(part for _ in range(17) for part in ("--journal-unit", f"svc{_}.service"))),
        ]
        for args in cases:
            with self.subTest(args=args):
                result = self.invoke(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("OK:", result.stdout)


if __name__ == "__main__":
    unittest.main()
