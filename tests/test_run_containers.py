# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Container inventory remains opt-in and survives managed updates safely."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "run.sh"
UPDATER = ROOT / "deploy" / "remote_update_worker.py"
AGENT = ROOT.parent / "sovagrid-agent"


class ContainerInstallTests(unittest.TestCase):
    def test_no_broad_socket_or_group_grant(self):
        source = RUN.read_text()
        self.assertIn("--with-containers", source)
        self.assertIn("--disable-containers", source)
        self.assertNotIn("usermod -aG docker", source)
        self.assertNotIn("usermod -aG podman", source)

    def test_bounded_systemd_service_when_agent_checkout_is_present(self):
        unit_path = AGENT / "deploy" / "sovagrid-container-inventory.service"
        if not unit_path.is_file():
            self.skipTest("Agent checkout is tested in its own repository")
        unit = unit_path.read_text()
        self.assertIn("ReadWritePaths=/var/lib/sovagrid-containers", unit)
        self.assertIn("SupplementaryGroups=docker", unit)
        self.assertIn("CapabilityBoundingSet=\n", unit)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("TimeoutStartSec=30", unit)
        self.assertNotIn("docker.sock", (AGENT / "deploy" / "sovagrid-agent.service").read_text())

    def test_updater_snapshots_opt_in_units_and_data(self):
        source = UPDATER.read_text()
        for expected in ("--with-containers", "sovagrid-container-inventory.timer",
                         "sovagrid-container-inventory.service", "/var/lib/sovagrid-containers",
                         "SOVAGRID_CONTAINER_INVENTORY_V1"):
            self.assertIn(expected, source)

    def test_argument_parser_rejects_ambiguous_opt_in(self):
        if shutil.which("bash") is None:
            self.skipTest("Bash unavailable")
        major = int(subprocess.check_output(["bash", "-c", "printf '%s' \"${BASH_VERSINFO[0]}\""]))
        if major < 4:
            self.skipTest("Ubuntu Bash 4+ required")
        source = RUN.read_text()
        start = source.index("hub_only=0\n")
        end = source.index("if (( containers_disable_requested )); then", start)
        parser = ("set -euo pipefail\n"
                  "die() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
                  + source[start:end]
                  + "printf 'OK:%s\\n' \"$containers_requested\"\n")
        def invoke(*args):
            return subprocess.run(["bash", "-c", parser, "sovagrid", *args], capture_output=True, text=True)
        accepted = invoke("--with-containers")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn("OK:1", accepted.stdout)
        for args in (("--with-containers", "--with-containers"),
                     ("--disable-containers", "--disable-containers"),
                     ("--with-containers", "--disable-containers")):
            with self.subTest(args=args):
                self.assertNotEqual(invoke(*args).returncode, 0)


if __name__ == "__main__":
    unittest.main()
