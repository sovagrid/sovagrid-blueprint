# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Suggest a local public address only when the installer can ask the user."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "bootstrap/run.sh"
TEXT = SCRIPT.read_text()
CODE = TEXT.split("# SOVAGRID_BOOTSTRAP_ADDRESS_SUGGESTION_PY\n", 1)[1].split("\nPY\n}", 1)[0]
PREFIX = TEXT.split("configure_web() {\n", 1)[0]


def interface(*addresses, up=True):
    return {"flags": ["UP"] if up else [], "addr_info": [
        {"family": "inet", "scope": "global", "local": address}
        for address in addresses
    ]}


class AddressSuggestionTests(unittest.TestCase):
    def setUp(self):
        self.scope = {"__name__": "bootstrap_test"}
        exec(compile(CODE, str(SCRIPT), "exec"), self.scope)

    def test_single_global_unicast_address_is_suggested(self):
        choose = self.scope["single_public_ipv4"]
        self.assertEqual(choose([interface("10.0.0.5", "8.8.8.8")]), "8.8.8.8")
        self.assertEqual(choose([interface("8.8.8.8"), interface("8.8.8.8")]), "8.8.8.8")

    def test_private_multicast_down_and_ambiguous_addresses_are_not_suggested(self):
        choose = self.scope["single_public_ipv4"]
        for interfaces in ([interface("10.0.0.5", "192.168.1.5", "100.64.0.5")],
                           [interface("224.0.0.5")], [interface("8.8.8.8", up=False)],
                           [interface("8.8.8.8", "9.9.9.9")], [], {"local": "8.8.8.8"}):
            with self.subTest(interfaces=interfaces):
                self.assertEqual(choose(interfaces), "")

    def test_discovery_reads_only_local_interface_json_and_tolerates_failure(self):
        reply = SimpleNamespace(returncode=0, stdout=json.dumps([interface("8.8.8.8")]).encode())
        with patch.object(self.scope["subprocess"], "run", return_value=reply) as run:
            self.assertEqual(self.scope["discover"](), "8.8.8.8")
        self.assertEqual(run.call_args.args[0],
                         ["ip", "-j", "-4", "address", "show", "scope", "global"])
        for reply in (SimpleNamespace(returncode=1, stdout=b""),
                      SimpleNamespace(returncode=0, stdout=b"invalid"),
                      SimpleNamespace(returncode=0, stdout=b" " * 65537)):
            with self.subTest(reply=reply):
                with patch.object(self.scope["subprocess"], "run", return_value=reply):
                    self.assertEqual(self.scope["discover"](), "")


@unittest.skipUnless(shutil.which("bash"), "Bash is unavailable")
class InteractiveAddressChoiceTests(unittest.TestCase):
    def choice(self, *, arguments=(), environment=None, interactive=True, answer=None):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "discovery-called"
            script = (PREFIX + "\n"
                      "say() { :; }\n"
                      "suggest_public_ipv4() { "
                      f"printf called > {shlex.quote(str(marker))}; "
                      "printf '8.8.8.8\\n'; }\n"
                      f"suggest_address_if_interactive {int(interactive)}\n")
            if answer is not None:
                script += f"apply_public_address_answer {shlex.quote(answer)}\n"
            script += "printf '%s\\n' \"$public_address\"\n"
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith("SOVAGRID_")}
            env.update(environment or {})
            result = subprocess.run(["bash", "-c", script, "bootstrap_test", *arguments],
                                    env=env, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip(), marker.exists()

    def test_interactive_enter_accepts_suggestion_and_dash_selects_ssh(self):
        self.assertEqual(self.choice(answer=""), ("8.8.8.8", True))
        self.assertEqual(self.choice(answer="-"), ("", True))
        self.assertEqual(self.choice(answer="panel.example"), ("panel.example", True))

    def test_explicit_empty_and_nonempty_addresses_are_never_autodetected(self):
        for address in ("", "panel.example"):
            with self.subTest(address=address, source="environment"):
                self.assertEqual(self.choice(environment={"SOVAGRID_PUBLIC_ADDRESS": address}),
                                 (address, False))
            with self.subTest(address=address, source="argument"):
                self.assertEqual(self.choice(arguments=("--public-address", address)),
                                 (address, False))

    def test_noninteractive_and_configure_modes_never_autodetect(self):
        self.assertEqual(self.choice(interactive=False), ("", False))
        self.assertEqual(self.choice(environment={"SOVAGRID_SETUP_NONINTERACTIVE": "1"}),
                         ("", False))
        self.assertEqual(self.choice(arguments=("--configure-web",)), ("", False))


if __name__ == "__main__":
    unittest.main()
