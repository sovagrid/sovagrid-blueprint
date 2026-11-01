# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
"""Capability contracts have no OS-name admission list."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "platform_policy_sync",
    Path(__file__).resolve().parents[1] / "tools/sync_platform_policy.py",
)
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


class PlatformPolicyTests(unittest.TestCase):
    def test_contract_describes_capabilities_and_isolates_restore_format(self):
        data, minima = sync.policy(sync.ROOT / "platforms/requirements.json")
        self.assertEqual(
            minima, {"SOVAGRID_MIN_PYTHON": "3.10", "SOVAGRID_MIN_SYSTEMD": "247"}
        )
        self.assertNotIn("platforms", data)
        self.assertNotIn("versions", data["managed_host"])
        self.assertEqual(data["managed_host"]["automatic_package_adapters"], ["apt"])
        self.assertEqual(
            data["portable_restore"]["platform_pairs"],
            ["ubuntu:22.04", "ubuntu:24.04", "ubuntu:26.04"],
        )

    def test_invalid_schema_or_unimplemented_capability_changes_refuse(self):
        original, _ = sync.policy(sync.ROOT / "platforms/requirements.json")
        cases = [None, [], {}]
        for key, value in [
            ("python_minimum", "3.9"),
            ("python_minimum", 3.10),
            ("systemd_minimum", "246"),
            ("systemd_minimum", 247.0),
            ("automatic_package_adapters", ["dnf"]),
            ("kernel", "darwin"),
        ]:
            data = copy.deepcopy(original)
            data["managed_host"][key] = value
            cases.append(data)
        data = copy.deepcopy(original)
        data["platforms"] = ["ubuntu"]
        cases.append(data)
        data = copy.deepcopy(original)
        data["portable_restore"]["platform_pairs"].append("debian:13")
        cases.append(data)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "requirements.json"
            for data in cases:
                with self.subTest(data=data):
                    path.write_text(json.dumps(data))
                    with self.assertRaises(ValueError):
                        sync.policy(path)

    def test_raised_minima_are_renderable_without_adding_os_names(self):
        data, _ = sync.policy(sync.ROOT / "platforms/requirements.json")
        data["managed_host"]["python_minimum"] = "3.11"
        data["managed_host"]["systemd_minimum"] = "250"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "requirements.json"
            path.write_text(json.dumps(data))
            _, minima = sync.policy(path)
            self.assertEqual(
                minima, {"SOVAGRID_MIN_PYTHON": "3.11", "SOVAGRID_MIN_SYSTEMD": "250"}
            )

    def test_all_standalone_styles_detect_drift_and_sync_minimum(self):
        samples = [
            "SOVAGRID_MIN_PYTHON='3.10'\n",
            'SOVAGRID_MIN_PYTHON = "3.10"\n',
            'const SOVAGRID_MIN_PYTHON = "3.10";\n',
            "        \"SOVAGRID_MIN_PYTHON='3.10'\",\n",
        ]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for index, sample in enumerate(samples):
                filename = str(index)
                (root / filename).write_text(sample)
                self.assertEqual(
                    sync.synchronize(root, "3.11", targets=(filename,)), [filename]
                )
                self.assertEqual((root / filename).read_text(), sample)
                sync.synchronize(root, "3.11", targets=(filename,), write=True)
                self.assertEqual(
                    sync.synchronize(root, "3.11", targets=(filename,)), []
                )
                self.assertEqual(
                    (root / filename).read_text(), sample.replace("3.10", "3.11")
                )

    def test_missing_anchor_fails_instead_of_skipping_client(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "client").write_text("unconnected policy")
            with self.assertRaisesRegex(ValueError, "missing standalone requirement"):
                sync.synchronize(root, "3.10", targets=("client",))

    def test_old_os_admission_list_is_rejected_even_with_minimum_markers(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "client").write_text(
                "SOVAGRID_MIN_PYTHON='3.10'\nSOVAGRID_PLATFORM_PAIRS='ubuntu:22.04'\n"
            )
            with self.assertRaisesRegex(ValueError, "obsolete OS admission list"):
                sync.synchronize(root, "3.10", targets=("client",))
