# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Existing-install Web setup must preserve data and recover the old route."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).resolve().parents[1] / "bootstrap/run.sh"
TEXT = SCRIPT.read_text()
CODE = TEXT.split("# SOVAGRID_BOOTSTRAP_WEB_CONFIGURE_PY\n", 1)[1].split("\nPY\n}", 1)[0]


def code():
    scope = {"__name__": "bootstrap_test"}
    exec(compile(CODE, str(SCRIPT), "exec"), scope)
    return scope


class WebConfigureTests(unittest.TestCase):
    def setUp(self):
        self.module = code()
        self.local_config = {"panel_path": "/control/panel/", "root_behavior": "untouched"}
        self.local = {"enabled": True, "config": self.local_config,
                      "expected_state_sha256": "a" * 64}
        self.disabled = {"enabled": False, "config": None, "expected_state_sha256": None}
        self.preview = {"expected_state_sha256": None, "source_manifest_sha256": "b" * 64}

    def test_local_to_public_preserves_existing_path_and_uses_cas(self):
        call = Mock(side_effect=[self.disabled, self.local, self.disabled,
                                 self.preview, {"url": "https://panel.example"}])
        validate = Mock(side_effect=lambda value: value)
        url = self.module["configure"]("panel.example", "", "", call, validate)
        self.assertEqual(url, "https://panel.example/control/panel/")
        self.assertEqual(call.call_args_list[2].args,
                         ("local_web.py", "disable", {"expected_state_sha256": "a" * 64}))
        request = call.call_args_list[-1].args[2]
        self.assertEqual(request["expected_state_sha256"], None)
        self.assertEqual(request["config"]["panel_path"], "/control/panel/")
        self.assertEqual(request["source_manifest_sha256"], "b" * 64)

    def test_public_failure_restores_original_local_config(self):
        failure = self.module["HelperError"]("certificate unavailable")
        call = Mock(side_effect=[self.disabled, self.local, self.disabled, failure,
                                 self.disabled, self.disabled, self.preview, {"ok": True}])
        with self.assertRaisesRegex(ValueError, "прежний локальный путь восстановлен"):
            self.module["configure"]("panel.example", "", "", call, lambda value: value)
        self.assertEqual(call.call_args_list[-1].args[2]["config"], self.local_config)
        self.assertEqual(call.call_args_list[-1].args[2]["expected_state_sha256"], None)

    def test_concurrent_change_is_not_overwritten_during_rollback(self):
        failure = self.module["HelperError"]("public failed")
        changed = {**self.disabled, "enabled": True}
        call = Mock(side_effect=[self.disabled, self.local, self.disabled, failure,
                                 changed, self.disabled])
        with self.assertRaisesRegex(ValueError, "восстановление локального пути не подтверждено"):
            self.module["configure"]("panel.example", "", "", call, lambda value: value)
        self.assertFalse(any(item.args[1] == "apply" for item in call.call_args_list))

    def test_invalid_config_does_not_disable_local_route(self):
        call = Mock(side_effect=[self.disabled, self.local])
        validate = Mock(side_effect=ValueError("invalid address"))
        with self.assertRaisesRegex(ValueError, "invalid address"):
            self.module["configure"]("https://invalid", "", "", call, validate)
        self.assertEqual(call.call_count, 2)

    def fixture(self, root):
        components = self.module["COMPONENTS"]
        hashes = {}
        for name in components:
            folder = root / name
            folder.mkdir(mode=0o755)
            payload = b"reviewed source\n"
            path = folder / "source.py"
            path.write_bytes(payload)
            path.chmod(0o644)
            hashes[path.relative_to(root).as_posix()] = hashlib.sha256(payload).hexdigest()
        raw = (json.dumps({"format": 1, "components": {name: {} for name in components},
                           "sha256": hashes}, sort_keys=True) + "\n").encode()
        (root / "sovagrid-bundle.json").write_bytes(raw)
        (root / "sovagrid-bundle.json").chmod(0o644)
        return hashlib.sha256(raw).hexdigest()

    def test_mismatched_manifest_or_source_refuses_before_import_or_helper(self):
        self.module["ROOT_UID"] = os.getuid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self.fixture(root)
            with patch.object(self.module["importlib"].util, "spec_from_file_location") as load:
                with self.assertRaisesRegex(ValueError, "нужен проверенный"):
                    self.module["main"]([str(root), "0" * 64, "panel.example", "", ""])
                load.assert_not_called()
                (root / "sovagrid-blueprint/source.py").write_bytes(b"raise RuntimeError('untrusted')\n")
                with self.assertRaisesRegex(ValueError, "исходники изменены"):
                    self.module["main"]([str(root), expected, "panel.example", "", ""])
                load.assert_not_called()

    def test_exact_source_passes_and_symlink_is_refused(self):
        self.module["ROOT_UID"] = os.getuid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self.fixture(root)
            self.module["verify_source"](root, expected)
            path = root / "sovagrid-blueprint/source.py"
            path.unlink()
            path.symlink_to(root / "sovagrid-hub/source.py")
            with self.assertRaisesRegex(ValueError, "небезопасный путь"):
                self.module["verify_source"](root, expected)


if __name__ == "__main__":
    unittest.main()
