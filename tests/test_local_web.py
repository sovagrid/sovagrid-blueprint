#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Local-only panel route transactions do not publish ports or lose rollback."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests.test_hub_only_update import update as hub_only


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("local_web_fixture", ROOT / "deploy/local_web.py")
web = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(web)
CONFIG = {"panel_path": "/ops/monitoring/", "root_behavior": "untouched"}
SOURCE = "a" * 64


class Fixture(web.LocalWeb):
    def __init__(self, root):
        super().__init__(root, uid=os.getuid(), runner=lambda *_args, **_kwargs: b"")
        self.running = None
        self.fail_health = False
        self.fail_start = False
        self.starts = []

    def source(self):
        return SOURCE

    def public_inactive(self):
        return None

    def templates(self):
        return "services:\n  web:\n    volumes:\n      - source: $caddy_dir\n        target: /etc/caddy/local\n        read_only: true\n"

    def validate_compose(self, _state):
        return None

    def start(self, state):
        if self.fail_start:
            raise web.LocalWebError("COMMAND_FAILED")
        self.running = None if state is None else state["generation"]
        self.starts.append(self.running)

    def runtime_matches(self, state):
        return self.running == (None if state is None else state["generation"])

    def panel_health(self, _config):
        if self.fail_health:
            self.fail_health = False
            raise web.LocalWebError("LOCAL_UNHEALTHY")

    def local_health(self):
        return None


class LocalWebTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "etc/sovagrid").mkdir(parents=True)
        (self.root / "var/lib/sovagrid").mkdir(parents=True, mode=0o700)
        (self.root / "var/lib/sovagrid").chmod(0o700)
        self.helper = Fixture(self.root)

    def test_config_and_generation_are_bounded(self):
        self.assertEqual(web.validate_config(CONFIG), CONFIG)
        for value in ({**CONFIG, "panel_path": "/api/v1/"},
                      {**CONFIG, "panel_path": "/wrong//"},
                      {**CONFIG, "panel_path": "http://host/"},
                      {**CONFIG, "root_behavior": ["redirect"]},
                      {"panel_path": CONFIG["panel_path"]}):
            with self.assertRaises(web.LocalWebError):
                web.validate_config(value)
        files = web.render(CONFIG, "/etc/sovagrid/local-web/generations/" + "a" * 32,
                           self.helper.templates())
        self.assertEqual(set(files), {"caddy/panel.caddy", "compose.yaml"})
        self.assertIn(b"handle_path /ops/monitoring/*", files["caddy/panel.caddy"])
        self.assertNotIn(b"redir / /ops/monitoring/", files["caddy/panel.caddy"])
        self.assertNotIn(b"443", files["compose.yaml"])
        self.assertNotIn(b"9443", files["compose.yaml"])

    def test_apply_cas_rollback_and_disable(self):
        preview = self.helper.preview(CONFIG)
        self.assertEqual(preview["expected_state_sha256"], None)
        applied = self.helper.apply(CONFIG, None, SOURCE, lock_held=True)
        self.assertTrue(applied["enabled"])
        old, old_sha = self.helper.state()
        self.assertEqual(old_sha, applied["expected_state_sha256"])
        self.assertEqual(self.helper.running, old["generation"])
        with self.assertRaises(web.LocalWebError) as stale:
            self.helper.apply({**CONFIG, "panel_path": "/other/"}, None, SOURCE, lock_held=True)
        self.assertEqual(stale.exception.code, "STATE_CHANGED")
        self.helper.fail_health = True
        with self.assertRaises(web.LocalWebError) as unhealthy:
            self.helper.apply({**CONFIG, "panel_path": "/other/"}, old_sha, SOURCE,
                              lock_held=True)
        self.assertEqual(unhealthy.exception.code, "LOCAL_UNHEALTHY")
        restored, restored_sha = self.helper.state()
        self.assertEqual(restored_sha, old_sha)
        self.assertEqual(self.helper.running, old["generation"])
        with self.assertRaises(web.LocalWebError) as stale:
            self.helper.disable("b" * 64)
        self.assertEqual(stale.exception.code, "STATE_CHANGED")
        disabled = self.helper.disable(old_sha)
        self.assertEqual(disabled, {"protocol": 1, "ok": True, "enabled": False,
                                    "changed": True, "expected_state_sha256": None})
        self.assertEqual(self.helper.state(), (None, None))
        self.assertIsNone(self.helper.running)

    def test_rejects_untrusted_state_and_public_owner(self):
        self.helper.apply(CONFIG, None, SOURCE, lock_held=True)
        state_file = self.root / "etc/sovagrid/local-web/state.json"
        state_file.write_text(state_file.read_text().replace("/ops/monitoring/", "/api/"))
        with self.assertRaises(web.LocalWebError) as untrusted:
            self.helper.state()
        self.assertEqual(untrusted.exception.code, "STATE_UNTRUSTED")
        self.assertIn("PUBLIC_ACTIVE", web.ERRORS)

    def test_fixed_template_has_no_public_port_and_base_imports_local_routes(self):
        template = (ROOT / "deploy/compose.local-web.template").read_text()
        web_source = Path(os.environ.get("SOVAGRID_TEST_WEB_SOURCE", ROOT.parent / "sovagrid-web"))
        caddy = (web_source / "deploy/Caddyfile.container").read_text()
        self.assertIn("target: /etc/caddy/local", template)
        self.assertNotIn("ports:", template)
        self.assertIn("import /etc/caddy/local/*.caddy", caddy)
        self.assertLess(caddy.index("import /etc/caddy/local/*.caddy"),
                        caddy.index("redir /sovagrid/monitoring"))

    def test_promoted_home_uses_its_own_local_hub_ca(self):
        calls = []
        helper = web.LocalWeb(self.root, uid=os.getuid(),
                              runner=lambda args, **_kwargs: calls.append(args) or b"")
        external = self.root / "etc/sovagrid/hub-ca.pem"
        external.write_text("external")
        external.chmod(0o644)
        helper.local_health()
        self.assertEqual(calls[-1][-1], str(external))
        local = self.root / "var/lib/sovagrid/local-hub-ca.pem"
        local.write_text("local")
        local.chmod(0o600)
        helper.local_health()
        self.assertEqual(calls[-1][-1], str(local))

    def test_updater_preserves_generation_and_refuses_conflicting_owner(self):
        common = hub_only.common
        self.helper.apply(CONFIG, None, SOURCE, lock_held=True)
        with patch.object(common, "ROOT", self.root), \
             patch.object(common, "PUBLIC_OWNER", os.getuid()):
            overlay = common.local_web_overlay()
            self.assertEqual(overlay, str(self.root / self.helper.overlay().lstrip("/")))
            args, _env = common.compose_args(self.root / "opt/sovagrid-src")
            self.assertIn(overlay, args)
            with patch.object(common, "public_web_overlay", return_value="/other/public.yaml"):
                with self.assertRaises(common.UpdateFailure):
                    common.compose_args(self.root / "opt/sovagrid-src")
            state = self.root / "etc/sovagrid/local-web/state.json"
            state.write_text(state.read_text().replace("untouched", "redirect\n"))
            with self.assertRaises(common.UpdateFailure):
                common.local_web_overlay()
        self.assertIn("/etc/sovagrid/local-web", hub_only.SNAPSHOT)
        self.assertNotIn("/etc/sovagrid/local-web", hub_only.SSH_GATEWAY_SNAPSHOT)

    def test_rollback_stop_uses_snapshot_env_and_skips_broken_overlay(self):
        common = hub_only.common
        transaction = self.root / "transaction"
        full_snapshot = transaction / "snapshot" / "0" / "deploy.env"
        full_snapshot.parent.mkdir(parents=True)
        full_snapshot.write_text("SOVAGRID_HUB_DATA_DIR=/var/lib/sovagrid/hub\n")
        self.helper.apply(CONFIG, None, SOURCE, lock_held=True)
        state = self.root / "etc/sovagrid/local-web/state.json"
        state.write_text("{malformed")
        with patch.object(common, "ROOT", self.root), \
             patch.object(common, "PUBLIC_OWNER", os.getuid()):
            with self.assertRaises(common.UpdateFailure):
                common.local_web_overlay()
            args, _env = common.rollback_stop_compose_args(
                self.root / "opt/sovagrid-src", transaction,
                ("/etc/sovagrid",), "installed")
            self.assertEqual(args[3], str(full_snapshot))
            self.assertEqual(len(args), 6)
            home_args, _env = common.rollback_stop_compose_args(
                self.root / "opt/sovagrid-src", transaction,
                ("/etc/sovagrid/deploy.env",), "installed")
            self.assertEqual(home_args[3], str(transaction / "snapshot/0"))
            preparing, _env = common.rollback_stop_compose_args(
                self.root / "opt/sovagrid-src", transaction,
                ("/etc/sovagrid",), "preparing")
            self.assertEqual(preparing[3], str(self.root / "etc/sovagrid/deploy.env"))


if __name__ == "__main__":
    unittest.main()
