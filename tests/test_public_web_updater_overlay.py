#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""An installed HTTPS generation remains readable by the next updater."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests.test_hub_only_update import update as hub_only

worker = hub_only.common


class PublicWebUpdaterOverlay(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "etc/sovagrid/public-web"
        self.base.mkdir(parents=True, mode=0o700)
        self.base.chmod(0o700)
        marker = self.base / ".managed"
        marker.write_bytes(b"SOVAGRID_PUBLIC_WEB_V1\n")
        marker.chmod(0o600)
        self.generation = "a" * 32
        self.folder = self.base / "generations" / self.generation
        self.folder.mkdir(parents=True, mode=0o700)
        self.folder.chmod(0o700)

    def publish(self, modern: bool):
        files = ("caddy/global/public.options", "caddy/sites/public.caddy", "compose.yaml")
        config = {"mode": "ip", "address": "8.8.8.8", "acme_environment": "production"}
        if modern:
            files += ("caddy/local/panel.caddy",)
            config.update(panel_path="/sovagrid/monitoring/", root_behavior="untouched")
        hashes = {}
        for name in files:
            target = self.folder / name
            target.parent.mkdir(parents=True, exist_ok=True)
            content = (name + "\n").encode()
            target.write_bytes(content)
            target.chmod(0o644)
            hashes[name] = hashlib.sha256(content).hexdigest()
        state = {"protocol": 1, "generation": self.generation,
                 "config": config, "sha256": hashes}
        path = self.base / "state.json"
        path.write_text(json.dumps(state))
        path.chmod(0o600)
        return state

    def test_legacy_and_current_immutable_generations(self):
        with patch.object(worker, "ROOT", self.root), patch.object(worker, "PUBLIC_OWNER", os.getuid()):
            for modern in (False, True):
                with self.subTest(modern=modern):
                    self.publish(modern)
                    self.assertEqual(worker.public_web_overlay(), str(self.folder / "compose.yaml"))

    def test_mixed_layout_tampering_and_reserved_path_fail_closed(self):
        with patch.object(worker, "ROOT", self.root), patch.object(worker, "PUBLIC_OWNER", os.getuid()):
            state = self.publish(True)
            state["sha256"].pop("caddy/local/panel.caddy")
            (self.base / "state.json").write_text(json.dumps(state))
            with self.assertRaises(worker.UpdateFailure):
                worker.public_web_overlay()
            state = self.publish(True)
            state["config"]["panel_path"] = "/api/v1/"
            (self.base / "state.json").write_text(json.dumps(state))
            with self.assertRaises(worker.UpdateFailure):
                worker.public_web_overlay()
            state = self.publish(True)
            state["config"]["root_behavior"] = ["panel"]
            (self.base / "state.json").write_text(json.dumps(state))
            with self.assertRaises(worker.UpdateFailure):
                worker.public_web_overlay()
            self.publish(True)
            (self.folder / "compose.yaml").write_text("tampered")
            with self.assertRaises(worker.UpdateFailure):
                worker.public_web_overlay()


if __name__ == "__main__":
    unittest.main()
