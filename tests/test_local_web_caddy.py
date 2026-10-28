#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Real Caddy adapter for the independent loopback panel generation."""

import http.client
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("local_web_caddy_fixture", ROOT / "deploy/local_web.py")
web = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(web)
CONFIG = {"panel_path": "/ops/monitoring/", "root_behavior": "untouched"}


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@unittest.skipUnless(os.environ.get("CADDY_BINARY"), "set CADDY_BINARY to a verified Caddy 2.11.7 binary")
class LocalCaddyRoutes(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.www = self.root / "web"
        self.www.mkdir()
        (self.www / "index.html").write_text('<html><body id="sshLoginMode">SovaGrid</body></html>')
        (self.www / "sw.js").write_text("self.addEventListener('install', () => {});")
        self.local = self.root / "local"
        self.local.mkdir()
        self.http_port = port()
        self.environment = {**os.environ, "XDG_DATA_HOME": str(self.root / "data"),
                            "XDG_CONFIG_HOME": str(self.root / "config")}

    def start(self, behavior):
        config = {**CONFIG, "root_behavior": behavior}
        fragment = web.render(config, "/fixed-generation", "source: $caddy_dir\n")["caddy/panel.caddy"]
        (self.local / "panel.caddy").write_bytes(
            fragment.replace(b"root * /srv", ("root * " + str(self.www)).encode()))
        base = (ROOT.parent / "sovagrid-web/deploy/Caddyfile.container").read_text()
        base = base.split("# Local TLS ingress for host Agent.")[0]
        base = base.replace("import /etc/caddy/local/*.caddy", "import " + str(self.local) + "/*.caddy")
        base = base.replace(":8080", ":" + str(self.http_port))
        base = base.replace("root * /srv", "root * " + str(self.www))
        (self.root / "Caddyfile").write_text(base)
        result = subprocess.run([os.environ["CADDY_BINARY"], "adapt", "--config",
                                 str(self.root / "Caddyfile"), "--adapter", "caddyfile"],
                                env=self.environment, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        log = self.root / "caddy.log"
        with log.open("wb") as errors:
            process = subprocess.Popen([os.environ["CADDY_BINARY"], "run", "--config",
                                        str(self.root / "Caddyfile"), "--adapter", "caddyfile"],
                                       env=self.environment, stdout=subprocess.DEVNULL,
                                       stderr=errors)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    self.fail("Caddy exited before route check: " + log.read_text(errors="replace")[-1200:])
                try:
                    self.request("/ops/monitoring/")
                    return process
                except OSError:
                    time.sleep(.05)
            self.fail("Caddy did not start: " + log.read_text(errors="replace")[-1200:])
        except BaseException:
            process.terminate()
            process.wait(5)
            raise

    def request(self, path):
        client = http.client.HTTPConnection("127.0.0.1", self.http_port, timeout=2)
        try:
            client.request("GET", path)
            response = client.getresponse()
            return response.status, response.getheader("Location"), response.read(65537)
        finally:
            client.close()

    def test_custom_path_and_existing_root_modes(self):
        for behavior, root_status in (("untouched", 200), ("panel", 200),
                                      ("redirect", 308), ("not_found", 404)):
            with self.subTest(behavior=behavior):
                process = self.start(behavior)
                try:
                    custom = self.request("/ops/monitoring/")
                    self.assertEqual(custom[0], 200, (custom[2][:200],
                                                      (self.root / "Caddyfile").read_text()))
                    self.assertEqual(self.request("/ops/monitoring/sw.js")[0], 200)
                    self.assertEqual(self.request("/sovagrid/monitoring/")[0], 200)
                    self.assertEqual(self.request("/ops/monitoring")[0], 308)
                    status, location, _ = self.request("/")
                    self.assertEqual(status, root_status)
                    if behavior == "redirect":
                        self.assertEqual(location, "/ops/monitoring/")
                finally:
                    process.terminate()
                    process.wait(5)


if __name__ == "__main__":
    unittest.main()
