# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Actual Caddy routing, no ACME calls; set CADDY_BINARY to a verified 2.11.7.

The TLS fixture substitutes only its issuer with Caddy's isolated internal CA.
The unmodified production configurations are separately adapted and inspected.
"""
from __future__ import annotations

import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from test_public_web import web, CONFIG, REPO
from test_public_web_docker import LIVE_CADDY_CONFIG


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@unittest.skipUnless(os.environ.get("CADDY_BINARY"), "set CADDY_BINARY for the real Caddy fixture")
class CaddyPublicWeb(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = os.environ["CADDY_BINARY"]
        self.environment = {**os.environ, "XDG_DATA_HOME": str(self.root / "data"), "XDG_CONFIG_HOME": str(self.root / "config")}
        self.site_template = (REPO / "deploy/public-web.site.template").read_text()
        self.compose_template = (REPO / "deploy/compose.public-web.template").read_text()
        self.upstream_requests = []

    def adapted(self, config):
        generated = web.render(config, "/fixed-generation", self.site_template, self.compose_template)
        text = "{\n admin off\n auto_https disable_redirects\n skip_install_trust\n" + generated["caddy/global/public.options"].decode() + "}\n"
        text += generated["caddy/sites/public.caddy"].decode()
        path = self.root / "Caddyfile"
        path.write_text(text)
        raw = subprocess.check_output([self.binary, "adapt", "--config", str(path), "--adapter", "caddyfile"], env=self.environment, stderr=subprocess.DEVNULL, timeout=20)
        return json.loads(raw), text

    def test_real_adapter_keeps_ip_acme_profile_and_dns_automation(self):
        for config in (CONFIG, {**CONFIG, "mode": "dns", "address": "panel.example.org"}, {**CONFIG, "address": "2606:4700:4700::1111"}):
            with self.subTest(config=config):
                adapted, _ = self.adapted(config)
                policies = adapted["apps"]["tls"]["automation"]["policies"]
                matching = [p for p in policies if config["address"] in p.get("subjects", [])]
                self.assertEqual(len(matching), 1)
                issuer = matching[0]["issuers"][0]
                self.assertEqual(issuer["module"], "acme")
                self.assertEqual(issuer["ca"], "https://acme-v02.api.letsencrypt.org/directory")
                self.assertEqual(issuer.get("profile"), "shortlived" if config["mode"] == "ip" else None)
                self.assertEqual(issuer["challenges"]["http"]["alternate_port"], 9080)
                self.assertEqual(issuer["challenges"]["tls-alpn"]["alternate_port"], 9443)

    def test_disposable_docker_live_base_is_valid_actual_caddy_syntax(self):
        path = self.root / "Caddyfile.fixture"
        path.write_text(LIVE_CADDY_CONFIG)
        result = subprocess.run([self.binary, "adapt", "--config", str(path), "--adapter", "caddyfile"],
                                env=self.environment, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def start_fixture(self, real_hub=None, *, config=CONFIG):
        seen = self.upstream_requests
        class Hub(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.command, self.path, dict(self.headers)))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.do_GET()
            def log_message(self, *_args):
                pass
        upstream = real_hub or http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hub)
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(upstream.server_close)
        self.addCleanup(upstream.shutdown)
        self.http_port, self.tls_port = port(), port()
        _, text = self.adapted(config)
        start = text.index("    tls {")
        end = text.index("    header {", start)
        text = text[:start] + "    tls internal\n" + text[end:]
        text = text.replace(":9080", ":" + str(self.http_port)).replace(":9443", ":" + str(self.tls_port))
        text = text.replace("hub:8765", "127.0.0.1:" + str(upstream.server_address[1]))
        self.site_root = self.root / "web"
        self.site_root.mkdir(exist_ok=True)
        (self.site_root / "index.html").write_text('<!doctype html><html><body id="sshLoginMode">SovaGrid fixture</body></html>')
        (self.site_root / "sw.js").write_text("self.addEventListener('install', () => {});")
        text = text.replace("root * /srv", "root * " + str(self.site_root))
        (self.root / "Caddyfile").write_text(text)
        process = subprocess.Popen([self.binary, "run", "--config", str(self.root / "Caddyfile"), "--adapter", "caddyfile"],
                                   env=self.environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def stop():
            process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(5)
        self.addCleanup(stop)
        for _ in range(100):
            if process.poll() is not None:
                self.fail("Caddy fixture exited before readiness")
            try:
                status, _ = self.request("GET", "/healthz")
                if status == 200:
                    seen.clear()
                    return
            except OSError:
                pass
            time.sleep(0.05)
        self.fail("Caddy fixture readiness timed out")

    def test_custom_panel_path_assets_and_root_modes(self):
        for behavior, expected_root in (("untouched", 404), ("panel", 200), ("redirect", 308), ("not_found", 404)):
            with self.subTest(root_behavior=behavior):
                self.start_fixture(config={**CONFIG, "panel_path": "/ops/monitoring/", "root_behavior": behavior})
                self.assertEqual(self.request("GET", "/ops/monitoring/")[0], 200)
                self.assertEqual(self.request("GET", "/ops/monitoring/sw.js")[0], 200)
                self.assertEqual(self.request("HEAD", "/ops/monitoring/sw.js")[0], 200)
                self.assertEqual(self.request("GET", "/ops/monitoring")[0], 308)
                self.assertEqual(self.request("GET", "/")[0], expected_root)
                self.assertEqual(self.request("GET", "/api/v1/session")[0], 200)

    def request(self, method, path, host="127.0.0.1", public_host=CONFIG["address"], payload=None, **headers):
        context = ssl._create_unverified_context()  # fixture-only isolated internal CA
        client = http.client.HTTPSConnection(host, self.tls_port, context=context, timeout=4)
        try:
            client.request(method, path, body=(json.dumps(payload).encode() if payload is not None else b"{}") if method == "POST" else None,
                           headers={"Host": public_host, "Content-Type": "application/json", **headers})
            response = client.getresponse()
            return response.status, response.read(8192)
        finally:
            client.close()

    def test_actual_agent_denial_precedes_proxy_and_browser_api_works(self):
        self.start_fixture()
        sid = "11111111-1111-4111-8111-111111111111"
        prefix = "/api/v1/servers/" + sid
        blocked = [("POST", "metrics"), ("GET", "agent-compatibility"),
                   ("GET", "agent-maintenance/lease"),
                   ("POST", "agent-maintenance/lease"),
                   ("POST", "agent-maintenance/lease/renew"),
                   ("POST", "agent-maintenance/lease/release"),
                   ("GET", "jobs/next"), ("POST", "jobs/j/result"),
                   ("GET", "terminal/next"), ("GET", "terminal/sessions/s/controls"),
                   ("POST", "terminal/sessions/s/ready"), ("POST", "terminal/sessions/s/output"),
                   ("POST", "terminal/sessions/s/exit"), ("GET", "files/next"),
                   ("POST", "files/operations/o/result"), ("POST", "checks/claim"),
                   ("POST", "checks/c/result")]
        for method, suffix in blocked:
            with self.subTest(method=method, suffix=suffix):
                self.assertEqual(self.request(method, prefix + "/" + suffix)[0], 404)
        self.assertEqual(self.upstream_requests, [], "Agent request must never reach Hub")
        for method, path in (("POST", "/api/v1/session"), ("GET", prefix + "/metrics"),
                             ("POST", prefix + "/terminal/sessions"), ("POST", prefix + "/files/operations")):
            self.assertEqual(self.request(method, path)[0], 200)
        self.assertEqual(len(self.upstream_requests), 4)
        self.assertEqual(self.request("GET", "/api/v1/session", public_host="unknown.example.org")[0], 404)
        self.assertEqual(len(self.upstream_requests), 4)

    def test_actual_proxy_overwrites_spoofed_identity_and_distinguishes_clients(self):
        self.start_fixture()
        self.request("POST", "/api/v1/session", **{"X-SovaGrid-Client-IP": "198.51.100.4", "X-Forwarded-For": "198.51.100.5"})
        first = self.upstream_requests[-1][2]
        self.assertEqual(first["X-Sovagrid-Client-Ip"].lower(), "127.0.0.1")
        try:
            status, _ = self.request("POST", "/api/v1/session", host="::1", **{"X-SovaGrid-Client-IP": "198.51.100.4"})
        except OSError:
            self.skipTest("IPv6 loopback unavailable for second actual network identity")
        self.assertEqual(status, 200)
        second = self.upstream_requests[-1][2]
        self.assertEqual(second["X-Sovagrid-Client-Ip"], "::1")
        self.assertNotEqual(first["X-Sovagrid-Client-Ip"], second["X-Sovagrid-Client-Ip"])

    def test_actual_hub_login_rate_limit_cannot_be_evaded_by_spoofed_headers(self):
        hub_source = Path(os.environ.get("HUB_SOURCE", str(REPO.parent / "sovagrid-hub")))
        if not (hub_source / "sovagrid_hub/http_api.py").is_file():
            self.skipTest("set HUB_SOURCE to the pinned Hub source checkout")
        sys.path.insert(0, str(hub_source))
        self.addCleanup(lambda: sys.path.remove(str(hub_source)))
        from sovagrid_hub.store import Store
        from sovagrid_hub.http_api import HubApp, make_server
        store = Store(self.root / "hub.sqlite")
        store.initialize("admin", "fixture-password-long")
        app = HubApp(store)
        self.start_fixture(make_server(app, 0))
        for index in range(5):
            status, _ = self.request("POST", "/api/v1/session", payload={"username": "admin", "password": "incorrect"},
                                     **{"X-SovaGrid-Client-IP": f"198.51.100.{index + 1}"})
            self.assertEqual(status, 401)
        self.assertEqual(self.request("POST", "/api/v1/session", payload={"username": "admin", "password": "fixture-password-long"},
                                      **{"X-SovaGrid-Client-IP": "203.0.113.1"})[0], 429)
        self.assertEqual(set(app.login_attempts), {"127.0.0.1"})
        try:
            status, raw = self.request("POST", "/api/v1/session", host="::1",
                                       payload={"username": "admin", "password": "fixture-password-long"})
        except OSError:
            self.skipTest("IPv6 loopback unavailable for independent real Hub identity")
        self.assertEqual(status, 200)
        session = json.loads(raw)
        self.assertEqual(session["user"]["role"], "admin")
        self.assertEqual(self.request("GET", "/api/v1/session", Authorization="Bearer " + session["token"])[0], 200)


if __name__ == "__main__":
    unittest.main()
