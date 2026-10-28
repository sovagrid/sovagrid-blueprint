# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Real loopback HTTP/TLS startup races; never touch a deployed host/port."""
import http.server
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from test_public_web import web, source_fixture


@unittest.skipUnless(shutil.which("openssl"), "ephemeral local TLS fixture needs OpenSSL")
class LocalReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certificates = tempfile.TemporaryDirectory(prefix="sovagrid-readiness-certs-")
        cls.addClassCleanup(cls.certificates.cleanup)
        cls.ca_dir = Path(cls.certificates.name)
        def openssl(*args):
            subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=20, cwd=cls.ca_dir)
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=SovaGrid Readiness Test CA", "-keyout", "ca.key", "-out", "ca.pem",
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                "-keyout", "server.key", "-out", "server.csr")
        (cls.ca_dir / "server.ext").write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n"
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
        openssl("x509", "-req", "-days", "1", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-out", "server.pem", "-extfile", "server.ext")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        source_fixture(self.root)
        (self.root / "etc/sovagrid/hub-ca.pem").write_bytes((self.ca_dir / "ca.pem").read_bytes())

    def server(self, *, tls=False, drops=0, status=200, body=b"ok", redirect=None):
        state = {"requests": [], "drops": drops, "status": status, "body": body, "redirect": redirect}
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                state["requests"].append(self.path)
                if state["drops"]:
                    state["drops"] -= 1
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                self.send_response(state["status"])
                if state["redirect"]:
                    self.send_header("Location", state["redirect"])
                self.send_header("Content-Length", str(len(state["body"])))
                self.end_headers()
                self.wfile.write(state["body"])
            def log_message(self, *_args):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.ca_dir / "server.pem", self.ca_dir / "server.key")
            server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, state

    def child_script(self, http_port, tls_port, *, deadline=1):
        script = web.LOCAL_HEALTH_SCRIPT
        for old, new in (("http://127.0.0.1:8766/healthz", f"http://127.0.0.1:{http_port}/healthz"),
                         ("https://localhost:8767/healthz", f"https://localhost:{tls_port}/healthz"),
                         ("deadline = time.monotonic() + 30.0", f"deadline = time.monotonic() + {deadline}")):
            self.assertEqual(script.count(old), 1)
            script = script.replace(old, new, 1)
        return script

    def execute(self, script, *, ca=None):
        return subprocess.run([sys.executable, "-I", "-c", script, str(ca or self.ca_dir / "ca.pem")],
                              capture_output=True, timeout=3,
                              env={**os.environ, "HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1", "NO_PROXY": ""})

    def test_first_connections_fail_then_both_channels_become_ready(self):
        http, http_state = self.server(drops=1)
        https, https_state = self.server(tls=True, drops=1)
        result = self.execute(self.child_script(http.server_port, https.server_port, deadline=1.5))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertGreaterEqual(len(http_state["requests"]), 2)
        self.assertGreaterEqual(len(https_state["requests"]), 2)

    def test_never_ready_uses_one_deadline_and_emits_no_response_body(self):
        http, _ = self.server(status=503, body=b"private health response fixture")
        https, _ = self.server(tls=True, status=503)
        started = time.monotonic()
        result = self.execute(self.child_script(http.server_port, https.server_port, deadline=0.35))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")
        self.assertLess(time.monotonic() - started, 2)

    def test_wrong_private_ca_never_passes(self):
        http, _ = self.server()
        https, _ = self.server(tls=True)
        # The normal system trust store does not trust this ephemeral test CA.
        script = self.child_script(http.server_port, https.server_port, deadline=0.35)
        script = script.replace("ssl.create_default_context(cafile=sys.argv[1])", "ssl.create_default_context()", 1)
        result = self.execute(script)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")

    def test_redirects_and_oversized_bodies_cannot_prove_readiness(self):
        https, https_state = self.server(tls=True)
        for settings in ({"status": 302, "redirect": f"https://localhost:{https.server_port}/redirected"},
                         {"body": b"x" * 8193}):
            with self.subTest(settings=list(settings)):
                http, _ = self.server(**settings)
                result = self.execute(self.child_script(http.server_port, https.server_port, deadline=0.35))
                self.assertEqual(result.returncode, 1)
                self.assertNotIn("/redirected", https_state["requests"])

    def test_parent_deadline_kills_a_stalled_system_resolver(self):
        actual = web.Runner()
        budgets = []
        def runner(args, timeout):
            budgets.append(timeout)
            self.assertEqual(args[:3], [sys.executable, "-I", "-c"])
            self.assertEqual(args[3], web.LOCAL_HEALTH_SCRIPT)
            blocked = "import socket,time\nsocket.getaddrinfo=lambda *args,**kwargs: time.sleep(60)\n" + args[3]
            return actual([*args[:3], blocked, *args[4:]], timeout=0.2)
        helper = web.PublicWeb(self.root, uid=os.getuid(), runner=runner)
        started = time.monotonic()
        with self.assertRaises(web.PublicWebError) as error:
            helper.local_health()
        self.assertEqual(error.exception.code, "LOCAL_UNHEALTHY")
        self.assertEqual(budgets, [35])
        self.assertLess(time.monotonic() - started, 2)


if __name__ == "__main__":
    unittest.main()
