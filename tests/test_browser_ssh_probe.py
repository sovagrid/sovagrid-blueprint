# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01

"""The installer accepts the Gateway's exact public SSH key reply."""

from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.error
from unittest.mock import Mock, patch
import unittest

from deploy import browser_ssh_probe as probe
from deploy import public_web
from deploy import remote_update_worker as update


def gateway_reply() -> dict:
    kind = b"ssh-ed25519"
    key = (len(kind).to_bytes(4, "big") + kind +
           (32).to_bytes(4, "big") + bytes(range(32)))
    return {"protocol": 1, "port": 22, "key_type": "ssh-ed25519",
            "fingerprint": "SHA256:" + base64.b64encode(
                hashlib.sha256(key).digest()).decode("ascii").rstrip("="),
            "host_key_blob": base64.b64encode(key).decode("ascii")}


class _Response:
    def __init__(self, body: bytes, content_type: str):
        self.body = body
        self.status = 200
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


class BrowserSSHProbeTests(unittest.TestCase):
    def test_exact_checked_out_gateway_contract_when_available(self):
        source = os.environ.get("SOVAGRID_CURRENT_WEB_SOURCE")
        if not source:
            self.skipTest("exact Web checkout is supplied by integrated install")
        if not (Path(source) / "gateway/server.js").is_file():
            self.fail("exact Web Gateway checkout is missing")
        script = '''import { hostKey } from "./gateway/server.js";
const kind = Buffer.from("ssh-ed25519");
const key = Buffer.concat([Buffer.from([0,0,0,kind.length]), kind,
  Buffer.from([0,0,0,32]), Buffer.alloc(32,7)]);
process.stdout.write(JSON.stringify({ protocol: 1, port: 22, ...hostKey(key),
  host_key_blob: key.toString("base64") }));'''
        reply = subprocess.check_output(
            ["node", "--input-type=module", "-e", script], cwd=source, timeout=10)
        probe.verify_host_key_response(reply)
        opener = Mock(open=Mock(return_value=_Response(reply, "application/json")))
        with patch.object(update, "_loopback_opener", return_value=opener):
            update.browser_ssh_route_health()

    def test_gateway_public_key_reply_and_ssh_first_panel(self):
        reply = json.dumps(gateway_reply()).encode("ascii")
        panel = b'<div id="sshLoginMode"></div><div id="browserSshView"></div>'
        open_url = Mock(side_effect=(
                _Response(reply, "application/json"),
                _Response(panel, "text/html; charset=utf-8")))
        with patch.object(probe, "direct_opener", return_value=Mock(open=open_url)):
            probe.probe_once()
        self.assertEqual(open_url.call_count, 2)
        request = open_url.call_args_list[0].args[0]
        self.assertEqual(request.full_url, probe.HOST_KEY_URL)
        self.assertEqual(request.data, b"{}")

    def test_real_loopback_probe_bypasses_environment_proxy_and_refuses_redirect(self):
        visited = []
        reply = json.dumps(gateway_reply()).encode("ascii")
        panel = b'<div id="sshLoginMode"></div><div id="browserSshView"></div>'

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                visited.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(reply)

            def do_GET(self):
                visited.append(self.path)
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/panel")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(panel)

        with (ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server,
              socket.socket() as unused_proxy):
            unused_proxy.bind(("127.0.0.1", 0))
            worker = threading.Thread(target=server.serve_forever, args=(0.01,), daemon=True)
            worker.start()
            try:
                origin = "http://127.0.0.1:" + str(server.server_port)
                proxy = "http://127.0.0.1:" + str(unused_proxy.getsockname()[1])
                with (patch.dict(os.environ, {"http_proxy": proxy, "https_proxy": proxy, "no_proxy": ""}),
                      patch.object(probe.urllib.request, "_opener", None),
                      patch.object(probe, "HOST_KEY_URL", origin + "/host-key")):
                    with patch.object(probe, "PANEL_URL", origin + "/panel"):
                        probe.probe_once()
                    with (patch.object(probe, "PANEL_URL", origin + "/redirect"),
                          self.assertRaises(urllib.error.HTTPError) as error):
                        probe.probe_once()
                    self.assertEqual(error.exception.code, 302)
                    error.exception.close()
                    with update._loopback_opener().open(origin + "/updater", timeout=1) as response:
                        self.assertEqual(response.status, 200)
                    with self.assertRaises(urllib.error.HTTPError) as error:
                        update._loopback_opener().open(origin + "/redirect", timeout=1)
                    self.assertEqual(error.exception.code, 302)
                    error.exception.close()
                self.assertEqual(visited, ["/host-key", "/panel", "/host-key", "/redirect",
                                           "/updater", "/redirect"])
            finally:
                server.shutdown()
                worker.join()

    def test_public_ssh_health_accepts_the_gateway_reply(self):
        config = {"address": "203.0.113.10", "acme_environment": "production",
                  "panel_path": "/custom/panel/"}
        origin = "https://" + config["address"]
        key_url = origin + "/api/v1/browser-ssh/host-key"
        panel_url = origin + config["panel_path"]
        panel = b'<div id="sshLoginMode"></div><div id="browserSshView"></div>'

        with tempfile.TemporaryDirectory() as root:
            helper = public_web.PublicWeb(root)
            installed_probe = helper.path(public_web.SOURCE + "/sovagrid-blueprint/deploy/browser_ssh_probe.py")
            installed_probe.parent.mkdir(parents=True)
            installed_probe.write_bytes(Path(probe.__file__).read_bytes())

            def run_child(argv, timeout):
                code_index = argv.index("-c") + 1
                with patch.object(sys, "argv", ["-c", *argv[code_index + 1:]]):
                    with self.assertRaises(SystemExit) as exit_status:
                        exec(compile(argv[code_index], "public SSH probe", "exec"), {})
                if exit_status.exception.code:
                    raise public_web.PublicWebError("COMMAND_FAILED")

            helper.run = run_child
            response = gateway_reply()
            for mismatch in (False, True):
                with self.subTest(mismatched_fingerprint=mismatch):
                    reply = dict(response)
                    if mismatch:
                        reply["fingerprint"] = "SHA256:" + "A" * 43
                    raw = json.dumps(reply).encode("ascii")

                    def open_request(request, timeout):
                        if isinstance(request, str):
                            self.assertEqual(request, panel_url)
                            return _Response(panel, "text/html; charset=utf-8")
                        self.assertEqual(request.full_url, key_url)
                        self.assertEqual(request.get_method(), "POST")
                        self.assertEqual(request.get_header("Origin"), origin)
                        return _Response(raw, "application/json")

                    opener = Mock(open=Mock(side_effect=open_request))
                    with patch("urllib.request.build_opener", return_value=opener), patch("time.sleep"):
                        if mismatch:
                            with self.assertRaises(public_web.PublicWebError):
                                helper.public_ssh_health(config)
                        else:
                            helper.public_ssh_health(config)
                            self.assertEqual(opener.open.call_count, 2)

    def test_changed_fingerprint_or_blob_and_extra_fields_are_rejected(self):
        for change in (lambda value: value.update(fingerprint="SHA256:" + "A" * 43),
                       lambda value: value.update(host_key_blob="AAAA"),
                       lambda value: value.update(key_type="ssh-rsa"),
                       lambda value: value.update(unexpected=True)):
            with self.subTest(change=change):
                value = gateway_reply()
                change(value)
                with self.assertRaises(ValueError):
                    probe.verify_host_key_response(json.dumps(value).encode("ascii"))

    def test_oversized_response_and_missing_panel_are_rejected(self):
        with self.assertRaises(ValueError):
            probe.verify_host_key_response(b" " * (probe.MAX_KEY_RESPONSE + 1))
        reply = json.dumps(gateway_reply()).encode("ascii")
        open_url = Mock(side_effect=(
                _Response(reply, "application/json"),
                _Response(b"<html>Old panel</html>", "text/html")))
        with patch.object(probe, "direct_opener", return_value=Mock(open=open_url)):
            with self.assertRaisesRegex(ValueError, "SSH-first panel"):
                probe.probe_once()

    def test_updater_accepts_gateway_reply_and_rejects_bad_host_key(self):
        reply = gateway_reply()
        open_url = Mock(return_value=_Response(json.dumps(reply).encode("ascii"), "application/json"))
        with patch.object(update, "_loopback_opener", return_value=Mock(open=open_url)):
            update.browser_ssh_route_health()
        self.assertEqual(open_url.call_args.args[0].full_url, probe.HOST_KEY_URL)

        invalid = []
        missing_blob = dict(reply)
        del missing_blob["host_key_blob"]
        invalid.append(missing_blob)
        for changed in ({"fingerprint": "SHA256:" + "A" * 43},
                        {"host_key_blob": "AAAA"}, {"key_type": "ssh-rsa"},
                        {"unexpected": True}):
            invalid.append({**reply, **changed})
        for value in invalid:
            with self.subTest(value=value):
                opener = Mock(open=Mock(return_value=_Response(json.dumps(value).encode("ascii"),
                                                              "application/json")))
                with patch.object(update, "_loopback_opener", return_value=opener):
                    with self.assertRaisesRegex(update.UpdateFailure, "browser SSH route reply invalid"):
                        update.browser_ssh_route_health()


if __name__ == "__main__":
    unittest.main()
