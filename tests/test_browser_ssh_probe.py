# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.

"""The installer accepts the Gateway's exact public SSH key reply."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch
import unittest

from deploy import browser_ssh_probe as probe
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
        with patch.object(update.urllib.request, "urlopen", return_value=_Response(reply, "application/json")):
            update.browser_ssh_route_health()

    def test_gateway_public_key_reply_and_ssh_first_panel(self):
        reply = json.dumps(gateway_reply()).encode("ascii")
        panel = b'<div id="sshLoginMode"></div><div id="browserSshView"></div>'
        with patch.object(probe.urllib.request, "urlopen", side_effect=(
                _Response(reply, "application/json"),
                _Response(panel, "text/html; charset=utf-8"))) as open_url:
            probe.probe_once()
        self.assertEqual(open_url.call_count, 2)
        request = open_url.call_args_list[0].args[0]
        self.assertEqual(request.full_url, probe.HOST_KEY_URL)
        self.assertEqual(request.data, b"{}")

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
        with patch.object(probe.urllib.request, "urlopen", side_effect=(
                _Response(reply, "application/json"),
                _Response(b"<html>Old panel</html>", "text/html"))):
            with self.assertRaisesRegex(ValueError, "SSH-first panel"):
                probe.probe_once()

    def test_updater_accepts_gateway_reply_and_rejects_bad_host_key(self):
        reply = gateway_reply()
        with patch.object(update.urllib.request, "urlopen", return_value=_Response(
                json.dumps(reply).encode("ascii"), "application/json")) as open_url:
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
                with patch.object(update.urllib.request, "urlopen", return_value=_Response(
                        json.dumps(value).encode("ascii"), "application/json")):
                    with self.assertRaisesRegex(update.UpdateFailure, "browser SSH route reply invalid"):
                        update.browser_ssh_route_health()


if __name__ == "__main__":
    unittest.main()
