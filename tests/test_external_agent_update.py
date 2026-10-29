# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The external Agent preview must never become an update authorization."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest import mock


DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
spec = importlib.util.spec_from_file_location("sovagrid_external_agent_update_test",
                                              DEPLOY / "external_agent_update.py")
assert spec and spec.loader
previewer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previewer)
REAL_PROMOTION_LOCK = previewer._promotion_lock
REAL_MANIFEST = previewer._manifest

CURRENT = "a" * 64
ARCHIVE = "b" * 64
EXTERNAL = "c" * 64
BASELINE = "d" * 64
SERVER_ID = "ebaf0c48-8ddd-4d9e-b36b-c32be307d05b"
TOKEN = "S" * 43
CA = "enrolled CA fixture"


def manifest(agent_hash: str) -> dict:
    hashes = {previewer.remote.SELF_NAME: "1" * 64,
              "sovagrid-agent/LICENSE": "2" * 64,
              "sovagrid-agent/NOTICE": "3" * 64,
              "sovagrid-agent/ATTRIBUTION.md": "4" * 64,
              "sovagrid-agent/deploy/sovagrid-agent.service": "5" * 64,
              "sovagrid-agent/sovagrid_agent/__main__.py": agent_hash}
    return {"format": 1, "components": {}, "sha256": hashes}


class ExternalAgentPreviewTests(unittest.TestCase):
    def setUp(self):
        self.before = manifest("6" * 64)
        self.after = manifest("7" * 64)
        self.promoted = {"phase": "activated", "external_agent_preserved": True,
                         "baseline_sha256": BASELINE}
        self.runtime = {unit: {"active": True, "enabled": True, "pid": 123}
                        for unit in previewer.promotion.UNITS}
        self.patches = [
            mock.patch.object(previewer.os, "geteuid", return_value=0),
            mock.patch.object(previewer, "_promotion_lock", return_value=contextlib.nullcontext()),
            mock.patch.object(previewer.update, "inspect",
                              return_value=(CURRENT, self.promoted, {}, BASELINE)),
            mock.patch.object(previewer, "_external_snapshot",
                              return_value=(EXTERNAL, self.before, {})),
            mock.patch.object(previewer.common, "candidate_source",
                              return_value=(Path("/verified/candidate/source"), {})),
            mock.patch.object(previewer, "_manifest", return_value=(CURRENT, self.after)),
            mock.patch.object(previewer.update, "_external_runtime", return_value=self.runtime),
            mock.patch.object(previewer.promotion, "capture_external", return_value={"proof": True}),
            mock.patch.object(previewer.promotion, "_private_json", return_value={"proof": True}),
            mock.patch.object(previewer.update, "_hash_file", return_value=BASELINE),
            mock.patch.object(previewer, "_original_hub_compatibility", return_value=None),
        ]
        for patcher in self.patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_verified_promotion_previews_only_changed_source_files(self):
        result = previewer.preview(ARCHIVE, CURRENT)
        self.assertEqual(result["source_paths_to_change"], [
            {"path": "/opt/sovagrid-agent/sovagrid_agent/__main__.py", "operation": "replace"},
            {"path": "/opt/sovagrid-agent-installer/source-manifest.json", "operation": "replace"},
        ])
        self.assertTrue(result["external_agent_preserved"] and result["tunnel_active"])
        self.assertFalse(result["apply_supported"])
        self.assertEqual(result["original_hub_compatibility"], "verified_same_bundle")
        self.assertEqual(result["apply_blockers"], ["EXTERNAL_AGENT_PREFLIGHT_REQUIRED"])
        self.assertNotIn("token", json.dumps(result).lower())

    def test_changed_external_baseline_or_stopped_tunnel_refuses(self):
        with mock.patch.object(previewer.promotion, "capture_external", return_value={"proof": False}), \
             self.assertRaisesRegex(previewer.Refused, "EXTERNAL_CHANGED"):
            previewer.preview(ARCHIVE, CURRENT)
        stopped = {name: dict(status) for name, status in self.runtime.items()}
        stopped["sovagrid-agent-tunnel.service"]["pid"] = 0
        with mock.patch.object(previewer.update, "_external_runtime", return_value=stopped), \
             self.assertRaisesRegex(previewer.Refused, "EXTERNAL_RUNTIME"):
            previewer.preview(ARCHIVE, CURRENT)

    def test_unverified_original_hub_cannot_produce_preview(self):
        with mock.patch.object(previewer, "_original_hub_compatibility",
                               side_effect=previewer.Refused("ORIGINAL_HUB_COMPATIBILITY_UNAVAILABLE")), \
             self.assertRaisesRegex(previewer.Refused, "ORIGINAL_HUB_COMPATIBILITY_UNAVAILABLE"):
            previewer.preview(ARCHIVE, CURRENT)

    def test_changed_or_unstaged_candidate_refuses_before_plan(self):
        with mock.patch.object(previewer, "_manifest", return_value=("e" * 64, self.after)), \
             self.assertRaisesRegex(previewer.Refused, "CANDIDATE_NOT_LOCAL_HUB"):
            previewer.preview(ARCHIVE, CURRENT)
        with mock.patch.object(previewer.common, "candidate_source",
                               side_effect=previewer.common.UpdateFailure("unsafe symlink")), \
             self.assertRaises(previewer.common.UpdateFailure):
            previewer.preview(ARCHIVE, CURRENT)

    def test_unactivated_or_stale_promotion_refuses_without_reading_candidate(self):
        for state in ({**self.promoted, "phase": "external_changed"},
                      {**self.promoted, "baseline_sha256": "e" * 64}):
            with self.subTest(state=state), \
                 mock.patch.object(previewer.update, "inspect",
                                   return_value=(CURRENT, state, {}, BASELINE)), \
                 mock.patch.object(previewer.common, "candidate_source") as candidate:
                with self.assertRaisesRegex(previewer.Refused, "PROMOTION_CHANGED"):
                    previewer.preview(ARCHIVE, CURRENT)
                candidate.assert_not_called()

    def test_symlinked_promotion_lock_is_rejected_without_opening(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("private", encoding="utf-8")
            link = root / "lock"
            link.symlink_to(target)
            with mock.patch.object(previewer, "_promotion_lock", REAL_PROMOTION_LOCK), \
                 mock.patch.object(previewer.update, "PROMOTION_LOCK", link), \
                 mock.patch.object(previewer.os, "open") as opener:
                with self.assertRaisesRegex(previewer.Refused, "LOCK_UNSAFE"):
                    with previewer._promotion_lock():
                        pass
                opener.assert_not_called()

    def test_symlinked_candidate_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "manifest-target"
            target.write_text("{}", encoding="utf-8")
            (root / "sovagrid-bundle.json").symlink_to(target)
            with mock.patch.object(previewer, "_manifest", REAL_MANIFEST), \
                 mock.patch.object(previewer.promotion, "_read_regular") as reader, \
                 self.assertRaisesRegex(previewer.Refused, "MANIFEST_INVALID"):
                previewer._manifest(root)
            reader.assert_not_called()


class FakeSocket:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)


class FakeReply:
    def __init__(self, status=200, payload=None, content_type="application/json", content_length=True):
        self.status = status
        self.payload = io.BytesIO(payload if payload is not None else
                                  json.dumps({"protocol": 1, "bundle_manifest_sha256": CURRENT}).encode())
        self.content_type = content_type
        self.content_length = content_length
        self.fp = mock.Mock()

    def getheader(self, name, default=None):
        headers = {"Content-Type": self.content_type}
        if self.content_length:
            headers["Content-Length"] = str(len(self.payload.getvalue()))
        return headers.get(name, default)

    def read(self, size):
        return self.payload.read(size)

    def isclosed(self):
        return self.payload.tell() >= len(self.payload.getvalue())


class FakeConnection:
    def __init__(self, reply=None, error=None):
        self.sock = FakeSocket()
        self.reply = reply or FakeReply()
        self.reply.fp.raw._sock = self.sock
        self.error = error
        self.request_args = None
        self.closed = False

    def connect(self):
        pass

    def request(self, method, path, headers):
        self.request_args = method, path, headers

    def getresponse(self):
        if self.error:
            raise self.error
        return self.reply

    def close(self):
        self.closed = True


class OriginalHubCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.state = {"identity": {"server_id": SERVER_ID}, "local_port": 2200,
                      "transport": {"hub_ca_pem": CA},
                      "agent_token_sha256": hashlib.sha256(TOKEN.encode()).hexdigest()}
        self.files = mock.Mock()
        self.files.read.side_effect = lambda path, **_kwargs: (
            (TOKEN + "\n").encode() if path == "/etc/sovagrid/agent.token" else CA.encode())
        self.context = mock.Mock(verify_mode=ssl.CERT_REQUIRED, check_hostname=True)
        self.patches = [mock.patch.object(previewer.remote, "Files", return_value=self.files),
                        mock.patch.object(previewer.ssl, "create_default_context", return_value=self.context)]
        for patcher in self.patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_probe(self, connection):
        with mock.patch.object(previewer.http.client, "HTTPSConnection", return_value=connection) as factory:
            previewer._original_hub_compatibility(self.state, CURRENT)
        factory.assert_called_once_with("localhost", 2200, context=self.context,
                                        timeout=previewer.COMPATIBILITY_TIMEOUT)
        return connection

    def test_verified_same_bundle_uses_enrolled_ca_token_and_local_tunnel(self):
        connection = self.run_probe(FakeConnection())
        self.assertEqual(connection.request_args,
                         ("GET", f"/api/v1/servers/{SERVER_ID}/agent-compatibility",
                          {"Authorization": "Bearer " + TOKEN, "Accept": "application/json"}))
        self.assertTrue(connection.closed)
        self.assertTrue(connection.sock.timeouts)
        previewer.ssl.create_default_context.assert_called_once_with(cadata=CA)

    def test_changed_enrollment_credentials_or_disabled_hostname_check_refuse_before_connect(self):
        with mock.patch.object(previewer.http.client, "HTTPSConnection") as factory:
            self.state["agent_token_sha256"] = EXTERNAL
            with self.assertRaisesRegex(previewer.Refused, "ORIGINAL_HUB_CREDENTIALS_CHANGED"):
                previewer._original_hub_compatibility(self.state, CURRENT)
            factory.assert_not_called()
            self.state["agent_token_sha256"] = hashlib.sha256(TOKEN.encode()).hexdigest()
            self.context.check_hostname = False
            with self.assertRaisesRegex(previewer.Refused, "ORIGINAL_HUB_TLS_INVALID"):
                previewer._original_hub_compatibility(self.state, CURRENT)
            factory.assert_not_called()

    def test_old_hub_and_redirect_fail_closed(self):
        for status in (404, 401, 302):
            with self.subTest(status=status), \
                 self.assertRaisesRegex(previewer.Refused, "ORIGINAL_HUB_COMPATIBILITY_UNAVAILABLE"):
                self.run_probe(FakeConnection(FakeReply(status=status)))

    def test_wrong_digest_and_invalid_payload_fail_closed(self):
        cases = [(json.dumps({"protocol": 1, "bundle_manifest_sha256": EXTERNAL}).encode(),
                  "ORIGINAL_HUB_COMPATIBILITY_MISMATCH"),
                 (b'{"protocol":1,"protocol":1,"bundle_manifest_sha256":"' + CURRENT.encode() + b'"}',
                  "ORIGINAL_HUB_COMPATIBILITY_INVALID"),
                 (json.dumps({"protocol": True, "bundle_manifest_sha256": CURRENT}).encode(),
                  "ORIGINAL_HUB_COMPATIBILITY_INVALID"),
                 (b"x" * (previewer.MAX_COMPATIBILITY_BODY + 1),
                  "ORIGINAL_HUB_COMPATIBILITY_INVALID")]
        for payload, code in cases:
            with self.subTest(code=code, payload=payload[:30]), self.assertRaisesRegex(previewer.Refused, code):
                self.run_probe(FakeConnection(FakeReply(payload=payload, content_length=False)))

    def test_invalid_tls_and_network_error_never_show_credentials(self):
        secret = TOKEN + "-private-detail"
        for error in (ssl.SSLCertVerificationError(secret), OSError(secret)):
            with self.subTest(error=type(error).__name__):
                connection = FakeConnection(error=error)
                with self.assertRaisesRegex(previewer.Refused, "ORIGINAL_HUB_COMPATIBILITY_UNAVAILABLE") as raised:
                    self.run_probe(connection)
                self.assertNotIn(TOKEN, str(raised.exception))
                self.assertNotIn(secret, str(raised.exception))
                self.assertTrue(connection.closed)

        stderr = io.StringIO()
        with mock.patch.object(previewer, "preview",
                               side_effect=previewer.Refused("ORIGINAL_HUB_COMPATIBILITY_UNAVAILABLE")), \
             contextlib.redirect_stderr(stderr):
            self.assertEqual(previewer.main(["preview", ARCHIVE, CURRENT]), 40)
        self.assertEqual(stderr.getvalue(),
                         "SG_EXTERNAL_AGENT_UPDATE_REFUSE:ORIGINAL_HUB_COMPATIBILITY_UNAVAILABLE\n")
        self.assertNotIn(TOKEN, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
