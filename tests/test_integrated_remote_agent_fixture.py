# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Local checks for the disposable Web Agent CI request boundary."""

import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError


sys.path.insert(0, str(Path(__file__).resolve().parent))
import integrated_remote_agent_vm as fixture


class Response(io.BytesIO):
    status = 200


class BrowserRequestTests(unittest.TestCase):
    def test_machine_roots_and_units_are_fixed_to_disposable_names(self):
        target = "sovagrid-ci-target-012345abcdef"
        web = "sovagrid-ci-web-target-012345abcdef"
        self.assertEqual(fixture.machine_root(target), Path("/var/lib/machines") / target)
        self.assertEqual(fixture.machine_root(web), Path("/var/lib/machines") / web)
        self.assertEqual(fixture.machine_unit(target), "sovagrid-ci-nspawn-target-012345abcdef.service")
        self.assertEqual(fixture.machine_unit(web), "sovagrid-ci-nspawn-web-target-012345abcdef.service")
        self.assertNotEqual(fixture.CONNECT_PORT, fixture.WEB_PORT)
        for name in ("sovagrid-ci-target-../../etc", "sovagrid-ci-target-012345abcdef/else",
                     "sovagrid-ci-target-untrusted", "sovagrid-ci-other-012345abcdef"):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                fixture.machine_root(name)

    def test_connect_journal_uses_a_root_owned_runtime_ancestor(self):
        records = fixture.ci_records_dir({"container": "sovagrid-ci-target-012345abcdef"})
        self.assertEqual(records, Path("/run/sovagrid-ci-connect-012345abcdef"))
        self.assertNotIn("_temp", str(records))
        for container in ("sovagrid-ci-target-../../etc",
                          "sovagrid-ci-target-012345abcdef/else", "unrelated"):
            with self.subTest(container=container), self.assertRaises(RuntimeError):
                fixture.ci_records_dir({"container": container})

    def test_route_sends_same_origin_and_ephemeral_credentials_only_in_body(self):
        seen = []

        class Opener:
            def open(self, request, *, timeout):
                seen.append((request, timeout))
                return Response(b'{"protocol":1,"phase":"prepared"}')

        with patch.object(fixture, "build_opener", return_value=Opener()):
            reply = fixture.browser_ssh_request(
                "/api/v1/browser-ssh/agent/prepare",
                {"private_key": "fixture-secret", "host": "192.0.2.10"}, "a" * 43,
                timeout=123)
        self.assertEqual(reply["phase"], "prepared")
        request, timeout = seen.pop()
        self.assertEqual(timeout, 123)
        self.assertEqual(request.get_header("Origin"), "http://127.0.0.1:8766")
        self.assertEqual(request.get_header("Authorization"), "Bearer " + "a" * 43)
        self.assertNotIn("fixture-secret", str(request.headers))
        self.assertEqual(json.loads(request.data)["private_key"], "fixture-secret")

    def test_refusal_never_reports_response_body_or_ssh_secret(self):
        secret = "sensitive-ssh-key"

        class Opener:
            def open(self, request, *, timeout):
                raise HTTPError(request.full_url, 422, "bad", {},
                                io.BytesIO(json.dumps({"error": secret}).encode()))

        with patch.object(fixture, "build_opener", return_value=Opener()):
            with self.assertRaises(RuntimeError) as failure:
                fixture.browser_ssh_request("/api/v1/browser-ssh/agent/prepare",
                                            {"private_key": secret}, "a" * 43)
        self.assertNotIn(secret, str(failure.exception))
        self.assertIn("HTTP_ERROR", str(failure.exception))


if __name__ == "__main__":
    unittest.main()
