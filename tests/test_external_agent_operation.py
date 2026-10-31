# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The fixed unit never accepts a caller-selected command or a stale request."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
from unittest import TestCase, mock


SCRIPT = Path(__file__).resolve().parents[1] / "deploy/external_agent_operation.py"
spec = importlib.util.spec_from_file_location("sovagrid_external_operation_test", SCRIPT)
assert spec and spec.loader
operation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operation)

REQUEST_ID = "9c941101-2acb-4e59-877c-136d3f43f1d8"
SHA = "a" * 64


class ExternalOperationTests(TestCase):
    def test_id_and_json_are_exact(self):
        self.assertEqual(operation._id(REQUEST_ID), REQUEST_ID)
        for value in ("../etc", REQUEST_ID.upper(), "9c9411012acb4e59877c136d3f43f1d8"):
            with self.subTest(value=value), self.assertRaises(operation.Refused):
                operation._id(value)
        with self.assertRaises(operation.Refused):
            operation._decode(b'{"format":1,"format":1}\n')
        with self.assertRaises(operation.Refused):
            operation._decode(b'{"format": 1}\n')

    def test_request_and_status_reject_extra_fields_and_noncanonical_state(self):
        request = {"format": 1, "request_id": REQUEST_ID,
                   "archive_sha256": SHA, "current_hub_manifest_sha256": SHA,
                   "external_agent_manifest_sha256": SHA, "review_sha256": SHA}
        status = {"format": 1, "request_id": REQUEST_ID, "phase": "accepted",
                  "created_at": 1, "updated_at": 1, "error": None}
        encoded = lambda value: (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with mock.patch.object(operation, "_read", side_effect=[encoded(request), encoded(status)]):
            self.assertEqual(operation._request(Path("/unused"), REQUEST_ID), request)
            self.assertEqual(operation._status(Path("/unused"), REQUEST_ID), status)
        request["private_key"] = "secret"
        with mock.patch.object(operation, "_read", return_value=encoded(request)):
            with self.assertRaises(operation.Refused):
                operation._request(Path("/unused"), REQUEST_ID)
        status["phase"] = "complete"
        status["error"] = "FORGED"
        with mock.patch.object(operation, "_read", return_value=encoded(status)):
            with self.assertRaises(operation.Refused):
                operation._status(Path("/unused"), REQUEST_ID)

    @staticmethod
    def _request():
        return {"archive_sha256": SHA, "current_hub_manifest_sha256": SHA,
                "external_agent_manifest_sha256": SHA, "review_sha256": SHA}

    def test_success_runs_only_installed_cli_with_exact_four_hashes(self):
        output = {"protocol": 1, "applied": True,
                  "external_agent_manifest_sha256": SHA, "review_sha256": SHA}
        transitions = []
        with mock.patch.object(operation.os, "geteuid", return_value=0), \
             mock.patch.object(operation.os, "getegid", return_value=0), \
             mock.patch.object(operation.sys, "platform", "linux"), \
             mock.patch.object(operation, "_record_dir", return_value=Path("/unused")), \
             mock.patch.object(operation, "_request", return_value=self._request()), \
             mock.patch.object(operation, "_transition", side_effect=lambda *a, **kw: transitions.append((a, kw))), \
             mock.patch.object(operation.subprocess, "run", return_value=subprocess.CompletedProcess(
                 [], 0, (json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n").encode(), b"")) as runner:
            self.assertEqual(operation._apply(REQUEST_ID), 0)
        command = runner.call_args.args[0]
        self.assertEqual(command, ["/usr/bin/python3", "-B", "-I", str(operation.UPDATE),
                                   "apply", SHA, SHA, SHA, SHA])
        self.assertEqual([item[0][3] for item in transitions], ["running", "complete"])

    def test_refusal_never_exposes_stderr_and_does_not_retry(self):
        transitions = []
        with mock.patch.object(operation.os, "geteuid", return_value=0), \
             mock.patch.object(operation.os, "getegid", return_value=0), \
             mock.patch.object(operation.sys, "platform", "linux"), \
             mock.patch.object(operation, "_record_dir", return_value=Path("/unused")), \
             mock.patch.object(operation, "_request", return_value=self._request()), \
             mock.patch.object(operation, "_transition", side_effect=lambda *a, **kw: transitions.append((a, kw))), \
             mock.patch.object(operation.subprocess, "run", return_value=subprocess.CompletedProcess(
                 [], 40, b"", b"secret\nSG_EXTERNAL_AGENT_UPDATE_REFUSE:APPLY_ROLLED_BACK\n")) as runner:
            self.assertEqual(operation._apply(REQUEST_ID), 40)
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(transitions[-1][0][3:], ("uncertain", "APPLY_UNCERTAIN"))

    def test_terminal_request_never_runs_apply_again(self):
        with mock.patch.object(operation.os, "geteuid", return_value=0), \
             mock.patch.object(operation.os, "getegid", return_value=0), \
             mock.patch.object(operation.sys, "platform", "linux"), \
             mock.patch.object(operation, "_record_dir", return_value=Path("/unused")), \
             mock.patch.object(operation, "_request", return_value=self._request()), \
             mock.patch.object(operation, "_transition",
                               side_effect=operation.Refused("OPERATION_ALREADY_STARTED")), \
             mock.patch.object(operation.subprocess, "run") as runner:
            with self.assertRaisesRegex(operation.Refused, "OPERATION_ALREADY_STARTED"):
                operation._apply(REQUEST_ID)
        runner.assert_not_called()


if __name__ == "__main__":
    import unittest
    unittest.main()
