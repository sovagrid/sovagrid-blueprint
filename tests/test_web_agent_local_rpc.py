# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Boundaries for the host-side half of remote Agent enrollment."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

BLUEPRINT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BLUEPRINT / "deploy"))
from web_agent_local_rpc import LocalHubFacade, LocalHubRPC, _bounded_python, _guard_vendor_import, _agent_rpc


class LocalHubRPCTests(unittest.TestCase):
    def test_facade_exposes_only_the_fixed_loopback_hub(self):
        facade = LocalHubFacade()
        self.assertEqual(facade.url, "http://127.0.0.1:8766/")
        self.assertEqual((facade.options.host, facade.options.user, facade.options.port,
                          facade.options.local_port), ("127.0.0.1", "root", 22, 8766))
        self.assertTrue(facade.alive)
        facade.close()
        self.assertFalse(facade.alive)

    def test_local_rpc_rejects_a_target_role_or_other_hub_identity(self):
        options = LocalHubFacade().options
        with self.assertRaises(ValueError):
            LocalHubRPC(options, role="target")
        with self.assertRaises(ValueError):
            LocalHubRPC(_agent_rpc.ConnectionOptions(host="server.example", user="root"), role="hub")

    def test_nonroot_and_arbitrary_snippets_fail_before_process_creation(self):
        rpc = LocalHubRPC(LocalHubFacade().options, role="hub", root_check=lambda: 1000)
        with self.assertRaises(_agent_rpc.RPCError) as error:
            rpc.preflight()
        self.assertEqual(error.exception.code, "ROOT_REQUIRED")
        with self.assertRaises(_agent_rpc.RPCError) as error:
            rpc._exchange("print('untrusted')", (), 1)
        self.assertEqual(error.exception.code, "ROOT_REQUIRED")
        rpc = LocalHubRPC(LocalHubFacade().options, role="hub", root_check=lambda: 0)
        with self.assertRaises(_agent_rpc.RPCError) as error:
            rpc._exchange("print('untrusted')", (), 1)
        self.assertEqual(error.exception.code, "INVALID_REQUEST")
        with self.assertRaises(_agent_rpc.RPCError) as error:
            rpc._exchange(_agent_rpc._CALL_SCRIPT, (b"x" * 32769,), 1)
        self.assertEqual(error.exception.code, "INVALID_REQUEST")

    def test_bounded_runner_uses_stdin_and_suppresses_stderr(self):
        script = "import sys; data=sys.stdin.buffer.read(); sys.stderr.write('private-canary'); sys.stdout.buffer.write(data)"
        payload = b'{"protocol":1,"action":"hub-preview"}'
        output, code = _bounded_python(script, payload, 5, threading.Event())
        self.assertEqual(code, 0)
        self.assertEqual(output, payload)
        self.assertNotIn(b"private-canary", output)

    def test_excess_output_is_rejected_before_unbounded_buffering(self):
        script = "import sys; sys.stdout.buffer.write(b'x'*32769); sys.stdout.flush()"
        with self.assertRaises(_agent_rpc.RPCError) as error:
            _bounded_python(script, b"", 5, threading.Event())
        self.assertEqual(error.exception.code, "INVALID_REPLY")

    def test_timeout_and_cancellation_stop_the_local_process(self):
        script = "import time; time.sleep(10)"
        started = time.monotonic()
        with self.assertRaises(_agent_rpc.RPCError) as error:
            _bounded_python(script, b"", 0.15, threading.Event())
        self.assertEqual(error.exception.code, "TIMEOUT")
        self.assertLess(time.monotonic() - started, 2)
        stop = threading.Event(); stop.set()
        with self.assertRaises(_agent_rpc.RPCError) as error:
            _bounded_python(script, b"", 5, stop)
        self.assertEqual(error.exception.code, "CANCELLED")

    def test_borrowed_enrollment_payload_contains_no_secret_fields(self):
        # The inherited strict validator is the only path to a local hub-* RPC.
        rpc = LocalHubRPC(LocalHubFacade().options, role="hub", root_check=lambda: 0)
        with self.assertRaises(_agent_rpc.RPCError) as error:
            rpc.call("hub-preview", {"protocol": 1, "password": "private-canary"})
        self.assertEqual(error.exception.code, "INVALID_REQUEST")

    def test_vendor_import_checks_manifest_bytes_before_loading_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "sovagrid-src"
            vendor = source / "sovagrid-blueprint/vendor/connect"
            package = vendor / "sovagrid_connect"
            package.mkdir(parents=True)
            marker = root / "managed"
            marker.write_bytes(b"managed")
            marker.chmod(0o600)
            names = ("__init__.py", "agent_rpc.py", "core.py", "enrollment_protocol.py", "installer.py")
            files = {}
            for name in names:
                data = ("# " + name + "\n").encode()
                (package / name).write_bytes(data)
                files[f"sovagrid-blueprint/vendor/connect/sovagrid_connect/{name}"] = hashlib.sha256(data).hexdigest()
            (source / "sovagrid-bundle.json").write_text(json.dumps({"format": 1,
                "components": {name: {} for name in ("sovagrid-blueprint", "sovagrid-hub",
                    "sovagrid-web", "sovagrid-agent", "sovagrid-vpn")}, "sha256": files}))
            _guard_vendor_import(source, vendor, marker, owner=os.geteuid())
            (package / "agent_rpc.py").write_text("# changed\n")
            with self.assertRaises(ImportError):
                _guard_vendor_import(source, vendor, marker, owner=os.geteuid())
            (package / "agent_rpc.py").write_text("# agent_rpc.py\n")
            (package / "unexpected.py").write_text("# extra\n")
            with self.assertRaises(ImportError):
                _guard_vendor_import(source, vendor, marker, owner=os.geteuid())


if __name__ == "__main__":
    unittest.main()
