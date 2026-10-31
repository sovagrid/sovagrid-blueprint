# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Fixed remote WireGuard installer bridge; no real SSH or root writes."""

from __future__ import annotations

from contextlib import nullcontext
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vendor" / "connect"))
sys.path.insert(0, str(ROOT / "deploy"))
import web_wireguard_control as control


STATE = "a" * 64
SOURCE = "b" * 64
FP = "SHA256:" + "A" * 43
OPTIONS = SimpleNamespace(host="example.test", port=22, user="operator")
CREDENTIAL = SimpleNamespace(method="password", password="secret", private_key="", passphrase="")


def response(value, status=0):
    return json.dumps({"ok": status == 0, **value}, separators=(",", ":")).encode(), status


def preview(**updates):
    value = {"schema_version": 1, "action": "preview", "writes": False,
             "state_revision": STATE, "source_revision": SOURCE,
             "installed_current": False, "socket_active": False,
             "service_active": False, "socket_enabled": False,
             "pending_recovery": False, "inventory_timer_active": False,
             "inventory_timer_enabled": False, "inventory_snapshot_present": False,
             "missing_dependencies": ["wg", "wg-quick"],
             "apparmor_profile_present": False, "can_apply": True,
             "requires_service_restart": False}
    value.update(updates)
    return response(value)


class FakeRPC:
    def __init__(self, replies, preflight_error=None):
        self.replies = list(replies)
        self.preflight_error = preflight_error
        self.calls = []
        self.ready = False

    def preflight(self):
        self.calls.append(("preflight",))
        if self.preflight_error:
            raise control.RPCError(self.preflight_error)
        self.ready = True

    def _exchange(self, script, chunks, timeout):
        self.calls.append(("exchange", script, tuple(chunks), timeout))
        assert self.ready
        assert control.CLI in script
        assert "secret" not in script
        return self.replies.pop(0)


class FakeTransport:
    def __init__(self, rpc, kwargs):
        self.rpc = rpc
        self.kwargs = kwargs
        self.options = OPTIONS
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.closed = True

    def target_rpc(self, options):
        assert options is self.options
        return self.rpc


class FakeJobs:
    def __init__(self):
        self.entered = 0

    def _exclusive(self):
        self.entered += 1
        return nullcontext()


class BridgeTests(unittest.TestCase):
    def bridge(self, *replies, preflight_error=None):
        rpc = FakeRPC(replies, preflight_error)
        transports = []

        def make_transport(**kwargs):
            transport = FakeTransport(rpc, kwargs)
            transports.append(transport)
            return transport

        jobs = FakeJobs()
        return control.WireguardControlJobs(jobs, transport_factory=make_transport), rpc, transports, jobs

    def run_action(self, bridge, action, **kwargs):
        return bridge.execute(action, options=OPTIONS, fingerprint=FP,
                              credential=CREDENTIAL, **kwargs)

    def test_preview_is_pinned_root_and_read_only(self):
        bridge, rpc, transports, jobs = self.bridge(preview())
        result = self.run_action(bridge, "preview")
        self.assertEqual(result["state_revision"], STATE)
        self.assertEqual(result["source_revision"], SOURCE)
        self.assertEqual(result["scope"], "entered_target")
        self.assertEqual(result["host_key_fingerprint"], FP)
        self.assertFalse(result["writes"])
        self.assertEqual([call[0] for call in rpc.calls], ["preflight", "exchange"])
        self.assertEqual(rpc.calls[1][2], ())
        self.assertIn('"preview"', rpc.calls[1][1])
        self.assertEqual(transports[0].kwargs["fingerprint"], FP)
        self.assertEqual(transports[0].kwargs["password"], "secret")
        self.assertTrue(transports[0].closed)
        self.assertEqual(jobs.entered, 1)

    def test_preview_through_jump_passes_both_pins_to_transport(self):
        bridge, _rpc, transports, _jobs = self.bridge(preview())
        options = SimpleNamespace(host="example.test", port=22, user="operator",
                                  jump_host="relay.test", jump_port=2200,
                                  jump_user="relay")
        jump = {"host": "relay.test", "port": 2200, "username": "relay",
                "fingerprint": "SHA256:" + "E" * 43,
                "method": "password", "password": "jump-secret",
                "private_key": "", "passphrase": "", "host_key_blob": "jump-blob"}
        credential = SimpleNamespace(method="password", password="target-secret",
                                     private_key="", passphrase="", jump=jump,
                                     target_host_key_blob="target-blob")
        result = bridge.execute("preview", options=options, fingerprint=FP,
                                credential=credential)
        self.assertEqual(transports[0].kwargs["jump"], jump)
        self.assertEqual(transports[0].kwargs["target_host_key_blob"], "target-blob")
        self.assertEqual((result["jump_host"], result["jump_port"],
                          result["jump_host_key_fingerprint"]),
                         ("relay.test", 2200, jump["fingerprint"]))
        with self.assertRaisesRegex(control.WireguardControlError, "INVALID_REQUEST"):
            bridge.execute("preview", options=SimpleNamespace(**{**vars(options),
                "jump_port": 2201}), fingerprint=FP, credential=credential)
        self.assertEqual(len(transports), 1)

    def test_apply_needs_confirmation_and_both_exact_revisions(self):
        bridge, rpc, transports, jobs = self.bridge()
        for kwargs in ({"expected": {"state_revision": STATE, "source_revision": SOURCE}},
                       {"expected": {"state_revision": STATE, "source_revision": SOURCE}, "confirm": False},
                       {"expected": {"state_revision": STATE + ";id", "source_revision": SOURCE}, "confirm": True},
                       {"expected": {"state_revision": STATE}, "confirm": True}):
            with self.assertRaises(control.WireguardControlError) as error:
                self.run_action(bridge, "apply", **kwargs)
            self.assertEqual(error.exception.code, "INVALID_REQUEST")
        self.assertEqual(rpc.calls, [])
        self.assertEqual(transports, [])
        self.assertEqual(jobs.entered, 0)

    def test_stale_preview_blocks_installer_before_writes(self):
        bridge, rpc, _transports, _jobs = self.bridge(preview(state_revision="c" * 64))
        with self.assertRaises(control.WireguardControlError) as error:
            self.run_action(bridge, "apply", expected={"state_revision": STATE,
                            "source_revision": SOURCE}, confirm=True)
        self.assertEqual(error.exception.code, "STALE_PREVIEW")
        self.assertEqual([call[0] for call in rpc.calls], ["preflight", "exchange"])

    def test_apply_uses_only_reviewed_state_and_checks_result_source(self):
        installed = response({"action": "installed", "socket_active": True,
            "service_active": True, "vpn_interface_changed": False,
            "inventory_timer_active": True, "inventory_snapshot_present": True,
            "source_revision": SOURCE})
        bridge, rpc, _transports, _jobs = self.bridge(preview(), installed)
        result = self.run_action(bridge, "apply", expected={"state_revision": STATE,
                                  "source_revision": SOURCE}, confirm=True)
        self.assertEqual(result["action"], "installed")
        self.assertFalse(result["vpn_interface_changed"])
        self.assertEqual([call[0] for call in rpc.calls], ["preflight", "exchange", "exchange"])
        self.assertIn('"--expected-state","' + STATE + '"', rpc.calls[2][1])
        self.assertNotIn('"recover"', rpc.calls[2][1])
        self.assertEqual(rpc.calls[2][3], 540)

    def test_recover_requires_confirmation_and_has_fixed_result(self):
        bridge, rpc, _transports, _jobs = self.bridge(response({"action": "recovered", "changed": True}))
        with self.assertRaises(control.WireguardControlError):
            self.run_action(bridge, "recover")
        self.assertEqual(rpc.calls, [])
        result = self.run_action(bridge, "recover", confirm=True)
        self.assertEqual(result["action"], "recovered")
        self.assertTrue(result["changed"])
        self.assertEqual(rpc.calls[-1][3], 360)

    def test_unsafe_remote_text_never_reaches_web(self):
        leaked = b'{"ok":true,"schema_version":1,"action":"preview","writes":false,"can_apply":false,"reason":"private target detail"}'
        result = control._response(leaked, 0, "preview")
        self.assertEqual(result["reason"], "OPERATION_FAILED")
        for action in ("preview", "apply", "recover"):
            with self.assertRaises(control.WireguardControlError) as error:
                control._response(b'{"ok":false,"error":"private target detail"}', 2, action)
            self.assertEqual(error.exception.code,
                             "APPLY_UNCERTAIN" if action == "apply" else
                             "RECOVERY_UNCERTAIN" if action == "recover" else "OPERATION_FAILED")
            self.assertNotIn("private", str(error.exception))

    def test_invalid_cli_shapes_and_duplicate_fields_fail_closed(self):
        for raw in (b'{"ok":true,"ok":true}', b'{"ok":true,"command":"id"}',
                    b'{"ok":true,"action":"installed","source_revision":"secret"}',
                    b'{"ok":true,"schema_version":1,"action":"preview","writes":false,"can_apply":false,"reason":{"secret":1}}'):
            with self.assertRaises(control.WireguardControlError):
                control._response(raw, 0, "preview")

    def test_preflight_requires_noninteractive_root(self):
        bridge, rpc, _transports, _jobs = self.bridge(preflight_error="ROOT_REQUIRED")
        with self.assertRaises(control.WireguardControlError) as error:
            self.run_action(bridge, "preview")
        self.assertEqual(error.exception.code, "ROOT_REQUIRED")
        self.assertEqual(rpc.calls, [("preflight",)])


if __name__ == "__main__":
    unittest.main()
