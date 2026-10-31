# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Fixed Amnezia provision bridge with fake SSH and no Docker/root writes."""

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
import web_amnezia_provision as module


STATE = "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
IMAGE_DIGEST = "sha256:" + "c" * 64
CONTAINER_ID = "d" * 64
FP = "SHA256:" + "A" * 43
OPTIONS = SimpleNamespace(host="target.example", port=2222, user="root")
CREDENTIAL = SimpleNamespace(method="password", password="test-secret", private_key="", passphrase="")
PARAMS = {"listen_port": 49289, "subnet": "10.91.7.0/24", "route_mode": "full"}


def payload(value):
    return (json.dumps(value, separators=(",", ":")) + "\n").encode(), 0


def preview(**changes):
    value = {"schema_version": 1, "action": "preview", "writes": False,
             "target": "awg2", "container": "amnezia-awg2", **PARAMS,
             "image_digest": IMAGE_DIGEST, "image_cached": False,
             "state_revision": STATE, "can_apply": True}
    value.update(changes)
    return payload(value)


def installed(**changes):
    value = {"schema_version": 1, "action": "installed", "target": "awg2",
             "container": "amnezia-awg2", "container_id": CONTAINER_ID,
             "image_id": IMAGE_ID, **PARAMS, "recovery_required": False}
    value.update(changes)
    return payload(value)


class FakeRPC:
    def __init__(self, replies, preflight_error=None):
        self.replies = list(replies)
        self.preflight_error = preflight_error
        self.calls = []

    def preflight(self):
        self.calls.append(("preflight",))
        if self.preflight_error:
            raise module.RPCError(self.preflight_error)

    def _exchange(self, script, chunks, timeout):
        self.calls.append(("exchange", script, tuple(chunks), timeout))
        assert module.CLI in script
        assert "/bin/sh" in script
        assert "test-secret" not in script
        assert tuple(chunks) == ()
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


class FakeTransport:
    def __init__(self, rpc, options, kwargs):
        self.rpc, self.options, self.kwargs = rpc, options, kwargs
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
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


class ProvisionBridgeTests(unittest.TestCase):
    def bridge(self, *replies, preflight_error=None):
        rpc = FakeRPC(replies, preflight_error)
        transports = []

        def factory(**kwargs):
            transport = FakeTransport(rpc, OPTIONS, kwargs)
            transports.append(transport)
            return transport

        jobs = FakeJobs()
        return module.AmneziaProvisionJobs(jobs, transport_factory=factory), rpc, transports, jobs

    @staticmethod
    def execute(bridge, action, **kwargs):
        return bridge.execute(action, options=OPTIONS, fingerprint=FP,
                              credential=CREDENTIAL, **kwargs)

    def test_preview_is_pinned_root_and_fixed_source(self):
        bridge, rpc, transports, jobs = self.bridge(preview())
        result = self.execute(bridge, "preview", **PARAMS)
        self.assertEqual(result["scope"], "entered_target")
        self.assertEqual(result["host_key_fingerprint"], FP)
        self.assertEqual(result["state_revision"], STATE)
        self.assertEqual([call[0] for call in rpc.calls], ["preflight", "exchange"])
        self.assertEqual(rpc.calls[1][3], 45)
        self.assertEqual(transports[0].kwargs["fingerprint"], FP)
        self.assertEqual(transports[0].kwargs["password"], "test-secret")
        self.assertTrue(transports[0].closed)
        self.assertEqual(jobs.entered, 1)
        self.assertIn(module.MODULE, rpc.calls[1][1])
        self.assertIn('argv=["/bin/sh","' + module.CLI + '"', rpc.calls[1][1])
        compile(rpc.calls[1][1], "<remote-amnezia-provision>", "exec")

    def test_preview_through_jump_uses_separate_credentials(self):
        bridge, _rpc, transports, _jobs = self.bridge(preview())
        options = SimpleNamespace(host="target.example", port=2222, user="root",
                                  jump_host="relay.example", jump_port=2200,
                                  jump_user="relay")
        jump = {"host": "relay.example", "port": 2200, "username": "relay",
                "fingerprint": "SHA256:" + "E" * 43,
                "method": "password", "password": "jump-secret",
                "private_key": "", "passphrase": "", "host_key_blob": "jump-blob"}
        credential = SimpleNamespace(method="password", password="target-secret",
                                     private_key="", passphrase="", jump=jump,
                                     target_host_key_blob="target-blob")
        result = bridge.execute("preview", options=options, fingerprint=FP,
                                credential=credential, **PARAMS)
        self.assertEqual(transports[0].kwargs["jump"], jump)
        self.assertEqual(transports[0].kwargs["target_host_key_blob"], "target-blob")
        self.assertEqual((result["jump_host"], result["jump_port"],
                          result["jump_host_key_fingerprint"]),
                         ("relay.example", 2200, jump["fingerprint"]))
        with self.assertRaisesRegex(module.AmneziaProvisionError, "INVALID_REQUEST"):
            bridge.execute("preview", options=SimpleNamespace(**{**vars(options),
                "jump_host": "changed.example"}), fingerprint=FP,
                credential=credential, **PARAMS)
        self.assertEqual(len(transports), 1)

    def test_apply_requires_confirmation_and_revision_before_ssh(self):
        bridge, rpc, transports, jobs = self.bridge()
        for kwargs in (PARAMS | {"expected_state": STATE},
                       PARAMS | {"expected_state": STATE, "confirm": False},
                       PARAMS | {"expected_state": STATE + ";id", "confirm": True},
                       PARAMS | {"expected_state": STATE, "confirm": True, "subnet": "203.0.113.0/24"},
                       PARAMS | {"expected_state": STATE, "confirm": True, "route_mode": "outside"}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(module.AmneziaProvisionError) as error:
                    self.execute(bridge, "apply", **kwargs)
                self.assertEqual(error.exception.code, "INVALID_REQUEST")
        self.assertEqual(rpc.calls, [])
        self.assertEqual(transports, [])
        self.assertEqual(jobs.entered, 0)

    def test_apply_rechecks_cas_and_exact_result(self):
        bridge, rpc, _transports, _jobs = self.bridge(preview(), installed())
        result = self.execute(bridge, "apply", **PARAMS, expected_state=STATE, confirm=True)
        self.assertEqual(result["container_id"], CONTAINER_ID)
        self.assertEqual([call[0] for call in rpc.calls], ["preflight", "exchange", "exchange"])
        self.assertEqual(rpc.calls[1][3], 45)
        self.assertEqual(rpc.calls[2][3], 330)
        self.assertIn('"--expected-state","' + STATE + '"', rpc.calls[2][1])
        self.assertNotIn('"recover"', rpc.calls[2][1])

    def test_stale_or_refused_preview_blocks_apply(self):
        for first, code in ((preview(state_revision="f" * 64), "STALE_PREVIEW"),
                            (preview(can_apply=False, reason="CONTAINER_EXISTS"), "CONTAINER_EXISTS")):
            with self.subTest(code=code):
                bridge, rpc, _transports, _jobs = self.bridge(first)
                with self.assertRaises(module.AmneziaProvisionError) as error:
                    self.execute(bridge, "apply", **PARAMS, expected_state=STATE, confirm=True)
                self.assertEqual(error.exception.code, code)
                self.assertEqual([call[0] for call in rpc.calls], ["preflight", "exchange"])

    def test_recover_has_no_parameters_and_requires_confirm(self):
        recovered = payload({"schema_version": 1, "action": "recovered",
                             "changed": True, "installed": False})
        bridge, rpc, _transports, _jobs = self.bridge(recovered)
        with self.assertRaises(module.AmneziaProvisionError):
            self.execute(bridge, "recover")
        self.assertEqual(rpc.calls, [])
        result = self.execute(bridge, "recover", confirm=True)
        self.assertFalse(result["installed"])
        self.assertEqual(rpc.calls[-1][3], 80)

    def test_transport_or_generic_error_after_mutation_is_uncertain(self):
        for action, input_kwargs, replies, expected in (
                ("apply", PARAMS | {"expected_state": STATE, "confirm": True},
                 (preview(), module.RPCError("SSH_FAILED")), "APPLY_UNCERTAIN"),
                ("recover", {"confirm": True},
                 (module.RPCError("TIMEOUT"),), "RECOVERY_UNCERTAIN")):
            with self.subTest(action=action):
                bridge, _rpc, _transports, _jobs = self.bridge(*replies)
                with self.assertRaises(module.AmneziaProvisionError) as error:
                    self.execute(bridge, action, **input_kwargs)
                self.assertEqual(error.exception.code, expected)
        for action, expected in (("apply", "APPLY_UNCERTAIN"),
                                 ("recover", "RECOVERY_UNCERTAIN")):
            with self.assertRaises(module.AmneziaProvisionError) as error:
                module._response(b'{"ok":false,"error":"AMNEZIA_PROVISION_FAILED"}', 3, action)
            self.assertEqual(error.exception.code, expected)

    def test_target_errors_are_fixed_and_status_bound(self):
        raw = b'{"ok":false,"error":"RECOVERY_REQUIRED"}'
        with self.assertRaises(module.AmneziaProvisionError) as error:
            module._response(raw, 2, "apply")
        self.assertEqual(error.exception.code, "RECOVERY_REQUIRED")
        with self.assertRaises(module.AmneziaProvisionError) as error:
            module._response(raw, 255, "apply")
        self.assertEqual(error.exception.code, "APPLY_UNCERTAIN")
        for text in (b'{"ok":false,"error":"private key"}',
                     b'{"ok":false,"error":"RECOVERY_REQUIRED","secret":1}',
                     b'{"ok":true,"ok":true}',
                     b'{"schema_version":1,"action":"preview","private_key":"secret"}'):
            with self.assertRaises(module.AmneziaProvisionError) as error:
                module._response(text, 0, "preview")
            self.assertEqual(error.exception.code, "OPERATION_FAILED")
            self.assertNotIn("secret", str(error.exception))

    def test_source_guard_refusals_remain_exact_before_mutation(self):
        for code in ("SOURCE_BUSY", "SOURCE_UNTRUSTED"):
            with self.subTest(code=code):
                refusal = (json.dumps({"ok": False, "error": code}) + "\n").encode(), 2
                for action in ("apply", "recover"):
                    with self.subTest(action=action):
                        replies = (preview(), refusal) if action == "apply" else (refusal,)
                        bridge, rpc, _transports, _jobs = self.bridge(*replies)
                        kwargs = PARAMS | {"expected_state": STATE, "confirm": True} if action == "apply" \
                            else {"confirm": True}
                        with self.assertRaises(module.AmneziaProvisionError) as error:
                            self.execute(bridge, action, **kwargs)
                        self.assertEqual(error.exception.code, code)
                        self.assertEqual([call[0] for call in rpc.calls],
                                         ["preflight", "exchange", "exchange"] if action == "apply"
                                         else ["preflight", "exchange"])

    def test_installation_drift_blocks_apply_and_recover_as_fixed_refusal(self):
        reason = "INSTALLATION_DRIFT"
        full = preview(can_apply=False, reason=reason)
        self.assertEqual(module._response(*full, "preview")["reason"], reason)
        bridge, rpc, _transports, _jobs = self.bridge(full)
        with self.assertRaises(module.AmneziaProvisionError) as error:
            self.execute(bridge, "apply", **PARAMS, expected_state=STATE, confirm=True)
        self.assertEqual(error.exception.code, reason)
        self.assertEqual([call[0] for call in rpc.calls], ["preflight", "exchange"])

        refusal = (b'{"ok":false,"error":"INSTALLATION_DRIFT"}\n', 2)
        for action, replies, kwargs in (
                ("apply", (preview(), refusal), PARAMS | {"expected_state": STATE, "confirm": True}),
                ("recover", (refusal,), {"confirm": True})):
            with self.subTest(action=action):
                bridge, _rpc, _transports, _jobs = self.bridge(*replies)
                with self.assertRaises(module.AmneziaProvisionError) as error:
                    self.execute(bridge, action, **kwargs)
                self.assertEqual(error.exception.code, reason)

    def test_preflight_and_preview_failure_before_apply_are_not_uncertain(self):
        bridge, rpc, _transports, _jobs = self.bridge(preflight_error="ROOT_REQUIRED")
        with self.assertRaises(module.AmneziaProvisionError) as error:
            self.execute(bridge, "apply", **PARAMS, expected_state=STATE, confirm=True)
        self.assertEqual(error.exception.code, "ROOT_REQUIRED")
        self.assertEqual(rpc.calls, [("preflight",)])

        bridge, rpc, _transports, _jobs = self.bridge(module.RPCError("SSH_FAILED"))
        with self.assertRaises(module.AmneziaProvisionError) as error:
            self.execute(bridge, "apply", **PARAMS, expected_state=STATE, confirm=True)
        self.assertEqual(error.exception.code, "SSH_UNAVAILABLE")
        self.assertEqual([call[0] for call in rpc.calls], ["preflight", "exchange"])

    def test_degraded_preview_has_no_secrets_or_revision(self):
        degraded = {"schema_version": 1, "action": "preview", "writes": False,
                    "target": "awg2", "container": "amnezia-awg2",
                    "can_apply": False, "reason": "RECOVERY_REQUIRED"}
        self.assertEqual(module._response(payload(degraded)[0], 0, "preview"), degraded)
        degraded["reason"] = "arbitrary target text"
        with self.assertRaises(module.AmneziaProvisionError):
            module._response(payload(degraded)[0], 0, "preview")
        full = preview(can_apply=False, reason="UDP_PORT_BUSY")[0]
        self.assertEqual(module._response(full, 0, "preview")["reason"], "UDP_PORT_BUSY")
        for code in ("SOURCE_BUSY", "SOURCE_UNTRUSTED", "INSTALLATION_DRIFT"):
            with self.subTest(code=code):
                degraded["reason"] = code
                self.assertEqual(module._response(payload(degraded)[0], 0, "preview"), degraded)

    def test_preflight_requires_noninteractive_root(self):
        bridge, rpc, _transports, _jobs = self.bridge(preflight_error="ROOT_REQUIRED")
        with self.assertRaises(module.AmneziaProvisionError) as error:
            self.execute(bridge, "preview", **PARAMS)
        self.assertEqual(error.exception.code, "ROOT_REQUIRED")
        self.assertEqual(rpc.calls, [("preflight",)])


if __name__ == "__main__":
    unittest.main()
