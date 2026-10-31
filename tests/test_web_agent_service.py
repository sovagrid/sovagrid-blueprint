# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Host socket protocol tests with no network or privileged process."""

from __future__ import annotations

from contextlib import nullcontext
import fcntl
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import web_agent_service as service


TOKEN = "b" * 43
FINGERPRINT = "SHA256:" + "A" * 43
REAL_STABLE_PUBLIC_WEB = service._stable_public_web


class FakeJobs:
    def __init__(self):
        self.calls = []

    def prepare(self, **kwargs):
        self.calls.append(("prepare", kwargs))
        return {"request_id": "public-id", "writes": True, "activation_writes": False}

    def resume(self, request_id, **kwargs):
        self.calls.append(("resume", request_id, kwargs))
        return {"request_id": request_id, "phase": "prepared"}

    def apply(self, request_id, expected_revision):
        self.calls.append(("apply", request_id, expected_revision))
        return {"phase": "active"}

    def cleanup(self, request_id, expected_revision):
        self.calls.append(("cleanup", request_id, expected_revision))
        return {"removed": True}

    def status(self, request_id):
        self.calls.append(("status", request_id))
        return {"phase": "prepared"}

    def interrupt(self, request_id):
        self.calls.append(("interrupt", request_id))
        return {"cancel_requested": True}

    def list(self):
        self.calls.append(("list",))
        return []


class FakeVpnSource:
    def __init__(self):
        self.calls = []

    def execute(self, action, **kwargs):
        self.calls.append((action, kwargs))
        return {"protocol": 1, "scope": "entered_target", "host": kwargs["options"].host,
                "port": kwargs["options"].port,
                "host_key_fingerprint": kwargs["fingerprint"]}


class FakeWireguardControl:
    def __init__(self):
        self.calls = []

    def execute(self, action, **kwargs):
        self.calls.append((action, kwargs))
        return {"protocol": 1, "scope": "entered_target", "action": action,
                "host": kwargs["options"].host, "port": kwargs["options"].port}


class FakeAmneziaProvision(FakeWireguardControl):
    pass


def request(action, payload):
    return {"action": action, "session_token": TOKEN, "payload": payload}


def login_payload():
    return {"host": "target.example", "port": 22, "username": "root",
            "method": "password", "fingerprint": FINGERPRINT,
            "password": "test-only-secret", "private_key": "", "passphrase": ""}


def jump_login_payload():
    return {**login_payload(), "host_key_blob": "public-target-blob",
            "jump": {"host": "relay.example", "port": 2200, "username": "relay",
                     "method": "password", "fingerprint": "SHA256:" + "E" * 43,
                     "password": "jump-only-secret", "private_key": "",
                     "passphrase": "", "host_key_blob": "public-jump-blob"}}


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.jobs = FakeJobs()
        lock_patch = patch.object(service, "_stable_public_web", return_value=nullcontext())
        lock_patch.start()
        self.addCleanup(lock_patch.stop)

    def test_direct_installer_lock_blocks_enrollment_admission(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "public-web.lock"
            target.touch(mode=0o600)
            target.chmod(0o600)
            with patch.object(service, "_PUBLIC_WEB_LOCK", target):
                with REAL_STABLE_PUBLIC_WEB(expected_uid=os.geteuid(), expected_gid=os.getegid()):
                    pass
                with target.open("rb+") as holder:
                    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with self.assertRaises(service.RequestError) as error:
                        with REAL_STABLE_PUBLIC_WEB(expected_uid=os.geteuid(), expected_gid=os.getegid()):
                            pass
                    self.assertEqual(error.exception.code, "BUSY")

    def test_prepare_dispatch_binds_options_and_scrubs_payload(self):
        payload = {**login_payload(), "name": "Remote", "hub_host": "192.0.2.1",
                   "hub_port": 22, "local_port": 18767}
        result = service.dispatch(self.jobs, request("prepare", payload), authorize=lambda token: None)
        self.assertTrue(result["writes"])
        self.assertFalse(result["activation_writes"])
        self.assertEqual(self.jobs.calls[0][1]["target_options"].host, "target.example")
        self.assertEqual(self.jobs.calls[0][1]["credential"].password, "")
        self.assertEqual(payload["password"], "")

    def test_jump_prepare_binds_both_host_pins_and_wipes_both_credentials(self):
        jump = {"host": "jump.example", "port": 2200, "username": "relay",
                "method": "password", "fingerprint": FINGERPRINT,
                "password": "jump-only-secret", "private_key": "", "passphrase": "",
                "host_key_blob": "public-jump-blob"}
        payload = {**login_payload(), "host_key_blob": "public-target-blob", "jump": jump,
                   "name": "Via jump", "hub_host": "192.0.2.1", "hub_port": 22,
                   "local_port": 18767}
        service.dispatch(self.jobs, request("prepare", payload), authorize=lambda token: None)
        options = self.jobs.calls[0][1]["target_options"]
        self.assertEqual((options.jump_host, options.jump_user, options.jump_port),
                         ("jump.example", "relay", 2200))
        self.assertEqual(options.jump_host_key_alias, service.host_key_alias(FINGERPRINT))
        credential = self.jobs.calls[0][1]["credential"]
        self.assertEqual(credential.password, "")
        self.assertEqual(credential.jump["password"], "")
        self.assertEqual(payload["password"], "")
        self.assertEqual(payload["jump"]["password"], "")

    def test_jump_rejects_extra_field_and_scrubs_nested_secret(self):
        jump = {"host": "jump.example", "port": 22, "username": "relay",
                "method": "password", "fingerprint": FINGERPRINT,
                "password": "jump-only-secret", "private_key": "", "passphrase": "",
                "host_key_blob": "public-jump-blob", "unsafe": "extra"}
        payload = {**login_payload(), "host_key_blob": "public-target-blob", "jump": jump,
                   "name": "Via jump", "hub_host": "192.0.2.1", "hub_port": 22,
                   "local_port": 18767}
        with self.assertRaises(service.RequestError):
            service.dispatch(self.jobs, request("prepare", payload), authorize=lambda token: None)
        self.assertEqual(payload["password"], "")
        self.assertEqual(jump["password"], "")

    def test_auth_runs_before_any_job(self):
        with self.assertRaises(service.RequestError) as error:
            service.dispatch(self.jobs, request("list", {}),
                             authorize=lambda token: (_ for _ in ()).throw(service.RequestError("AUTH_REQUIRED")))
        self.assertEqual(error.exception.code, "AUTH_REQUIRED")
        self.assertEqual(self.jobs.calls, [])

    def test_only_fixed_actions_and_shapes(self):
        for value in (request("shell", {"command": "id"}),
                      request("apply", {"request_id": "id", "expected_revision": 1, "command": "id"}),
                      request("prepare", {**login_payload(), "name": "R"})):
            with self.assertRaises(service.RequestError):
                service.dispatch(self.jobs, value, authorize=lambda token: None)
        self.assertEqual(self.jobs.calls, [])

    def test_apply_and_read_actions(self):
        self.assertEqual(service.dispatch(self.jobs, request("apply", {"request_id": "id", "expected_revision": 2}),
                                          authorize=lambda token: None)["phase"], "active")
        self.assertEqual(service.dispatch(self.jobs, request("status", {"request_id": "id"}),
                                          authorize=lambda token: None)["phase"], "prepared")
        self.assertEqual(service.dispatch(self.jobs, request("list", {}), authorize=lambda token: None), [])
        self.assertEqual(self.jobs.calls, [("apply", "id", 2), ("status", "id"), ("list",)])

    def test_vpn_source_actions_require_exact_shape_and_wipe_credentials(self):
        vpn = FakeVpnSource()
        payload = login_payload()
        result = service.dispatch(self.jobs, request("vpn-source-preview", payload),
                                  authorize=lambda token: None, vpn_source=vpn)
        self.assertEqual(result["scope"], "entered_target")
        self.assertEqual(vpn.calls[0][0], "preview")
        self.assertEqual(vpn.calls[0][1]["credential"].password, "")
        self.assertEqual(payload["password"], "")
        with self.assertRaises(service.RequestError):
            service.dispatch(self.jobs, request("vpn-source-apply", login_payload()),
                             authorize=lambda token: None, vpn_source=vpn)
        self.assertEqual(len(vpn.calls), 1)

    def test_vpn_actions_bind_jump_route_and_wipe_both_secrets(self):
        for action, bridge, extra in (
            ("vpn-source-preview", FakeVpnSource(), {}),
            ("wg-control-preview", FakeWireguardControl(), {}),
            ("amnezia-provision-preview", FakeAmneziaProvision(),
             {"listen_port": 49001, "subnet": "10.91.7.0/24", "route_mode": "full"}),
        ):
            with self.subTest(action=action):
                payload = {**jump_login_payload(), **extra}
                kwargs = {"vpn_source": bridge} if action.startswith("vpn-source") else \
                         {"wg_control": bridge} if action.startswith("wg-control") else \
                         {"amnezia_provision": bridge}
                service.dispatch(self.jobs, request(action, payload),
                                 authorize=lambda token: None, **kwargs)
                options = bridge.calls[0][1]["options"]
                credential = bridge.calls[0][1]["credential"]
                self.assertEqual((options.jump_host, options.jump_user, options.jump_port),
                                 ("relay.example", "relay", 2200))
                self.assertEqual(credential.target_host_key_blob, "")
                self.assertEqual(credential.password, "")
                self.assertEqual(credential.jump["password"], "")
                self.assertEqual(payload["password"], "")
                self.assertEqual(payload["jump"]["password"], "")

    def test_vpn_jump_rejects_extra_field_and_scrubs_secrets(self):
        payload = jump_login_payload()
        payload["jump"]["unexpected"] = "x"
        with self.assertRaises(service.RequestError):
            service.dispatch(self.jobs, request("vpn-source-preview", payload),
                             authorize=lambda token: None, vpn_source=FakeVpnSource())
        self.assertEqual(payload["password"], "")
        self.assertEqual(payload["jump"]["password"], "")

    def test_wireguard_control_requires_fresh_admin_and_exact_confirmed_shape(self):
        wg = FakeWireguardControl()
        payload = login_payload()
        authorized = []
        self.assertEqual(service.dispatch(self.jobs, request("wg-control-preview", payload),
            authorize=lambda token: authorized.append(token), wg_control=wg)["action"], "preview")
        self.assertEqual(authorized, [TOKEN])
        self.assertEqual(payload["password"], "")
        self.assertEqual(wg.calls[0][1]["credential"].password, "")
        self.assertEqual(wg.calls[0][1]["fingerprint"], FINGERPRINT)
        for bad in (
                request("wg-control-preview", {**login_payload(), "command": "id"}),
                request("wg-control-apply", {**login_payload(), "confirm": True}),
                request("wg-control-recover", {**login_payload(), "expected": {}})):
            with self.assertRaises(service.RequestError):
                service.dispatch(self.jobs, bad, authorize=lambda token: authorized.append(token),
                                 wg_control=wg)
            self.assertEqual(bad["payload"]["password"], "")
        self.assertEqual(len(wg.calls), 1)
        expected = {"state_revision": "a" * 64, "source_revision": "b" * 64}
        applied = login_payload() | {"expected": expected, "confirm": True}
        service.dispatch(self.jobs, request("wg-control-apply", applied),
                         authorize=lambda token: authorized.append(token), wg_control=wg)
        self.assertEqual(wg.calls[-1][0], "apply")
        self.assertEqual(wg.calls[-1][1]["expected"], expected)
        self.assertIs(wg.calls[-1][1]["confirm"], True)
        self.assertEqual(applied["password"], "")
        recovered = login_payload() | {"confirm": True}
        service.dispatch(self.jobs, request("wg-control-recover", recovered),
                         authorize=lambda token: authorized.append(token), wg_control=wg)
        self.assertEqual(wg.calls[-1][0], "recover")
        self.assertEqual(len(authorized), 6)

    def test_amnezia_provision_requires_fresh_admin_and_wipes_credentials(self):
        provision = FakeAmneziaProvision()
        authorized = []
        preview = login_payload() | {"listen_port": 49289, "subnet": "10.91.7.0/24",
                                     "route_mode": "full"}
        result = service.dispatch(self.jobs, request("amnezia-provision-preview", preview),
            authorize=lambda token: authorized.append(token), amnezia_provision=provision)
        self.assertEqual(result["action"], "preview")
        self.assertEqual(authorized, [TOKEN])
        self.assertEqual(preview["password"], "")
        self.assertEqual(provision.calls[-1][1]["credential"].password, "")
        for bad in (
                request("amnezia-provision-preview", login_payload() | {"command": "id"}),
                request("amnezia-provision-apply", login_payload() | {
                    "listen_port": 49289, "subnet": "10.91.7.0/24", "route_mode": "full",
                    "expected_state": "a" * 64}),
                request("amnezia-provision-recover", login_payload() | {"route_mode": "split"})):
            with self.assertRaises(service.RequestError):
                service.dispatch(self.jobs, bad, authorize=lambda token: authorized.append(token),
                                 amnezia_provision=provision)
            self.assertEqual(bad["payload"]["password"], "")
        applied = login_payload() | {"listen_port": 49289, "subnet": "10.91.7.0/24",
                                     "route_mode": "full", "expected_state": "a" * 64,
                                     "confirm": True}
        service.dispatch(self.jobs, request("amnezia-provision-apply", applied),
                         authorize=lambda token: authorized.append(token), amnezia_provision=provision)
        self.assertEqual(provision.calls[-1][0], "apply")
        self.assertEqual(provision.calls[-1][1]["expected_state"], "a" * 64)
        self.assertEqual(applied["password"], "")
        recovered = login_payload() | {"confirm": True}
        service.dispatch(self.jobs, request("amnezia-provision-recover", recovered),
                         authorize=lambda token: authorized.append(token), amnezia_provision=provision)
        self.assertEqual(provision.calls[-1][0], "recover")
        self.assertEqual(len(authorized), 6)

    def _socket_reply(self, payload: bytes, *, uid=service._GATEWAY_UID):
        client, server = socket.socketpair()
        worker = threading.Thread(target=service._handle,
            args=(server, self.jobs), kwargs={"peer_uid": uid, "authorize": lambda token: None})
        try:
            if uid == service._GATEWAY_UID:
                worker.start()
            try:
                client.sendall(payload)
            except BrokenPipeError:
                pass  # The service can reject an oversized request while it is still sent.
            try:
                client.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            if worker.ident is None:
                worker.start()
            reply = bytearray()
            while b"\n" not in reply:
                chunk = client.recv(4096)
                if not chunk:
                    break
                reply.extend(chunk)
            return json.loads(reply)
        finally:
            client.close()
            if worker.ident is not None:
                worker.join(timeout=2)
                self.assertFalse(worker.is_alive())

    def test_socket_rejects_other_peer_and_duplicate_json_keys(self):
        good = (json.dumps(request("list", {})) + "\n").encode()
        self.assertEqual(self._socket_reply(good, uid=9999)["error"], "FORBIDDEN")
        self.assertEqual(self._socket_reply(b'{"action":"list","action":"apply",' +
                                            b'"session_token":"' + TOKEN.encode() + b'","payload":{}}\n')["error"],
                         "INVALID_INPUT")
        self.assertEqual(self.jobs.calls, [])

    def test_socket_has_bounded_reply_and_no_exception_text(self):
        self.assertEqual(self._socket_reply((json.dumps(request("list", {})) + "\n").encode()),
                         {"ok": True, "result": []})
        self.assertEqual(self._socket_reply(b"{" + b"x" * (service._MAX_REQUEST + 1) + b"\n")["error"],
                         "INVALID_INPUT")


if __name__ == "__main__":
    unittest.main()
