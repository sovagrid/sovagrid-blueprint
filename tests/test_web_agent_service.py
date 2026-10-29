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


def request(action, payload):
    return {"action": action, "session_token": TOKEN, "payload": payload}


def login_payload():
    return {"host": "target.example", "port": 22, "username": "root",
            "method": "password", "fingerprint": FINGERPRINT,
            "password": "test-only-secret", "private_key": "", "passphrase": ""}


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
