# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The automatic updater must authenticate and retain the Agent idle ACK."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "deploy" / "remote_update_worker.py"
spec = importlib.util.spec_from_file_location("sovagrid_update_agent_idle_test", SOURCE)
assert spec and spec.loader
update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update)


def ack(pid: int, *, network_checks: int = 0) -> bytes:
    return (json.dumps({
        "protocol": 1, "state": "idle", "pid": pid, "epoch": "a" * 32,
        "jobs_inflight": 0, "file_operations": 0, "terminal_sessions": 0,
        "upload_sessions": 0, "network_checks": network_checks,
        "probe_helpers": 0,
    }, separators=(",", ":")) + "\n").encode()


class AgentQuiescenceTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.pid, self.uid, self.gid = 4242, os.getuid(), os.getgid()
        patcher = mock.patch.object(update, "ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_ack_requires_every_counter_zero_and_unique_fields(self) -> None:
        self.assertEqual(update._agent_idle_ack(ack(self.pid), self.pid), "a" * 32)
        with self.assertRaisesRegex(update.UpdateFailure, "STATE"):
            update._agent_idle_ack(ack(self.pid, network_checks=1), self.pid)
        with self.assertRaisesRegex(update.UpdateFailure, "STATE"):
            update._agent_idle_ack(ack(self.pid).replace(b'"network_checks":0',
                                                       b'"network_checks":0,"network_checks":0'), self.pid)
        with self.assertRaisesRegex(update.UpdateFailure, "STATE"):
            update._agent_idle_ack(ack(self.pid + 1), self.pid)

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED") and os.name == "posix",
                         "requires Linux peer credentials")
    def test_kernel_peer_credentials_match_connected_process(self) -> None:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with left, right:
            self.assertEqual(update._agent_peercred(left),
                             (os.getpid(), os.getuid(), os.getgid()))

    def test_old_agent_without_socket_defers_automatic_update(self) -> None:
        with mock.patch.object(update.sys, "platform", "linux"), \
             mock.patch.object(update.os, "geteuid", return_value=0), \
             mock.patch.object(update, "_agent_identity", return_value=(self.pid, self.uid, self.gid)):
            with self.assertRaisesRegex(update.UpdateFailure, "BUSY"):
                with update.automatic_agent_quiescence():
                    self.fail("missing Agent socket was admitted")

    def test_verified_socket_holds_until_release(self) -> None:
        parent = self.root / "run/sovagrid-agent-control"
        parent.mkdir(parents=True, mode=0o700)
        endpoint = parent / "agent.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(endpoint))
        endpoint.chmod(0o600)
        listener.listen(1)
        self.addCleanup(listener.close)
        commands = []
        error = []

        def line(connection):
            result = bytearray()
            while not result.endswith(b"\n"):
                item = connection.recv(1)
                if not item:
                    break
                result.extend(item)
            return bytes(result)

        def serve():
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(5)
                    commands.append(line(connection))
                    connection.sendall(ack(self.pid))
                    while True:
                        request = line(connection)
                        if not request:
                            return
                        commands.append(request)
                        if request == b"PING 1\n":
                            connection.sendall(b"PONG 1 " + b"a" * 32 + b"\n")
                        elif request == b"RELEASE 1\n":
                            connection.sendall(b"RELEASED 1\n")
                            return
            except BaseException as exc:
                error.append(exc)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        with mock.patch.object(update.sys, "platform", "linux"), \
             mock.patch.object(update.os, "geteuid", return_value=0), \
             mock.patch.object(update, "_agent_identity", return_value=(self.pid, self.uid, self.gid)), \
             mock.patch.object(update, "_agent_peercred", return_value=(self.pid, self.uid, self.gid)):
            with update.automatic_agent_quiescence() as guard:
                guard.assert_held()
                self.assertEqual(commands[:2], [b"QUIESCE 1\n", b"PING 1\n"])
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertFalse(error)
        self.assertEqual(commands[-1], b"RELEASE 1\n")

    def test_wrong_peer_is_rejected_before_quiesce(self) -> None:
        parent = self.root / "run/sovagrid-agent-control"
        parent.mkdir(parents=True, mode=0o700)
        endpoint = parent / "agent.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(endpoint))
        endpoint.chmod(0o600)
        listener.listen(1)
        self.addCleanup(listener.close)
        with mock.patch.object(update.sys, "platform", "linux"), \
             mock.patch.object(update.os, "geteuid", return_value=0), \
             mock.patch.object(update, "_agent_identity", return_value=(self.pid, self.uid, self.gid)), \
             mock.patch.object(update, "_agent_peercred", return_value=(self.pid + 1, self.uid, self.gid)):
            with self.assertRaisesRegex(update.UpdateFailure, "STATE"):
                with update.automatic_agent_quiescence():
                    self.fail("wrong socket peer was admitted")


if __name__ == "__main__":
    unittest.main()
