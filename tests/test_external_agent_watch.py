# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Live-socket trial boundary tests; no production apply path is enabled."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest
from unittest import mock


DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
spec = importlib.util.spec_from_file_location("sovagrid_external_watch_test",
                                              DEPLOY / "external_agent_update.py")
assert spec and spec.loader
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)


def line(connection: socket.socket) -> str:
    raw = bytearray()
    connection.settimeout(2)
    while True:
        value = connection.recv(1)
        if value == b"\n":
            return raw.decode("ascii")
        if not value:
            return ""
        raw.extend(value)


class TrialWatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "trial"
        self.directory.mkdir(mode=0o710)
        self.directory.chmod(0o710)
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.flags = {"journal": "a" * 64, "lease": True, "idle": True,
                      "peer": True}
        self.peer_patch = mock.patch.object(planner, "_watch_peer",
                                            return_value=(os.getpid(), self.uid, self.gid))
        self.peer_patch.start()
        self.addCleanup(self.peer_patch.stop)

    def server(self) -> planner.TrialWatchServer:
        server = planner.TrialWatchServer(
            "a" * 64, directory=self.directory, owner=self.uid,
            group=self.gid, agent_uid=self.uid,
            journal_current=lambda: self.flags["journal"],
            lease_active=lambda: self.flags["lease"],
            agent_idle_proven=lambda: self.flags["idle"],
            agent_peer_allowed=lambda _pid, _uid, _gid: self.flags["peer"])
        server.start()
        self.addCleanup(server.close)
        return server

    def connect(self, server: planner.TrialWatchServer) -> socket.socket:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.connect(str(server.socket_path))
        self.addCleanup(connection.close)
        return connection

    def test_trial_requires_live_handshake_and_renewed_evidence(self) -> None:
        server = self.server()
        self.assertEqual(server.epoch_path.read_text(),
                         f"SOVAGRID_EXTERNAL_TRIAL_EPOCH={server.epoch}\n")
        self.assertEqual(stat.S_IMODE(server.epoch_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(server.socket_path.stat().st_mode), 0o660)
        client = self.connect(server)
        client.sendall(f"HELLO 1 {server.epoch}\n".encode())
        self.assertEqual(line(client), f"READY 1 {server.epoch}")
        client.sendall(b"PING 0\n")
        self.assertEqual(line(client), "PONG 0")
        self.flags["lease"] = False
        client.sendall(b"PING 1\n")
        self.assertEqual(line(client), "")
        self.flags["lease"] = True
        self.assertTrue(server.closed.is_set())
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as retry:
            with self.assertRaises(OSError):
                retry.connect(str(server.socket_path))

    def test_changed_journal_or_idle_ack_denies_next_ping(self) -> None:
        for changed, value in (("journal", "b" * 64), ("idle", False),
                               ("peer", False)):
            with self.subTest(changed=changed):
                self.flags[changed] = ("a" * 64 if changed == "journal" else True)
                server = self.server()
                client = self.connect(server)
                client.sendall(f"HELLO 1 {server.epoch}\nPING 0\n".encode())
                self.assertEqual(line(client), f"READY 1 {server.epoch}")
                self.assertEqual(line(client), "PONG 0")
                self.flags[changed] = value
                client.sendall(b"PING 1\n")
                self.assertEqual(line(client), "")
                client.close()
                server.close()
                self.flags[changed] = ("a" * 64 if changed == "journal" else True)

    def test_wrong_epoch_and_replayed_ping_never_authorize(self) -> None:
        server = self.server()
        wrong = self.connect(server)
        wrong.sendall(b"HELLO 1 00000000000000000000000000000000\n")
        self.assertEqual(line(wrong), "")
        good = self.connect(server)
        good.sendall(f"HELLO 1 {server.epoch}\nPING 0\nPING 0\n".encode())
        self.assertEqual(line(good), f"READY 1 {server.epoch}")
        self.assertEqual(line(good), "PONG 0")
        self.assertEqual(line(good), "")

    def test_dead_supervisor_fails_before_agent_can_connect(self) -> None:
        server = self.server()
        server.close()
        self.assertFalse(server.socket_path.exists())
        self.assertFalse(server.epoch_path.exists())
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            with self.assertRaises(OSError):
                client.connect(str(server.socket_path))

    def test_untrusted_socket_path_fails_closed(self) -> None:
        target = self.directory / "fake"
        target.write_text("not a socket")
        (self.directory / "gate.sock").symlink_to(target)
        server = planner.TrialWatchServer(
            "a" * 64, directory=self.directory, owner=self.uid,
            group=self.gid, agent_uid=self.uid,
            journal_current=lambda: "a" * 64,
            lease_active=lambda: True,
            agent_idle_proven=lambda: True,
            agent_peer_allowed=lambda _pid, _uid, _gid: True)
        with self.assertRaisesRegex(planner.Refused, "TRIAL_WATCH_PATH"):
            server.start()


if __name__ == "__main__":
    unittest.main()
