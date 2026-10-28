# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Authenticated Agent idle ACK retained until exact systemd stop proof."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "external_agent_update.py"
spec = importlib.util.spec_from_file_location("sovagrid_external_idle_test", SCRIPT)
assert spec and spec.loader
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


def ack(pid: int, *, epoch: str = "a" * 32, network_checks: int = 0) -> bytes:
    return (json.dumps({
        "protocol": 1, "state": "idle", "pid": pid, "epoch": epoch,
        "jobs_inflight": 0, "file_operations": 0, "terminal_sessions": 0,
        "upload_sessions": 0, "network_checks": network_checks,
        "probe_helpers": 0,
    }, separators=(",", ":")) + "\n").encode()


class IdleProofTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.parent = self.root / "agent-control"
        self.parent.mkdir(mode=0o700)
        self.endpoint = self.parent / "agent.sock"
        self.pid, self.uid, self.gid = 4242, os.getuid(), os.getgid()
        self.mainpid = str(self.pid)
        self.state = "active"
        self.substate = "running"
        self.invocation = "b" * 32
        self.stopped = False
        self.proof = object.__new__(worker.ExternalAgentStopProof)
        self.proof.pid = self.pid
        self.proof.cgroup = "/system.slice/sovagrid-agent.service"
        self.proof.invocation_id = self.invocation
        self.proof.start_ticks = 12345
        self.proof.root = self.root
        self.proof.run = self.systemctl
        self.proof.stopped = lambda: self.stopped
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.endpoint))
        self.endpoint.chmod(0o600)
        self.listener.listen(1)
        self.addCleanup(self.listener.close)
        self.accepted: socket.socket | None = None
        self.accepted_ready = threading.Event()
        self.commands: list[bytes] = []
        self.server_errors: list[BaseException] = []
        self.thread: threading.Thread | None = None
        self.reply = ack(self.pid)
        self.pong = b"PONG 1 " + b"a" * 32 + b"\n"
        self.patchers = [
            mock.patch.object(worker.sys, "platform", "linux"),
            mock.patch.object(worker.os, "geteuid", return_value=0),
            mock.patch.object(worker.pwd, "getpwnam",
                              return_value=SimpleNamespace(pw_uid=self.uid)),
            mock.patch.object(worker.grp, "getgrnam",
                              return_value=SimpleNamespace(gr_gid=self.gid)),
            mock.patch.object(worker, "_proc_start_ticks", return_value=12345),
            mock.patch.object(worker, "_agent_idle_peer",
                              return_value=(self.pid, self.uid, self.gid)),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def systemctl(self, command, **kwargs):
        self.assertEqual(command[:3], ["/usr/bin/systemctl", "show",
                                       "sovagrid-agent.service"])
        self.assertEqual(kwargs["timeout"], 5)
        fields = {
            "Id": "sovagrid-agent.service", "ActiveState": self.state,
            "SubState": self.substate, "MainPID": self.mainpid,
            "ControlGroup": self.proof.cgroup,
            "InvocationID": self.invocation,
            "FragmentPath": worker.AGENT_UNIT_FILE,
            "NeedDaemonReload": "no", "User": "sovagrid", "Group": "sovagrid",
        }
        body = "".join(f"{key}={value}\n" for key, value in fields.items())
        return subprocess.CompletedProcess(command, 0, body.encode(), b"")

    @staticmethod
    def line(connection: socket.socket) -> bytes:
        raw = bytearray()
        while not raw.endswith(b"\n"):
            item = connection.recv(1)
            if not item:
                break
            raw.extend(item)
        return bytes(raw)

    def start_server(self) -> None:
        def serve() -> None:
            try:
                with self.listener.accept()[0] as connection:
                    self.accepted = connection
                    self.accepted_ready.set()
                    connection.settimeout(5)
                    while True:
                        request = self.line(connection)
                        if not request:
                            return
                        self.commands.append(request)
                        if request == b"QUIESCE 1\n":
                            connection.sendall(self.reply)
                        elif request == b"PING 1\n":
                            connection.sendall(self.pong)
                        elif request == b"RELEASE 1\n":
                            connection.sendall(b"RELEASED 1\n")
                            return
            except (OSError, TimeoutError):
                # A simulated systemd stop shuts down the accepted socket.
                return
            except BaseException as exc:
                self.server_errors.append(exc)

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 5)

    def new_guard(self) -> worker.AgentIdleProof:
        return worker.AgentIdleProof(self.proof, socket_path=self.endpoint)

    def stop_agent(self) -> None:
        self.stopped = True
        self.state, self.substate, self.mainpid = "inactive", "dead", "0"
        self.assertTrue(self.accepted_ready.wait(2))
        assert self.accepted is not None
        self.accepted.shutdown(socket.SHUT_RDWR)

    def test_ack_requires_exact_zero_counters_pid_and_unique_fields(self):
        self.assertEqual(worker._agent_idle_ack(ack(self.pid), self.pid), "a" * 32)
        for invalid in (ack(self.pid, network_checks=1), ack(self.pid + 1),
                        ack(self.pid, epoch="z" * 32),
                        ack(self.pid).replace(b'"network_checks":0',
                                              b'"network_checks":0,"network_checks":0')):
            with self.subTest(invalid=invalid[:50]), \
                 self.assertRaisesRegex(worker.Refused, "AGENT_IDLE_PROTOCOL"):
                worker._agent_idle_ack(invalid, self.pid)
        with self.assertRaisesRegex(worker.Refused, "AGENT_IDLE_BUSY"):
            worker._agent_idle_ack(b"BUSY 1\n", self.pid)

    def test_socket_path_rejects_world_writable_endpoint(self):
        self.endpoint.chmod(0o666)
        with self.assertRaisesRegex(worker.Refused, "AGENT_IDLE_PATH"):
            self.new_guard().acquire()

    def test_peer_mismatch_is_rejected_before_quiesce(self):
        self.start_server()
        with mock.patch.object(worker, "_agent_idle_peer",
                               return_value=(self.pid + 1, self.uid, self.gid)):
            with self.assertRaisesRegex(worker.Refused, "AGENT_IDLE_PEER"):
                self.new_guard().acquire()
        self.assertEqual(self.commands, [])

    def test_nonidle_ack_is_rejected_before_heartbeat(self):
        self.reply = ack(self.pid, network_checks=1)
        self.start_server()
        with self.assertRaisesRegex(worker.Refused, "AGENT_IDLE_PROTOCOL"):
            self.new_guard().acquire()
        self.assertEqual(self.commands, [b"QUIESCE 1\n"])

    def test_valid_ack_is_held_then_released_without_stop(self):
        self.start_server()
        with self.new_guard() as guard:
            guard.assert_held()
            self.assertEqual(self.commands[:2], [b"QUIESCE 1\n", b"PING 1\n"])
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())
        self.assertFalse(self.server_errors)
        self.assertEqual(self.commands[-1], b"RELEASE 1\n")

    def test_stopped_requires_exact_proof_and_closed_original_socket(self):
        self.start_server()
        with self.new_guard() as guard:
            guard.begin_stop()
            with self.assertRaisesRegex(worker.Refused, "AGENT_STOP_NOT_PROVEN"):
                guard.confirm_stopped()
            self.stop_agent()
            guard.confirm_stopped()
            self.assertTrue(guard.confirmed)
        self.assertFalse(self.server_errors)

    def test_restart_during_final_socket_check_is_rejected(self):
        self.start_server()
        with self.new_guard() as guard:
            guard.begin_stop()
            self.stop_agent()
            calls = []

            def changed_stop_proof() -> bool:
                calls.append(1)
                return len(calls) == 1

            self.proof.stopped = changed_stop_proof
            with self.assertRaisesRegex(worker.Refused, "AGENT_STOP_NOT_PROVEN"):
                guard.confirm_stopped()
            self.assertEqual(len(calls), 2)

    def test_stop_proof_cannot_accept_live_socket_or_expired_idle_hold(self):
        self.start_server()
        with self.new_guard() as guard:
            guard.begin_stop()
            self.stopped = True
            self.assertTrue(self.accepted_ready.wait(2))
            assert self.accepted is not None
            self.accepted.sendall(b"X")
            with self.assertRaisesRegex(worker.Refused, "AGENT_IDLE_STILL_OPEN"):
                guard.confirm_stopped()
            guard.started -= worker.AGENT_IDLE_MAX_HOLD + 1
            with self.assertRaisesRegex(worker.Refused, "AGENT_IDLE_LOST"):
                guard.confirm_stopped()

    def test_replaced_socket_path_invalidates_live_ack(self):
        self.start_server()
        with self.new_guard() as guard:
            self.endpoint.unlink()
            self.endpoint.symlink_to(self.root / "replacement")
            with self.assertRaisesRegex(worker.Refused, "AGENT_IDLE_PATH"):
                guard.assert_held()

    def test_changed_pid_fails_closed(self):
        self.start_server()
        with self.new_guard() as guard:
            self.mainpid = "5333"
            with self.assertRaisesRegex(worker.Refused, "AGENT_IDLE_IDENTITY"):
                guard.assert_held()

    def test_changed_epoch_fails_closed(self):
        self.start_server()
        self.pong = b"PONG 1 " + b"c" * 32 + b"\n"
        with self.assertRaisesRegex(worker.Refused, "AGENT_IDLE_PROTOCOL"):
            self.new_guard().acquire()

    def test_early_eof_prevents_begin_stop(self):
        self.start_server()
        with self.new_guard() as guard:
            self.assertTrue(self.accepted_ready.wait(2))
            assert self.accepted is not None
            self.accepted.shutdown(socket.SHUT_RDWR)
            with self.assertRaises(worker.Refused):
                guard.begin_stop()

    def test_eof_before_exact_stop_proof_remains_failed(self):
        self.start_server()
        with self.new_guard() as guard:
            guard.begin_stop()
            self.assertTrue(self.accepted_ready.wait(2))
            assert self.accepted is not None
            self.accepted.shutdown(socket.SHUT_RDWR)
            with mock.patch.object(guard._stop, "wait", return_value=False):
                guard._heartbeat()
            self.assertTrue(guard.failed)
            self.stopped = True
            with self.assertRaisesRegex(worker.Refused, "AGENT_IDLE_LOST"):
                guard.confirm_stopped()


if __name__ == "__main__":
    unittest.main()
