# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Mocked fail-closed boundaries of the external Agent apply coordinator."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock


DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
spec = importlib.util.spec_from_file_location("sovagrid_external_apply_test",
                                              DEPLOY / "external_agent_update.py")
assert spec and spec.loader
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)

CURRENT, OLD, ARCHIVE, BASELINE, REVIEW = (character * 64 for character in "abcde")


class ReviewAndBootGateTests(unittest.TestCase):
    def test_review_binds_all_mutable_input(self):
        state = {"identity": {"server_id": "example"}, "source_files": {"a": "b"}}
        changes = [{"path": "/opt/sovagrid-agent/a", "operation": "replace"}]
        expected = planner._review_digest(ARCHIVE, CURRENT, OLD, BASELINE,
                                          state, changes)
        self.assertEqual(len(expected), 64)
        for modified in (
            ("f" * 64, CURRENT, OLD, BASELINE, state, changes),
            (ARCHIVE, "f" * 64, OLD, BASELINE, state, changes),
            (ARCHIVE, CURRENT, "f" * 64, BASELINE, state, changes),
            (ARCHIVE, CURRENT, OLD, "f" * 64, state, changes),
            (ARCHIVE, CURRENT, OLD, BASELINE,
             {**state, "identity": {"server_id": "different"}}, changes),
            (ARCHIVE, CURRENT, OLD, BASELINE, state,
             [{"path": "/opt/sovagrid-agent/b", "operation": "replace"}]),
        ):
            self.assertNotEqual(planner._review_digest(*modified), expected)

    def test_boot_unit_requires_exact_file_and_loaded_dependency(self):
        class FakeUnit:
            contents = (DEPLOY / planner.RECOVERY_UNIT).read_bytes()

            def lstat(self):
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o644,
                                       st_uid=0, st_gid=0, st_nlink=1)

            def read_bytes(self):
                return self.contents

            def __str__(self):
                return "/etc/systemd/system/" + planner.RECOVERY_UNIT

        unit = FakeUnit()
        show = (f"Id={planner.EXTERNAL_AGENT_UNIT}\n"
                f"Requires={planner.RECOVERY_UNIT} network.target\n"
                "Before=\n"
                f"FragmentPath={planner.AGENT_UNIT_FILE}\n"
                "NeedDaemonReload=no\n\n"
                f"Id={planner.RECOVERY_UNIT}\n"
                "Requires=\n"
                f"Before={planner.EXTERNAL_AGENT_UNIT}\n"
                f"FragmentPath={unit}\n"
                "NeedDaemonReload=no\n").encode()
        enabled = SimpleNamespace(returncode=0)
        loaded = SimpleNamespace(returncode=0, stdout=show)
        with mock.patch.object(planner, "RECOVERY_UNIT_FILE", unit), \
             mock.patch.object(planner.subprocess, "run",
                               side_effect=[enabled, loaded]):
            planner._recovery_unit_ready()
        unit.contents = b"[Unit]\nDescription=changed\n"
        with mock.patch.object(planner, "RECOVERY_UNIT_FILE", unit), \
             mock.patch.object(planner.subprocess, "run") as runner, \
             self.assertRaisesRegex(planner.Refused,
                                     "BOOT_RECOVERY_UNAVAILABLE"):
            planner._recovery_unit_ready()
        runner.assert_not_called()

    def test_live_gate_probe_is_not_a_persistent_authorization(self):
        transaction = mock.Mock()
        transaction._load_journal.return_value = {"phase": "trial"}
        transaction.verify_trial_state.return_value = CURRENT
        enrollment = mock.Mock(files=mock.Mock())
        with mock.patch.object(planner.remote, "Enrollment", return_value=enrollment), \
             mock.patch.object(planner.recovery, "Recovery", return_value=transaction), \
             mock.patch.object(planner, "_systemd_trial_guard_loaded", return_value=True), \
             mock.patch.object(planner.recovery, "probe_trial_gate",
                               side_effect=[True, False]) as probe:
            self.assertTrue(planner._live_trial_permit("recover"))
            self.assertFalse(planner._live_trial_permit("recover"))
        self.assertEqual(probe.call_args_list,
                         [mock.call("recover", CURRENT), mock.call("recover", CURRENT)])

    def test_recovery_child_lock_refuses_immediately_behind_supervisor(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "transaction.lock"
            with mock.patch.object(planner.common, "validate_lock", return_value=None):
                first = planner._exclusive_lock(path)
                try:
                    with self.assertRaisesRegex(planner.Refused, "BUSY"):
                        planner._exclusive_lock(path)
                finally:
                    os.close(first)


class PromotionWireTests(unittest.TestCase):
    def server(self, committed):
        return planner.TrialWatchServer(
            CURRENT, group=1001, agent_uid=1001,
            journal_current=lambda: CURRENT,
            lease_active=lambda: True,
            agent_idle_proven=lambda: True,
            agent_peer_allowed=lambda *_args: True,
            committed_current=lambda: committed["value"])

    def test_promotion_ready_and_release_require_ordered_nonce_bound_ack(self):
        committed = {"value": False}
        server = self.server(committed)
        connection = mock.Mock()
        server.active = connection
        lines = [f"HELLO 1 {server.epoch}", "PING 0", "PING 1", "PING 2"]
        index = 0

        def next_line(_connection):
            nonlocal index
            if index == 2:
                server.request_promotion()
            if index == 4:
                lines.append(f"PING 3 READY {server._promotion_nonce}")
            if index == 5:
                committed["value"] = True
                server.request_release()
                lines.append(f"PING 4 READY {server._promotion_nonce}")
                lines.append(f"ACK RELEASE {server._promotion_nonce}")
            result = lines[index]
            index += 1
            return result

        with mock.patch.object(planner, "_watch_peer", return_value=(456, 1001, 1001)), \
             mock.patch.object(planner, "_watch_line", side_effect=next_line), \
             mock.patch.object(server, "_eligible", return_value=True):
            server._handle(connection)
        wire = [call.args[0].decode().strip()
                for call in connection.sendall.call_args_list]
        self.assertEqual(wire[0], f"READY 1 {server.epoch}")
        self.assertEqual(wire[1], "PONG 0")
        self.assertEqual(wire[2], f"PROMOTE 1 {server._promotion_nonce}")
        self.assertEqual(wire[3:5], ["PONG 2", "PONG 3"])
        self.assertEqual(wire[5], f"RELEASE 4 {server._promotion_nonce}")
        self.assertTrue(server.normal_ready.is_set() and server.released.is_set())

    def test_ready_before_promotion_or_wrong_nonce_is_refused(self):
        server = self.server({"value": False})
        connection = mock.Mock()
        with mock.patch.object(planner, "_watch_peer", return_value=(456, 1001, 1001)), \
             mock.patch.object(server, "_eligible", return_value=True), \
             mock.patch.object(planner, "_watch_line",
                               side_effect=[f"HELLO 1 {server.epoch}",
                                            "PING 0 READY " + "f" * 32]), \
             self.assertRaisesRegex(planner.Refused, "TRIAL_WATCH_PROTOCOL"):
            server._handle(connection)
        self.assertFalse(server.normal_ready.is_set())

    def test_release_without_durable_commit_is_refused(self):
        committed = {"value": False}
        server = self.server(committed)
        server.ready.set()
        server.active = object()
        server.last_ping = time.monotonic()
        server.request_promotion()
        server._promotion_sent = True
        server.normal_ready.set()
        with self.assertRaisesRegex(planner.Refused, "TRIAL_RELEASE_NOT_READY"):
            server.request_release()
        committed["value"] = True
        server.request_release()


class FakeTransaction:
    def __init__(self):
        self.journal = None
        self.events = []
        self.trial_sha = None

    def _load_journal(self):
        return self.journal

    def prepare(self, **_kwargs):
        self.events.append("prepare")
        self.journal = {"protocol": 2, "phase": "prepared"}

    def _switch_under_quiescence(self, **_kwargs):
        self.events.append("switch")
        self.journal["phase"] = "switched"
        self.trial_sha = hashlib.sha256(
            planner.remote.encode({**self.journal, "phase": "trial"}) + b"\n").hexdigest()

    def begin_trial(self, **kwargs):
        self.events.append("trial")
        assert all(callback() for callback in kwargs.values())
        self.journal["phase"] = "trial"

    def trial_journal_sha256(self):
        return self.trial_sha

    def commit_trial(self, **kwargs):
        self.events.append("commit")
        assert all(callback() for callback in kwargs.values())
        self.journal["phase"] = "committed"

    def finalize_committed(self):
        self.events.append("finalize")
        self.journal = None

    def recover_pending(self, **kwargs):
        self.events.append("rollback")
        assert kwargs["agent_stopped"]()
        self.journal = None


class FakeLease:
    def __init__(self):
        self.events = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.events.append("release")

    def assert_held(self, *, fresh=False):
        self.events.append("fresh" if fresh else "held")

    def valid(self):
        return True


class FakeIdle:
    def __init__(self):
        self.started = time.monotonic()
        self.failed = False
        self.stopping = False
        self.confirmed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def assert_held(self):
        pass

    def begin_stop(self):
        self.stopping = True

    def confirm_stopped(self):
        self.confirmed = True


class ApplyCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.transaction = FakeTransaction()
        self.lease = FakeLease()
        self.idle = FakeIdle()
        self.stop_proof = SimpleNamespace(pid=123, start_ticks=10,
                                          cgroup="/system.slice/sovagrid-agent.service",
                                          invocation_id="1" * 32,
                                          stopped=lambda: True)
        self.enrollment = mock.Mock(files=mock.Mock())
        self.enrollment.locked.return_value = contextlib.nullcontext()
        self.before = {"sha256": {}}
        self.after = {"sha256": {"sovagrid-agent/sovagrid_agent/trial_gate.py": "1" * 64}}
        self.state = {"identity": {"server_id": "example"}}
        self.baseline = {"files": {}}
        self.commands = []
        self.boot_gate_events = []

    def fixture(self, stack):
        def patched(obj, name, value):
            stack.enter_context(mock.patch.object(obj, name, value))

        patched(planner.os, "geteuid", lambda: 0)
        patched(planner.os, "getegid", lambda: 0)
        patched(planner.sys, "platform", "linux")
        patched(planner, "_normal_activation_ready", lambda: True)
        patched(planner, "preflight", lambda *_: {
            "external_agent_manifest_sha256": OLD, "review_sha256": REVIEW})
        patched(planner, "_exclusive_lock", lambda _path: os.open(os.devnull, os.O_RDONLY))
        patched(planner.update, "inspect", lambda: (CURRENT, {
            "phase": "activated", "external_agent_preserved": True,
            "baseline_sha256": BASELINE}, {}, BASELINE))
        enrollment_factory = mock.Mock(return_value=self.enrollment)
        enrollment_factory.installed_projection = lambda _manifest: {
            "/opt/sovagrid-agent/trial_gate.py": "1" * 64}
        patched(planner.remote, "Enrollment", enrollment_factory)
        patched(planner.recovery, "Recovery", lambda _files: self.transaction)
        patched(planner, "_external_snapshot_locked",
                lambda _enrollment: (CURRENT if "finalize" in self.transaction.events else OLD,
                                     self.before, self.state))
        patched(planner.common, "candidate_source", lambda _sha: (Path("/candidate"), {}))
        patched(planner, "_manifest", lambda _root: (CURRENT, self.after))
        patched(planner, "_candidate_agent_files",
                lambda *_args: {"/opt/sovagrid-agent/trial_gate.py": "1" * 64})
        patched(planner, "_installed_agent_tree", lambda *_args: None)
        patched(planner, "_changes", lambda *_args: [])
        patched(planner, "_review_digest", lambda *_args: REVIEW)
        patched(planner.promotion, "_private_json", lambda _path: self.baseline)
        patched(planner.promotion, "capture_external", lambda: self.baseline)
        patched(planner.update, "_hash_file", lambda _path: BASELINE)
        patched(planner, "_original_hub_compatibility", lambda *_args: None)
        patched(planner, "_recovery_unit_ready", lambda **_kwargs: None)
        patched(planner, "_enable_recovery_unit",
                lambda: self.boot_gate_events.append("enable"))
        patched(planner, "_disable_recovery_unit",
                lambda: self.boot_gate_events.append("disable"))
        patched(planner, "_new_metadata", lambda *_args: ({"old": OLD}, {"new": CURRENT}, {}))
        patched(planner, "ExternalAgentStopProof", lambda: self.stop_proof)
        patched(planner, "OriginalHubLease", lambda *_args: self.lease)
        patched(planner, "AgentIdleProof", lambda _stop: self.idle)
        patched(planner, "_systemctl",
                lambda *args, **_kwargs: self.commands.append(args))
        patched(planner, "_systemd_trial_guard_loaded", lambda: True)
        patched(planner, "_runtime_directory", lambda *_args, **_kwargs: None)
        patched(planner, "_proc_start_ticks", lambda pid: 20 if pid == 456 else None)
        patched(planner, "_agent_fully_stopped", lambda _cgroup: True)
        patched(planner.pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=1001))
        patched(planner.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=1001))
        patched(planner, "_external_snapshot", lambda: (CURRENT, self.after, self.state))
        patched(planner, "_external_unit_properties", lambda: {
            "ActiveState": "active", "SubState": "running", "MainPID": "456"})

        def peer(_pid, _uid, _gid, *, identity, **_kwargs):
            identity.update(pid=456, ticks=20, invocation="2" * 32)
            return True

        patched(planner, "_trial_peer", peer)
        gate = SimpleNamespace(granted={"recover", "start"},
                               thread=SimpleNamespace(is_alive=lambda: True),
                               closed=threading.Event(), close=lambda: None,
                               start=lambda: gate)
        patched(planner.recovery, "TrialGateServer", lambda *_args, **_kwargs: gate)

        def watch_factory(*_args, agent_peer_allowed, **_kwargs):
            agent_peer_allowed(456, 1001, 1001)
            watcher = SimpleNamespace(
                thread=SimpleNamespace(is_alive=lambda: True),
                closed=threading.Event(), close=lambda: None,
                ready=threading.Event(), ping_count=3,
                normal_ready=threading.Event(), released=threading.Event(),
                last_ping=time.monotonic(), active=object())
            watcher.ready.set()
            watcher.normal_ready.set()
            watcher.request_promotion = lambda: "0" * 32
            watcher.request_release = lambda: watcher.released.set()
            watcher.start = lambda: watcher
            self.watcher = watcher
            return watcher

        patched(planner, "TrialWatchServer", watch_factory)

    def test_exact_review_mismatch_prevents_any_mutation(self):
        with mock.patch.object(planner.os, "geteuid", return_value=0), \
             mock.patch.object(planner.os, "getegid", return_value=0), \
             mock.patch.object(planner.sys, "platform", "linux"), \
             mock.patch.object(planner, "_normal_activation_ready", return_value=True), \
             mock.patch.object(planner, "preflight", return_value={
                 "external_agent_manifest_sha256": OLD,
                 "review_sha256": REVIEW}), \
             mock.patch.object(planner, "_exclusive_lock") as lock, \
             self.assertRaisesRegex(planner.Refused, "REVIEW_CHANGED"):
            planner.apply(ARCHIVE, CURRENT, OLD, "f" * 64)
        lock.assert_not_called()

    def test_public_apply_route_and_internal_activation_are_closed(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(planner.main(["apply", ARCHIVE, CURRENT, OLD, REVIEW]), 2)
        with mock.patch.object(planner.os, "geteuid", return_value=0), \
             mock.patch.object(planner.os, "getegid", return_value=0), \
             mock.patch.object(planner.sys, "platform", "linux"), \
             mock.patch.object(planner, "preflight") as preflight, \
             self.assertRaisesRegex(planner.Refused, "NORMAL_ACTIVATION_GATE_MISSING"):
            planner.apply(ARCHIVE, CURRENT, OLD, REVIEW)
        preflight.assert_not_called()

    def test_guarded_success_releases_the_same_normal_agent_after_commit(self):
        with contextlib.ExitStack() as stack:
            self.fixture(stack)
            result = planner.apply(ARCHIVE, CURRENT, OLD, REVIEW)
        self.assertTrue(result["applied"])
        self.assertEqual(self.transaction.events,
                         ["prepare", "switch", "trial", "commit", "finalize"])
        self.assertEqual(self.commands,
                         [("daemon-reload",), ("stop", planner.EXTERNAL_AGENT_UNIT),
                          ("daemon-reload",), ("start", planner.EXTERNAL_AGENT_UNIT),
                          ("daemon-reload",)])
        self.assertIn("release", self.lease.events)
        self.assertEqual(self.boot_gate_events, ["enable", "disable"])

    def test_switch_failure_rolls_back_before_restarting_old_agent(self):
        with contextlib.ExitStack() as stack:
            self.fixture(stack)

            def partial_switch(**_kwargs):
                self.transaction.events.append("switch")
                self.transaction.journal["phase"] = "switched"
                raise planner.Refused("SWITCH_INTERRUPTED")

            self.transaction._switch_under_quiescence = partial_switch
            stack.enter_context(mock.patch.object(planner, "_external_snapshot",
                                            return_value=(OLD, self.before, self.state)))
            with self.assertRaisesRegex(planner.Refused, "SWITCH_INTERRUPTED"):
                planner.apply(ARCHIVE, CURRENT, OLD, REVIEW)
        self.assertEqual(self.transaction.events, ["prepare", "switch", "rollback"])
        self.assertEqual(self.boot_gate_events, ["enable", "disable"])
        self.assertEqual(self.commands[-2:],
                         [("daemon-reload",), ("start", planner.EXTERNAL_AGENT_UNIT)])

    def test_missing_boot_gate_prevents_journal_and_stop(self):
        with contextlib.ExitStack() as stack:
            self.fixture(stack)
            stack.enter_context(mock.patch.object(planner, "_recovery_unit_ready",
                                                side_effect=planner.Refused("BOOT_RECOVERY_UNAVAILABLE")))
            with self.assertRaisesRegex(planner.Refused, "BOOT_RECOVERY_UNAVAILABLE"):
                planner.apply(ARCHIVE, CURRENT, OLD, REVIEW)
        self.assertEqual(self.transaction.events, [])
        self.assertEqual(self.commands, [])
        self.assertEqual(self.boot_gate_events, [])

    def test_failed_read_only_normal_cycle_rolls_back_before_commit(self):
        with contextlib.ExitStack() as stack:
            self.fixture(stack)
            original_watch = planner.TrialWatchServer

            def not_ready(*args, **kwargs):
                watcher = original_watch(*args, **kwargs)
                watcher.normal_ready.clear()
                watcher.normal_ready.wait = lambda _seconds: False
                return watcher

            stack.enter_context(mock.patch.object(planner, "TrialWatchServer", not_ready))
            stack.enter_context(mock.patch.object(planner, "_external_snapshot",
                                            return_value=(OLD, self.before, self.state)))
            with self.assertRaisesRegex(planner.Refused, "NORMAL_READINESS_FAILED"):
                planner.apply(ARCHIVE, CURRENT, OLD, REVIEW)
        self.assertEqual(self.transaction.events,
                         ["prepare", "switch", "trial", "rollback"])


class RecoveryWindowTests(unittest.TestCase):
    def test_boot_recovery_disables_temporary_unit_only_after_journal_clears(self):
        enrollment = mock.Mock(files=mock.Mock())
        enrollment.locked.return_value = contextlib.nullcontext()
        transaction = mock.Mock()
        transaction.recover_pending.side_effect = lambda *, agent_stopped: agent_stopped()
        transaction._load_journal.return_value = None
        with mock.patch.object(planner.os, "geteuid", return_value=0), \
             mock.patch.object(planner, "_live_trial_permit", return_value=False), \
             mock.patch.object(planner, "_exclusive_lock",
                               side_effect=lambda _path: os.open(os.devnull, os.O_RDONLY)), \
             mock.patch.object(planner.remote, "Enrollment", return_value=enrollment), \
             mock.patch.object(planner.recovery, "Recovery", return_value=transaction), \
             mock.patch.object(planner.subprocess, "run",
                               return_value=SimpleNamespace(returncode=1)), \
             mock.patch.object(planner, "_disable_recovery_unit") as disable:
            self.assertEqual(planner.recover_pending(),
                             {"protocol": 1, "recovered": True})
            disable.assert_called_once_with()
            transaction._load_journal.return_value = {"phase": "prepared"}
            with self.assertRaisesRegex(planner.Refused, "RECOVERY_PENDING"):
                planner.recover_pending()
            disable.assert_called_once_with()

    def test_prepared_running_agent_requires_fresh_lease_and_idle_before_stop(self):
        transaction = FakeTransaction()
        transaction.journal = {"phase": "prepared"}
        idle, lease = FakeIdle(), FakeLease()
        calls = []
        with mock.patch.object(planner, "_agent_fully_stopped",
                               side_effect=[False, True, True]), \
             mock.patch.object(planner, "_systemctl",
                               side_effect=lambda *args, **_kwargs: calls.append(args)):
            self.assertEqual(planner._repair_interrupted(transaction, "/system.slice/sovagrid-agent.service",
                                                          idle=idle, lease=lease), "old")
        self.assertTrue(idle.stopping)
        self.assertIn("fresh", lease.events)
        self.assertEqual(calls, [("daemon-reload",),
                                 ("stop", planner.EXTERNAL_AGENT_UNIT),
                                 ("daemon-reload",)])
        self.assertEqual(transaction.events, ["rollback"])

    def test_lost_lease_leaves_prepared_journal_and_old_agent_running(self):
        transaction = FakeTransaction()
        transaction.journal = {"phase": "prepared"}
        idle = FakeIdle()
        lease = FakeLease()
        lease.assert_held = mock.Mock(side_effect=planner.Refused("LEASE_LOST"))
        with mock.patch.object(planner, "_agent_fully_stopped", return_value=False), \
             mock.patch.object(planner, "_systemctl") as systemctl, \
             self.assertRaisesRegex(planner.Refused, "LEASE_LOST"):
            planner._repair_interrupted(transaction, "/system.slice/sovagrid-agent.service",
                                        idle=idle, lease=lease)
        self.assertEqual(transaction.journal["phase"], "prepared")
        systemctl.assert_called_once_with("daemon-reload")


if __name__ == "__main__":
    unittest.main()
