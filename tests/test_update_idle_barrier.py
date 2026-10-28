# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""A real SQLite writer must not cross the automatic update's final idle read."""

from __future__ import annotations

import contextlib
import importlib.util
import os
from pathlib import Path
import select
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "deploy" / "remote_update_worker.py"
spec = importlib.util.spec_from_file_location("sovagrid_idle_barrier_test", SOURCE)
assert spec and spec.loader
update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update)


class IdleBarrierTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        db_path = root / "var/lib/sovagrid/hub/hub.sqlite"
        db_path.parent.mkdir(parents=True)
        with contextlib.closing(sqlite3.connect(db_path)) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE sessions (expires_at INTEGER NOT NULL)")
            db.execute("CREATE TABLE jobs (state TEXT NOT NULL)")
            db.execute("CREATE TABLE pending_commands (expires_at INTEGER NOT NULL)")
            db.commit()
        self.db_path = db_path
        patcher = mock.patch.object(update, "ROOT", root)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name, value in (("HUB_UID", os.getuid()), ("HUB_GID", os.getgid())):
            patcher = mock.patch.object(update, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def writer(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=0, isolation_level=None)

    @staticmethod
    @contextlib.contextmanager
    def fake_agent_gate():
        class Guard:
            def assert_held(self):
                pass

            def begin_stop(self):
                pass

            def confirm_stopped(self):
                pass

        yield Guard()

    def test_existing_writer_defers_without_taking_over_database(self) -> None:
        with contextlib.closing(self.writer()) as writer:
            writer.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(update.UpdateFailure, "BUSY"):
                with update.automatic_idle_barrier():
                    self.fail("barrier entered during an active write")
            writer.rollback()
        with update.automatic_idle_barrier():
            pass

    def test_barrier_blocks_new_login_until_hub_stop_point(self) -> None:
        with update.automatic_idle_barrier():
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(self.db_path) + suffix)
                self.assertEqual((sidecar.stat().st_uid, sidecar.stat().st_gid),
                                 (os.getuid(), os.getgid()))
            with contextlib.closing(self.writer()) as login:
                with self.assertRaises(sqlite3.OperationalError):
                    login.execute("BEGIN IMMEDIATE")
                self.assertEqual(login.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
        with contextlib.closing(self.writer()) as login:
            login.execute("BEGIN IMMEDIATE")
            login.execute("INSERT INTO sessions (expires_at) VALUES (9999999999)")
            login.commit()
        with self.assertRaisesRegex(update.UpdateFailure, "BUSY"):
            with update.automatic_idle_barrier():
                self.fail("a newly admitted session was ignored")

    def test_failed_stop_releases_reservation_for_rollback(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "stop failed"):
            with update.automatic_idle_barrier():
                raise RuntimeError("stop failed")
        with contextlib.closing(self.writer()) as writer:
            writer.execute("BEGIN IMMEDIATE")
            writer.execute("INSERT INTO jobs (state) VALUES ('succeeded')")
            writer.commit()

    def test_holder_death_aborts_before_snapshot_and_releases_writer(self) -> None:
        with update.automatic_idle_barrier() as holder:
            os.kill(holder.pid, signal.SIGKILL)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    holder.assert_held()
                except update.UpdateFailure as exc:
                    self.assertEqual(str(exc), "STATE")
                    break
                time.sleep(0.01)
            else:
                self.fail("dead child was not detected")
        with contextlib.closing(self.writer()) as writer:
            writer.execute("BEGIN IMMEDIATE")
            writer.rollback()

    def test_parent_death_releases_writer_through_pipe_eof(self) -> None:
        program = "\n".join((
            "import importlib.util, os, pathlib",
            f"p = pathlib.Path({str(SOURCE)!r})",
            "s = importlib.util.spec_from_file_location('idle_worker_child', p)",
            "m = importlib.util.module_from_spec(s); s.loader.exec_module(m)",
            f"m.ROOT = pathlib.Path({str(self.db_path.parents[4])!r})",
            "m.HUB_UID = os.getuid(); m.HUB_GID = os.getgid()",
            "with m.automatic_idle_barrier():",
            "    print('READY', flush=True)",
            "    os.read(0, 1)",
        ))
        parent = subprocess.Popen([sys.executable, "-c", program], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertTrue(select.select([parent.stdout], [], [], 5)[0],
                            "barrier parent did not report readiness")
            self.assertEqual(parent.stdout.readline().strip(), "READY")
            parent.kill()
            parent.wait(timeout=5)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    with contextlib.closing(self.writer()) as writer:
                        writer.execute("BEGIN IMMEDIATE")
                        writer.rollback()
                    break
                except sqlite3.OperationalError:
                    time.sleep(0.02)
            else:
                self.fail("orphaned holder kept the DB writer lock")
        finally:
            if parent.poll() is None:
                parent.kill()
                parent.wait(timeout=5)
            parent.stdin.close()
            parent.stdout.close()
            parent.stderr.close()

    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                         "requires a Linux root fixture to test the real Hub UID")
    def test_root_holder_creates_hub_owned_wal_files(self) -> None:
        # run.sh makes the parent root-only and the Hub leaf/DB UID 10001.
        # This catches accidentally opening SQLite as root in the updater.
        self.db_path.parents[1].chmod(0o700)
        os.chown(self.db_path.parent, 10001, 10001)
        os.chown(self.db_path, 10001, 10001)
        self.db_path.parent.chmod(0o700)
        self.db_path.chmod(0o600)
        with mock.patch.object(update, "HUB_UID", 10001), \
             mock.patch.object(update, "HUB_GID", 10001):
            with update.automatic_idle_barrier():
                for suffix in ("-wal", "-shm"):
                    sidecar = Path(str(self.db_path) + suffix)
                    self.assertEqual((sidecar.stat().st_uid, sidecar.stat().st_gid),
                                     (10001, 10001))

    def test_auto_apply_releases_barrier_before_preparing_rollback(self) -> None:
        root = self.db_path.parents[4]
        source = root / "opt/sovagrid-src"
        candidates = root / "opt/sovagrid-candidates"
        staged = candidates / "staged"
        source.mkdir(parents=True)
        staged.mkdir(parents=True, mode=0o700)
        candidate_hash, old_hash = "a" * 64, "b" * 64
        rollback_wrote = []

        def command(argv, **_kwargs):
            if argv[:2] == ["docker", "compose"] and "stop" in argv:
                raise update.UpdateFailure("compose stop failed")
            return 0

        def restore(_folder, _state):
            # The preparing phase never copies the Hub database. Its rollback
            # must still be able to write after a failed Compose stop.
            with contextlib.closing(self.writer()) as writer:
                writer.execute("BEGIN IMMEDIATE")
                writer.execute("INSERT INTO jobs (state) VALUES ('succeeded')")
                writer.commit()
            rollback_wrote.append(True)
            return True

        with mock.patch.object(update, "private_candidate_root"), \
             mock.patch.object(update, "validate_lock"), \
             mock.patch.object(update, "automatic_agent_quiescence", self.fake_agent_gate), \
             mock.patch.object(update, "public_web_lock", side_effect=contextlib.nullcontext), \
             mock.patch.object(update, "service_setup_lock", side_effect=contextlib.nullcontext), \
             mock.patch.object(update, "managed_vpn_locks", side_effect=contextlib.nullcontext), \
             mock.patch.object(update, "inspect_state", return_value=(source, old_hash, {"hub": "old"}, [], ())), \
             mock.patch.object(update, "candidate_source", return_value=(staged, {"hub": "new"})), \
             mock.patch.object(update, "candidate_features_compatible"), \
             mock.patch.object(update, "safe_snapshot_item", return_value=0), \
             mock.patch.object(update, "gateway_prior_state", return_value={}), \
             mock.patch.object(update, "compose_services", return_value=("hub",)), \
             mock.patch.object(update, "compose_args", return_value=(["docker", "compose"], {})), \
             mock.patch.object(update, "state_write"), \
             mock.patch.object(update, "command", side_effect=command), \
             mock.patch.object(update, "restore", side_effect=restore), \
             mock.patch.object(update, "finalize_rollback"), \
             mock.patch.object(update.subprocess, "run",
                               return_value=types.SimpleNamespace(stdout="sha256:" + candidate_hash + "\n")):
            with self.assertRaisesRegex(update.UpdateFailure, "rolled back"):
                update.apply(candidate_hash, old_hash, automatic=True)
        self.assertEqual(rollback_wrote, [True])

    def test_auto_apply_releases_barrier_immediately_after_hub_stops(self) -> None:
        root = self.db_path.parents[4]
        source = root / "opt/sovagrid-src"
        candidates = root / "opt/sovagrid-candidates"
        staged = candidates / "staged"
        source.mkdir(parents=True)
        staged.mkdir(parents=True, mode=0o700)
        candidate_hash, old_hash = "a" * 64, "b" * 64
        events = []
        real_barrier = update.automatic_idle_barrier

        @contextlib.contextmanager
        def agent_gate():
            events.append("agent_enter")

            class Guard:
                def assert_held(self):
                    events.append("agent_verified")

                def begin_stop(self):
                    events.append("agent_stop_begin")

                def confirm_stopped(self):
                    events.append("agent_stop_confirmed")

            try:
                yield Guard()
            finally:
                events.append("agent_exit")

        @contextlib.contextmanager
        def writer_barrier():
            events.append("writer_enter")
            with real_barrier() as holder:
                try:
                    yield holder
                finally:
                    events.append("writer_exit")

        def command(argv, **_kwargs):
            if argv[:2] == ["docker", "compose"] and argv[-4:] == ["stop", "--timeout", "30", "hub"]:
                events.append("hub_stopped")
            if argv == ["systemctl", "stop", update.AGENT_UNIT]:
                with contextlib.closing(self.writer()) as writer:
                    writer.execute("BEGIN IMMEDIATE")
                    writer.rollback()
                events.append("agent_stopped_with_writer_released")
            elif argv[:2] == ["systemctl", "stop"]:
                events.append("other_stop")
                raise update.UpdateFailure("systemd stop failed")
            return 0

        def docker(argv, **_kwargs):
            if argv[:3] == ["docker", "image", "inspect"]:
                return types.SimpleNamespace(stdout="sha256:" + candidate_hash + "\n")
            if argv[:2] == ["docker", "ps"]:
                return types.SimpleNamespace(stdout="")
            self.fail(f"Unexpected Docker command: {argv}")

        with mock.patch.object(update, "private_candidate_root"), \
             mock.patch.object(update, "validate_lock"), \
             mock.patch.object(update, "automatic_agent_quiescence", agent_gate), \
             mock.patch.object(update, "automatic_idle_barrier", writer_barrier), \
             mock.patch.object(update, "public_web_lock", side_effect=contextlib.nullcontext), \
             mock.patch.object(update, "service_setup_lock", side_effect=contextlib.nullcontext), \
             mock.patch.object(update, "managed_vpn_locks", side_effect=contextlib.nullcontext), \
             mock.patch.object(update, "inspect_state", return_value=(source, old_hash, {"hub": "old"}, [], ())), \
             mock.patch.object(update, "candidate_source", return_value=(staged, {"hub": "new"})), \
             mock.patch.object(update, "candidate_features_compatible"), \
             mock.patch.object(update, "safe_snapshot_item", return_value=0), \
             mock.patch.object(update, "gateway_prior_state", return_value={}), \
             mock.patch.object(update, "compose_services", return_value=("hub",)), \
             mock.patch.object(update, "compose_args", return_value=(["docker", "compose"], {})), \
             mock.patch.object(update, "state_write"), \
             mock.patch.object(update, "command", side_effect=command), \
             mock.patch.object(update, "restore", return_value=True), \
             mock.patch.object(update, "finalize_rollback"), \
             mock.patch.object(update.subprocess, "run", side_effect=docker):
            with self.assertRaisesRegex(update.UpdateFailure, "rolled back"):
                update.apply(candidate_hash, old_hash, automatic=True)
        self.assertEqual(events, ["agent_enter", "writer_enter", "hub_stopped",
                                  "agent_verified", "writer_exit",
                                  "agent_stop_begin", "agent_stopped_with_writer_released",
                                  "agent_stop_confirmed", "agent_exit", "other_stop"])


if __name__ == "__main__":
    unittest.main()
