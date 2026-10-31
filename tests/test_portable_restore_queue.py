# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Restored commands must become inert before activation; undo proves bytes."""

from __future__ import annotations

from contextlib import closing, contextmanager
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from deploy import host_restore as restore
from deploy import portable_restore_apply as core
from deploy import portable_restore_queue as queue


class PowerLoss(BaseException):
    pass


class QueueTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.hub = self.root / "var/lib/sovagrid/hub"
        self.hub.mkdir(parents=True, mode=0o700)
        self.db = self.hub / "hub.sqlite"
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE jobs(id TEXT PRIMARY KEY, source TEXT, session_token_hash TEXT,
                    control_kind TEXT, state TEXT, command TEXT, created_at INTEGER,
                    completed_at INTEGER, delivered_at INTEGER, output TEXT);
                CREATE TABLE sessions(token_hash TEXT PRIMARY KEY, expires_at INTEGER);
                CREATE TABLE pending_commands(code_hash TEXT PRIMARY KEY, command TEXT);
                CREATE TABLE audit_events(id INTEGER PRIMARY KEY, at INTEGER, actor TEXT,
                    action TEXT, server_id TEXT, subject_id TEXT, details TEXT);
                INSERT INTO sessions VALUES ('still-valid-session', 9999999999);
                INSERT INTO jobs VALUES ('arbitrary', 'web', 'still-valid-session', 'generic',
                    'queued', 'touch /tmp/test-only-stale-command', 1700000000, NULL, NULL, NULL);
                INSERT INTO jobs VALUES ('vpn', 'web', 'still-valid-session', 'vpn',
                    'queued', 'test-only-vpn-command', 1700000000, NULL, NULL, NULL);
                INSERT INTO jobs VALUES ('delivered', 'web', 'still-valid-session', 'generic',
                    'delivered', '', 1700000000, NULL, 1700000001, NULL);
                INSERT INTO jobs VALUES ('completed', 'telegram', NULL, 'generic',
                    'completed', '', 1700000000, 1700000002, 1700000001, 'old history');
                INSERT INTO pending_commands VALUES ('confirmation', 'test-only-pending-secret');
                INSERT INTO audit_events VALUES (1, 1700000000, 'old-actor', 'old-action',
                    'old-server', 'old-subject', '{"retained":true}');
            """)
            self.assertEqual(db.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        self.db.chmod(0o600)
        self.step = {"kind": "queue", "resource": queue.DATABASE, "desired": dict(queue.POLICY)}
        self.identity = "a" * 32
        patches = [patch.object(restore.backup, "ROOT", self.root),
                   patch.object(restore.backup, "ROOT_UID", os.getuid()),
                   patch.object(restore.backup, "ROOT_GID", os.getgid()),
                   patch.object(queue, "HUB_UID", os.getuid()),
                   patch.object(queue, "HUB_GID", os.getgid())]
        # Constructor observes the fixture identities (production defaults remain fixed).
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        self.driver = queue.Queue(restore, core, {"id": self.identity})
        if not sys.platform.startswith("linux"):
            item = patch.object(core, "_rename_noreplace", self.rename)
            item.start()
            self.addCleanup(item.stop)
            item = patch.object(self.driver, "_move", self.move)
            item.start()
            self.addCleanup(item.stop)

    @staticmethod
    def move(source, target, name):
        try:
            os.stat(name, dir_fd=target, follow_symlinks=False)
        except FileNotFoundError:
            os.rename(name, name, src_dir_fd=source, dst_dir_fd=target)
        else:
            raise core.Refused("RESTORE_QUEUE_CHANGED")

    @staticmethod
    def rename(parent, source, target):
        try:
            os.stat(target, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            os.rename(source, target, src_dir_fd=parent, dst_dir_fd=parent)
        else:
            raise core.Refused("RESTORE_TARGET_EXISTS")

    @contextmanager
    def connection(self):
        with closing(sqlite3.connect(self.db)) as database:
            with database:
                yield database

    def work(self, proof):
        return self.root / "var/lib" / self.driver._name(proof)

    def apply(self):
        proof = self.driver.prepare(self.step)
        self.driver.execute(self.step, proof)
        self.driver.verify(self.step, proof)
        return proof

    def rows(self):
        with self.connection() as db:
            return list(db.execute("SELECT id,state,command,completed_at,delivered_at,output FROM jobs ORDER BY id"))

    def test_quarantines_arbitrary_and_vpn_jobs_with_live_session_and_preserves_history(self):
        before = self.rows()
        proof = self.apply()
        rows = {row[0]: row for row in self.rows()}
        for name in ('arbitrary', 'vpn'):
            self.assertEqual(rows[name][1:4], ('cancelled', '', proof['at']))
        old = {row[0]: row for row in before}
        self.assertEqual(rows['completed'], old['completed'])
        self.assertEqual(rows['delivered'], old['delivered'])
        with self.connection() as db:
            self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pending_commands').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT expires_at FROM sessions').fetchone()[0], 9999999999)
            audit = list(db.execute('SELECT actor,action,server_id,subject_id,details FROM audit_events ORDER BY id'))
        self.assertEqual(audit[0], ('old-actor', 'old-action', 'old-server', 'old-subject', '{"retained":true}'))
        self.assertEqual(audit[1][:4], ('system', 'portable_restore_queue_quarantined', None, None))
        self.assertEqual(json.loads(audit[1][4]), {'queued_jobs_cancelled': 2, 'pending_commands_removed': 1})
        receipt = (self.work(proof) / 'result.json').read_bytes()
        self.assertEqual(json.loads(receipt)["journal_mode"], "wal")
        for secret in (b'test-only-stale-command', b'test-only-vpn-command', b'test-only-pending-secret', b'still-valid-session'):
            self.assertNotIn(secret, receipt)
        self.assertEqual(stat.S_IMODE(self.db.stat().st_mode), 0o600)
        self.assertEqual((self.db.stat().st_uid, self.db.stat().st_gid), (os.getuid(), os.getgid()))
        self.assertFalse(self.db.with_name('hub.sqlite-wal').exists())
        self.assertFalse(self.db.with_name('hub.sqlite-shm').exists())

    def test_undo_restores_exact_original_inode_and_bytes_and_is_idempotent(self):
        before, inode = self.db.read_bytes(), self.db.stat().st_ino
        proof = self.apply()
        self.assertNotEqual(self.db.stat().st_ino, inode)
        self.driver.undo(self.step, proof)
        self.driver.undo(self.step, proof)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(self.db.stat().st_ino, inode)
        self.assertFalse(self.work(proof).exists())

    def test_delete_journal_mode_remains_delete_after_quarantine(self):
        with self.connection() as db:
            self.assertEqual(db.execute('PRAGMA journal_mode=DELETE').fetchone()[0], 'delete')
        before, inode = self.db.read_bytes(), self.db.stat().st_ino
        proof = self.apply()
        with self.connection() as db:
            self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0], 'delete')
        self.assertEqual(json.loads((self.work(proof) / 'result.json').read_bytes())['journal_mode'], 'delete')
        self.driver.verify(self.step, proof)
        self.driver.undo(self.step, proof)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(self.db.stat().st_ino, inode)

    def test_changed_runtime_db_is_preserved_and_undo_refuses(self):
        proof = self.apply()
        with self.connection() as db:
            db.execute("INSERT INTO jobs VALUES ('new-job','web','still-valid-session','generic','queued','new authorized work',1,NULL,NULL,NULL)")
        before = self.db.read_bytes()
        with self.assertRaisesRegex(core.Refused, 'RESTORE_QUEUE_CHANGED'):
            self.driver.undo(self.step, proof)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertTrue((self.work(proof) / 'original/hub.sqlite').exists())

    def test_equal_byte_replacement_inode_is_not_adopted(self):
        proof = self.apply()
        replacement = self.hub / 'replacement'
        shutil.copyfile(self.db, replacement)
        replacement.chmod(0o600)
        replacement.replace(self.db)
        with self.assertRaisesRegex(core.Refused, 'RESTORE_QUEUE_CHANGED'):
            self.driver.undo(self.step, proof)
        self.assertTrue(self.db.exists())

    def test_tampered_retained_original_refuses_before_deleting_output(self):
        proof = self.apply()
        original = self.work(proof) / 'original/hub.sqlite'
        with original.open('ab') as stream:
            stream.write(b'tamper')
        before = self.db.read_bytes()
        with self.assertRaisesRegex(core.Refused, 'RESTORE_QUEUE_CHANGED'):
            self.driver.undo(self.step, proof)
        self.assertEqual(self.db.read_bytes(), before)
        with self.assertRaisesRegex(core.Refused, 'RESTORE_QUEUE_CHANGED'):
            self.driver.cleanup_commit(self.step, proof)
        self.assertTrue(original.exists())

    def test_wal_only_committed_rows_are_quarantined_and_original_wal_is_restored(self):
        source = self.root / 'source.sqlite'
        shutil.copyfile(self.db, source)
        connection = sqlite3.connect(source)
        self.addCleanup(connection.close)
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('PRAGMA wal_autocheckpoint=0')
        connection.execute("INSERT INTO jobs VALUES ('wal-only','web','still-valid-session','vpn','queued','wal-only-secret',1,NULL,NULL,NULL)")
        connection.commit()
        # Copy a consistent cold archive with a committed, nonempty WAL while
        # its original writer remains open (closing it would checkpoint).
        for suffix in ('', '-wal', '-shm'):
            shutil.copyfile(Path(str(source) + suffix), Path(str(self.db) + suffix))
            Path(str(self.db) + suffix).chmod(0o600)
        original = {name: (self.hub / name).read_bytes() for name in queue.FILES}
        inodes = {name: (self.hub / name).stat().st_ino for name in queue.FILES}
        proof = self.apply()
        rows = {row[0]: row for row in self.rows()}
        self.assertEqual(rows['wal-only'][1:4], ('cancelled', '', proof['at']))
        with self.connection() as db:
            self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
        self.driver.verify(self.step, proof)
        self.driver.undo(self.step, proof)
        for name in queue.FILES:
            self.assertEqual((self.hub / name).read_bytes(), original[name])
            self.assertEqual((self.hub / name).stat().st_ino, inodes[name])

    def test_crash_after_sqlite_commit_before_result_receipt_fails_closed(self):
        proof = self.driver.prepare(self.step)
        before, inode = self.db.read_bytes(), self.db.stat().st_ino
        quarantine = self.driver._quarantine
        def crash(derived, at):
            quarantine(derived, at)
            raise PowerLoss()
        with patch.object(self.driver, '_quarantine', side_effect=crash):
            with self.assertRaises(PowerLoss):
                self.driver.execute(self.step, proof)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(self.db.stat().st_ino, inode)
        unknown = self.work(proof) / 'derived/hub.sqlite'
        derived_bytes = unknown.read_bytes()
        with closing(sqlite3.connect(unknown)) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        with self.assertRaisesRegex(core.Refused, 'RESTORE_QUEUE_PROOF_INCOMPLETE'):
            self.driver.undo(self.step, proof)
        self.assertEqual(unknown.read_bytes(), derived_bytes)
        self.assertFalse((self.work(proof) / 'result.json').exists())

    def test_every_original_publication_prefix_is_reversible(self):
        for crash_after in (1, 2):
            with self.subTest(crash_after=crash_after):
                proof = self.driver.prepare(self.step)
                before, inode = self.db.read_bytes(), self.db.stat().st_ino
                move, moves = self.driver._move, [0]
                def crash(source, target, name):
                    result = move(source, target, name)
                    if name == 'hub.sqlite':
                        moves[0] += 1
                        if moves[0] == crash_after:
                            raise PowerLoss()
                    return result
                with patch.object(self.driver, '_move', side_effect=crash):
                    with self.assertRaises(PowerLoss):
                        self.driver.execute(self.step, proof)
                self.driver.undo(self.step, proof)
                self.assertEqual(self.db.read_bytes(), before)
                self.assertEqual(self.db.stat().st_ino, inode)

    def test_unexpected_live_wal_is_preserved(self):
        proof = self.apply()
        wal = self.hub / 'hub.sqlite-wal'
        wal.write_bytes(b'new runtime bytes')
        wal.chmod(0o600)
        with self.assertRaisesRegex(core.Refused, 'RESTORE_QUEUE_CHANGED'):
            self.driver.undo(self.step, proof)
        self.assertEqual(wal.read_bytes(), b'new runtime bytes')

    def test_commit_cleanup_removes_retained_secrets_but_preserves_new_runtime_rows(self):
        proof = self.apply()
        with self.connection() as db:
            db.execute("UPDATE jobs SET output='new runtime result' WHERE id='completed'")
        before = self.db.read_bytes()
        self.driver.cleanup_commit(self.step, proof)
        self.driver.cleanup_commit(self.step, proof)
        self.assertFalse(self.work(proof).exists())
        self.assertEqual(self.db.read_bytes(), before)

    def test_inspection_is_read_only_and_source_mutation_before_execution_is_refused(self):
        before = self.db.read_bytes()
        proof = self.driver.prepare(self.step)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertFalse(self.work(proof).exists())
        with self.db.open('ab') as stream:
            stream.write(b'changed')
        with self.assertRaisesRegex(core.Refused, 'RESTORE_QUEUE_CHANGED'):
            self.driver.execute(self.step, proof)
        self.assertFalse(self.work(proof).exists())

    def test_changed_runtime_data_requires_recovery_and_retains_installation_fence(self):
        stage = self.root / 'stage'
        stage.mkdir(mode=0o700)
        descriptor = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        journal = core.Journal(descriptor, self.identity, uid=os.getuid(), gid=os.getgid())
        fence = core.Fence(self.root, uid=os.getuid(), gid=os.getgid())
        def health(_value):
            with self.connection() as db:
                db.execute("UPDATE jobs SET output='accepted runtime data' WHERE id='completed'")
            raise core.Refused('RESTORE_HEALTH_FAILED')
        driver = SimpleNamespace(prepare=self.driver.prepare, execute=self.driver.execute,
            verify=self.driver.verify, undo=self.driver.undo, health=health)
        result = core.run(journal, driver, {key: 'a' * 64 for key in core.BINDINGS},
                          [self.step], fence=fence)
        self.assertEqual(result['phase'], 'recovery_required')
        self.assertTrue((self.root / str(core.FENCE).lstrip('/')).exists())
        with self.connection() as db:
            self.assertEqual(db.execute("SELECT output FROM jobs WHERE id='completed'").fetchone()[0],
                             'accepted runtime data')

    def test_unsupported_schema_or_trigger_cannot_activate(self):
        with self.connection() as db:
            db.execute("CREATE TRIGGER tamper AFTER UPDATE ON jobs BEGIN UPDATE jobs SET command='leaked-secret' WHERE id=NEW.id; END")
        proof = self.driver.prepare(self.step)
        with self.assertRaisesRegex(core.Refused, 'RESTORE_QUEUE_QUARANTINE_FAILED'):
            self.driver.execute(self.step, proof)
        self.assertFalse((self.work(proof) / 'result.json').exists())
        self.assertIn(b'test-only-stale-command', self.db.read_bytes())


if __name__ == '__main__':
    unittest.main()
