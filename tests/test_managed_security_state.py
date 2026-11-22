# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
import os
from pathlib import Path
import runpy
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from tests.test_web_restore_update_compat import worker


SECURITY = runpy.run_path(str(Path(__file__).resolve().parents[1] / "deploy/managed_security_state.py"))


@unittest.skipIf(os.geteuid() == 0, "filesystem fixtures run as the current non-root UID")
class ManagedSecurityStateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database = self.root / SECURITY["DATABASE"].lstrip("/")
        self.database.parent.mkdir(parents=True, mode=0o700)
        self.db = sqlite3.connect(self.database)
        self.addCleanup(self.db.close)
        self.source = self.root / "candidate"
        self.source.mkdir()
        for item in (patch.object(worker, "ROOT", self.root), patch.object(worker, "HUB_UID", os.getuid()),
                     patch.object(worker, "HUB_GID", os.getgid())):
            item.start()
            self.addCleanup(item.stop)

    def inspect(self):
        return SECURITY["inspect_database"](self.database, uid=os.getuid(), gid=os.getgid())

    def test_explicit_denial_in_a_committed_wal_requires_compatible_candidate(self):
        self.db.executescript("CREATE TABLE servers(id TEXT PRIMARY KEY); INSERT INTO servers VALUES ('first');")
        self.assertTrue(worker.candidate_security_compatible(self.source))
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA wal_autocheckpoint=0")
        self.db.execute("ALTER TABLE servers ADD COLUMN terminal_enabled INTEGER")
        self.db.commit()
        self.assertTrue(worker.candidate_security_compatible(self.source))
        self.db.execute("UPDATE servers SET terminal_enabled=0")
        self.db.commit()
        self.assertGreater(Path(str(self.database) + "-wal").stat().st_size, 0)
        self.assertEqual(self.inspect(), {SECURITY["TERMINAL"]})
        self.assertFalse(worker.candidate_security_compatible(self.source))

        for relative, evidence in (
            ("sovagrid-blueprint/run.sh", "# SOVAGRID_INDEPENDENT_TERMINAL_V1\n"),
            ("sovagrid-blueprint/deploy/managed_security_state.py", "def inspect_database("),
            ("sovagrid-hub/sovagrid_hub/agent_management.py", "def save_agent_management_permissions("),
            ("sovagrid-hub/sovagrid_hub/api/routes/relays.py", "self.app.store.terminal_access_valid("),
            ("sovagrid-hub/sovagrid_hub/persistence/servers.py", "terminal_access_policy("),
            ("sovagrid-agent/sovagrid_agent/terminal_policy.py", "def terminal_poll_allowed("),
        ):
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(evidence)
        self.assertTrue(worker.candidate_security_compatible(self.source))
        path.unlink()
        self.assertFalse(worker.candidate_security_compatible(self.source))

    def test_unsuitable_database_sidecar_refuses_update(self):
        self.db.execute("CREATE TABLE servers(id TEXT PRIMARY KEY)")
        self.db.commit()
        unreadable = Path(str(self.database) + "-wal")
        unreadable.symlink_to(self.database)
        try:
            self.assertFalse(worker.candidate_security_compatible(self.source))
        finally:
            unreadable.unlink()
