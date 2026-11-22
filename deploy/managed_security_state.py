# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Compatibility checks for security state that older runtimes ignore."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys


TERMINAL = "independent-terminal"
DATABASE = "/var/lib/sovagrid/hub/hub.sqlite"

# Keep the query identical for the update reader and the quarantined portable
# restore clone. Both scripts execute it as the unprivileged Hub identity.
SQL_PROBE = """
def protected_security_state(db):
    table = db.execute("SELECT type,sql FROM sqlite_master WHERE name='servers'").fetchone()
    if table is None:
        return []
    kind, definition = table
    if kind != 'table' or not definition or 'CREATE VIRTUAL TABLE' in definition.upper():
        raise ValueError()
    columns = {row[1] for row in db.execute('PRAGMA table_info(servers)')}
    if ('terminal_enabled' in columns and db.execute(
            'SELECT 1 FROM servers WHERE terminal_enabled IS NOT NULL LIMIT 1').fetchone()):
        return ['independent-terminal']
    return []
"""

READ_HELPER = SQL_PROBE + r"""
import json, os, sqlite3, sys, time
try:
    descriptor, uid, gid = map(int, sys.argv[1:])
    os.fchdir(descriptor)
    if os.geteuid() == 0:
        os.chroot('.')
        os.chdir('/')
        os.setgroups([])
    if os.getegid() != gid:
        os.setgid(gid)
    if os.geteuid() != uid:
        os.setuid(uid)
    os.close(descriptor)
    os.umask(0o077)
    deadline = time.monotonic() + 3
    db = sqlite3.connect('file:hub.sqlite?mode=ro', uri=True, timeout=1)
    try:
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('PRAGMA mmap_size=0')
        print(json.dumps(protected_security_state(db)))
    finally:
        db.close()
except BaseException:
    sys.exit(1)
"""


def inspect_database(database: Path, *, uid: int, gid: int):
    """Inspect an existing managed Hub, including committed WAL records."""
    directory = os.open(database.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if (info.st_uid, info.st_gid) != (uid, gid) or info.st_mode & 0o022:
            raise ValueError("Unsafe Hub database directory")
        for name in ("hub.sqlite", "hub.sqlite-wal", "hub.sqlite-shm"):
            try:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                if name != "hub.sqlite":
                    continue
                raise
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    (info.st_uid, info.st_gid) != (uid, gid) or info.st_mode & 0o022):
                raise ValueError("Unsafe Hub database file")
        result = subprocess.run([sys.executable, "-I", "-S", "-c", READ_HELPER,
            str(directory), str(uid), str(gid)], pass_fds=(directory,), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=True,
            env={"PATH": "/usr/bin:/bin"})
        return parse_features(json.loads(result.stdout))
    finally:
        os.close(directory)


def parse_features(value):
    if not isinstance(value, list) or value not in ([], [TERMINAL]):
        raise ValueError("Unrecognized managed Hub security state")
    return frozenset(value)


def bundle_supports(source: Path):
    """Check the capability on a source tree already verified by the caller."""
    checks = (
        ("sovagrid-blueprint/run.sh", b"# SOVAGRID_INDEPENDENT_TERMINAL_V1\n"),
        ("sovagrid-blueprint/deploy/managed_security_state.py", b"def inspect_database("),
        ("sovagrid-hub/sovagrid_hub/agent_management.py", b"def save_agent_management_permissions("),
        ("sovagrid-hub/sovagrid_hub/api/routes/relays.py", b"self.app.store.terminal_access_valid("),
        ("sovagrid-hub/sovagrid_hub/persistence/servers.py", b"terminal_access_policy("),
        ("sovagrid-agent/sovagrid_agent/terminal_policy.py", b"def terminal_poll_allowed("),
    )
    for relative, evidence in checks:
        candidate = source / relative
        if candidate.is_symlink() or not candidate.is_file() or evidence not in candidate.read_bytes():
            return frozenset()
    return frozenset((TERMINAL,))
