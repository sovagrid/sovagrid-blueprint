#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Durable transaction primitive for a future external Agent source update.

The caller must hold the promotion, candidate and target-enrollment locks.
This module never obtains a Hub lease, stops or starts a service, and has no
public apply command. A boot unit can call ``recover_pending`` before the
original Agent starts. Trial startup requires a live supervisor gate supplied
by a future caller; the existing boot CLI deliberately supplies none and
rolls back an interrupted trial. Only the Agent source, its helper/unit, and
two local metadata records are mutable; tunnel credentials and units are hash
guards.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import struct
import sys
import threading
import time
from typing import Callable


ROOT = "/var/lib/sovagrid-external-agent-update"
TXN = ROOT + "/transaction"
JOURNAL = TXN + "/journal.json"
PREPARING = TXN + "/preparing.json"
RECOVERED = TXN + "/recovered.json"
COMMITTED = ROOT + "/committed.json"
TRIAL_GATE_DIR = "/run/sovagrid-external-agent-update"
TRIAL_GATE_SOCKET = TRIAL_GATE_DIR + "/trial.sock"
TRIAL_DROPIN = "/etc/systemd/system/sovagrid-agent.service.d/50-sovagrid-external-trial.conf"
TRIAL_GATE_MAX = 2048
TRIAL_GATE_TIMEOUT = 3.0
TRIAL_GATE_MAX_AGE = 900.0
AGENT = "/opt/sovagrid-agent"
OLD_AGENT = TXN + "/old-agent"
NEW_AGENT = TXN + "/new-agent"
OLD_META = TXN + "/old-meta"
NEW_META = TXN + "/new-meta"
MAX_TREE_FILES = 256
MAX_TREE_BYTES = 256 * 1024**2
MAX_JOURNAL = 131072
SHA = re.compile(r"[0-9a-f]{64}\Z")
RELATIVE = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z")
PHASES = frozenset({"prepared", "switched", "trial", "committed"})

# Fixed order: restore in reverse so the promotion baseline becomes old first.
META = (
    ("/opt/sovagrid-agent-installer/remote_agent.py", 0o644, 1024 * 1024),
    ("/etc/systemd/system/sovagrid-agent.service", 0o644, 64 * 1024),
    ("/opt/sovagrid-agent-installer/source-manifest.json", 0o644, 512 * 1024),
    ("/var/lib/sovagrid-agent-enrollment/state.json", 0o600, 4 * 1024**2),
    ("/var/lib/sovagrid-promotion/baseline.json", 0o600, 32768),
)
GUARDS = (
    ("/etc/sovagrid/agent.token", 16384, True),
    ("/etc/sovagrid/hub-ca.pem", 16384, True),
    ("/etc/sovagrid-agent-tunnel/id_ed25519", 16384, True),
    ("/etc/sovagrid-agent-tunnel-public/known_hosts", 16384, True),
    ("/etc/systemd/system/sovagrid-agent-tunnel.service", 65536, True),
    (TRIAL_DROPIN, 65536, False),
)
GUARD_MODES = {
    "/etc/sovagrid/agent.token": 0o640,
    "/etc/sovagrid/hub-ca.pem": 0o644,
    "/etc/sovagrid-agent-tunnel/id_ed25519": 0o600,
    "/etc/sovagrid-agent-tunnel-public/known_hosts": 0o644,
    "/etc/systemd/system/sovagrid-agent-tunnel.service": 0o644,
    TRIAL_DROPIN: 0o644,
}
ADDITIONAL_UNIT = re.compile(r"/etc/systemd/system/[A-Za-z0-9_.@-]+\.service\Z")
MAX_ADDITIONAL_UNITS = 16


class RecoveryError(Exception):
    pass


def need(ok: bool, code: str) -> None:
    if not ok:
        raise RecoveryError(code)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _linux_peer(connection: socket.socket) -> tuple[int, int, int]:
    """Return kernel-authenticated pid/uid/gid; fail closed off Linux."""
    need(sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"),
         "TRIAL_GATE_UNAVAILABLE")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                struct.calcsize("3i"))
    need(len(raw) == struct.calcsize("3i"), "TRIAL_GATE_PEER")
    pid, uid, gid = struct.unpack("3i", raw)
    need(pid > 1 and uid == 0 and gid == 0, "TRIAL_GATE_PEER")
    return pid, uid, gid


def _private_gate_path(path: Path, *, owner: int = 0) -> None:
    parent = path.parent.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == owner and
         stat.S_IMODE(parent.st_mode) == 0o700, "TRIAL_GATE_PATH")


def probe_trial_gate(op: str, journal_sha256: str, *,
                     path: str = TRIAL_GATE_SOCKET, owner: int = 0,
                     group: int = 0) -> bool:
    """Ask a live root supervisor for one transaction-bound trial permit.

    A socket file left after supervisor death cannot answer. The caller checks
    SO_PEERCRED, the fresh nonce, and the exact journal digest. A future live
    writer must keep its Hub lease and old Agent ACK evidence in memory while
    serving this socket; a disk boolean is never accepted as proof.
    """
    need(op in ("recover", "start") and isinstance(journal_sha256, str) and
         SHA.fullmatch(journal_sha256) is not None, "TRIAL_GATE_REQUEST")
    target = Path(path)
    try:
        _private_gate_path(target, owner=owner)
        info = target.lstat()
        need(stat.S_ISSOCK(info.st_mode) and info.st_uid == owner and
             stat.S_IMODE(info.st_mode) == 0o600, "TRIAL_GATE_PATH")
        nonce = secrets.token_hex(24)
        request = {"protocol": 1, "op": op, "journal_sha256": journal_sha256,
                   "nonce": nonce}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(TRIAL_GATE_TIMEOUT)
            connection.connect(path)
            pid, uid, gid = _linux_peer(connection)
            need(uid == owner and gid == group, "TRIAL_GATE_PEER")
            connection.sendall((json.dumps(request, sort_keys=True,
                                           separators=(",", ":")) + "\n").encode())
            raw = bytearray()
            while len(raw) <= TRIAL_GATE_MAX:
                chunk = connection.recv(1)
                if chunk == b"\n":
                    break
                need(chunk != b"", "TRIAL_GATE_RESPONSE")
                raw.extend(chunk)
            need(len(raw) <= TRIAL_GATE_MAX and chunk == b"\n",
                 "TRIAL_GATE_RESPONSE")
        value = json.loads(raw, object_pairs_hook=_unique)
        need(isinstance(value, dict) and set(value) ==
             {"protocol", "op", "journal_sha256", "nonce", "pid", "allowed"} and
             type(value["protocol"]) is int and value["protocol"] == 1 and
             value["op"] == op and value["journal_sha256"] == journal_sha256 and
             value["nonce"] == nonce and type(value["pid"]) is int and
             value["pid"] == pid and type(value["allowed"]) is bool,
             "TRIAL_GATE_RESPONSE")
        return value["allowed"]
    except (OSError, ValueError, UnicodeError, TypeError, RecoveryError):
        return False


class TrialGateServer:
    """One-use-per-stage live trial gate owned by a future root supervisor.

    This class is deliberately not invoked by any public apply command. The
    supervisor must provide callbacks that *actively* verify the Hub lease,
    the old Agent ACK evidence, and its own intended transaction at each
    request. Each stage is granted at most once and in recover→start order.
    """

    def __init__(self, journal_sha256: str, *, lease_active: Callable[[], bool],
                 agent_idle_proven: Callable[[], bool],
                 path: str = TRIAL_GATE_SOCKET, owner: int = 0, group: int = 0):
        need(isinstance(journal_sha256, str) and SHA.fullmatch(journal_sha256) is not None,
             "TRIAL_GATE_REQUEST")
        self.journal_sha256 = journal_sha256
        self.lease_active = lease_active
        self.agent_idle_proven = agent_idle_proven
        self.path = Path(path)
        self.owner = owner
        self.group = group
        self.pid = os.getpid()
        self.started = time.monotonic()
        self.granted: set[str] = set()
        self.closed = threading.Event()
        self.listener: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.inode: int | None = None

    def start(self) -> "TrialGateServer":
        need(os.geteuid() == self.owner and os.getegid() == self.group,
             "TRIAL_GATE_OWNER")
        _private_gate_path(self.path, owner=self.owner)
        need(not self.path.exists() and not self.path.is_symlink(),
             "TRIAL_GATE_PATH")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.path))
            self.inode = self.path.lstat().st_ino
            os.chmod(self.path, 0o600)
            info = self.path.lstat()
            need(stat.S_ISSOCK(info.st_mode) and info.st_uid == self.owner and
                 stat.S_IMODE(info.st_mode) == 0o600, "TRIAL_GATE_PATH")
            self.inode = info.st_ino
            listener.listen(2)
            listener.settimeout(0.2)
            self.listener = listener
            self.thread = threading.Thread(target=self._serve, daemon=True,
                                           name="sovagrid-external-agent-trial")
            self.thread.start()
            return self
        except BaseException:
            listener.close()
            if self.path.exists() and self.path.lstat().st_ino == self.inode:
                self.path.unlink()
            raise

    def _serve(self) -> None:
        assert self.listener is not None
        while not self.closed.is_set() and time.monotonic() - self.started < TRIAL_GATE_MAX_AGE:
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                connection.settimeout(TRIAL_GATE_TIMEOUT)
                try:
                    self._reply(connection)
                except (OSError, ValueError, UnicodeError, TypeError, RecoveryError):
                    continue
        self.close()

    def _reply(self, connection: socket.socket) -> None:
        pid, uid, gid = _linux_peer(connection)
        need(uid == self.owner and gid == self.group, "TRIAL_GATE_PEER")
        raw = bytearray()
        while len(raw) <= TRIAL_GATE_MAX:
            chunk = connection.recv(1)
            if chunk == b"\n":
                break
            need(chunk != b"", "TRIAL_GATE_REQUEST")
            raw.extend(chunk)
        need(len(raw) <= TRIAL_GATE_MAX and chunk == b"\n", "TRIAL_GATE_REQUEST")
        request = json.loads(raw, object_pairs_hook=_unique)
        need(isinstance(request, dict) and set(request) ==
             {"protocol", "op", "journal_sha256", "nonce"} and
             type(request["protocol"]) is int and request["protocol"] == 1 and
             request["op"] in ("recover", "start") and
             request["journal_sha256"] == self.journal_sha256 and
             isinstance(request["nonce"], str) and
             re.fullmatch(r"[0-9a-f]{48}", request["nonce"]) is not None,
             "TRIAL_GATE_REQUEST")
        op = request["op"]
        eligible = (not self.closed.is_set() and
                    time.monotonic() - self.started < TRIAL_GATE_MAX_AGE and
                    op not in self.granted and
                    (op == "recover" or "recover" in self.granted))
        if eligible:
            lease = self.lease_active()
            idle = self.agent_idle_proven()
            eligible = type(lease) is bool and lease and type(idle) is bool and idle
        allowed = eligible
        if allowed:
            self.granted.add(op)
        response = {"protocol": 1, "op": op,
                    "journal_sha256": self.journal_sha256,
                    "nonce": request["nonce"], "pid": os.getpid(),
                    "allowed": allowed}
        connection.sendall((json.dumps(response, sort_keys=True,
                                       separators=(",", ":")) + "\n").encode())

    def close(self) -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        if self.listener is not None:
            self.listener.close()
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return
        if (os.getpid() == self.pid and self.inode is not None and
                info.st_ino == self.inode and stat.S_ISSOCK(info.st_mode)):
            self.path.unlink()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "JOURNAL_INVALID")
        result[key] = value
    return result


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_tree(root: Path) -> None:
    """Make copied rollback/source bytes durable before publishing a journal."""
    directories = [root]
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            directories.append(path)
            continue
        need(stat.S_ISREG(mode), "TREE_UNSAFE")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        _fsync_directory(directory)


def _exchange_directories(left: Path, right: Path) -> None:
    """Swap two existing directories atomically on one Linux/macOS volume."""
    need(left.stat().st_dev == right.stat().st_dev, "FILESYSTEM")
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        operation = getattr(libc, "renameat2", None)
        need(operation is not None, "ATOMIC_SWAP_UNAVAILABLE")
        operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                              ctypes.c_char_p, ctypes.c_uint]
        operation.restype = ctypes.c_int
        result = operation(-100, os.fsencode(left), -100, os.fsencode(right), 2)
    elif sys.platform == "darwin":
        operation = getattr(libc, "renamex_np", None)
        need(operation is not None, "ATOMIC_SWAP_UNAVAILABLE")
        operation.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        operation.restype = ctypes.c_int
        result = operation(os.fsencode(left), os.fsencode(right), 2)
    else:
        raise RecoveryError("ATOMIC_SWAP_UNAVAILABLE")
    if result != 0:
        error = ctypes.get_errno()
        raise RecoveryError("FILESYSTEM" if error == errno.EXDEV else
                            "ATOMIC_SWAP_FAILED")
    _fsync_directory(left.parent)
    _fsync_directory(right.parent)


class Recovery:
    """Strict path wrapper; ``files`` is remote_agent.Files rooted at /.

    Injected roots and owners are only for isolated filesystem tests. A live
    call must use Files() with owner/group 0 and hold the external locks.
    """

    def __init__(self, files, *, owner: int = 0, group: int = 0):
        self.files = files
        self.owner = owner
        self.group = group
        need(files.owner == owner, "OWNER")

    def path(self, name: str) -> Path:
        return self.files.path(name)

    def _read(self, name: str, limit: int, *, mode: int | None = None,
              missing: bool = False) -> tuple[bytes, dict] | None:
        info = self.files.inspect(name, missing=missing)
        if info is None:
            return None
        need(info.st_size <= limit and info.st_uid == self.owner and
             (mode is None or stat.S_IMODE(info.st_mode) == mode), "FILE_UNSAFE")
        data = self.files.read(name, limit=limit)
        return data, {"sha256": _sha(data), "mode": stat.S_IMODE(info.st_mode),
                      "uid": info.st_uid, "gid": info.st_gid}

    def _tree(self, name: str, expected: dict[str, str]) -> None:
        """Validate the complete tree, including otherwise easy-to-lose dirs."""
        self.files.inspect(name, directory=True)
        root = self.path(name)
        root_info = root.lstat()
        need(root_info.st_uid == self.owner and root_info.st_gid == self.group and
             stat.S_IMODE(root_info.st_mode) == 0o755, "TREE_UNSAFE")
        wanted_dirs = {parent.as_posix() for relative in expected
                       for parent in Path(relative).parents if parent != Path(".")}
        files_seen = set()
        dirs_seen = set()
        total = 0
        count = 0
        for path in root.rglob("*"):
            count += 1
            need(count <= MAX_TREE_FILES * 3, "TREE_TOO_LARGE")
            relative = path.relative_to(root).as_posix()
            name_here = name + "/" + relative
            info = path.lstat()
            need(info.st_dev == root_info.st_dev and info.st_uid == self.owner and
                 info.st_gid == self.group and
                 not info.st_mode & 0o022 and
                 not stat.S_ISLNK(info.st_mode), "TREE_UNSAFE")
            if stat.S_ISDIR(info.st_mode):
                need(stat.S_IMODE(info.st_mode) == 0o755, "TREE_UNSAFE")
                dirs_seen.add(relative)
                continue
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                 stat.S_IMODE(info.st_mode) == 0o644 and relative in expected,
                 "TREE_UNSAFE")
            total += info.st_size
            need(total <= MAX_TREE_BYTES and info.st_size <= 32 * 1024**2,
                 "TREE_TOO_LARGE")
            need(self._read(name_here, 32 * 1024**2, mode=0o644)[1]["sha256"] == expected[relative],
                 "TREE_CHANGED")
            files_seen.add(relative)
        need(files_seen == set(expected) and dirs_seen == wanted_dirs,
             "TREE_CHANGED")

    def _projection(self, value: dict) -> dict[str, str]:
        need(isinstance(value, dict) and 1 <= len(value) <= MAX_TREE_FILES,
             "JOURNAL_INVALID")
        legal = {"LICENSE", "NOTICE", "ATTRIBUTION.md", "README.md",
                 "THIRD_PARTY_NOTICES.txt", "deploy/sovagrid-agent.service"}
        need({"LICENSE", "NOTICE", "ATTRIBUTION.md", "deploy/sovagrid-agent.service",
              "sovagrid_agent/__main__.py"} <= set(value), "JOURNAL_INVALID")
        for relative, digest in value.items():
            need(isinstance(relative, str) and RELATIVE.fullmatch(relative) is not None and
                 all(part not in (".", "..") for part in relative.split("/")) and
                 (relative in legal or
                  relative.startswith("sovagrid_agent/") and relative.endswith(".py") and
                  "__pycache__" not in relative.split("/")) and
                 isinstance(digest, str) and SHA.fullmatch(digest) is not None,
                 "JOURNAL_INVALID")
        return value

    def _guard_specs(self, recorded: dict | None = None, *, code: str = "GUARD_CHANGED") -> tuple:
        """Include independently managed tunnel units from the private baseline.

        Recorded guards remain authoritative during recovery, even if the
        baseline metadata is temporarily between its old and new versions.
        This also accepts journals written by an earlier package version.
        """
        if recorded is None:
            baseline = self._read("/var/lib/sovagrid-promotion/baseline.json", 32768,
                                  mode=0o600)
            need(baseline is not None, code)
            try:
                data = json.loads(baseline[0], object_pairs_hook=_unique)
            except (ValueError, UnicodeError, TypeError):
                raise RecoveryError(code) from None
            need(isinstance(data, dict) and isinstance(data.get("files"), dict) and
                 isinstance(data.get("units"), dict), code)
            extra = {name for name in data["files"]
                     if isinstance(name, str) and ADDITIONAL_UNIT.fullmatch(name) and
                     name not in {"/etc/systemd/system/sovagrid-agent.service",
                                  "/etc/systemd/system/sovagrid-agent-tunnel.service"}}
            need(all(data["units"].get(Path(name).name) is True for name in extra), code)
        else:
            need(isinstance(recorded, dict), code)
            extra = set(recorded) - {name for name, _limit, _required in GUARDS}
        need(len(extra) <= MAX_ADDITIONAL_UNITS and
             all(isinstance(name, str) and ADDITIONAL_UNIT.fullmatch(name)
                 for name in extra), code)
        specs = GUARDS + tuple((name, 65536, False) for name in sorted(extra))
        if recorded is not None:
            need(set(recorded) == {name for name, _limit, _required in specs}, code)
        return specs

    @staticmethod
    def _guard_mode(name: str) -> int:
        return GUARD_MODES.get(name, 0o644)

    def _guards(self, recorded: dict | None = None) -> dict:
        result = {}
        for name, limit, required in self._guard_specs(recorded):
            item = self._read(name, limit, mode=self._guard_mode(name), missing=not required)
            need(item is not None or not required, "GUARD_CHANGED")
            result[name] = None if item is None else item[1]
        return result

    def _validate_guards(self, expected: dict) -> None:
        need(expected == self._guards(expected), "GUARD_CHANGED")

    def _require_trial_dropin(self, journal: dict) -> None:
        expected = Path(__file__).with_name("sovagrid-external-agent-trial.conf").read_bytes()
        item = self._read(TRIAL_DROPIN, 65536, mode=0o644, missing=True)
        need(item is not None and item[0] == expected and
             journal["guards"].get(TRIAL_DROPIN) == item[1],
             "TRIAL_START_GUARD_REQUIRED")

    def verify_trial_state(self) -> str:
        """Validate exactly the new Agent for a guarded pre-start check."""
        journal = self._load_journal()
        need(journal is not None and journal["phase"] == "trial",
             "TRIAL_GATE_REQUEST")
        self._validate_guards(journal["guards"])
        self._require_trial_dropin(journal)
        self._check_meta(journal)
        self._tree(OLD_AGENT, journal["old_tree"])
        self._current_matches_committed(self._committed_marker(journal))
        return self.trial_journal_sha256()

    def _validate_journal(self, value: dict) -> dict:
        need(isinstance(value, dict) and set(value) ==
             {"protocol", "phase", "old_tree", "new_tree", "meta", "guards"} and
             type(value["protocol"]) is int and value["protocol"] == 2 and
             isinstance(value["phase"], str) and value["phase"] in PHASES,
             "JOURNAL_INVALID")
        self._projection(value["old_tree"])
        self._projection(value["new_tree"])
        need(isinstance(value["meta"], dict) and
             set(value["meta"]) == {name for name, _mode, _limit in META} and
             isinstance(value["guards"], dict),
             "JOURNAL_INVALID")
        guard_specs = self._guard_specs(value["guards"], code="JOURNAL_INVALID")
        for name, mode, _limit in META:
            item = value["meta"][name]
            need(isinstance(item, dict) and set(item) ==
                 {"old", "new", "mode", "uid", "gid"} and
                 all(isinstance(item[key], str) and SHA.fullmatch(item[key])
                     for key in ("old", "new")) and
                 type(item["mode"]) is int and item["mode"] == mode and
                 type(item["uid"]) is int and item["uid"] == self.owner and
                 type(item["gid"]) is int and item["gid"] == self.group,
                 "JOURNAL_INVALID")
        for name, _limit, required in guard_specs:
            item = value["guards"][name]
            need((item is None and not required) or
                 (isinstance(item, dict) and set(item) ==
                  {"sha256", "mode", "uid", "gid"} and
                  isinstance(item["sha256"], str) and SHA.fullmatch(item["sha256"]) and
                  type(item["mode"]) is int and item["mode"] == self._guard_mode(name) and
                  type(item["uid"]) is int and item["uid"] == self.owner and
                  type(item["gid"]) is int and item["gid"] >= 0),
                 "JOURNAL_INVALID")
        return value

    def _load_journal(self) -> dict | None:
        item = self._read(JOURNAL, MAX_JOURNAL, mode=0o600, missing=True)
        if item is None:
            return None
        need(item[1]["gid"] == self.group, "JOURNAL_INVALID")
        try:
            value = json.loads(item[0], object_pairs_hook=_unique)
        except (ValueError, UnicodeError, TypeError):
            raise RecoveryError("JOURNAL_INVALID") from None
        return self._validate_journal(value)

    def trial_journal_sha256(self) -> str:
        journal = self._load_journal()
        need(journal is not None and journal["phase"] == "trial",
             "TRIAL_GATE_REQUEST")
        item = self._read(JOURNAL, MAX_JOURNAL, mode=0o600)
        need(item is not None and item[1]["gid"] == self.group,
             "TRIAL_GATE_REQUEST")
        return _sha(item[0])

    def _write_journal(self, journal: dict) -> None:
        self._validate_journal(journal)
        raw = (json.dumps(journal, sort_keys=True, separators=(",", ":")) + "\n").encode()
        need(len(raw) <= MAX_JOURNAL, "JOURNAL_INVALID")
        self.files.write(JOURNAL, raw, mode=0o600, gid=self.group)
        _fsync_directory(self.path(TXN))

    def _set_phase(self, journal: dict, phase: str) -> dict:
        need(phase in PHASES, "JOURNAL_INVALID")
        updated = {**journal, "phase": phase}
        self._write_journal(updated)
        return updated

    def _validate_marker(self, value: dict) -> dict:
        need(isinstance(value, dict) and set(value) ==
             {"protocol", "old_tree", "old_meta", "guards"} and
             type(value["protocol"]) is int and value["protocol"] == 1 and
             isinstance(value["old_meta"], dict) and
             set(value["old_meta"]) == {name for name, _mode, _limit in META} and
             all(isinstance(digest, str) and SHA.fullmatch(digest)
                 for digest in value["old_meta"].values()) and
             isinstance(value["guards"], dict),
             "MARKER_INVALID")
        guard_specs = self._guard_specs(value["guards"], code="MARKER_INVALID")
        self._projection(value["old_tree"])
        for name, _limit, required in guard_specs:
            item = value["guards"][name]
            need((item is None and not required) or
                 (isinstance(item, dict) and set(item) ==
                  {"sha256", "mode", "uid", "gid"} and
                  isinstance(item["sha256"], str) and SHA.fullmatch(item["sha256"]) and
                  item["mode"] == self._guard_mode(name) and
                  type(item["uid"]) is int and item["uid"] == self.owner and
                  type(item["gid"]) is int and item["gid"] >= 0),
                 "MARKER_INVALID")
        return value

    def _load_marker(self, name: str) -> dict | None:
        item = self._read(name, MAX_JOURNAL, mode=0o600, missing=True)
        if item is None:
            return None
        need(item[1]["gid"] == self.group, "MARKER_INVALID")
        try:
            value = json.loads(item[0], object_pairs_hook=_unique)
        except (ValueError, UnicodeError, TypeError):
            raise RecoveryError("MARKER_INVALID") from None
        return self._validate_marker(value)

    def _write_marker(self, name: str, marker: dict) -> None:
        self._validate_marker(marker)
        raw = (json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n").encode()
        need(len(raw) <= MAX_JOURNAL, "MARKER_INVALID")
        self.files.write(name, raw, mode=0o600, gid=self.group)
        _fsync_directory(self.path(TXN))

    def _committed_marker(self, journal: dict) -> dict:
        return {"protocol": 2, "new_tree": journal["new_tree"],
                "new_meta": {name: journal["meta"][name]["new"]
                             for name, _mode, _limit in META},
                "guards": journal["guards"]}

    def _validate_committed_marker(self, marker: dict) -> dict:
        need(isinstance(marker, dict) and set(marker) ==
             {"protocol", "new_tree", "new_meta", "guards"} and
             type(marker["protocol"]) is int and marker["protocol"] == 2 and
             isinstance(marker["new_meta"], dict) and
             set(marker["new_meta"]) == {name for name, _mode, _limit in META} and
             all(isinstance(digest, str) and SHA.fullmatch(digest)
                 for digest in marker["new_meta"].values()) and
             isinstance(marker["guards"], dict),
             "COMMIT_MARKER_INVALID")
        guard_specs = self._guard_specs(marker["guards"], code="COMMIT_MARKER_INVALID")
        self._projection(marker["new_tree"])
        for name, _limit, required in guard_specs:
            item = marker["guards"][name]
            need((item is None and not required) or
                 (isinstance(item, dict) and set(item) ==
                  {"sha256", "mode", "uid", "gid"} and
                  isinstance(item["sha256"], str) and SHA.fullmatch(item["sha256"]) and
                  type(item["mode"]) is int and item["mode"] == self._guard_mode(name) and
                  type(item["uid"]) is int and item["uid"] == self.owner and
                  type(item["gid"]) is int and item["gid"] >= 0),
                 "COMMIT_MARKER_INVALID")
        return marker

    def _load_committed_marker(self) -> dict | None:
        if self.files.inspect(ROOT, directory=True, private=True, missing=True) is None:
            return None
        item = self._read(COMMITTED, MAX_JOURNAL, mode=0o600, missing=True)
        if item is None:
            return None
        need(item[1]["gid"] == self.group, "COMMIT_MARKER_INVALID")
        try:
            value = json.loads(item[0], object_pairs_hook=_unique)
        except (ValueError, UnicodeError, TypeError):
            raise RecoveryError("COMMIT_MARKER_INVALID") from None
        return self._validate_committed_marker(value)

    def _write_committed_marker(self, marker: dict) -> None:
        self._validate_committed_marker(marker)
        raw = (json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n").encode()
        need(len(raw) <= MAX_JOURNAL, "COMMIT_MARKER_INVALID")
        self.files.write(COMMITTED, raw, mode=0o600, gid=self.group)
        _fsync_directory(self.path(ROOT))

    def _current_matches_committed(self, marker: dict) -> None:
        self._tree(AGENT, marker["new_tree"])
        for name, mode, limit in META:
            current = self._read(name, limit, mode=mode)
            need(current is not None and current[1]["gid"] == self.group and
                 current[1]["sha256"] == marker["new_meta"][name],
                 "COMMITTED_CHANGED")
        self._validate_guards(marker["guards"])

    def _clear_committed_orphan(self) -> bool:
        """Finish a committed cleanup after a crash, never revert new source."""
        marker = self._load_committed_marker()
        if marker is None:
            return False
        self._current_matches_committed(marker)
        need(self._load_journal() is None, "COMMITTED_REQUIRES_REVIEW")
        if self.files.inspect(TXN, directory=True, private=True, missing=True) is not None:
            shutil.rmtree(self.path(TXN))
            _fsync_directory(self.path(ROOT))
        self.path(COMMITTED).unlink()
        _fsync_directory(self.path(ROOT))
        return True

    def _current_matches_marker(self, marker: dict) -> None:
        self._tree(AGENT, marker["old_tree"])
        for name, mode, limit in META:
            current = self._read(name, limit, mode=mode)
            need(current is not None and current[1]["gid"] == self.group and
                 current[1]["sha256"] == marker["old_meta"][name],
                 "ORPHAN_UNSAFE")
        self._validate_guards(marker["guards"])

    def _clear_orphan(self) -> bool:
        """Clean only staging that the switch could not have consumed."""
        need(self._load_journal() is None, "ORPHAN_REQUIRES_REVIEW")
        if self.files.inspect(TXN, directory=True, private=True, missing=True) is None:
            return False
        recovered = self._load_marker(RECOVERED)
        preparing = self._load_marker(PREPARING)
        if recovered is not None:
            self._current_matches_marker(recovered)
        elif preparing is not None:
            self._current_matches_marker(preparing)
        else:
            # A SIGKILL can happen after mkdir or during the atomic marker
            # write. Only an empty directory or Files.write scratch is safe.
            for item in self.path(TXN).iterdir():
                info = item.lstat()
                need(item.name.startswith(".enroll-") and
                     stat.S_ISREG(info.st_mode) and info.st_uid == self.owner and
                     info.st_gid == self.group and stat.S_IMODE(info.st_mode) == 0o600 and
                     info.st_nlink == 1, "ORPHAN_REQUIRES_REVIEW")
        shutil.rmtree(self.path(TXN))
        _fsync_directory(self.path(ROOT))
        return True

    def _snapshot_meta(self, name: str, index: int, data: bytes, *, old: bool) -> None:
        directory = OLD_META if old else NEW_META
        self.files.write(directory + "/" + str(index), data, mode=0o600,
                         gid=self.group)

    def _meta_bytes(self, index: int, *, old: bool, limit: int, expected: str) -> bytes:
        directory = OLD_META if old else NEW_META
        item = self._read(directory + "/" + str(index), limit, mode=0o600)
        need(item is not None and item[1]["gid"] == self.group and
             item[1]["sha256"] == expected,
             "SNAPSHOT_CHANGED")
        return item[0]

    def _copy_tree(self, source: str, destination: str, projection: dict[str, str]) -> None:
        self._tree(source, projection)
        need(not self.path(destination).exists() and not self.path(destination).is_symlink(),
             "TRANSACTION_EXISTS")
        shutil.copytree(self.path(source), self.path(destination), symlinks=True)
        self._tree(destination, projection)
        _fsync_tree(self.path(destination))
        _fsync_directory(self.path(destination).parent)

    @staticmethod
    def _json(data: bytes) -> dict:
        try:
            value = json.loads(data, object_pairs_hook=_unique)
        except (ValueError, UnicodeError, TypeError):
            raise RecoveryError("META_INVALID") from None
        need(isinstance(value, dict), "META_INVALID")
        return value

    def _metadata_consistent(self, old_payloads: dict[str, bytes],
                             new_payloads: dict[str, bytes],
                             old_tree: dict[str, str], new_tree: dict[str, str]) -> None:
        """Ensure the proposed metadata only adopts Agent source, never keys."""
        old_manifest = self._json(old_payloads[META[2][0]])
        new_manifest = self._json(new_payloads[META[2][0]])
        old_state = self._json(old_payloads[META[3][0]])
        new_state = self._json(new_payloads[META[3][0]])
        old_baseline = self._json(old_payloads[META[4][0]])
        new_baseline = self._json(new_payloads[META[4][0]])
        helper_name = "sovagrid-blueprint/deploy/remote_agent.py"
        unit_name = "sovagrid-agent/deploy/sovagrid-agent.service"
        source_root = "/opt/sovagrid-agent/"
        helper_path, unit_path, manifest_path, state_path, _baseline_path = (
            entry[0] for entry in META)

        def source_projection(manifest, tree, payloads):
            hashes = manifest.get("sha256")
            need(isinstance(hashes, dict) and
                 hashes.get(helper_name) == _sha(payloads[helper_path]) and
                 hashes.get(unit_name) == _sha(payloads[unit_path]) and
                 all(hashes.get("sovagrid-agent/" + name) == digest
                     for name, digest in tree.items()), "META_INVALID")
            return {helper_path: _sha(payloads[helper_path]),
                    **{source_root + name: digest for name, digest in tree.items()}}

        old_projection = source_projection(old_manifest, old_tree, old_payloads)
        new_projection = source_projection(new_manifest, new_tree, new_payloads)
        mutable = set(old_projection) | set(new_projection) | {unit_path, manifest_path}
        old_dirs = {parent.as_posix() for name in old_tree
                    for parent in Path(name).parents if parent != Path(".")}
        new_dirs = {parent.as_posix() for name in new_tree
                    for parent in Path(name).parents if parent != Path(".")}
        need(set(old_tree) <= set(new_tree) and old_dirs <= new_dirs,
             "SOURCE_LAYOUT_CHANGED")

        for state, projection, payloads in ((old_state, old_projection, old_payloads),
                                            (new_state, new_projection, new_payloads)):
            owned = state.get("owned_files")
            need(state.get("protocol") == 1 and type(state.get("protocol")) is int and
                 state.get("kind") == "target" and state.get("phase") == "active" and
                 not state.get("removed") and state.get("pending_writes") == {} and
                 state.get("source_files") == projection and
                 state.get("source_manifest_sha256") == _sha(payloads[manifest_path]) and
                 isinstance(owned, dict) and
                 all(owned.get(path) == digest for path, digest in projection.items()) and
                 owned.get(unit_path) == _sha(payloads[unit_path]) and
                 owned.get(manifest_path) == _sha(payloads[manifest_path]),
                 "META_INVALID")
        immutable_state = ("identity", "agent_token_sha256", "transport", "local_port",
                           "ssh_public_key", "ssh_key_fingerprint", "accounts")
        changed_state = {"source_manifest_sha256", "source_files", "owned_files",
                         "owned_directories", "file_metadata"}
        old_file_metadata = old_state.get("file_metadata")
        new_file_metadata = new_state.get("file_metadata")
        old_owned_dirs = old_state.get("owned_directories")
        new_owned_dirs = new_state.get("owned_directories")
        added_files = set(new_projection) - set(old_projection)
        added_dirs = {AGENT + "/" + name for name in new_dirs - old_dirs}
        need(set(old_state) == set(new_state) and
             all(old_state[key] == new_state[key]
                 for key in old_state if key not in changed_state) and
             all(old_state.get(key) == new_state.get(key) for key in immutable_state) and
             isinstance(old_file_metadata, dict) and
             isinstance(new_file_metadata, dict) and
             set(new_file_metadata) == set(old_file_metadata) | added_files and
             all(new_file_metadata[key] == old_file_metadata[key]
                 for key in old_file_metadata) and
             all(new_file_metadata[key] == {"mode": 0o644, "gid": self.group}
                 for key in added_files) and
             isinstance(old_owned_dirs, dict) and isinstance(new_owned_dirs, dict) and
             set(new_owned_dirs) == set(old_owned_dirs) | added_dirs and
             all(new_owned_dirs[key] == old_owned_dirs[key]
                 for key in old_owned_dirs) and
             all(new_owned_dirs[key] == 0o755 for key in added_dirs) and
             {key: value for key, value in old_state["owned_files"].items()
              if key not in mutable} ==
             {key: value for key, value in new_state["owned_files"].items()
              if key not in mutable} and
             set(new_state["owned_files"]) - mutable ==
             set(old_state["owned_files"]) - mutable,
             "IDENTITY_CHANGED")

        for baseline, payloads in ((old_baseline, old_payloads),
                                   (new_baseline, new_payloads)):
            records = baseline.get("files")
            need(baseline.get("protocol") == 1 and type(baseline.get("protocol")) is int
                 and isinstance(records, dict) and
                 all(isinstance(records.get(path), dict) and
                     records[path].get("sha256") == _sha(payloads[path])
                     for path in (unit_path, manifest_path, state_path)),
                 "META_INVALID")
        changed_baseline = {unit_path, manifest_path, state_path}
        need(set(old_baseline) == set(new_baseline) and
             all(old_baseline[key] == new_baseline[key]
                 for key in old_baseline if key != "files") and
             set(old_baseline["files"]) == set(new_baseline["files"]) and
             all(old_baseline["files"][key] == new_baseline["files"][key]
                 for key in old_baseline["files"] if key not in changed_baseline) and
             all({field: value for field, value in old_baseline["files"][key].items()
                  if field != "sha256"} ==
                 {field: value for field, value in new_baseline["files"][key].items()
                  if field != "sha256"}
                 for key in changed_baseline), "IDENTITY_CHANGED")

    def prepare(self, *, candidate_tree: str, old_tree: dict[str, str],
                new_tree: dict[str, str], new_meta: dict[str, bytes],
                checkpoint: Callable[[str], None] | None = None) -> dict:
        """Snapshot all rollback bytes before a future caller stops the Agent.

        No original Agent path changes here. A failure or SIGKILL before the
        journal is durable leaves only private staging bytes to clean later.
        """
        self._projection(old_tree)
        self._projection(new_tree)
        need(set(new_meta) == {name for name, _mode, _limit in META},
             "META_INVALID")
        need(self.path(AGENT).stat().st_dev == self.path(ROOT).parent.stat().st_dev,
             "FILESYSTEM")
        self._tree(AGENT, old_tree)
        self._tree(candidate_tree, new_tree)
        old_payloads = {}
        metadata = {}
        for name, mode, limit in META:
            old = self._read(name, limit, mode=mode)
            need(old is not None and old[1]["gid"] == self.group, "META_CHANGED")
            data = new_meta[name]
            need(isinstance(data, bytes) and 0 < len(data) <= limit, "META_INVALID")
            old_payloads[name] = old[0]
            metadata[name] = {"old": old[1]["sha256"], "new": _sha(data),
                              "mode": mode, "uid": self.owner, "gid": self.group}
        self._metadata_consistent(old_payloads, new_meta, old_tree, new_tree)
        guards = self._guards()
        self.files.mkdir(ROOT, 0o700)
        _fsync_directory(self.path(ROOT).parent)
        self._clear_committed_orphan()
        self._clear_orphan()
        need(not self.path(TXN).exists() and not self.path(TXN).is_symlink(),
             "TRANSACTION_EXISTS")
        self.files.mkdir(TXN, 0o700)
        _fsync_directory(self.path(ROOT))
        if checkpoint:
            checkpoint("txn-created")
        marker = {"protocol": 1, "old_tree": old_tree,
                  "old_meta": {name: metadata[name]["old"] for name, _mode, _limit in META},
                  "guards": guards}
        self._write_marker(PREPARING, marker)
        if checkpoint:
            checkpoint("prepare-marker")
        self.files.mkdir(OLD_META, 0o700)
        self.files.mkdir(NEW_META, 0o700)
        _fsync_directory(self.path(TXN))
        self._copy_tree(AGENT, OLD_AGENT, old_tree)
        if checkpoint:
            checkpoint("old-tree")
        self._copy_tree(candidate_tree, NEW_AGENT, new_tree)
        if checkpoint:
            checkpoint("new-tree")
        for index, (name, mode, limit) in enumerate(META):
            self._snapshot_meta(name, index, old_payloads[name], old=True)
            self._snapshot_meta(name, index, new_meta[name], old=False)
            need(self._read(name, limit, mode=mode)[1]["sha256"] == metadata[name]["old"],
                 "META_CHANGED")
            if checkpoint:
                checkpoint("meta-" + str(index))
        self._validate_guards(guards)
        journal = self._validate_journal({"protocol": 2, "phase": "prepared",
                                          "old_tree": old_tree,
                                          "new_tree": new_tree, "meta": metadata,
                                          "guards": guards})
        self._write_journal(journal)
        if checkpoint:
            checkpoint("journal")
        self.path(PREPARING).unlink()
        _fsync_directory(self.path(TXN))
        if checkpoint:
            checkpoint("marker-removed")
        return journal

    def _check_meta(self, journal: dict) -> None:
        for index, (name, mode, limit) in enumerate(META):
            record = journal["meta"][name]
            self._meta_bytes(index, old=True, limit=limit, expected=record["old"])
            self._meta_bytes(index, old=False, limit=limit, expected=record["new"])
            current = self._read(name, limit, mode=mode)
            need(current is not None and current[1]["gid"] == self.group and
                 current[1]["sha256"] in (record["old"], record["new"]),
                 "META_CHANGED")

    def _tree_version(self, journal: dict) -> str:
        for version in ("old", "new"):
            try:
                self._tree(AGENT, journal[version + "_tree"])
            except RecoveryError:
                continue
            return version
        raise RecoveryError("TREE_CHANGED")

    def _switch_under_quiescence(self, *, agent_stopped: Callable[[], bool],
                                 remote_lease_active: Callable[[], bool],
                                 agent_idle_ack: Callable[[], bool],
                                 checkpoint: Callable[[str], None] | None = None) -> None:
        """Internal switch primitive. No public caller exists until both gates.

        The journal remains present after this method returns. A future caller
        must check the original Hub lease and Agent idle acknowledgement before
        commit. A Hub lease alone cannot prove that an older file relay has
        finished on the Agent.
        """
        journal = self._load_journal()
        need(journal is not None and journal["phase"] == "prepared" and
             remote_lease_active() and agent_idle_ack() and
             agent_stopped(), "QUIESCENCE_REQUIRED")
        need(self._load_marker(PREPARING) is None and
             self._load_marker(RECOVERED) is None, "TRANSACTION_NOT_READY")
        self._validate_guards(journal["guards"])
        self._check_meta(journal)
        need(self._tree_version(journal) == "old", "TREE_CHANGED")
        self._tree(NEW_AGENT, journal["new_tree"])
        _exchange_directories(self.path(AGENT), self.path(NEW_AGENT))
        if checkpoint:
            checkpoint("tree")
        for index, (name, mode, limit) in enumerate(META):
            data = self._meta_bytes(index, old=False, limit=limit,
                                    expected=journal["meta"][name]["new"])
            self.files.write(name, data, mode=mode, gid=self.group)
            if checkpoint:
                checkpoint("meta-" + str(index))
        self._tree(AGENT, journal["new_tree"])
        self._check_meta(journal)
        self._validate_guards(journal["guards"])
        self._set_phase(journal, "switched")
        if checkpoint:
            checkpoint("switched")

    def begin_trial(self, *, agent_stopped: Callable[[], bool],
                    remote_lease_active: Callable[[], bool],
                    supervisor_active: Callable[[], bool],
                    agent_idle_proven: Callable[[], bool]) -> None:
        """Authorize one trial startup while a future supervisor holds gates.

        The boot recovery CLI does not yet have a live supervisor verifier, so
        it will roll this phase back. A future writer must supply a verifiable
        live gate to the boot unit before it can start the new Agent.
        """
        journal = self._load_journal()
        need(journal is not None and journal["phase"] == "switched" and
             agent_stopped() and remote_lease_active() and supervisor_active() and
             agent_idle_proven(), "TRIAL_GATE_REQUIRED")
        self._require_trial_dropin(journal)
        self._check_meta(journal)
        self._tree(OLD_AGENT, journal["old_tree"])
        self._current_matches_committed(self._committed_marker(journal))
        self._set_phase(journal, "trial")

    def commit_trial(self, *, agent_running: Callable[[], bool],
                     agent_healthy: Callable[[], bool],
                     remote_lease_active: Callable[[], bool],
                     supervisor_active: Callable[[], bool],
                     agent_idle_proven: Callable[[], bool]) -> None:
        """Persist the point of no return only after a healthy live trial."""
        journal = self._load_journal()
        need(journal is not None and journal["phase"] == "trial" and
             agent_running() and agent_healthy() and remote_lease_active() and
             supervisor_active() and agent_idle_proven(), "COMMIT_GATE_REQUIRED")
        self._check_meta(journal)
        self._tree(OLD_AGENT, journal["old_tree"])
        self._current_matches_committed(self._committed_marker(journal))
        self._set_phase(journal, "committed")

    def finalize_committed(self, *, checkpoint: Callable[[str], None] | None = None) -> bool:
        """Idempotently discard rollback bytes after a durable commit.

        A root-owned marker outside the transaction directory is fsynced
        before removing the journal. It proves the accepted new tree across a
        crash at any later cleanup step, including a partial rmtree.
        """
        journal = self._load_journal()
        if journal is None:
            return self._clear_committed_orphan()
        need(journal["phase"] == "committed", "COMMIT_REQUIRED")
        marker = self._committed_marker(journal)
        existing = self._load_committed_marker()
        need(existing is None or existing == marker, "COMMIT_MARKER_INVALID")
        self._check_meta(journal)
        self._tree(OLD_AGENT, journal["old_tree"])
        self._current_matches_committed(marker)
        self._write_committed_marker(marker)
        if checkpoint:
            checkpoint("committed-marker")
        self.path(JOURNAL).unlink()
        _fsync_directory(self.path(TXN))
        if checkpoint:
            checkpoint("committed-journal-removed")
        try:
            self._clear_committed_orphan()
        except OSError:
            # The marker is durable outside the scratch directory. A later
            # recover retries cleanup without risking rollback of new source.
            pass
        return True

    def recover_pending(self, *, agent_stopped: Callable[[], bool],
                        trial_authorized: Callable[[], bool] | None = None,
                        checkpoint: Callable[[str], None] | None = None) -> bool:
        """Restore precommit work; preserve a proven committed new Agent.

        The default boot path has no trial authorization and rolls trial back.
        A future supervisor may supply a fresh live verifier for its one trial
        start. A stale file or boolean persisted on disk must not be used.
        """
        journal = self._load_journal()
        if journal is None:
            if self._clear_committed_orphan():
                return True
            return self._clear_orphan()
        if journal["phase"] == "committed":
            return self.finalize_committed(checkpoint=checkpoint)
        need(agent_stopped(), "AGENT_RUNNING")
        self._validate_guards(journal["guards"])
        self._check_meta(journal)
        if journal["phase"] == "trial" and trial_authorized is not None and \
                trial_authorized():
            self.verify_trial_state()
            return False
        version = self._tree_version(journal)
        if version == "new":
            self._tree(OLD_AGENT, journal["old_tree"])
            _exchange_directories(self.path(AGENT), self.path(OLD_AGENT))
            if checkpoint:
                checkpoint("tree")
        for index, (name, mode, limit) in reversed(tuple(enumerate(META))):
            record = journal["meta"][name]
            current = self._read(name, limit, mode=mode)
            need(current is not None and current[1]["sha256"] in
                 (record["old"], record["new"]), "META_CHANGED")
            if current[1]["sha256"] != record["old"]:
                data = self._meta_bytes(index, old=True, limit=limit,
                                        expected=record["old"])
                self.files.write(name, data, mode=mode, gid=self.group)
            if checkpoint:
                checkpoint("meta-" + str(index))
        self._tree(AGENT, journal["old_tree"])
        self._check_meta(journal)
        self._validate_guards(journal["guards"])
        for name, _mode, limit in META:
            need(self._read(name, limit)[1]["sha256"] == journal["meta"][name]["old"],
                 "META_CHANGED")
        marker = {"protocol": 1, "old_tree": journal["old_tree"],
                  "old_meta": {name: journal["meta"][name]["old"]
                               for name, _mode, _limit in META},
                  "guards": journal["guards"]}
        self._write_marker(RECOVERED, marker)
        self.path(JOURNAL).unlink()
        _fsync_directory(self.path(TXN))
        try:
            self._clear_orphan()
        except OSError:
            # The old source and metadata are already durable and the journal
            # is gone. Leftover private snapshots block a new transaction,
            # but must not prevent the recovered Agent from starting.
            pass
        return True
