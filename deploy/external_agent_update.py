#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Read-only planning for a future update of a preserved external Agent.

A server with its own Hub has two independent Agents. The Hub-only updater
deliberately never adopts the original Agent. This helper verifies that boundary and shows
the exact Agent source and enrollment metadata a separate transaction would
need to change. It has no apply command and does not write a policy, journal,
file or systemd unit. A live apply also requires an original-Hub lease that
atomically drains and pauses command delivery; the compatibility GET is not
such a lease.
"""

from __future__ import annotations

import contextlib
import copy
import fcntl
import grp
import hashlib
import http.client
import importlib.util
import json
import math
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True


SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_OUTPUT = 32768
MAX_CHANGES = 256
MAX_COMPATIBILITY_BODY = 4096
COMPATIBILITY_TIMEOUT = 5.0
SOURCE_PREFIX = "/opt/sovagrid-agent/"
MANIFEST_FILE = "/opt/sovagrid-agent-installer/source-manifest.json"
AGENT_UNIT_FILE = "/etc/systemd/system/sovagrid-agent.service"
TRIAL_WATCH_DIR = Path("/run/sovagrid-external-agent-trial")
TRIAL_WATCH_SOCKET = TRIAL_WATCH_DIR / "gate.sock"
TRIAL_WATCH_EPOCH = TRIAL_WATCH_DIR / "epoch.env"
TRIAL_WATCH_LINE_MAX = 96
TRIAL_WATCH_TIMEOUT = 3.0
TRIAL_WATCH_MAX_AGE = 900.0
ORIGINAL_HUB_LEASE_TIMEOUT = 5.0
ORIGINAL_HUB_LEASE_BODY_MAX = 2048
ORIGINAL_HUB_LEASE_MAX_LOCAL_AGE = 880.0
ORIGINAL_HUB_LEASE_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
EXTERNAL_AGENT_CGROUP = re.compile(
    r"/(?:[A-Za-z0-9_.:-]+/)*sovagrid-agent\.service\Z")
EXTERNAL_AGENT_UNIT = "sovagrid-agent.service"
AGENT_IDLE_SOCKET = Path("/run/sovagrid-agent-control/agent.sock")
AGENT_IDLE_FIELDS = frozenset(("jobs_inflight", "file_operations",
                               "terminal_sessions", "upload_sessions",
                               "network_checks", "probe_helpers"))
AGENT_IDLE_MAX_HOLD = 880.0
AGENT_IDLE_ACK_TIMEOUT = 185.0
AGENT_IDLE_LINE_MAX = 512


def _module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise RuntimeError("MISSING_DEPENDENCY")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


update = _module("sovagrid_external_agent_hub_only_update", "hub_only_update.py")
remote = _module("sovagrid_external_agent_enrollment", "remote_agent.py")
recovery = _module("sovagrid_external_agent_recovery", "external_agent_recovery.py")
common = update.common
promotion = update.promotion


class Refused(Exception):
    pass


def need(condition: bool, code: str) -> None:
    if not condition:
        raise Refused(code)


def _watch_peer(connection: socket.socket) -> tuple[int, int, int]:
    """Identify the Agent by kernel credentials, never by supplied text."""
    need(sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"),
         "TRIAL_WATCH_UNAVAILABLE")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                struct.calcsize("3i"))
    need(len(raw) == struct.calcsize("3i"), "TRIAL_WATCH_PEER")
    pid, uid, gid = struct.unpack("3i", raw)
    need(pid > 1, "TRIAL_WATCH_PEER")
    return pid, uid, gid


def _watch_line(connection: socket.socket) -> str:
    """Read one bounded ASCII protocol line under one wall-clock deadline."""
    deadline = time.monotonic() + TRIAL_WATCH_TIMEOUT
    raw = bytearray()
    while len(raw) <= TRIAL_WATCH_LINE_MAX:
        left = deadline - time.monotonic()
        need(left > 0, "TRIAL_WATCH_TIMEOUT")
        connection.settimeout(left)
        value = connection.recv(1)
        need(value != b"", "TRIAL_WATCH_CLOSED")
        if value == b"\n":
            try:
                return raw.decode("ascii")
            except UnicodeError:
                raise Refused("TRIAL_WATCH_PROTOCOL") from None
        raw.extend(value)
    raise Refused("TRIAL_WATCH_PROTOCOL")


class TrialWatchServer:
    """Future trial supervisor's live Agent watchdog socket.

    This primitive has no public caller or apply route. A writer must keep the
    original Hub lease and old Agent idle ACK alive in its callbacks, prove the
    exact journal, and identify the systemd Agent cgroup for every ping. An
    active Agent cannot reach Hub until HELLO and PING 0 both succeed.
    """

    def __init__(self, journal_sha256: str, *, group: int, agent_uid: int,
                 journal_current, lease_active, agent_idle_proven,
                 agent_peer_allowed, directory: Path = TRIAL_WATCH_DIR,
                 owner: int = 0):
        need(isinstance(journal_sha256, str) and SHA.fullmatch(journal_sha256) is not None and
             type(group) is int and group >= 0 and type(agent_uid) is int and agent_uid >= 0,
             "TRIAL_WATCH_REQUEST")
        for callback in (journal_current, lease_active, agent_idle_proven,
                         agent_peer_allowed):
            need(callable(callback), "TRIAL_WATCH_REQUEST")
        self.journal_sha256 = journal_sha256
        self.group = group
        self.agent_uid = agent_uid
        self.owner = owner
        self.directory = Path(directory)
        self.socket_path = self.directory / "gate.sock"
        self.epoch_path = self.directory / "epoch.env"
        self.epoch = secrets.token_hex(16)
        self.journal_current = journal_current
        self.lease_active = lease_active
        self.agent_idle_proven = agent_idle_proven
        self.agent_peer_allowed = agent_peer_allowed
        self.started = time.monotonic()
        self.closed = threading.Event()
        self.listener: socket.socket | None = None
        self.active: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.socket_inode: int | None = None
        self.epoch_inode: int | None = None

    def _directory(self) -> None:
        info = self.directory.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == self.owner and
             info.st_gid == self.group and stat.S_IMODE(info.st_mode) == 0o710,
             "TRIAL_WATCH_PATH")

    def _eligible(self, pid: int, uid: int, gid: int) -> bool:
        if self.closed.is_set() or time.monotonic() - self.started >= TRIAL_WATCH_MAX_AGE:
            self.close()
            return False
        try:
            journal = self.journal_current()
            lease = self.lease_active()
            idle = self.agent_idle_proven()
            peer = self.agent_peer_allowed(pid, uid, gid)
            allowed = (journal == self.journal_sha256 and type(lease) is bool and lease and
                       type(idle) is bool and idle and type(peer) is bool and peer)
        except Exception:
            allowed = False
        if not allowed:
            # An expired lease or changed journal is terminal for this trial.
            # A later callback improvement cannot revive the same epoch.
            self.close()
        return allowed

    def start(self) -> "TrialWatchServer":
        need(os.geteuid() == self.owner, "TRIAL_WATCH_OWNER")
        self._directory()
        need(not os.path.lexists(self.socket_path) and
             not os.path.lexists(self.epoch_path), "TRIAL_WATCH_PATH")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = os.open(self.epoch_path, flags, 0o600)
        try:
            self.epoch_inode = os.fstat(descriptor).st_ino
            payload = f"SOVAGRID_EXTERNAL_TRIAL_EPOCH={self.epoch}\n".encode("ascii")
            written = 0
            while written < len(payload):
                count = os.write(descriptor, payload[written:])
                need(count > 0, "TRIAL_WATCH_PATH")
                written += count
            os.fsync(descriptor)
            info = os.fstat(descriptor)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == self.owner and
                 stat.S_IMODE(info.st_mode) == 0o600, "TRIAL_WATCH_PATH")
        except BaseException:
            os.close(descriptor)
            self._unlink_owned(self.epoch_path, self.epoch_inode)
            raise
        os.close(descriptor)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.socket_path))
            self.socket_inode = self.socket_path.lstat().st_ino
            os.chown(self.socket_path, self.owner, self.group)
            os.chmod(self.socket_path, 0o660)
            info = self.socket_path.lstat()
            need(stat.S_ISSOCK(info.st_mode) and info.st_uid == self.owner and
                 info.st_gid == self.group and stat.S_IMODE(info.st_mode) == 0o660,
                 "TRIAL_WATCH_PATH")
            listener.listen(1)
            listener.settimeout(0.2)
            self.listener = listener
            self.thread = threading.Thread(target=self._serve, daemon=True,
                                           name="sovagrid-external-agent-watch")
            self.thread.start()
            return self
        except BaseException:
            listener.close()
            self._unlink_owned(self.socket_path, self.socket_inode)
            self._unlink_owned(self.epoch_path, self.epoch_inode)
            raise

    @staticmethod
    def _unlink_owned(path: Path, inode: int | None) -> None:
        if inode is None:
            return
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        if info.st_ino == inode and not stat.S_ISLNK(info.st_mode):
            path.unlink()

    def _serve(self) -> None:
        assert self.listener is not None
        try:
            while not self.closed.is_set() and time.monotonic() - self.started < TRIAL_WATCH_MAX_AGE:
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with connection:
                    self.active = connection
                    try:
                        self._handle(connection)
                    except (OSError, ValueError, Refused):
                        pass
                    finally:
                        self.active = None
        finally:
            self.close()

    def _handle(self, connection: socket.socket) -> None:
        pid, uid, gid = _watch_peer(connection)
        need(uid == self.agent_uid and gid == self.group and
             self._eligible(pid, uid, gid), "TRIAL_WATCH_PEER")
        need(_watch_line(connection) == f"HELLO 1 {self.epoch}", "TRIAL_WATCH_PROTOCOL")
        need(self._eligible(pid, uid, gid), "TRIAL_WATCH_DENIED")
        connection.sendall(f"READY 1 {self.epoch}\n".encode("ascii"))
        sequence = 0
        while not self.closed.is_set() and time.monotonic() - self.started < TRIAL_WATCH_MAX_AGE:
            need(_watch_line(connection) == f"PING {sequence}", "TRIAL_WATCH_PROTOCOL")
            need(self._eligible(pid, uid, gid), "TRIAL_WATCH_DENIED")
            connection.sendall(f"PONG {sequence}\n".encode("ascii"))
            sequence += 1

    def close(self) -> None:
        if self.closed.is_set():
            if self.thread is not None and threading.current_thread() is not self.thread:
                self.thread.join(timeout=TRIAL_WATCH_TIMEOUT + 1)
            return
        self.closed.set()
        if self.active is not None:
            try:
                self.active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self.listener is not None:
            self.listener.close()
        self._unlink_owned(self.socket_path, self.socket_inode)
        self._unlink_owned(self.epoch_path, self.epoch_inode)
        if self.thread is not None and threading.current_thread() is not self.thread:
            self.thread.join(timeout=TRIAL_WATCH_TIMEOUT + 1)


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, "MANIFEST_INVALID")
        value[key] = item
    return value


@contextlib.contextmanager
def _promotion_lock():
    """Share the existing lock; never create it during a read-only preview."""
    path = update.PROMOTION_LOCK
    need(not path.is_symlink(), "LOCK_UNSAFE")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise Refused("LOCK_UNAVAILABLE") from exc
    try:
        common.validate_lock(os.fstat(descriptor))
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused("BUSY") from exc
        yield
    finally:
        os.close(descriptor)


def _manifest(root: Path) -> tuple[str, dict]:
    """Read a manifest only after its whole source tree was verified."""
    path = root / "sovagrid-bundle.json"
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0 and
         info.st_size <= 512 * 1024, "MANIFEST_INVALID")
    raw = promotion._read_regular(path, 512 * 1024)
    need(len(raw) <= 512 * 1024, "MANIFEST_INVALID")
    value = json.loads(raw, object_pairs_hook=_unique_pairs)
    need(isinstance(value, dict) and set(value) == {"format", "components", "sha256"} and
         type(value["format"]) is int and value["format"] == 1 and
         isinstance(value["sha256"], dict), "MANIFEST_INVALID")
    return hashlib.sha256(raw).hexdigest(), value


def _external_snapshot() -> tuple[str, dict, dict]:
    """Verify the installed helper, runtime, enrollment and active units."""
    enrollment = remote.Enrollment(executable=remote.TARGET_HELPER)
    with enrollment.locked("target", readonly=True):
        state = enrollment.load_state("target")
        need(isinstance(state, dict) and state.get("kind") == "target" and
             state.get("phase") == "active" and not state.get("removed") and
             not state.get("pending_writes") and isinstance(state.get("identity"), dict),
             "EXTERNAL_ENROLLMENT")
        request_id = remote.canonical_uuid(state["identity"].get("request_id"))
        state = enrollment.target_state(request_id, required=True)
        source_sha, source_manifest = enrollment.source("target")
        enrollment.verify_installed_files(state)
        enrollment.verify_credentials(state)
        enrollment.check_loaded_unit("sovagrid-agent-tunnel.service", state)
        enrollment.check_loaded_unit("sovagrid-agent.service", state)
        need(enrollment.services() == {"tunnel": True, "agent": True}, "EXTERNAL_SERVICE")
        need(state.get("source_manifest_sha256") == source_sha and
             state.get("source_files") == enrollment.installed_projection(source_manifest),
             "EXTERNAL_SOURCE")
        config = json.loads(enrollment.files.read("/etc/sovagrid/agent.json", limit=32768),
                            object_pairs_hook=_unique_pairs)
        need(isinstance(config, dict) and type(state.get("local_port")) is int and
             1024 <= state["local_port"] <= 65535, "EXTERNAL_IDENTITY")
        need(config.get("server_id") == state["identity"]["server_id"] and
             config.get("hub_url") == f"https://localhost:{state.get('local_port')}" and
             config.get("token_file") == "/etc/sovagrid/agent.token" and
             config.get("ca_file") == "/etc/sovagrid/hub-ca.pem" and
             isinstance(state.get("transport"), dict), "EXTERNAL_IDENTITY")
        return source_sha, source_manifest, state


def _changes(before: dict, after: dict) -> list[dict[str, str]]:
    old = remote.Enrollment.installed_projection(before)
    new = remote.Enrollment.installed_projection(after)
    need(len(old) <= MAX_CHANGES and len(new) <= MAX_CHANGES, "PROJECTION_TOO_LARGE")
    changes = []
    for path in sorted(set(old) | set(new)):
        if old.get(path) == new.get(path):
            continue
        changes.append({"path": path, "operation": ("create" if path not in old else
                                                     "remove" if path not in new else "replace")})
    service = "sovagrid-agent/deploy/sovagrid-agent.service"
    if before["sha256"].get(service) != after["sha256"].get(service):
        changes.append({"path": "/etc/systemd/system/sovagrid-agent.service",
                        "operation": "replace"})
    need(bool(changes) and len(changes) <= MAX_CHANGES, "SAME_AGENT_SOURCE")
    return changes


def _project_target_state(state: dict, before: dict, after: dict,
                          after_sha256: str) -> dict:
    """Compute an enrollment update without changing credentials or the host.

    This is a planning primitive, not an apply operation. The eventual writer
    must hold the promotion, candidate and enrollment locks, journal the old
    state, acquire an original-Hub drain lease, and verify every file again.
    """
    need(isinstance(after_sha256, str) and SHA.fullmatch(after_sha256) is not None,
         "CANDIDATE_INVALID")
    old = remote.Enrollment.installed_projection(before)
    new = remote.Enrollment.installed_projection(after)
    need(isinstance(state, dict) and state.get("kind") == "target" and
         state.get("phase") == "active" and state.get("removed") is not True and
         state.get("pending_writes") == {} and state.get("source_files") == old and
         isinstance(state.get("owned_files"), dict) and
         isinstance(state.get("file_metadata"), dict) and
         isinstance(state.get("owned_directories"), dict) and
         old.keys() <= new.keys(), "EXTERNAL_ENROLLMENT")
    owned = state["owned_files"]
    need(all(owned.get(path) == digest for path, digest in old.items()) and
         owned.get(AGENT_UNIT_FILE) ==
         before["sha256"].get("sovagrid-agent/deploy/sovagrid-agent.service") and
         owned.get(MANIFEST_FILE) == state.get("source_manifest_sha256"),
         "EXTERNAL_ENROLLMENT")
    result = copy.deepcopy(state)
    for path in old.keys() - new.keys():
        result["owned_files"].pop(path, None)
        result["file_metadata"].pop(path, None)
    for path, digest in new.items():
        result["owned_files"][path] = digest
        if path not in result["file_metadata"]:
            result["file_metadata"][path] = {"mode": 0o644, "gid": 0}
    source_root = Path(SOURCE_PREFIX.rstrip("/"))
    old_dirs = {str(parent) for path in old if path.startswith(SOURCE_PREFIX)
                for parent in Path(path).parents if parent != source_root and
                source_root in parent.parents}
    new_dirs = {str(parent) for path in new if path.startswith(SOURCE_PREFIX)
                for parent in Path(path).parents if parent != source_root and
                source_root in parent.parents}
    for directory in new_dirs - old_dirs:
        need(directory not in result["owned_directories"], "EXTERNAL_ENROLLMENT")
        result["owned_directories"][directory] = 0o755
    result["source_manifest_sha256"] = after_sha256
    result["source_files"] = new
    result["owned_files"][MANIFEST_FILE] = after_sha256
    result["owned_files"][AGENT_UNIT_FILE] = after["sha256"][
        "sovagrid-agent/deploy/sovagrid-agent.service"]
    need(result["identity"] == state["identity"] and
         result.get("agent_token_sha256") == state.get("agent_token_sha256") and
         result.get("transport") == state.get("transport") and
         result.get("local_port") == state.get("local_port") and
         result.get("ssh_public_key") == state.get("ssh_public_key") and
         result.get("ssh_key_fingerprint") == state.get("ssh_key_fingerprint"),
         "EXTERNAL_IDENTITY")
    return result


def _candidate_agent_files(root: Path, manifest: dict) -> dict[str, str]:
    """Validate every would-be installed source file and Python syntax."""
    projection = remote.Enrollment.installed_projection(manifest)
    need(1 <= len(projection) <= MAX_CHANGES, "PROJECTION_TOO_LARGE")
    total = 0
    for destination, expected in projection.items():
        relative = (remote.SELF_NAME if destination == remote.TARGET_HELPER else
                    "sovagrid-agent/" + destination.removeprefix(SOURCE_PREFIX))
        need(destination == remote.TARGET_HELPER or destination.startswith(SOURCE_PREFIX),
             "CANDIDATE_INVALID")
        path = root / relative
        data = promotion._read_regular(path, 32 * 1024**2)
        total += len(data)
        need(total <= 256 * 1024**2 and hashlib.sha256(data).hexdigest() == expected,
             "CANDIDATE_INVALID")
        if relative.endswith(".py"):
            try:
                compile(data, str(path), "exec", dont_inherit=True)
            except (SyntaxError, ValueError, TypeError):
                raise Refused("CANDIDATE_PYTHON_INVALID") from None
    need(projection.get(remote.TARGET_HELPER) == manifest["sha256"].get(remote.SELF_NAME),
         "CANDIDATE_INVALID")
    return projection


def _installed_agent_tree(projection: dict[str, str], *, root: Path | None = None,
                          owner: int = 0) -> None:
    """Refuse replacing an Agent source directory with untracked user files."""
    source_root = Path(SOURCE_PREFIX.rstrip("/"))
    root = source_root if root is None else Path(root)
    info = root.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and
         not info.st_mode & 0o022, "EXTERNAL_SOURCE")
    expected = {Path(path).relative_to(source_root).as_posix() for path in projection
                if path.startswith(SOURCE_PREFIX)}
    found = set()
    found_dirs = set()
    expected_dirs = {parent.as_posix() for relative in expected
                     for parent in Path(relative).parents if parent != Path(".")}
    count = 0
    for path in root.rglob("*"):
        count += 1
        need(count <= MAX_CHANGES * 3, "PROJECTION_TOO_LARGE")
        entry = path.lstat()
        need(entry.st_uid == owner and not entry.st_mode & 0o022 and
             not stat.S_ISLNK(entry.st_mode), "EXTERNAL_SOURCE")
        if stat.S_ISDIR(entry.st_mode):
            found_dirs.add(path.relative_to(root).as_posix())
            continue
        need(stat.S_ISREG(entry.st_mode) and entry.st_nlink == 1,
             "EXTERNAL_SOURCE")
        found.add(path.relative_to(root).as_posix())
    need(found == expected and found_dirs == expected_dirs, "EXTERNAL_SOURCE")


def preflight(archive_sha256: str, current_manifest_sha256: str) -> dict:
    """Validate the exact local source/state transition without writing it.

    The result cannot be replayed as an authorization: all locks, source bytes,
    enrollment state and the original Hub must be checked again by an eventual
    transactional writer. In particular, a read-only compatibility response
    cannot prove that a remote command queue is idle.
    """
    earlier = preview(archive_sha256, current_manifest_sha256)
    with _promotion_lock():
        current, promoted, _commits, baseline = update.inspect()
        need(current == earlier["current_hub_manifest_sha256"] and
             promoted.get("phase") == "activated" and
             promoted.get("baseline_sha256") == baseline,
             "PROMOTION_CHANGED")
        external_sha, before, state = _external_snapshot()
        need(external_sha == earlier["external_agent_manifest_sha256"] and
             state.get("source_manifest_sha256") == external_sha,
             "EXTERNAL_CHANGED")
        candidate_root, _ = common.candidate_source(archive_sha256)
        candidate_sha, after = _manifest(candidate_root)
        need(candidate_sha == current, "CANDIDATE_NOT_LOCAL_HUB")
        old = remote.Enrollment.installed_projection(before)
        new = _candidate_agent_files(candidate_root, after)
        _installed_agent_tree(old)
        need(old.keys() <= new.keys(), "UNSUPPORTED_SOURCE_REMOVAL")
        # Atomic tree exchange can add vetted source files and directories.
        # Removing an old installed file is intentionally a separate review.
        old_parents = {str(Path(path).parent) for path in old if path.startswith(SOURCE_PREFIX)}
        new_parents = {str(Path(path).parent) for path in new if path.startswith(SOURCE_PREFIX)}
        need(old_parents <= new_parents, "UNSUPPORTED_SOURCE_REMOVAL")
        projected = _project_target_state(state, before, after, candidate_sha)
        need(projected["source_files"] == new and
             projected["identity"] == state["identity"], "EXTERNAL_IDENTITY")
        need(promotion.capture_external() == promotion._private_json(promotion.BASELINE) and
             update._hash_file(promotion.BASELINE) == baseline,
             "EXTERNAL_CHANGED")
    result = {**earlier, "candidate_agent_file_count": len(new),
              "metadata_paths_to_change": [MANIFEST_FILE,
                                           "/var/lib/sovagrid-agent-enrollment/state.json",
                                           "/var/lib/sovagrid-promotion/baseline.json"],
              "apply_supported": False,
              "apply_blockers": ["ORIGINAL_HUB_AGENT_UPDATE_LEASE_NOT_VERIFIED",
                                 "AGENT_IDLE_ACK_NOT_VERIFIED",
                                 "TRIAL_FD_WATCHDOG_NOT_VERIFIED",
                                 "EXTERNAL_AGENT_APPLY_NOT_ENABLED"]}
    need(len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()) <= MAX_OUTPUT,
         "OUTPUT_TOO_LARGE")
    return result


def recover_pending() -> dict:
    """Boot-safe rollback entry point, ordered before the original Agent unit.

    The install/enable step for the accompanying RequiredBy unit belongs to a
    future lease-guarded updater. A read-only preflight never installs it.
    """
    need(os.geteuid() == 0, "ROOT")
    with contextlib.ExitStack() as locks:
        locks.callback(os.close, update._lock(update.PROMOTION_LOCK))
        locks.callback(os.close, update._lock(update.CANDIDATES / ".lock"))
        enrollment = remote.Enrollment(executable=remote.TARGET_HELPER)
        locks.enter_context(enrollment.locked("target"))
        transaction = recovery.Recovery(enrollment.files)

        def stopped() -> bool:
            status = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet",
                                     "sovagrid-agent.service"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=10, check=False)
            return status.returncode != 0

        # Deliberately omit trial_authorized until the Agent can keep a
        # supervisor FD alive through ExecStart and fail closed on its loss.
        # The root-only socket primitive is present but not a live apply path.
        changed = transaction.recover_pending(agent_stopped=stopped)
        if changed:
            subprocess.run(["/usr/bin/systemctl", "daemon-reload"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=30, check=True)
    return {"protocol": 1, "recovered": changed}


def _systemd_trial_guard_loaded() -> bool:
    """Require both pre-start and Agent-side gate in the loaded unit.

    ExecStartPre alone has a supervisor-death race before ExecStart. The
    environment setting makes a capable candidate Agent reconnect to the
    supervisor from within its own process before any Hub request. It stays
    harmless to the old Agent after a boot rollback.
    """
    command = ("/usr/bin/python3 -I /opt/sovagrid-src/sovagrid-blueprint/deploy/"
               "external_agent_update.py trial-start-guard")
    try:
        result = subprocess.run(["/usr/bin/systemctl", "show", "sovagrid-agent.service",
                                 "--property=NeedDaemonReload", "--property=ExecStartPre",
                                 "--property=Environment", "--property=EnvironmentFiles",
                                 "--no-pager"], capture_output=True, timeout=5, check=False)
        if result.returncode != 0 or len(result.stdout) > 8192:
            return False
        lines = result.stdout.decode("utf-8").splitlines()
        properties = dict(line.split("=", 1) for line in lines if "=" in line)
        prestart = properties.get("ExecStartPre", "")
        return (properties.get("NeedDaemonReload") == "no" and
                properties.get("Environment") == "SOVAGRID_EXTERNAL_TRIAL_GATE=1" and
                properties.get("EnvironmentFiles") ==
                "/run/sovagrid-external-agent-trial/epoch.env (ignore_errors=yes)" and
                ("argv[]=" + command + " ;") in prestart)
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return False


def trial_start_guard() -> dict:
    """Run immediately before Agent ExecStart from the guarded drop-in.

    No transaction is a normal service start. Trial startup is deliberately
    closed until an Agent-side live-socket watchdog closes the gap between
    ExecStartPre and ExecStart. Other pending phases also fail closed.
    """
    need(os.geteuid() == 0, "ROOT")
    with contextlib.ExitStack() as locks:
        locks.callback(os.close, update._lock(update.PROMOTION_LOCK))
        locks.callback(os.close, update._lock(update.CANDIDATES / ".lock"))
        enrollment = remote.Enrollment(executable=remote.TARGET_HELPER)
        locks.enter_context(enrollment.locked("target"))
        transaction = recovery.Recovery(enrollment.files)
        journal = transaction._load_journal()
        if journal is None:
            need(transaction._load_committed_marker() is None and
                 transaction.files.inspect(recovery.TXN, directory=True,
                                           private=True, missing=True) is None,
                 "PENDING_RECOVERY")
            return {"protocol": 1, "trial": False, "allowed": True}
        need(journal["phase"] == "trial" and _systemd_trial_guard_loaded(),
             "TRIAL_GATE_REQUIRED")
        transaction.verify_trial_state()
        raise Refused("TRIAL_RUNTIME_NOT_READY")


def _compatibility_pairs(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, "ORIGINAL_HUB_COMPATIBILITY_INVALID")
        value[key] = item
    return value


def _original_hub_compatibility(state: dict, expected_manifest_sha256: str) -> None:
    """Prove the original Hub serves the same bundle over the enrolled tunnel.

    This is evidence for the preview only. It does not authorize an Agent update.
    The URL is built solely from verified enrollment fields, never from a reply.
    """
    need(isinstance(state, dict) and isinstance(state.get("identity"), dict) and
         isinstance(state.get("transport"), dict) and type(state.get("local_port")) is int and
         1024 <= state["local_port"] <= 65535 and
         isinstance(expected_manifest_sha256, str) and SHA.fullmatch(expected_manifest_sha256),
         "ORIGINAL_HUB_COMPATIBILITY_INVALID")
    try:
        server_id = remote.canonical_uuid(state["identity"].get("server_id"))
        files = remote.Files()
        token = files.read("/etc/sovagrid/agent.token", limit=256)
        ca = files.read("/etc/sovagrid/hub-ca.pem", limit=16384)
        need(re.fullmatch(rb"[A-Za-z0-9_-]{43}\n", token) is not None and
             hashlib.sha256(token.rstrip(b"\n")).hexdigest() == state.get("agent_token_sha256") and
             ca.decode("ascii") == state["transport"].get("hub_ca_pem"),
             "ORIGINAL_HUB_CREDENTIALS_CHANGED")
        context = ssl.create_default_context(cadata=ca.decode("ascii"))
        need(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname,
             "ORIGINAL_HUB_TLS_INVALID")
    except Refused:
        raise
    except (remote.Refuse, OSError, UnicodeError, ValueError, ssl.SSLError, TypeError):
        raise Refused("ORIGINAL_HUB_CREDENTIALS_CHANGED") from None

    # http.client connects directly to localhost; it has no proxy or redirect
    # handling. A 3xx response therefore fails the 200-only check below.
    connection = http.client.HTTPSConnection("localhost", state["local_port"],
                                             context=context, timeout=COMPATIBILITY_TIMEOUT)
    deadline = time.monotonic() + COMPATIBILITY_TIMEOUT

    def remaining() -> float:
        left = deadline - time.monotonic()
        need(left > 0, "ORIGINAL_HUB_COMPATIBILITY_UNAVAILABLE")
        return left

    try:
        connection.connect()
        need(connection.sock is not None, "ORIGINAL_HUB_COMPATIBILITY_UNAVAILABLE")
        sock = connection.sock
        sock.settimeout(remaining())
        connection.request("GET", f"/api/v1/servers/{server_id}/agent-compatibility",
                           headers={"Authorization": "Bearer " + token.decode("ascii").strip(),
                                    "Accept": "application/json"})
        sock.settimeout(remaining())
        response = connection.getresponse()
        need(response.status == 200 and
             response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() == "application/json",
             "ORIGINAL_HUB_COMPATIBILITY_UNAVAILABLE")
        content_length = response.getheader("Content-Length")
        if content_length is not None:
            need(content_length.isdecimal() and int(content_length) <= MAX_COMPATIBILITY_BODY,
                 "ORIGINAL_HUB_COMPATIBILITY_INVALID")
        # One-byte reads make the wall-clock deadline effective even if a peer
        # deliberately drips a response. The reply is tiny (two JSON fields).
        raw = bytearray()
        while len(raw) <= MAX_COMPATIBILITY_BODY:
            if response.isclosed():
                break
            # http.client may clear connection.sock for a Connection: close
            # response. Keep the socket captured before getresponse().
            sock.settimeout(remaining())
            byte = response.read(1)
            if not byte:
                break
            raw.extend(byte)
        need(len(raw) <= MAX_COMPATIBILITY_BODY, "ORIGINAL_HUB_COMPATIBILITY_INVALID")
        try:
            value = json.loads(raw, object_pairs_hook=_compatibility_pairs)
        except (ValueError, UnicodeError, TypeError):
            raise Refused("ORIGINAL_HUB_COMPATIBILITY_INVALID") from None
        need(isinstance(value, dict) and set(value) == {"protocol", "bundle_manifest_sha256"} and
             type(value["protocol"]) is int and value["protocol"] == 1 and
             isinstance(value["bundle_manifest_sha256"], str) and
             SHA.fullmatch(value["bundle_manifest_sha256"]) is not None,
             "ORIGINAL_HUB_COMPATIBILITY_INVALID")
        need(value["bundle_manifest_sha256"] == expected_manifest_sha256,
             "ORIGINAL_HUB_COMPATIBILITY_MISMATCH")
    except Refused:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError, TypeError):
        raise Refused("ORIGINAL_HUB_COMPATIBILITY_UNAVAILABLE") from None
    finally:
        connection.close()


def _lease_pairs(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, "ORIGINAL_HUB_LEASE_INVALID")
        value[key] = item
    return value


def _original_hub_lease_request(state: dict, action: str, payload: dict) -> dict:
    """Use the enrolled original-Hub tunnel, with no redirect or proxy.

    The Agent token and CA are rechecked against enrollment on every request.
    The remote Unix time is never compared with the local clock: a monotonic
    local deadline and each renewal response bound the lease instead.
    """
    paths = {"acquire": "lease", "renew": "lease/renew",
             "release": "lease/release"}
    need(action in paths and isinstance(payload, dict), "ORIGINAL_HUB_LEASE_INVALID")
    try:
        server_id = remote.canonical_uuid(state["identity"]["server_id"])
        port = state["local_port"]
        need(type(port) is int and 1024 <= port <= 65535,
             "ORIGINAL_HUB_LEASE_INVALID")
        files = remote.Files()
        token = files.read("/etc/sovagrid/agent.token", limit=256)
        ca = files.read("/etc/sovagrid/hub-ca.pem", limit=16384)
        need(re.fullmatch(rb"[A-Za-z0-9_-]{43}\n", token) is not None and
             hashlib.sha256(token.rstrip(b"\n")).hexdigest() ==
             state.get("agent_token_sha256") and
             ca.decode("ascii") == state["transport"].get("hub_ca_pem"),
             "ORIGINAL_HUB_CREDENTIALS_CHANGED")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=ca.decode("ascii"))
        need(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname,
             "ORIGINAL_HUB_TLS_INVALID")
        body = json.dumps(payload, sort_keys=True,
                          separators=(",", ":")).encode("ascii")
        need(len(body) <= 256, "ORIGINAL_HUB_LEASE_INVALID")
    except Refused:
        raise
    except (KeyError, remote.Refuse, OSError, UnicodeError, ValueError,
            TypeError, ssl.SSLError):
        raise Refused("ORIGINAL_HUB_LEASE_INVALID") from None

    connection = http.client.HTTPSConnection(
        "localhost", port, context=context, timeout=ORIGINAL_HUB_LEASE_TIMEOUT)
    deadline = time.monotonic() + ORIGINAL_HUB_LEASE_TIMEOUT

    def remaining() -> float:
        left = deadline - time.monotonic()
        need(left > 0, "ORIGINAL_HUB_LEASE_UNAVAILABLE")
        return left

    try:
        connection.connect()
        need(connection.sock is not None, "ORIGINAL_HUB_LEASE_UNAVAILABLE")
        sock = connection.sock
        sock.settimeout(remaining())
        connection.request(
            "POST", f"/api/v1/servers/{server_id}/agent-maintenance/{paths[action]}",
            body=body,
            headers={"Authorization": "Bearer " + token.decode("ascii").strip(),
                     "Accept": "application/json", "Content-Type": "application/json"})
        sock.settimeout(remaining())
        response = connection.getresponse()
        need(response.status == (201 if action == "acquire" else 200) and
             response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() ==
             "application/json", "ORIGINAL_HUB_LEASE_UNAVAILABLE")
        length = response.getheader("Content-Length")
        if length is not None:
            need(length.isdecimal() and int(length) <= ORIGINAL_HUB_LEASE_BODY_MAX,
                 "ORIGINAL_HUB_LEASE_INVALID")
        raw = bytearray()
        while len(raw) <= ORIGINAL_HUB_LEASE_BODY_MAX:
            if response.isclosed():
                break
            sock.settimeout(remaining())
            byte = response.read(1)
            if not byte:
                break
            raw.extend(byte)
        need(len(raw) <= ORIGINAL_HUB_LEASE_BODY_MAX,
             "ORIGINAL_HUB_LEASE_INVALID")
        value = json.loads(raw, object_pairs_hook=_lease_pairs)
        need(isinstance(value, dict), "ORIGINAL_HUB_LEASE_INVALID")
        return value
    except Refused:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException,
            ValueError, TypeError, UnicodeError):
        raise Refused("ORIGINAL_HUB_LEASE_UNAVAILABLE") from None
    finally:
        connection.close()


def _lease_reply(value: dict, *, acquired: bool, epoch: str | None = None,
                 max_until: int | None = None, expires_at: int | None = None) -> dict:
    fields = {"protocol", "scope", "hub_epoch", "expires_at", "max_until",
              "agent_idle_proven"}
    need(isinstance(value, dict) and set(value) ==
         (fields | {"lease_token"} if acquired else fields) and
         type(value["protocol"]) is int and value["protocol"] == 1 and
         value["scope"] == "jobs_and_new_relays" and
         isinstance(value["hub_epoch"], str) and
         re.fullmatch(r"[0-9a-f]{32}", value["hub_epoch"]) is not None and
         type(value["expires_at"]) is int and
         type(value["max_until"]) is int and
         0 < value["expires_at"] <= value["max_until"] and
         value["max_until"] - value["expires_at"] <= 900 and
         value["agent_idle_proven"] is False,
         "ORIGINAL_HUB_LEASE_INVALID")
    if acquired:
        need(isinstance(value["lease_token"], str) and
             ORIGINAL_HUB_LEASE_TOKEN.fullmatch(value["lease_token"]) is not None,
             "ORIGINAL_HUB_LEASE_INVALID")
    else:
        need(value["hub_epoch"] == epoch and value["max_until"] == max_until and
             value["expires_at"] >= expires_at,
             "ORIGINAL_HUB_LEASE_CHANGED")
    return value


class OriginalHubLease:
    """Future writer's in-memory renewable command/relay drain lease.

    This is intentionally not an Agent idle proof and has no public apply
    caller. A lost renewal is terminal even if a later HTTP request succeeds.
    The candidate Agent watchdog calls ``active`` for a synchronous proof on
    every heartbeat; a commit must also call ``assert_held(fresh=True)``.
    """

    def __init__(self, state: dict, bundle_manifest_sha256: str, *,
                 request=None, clock=time.monotonic, renew_interval: float = 5.0):
        need(isinstance(state, dict) and callable(clock) and
             (request is None or callable(request)) and
             type(renew_interval) in (int, float) and
             math.isfinite(renew_interval) and
             isinstance(bundle_manifest_sha256, str) and
             SHA.fullmatch(bundle_manifest_sha256) is not None and
             1.0 <= renew_interval <= 30.0,
             "ORIGINAL_HUB_LEASE_INVALID")
        self.state = copy.deepcopy(state)
        self.manifest = bundle_manifest_sha256
        self.request = request or (lambda action, payload:
                                   _original_hub_lease_request(self.state,
                                                               action, payload))
        self.clock = clock
        self.renew_interval = renew_interval
        self._mutex = threading.RLock()
        self._closed = threading.Event()
        self._failed = False
        self._token: str | None = None
        self._epoch: str | None = None
        self._max_until: int | None = None
        self._expires_at: int | None = None
        self._last_proof: float | None = None
        self._deadline: float | None = None
        self._thread: threading.Thread | None = None

    def acquire(self) -> "OriginalHubLease":
        with self._mutex:
            need(self._token is None and not self._closed.is_set(),
                 "ORIGINAL_HUB_LEASE_INVALID")
            started = self.clock()
            value = _lease_reply(self.request("acquire", {
                "bundle_manifest_sha256": self.manifest}), acquired=True)
            self._token = value["lease_token"]
            self._epoch = value["hub_epoch"]
            self._max_until = value["max_until"]
            self._expires_at = value["expires_at"]
            self._last_proof = self.clock()
            self._deadline = started + ORIGINAL_HUB_LEASE_MAX_LOCAL_AGE
            self._thread = threading.Thread(target=self._renew_loop, daemon=True,
                                            name="sovagrid-original-hub-lease")
            try:
                self._thread.start()
            except RuntimeError:
                self.close()
                raise Refused("ORIGINAL_HUB_LEASE_UNAVAILABLE") from None
            return self

    def _renew_loop(self) -> None:
        while not self._closed.wait(self.renew_interval):
            try:
                self.renew()
            except (Refused, OSError, ValueError, TypeError):
                return

    def renew(self) -> None:
        with self._mutex:
            need(not self._failed and not self._closed.is_set() and
                 self._token is not None and self._deadline is not None,
                 "ORIGINAL_HUB_LEASE_LOST")
            if self.clock() >= self._deadline:
                self._failed = True
                raise Refused("ORIGINAL_HUB_LEASE_EXPIRED")
            try:
                value = _lease_reply(self.request("renew", {
                    "lease_token": self._token}), acquired=False,
                    epoch=self._epoch, max_until=self._max_until,
                    expires_at=self._expires_at)
            except Exception:
                self._failed = True
                raise Refused("ORIGINAL_HUB_LEASE_LOST") from None
            self._expires_at = value["expires_at"]
            self._last_proof = self.clock()

    def assert_held(self, *, fresh: bool = False) -> None:
        if fresh:
            self.renew()
        with self._mutex:
            need(not self._failed and not self._closed.is_set() and
                 self._token is not None and self._deadline is not None and
                 self._last_proof is not None and
                 self._thread is not None and self._thread.is_alive() and
                 self.clock() < self._deadline and
                 self.clock() - self._last_proof <= self.renew_interval + 5,
                 "ORIGINAL_HUB_LEASE_LOST")

    def active(self) -> bool:
        try:
            self.assert_held(fresh=True)
            return True
        except Refused:
            return False

    def close(self) -> None:
        self._closed.set()
        if (self._thread is not None and self._thread.is_alive() and
                self._thread is not threading.current_thread()):
            self._thread.join(timeout=ORIGINAL_HUB_LEASE_TIMEOUT + 1)
        with self._mutex:
            token = self._token
            self._token = None
            if token is not None:
                try:
                    value = self.request("release", {"lease_token": token})
                    need(value == {"released": True}, "ORIGINAL_HUB_LEASE_INVALID")
                except Exception:
                    # The Hub's 120-second expiry remains the final release.
                    pass

    def __enter__(self) -> "OriginalHubLease":
        return self.acquire()

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()


def _external_unit_properties(*, run=subprocess.run) -> dict[str, str]:
    """Read the one systemd unit without parsing human-facing status output."""
    fields = ("Id", "ActiveState", "SubState", "MainPID", "ControlGroup",
              "InvocationID", "FragmentPath", "NeedDaemonReload", "User", "Group")
    try:
        result = run(["/usr/bin/systemctl", "show", EXTERNAL_AGENT_UNIT,
                      *("--property=" + name for name in fields), "--no-pager"],
                     capture_output=True, timeout=5, check=False)
        need(result.returncode == 0 and len(result.stdout) <= 8192,
             "EXTERNAL_UNIT_UNAVAILABLE")
        lines = result.stdout.decode("utf-8").splitlines()
        value = {}
        for line in lines:
            need("=" in line, "EXTERNAL_UNIT_INVALID")
            key, item = line.split("=", 1)
            need(key in fields and key not in value and "\x00" not in item,
                 "EXTERNAL_UNIT_INVALID")
            value[key] = item
        need(set(value) == set(fields) and
             value["Id"] == EXTERNAL_AGENT_UNIT and
             value["FragmentPath"] == AGENT_UNIT_FILE and
             value["NeedDaemonReload"] == "no", "EXTERNAL_UNIT_INVALID")
        return value
    except Refused:
        raise
    except (OSError, UnicodeError, TypeError, ValueError,
            subprocess.TimeoutExpired):
        raise Refused("EXTERNAL_UNIT_UNAVAILABLE") from None


def _read_kernel_file(path: Path, limit: int, code: str) -> bytes:
    """Read one procfs/cgroupfs file without following a replacement link."""
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        need(stat.S_ISREG(info.st_mode) and info.st_size <= limit, code)
        raw = os.read(descriptor, limit + 1)
        need(len(raw) <= limit, code)
        return raw
    except Refused:
        raise
    except FileNotFoundError:
        raise
    except OSError:
        raise Refused(code) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _proc_start_ticks(pid: int, *, root: Path = Path("/")) -> int | None:
    """Read Linux start ticks so PID reuse cannot masquerade as the old Agent."""
    need(type(pid) is int and pid > 1, "EXTERNAL_PID_INVALID")
    path = root / "proc" / str(pid) / "stat"
    try:
        raw = _read_kernel_file(path, 8192, "EXTERNAL_PID_INVALID")
    except FileNotFoundError:
        return None
    split = raw.rfind(b") ")
    need(split > 0 and raw[:split].startswith(str(pid).encode() + b" (") and
         len(raw[split + 2:].split()) >= 20, "EXTERNAL_PID_INVALID")
    start = raw[split + 2:].split()[19]
    need(start.isdigit(), "EXTERNAL_PID_INVALID")
    return int(start)


def _cgroup_empty(cgroup: str, *, root: Path = Path("/"), owner: int = 0) -> bool:
    """Inspect the exact cgroup-v2 unit subtree, including delegated children."""
    need(isinstance(cgroup, str) and EXTERNAL_AGENT_CGROUP.fullmatch(cgroup)
         is not None, "EXTERNAL_CGROUP_INVALID")
    mount = root / "sys/fs/cgroup"
    need((mount / "cgroup.controllers").is_file(), "EXTERNAL_CGROUP_UNAVAILABLE")
    current = mount
    for part in cgroup.lstrip("/").split("/"):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            # systemd normally removes the empty unit cgroup after stopping.
            return True
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and
             not stat.S_ISLNK(info.st_mode), "EXTERNAL_CGROUP_INVALID")
    stack = [current]
    seen = 0
    while stack:
        directory = stack.pop()
        seen += 1
        need(seen <= 128, "EXTERNAL_CGROUP_INVALID")
        processes = directory / "cgroup.procs"
        try:
            raw = _read_kernel_file(processes, 65536,
                                    "EXTERNAL_CGROUP_UNAVAILABLE")
        except FileNotFoundError:
            raise Refused("EXTERNAL_CGROUP_UNAVAILABLE") from None
        need(all(line.isdigit() for line in raw.splitlines()),
             "EXTERNAL_CGROUP_INVALID")
        if raw.strip():
            return False
        try:
            entries = tuple(directory.iterdir())
        except OSError:
            raise Refused("EXTERNAL_CGROUP_UNAVAILABLE") from None
        for entry in entries:
            try:
                info = entry.lstat()
            except OSError:
                raise Refused("EXTERNAL_CGROUP_UNAVAILABLE") from None
            need(not stat.S_ISLNK(info.st_mode), "EXTERNAL_CGROUP_INVALID")
            if stat.S_ISDIR(info.st_mode):
                need(info.st_uid == owner, "EXTERNAL_CGROUP_INVALID")
                stack.append(entry)
    return True


class ExternalAgentStopProof:
    """Read-only evidence that the exact pre-stop Agent is fully gone.

    A future writer must install a boot-safe start guard before stopping the
    service and call ``stopped`` immediately before every source switch.
    This object does not stop, mask, or start a service on its own.
    """

    def __init__(self, *, run=subprocess.run, root: Path = Path("/"),
                 owner: int = 0):
        self.run, self.root, self.owner = run, Path(root), owner
        properties = _external_unit_properties(run=self.run)
        need(properties["ActiveState"] == "active" and
             properties["SubState"] == "running" and
             properties["MainPID"].isdecimal() and
             int(properties["MainPID"]) > 1 and
             EXTERNAL_AGENT_CGROUP.fullmatch(properties["ControlGroup"])
             is not None and
             re.fullmatch(r"[0-9a-f]{32}", properties["InvocationID"])
             is not None, "EXTERNAL_UNIT_NOT_RUNNING")
        self.pid = int(properties["MainPID"])
        self.cgroup = properties["ControlGroup"]
        self.invocation_id = properties["InvocationID"]
        start = _proc_start_ticks(self.pid, root=self.root)
        need(start is not None, "EXTERNAL_PID_INVALID")
        self.start_ticks = start
        membership = _read_kernel_file(self.root / "proc" / str(self.pid) /
                                       "cgroup", 4096,
                                       "EXTERNAL_CGROUP_UNAVAILABLE")
        need(membership == f"0::{self.cgroup}\n".encode("ascii"),
             "EXTERNAL_CGROUP_INVALID")

    def stopped(self) -> bool:
        before = _external_unit_properties(run=self.run)
        if (before["ActiveState"] != "inactive" or
                before["SubState"] != "dead" or
                before["MainPID"] != "0" or
                before["ControlGroup"] not in ("", self.cgroup) or
                before["InvocationID"] != self.invocation_id):
            return False
        old_process = _proc_start_ticks(self.pid, root=self.root)
        if old_process == self.start_ticks:
            return False
        if not _cgroup_empty(self.cgroup, root=self.root,
                             owner=self.owner):
            return False
        after = _external_unit_properties(run=self.run)
        return (after["ActiveState"] == "inactive" and
                after["SubState"] == "dead" and
                after["MainPID"] == "0" and
                after["ControlGroup"] in ("", self.cgroup) and
                after["InvocationID"] == self.invocation_id)


def _agent_idle_peer(connection: socket.socket) -> tuple[int, int, int]:
    """Use kernel credentials from the connected socket, never protocol text."""
    need(sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"),
         "AGENT_IDLE_UNAVAILABLE")
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                    struct.calcsize("3i"))
        need(len(raw) == struct.calcsize("3i"), "AGENT_IDLE_PEER")
        return struct.unpack("3i", raw)
    except Refused:
        raise
    except (OSError, ValueError, struct.error):
        raise Refused("AGENT_IDLE_PEER") from None


def _agent_idle_line(connection: socket.socket, *, deadline: float,
                     limit: int = AGENT_IDLE_LINE_MAX) -> bytes:
    """Read a single bounded line with a wall-clock deadline."""
    raw = bytearray()
    while len(raw) < limit:
        remaining = deadline - time.monotonic()
        need(remaining > 0, "AGENT_IDLE_TIMEOUT")
        try:
            connection.settimeout(remaining)
            item = connection.recv(1)
        except socket.timeout:
            raise Refused("AGENT_IDLE_TIMEOUT") from None
        except OSError:
            raise Refused("AGENT_IDLE_CLOSED") from None
        need(item != b"", "AGENT_IDLE_CLOSED")
        raw.extend(item)
        if item == b"\n":
            return bytes(raw)
    raise Refused("AGENT_IDLE_PROTOCOL")


def _agent_idle_pairs(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, "AGENT_IDLE_PROTOCOL")
        value[key] = item
    return value


def _agent_idle_ack(raw: bytes, pid: int) -> str:
    if raw == b"BUSY 1\n":
        raise Refused("AGENT_IDLE_BUSY")
    try:
        value = json.loads(raw, object_pairs_hook=_agent_idle_pairs)
    except Refused:
        raise
    except (ValueError, UnicodeError, TypeError):
        raise Refused("AGENT_IDLE_PROTOCOL") from None
    need(isinstance(value, dict) and
         set(value) == AGENT_IDLE_FIELDS | {"protocol", "state", "pid", "epoch"} and
         type(value["protocol"]) is int and value["protocol"] == 1 and
         value["state"] == "idle" and
         type(value["pid"]) is int and value["pid"] == pid and
         isinstance(value["epoch"], str) and
         re.fullmatch(r"[0-9a-f]{32}", value["epoch"]) is not None and
         all(type(value[key]) is int and value[key] == 0 for key in AGENT_IDLE_FIELDS),
         "AGENT_IDLE_PROTOCOL")
    return value["epoch"]


class AgentIdleProof:
    """Hold the original Agent's idle ACK until its exact unit has stopped.

    This primitive neither stops the unit nor changes files. A future writer
    must hold its original-Hub lease and transaction locks independently, then
    call ``begin_stop`` before stopping the service and ``confirm_stopped``
    before switching any source. An EOF after begin_stop is accepted only when
    the exact cgroup/PID proof confirms the service is fully stopped.
    """

    def __init__(self, stop_proof: ExternalAgentStopProof, *,
                 socket_path: Path = AGENT_IDLE_SOCKET):
        need(isinstance(stop_proof, ExternalAgentStopProof), "AGENT_IDLE_REQUEST")
        self.stop_proof = stop_proof
        self.socket_path = Path(socket_path)
        self.connection: socket.socket | None = None
        self.endpoint_identity: tuple[int, int] | None = None
        self.uid: int | None = None
        self.gid: int | None = None
        self.epoch: str | None = None
        self.started: float | None = None
        self.last_pong: float | None = None
        self.stopping = False
        self.confirmed = False
        self.failed = False
        self.closed_during_stop = False
        self._stop = threading.Event()
        self._state_lock = threading.Lock()
        self._io_lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def _identity(self) -> tuple[int, int, int]:
        properties = _external_unit_properties(run=self.stop_proof.run)
        need(properties["ActiveState"] == "active" and
             properties["SubState"] == "running" and
             properties["MainPID"] == str(self.stop_proof.pid) and
             properties["ControlGroup"] == self.stop_proof.cgroup and
             properties["InvocationID"] == self.stop_proof.invocation_id and
             properties["User"] == "sovagrid" and
             properties["Group"] == "sovagrid" and
             _proc_start_ticks(self.stop_proof.pid,
                               root=self.stop_proof.root) == self.stop_proof.start_ticks,
             "AGENT_IDLE_IDENTITY")
        try:
            uid = pwd.getpwnam("sovagrid").pw_uid
            gid = grp.getgrnam("sovagrid").gr_gid
        except KeyError:
            raise Refused("AGENT_IDLE_IDENTITY") from None
        need(type(uid) is int and type(gid) is int and uid > 0 and gid > 0,
             "AGENT_IDLE_IDENTITY")
        return self.stop_proof.pid, uid, gid

    def _endpoint(self, uid: int, gid: int) -> tuple[int, int]:
        try:
            parent = self.socket_path.parent.lstat()
            endpoint = self.socket_path.lstat()
        except OSError:
            raise Refused("AGENT_IDLE_PATH") from None
        need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == uid and
             parent.st_gid == gid and stat.S_IMODE(parent.st_mode) == 0o700 and
             stat.S_ISSOCK(endpoint.st_mode) and endpoint.st_uid == uid and
             endpoint.st_gid == gid and stat.S_IMODE(endpoint.st_mode) == 0o600 and
             endpoint.st_nlink == 1, "AGENT_IDLE_PATH")
        return endpoint.st_dev, endpoint.st_ino

    def _ping(self) -> None:
        need(self.connection is not None and self.epoch is not None,
             "AGENT_IDLE_NOT_HELD")
        with self._io_lock:
            try:
                self.connection.settimeout(5)
                self.connection.sendall(b"PING 1\n")
            except OSError:
                raise Refused("AGENT_IDLE_CLOSED") from None
            response = _agent_idle_line(self.connection,
                                        deadline=time.monotonic() + 5, limit=64)
            need(response == b"PONG 1 " + self.epoch.encode("ascii") + b"\n",
                 "AGENT_IDLE_PROTOCOL")
        with self._state_lock:
            self.last_pong = time.monotonic()

    def _heartbeat(self) -> None:
        while not self._stop.wait(10):
            try:
                self._ping()
            except Refused as exc:
                stopped_at_close = False
                if self.stopping and str(exc) == "AGENT_IDLE_CLOSED":
                    try:
                        stopped_at_close = self.stop_proof.stopped()
                    except Exception:
                        pass
                with self._state_lock:
                    if stopped_at_close:
                        self.closed_during_stop = True
                    else:
                        self.failed = True
                return

    def acquire(self) -> "AgentIdleProof":
        need(self.connection is None and self._thread is None and
             not self._stop.is_set(), "AGENT_IDLE_REQUEST")
        need(sys.platform.startswith("linux") and os.geteuid() == 0,
             "AGENT_IDLE_UNAVAILABLE")
        pid, uid, gid = self._identity()
        endpoint_identity = self._endpoint(uid, gid)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(5)
            try:
                connection.connect(str(self.socket_path))
            except (ConnectionRefusedError, FileNotFoundError):
                raise Refused("AGENT_IDLE_BUSY") from None
            except OSError:
                raise Refused("AGENT_IDLE_PATH") from None
            need(_agent_idle_peer(connection) == (pid, uid, gid), "AGENT_IDLE_PEER")
            need(self._endpoint(uid, gid) == endpoint_identity and
                 self._identity() == (pid, uid, gid), "AGENT_IDLE_IDENTITY")
            try:
                connection.sendall(b"QUIESCE 1\n")
            except OSError:
                raise Refused("AGENT_IDLE_CLOSED") from None
            epoch = _agent_idle_ack(
                _agent_idle_line(connection,
                                 deadline=time.monotonic() + AGENT_IDLE_ACK_TIMEOUT), pid)
            need(self._identity() == (pid, uid, gid) and
                 self._endpoint(uid, gid) == endpoint_identity,
                 "AGENT_IDLE_IDENTITY")
            self.connection = connection
            self.epoch = epoch
            self.uid, self.gid = uid, gid
            self.endpoint_identity = endpoint_identity
            self.started = time.monotonic()
            self._ping()
            self._thread = threading.Thread(target=self._heartbeat, daemon=True,
                                            name="sovagrid-external-agent-idle")
            self._thread.start()
            self.assert_held()
            return self
        except BaseException:
            if self.connection is not None:
                self.close()
            else:
                connection.close()
            raise

    def assert_held(self) -> None:
        with self._state_lock:
            failed, pong = self.failed, self.last_pong
        need(not self.stopping and not failed and
             self.connection is not None and self._thread is not None and
             self._thread.is_alive() and self.started is not None and
             pong is not None and time.monotonic() - pong <= 25 and
             time.monotonic() - self.started < AGENT_IDLE_MAX_HOLD,
             "AGENT_IDLE_LOST")
        need(self._identity() == (self.stop_proof.pid, self.uid, self.gid) and
             self._endpoint(self.uid, self.gid) == self.endpoint_identity,
             "AGENT_IDLE_LOST")

    def begin_stop(self) -> None:
        self.assert_held()
        # A fresh reply closes the gap between the last background ping and
        # the caller's systemctl stop request.
        self._ping()
        self.assert_held()
        with self._state_lock:
            self.stopping = True

    def confirm_stopped(self) -> None:
        with self._state_lock:
            need(self.stopping and not self.failed and self.started is not None and
                 time.monotonic() - self.started < AGENT_IDLE_MAX_HOLD,
                 "AGENT_IDLE_LOST")
        need(self.stop_proof.stopped(), "AGENT_STOP_NOT_PROVEN")
        # The old process is gone. Its end of this exact connection must now
        # be closed; an inherited FD or a forged continued PONG is refused.
        assert self.connection is not None
        with self._io_lock:
            try:
                self.connection.settimeout(3)
                need(self.connection.recv(1) == b"", "AGENT_IDLE_STILL_OPEN")
            except socket.timeout:
                raise Refused("AGENT_IDLE_STILL_OPEN") from None
            except OSError:
                raise Refused("AGENT_IDLE_CLOSED") from None
        with self._state_lock:
            need(not self.failed, "AGENT_IDLE_LOST")
        need(self.stop_proof.stopped(), "AGENT_STOP_NOT_PROVEN")
        with self._state_lock:
            self.confirmed = True

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=6)
        if self.connection is not None:
            if not self.stopping and self._thread is not None and not self._thread.is_alive():
                try:
                    with self._io_lock:
                        self.connection.settimeout(2)
                        self.connection.sendall(b"RELEASE 1\n")
                        _agent_idle_line(self.connection,
                                         deadline=time.monotonic() + 2, limit=64)
                except (OSError, Refused):
                    pass
            self.connection.close()
            self.connection = None

    def __enter__(self) -> "AgentIdleProof":
        return self.acquire()

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()


def preview(archive_sha256: str, current_manifest_sha256: str) -> dict:
    need(os.geteuid() == 0, "ROOT")
    need(isinstance(archive_sha256, str) and SHA.fullmatch(archive_sha256) is not None and
         isinstance(current_manifest_sha256, str) and SHA.fullmatch(current_manifest_sha256) is not None,
         "HASH")
    with _promotion_lock():
        current, promoted, _commits, baseline = update.inspect()
        need(current == current_manifest_sha256 and
             promoted.get("phase") == "activated" and
             promoted.get("external_agent_preserved") is True and
             baseline == promoted.get("baseline_sha256"), "PROMOTION_CHANGED")
        external_sha, external_manifest, state = _external_snapshot()
        candidate_root, _candidate_commits = common.candidate_source(archive_sha256)
        candidate_sha, candidate_manifest = _manifest(candidate_root)
        # The candidate must be exactly the version already running the local
        # Hub. The original remote Hub is checked separately below.
        need(candidate_sha == current, "CANDIDATE_NOT_LOCAL_HUB")
        changes = _changes(external_manifest, candidate_manifest)
        changes.append({"path": "/opt/sovagrid-agent-installer/source-manifest.json",
                        "operation": "replace"})
        runtime = update._external_runtime()
        for name in ("sovagrid-agent.service", "sovagrid-agent-tunnel.service"):
            need(runtime[name]["active"] and runtime[name]["enabled"] and runtime[name]["pid"] > 1,
                 "EXTERNAL_RUNTIME")
        need(promotion.capture_external() == promotion._private_json(promotion.BASELINE) and
             update._hash_file(promotion.BASELINE) == baseline, "EXTERNAL_CHANGED")
        _original_hub_compatibility(state, candidate_sha)
        result = {"protocol": 1, "current_hub_manifest_sha256": current,
                  "candidate_manifest_sha256": candidate_sha,
                  "external_agent_manifest_sha256": external_sha,
                  "external_agent_preserved": True, "tunnel_active": True,
                  "source_paths_to_change": changes,
                  "future_metadata_paths": ["/var/lib/sovagrid-agent-enrollment/state.json",
                                            "/var/lib/sovagrid-promotion/baseline.json"],
                  "original_hub_compatibility": "verified_same_bundle",
                  "apply_supported": False,
                  "apply_blockers": ["EXTERNAL_AGENT_TRANSACTION_MISSING"]}
        raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        need(len(raw) <= MAX_OUTPUT, "OUTPUT_TOO_LARGE")
        return result


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args == ["recover"]:
        action = lambda: recover_pending()
    elif args == ["trial-start-guard"]:
        action = lambda: trial_start_guard()
    elif len(args) == 3 and args[0] in ("preview", "preflight"):
        action = lambda: (preview if args[0] == "preview" else preflight)(args[1], args[2])
    else:
        print("usage: external_agent_update.py {preview|preflight} ARCHIVE_SHA256 CURRENT_MANIFEST_SHA256 | recover | trial-start-guard", file=sys.stderr)
        return 2
    try:
        result = action()
    except Refused as exc:
        print("SG_EXTERNAL_AGENT_UPDATE_REFUSE:" + str(exc), file=sys.stderr)
        return 40
    except recovery.RecoveryError as exc:
        print("SG_EXTERNAL_AGENT_UPDATE_REFUSE:" + str(exc), file=sys.stderr)
        return 40
    except Exception:
        print("SG_EXTERNAL_AGENT_UPDATE_REFUSE:UNSAFE_STATE", file=sys.stderr)
        return 40
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
