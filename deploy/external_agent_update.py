#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Plan and coordinate a guarded update of a preserved external Agent.

A server with its own Hub has two independent Agents. The Hub-only updater
deliberately never adopts the original Agent. A separate, explicit transaction
requires the original Hub's command drain lease and the original Agent's idle
acknowledgement before changing its source. The read-only compatibility GET is
not such a lease.
"""

from __future__ import annotations

import contextlib
import copy
import errno
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
import tempfile
import threading
import time
import uuid

sys.dont_write_bytecode = True


SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_OUTPUT = 32768
MAX_CHANGES = 256
MAX_COMPATIBILITY_BODY = 4096
COMPATIBILITY_TIMEOUT = 5.0
SOURCE_PREFIX = "/opt/sovagrid-agent/"
MANIFEST_FILE = "/opt/sovagrid-agent-installer/source-manifest.json"
AGENT_UNIT_FILE = "/etc/systemd/system/sovagrid-agent.service"
RECOVERY_UNIT = "sovagrid-external-agent-recovery.service"
RECOVERY_UNIT_FILE = Path("/etc/systemd/system") / RECOVERY_UNIT
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
TRIAL_AGENT_FILES = frozenset((
    "sovagrid-agent/sovagrid_agent/__main__.py",
    "sovagrid-agent/sovagrid_agent/agent.py",
    "sovagrid-agent/sovagrid_agent/trial_gate.py",
    "sovagrid-agent/deploy/sovagrid-agent.service",
))


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
operation = _module("sovagrid_external_agent_operation", "external_agent_operation.py")
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
    """Trial supervisor's live Agent watchdog socket.

    Apply keeps the original Hub lease and old Agent idle ACK alive in its
    callbacks, proves the exact journal, and checks the Agent process identity.
    An active Agent cannot reach Hub until HELLO and PING 0 both succeed.
    """

    def __init__(self, journal_sha256: str, *, group: int, agent_uid: int,
                 journal_current, lease_active, agent_idle_proven,
                 agent_peer_allowed, directory: Path = TRIAL_WATCH_DIR,
                 owner: int = 0, committed_current=None):
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
        self.committed_current = committed_current or (lambda: False)
        self.started = time.monotonic()
        self.closed = threading.Event()
        self.listener: socket.socket | None = None
        self.active: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.socket_inode: int | None = None
        self.epoch_inode: int | None = None
        self.ready = threading.Event()
        self.last_ping: float | None = None
        self.ping_count = 0
        self.normal_ready = threading.Event()
        self.released = threading.Event()
        self.dispatch_ready = threading.Event()
        self.detached = threading.Event()
        self._state_lock = threading.Lock()
        self._promotion_nonce: str | None = None
        self._promotion_sent = False
        self._release_requested = False
        self._detach_requested = False

    def request_promotion(self) -> str:
        """Ask the exact trial Agent for a read-only normal configuration test."""
        with self._state_lock:
            need(self.ready.is_set() and not self.closed.is_set() and
                 self.active is not None and self.last_ping is not None and
                 time.monotonic() - self.last_ping < 3 and
                 self._promotion_nonce is None, "TRIAL_PROMOTION_NOT_READY")
            self._promotion_nonce = secrets.token_hex(16)
            return self._promotion_nonce

    def request_release(self) -> None:
        """Release dispatch only after the committed journal is durable."""
        with self._state_lock:
            committed = self.committed_current()
            need(type(committed) is bool and committed and
                 self.normal_ready.is_set() and self._promotion_sent and
                 self.active is not None and self.last_ping is not None and
                 time.monotonic() - self.last_ping < 3 and
                 not self._release_requested and not self.closed.is_set(),
                 "TRIAL_RELEASE_NOT_READY")
            self._release_requested = True

    def request_detach(self) -> None:
        """Detach the watchdog only after the same Agent starts normal dispatch."""
        with self._state_lock:
            committed = self.committed_current()
            need(type(committed) is bool and committed and
                 self.released.is_set() and self.dispatch_ready.is_set() and
                 self.active is not None and self.last_ping is not None and
                 time.monotonic() - self.last_ping < 3 and
                 not self._detach_requested and not self.closed.is_set(),
                 "TRIAL_DETACH_NOT_READY")
            self._detach_requested = True

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
            line = _watch_line(connection)
            need(self._eligible(pid, uid, gid), "TRIAL_WATCH_DENIED")
            with self._state_lock:
                nonce = self._promotion_nonce
                if nonce is not None and not self._promotion_sent:
                    need(line == f"PING {sequence}", "TRIAL_WATCH_PROTOCOL")
                    response = f"PROMOTE {sequence} {nonce}\n"
                    self._promotion_sent = True
                elif nonce is not None and line == f"PING {sequence} READY {nonce}":
                    need(not self.dispatch_ready.is_set(), "TRIAL_WATCH_PROTOCOL")
                    self.normal_ready.set()
                    if self._release_requested and not self.released.is_set():
                        committed = self.committed_current()
                        need(type(committed) is bool and committed,
                             "TRIAL_RELEASE_NOT_READY")
                        response = f"RELEASE {sequence} {nonce}\n"
                    else:
                        response = f"PONG {sequence}\n"
                elif nonce is not None and line == f"PING {sequence} ACTIVE {nonce}":
                    need(self.released.is_set(), "TRIAL_WATCH_PROTOCOL")
                    self.dispatch_ready.set()
                    if self._detach_requested:
                        committed = self.committed_current()
                        need(type(committed) is bool and committed,
                             "TRIAL_DETACH_NOT_READY")
                        response = f"DETACH {sequence} {nonce}\n"
                    else:
                        response = f"PONG {sequence}\n"
                else:
                    need(line == f"PING {sequence}" and
                         not self.normal_ready.is_set(), "TRIAL_WATCH_PROTOCOL")
                    response = f"PONG {sequence}\n"
                releasing = response.startswith("RELEASE ")
                detaching = response.startswith("DETACH ")
            connection.sendall(response.encode("ascii"))
            self.last_ping = time.monotonic()
            sequence += 1
            self.ping_count = sequence
            self.ready.set()
            if releasing:
                need(_watch_line(connection) == f"ACK RELEASE {nonce}",
                     "TRIAL_WATCH_PROTOCOL")
                self.released.set()
            if detaching:
                need(_watch_line(connection) == f"ACK DETACH {nonce}",
                     "TRIAL_WATCH_PROTOCOL")
                self.detached.set()
                self.close()
                return

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


def _exclusive_lock(path: Path) -> int:
    """Never wait behind a live supervisor from a systemd child process."""
    need(not path.is_symlink(), "LOCK_UNSAFE")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        common.validate_lock(os.fstat(descriptor))
        need(os.fstat(descriptor).st_nlink == 1, "LOCK_UNSAFE")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BaseException as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if isinstance(exc, BlockingIOError):
            raise Refused("BUSY") from None
        if isinstance(exc, Refused):
            raise
        raise Refused("LOCK_UNAVAILABLE") from None


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


def _external_snapshot_locked(enrollment) -> tuple[str, dict, dict]:
    """Validate an enrollment whose caller already holds its target lock."""
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


def _external_snapshot() -> tuple[str, dict, dict]:
    """Verify the installed helper, runtime, enrollment and active units."""
    enrollment = remote.Enrollment(executable=remote.TARGET_HELPER)
    with enrollment.locked("target", readonly=True):
        return _external_snapshot_locked(enrollment)


def _idle_endpoint_present() -> bool:
    """Inspect socket metadata only; status must never quiesce the Agent."""
    try:
        uid = pwd.getpwnam("sovagrid").pw_uid
        gid = grp.getgrnam("sovagrid").gr_gid
        parent = AGENT_IDLE_SOCKET.parent.lstat()
        endpoint = AGENT_IDLE_SOCKET.lstat()
    except (OSError, KeyError):
        return False
    return (stat.S_ISDIR(parent.st_mode) and parent.st_uid == uid and
            parent.st_gid == gid and stat.S_IMODE(parent.st_mode) == 0o700 and
            stat.S_ISSOCK(endpoint.st_mode) and endpoint.st_uid == uid and
            endpoint.st_gid == gid and stat.S_IMODE(endpoint.st_mode) == 0o600 and
            endpoint.st_nlink == 1)


def status() -> dict:
    """Return verified local manifest IDs without a candidate or secret data."""
    need(os.geteuid() == 0, "ROOT")
    with _promotion_lock():
        # An uncertain operation still needs a read-only status page. The
        # normal Hub-only writer continues to reject it until reconciliation.
        current, promoted, _commits, baseline = update.inspect(
            read_only_uncertain=True)
        hub_only = (promoted.get("phase") == "activated" and
                    promoted.get("external_agent_preserved") is True and
                    promoted.get("baseline_sha256") == baseline)
        result = {"protocol": 1, "hub_only": hub_only,
                  "current_hub_manifest_sha256": current,
                  "external_agent_manifest_sha256": None,
                  "idle_endpoint_present": False,
                  "live_idle_ack_verified": False}
        if hub_only:
            external_sha, _manifest_value, _state = _external_snapshot()
            result["external_agent_manifest_sha256"] = external_sha
            result["idle_endpoint_present"] = _idle_endpoint_present()
        return result


def _operation_unit_quiescent(request_id: str) -> None:
    """Prove that the one-shot worker cannot still be changing the Agent."""
    unit = "sovagrid-external-agent-apply@" + request_id + ".service"
    fields = ("Id", "ActiveState", "MainPID", "Job", "ControlGroup",
              "FragmentPath", "NeedDaemonReload")
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "show", unit,
             *("--property=" + field for field in fields), "--no-pager"],
            capture_output=True, timeout=5, check=False)
        need(result.returncode == 0 and len(result.stdout) <= 4096,
             "OPERATION_WORKER_BUSY")
        lines = result.stdout.decode("ascii").splitlines()
        pairs = [line.split("=", 1) for line in lines]
        need(all(len(pair) == 2 for pair in pairs), "OPERATION_WORKER_BUSY")
        values = dict(pairs)
        need(len(values) == len(pairs) and set(values) == set(fields) and
             values["Id"] == unit and
             values["ActiveState"] in ("inactive", "failed") and
             values["MainPID"] == "0" and values["Job"] in ("", "0") and
             values["FragmentPath"] == update.EXTERNAL_APPLY_UNIT and
             values["NeedDaemonReload"] == "no", "OPERATION_WORKER_BUSY")
        source_unit = Path(__file__).with_name("sovagrid-external-agent-apply@.service")
        installed_unit = Path(update.EXTERNAL_APPLY_UNIT)
        need(promotion._read_regular(installed_unit, 8192) ==
             promotion._read_regular(source_unit, 8192), "OPERATION_WORKER_BUSY")
        cgroup = values["ControlGroup"]
        if cgroup:
            expected = ("/sovagrid-external-agent-apply@" + request_id + ".service")
            need(cgroup.endswith(expected) and
                 re.fullmatch(r"/(?:[A-Za-z0-9_.:-]+/)*"
                              r"sovagrid-external-agent-apply@"
                              + re.escape(request_id) + r"\.service", cgroup) is not None,
                 "OPERATION_WORKER_BUSY")
            need(_cgroup_empty(cgroup, pattern=re.compile(
                 r"/(?:[A-Za-z0-9_.:-]+/)*sovagrid-external-agent-apply@"
                 + re.escape(request_id) + r"\.service\Z")),
                 "OPERATION_WORKER_BUSY")
    except Refused:
        raise
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        raise Refused("OPERATION_WORKER_BUSY") from None


def _only_uncertain_operation(request_id: str) -> dict:
    """A later ambiguous request would make the observed source ambiguous."""
    path = operation._record_dir(request_id)
    request = operation._request(path, request_id)
    current = operation._status(path, request_id)
    need(current["phase"] == "uncertain", "OPERATION_NOT_UNCERTAIN")
    entries = [item for item in operation.OPERATIONS.iterdir()
               if item.name != ".lock"]
    need(len(entries) <= 128, "OPERATION_STATE")
    for item in entries:
        try:
            identifier = operation._id(item.name)
        except operation.Refused:
            raise Refused("OPERATION_STATE") from None
        other = operation._record_dir(identifier)
        operation._request(other, identifier)
        status_value = operation._status(other, identifier)
        need(status_value["phase"] in
             (("uncertain",) if identifier == request_id else ("complete", "failed")),
             "OPERATION_AMBIGUOUS")
        if identifier != request_id:
            # A later completed request could have produced the observed
            # source. Ties also require manual review instead of a guess.
            need(status_value["updated_at"] < current["created_at"],
                 "OPERATION_AMBIGUOUS")
    return request


def reconcile(request_id: str) -> dict:
    """Resolve one uncertain request only from a healthy, fully settled host.

    This never retries apply or guesses from a journal. A pending journal,
    trial guard, other uncertain request, or ambiguous source leaves the
    operation uncertain for explicit host recovery and another inspection.
    """
    need(os.geteuid() == 0 and os.getegid() == 0 and
         sys.platform.startswith("linux"), "ROOT_LINUX")
    try:
        request_id = operation._id(request_id)
    except operation.Refused:
        raise Refused("OPERATION_ID") from None
    with contextlib.ExitStack() as locks:
        locks.callback(os.close, _exclusive_lock(update.PROMOTION_LOCK))
        locks.callback(os.close, _exclusive_lock(update.CANDIDATES / ".lock"))
        enrollment = remote.Enrollment(executable=remote.TARGET_HELPER)
        locks.enter_context(enrollment.locked("target", readonly=True))
        request = _only_uncertain_operation(request_id)
        _operation_unit_quiescent(request_id)
        current, promoted, _commits, baseline = update.inspect(
            read_only_uncertain=True)
        need(current == request["current_hub_manifest_sha256"] and
             promoted.get("phase") == "activated" and
             promoted.get("external_agent_preserved") is True and
             promoted.get("baseline_sha256") == baseline and
             request["external_agent_manifest_sha256"] != current,
             "OPERATION_SOURCE_CHANGED")
        transaction = recovery.Recovery(enrollment.files)
        need(transaction._load_journal() is None and
             transaction._load_committed_marker() is None and
             enrollment.files.inspect(recovery.TXN, directory=True, private=True,
                                      missing=True) is None and
             not any(os.path.lexists(name) for name in
                     (recovery.TRIAL_DROPIN, recovery.TRIAL_GATE_SOCKET,
                      TRIAL_WATCH_SOCKET, TRIAL_WATCH_EPOCH)),
             "OPERATION_RECOVERY_PENDING")
        external_sha, _source, _state = _external_snapshot_locked(enrollment)
        running = _external_unit_properties()
        pid = running["MainPID"]
        need(running["ActiveState"] == "active" and
             running["SubState"] == "running" and pid.isdecimal() and
             int(pid) > 1 and _proc_start_ticks(int(pid)) is not None and
             promotion.capture_external() == promotion._private_json(
                 promotion.BASELINE), "OPERATION_AGENT_UNHEALTHY")
        if external_sha == current:
            phase, error = "complete", None
        elif external_sha == request["external_agent_manifest_sha256"]:
            phase, error = "failed", "RECONCILED_ROLLBACK"
        else:
            raise Refused("OPERATION_SOURCE_CHANGED")
        _operation_unit_quiescent(request_id)
        path = operation._record_dir(request_id)
        try:
            operation._transition(path, request_id, frozenset(("uncertain",)),
                                  phase, error)
        except operation.Refused:
            raise Refused("OPERATION_STATE") from None
    return {"protocol": 1, "request_id": request_id, "phase": phase,
            "external_agent_manifest_sha256": external_sha}


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


@contextlib.contextmanager
def _projected_candidate_tree(candidate_root: Path, new_tree: dict[str, str],
                              transaction: recovery.Recovery, *,
                              staging_parent: Path | None = None,
                              owner: int = 0, group: int = 0):
    """Present exactly the Agent's installable files to Recovery.prepare.

    The signed bundle also contains tests and documentation, while Recovery's
    tree exchange accepts only the installed Agent projection. Keep the copy
    inside the root-only candidate area and discard it as soon as prepare has
    durably copied its own validated snapshot. A supervisor killed during
    prepare may leave an inert private directory; it is never executable.
    """
    parent = update.CANDIDATES if staging_parent is None else Path(staging_parent)
    try:
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and
             info.st_gid == group and stat.S_IMODE(info.st_mode) == 0o700,
             "PROJECTION_STAGING_UNSAFE")
    except OSError:
        raise Refused("PROJECTION_STAGING_UNSAFE") from None
    need(isinstance(new_tree, dict) and 1 <= len(new_tree) <= MAX_CHANGES and
         all(isinstance(name, str) and recovery.RELATIVE.fullmatch(name) is not None and
             all(part not in (".", "..") for part in name.split("/")) and
             isinstance(digest, str) and SHA.fullmatch(digest) is not None
             for name, digest in new_tree.items()), "PROJECTION_INVALID")
    total = 0
    with tempfile.TemporaryDirectory(prefix=".external-agent-projection-",
                                     dir=parent) as temporary:
        root = Path(temporary)
        created: set[Path] = set()
        for relative, expected in sorted(new_tree.items()):
            source = candidate_root / "sovagrid-agent" / relative
            try:
                current_source = candidate_root
                for part in ("sovagrid-agent", *Path(relative).parts[:-1]):
                    directory = current_source.lstat()
                    need(stat.S_ISDIR(directory.st_mode) and directory.st_uid == owner and
                         not directory.st_mode & 0o022, "CANDIDATE_CHANGED")
                    current_source /= part
                directory = current_source.lstat()
                need(stat.S_ISDIR(directory.st_mode) and directory.st_uid == owner and
                     not directory.st_mode & 0o022, "CANDIDATE_CHANGED")
                before = source.lstat()
                need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                     before.st_uid == owner and not before.st_mode & 0o022 and
                     0 < before.st_size <= 32 * 1024**2, "CANDIDATE_CHANGED")
                fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    opened = os.fstat(fd)
                    need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino) and
                         stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and
                         opened.st_uid == owner and not opened.st_mode & 0o022,
                         "CANDIDATE_CHANGED")
                    data = os.read(fd, 32 * 1024**2 + 1)
                finally:
                    os.close(fd)
            except OSError:
                raise Refused("CANDIDATE_CHANGED") from None
            total += len(data)
            need(len(data) == before.st_size and total <= 256 * 1024**2 and
                 hashlib.sha256(data).hexdigest() == expected, "CANDIDATE_CHANGED")
            destination = root / relative
            current = root
            for part in Path(relative).parts[:-1]:
                current /= part
                if current not in created:
                    current.mkdir(mode=0o755)
                    current.chmod(0o755)
                    created.add(current)
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(data)
                output.flush()
                os.fchmod(output.fileno(), 0o644)
                os.fsync(output.fileno())
        root.chmod(0o755)
        transaction._tree(str(root), new_tree)
        yield root


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


def _review_digest(archive_sha256: str, current_sha256: str,
                   external_sha256: str, baseline_sha256: str,
                   state: dict, changes: list[dict[str, str]]) -> str:
    """Bind one review to the exact source and enrollment transition."""
    payload = {"protocol": 1, "archive_sha256": archive_sha256,
               "current_hub_manifest_sha256": current_sha256,
               "external_agent_manifest_sha256": external_sha256,
               "baseline_sha256": baseline_sha256,
               "enrollment_sha256": hashlib.sha256(remote.encode(state)).hexdigest(),
               "source_paths_to_change": changes}
    return hashlib.sha256(remote.encode(payload)).hexdigest()


def _systemctl(*arguments: str, timeout: int = 30) -> None:
    try:
        result = subprocess.run(["/usr/bin/systemctl", *arguments],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=False)
        need(result.returncode == 0, "SYSTEMD_ACTION_FAILED")
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("SYSTEMD_ACTION_FAILED") from None


def _recovery_unit_ready(*, require_enabled: bool = True) -> None:
    """Prove the boot rollback unit is loaded and required by the Agent."""
    template = Path(__file__).with_name(RECOVERY_UNIT)
    try:
        info = RECOVERY_UNIT_FILE.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
             info.st_gid == 0 and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o644 and
             RECOVERY_UNIT_FILE.read_bytes() == template.read_bytes(),
             "BOOT_RECOVERY_UNAVAILABLE")
        if require_enabled:
            enabled = subprocess.run(["/usr/bin/systemctl", "is-enabled", "--quiet",
                                      RECOVERY_UNIT], stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, timeout=5, check=False)
            need(enabled.returncode == 0, "BOOT_RECOVERY_UNAVAILABLE")
        result = subprocess.run(["/usr/bin/systemctl", "show", EXTERNAL_AGENT_UNIT,
                                 RECOVERY_UNIT, "--property=Id", "--property=Requires",
                                 "--property=Before", "--property=FragmentPath",
                                 "--property=NeedDaemonReload", "--no-pager"],
                                capture_output=True, timeout=5, check=False)
        need(result.returncode == 0 and len(result.stdout) <= 16384,
             "BOOT_RECOVERY_UNAVAILABLE")
        sections = result.stdout.decode("utf-8").strip().split("\n\n")
        need(len(sections) == 2, "BOOT_RECOVERY_UNAVAILABLE")
        values = []
        for section in sections:
            pairs = [line.split("=", 1) for line in section.splitlines()]
            need(all(len(pair) == 2 for pair in pairs), "BOOT_RECOVERY_UNAVAILABLE")
            item = dict(pairs)
            need(len(item) == len(pairs) and item.get("NeedDaemonReload") == "no",
                 "BOOT_RECOVERY_UNAVAILABLE")
            values.append(item)
        agent, guard = values
        need(agent.get("Id") == EXTERNAL_AGENT_UNIT and
             agent.get("FragmentPath") == AGENT_UNIT_FILE and
             (not require_enabled or
              RECOVERY_UNIT in agent.get("Requires", "").split()) and
             guard.get("Id") == RECOVERY_UNIT and
             guard.get("FragmentPath") == str(RECOVERY_UNIT_FILE) and
             EXTERNAL_AGENT_UNIT in guard.get("Before", "").split(),
             "BOOT_RECOVERY_UNAVAILABLE")
    except Refused:
        raise
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        raise Refused("BOOT_RECOVERY_UNAVAILABLE") from None


def _enable_recovery_unit() -> None:
    _recovery_unit_ready(require_enabled=False)
    _systemctl("enable", RECOVERY_UNIT)
    _systemctl("daemon-reload")
    _recovery_unit_ready()


def _disable_recovery_unit() -> None:
    _systemctl("disable", RECOVERY_UNIT)
    _systemctl("daemon-reload")
    try:
        result = subprocess.run(["/usr/bin/systemctl", "is-enabled", "--quiet",
                                 RECOVERY_UNIT], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=5, check=False)
        need(result.returncode != 0, "BOOT_RECOVERY_STILL_ENABLED")
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("BOOT_RECOVERY_STILL_ENABLED") from None


def _new_metadata(candidate_root: Path, manifest: dict, state: dict,
                  old_manifest: dict, candidate_sha256: str,
                  baseline: dict) -> tuple[dict[str, str], dict[str, str], dict[str, bytes]]:
    old_projection = remote.Enrollment.installed_projection(old_manifest)
    new_projection = remote.Enrollment.installed_projection(manifest)
    old_tree = {name.removeprefix(SOURCE_PREFIX): digest
                for name, digest in old_projection.items()
                if name.startswith(SOURCE_PREFIX)}
    new_tree = {name.removeprefix(SOURCE_PREFIX): digest
                for name, digest in new_projection.items()
                if name.startswith(SOURCE_PREFIX)}
    projected = _project_target_state(state, old_manifest, manifest, candidate_sha256)
    source_manifest = promotion._read_regular(candidate_root / "sovagrid-bundle.json",
                                              512 * 1024)
    need(hashlib.sha256(source_manifest).hexdigest() == candidate_sha256,
         "CANDIDATE_CHANGED")
    raw = {
        recovery.META[0][0]: promotion._read_regular(candidate_root / remote.SELF_NAME,
                                                     1024 * 1024),
        recovery.META[1][0]: promotion._read_regular(
            candidate_root / "sovagrid-agent/deploy/sovagrid-agent.service", 65536),
        recovery.META[2][0]: source_manifest,
        recovery.META[3][0]: remote.encode(projected) + b"\n",
    }
    updated_baseline = copy.deepcopy(baseline)
    for path in (recovery.META[1][0], recovery.META[2][0], recovery.META[3][0]):
        need(path in updated_baseline["files"], "EXTERNAL_CHANGED")
        updated_baseline["files"][path]["sha256"] = hashlib.sha256(raw[path]).hexdigest()
    raw[recovery.META[4][0]] = remote.encode(updated_baseline) + b"\n"
    need(set(raw) == {name for name, _mode, _limit in recovery.META}, "META_INVALID")
    return old_tree, new_tree, raw


def _writer_request_id() -> str | None:
    value = os.environ.get("SOVAGRID_EXTERNAL_APPLY_REQUEST_ID")
    if value is None:
        return None
    try:
        need(str(uuid.UUID(value)) == value, "EXTERNAL_OPERATION_ID")
    except (ValueError, AttributeError):
        raise Refused("EXTERNAL_OPERATION_ID") from None
    return value


def _inspect_for_writer(request_id: str | None):
    if request_id is None:
        return update.inspect()
    try:
        need(type(request_id) is str and str(uuid.UUID(request_id)) == request_id,
             "EXTERNAL_OPERATION_ID")
    except (ValueError, AttributeError):
        raise Refused("EXTERNAL_OPERATION_ID") from None
    return update.inspect(external_apply_request_id=request_id)


def preflight(archive_sha256: str, current_manifest_sha256: str, *,
              external_apply_request_id: str | None = None) -> dict:
    """Validate the exact local source/state transition without writing it.

    The returned digest is only an exact review token. Apply rechecks all
    locks, bytes, enrollment state and original-Hub gates before a write.
    """
    earlier = (preview(archive_sha256, current_manifest_sha256)
               if external_apply_request_id is None else
               preview(archive_sha256, current_manifest_sha256,
                       external_apply_request_id=external_apply_request_id))
    with _promotion_lock():
        current, promoted, _commits, baseline = _inspect_for_writer(external_apply_request_id)
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
        need(_normal_activation_ready(after), "TRIAL_CAPABILITY_MISSING")
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
    review_sha256 = _review_digest(archive_sha256, current, external_sha,
                                   baseline, state, earlier["source_paths_to_change"])
    result = {**earlier, "candidate_agent_file_count": len(new),
              "archive_sha256": archive_sha256,
              "baseline_sha256": baseline,
              "enrollment_sha256": hashlib.sha256(remote.encode(state)).hexdigest(),
              "review_sha256": review_sha256,
              "metadata_paths_to_change": [MANIFEST_FILE,
                                           "/var/lib/sovagrid-agent-enrollment/state.json",
                                           "/var/lib/sovagrid-promotion/baseline.json"],
              "apply_supported": True,
              "apply_blockers": [],
              "live_gates_pending": ["ORIGINAL_HUB_AGENT_UPDATE_LEASE",
                                     "AGENT_IDLE_ACK", "TRIAL_FD_WATCHDOG"],
              "explicit_review_required": True}
    need(len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()) <= MAX_OUTPUT,
         "OUTPUT_TOO_LARGE")
    return result


def recover_pending() -> dict:
    """Boot-safe rollback entry point, ordered before the original Agent unit.

    A live supervisor may grant one trial start while it holds the transaction
    locks. Without that root socket, boot takes the normal locked rollback path.
    """
    need(os.geteuid() == 0, "ROOT")
    if _live_trial_permit("recover"):
        return {"protocol": 1, "recovered": False, "trial_authorized": True}
    with contextlib.ExitStack() as locks:
        locks.callback(os.close, _exclusive_lock(update.PROMOTION_LOCK))
        locks.callback(os.close, _exclusive_lock(update.CANDIDATES / ".lock"))
        enrollment = remote.Enrollment(executable=remote.TARGET_HELPER)
        locks.enter_context(enrollment.locked("target"))
        transaction = recovery.Recovery(enrollment.files)

        def stopped() -> bool:
            return _agent_stopped_for_recovery()

        changed = transaction.recover_pending(agent_stopped=stopped)
        if changed:
            subprocess.run(["/usr/bin/systemctl", "daemon-reload"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=30, check=True)
        need(transaction._load_journal() is None, "RECOVERY_PENDING")
        _cleanup_stale_trial_runtime(agent_stopped=stopped)
        _disable_recovery_unit()
    return {"protocol": 1, "recovered": changed}


def _agent_stopped_for_recovery() -> bool:
    """Accept a queued systemd start job only before its Agent process runs."""
    properties = _external_unit_properties(allow_reload=True)
    if (properties["ActiveState"] not in ("inactive", "failed", "activating") or
            properties["MainPID"] != "0"):
        return False
    cgroup = properties["ControlGroup"] or "/system.slice/sovagrid-agent.service"
    return _cgroup_empty(cgroup)


def _cleanup_stale_trial_runtime(*, agent_stopped,
                                 owner: int = 0, owner_group: int = 0,
                                 watch_group: int | None = None,
                                 watch_dir: Path = TRIAL_WATCH_DIR,
                                 gate_dir: Path = Path(recovery.TRIAL_GATE_DIR)) -> None:
    """Remove supervisor sockets left by SIGKILL after locked boot recovery.

    The caller must hold the promotion, candidate and enrollment locks, prove
    there is no trial journal, and only invoke this after a failed live trial
    permit. A listening socket or unexpected inode is never unlinked.
    """
    paths = ((Path(gate_dir), "trial.sock", 0o700, owner_group,
              (("trial.sock", "socket", 0o600, owner_group),)),
             (Path(watch_dir), "gate.sock", 0o710, watch_group,
              (("gate.sock", "socket", 0o660, watch_group),
               ("epoch.env", "regular", 0o600, owner_group))))
    present = any(os.path.lexists(directory / item[0])
                  for directory, _name, _mode, _group, items in paths
                  for item in items)
    if not present:
        return
    need(agent_stopped(), "TRIAL_RUNTIME_AGENT_RUNNING")
    properties = _external_unit_properties(allow_reload=True)
    need(properties["ActiveState"] in ("inactive", "failed", "activating") and
         properties["MainPID"] == "0", "TRIAL_RUNTIME_AGENT_RUNNING")
    if watch_group is None:
        try:
            watch_group = grp.getgrnam("sovagrid").gr_gid
        except KeyError:
            raise Refused("TRIAL_RUNTIME_PATH") from None
    verified: list[tuple[Path, os.stat_result, list[tuple[Path, os.stat_result]]]] = []
    for directory, _name, mode, group, items in paths:
        group = watch_group if group is None else group
        try:
            info = directory.lstat()
        except FileNotFoundError:
            need(not any(os.path.lexists(directory / item[0]) for item in items),
                 "TRIAL_RUNTIME_PATH")
            continue
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and
             info.st_gid == group and stat.S_IMODE(info.st_mode) == mode,
             "TRIAL_RUNTIME_PATH")
        entries: list[tuple[Path, os.stat_result]] = []
        for name, kind, file_mode, file_group in items:
            file_group = watch_group if file_group is None else file_group
            path = directory / name
            try:
                entry = path.lstat()
            except FileNotFoundError:
                continue
            need(entry.st_uid == owner and entry.st_gid == file_group and
                 entry.st_nlink == 1 and stat.S_IMODE(entry.st_mode) == file_mode and
                 (stat.S_ISSOCK(entry.st_mode) if kind == "socket" else
                  stat.S_ISREG(entry.st_mode) and entry.st_size <= 128),
                 "TRIAL_RUNTIME_PATH")
            if kind == "socket":
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.settimeout(0.2)
                    outcome = probe.connect_ex(str(path))
                need(outcome == errno.ECONNREFUSED, "TRIAL_RUNTIME_SOCKET_LIVE")
            entries.append((path, entry))
        verified.append((directory, info, entries))
    for directory, info, entries in verified:
        for path, entry in entries:
            current = path.lstat()
            need(current.st_ino == entry.st_ino and
                 current.st_mode == entry.st_mode and
                 current.st_uid == entry.st_uid and
                 current.st_gid == entry.st_gid, "TRIAL_RUNTIME_PATH")
            path.unlink()
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            need(os.fstat(descriptor).st_ino == info.st_ino, "TRIAL_RUNTIME_PATH")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _live_trial_permit(operation: str) -> bool:
    """Allow only a validated trial backed by a live one-use root gate."""
    enrollment = remote.Enrollment(executable=remote.TARGET_HELPER)
    transaction = recovery.Recovery(enrollment.files)
    journal = transaction._load_journal()
    if journal is None or journal["phase"] != "trial":
        return False
    need(_systemd_trial_guard_loaded(), "TRIAL_GATE_REQUIRED")
    digest = transaction.verify_trial_state()
    allowed = recovery.probe_trial_gate(operation, digest)
    return type(allowed) is bool and allowed


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

    No transaction is a normal service start. The live one-use root gate
    authorizes this pre-start step; the Agent's own watchdog closes the gap
    between ExecStartPre and ExecStart.
    """
    need(os.geteuid() == 0, "ROOT")
    if _live_trial_permit("start"):
        return {"protocol": 1, "trial": True, "allowed": True}
    with contextlib.ExitStack() as locks:
        locks.callback(os.close, _exclusive_lock(update.PROMOTION_LOCK))
        locks.callback(os.close, _exclusive_lock(update.CANDIDATES / ".lock"))
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
        raise Refused("TRIAL_GATE_REQUIRED")


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
    """In-memory renewable command/relay drain lease.

    This is intentionally not an Agent idle proof. A lost renewal is terminal
    even if a later HTTP request succeeds. A commit refreshes synchronously;
    the Agent watchdog checks the background renewal state without blocking.
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

    def valid(self) -> bool:
        """Check the background-renewed lease without blocking a 3s socket."""
        try:
            self.assert_held()
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


def _external_unit_properties(*, run=subprocess.run,
                              allow_reload: bool = False) -> dict[str, str]:
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
             (value["NeedDaemonReload"] == "no" or
              (allow_reload and value["NeedDaemonReload"] == "yes")),
             "EXTERNAL_UNIT_INVALID")
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


def _cgroup_empty(cgroup: str, *, root: Path = Path("/"), owner: int = 0,
                  pattern=EXTERNAL_AGENT_CGROUP) -> bool:
    """Inspect the exact cgroup-v2 unit subtree, including delegated children."""
    need(isinstance(cgroup, str) and pattern.fullmatch(cgroup)
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

    Apply installs a boot-safe start guard before stopping the service and
    calls ``stopped`` immediately before the source switch. This object does
    not stop, mask, or start a service on its own.
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

    This primitive neither stops the unit nor changes files. Apply holds its
    original-Hub lease and transaction locks independently, calls
    ``begin_stop`` before stopping, and confirms the exact stopped cgroup/PID
    before switching source. EOF alone is never an idle proof.
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
                    # The original unit is no longer required to remain
                    # inactive once confirm_stopped has proved its exact PID,
                    # cgroup and socket are gone. A delayed EOF must not
                    # invalidate that proof after the trial Agent starts.
                    if self.confirmed:
                        return
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
        self._stop.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=6)

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


def preview(archive_sha256: str, current_manifest_sha256: str, *,
            external_apply_request_id: str | None = None) -> dict:
    need(os.geteuid() == 0, "ROOT")
    need(isinstance(archive_sha256, str) and SHA.fullmatch(archive_sha256) is not None and
         isinstance(current_manifest_sha256, str) and SHA.fullmatch(current_manifest_sha256) is not None,
         "HASH")
    with _promotion_lock():
        current, promoted, _commits, baseline = _inspect_for_writer(external_apply_request_id)
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
        capable = _normal_activation_ready(candidate_manifest)
        result = {"protocol": 1, "current_hub_manifest_sha256": current,
                  "candidate_manifest_sha256": candidate_sha,
                  "external_agent_manifest_sha256": external_sha,
                  "external_agent_preserved": True, "tunnel_active": True,
                  "source_paths_to_change": changes,
                  "future_metadata_paths": ["/var/lib/sovagrid-agent-enrollment/state.json",
                                            "/var/lib/sovagrid-promotion/baseline.json"],
                  "original_hub_compatibility": "verified_same_bundle",
                  "apply_supported": capable,
                  "apply_blockers": ["EXTERNAL_AGENT_PREFLIGHT_REQUIRED" if capable else
                                     "TRIAL_CAPABILITY_MISSING"],
                  "explicit_review_required": True}
        raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        need(len(raw) <= MAX_OUTPUT, "OUTPUT_TOO_LARGE")
        return result


def _runtime_directory(path: Path, *, group: int, mode: int) -> None:
    need(path.parent == Path("/run") and os.geteuid() == 0,
         "TRIAL_RUNTIME_PATH")
    try:
        parent = path.parent.lstat()
        need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and
             not parent.st_mode & 0o022, "TRIAL_RUNTIME_PATH")
        if not path.exists() and not path.is_symlink():
            path.mkdir(mode=mode)
            os.chown(path, 0, group)
            os.chmod(path, mode)
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
             info.st_gid == group and stat.S_IMODE(info.st_mode) == mode,
             "TRIAL_RUNTIME_PATH")
    except Refused:
        raise
    except OSError:
        raise Refused("TRIAL_RUNTIME_PATH") from None


def _agent_fully_stopped(cgroup: str) -> bool:
    """Check the exact service and its cgroup, including after partial writes."""
    first = _external_unit_properties(allow_reload=True)
    if (first["ActiveState"] != "inactive" or first["SubState"] != "dead" or
            first["MainPID"] != "0" or
            first["ControlGroup"] not in ("", cgroup) or
            not _cgroup_empty(cgroup)):
        return False
    second = _external_unit_properties(allow_reload=True)
    return (second["ActiveState"] == "inactive" and
            second["SubState"] == "dead" and second["MainPID"] == "0" and
            second["ControlGroup"] in ("", cgroup))


def _trial_peer(pid: int, uid: int, gid: int, *, expected_uid: int,
                expected_gid: int, old: ExternalAgentStopProof,
                identity: dict, full: bool = False) -> bool:
    if uid != expected_uid or gid != expected_gid:
        return False
    if identity and not full:
        return (identity["pid"] == pid and
                _proc_start_ticks(pid) == identity["ticks"] and
                _read_kernel_file(Path("/proc") / str(pid) / "cgroup", 4096,
                                  "EXTERNAL_CGROUP_UNAVAILABLE") ==
                f"0::{old.cgroup}\n".encode("ascii"))
    props = _external_unit_properties()
    if (props["ActiveState"] != "active" or props["SubState"] != "running" or
            props["MainPID"] != str(pid) or props["ControlGroup"] != old.cgroup or
            props["InvocationID"] == old.invocation_id or
            props["User"] != "sovagrid" or props["Group"] != "sovagrid" or
            not _systemd_trial_guard_loaded()):
        return False
    ticks = _proc_start_ticks(pid)
    if ticks is None or _read_kernel_file(Path("/proc") / str(pid) / "cgroup", 4096,
                                          "EXTERNAL_CGROUP_UNAVAILABLE") != \
            f"0::{old.cgroup}\n".encode("ascii"):
        return False
    observed = {"pid": pid, "ticks": ticks, "invocation": props["InvocationID"]}
    if identity:
        return identity == observed
    identity.update(observed)
    return True


def _trial_journal_current(transaction, trial_sha256: str,
                           committed_sha256: str) -> str | None:
    journal = transaction._load_journal()
    if journal is None:
        return None
    item = transaction._read(recovery.JOURNAL, recovery.MAX_JOURNAL, mode=0o600)
    if item is None:
        return None
    actual = hashlib.sha256(item[0]).hexdigest()
    if ((journal["phase"] == "trial" and actual == trial_sha256) or
            (journal["phase"] == "committed" and actual == committed_sha256)):
        return trial_sha256
    return None


def _committed_journal_current(transaction, trial_sha256: str,
                               committed_sha256: str) -> bool:
    journal = transaction._load_journal()
    return (journal is not None and journal["phase"] == "committed" and
            _trial_journal_current(transaction, trial_sha256,
                                   committed_sha256) == trial_sha256)


def _repair_interrupted(transaction, cgroup: str, *, idle: AgentIdleProof,
                        lease: OriginalHubLease) -> str | None:
    """Finish a committed update or restore the old Agent before restart."""
    journal = transaction._load_journal()
    if journal is None:
        return None
    if not _agent_fully_stopped(cgroup):
        if journal["phase"] == "prepared":
            # Do not interrupt the old Agent without a fresh drain + idle ACK.
            _systemctl("daemon-reload")
            lease.assert_held(fresh=True)
            if not idle.stopping:
                idle.begin_stop()
        _systemctl("stop", EXTERNAL_AGENT_UNIT, timeout=60)
    need(_agent_fully_stopped(cgroup), "RECOVERY_REQUIRES_REVIEW")
    if journal["phase"] == "committed":
        transaction.finalize_committed()
        result = "new"
    else:
        transaction.recover_pending(agent_stopped=lambda: _agent_fully_stopped(cgroup))
        result = "old"
    _systemctl("daemon-reload")
    return result


def _normal_activation_ready(manifest: dict) -> bool:
    """Require the candidate's normal-dispatch and trial protocol files.

    These manifest entries are a static capability check, not live proof.
    Apply obtains the original Agent idle ACK and Hub lease separately and
    refuses before mutation when the old Agent lacks that protocol.
    """
    hashes = manifest.get("sha256") if isinstance(manifest, dict) else None
    return (isinstance(hashes, dict) and all(
        isinstance(hashes.get(path), str) and SHA.fullmatch(hashes[path]) is not None
        for path in TRIAL_AGENT_FILES))


def apply(archive_sha256: str, current_manifest_sha256: str,
          external_manifest_sha256: str, review_sha256: str) -> dict:
    """Apply one explicitly reviewed external-Agent transition.

    The Agent remains separate from the local Hub. Every mutable step is
    journaled before stop. A dead supervisor loses its in-memory trial gates;
    the required systemd recovery unit then rolls the new source back.
    """
    need(os.geteuid() == 0 and os.getegid() == 0 and
         sys.platform.startswith("linux"), "ROOT_LINUX")
    need(all(isinstance(item, str) and SHA.fullmatch(item) is not None
             for item in (archive_sha256, current_manifest_sha256,
                          external_manifest_sha256, review_sha256)), "HASH")
    own_request_id = _writer_request_id()
    review = (preflight(archive_sha256, current_manifest_sha256)
              if own_request_id is None else
              preflight(archive_sha256, current_manifest_sha256,
                        external_apply_request_id=own_request_id))
    need(review["external_agent_manifest_sha256"] == external_manifest_sha256 and
         review["review_sha256"] == review_sha256, "REVIEW_CHANGED")
    failure: Exception | None = None
    restart: str | None = None
    succeeded = False
    watch: TrialWatchServer | None = None
    with contextlib.ExitStack() as stack:
        stack.callback(os.close, _exclusive_lock(update.PROMOTION_LOCK))
        stack.callback(os.close, _exclusive_lock(update.CANDIDATES / ".lock"))
        enrollment = remote.Enrollment(executable=remote.TARGET_HELPER)
        stack.enter_context(enrollment.locked("target"))
        transaction = recovery.Recovery(enrollment.files)
        current, promoted, _commits, baseline_sha256 = _inspect_for_writer(own_request_id)
        need(current == current_manifest_sha256 and
             promoted.get("phase") == "activated" and
             promoted.get("external_agent_preserved") is True and
             promoted.get("baseline_sha256") == baseline_sha256,
             "PROMOTION_CHANGED")
        external_sha, before, state = _external_snapshot_locked(enrollment)
        need(external_sha == external_manifest_sha256, "EXTERNAL_CHANGED")
        candidate_root, _ = common.candidate_source(archive_sha256)
        candidate_sha, after = _manifest(candidate_root)
        need(candidate_sha == current, "CANDIDATE_NOT_LOCAL_HUB")
        old_projection = remote.Enrollment.installed_projection(before)
        new_projection = _candidate_agent_files(candidate_root, after)
        _installed_agent_tree(old_projection)
        need(old_projection.keys() <= new_projection.keys() and
             _normal_activation_ready(after),
             "TRIAL_CAPABILITY_MISSING")
        changes = _changes(before, after)
        changes.append({"path": MANIFEST_FILE, "operation": "replace"})
        need(_review_digest(archive_sha256, current, external_sha,
                            baseline_sha256, state, changes) == review_sha256,
             "REVIEW_CHANGED")
        baseline = promotion._private_json(promotion.BASELINE)
        need(promotion.capture_external() == baseline and
             update._hash_file(promotion.BASELINE) == baseline_sha256,
             "EXTERNAL_CHANGED")
        _original_hub_compatibility(state, candidate_sha)
        _recovery_unit_ready(require_enabled=False)
        old_tree, new_tree, new_meta = _new_metadata(candidate_root, after,
                                                       state, before, candidate_sha,
                                                       baseline)
        stop_proof = ExternalAgentStopProof()
        with OriginalHubLease(state, candidate_sha) as lease:
            with AgentIdleProof(stop_proof) as idle:
                try:
                    _enable_recovery_unit()
                    lease.assert_held(fresh=True)
                    idle.assert_held()
                    with _projected_candidate_tree(candidate_root, new_tree,
                                                   transaction) as prepared_tree:
                        transaction.prepare(candidate_tree=str(prepared_tree),
                                            old_tree=old_tree, new_tree=new_tree,
                                            new_meta=new_meta)
                    _systemctl("daemon-reload")
                    need(_systemd_trial_guard_loaded(), "TRIAL_GUARD_UNAVAILABLE")
                    lease.assert_held(fresh=True)
                    idle.begin_stop()
                    _systemctl("stop", EXTERNAL_AGENT_UNIT, timeout=60)
                    idle.confirm_stopped()
                    lease.assert_held(fresh=True)

                    def old_idle() -> bool:
                        return (idle.confirmed and not idle.failed and
                                idle.started is not None and
                                time.monotonic() - idle.started < AGENT_IDLE_MAX_HOLD and
                                _proc_start_ticks(stop_proof.pid) != stop_proof.start_ticks)

                    transaction._switch_under_quiescence(
                        agent_stopped=stop_proof.stopped,
                        remote_lease_active=lease.valid, agent_idle_ack=old_idle)
                    _systemctl("daemon-reload")
                    need(_systemd_trial_guard_loaded(), "TRIAL_GUARD_UNAVAILABLE")
                    switched = transaction._load_journal()
                    need(switched is not None and switched["phase"] == "switched",
                         "JOURNAL_INVALID")
                    trial_sha = hashlib.sha256(remote.encode({**switched,
                                                               "phase": "trial"}) + b"\n").hexdigest()
                    committed_sha = hashlib.sha256(remote.encode({**switched,
                                                                   "phase": "committed"}) + b"\n").hexdigest()
                    uid, gid = pwd.getpwnam("sovagrid").pw_uid, grp.getgrnam("sovagrid").gr_gid
                    _runtime_directory(Path(recovery.TRIAL_GATE_DIR), group=0, mode=0o700)
                    _runtime_directory(TRIAL_WATCH_DIR, group=gid, mode=0o710)
                    identity: dict = {}
                    gate = recovery.TrialGateServer(
                        trial_sha, lease_active=lease.valid,
                        agent_idle_proven=old_idle).start()
                    stack.callback(gate.close)
                    watch = TrialWatchServer(
                        trial_sha, group=gid, agent_uid=uid,
                        journal_current=lambda: _trial_journal_current(
                            transaction, trial_sha, committed_sha),
                        committed_current=lambda: _committed_journal_current(
                            transaction, trial_sha, committed_sha),
                        lease_active=lease.valid, agent_idle_proven=old_idle,
                        agent_peer_allowed=lambda pid, peer_uid, peer_gid: _trial_peer(
                            pid, peer_uid, peer_gid, expected_uid=uid,
                            expected_gid=gid, old=stop_proof, identity=identity)).start()
                    stack.callback(watch.close)

                    def supervisor_active() -> bool:
                        return (gate.thread is not None and gate.thread.is_alive() and
                                not gate.closed.is_set() and watch.thread is not None and
                                watch.thread.is_alive() and not watch.closed.is_set())

                    lease.assert_held(fresh=True)
                    transaction.begin_trial(
                        agent_stopped=stop_proof.stopped,
                        remote_lease_active=lease.valid,
                        supervisor_active=supervisor_active,
                        agent_idle_proven=old_idle)
                    need(transaction.trial_journal_sha256() == trial_sha,
                         "JOURNAL_CHANGED")
                    _systemctl("start", EXTERNAL_AGENT_UNIT, timeout=60)
                    need(gate.granted == {"recover", "start"} and
                         watch.ready.wait(20), "TRIAL_START_FAILED")
                    deadline = time.monotonic() + 15
                    while watch.ping_count < 3 and not watch.closed.is_set() and \
                            time.monotonic() < deadline:
                        time.sleep(0.2)

                    def trial_healthy() -> bool:
                        return (supervisor_active() and watch.normal_ready.is_set() and
                                watch.active is not None and
                                watch.ping_count >= 3 and watch.last_ping is not None and
                                time.monotonic() - watch.last_ping < 3 and
                                "pid" in identity and
                                _trial_peer(identity["pid"], uid, gid,
                                            expected_uid=uid, expected_gid=gid,
                                            old=stop_proof, identity=identity,
                                            full=True) and
                                _original_hub_compatibility(state, candidate_sha) is None)

                    watch.request_promotion()
                    need(watch.normal_ready.wait(120) and trial_healthy(),
                         "NORMAL_READINESS_FAILED")
                    lease.assert_held(fresh=True)
                    transaction.commit_trial(
                        agent_running=lambda: "pid" in identity and
                        _trial_peer(identity["pid"], uid, gid, expected_uid=uid,
                                    expected_gid=gid, old=stop_proof,
                                    identity=identity, full=True),
                        agent_healthy=trial_healthy,
                        remote_lease_active=lease.valid,
                        supervisor_active=supervisor_active,
                        agent_idle_proven=old_idle)
                    need(_trial_peer(identity["pid"], uid, gid,
                                     expected_uid=uid, expected_gid=gid,
                                     old=stop_proof, identity=identity,
                                     full=True), "TRIAL_AGENT_CHANGED")
                    watch.request_release()
                    need(watch.released.wait(10), "RELEASE_ACK_MISSING")
                    need(watch.dispatch_ready.wait(30) and
                         trial_healthy(), "NORMAL_DISPATCH_READY_MISSING")
                    lease.assert_held(fresh=True)
                    watch.request_detach()
                    need(watch.detached.wait(10), "DETACH_ACK_MISSING")
                    transaction.finalize_committed()
                    _systemctl("daemon-reload")
                    observed_sha, _manifest_value, _state = _external_snapshot_locked(enrollment)
                    running = _external_unit_properties()
                    need(observed_sha == current_manifest_sha256 and
                         running["ActiveState"] == "active" and
                         running["SubState"] == "running" and
                         running["MainPID"] == str(identity["pid"]) and
                         _proc_start_ticks(identity["pid"]) == identity["ticks"] and
                         promotion.capture_external() ==
                         promotion._private_json(promotion.BASELINE),
                         "POST_RELEASE_HEALTH_FAILED")
                    succeeded = True
                except Exception as exc:
                    failure = exc
                    try:
                        journal = transaction._load_journal()
                        if (journal is not None and journal["phase"] == "committed" and
                                watch is not None and watch.released.is_set()):
                            # Commit is durable. If the same Agent never proved
                            # normal dispatch and detached, stop it before
                            # removing the trial guard and retry normal start.
                            if not watch.detached.is_set():
                                _systemctl("stop", EXTERNAL_AGENT_UNIT, timeout=60)
                                need(_agent_fully_stopped(stop_proof.cgroup),
                                     "AGENT_STOP_UNPROVEN")
                                restart = "new"
                            transaction.finalize_committed()
                            _systemctl("daemon-reload")
                        else:
                            restart = _repair_interrupted(transaction,
                                                           stop_proof.cgroup,
                                                           idle=idle, lease=lease)
                    except Exception as repair_exc:
                        raise Refused("RECOVERY_REQUIRES_REVIEW") from repair_exc
                if transaction._load_journal() is None:
                    _disable_recovery_unit()
    if restart is not None:
        _systemctl("start", EXTERNAL_AGENT_UNIT, timeout=60)
        observed_sha, _manifest_value, _state = _external_snapshot()
        running = _external_unit_properties()
        need(observed_sha == (current_manifest_sha256 if restart == "new" else
                              external_manifest_sha256) and
             running["ActiveState"] == "active" and
             running["SubState"] == "running" and
             running["MainPID"].isdecimal() and int(running["MainPID"]) > 1 and
             promotion.capture_external() == promotion._private_json(promotion.BASELINE),
             "POST_RESTART_HEALTH_FAILED")
    if failure is not None:
        if isinstance(failure, Refused):
            raise failure
        raise Refused("APPLY_ROLLED_BACK") from failure
    need(succeeded, "APPLY_INCOMPLETE")
    return {"protocol": 1, "applied": True,
            "external_agent_manifest_sha256": current_manifest_sha256,
            "review_sha256": review_sha256}


def _safe_exception_marker(exc: Exception) -> str:
    """Expose only a code location for an otherwise opaque unexpected error."""
    try:
        names = {"external_agent_update.py": "update",
                 "external_agent_recovery.py": "recovery",
                 "remote_agent.py": "enrollment",
                 "remote_update_worker.py": "worker"}
        selected = None
        trace = exc.__traceback__
        while trace is not None:
            label = names.get(Path(trace.tb_frame.f_code.co_filename).name)
            function, line = trace.tb_frame.f_code.co_name, trace.tb_lineno
            if (label is not None and
                    re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", function) and
                    type(line) is int and 1 <= line <= 999999):
                selected = (label, function, line)
            trace = trace.tb_next
        kind = type(exc).__name__
        if selected is not None:
            label, function, line = selected
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", kind):
                return f"SG_EXTERNAL_AGENT_UPDATE_DIAGNOSTIC:{kind}:{label}:{function}:{line}"
    except Exception:
        pass
    return "SG_EXTERNAL_AGENT_UPDATE_DIAGNOSTIC:UNAVAILABLE"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args == ["status"]:
        action = lambda: status()
    elif len(args) == 2 and args[0] == "reconcile":
        action = lambda: reconcile(args[1])
    elif args == ["recover"]:
        action = lambda: recover_pending()
    elif args == ["trial-start-guard"]:
        action = lambda: trial_start_guard()
    elif len(args) == 3 and args[0] in ("preview", "preflight"):
        action = lambda: (preview if args[0] == "preview" else preflight)(args[1], args[2])
    elif len(args) == 5 and args[0] == "apply":
        action = lambda: apply(args[1], args[2], args[3], args[4])
    else:
        print("usage: external_agent_update.py status | reconcile REQUEST_UUID | {preview|preflight} ARCHIVE_SHA256 CURRENT_MANIFEST_SHA256 | apply ARCHIVE_SHA256 CURRENT_MANIFEST_SHA256 EXTERNAL_MANIFEST_SHA256 REVIEW_SHA256 | recover | trial-start-guard", file=sys.stderr)
        return 2
    try:
        result = action()
    except Refused as exc:
        print("SG_EXTERNAL_AGENT_UPDATE_REFUSE:" + str(exc), file=sys.stderr)
        return 40
    except recovery.RecoveryError as exc:
        print("SG_EXTERNAL_AGENT_UPDATE_REFUSE:" + str(exc), file=sys.stderr)
        return 40
    except operation.Refused:
        print("SG_EXTERNAL_AGENT_UPDATE_REFUSE:OPERATION_STATE", file=sys.stderr)
        return 40
    except Exception as exc:
        print(_safe_exception_marker(exc))
        print("SG_EXTERNAL_AGENT_UPDATE_REFUSE:UNSAFE_STATE", file=sys.stderr)
        return 40
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
