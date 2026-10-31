#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Durable orchestration core for a future Hub-hosted Web Agent installer.

This module has no HTTP listener. A narrow host-side service must authenticate
its caller, create a headless SSH binding, and call these blocking methods on a
worker thread. The Connect EnrollmentJournal and completed-record audit persist;
passwords, private keys and borrowed Hub bearer sessions remain in the live binding.

Connect caps its recovery journal at 128 records. Before that cap is reached,
completed, cleanup-free enrollments beyond the most recent 64 are copied to a
private, hash-chained, append-only audit file and fsynced before their journal
records are removed. Incomplete jobs are never retired. This version caps the
audit file at 64 MiB, matching host backup; when full, a new preparation fails
before any remote write with ARCHIVE_FULL. Archived completions remain visible
through the audit file, while per-request installer status returns NOT_FOUND.
The list API includes every unfinished job and at most 32 recent completions
within a 24 KiB payload budget; older live journal entries remain addressable
by request ID until retired.
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid
from typing import Callable

from web_agent_target_ssh import HostKeyChanged


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_BUNDLE_NAME = re.compile(r"source-([0-9a-f]{64})\.tar\.gz\Z")
_BEARER = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
_PHASES = frozenset({"prepared", "transport_ready", "registered", "active"})
_MAX_BUNDLE = 64 * 1024 * 1024
_LEASE_SECONDS = 600
_COMPLETED_ARCHIVE = "completed-enrollments.jsonl"
_ARCHIVE_TAIL_BYTES = 128 * 1024
_ARCHIVE_MAX_BYTES = 64 * 1024 * 1024  # Matches the host-backup inventory limit.
_ZERO_SHA = "0" * 64
_MAX_LIST_ACTIVE = 32
_MAX_LIST_BYTES = 24 * 1024  # Leave room for the service's JSON envelope and newline.


class JobError(RuntimeError):
    """Fixed public error code; never format an SSH/Hub exception into a reply."""

    def __init__(self, code: str, request_id: str | None = None):
        self.code = code
        self.request_id = request_id
        super().__init__(code)


def _uuid(value: str) -> str:
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError
    except (TypeError, ValueError, AttributeError):
        raise JobError("INVALID_REQUEST_ID") from None
    return value


def _alias(fingerprint: str) -> str:
    """Bind the reviewed public key to Journal.target_connection.host_key_alias."""
    if not isinstance(fingerprint, str) or _FINGERPRINT.fullmatch(fingerprint) is None:
        raise JobError("INVALID_FINGERPRINT")
    try:
        digest = base64.b64decode(fingerprint[7:] + "=", validate=True)
    except (ValueError, TypeError):
        raise JobError("INVALID_FINGERPRINT") from None
    if len(digest) != 32 or "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=") != fingerprint:
        raise JobError("INVALID_FINGERPRINT")
    return "sg-" + base64.b32encode(digest).decode("ascii").rstrip("=").lower()


def _vendor():
    """Load only the pinned Connect runtime inside this Blueprint source root."""
    import sys
    root = Path(__file__).resolve().parents[1] / "vendor/connect"
    if not (root / "sovagrid_connect/agent_enrollment.py").is_file():
        raise JobError("RUNTIME_UNAVAILABLE")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        from sovagrid_connect.core import ConnectionOptions
        from sovagrid_connect.enrollment_journal import EnrollmentJournal, EnrollmentJournalError
    except ImportError:
        raise JobError("RUNTIME_UNAVAILABLE") from None
    for module in (sys.modules["sovagrid_connect.core"], sys.modules["sovagrid_connect.enrollment_journal"]):
        try:
            Path(module.__file__).resolve().relative_to(root)
        except (ValueError, TypeError, AttributeError):
            raise JobError("RUNTIME_UNAVAILABLE") from None
    return ConnectionOptions, EnrollmentJournal, EnrollmentJournalError


@dataclass(repr=False)
class ControllerBinding:
    """Factory result: an AgentEnrollment and its ephemeral target transport."""

    controller: object
    target_options: object
    close_transport: Callable[[], None]


@dataclass(repr=False)
class _Live:
    binding: ControllerBinding
    credential: object = field(repr=False)
    request_id: str | None
    expires_at: float
    expiry_timer: threading.Timer | None = field(default=None, repr=False)


def _public_record(record: dict) -> dict:
    target = record.get("target") or {}
    registration = record.get("registration") or {}
    phase = record.get("phase")
    if phase not in _PHASES:
        raise JobError("INVALID_JOURNAL")
    return {"protocol": 1, "request_id": _uuid(record.get("request_id")),
            "name": record.get("name"), "phase": phase,
            "revision": record.get("revision"),
            "created_at": record.get("created_at"), "updated_at": record.get("updated_at"),
            "cleanup_required": record.get("cleanup_required") is True,
            "server_id": target.get("server_id"),
            "registration_state": registration.get("state"),
            "recoverable": phase != "active" or record.get("cleanup_required") is True}


def _unique_json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate archive field")
        value[key] = item
    return value


class WebAgentJobs:
    """One mutating enrollment at a time; durable public state survives restart.

    ``controller_factory`` receives keyword-only ``target_options`` (already
    bound to the reviewed host-key alias), ``fingerprint``, ``credential``,
    ``journal`` and ``progress``. It returns ControllerBinding. The factory
    must pin OpenSSH to the exact reviewed key, keep secrets only in memory or
    root-owned tmpfs, and make close_transport idempotent.
    """

    def __init__(self, *, journal_root: Path, bundle_path: Path, bundle_sha256: str,
                 controller_factory: Callable[..., ControllerBinding],
                 root_check: Callable[[], bool] | None = None,
                 monotonic: Callable[[], float] = time.monotonic):
        ConnectionOptions, EnrollmentJournal, EnrollmentJournalError = _vendor()
        import sys
        max_records = sys.modules["sovagrid_connect.enrollment_journal"].MAX_RECORDS
        if type(max_records) is not int or max_records < 2:
            raise JobError("RUNTIME_UNAVAILABLE")
        self._options_class = ConnectionOptions
        self._journal_error = EnrollmentJournalError
        self.journal = EnrollmentJournal(Path(journal_root))
        self._journal_max_records = max_records
        self._bundle_path = Path(bundle_path)
        if (not self._bundle_path.is_absolute() or ".." in self._bundle_path.parts or
                not isinstance(bundle_sha256, str) or _SHA.fullmatch(bundle_sha256) is None or
                self._bundle_path.name != f"source-{bundle_sha256}.tar.gz"):
            raise JobError("INVALID_BUNDLE_PIN")
        self._bundle_sha256 = bundle_sha256
        if not callable(controller_factory):
            raise JobError("INVALID_FACTORY")
        self._factory = controller_factory
        self._root_check = root_check or (lambda: os.geteuid() == 0)
        self._monotonic = monotonic
        self._operation_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._live: _Live | None = None
        self._lock_path = self.journal.root / ".enrollment-web-mutation"

    def _root(self):
        if not self._root_check():
            raise JobError("ROOT_REQUIRED")

    def _bundle(self, path: Path | None = None, sha256: str | None = None) -> Path:
        selected = self._bundle_path if path is None else Path(path)
        digest_pin = self._bundle_sha256 if sha256 is None else sha256
        if (not selected.is_absolute() or ".." in selected.parts or
                selected.parent != self._bundle_path.parent or
                not isinstance(digest_pin, str) or _SHA.fullmatch(digest_pin) is None or
                selected.name != f"source-{digest_pin}.tar.gz"):
            raise JobError("SOURCE_UNTRUSTED")
        try:
            directory = selected.parent.lstat()
            if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid() or
                    stat.S_IMODE(directory.st_mode) != 0o700):
                raise JobError("SOURCE_UNTRUSTED")
            before = selected.lstat()
            descriptor = os.open(selected, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                if ((before.st_dev, before.st_ino) != (info.st_dev, info.st_ino) or
                        not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                        info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or
                        not 0 < info.st_size <= _MAX_BUNDLE):
                    raise JobError("SOURCE_UNTRUSTED")
                digest = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            if not hmac.compare_digest(digest.hexdigest(), digest_pin):
                raise JobError("SOURCE_UNTRUSTED")
        except OSError:
            raise JobError("SOURCE_UNTRUSTED") from None
        return selected

    @contextmanager
    def _exclusive(self):
        self._root()
        if not self._operation_lock.acquire(blocking=False):
            raise JobError("BUSY")
        descriptor = None
        try:
            # Journal performs its own owner/mode/ancestor checks and creates
            # the root directory before the global lock is opened there.
            self.journal.list()
            flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(self._lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                descriptor = os.open(self._lock_path, flags)
            info = os.fstat(descriptor)
            path_info = self._lock_path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or
                    (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)):
                raise JobError("UNSAFE_LOCK")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise JobError("BUSY") from None
            yield
        except JobError:
            raise
        except self._journal_error:
            raise JobError("JOURNAL_UNAVAILABLE") from None
        except (OSError, ValueError):
            raise JobError("UNSAFE_LOCK") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            self._operation_lock.release()

    @staticmethod
    def _wipe(credential):
        try:
            credential.wipe()
        except Exception:
            pass

    @contextmanager
    def _credential_guard(self, credential):
        if not callable(getattr(credential, "wipe", None)):
            raise JobError("INVALID_CREDENTIAL")
        try:
            yield
        except BaseException:
            with self._state_lock:
                retained = self._live is not None and self._live.credential is credential
            if not retained:
                self._wipe(credential)
            raise

    @staticmethod
    def _close(binding: ControllerBinding):
        failure = False
        try:
            binding.controller.close()
        except Exception:
            failure = True
        finally:
            try:
                binding.close_transport()
            except Exception:
                failure = True
        if failure:
            raise JobError("CLOSE_UNCERTAIN")

    def _release(self):
        with self._state_lock:
            live, self._live = self._live, None
        if live is not None:
            if live.expiry_timer is not None:
                live.expiry_timer.cancel()
            try:
                self._close(live.binding)
            finally:
                self._wipe(live.credential)

    def _schedule_expiry(self, live: _Live, seconds: float) -> None:
        timer = threading.Timer(seconds, self._expire_live, args=(live,))
        timer.daemon = True
        with self._state_lock:
            if self._live is not live:
                return
            if live.expiry_timer is not None:
                live.expiry_timer.cancel()
            live.expiry_timer = timer
        timer.start()

    def _expire_live(self, live: _Live) -> None:
        # An in-flight SSH call owns the operation lock; retry briefly after it
        # returns. A quiet reviewed job cannot retain its SSH secret forever.
        if not self._operation_lock.acquire(blocking=False):
            self._schedule_expiry(live, 1)
            return
        try:
            with self._state_lock:
                expired = self._live is live and self._monotonic() >= live.expires_at
            if expired:
                try:
                    self._release()
                except JobError:
                    pass
            elif self._live is live:
                self._schedule_expiry(live, max(0.01, live.expires_at - self._monotonic()))
        finally:
            self._operation_lock.release()

    def _binding(self, target_options, fingerprint, credential) -> ControllerBinding:
        alias = _alias(fingerprint)
        if not isinstance(target_options, self._options_class):
            raise JobError("INVALID_TARGET")
        try:
            options = target_options.validated()
        except (ValueError, TypeError, OSError):
            raise JobError("INVALID_TARGET") from None
        if options.host_key_alias not in (None, alias):
            raise JobError("HOST_KEY_MISMATCH")
        options = self._options_class(**{**asdict(options), "host_key_alias": alias}).validated()
        binding = None
        try:
            binding = self._factory(target_options=options, fingerprint=fingerprint,
                                    credential=credential, journal=self.journal, progress=lambda _message: None)
            if not isinstance(binding, ControllerBinding) or not callable(binding.close_transport):
                raise JobError("INVALID_FACTORY")
            effective = binding.target_options.validated()
            stable = set(asdict(options)) - {"identity", "jump_identity"}
            if any(getattr(effective, key) != getattr(options, key) for key in stable):
                raise JobError("INVALID_FACTORY")
            return binding
        except JobError:
            if isinstance(binding, ControllerBinding):
                try:
                    self._close(binding)
                except JobError:
                    pass
            raise
        except HostKeyChanged:
            if isinstance(binding, ControllerBinding):
                try:
                    self._close(binding)
                except JobError:
                    pass
            raise JobError("HOST_KEY_CHANGED") from None
        except Exception:
            if isinstance(binding, ControllerBinding):
                try:
                    self._close(binding)
                except JobError:
                    pass
            raise JobError("SSH_UNAVAILABLE") from None

    @staticmethod
    def _canonical(value) -> bytes:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":")).encode("utf-8")

    @classmethod
    def _archive_entry(cls, line: bytes, previous_sha: str | None = None,
                       sequence: int | None = None) -> dict:
        try:
            value = json.loads(line, object_pairs_hook=_unique_json_object)
            if (type(value) is not dict or set(value) != {"protocol", "sequence", "archived_at",
                    "record", "record_sha256", "previous_sha256", "entry_sha256"} or
                    type(value["protocol"]) is not int or value["protocol"] != 1 or
                    type(value["sequence"]) is not int or value["sequence"] < 1 or
                    type(value["archived_at"]) is not int or value["archived_at"] < 1 or
                    type(value["record"]) is not dict or
                    value["record"].get("phase") != "active" or
                    value["record"].get("cleanup_required") is not False or
                    _SHA.fullmatch(value["record_sha256"]) is None or
                    _SHA.fullmatch(value["previous_sha256"]) is None or
                    _SHA.fullmatch(value["entry_sha256"]) is None or
                    cls._canonical(value) != line or
                    hashlib.sha256(cls._canonical(value["record"])).hexdigest() != value["record_sha256"] or
                    hashlib.sha256(cls._canonical({key: item for key, item in value.items()
                                                  if key != "entry_sha256"})).hexdigest() != value["entry_sha256"] or
                    (previous_sha is not None and value["previous_sha256"] != previous_sha) or
                    (sequence is not None and value["sequence"] != sequence)):
                raise ValueError
            _uuid(value["record"].get("request_id"))
            return value
        except (ValueError, TypeError, KeyError, UnicodeError, OverflowError,
                RecursionError, JobError):
            raise JobError("ARCHIVE_UNSAFE") from None

    def _archive_fd(self, *, create: bool) -> tuple[int, bool]:
        directory = self._bundle_path.parent
        try:
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
                    stat.S_IMODE(info.st_mode) != 0o700):
                raise JobError("ARCHIVE_UNSAFE")
            path = directory / _COMPLETED_ARCHIVE
            existed = os.path.lexists(path)
            if not existed and not create:
                return -1, False
            flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
            if create:
                flags |= os.O_CREAT | (os.O_EXCL if not existed else 0)
            descriptor = os.open(path, flags, 0o600)
            if not existed:
                os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
            named = path.lstat()
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or
                    opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o600 or
                    (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
                os.close(descriptor)
                raise JobError("ARCHIVE_UNSAFE")
            return descriptor, not existed
        except OSError:
            raise JobError("ARCHIVE_UNSAFE") from None

    @classmethod
    def _archive_tail(cls, descriptor: int) -> dict | None:
        try:
            size = os.fstat(descriptor).st_size
            if size > _ARCHIVE_MAX_BYTES:
                raise JobError("ARCHIVE_UNSAFE")
            if size == 0:
                return None
            start = max(0, size - _ARCHIVE_TAIL_BYTES)
            os.lseek(descriptor, start, os.SEEK_SET)
            tail = os.read(descriptor, size - start)
            if len(tail) != size - start:
                raise JobError("ARCHIVE_UNSAFE")
            if not tail.endswith(b"\n"):
                last_newline = tail.rfind(b"\n")
                if last_newline < 0 and start:
                    raise JobError("ARCHIVE_UNSAFE")
                # A torn final append cannot have been followed by a journal
                # removal. Discard only this incomplete tail and retry it.
                new_size = start + last_newline + 1
                os.ftruncate(descriptor, new_size)
                os.fsync(descriptor)
                if new_size == 0:
                    return None
                tail = tail[:last_newline + 1]
            line = tail[:-1].rsplit(b"\n", 1)[-1]
            if not line:
                raise JobError("ARCHIVE_UNSAFE")
            return cls._archive_entry(line)
        except OSError:
            raise JobError("ARCHIVE_UNSAFE") from None

    def _archive_completed(self, record: dict) -> None:
        if record["phase"] != "active" or record["cleanup_required"]:
            raise JobError("ARCHIVE_UNSAFE")
        descriptor, created = self._archive_fd(create=True)
        try:
            previous = self._archive_tail(descriptor)
            record_sha = hashlib.sha256(self._canonical(record)).hexdigest()
            if previous is not None and previous["record"]["request_id"] == record["request_id"]:
                if previous["record_sha256"] != record_sha:
                    raise JobError("ARCHIVE_UNSAFE")
                return  # Crash after durable append, before journal removal.
            entry = {"protocol": 1, "sequence": previous["sequence"] + 1 if previous else 1,
                     "archived_at": max(1, int(time.time())), "record": record,
                     "record_sha256": record_sha,
                     "previous_sha256": previous["entry_sha256"] if previous else _ZERO_SHA}
            entry["entry_sha256"] = hashlib.sha256(self._canonical(entry)).hexdigest()
            line = self._canonical(entry) + b"\n"
            if len(line) > _ARCHIVE_TAIL_BYTES // 2:
                raise JobError("ARCHIVE_UNSAFE")
            if os.fstat(descriptor).st_size + len(line) > _ARCHIVE_MAX_BYTES:
                raise JobError("ARCHIVE_FULL")
            while line:
                written = os.write(descriptor, line)
                if written <= 0:
                    raise JobError("ARCHIVE_UNSAFE")
                line = line[written:]
            os.fsync(descriptor)
            if created:
                parent = os.open(self._bundle_path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
        except OSError:
            raise JobError("ARCHIVE_UNSAFE") from None
        finally:
            os.close(descriptor)

    def _retire_completed(self, rows: list[dict]) -> None:
        if len(rows) < self._journal_max_records - 1:
            return
        # Keep a recent installer history while guaranteeing room for new
        # installations. Recoverable records are checked before this method.
        retain = max(1, min(64, self._journal_max_records // 2))
        completed = sorted(rows, key=lambda row: (row["updated_at"], row["created_at"],
                                                  row["request_id"]))
        for record in completed[:max(0, len(rows) - retain)]:
            self._archive_completed(record)
            self.journal.remove(record["request_id"], record["revision"])

    def verify_completed_archive(self) -> dict:
        """Verify the whole private archive chain for backup or local audit."""
        with self._exclusive():
            descriptor, _created = self._archive_fd(create=False)
            if descriptor < 0:
                return {"records": 0, "last_sha256": _ZERO_SHA}
            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                with os.fdopen(os.dup(descriptor), "rb") as stream:
                    previous = _ZERO_SHA
                    count = 0
                    for line in stream:
                        if len(line) > _ARCHIVE_TAIL_BYTES // 2 or not line.endswith(b"\n"):
                            raise JobError("ARCHIVE_UNSAFE")
                        entry = self._archive_entry(line[:-1], previous, count + 1)
                        previous = entry["entry_sha256"]
                        count += 1
                return {"records": count, "last_sha256": previous}
            finally:
                os.close(descriptor)

    def _current(self, request_id: str, expected_revision: int) -> _Live:
        _uuid(request_id)
        if type(expected_revision) is not int or expected_revision < 1:
            raise JobError("INVALID_REVISION")
        with self._state_lock:
            live = self._live
        if live is None or live.request_id != request_id:
            raise JobError("RESUME_REQUIRED", request_id)
        if self._monotonic() >= live.expires_at:
            self._release()
            raise JobError("RESUME_REQUIRED", request_id)
        record = self.journal.load(request_id)
        if record is None:
            raise JobError("NOT_FOUND")
        if record["revision"] != expected_revision or live.binding.controller.record["revision"] != expected_revision:
            raise JobError("STALE_REVISION", request_id)
        return live

    def prepare(self, *, target_options, reviewed_fingerprint: str, credential, session_token: str,
                name: str, hub_host: str, hub_port: int, local_port: int) -> dict:
        with self._credential_guard(credential), self._exclusive():
            if not isinstance(session_token, str) or _BEARER.fullmatch(session_token) is None:
                raise JobError("AUTH_REQUIRED")
            rows = self.journal.list()
            pending = [row for row in rows if row["phase"] != "active" or row["cleanup_required"]]
            if pending:
                raise JobError("RECOVERY_REQUIRED", pending[0]["request_id"])
            self._release()
            bundle_path = self._bundle()
            self._retire_completed(rows)
            try:
                binding = self._binding(target_options, reviewed_fingerprint, credential)
            except Exception:
                self._wipe(credential)
                raise
            live = _Live(binding, credential, None, self._monotonic() + _LEASE_SECONDS)
            with self._state_lock:
                self._live = live
            try:
                preview = binding.controller.prepare(target_options=binding.target_options,
                    name=name, bundle=bundle_path, hub_host=hub_host, hub_port=hub_port,
                    local_port=local_port, session_token=session_token)
                record = preview["record"]
                live.request_id = _uuid(record["request_id"])
                live.expires_at = self._monotonic() + _LEASE_SECONDS
                self._schedule_expiry(live, _LEASE_SECONDS)
                return {**_public_record(record), "hub_fingerprint": preview["hub_fingerprint"],
                        "platform": preview["platform"], "source_commits": preview["source_commits"],
                        "writes": True, "activation_writes": False}
            except Exception:
                record = getattr(binding.controller, "record", None)
                request_id = record.get("request_id") if isinstance(record, dict) else None
                if request_id is None:
                    self._release()
                else:
                    live.request_id = _uuid(request_id)
                    live.expires_at = self._monotonic() + _LEASE_SECONDS
                    self._schedule_expiry(live, _LEASE_SECONDS)
                raise JobError("PREPARE_UNCERTAIN", request_id) from None

    def apply(self, request_id: str, expected_revision: int) -> dict:
        with self._exclusive():
            live = self._current(request_id, expected_revision)
            try:
                record = live.binding.controller.apply()
                return _public_record(record)
            except Exception:
                raise JobError("APPLY_UNCERTAIN", request_id) from None
            finally:
                self._release()

    def resume(self, request_id: str, *, target_options, reviewed_fingerprint: str,
               credential, session_token: str) -> dict:
        with self._credential_guard(credential), self._exclusive():
            _uuid(request_id)
            if not isinstance(session_token, str) or _BEARER.fullmatch(session_token) is None:
                raise JobError("AUTH_REQUIRED")
            record = self.journal.load(request_id)
            if record is None:
                raise JobError("NOT_FOUND")
            if record["phase"] == "active" and not record["cleanup_required"]:
                raise JobError("ALREADY_ACTIVE", request_id)
            if not hmac.compare_digest(record["target_connection"]["host_key_alias"] or "", _alias(reviewed_fingerprint)):
                raise JobError("HOST_KEY_MISMATCH", request_id)
            self._release()
            saved_bundle = record["bundle"]
            bundle_path = self._bundle(Path(saved_bundle["path"]), saved_bundle["sha256"])
            try:
                binding = self._binding(target_options, reviewed_fingerprint, credential)
            except Exception:
                self._wipe(credential)
                raise
            saved = record["target_connection"]
            options = binding.target_options
            if any(getattr(options, key) != saved[key] for key in
                   ("host", "user", "port", "jump_host", "jump_user", "jump_port", "host_key_alias", "jump_host_key_alias")):
                try:
                    self._close(binding)
                finally:
                    self._wipe(credential)
                raise JobError("TARGET_CHANGED", request_id)
            live = _Live(binding, credential, request_id, self._monotonic() + _LEASE_SECONDS)
            with self._state_lock:
                self._live = live
            try:
                preview = binding.controller.resume(request_id, session_token=session_token,
                    target_identity=options.identity, jump_identity=options.jump_identity,
                    bundle_path=bundle_path)
                live.expires_at = self._monotonic() + _LEASE_SECONDS
                self._schedule_expiry(live, _LEASE_SECONDS)
                return {**_public_record(preview["record"]),
                        "hub_fingerprint": preview["hub_fingerprint"],
                        "platform": preview["platform"], "source_commits": preview["source_commits"],
                        "writes": True, "activation_writes": False}
            except Exception:
                self._release()
                raise JobError("RESUME_UNCERTAIN", request_id) from None

    def cleanup(self, request_id: str, expected_revision: int) -> dict:
        with self._exclusive():
            live = self._current(request_id, expected_revision)
            try:
                outcome = live.binding.controller.cleanup()
                if outcome.get("removed") is True:
                    return {"protocol": 1, "request_id": request_id, "removed": True, "active": False}
                return {**_public_record(outcome["record"]), "removed": False, "active": True}
            except Exception:
                raise JobError("CLEANUP_UNCERTAIN", request_id) from None
            finally:
                self._release()

    def interrupt(self, request_id: str | None = None) -> dict:
        """Signal cancellation without waiting for a blocked SSH operation."""
        if request_id is not None:
            _uuid(request_id)
        with self._state_lock:
            live = self._live
        if live is None or request_id is not None and live.request_id != request_id:
            raise JobError("NOT_RUNNING")
        try:
            live.binding.controller.cancel()
        except Exception:
            raise JobError("INTERRUPT_UNCERTAIN", live.request_id) from None
        return {"protocol": 1, "request_id": live.request_id, "cancel_requested": True}

    def status(self, request_id: str) -> dict:
        try:
            record = self.journal.load(_uuid(request_id))
        except self._journal_error:
            raise JobError("JOURNAL_UNAVAILABLE") from None
        if record is None:
            raise JobError("NOT_FOUND")
        return _public_record(record)

    def list(self) -> list[dict]:
        try:
            records = self.journal.list()
        except self._journal_error:
            raise JobError("JOURNAL_UNAVAILABLE") from None
        pending = [_public_record(record) for record in records
                   if record["phase"] != "active" or record["cleanup_required"]]
        if len(self._canonical(pending)) > _MAX_LIST_BYTES:
            # Never silently hide a recoverable enrollment.
            raise JobError("JOURNAL_UNAVAILABLE")
        completed = sorted((record for record in records
                            if record["phase"] == "active" and not record["cleanup_required"]),
                           key=lambda row: (row["updated_at"], row["created_at"],
                                            row["request_id"]), reverse=True)
        result = pending
        for record in completed[:_MAX_LIST_ACTIVE]:
            candidate = result + [_public_record(record)]
            if len(self._canonical(candidate)) > _MAX_LIST_BYTES:
                break
            result = candidate
        return result

    def close(self):
        """Drop live credentials; durable unfinished records remain recoverable."""
        with self._state_lock:
            live = self._live
        if live is not None:
            try:
                live.binding.controller.cancel()
            except Exception:
                pass
        with self._operation_lock:
            self._release()
