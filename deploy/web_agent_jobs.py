#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Durable orchestration core for a future Hub-hosted Web Agent installer.

This module has no HTTP listener. A narrow host-side service must authenticate
its caller, create a headless SSH binding, and call these blocking methods on a
worker thread. Only the existing Connect EnrollmentJournal persists; passwords,
private keys and borrowed Hub bearer sessions remain in the live binding.
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
import fcntl
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid
from typing import Callable


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_BUNDLE_NAME = re.compile(r"source-([0-9a-f]{64})\.tar\.gz\Z")
_BEARER = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
_PHASES = frozenset({"prepared", "transport_ready", "registered", "active"})
_MAX_BUNDLE = 64 * 1024 * 1024
_LEASE_SECONDS = 600


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
        self._options_class = ConnectionOptions
        self._journal_error = EnrollmentJournalError
        self.journal = EnrollmentJournal(Path(journal_root))
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
        except Exception:
            if isinstance(binding, ControllerBinding):
                try:
                    self._close(binding)
                except JobError:
                    pass
            raise JobError("SSH_UNAVAILABLE") from None

    def _pending(self):
        return [row for row in self.journal.list() if row["phase"] != "active" or row["cleanup_required"]]

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
            pending = self._pending()
            if pending:
                raise JobError("RECOVERY_REQUIRED", pending[0]["request_id"])
            self._release()
            bundle_path = self._bundle()
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
            return [_public_record(record) for record in self.journal.list()]
        except self._journal_error:
            raise JobError("JOURNAL_UNAVAILABLE") from None

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
