# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Private, nonsecret checkpoints. A checkpoint never authorizes remote execution.

All readers and writers share a bounded OS lock. Resume still requires explicit
review and fresh remote ownership/source/policy checks by the orchestrator.
"""
from __future__ import annotations

import contextlib
import copy
import csv
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import uuid

from .core import _host, _port, _user
from .enrollment_protocol import (ProtocolError, validate_cas, validate_hub_trust,
                                  validate_registration, validate_stage_descriptor,
                                  validate_target)
from .theme import preference_file

MAX_BYTES = 32 * 1024
MAX_RECORDS = 128
LOCK_TIMEOUT = 2.0
PHASES = ("prepared", "transport_ready", "registered", "active")
DETAIL_FIELDS = {"protocol", "request_id", "name", "phase", "hub_connection", "target_connection",
                 "hub_endpoint", "bundle", "target", "registration", "hub_trust", "hub_authorized",
                 "cleanup_required", "cas", "stage"}
CONNECTION_FIELDS = {"host", "user", "port", "jump_host", "jump_user", "jump_port", "identity",
                     "jump_identity", "host_key_alias", "jump_host_key_alias", "local_port", "remote_port"}
SHA = re.compile(r"[0-9a-f]{64}\Z")


class EnrollmentJournalError(RuntimeError):
    """Fixed, user-readable error; never includes persisted values or OS output."""


class EnrollmentJournalConflict(EnrollmentJournalError):
    """The record changed, exists already, or the bounded store is full."""


def _require(condition):
    if not condition:
        raise EnrollmentJournalError("Неверные или небезопасные данные сохранённой установки.")


def _exact(value, fields):
    _require(type(value) is dict and set(value) == set(fields))


def _uuid(value):
    try:
        _require(isinstance(value, str) and str(uuid.UUID(value)) == value)
    except (ValueError, AttributeError):
        _require(False)
    return value


def _text(value, maximum):
    _require(isinstance(value, str) and 1 <= len(value) <= maximum and value.isprintable())
    # Strict field whitelists prevent credential fields; also refuse private
    # material disguised as an otherwise printable name or local path.
    _require("PRIVATE KEY" not in value and "-----BEGIN OPENSSH" not in value)
    return value


def _path(value):
    _text(value, 4096)
    _require(Path(value).is_absolute() and ".." not in Path(value).parts)
    return value


def _connection(value):
    _exact(value, CONNECTION_FIELDS)
    for key in ("host", "user"):
        _text(value[key], 253 if key == "host" else 64)
    _host(value["host"], "host"); _user(value["user"], "user")
    for key in ("jump_host", "host_key_alias", "jump_host_key_alias"):
        if value[key] is not None:
            _host(_text(value[key], 253), key)
    if value["jump_user"] is not None:
        _user(_text(value["jump_user"], 64), "jump_user")
    if value["jump_host"] is None:
        _require(all(value[key] is None for key in ("jump_user", "jump_identity", "jump_host_key_alias")))
    for key in ("identity", "jump_identity"):
        if value[key] is not None:
            _path(value[key])  # No exists(), resolve(), file access or SSH invocation.
    for key in ("port", "jump_port", "remote_port", "local_port"):
        _port(value[key], key, allow_zero=key == "local_port")


def _record(value):
    try:
        _exact(value, DETAIL_FIELDS | {"revision", "created_at", "updated_at"})
        _require(type(value["protocol"]) is int and value["protocol"] == 1)
        _uuid(value["request_id"])
        _require(_text(value["name"], 80) == value["name"].strip())
        _require(value["phase"] in PHASES)
        for key in ("revision", "created_at", "updated_at"):
            _require(type(value[key]) is int and 1 <= value[key] <= 2**63 - 1)
        _require(value["updated_at"] >= value["created_at"])
        _connection(value["hub_connection"]); _connection(value["target_connection"])
        endpoint = value["hub_endpoint"]
        _exact(endpoint, {"host", "port", "local_port"})
        _require(isinstance(endpoint["host"], str) and "%" not in endpoint["host"])
        address = ipaddress.ip_address(endpoint["host"])
        address = getattr(address, "ipv4_mapped", None) or address
        _require(not (address.is_loopback or address.is_unspecified or address.is_multicast))
        _port(endpoint["port"], "port"); _port(endpoint["local_port"], "local_port")
        _require(endpoint["local_port"] >= 1024)
        _exact(value["bundle"], {"path", "sha256"})
        _path(value["bundle"]["path"])
        _require(isinstance(value["bundle"]["sha256"], str) and SHA.fullmatch(value["bundle"]["sha256"]))
        target = value["target"]
        if target is not None:
            validate_target(target, allow_partial=True)
            _require(target["request_id"] == value["request_id"] and target["phase"] == value["phase"])
            _require(target["local_port"] is None or target["local_port"] == endpoint["local_port"])
        else:
            _require(value["phase"] == "prepared")
        if value["registration"] is not None:
            _require(target is not None)
            validate_registration(value["registration"], identity=target)
            _require(value["registration"]["name"] == value["name"])
        if value["phase"] == "active":
            _require(value["registration"] is not None and value["registration"]["state"] == "active")
        if value["hub_trust"] is not None:
            validate_hub_trust(value["hub_trust"])
        for key in ("hub_authorized", "cleanup_required"):
            _require(type(value[key]) is bool)
        _exact(value["cas"], {"hub", "target"})
        for cas in value["cas"].values():
            if cas is not None:
                validate_cas(cas)
        if value["stage"] is not None:
            validate_stage_descriptor(value["stage"])
            _require(value["stage"]["sha256"] == value["bundle"]["sha256"])
        return copy.deepcopy(value)
    except (ValueError, TypeError, AttributeError, KeyError, UnicodeError, ProtocolError):
        _require(False)


def _encoded(value):
    try:
        raw = (json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                          separators=(",", ":")) + "\n").encode("utf-8")
        _require(len(raw) <= MAX_BYTES)
        return raw
    except (ValueError, TypeError, UnicodeError):
        _require(False)


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _windows_sid():
    from .keygen import _windows_tool
    result = subprocess.run([_windows_tool("whoami.exe"), "/user", "/fo", "csv", "/nh"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
    _require(result.returncode == 0 and len(result.stdout) <= 4096)
    rows = list(csv.reader(io.StringIO(result.stdout.decode("utf-8", "replace"))))
    _require(len(rows) == 1 and len(rows[0]) == 2 and re.fullmatch(r"S-1-(?:[0-9]+-)*[0-9]+", rows[0][1]))
    return rows[0][1]


def _windows_protect(path, *, directory=False, sid=None):
    from .keygen import (KeyGenerationError, _protect_windows_directory,
                         _protect_windows_private_file, _windows_tool)
    try:
        if directory:
            sid = _protect_windows_directory(path)
        else:
            _protect_windows_private_file(path, sid)
        # An elevated Windows token can otherwise give new files the
        # Administrators owner SID instead of the interactive user's SID.
        result = subprocess.run([_windows_tool("icacls.exe"), str(path), "/setowner", "*" + sid],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        _require(result.returncode == 0)
        return sid
    except KeyGenerationError:
        raise EnrollmentJournalError("Не удалось ограничить доступ к журналу вашей учётной записью Windows.") from None


def _windows_acl(path, sid):
    """Verify owner plus one protected current-user full-control ACE, without locale parsing."""
    import ctypes as c
    from ctypes import wintypes as w
    api = c.WinDLL("advapi32", use_last_error=True)
    kernel = c.WinDLL("kernel32", use_last_error=True)
    api.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, w.DWORD, w.DWORD] + [c.POINTER(c.c_void_p)] * 5
    api.GetNamedSecurityInfoW.restype = w.DWORD
    api.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(w.LPWSTR)]
    api.ConvertSidToStringSidW.restype = w.BOOL
    api.GetSecurityDescriptorControl.argtypes = [c.c_void_p, c.POINTER(w.WORD), c.POINTER(w.DWORD)]
    api.GetSecurityDescriptorControl.restype = w.BOOL
    api.GetAce.argtypes = [c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)]
    api.GetAce.restype = w.BOOL
    kernel.LocalFree.argtypes = [c.c_void_p]; kernel.LocalFree.restype = c.c_void_p
    owner, group, dacl, sacl, descriptor = (c.c_void_p() for _ in range(5))
    code = api.GetNamedSecurityInfoW(str(path), 1, 0x5, c.byref(owner), c.byref(group), c.byref(dacl), c.byref(sacl), c.byref(descriptor))
    _require(code == 0 and descriptor.value and owner.value and dacl.value)
    def sid_text(pointer):
        text = w.LPWSTR()
        _require(api.ConvertSidToStringSidW(pointer, c.byref(text)))
        try:
            return text.value
        finally:
            kernel.LocalFree(c.cast(text, c.c_void_p))
    try:
        _require(sid_text(owner) == sid)
        control, revision = w.WORD(), w.DWORD()
        _require(api.GetSecurityDescriptorControl(descriptor, c.byref(control), c.byref(revision)) and control.value & 0x1000)
        # ACL header: revision/reserved/size/ACE count/reserved.
        _require(c.c_ushort.from_address(dacl.value + 4).value == 1)
        ace = c.c_void_p()
        _require(api.GetAce(dacl, 0, c.byref(ace)) and ace.value)
        _require(c.c_ubyte.from_address(ace.value).value == 0
                 and not c.c_ubyte.from_address(ace.value + 1).value & 0x10
                 and c.c_uint32.from_address(ace.value + 4).value == 0x1f01ff
                 and sid_text(c.c_void_p(ace.value + 8)) == sid)
    finally:
        kernel.LocalFree(descriptor)


class EnrollmentJournal:
    def __init__(self, root: Path | None = None):
        self.root = Path(root) if root is not None else preference_file().parent / "agent-enrollments"
        _require(self.root.is_absolute() and ".." not in self.root.parts)
        self._sid = None

    def _inspect(self, path, *, directory=False):
        info = path.lstat()
        _require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400)
        _require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        if os.name == "nt":
            if self._sid is None:
                self._sid = _windows_sid()
            _windows_acl(path, self._sid)
        else:
            _require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600))
        return info

    def _directory(self):
        # Reject symlink/reparse ancestors before creating any directory. POSIX
        # shared temporary roots are safe only with the root-owned sticky bit.
        current = Path(self.root.anchor)
        for part in self.root.parts[1:]:
            current /= part
            try:
                info = current.lstat()
            except FileNotFoundError:
                try:
                    current.mkdir(mode=0o700)
                except FileExistsError:
                    # Another Connect may have created the directory. Never
                    # change its ACL or permissions; inspect it below instead.
                    pass
                else:
                    if os.name == "nt":
                        self._sid = _windows_protect(current, directory=True)
                info = current.lstat()
            _require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                     and not getattr(info, "st_file_attributes", 0) & 0x400)
            if os.name != "nt":
                sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
                _require(info.st_uid in (0, os.getuid()) and (not info.st_mode & 0o022 or sticky))
        self._inspect(self.root, directory=True)

    def _open(self, path, flags=0):
        before = self._inspect(path)
        fd = os.open(path, flags | os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            after = os.fstat(fd)
            _require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
                     and stat.S_ISREG(after.st_mode) and after.st_nlink == 1)
            return fd
        except BaseException:
            os.close(fd)
            raise

    @contextlib.contextmanager
    def _locked(self):
        fd = None
        try:
            self._directory()
            lock = self.root / ".lock"
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
                if os.name == "nt":
                    _windows_protect(lock, sid=self._sid)
                os.write(fd, b"\0"); os.fsync(fd)
                self._inspect(lock)
            except FileExistsError:
                fd = self._open(lock, os.O_RDWR)
            deadline = time.monotonic() + LOCK_TIMEOUT
            while True:
                try:
                    if os.name == "nt":
                        import msvcrt
                        os.lseek(fd, 0, os.SEEK_SET); msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except (BlockingIOError, OSError):
                    if time.monotonic() >= deadline:
                        raise EnrollmentJournalConflict("Другая копия Connect использует журнал установки.") from None
                    time.sleep(0.025)
            self._inspect(self.root, directory=True)
            yield
        except EnrollmentJournalError:
            raise
        except (OSError, ValueError, subprocess.SubprocessError):
            raise EnrollmentJournalError("Не удалось безопасно открыть журнал установки.") from None
        finally:
            if fd is not None:
                os.close(fd)  # Closing releases flock / Windows byte-range lock.

    def _read(self, request_id):
        path = self.root / (_uuid(request_id) + ".json")
        try:
            fd = self._open(path)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, "rb") as stream:
            _require(os.fstat(stream.fileno()).st_size <= MAX_BYTES)
            raw = stream.read(MAX_BYTES + 1)
        _require(len(raw) <= MAX_BYTES)
        try:
            value = _record(json.loads(raw, object_pairs_hook=_object))
        except (ValueError, UnicodeError, RecursionError):
            _require(False)
        _require(value["request_id"] == request_id)
        return value

    def _ids(self):
        result = []
        with os.scandir(self.root) as entries:
            for index, entry in enumerate(entries):
                _require(index < MAX_RECORDS + 32)
                if entry.name == ".lock" or entry.name.startswith(".enrollment-"):
                    continue
                _require(entry.name.endswith(".json"))
                result.append(_uuid(entry.name[:-5]))
                _require(len(result) <= MAX_RECORDS)
        return sorted(result)

    def _sync_directory(self):
        if os.name != "nt":
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def _write(self, value):
        raw = _encoded(value)
        path = self.root / (value["request_id"] + ".json")
        if os.path.lexists(path):
            self._inspect(path)
        fd, temporary = tempfile.mkstemp(prefix=".enrollment-", dir=self.root)
        try:
            if os.name == "nt":
                _windows_protect(Path(temporary), sid=self._sid)
            else:
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                fd = None
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            self._inspect(Path(temporary))
            if os.name == "nt":
                import ctypes
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.MoveFileExW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
                kernel.MoveFileExW.restype = ctypes.c_int
                _require(kernel.MoveFileExW(temporary, str(path), 0x1 | 0x8))
            else:
                os.replace(temporary, path)
            self._sync_directory()
        finally:
            if fd is not None:
                os.close(fd)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)

    @staticmethod
    def _revision(value):
        _require(type(value) is int and 1 <= value <= 2**63 - 1)

    def create(self, details):
        _exact(details, DETAIL_FIELDS)
        now = max(1, int(time.time()))
        value = _record(dict(details, revision=1, created_at=now, updated_at=now))
        _encoded(value)
        with self._locked():
            if self._read(value["request_id"]) is not None or len(self._ids()) >= MAX_RECORDS:
                raise EnrollmentJournalConflict("Установка уже сохранена или журнал заполнен.")
            self._write(value)
        return copy.deepcopy(value)

    def update(self, request_id, changes, expected_revision):
        _uuid(request_id); self._revision(expected_revision)
        _require(type(changes) is dict and set(changes) <= DETAIL_FIELDS)
        with self._locked():
            previous = self._read(request_id)
            if previous is None or previous["revision"] != expected_revision:
                raise EnrollmentJournalConflict("Запись установки изменилась. Обновите её перед продолжением.")
            current = _record(dict(previous, **changes, revision=expected_revision + 1,
                                   updated_at=max(previous["updated_at"], int(time.time()))))
            for key in ("protocol", "request_id", "hub_endpoint"):
                _require(current[key] == previous[key])
            _require(current["bundle"]["sha256"] == previous["bundle"]["sha256"])
            for side in ("hub_connection", "target_connection"):
                _require(all(current[side][key] == previous[side][key]
                             for key in CONNECTION_FIELDS - {"identity", "jump_identity"}))
            _require(PHASES.index(current["phase"]) >= PHASES.index(previous["phase"]))
            if previous["hub_trust"] is not None:
                _require(current["hub_trust"] == previous["hub_trust"])
            if previous["target"] is not None:
                _require(current["target"] is not None)
                for key in ("request_id", "enrollment_id", "server_id", "agent_token_sha256", "ssh_public_key", "ssh_key_fingerprint"):
                    if previous["target"][key] is not None:
                        _require(current["target"][key] == previous["target"][key])
            if previous["registration"] is not None:
                _require(current["registration"] is not None)
                for key in ("id", "server_id", "name", "created_at"):
                    _require(current["registration"][key] == previous["registration"][key])
            self._write(current)
        return copy.deepcopy(current)

    def load(self, request_id):
        _uuid(request_id)
        with self._locked():
            return self._read(request_id)

    def list(self):
        with self._locked():
            return [self._read(identifier) for identifier in self._ids()]

    def remove(self, request_id, expected_revision):
        _uuid(request_id); self._revision(expected_revision)
        with self._locked():
            value = self._read(request_id)
            if value is None or value["revision"] != expected_revision:
                raise EnrollmentJournalConflict("Запись установки изменилась. Обновите её перед удалением.")
            (self.root / (request_id + ".json")).unlink()
            self._sync_directory()
