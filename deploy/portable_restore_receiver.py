#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Private, resumable five-artifact receiver for a pinned restore runner.

No uploaded backup member is executed. The runner is delivered independently
from a client-reviewed source release, outside every live SovaGrid path.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from datetime import datetime
from datetime import datetime
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
PROTOCOL = "sovagrid-portable-restore-target-v1"
ROOT = Path("/")
BASE = Path("/root/.sovagrid-restore")
UID, GID = 0, 0
MAX_CHUNK = 4 * 1024**2
MAX_CHUNKS = 8192
MAX_JSON = 2 * 1024**2
MAX_FRAME = 64 * 1024
MAX_PARTS = {"host_manifest": 64 * 1024, "host": 8 * 1024**3,
             "images_manifest": 4096, "images": 8 * 1024**3, "receipt": 8192}
ORDER = ("host_manifest", "host", "images_manifest", "images", "receipt")
ID = re.compile(r"[0-9a-f]{32}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
COMPONENTS = frozenset(("sovagrid-blueprint", "sovagrid-hub", "sovagrid-web", "sovagrid-agent", "sovagrid-vpn"))


class Refused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def _id(value):
    need(isinstance(value, str) and ID.fullmatch(value), "INVALID_OPERATION")
    return value


def _sha(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "INVALID_JSON")
        result[key] = value
    return result


def _parse(raw):
    try:
        return json.loads(raw, object_pairs_hook=_unique,
                          parse_constant=lambda _value: (_ for _ in ()).throw(Refused("INVALID_JSON")))
    except (ValueError, UnicodeError) as exc:
        raise Refused("INVALID_JSON") from exc


def _host(path):
    return ROOT / str(path).lstrip("/")


def _private(info, *, directory=False, nlinks=(1,)):
    need((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) and
         info.st_uid == UID and info.st_gid == GID and
         stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600) and
         (directory or info.st_nlink in nlinks), "UNSAFE_RECEIVER_STATE")


def _fingerprint(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _safe_open(path, *, directory=False):
    need(path.is_absolute() and path != Path("/"), "INVALID_PATH")
    descriptor = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, name in enumerate(path.parts[1:]):
            need(name not in ("", ".", ".."), "INVALID_PATH")
            last = index == len(path.parts) - 2
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                            (os.O_DIRECTORY if directory or not last else 0), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(child)
            need(info.st_uid == UID and info.st_gid == GID and not info.st_mode & 0o022,
                 "UNSAFE_RECEIVER_STATE")
            if not last:
                need(stat.S_ISDIR(info.st_mode), "UNSAFE_RECEIVER_STATE")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read(parent, name, limit=MAX_JSON):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        before = os.fstat(descriptor)
        _private(before)
        need(0 < before.st_size <= limit, "UNSAFE_RECEIVER_STATE")
        raw = bytearray()
        while len(raw) <= limit:
            block = os.read(descriptor, min(65536, limit + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        need(len(raw) == before.st_size and _fingerprint(before) == _fingerprint(os.fstat(descriptor)),
             "RECEIVER_STATE_CHANGED")
        return _parse(raw)
    finally:
        os.close(descriptor)


def _rename(source_fd, source, destination_fd, destination):
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    need(rename is not None, "ATOMIC_PUBLICATION_UNAVAILABLE")
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(source_fd, os.fsencode(source), destination_fd, os.fsencode(destination), 1):
        value = ctypes.get_errno()
        if value in (errno.EEXIST, errno.ENOTEMPTY):
            raise Refused("RECEIVER_DESTINATION_EXISTS")
        raise OSError(value, "receiver atomic publication failed")


def _write_all(descriptor, raw, offset=None):
    at = 0
    while at < len(raw):
        count = (os.write(descriptor, raw[at:]) if offset is None else
                 os.pwrite(descriptor, raw[at:], offset + at))
        need(count > 0, "RECEIVER_IO_FAILED")
        at += count


def _save(parent, name, value, *, initial=False):
    raw = _canonical(value)
    need(len(raw) <= MAX_JSON, "RECEIVER_STATE_LIMIT")
    if not initial:
        _read(parent, name)
    temporary = "." + name + "." + uuid.uuid4().hex + ".tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        os.fchmod(descriptor, 0o600)
        _private(os.fstat(descriptor))
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if initial:
        _rename(parent, temporary, parent, name)
    else:
        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
    os.fsync(parent)


def _directory(parent, name, *, create=False):
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        _private(os.fstat(descriptor), directory=True)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _operation(operation):
    _id(operation)
    for path in (Path("/root"), BASE):
        ancestor = _safe_open(path, directory=True)
        try:
            _private(os.fstat(ancestor), directory=True)
        finally:
            os.close(ancestor)
    descriptor = _safe_open(BASE / operation, directory=True)
    try:
        _private(os.fstat(descriptor), directory=True)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def installation_lock():
    need(os.geteuid() == UID, "ROOT_REQUIRED")
    run = _safe_open(Path("/run"), directory=True)
    descriptor = None
    try:
        descriptor = os.open("sovagrid-installation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                             0o600, dir_fd=run)
        _private(os.fstat(descriptor))
        need(os.fstat(descriptor).st_size == 0, "UNSAFE_INSTALLATION_LOCK")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused("BUSY") from exc
        need(not os.path.lexists(_host(Path("/var/lib/.sovagrid-host-restore-in-progress"))),
             "RESTORE_RECOVERY_REQUIRED")
        yield descriptor
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(run)


@contextmanager
def _locked(operation, *, mutation=False, shared=False):
    need(os.geteuid() == UID, "ROOT_REQUIRED")
    need(not mutation or not shared, "INVALID_RECEIVER_LOCK")
    with ExitStack() as stack:
        if mutation:
            stack.enter_context(installation_lock())
        parent = _operation(operation)
        stack.callback(os.close, parent)
        descriptor = os.open("receiver.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        stack.callback(os.close, descriptor)
        _private(os.fstat(descriptor))
        need(os.fstat(descriptor).st_size == 0, "UNSAFE_RECEIVER_STATE")
        try:
            fcntl.flock(descriptor, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused("BUSY") from exc
        yield parent


def _runner_metadata(parent, operation):
    record = _read(parent, "runner.json", 4096)
    need(isinstance(record, dict) and set(record) == {"protocol", "operation_id", "runner_bytes",
         "runner_archive_sha256", "runner_manifest_sha256", "dependencies_ready"} and
         record["protocol"] == "sovagrid-portable-restore-runner-v1" and record["operation_id"] == operation and
         type(record["runner_bytes"]) is int and 0 < record["runner_bytes"] <= 64 * 1024**2 and
         _sha(record["runner_archive_sha256"]) and _sha(record["runner_manifest_sha256"]) and
         type(record["dependencies_ready"]) is bool, "INVALID_RUNNER")
    return record


def verified_runner(operation):
    """Verify the independently pinned source map before loading siblings."""
    need(os.geteuid() == UID, "ROOT_REQUIRED")
    parent = _operation(operation)
    try:
        record = _runner_metadata(parent, operation)
        runner = os.open("runner", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            root_info = os.fstat(runner)
            need(root_info.st_uid == UID and root_info.st_gid == GID and
                 stat.S_IMODE(root_info.st_mode) in (0o700, 0o755), "INVALID_RUNNER")
            descriptor = os.open("sovagrid-bundle.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=runner)
            try:
                info = os.fstat(descriptor)
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == UID and
                     info.st_gid == GID and stat.S_IMODE(info.st_mode) == 0o644 and info.st_size <= 512 * 1024,
                     "INVALID_RUNNER")
                raw = os.read(descriptor, 512 * 1024 + 1)
                need(len(raw) == info.st_size and hashlib.sha256(raw).hexdigest() == record["runner_manifest_sha256"],
                     "RUNNER_HASH_MISMATCH")
            finally:
                os.close(descriptor)
            manifest = _parse(raw)
            need(isinstance(manifest, dict) and set(manifest) == {"format", "components", "sha256"} and manifest["format"] == 1 and
                 set(manifest["components"]) == COMPONENTS and isinstance(manifest["sha256"], dict) and
                 1 <= len(manifest["sha256"]) <= 4096, "INVALID_RUNNER")
            hashes = manifest["sha256"]
            allowed_dirs = set(COMPONENTS)
            for name, digest in hashes.items():
                need(isinstance(name, str) and len(name) <= 240 and re.fullmatch(
                    r"[A-Za-z0-9_.@-]+(?:/[A-Za-z0-9_.@-]+)*", name) and
                    all(part not in (".", "..") for part in name.split("/")) and
                    name.partition("/")[0] in COMPONENTS and _sha(digest), "INVALID_RUNNER")
                allowed_dirs.update(str(value) for value in Path(name).parents if str(value) != ".")
            actual, total = set(), 0
            def walk(folder, prefix):
                nonlocal total
                for name in os.listdir(folder):
                    relative = prefix + name
                    info = os.stat(name, dir_fd=folder, follow_symlinks=False)
                    need(info.st_uid == UID and info.st_gid == GID and not info.st_mode & 0o022,
                         "INVALID_RUNNER")
                    if stat.S_ISDIR(info.st_mode):
                        need(relative in allowed_dirs, "INVALID_RUNNER")
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=folder)
                        try:
                            walk(child, relative + "/")
                        finally:
                            os.close(child)
                    else:
                        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                             (relative in hashes or relative == "sovagrid-bundle.json") and
                             info.st_size <= 32 * 1024**2, "INVALID_RUNNER")
                        total += info.st_size
                        need(total <= 256 * 1024**2, "INVALID_RUNNER")
                        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=folder)
                        try:
                            need(_fingerprint(os.fstat(descriptor)) == _fingerprint(info), "RUNNER_CHANGED")
                            digest = _hash_fd(descriptor, info.st_size)
                            need(_fingerprint(os.fstat(descriptor)) == _fingerprint(info), "RUNNER_CHANGED")
                        finally:
                            os.close(descriptor)
                        if relative in hashes:
                            need(digest == hashes[relative], "RUNNER_HASH_MISMATCH")
                            actual.add(relative)
            walk(runner, "")
            need(actual == set(hashes), "INVALID_RUNNER")
        finally:
            os.close(runner)
        return _host(BASE / operation / "runner")
    finally:
        os.close(parent)


def _hash_fd(descriptor, count, *, offset=0):
    digest, position, deadline = hashlib.sha256(), offset, time.monotonic() + 1200
    while position < offset + count:
        need(time.monotonic() < deadline, "TIME_LIMIT")
        block = os.pread(descriptor, min(1024 * 1024, offset + count - position), position)
        need(bool(block), "RECEIVER_PART_CHANGED")
        digest.update(block)
        position += len(block)
    return digest.hexdigest()


def _validate_request(value, operation, runner):
    need(isinstance(value, dict) and set(value) == {"protocol", "operation_id", "archive_id",
         "runner_manifest_sha256", "runner_archive_sha256", "artifacts"} and
         value["protocol"] == PROTOCOL and value["operation_id"] == operation and
         isinstance(value["archive_id"], str) and ID.fullmatch(value["archive_id"]) and
         value["runner_manifest_sha256"] == runner["runner_manifest_sha256"] and
         value["runner_archive_sha256"] == runner["runner_archive_sha256"] and
         isinstance(value["artifacts"], dict) and set(value["artifacts"]) == set(MAX_PARTS), "INVALID_REQUEST")
    for name, part in value["artifacts"].items():
        need(isinstance(part, dict) and set(part) == {"bytes", "sha256"} and type(part["bytes"]) is int and
             0 < part["bytes"] <= MAX_PARTS[name] and _sha(part["sha256"]), "INVALID_REQUEST")
    return value


def _request(parent, operation):
    return _validate_request(_read(parent, "request.json", MAX_FRAME), operation,
                             _runner_metadata(parent, operation))


def load_request(operation):
    with _locked(operation, shared=True) as parent:
        return _request(parent, operation)


def _new_state(request):
    return {"protocol": PROTOCOL, "operation_id": request["operation_id"],
            "request_sha256": hashlib.sha256(_canonical(request)).hexdigest(), "registered": False,
            "intent": None, "registration": None,
            "parts": {part: {"received": 0, "chunks": [], "fingerprint": None, "complete": False} for part in ORDER}}


def _state(parent, request):
    state = _read(parent, "upload.json")
    need(isinstance(state, dict) and set(state) == {"protocol", "operation_id", "request_sha256", "registered",
         "intent", "registration", "parts"} and state["protocol"] == PROTOCOL and
         state["operation_id"] == request["operation_id"] and
         state["request_sha256"] == hashlib.sha256(_canonical(request)).hexdigest() and
         type(state["registered"]) is bool and isinstance(state["parts"], dict) and set(state["parts"]) == set(ORDER),
         "INVALID_UPLOAD_STATE")
    chunks = 0
    for name, part in state["parts"].items():
        need(isinstance(part, dict) and set(part) == {"received", "chunks", "fingerprint", "complete"} and
             type(part["received"]) is int and 0 <= part["received"] <= request["artifacts"][name]["bytes"] and
             isinstance(part["chunks"], list) and type(part["complete"]) is bool and
             part["complete"] == (part["received"] == request["artifacts"][name]["bytes"]) and
             (part["fingerprint"] is None if part["received"] == 0 else
              isinstance(part["fingerprint"], list) and len(part["fingerprint"]) == 5 and
              all(type(item) is int for item in part["fingerprint"])), "INVALID_UPLOAD_STATE")
        at = 0
        for record in part["chunks"]:
            need(isinstance(record, dict) and set(record) == {"offset", "length", "sha256"} and
                 type(record["offset"]) is int and record["offset"] == at and type(record["length"]) is int and
                 0 < record["length"] <= MAX_CHUNK and _sha(record["sha256"]), "INVALID_UPLOAD_STATE")
            at += record["length"]
        need(at == part["received"], "INVALID_UPLOAD_STATE")
        chunks += len(part["chunks"])
    need(chunks <= MAX_CHUNKS, "INVALID_UPLOAD_STATE")
    intent = state["intent"]
    if intent is not None:
        need(isinstance(intent, dict) and set(intent) == {"part", "offset", "length", "sha256", "inode"} and
             intent["part"] in ORDER and type(intent["offset"]) is int and
             intent["offset"] == state["parts"][intent["part"]]["received"] and
             type(intent["length"]) is int and 0 < intent["length"] <= MAX_CHUNK and
             intent["offset"] + intent["length"] <= request["artifacts"][intent["part"]]["bytes"] and
             _sha(intent["sha256"]) and (intent["inode"] is None and intent["offset"] == 0 or
             isinstance(intent["inode"], list) and len(intent["inode"]) == 2 and
             all(type(item) is int for item in intent["inode"])),
             "INVALID_UPLOAD_STATE")
    registration = state["registration"]
    if registration is not None:
        need(isinstance(registration, dict) and set(registration) == {"parts", "image_folder"} and
             isinstance(registration["parts"], dict) and set(registration["parts"]) == set(ORDER), "INVALID_UPLOAD_STATE")
        for proof in registration["parts"].values():
            need(proof is None or isinstance(proof, dict) and set(proof) == {"inode", "parent", "published"} and
                 type(proof["published"]) is bool and isinstance(proof["parent"], list) and len(proof["parent"]) == 2 and
                 all(type(item) is int for item in proof["parent"]) and (proof["inode"] is None or
                 isinstance(proof["inode"], list) and len(proof["inode"]) == 2 and
                 all(type(item) is int for item in proof["inode"])), "INVALID_UPLOAD_STATE")
        proof = registration["image_folder"]
        need(proof is None or isinstance(proof, list) and len(proof) == 2 and
             all(type(item) is int for item in proof), "INVALID_UPLOAD_STATE")
    return state


def _public(request, state):
    return {"ok": True, "protocol": PROTOCOL, "operation_id": request["operation_id"],
            "archive_id": request["archive_id"], "request_sha256": state["request_sha256"],
            "registered": state["registered"], "max_chunk_bytes": MAX_CHUNK,
            "pending_chunk": ({key: value for key, value in state["intent"].items() if key != "inode"}
                              if state["intent"] else None),
            "artifacts": {name: {"received": state["parts"][name]["received"], "bytes": record["bytes"],
                             "sha256": record["sha256"], "complete": state["parts"][name]["complete"]}
                      for name, record in request["artifacts"].items()}}


def initialize(operation, request):
    with _locked(operation, mutation=True) as parent:
        request = _validate_request(request, operation, _runner_metadata(parent, operation))
        try:
            previous = _request(parent, operation)
        except FileNotFoundError:
            _save(parent, "request.json", request, initial=True)
        else:
            need(previous == request, "REQUEST_EXISTS")
        try:
            state = _state(parent, request)
        except FileNotFoundError:
            varlib = _safe_open(Path("/var/lib"), directory=True)
            try:
                required = sum(item["bytes"] for item in request["artifacts"].values())
                source_info, target_info = os.fstat(parent), os.fstat(varlib)
                source_free, target_free = os.fstatvfs(parent), os.fstatvfs(varlib)
                need(source_free.f_bavail * source_free.f_frsize >= required * (
                     2 if source_info.st_dev == target_info.st_dev else 1) + 512 * 1024**2 and
                     target_free.f_bavail * target_free.f_frsize >= required + 512 * 1024**2, "DISK_SPACE")
            finally:
                os.close(varlib)
            parts = _directory(parent, "parts", create=True)
            try:
                need(not os.listdir(parts), "UNSAFE_RECEIVER_STATE")
            finally:
                os.close(parts)
            state = _new_state(request)
            _save(parent, "upload.json", state, initial=True)
        return _public(request, state)


def _part(parent, name, state, *, pending=False):
    parts = _directory(parent, "parts")
    try:
        descriptor = os.open(name + ".data", os.O_RDWR | os.O_NOFOLLOW, dir_fd=parts)
    finally:
        os.close(parts)
    try:
        info = os.fstat(descriptor)
        _private(info)
        expected = state["parts"][name]
        if not pending:
            need(_fingerprint(info) == expected["fingerprint"], "RECEIVER_PART_CHANGED")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _prefix(descriptor, part):
    for chunk in part["chunks"]:
        need(_hash_fd(descriptor, chunk["length"], offset=chunk["offset"]) == chunk["sha256"],
             "RECEIVER_PART_CHANGED")


def _empty_part(parent, part, *, resuming):
    parts = _directory(parent, "parts")
    try:
        try:
            descriptor = os.open(part + ".data", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=parts)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(parts)
        except FileExistsError:
            need(resuming, "RECEIVER_PART_CHANGED")
            descriptor = os.open(part + ".data", os.O_RDWR | os.O_NOFOLLOW, dir_fd=parts)
        try:
            _private(os.fstat(descriptor))
            need(os.fstat(descriptor).st_size == 0, "RECEIVER_PART_CHANGED")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise
    finally:
        os.close(parts)


def receive(operation, part, offset, length, digest, payload):
    need(part in ORDER and type(offset) is int and offset >= 0 and type(length) is int and
         0 < length <= MAX_CHUNK and _sha(digest) and isinstance(payload, bytes) and len(payload) == length and
         hashlib.sha256(payload).hexdigest() == digest, "INVALID_CHUNK")
    with _locked(operation, mutation=True) as parent:
        request, state = _request(parent, operation), None
        state = _state(parent, request)
        need(not state["registered"] and state["registration"] is None, "UPLOAD_CLOSED")
        value = state["parts"][part]
        need(offset + length <= request["artifacts"][part]["bytes"], "INVALID_CHUNK")
        if state["intent"] is None and offset < value["received"]:
            need({"offset": offset, "length": length, "sha256": digest} in value["chunks"], "OFFSET_MISMATCH")
            descriptor = _part(parent, part, state)
            try:
                need(_hash_fd(descriptor, length, offset=offset) == digest, "RECEIVER_PART_CHANGED")
            finally:
                os.close(descriptor)
            return _public(request, state)
        need(offset == value["received"], "OFFSET_MISMATCH")
        descriptor = None
        try:
            intent = state["intent"]
            if intent is not None:
                need({key: intent[key] for key in ("part", "offset", "length", "sha256")} ==
                     {"part": part, "offset": offset, "length": length, "sha256": digest}, "PENDING_CHUNK")
                if intent["inode"] is None:
                    descriptor = _empty_part(parent, part, resuming=True)
                    info = os.fstat(descriptor)
                    intent["inode"] = [info.st_dev, info.st_ino]
                    _save(parent, "upload.json", state)
                else:
                    descriptor = _part(parent, part, state, pending=True)
                info = os.fstat(descriptor)
                need([info.st_dev, info.st_ino] == intent["inode"] and offset <= info.st_size <= offset + length,
                     "RECEIVER_PART_CHANGED")
                _prefix(descriptor, value)
                tail = os.pread(descriptor, info.st_size - offset, offset)
                need(tail == payload[:len(tail)], "RECEIVER_PART_CHANGED")
            else:
                need(sum(len(item["chunks"]) for item in state["parts"].values()) < MAX_CHUNKS, "CHUNK_LIMIT")
                if offset:
                    descriptor = _part(parent, part, state)
                else:
                    parts = _directory(parent, "parts")
                    try:
                        try:
                            os.stat(part + ".data", dir_fd=parts, follow_symlinks=False)
                        except FileNotFoundError:
                            pass
                        else:
                            raise Refused("RECEIVER_PART_CHANGED")
                    finally:
                        os.close(parts)
                state["intent"] = {"part": part, "offset": offset, "length": length,
                                   "sha256": digest, "inode": (None if descriptor is None else
                                      [os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino])}
                _save(parent, "upload.json", state)
                if descriptor is None:
                    descriptor = _empty_part(parent, part, resuming=False)
                    info = os.fstat(descriptor)
                    state["intent"]["inode"] = [info.st_dev, info.st_ino]
                    _save(parent, "upload.json", state)
            _write_all(descriptor, payload, offset)
            os.fsync(descriptor)
            value["received"] = offset + length
            value["chunks"].append({"offset": offset, "length": length, "sha256": digest})
            value["complete"] = value["received"] == request["artifacts"][part]["bytes"]
            if value["complete"]:
                need(_hash_fd(descriptor, value["received"]) == request["artifacts"][part]["sha256"],
                     "PART_HASH_MISMATCH")
            value["fingerprint"] = _fingerprint(os.fstat(descriptor))
            state["intent"] = None
            _save(parent, "upload.json", state)
            return _public(request, state)
        finally:
            if descriptor is not None:
                os.close(descriptor)


def request_status(operation):
    with _locked(operation, shared=True) as parent:
        request = _request(parent, operation)
        state = _state(parent, request)
        for name, part in state["parts"].items():
            if part["received"] == 0 and not (state["intent"] and state["intent"]["part"] == name):
                continue
            pending = bool(state["intent"] and state["intent"]["part"] == name)
            if pending and state["intent"]["inode"] is None:
                parts = _directory(parent, "parts")
                try:
                    try:
                        info = os.stat(name + ".data", dir_fd=parts, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    _private(info)
                    need(info.st_size == 0, "RECEIVER_PART_CHANGED")
                    continue
                finally:
                    os.close(parts)
            descriptor = _part(parent, name, state, pending=pending)
            try:
                if pending:
                    info, intent = os.fstat(descriptor), state["intent"]
                    need([info.st_dev, info.st_ino] == intent["inode"] and
                         part["received"] <= info.st_size <= part["received"] + intent["length"], "RECEIVER_PART_CHANGED")
                _prefix(descriptor, part)
                if part["complete"]:
                    need(_hash_fd(descriptor, part["received"]) == request["artifacts"][name]["sha256"],
                         "RECEIVER_PART_CHANGED")
            finally:
                os.close(descriptor)
        if state["registered"]:
            _check_registered(request, state)
        return _public(request, state)


def _targets(request):
    archive = request["archive_id"]
    return {"host_manifest": (Path("/var/lib/sovagrid-host-backups"), archive + ".manifest.json"),
            "host": (Path("/var/lib/sovagrid-host-backups"), archive + ".tar.gz"),
            "images_manifest": (Path("/var/lib/sovagrid-host-image-exports") / archive, "manifest.json"),
            "images": (Path("/var/lib/sovagrid-host-image-exports") / archive, "images.tar"),
            "receipt": (Path("/var/lib/sovagrid-host-image-exports") / archive, "receipt.json")}


def _destination_folder(path):
    varlib = _safe_open(Path("/var/lib"), directory=True)
    current = varlib
    try:
        for name in path.parts[3:]:
            child = _directory(current, name, create=True)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _check_registered(request, state):
    for part, (folder, name) in _targets(request).items():
        parent = _safe_open(folder, directory=True)
        descriptor = None
        try:
            _private(os.fstat(parent), directory=True)
            proof = state["registration"]["parts"][part]
            need(proof is not None and proof["published"], "INVALID_UPLOAD_STATE")
            info = os.fstat(parent)
            need([info.st_dev, info.st_ino] == proof["parent"], "RECEIVER_DESTINATION_CHANGED")
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            info = os.fstat(descriptor)
            _private(info)
            expected = request["artifacts"][part]
            need([info.st_dev, info.st_ino] == proof["inode"] and info.st_size == expected["bytes"] and
                 _hash_fd(descriptor, info.st_size) == expected["sha256"] and
                 _fingerprint(os.fstat(descriptor)) == _fingerprint(info), "RECEIVER_DESTINATION_CHANGED")
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)


def _copy_registered(parent, request, state, part):
    folder, filename = _targets(request)[part]
    destination = _destination_folder(folder)
    source = _part(parent, part, state)
    target = None
    try:
        publication = state["registration"]["parts"][part]
        temporary = ".receive-" + request["operation_id"] + "-" + part
        if publication is None:
            # No existing final or temporary path can be adopted, even with
            # equal bytes. The inode is saved before copying the first byte.
            for name in (filename, temporary):
                try:
                    os.stat(name, dir_fd=destination, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise Refused("RECEIVER_DESTINATION_EXISTS")
            directory = os.fstat(destination)
            publication = {"inode": None, "parent": [directory.st_dev, directory.st_ino],
                           "published": False}
            state["registration"]["parts"][part] = publication
            _save(parent, "upload.json", state)
        if publication["inode"] is None:
            # The durable creation intent precedes opening the private empty
            # file. An interruption here may leave only an empty owned file;
            # no byte is written until its exact inode has been synchronized.
            try:
                os.stat(filename, dir_fd=destination, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refused("RECEIVER_DESTINATION_CHANGED")
            try:
                target = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=destination)
                os.fchmod(target, 0o600)
            except FileExistsError:
                target = os.open(temporary, os.O_RDWR | os.O_NOFOLLOW, dir_fd=destination)
            info = os.fstat(target)
            _private(info)
            need(info.st_size == 0, "RECEIVER_DESTINATION_CHANGED")
            publication["inode"] = [info.st_dev, info.st_ino]
            os.fsync(target)
            os.fsync(destination)
            _save(parent, "upload.json", state)
        elif target is None:
            need(isinstance(publication, dict) and set(publication) == {"inode", "parent", "published"} and
                 type(publication["published"]) is bool, "INVALID_UPLOAD_STATE")
            info = os.fstat(destination)
            need([info.st_dev, info.st_ino] == publication["parent"], "RECEIVER_DESTINATION_CHANGED")
            present = []
            for name in (filename, temporary):
                try:
                    info = os.stat(name, dir_fd=destination, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                need([info.st_dev, info.st_ino] == publication["inode"], "RECEIVER_DESTINATION_CHANGED")
                present.append(name)
            need(len(present) == 1, "RECEIVER_DESTINATION_CHANGED")
            target = os.open(present[0], os.O_RDWR | os.O_NOFOLLOW, dir_fd=destination)
            if present[0] == filename:
                publication["published"] = True
        _private(os.fstat(target))
        info = os.fstat(target)
        expected = request["artifacts"][part]
        need(0 <= info.st_size <= expected["bytes"], "RECEIVER_DESTINATION_CHANGED")
        at = 0
        while at < info.st_size:
            count = min(1024 * 1024, info.st_size - at)
            need(os.pread(target, count, at) == os.pread(source, count, at), "RECEIVER_DESTINATION_CHANGED")
            at += count
        if publication["published"]:
            need(info.st_size == expected["bytes"], "RECEIVER_DESTINATION_CHANGED")
        else:
            while at < expected["bytes"]:
                block = os.pread(source, min(1024 * 1024, expected["bytes"] - at), at)
                need(bool(block), "RECEIVER_PART_CHANGED")
                _write_all(target, block, at)
                at += len(block)
            os.fsync(target)
            need(_hash_fd(target, expected["bytes"]) == expected["sha256"], "RECEIVER_DESTINATION_CHANGED")
            _rename(destination, temporary, destination, filename)
            os.fsync(destination)
            publication["published"] = True
        _save(parent, "upload.json", state)
    finally:
        if target is not None:
            os.close(target)
        os.close(source)
        os.close(destination)


def _module(name):
    spec = importlib.util.spec_from_file_location("_sovagrid_receiver_" + name, Path(__file__).with_name(name + ".py"))
    need(spec is not None and spec.loader is not None, "RUNNER_UNAVAILABLE")
    result = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = result
    spec.loader.exec_module(result)
    return result


def _verify_registration(request):
    restore = _module("host_restore")
    exporter = restore._portable_export_module()
    try:
        verified = exporter.verify(request["archive_id"], require_receipt=True)
        need(verified.get("verified") is True, "ARTIFACT_VERIFICATION_FAILED")
    except RuntimeError as exc:
        code = str(exc)
        raise Refused(code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code) else "ARTIFACT_VERIFICATION_FAILED") from None


def _verify_uploaded(parent, request, state):
    """Use the existing bounded archive parsers before any public input name.

    _record() itself needs published filenames. Its small JSON envelope is
    checked here; all host members, bundle bytes, image/config/RootFS and
    receipt bindings are parsed by the same pinned helpers used by verify().
    """
    restore = _module("host_restore")
    exporter = restore._portable_export_module()
    try:
        with ExitStack() as stack:
            descriptors = {}
            for part in ORDER:
                descriptors[part] = _part(parent, part, state)
                stack.callback(os.close, descriptors[part])
            raw = os.pread(descriptors["host_manifest"], 2049, 0)
            host = _parse(raw)
            need(len(raw) <= 2048 and isinstance(host, dict) and set(host) == {
                "protocol", "id", "created_at", "layout", "bytes", "files", "sha256", "source_manifest_sha256"} and
                host["protocol"] == restore.backup.PROTOCOL and host["id"] == request["archive_id"] and
                host["layout"] in ("full", "hub-only") and type(host["bytes"]) is int and
                host["bytes"] == request["artifacts"]["host"]["bytes"] and type(host["files"]) is int and
                0 < host["files"] <= restore.backup.MAX_FILES and
                host["sha256"] == request["artifacts"]["host"]["sha256"] and _sha(host["source_manifest_sha256"]) and
                isinstance(host["created_at"], str) and len(host["created_at"]) <= 40 and
                host["created_at"].endswith("+00:00"), "INVALID_MANIFEST")
            datetime.fromisoformat(host["created_at"])
            deadline = time.monotonic() + 1200
            restore._hash_archive(descriptors["host"], host, deadline=deadline)
            units = {}
            restore._inspect_tar(descriptors["host"], host, restore.backup._sources(host["layout"]),
                                 deadline=deadline, managed_unit_hashes=units)
            os.lseek(descriptors["images_manifest"], 0, os.SEEK_SET)
            images = exporter._manifest(descriptors["images_manifest"], request["archive_id"])
            need(images["host_archive_sha256"] == host["sha256"] and images["layout"] == host["layout"] and
                 images["source_manifest_sha256"] == host["source_manifest_sha256"] and
                 images["bytes"] == request["artifacts"]["images"]["bytes"] and
                 images["sha256"] == request["artifacts"]["images"]["sha256"], "HOST_ARCHIVE_MISMATCH")
            exporter._hash_tar(descriptors["images"], images, deadline=time.monotonic() + 1200)
            platforms, exported = {}, {}
            count = exporter._inspect_image_tar(descriptors["images"], images["images"],
                deadline=time.monotonic() + 1200, platforms=platforms,
                source_rootfs=images["rootfs_sha256"], exported_configs=exported)
            receipt = _parse(os.pread(descriptors["receipt"], 8193, 0))
            need(count == images["files"] and exported == images["exported_configs"] and
                 exporter._valid_portable_receipt(receipt, request["archive_id"], images), "INVALID_RECEIPT")
            if receipt["protocol"] == exporter.PORTABLE_RECEIPT:
                need({name: item["sha256"] for name, item in receipt["unit_states"].items()} == units,
                     "INVALID_RECEIPT")
    except RuntimeError as exc:
        code = str(exc)
        raise Refused(code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code) else "ARTIFACT_VERIFICATION_FAILED") from None


def register(operation):
    with _locked(operation, mutation=True) as parent:
        request = _request(parent, operation)
        state = _state(parent, request)
        need(state["intent"] is None and all(item["complete"] for item in state["parts"].values()), "UPLOAD_INCOMPLETE")
        for part in ORDER:
            descriptor = _part(parent, part, state)
            try:
                need(_hash_fd(descriptor, request["artifacts"][part]["bytes"]) == request["artifacts"][part]["sha256"],
                     "RECEIVER_PART_CHANGED")
            finally:
                os.close(descriptor)
        _verify_uploaded(parent, request, state)
        image_root = _destination_folder(Path("/var/lib/sovagrid-host-image-exports"))
        try:
            try:
                fcntl.flock(image_root, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Refused("BUSY") from exc
            if state["registration"] is None:
                for folder, name in _targets(request).values():
                    if folder.name == request["archive_id"]:
                        need(not os.path.lexists(_host(folder)), "RECEIVER_DESTINATION_EXISTS")
                    else:
                        need(not os.path.lexists(_host(folder) / name), "RECEIVER_DESTINATION_EXISTS")
                state["registration"] = {"parts": {part: None for part in ORDER}, "image_folder": None}
                _save(parent, "upload.json", state)
            image_folder = state["registration"]["image_folder"]
            try:
                artifact = os.open(request["archive_id"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=image_root)
            except FileNotFoundError:
                need(image_folder is None, "RECEIVER_DESTINATION_CHANGED")
                os.mkdir(request["archive_id"], 0o700, dir_fd=image_root)
                os.fsync(image_root)
                artifact = os.open(request["archive_id"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=image_root)
            try:
                _private(os.fstat(artifact), directory=True)
                info = os.fstat(artifact)
                if image_folder is None:
                    need(not os.listdir(artifact), "RECEIVER_DESTINATION_CHANGED")
                    state["registration"]["image_folder"] = [info.st_dev, info.st_ino]
                    _save(parent, "upload.json", state)
                else:
                    need([info.st_dev, info.st_ino] == image_folder, "RECEIVER_DESTINATION_CHANGED")
                allowed = {name for folder, name in _targets(request).values() if folder.name == request["archive_id"]}
                allowed.update(".receive-" + operation + "-" + part for part in ("images_manifest", "images", "receipt"))
                need(set(os.listdir(artifact)) <= allowed, "RECEIVER_DESTINATION_CHANGED")
            finally:
                os.close(artifact)
            for part in ORDER:
                _copy_registered(parent, request, state, part)
            _verify_registration(request)
            state["registered"] = True
            _save(parent, "upload.json", state)
            return _public(request, state)
        finally:
            os.close(image_root)


def dependencies(operation):
    runner = verified_runner(operation)
    # No operation lock is held while run.sh acquires installation lock.
    parent = _operation(operation)
    try:
        record = _runner_metadata(parent, operation)
    finally:
        os.close(parent)
    try:
        result = subprocess.run(["/bin/bash", str(runner / "sovagrid-blueprint/run.sh"),
            "--restore-dependencies-only", "--expected-source-manifest-sha256", record["runner_manifest_sha256"]],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800,
            check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"})
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refused("DEPENDENCIES_FAILED") from exc
    need(result.returncode == 0, "DEPENDENCIES_FAILED")
    with _locked(operation) as parent:
        record = _runner_metadata(parent, operation)
        record["dependencies_ready"] = True
        _save(parent, "runner.json", record)
    return {"ok": True, "protocol": PROTOCOL, "operation_id": operation,
            "runner_manifest_sha256": record["runner_manifest_sha256"],
            "runner_archive_sha256": record["runner_archive_sha256"], "dependencies_ready": True}


def dispatch_frame(operation, frame, stream):
    need(isinstance(frame, dict) and isinstance(frame.get("action"), str), "INVALID_FRAME")
    action = frame["action"]
    if action == "init":
        need(set(frame) == {"action", "request"}, "INVALID_FRAME")
        return initialize(operation, frame["request"])
    if action == "receive":
        need(set(frame) == {"action", "part", "offset", "length", "sha256"} and
             type(frame["length"]) is int and 0 < frame["length"] <= MAX_CHUNK, "INVALID_FRAME")
        remaining, raw = frame["length"], bytearray()
        while remaining:
            block = stream.read(remaining)
            need(bool(block), "INCOMPLETE_CHUNK")
            raw.extend(block)
            remaining -= len(block)
        return receive(operation, frame["part"], frame["offset"], frame["length"], frame["sha256"], bytes(raw))
    if action in ("status", "register", "deps"):
        need(set(frame) == {"action"}, "INVALID_FRAME")
        return {"status": request_status, "register": register, "deps": dependencies}[action](operation)
    if action in ("preview", "start", "operation-status", "recover", "retry"):
        verified_runner(operation)
        return _module("portable_restore_target").dispatch_frame(operation, frame)
    raise Refused("INVALID_FRAME")


def serve(operation, input_stream=None, output_stream=None):
    _id(operation)
    verified_runner(operation)
    input_stream = input_stream or sys.stdin.buffer
    output_stream = output_stream or sys.stdout.buffer
    while True:
        line = input_stream.readline(MAX_FRAME + 1)
        if not line:
            return
        failed = False
        try:
            need(len(line) <= MAX_FRAME and line.endswith(b"\n"), "INVALID_FRAME")
            frame = _parse(line)
            value = dispatch_frame(operation, frame, input_stream)
        except (RuntimeError, OSError, ValueError, TypeError) as exc:
            code = str(exc) if isinstance(exc, RuntimeError) and re.fullmatch(
                r"[A-Z][A-Z0-9_]{0,63}", str(exc)) else "RECEIVER_IO_FAILED"
            value = {"ok": False, "protocol": PROTOCOL, "operation_id": operation, "error": code}
            failed = True
        output_stream.write(_canonical(value))
        output_stream.flush()
        if failed:
            # Invalid length/JSON may leave an unknowable frame boundary.
            # Reconnect and query status; never parse remaining payload as a
            # new command after rejecting a receive frame.
            return


def main(argv):
    operation = argv[1] if len(argv) > 1 else ""
    try:
        need(len(argv) >= 2, "USAGE")
        _id(operation)
        verified_runner(operation)
        action = argv[0]
        if action == "serve" and len(argv) == 2:
            serve(operation)
            return 0
        if action == "init" and len(argv) == 2:
            raw = sys.stdin.buffer.read(MAX_FRAME + 1)
            need(len(raw) <= MAX_FRAME, "INVALID_REQUEST")
            value = initialize(operation, _parse(raw))
        elif action == "receive" and len(argv) == 6:
            need(argv[3].isascii() and argv[3].isdecimal() and argv[4].isascii() and argv[4].isdecimal(), "INVALID_CHUNK")
            length = int(argv[4])
            need(0 < length <= MAX_CHUNK, "INVALID_CHUNK")
            raw = sys.stdin.buffer.read(length + 1)
            value = receive(operation, argv[2], int(argv[3]), length, argv[5], raw)
        elif action in ("status", "register", "deps") and len(argv) == 2:
            value = {"status": request_status, "register": register, "deps": dependencies}[action](operation)
        elif action == "runner-status" and len(argv) == 2:
            parent = _operation(operation)
            try:
                record = _runner_metadata(parent, operation)
            finally:
                os.close(parent)
            value = {"ok": True, "protocol": PROTOCOL, "operation_id": operation,
                     "runner_manifest_sha256": record["runner_manifest_sha256"],
                     "runner_archive_sha256": record["runner_archive_sha256"],
                     "dependencies_ready": record["dependencies_ready"]}
        else:
            raise Refused("USAGE")
        print(_canonical(value).decode("ascii"), end="")
        return 0
    except (RuntimeError, OSError, ValueError, TypeError, ImportError) as exc:
        code = str(exc) if isinstance(exc, Refused) else "RECEIVER_IO_FAILED"
        print(_canonical({"ok": False, "protocol": PROTOCOL, "operation_id": operation,
                          "error": code}).decode("ascii"), end="")
        return 40


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
