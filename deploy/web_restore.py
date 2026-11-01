#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Root-private Web restore jobs and bounded five-file browser import.

The gateway supplies an already authenticated administrator. Every request and
background transfer rechecks that live role. SSH credentials only live in the
temporary pinned transport; journals contain public pins and operation state.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import threading
import time


PROTOCOL = "sovagrid-web-restore-v1"
TARGET = "sovagrid-portable-restore-target-v1"
BASE = Path("/var/lib/sovagrid/web-agent/restores")
SPOOL = Path("/var/cache/sovagrid-web-restores")
CHUNK = 4 * 1024**2
LIMITS = {"host_manifest": 64 * 1024, "host": 8 * 1024**3,
          "images_manifest": 4096, "images": 8 * 1024**3, "receipt": 8192}
ORDER = tuple(LIMITS)
ID = re.compile(r"[0-9a-f]{32}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
ERROR = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
MAX_STATE = 2 * 1024**2


class RestoreError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(value, code="INVALID_INPUT"):
    if not value:
        raise RestoreError(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


def object_json(raw):
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, TypeError):
        raise RestoreError("INVALID_INPUT") from None
    need(type(value) is dict)
    return value


def identity(value):
    need(isinstance(value, str) and ID.fullmatch(value), "INVALID_OPERATION")
    return value


def artifacts(value):
    need(type(value) is dict and set(value) == set(ORDER))
    for part, meta in value.items():
        need(type(meta) is dict and set(meta) == {"bytes", "sha256"} and
             type(meta["bytes"]) is int and 0 < meta["bytes"] <= LIMITS[part] and
             isinstance(meta["sha256"], str) and SHA.fullmatch(meta["sha256"]))
    need(sum(item["bytes"] for item in value.values()) <= 16 * 1024**3)
    return value


def route(options, fingerprint, credential):
    value = {"host": options.host, "port": options.port, "username": options.user,
             "fingerprint": fingerprint}
    jump = getattr(credential, "jump", None)
    if jump is not None:
        value["jump"] = {key: jump[key] for key in ("host", "port", "username", "fingerprint")}
    return value


def proof(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


class PrivateStore:
    def __init__(self, root=BASE, uid=0, gid=0):
        self.root, self.uid, self.gid = Path(root), uid, gid
        self.thread_guard = threading.Lock()
        self.thread_locks = {}

    def directory(self, path, create=False):
        created = False
        if create:
            try:
                path.mkdir(mode=0o700, parents=False, exist_ok=False)
                created = True
            except FileExistsError:
                pass
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
             (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (self.uid, self.gid, 0o700),
             "UNSAFE_STATE")
        if created:
            # state.json is a recovery anchor only after its enclosing
            # directory entry also survives a machine power loss.
            parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        return path

    def prepare(self):
        parent = self.root.parent.lstat()
        need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == self.uid and not parent.st_mode & 0o022,
             "UNSAFE_STATE")
        self.directory(self.root, True)
        for name in ("imports", "operations"):
            self.directory(self.root / name, True)

    def folder(self, kind, value, create=False):
        identity(value)
        need(kind in ("imports", "operations"))
        self.prepare()
        return self.directory(self.root / kind / value, create)

    def file(self, path, limit=MAX_STATE):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                 (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (self.uid, self.gid, 0o600) and
                 0 < info.st_size <= limit, "UNSAFE_STATE")
            raw = bytearray()
            while len(raw) < info.st_size:
                block = os.read(fd, min(1024 * 1024, info.st_size - len(raw)))
                need(block, "SOURCE_CHANGED")
                raw.extend(block)
            need(proof(os.fstat(fd)) == proof(info), "SOURCE_CHANGED")
            return bytes(raw)
        finally:
            os.close(fd)

    def read(self, folder, name="state.json"):
        return object_json(self.file(folder / name))

    def write(self, folder, value, name="state.json"):
        self.directory(folder)
        raw = canonical(value)
        need(len(raw) <= MAX_STATE, "ARCHIVE_FULL")
        temporary = folder / ("." + secrets.token_hex(16) + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(raw); out.flush(); os.fsync(out.fileno())
            target = folder / name
            if os.path.lexists(target):
                self.file(target)
            os.replace(temporary, target)
            parent = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            temporary.unlink(missing_ok=True)

    @contextmanager
    def lock(self, folder):
        with self.thread_guard:
            local = self.thread_locks.setdefault(str(folder), threading.Lock())
        need(local.acquire(blocking=False), "BUSY")
        path = folder / ".lock"
        fd = None
        try:
            try:
                fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                 (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (self.uid, self.gid, 0o600),
                 "UNSAFE_STATE")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RestoreError("BUSY") from None
            yield
        finally:
            if fd is not None:
                os.close(fd)
            local.release()


def names(archive):
    return {"host_manifest": archive + ".manifest.json", "host": archive + ".tar.gz",
            "images_manifest": "manifest.json", "images": "images.tar", "receipt": "receipt.json"}


class BrowserImports:
    def __init__(self, store, spool=None):
        self.store = store
        self.spool = spool or PrivateStore(SPOOL, store.uid, store.gid)

    def _data(self, state):
        self.spool.prepare()
        path = self.spool.root / "imports" / state["source_id"]
        if not os.path.lexists(path):
            self.spool.folder("imports", state["source_id"], True)
            # The durable journal is backed up; bulk cache bytes are not.
            # A new host can receive the same immutable files again via UI.
            state["files"] = {part: {"received": 0, "inode": None} for part in ORDER}
            state["chunks"], state["pending"] = [], None
            self.store.write(self.store.folder("imports", state["source_id"]), state)
        return self.spool.folder("imports", state["source_id"])

    def _state(self, folder):
        state = self.store.read(folder)
        need(set(state) == {"protocol", "source_id", "archive_id", "artifacts", "files", "chunks", "pending"} and
             state["protocol"] == PROTOCOL and state["source_id"] == folder.name and
             ID.fullmatch(state["archive_id"]), "UNSAFE_STATE")
        artifacts(state["artifacts"])
        need(type(state["files"]) is dict and set(state["files"]) == set(ORDER) and
             type(state["chunks"]) is list and len(state["chunks"]) <= 8192 and
             (state["pending"] is None or type(state["pending"]) is dict), "UNSAFE_STATE")
        return state

    def status_value(self, state):
        return {"protocol": PROTOCOL, "source_id": state["source_id"], "archive_id": state["archive_id"],
                "max_chunk_bytes": CHUNK, "pending_chunk": state["pending"],
                "complete": all(v["received"] == state["artifacts"][k]["bytes"] for k, v in state["files"].items()),
                "artifacts": {kind: {**meta, "received": state["files"][kind]["received"],
                    "complete": state["files"][kind]["received"] == meta["bytes"]}
                    for kind, meta in state["artifacts"].items()}}

    def init(self, payload):
        need(type(payload) is dict and set(payload) == {"source_id", "archive_id", "artifacts"})
        source, archive = identity(payload["source_id"]), identity(payload["archive_id"])
        artifacts(payload["artifacts"])
        self.store.prepare()
        need(len(list((self.store.root / "imports").iterdir())) < 16 or
             (self.store.root / "imports" / source).exists(), "ARCHIVE_FULL")
        folder = self.store.folder("imports", source, True)
        with self.store.lock(folder):
            if (folder / "state.json").exists():
                state = self._state(folder)
                need(state["archive_id"] == archive and state["artifacts"] == payload["artifacts"], "SOURCE_CHANGED")
            else:
                self.spool.prepare()
                available = os.statvfs(self.spool.root)
                need(available.f_bavail * available.f_frsize >=
                     sum(v["bytes"] for v in payload["artifacts"].values()) + 128 * 1024**2,
                     "INSUFFICIENT_SPACE")
                need(set(p.name for p in folder.iterdir()) == {".lock"}, "UNSAFE_STATE")
                state = {"protocol": PROTOCOL, "source_id": source, "archive_id": archive,
                         "artifacts": payload["artifacts"],
                         "files": {part: {"received": 0, "inode": None} for part in ORDER},
                         "chunks": [], "pending": None}
                self.store.write(folder, state)
            self._data(state)
            return self.status_value(state)

    def status(self, source):
        folder = self.store.folder("imports", source)
        with self.store.lock(folder):
            state = self._state(folder)
            self._data(state)
            return self.status_value(state)

    def receive(self, payload, raw):
        need(type(payload) is dict and set(payload) == {"source_id", "part", "offset", "length", "sha256"})
        source = identity(payload["source_id"])
        part, offset, length, sha = (payload[k] for k in ("part", "offset", "length", "sha256"))
        need(part in ORDER and type(offset) is int and offset >= 0 and type(length) is int and
             0 < length <= CHUNK and isinstance(sha, str) and SHA.fullmatch(sha) and
             isinstance(raw, bytes) and len(raw) == length and hashlib.sha256(raw).hexdigest() == sha)
        folder = self.store.folder("imports", source)
        with self.store.lock(folder):
            state = self._state(folder)
            data_folder = self._data(state)
            meta, file = state["artifacts"][part], state["files"][part]
            chunk = {key: payload[key] for key in ("part", "offset", "length", "sha256")}
            need(offset + length <= meta["bytes"], "INVALID_OFFSET")
            path = data_folder / names(state["archive_id"])[part]
            if offset < file["received"]:
                need(chunk in state["chunks"], "SOURCE_CHANGED")
                return self.status_value(state)
            need(offset == file["received"] and (state["pending"] is None or state["pending"] == chunk), "INVALID_OFFSET")
            fd = None
            try:
                if file["inode"] is None:
                    need(offset == 0, "UNSAFE_STATE")
                    recovering_empty = state["pending"] == chunk
                    state["pending"] = chunk
                    self.store.write(folder, state)
                    try:
                        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    except FileExistsError:
                        # Only an empty cache file after this exact durable
                        # create intent can belong to an interrupted creation.
                        need(recovering_empty, "SOURCE_CHANGED")
                        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
                    info = os.fstat(fd)
                    need(stat.S_ISREG(info.st_mode) and info.st_size == 0 and info.st_nlink == 1 and
                         (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
                         (self.store.uid, self.store.gid, 0o600), "SOURCE_CHANGED")
                    file["inode"] = list((info.st_dev, info.st_ino))
                    directory_fd = os.open(data_folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        os.fsync(fd)
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                else:
                    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
                info = os.fstat(fd)
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                     (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
                     (self.store.uid, self.store.gid, 0o600) and
                     list((info.st_dev, info.st_ino)) == file["inode"] and
                     offset <= info.st_size <= offset + length, "SOURCE_CHANGED")
                state["pending"] = chunk
                self.store.write(folder, state)
                prefix = os.pread(fd, info.st_size - offset, offset)
                need(prefix == raw[:len(prefix)], "SOURCE_CHANGED")
                view = memoryview(raw[len(prefix):])
                os.lseek(fd, offset + len(prefix), os.SEEK_SET)
                while view:
                    count = os.write(fd, view); need(count > 0, "SOURCE_CHANGED"); view = view[count:]
                os.fsync(fd)
                if offset + length == meta["bytes"]:
                    os.lseek(fd, 0, os.SEEK_SET)
                    hasher = hashlib.sha256()
                    while block := os.read(fd, 1024 * 1024):
                        hasher.update(block)
                    need(hasher.hexdigest() == meta["sha256"], "SOURCE_CHANGED")
                file["received"] = offset + length
                state["chunks"].append(chunk); state["pending"] = None
                self.store.write(folder, state)
                return self.status_value(state)
            finally:
                if fd is not None:
                    os.close(fd)

    def paths(self, source):
        folder = self.store.folder("imports", source)
        with self.store.lock(folder):
            state = self._state(folder)
            data_folder = self._data(state)
            need(self.status_value(state)["complete"] and state["pending"] is None, "SOURCE_INCOMPLETE")
            return state["archive_id"], state["artifacts"], {k: data_folder / v for k, v in names(state["archive_id"]).items()}

    def delete(self, source):
        folder = self.store.folder("imports", identity(source))
        with self.store.lock(folder):
            state = self._state(folder)
            data_folder = self._data(state)
            need(all(p.name in ("state.json", ".lock") or re.fullmatch(r"\.[0-9a-f]{32}\.tmp", p.name)
                     for p in folder.iterdir()) and
                 set(p.name for p in data_folder.iterdir()) <= set(names(state["archive_id"]).values()), "UNSAFE_STATE")
            for path in (*folder.iterdir(), *data_folder.iterdir()):
                info = path.lstat()
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                     (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
                     (self.store.uid, self.store.gid, 0o600), "UNSAFE_STATE")
            # This removes only a user's explicitly selected private import
            # cache; the original backup and its source files stay elsewhere.
            for path in data_folder.iterdir():
                path.unlink()
            data_folder.rmdir()
            for path in folder.iterdir():
                path.unlink()
            folder.rmdir()
        return {"protocol": PROTOCOL, "source_id": source, "deleted": True}


class RecordAdapter:
    def __init__(self, record):
        self.record = record

    def save(self, value):
        need(value == self.record, "SOURCE_CHANGED")


def safe_target(value):
    need(type(value) is dict and value.get("protocol") == TARGET and
         type(value.get("ok")) is bool and value["ok"], "TARGET_UNAVAILABLE")
    fields = ("protocol", "operation_id", "archive_id", "request_sha256", "registered", "phase",
              "backend_supported", "target_ready", "apply_available", "blockers", "apply_review_sha256",
              "worker_active", "retry_available", "retry_in_progress", "terminal_sha256", "error")
    result = {key: value[key] for key in fields if key in value}
    need(isinstance(result.get("phase"), str) and re.fullmatch(r"[a-z_]{1,48}", result["phase"]) and
         (result.get("error") is None or isinstance(result["error"], str) and ERROR.fullmatch(result["error"])),
         "TARGET_UNAVAILABLE")
    preview = value.get("preview")
    if type(preview) is dict:
        result["preview"] = {key: preview[key] for key in
            ("target_free_bytes", "required_free_bytes", "target_empty", "policy") if key in preview}
        need(all(type(preview[key]) is int and 0 <= preview[key] <= 2**53 - 1
                 for key in ("target_free_bytes", "required_free_bytes") if key in preview) and
             ("target_empty" not in preview or type(preview["target_empty"]) is bool), "TARGET_UNAVAILABLE")
        policy = result["preview"].get("policy")
        if policy is not None:
            need(policy == {"queued_jobs": "cancel", "telegram_confirmations": "cancel",
                            "vpn": "restore_configuration_down", "public_address_override": False}, "TARGET_UNAVAILABLE")
    need(len(canonical(result)) <= 24 * 1024, "RESPONSE_TOO_LARGE")
    return result


class WebRestoreJobs:
    def __init__(self, bundle_path, bundle_sha256, *, store=None, transport_factory=None,
                 source_resolver=None, spool=None, source_guard=nullcontext):
        self.bundle = Path(bundle_path)
        need(SHA.fullmatch(bundle_sha256), "SOURCE_UNTRUSTED")
        self.bundle_sha = bundle_sha256
        self.store = store or PrivateStore()
        self.imports = BrowserImports(self.store, spool)
        self.source_guard = source_guard
        self.admission = threading.Lock()
        self.source_resolver = source_resolver or self._backup_source
        if transport_factory is None:
            from web_agent_target_ssh import PinnedTargetSSH
            transport_factory = PinnedTargetSSH
        self.transport_factory = transport_factory
        self.workers = {}
        self.guard = threading.Lock()

    def _runner_manifest(self):
        import tarfile
        with tarfile.open(self.bundle, "r:gz") as archive:
            raw = archive.extractfile("sovagrid-bundle.json").read(512 * 1024 + 1)
        need(len(raw) <= 512 * 1024, "SOURCE_UNTRUSTED")
        return hashlib.sha256(raw).hexdigest()

    def _backup_source(self, request):
        identity(request)
        result = subprocess.run(["/usr/bin/python3", "-B", "-I",
            str(Path(__file__).with_name("host_backup_orchestrator.py")), "portable-status", request],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=90, check=False)
        need(result.returncode == 0 and len(result.stdout) <= 32 * 1024, "SOURCE_UNAVAILABLE")
        value = object_json(result.stdout)
        need(value.get("ok") is True and value.get("phase") == "complete" and
             value.get("request_id") == request and type(value.get("archive")) is dict, "SOURCE_UNAVAILABLE")
        archive = identity(value["archive"]["id"])
        root = Path("/var/lib/sovagrid-host-image-exports") / archive
        paths = {"host_manifest": Path("/var/lib/sovagrid-host-backups") / (archive + ".manifest.json"),
                 "host": Path("/var/lib/sovagrid-host-backups") / (archive + ".tar.gz"),
                 "images_manifest": root / "manifest.json", "images": root / "images.tar", "receipt": root / "receipt.json"}
        receipt = object_json(self.store.file(paths["receipt"], 8192))
        need(receipt.get("protocol") == "sovagrid-portable-host-receipt-v2" and
             receipt.get("host_archive_id") == archive, "SOURCE_UNSUPPORTED")
        metadata = {}
        for part, path in paths.items():
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                 (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (self.store.uid, self.store.gid, 0o600) and
                 0 < info.st_size <= LIMITS[part], "SOURCE_UNAVAILABLE")
            sha = receipt.get("host_archive_sha256" if part == "host" else "images_sha256") if part in ("host", "images") else hashlib.sha256(self.store.file(path, LIMITS[part])).hexdigest()
            metadata[part] = {"bytes": info.st_size, "sha256": sha}
        artifacts(metadata)
        return archive, metadata, paths

    def _source(self, source):
        need(type(source) is dict and set(source) == {"kind", "id"} and source["kind"] in ("backup", "upload"))
        return self.imports.paths(identity(source["id"])) if source["kind"] == "upload" else self.source_resolver(identity(source["id"]))

    def _state(self, operation):
        folder = self.store.folder("operations", operation)
        state = self.store.read(folder)
        need(state.get("protocol") == PROTOCOL and state.get("operation_id") == operation and
             type(state.get("route")) is dict and type(state.get("record")) is dict, "UNSAFE_STATE")
        return folder, state

    def public(self, state, *, active=None):
        if active is None:
            with self.guard:
                active = state["operation_id"] in self.workers
        reply = {"protocol": PROTOCOL, "operation_id": state["operation_id"], "source": state["source"],
                 "created_at": state["record"]["created_at"],
                 "archive_id": state["record"]["request"]["archive_id"], "route": state["route"],
                 "phase": state["phase"], "worker_active": active, "progress": state["progress"],
                 "target": state["target"], "error": state["error"],
                 "expected_revision": digest({"route": state["route"], "request": state["record"]["request"],
                     "target": state["target"], "control": state["control"]})}
        if not active and state["phase"] == "preparing":
            reply["phase"] = "resume_required"
        return reply

    def status(self, operation):
        _folder, state = self._state(identity(operation))
        return self.public(state)

    def list(self):
        self.store.prepare()
        values = list((self.store.root / "operations").iterdir())
        need(len(values) <= 128, "ARCHIVE_FULL")
        # A crash before the first durable publication can leave only a lock;
        # that unadvertised operation must not hide the rest of the history.
        results = [self.status(path.name) for path in values
                   if ID.fullmatch(path.name) and (path / "state.json").exists()]
        results.sort(key=lambda item: (item["created_at"], item["operation_id"]), reverse=True)
        for item in results:
            item["target"], item["progress"] = None, ""
        return {"protocol": PROTOCOL, "operations": results[:8]}

    def _transport(self, options, fingerprint, credential):
        return self.transport_factory(host=options.host, port=options.port, username=options.user,
            fingerprint=fingerprint, method=credential.method, password=credential.password,
            private_key=credential.private_key, passphrase=credential.passphrase,
            jump=getattr(credential, "jump", None),
            target_host_key_blob=getattr(credential, "target_host_key_blob", ""))

    def _controller(self, transport, state, paths, progress):
        from sovagrid_connect.portable_restore import PortableArtifacts
        return transport.restore_controller(approved_archive_sha256=state["record"]["request"]["runner_archive_sha256"],
            record_target_id=state["record"]["target_id"], store=RecordAdapter(state["record"]),
            artifacts_factory=lambda directory, **kwargs: PortableArtifacts(directory, source_paths=paths, **kwargs),
            progress=progress)

    def delete_import(self, source):
        with self.admission:
            return self._delete_import(source)

    def _delete_import(self, source):
        identity(source)
        self.store.prepare()
        with self.guard:
            for path in (self.store.root / "operations").iterdir():
                if not ID.fullmatch(path.name) or not (path / "state.json").exists():
                    continue
                state = self.store.read(path)
                if state["source"] == {"kind": "upload", "id": source}:
                    # Keep operation/pins for remote status. Explicit removal
                    # of an interrupted cache is reversible by reselecting the
                    # exact five files using that operation's source ID.
                    need(path.name not in self.workers, "BUSY")
        return self.imports.delete(source)

    def prepare(self, operation, source, *, options, fingerprint, credential, authorize):
        # Serialize source selection/publication against explicit cache removal;
        # background transfer releases this lock after its worker is reserved.
        with self.admission:
            return self._prepare(operation, source, options=options, fingerprint=fingerprint,
                                 credential=credential, authorize=authorize)

    def _prepare(self, operation, source, *, options, fingerprint, credential, authorize):
        operation = identity(operation)
        selected = route(options, fingerprint, credential)
        self.store.prepare()
        root = self.store.root / "operations"
        need((root / operation).exists() or len(list(root.iterdir())) < 128, "ARCHIVE_FULL")
        archive, metadata, paths = self._source(source)
        folder = self.store.folder("operations", operation, True)
        with self.store.lock(folder):
            if (folder / "state.json").exists():
                state = self.store.read(folder)
                need(state["route"] == selected and state["source"] == source and
                     state["record"]["request"]["artifacts"] == metadata and
                     state["record"]["request"]["archive_id"] == archive, "TARGET_CHANGED")
                need(state["control"] is None, "RESUME_REQUIRED")
            else:
                request = {"protocol": TARGET, "operation_id": operation, "archive_id": archive,
                           "runner_manifest_sha256": self._runner_manifest(), "runner_archive_sha256": self.bundle_sha,
                           "artifacts": metadata}
                need(set(p.name for p in folder.iterdir()) == {".lock"}, "UNSAFE_STATE")
                state = {"protocol": PROTOCOL, "operation_id": operation, "route": selected, "source": source,
                         "phase": "preparing", "target": None, "error": None, "progress": "Подготовка…", "control": None,
                         "record": {"format": 1, "target_id": digest(selected), "operation_id": operation,
                             "created_at": int(time.time()), "folder": str(folder), "runner_path": str(self.bundle), "request": request}}
                self.store.write(folder, state)
        with self.guard:
            if operation in self.workers:
                return self.public(state, active=True)
            need(len(self.workers) < 2, "BUSY")
            transport = self._transport(options, fingerprint, credential)
            self.workers[operation] = True

        def worker():
            controller = None
            try:
                authorize()
                with self.source_guard(), transport:
                    def progress(message):
                        authorize()
                        with self.store.lock(folder):
                            current = self.store.read(folder)
                            current["progress"] = message[:256]
                            self.store.write(folder, current)
                    authorize()
                    controller = self._controller(transport, state, paths, progress)
                    _record, result = controller.prepare(folder, Path(state["record"]["runner_path"]), record=state["record"])
                    authorize()
                    with self.store.lock(folder):
                        current = self.store.read(folder)
                        current.update(phase="review", target=safe_target(result), progress="План готов", error=None)
                        self.store.write(folder, current)
            except BaseException as error:
                code = getattr(error, "code", None)
                if not isinstance(code, str) or ERROR.fullmatch(code) is None:
                    code = "RESTORE_PREPARE_FAILED"
                try:
                    with self.store.lock(folder):
                        current = self.store.read(folder)
                        current.update(phase="resume_required", error=code, progress="Подготовка остановлена; её можно продолжить")
                        self.store.write(folder, current)
                except (OSError, RestoreError):
                    pass
            finally:
                if controller is not None:
                    controller.cancel()
                transport.close()
                with self.guard:
                    self.workers.pop(operation, None)
        threading.Thread(target=worker, daemon=True, name="sovagrid-web-restore-prepare").start()
        return self.status(operation)

    def control(self, operation, action, **kwargs):
        identity(operation)
        with self.guard:
            need(operation not in self.workers, "BUSY")
            self.workers[operation] = True
        try:
            return self._control(operation, action, **kwargs)
        finally:
            with self.guard:
                self.workers.pop(operation, None)

    def _control(self, operation, action, *, options, fingerprint, credential, authorize,
                expected_revision=None, apply_review_sha256=None, terminal_sha256=None):
        need(action in ("inspect", "preview", "start", "recover", "retry"))
        folder, state = self._state(identity(operation))
        need(route(options, fingerprint, credential) == state["route"], "TARGET_CHANGED")
        # Status/recovery use the independently retained target runner and its
        # immutable request. They remain available after a local cache is gone.
        paths = {}
        requested = {"action": action, "apply_review_sha256": apply_review_sha256, "terminal_sha256": terminal_sha256}
        with self.store.lock(folder):
            state = self.store.read(folder)
            duplicate = action == "start" and state["control"] == requested
            if action in ("start", "recover", "retry") and not duplicate:
                need(isinstance(expected_revision, str) and SHA.fullmatch(expected_revision) and
                     self.public(state)["expected_revision"] == expected_revision, "STALE_REVISION")
                if action == "start":
                    need(isinstance(apply_review_sha256, str) and SHA.fullmatch(apply_review_sha256) and
                         state["target"] is not None and state["target"].get("apply_available") is True and
                         state["target"].get("apply_review_sha256") == apply_review_sha256, "STALE_REVISION")
                if action == "retry":
                    need(isinstance(terminal_sha256, str) and SHA.fullmatch(terminal_sha256) and
                         state["target"] is not None and state["target"].get("retry_available") is True and
                         state["target"].get("terminal_sha256") == terminal_sha256, "STALE_REVISION")
                state["control"] = requested; state["phase"] = "uncertain"
                self.store.write(folder, state)
        authorize()
        controller = None
        try:
            with self._transport(options, fingerprint, credential) as transport:
                controller = self._controller(transport, state, paths, lambda _message: authorize())
                selected_action = "operation-status" if action == "inspect" or duplicate else action
                arguments = ({"apply_review_sha256": apply_review_sha256} if selected_action == "start" else
                             {"terminal_sha256": terminal_sha256} if selected_action == "retry" else {})
                authorize()
                result = controller.action(state["record"], selected_action, **arguments)
                authorize()
                with self.store.lock(folder):
                    current = self.store.read(folder)
                    current.update(phase=result["phase"], target=safe_target(result), progress="Состояние получено", error=None)
                    if action in ("inspect", "preview"):
                        current["control"] = None
                    self.store.write(folder, current)
                return self.status(operation)
        except RestoreError:
            raise
        except Exception:
            raise RestoreError("RESTORE_RESPONSE_UNCERTAIN") from None
        finally:
            if controller is not None:
                controller.cancel()
