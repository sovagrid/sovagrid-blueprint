# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Pinned, resumable restoration over one authenticated SSH stream.

Only the independently reviewed runner supplies executable code. The five
backup files are held open, hashed and sent as data to fixed receiver actions.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid

from .auto_update import target_id
from .host_backup import HostArchive, HostBackupController
from .host_backup_request import HostBackupRequestStore
from .host_backup_transfer import _check_metadata, _publish_exclusive, _windows_publish
from .installer import InstallError, ServerInstaller, _snapshot_with_digest


PROTOCOL = "sovagrid-portable-restore-target-v1"
SHA = re.compile(r"[0-9a-f]{64}\Z")
IDENTITY = re.compile(r"[0-9a-f]{32}\Z")
CHUNK = 4 * 1024**2
MAX_REPLY = 2 * 1024**2
LIMITS = {"host_manifest": 64 * 1024, "host": 8 * 1024**3,
          "images_manifest": 4096, "images": 8 * 1024**3, "receipt": 8192}
ORDER = tuple(LIMITS)
PART_LABELS = {"host_manifest": "описания архива", "host": "архива сервера",
               "images_manifest": "описания образов", "images": "образов Docker",
               "receipt": "квитанции копии"}
RUNNER = "/root/.sovagrid-restore/{}/runner/sovagrid-blueprint/deploy/portable_restore_receiver.py"
BOOTSTRAP = "sovagrid-blueprint/deploy/portable_restore_bootstrap.sh"


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("ascii")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _json(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, UnicodeError, TypeError) as exc:
        raise InstallError("Некорректные метаданные восстановления") from exc


def _fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_nlink)


class PortableArtifacts:
    """Retain all five local input descriptors until the transfer completes."""

    def __init__(self, directory, *, check=None, progress=None, source_paths=None):
        self.directory = Path(directory).absolute()
        self.files = {}
        self.metadata = {}
        self.check = check or (lambda: None)
        self.progress = progress or (lambda _message: None)
        if source_paths is not None and (not isinstance(source_paths, dict) or set(source_paths) != set(ORDER) or
                any(not Path(path).is_absolute() for path in source_paths.values())):
            raise InstallError("Неверный список локальных файлов переносимой копии")
        # Server callers resolve this mapping from their own verified backup ID.
        # It is never accepted as paths from the browser or sent to the target.
        self.source_paths = None if source_paths is None else {part: Path(path) for part, path in source_paths.items()}

    def __enter__(self):
        self.stack = ExitStack()
        try:
            if self.source_paths is None:
                info = self.directory.lstat()
                if (not stat.S_ISDIR(info.st_mode) or
                        getattr(info, "st_file_attributes", 0) & 0x400):
                    raise InstallError("Выберите обычную папку переносимой копии")
            receipt = self._open("receipt", "receipt.json")
            value = self._metadata(receipt, LIMITS["receipt"])
            identity = value.get("host_archive_id")
            if not isinstance(identity, str) or IDENTITY.fullmatch(identity) is None:
                raise InstallError("В квитанции нет корректного номера копии")
            if value.get("protocol") != "sovagrid-portable-host-receipt-v2":
                raise InstallError("Для полного восстановления нужна переносимая копия v2")
            self.archive_id = identity
            for part, name in (("host_manifest", identity + ".manifest.json"),
                               ("host", identity + ".tar.gz"),
                               ("images_manifest", "manifest.json"), ("images", "images.tar")):
                self._open(part, name)
            host = self._metadata(self.files["host_manifest"], LIMITS["host_manifest"])
            images = self._metadata(self.files["images_manifest"], LIMITS["images_manifest"])
            archive = HostArchive(host["id"], host["created_at"], host["layout"],
                                  host["bytes"], host["files"])
            if (archive.id != identity or archive.layout != "full" or
                    type(archive.bytes) is not int or archive.bytes != self.metadata["host"]["bytes"] or
                    type(archive.files) is not int or not 0 < archive.files <= 20_000):
                raise InstallError("Копия не соответствует полной установке Hub и Agent")
            HostBackupController._receipt(None, value, archive, None)
            _check_metadata("host_manifest", host,
                            {key: host[key] for key in ("id", "created_at", "layout", "bytes", "files")},
                            self.metadata["images"]["bytes"], value)
            _check_metadata("images_manifest", images,
                            {key: host[key] for key in ("id", "created_at", "layout", "bytes", "files")},
                            self.metadata["images"]["bytes"], value)
            if (self.metadata["host"]["sha256"] != value["host_archive_sha256"] or
                    self.metadata["images"]["sha256"] != value["images_sha256"]):
                raise InstallError("SHA-256 файлов не совпал с квитанцией копии")
            self.receipt = value
            return self
        except (OSError, KeyError, TypeError, ValueError) as exc:
            self.stack.close()
            raise InstallError("Не удалось проверить все пять файлов переносимой копии") from exc
        except BaseException:
            self.stack.close()
            raise

    def _open(self, part, name):
        self.check()
        path = self.directory / name if self.source_paths is None else self.source_paths[part]
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                getattr(info, "st_file_attributes", 0) & 0x400):
            raise InstallError("Копия содержит ссылку или необычный файл")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        stream = self.stack.enter_context(os.fdopen(fd, "rb", buffering=0))
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or _fingerprint(before) != _fingerprint(info) or
                not 0 < before.st_size <= LIMITS[part]):
            raise InstallError("Файл копии изменился или превышает допустимый размер")
        digest = hashlib.sha256()
        checked, next_progress = 0, 64 * 1024**2
        self.progress("Проверка " + PART_LABELS[part] + "…")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            self.check()
            digest.update(block)
            checked += len(block)
            if checked >= next_progress:
                self.progress(f"Проверка {PART_LABELS[part]}: {checked:,} / {before.st_size:,} байт")
                next_progress = checked + 64 * 1024**2
        if _fingerprint(os.fstat(fd)) != _fingerprint(before):
            raise InstallError("Файл копии изменился во время проверки")
        stream.seek(0)
        self.files[part] = (stream, _fingerprint(before))
        self.metadata[part] = {"bytes": before.st_size, "sha256": digest.hexdigest()}
        return self.files[part]

    @staticmethod
    def _metadata(held, limit):
        stream, proof = held
        stream.seek(0)
        raw = stream.read(limit + 1)
        if len(raw) > limit or _fingerprint(os.fstat(stream.fileno())) != proof:
            raise InstallError("Манифест копии изменился")
        return _json(raw)

    def read_chunk(self, part, offset, length):
        self.check()
        stream, proof = self.files[part]
        if (type(offset) is not int or type(length) is not int or
                not 0 <= offset < self.metadata[part]["bytes"] or
                not 0 < length <= min(CHUNK, self.metadata[part]["bytes"] - offset) or
                _fingerprint(os.fstat(stream.fileno())) != proof):
            raise InstallError("Входной файл или позиция передачи изменились")
        stream.seek(offset)
        raw = bytearray()
        while len(raw) < length:
            block = stream.read(length - len(raw))
            if not block:
                raise InstallError("Файл копии оборвался во время передачи")
            raw.extend(block)
        if _fingerprint(os.fstat(stream.fileno())) != proof:
            raise InstallError("Файл копии изменился во время передачи")
        return bytes(raw)

    def __exit__(self, *args):
        return self.stack.__exit__(*args)


class RestoreRecordStore(HostBackupRequestStore):
    """Immutable operation pointers; no SSH password, key bytes or Hub session."""

    @staticmethod
    def default():
        base = HostBackupRequestStore.default().directory.parent
        return RestoreRecordStore(base / "host-restore-requests")

    @staticmethod
    def validate(value):
        keys = {"format", "target_id", "operation_id", "created_at", "folder", "runner_path", "request"}
        if (not isinstance(value, dict) or set(value) != keys or type(value["format"]) is not int or
                value["format"] != 1 or not isinstance(value["target_id"], str) or
                SHA.fullmatch(value["target_id"]) is None or
                not isinstance(value["operation_id"], str) or IDENTITY.fullmatch(value["operation_id"]) is None or
                type(value["created_at"]) is not int or not 0 < value["created_at"] <= 253402300799 or
                any(not isinstance(value[key], str) or len(value[key]) > 4096 or
                    "\x00" in value[key] or not Path(value[key]).is_absolute()
                    for key in ("folder", "runner_path"))):
            raise InstallError("Сохранённая операция восстановления повреждена")
        request = value["request"]
        expected = {"protocol", "operation_id", "archive_id", "runner_manifest_sha256",
                    "runner_archive_sha256", "artifacts"}
        if (not isinstance(request, dict) or set(request) != expected or request["protocol"] != PROTOCOL or
                request["operation_id"] != value["operation_id"] or
                not isinstance(request["archive_id"], str) or IDENTITY.fullmatch(request["archive_id"]) is None or
                any(not isinstance(request[key], str) or SHA.fullmatch(request[key]) is None
                    for key in ("runner_archive_sha256", "runner_manifest_sha256")) or
                not isinstance(request["artifacts"], dict) or set(request["artifacts"]) != set(ORDER)):
            raise InstallError("Сохранённый план передачи повреждён")
        for part, item in request["artifacts"].items():
            if (not isinstance(item, dict) or set(item) != {"bytes", "sha256"} or
                    type(item["bytes"]) is not int or not 0 < item["bytes"] <= LIMITS[part] or
                    not isinstance(item["sha256"], str) or SHA.fullmatch(item["sha256"]) is None):
                raise InstallError("Сохранённый список файлов повреждён")
        return value

    def save(self, value):
        value = self.validate(value)
        self._directory(create=True)
        path = self.directory / (value["operation_id"] + ".json")
        raw = _canonical(value)
        if len(raw) > 16 * 1024:
            raise InstallError("Сохранённый план слишком большой")
        temporary = self.directory / ("." + secrets.token_hex(16) + ".tmp")
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            if os.name == "nt":
                _windows_publish(temporary, path)
            else:
                parent = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    _publish_exclusive(parent, temporary.name, path.name)
                    os.fsync(parent)
                finally:
                    os.close(parent)
        except OSError:
            if not path.exists() or self.load(value["operation_id"]) != value:
                raise InstallError("Номер операции уже занят или не удалось сохранить план") from None
        finally:
            temporary.unlink(missing_ok=True)

    def load(self, identity):
        if not isinstance(identity, str) or IDENTITY.fullmatch(identity) is None:
            raise InstallError("Неверный номер операции восстановления")
        self._directory(create=False)
        fd = os.open(self.directory / (identity + ".json"), os.O_RDONLY |
                     getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            self._file(os.fstat(fd))
            raw = stream.read(16 * 1024 + 1)
        if len(raw) > 16 * 1024:
            raise InstallError("Сохранённая операция слишком большая")
        value = self.validate(_json(raw))
        if value["operation_id"] != identity:
            raise InstallError("Сохранённый номер операции не совпал")
        return value

    def for_target(self, options):
        try:
            self._directory(create=False)
        except FileNotFoundError:
            return []
        names = list(self.directory.iterdir())
        if len(names) > 1000:
            raise InstallError("Слишком много сохранённых операций восстановления")
        result = []
        for path in names:
            if path.suffix == ".json" and IDENTITY.fullmatch(path.stem):
                value = self.load(path.stem)
                if value["target_id"] == target_id(options):
                    result.append(value)
        return sorted(result, key=lambda item: (item["created_at"], item["operation_id"]), reverse=True)


class RestoreSSHStream:
    def __init__(self, process, identity):
        self.process, self.identity = process, identity

    def request(self, frame, payload=b"", *, timeout=120):
        raw = _canonical(frame)
        if len(raw) > 64 * 1024 or len(payload) > CHUNK:
            raise InstallError("Запрос передачи превышает лимит")
        if (frame.get("action") == "receive" and
                (type(frame.get("length")) is not int or not 0 < frame["length"] == len(payload)) or
                frame.get("action") != "receive" and payload):
            raise InstallError("Длина двоичного фрагмента не соответствует запросу")
        expired = threading.Event()

        def stop():
            expired.set()
            try:
                self.process.kill()
            except OSError:
                pass

        timer = threading.Timer(timeout, stop)
        timer.daemon = True
        timer.start()
        try:
            for data in (raw, payload):
                view = memoryview(data)
                while view:
                    written = self.process.stdin.write(view)
                    if written is None or written <= 0:
                        raise OSError("closed SSH input")
                    view = view[written:]
            self.process.stdin.flush()
            reply = self.process.stdout.readline(MAX_REPLY + 1)
            if expired.is_set():
                raise InstallError("SSH не ответил вовремя; проверьте сохранённую операцию повторно")
            if not reply.endswith(b"\n") or len(reply) > MAX_REPLY:
                raise InstallError("SSH-приёмник не подтвердил операцию")
            value = _json(reply)
            if (value.get("protocol") != PROTOCOL or value.get("operation_id") != self.identity or
                    type(value.get("ok")) is not bool):
                raise InstallError("Ответ относится к другой операции восстановления")
            if not value["ok"]:
                code = value.get("error")
                if not isinstance(code, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code) is None:
                    raise InstallError("Приёмник отклонил некорректный ответ")
                raise InstallError("Восстановление остановлено: " + code)
            return value
        except (OSError, ValueError) as exc:
            raise InstallError("SSH-передача прервана. Операцию можно проверить и продолжить") from exc
        finally:
            timer.cancel()


class PortableRestoreController:
    def __init__(self, options, *, approved_archive_sha256, store=None, progress=None,
                 popen=subprocess.Popen, artifacts_factory=PortableArtifacts, record_target_id=None):
        if not isinstance(approved_archive_sha256, str) or SHA.fullmatch(approved_archive_sha256) is None:
            raise InstallError("Нужен закреплённый доверенный серверный пакет")
        self.manager = ServerInstaller(options, popen=popen)
        self.options = self.manager.options
        if record_target_id is not None and (not isinstance(record_target_id, str) or
                                             SHA.fullmatch(record_target_id) is None):
            raise InstallError("Неверная привязка проверенного SSH-маршрута")
        self.record_target_id = target_id(self.options) if record_target_id is None else record_target_id
        self.artifacts_factory = artifacts_factory
        self.approved_archive_sha256 = approved_archive_sha256
        self.store = store or RestoreRecordStore.default()
        self.progress = progress or (lambda _message: None)
        self._cancelled = threading.Event()
        self._launch_lock = threading.Lock()
        self.current_record = None
        self._channel = self._channel_context = self._channel_identity = None
        self._channel_use_lock = threading.Lock()

    def cancel(self):
        with self._launch_lock:
            self._cancelled.set()
            self.manager.cancel()
        if self._channel_use_lock.acquire(blocking=False):
            try:
                self._drop_channel()
            finally:
                self._channel_use_lock.release()

    def _drop_channel(self):
        context = self._channel_context
        self._channel = self._channel_context = self._channel_identity = None
        if context is not None:
            context.__exit__(None, None, None)

    def _connection(self, identity):
        self._check_cancelled()
        if (self._channel is not None and self._channel_identity == identity and
                self._channel.process.poll() is None):
            with self._launch_lock:
                self._check_cancelled()
                with self.manager._lock:
                    self.manager._process = self._channel.process
                return self._channel
        self._drop_channel()
        context = self.session(identity)
        channel = context.__enter__()
        self._channel_context, self._channel, self._channel_identity = context, channel, identity
        return channel

    @contextmanager
    def connection(self, identity):
        with self._channel_use_lock:
            try:
                yield self._connection(identity)
            except BaseException:
                self._drop_channel()
                raise
            finally:
                if self._cancelled.is_set():
                    self._drop_channel()

    def _check_cancelled(self):
        if self._cancelled.is_set():
            raise InstallError("Операция отменена на этом устройстве. Серверное состояние можно проверить повторно")

    def _ssh(self, *args, **kwargs):
        with self._launch_lock:
            self._check_cancelled()
            return self.manager._ssh(*args, **kwargs)

    @contextmanager
    def session(self, identity):
        if not isinstance(identity, str) or IDENTITY.fullmatch(identity) is None:
            raise InstallError("Неверный номер операции восстановления")
        command = shlex.join(["/usr/bin/python3", "-B", "-I", RUNNER.format(identity), "serve", identity])
        with self.manager._session() as (config, helper):
            process = self._ssh(config, helper, command, input_file=subprocess.PIPE)
            try:
                yield RestoreSSHStream(process, identity)
            finally:
                if process.stdin:
                    try:
                        process.stdin.close()
                    except OSError:
                        pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                if process.stdout:
                    process.stdout.close()

    @staticmethod
    def _transfer_state(value, request):
        digest = hashlib.sha256(_canonical(request)).hexdigest()
        if (value.get("request_sha256") != digest or value.get("archive_id") != request["archive_id"] or
                type(value.get("registered")) is not bool or
                value.get("max_chunk_bytes") != CHUNK or
                not isinstance(value.get("artifacts"), dict) or set(value["artifacts"]) != set(ORDER)):
            raise InstallError("Приёмник подтвердил другой план передачи")
        for part, remote in value["artifacts"].items():
            expected = request["artifacts"][part]
            if (not isinstance(remote, dict) or set(remote) != {"received", "bytes", "sha256", "complete"} or
                    type(remote["received"]) is not int or not 0 <= remote["received"] <= expected["bytes"] or
                    type(remote["bytes"]) is not int or remote["bytes"] != expected["bytes"] or
                    remote["sha256"] != expected["sha256"] or
                    type(remote["complete"]) is not bool or
                    remote["complete"] != (remote["received"] == expected["bytes"])):
                raise InstallError("Приёмник подтвердил неверную позицию файла")
        if value["registered"] and not all(item["complete"] for item in value["artifacts"].values()):
            raise InstallError("Приёмник зарегистрировал неполную копию")
        return value

    def _bootstrap(self, snapshot, identity, archive_sha, manifest_sha, script):
        self.progress("Доставка проверенного исполнителя и подготовка зависимостей Ubuntu…")
        command = shlex.join(["/bin/bash", "-c", script, "--", identity,
                              str(snapshot.stat().st_size), archive_sha, manifest_sha])
        with self.manager._session() as (config, helper), snapshot.open("rb") as source:
            process = self._ssh(config, helper, command, input_file=source)
            raw = self.manager._read_bounded(process, timeout=1800, limit=MAX_REPLY)
        value = _json(raw)
        if (process.returncode != 0 or value.get("ok") is not True or value.get("protocol") != PROTOCOL or
                value.get("operation_id") != identity or
                value.get("runner_archive_sha256") != archive_sha or
                value.get("runner_manifest_sha256") != manifest_sha or
                value.get("dependencies_ready") is not True):
            raise InstallError("Целевой сервер не подтвердил проверенный исполнитель")

    def prepare(self, directory, runner, *, record=None):
        self._check_cancelled()
        if record is not None:
            RestoreRecordStore.validate(record)
            if record["target_id"] != self.record_target_id:
                raise InstallError("Для операции выбран другой SSH-маршрут")
        self.progress("Проверка всех пяти файлов и серверного исполнителя…")
        with self.artifacts_factory(directory, check=self._check_cancelled, progress=self.progress) as parts, \
                tempfile.TemporaryDirectory(prefix="sovagrid-restore-") as tmp:
            snapshot = Path(tmp) / "runner.tar.gz"
            expected = self.approved_archive_sha256 if record is None else record["request"]["runner_archive_sha256"]
            _summary, digest = _snapshot_with_digest(Path(runner), snapshot, expected)
            with tarfile.open(snapshot, "r:gz") as archive:
                try:
                    manifest_raw = archive.extractfile("sovagrid-bundle.json").read(512 * 1024 + 1)
                    script_raw = archive.extractfile(BOOTSTRAP).read(64 * 1024 + 1)
                except (KeyError, AttributeError):
                    raise InstallError("Серверный пакет ещё не содержит мастер полного восстановления") from None
            if len(manifest_raw) > 512 * 1024 or not 0 < len(script_raw) <= 64 * 1024:
                raise InstallError("Размер исполнителя восстановления неверен")
            manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
            identity = uuid.uuid4().hex if record is None else record["operation_id"]
            request = {"protocol": PROTOCOL, "operation_id": identity, "archive_id": parts.archive_id,
                       "runner_archive_sha256": digest, "runner_manifest_sha256": manifest_sha,
                       "artifacts": {part: parts.metadata[part] for part in ORDER}}
            if record is None:
                record = {"format": 1, "target_id": self.record_target_id, "operation_id": identity,
                          "created_at": int(time.time()), "folder": str(Path(directory).absolute()),
                          "runner_path": str(Path(runner).absolute()), "request": request}
            else:
                RestoreRecordStore.validate(record)
                if record["target_id"] != self.record_target_id or record["request"] != request:
                    raise InstallError("SSH-маршрут, исполнитель или копия изменились после сохранения")
            self.store.save(record)
            self.current_record = record
            self._bootstrap(snapshot, identity, digest, manifest_sha, script_raw.decode("utf-8"))
            with self.connection(identity) as channel:
                state = self._transfer_state(channel.request({"action": "init", "request": request}), request)
                for part in ORDER:
                    while state["artifacts"][part]["received"] < parts.metadata[part]["bytes"]:
                        offset = state["artifacts"][part]["received"]
                        pending = state.get("pending_chunk")
                        length = min(CHUNK, parts.metadata[part]["bytes"] - offset)
                        if pending is not None:
                            if (not isinstance(pending, dict) or set(pending) != {"part", "offset", "length", "sha256"} or
                                    pending["part"] != part or type(pending["offset"]) is not int or
                                    pending["offset"] != offset or
                                    type(pending["length"]) is not int or not 0 < pending["length"] <= length):
                                raise InstallError("Незавершённый фрагмент требует проверки приёмника")
                            length = pending["length"]
                        raw = parts.read_chunk(part, offset, length)
                        sha = hashlib.sha256(raw).hexdigest()
                        if pending is not None and pending["sha256"] != sha:
                            raise InstallError("Незавершённый фрагмент относится к другой копии")
                        self.progress(f"Передача {PART_LABELS[part]}: {offset + length:,} / {parts.metadata[part]['bytes']:,} байт")
                        next_state = self._transfer_state(channel.request(
                            {"action": "receive", "part": part, "offset": offset, "length": length, "sha256": sha},
                            raw, timeout=300), request)
                        if next_state["artifacts"][part]["received"] != offset + length:
                            raise InstallError("Приёмник не подтвердил переданный фрагмент")
                        state = next_state
                state = self._transfer_state(channel.request({"action": "register"}, timeout=2400), request)
                if not state["registered"]:
                    raise InstallError("Приёмник не завершил проверку копии")
                self.progress("Копия передана и проверена. Проверяем чистую цель и план восстановления…")
                return record, self._operation_reply(channel.request({"action": "preview"}, timeout=2400), record)

    @staticmethod
    def _operation_reply(value, record):
        if (value.get("request_sha256") != hashlib.sha256(_canonical(record["request"])).hexdigest() or
                value.get("archive_id") != record["request"]["archive_id"] or
                not isinstance(value.get("phase"), str) or
                re.fullmatch(r"[a-z][a-z_]{0,47}", value["phase"]) is None or
                any(type(value.get(key)) is not bool for key in
                    ("backend_supported", "target_ready", "apply_available")) or
                not isinstance(value.get("blockers"), list) or len(value["blockers"]) > 256 or
                any(not isinstance(code, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code) is None
                    for code in value["blockers"])):
            raise InstallError("Сервер вернул неверный план восстановления")
        if value["apply_available"] and (not value["backend_supported"] or
                                          not value["target_ready"] or value["blockers"]):
            raise InstallError("Сервер подтвердил противоречивый план восстановления")
        return value

    def action(self, record, action, **values):
        RestoreRecordStore.validate(record)
        if record["target_id"] != self.record_target_id:
            raise InstallError("Для операции выбран другой SSH-маршрут")
        allowed = {"preview": set(), "operation-status": set(), "recover": set(),
                   "start": {"apply_review_sha256"}, "retry": {"terminal_sha256"}}
        if action not in allowed or set(values) != allowed[action] or any(
                not isinstance(value, str) or SHA.fullmatch(value) is None for value in values.values()):
            raise InstallError("Неверное действие восстановления")
        with self.connection(record["operation_id"]) as channel:
            return self._operation_reply(channel.request({"action": action, **values}, timeout=2400), record)
