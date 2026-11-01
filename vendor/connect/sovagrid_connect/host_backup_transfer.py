# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Private, hash-bound streaming of a verified portable host backup pair."""

from __future__ import annotations

import ctypes
from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import sys
import threading
from typing import Callable

from .installer import InstallError
from .release_feed_remote import SOURCE_PROOF


MAX_ARCHIVE_BYTES = 8 * 1024**3
MAX_HOST_MANIFEST_BYTES = 2048
MAX_IMAGE_MANIFEST_BYTES = 4096
MAX_RECEIPT_BYTES = 8192
TRANSFER_TIMEOUT = 4 * 3600
CHUNK_BYTES = 1024 * 1024
PROGRESS_BYTES = 64 * 1024**2
SHA = re.compile(r"[0-9a-f]{64}\Z")
IDENTITY = re.compile(r"[0-9a-f]{32}\Z")
ZERO_DIGEST = "0" * 64
METADATA_LIMITS = {"host_manifest": MAX_HOST_MANIFEST_BYTES,
                   "images_manifest": MAX_IMAGE_MANIFEST_BYTES}
PARTS = ("host_manifest", "host", "images_manifest", "images")
ARCHIVE_FIELDS = frozenset(("id", "created_at", "layout", "bytes", "files"))
HOST_MANIFEST_FIELDS = ARCHIVE_FIELDS | {"protocol", "sha256", "source_manifest_sha256"}
IMAGE_MANIFEST_FIELDS = frozenset((
    "protocol", "id", "host_archive_sha256", "source_manifest_sha256",
    "layout", "created_at", "bytes", "sha256", "files", "images",
    "container_ids", "exported_configs", "rootfs_sha256",
))


# The source manifest is checked on the same root SSH session that opens each
# artifact. No caller-supplied path reaches the server. Refusals go only to the
# suppressed SSH stderr; stdout is exclusively the selected artifact stream.
STREAM_SCRIPT = SOURCE_PROOF + r'''
fds = []
try:
    need(len(sys.argv) == 6, 'ARGS')
    manifest, kind, identity, length_text, wanted = sys.argv[1:]
    source(manifest)
    need(kind in ('host', 'images', 'host_manifest', 'images_manifest') and
         re.fullmatch(r'[0-9a-f]{32}', identity) is not None and
         re.fullmatch(r'[0-9]{1,10}', length_text) is not None and
         SHA.fullmatch(wanted) is not None, 'ARGS')
    length = int(length_text)
    limits = {'host_manifest': 2048, 'images_manifest': 4096}
    metadata = kind in limits
    need((length == limits[kind] and wanted == '0' * 64) if metadata else
         (0 < length <= 8 * 1024**3), 'SIZE')
    names = (['var', 'lib', 'sovagrid-host-backups'] if kind in ('host', 'host_manifest') else
             ['var', 'lib', 'sovagrid-host-image-exports', identity])
    filename = {'host': identity + '.tar.gz',
                'host_manifest': identity + '.manifest.json',
                'images': 'images.tar', 'images_manifest': 'manifest.json'}[kind]
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    fds.append(fd)
    for index, name in enumerate(names):
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                     os.O_CLOEXEC, dir_fd=fd)
        fds.append(fd)
        info = os.fstat(fd)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
             (stat.S_IMODE(info.st_mode) == 0o700 if index >= 2 else
              not info.st_mode & 0o022), 'UNSAFE_DIRECTORY')
        if index >= 2:
            need(info.st_gid == 0, 'UNSAFE_DIRECTORY')
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                 dir_fd=fd)
    fds.append(fd)
    before = os.fstat(fd)
    need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
         before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o600 and
         before.st_nlink == 1 and
         (0 < before.st_size <= length if metadata else before.st_size == length),
         'UNSAFE_FILE')
    fingerprint = lambda info: (info.st_dev, info.st_ino, info.st_mode,
                                info.st_uid, info.st_gid, info.st_nlink,
                                info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    digest = hashlib.sha256()
    remaining = before.st_size
    while remaining:
        block = os.read(fd, min(1024 * 1024, remaining))
        need(block, 'SHORT_FILE')
        digest.update(block)
        remaining -= len(block)
        view = memoryview(block)
        while view:
            written = os.write(1, view)
            need(written > 0, 'STREAM_FAILED')
            view = view[written:]
    need(not os.read(fd, 1) and (metadata or digest.hexdigest() == wanted) and
         fingerprint(os.fstat(fd)) == fingerprint(before), 'FILE_CHANGED')
except (Refused, OSError, ValueError, TypeError, UnicodeError):
    raise SystemExit(40)
finally:
    for fd in reversed(fds):
        os.close(fd)
'''


def _write_all(fd: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _unique(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate metadata field")
        value[key] = item
    return value


def _read_metadata(fd: int, size: int, digest: str, limit: int) -> dict:
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
            before.st_size != size or not 0 < size <= limit):
        raise InstallError("Манифест переносимой копии изменился")
    os.lseek(fd, 0, os.SEEK_SET)
    raw = bytearray()
    while len(raw) < size:
        block = os.read(fd, size - len(raw))
        if not block:
            raise InstallError("Манифест переносимой копии неполный")
        raw.extend(block)
    after = os.fstat(fd)
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
         before.st_ctime_ns) !=
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
         after.st_ctime_ns) or hashlib.sha256(raw).hexdigest() != digest):
        raise InstallError("Манифест переносимой копии изменился")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise InstallError("Манифест переносимой копии повреждён") from exc
    if not isinstance(value, dict):
        raise InstallError("Манифест переносимой копии повреждён")
    return value


def _check_metadata(kind: str, value: dict, archive: dict,
                    image_bytes: int, receipt: dict) -> None:
    if kind == "host_manifest":
        expected = {**archive, "protocol": "sovagrid-host-backup-v1",
                    "sha256": receipt["host_archive_sha256"],
                    "source_manifest_sha256": receipt["source_manifest_sha256"]}
        valid = (set(value) == HOST_MANIFEST_FIELDS and value == expected and
                 type(value["bytes"]) is int and type(value["files"]) is int)
    elif kind == "images_manifest":
        fixed = {"protocol": "sovagrid-host-images-v1", "id": archive["id"],
                 "host_archive_sha256": receipt["host_archive_sha256"],
                 "source_manifest_sha256": receipt["source_manifest_sha256"],
                 "layout": archive["layout"], "bytes": image_bytes,
                 "sha256": receipt["images_sha256"]}
        for name in ("images", "container_ids", "exported_configs", "rootfs_sha256"):
            fixed[name] = receipt[name]
        stamp = value.get("created_at")
        try:
            valid_time = (isinstance(stamp, str) and len(stamp) <= 40 and
                          stamp.endswith("+00:00") and
                          datetime.fromisoformat(stamp).utcoffset() == timedelta(0))
        except ValueError:
            valid_time = False
        valid = (set(value) == IMAGE_MANIFEST_FIELDS and valid_time and
                 type(value.get("bytes")) is int and
                 type(value.get("files")) is int and 0 < value["files"] <= 20_000 and
                 all(value.get(name) == expected for name, expected in fixed.items()))
    else:
        raise InstallError("Неизвестный манифест переносимой копии")
    if not valid:
        raise InstallError("Манифест переносимой копии не соответствует квитанции")


def _stream_remote(transport, kind: str, identity: str, manifest: str,
                   expected_size: int, expected_sha256: str, output_fd: int,
                   progress: Callable[[str], None]) -> tuple[int, str]:
    metadata = kind in METADATA_LIMITS
    if (kind not in PARTS or IDENTITY.fullmatch(identity) is None or
            SHA.fullmatch(manifest) is None or SHA.fullmatch(expected_sha256) is None or
            type(expected_size) is not int or
            (expected_size != METADATA_LIMITS[kind] or expected_sha256 != ZERO_DIGEST
             if metadata else not 0 < expected_size <= MAX_ARCHIVE_BYTES)):
        raise InstallError("Неверные параметры передачи переносимой копии")
    command = (transport._privileged + "/usr/bin/python3 -B -I -c " +
               shlex.quote(STREAM_SCRIPT) + " " + manifest + " " + kind + " " +
               identity + " " + str(expected_size) + " " + expected_sha256)
    manager = transport.manager
    received = 0
    digest = hashlib.sha256()
    timed_out = threading.Event()
    process = None

    def stop_on_timeout() -> None:
        timed_out.set()
        if process is not None and process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass

    with manager._session() as (config, helper):
        # The transport already selected its explicit root/sudo prefix.
        process = manager._ssh(config, helper, command, privileged=False)
        timer = threading.Timer(TRANSFER_TIMEOUT, stop_on_timeout)
        timer.daemon = True
        timer.start()
        try:
            if process.stdout is None:
                raise InstallError("SSH не открыл поток переносимой копии")
            next_progress = PROGRESS_BYTES
            while True:
                block = process.stdout.read(min(CHUNK_BYTES, expected_size - received + 1))
                if not block:
                    break
                received += len(block)
                if received > expected_size:
                    raise InstallError("Сервер передал слишком большой файл переносимой копии")
                digest.update(block)
                _write_all(output_fd, block)
                if received >= next_progress:
                    progress(f"Получено {received // (1024**2)} МиБ переносимой копии…")
                    next_progress += PROGRESS_BYTES
            process.wait()
        finally:
            timer.cancel()
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            process.wait()
            if process.stdout is not None:
                process.stdout.close()
            with manager._lock:
                if manager._process is process:
                    manager._process = None
    if (timed_out.is_set() or process.returncode != 0 or
            (not 0 < received <= expected_size if metadata else received != expected_size) or
            (not metadata and digest.hexdigest() != expected_sha256)):
        raise InstallError("Переданный архив переносимой копии не прошёл проверку")
    os.fsync(output_fd)
    return received, digest.hexdigest()


def _publish_exclusive(parent_fd: int, stage_name: str, final_name: str) -> None:
    """Rename a complete directory without replacing an existing destination."""
    if sys.platform == "darwin":
        routine, flag = "renameatx_np", 0x00000004  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        routine, flag = "renameat2", 1  # RENAME_NOREPLACE
    else:
        raise InstallError("Безопасное сохранение копии недоступно на этой системе")
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, routine, None)
    if rename is None:
        raise InstallError("Безопасное сохранение копии недоступно на этой системе")
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(parent_fd, os.fsencode(stage_name), parent_fd,
              os.fsencode(final_name), flag) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _open_destination(destination: Path) -> int:
    if not destination.is_absolute():
        raise InstallError("Выберите существующий локальный каталог для переносимой копии")
    fd = -1
    try:
        before = destination.lstat()
        if not stat.S_ISDIR(before.st_mode):
            raise InstallError("Выбранный путь не является обычным каталогом")
        fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        after = os.fstat(fd)
        if (not stat.S_ISDIR(after.st_mode) or
                (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)):
            raise InstallError("Выбранный каталог изменился")
        return fd
    except InstallError:
        if fd >= 0:
            os.close(fd)
        raise
    except OSError as exc:
        if fd >= 0:
            os.close(fd)
        raise InstallError("Не удалось открыть выбранный каталог") from exc


def _windows_protect(path: Path, *, directory: bool = False,
                     sid: str | None = None) -> str:
    from .enrollment_journal import (EnrollmentJournalError, _windows_acl,
                                     _windows_protect)
    try:
        protected_sid = _windows_protect(path, directory=directory, sid=sid)
        _windows_acl(path, protected_sid)
        return protected_sid
    except EnrollmentJournalError as exc:
        raise InstallError("Не удалось ограничить доступ к переносимой копии") from exc


def _windows_verify(path: Path, sid: str, *, directory: bool = False) -> None:
    from .enrollment_journal import EnrollmentJournalError, _windows_acl
    info = path.lstat()
    if (not (stat.S_ISDIR(info.st_mode) if directory else
             stat.S_ISREG(info.st_mode) and info.st_nlink == 1) or
            getattr(info, "st_file_attributes", 0) & 0x400):
        raise InstallError("Права локальной переносимой копии изменились")
    try:
        _windows_acl(path, sid)
    except EnrollmentJournalError as exc:
        raise InstallError("Права локальной переносимой копии изменились") from exc


def _windows_destination(destination: Path) -> os.stat_result:
    if not destination.is_absolute():
        raise InstallError("Выберите существующий локальный каталог для переносимой копии")
    for path in (destination, *destination.parents):
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or
                getattr(info, "st_file_attributes", 0) & 0x400):
            raise InstallError("Выбранный путь содержит ссылку или не является каталогом")
        if path == destination:
            selected = info
    return selected


def _windows_publish(stage: Path, final: Path) -> None:
    # MOVEFILE_WRITE_THROUGH without MOVEFILE_REPLACE_EXISTING. Both paths
    # share a parent, so Windows performs an exclusive same-volume rename.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.MoveFileExW.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p,
                                   ctypes.c_ulong)
    kernel.MoveFileExW.restype = ctypes.c_int
    if not kernel.MoveFileExW(str(stage), str(final), 0x8):
        raise ctypes.WinError(ctypes.get_last_error())


def _filenames(archive_id: str) -> tuple[str, ...]:
    return (archive_id + ".manifest.json", archive_id + ".tar.gz",
            "manifest.json", "images.tar", "receipt.json")


def _parts(archive_id: str, archive_bytes: int, image_bytes: int,
           receipt: dict) -> tuple[tuple[str, str, int, str], ...]:
    return ((archive_id + ".manifest.json", "host_manifest",
             MAX_HOST_MANIFEST_BYTES, ZERO_DIGEST),
            (archive_id + ".tar.gz", "host", archive_bytes,
             receipt["host_archive_sha256"]),
            ("manifest.json", "images_manifest",
             MAX_IMAGE_MANIFEST_BYTES, ZERO_DIGEST),
            ("images.tar", "images", image_bytes, receipt["images_sha256"]))


def _windows_cleanup(folder: Path, original: os.stat_result,
                     archive_id: str) -> None:
    try:
        info = folder.lstat()
    except FileNotFoundError:
        return
    if (not stat.S_ISDIR(info.st_mode) or
            getattr(info, "st_file_attributes", 0) & 0x400 or
            (info.st_dev, info.st_ino) != (original.st_dev, original.st_ino)):
        return
    for name in _filenames(archive_id):
        try:
            (folder / name).unlink()
        except FileNotFoundError:
            pass
    folder.rmdir()


def _export_windows(transport, destination: Path, *, archive_id: str,
                    archive_bytes: int, image_bytes: int, receipt: dict,
                    archive_record: dict,
                    raw_receipt: bytes, current_manifest_sha256: str,
                    progress: Callable[[str], None]) -> Path:
    try:
        selected = _windows_destination(destination)
        final = destination / ("sovagrid-backup-" + archive_id)
        if os.path.lexists(final):
            raise InstallError("Папка этой переносимой копии уже существует")
        stage = destination / (".sovagrid-backup-" + archive_id + "." +
                               secrets.token_hex(16) + ".partial")
        stage.mkdir(mode=0o700)
        original = stage.lstat()
        published = completed = False
        try:
            sid = _windows_protect(stage, directory=True)
            if list(stage.iterdir()):
                raise InstallError("Временная папка переносимой копии изменена")
            for filename, kind, size, digest in _parts(
                    archive_id, archive_bytes, image_bytes, receipt):
                progress("Передаём архив узла…" if kind == "host" else
                         "Передаём архив образов контейнеров…" if kind == "images" else
                         "Передаём манифест переносимой копии…")
                path = stage / filename
                fd = os.open(path, (os.O_RDWR if kind in METADATA_LIMITS else os.O_WRONLY) |
                             os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_BINARY", 0), 0o600)
                try:
                    _windows_protect(path, sid=sid)
                    _windows_verify(path, sid)
                    received, actual = _stream_remote(
                        transport, kind, archive_id, current_manifest_sha256,
                        size, digest, fd, progress)
                    if kind in METADATA_LIMITS:
                        _check_metadata(kind, _read_metadata(
                            fd, received, actual, size), archive_record,
                            image_bytes, receipt)
                finally:
                    os.close(fd)
            path = stage / "receipt.json"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_BINARY", 0), 0o600)
            try:
                _windows_protect(path, sid=sid)
                _windows_verify(path, sid)
                _write_all(fd, raw_receipt)
                os.fsync(fd)
            finally:
                os.close(fd)
            for name in _filenames(archive_id):
                _windows_verify(stage / name, sid)
            _windows_verify(stage, sid, directory=True)
            current = _windows_destination(destination)
            if (current.st_dev, current.st_ino) != (selected.st_dev, selected.st_ino):
                raise InstallError("Выбранный каталог изменился во время передачи")
            _windows_publish(stage, final)
            published = True
            progress("Переносимая копия сохранена и проверена.")
            completed = True
            return final
        finally:
            if not completed:
                _windows_cleanup(final if published else stage, original,
                                 archive_id)
    except InstallError:
        raise
    except (OSError, ValueError) as exc:
        raise InstallError("Не удалось безопасно сохранить переносимую копию") from exc


def _absent(parent_fd: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise InstallError("Папка этой переносимой копии уже существует")


def _cleanup(parent_fd: int, stage_fd: int, name: str,
             archive_id: str) -> None:
    for filename in _filenames(archive_id):
        try:
            os.unlink(filename, dir_fd=stage_fd)
        except FileNotFoundError:
            pass
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        opened = os.fstat(stage_fd)
        if (info.st_dev, info.st_ino) == (opened.st_dev, opened.st_ino):
            os.rmdir(name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass


def export_portable_files(transport, destination: Path, *, archive_id: str,
                          archive_bytes: int, image_bytes: int, receipt: dict,
                          archive_record: dict,
                          current_manifest_sha256: str,
                          progress: Callable[[str], None]) -> Path:
    """Publish only a fully synced and hash-matched pair in a new private folder."""
    if (not isinstance(archive_id, str) or IDENTITY.fullmatch(archive_id) is None or
            not isinstance(current_manifest_sha256, str) or
            SHA.fullmatch(current_manifest_sha256) is None or
            not isinstance(receipt, dict) or receipt.get("host_archive_id") != archive_id or
            not isinstance(archive_record, dict) or set(archive_record) != ARCHIVE_FIELDS or
            archive_record["id"] != archive_id or
            archive_record["bytes"] != archive_bytes or
            archive_record["layout"] not in ("full", "hub-only") or
            type(archive_record["files"]) is not int or archive_record["files"] <= 0 or
            not isinstance(archive_record["created_at"], str) or
            not 0 < len(archive_record["created_at"]) <= 40):
        raise InstallError("Неверная квитанция переносимой копии")
    raw_receipt = (json.dumps(receipt, sort_keys=True,
                              separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    if not 0 < len(raw_receipt) <= MAX_RECEIPT_BYTES:
        raise InstallError("Квитанция переносимой копии слишком велика")
    try:
        destination = Path(destination)
    except (TypeError, ValueError) as exc:
        raise InstallError("Выберите существующий локальный каталог") from exc
    if os.name == "nt":
        return _export_windows(
            transport, destination, archive_id=archive_id,
            archive_bytes=archive_bytes, image_bytes=image_bytes,
            receipt=receipt, archive_record=archive_record,
            raw_receipt=raw_receipt,
            current_manifest_sha256=current_manifest_sha256,
            progress=progress)
    parent_fd = _open_destination(destination)
    final_name = "sovagrid-backup-" + archive_id
    stage_name = "." + final_name + "." + secrets.token_hex(16) + ".partial"
    stage_fd = -1
    created = False
    published = False
    completed = False
    try:
        _absent(parent_fd, final_name)
        os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
        created = True
        stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY |
                           os.O_NOFOLLOW, dir_fd=parent_fd)
        info = os.fstat(stage_fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise InstallError("Временная папка переносимой копии изменилась")
        os.fchmod(stage_fd, 0o700)
        if stat.S_IMODE(os.fstat(stage_fd).st_mode) != 0o700:
            raise InstallError("Не удалось защитить временную папку переносимой копии")
        for filename, kind, size, digest in _parts(
                archive_id, archive_bytes, image_bytes, receipt):
            progress("Передаём архив узла…" if kind == "host" else
                     "Передаём архив образов контейнеров…" if kind == "images" else
                     "Передаём манифест переносимой копии…")
            fd = os.open(filename, (os.O_RDWR if kind in METADATA_LIMITS else os.O_WRONLY) |
                         os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | getattr(os, "O_BINARY", 0),
                         0o600, dir_fd=stage_fd)
            try:
                os.fchmod(fd, 0o600)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                        info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
                    raise InstallError("Не удалось защитить архив переносимой копии")
                received, actual = _stream_remote(
                    transport, kind, archive_id, current_manifest_sha256,
                    size, digest, fd, progress)
                if kind in METADATA_LIMITS:
                    _check_metadata(kind, _read_metadata(fd, received, actual, size),
                                    archive_record, image_bytes, receipt)
            finally:
                os.close(fd)
        fd = os.open("receipt.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | getattr(os, "O_BINARY", 0),
                     0o600, dir_fd=stage_fd)
        try:
            os.fchmod(fd, 0o600)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
                raise InstallError("Не удалось защитить квитанцию переносимой копии")
            _write_all(fd, raw_receipt)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(stage_fd)
        _publish_exclusive(parent_fd, stage_name, final_name)
        published = True
        os.fsync(parent_fd)
        current = destination.lstat()
        opened = os.fstat(parent_fd)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise InstallError("Выбранный каталог изменился во время передачи")
        progress("Переносимая копия сохранена и проверена.")
        completed = True
        return destination / final_name
    except OSError as exc:
        raise InstallError("Не удалось сохранить переносимую копию") from exc
    finally:
        try:
            if stage_fd >= 0 and not completed:
                _cleanup(parent_fd, stage_fd,
                         final_name if published else stage_name, archive_id)
            elif created and stage_fd < 0:
                os.rmdir(stage_name, dir_fd=parent_fd)
        finally:
            try:
                if stage_fd >= 0:
                    os.close(stage_fd)
            finally:
                os.close(parent_fd)
