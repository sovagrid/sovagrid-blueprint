# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Private, nonsecret marker for finding a host backup after SSH or app loss."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

from .auto_update import target_id
from .core import ConnectionOptions
from .installer import InstallError


SHA = re.compile(r"[0-9a-f]{64}\Z")
REQUEST = re.compile(r"[0-9a-f]{32}\Z")
MAX_BYTES = 512


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


@dataclass(frozen=True)
class HostBackupRequest:
    format: int
    target_id: str
    request_id: str
    manifest_sha256: str
    created_at: int
    mode: str

    def validated(self) -> "HostBackupRequest":
        if (type(self.format) is not int or self.format != 2 or
                not isinstance(self.target_id, str) or SHA.fullmatch(self.target_id) is None or
                not isinstance(self.request_id, str) or REQUEST.fullmatch(self.request_id) is None or
                not isinstance(self.manifest_sha256, str) or SHA.fullmatch(self.manifest_sha256) is None or
                type(self.created_at) is not int or not 1 <= self.created_at <= 253402300799 or
                self.mode not in ("online", "portable")):
            raise InstallError("Сохранённый запрос полной копии повреждён")
        return self

    @classmethod
    def new(cls, options: ConnectionOptions, request_id: str,
            manifest_sha256: str, *, mode: str = "online") -> "HostBackupRequest":
        return cls(2, target_id(options), request_id, manifest_sha256,
                   int(time.time()), mode).validated()


class HostBackupRequestStore:
    def __init__(self, directory: Path):
        self.directory = directory

    @staticmethod
    def default() -> "HostBackupRequestStore":
        if os.name == "nt":
            base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        else:
            base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        return HostBackupRequestStore(base / "sovagrid-connect" / "host-backup-requests")

    def _directory(self, *, create: bool) -> None:
        if create:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or
                os.name != "nt" and (info.st_uid != os.getuid() or
                                     stat.S_IMODE(info.st_mode) != 0o700)):
            raise InstallError("Каталог сохранённых запросов небезопасен")

    def _path(self, key: str) -> Path:
        if not isinstance(key, str) or SHA.fullmatch(key) is None:
            raise InstallError("Неверный SSH-маршрут запроса полной копии")
        return self.directory / (key + ".json")

    @staticmethod
    def _file(info: os.stat_result) -> None:
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                os.name != "nt" and (info.st_uid != os.getuid() or
                                     stat.S_IMODE(info.st_mode) != 0o600)):
            raise InstallError("Сохранённый запрос полной копии имеет небезопасные права")

    def load(self, options: ConnectionOptions) -> HostBackupRequest | None:
        return self.load_by_key(target_id(options))

    def save(self, request: HostBackupRequest, *, replacing: str | None = None) -> None:
        request.validated()
        self._directory(create=True)
        current = self.load_by_key(request.target_id)
        if (current is not None and current.request_id != replacing or
                current is None and replacing is not None):
            raise InstallError("Есть другой сохранённый запрос полной копии")
        raw = (json.dumps(asdict(request), sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(raw) > MAX_BYTES:
            raise InstallError("Сохранённый запрос полной копии слишком велик")
        temporary = self.directory / ("." + secrets.token_hex(16) + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._path(request.target_id))
            if os.name != "nt":
                folder_fd = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(folder_fd)
                finally:
                    os.close(folder_fd)
        finally:
            temporary.unlink(missing_ok=True)

    def clear(self, request: HostBackupRequest) -> None:
        request.validated()
        current = self.load_by_key(request.target_id)
        if current != request:
            raise InstallError("Сохранённый запрос изменился; удаление остановлено")
        self._path(request.target_id).unlink()
        if os.name != "nt":
            folder_fd = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(folder_fd)
            finally:
                os.close(folder_fd)

    def load_by_key(self, key: str) -> HostBackupRequest | None:
        # Only a saved, exact target digest is accepted. Caller already proved
        # route ownership by constructing the key with target_id().
        if not isinstance(key, str) or SHA.fullmatch(key) is None:
            raise InstallError("Неверный SSH-маршрут запроса полной копии")
        try:
            self._directory(create=False)
        except FileNotFoundError:
            return None
        try:
            fd = os.open(self._path(key), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise InstallError("Не удалось прочитать сохранённый запрос полной копии") from exc
        try:
            self._file(os.fstat(fd))
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_BYTES:
            raise InstallError("Сохранённый запрос полной копии слишком велик")
        try:
            value = json.loads(raw, object_pairs_hook=_unique)
            if not isinstance(value, dict):
                raise ValueError("shape")
            if set(value) == set(HostBackupRequest.__dataclass_fields__):
                request = HostBackupRequest(**value).validated()
            elif (set(value) == set(HostBackupRequest.__dataclass_fields__) - {"mode"} and
                  type(value["format"]) is int and value["format"] == 1):
                # Format 1 had only online jobs. Its exact shape is converted
                # on read; the next write persists the format 2 mode field.
                request = HostBackupRequest(**{**value, "format": 2, "mode": "online"}).validated()
            else:
                raise ValueError("shape")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise InstallError("Сохранённый запрос полной копии повреждён") from exc
        if request.target_id != key:
            raise InstallError("Сохранённый запрос относится к другому SSH-маршруту")
        return request
