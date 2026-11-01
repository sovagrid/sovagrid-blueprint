# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in, one-candidate update policy for one SSH target.

There is deliberately no "latest" URL here. A candidate is approved by its
exact archive SHA-256 and current server manifest. The client may check and
stage it automatically; applying requires an updater that invokes the remote
apply-auto mode, whose idle check runs under the server's update lock.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from .core import ConnectionOptions
from .installer import MAX_ARCHIVE_BYTES, ServerInstaller


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_POLICY_KEYS = frozenset({
    "format", "target_id", "archive_path", "archive_sha256",
    "expected_current_manifest", "enabled", "window_start_utc", "window_end_utc",
})
_MAX_POLICY_BYTES = 4096


class AutoUpdateError(ValueError):
    """A policy or local package cannot be used for unattended updates."""


def target_id(options: ConnectionOptions) -> str:
    """Bind approval to the exact SSH route and login, without storing secrets."""
    options = options.validated()
    route = {
        "host": options.host, "user": options.user, "port": options.port,
        "jump_host": options.jump_host, "jump_user": options.jump_user,
        "jump_port": options.jump_port, "host_key_alias": options.host_key_alias,
        "jump_host_key_alias": options.jump_host_key_alias,
        "identity": options.identity, "jump_identity": options.jump_identity,
        "ssh_executable": options.ssh_executable,
    }
    raw = json.dumps(route, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class AutoUpdatePolicy:
    format: int
    target_id: str
    archive_path: str
    archive_sha256: str
    expected_current_manifest: str
    enabled: bool = False
    window_start_utc: int = 0
    window_end_utc: int = 24

    @classmethod
    def approve(
        cls, options: ConnectionOptions, archive: Path, sha256: str,
        current_manifest: str, *, enabled: bool = False,
        window_start_utc: int = 0, window_end_utc: int = 24,
    ) -> "AutoUpdatePolicy":
        return cls(1, target_id(options), str(archive), sha256, current_manifest,
                   enabled, window_start_utc, window_end_utc).validated()

    def validated(self) -> "AutoUpdatePolicy":
        if type(self.format) is not int or self.format != 1:
            raise AutoUpdateError("Неподдерживаемый формат настройки обновлений")
        if (not isinstance(self.target_id, str) or not _DIGEST.fullmatch(self.target_id)
                or not isinstance(self.archive_sha256, str)
                or not _DIGEST.fullmatch(self.archive_sha256)
                or not isinstance(self.expected_current_manifest, str)
                or not _DIGEST.fullmatch(self.expected_current_manifest)):
            raise AutoUpdateError("Неверный отпечаток сервера или пакета")
        if (not isinstance(self.archive_path, str) or len(self.archive_path) > 2048
                or "\x00" in self.archive_path or not Path(self.archive_path).is_absolute()):
            raise AutoUpdateError("Укажите абсолютный путь к одобренному пакету")
        if type(self.enabled) is not bool:
            raise AutoUpdateError("Неверное состояние автообновления")
        if (type(self.window_start_utc) is not int or type(self.window_end_utc) is not int
                or not 0 <= self.window_start_utc < 24
                or not 1 <= self.window_end_utc <= 24
                or self.window_start_utc == self.window_end_utc):
            raise AutoUpdateError("Неверное окно обновления UTC")
        return self

    def due(self, timestamp: float) -> bool:
        self.validated()
        hour = datetime.fromtimestamp(timestamp, timezone.utc).hour
        start, end = self.window_start_utc, self.window_end_utc
        return self.enabled and (start <= hour < end if start < end else
                                 hour >= start or hour < end)


def _private_file(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise AutoUpdateError("Настройка обновлений должна быть обычным файлом")
    if os.name != "nt" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
        raise AutoUpdateError("Небезопасные права на настройку обновлений")


class AutoUpdatePolicyStore:
    """Small private JSON store; only the selected target's policy is read."""

    def __init__(self, directory: Path):
        self.directory = directory

    def _check_dir(self, *, create: bool) -> None:
        if create:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            info = self.directory.lstat()
        except OSError as exc:
            raise AutoUpdateError("Не удалось открыть каталог автообновлений") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise AutoUpdateError("Каталог автообновлений изменён")
        if os.name != "nt" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise AutoUpdateError("Небезопасные права на каталог автообновлений")

    def _path(self, key: str) -> Path:
        if not isinstance(key, str) or not _DIGEST.fullmatch(key):
            raise AutoUpdateError("Неверный идентификатор сервера")
        return self.directory / (key + ".json")

    def load(self, key: str) -> AutoUpdatePolicy | None:
        try:
            self.directory.lstat()
        except FileNotFoundError:
            return None
        self._check_dir(create=False)
        destination = self._path(key)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(destination, flags)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise AutoUpdateError("Не удалось прочитать настройку обновлений") from exc
        with os.fdopen(fd, "rb") as stream:
            _private_file(os.fstat(stream.fileno()))
            raw = stream.read(_MAX_POLICY_BYTES + 1)
        if len(raw) > _MAX_POLICY_BYTES:
            raise AutoUpdateError("Настройка обновлений слишком велика")
        try:
            data = json.loads(raw)
        except (UnicodeError, ValueError) as exc:
            raise AutoUpdateError("Настройка обновлений повреждена") from exc
        if not isinstance(data, dict) or set(data) != _POLICY_KEYS:
            raise AutoUpdateError("Неизвестные поля в настройке обновлений")
        policy = AutoUpdatePolicy(**data).validated()
        if policy.target_id != key:
            raise AutoUpdateError("Настройка принадлежит другому серверу")
        return policy

    def save(self, policy: AutoUpdatePolicy) -> None:
        policy.validated()
        self._check_dir(create=True)
        destination = self._path(policy.target_id)
        try:
            old = destination.lstat()
        except FileNotFoundError:
            old = None
        if old is not None:
            _private_file(old)
        raw = (json.dumps(asdict(policy), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(raw) > _MAX_POLICY_BYTES:
            raise AutoUpdateError("Настройка обновлений слишком велика")
        temporary = self.directory / ("." + secrets.token_hex(16) + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


@dataclass(frozen=True)
class AutoUpdateOutcome:
    status: str  # disabled, outside_window, staged, applied
    archive_sha256: str
    current_manifest: str


def _verify_archive_pin(path: Path, expected: str) -> None:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_ARCHIVE_BYTES:
            raise AutoUpdateError("Одобренный пакет отсутствует или имеет неверный тип")
        digest = hashlib.sha256()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != info.st_dev
                    or opened.st_ino != info.st_ino or not 0 < opened.st_size <= MAX_ARCHIVE_BYTES):
                raise AutoUpdateError("Одобренный пакет изменился при открытии")
            total = 0
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise AutoUpdateError("Одобренный пакет слишком велик")
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise AutoUpdateError("SHA-256 одобренного пакета изменился")
    except OSError as exc:
        raise AutoUpdateError("Не удалось прочитать одобренный пакет") from exc


def run_pinned_update(
    policy: AutoUpdatePolicy, options: ConnectionOptions, installer: ServerInstaller,
    *, now: float,
) -> AutoUpdateOutcome:
    """Check and stage a pin, then call the remote idle-gated applier if present.

    Older ServerInstaller versions only stage: they do not expose the separate
    apply_automatic_update method with a remote idle gate. The manual apply
    method is never used by this controller.
    """
    policy.validated()
    if policy.target_id != target_id(options):
        raise AutoUpdateError("Одобрение относится к другому SSH-соединению")
    installer_options = getattr(installer, "options", None)
    if installer_options is None or target_id(installer_options) != policy.target_id:
        raise AutoUpdateError("Обновлятор подключён к другому SSH-серверу")
    if options.validated().user != "root":
        raise AutoUpdateError("Автообновление требует SSH-входа root")
    if not policy.enabled:
        return AutoUpdateOutcome("disabled", policy.archive_sha256, policy.expected_current_manifest)
    if not policy.due(now):
        return AutoUpdateOutcome("outside_window", policy.archive_sha256, policy.expected_current_manifest)
    if getattr(installer, "automatic_apply_supported", True) is False:
        raise AutoUpdateError("Применение при простое через Connect пока недоступно; старое локальное разрешение выключено")
    archive = Path(policy.archive_path)
    _verify_archive_pin(archive, policy.archive_sha256)
    preview = installer.preview_update(archive, expected_sha256=policy.archive_sha256)
    if preview.sha256 != policy.archive_sha256:
        raise AutoUpdateError("Проверка SHA-256 пакета дала другой результат")
    if preview.current_manifest_sha256 != policy.expected_current_manifest:
        raise AutoUpdateError("Версия сервера изменилась после одобрения; повторите проверку")
    prepared = installer.prepare_update(archive, expected_sha256=policy.archive_sha256)
    if prepared.sha256 != policy.archive_sha256 or prepared.remote_path != (
        f"/opt/sovagrid-candidates/{policy.archive_sha256}"
    ):
        raise AutoUpdateError("Подготовленный пакет не совпал с одобренным")
    apply_auto = getattr(installer, "apply_automatic_update", None)
    if apply_auto is None:
        return AutoUpdateOutcome("staged", policy.archive_sha256, policy.expected_current_manifest)
    apply_auto(prepared, expected_current_manifest=policy.expected_current_manifest)
    return AutoUpdateOutcome("applied", policy.archive_sha256, policy.expected_current_manifest)
