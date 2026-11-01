# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Review-first control of a promoted Hub's separate local Agent features."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import shlex
import subprocess
from typing import Callable
import uuid

from .approved_manifest import ApprovedManifestMixin
from .core import ConnectionOptions
from .installer import InstallError
from .promotion import PromotionController


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HELPER = "/opt/sovagrid-src/sovagrid-blueprint/deploy/local_operations.py"

# Standard-library-only probe. It runs before installed helper code and proves
# that the local helper and its imported promotion module belong to the exact
# approved, root-owned bundle. It returns no token or CA bytes.
_SOURCE_PROBE = r'''
import hashlib, json, pathlib, re, stat, sys, uuid
expected = sys.argv[1]
assert re.fullmatch('[0-9a-f]{64}', expected)
root = pathlib.Path('/opt/sovagrid-src')
for path in (root, root / 'sovagrid-blueprint', root / 'sovagrid-blueprint/deploy',
             pathlib.Path('/var/lib/sovagrid-promotion')):
    info = path.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
def checked_file(path, modes, limit):
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
    assert stat.S_IMODE(info.st_mode) in modes and 0 < info.st_size <= limit
    return path.read_bytes()
manifest_raw = checked_file(root / 'sovagrid-bundle.json', {0o644}, 524288)
assert hashlib.sha256(manifest_raw).hexdigest() == expected
manifest = json.loads(manifest_raw)
assert isinstance(manifest, dict) and set(manifest) == {'format', 'components', 'sha256'}
assert type(manifest['format']) is int and manifest['format'] == 1
hashes = manifest['sha256']
assert isinstance(hashes, dict)
required = (
    'sovagrid-blueprint/deploy/local_operations.py',
    'sovagrid-blueprint/deploy/promote_agent_only.py',
    'sovagrid-agent/deploy/sovagrid-terminal-local-control.socket',
    'sovagrid-agent/deploy/sovagrid-terminal-local-control.service',
)
for relative in required:
    digest = hashes.get(relative)
    assert isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest)
    if relative.startswith('sovagrid-blueprint/'):
        raw = checked_file(root / relative, {0o644, 0o755}, 1048576)
        assert hashlib.sha256(raw).hexdigest() == digest
pin = json.loads(checked_file(pathlib.Path('/var/lib/sovagrid-promotion/bundle-pin.json'), {0o600}, 32768))
assert isinstance(pin, dict) and set(pin) == {'protocol', 'manifest_sha256'}
assert type(pin['protocol']) is int and pin['protocol'] == 1 and pin['manifest_sha256'] == expected
local = json.loads(checked_file(pathlib.Path('/var/lib/sovagrid-promotion/local-agent.json'), {0o600}, 32768))
assert isinstance(local, dict) and set(local) == {'protocol', 'server_id', 'token_sha256', 'commands'}
assert type(local['protocol']) is int and local['protocol'] == 1
server_id = local['server_id']
assert isinstance(server_id, str) and str(uuid.UUID(server_id)) == server_id
assert type(local['commands']) is bool
print(json.dumps({'protocol': 1, 'manifest_sha256': expected,
                  'local_server_id': server_id, 'commands': local['commands']}, separators=(',', ':')))
'''


@dataclass(frozen=True)
class LocalOperationsState:
    options: ConnectionOptions
    manifest_sha256: str
    local_server_id: str
    phase: str
    terminal: bool
    files: bool
    requested_terminal: bool | None
    requested_files: bool | None
    external_agent_preserved: bool | None
    state_revision: str | None


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _json(raw: bytes) -> dict:
    if len(raw) > 4096:
        raise InstallError("Ответ локального Agent слишком велик")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise InstallError("Сервер прислал неверное состояние локального Agent") from exc
    if not isinstance(value, dict) or type(value.get("protocol")) is not int or value["protocol"] != 1:
        raise InstallError("Сервер прислал неподдерживаемое состояние локального Agent")
    return value


def _flags(value: object) -> tuple[bool, bool]:
    if (not isinstance(value, dict) or set(value) != {"protocol", "terminal", "files"} or
            type(value["protocol"]) is not int or value["protocol"] != 1 or
            type(value["terminal"]) is not bool or type(value["files"]) is not bool):
        raise InstallError("Сервер прислал неверные настройки терминала и файлов")
    return value["terminal"], value["files"]


class LocalOperationsController(ApprovedManifestMixin):
    def __init__(self, options: ConnectionOptions, *, approved_manifest_sha256: str | tuple[str, ...] | None,
                 popen: Callable[..., subprocess.Popen] = subprocess.Popen,
                 progress: Callable[[str], None] | None = None,
                 transport: PromotionController | None = None) -> None:
        self.transport = transport or PromotionController(
            options, approved_archive_sha256="0" * 64, popen=popen, progress=progress,
        )
        self.options = self.transport.options
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.progress = progress or (lambda _message: None)

    def _run(self, command: str, *, timeout: float = 90) -> tuple[int, bytes]:
        return self.transport._execute(self.transport._privileged + command, timeout=timeout)

    def _source(self) -> tuple[str, str]:
        approved = self.approved_manifest_sha256
        if approved is None:
            raise InstallError("Для настройки локального Agent нужен проверенный серверный выпуск")
        self.transport._verify_root_access()
        code, raw = self._run("/usr/bin/python3 -I -c " + shlex.quote(_SOURCE_PROBE) + " " + approved)
        if code != 0:
            raise InstallError("Серверный код локального Agent не совпадает с проверенным выпуском")
        value = _json(raw)
        if (set(value) != {"protocol", "manifest_sha256", "local_server_id", "commands"} or
                value["manifest_sha256"] != approved or
                not isinstance(value["local_server_id"], str) or
                type(value["commands"]) is not bool):
            raise InstallError("Сервер прислал неверное подтверждение исходников")
        try:
            if str(uuid.UUID(value["local_server_id"])) != value["local_server_id"]:
                raise ValueError("noncanonical UUID")
        except ValueError as exc:
            raise InstallError("Сервер прислал неверный ID локального Agent") from exc
        if not value["commands"]:
            raise InstallError("Сначала откройте «Разрешить команды своего Hub…» и подтвердите включение")
        return approved, value["local_server_id"]

    def _helper(self, action: str, feature: str | None = None, *,
                expected_state: str | None = None, timeout: float = 90) -> tuple[int, bytes]:
        if (action not in {"preview", "enable", "disable", "recover"} or
                (action in {"enable", "disable"} and feature not in {"terminal", "files"}) or
                (action in {"preview", "recover"} and feature is not None) or
                (action in {"preview", "recover"} and expected_state is not None) or
                (action in {"enable", "disable"} and
                 (expected_state is None or _SHA.fullmatch(expected_state) is None))):
            raise ValueError("unsupported local operation")
        command = "/usr/bin/python3 -I " + _HELPER + " " + action
        if feature is not None:
            command += " " + feature
        if expected_state is not None:
            command += " --expected-state " + expected_state
        return self._run(command, timeout=timeout)

    @staticmethod
    def _failure(raw: bytes) -> InstallError:
        lines = raw.splitlines()
        if b"SG_LOCAL_OPERATIONS_REFUSE:ROLLED_BACK" in lines:
            return InstallError("Изменение не удалось; прежние настройки локального Agent восстановлены")
        if b"SG_LOCAL_OPERATIONS_REFUSE:ROLLBACK_NEEDS_RECOVERY" in lines:
            return InstallError("Изменение прервано, требуется восстановление в этом мастере")
        if b"SG_LOCAL_OPERATIONS_REFUSE:COMMANDS_REQUIRED" in lines:
            return InstallError("Сначала разрешите команды для локального Agent в собственном Hub")
        if b"SG_LOCAL_OPERATIONS_REFUSE:EXTERNAL_CHANGED" in lines:
            return InstallError("Внешний Agent изменился; настройка локального Agent остановлена")
        if b"SG_LOCAL_OPERATIONS_REFUSE:STATE_CHANGED" in lines:
            return InstallError("Настройки локального Agent изменились; повторите проверку")
        return InstallError("Сервер отклонил действие с локальным Agent; повторно проверьте состояние")

    def _state(self, raw: bytes, manifest: str, local_id: str) -> LocalOperationsState:
        value = _json(raw)
        phase = value.get("phase")
        if phase == "ready":
            if (set(value) != {"protocol", "phase", "current", "local_server_id",
                               "external_agent_preserved", "state_revision"} or
                    value["local_server_id"] != local_id or
                    value["external_agent_preserved"] is not True or
                    not isinstance(value["state_revision"], str) or
                    _SHA.fullmatch(value["state_revision"]) is None):
                raise InstallError("Локальный Agent или внешний Agent не подтвердились")
            terminal, files = _flags(value["current"])
            return LocalOperationsState(self.options, manifest, local_id, phase,
                                        terminal, files, None, None, True, value["state_revision"])
        if phase == "recovery_required":
            if (set(value) != {"protocol", "phase", "current", "requested",
                               "external_agent_preserved", "state_revision"} or
                    value["external_agent_preserved"] is not None or
                    value["state_revision"] is not None):
                raise InstallError("Сервер прислал неверный журнал восстановления")
            terminal, files = _flags(value["current"])
            requested_terminal, requested_files = _flags(value["requested"])
            return LocalOperationsState(self.options, manifest, local_id, phase,
                                        terminal, files, requested_terminal, requested_files, None, None)
        raise InstallError("Сервер прислал неизвестный этап настройки локального Agent")

    def preview(self) -> LocalOperationsState:
        self.progress("Проверка SSH-маршрута и исходников локального Agent…")
        manifest, local_id = self._source()
        code, raw = self._helper("preview")
        if code != 0:
            raise self._failure(raw)
        return self._state(raw, manifest, local_id)

    def _recheck(self, expected: LocalOperationsState) -> None:
        if (expected.options != self.options or expected.manifest_sha256 != self.approved_manifest_sha256 or
                self.preview() != expected):
            raise InstallError("Состояние сервера изменилось; повторите проверку перед действием")

    def change(self, feature: str, enabled: bool, expected: LocalOperationsState) -> LocalOperationsState:
        if feature not in {"terminal", "files"} or type(enabled) is not bool:
            raise ValueError("unsupported local operation")
        if expected.phase != "ready" or expected.external_agent_preserved is not True:
            raise InstallError("Сначала восстановите незавершённую настройку локального Agent")
        self._recheck(expected)
        if expected.state_revision is None:
            raise InstallError("Сервер не подтвердил ревизию настроек локального Agent")
        if getattr(expected, feature) == enabled:
            return expected
        self.progress("Применение одной функции локального Agent…")
        code, raw = self._helper("enable" if enabled else "disable", feature,
                                 expected_state=expected.state_revision, timeout=420)
        if code != 0:
            raise self._failure(raw)
        result = self._state(raw, expected.manifest_sha256, expected.local_server_id)
        if (result.phase != "ready" or getattr(result, feature) != enabled or
                getattr(result, "files" if feature == "terminal" else "terminal") !=
                getattr(expected, "files" if feature == "terminal" else "terminal")):
            raise InstallError("Сервер не подтвердил выбранное изменение локального Agent")
        after = self.preview()
        if after != result:
            raise InstallError("Сервер изменился после настройки; повторите проверку")
        return after

    def recover(self, expected: LocalOperationsState) -> LocalOperationsState:
        if expected.phase != "recovery_required":
            raise InstallError("На сервере нет подтверждённой операции для восстановления")
        self._recheck(expected)
        self.progress("Возврат локального Agent к сохранённым настройкам…")
        code, raw = self._helper("recover", timeout=420)
        if code != 0:
            raise self._failure(raw)
        result = self._state(raw, expected.manifest_sha256, expected.local_server_id)
        if (result.phase != "ready" or result.terminal != expected.terminal or
                result.files != expected.files or self.preview() != result):
            raise InstallError("Сервер не подтвердил восстановление прежних настроек")
        return result
