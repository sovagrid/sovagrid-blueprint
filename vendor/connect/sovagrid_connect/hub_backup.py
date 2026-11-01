# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Pinned root SSH access to Hub's bounded backup metadata CLI."""

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
from .local_operations import _unique
from .promotion import PromotionController
from .hub_backup_remote import SCRIPT


SHA = re.compile(r"[0-9a-f]{64}\Z")
BACKUP_ENTRY = (
    "import sys; "
    "sys.path.insert(0, '/opt/sovagrid-src/sovagrid-hub'); "
    "from sovagrid_hub.backup import main; "
    "raise SystemExit(main())"
)
RESTORE_ENTRY = (
    "import sys; "
    "sys.path.insert(0, '/opt/sovagrid-src/sovagrid-hub'); "
    "from sovagrid_hub.backup_restore import main; "
    "raise SystemExit(main())"
)
RESTORE_PHASES = frozenset((
    "pending", "stopping", "stopped", "planning", "planned", "applying",
    "applied", "starting", "started", "finalizing", "complete",
    "failed_recovered", "recovery_required",
))
RESTORE_ERROR = re.compile(r"[A-Z][A-Z0-9_]{2,63}\Z")
MAX_DATABASE_BYTES = 4 * 1024**3
ERRORS = {
    "TOO_MANY_SNAPSHOTS": "Достигнут предел резервных копий. Проверьте сервер.",
    "INSUFFICIENT_SPACE": "Недостаточно свободного места для резервной копии.",
    "TOKEN_DATABASE_MISMATCH": "Настройки Telegram и база Hub расходятся. Копия не создана.",
    "TOKEN_SOURCE_AMBIGUOUS": "Найдено два источника токена Telegram. Проверьте сервер.",
    "HASH_MISMATCH": "Резервная копия изменилась и не прошла проверку.",
    "DATABASE_INTEGRITY": "База данных не прошла проверку целостности.",
    "DATABASE_SCHEMA": "Схема базы данных не поддерживается.",
    "SNAPSHOT_TIMEOUT": "Создание копии заняло слишком много времени. Проверьте список.",
}


def _object(raw: bytes, maximum: int = 65536) -> dict:
    if len(raw) > maximum:
        raise InstallError("Сервер прислал слишком большой ответ о резервных копиях")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise InstallError("Сервер прислал неверный ответ о резервных копиях") from exc
    if not isinstance(value, dict):
        raise InstallError("Сервер прислал неверный ответ о резервных копиях")
    return value


def _id(value: object) -> str:
    if not isinstance(value, str):
        raise InstallError("Неверный идентификатор резервной копии")
    try:
        if str(uuid.UUID(value)) == value:
            return value
    except ValueError:
        pass
    raise InstallError("Неверный идентификатор резервной копии")


@dataclass(frozen=True)
class HubBackupState:
    options: ConnectionOptions
    manifest_sha256: str
    backups_present: bool
    ids: tuple[str, ...]


@dataclass(frozen=True)
class HubBackupDetails:
    id: str
    created_at: int
    database_bytes: int
    telegram_token_included: bool
    verified: bool


@dataclass(frozen=True)
class HubRestoreStatus:
    request_id: str
    target_id: str
    phase: str
    safety_id: str | None
    plan_id: str | None
    hub_running: bool | None
    error: str | None
    ok: bool
    created_at: int


class HubBackupController(ApprovedManifestMixin):
    def __init__(self, options: ConnectionOptions, *, approved_manifest_sha256: str | tuple[str, ...] | None,
                 popen: Callable[..., subprocess.Popen] = subprocess.Popen,
                 progress: Callable[[str], None] | None = None,
                 transport: PromotionController | None = None):
        self.transport = transport or PromotionController(
            options, approved_archive_sha256="0" * 64, popen=popen, progress=progress)
        self.options = self.transport.options
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.progress = progress or (lambda _message: None)

    def _source(self) -> bool:
        expected = self.approved_manifest_sha256
        if expected is None:
            raise InstallError("Резервные копии ждут общий проверенный серверный выпуск")
        self.transport._verify_root_access()
        command = (self.transport._privileged + "/usr/bin/python3 -B -I -c " +
                   shlex.quote(SCRIPT) + " " + expected)
        code, raw = self.transport._execute(command, timeout=60)
        if code != 0:
            raise InstallError("Код или данные Hub не совпадают с проверенным выпуском. Сервер не изменён")
        value = _object(raw, 1024)
        if (set(value) != {"protocol", "manifest_sha256", "backups_present"} or
                value["protocol"] != 1 or value["manifest_sha256"] != expected or
                type(value["backups_present"]) is not bool):
            raise InstallError("Код или данные Hub не совпадают с проверенным выпуском. Сервер не изменён")
        return value["backups_present"]

    def _restore_source(self) -> None:
        expected = self.approved_manifest_sha256
        if expected is None:
            raise InstallError("Восстановление ждёт общий проверенный серверный выпуск")
        self.transport._verify_root_access()
        command = (self.transport._privileged + "/usr/bin/python3 -B -I -c " +
                   shlex.quote(SCRIPT) + " " + expected + " source-only")
        code, raw = self.transport._execute(command, timeout=60)
        if code != 0:
            raise InstallError("Код Hub не совпадает с проверенным выпуском. Сервер не изменён")
        value = _object(raw, 1024)
        if (set(value) != {"protocol", "manifest_sha256", "source_verified"} or
                type(value["protocol"]) is not int or value["protocol"] != 1 or
                value["manifest_sha256"] != expected or value["source_verified"] is not True):
            raise InstallError("Код Hub не совпадает с проверенным выпуском. Сервер не изменён")

    def _action(self, action: str, identity: str | None = None) -> dict:
        if action not in ("list", "create", "verify") or (identity is None) != (action != "verify"):
            raise InstallError("Недопустимое действие с резервной копией")
        argument = "" if identity is None else " " + _id(identity)
        command = (self.transport._privileged + "/usr/bin/python3 -B -I -c " +
                   shlex.quote(BACKUP_ENTRY) + " " + action + argument)
        code, raw = self.transport._execute(command, timeout={
            "list": 90, "create": 900, "verify": 600,
        }[action])
        try:
            value = _object(raw)
        except InstallError as exc:
            if action == "create":
                raise InstallError("Ответ о создании не получен: копия могла появиться. "
                                   "Обновите список и проверьте её перед повтором") from exc
            raise
        if code != 0 or value.get("ok") is not True:
            reason = value.get("error") if isinstance(value.get("error"), str) else ""
            if action == "create":
                explanation = ERRORS.get(reason)
                if explanation is not None:
                    raise InstallError(explanation + " Обновите список перед повтором.")
                raise InstallError("Результат создания неизвестен: копия могла появиться. "
                                   "Обновите список и проверьте её перед повтором.")
            raise InstallError(ERRORS.get(reason,
                "Сервер не подтвердил состояние копии. Повторите проверку списка."))
        return value

    @staticmethod
    def _details(value: dict, *, verified: bool) -> HubBackupDetails:
        keys = {"ok", "id", "created_at", "database_bytes", "telegram_token_included"}
        if verified:
            keys.add("verified")
        if (set(value) != keys or value.get("ok") is not True or
                type(value["created_at"]) is not int or
                not 1 <= value["created_at"] <= 253402300799 or
                type(value["database_bytes"]) is not int or
                not 0 < value["database_bytes"] <= MAX_DATABASE_BYTES or
                type(value["telegram_token_included"]) is not bool or
                (verified and value["verified"] is not True)):
            raise InstallError("Сервер прислал неверное описание резервной копии")
        return HubBackupDetails(_id(value["id"]), value["created_at"],
                                value["database_bytes"], value["telegram_token_included"], verified)

    def inspect(self) -> HubBackupState:
        self.progress("Сверяем серверный код и список копий без изменений…")
        present = self._source()
        ids: tuple[str, ...] = ()
        if present:
            value = self._action("list")
            if set(value) != {"ok", "ids"} or not isinstance(value["ids"], list) or len(value["ids"]) > 1000:
                raise InstallError("Сервер прислал неверный список резервных копий")
            ids = tuple(_id(item) for item in value["ids"])
            if len(set(ids)) != len(ids):
                raise InstallError("Сервер прислал повторяющиеся резервные копии")
        return HubBackupState(self.options, self.approved_manifest_sha256, present, ids)

    def verify(self, identity: str) -> HubBackupDetails:
        self._source()
        return self._details(self._action("verify", _id(identity)), verified=True)

    def create(self, reviewed: HubBackupState) -> HubBackupDetails:
        if (reviewed.options != self.options or
                reviewed.manifest_sha256 != self.approved_manifest_sha256 or
                self.inspect() != reviewed):
            raise InstallError("Список копий или код сервера изменился. Проверьте заново")
        self.progress("Создаём согласованный снимок Hub; не закрывайте окно…")
        created = self._details(self._action("create"), verified=False)
        verified = self.verify(created.id)
        if (verified.id, verified.created_at, verified.database_bytes,
                verified.telegram_token_included) != (
                created.id, created.created_at, created.database_bytes,
                created.telegram_token_included):
            raise InstallError("Копия создана, но проверка дала другой результат. Проверьте список")
        return verified

    @staticmethod
    def _restore_status(value: dict, request_id: str | None = None,
                        target_id: str | None = None) -> HubRestoreStatus:
        keys = {"ok", "protocol", "request_id", "target_id", "phase", "safety_id",
                "plan_id", "hub_running", "error", "created_at"}
        if (not isinstance(value, dict) or set(value) != keys or type(value["ok"]) is not bool or
                type(value["protocol"]) is not int or value["protocol"] != 1 or
                not isinstance(value["phase"], str) or value["phase"] not in RESTORE_PHASES or
                value["ok"] is not (value["phase"] == "complete") or
                (value["hub_running"] is not None and type(value["hub_running"]) is not bool) or
                (value["error"] is not None and (not isinstance(value["error"], str) or
                 RESTORE_ERROR.fullmatch(value["error"]) is None)) or
                (value["phase"] == "complete" and value["error"] is not None) or
                (value["phase"] != "complete" and value["error"] is None) or
                type(value["created_at"]) is not int or
                not 1 <= value["created_at"] <= 253402300799):
            raise InstallError("Сервер прислал неверное состояние восстановления")
        identity = _id(value["request_id"])
        if request_id is not None and identity != request_id:
            raise InstallError("Сервер ответил о другом восстановлении")
        target = _id(value["target_id"])
        if target_id is not None and target != target_id:
            raise InstallError("Сервер ответил о другой резервной копии")
        safety = None if value["safety_id"] is None else _id(value["safety_id"])
        plan = None if value["plan_id"] is None else _id(value["plan_id"])
        return HubRestoreStatus(identity, target, value["phase"], safety, plan,
                                value["hub_running"], value["error"], value["ok"],
                                value["created_at"])

    def _restore_action(self, action: str, *, request_id: str | None = None,
                        target_id: str | None = None) -> dict:
        if action == "apply":
            arguments = " apply " + _id(target_id) + " " + _id(request_id)
            timeout = 1800
        elif action == "status":
            arguments = " status " + _id(request_id)
            timeout = 30
        elif action == "recover":
            arguments = " recover " + _id(request_id)
            timeout = 1800
        elif action == "list":
            arguments = " list"
            timeout = 30
        else:
            raise InstallError("Недопустимое действие восстановления")
        self._restore_source()
        command = (self.transport._privileged + "/usr/bin/python3 -B -I -c " +
                   shlex.quote(RESTORE_ENTRY) + arguments)
        code, raw = self.transport._execute(command, timeout=timeout)
        value = _object(raw)
        if code != 0 and (value.get("ok") is not False or value.get("protocol") != 1):
            raise InstallError("Сервер не подтвердил состояние восстановления")
        return value

    def restore_status(self, request_id: str) -> HubRestoreStatus:
        identity = _id(request_id)
        return self._restore_status(self._restore_action("status", request_id=identity), identity)

    def recover_restore(self, request_id: str) -> HubRestoreStatus:
        identity = _id(request_id)
        self.progress("Проверяем прерванное восстановление и состояние Hub…")
        try:
            value = self._restore_action("recover", request_id=identity)
            return self._restore_status(value, identity)
        except (InstallError, OSError, subprocess.TimeoutExpired):
            # Recovery also has a durable journal. Query once, never send a
            # second mutating command after an uncertain SSH result.
            try:
                return self.restore_status(identity)
            except (InstallError, OSError, subprocess.TimeoutExpired) as exc:
                raise InstallError(
                    "Ответ о восстановлении после сбоя потерян. Проверьте сохранённый запрос "
                    "перед новым действием"
                ) from exc

    def restore_list(self) -> tuple[HubRestoreStatus, ...]:
        value = self._restore_action("list")
        records = value.get("restores")
        if (set(value) != {"ok", "protocol", "restores"} or value["ok"] is not True or
                type(value["protocol"]) is not int or value["protocol"] != 1 or
                not isinstance(records, list) or len(records) > 100):
            raise InstallError("Сервер прислал неверный список восстановлений")
        result = tuple(self._restore_status(item) for item in records)
        if len({item.request_id for item in result}) != len(result):
            raise InstallError("Сервер прислал повторяющиеся восстановления")
        return result

    def restore(self, reviewed: HubBackupState, details: HubBackupDetails,
                request_id: str) -> HubRestoreStatus:
        identity = _id(request_id)
        if (reviewed.options != self.options or
                reviewed.manifest_sha256 != self.approved_manifest_sha256 or
                not details.verified or details.id not in reviewed.ids or
                self.inspect() != reviewed or self.verify(details.id) != details):
            raise InstallError("Копия, сервер или проверенный код изменились. Обновите список")
        self.progress("Восстанавливаем Hub; SSH-соединение может прерваться при перезапуске…")
        try:
            value = self._restore_action("apply", request_id=identity, target_id=details.id)
            return self._restore_status(value, identity, details.id)
        except (InstallError, OSError, subprocess.TimeoutExpired):
            # A lost SSH reply can follow a successful restore. Never send a
            # second apply; inspect the durable journal with the same key.
            try:
                status = self.restore_status(identity)
            except (InstallError, OSError, subprocess.TimeoutExpired) as exc:
                raise InstallError(
                    "Ответ восстановления потерян. Сохраните окно и проверьте состояние запроса; "
                    "повторять восстановление сейчас нельзя"
                ) from exc
            if status.target_id != details.id:
                raise InstallError("Сервер ответил о другой резервной копии")
            return status
