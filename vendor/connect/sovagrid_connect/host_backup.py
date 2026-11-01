# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Pinned root SSH control of offline archives and journaled online backup jobs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import json
from pathlib import Path
import re
import shlex
import subprocess
from typing import Callable

from .approved_manifest import ApprovedManifestMixin
from .core import ConnectionOptions
from .host_backup_remote import SCRIPT
from .host_backup_request import HostBackupRequest, HostBackupRequestStore
from .host_backup_transfer import export_portable_files
from .hub_backup import _object
from .installer import InstallError
from .promotion import PromotionController


PROTOCOL = "sovagrid-host-backup-v1"
OPERATION_PROTOCOL = "sovagrid-host-backup-operation-v1"
IMAGE_PROTOCOL = "sovagrid-host-images-v1"
PORTABLE_RECEIPT_PROTOCOL = "sovagrid-portable-host-receipt-v1"
PORTABLE_RECEIPT_PROTOCOL_V2 = "sovagrid-portable-host-receipt-v2"
SHA = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
ARCHIVE_ID = re.compile(r"[0-9a-f]{32}\Z")
UTC_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?\+00:00\Z")
MAX_ARCHIVES = 100
MAX_BYTES = 8 * 1024**3
MAX_FILES = 20_000
MAX_PORTABLE_RECEIPT = 8192
PORTABLE_UNIT_ENABLEMENT = frozenset((
    "enabled", "enabled-runtime", "disabled", "static", "indirect", "alias",
    "masked", "masked-runtime", "linked", "linked-runtime", "generated", "transient",
))
# Exact unit-file sources archived by Blueprint; arbitrary systemd names are
# never accepted as restore metadata.
PORTABLE_MANAGED_UNITS = {
    "full": frozenset("""
        sovagrid-agent.service sovagrid-amnezia-control.service sovagrid-amnezia-control.socket
        sovagrid-auto-update.service sovagrid-auto-update.timer
        sovagrid-container-inventory.service sovagrid-container-inventory.timer
        sovagrid-hub-backup-control.service sovagrid-hub-backup-control.socket
        sovagrid-journal-control.service sovagrid-journal-control.socket
        sovagrid-release-feed.service sovagrid-release-feed.timer
        sovagrid-service-control.service sovagrid-service-control.socket
        sovagrid-terminal-control.service sovagrid-terminal-control.socket
        sovagrid-vpn-control.service sovagrid-vpn-control.socket sovagrid-vpn-routing.service
        sovagrid-vpn-status.service sovagrid-vpn-status.timer
        sovagrid-web-agent-control.service sovagrid-web-agent-control.socket
    """.split()),
    "hub-only": frozenset("""
        sovagrid-agent-local.service
        sovagrid-container-inventory-local.service sovagrid-container-inventory-local.timer
        sovagrid-external-agent-apply@.service sovagrid-external-agent-recovery.service
        sovagrid-hub-backup-control.service sovagrid-hub-backup-control.socket
        sovagrid-hub-only-update.service sovagrid-hub-only-update.timer
        sovagrid-release-feed.service sovagrid-release-feed.timer
        sovagrid-service-local-control.service sovagrid-service-local-control.socket
        sovagrid-terminal-local-control.service sovagrid-terminal-local-control.socket
        sovagrid-vpn-routing.service sovagrid-vpn-status.service sovagrid-vpn-status.timer
        sovagrid-web-agent-control.service sovagrid-web-agent-control.socket
    """.split()),
}
PORTABLE_WRITER_UNITS = {
    "full": frozenset("""
        sovagrid-amnezia-control.service sovagrid-amnezia-control.socket
        sovagrid-auto-update.service sovagrid-auto-update.timer
        sovagrid-container-inventory.service sovagrid-container-inventory.timer
        sovagrid-hub-backup-control.service sovagrid-hub-backup-control.socket
        sovagrid-release-feed.service sovagrid-release-feed.timer
        sovagrid-vpn-control.service sovagrid-vpn-control.socket
        sovagrid-vpn-status.service sovagrid-vpn-status.timer
        sovagrid-web-agent-control.service sovagrid-web-agent-control.socket
    """.split()),
    "hub-only": frozenset("""
        sovagrid-container-inventory-local.service sovagrid-container-inventory-local.timer
        sovagrid-hub-backup-control.service sovagrid-hub-backup-control.socket
        sovagrid-hub-only-update.service sovagrid-hub-only-update.timer
        sovagrid-release-feed.service sovagrid-release-feed.timer
        sovagrid-vpn-status.service sovagrid-vpn-status.timer
        sovagrid-web-agent-control.service sovagrid-web-agent-control.socket
    """.split()),
}
PORTABLE_REPLY_LIMIT = 12288
PORTABLE_SERVICES = (frozenset(("hub", "web")),
                     frozenset(("hub", "web", "ssh-gateway")))
OPERATION_PHASES = frozenset(("accepted", "stopping", "archiving", "restarting",
                              "complete", "recovery_requested", "recovered", "failed",
                              "recovery_required"))
TERMINAL_PHASES = frozenset(("complete", "recovered", "failed"))
OPERATION_ERROR = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
UNIT = re.compile(r"sovagrid-[a-z0-9_.@-]{1,80}\.(?:service|socket|timer)\Z")
CONTAINER = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
ERRORS = {
    "SERVICES_RUNNING": "Перед полной копией остановите службы SovaGrid на сервере.",
    "CONTAINERS_RUNNING": "Перед полной копией остановите контейнеры SovaGrid на сервере.",
    "OFFLINE_CHECK_UNAVAILABLE": "Не удалось подтвердить, что службы и контейнеры остановлены.",
    "UNMANAGED_UNIT": "Служба SovaGrid не совпадает с управляемой установкой.",
    "CONTAINER_AMBIGUOUS": "Набор контейнеров SovaGrid неоднозначен.",
    "BUSY": "Сервер сейчас занят обновлением или другой операцией.",
    "LOCK_UNAVAILABLE": "Защитная блокировка сервера недоступна.",
    "MISSING_SOURCE": "На сервере отсутствует обязательная часть SovaGrid.",
    "UNSAFE_SOURCE": "Файлы SovaGrid на сервере не прошли проверку владельца и типа.",
    "SOURCE_UNSAFE": "Установленный пакет SovaGrid изменился. Обновите его из проверенного выпуска.",
    "SOURCE_UNAVAILABLE": "Исходный код SovaGrid недоступен для проверки.",
    "DISK_SPACE": "Недостаточно свободного места для полной копии.",
    "TIME_LIMIT": "Создание копии превысило допустимое время.",
    "SIZE_LIMIT": "Размер данных превышает предел полной копии.",
    "FILE_LIMIT": "Количество файлов превышает предел полной копии.",
    "ARCHIVE_LIMIT": "На сервере достигнут предел сохранённых копий.",
    "OPERATION_LIMIT": "На сервере достигнут предел заданий полной копии.",
    "DEGRADED_CONTAINERS": "Контейнеры Hub/Web запущены не полностью. Проверьте сервер перед копией.",
    "SOURCE_CHANGED": "Установленный серверный пакет изменился. Проверьте его заново.",
    "SPAWN_FAILED": "Сервер не смог запустить задание полной копии.",
    "UNSAFE_STATE": "Журнал задания имеет небезопасные права или повреждён.",
    "INVALID_STATE": "Журнал задания повреждён или не совпадает с текущим сервером.",
    "NOT_FOUND": "Копия больше не найдена на сервере.",
    "ARCHIVE_CHANGED": "Архив изменился и не прошёл проверку.",
    "INVALID_ARCHIVE": "Архив повреждён или имеет недопустимую структуру.",
    "UNSAFE_ARCHIVE": "Права или тип архива изменились; проверка остановлена.",
    "INVALID_MANIFEST": "Описание архива повреждено.",
}


def _id(value: object) -> str:
    if not isinstance(value, str) or ARCHIVE_ID.fullmatch(value) is None:
        raise InstallError("Неверный идентификатор полной копии")
    return value


@dataclass(frozen=True)
class HostArchive:
    id: str
    created_at: str
    layout: str
    bytes: int
    files: int
    verified: bool = False


@dataclass(frozen=True)
class HostBackupPlan:
    layout: str
    active_units: tuple[str, ...]
    running_containers: tuple[str, ...]
    offline_ready: bool


@dataclass(frozen=True)
class HostBackupState:
    options: ConnectionOptions
    manifest_sha256: str
    archives: tuple[HostArchive, ...]
    plan: HostBackupPlan


@dataclass(frozen=True)
class HostBackupOperation:
    request_id: str
    phase: str
    archive: HostArchive | None
    error: str | None
    created_at: str

    @property
    def terminal(self) -> bool:
        return self.phase in TERMINAL_PHASES


@dataclass(frozen=True)
class HostPortableOperation:
    operation: HostBackupOperation
    image_receipt: dict | None


@dataclass(frozen=True)
class HostPortablePair:
    operation: HostBackupOperation
    archive: HostArchive
    image_receipt: dict
    image_count: int
    image_bytes: int
    platforms: dict[str, dict[str, str]]


class HostBackupRejected(InstallError):
    """A structured server refusal before the requested mutation was accepted."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class HostBackupController(ApprovedManifestMixin):
    def __init__(self, options: ConnectionOptions, *, approved_manifest_sha256: str | tuple[str, ...] | None,
                 popen: Callable[..., subprocess.Popen] = subprocess.Popen,
                 progress: Callable[[str], None] | None = None,
                 transport: PromotionController | None = None,
                 request_store: HostBackupRequestStore | None = None) -> None:
        self.transport = transport or PromotionController(
            options, approved_archive_sha256="0" * 64, popen=popen, progress=progress)
        self.options = self.transport.options
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.progress = progress or (lambda _message: None)
        self.request_store = request_store or HostBackupRequestStore.default()

    def _source(self, *, portable: bool = False) -> None:
        expected = self.approved_manifest_sha256
        if expected is None:
            raise InstallError("Полная копия ждёт общий проверенный серверный выпуск")
        self.transport._verify_root_access()
        command = (self.transport._privileged + "/usr/bin/python3 -B -I -c " +
                   shlex.quote(SCRIPT) + " " + expected +
                   (" portable" if portable else ""))
        code, raw = self.transport._execute(command, timeout=120)
        if code != 0:
            if (portable and code == 40 and
                    raw.strip() == b"SG_HOST_BACKUP_SOURCE_REFUSE:PORTABLE_UNAVAILABLE"):
                raise HostBackupRejected(
                    "PORTABLE_UNAVAILABLE",
                    "Серверный выпуск ещё не поддерживает переносимую копию")
            raise InstallError("Установленный серверный пакет не совпал с проверенным выпуском")
        value = _object(raw, 1024)
        keys = {"protocol", "manifest_sha256", "host_backup_verified"}
        if portable:
            keys.add("portable_verified")
        if (set(value) != keys or
                type(value["protocol"]) is not int or value["protocol"] != 1 or
                value["manifest_sha256"] != expected or
                value["host_backup_verified"] is not True or
                (portable and value["portable_verified"] is not True)):
            raise InstallError("Установленный серверный пакет не совпал с проверенным выпуском")

    def portable_available(self) -> bool:
        if self.approved_manifest_sha256 is None:
            return False
        try:
            self._source(portable=True)
        except HostBackupRejected as exc:
            if exc.code == "PORTABLE_UNAVAILABLE":
                return False
            raise
        return True

    @staticmethod
    def _archive(value: object, *, verified: bool) -> HostArchive:
        if (not isinstance(value, dict) or
                set(value) != {"id", "created_at", "layout", "bytes", "files"} or
                not isinstance(value["created_at"], str) or
                UTC_TIME.fullmatch(value["created_at"]) is None or
                value["layout"] not in ("full", "hub-only") or
                type(value["bytes"]) is not int or not 0 < value["bytes"] <= MAX_BYTES or
                type(value["files"]) is not int or not 0 < value["files"] <= MAX_FILES):
            raise InstallError("Сервер прислал неверное описание полной копии")
        try:
            stamp = datetime.fromisoformat(value["created_at"])
        except ValueError as exc:
            raise InstallError("Сервер прислал неверное время полной копии") from exc
        if stamp.utcoffset() != timedelta(0):
            raise InstallError("Сервер прислал неверное время полной копии")
        return HostArchive(_id(value["id"]), value["created_at"], value["layout"],
                           value["bytes"], value["files"], verified)

    def _action(self, action: str, identity: str | None = None) -> dict:
        if action not in ("plan", "list", "create", "verify") or (identity is None) != (action != "verify"):
            raise InstallError("Недопустимое действие с полной копией")
        argument = "" if identity is None else " " + _id(identity)
        command = (self.transport._privileged + "/usr/bin/python3 -B -I " +
                   "/opt/sovagrid-src/sovagrid-blueprint/deploy/host_backup.py " +
                   action + argument)
        timeout = {"plan": 60, "list": 60, "create": 420, "verify": 420}[action]
        code, raw = self.transport._execute(command, timeout=timeout,
                                            limit=32768 if action == "list" else 4096)
        try:
            value = _object(raw, 32768)
        except InstallError as exc:
            if action == "create":
                raise InstallError("Ответ о создании потерян: копия могла появиться. "
                                   "Обновите список перед повтором") from exc
            raise
        if value.get("protocol") != PROTOCOL or type(value.get("ok")) is not bool:
            raise InstallError("Сервер прислал неверный ответ о полной копии")
        if code != 0 or value["ok"] is not True:
            reason = value.get("error")
            if (set(value) != {"ok", "protocol", "error"} or value["ok"] is not False or
                    not isinstance(reason, str) or
                    re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", reason) is None):
                raise InstallError("Сервер не подтвердил результат полной копии")
            explanation = ERRORS.get(reason, "Сервер отказал в операции с полной копией.")
            if action == "create":
                explanation += " Обновите список перед повтором."
            raise InstallError(explanation)
        return value

    def inspect(self) -> HostBackupState:
        self.progress("Проверяем исходный код и список полных копий без изменений…")
        self._source()
        plan_value = self._action("plan")
        if (set(plan_value) != {"ok", "protocol", "layout", "active_units",
                                "running_containers", "offline_ready"} or
                plan_value["layout"] not in ("full", "hub-only") or
                type(plan_value["offline_ready"]) is not bool or
                not isinstance(plan_value["active_units"], list) or
                not isinstance(plan_value["running_containers"], list) or
                len(plan_value["active_units"]) > 64 or
                len(plan_value["running_containers"]) > 16 or
                any(not isinstance(item, str) or UNIT.fullmatch(item) is None
                    for item in plan_value["active_units"]) or
                any(not isinstance(item, str) or CONTAINER.fullmatch(item) is None
                    for item in plan_value["running_containers"]) or
                len(set(plan_value["active_units"])) != len(plan_value["active_units"]) or
                len(set(plan_value["running_containers"])) != len(plan_value["running_containers"]) or
                (plan_value["offline_ready"] and
                 (plan_value["active_units"] or plan_value["running_containers"]))):
            raise InstallError("Сервер прислал неверный план полной копии")
        plan = HostBackupPlan(plan_value["layout"], tuple(plan_value["active_units"]),
                              tuple(plan_value["running_containers"]),
                              plan_value["offline_ready"])
        value = self._action("list")
        records = value.get("archives")
        if (set(value) != {"ok", "protocol", "archives"} or
                not isinstance(records, list) or len(records) > MAX_ARCHIVES):
            raise InstallError("Сервер прислал неверный список полных копий")
        archives = tuple(self._archive(item, verified=False) for item in records)
        if len({item.id for item in archives}) != len(archives):
            raise InstallError("Сервер прислал повторяющиеся полные копии")
        return HostBackupState(self.options, self.approved_manifest_sha256, archives, plan)

    def verify(self, identity: str) -> HostArchive:
        self._source()
        identity = _id(identity)
        value = self._action("verify", identity)
        if (set(value) != {"ok", "protocol", "archive", "verified"} or
                value["verified"] is not True):
            raise InstallError("Сервер не подтвердил проверку полной копии")
        archive = self._archive(value["archive"], verified=True)
        if archive.id != identity:
            raise InstallError("Сервер ответил о другой полной копии")
        return archive

    def create(self, reviewed: HostBackupState) -> tuple[HostArchive, HostBackupState]:
        if (reviewed.options != self.options or not reviewed.plan.offline_ready or
                reviewed.manifest_sha256 != self.approved_manifest_sha256 or
                self.inspect() != reviewed):
            raise InstallError("Список копий или код сервера изменились. Обновите список")
        self.progress("Создаём полную закрытую копию узла; не закрывайте окно…")
        try:
            value = self._action("create")
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InstallError("Ответ о создании потерян: копия могла появиться. "
                               "Обновите список перед повтором") from exc
        if set(value) != {"ok", "protocol", "archive"}:
            raise InstallError("Сервер не подтвердил создание полной копии")
        created = self._archive(value["archive"], verified=False)
        state = self.inspect()
        if created not in state.archives:
            raise InstallError("Копия создана, но исчезла из списка. Проверьте сервер")
        verified = self.verify(created.id)
        if (verified.id, verified.created_at, verified.layout, verified.bytes, verified.files) != (
                created.id, created.created_at, created.layout, created.bytes, created.files):
            raise InstallError("Копия создана, но проверка дала другой результат")
        return verified, state

    @staticmethod
    def _operation(value: object, identity: str | None = None) -> HostBackupOperation:
        keys = {"ok", "protocol", "request_id", "phase", "archive", "error", "created_at"}
        if (not isinstance(value, dict) or set(value) != keys or value["ok"] is not True or
                value["protocol"] != OPERATION_PROTOCOL or
                not isinstance(value["phase"], str) or
                value["phase"] not in OPERATION_PHASES or
                (value["error"] is not None and
                 (not isinstance(value["error"], str) or
                  OPERATION_ERROR.fullmatch(value["error"]) is None)) or
                not isinstance(value["created_at"], str) or
                UTC_TIME.fullmatch(value["created_at"]) is None):
            raise InstallError("Сервер прислал неверное состояние полной копии")
        request_id = _id(value["request_id"])
        if identity is not None and request_id != identity:
            raise InstallError("Сервер ответил о другом запросе полной копии")
        try:
            stamp = datetime.fromisoformat(value["created_at"])
        except ValueError as exc:
            raise InstallError("Сервер прислал неверное время запроса") from exc
        if stamp.utcoffset() != timedelta(0):
            raise InstallError("Сервер прислал неверное время запроса")
        archive = (None if value["archive"] is None else
                   HostBackupController._archive(value["archive"], verified=False))
        if value["phase"] == "complete" and archive is None:
            raise InstallError("Завершённая полная копия не содержит архив")
        return HostBackupOperation(request_id, value["phase"], archive,
                                   value["error"], value["created_at"])

    def _receipt(self, value: object, archive: HostArchive,
                 expected_manifest_sha256: str | None) -> dict:
        keys = {"protocol", "host_archive_id", "host_archive_sha256",
                "source_manifest_sha256", "images_sha256", "images",
                "container_ids", "exported_configs", "rootfs_sha256",
                "active_units", "unit_hashes"}
        if not isinstance(value, dict):
            raise InstallError("Сервер прислал неверную квитанцию переносимой копии")
        v2 = value.get("protocol") == PORTABLE_RECEIPT_PROTOCOL_V2
        if set(value) != (keys | {"unit_states"} if v2 else keys):
            raise InstallError("Сервер прислал неверную квитанцию переносимой копии")
        receipt_bytes = len(json.dumps(value, sort_keys=True,
                                       separators=(",", ":")).encode("utf-8")) + 1
        if (receipt_bytes > MAX_PORTABLE_RECEIPT or
                value["protocol"] not in (PORTABLE_RECEIPT_PROTOCOL, PORTABLE_RECEIPT_PROTOCOL_V2) or
                value["host_archive_id"] != archive.id or
                not isinstance(value["host_archive_sha256"], str) or
                SHA.fullmatch(value["host_archive_sha256"]) is None or
                not isinstance(value["source_manifest_sha256"], str) or
                SHA.fullmatch(value["source_manifest_sha256"]) is None or
                (expected_manifest_sha256 is not None and
                 value["source_manifest_sha256"] != expected_manifest_sha256) or
                not isinstance(value["images_sha256"], str) or
                SHA.fullmatch(value["images_sha256"]) is None):
            raise InstallError("Сервер прислал неверную квитанцию переносимой копии")
        services = value["images"]
        if (not isinstance(services, dict) or frozenset(services) not in PORTABLE_SERVICES or
                any(not isinstance(item, str) or IMAGE_ID.fullmatch(item) is None
                    for item in services.values()) or
                len(set(services.values())) != len(services)):
            raise InstallError("Сервер прислал неверную квитанцию переносимой копии")
        for key, pattern in (("container_ids", SHA), ("exported_configs", IMAGE_ID),
                             ("rootfs_sha256", SHA)):
            entries = value[key]
            if (not isinstance(entries, dict) or set(entries) != set(services) or
                    any(not isinstance(item, str) or pattern.fullmatch(item) is None
                        for item in entries.values())):
                raise InstallError("Сервер прислал неверную квитанцию переносимой копии")
        if len(set(value["exported_configs"].values())) != len(services):
            raise InstallError("Сервер прислал неверную квитанцию переносимой копии")
        units = value["active_units"]
        hashes = value["unit_hashes"]
        if (not isinstance(units, list) or len(units) > 32 or
                any(not isinstance(item, str) or UNIT.fullmatch(item) is None
                    for item in units) or len(set(units)) != len(units) or
                not isinstance(hashes, dict) or set(hashes) != set(units) or
                any(not isinstance(item, str) or SHA.fullmatch(item) is None
                    for item in hashes.values())):
            raise InstallError("Сервер прислал неверную квитанцию переносимой копии")
        if v2:
            states = value["unit_states"]
            if (not isinstance(states, dict) or len(states) > 32 or
                    any(not isinstance(name, str) or name not in PORTABLE_MANAGED_UNITS[archive.layout] or
                        not isinstance(state, dict) or set(state) != {"active", "enablement", "sha256"} or
                        type(state["active"]) is not bool or
                        not isinstance(state["enablement"], str) or state["enablement"] not in PORTABLE_UNIT_ENABLEMENT or
                        not isinstance(state["sha256"], str) or SHA.fullmatch(state["sha256"]) is None
                        for name, state in states.items()) or
                    set(units) != {name for name, state in states.items()
                                   if name in PORTABLE_WRITER_UNITS[archive.layout] and state["active"]} or
                    not set(hashes).issubset(states) or
                    any(states[name]["sha256"] != digest for name, digest in hashes.items())):
                raise InstallError("Сервер прислал неверную квитанцию переносимой копии")
        return value

    def _portable_operation(self, value: object, identity: str,
                            expected_manifest_sha256: str | None) -> HostPortableOperation:
        if (not isinstance(value, dict) or
                set(value) != {"ok", "protocol", "request_id", "phase", "archive",
                               "error", "created_at", "image_receipt"}):
            raise InstallError("Сервер прислал неверное состояние переносимой копии")
        operation = self._operation({key: item for key, item in value.items()
                                     if key != "image_receipt"}, identity)
        receipt = value["image_receipt"]
        if (operation.phase == "complete") != (receipt is not None):
            raise InstallError("Сервер прислал неверное состояние переносимой копии")
        if receipt is not None:
            if operation.archive is None:
                raise InstallError("Переносимая копия не содержит архив")
            receipt = self._receipt(receipt, operation.archive,
                                    expected_manifest_sha256)
        return HostPortableOperation(operation, receipt)

    def _operation_action(self, action: str, request_id: str | None = None,
                          *, portable: bool = False) -> dict:
        if action not in ("start", "start-portable", "status", "portable-status",
                           "recover", "list") or (
                request_id is None) != (action == "list"):
            raise InstallError("Недопустимое действие с заданием полной копии")
        self._source(portable=portable or action in ("start-portable", "portable-status"))
        arguments = " " + action
        if request_id is not None:
            arguments += " " + _id(request_id)
        if action in ("start", "start-portable"):
            if self.approved_manifest_sha256 is None:
                raise InstallError("Задание ждёт проверенный серверный выпуск")
            arguments += " " + self.approved_manifest_sha256
        command = (self.transport._privileged + "/usr/bin/python3 -B -I " +
                   "/opt/sovagrid-src/sovagrid-blueprint/deploy/host_backup_orchestrator.py" +
                   arguments)
        maximum = (98304 if action == "list" else
                   PORTABLE_REPLY_LIMIT if action == "portable-status" else 4096)
        code, raw = self.transport._execute(command, timeout=90 if action in
                                            ("start", "start-portable") else 60,
                                            limit=maximum)
        value = _object(raw, maximum)
        if value.get("protocol") != OPERATION_PROTOCOL or type(value.get("ok")) is not bool:
            raise InstallError("Сервер прислал неверный ответ задания полной копии")
        if code != 0 or value["ok"] is not True:
            error = value.get("error")
            if (set(value) != {"ok", "protocol", "error"} or value["ok"] is not False or
                    not isinstance(error, str) or OPERATION_ERROR.fullmatch(error) is None):
                raise InstallError("Сервер не подтвердил задание полной копии")
            if action == "recover" and error == "BUSY":
                raise HostBackupRejected(error, "Операция ещё выполняется. Сервер не стал запускать восстановление параллельно")
            if error == "NOT_FOUND":
                raise HostBackupRejected(error, "Задание полной копии не найдено на сервере")
            raise HostBackupRejected(error, ERRORS.get(error, "Сервер отказал в задании полной копии."))
        return value

    def _verify_portable_images(self, archive_id: str) -> dict:
        self._source(portable=True)
        command = (self.transport._privileged + "/usr/bin/python3 -B -I " +
                   "/opt/sovagrid-src/sovagrid-blueprint/deploy/host_image_export.py " +
                   "verify-portable " + _id(archive_id))
        code, raw = self.transport._execute(command, timeout=2400,
                                            limit=PORTABLE_REPLY_LIMIT)
        value = _object(raw, PORTABLE_REPLY_LIMIT)
        if value.get("protocol") != IMAGE_PROTOCOL or type(value.get("ok")) is not bool:
            raise InstallError("Сервер прислал неверный ответ о переносимой копии")
        if code != 0 or value["ok"] is not True:
            error = value.get("error")
            if (set(value) != {"ok", "protocol", "error"} or value["ok"] is not False or
                    not isinstance(error, str) or OPERATION_ERROR.fullmatch(error) is None):
                raise InstallError("Сервер не подтвердил проверку переносимой копии")
            raise HostBackupRejected(error, ERRORS.get(error,
                "Сервер отказал в проверке переносимой копии."))
        return value

    def saved_request(self) -> HostBackupRequest | None:
        return self.request_store.load(self.options)

    def _saved_mode(self, identity: str, mode: str) -> HostBackupRequest | None:
        current = self.saved_request()
        if current is not None and current.request_id == identity:
            if current.mode != mode:
                raise InstallError("Режим сохранённого запроса не совпадает")
            return current
        return None

    def operation_status(self, request_id: str) -> HostBackupOperation:
        identity = _id(request_id)
        current = self.saved_request()
        if current is not None and current.request_id == identity:
            if current.mode == "portable":
                # Existing dialog polling expects HostBackupOperation. Validate
                # the portable receipt, then return the familiar status fields.
                return self.portable_status(identity).operation
        return self._operation(self._operation_action("status", identity), identity)

    def portable_status(self, request_id: str) -> HostPortableOperation:
        identity = _id(request_id)
        current = self._saved_mode(identity, "portable")
        return self._portable_operation(
            self._operation_action("portable-status", identity), identity,
            current.manifest_sha256 if current is not None else None)

    def saved_operation_status(self) -> HostBackupOperation | HostPortableOperation | None:
        request = self.saved_request()
        if request is None:
            return None
        if request.mode == "portable":
            return self.portable_status(request.request_id)
        return self.operation_status(request.request_id)

    def operation_list(self) -> tuple[HostBackupOperation, ...]:
        value = self._operation_action("list")
        records = value.get("operations")
        if (set(value) != {"ok", "protocol", "operations"} or
                not isinstance(records, list) or len(records) > 100):
            raise InstallError("Сервер прислал неверную историю полных копий")
        operations = tuple(self._operation(record) for record in records)
        if len({item.request_id for item in operations}) != len(operations):
            raise InstallError("Сервер прислал повторяющиеся задания")
        return operations

    def verify_portable(self, request_id: str) -> HostPortablePair:
        status = self.portable_status(request_id)
        operation = status.operation
        receipt = status.image_receipt
        if operation.phase != "complete" or operation.archive is None or receipt is None:
            raise InstallError("Переносимая копия ещё не завершена")
        archive = self.verify(operation.archive.id)
        if (archive.id, archive.created_at, archive.layout, archive.bytes,
                archive.files) != (operation.archive.id, operation.archive.created_at,
                                  operation.archive.layout, operation.archive.bytes,
                                  operation.archive.files):
            raise InstallError("Архив переносимой копии не совпал с заданием")
        value = self._verify_portable_images(archive.id)
        platforms = value.get("platforms")
        if (set(value) != {"ok", "protocol", "id", "verified", "image_count",
                           "bytes", "apply_available", "receipt", "platforms"} or
                value["id"] != archive.id or value["verified"] is not True or
                type(value["image_count"]) is not int or
                value["image_count"] != len(receipt["images"]) or
                type(value["bytes"]) is not int or
                not 0 < value["bytes"] <= MAX_BYTES or
                value["apply_available"] is not False or
                value["receipt"] != receipt or
                not isinstance(platforms, dict) or
                set(platforms) != set(receipt["images"]) or
                any(not isinstance(item, dict) or
                    set(item) != {"os", "architecture"} or
                    item["os"] != "linux" or
                    item["architecture"] not in ("amd64", "arm64")
                    for item in platforms.values())):
            raise InstallError("Сервер прислал неверный результат проверки переносимой копии")
        return HostPortablePair(operation, archive, receipt,
                                value["image_count"], value["bytes"], platforms)

    def export_portable(self, request_id: str, destination: Path) -> Path:
        self.progress("Проверяем пару архивов перед передачей…")
        pair = self.verify_portable(request_id)
        if self.approved_manifest_sha256 is None:
            raise InstallError("Переносимая копия ждёт проверенный серверный выпуск")
        return export_portable_files(
            self.transport, destination, archive_id=pair.archive.id,
            archive_bytes=pair.archive.bytes, image_bytes=pair.image_bytes,
            receipt=pair.image_receipt,
            archive_record={"id": pair.archive.id,
                            "created_at": pair.archive.created_at,
                            "layout": pair.archive.layout,
                            "bytes": pair.archive.bytes,
                            "files": pair.archive.files},
            current_manifest_sha256=self.approved_manifest_sha256,
            progress=self.progress)

    def start_online(self, reviewed: HostBackupState, request_id: str) -> HostBackupOperation:
        identity = _id(request_id)
        if (reviewed.options != self.options or
                reviewed.manifest_sha256 != self.approved_manifest_sha256 or
                self.inspect() != reviewed):
            raise InstallError("План или серверный пакет изменились. Обновите список")
        current = self.saved_request()
        if current is not None:
            previous = self.saved_operation_status()
            if isinstance(previous, HostPortableOperation):
                previous = previous.operation
            if previous is not None and not previous.terminal:
                raise InstallError("На этом SSH-маршруте есть незавершённая полная копия. "
                                   "Проверьте её состояние")
        marker = HostBackupRequest.new(self.options, identity, self.approved_manifest_sha256)
        self.request_store.save(marker, replacing=current.request_id if current else None)
        self.progress("Задание сохранено. Сервер остановит только свои записывающие службы…")
        try:
            value = self._operation_action("start", identity)
            return self._operation(value, identity)
        except HostBackupRejected as exc:
            # A structured start refusal is definitive: the server writes an
            # accepted journal before it can return ok:true. Remove only our
            # exact local marker so the user can revise the plan and retry.
            if self.saved_request() == marker:
                self.request_store.clear(marker)
            raise
        except (InstallError, OSError, subprocess.TimeoutExpired) as exc:
            try:
                return self.operation_status(identity)
            except (InstallError, OSError, subprocess.TimeoutExpired):
                raise InstallError("Ответ о запуске потерян. Запрос сохранён; проверьте его "
                                   "состояние, не запускайте новую копию") from exc

    def start_portable(self, reviewed: HostBackupState,
                       request_id: str) -> HostPortableOperation:
        identity = _id(request_id)
        if (reviewed.options != self.options or
                reviewed.manifest_sha256 != self.approved_manifest_sha256 or
                self.inspect() != reviewed):
            raise InstallError("План или серверный пакет изменились. Обновите список")
        # Check the portable commands before writing a marker. An installed
        # legacy bundle can still pass the ordinary archive source proof.
        self._source(portable=True)
        current = self.saved_request()
        if current is not None:
            previous = self.saved_operation_status()
            if isinstance(previous, HostPortableOperation):
                previous = previous.operation
            if previous is not None and not previous.terminal:
                raise InstallError("На этом SSH-маршруте есть незавершённая полная копия. "
                                   "Проверьте её состояние")
        marker = HostBackupRequest.new(self.options, identity,
                                       self.approved_manifest_sha256, mode="portable")
        self.request_store.save(marker, replacing=current.request_id if current else None)
        self.progress("Задание переносимой копии сохранено; сервер подготовит пару архивов…")
        try:
            value = self._operation_action("start-portable", identity)
            operation = self._operation(value, identity)
            if operation.phase == "complete":
                return self.portable_status(identity)
            return HostPortableOperation(operation, None)
        except HostBackupRejected:
            if self.saved_request() == marker:
                self.request_store.clear(marker)
            raise
        except (InstallError, OSError, subprocess.TimeoutExpired) as exc:
            try:
                return self.portable_status(identity)
            except (InstallError, OSError, subprocess.TimeoutExpired):
                raise InstallError("Ответ о запуске потерян. Запрос сохранён; проверьте его "
                                   "состояние, не запускайте новую копию") from exc

    def recover_operation(self, request_id: str) -> HostBackupOperation:
        identity = _id(request_id)
        current = self.saved_request()
        if current is not None and current.request_id == identity and current.mode == "portable":
            return self.recover_portable_operation(identity).operation
        before = self.operation_status(identity)
        if before.terminal:
            raise InstallError("Восстановление служб не требуется для этого задания")
        self.progress("Сервер запускает только службы, остановленные для этой копии…")
        try:
            return self._operation(self._operation_action("recover", identity), identity)
        except (InstallError, OSError, subprocess.TimeoutExpired) as exc:
            try:
                return self.operation_status(identity)
            except (InstallError, OSError, subprocess.TimeoutExpired):
                raise InstallError("Ответ о восстановлении служб потерян. Запрос сохранён; "
                                   "проверьте его состояние, не повторяйте действие вслепую") from exc

    def recover_portable_operation(self, request_id: str) -> HostPortableOperation:
        identity = _id(request_id)
        before = self.portable_status(identity)
        if before.operation.terminal:
            raise InstallError("Восстановление служб не требуется для этого задания")
        self.progress("Сервер запускает только службы, остановленные для этой копии…")
        try:
            self._operation(self._operation_action("recover", identity, portable=True), identity)
            return self.portable_status(identity)
        except (InstallError, OSError, subprocess.TimeoutExpired) as exc:
            try:
                return self.portable_status(identity)
            except (InstallError, OSError, subprocess.TimeoutExpired):
                raise InstallError("Ответ о восстановлении служб потерян. Запрос сохранён; "
                                   "проверьте его состояние, не повторяйте действие вслепую") from exc
