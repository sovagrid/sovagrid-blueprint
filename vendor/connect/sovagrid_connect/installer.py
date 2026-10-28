# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""GUI installation and guarded updates from verified source bundles.

The bundle is a source distribution, not a signature. A user must obtain it
from a trusted source: its manifest detects damage and layout tricks, while
the selected run.sh necessarily executes as root on the chosen server.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator

from .askpass import helper_path
from .core import ConnectionOptions, TunnelError, _safe_config_directory, _ssh_config
from .remote_update import REMOTE_SCRIPT
from .server_status import STATUS_COMMAND, STATUS_MARKER, STATUS_SCRIPT, ServerStatus, parse_status
from .server_timer import (SERVER_TIMER_COMMAND, ServerTimerStatus, parse_server_timer_status)


COMPONENTS = frozenset({
    "sovagrid-blueprint", "sovagrid-hub", "sovagrid-web", "sovagrid-agent", "sovagrid-vpn",
})
REQUIRED_FILES = frozenset({
    "sovagrid-blueprint/run.sh", "sovagrid-blueprint/deploy/compose.yaml",
    "sovagrid-hub/Dockerfile", "sovagrid-web/Dockerfile",
    "sovagrid-web/deploy/Caddyfile.container",
    "sovagrid-agent/deploy/sovagrid-agent.service",
    "sovagrid-vpn/deploy/sovagrid-vpn-status.service",
})
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_FILES = 4096
_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_PROGRESS_MARKERS = {
    "SG_INSTALL_STAGE:TRANSFER": "Пакет передан на сервер",
    "SG_INSTALL_STAGE:EXTRACT": "Проверка и распаковка на сервере",
    "SG_INSTALL_STAGE:RUN": "Установка Hub, Agent и компонентов…",
    "SG_INSTALL_STAGE:DOCKER": "Установка Docker на Ubuntu…",
    "SG_INSTALL_STAGE:COMPOSE": "Установка Docker Compose…",
    "SG_INSTALL_STAGE:BUILD": "Сборка и запуск Hub и веб-панели…",
    "SG_INSTALL_STAGE:HEALTH": "Hub и веб-панель отвечают; настройка Agent…",
    "SG_INSTALL_STAGE:AGENT": "Agent запущен; завершаем проверку…",
    "SG_INSTALL_STAGE:DONE": "Установка завершена; можно подключаться к панели",
    "SG_UPDATE_STAGE:TRANSFER": "Пакет обновления передан на сервер",
    "SG_UPDATE_STAGE:VERIFY": "Пакет и файлы обновления проверены на сервере",
    "SG_UPDATE_STAGE:ALREADY": "Этот пакет уже подготовлен на сервере",
    "SG_UPDATE_STAGE:DONE": "Пакет обновления подготовлен; действующие службы не менялись",
    "SG_APPLY_STAGE:VERIFIED": "Версии, пакет и состояние служб проверены",
    "SG_APPLY_STAGE:STOPPED": "Службы остановлены для согласованной резервной копии",
    "SG_APPLY_STAGE:INSTALLING": "Новая версия устанавливается; резервная копия готова",
    "SG_APPLY_STAGE:CHECKING": "Проверка Hub, панели, Agent и включённых функций…",
    "SG_APPLY_STAGE:ROLLBACK": "Ошибка обновления; восстанавливается предыдущая версия…",
    "SG_APPLY_STAGE:ROLLED_BACK": "Предыдущая версия восстановлена и прошла проверку",
    "SG_APPLY_STAGE:ROLLBACK_FAILED": "Откат не завершён; резервная копия сохранена",
    "SG_APPLY_STAGE:LOG_SAVED": "Журнал ошибки установки сохранён в закрытом каталоге сервера",
    "SG_APPLY_STAGE:LOG_UNAVAILABLE": "Откат завершён, но журнал ошибки сохранить не удалось",
    "SG_APPLY_STAGE:CLEANUP_INCOMPLETE": "Откат завершён; очистка временной копии требует проверки",
    "SG_APPLY_STAGE:RECOVERING": "Найдено прерванное обновление; восстанавливается старая версия…",
    "SG_APPLY_STAGE:DONE": "Обновление применено; проверки пройдены",
}
_PREFLIGHT_OK = "SG_INSTALL_PREFLIGHT:OK"
_FEATURE_PREFLIGHT_OK = "SG_FEATURE_PREFLIGHT:OK"
_FEATURE_MARKERS = frozenset(
    f"SG_FEATURE:{name}:{enabled}"
    for name in ("WIREGUARD", "TERMINAL", "FILES", "JOURNAL", "JOURNAL_CONFIGURED", "JOURNAL_SUPPORTED",
                 "CONTAINERS", "CONTAINERS_CONFIGURED", "CONTAINERS_SUPPORTED")
    for enabled in ("0", "1")
)
_JOURNAL_UNIT = re.compile(r"[A-Za-z0-9_.@-]{1,96}\.service\Z")
_JOURNAL_UNIT_MARKER = re.compile(r"SG_JOURNAL_UNIT:([A-Za-z0-9_.@-]{1,96}\.service)\Z")
_JOURNAL_INSTALL_MARKER = b"# SOVAGRID_JOURNAL_INSTALL_V1"
_FEATURE_CAS_MARKER = re.compile(r"SG_FEATURE_CAS:([0-9a-f]{64})\Z")
_CURRENT_MANIFEST_MARKER = re.compile(r"SG_CURRENT_MANIFEST:([0-9a-f]{64})\Z")
_CURRENT_COMMIT_MARKER = re.compile(r"SG_CURRENT_COMMIT:(sovagrid-[a-z]+):([0-9a-f]{40})\Z")
_VERSION_PREFLIGHT_OK = "SG_VERSION_PREFLIGHT:OK"
_SERVER_TIMER_ACTIONS = frozenset({
    "SG_AUTO_UPDATE:ARMED", "SG_AUTO_UPDATE:ALREADY_ARMED", "SG_AUTO_UPDATE:DISABLED",
})
_REFUSALS = {
    "SG_INSTALL_REFUSE:ROOT": "Для первой установки нужен SSH-вход под root.",
    "SG_INSTALL_REFUSE:UBUNTU": "Первая установка сейчас поддерживает только Ubuntu.",
    "SG_INSTALL_REFUSE:EXISTING": (
        "На сервере уже есть SovaGrid или занято его место. Автоматическая первая установка "
        "ничего не меняла. Для проверки нового пакета выберите «Обновить сервер…»."
    ),
    "SG_INSTALL_REFUSE:LAYOUT": "Сервер отклонил структуру пакета; установка не началась.",
    "SG_INSTALL_REFUSE:ARCHIVE": "Сервер не смог распаковать пакет; установка не началась.",
    "SG_INSTALL_REFUSE:SOURCE": (
        "На сервере нет доверенных исходников в /opt/sovagrid-src или их права небезопасны. "
        "Включение функций не запускалось."
    ),
    "SG_INSTALL_REFUSE:UNMANAGED": (
        "На сервере нет подтверждённой установки SovaGrid через run.sh; "
        "включение функций не запускалось."
    ),
    "SG_INSTALL_REFUSE:UNHEALTHY": (
        "Hub, веб-панель или Agent сейчас не работают исправно. "
        "Сначала восстановите существующую установку."
    ),
    "SG_INSTALL_REFUSE:HASH": "Переданный пакет не совпал с проверенным SHA-256; обновление не подготовлено.",
    "SG_INSTALL_REFUSE:STAGED": "На сервере уже занят путь этого пакета; его содержимое не удалось подтвердить.",
    "SG_INSTALL_REFUSE:STAGE": "Не удалось безопасно подготовить пакет на сервере; работающие службы не менялись.",
    "SG_INSTALL_REFUSE:JOURNAL": (
        "Активная версия установщика на сервере ещё не поддерживает защищённый просмотр журналов. "
        "Подготовленный пакет обновления не включает функцию до её применения."
    ),
    "SG_INSTALL_REFUSE:CONTAINERS": (
        "Активный исходный код сервера ещё не поддерживает просмотр контейнеров. "
        "Сначала установите проверенную новую версию серверных компонентов."
    ),
    "SG_INSTALL_REFUSE:STATE": "Состояние функций или исходников сервера изменилось после проверки. Повторите проверку.",
    "SG_UPDATE_REFUSE:VERSION": "Версия исходников на сервере изменилась после проверки. Откройте обновление заново.",
    "SG_UPDATE_REFUSE:SAME_VERSION": "В пакете те же версии всех компонентов; обновлять нечего.",
    "SG_UPDATE_REFUSE:COMPAT": "В пакете нет файлов для уже включённых функций сервера; обновление не началось.",
    "SG_UPDATE_REFUSE:CANDIDATE": "Подготовленный пакет или его содержимое изменились; подготовьте пакет заново.",
    "SG_UPDATE_REFUSE:HASH": "SHA-256 подготовленного пакета не совпал; обновление не началось.",
    "SG_UPDATE_REFUSE:HOST": "Обновление поддерживается только для Ubuntu с входом root.",
    "SG_UPDATE_REFUSE:ACTIVE": "Активная установка не имеет проверенного манифеста или признаков управления run.sh.",
    "SG_UPDATE_REFUSE:STATE": "Состояние функций или резервной копии неоднозначно; обновление остановлено.",
    "SG_UPDATE_REFUSE:BUSY": "На сервере есть активные сеансы или незавершённые действия; автоматическое обновление отложено.",
    "SG_UPDATE_REFUSE:SPACE": "Недостаточно свободного места для резервной копии и сборки новых образов.",
    "SG_UPDATE_REFUSE:RECOVERED": "Прерванное обновление восстановлено. Проверьте сервер и запустите проверку пакета заново.",
    "SG_UPDATE_REFUSE:RECOVERY": "Не удалось восстановить прерванное обновление. Резервная копия сохранена на сервере.",
    "SG_UPDATE_REFUSE:UNEXPECTED": "Обновление остановилось с неожиданной ошибкой. Проверьте состояние сервера.",
    "SG_AUTO_UPDATE_REFUSE:ROOT_REQUIRED": "Для автообновления на самом сервере нужен SSH-вход root.",
    "SG_AUTO_UPDATE_REFUSE:INVALID_DIGEST": "Неверный SHA-256 пакета или установленной версии.",
    "SG_AUTO_UPDATE_REFUSE:ALREADY_ARMED": "На сервере уже разрешён другой пакет. Сначала отключите его в этом окне.",
    "SG_AUTO_UPDATE_REFUSE:PREFLIGHT_FAILED": "Сервер не подтвердил подготовленный пакет и текущую версию. Проверьте пакет заново.",
    "SG_AUTO_UPDATE_REFUSE:TIMER_UNAVAILABLE": "Служба автообновления на сервере недоступна. Обновите сервер и повторите.",
    "SG_AUTO_UPDATE_REFUSE:UNSAFE_FILE": "Файл настройки автообновления на сервере имеет небезопасные права.",
    "SG_AUTO_UPDATE_REFUSE:INVALID_POLICY": "Настройка автообновления на сервере повреждена; требуется проверка администратора.",
    "SG_AUTO_UPDATE_REFUSE:UPDATE_FAILED": "Сервер остановил автоматическое обновление; проверьте состояние и журнал службы.",
}


class InstallError(TunnelError):
    """A safe-to-display installation error."""


@dataclass(frozen=True)
class BundleSummary:
    path: Path
    size: int
    files: int
    commits: dict[str, str]


@dataclass(frozen=True)
class UpdatePreview:
    bundle: BundleSummary
    sha256: str
    features: FeatureState
    current_manifest_sha256: str
    current_commits: dict[str, str]


@dataclass(frozen=True)
class PreparedUpdate:
    bundle: BundleSummary
    sha256: str
    remote_path: str
    already_prepared: bool


def nearby_server_bundle() -> tuple[Path, str] | None:
    """Offer a bundle beside a starter GUI without saving or accepting it."""
    executable = Path(sys.executable).resolve()
    if getattr(sys, "frozen", False):
        roots = [executable.parent, executable.parent.parent]
        if executable.parent.name == "MacOS" and executable.parent.parent.name == "Contents":
            roots.append(executable.parents[3])
    else:
        roots = [Path(__file__).resolve().parents[2]]
    for root in roots:
        candidate = root / "SovaGrid-server-source.tar.gz"
        try:
            descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_ARCHIVE_BYTES:
                    continue
                digest = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
        except OSError:
            continue
        return candidate, digest.hexdigest()
    return None


def _validate_name(name: str, *, directory: bool = False) -> str:
    if len(name) > 240 or not name.isascii() or "\\" in name or "\x00" in name:
        raise InstallError("Недопустимое имя файла в пакете")
    if directory:
        name = name.rstrip("/")
    path = PurePosixPath(name)
    parts = path.parts
    if not parts or name.startswith("/") or name.endswith("/") or any(
        part in ("", ".", "..") or not _NAME.fullmatch(part) for part in parts
    ) or "/".join(parts) != name:
        raise InstallError("Недопустимый путь файла в пакете")
    if name != "sovagrid-bundle.json" and parts[0] not in COMPONENTS:
        raise InstallError("В пакете есть неизвестный компонент")
    return name


def verify_bundle(path: Path) -> BundleSummary:
    """Validate a private, stable local snapshot before sending it to SSH."""
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise InstallError("Не удаётся открыть выбранный пакет") from exc
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_ARCHIVE_BYTES:
        raise InstallError("Выберите обычный архив SovaGrid размером до 64 МиБ")
    seen: set[str] = set()
    files: dict[str, str] = {}
    manifest_bytes: bytes | None = None
    expanded = 0
    try:
        with tarfile.open(path, "r:gz") as archive:
            if archive.pax_headers:
                raise InstallError("Пакет содержит неподдерживаемые расширенные атрибуты tar")
            for entry in archive:
                name = _validate_name(entry.name, directory=entry.isdir())
                if entry.pax_headers or entry.mode not in ((0o755,) if entry.isdir() else (0o644, 0o755)):
                    raise InstallError("Пакет содержит неподдерживаемые права или атрибуты tar")
                if name == "sovagrid-web/deploy/Caddyfile.container" and entry.mode != 0o644:
                    raise InstallError("Caddyfile в пакете должен иметь права 0644")
                if name in seen:
                    raise InstallError("В пакете повторяется путь")
                seen.add(name)
                if entry.isdir():
                    if name not in COMPONENTS and not any(name.startswith(component + "/") for component in COMPONENTS):
                        raise InstallError("В пакете есть лишняя папка")
                    continue
                if not entry.isfile() or entry.size < 0 or entry.size > MAX_FILE_BYTES:
                    raise InstallError("В пакете есть ссылка, особый или слишком большой файл")
                if entry.name == "sovagrid-bundle.json" and entry.size > 512 * 1024:
                    raise InstallError("Манифест пакета слишком большой")
                expanded += entry.size
                if expanded > MAX_EXPANDED_BYTES or len(files) >= MAX_FILES:
                    raise InstallError("Пакет превышает лимит размера или количества файлов")
                source = archive.extractfile(entry)
                if source is None:
                    raise InstallError("Не удалось прочитать файл из пакета")
                digest = hashlib.sha256()
                content = bytearray() if name == "sovagrid-bundle.json" else None
                remaining = entry.size
                while remaining:
                    part = source.read(min(128 * 1024, remaining))
                    if not part:
                        raise InstallError("Файл внутри пакета обрезан")
                    digest.update(part)
                    if content is not None:
                        content.extend(part)
                    remaining -= len(part)
                if content is not None:
                    manifest_bytes = bytes(content)
                else:
                    files[name] = digest.hexdigest()
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise InstallError("Пакет повреждён или имеет неверный формат tar.gz") from exc
    if manifest_bytes is None or not REQUIRED_FILES <= files.keys():
        raise InstallError("В пакете нет манифеста или обязательных файлов SovaGrid")
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError("Манифест пакета повреждён") from exc
    if not isinstance(manifest, dict) or set(manifest) != {"format", "components", "sha256"} or type(manifest["format"]) is not int or manifest["format"] != 1:
        raise InstallError("Формат манифеста SovaGrid не поддерживается")
    components = manifest["components"]
    hashes = manifest["sha256"]
    if not isinstance(components, dict) or set(components) != COMPONENTS or not isinstance(hashes, dict) or hashes != files:
        raise InstallError("Хеши или список компонентов пакета не совпадают с манифестом")
    commits: dict[str, str] = {}
    for name, record in components.items():
        if not isinstance(record, dict) or set(record) != {"commit", "file_count"}:
            raise InstallError("Запись компонента в манифесте повреждена")
        commit, count = record["commit"], record["file_count"]
        actual_count = sum(file.startswith(name + "/") for file in files)
        if not isinstance(commit, str) or not _COMMIT.fullmatch(commit) or type(count) is not int or count != actual_count or count < 1:
            raise InstallError("Количество файлов или версия компонента не совпадают")
        commits[name] = commit
    # The metadata hash map must contain only SHA-256 strings; equality above
    # already checks each value against the file that was actually read.
    if not all(isinstance(value, str) and _SHA256.fullmatch(value) for value in hashes.values()):
        raise InstallError("Манифест содержит неверный хеш")
    return BundleSummary(path=path, size=metadata.st_size, files=len(files), commits=commits)


def snapshot_bundle(source: Path, destination: Path) -> BundleSummary:
    """Copy a selected bundle once to a 0600 file, then verify that exact copy."""
    try:
        metadata = source.lstat()
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_ARCHIVE_BYTES:
            raise InstallError("Выберите обычный архив SovaGrid размером до 64 МиБ")
        source_descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(source_descriptor, "rb") as input_file:
            actual = os.fstat(input_file.fileno())
            if not stat.S_ISREG(actual.st_mode) or not 0 < actual.st_size <= MAX_ARCHIVE_BYTES:
                raise InstallError("Выберите обычный архив SovaGrid размером до 64 МиБ")
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as output_file:
                    copied = 0
                    while True:
                        chunk = input_file.read(128 * 1024)
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > MAX_ARCHIVE_BYTES:
                            raise InstallError("Пакет стал слишком большим во время копирования")
                        output_file.write(chunk)
            except BaseException:
                destination.unlink(missing_ok=True)
                raise
    except InstallError:
        raise
    except OSError as exc:
        raise InstallError("Не удаётся безопасно скопировать выбранный пакет") from exc
    return verify_bundle(destination)


def _snapshot_with_digest(source: Path, destination: Path, expected_sha256: str | None = None) -> tuple[BundleSummary, str]:
    summary = snapshot_bundle(source, destination)
    digest = hashlib.sha256()
    with destination.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    actual = digest.hexdigest()
    if expected_sha256 is not None and actual != expected_sha256:
        raise InstallError("Пакет изменился после отображения SHA-256; откройте проверку заново")
    return summary, actual


_CHECKS = r'''
set -Eeuo pipefail
umask 077
if [[ $(id -u) != 0 ]]; then printf 'SG_INSTALL_REFUSE:ROOT\n'; exit 20; fi
if [[ ! -r /etc/os-release ]]; then printf 'SG_INSTALL_REFUSE:UBUNTU\n'; exit 21; fi
. /etc/os-release
if [[ ${ID:-} != ubuntu ]]; then printf 'SG_INSTALL_REFUSE:UBUNTU\n'; exit 21; fi
for path in /opt/sovagrid-src /opt/sovagrid-agent /opt/sovagrid-vpn /etc/sovagrid /etc/sovagrid-hub /var/lib/sovagrid /var/lib/sovagrid-agent /var/lib/sovagrid-first-install; do
  if [[ -e $path || -L $path ]]; then printf 'SG_INSTALL_REFUSE:EXISTING\n'; exit 22; fi
done
if [[ -n $(find /etc/systemd/system -maxdepth 1 -name 'sovagrid-*' -print -quit 2>/dev/null) ]]; then
  printf 'SG_INSTALL_REFUSE:EXISTING\n'; exit 22
fi
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if [[ -n $(docker ps -a --filter label=com.docker.compose.project=sovagrid --format '{{.ID}}') ]]; then
    printf 'SG_INSTALL_REFUSE:EXISTING\n'; exit 22
  fi
fi
'''
_PREFLIGHT_COMMAND = "bash -c " + shlex.quote(_CHECKS + "printf 'SG_INSTALL_PREFLIGHT:OK\\n'\n")
_INSTALL_SCRIPT = _CHECKS + r'''
command -v flock >/dev/null 2>&1 || { printf 'SG_INSTALL_REFUSE:UNKNOWN\n'; exit 22; }
exec 9>/run/sovagrid-first-install.lock
flock -n 9 || { printf 'SG_INSTALL_REFUSE:EXISTING\n'; exit 22; }
archive=$(mktemp /opt/.sovagrid-bundle.XXXXXXXX)
stage=$(mktemp -d /opt/.sovagrid-stage.XXXXXXXX)
cleanup() { rm -f -- "$archive"; if [[ -d $stage ]]; then rm -rf -- "$stage"; fi; }
trap cleanup EXIT
cat > "$archive"
if [[ ! -s $archive || $(stat -c %s "$archive") -gt 67108864 ]]; then
  printf 'SG_INSTALL_REFUSE:ARCHIVE\n'; exit 23
fi
printf 'SG_INSTALL_STAGE:TRANSFER\n'
if ! tar --no-same-owner --same-permissions -xzf "$archive" -C "$stage" >/dev/null 2>&1; then
  printf 'SG_INSTALL_REFUSE:ARCHIVE\n'; exit 23
fi
printf 'SG_INSTALL_STAGE:EXTRACT\n'
for component in sovagrid-blueprint sovagrid-hub sovagrid-web sovagrid-agent sovagrid-vpn; do
  if [[ ! -d $stage/$component || -L $stage/$component ]]; then
    printf 'SG_INSTALL_REFUSE:LAYOUT\n'; exit 24
  fi
done
for required in sovagrid-blueprint/run.sh sovagrid-blueprint/deploy/compose.yaml sovagrid-hub/Dockerfile sovagrid-web/Dockerfile sovagrid-web/deploy/Caddyfile.container sovagrid-agent/deploy/sovagrid-agent.service sovagrid-vpn/deploy/sovagrid-vpn-status.service sovagrid-bundle.json; do
  if [[ ! -f $stage/$required || -L $stage/$required ]]; then
    printf 'SG_INSTALL_REFUSE:LAYOUT\n'; exit 24
  fi
done
if [[ $(find "$stage" -mindepth 1 -maxdepth 1 -print | wc -l) -ne 6 ]] ||
   [[ -n $(find "$stage" ! -type f ! -type d -print -quit) ]] ||
   [[ -n $(find "$stage" -mindepth 1 -type d ! -perm 0755 -print -quit) ]] ||
   [[ -n $(find "$stage" -type f ! -perm 0644 ! -perm 0755 -print -quit) ]] ||
   [[ $(stat -c '%a' "$stage/sovagrid-web/deploy/Caddyfile.container") != 644 ]] ||
   [[ -e /opt/sovagrid-src || -L /opt/sovagrid-src ]]; then
  printf 'SG_INSTALL_REFUSE:LAYOUT\n'; exit 24
fi
''' + _CHECKS + r'''
mv -T -- "$stage" /opt/sovagrid-src
printf 'SG_INSTALL_STAGE:RUN\n'
bash /opt/sovagrid-src/sovagrid-blueprint/run.sh "$@" 2>&1 | while IFS= read -r line; do
  case "$line" in
    'SovaGrid: installing Docker from Ubuntu packages') printf 'SG_INSTALL_STAGE:DOCKER\n' ;;
    'SovaGrid: installing the Docker Compose plugin') printf 'SG_INSTALL_STAGE:COMPOSE\n' ;;
    'SovaGrid: building and starting only SovaGrid Hub and Web') printf 'SG_INSTALL_STAGE:BUILD\n' ;;
    'SovaGrid: Hub and Web health checks passed on loopback; no public ports were opened') printf 'SG_INSTALL_STAGE:HEALTH\n' ;;
    'SovaGrid: host Agent is active under the unprivileged sovagrid user') printf 'SG_INSTALL_STAGE:AGENT\n' ;;
  esac
done
printf 'SG_INSTALL_STAGE:DONE\n'
'''


def validate_journal_units(units: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Accept only an explicit, bounded list of exact systemd service names."""
    if not isinstance(units, (tuple, list)) or not 1 <= len(units) <= 16:
        raise InstallError("Для журнала укажите от 1 до 16 точных имён служб .service")
    result = tuple(units)
    if any(not isinstance(unit, str) or not _JOURNAL_UNIT.fullmatch(unit) for unit in result):
        raise InstallError("Имя службы должно точно оканчиваться на .service (например, ssh.service)")
    if len(set(result)) != len(result):
        raise InstallError("Список служб содержит повторяющиеся имена")
    return result


def parse_journal_units(value: str) -> tuple[str, ...]:
    """Parse GUI input: one exact service name per nonblank line."""
    if not isinstance(value, str):
        raise InstallError("Укажите точные имена служб .service")
    return validate_journal_units(tuple(line.strip() for line in value.splitlines() if line.strip()))


@dataclass(frozen=True)
class InstallFeatures:
    wireguard: bool = False
    terminal: bool = False
    files: bool = False
    journal_units: tuple[str, ...] = ()
    journal_disable: bool = False
    containers: bool = False
    containers_disable: bool = False

    def __post_init__(self) -> None:
        if self.journal_units:
            object.__setattr__(self, "journal_units", validate_journal_units(self.journal_units))
        if self.journal_units and self.journal_disable:
            raise InstallError("Нельзя одновременно включить и выключить журналы")
        if self.containers and self.containers_disable:
            raise InstallError("Нельзя одновременно включить и выключить просмотр контейнеров")

    def flags(self) -> tuple[str, ...]:
        flags = tuple(flag for enabled, flag in (
            (self.wireguard, "--with-wireguard"),
            (self.terminal, "--with-terminal"),
            (self.files, "--with-files"),
        ) if enabled)
        if self.journal_units:
            flags += ("--with-journal",)
            for unit in self.journal_units:
                flags += ("--journal-unit", unit)
        if self.journal_disable:
            flags += ("--disable-journal",)
        if self.containers:
            flags += ("--with-containers",)
        if self.containers_disable:
            flags += ("--disable-containers",)
        return flags

    def any_enabled(self) -> bool:
        return (self.wireguard or self.terminal or self.files or bool(self.journal_units)
                or self.journal_disable or self.containers or self.containers_disable)


@dataclass(frozen=True)
class FeatureState:
    wireguard: bool
    terminal: bool
    files: bool
    journal: bool = False
    journal_configured: bool = False
    journal_supported: bool = False
    journal_units: tuple[str, ...] = ()
    containers: bool = False
    containers_configured: bool = False
    containers_supported: bool = False
    cas_sha256: str | None = None

    @classmethod
    def from_markers(cls, markers: list[str]) -> "FeatureState":
        values = []
        for name in ("WIREGUARD", "TERMINAL", "FILES", "JOURNAL", "JOURNAL_CONFIGURED", "JOURNAL_SUPPORTED"):
            matching = [marker for marker in markers if marker in (f"SG_FEATURE:{name}:0", f"SG_FEATURE:{name}:1")]
            if len(matching) != 1:
                raise InstallError("Сервер прислал неполный ответ о включённых функциях")
            values.append(matching[0].endswith(":1"))
        units = tuple(match.group(1) for marker in markers
                      if (match := _JOURNAL_UNIT_MARKER.fullmatch(marker)))
        if len(units) > 16 or len(set(units)) != len(units) or (values[3] and not units):
            raise InstallError("Сервер прислал неверный список служб журнала")
        container_values = []
        for name in ("CONTAINERS", "CONTAINERS_CONFIGURED", "CONTAINERS_SUPPORTED"):
            matching = [marker for marker in markers if marker in (f"SG_FEATURE:{name}:0", f"SG_FEATURE:{name}:1")]
            if len(matching) > 1:
                raise InstallError("Сервер прислал противоречивое состояние контейнеров")
            container_values.append(bool(matching and matching[0].endswith(":1")))
        cas = [match.group(1) for marker in markers if (match := _FEATURE_CAS_MARKER.fullmatch(marker))]
        if len(cas) > 1:
            raise InstallError("Сервер прислал противоречивую версию состояния")
        return cls(*values, units, *container_values, cas[0] if cas else None)

    def covers(self, selected: InstallFeatures) -> bool:
        return (not selected.wireguard or self.wireguard) and \
            (not selected.terminal or self.terminal) and \
            (not selected.files or self.files) and \
            (not selected.journal_units or
             (self.journal and set(self.journal_units) == set(selected.journal_units))) and \
            (not selected.journal_disable or not self.journal_configured) and \
            (not selected.containers or self.containers) and \
            (not selected.containers_disable or not self.containers_configured)


_EXISTING_CHECKS = r'''
set -Eeuo pipefail
umask 077
refuse() { printf 'SG_INSTALL_REFUSE:%s\n' "$1"; exit 30; }
[[ $(id -u) == 0 ]] || refuse ROOT
[[ -r /etc/os-release ]] || refuse UBUNTU
. /etc/os-release
[[ ${ID:-} == ubuntu ]] || refuse UBUNTU
source_root=/opt/sovagrid-src
for path in /opt "$source_root" "$source_root/sovagrid-blueprint" "$source_root/sovagrid-hub" "$source_root/sovagrid-web" "$source_root/sovagrid-agent" "$source_root/sovagrid-vpn"; do
  [[ -d $path && ! -L $path && $(stat -c %u "$path") == 0 ]] || refuse SOURCE
  [[ -z $(find "$path" -maxdepth 0 -perm /022 -print -quit) ]] || refuse SOURCE
done
for path in "$source_root/sovagrid-blueprint/run.sh" "$source_root/sovagrid-blueprint/deploy/compose.yaml" "$source_root/sovagrid-hub/Dockerfile" "$source_root/sovagrid-web/Dockerfile" "$source_root/sovagrid-agent/deploy/sovagrid-agent.service" "$source_root/sovagrid-vpn/deploy/sovagrid-vpn-status.service"; do
  [[ -f $path && ! -L $path ]] || refuse SOURCE
done
[[ -z $(find "$source_root" \( -type l -o ! -user root -o -perm /022 -o ! -type f ! -type d \) -print -quit) ]] || refuse SOURCE
for path in /var/lib/sovagrid/.managed-by-run-sh /etc/sovagrid/.agent-unit-managed-by-run-sh /etc/sovagrid/.vpn-unit-managed-by-run-sh /var/lib/sovagrid/hub/hub.sqlite /etc/sovagrid/agent.json; do
  [[ -f $path && ! -L $path ]] || refuse UNMANAGED
done
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 || refuse UNHEALTHY
systemctl is-active --quiet sovagrid-agent.service || refuse UNHEALTHY
hub=$(docker ps --filter label=com.docker.compose.project=sovagrid --filter label=com.docker.compose.service=hub --format '{{.ID}}')
web=$(docker ps --filter label=com.docker.compose.project=sovagrid --filter label=com.docker.compose.service=web --format '{{.ID}}')
[[ -n $hub && -n $web && $hub != *$'\n'* && $web != *$'\n'* ]] || refuse UNHEALTHY
[[ $(docker inspect --format '{{.State.Health.Status}}' "$hub") == healthy ]] || refuse UNHEALTHY
python3 -c 'import urllib.request; r=urllib.request.urlopen("http://127.0.0.1:8766/healthz", timeout=5); assert r.status == 200; r.close()' >/dev/null 2>&1 || refuse UNHEALTHY
if [[ -f /etc/sovagrid/.vpn-control-managed-by-run-sh ]] && systemctl is-active --quiet sovagrid-vpn-control.socket; then
  printf 'SG_FEATURE:WIREGUARD:1\n'
else
  printf 'SG_FEATURE:WIREGUARD:0\n'
fi
if [[ -f /etc/sovagrid/.terminal-unit-managed-by-run-sh ]] && systemctl is-active --quiet sovagrid-terminal-control.socket; then
  printf 'SG_FEATURE:TERMINAL:1\n'
else
  printf 'SG_FEATURE:TERMINAL:0\n'
fi
if python3 -c 'import json; d=json.load(open("/etc/sovagrid/agent.json", encoding="utf-8")); assert d.get("allow_file_manager") is True and d.get("file_roots", {}).get("workspace") == "/var/lib/sovagrid-agent/files"' >/dev/null 2>&1; then
  printf 'SG_FEATURE:FILES:1\n'
else
  printf 'SG_FEATURE:FILES:0\n'
fi
if grep -Fxq '# SOVAGRID_JOURNAL_INSTALL_V1' "$source_root/sovagrid-blueprint/run.sh" &&
   [[ -f $source_root/sovagrid-agent/sovagrid_agent/journal_broker.py &&
      -f $source_root/sovagrid-agent/deploy/sovagrid-journal-control.socket &&
      -f $source_root/sovagrid-agent/deploy/sovagrid-journal-control.service ]]; then
  printf 'SG_FEATURE:JOURNAL_SUPPORTED:1\n'
else
  printf 'SG_FEATURE:JOURNAL_SUPPORTED:0\n'
fi
journal_broker=0
if systemctl is-active --quiet sovagrid-journal-control.socket &&
   systemctl is-active --quiet sovagrid-journal-control.service; then journal_broker=1; fi
for broad_group in systemd-journal adm; do
  if id -nG sovagrid | tr ' ' '\n' | grep -Fxq "$broad_group"; then journal_broker=0; fi
done
if ! python3 - "$journal_broker" <<'PY'
import grp, json, pathlib, re, stat, sys
config = json.loads(pathlib.Path('/etc/sovagrid/agent.json').read_text(encoding='utf-8'))
enabled = config.get('allow_systemd_journal', False)
units = config.get('journal_units', [])
pattern = re.compile(r'[A-Za-z0-9_.@-]{1,96}\.service\Z')
if not isinstance(enabled, bool) or not isinstance(units, list) or len(units) > 16 or len(set(units)) != len(units) or any(not isinstance(unit, str) or not pattern.fullmatch(unit) for unit in units):
    raise SystemExit(1)
policy_path = pathlib.Path('/etc/sovagrid-journal/units.json')
policy_ok = False
if policy_path.is_file() and not policy_path.is_symlink() and not policy_path.parent.is_symlink():
    try:
        info = policy_path.lstat()
        gid = grp.getgrnam('sovagrid-journal').gr_gid
        if (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 1 <= info.st_size <= 4096 and info.st_uid == 0 and
                info.st_gid == gid and stat.S_IMODE(info.st_mode) == 0o640):
            policy = json.loads(policy_path.read_text(encoding='utf-8'))
            policy_ok = isinstance(policy, dict) and policy.get('units') == units
    except (OSError, KeyError, ValueError):
        pass
active = bool(enabled and units and policy_ok and sys.argv[1] == '1')
print('SG_FEATURE:JOURNAL:' + ('1' if active else '0'))
configured = bool(enabled or pathlib.Path('/etc/sovagrid/.journal-managed-by-run-sh').is_file())
print('SG_FEATURE:JOURNAL_CONFIGURED:' + ('1' if configured else '0'))
for unit in units:
    print('SG_JOURNAL_UNIT:' + unit)
PY
then refuse UNMANAGED; fi
container_run="$source_root/sovagrid-blueprint/run.sh"
if grep -Fxq '# SOVAGRID_CONTAINER_INVENTORY_V1' "$container_run" &&
   [[ -f $source_root/sovagrid-agent/sovagrid_agent/containers.py &&
      -f $source_root/sovagrid-agent/sovagrid_agent/container_collector.py &&
      -f $source_root/sovagrid-agent/deploy/sovagrid-container-inventory.service &&
      -f $source_root/sovagrid-agent/deploy/sovagrid-container-inventory.timer ]]; then
  printf 'SG_FEATURE:CONTAINERS_SUPPORTED:1\n'
else
  printf 'SG_FEATURE:CONTAINERS_SUPPORTED:0\n'
fi
container_marker=/etc/sovagrid/.containers-managed-by-run-sh
if [[ -e $container_marker || -L $container_marker ]]; then
  [[ -f $container_marker && ! -L $container_marker &&
     $(stat -c '%U:%G:%a' "$container_marker") == root:root:600 ]] || refuse UNMANAGED
  [[ -d /var/lib/sovagrid-containers && ! -L /var/lib/sovagrid-containers ]] || refuse UNMANAGED
  printf 'SG_FEATURE:CONTAINERS_CONFIGURED:1\n'
  if systemctl is-active --quiet sovagrid-container-inventory.timer &&
     [[ -f /var/lib/sovagrid-containers/snapshot.json &&
        ! -L /var/lib/sovagrid-containers/snapshot.json &&
        $(stat -c '%U:%G:%a:%h' /var/lib/sovagrid-containers/snapshot.json) == root:sovagrid:640:1 ]]; then
    printf 'SG_FEATURE:CONTAINERS:1\n'
  else
    printf 'SG_FEATURE:CONTAINERS:0\n'
  fi
else
  for footprint in /etc/systemd/system/sovagrid-container-inventory.service \
                   /etc/systemd/system/sovagrid-container-inventory.timer \
                   /var/lib/sovagrid-containers; do
    [[ ! -e $footprint && ! -L $footprint ]] || refuse UNMANAGED
  done
  printf 'SG_FEATURE:CONTAINERS_CONFIGURED:0\n'
  printf 'SG_FEATURE:CONTAINERS:0\n'
fi
printf 'SG_FEATURE_PREFLIGHT:OK\n'
'''
_FEATURE_PROBE_SCRIPT = ("set -Eeuo pipefail\n"
                         "probe=$(bash -c " + shlex.quote(_EXISTING_CHECKS) + ")\n"
                         "printf '%s\\n' \"$probe\"\n"
                         "source_digest=$(find /opt/sovagrid-src -type f -print0 | sort -z | "
                         "xargs -0 sha256sum | sha256sum | cut -d' ' -f1)\n"
                         "config_digest=$(sha256sum /etc/sovagrid/agent.json | cut -d' ' -f1)\n"
                         "current_cas=$(printf '%s\\n' \"$probe\" \"$source_digest\" \"$config_digest\" | "
                         "sha256sum | cut -d' ' -f1)\n"
                         "printf 'SG_FEATURE_CAS:%s\\n' \"$current_cas\"\n")
_FEATURE_PREFLIGHT_COMMAND = "bash -c " + shlex.quote(_FEATURE_PROBE_SCRIPT)
_FEATURE_ENABLE_SCRIPT = _FEATURE_PROBE_SCRIPT + r'''
refuse() { printf 'SG_INSTALL_REFUSE:%s\n' "$1"; exit 30; }
expected_cas=$1
shift
if [[ $expected_cas == - ]]; then
  for flag in "$@"; do
    [[ $flag != --with-containers && $flag != --disable-containers ]] || refuse STATE
  done
else
  [[ $expected_cas =~ ^[0-9a-f]{64}$ && $current_cas == "$expected_cas" ]] || refuse STATE
fi
for flag in "$@"; do
  if [[ $flag == --with-journal || $flag == --disable-journal ]] &&
     ! grep -Fxq '# SOVAGRID_JOURNAL_INSTALL_V1' /opt/sovagrid-src/sovagrid-blueprint/run.sh; then
    refuse JOURNAL
  fi
  if [[ $flag == --with-containers || $flag == --disable-containers ]] &&
     ! grep -Fxq '# SOVAGRID_CONTAINER_INVENTORY_V1' /opt/sovagrid-src/sovagrid-blueprint/run.sh; then
    refuse CONTAINERS
  fi
done
printf 'SG_INSTALL_STAGE:RUN\n'
bash /opt/sovagrid-src/sovagrid-blueprint/run.sh "$@" 2>&1 | while IFS= read -r line; do
  case "$line" in
    'SovaGrid: installing Docker from Ubuntu packages') printf 'SG_INSTALL_STAGE:DOCKER\n' ;;
    'SovaGrid: installing the Docker Compose plugin') printf 'SG_INSTALL_STAGE:COMPOSE\n' ;;
    'SovaGrid: building and starting only SovaGrid Hub and Web') printf 'SG_INSTALL_STAGE:BUILD\n' ;;
    'SovaGrid: Hub and Web health checks passed on loopback; no public ports were opened') printf 'SG_INSTALL_STAGE:HEALTH\n' ;;
    'SovaGrid: host Agent is active under the unprivileged sovagrid user') printf 'SG_INSTALL_STAGE:AGENT\n' ;;
  esac
done
printf 'SG_INSTALL_STAGE:DONE\n'
'''

# This command only stores a content-addressed candidate. Applying it is a
# separate, confirmed transaction handled by REMOTE_SCRIPT.
_STAGE_CANDIDATE_BODY = r'''
expected=$1
[[ $expected =~ ^[0-9a-f]{64}$ ]] || refuse HASH
command -v flock >/dev/null 2>&1 || refuse STAGE
candidate_root=/opt/sovagrid-candidates
if [[ -e $candidate_root || -L $candidate_root ]]; then
  [[ -d $candidate_root && ! -L $candidate_root && $(stat -c '%u:%a' "$candidate_root") == 0:700 ]] || refuse STAGE
else
  install -d -o root -g root -m 0700 -- "$candidate_root" || refuse STAGE
fi
lock=$candidate_root/.lock
[[ ! -L $lock ]] || refuse STAGE
if [[ ! -e $lock ]]; then
  install -o root -g root -m 0600 -- /dev/null "$lock" || refuse STAGE
fi
[[ -f $lock && $(stat -c '%u:%a' "$lock") == 0:600 ]] || refuse STAGE
exec 9>>"$lock"
[[ -f $lock && $(stat -c '%u:%a' "$lock") == 0:600 ]] || refuse STAGE
flock -x 9 || refuse STAGE
candidate=$candidate_root/$expected

validate_source() {
  python3 - "$1" <<'PY' >/dev/null 2>&1
import hashlib, json, os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
root_info = os.lstat(root)
assert stat.S_ISDIR(root_info.st_mode) and root_info.st_uid == 0
assert not (root_info.st_mode & 0o022)
required = {'sovagrid-blueprint/run.sh', 'sovagrid-blueprint/deploy/compose.yaml',
            'sovagrid-hub/Dockerfile', 'sovagrid-web/Dockerfile',
            'sovagrid-web/deploy/Caddyfile.container',
            'sovagrid-agent/deploy/sovagrid-agent.service',
            'sovagrid-vpn/deploy/sovagrid-vpn-status.service'}
components = {'sovagrid-blueprint', 'sovagrid-hub', 'sovagrid-web',
              'sovagrid-agent', 'sovagrid-vpn'}
manifest = json.loads((root / 'sovagrid-bundle.json').read_text(encoding='utf-8'))
hashes = manifest['sha256']
assert isinstance(hashes, dict) and required <= hashes.keys()
assert set(manifest['components']) == components
assert {p.name for p in root.iterdir()} == components | {'sovagrid-bundle.json'}
seen = set()
for parent, dirs, files in os.walk(root, followlinks=False):
    for name in dirs + files:
        path = pathlib.Path(parent) / name
        info = os.lstat(path)
        assert info.st_uid == 0 and not (info.st_mode & 0o022)
        if name in dirs:
            assert stat.S_ISDIR(info.st_mode)
            assert stat.S_IMODE(info.st_mode) == 0o755
            continue
        assert stat.S_ISREG(info.st_mode)
        relative = path.relative_to(root).as_posix()
        assert stat.S_IMODE(info.st_mode) in (0o644, 0o755)
        if relative == 'sovagrid-web/deploy/Caddyfile.container':
            assert stat.S_IMODE(info.st_mode) == 0o644
        if relative == 'sovagrid-bundle.json':
            continue
        assert relative in hashes
        digest_state = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest_state.update(block)
        digest = digest_state.hexdigest()
        assert digest == hashes[relative]
        seen.add(relative)
assert seen == set(hashes)
PY
}

stage=$(mktemp -d "$candidate_root/.stage.XXXXXXXX") || refuse STAGE
cleanup() { [[ -z $stage ]] || rm -rf -- "$stage"; }
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
cat > "$stage/bundle.tar.gz" || refuse STAGE
[[ -s $stage/bundle.tar.gz && $(stat -c %s "$stage/bundle.tar.gz") -le 67108864 ]] || refuse HASH
printf 'SG_UPDATE_STAGE:TRANSFER\n'
[[ $(sha256sum "$stage/bundle.tar.gz" | cut -d' ' -f1) == "$expected" ]] || refuse HASH
if [[ -e $candidate || -L $candidate ]]; then
  [[ -d $candidate && ! -L $candidate && $(stat -c '%u:%a' "$candidate") == 0:700 &&
     -f $candidate/.ready && ! -L $candidate/.ready &&
     -f $candidate/bundle.tar.gz && ! -L $candidate/bundle.tar.gz &&
     $(cat "$candidate/.ready") == "$expected" &&
     $(sha256sum "$candidate/bundle.tar.gz" | cut -d' ' -f1) == "$expected" ]] || refuse STAGED
  validate_source "$candidate/source" || refuse STAGED
  printf 'SG_UPDATE_STAGE:ALREADY\nSG_UPDATE_STAGE:DONE\n'
  exit 0
fi
mkdir -m 0700 -- "$stage/source" || refuse STAGE
tar --no-same-owner --same-permissions -xzf "$stage/bundle.tar.gz" -C "$stage/source" >/dev/null 2>&1 || refuse STAGE
validate_source "$stage/source" || refuse STAGE
printf 'SG_UPDATE_STAGE:VERIFY\n'
printf '%s\n' "$expected" > "$stage/.ready"
chmod 0600 "$stage/.ready" "$stage/bundle.tar.gz"
mv -T -- "$stage" "$candidate" || refuse STAGE
stage=''
printf 'SG_UPDATE_STAGE:DONE\n'
'''
_STAGE_UPDATE_SCRIPT = _EXISTING_CHECKS + _STAGE_CANDIDATE_BODY


class ServerInstaller:
    def __init__(
        self, options: ConnectionOptions, *,
        popen: Callable[..., subprocess.Popen] = subprocess.Popen,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        self.options = options.validated()
        self._popen = popen
        self._progress = progress or (lambda _message: None)
        self._process: subprocess.Popen | None = None
        self._lock = threading.Lock()

    @contextmanager
    def _session(self) -> Iterator[tuple[str, str]]:
        config_dir, config = _safe_config_directory()
        try:
            path = Path(config_dir.name) / "ssh_config"
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(_ssh_config(self.options, confirm_host_keys=True))
            yield config, helper_path(config_dir.name)
        finally:
            config_dir.cleanup()

    def _ssh(self, config: str, helper: str, command: str, *, input_file=None) -> subprocess.Popen:
        ssh = shutil.which(self.options.ssh_executable)
        if ssh is None:
            raise InstallError("Не найден системный OpenSSH; установите ssh и повторите")
        env = os.environ.copy()
        env["SSH_ASKPASS"] = helper
        env["SSH_ASKPASS_REQUIRE"] = "force"
        argv = [
            ssh, "-F", config, "-T", "-o", "BatchMode=no",
            "-o", "ConnectTimeout=10", "-o", "ClearAllForwardings=yes",
            "sovagrid-target", command,
        ]
        try:
            process = self._popen(
                argv, env=env, stdin=input_file if input_file is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
            )
        except OSError as exc:
            raise InstallError("Не удалось запустить OpenSSH") from exc
        with self._lock:
            self._process = process
        return process

    def _read_markers(self, process: subprocess.Popen, *, timeout: float) -> list[str]:
        markers: list[str] = []
        timed_out = threading.Event()

        def stop_on_timeout() -> None:
            timed_out.set()
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass

        timer = threading.Timer(timeout, stop_on_timeout)
        timer.daemon = True
        timer.start()
        try:
            assert process.stdout is not None
            while True:
                line = process.stdout.readline(8192)
                if not line:
                    break
                marker = line.decode("ascii", errors="ignore").strip()
                if marker in _PROGRESS_MARKERS:
                    markers.append(marker)
                    self._progress(_PROGRESS_MARKERS[marker])
                elif (marker in _REFUSALS or marker in (_PREFLIGHT_OK, _FEATURE_PREFLIGHT_OK, _VERSION_PREFLIGHT_OK)
                      or marker in _SERVER_TIMER_ACTIONS
                      or STATUS_MARKER.fullmatch(marker)
                      or marker in _FEATURE_MARKERS or _JOURNAL_UNIT_MARKER.fullmatch(marker)
                      or _FEATURE_CAS_MARKER.fullmatch(marker)
                      or _CURRENT_MANIFEST_MARKER.fullmatch(marker) or _CURRENT_COMMIT_MARKER.fullmatch(marker)):
                    markers.append(marker)
            process.wait()
        finally:
            timer.cancel()
            if process.stdout is not None:
                process.stdout.close()
            with self._lock:
                if self._process is process:
                    self._process = None
        if timed_out.is_set():
            raise InstallError("SSH или установка не ответили вовремя")
        refusal = next((marker for marker in markers if marker in _REFUSALS), None)
        if refusal is not None:
            raise InstallError(_REFUSALS[refusal])
        return markers

    def _read_bounded(self, process: subprocess.Popen, *, timeout: float, limit: int = 4096) -> bytes:
        """Read a small fixed remote status without displaying arbitrary SSH output."""
        timed_out = threading.Event()

        def stop_on_timeout() -> None:
            timed_out.set()
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass

        timer = threading.Timer(timeout, stop_on_timeout)
        timer.daemon = True
        timer.start()
        try:
            assert process.stdout is not None
            data = bytearray()
            while True:
                chunk = process.stdout.read(min(1024, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    try:
                        process.kill()
                    except OSError:
                        pass
                    raise InstallError("Сервер вернул слишком большой ответ автообновления")
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
            with self._lock:
                if self._process is process:
                    self._process = None
        if timed_out.is_set():
            raise InstallError("SSH не ответил при проверке автообновления")
        return bytes(data)

    def probe_status(self) -> ServerStatus:
        """Classify an SSH target without changing it or trusting a dead panel."""
        with tempfile.TemporaryDirectory(prefix="sovagrid-status-") as private_dir:
            script = Path(private_dir) / "status.py"
            script.write_text(STATUS_SCRIPT, encoding="utf-8")
            with self._session() as (config, helper), script.open("rb") as input_file:
                process = self._ssh(config, helper, STATUS_COMMAND, input_file=input_file)
                markers = self._read_markers(process, timeout=45)
        return parse_status(markers, returncode=process.returncode)

    def install(self, source: Path, features: InstallFeatures = InstallFeatures(),
                *, expected_sha256: str | None = None) -> BundleSummary:
        if self.options.user != "root":
            raise InstallError("Для первой установки укажите SSH-пользователя root")
        if features.journal_disable:
            raise InstallError("Выключение журналов доступно только для существующей установки")
        with tempfile.TemporaryDirectory(prefix="sovagrid-install-") as private_dir:
            bundle = Path(private_dir) / "bundle.tar.gz"
            self._progress("Проверка пакета…")
            summary, _digest = _snapshot_with_digest(source, bundle, expected_sha256)
            if features.journal_units:
                with tarfile.open(bundle, "r:gz") as archive:
                    script = archive.extractfile("sovagrid-blueprint/run.sh")
                    if script is None or _JOURNAL_INSTALL_MARKER not in script.read(MAX_FILE_BYTES + 1):
                        raise InstallError("Этот пакет ещё не поддерживает защищённый просмотр журналов")
                    for required in (
                        "sovagrid-agent/sovagrid_agent/journal_broker.py",
                        "sovagrid-agent/deploy/sovagrid-journal-control.socket",
                        "sovagrid-agent/deploy/sovagrid-journal-control.service",
                    ):
                        if required not in archive.getnames():
                            raise InstallError("В пакете нет компонента защищённого просмотра журналов")
            self._progress(f"Пакет проверен: {summary.files} файлов, {summary.size // 1024} КиБ")
            with self._session() as (config, helper):
                self._progress("Проверка Ubuntu и прав root по SSH…")
                preflight = self._ssh(config, helper, _PREFLIGHT_COMMAND)
                markers = self._read_markers(preflight, timeout=180)
                if preflight.returncode != 0 or _PREFLIGHT_OK not in markers:
                    raise InstallError("SSH не прошёл проверку. Проверьте ключ сервера, root-вход и права доступа")
                flags = " ".join(shlex.quote(flag) for flag in features.flags())
                command = "bash -c " + shlex.quote(_INSTALL_SCRIPT) + " sovagrid" + (" " + flags if flags else "")
                self._progress("Отправка пакета на сервер…")
                with bundle.open("rb") as input_file:
                    process = self._ssh(config, helper, command, input_file=input_file)
                    markers = self._read_markers(process, timeout=2700)
                if process.returncode != 0 or "SG_INSTALL_STAGE:DONE" not in markers:
                    if "SG_INSTALL_STAGE:RUN" in markers:
                        raise InstallError(
                            "Установщик на сервере завершился с ошибкой. Исходники остались в "
                            "/opt/sovagrid-src; проверьте состояние SovaGrid перед повторной установкой."
                        )
                    raise InstallError("Передача или проверка пакета на сервере не удалась; SovaGrid не запущен")
                return summary

    def preflight_features(self) -> FeatureState:
        """Read-only check of a managed, healthy existing Hub+Agent host."""
        if self.options.user != "root":
            raise InstallError("Для включения функций укажите SSH-пользователя root")
        with self._session() as (config, helper):
            self._progress("Проверка существующей установки без изменений…")
            process = self._ssh(config, helper, _FEATURE_PREFLIGHT_COMMAND)
            markers = self._read_markers(process, timeout=180)
            if process.returncode != 0 or _FEATURE_PREFLIGHT_OK not in markers:
                raise InstallError("Не удалось подтвердить исправную установку SovaGrid на сервере")
            return FeatureState.from_markers(markers)

    def enable_features(self, selected: InstallFeatures, *, expected_state: FeatureState | None = None) -> None:
        """Recheck state remotely and run only its existing root-owned run.sh."""
        if self.options.user != "root":
            raise InstallError("Для включения функций укажите SSH-пользователя root")
        if not selected.any_enabled():
            raise InstallError("Выберите хотя бы одну функцию")
        if (selected.containers or selected.containers_disable) and (
                expected_state is None or not expected_state.containers_supported or
                expected_state.cas_sha256 is None):
            raise InstallError("Просмотр контейнеров требует проверки новой версии сервера перед изменением")
        expected_cas = expected_state.cas_sha256 if expected_state is not None else None
        if expected_state is not None and expected_cas is None:
            raise InstallError("Проверка состояния сервера неполна; повторите её")
        if expected_cas is not None and not _SHA256.fullmatch(expected_cas):
            raise InstallError("Проверка состояния сервера повреждена; повторите её")
        flags = " ".join(shlex.quote(flag) for flag in selected.flags())
        command = "bash -c " + shlex.quote(_FEATURE_ENABLE_SCRIPT) + " sovagrid " + (expected_cas or "-") + " " + flags
        with self._session() as (config, helper):
            self._progress("Повторная проверка сервера перед изменением…")
            process = self._ssh(config, helper, command)
            markers = self._read_markers(process, timeout=2700)
            if process.returncode != 0 or "SG_INSTALL_STAGE:DONE" not in markers:
                if "SG_INSTALL_STAGE:RUN" in markers:
                    raise InstallError(
                        "run.sh остановился с ошибкой после начала настройки. "
                        "Проверьте здоровье Hub и Agent перед повторной попыткой."
                    )
                raise InstallError("Сервер отклонил включение функций до запуска run.sh")

    def preview_update(self, source: Path, *, expected_sha256: str | None = None) -> UpdatePreview:
        """Check a candidate and the active installation without writing remotely."""
        if self.options.user != "root":
            raise InstallError("Для подготовки обновления укажите SSH-пользователя root")
        with tempfile.TemporaryDirectory(prefix="sovagrid-update-preview-") as private_dir:
            bundle = Path(private_dir) / "bundle.tar.gz"
            self._progress("Проверка выбранного пакета…")
            summary, digest = _snapshot_with_digest(source, bundle, expected_sha256)
        features = self.preflight_features()
        with tempfile.TemporaryDirectory(prefix="sovagrid-update-preflight-") as private_dir:
            script = Path(private_dir) / "remote_update.py"
            script.write_text(REMOTE_SCRIPT, encoding="utf-8")
            command = "python3 - preview"
            with self._session() as (config, helper), script.open("rb") as input_file:
                process = self._ssh(config, helper, command, input_file=input_file)
                markers = self._read_markers(process, timeout=180)
        if process.returncode != 0 or _VERSION_PREFLIGHT_OK not in markers:
            raise InstallError("Не удалось подтвердить версии исходников и состояние всех служб на сервере")
        manifests = [match.group(1) for marker in markers
                     if (match := _CURRENT_MANIFEST_MARKER.fullmatch(marker))]
        commits = {match.group(1): match.group(2) for marker in markers
                   if (match := _CURRENT_COMMIT_MARKER.fullmatch(marker))}
        if len(manifests) != 1 or len(commits) != len(COMPONENTS) or set(commits) != COMPONENTS:
            raise InstallError("Сервер вернул неполные сведения о действующей версии")
        if commits == summary.commits:
            raise InstallError("В пакете те же версии всех пяти компонентов; обновлять нечего")
        return UpdatePreview(summary, digest, features, manifests[0], commits)

    def prepare_update(self, source: Path, *, expected_sha256: str) -> PreparedUpdate:
        """Stage a verified candidate beside the active source; never run it."""
        if self.options.user != "root":
            raise InstallError("Для подготовки обновления укажите SSH-пользователя root")
        if not _SHA256.fullmatch(expected_sha256):
            raise InstallError("Неверный SHA-256 пакета обновления")
        with tempfile.TemporaryDirectory(prefix="sovagrid-update-") as private_dir:
            bundle = Path(private_dir) / "bundle.tar.gz"
            self._progress("Повторная проверка пакета перед передачей…")
            summary, digest = _snapshot_with_digest(source, bundle, expected_sha256)
            command = "bash -c " + shlex.quote(_STAGE_UPDATE_SCRIPT) + " sovagrid " + digest
            with self._session() as (config, helper):
                self._progress("Повторная проверка сервера и передача пакета…")
                with bundle.open("rb") as input_file:
                    process = self._ssh(config, helper, command, input_file=input_file)
                    markers = self._read_markers(process, timeout=900)
            if process.returncode != 0 or "SG_UPDATE_STAGE:DONE" not in markers:
                raise InstallError(
                    "Пакет обновления не подтверждён на сервере. Действующие исходники и службы не менялись."
                )
            return PreparedUpdate(
                summary, digest, f"/opt/sovagrid-candidates/{digest}",
                "SG_UPDATE_STAGE:ALREADY" in markers,
            )

    def apply_update(self, prepared: PreparedUpdate, *, expected_current_manifest: str) -> None:
        """Apply an already staged digest; remote updater owns backup and rollback."""
        self._apply_update(prepared, expected_current_manifest=expected_current_manifest, mode="apply")

    def apply_automatic_update(self, prepared: PreparedUpdate, *, expected_current_manifest: str) -> None:
        """Apply an approved pin only if the remote updater's idle gate passes."""
        self._apply_update(prepared, expected_current_manifest=expected_current_manifest, mode="apply-auto")

    def _apply_update(self, prepared: PreparedUpdate, *, expected_current_manifest: str, mode: str) -> None:
        if mode not in ("apply", "apply-auto"):
            raise ValueError("unsupported update mode")
        if self.options.user != "root":
            raise InstallError("Для обновления укажите SSH-пользователя root")
        digest = prepared.sha256
        if not _SHA256.fullmatch(digest) or not _SHA256.fullmatch(expected_current_manifest) or \
                prepared.remote_path != f"/opt/sovagrid-candidates/{digest}":
            raise InstallError("Подготовленный пакет или проверенная версия сервера имеют неверный формат")
        with tempfile.TemporaryDirectory(prefix="sovagrid-update-apply-") as private_dir:
            script = Path(private_dir) / "remote_update.py"
            script.write_text(REMOTE_SCRIPT, encoding="utf-8")
            command = "python3 - " + mode + " " + digest + " " + expected_current_manifest
            with self._session() as (config, helper), script.open("rb") as input_file:
                self._progress("Повторная проверка сервера перед обновлением…")
                process = self._ssh(config, helper, command, input_file=input_file)
                markers = self._read_markers(process, timeout=3600)
        if process.returncode == 0 and "SG_APPLY_STAGE:DONE" in markers:
            return
        if "SG_APPLY_STAGE:ROLLED_BACK" in markers:
            detail = ""
            if "SG_APPLY_STAGE:LOG_SAVED" in markers:
                detail += " Диагностика сохранена в защищённом каталоге /opt/sovagrid-candidates/failure-logs/ на сервере."
            elif "SG_APPLY_STAGE:LOG_UNAVAILABLE" in markers:
                detail += " Журнал ошибки сохранить не удалось."
            if "SG_APPLY_STAGE:CLEANUP_INCOMPLETE" in markers:
                detail += " Очистка временных файлов требует проверки."
            raise InstallError("Обновление не прошло проверку. Предыдущая версия восстановлена; проверьте панель." + detail)
        if "SG_APPLY_STAGE:ROLLBACK_FAILED" in markers:
            raise InstallError("Обновление не завершено, автоматический откат не прошёл проверку. Резервная копия сохранена на сервере; требуется восстановление.")
        raise InstallError(
            "Нет подтверждения завершения обновления. Соединение могло прерваться; повторная попытка сначала "
            "проверит и восстановит незавершённую операцию."
        )

    def arm_server_timer(self, prepared: PreparedUpdate, *, expected_current_manifest: str) -> str:
        """Allow only this staged digest to update later, without Connect open."""
        if self.options.user != "root":
            raise InstallError("Для серверного автообновления укажите SSH-пользователя root")
        archive = prepared.sha256
        if (not _SHA256.fullmatch(archive) or
                not _SHA256.fullmatch(expected_current_manifest) or
                prepared.remote_path != f"/opt/sovagrid-candidates/{archive}"):
            raise InstallError("Подготовленный пакет или версия сервера имеют неверный формат")
        command = f"{SERVER_TIMER_COMMAND} arm {archive} {expected_current_manifest}"
        with self._session() as (config, helper):
            process = self._ssh(config, helper, command)
            markers = self._read_markers(process, timeout=180)
        if process.returncode == 0 and "SG_AUTO_UPDATE:ARMED" in markers:
            return "armed"
        if process.returncode == 0 and "SG_AUTO_UPDATE:ALREADY_ARMED" in markers:
            return "already_armed"
        raise InstallError("Этот сервер ещё не поддерживает автообновление по таймеру или не подтвердил разрешение. Сначала установите версию сервера с этой функцией.")

    def server_timer_status(self) -> ServerTimerStatus:
        """Read the selected host's root-owned one-candidate policy."""
        if self.options.user != "root":
            raise InstallError("Для состояния автообновления укажите SSH-пользователя root")
        with self._session() as (config, helper):
            process = self._ssh(config, helper, SERVER_TIMER_COMMAND + " status")
            raw = self._read_bounded(process, timeout=45)
        if process.returncode != 0:
            marker = raw.decode("ascii", errors="ignore").strip()
            if marker in _REFUSALS:
                raise InstallError(_REFUSALS[marker])
            raise InstallError("На выбранном сервере нет работающего таймера автообновления. Установите новую версию сервера.")
        try:
            return parse_server_timer_status(raw)
        except ValueError as exc:
            raise InstallError(str(exc)) from exc

    def disarm_server_timer(self) -> None:
        """Remove the one-candidate approval on this exact SSH target."""
        if self.options.user != "root":
            raise InstallError("Для отключения автообновления укажите SSH-пользователя root")
        with self._session() as (config, helper):
            process = self._ssh(config, helper, SERVER_TIMER_COMMAND + " disarm")
            markers = self._read_markers(process, timeout=45)
        if process.returncode != 0 or "SG_AUTO_UPDATE:DISABLED" not in markers:
            raise InstallError("Не удалось подтвердить отключение автообновления на сервере")

    def cancel(self) -> None:
        with self._lock:
            process = self._process
        if process is not None and process.poll() is None:
            process.terminate()
