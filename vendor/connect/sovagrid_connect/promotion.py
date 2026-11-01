# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Pinned SSH promotion from an external Agent to an additional local Hub.

The original Agent, enrollment and reverse SSH tunnel remain owned by their
existing installer. Every continuation inspects the exact promotion journal;
generic ``conflict`` and partially installed Hubs are never treated as safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import tempfile
from typing import Callable
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .core import ConnectionOptions
from .installer import (BundleSummary, InstallError, ServerInstaller, _snapshot_with_digest)
from .promotion_protocol import PromotionState, parse_promotion_state
from .promotion_remote import ACTION_SCRIPT, STAGE_SCRIPT


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HELPER_PATH = "sovagrid-blueprint/deploy/promote_agent_only.py"
_MANIFEST_PATH = "sovagrid-bundle.json"
_LOCKED_PREPARE = r'''set -Eeuo pipefail
umask 077
[[ $(id -u) == 0 ]] || exit 1
lock=/run/sovagrid-promotion.lock
[[ ! -L $lock ]] || exit 1
exec 9>>"$lock"
[[ -f $lock && $(stat -c '%u:%a' "$lock") == 0:600 ]] || exit 1
flock -n 9 || exit 1
python3 - prepare --manifest-sha256 "$1"
'''


@dataclass(frozen=True)
class PromotionPreview:
    options: ConnectionOptions
    bundle: BundleSummary
    archive_sha256: str
    manifest_sha256: str
    state: PromotionState


def _candidate_parts(bundle: Path) -> tuple[str, bytes]:
    try:
        with tarfile.open(bundle, "r:gz") as archive:
            manifest_member = archive.getmember(_MANIFEST_PATH)
            helper_member = archive.getmember(_HELPER_PATH)
            if not manifest_member.isfile() or not helper_member.isfile() or helper_member.size > 256 * 1024:
                raise InstallError("В пакете нет безопасного помощника локального Hub")
            manifest_stream = archive.extractfile(manifest_member)
            helper_stream = archive.extractfile(helper_member)
            if manifest_stream is None or helper_stream is None:
                raise InstallError("Не удалось прочитать помощник локального Hub")
            manifest_sha = hashlib.sha256(manifest_stream.read()).hexdigest()
            helper = helper_stream.read()
    except (KeyError, tarfile.TarError, OSError) as exc:
        raise InstallError("В пакете нет помощника локального Hub") from exc
    if not helper.startswith(b"#!/usr/bin/env python3\n"):
        raise InstallError("Помощник локального Hub имеет неверный формат")
    return manifest_sha, helper


def _check_state(state: PromotionState, manifest_sha: str) -> None:
    if state.phase == "external_changed":
        raise InstallError("Внешний Agent или SSH-туннель изменился. Мастер остановлен без изменений")
    if state.phase == "unknown" or not state.can_continue:
        raise InstallError("Состояние локального Hub неоднозначно. Автоматическое продолжение остановлено")
    if state.pinned_manifest_sha256 is not None and state.pinned_manifest_sha256 != manifest_sha:
        raise InstallError("На сервере уже закреплён другой пакет локального Hub")
    if state.source_manifest_sha256 is not None and state.source_manifest_sha256 != manifest_sha:
        raise InstallError("Исходники локального Hub не совпали с выбранным пакетом")


class PromotionController:
    """One reviewed bundle and one confirmed root SSH route per attempt."""

    def __init__(self, options: ConnectionOptions, *, approved_archive_sha256: str,
                 popen: Callable[..., subprocess.Popen] = subprocess.Popen,
                 progress: Callable[[str], None] | None = None) -> None:
        if not isinstance(approved_archive_sha256, str) or _SHA.fullmatch(approved_archive_sha256) is None:
            raise InstallError("Для локального Hub нужен опубликованный проверенный пакет")
        self.manager = ServerInstaller(options, popen=popen, progress=progress)
        self.options = self.manager.options
        self.approved_archive_sha256 = approved_archive_sha256
        self.progress = progress or (lambda _message: None)

    @property
    def _privileged(self) -> str:
        return "" if self.options.user == "root" else "sudo -n -- "

    def _verify_root_access(self) -> None:
        """Read-only proof of existing root or passwordless sudo on this SSH host."""
        returncode, raw = self._execute(self._privileged + "id -u", timeout=45)
        if returncode != 0 or raw.strip() != b"0":
            raise InstallError("Нужен SSH-вход root или действующее sudo без запроса пароля")

    def _execute(self, command: str, *, data: bytes | None = None, source: Path | None = None,
                 timeout: float = 45, limit: int = 4096) -> tuple[int, bytes]:
        if type(limit) is not int or not 1 <= limit <= 98304:
            raise InstallError("Недопустимый размер ответа сервера")
        # Commands already carry the reviewed root/sudo route selected above.
        with tempfile.TemporaryDirectory(prefix="sovagrid-promotion-command-") as private_dir:
            input_path = source
            if data is not None:
                input_path = Path(private_dir) / "helper.py"
                descriptor = os.open(input_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(data)
            with self.manager._session() as (config, helper):
                if input_path is None:
                    process = self.manager._ssh(config, helper, command, privileged=False)
                    raw = self.manager._read_bounded(process, timeout=timeout, limit=limit)
                else:
                    with input_path.open("rb") as input_file:
                        process = self.manager._ssh(config, helper, command, input_file=input_file,
                                                    privileged=False)
                        raw = self.manager._read_bounded(process, timeout=timeout, limit=limit)
        return process.returncode, raw

    def _inspect(self, helper: bytes, manifest_sha: str) -> PromotionState:
        returncode, raw = self._execute(self._privileged + "python3 - inspect", data=helper, timeout=90)
        if returncode != 0:
            raise InstallError("Сервер не поддерживает безопасную проверку локального Hub")
        try:
            state = parse_promotion_state(raw)
        except ValueError as exc:
            raise InstallError(str(exc)) from exc
        _check_state(state, manifest_sha)
        return state

    def preview(self, source: Path) -> PromotionPreview:
        """Only read the SSH host and verify the exact release bundle locally."""
        with tempfile.TemporaryDirectory(prefix="sovagrid-promotion-preview-") as private_dir:
            snapshot = Path(private_dir) / "bundle.tar.gz"
            self.progress("Проверка закреплённого серверного пакета…")
            summary, digest = _snapshot_with_digest(source, snapshot, self.approved_archive_sha256)
            manifest_sha, helper = _candidate_parts(snapshot)
            self.progress("Проверка существующих root/sudo прав без изменений…")
            self._verify_root_access()
            self.progress("Проверка внешнего Agent и локального Hub без изменений…")
            state = self._inspect(helper, manifest_sha)
        return PromotionPreview(self.options, summary, digest, manifest_sha, state)

    def _expect_phase(self, helper: bytes, manifest_sha: str, expected: str) -> PromotionState:
        state = self._inspect(helper, manifest_sha)
        if state.phase != expected:
            raise InstallError("Состояние сервера изменилось. Повторно проверьте план локального Hub")
        return state

    def _marker(self, command: str, expected: bytes, *, data: bytes | None = None,
                source: Path | None = None, timeout: float) -> None:
        returncode, raw = self._execute(command, data=data, source=source, timeout=timeout)
        if returncode != 0 or raw.strip() != expected:
            raise InstallError("Операция локального Hub не подтверждена. Повторно проверьте сервер перед продолжением")

    def apply(self, source: Path, preview: PromotionPreview) -> PromotionState:
        """Resume only the exact reviewed host, bundle, baseline and phase."""
        if preview.options != self.options or preview.archive_sha256 != self.approved_archive_sha256:
            raise InstallError("SSH-сервер или проверенный пакет изменился. Откройте проверку заново")
        with tempfile.TemporaryDirectory(prefix="sovagrid-promotion-apply-") as private_dir:
            snapshot = Path(private_dir) / "bundle.tar.gz"
            self.progress("Повторная проверка пакета перед передачей…")
            summary, digest = _snapshot_with_digest(source, snapshot, preview.archive_sha256)
            manifest_sha, helper = _candidate_parts(snapshot)
            if summary.commits != preview.bundle.commits or manifest_sha != preview.manifest_sha256:
                raise InstallError("Пакет изменился после проверки. Откройте мастер заново")
            self._verify_root_access()
            state = self._inspect(helper, manifest_sha)
            if state != preview.state:
                raise InstallError("Состояние сервера изменилось. Повторно проверьте план локального Hub")
            if state.phase == "eligible":
                self.progress("Сохранение защищённого снимка внешнего Agent и туннеля…")
                command = self._privileged + "bash -c " + shlex.quote(_LOCKED_PREPARE) + " sovagrid " + manifest_sha
                returncode, _raw = self._execute(command, data=helper, timeout=120)
                if returncode != 0:
                    raise InstallError("Сервер не подтвердил подготовку. Повторно проверьте состояние")
                state = self._expect_phase(helper, manifest_sha, "prepared")
            if state.phase == "prepared":
                self.progress("Передача и повторная проверка пакета на сервере…")
                command = self._privileged + "python3 -c " + shlex.quote(STAGE_SCRIPT) + " " + digest + " " + manifest_sha
                self._marker(command, b"SG_PROMOTION_STAGE:DONE", source=snapshot, timeout=900)
                state = self._expect_phase(helper, manifest_sha, "source_staged")
            if state.phase == "source_staged":
                self.progress("Запуск собственного Hub без остановки внешнего Agent…")
                command = self._privileged + "python3 -c " + shlex.quote(ACTION_SCRIPT) + " hub " + manifest_sha
                self._marker(command, b"SG_PROMOTION_HUB:DONE", timeout=3600)
                state = self._expect_phase(helper, manifest_sha, "hub_installed")
            if state.phase == "hub_installed":
                self.progress("Подключение отдельного локального Agent к новому Hub…")
                command = self._privileged + "python3 -c " + shlex.quote(ACTION_SCRIPT) + " activate " + manifest_sha
                self._marker(command, b"SG_PROMOTION_AGENT:DONE", timeout=600)
                state = self._expect_phase(helper, manifest_sha, "activated")
            if state.phase != "activated" or state.local_server_id is None:
                raise InstallError("Локальный Agent не подтвердил активацию")
            return state

    def cancel(self) -> None:
        self.manager.cancel()


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Повторяющееся поле Hub")
        value[key] = item
    return value


def verify_promoted_panel(tunnel, local_server_id: str) -> None:
    """Prove /healthz via Tunnel.start, then a fresh local Agent via Hub API.

    The temporary admin grant and bearer exist only in memory. The Hub's
    ``online`` value uses its own receipt clock, so the client's time zone or
    a bounded host clock offset does not change the decision.
    """
    if not tunnel.alive:
        raise InstallError("SSH-панель локального Hub не отвечает")
    base = tunnel.url.rstrip("/")
    parsed = urlsplit(base)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None or
            parsed.username is not None or parsed.password is not None or
            parsed.path or parsed.query or parsed.fragment):
        raise InstallError("Нужен подтверждённый локальный SSH-проброс к Hub")
    try:
        import uuid
        if str(uuid.UUID(local_server_id)) != local_server_id:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise InstallError("ID локального Agent не подтверждён") from exc
    opener = build_opener(ProxyHandler({}), _NoRedirect())

    def request(method: str, path: str, *, body: dict | None = None, bearer: str | None = None,
                limit: int = 256 * 1024) -> tuple[dict, int | None]:
        data = json.dumps(body, separators=(",", ":")).encode("ascii") if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if bearer is not None:
            headers["Authorization"] = "Bearer " + bearer
        message = Request(base + path, data=data, method=method, headers=headers)
        with opener.open(message, timeout=10) as response:
            if response.status != 200:
                raise InstallError("Hub не подтвердил состояние локального Agent")
            response_date = response.headers.get("Date")
            raw = response.read(limit + 1)
        if len(raw) > limit:
            raise InstallError("Ответ Hub о локальном Agent слишком велик")
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(value, dict):
            raise InstallError("Hub прислал неверное состояние локального Agent")
        server_time = None
        if method == "GET" and response_date is not None:
            parsed_time = parsedate_to_datetime(response_date)
            if parsed_time.utcoffset() is None:
                raise InstallError("Hub не прислал время UTC для проверки свежести метрики")
            server_time = int(parsed_time.timestamp())
        return value, server_time

    try:
        grant = tunnel.request_ssh_grant()
        login, _ = request("POST", "/api/v1/session/ssh-grant", body={"grant": grant.value}, limit=4096)
        bearer = login.get("token")
        if not isinstance(bearer, str) or re.fullmatch(r"[A-Za-z0-9_-]{20,256}", bearer) is None:
            raise InstallError("Hub не подтвердил временный вход администратора")
        try:
            listing, hub_time = request("GET", "/api/v1/servers", bearer=bearer)
            servers = listing.get("servers")
            if not isinstance(servers, list) or not any(
                isinstance(item, dict) and item.get("id") == local_server_id and
                item.get("online") is True and type(item.get("last_seen")) is int and
                hub_time is not None and 0 <= hub_time - item["last_seen"] <= 180
                for item in servers
            ):
                raise InstallError("Локальный Agent ещё не передал свежие метрики в собственный Hub")
        finally:
            try:
                request("DELETE", "/api/v1/session", bearer=bearer, limit=4096)
            except (OSError, ValueError, HTTPError, InstallError):
                pass
    except InstallError:
        raise
    except (OSError, ValueError, TypeError, HTTPError) as exc:
        raise InstallError("Не удалось подтвердить Hub и свежие метрики через SSH") from exc
