# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Strict, secret-free status contract for Agent-only → local Hub promotion."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import uuid


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_REASON = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
PHASES = frozenset({
    "eligible", "prepared", "source_staged", "hub_installed", "activated",
    "external_changed", "unknown",
})
_KEYS = frozenset({
    "protocol", "phase", "external_agent_preserved", "baseline_sha256",
    "pinned_manifest_sha256", "source_manifest_sha256", "local_server_id", "reason_code",
})


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Повторяющееся поле ответа сервера")
        value[key] = item
    return value


@dataclass(frozen=True)
class PromotionState:
    phase: str
    external_agent_preserved: bool | None
    baseline_sha256: str | None
    pinned_manifest_sha256: str | None
    source_manifest_sha256: str | None
    local_server_id: str | None
    reason_code: str | None

    @property
    def can_continue(self) -> bool:
        return self.phase not in {"external_changed", "unknown"} and self.external_agent_preserved is True


def parse_promotion_state(raw: bytes) -> PromotionState:
    """Reject extra fields, secrets, loose types and inconsistent phases."""
    if len(raw) > 4096:
        raise ValueError("Сервер прислал слишком большой ответ о локальном Hub")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Сервер прислал неверный ответ о локальном Hub") from exc
    if not isinstance(value, dict) or set(value) != _KEYS or type(value["protocol"]) is not int or value["protocol"] != 1:
        raise ValueError("Сервер прислал неподдерживаемый ответ о локальном Hub")
    phase = value["phase"]
    if not isinstance(phase, str) or phase not in PHASES:
        raise ValueError("Состояние локального Hub не распознано")
    preserved = value["external_agent_preserved"]
    if preserved is not None and type(preserved) is not bool:
        raise ValueError("Ответ о внешнем Agent имеет неверный тип")
    for name in ("baseline_sha256", "pinned_manifest_sha256", "source_manifest_sha256"):
        item = value[name]
        if item is not None and (not isinstance(item, str) or _SHA.fullmatch(item) is None):
            raise ValueError("Контрольная сумма состояния локального Hub неверна")
    server_id = value["local_server_id"]
    if server_id is not None:
        if not isinstance(server_id, str):
            raise ValueError("ID локального Agent неверен")
        try:
            if str(uuid.UUID(server_id)) != server_id:
                raise ValueError
        except ValueError as exc:
            raise ValueError("ID локального Agent неверен") from exc
    reason = value["reason_code"]
    if reason is not None and (not isinstance(reason, str) or _REASON.fullmatch(reason) is None):
        raise ValueError("Код состояния локального Hub неверен")
    state = PromotionState(phase, preserved, value["baseline_sha256"],
                           value["pinned_manifest_sha256"], value["source_manifest_sha256"],
                           server_id, reason)
    if phase == "eligible":
        if not state.can_continue or any((state.baseline_sha256, state.pinned_manifest_sha256,
                                          state.source_manifest_sha256, state.local_server_id,
                                          state.reason_code)):
            raise ValueError("Неподготовленный сервер прислал противоречивое состояние")
    elif phase in {"prepared", "source_staged", "hub_installed", "activated"}:
        if not state.can_continue or state.baseline_sha256 is None or state.pinned_manifest_sha256 is None:
            raise ValueError("Подготовленное состояние локального Hub неполно")
        if state.reason_code is not None:
            raise ValueError("Подготовленный Hub прислал противоречивую причину отказа")
        if phase == "prepared" and state.source_manifest_sha256 is not None:
            raise ValueError("Исходники Hub появились до этапа передачи")
        if phase in {"source_staged", "hub_installed", "activated"} and \
                state.source_manifest_sha256 != state.pinned_manifest_sha256:
            raise ValueError("Исходники Hub не совпали с разрешённым пакетом")
        if phase == "activated" and state.local_server_id is None:
            raise ValueError("Локальный Agent не подтверждён")
        if phase != "activated" and state.local_server_id is not None:
            raise ValueError("Локальный Agent объявлен до активации")
    return state
