# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Strict, secret-free view of the per-server one-candidate update timer."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re


_HASH = re.compile(r"[0-9a-f]{64}\Z")
_STATES = frozenset({"armed", "disabled", "deferred_busy", "applied", "expired", "needs_attention"})
SERVER_TIMER_COMMAND = "/usr/bin/python3 -I /opt/sovagrid-src/sovagrid-blueprint/deploy/auto_update.py"


@dataclass(frozen=True)
class ServerTimerStatus:
    archive_sha256: str | None
    expected_current_manifest: str | None
    expires_at: int | None
    last_state: str | None
    updated_at: int | None

    @property
    def armed(self) -> bool:
        return self.archive_sha256 is not None


def parse_server_timer_status(raw: bytes) -> ServerTimerStatus:
    if len(raw) > 4096:
        raise ValueError("Сервер вернул слишком большой ответ автообновления")
    try:
        data = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Сервер вернул неверное состояние автообновления") from exc
    if not isinstance(data, dict) or set(data) != {"policy", "last"}:
        raise ValueError("Сервер вернул неизвестный формат автообновления")
    policy = data["policy"]
    archive = current = expiry = None
    if policy is not None:
        if (not isinstance(policy, dict) or set(policy) != {"format", "archive_sha256",
                "expected_current_manifest", "created_at", "expires_at"} or
                type(policy["format"]) is not int or policy["format"] != 1 or
                type(policy["created_at"]) is not int or type(policy["expires_at"]) is not int or
                not 0 < policy["created_at"] < policy["expires_at"] <= min(
                    4102444800, policy["created_at"] + 30 * 86400) or
                not isinstance(policy["archive_sha256"], str) or
                not _HASH.fullmatch(policy["archive_sha256"]) or
                not isinstance(policy["expected_current_manifest"], str) or
                not _HASH.fullmatch(policy["expected_current_manifest"])):
            raise ValueError("Сервер вернул неверную политику автообновления")
        archive, current, expiry = (policy["archive_sha256"],
                                    policy["expected_current_manifest"], policy["expires_at"])
    last = data["last"]
    last_state = updated = None
    if last is not None:
        if (not isinstance(last, dict) or set(last) != {"format", "state", "updated_at",
                "archive_sha256", "expected_current_manifest", "detail"} or
                type(last["format"]) is not int or last["format"] != 1 or
                not isinstance(last["state"], str) or last["state"] not in _STATES or
                type(last["updated_at"]) is not int or not 0 < last["updated_at"] <= 4102444800 or
                not isinstance(last["detail"], str) or len(last["detail"]) > 160 or
                any(value is not None and (not isinstance(value, str) or not _HASH.fullmatch(value))
                    for value in (last["archive_sha256"], last["expected_current_manifest"]))):
            raise ValueError("Сервер вернул неверный результат автообновления")
        last_state, updated = last["state"], last["updated_at"]
    return ServerTimerStatus(archive, current, expiry, last_state, updated)
