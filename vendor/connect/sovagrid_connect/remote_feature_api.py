# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Bounded admin-only management policy API on the verified Hub tunnel."""
from __future__ import annotations

import re

from .enrollment_api import EnrollmentAPI, EnrollmentAPIError, _uuid

SHA = re.compile(r"[0-9a-f]{64}\Z")
FIELDS = {"server_id", "enrollment_id", "agent_token_sha256", "enabled", "revision"}
PERMISSION_FIELDS = (FIELDS - {"enabled"}) | {"commands_enabled", "terminal_access"}


def management(value, server_id):
    try:
        if not isinstance(value, dict) or set(value) != FIELDS:
            raise ValueError
        _uuid(value["server_id"]); _uuid(value["enrollment_id"])
        if (value["server_id"] != server_id or not isinstance(value["agent_token_sha256"], str)
                or SHA.fullmatch(value["agent_token_sha256"]) is None
                or type(value["enabled"]) is not bool or type(value["revision"]) is not int
                or not 0 <= value["revision"] <= 2**63 - 1):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise EnrollmentAPIError("Hub вернул неподтверждённые разрешения Agent.") from None
    return dict(value)


def permissions(value, server_id):
    if not isinstance(value, dict) or set(value) != PERMISSION_FIELDS:
        raise EnrollmentAPIError("Hub вернул неподтверждённые разрешения Agent.")
    common = {key: value[key] for key in FIELDS - {"enabled"}}
    management({**common, "enabled": value["commands_enabled"]}, server_id)
    terminal = value["terminal_access"]
    if (not isinstance(terminal, dict) or set(terminal) != {"enabled", "mode"}
            or type(terminal["enabled"]) is not bool or terminal["mode"] not in ("legacy", "explicit")
            or terminal["mode"] == "legacy" and terminal["enabled"] != value["commands_enabled"]):
        raise EnrollmentAPIError("Hub вернул неподтверждённый допуск терминала.")
    return {**value, "terminal_access": dict(terminal)}


class RemoteFeatureAPI(EnrollmentAPI):
    def _response_limit(self, method, path):
        # Only the fixed account-free picker route may exceed the usual 4 KiB.
        return 256 * 1024 if method == "GET" and path == "/api/v1/agent-management" else super()._response_limit(method, path)

    def list_servers(self):
        reply = self._operation("GET", "/api/v1/agent-management")
        if (not isinstance(reply, dict) or set(reply) != {"servers", "truncated"}
                or type(reply["truncated"]) is not bool or not isinstance(reply["servers"], list)
                or len(reply["servers"]) > 256):
            raise EnrollmentAPIError("Hub вернул неподтверждённый список Agent.")
        if reply["truncated"]:
            raise EnrollmentAPIError("В Hub больше 256 удалённых Agent. Этот мастер поддерживает до 256 серверов.")
        rows, seen = [], set()
        try:
            for row in reply["servers"]:
                if not isinstance(row, dict) or set(row) != {"id", "name"}:
                    raise ValueError
                _uuid(row["id"])
                if (row["id"] in seen or not isinstance(row["name"], str)
                        or not 1 <= len(row["name"]) <= 80 or not row["name"].isprintable()
                        or row["name"] != row["name"].strip()):
                    raise ValueError
                seen.add(row["id"]); rows.append(dict(row))
        except (ValueError, KeyError, TypeError):
            raise EnrollmentAPIError("Hub вернул неподтверждённый список Agent.") from None
        return rows

    def management(self, server_id):
        _uuid(server_id)
        return management(self._operation("GET", "/api/v1/servers/" + server_id + "/agent-management"), server_id)

    def set_management(self, expected, enabled):
        if not isinstance(expected, dict):
            raise ValueError("Сначала проверьте текущие разрешения Agent.")
        clean = management(expected, expected.get("server_id"))
        if type(enabled) is not bool:
            raise ValueError("Выберите разрешение удалённого управления.")
        body = {key: clean[key] for key in ("enrollment_id", "agent_token_sha256")}
        body.update(expected_revision=clean["revision"], enabled=enabled)
        reply = self._operation("POST", "/api/v1/servers/" + clean["server_id"] + "/agent-management", body)
        if not isinstance(reply, dict) or set(reply) != FIELDS | {"changed"} or type(reply["changed"]) is not bool:
            raise EnrollmentAPIError("Hub не подтвердил изменение разрешений Agent.")
        result = management({key: reply[key] for key in FIELDS}, clean["server_id"])
        if (any(result[key] != clean[key] for key in ("server_id", "enrollment_id", "agent_token_sha256"))
                or result["enabled"] != enabled
                or result["revision"] != clean["revision"] + int(reply["changed"])
                or reply["changed"] != (clean["enabled"] != enabled)):
            raise EnrollmentAPIError("Hub подтвердил другую версию разрешений Agent.")
        return result

    def permissions(self, server_id):
        _uuid(server_id)
        path = "/api/v1/servers/" + server_id + "/agent-management/permissions"
        return permissions(self._operation("GET", path), server_id)

    def set_terminal_permission(self, expected, enabled):
        if not isinstance(expected, dict) or type(enabled) is not bool:
            raise ValueError("Сначала проверьте текущий допуск терминала.")
        clean = permissions(expected, expected.get("server_id"))
        pinned = ("enrollment_id", "agent_token_sha256", "commands_enabled")
        body = {key: clean[key] for key in pinned}
        body.update(expected_revision=clean["revision"], terminal_enabled=enabled)
        path = "/api/v1/servers/" + clean["server_id"] + "/agent-management/permissions"
        reply = self._operation("POST", path, body)
        if (not isinstance(reply, dict) or set(reply) != PERMISSION_FIELDS | {"changed"}
                or type(reply["changed"]) is not bool):
            raise EnrollmentAPIError("Hub не подтвердил изменение допуска терминала.")
        result = permissions({key: reply[key] for key in PERMISSION_FIELDS}, clean["server_id"])
        terminal = {"enabled": enabled, "mode": "explicit"}
        changed = clean["terminal_access"] != terminal
        if (any(result[key] != clean[key] for key in pinned)
                or result["terminal_access"] != terminal
                or reply["changed"] != changed or result["revision"] != clean["revision"] + int(changed)):
            raise EnrollmentAPIError("Hub подтвердил другую версию допуска терминала.")
        return result
