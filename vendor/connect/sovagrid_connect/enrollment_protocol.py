# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Strict public-only protocol for the fixed remote Agent installer helper."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import ssl
import struct
import uuid

MAX_RPC = 32768
CAS_FIELDS = {"source_manifest_sha256", "features_sha256", "policy_sha256", "state_sha256"}
PHASES = ("prepared", "transport_ready", "registered", "active")
FEATURE_ACTIONS = frozenset(("target-features-status", "target-features-preview", "target-features-apply"))
ACTIONS = frozenset(("target-preview", "target-prepare", "target-transport", "target-registered",
    "target-activate", "target-status", "target-remove", "hub-preview", "hub-authorize", "hub-status", "hub-revoke")) | FEATURE_ACTIONS
ERROR_MESSAGES = {
    "INVALID_REQUEST": "Помощник отклонил параметры установки.",
    "ROOT_REQUIRED": "Нужен SSH-вход root или пользователь с доступом sudo без пароля.",
    "UNSUPPORTED_PLATFORM": "Нужен Ubuntu 22.04, 24.04 или 26.04 с Python 3.10 или новее.",
    "UNSUPPORTED_SYSTEMD": "На сервере недоступны systemd и защищённая передача ключа службе.",
    "SOURCE_UNTRUSTED": "Не удалось подтвердить происхождение установщика. Обновите Hub проверенным пакетом.",
    "SOURCE_CHANGED": "Исходники изменились. Повторите проверку установки.",
    "STALE_PREVIEW": "Настройки сервера изменились. Откройте проверку заново.",
    "OWNERSHIP_CONFLICT": "Найдены файлы или пользователи, которыми эта установка не управляет.",
    "EXISTING_AGENT": "На сервере уже есть Agent. Автоматическая первая установка остановлена.",
    "STATE_CONFLICT": "Состояние установки не совпало. Сначала восстановите её состояние.",
    "KEY_CONFLICT": "Ключи установки отсутствуют или изменены. Автоматическая замена остановлена.",
    "PORT_BUSY": "Выбранный локальный порт на сервере занят.",
    "SSH_POLICY_CONFLICT": "Политика SSH не позволяет создать ограниченный служебный доступ.",
    "SSH_RELOAD_FAILED": "Не удалось безопасно применить настройки служебного SSH-доступа.",
    "SSH_ENDPOINT_UNREACHABLE": "Agent не может подключиться к указанному SSH-адресу Hub.",
    "TLS_VERIFY_FAILED": "Agent не подтвердил сертификат Hub. Проверьте доверенный сертификат и имя.",
    "TLS_UNAVAILABLE": "SSH работает, но защищённый API Hub пока не отвечает.",
    "SERVICE_FAILED": "Служба установки не прошла проверку. Проверьте состояние перед повтором.",
    "ACTIVE_ENROLLMENT": "Agent уже подключился. Автоматическое удаление остановлено.",
    "AGENT_UPDATE_REQUIRED": "Установленный Agent отличается от выбранного пакета. Сначала требуется отдельное обновление Agent.",
    "CLEANUP_REQUIRED": "Очистка завершена не полностью. Сохраните установку для повторной проверки.",
    "INTERNAL_ERROR": "Помощник не завершил действие. Проверьте состояние перед повтором.",
}


class ProtocolError(ValueError):
    def __init__(self):
        super().__init__("Сервер вернул неподдерживаемый или некорректный ответ установщика.")


class HelperError(RuntimeError):
    def __init__(self, code):
        if code not in ERROR_MESSAGES:
            raise ProtocolError()
        self.code = code
        super().__init__(ERROR_MESSAGES[code])


def _require(condition):
    if not condition:
        raise ProtocolError()


def exact(value, fields):
    _require(isinstance(value, dict) and set(value) == set(fields))
    return value


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def canonical_uuid(value):
    try:
        _require(isinstance(value, str) and str(uuid.UUID(value)) == value)
    except (ValueError, AttributeError):
        raise ProtocolError() from None
    return value


def _sha(value):
    _require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None)
    return value


def _text(value, maximum):
    _require(isinstance(value, str) and 1 <= len(value) <= maximum and value.isprintable())
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ProtocolError() from None
    return value


def validate_cas(value):
    exact(value, CAS_FIELDS)
    return {key: _sha(value[key]) for key in sorted(CAS_FIELDS)}


def public_key_fingerprint(value):
    _require(isinstance(value, str) and len(value) <= 128 and value.count(" ") == 1)
    kind, blob = value.split(" ")
    _require(kind == "ssh-ed25519")
    try:
        raw = base64.b64decode(blob, validate=True)
    except (ValueError, UnicodeError):
        raise ProtocolError() from None
    prefix = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)
    _require(len(raw) == len(prefix) + 32 and raw.startswith(prefix)
             and base64.b64encode(raw).decode("ascii") == blob)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")


def _fingerprint(value):
    _require(isinstance(value, str) and re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", value) is not None)
    try:
        raw = base64.b64decode(value[7:] + "=", validate=True)
    except ValueError:
        raise ProtocolError() from None
    _require(len(raw) == 32 and base64.b64encode(raw).decode("ascii").rstrip("=") == value[7:])
    return value


def validate_hub_trust(value):
    exact(value, {"hub_host_key", "hub_ca_pem"})
    public_key_fingerprint(value["hub_host_key"])
    ca = value["hub_ca_pem"]
    _require(isinstance(ca, str))
    try:
        _require(1 <= len(ca.encode("ascii")) <= 16384)
        # A public CA field must never carry a PEM private key or other text.
        certificate = r"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----"
        _require(re.fullmatch(r"\s*(?:" + certificate + r"\s*)+", ca) is not None)
        ssl.create_default_context(cadata=ca)
    except (ValueError, UnicodeError, ssl.SSLError):
        raise ProtocolError() from None
    return dict(value)


def validate_target(value, *, allow_partial=False):
    fields = {"request_id", "enrollment_id", "server_id", "phase", "agent_token_sha256",
              "ssh_public_key", "ssh_key_fingerprint", "local_port"}
    exact(value, fields)
    for key in ("request_id", "enrollment_id", "server_id"):
        canonical_uuid(value[key])
    _require(value["phase"] in PHASES)
    partial = allow_partial and value["phase"] == "prepared"
    if value["agent_token_sha256"] is None:
        _require(partial)
    else:
        _sha(value["agent_token_sha256"])
    if value["ssh_public_key"] is None or value["ssh_key_fingerprint"] is None:
        _require(partial and value["ssh_public_key"] is None and value["ssh_key_fingerprint"] is None)
    else:
        _require(public_key_fingerprint(value["ssh_public_key"]) == value["ssh_key_fingerprint"])
    _require(integer(value["local_port"], 1024, 65535)
             or value["local_port"] is None and value["phase"] == "prepared")
    return dict(value)


def validate_registration(value, *, identity=None, states=("pending", "active", "cancelled")):
    exact(value, {"id", "server_id", "name", "state", "revision", "created_at", "last_seen"})
    canonical_uuid(value["id"]); canonical_uuid(value["server_id"])
    _text(value["name"], 80)
    _require(value["name"] == value["name"].strip() and value["state"] in states)
    _require(type(value["revision"]) is int and value["revision"] == (2 if value["state"] == "cancelled" else 1))
    _require(integer(value["created_at"], 1, 253402300799)
             and (value["last_seen"] is None or integer(value["last_seen"], 1, 253402300799)))
    _require((value["state"] == "active") == (value["last_seen"] is not None))
    if identity is not None:
        _require(value["id"] == identity["enrollment_id"] and value["server_id"] == identity["server_id"])
    return dict(value)


def validate_stage_descriptor(value):
    exact(value, {"remote_dir", "sha256", "source_manifest_sha256", "helper_sha256", "stage_id"})
    identifier = value["stage_id"]
    _require(isinstance(identifier, str) and re.fullmatch(r"[0-9a-f]{32}", identifier) is not None)
    _require(value["remote_dir"] == "/var/tmp/sovagrid-agent-enroll." + identifier)
    for key in ("sha256", "source_manifest_sha256", "helper_sha256"):
        _sha(value[key])
    return dict(value)


def hub_username(server_id):
    return "sgt_" + base64.b32encode(uuid.UUID(canonical_uuid(server_id)).bytes).decode("ascii").lower().rstrip("=")


def validate_request(action, value):
    _require(isinstance(action, str) and action in ACTIONS)
    if action in FEATURE_ACTIONS:
        fields = {"protocol", "server_id"}
        if action != "target-features-status":
            fields.add("features")
        if action == "target-features-apply":
            fields |= {"expected", "enrollment_id", "agent_token_sha256"}
        exact(value, fields)
        _require(type(value["protocol"]) is int and value["protocol"] == 1)
        canonical_uuid(value["server_id"])
        result = dict(value)
        if "features" in value:
            result["features"] = validate_features(value["features"])
        if "expected" in value:
            result["expected"] = validate_cas(value["expected"])
            canonical_uuid(value["enrollment_id"]); _sha(value["agent_token_sha256"])
        return result
    fields = {"protocol"}
    if action.startswith("target-"):
        fields.add("request_id")
    if action in ("hub-status", "hub-authorize", "hub-revoke") or action.startswith("target-") and action not in ("target-preview", "target-prepare", "target-status"):
        fields |= {"enrollment_id", "server_id"}
    if action not in ("target-preview", "target-status", "hub-preview", "hub-status"):
        fields.add("expected")
    extras = {"target-transport": {"hub_host", "hub_port", "local_port", "hub_host_key", "hub_ca_pem"},
              "target-registered": {"registration"}, "target-activate": {"registration"},
              "target-remove": {"registration"}, "hub-authorize": {"ssh_public_key", "ssh_key_fingerprint"},
              "hub-revoke": {"ssh_key_fingerprint"}}
    exact(value, fields | extras.get(action, set()))
    _require(type(value["protocol"]) is int and value["protocol"] == 1)
    result = dict(value)
    for key in ("request_id", "enrollment_id", "server_id"):
        if key in value:
            canonical_uuid(value[key])
    if "expected" in value:
        result["expected"] = validate_cas(value["expected"])
    if action == "target-transport":
        try:
            _require(isinstance(value["hub_host"], str) and "%" not in value["hub_host"])
            address = ipaddress.ip_address(value["hub_host"])
        except ValueError:
            raise ProtocolError() from None
        effective = getattr(address, "ipv4_mapped", None) or address
        _require(not (effective.is_loopback or effective.is_unspecified or effective.is_multicast))
        _require(integer(value["hub_port"], 1, 65535) and integer(value["local_port"], 1024, 65535))
        validate_hub_trust({key: value[key] for key in ("hub_host_key", "hub_ca_pem")})
    if "ssh_public_key" in value:
        _require(public_key_fingerprint(value["ssh_public_key"]) == value["ssh_key_fingerprint"])
    elif "ssh_key_fingerprint" in value:
        _fingerprint(value["ssh_key_fingerprint"])
    if "registration" in value:
        if value["registration"] is None:
            _require(action == "target-remove")
        else:
            states = ("active",) if action == "target-activate" else ("cancelled",) if action == "target-remove" else ("pending", "active")
            result["registration"] = validate_registration(value["registration"], identity=value, states=states)
    try:
        _require(len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) <= MAX_RPC)
    except (ValueError, UnicodeError, RecursionError):
        raise ProtocolError() from None
    return result


def validate_reply(action, value, *, request=None):
    _require(isinstance(action, str) and action in ACTIONS and isinstance(value, dict) and type(value.get("protocol")) is int and value["protocol"] == 1
             and type(value.get("ok")) is bool)
    if value["ok"] is False:
        exact(value, {"protocol", "ok", "error"})
        _require(isinstance(value["error"], str) and value["error"] in ERROR_MESSAGES)
        raise HelperError(value["error"])
    if action in FEATURE_ACTIONS:
        return validate_feature_reply(action, value, request=request)
    fields = {"protocol", "ok"}
    if action in ("target-remove", "hub-revoke"):
        flag = "removed" if action == "target-remove" else "revoked"
        exact(value, fields | {flag, "cleanup_required"})
        _require(value[flag] is True and value["cleanup_required"] is False)
        return dict(value)
    fields.add("cas")
    if action == "hub-preview":
        fields |= {"helper_v1", "hub_host_key", "hub_ca_pem"}
        exact(value, fields); _require(value["helper_v1"] is True)
        validate_hub_trust({key: value[key] for key in ("hub_host_key", "hub_ca_pem")})
    elif action in ("hub-authorize", "hub-status"):
        fields |= {"enrollment_id", "server_id", "username", "ssh_key_fingerprint", "authorized"}
        exact(value, fields)
        canonical_uuid(value["enrollment_id"]); canonical_uuid(value["server_id"])
        _require(type(value["authorized"]) is bool and value["username"] == hub_username(value["server_id"]))
        if value["authorized"]:
            _fingerprint(value["ssh_key_fingerprint"])
        elif value["ssh_key_fingerprint"] is not None:
            _fingerprint(value["ssh_key_fingerprint"])
        _require(action != "hub-authorize" or value["authorized"] is True)
        if request is not None:
            _require(all(value[key] == request[key] for key in ("enrollment_id", "server_id")))
            if "ssh_key_fingerprint" in request:
                _require(value["ssh_key_fingerprint"] == request["ssh_key_fingerprint"])
    else:
        fields.add("target")
        if action == "target-preview":
            fields.add("platform")
        if action in ("target-status", "target-transport", "target-registered", "target-activate"):
            fields.add("services")
        if action == "target-transport":
            fields.add("tls_ready")
        exact(value, fields)
        if value["target"] is None:
            _require(action in ("target-preview", "target-status"))
        else:
            validate_target(value["target"], allow_partial=action in ("target-preview", "target-status"))
            if request is not None:
                _require(all(value["target"][key] == request[key] for key in ("request_id", "enrollment_id", "server_id") if key in request))
            if action == "target-transport":
                _require(value["target"]["phase"] in ("transport_ready", "registered", "active"))
            if action == "target-registered":
                _require(value["target"]["phase"] in ("registered", "active"))
            if action == "target-activate":
                _require(value["target"]["phase"] == "active")
        if "platform" in value:
            exact(value["platform"], {"ubuntu_version", "python_version", "systemd_version"})
            for item in value["platform"].values(): _text(item, 64)
        if "services" in value:
            exact(value["services"], {"tunnel", "agent"})
            _require(all(type(item) is bool for item in value["services"].values()))
            if value["target"] is None:
                _require(not any(value["services"].values()))
            if action == "target-activate":
                _require(all(value["services"].values()))
        if "tls_ready" in value:
            _require(value["tls_ready"] is True)
    result = json.loads(json.dumps(value))
    result["cas"] = validate_cas(value["cas"])
    return result


def validate_features(value):
    exact(value, {"commands", "terminal", "files"})
    _require(all(type(item) is bool for item in value.values()))
    _require(value["commands"] or not (value["terminal"] or value["files"]))
    return dict(value)


def validate_feature_identity(value):
    exact(value, {"request_id", "enrollment_id", "server_id", "agent_token_sha256"})
    for key in ("request_id", "enrollment_id", "server_id"):
        canonical_uuid(value[key])
    _sha(value["agent_token_sha256"])
    return dict(value)


def validate_feature_reply(action, value, *, request=None):
    fields = {"protocol", "ok", "identity", "current", "expected", "source_manifest_sha256",
              "recovery_required", "pending_features", "services"}
    if action != "target-features-status":
        fields |= {"desired", "changed"}
    if action == "target-features-apply":
        fields.add("applied")
    exact(value, fields)
    identity = validate_feature_identity(value["identity"])
    current = validate_features(value["current"])
    expected = validate_cas(value["expected"])
    _sha(value["source_manifest_sha256"])
    _require(expected["source_manifest_sha256"] == value["source_manifest_sha256"]
             and type(value["recovery_required"]) is bool)
    pending = value["pending_features"]
    if pending is not None:
        validate_features(pending)
    _require(value["recovery_required"] == (pending is not None))
    exact(value["services"], {"agent", "tunnel", "terminal"})
    _require(all(type(item) is bool for item in value["services"].values()))
    if request is not None:
        _require(identity["server_id"] == request["server_id"])
        for key in ("enrollment_id", "agent_token_sha256"):
            if key in request:
                _require(identity[key] == request[key])
    if "desired" in value:
        desired = validate_features(value["desired"])
        _require(type(value["changed"]) is bool)
        if request is not None:
            _require(desired == request["features"])
    if action == "target-features-apply":
        _require(value["applied"] is True and current == desired
                 and value["recovery_required"] is False and pending is None
                 and value["services"]["agent"] is True and value["services"]["tunnel"] is True
                 and value["services"]["terminal"] == desired["terminal"])
    return json.loads(json.dumps(value))


def decode_reply(action, raw, *, request=None):
    _require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_RPC)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            _require(key not in value); value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise ProtocolError() from None
    return validate_reply(action, value, request=request)
