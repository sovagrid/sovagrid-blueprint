# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Short-lived admin session over the already verified panel SSH tunnel.

Only public registration digests enter this client. A remote Agent's token and
tunnel private key are generated on that Agent and never pass through Connect.
"""
from __future__ import annotations

import json
import re
import threading
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import uuid

MAX_RESPONSE = 4096


class EnrollmentAPIError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def _uuid(value):
    if not isinstance(value, str):
        raise ValueError("Некорректный идентификатор установки.")
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError
    except ValueError:
        raise ValueError("Некорректный идентификатор установки.") from None
    return value


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate field")
        value[key] = item
    return value


def _identity(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("user"), dict):
        raise EnrollmentAPIError("Обновите Hub: не удалось подтвердить учётную запись.")
    user = payload["user"]
    if (not isinstance(user.get("id"), str) or not user["id"] or len(user["id"]) > 128
            or not isinstance(user.get("username"), str) or not 1 <= len(user["username"]) <= 80
            or user.get("enabled") is not True or user.get("role") not in ("viewer", "operator", "admin")):
        raise EnrollmentAPIError("Hub вернул неверные права доступа.")
    if user["role"] != "admin":
        raise EnrollmentAPIError("Для установки Agent нужны права администратора Hub.", 403)
    return user["id"], user["username"], user["role"]


def _unrestricted_access(payload):
    access = payload.get("access") if isinstance(payload, dict) and set(payload) == {"access"} else None
    if (not isinstance(access, dict) or set(access) != {"mode", "revision", "unrestricted_admin"}
            or access["mode"] != "all" or type(access["revision"]) is not int
            or not 0 <= access["revision"] <= 2**63 - 1
            or access["unrestricted_admin"] is not True):
        raise EnrollmentAPIError("Для установки Agent нужен администратор с доступом ко всем серверам.", 403)
    return access["mode"], access["revision"], access["unrestricted_admin"]


def enrollment_reply(payload, enrollment_id, *, required=False):
    if (not isinstance(payload, dict) or set(payload) != {"protocol", "enrollment"}
            or type(payload["protocol"]) is not int or payload["protocol"] != 1):
        raise EnrollmentAPIError("Hub вернул неверный ответ регистрации Agent.")
    row = payload["enrollment"]
    if row is None:
        if required:
            raise EnrollmentAPIError("Hub не подтвердил регистрацию Agent.")
        return None
    fields = {"id", "server_id", "name", "state", "revision", "created_at", "last_seen"}
    if not isinstance(row, dict) or set(row) != fields:
        raise EnrollmentAPIError("Hub вернул неверное состояние установки.")
    try:
        _uuid(row["id"]); _uuid(row["server_id"])
    except ValueError:
        raise EnrollmentAPIError("Hub вернул неверный идентификатор установки.") from None
    if (row["id"] != enrollment_id or not isinstance(row["name"], str) or not 1 <= len(row["name"]) <= 80
            or row["state"] not in ("pending", "active", "cancelled")
            or type(row["revision"]) is not int or not 1 <= row["revision"] <= 2**63 - 1
            or type(row["created_at"]) is not int or not 1 <= row["created_at"] <= 253402300799
            or not (row["last_seen"] is None or type(row["last_seen"]) is int and 1 <= row["last_seen"] <= 253402300799)):
        raise EnrollmentAPIError("Hub вернул неверное состояние установки.")
    if (row["state"] == "active") != (row["last_seen"] is not None):
        raise EnrollmentAPIError("Hub вернул противоречивое состояние установки.")
    return dict(row)


class EnrollmentAPI:
    """No automatic mutation retries, persistent credentials, proxies or redirects."""
    def __init__(self, tunnel, *, opener=None):
        self._tunnel = tunnel
        self._base = tunnel.url.rstrip("/")
        parsed = urlsplit(self._base)
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username is not None
                or parsed.password is not None or parsed.path or parsed.query or parsed.fragment
                or parsed.port is None or not 1 <= parsed.port <= 65535):
            raise ValueError("Нужен подтверждённый SSH-туннель к панели Hub.")
        self._opener = opener or build_opener(ProxyHandler({}), _NoRedirect()).open
        self._lock = threading.RLock()
        self._epoch = 0
        self._token = None
        self._identity = None
        self._access = None
        self._owned_token = False
        self._connected()

    def _connected(self):
        if not self._tunnel.alive or self._tunnel.url.rstrip("/") != self._base:
            raise EnrollmentAPIError("SSH-соединение с Hub закрыто. Подключитесь снова.")

    def _response_limit(self, method, path):
        return MAX_RESPONSE

    def _request(self, method, path, body=None, *, token=None, epoch=None):
        self._connected()
        response_limit = self._response_limit(method, path)
        if type(response_limit) is not int or not MAX_RESPONSE <= response_limit <= 256 * 1024:
            raise ValueError("Неверное ограничение ответа Hub.")
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            limit = 16384 if method == "POST" and path == "/api/v1/session" else 4096
            if len(data) > limit:
                raise ValueError("Запрос установки слишком велик.")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
        request = Request(self._base + path, data=data, method=method, headers=headers)
        try:
            deadline = time.monotonic() + 10
            with self._opener(request, timeout=5) as response:
                raw = bytearray()
                while len(raw) <= response_limit:
                    if time.monotonic() >= deadline:
                        raise TimeoutError
                    chunk = response.read1(min(1024, response_limit - len(raw) + 1))
                    if not chunk:
                        break
                    raw.extend(chunk)
            if len(raw) > response_limit:
                raise ValueError("Response limit")
            value = json.loads(raw, object_pairs_hook=_object)
            self._connected()
            return value
        except HTTPError as error:
            status = error.code
            error.close()
            if status in (401, 403):
                with self._lock:
                    if epoch is not None and self._token == token and self._epoch == epoch:
                        self._epoch += 1; self._token = None; self._identity = None
                        self._access = None; self._owned_token = False
            messages = {401: "Сеанс Hub завершён. Войдите снова.", 403: "Нужны права администратора Hub.",
                404: "Обновите Hub для установки удалённых Agent.", 409: "Состояние установки изменилось. Обновите его перед продолжением.",
                429: "Hub временно ограничил запросы. Повторите позже."}
            raise EnrollmentAPIError(messages.get(status, "Hub не подтвердил действие. Проверьте состояние перед повтором."), status) from None
        except EnrollmentAPIError:
            raise
        except (OSError, ValueError, TypeError, RecursionError):
            # Never include response bodies, URLs with credentials or exceptions.
            raise EnrollmentAPIError("Не удалось подтвердить ответ Hub. Проверьте состояние установки.") from None

    def login(self, username, password):
        if (not isinstance(username, str) or not 1 <= len(username) <= 80 or not username.isprintable()
                or not isinstance(password, str) or not 1 <= len(password) <= 1024):
            raise ValueError("Введите логин и пароль Hub длиной до 1024 символов.")
        try:
            username.encode("utf-8"); password.encode("utf-8")
        except UnicodeError:
            raise ValueError("Логин или пароль содержит недопустимые символы.") from None
        with self._lock:
            self._epoch += 1
            epoch = self._epoch
            previous, previous_owned = self._token, self._owned_token
            self._token = None; self._identity = None; self._access = None; self._owned_token = False
        if previous and previous_owned:
            try:
                self._request("DELETE", "/api/v1/session", token=previous)
            except EnrollmentAPIError:
                pass
        reply = self._request("POST", "/api/v1/session", {"username": username, "password": password})
        password = None
        token = reply.get("token") if isinstance(reply, dict) else None
        if not isinstance(token, str) or re.fullmatch(r"[A-Za-z0-9_-]{20,256}", token) is None:
            raise EnrollmentAPIError("Hub не подтвердил сеанс установки.")
        try:
            identity = _identity(reply)
            with self._lock:
                if epoch != self._epoch:
                    raise EnrollmentAPIError("Вход отменён. Откройте установку снова.")
                self._token = token; self._identity = identity; self._owned_token = True
        except EnrollmentAPIError:
            try:
                self._request("DELETE", "/api/v1/session", token=token)
            except EnrollmentAPIError:
                pass
            raise

    def adopt_bearer(self, token):
        """Borrow a browser admin session. Never revoke it on close or failure.

        The bearer stays only in this object; the durable enrollment journal
        receives public IDs and digests, never this credential.
        """
        if not isinstance(token, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
            raise ValueError("Неверный сеанс Hub для установки Agent.")
        with self._lock:
            self._epoch += 1
            epoch = self._epoch
            previous, previous_owned = self._token, self._owned_token
            self._token = None; self._identity = None; self._access = None; self._owned_token = False
        if previous and previous_owned:
            try:
                self._request("DELETE", "/api/v1/session", token=previous)
            except EnrollmentAPIError:
                pass
        identity = _identity(self._request("GET", "/api/v1/session", token=token))
        access = _unrestricted_access(self._request("GET", "/api/v1/session/access", token=token))
        with self._lock:
            if epoch != self._epoch:
                raise EnrollmentAPIError("Вход отменён. Откройте установку снова.")
            self._token = token; self._identity = identity; self._access = access

    def _session(self):
        with self._lock:
            token, identity, access, epoch = self._token, self._identity, self._access, self._epoch
        if token is None:
            raise EnrollmentAPIError("Войдите в Hub для установки Agent.")
        reply = self._request("GET", "/api/v1/session", token=token, epoch=epoch)
        with self._lock:
            if self._token != token or self._epoch != epoch:
                raise EnrollmentAPIError("Сеанс установки завершён.")
        try:
            if _identity(reply) != identity:
                raise EnrollmentAPIError("Учётная запись Hub изменилась. Войдите снова.")
            if access is not None:
                current_access = _unrestricted_access(self._request(
                    "GET", "/api/v1/session/access", token=token, epoch=epoch))
                if current_access != access:
                    raise EnrollmentAPIError("Права доступа Hub изменились. Откройте установку снова.", 403)
        except EnrollmentAPIError:
            with self._lock:
                if self._token == token and self._epoch == epoch:
                    owned = self._owned_token
                    self._epoch += 1; self._token = None; self._identity = None
                    self._access = None; self._owned_token = False
                else:
                    owned = False
            if owned:
                try:
                    self._request("DELETE", "/api/v1/session", token=token)
                except EnrollmentAPIError:
                    pass
            raise
        with self._lock:
            if self._token != token or self._epoch != epoch:
                raise EnrollmentAPIError("Сеанс установки завершён.")
        return token, epoch

    def _operation(self, method, path, body=None):
        token, epoch = self._session()
        with self._lock:
            if self._token != token or self._epoch != epoch:
                raise EnrollmentAPIError("Сеанс установки завершён.")
        reply = self._request(method, path, body, token=token, epoch=epoch)
        with self._lock:
            if self._token != token or self._epoch != epoch:
                raise EnrollmentAPIError("Сеанс установки завершён. Войдите снова и проверьте её состояние.")
        return reply

    def verify(self):
        """Recheck the live admin session before a remote root-side effect."""
        self._session()

    def get(self, enrollment_id):
        _uuid(enrollment_id)
        return enrollment_reply(self._operation("GET", "/api/v1/agent-enrollments/" + enrollment_id), enrollment_id)

    def register(self, enrollment_id, server_id, name, agent_token_sha256):
        _uuid(enrollment_id); _uuid(server_id)
        if (not isinstance(name, str) or not 1 <= len(name) <= 80 or name != name.strip()
                or not name.isprintable()
                or not isinstance(agent_token_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", agent_token_sha256) is None):
            raise ValueError("Некорректные параметры регистрации Agent.")
        row = enrollment_reply(self._operation("POST", "/api/v1/agent-enrollments/" + enrollment_id,
            {"server_id": server_id, "name": name, "agent_token_sha256": agent_token_sha256}), enrollment_id, required=True)
        if row["server_id"] != server_id or row["name"] != name or row["state"] == "cancelled":
            raise EnrollmentAPIError("Hub подтвердил другую установку. Продолжение остановлено.")
        return row

    def cancel(self, enrollment_id, revision):
        _uuid(enrollment_id)
        if type(revision) is not int or revision < 1:
            raise ValueError("Некорректная ревизия установки.")
        row = enrollment_reply(self._operation("POST", "/api/v1/agent-enrollments/" + enrollment_id + "/cancel",
            {"revision": revision}), enrollment_id, required=True)
        if row["state"] != "cancelled":
            raise EnrollmentAPIError("Hub не подтвердил отмену установки.")
        return row

    def logout(self):
        with self._lock:
            token, owned = self._token, self._owned_token
            self._epoch += 1; self._token = None; self._identity = None
            self._access = None; self._owned_token = False
        if token and owned:
            try:
                self._request("DELETE", "/api/v1/session", token=token)
            except EnrollmentAPIError:
                pass
