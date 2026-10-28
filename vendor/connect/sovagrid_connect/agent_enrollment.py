# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Recoverable orchestration; public checkpoints, target-only credentials.

Run blocking methods on a worker thread. Cancelling transport never implies
rollback: cleanup first reconciles both machines and the Hub registration.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import ipaddress
from pathlib import Path
import tarfile
import threading
import time
import uuid

from .core import ConnectionOptions
from .enrollment_api import EnrollmentAPI, EnrollmentAPIError
from .enrollment_protocol import public_key_fingerprint
from .installer import verify_bundle

HELPER = "sovagrid-blueprint/deploy/remote_agent.py"
MARKER = b"SOVAGRID_REMOTE_AGENT_HELPER_V1"
PHASES = ("prepared", "transport_ready", "registered", "active")
_UNSET = object()


class EnrollmentError(RuntimeError):
    pass


class EnrollmentCancelled(EnrollmentError):
    pass


def source_bundle(path):
    path = Path(path).expanduser().resolve()
    summary = verify_bundle(path)
    with tarfile.open(path, "r:gz") as archive:
        try:
            item = archive.getmember(HELPER)
        except KeyError:
            raise EnrollmentError("Выберите новый серверный пакет с мастером установки удалённых Agent.") from None
        if not item.isfile() or item.size > 512 * 1024:
            raise EnrollmentError("Пакет не содержит поддерживаемого установщика Agent.")
        with archive.extractfile(item) as stream:
            if MARKER not in stream.read(32768):
                raise EnrollmentError("Пакет не содержит поддерживаемого установщика Agent.")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "sha256": digest.hexdigest()}, summary


def _connection(options):
    options = options.validated()
    if options.ssh_executable != "ssh":
        raise EnrollmentError("Для мастера установки используйте системный OpenSSH.")
    values = asdict(options)
    values.pop("ssh_executable")
    return values


def _endpoint(host, port, local_port):
    try:
        address = ipaddress.ip_address(host)
    except (TypeError, ValueError):
        raise EnrollmentError("Укажите IP-адрес Hub, доступный именно с нового сервера.") from None
    mapped = getattr(address, "ipv4_mapped", None)
    if (address.is_loopback or address.is_unspecified or address.is_multicast or getattr(address, "scope_id", None)
            or mapped is not None and (mapped.is_loopback or mapped.is_unspecified or mapped.is_multicast)
            or type(port) is not int or not 1 <= port <= 65535
            or type(local_port) is not int or not 1024 <= local_port <= 65535):
        raise EnrollmentError("Проверьте IP Hub, SSH-порт и локальный порт подключения Agent.")
    return {"host": str(address), "port": port, "local_port": local_port}


class AgentEnrollment:
    def __init__(self, tunnel, *, journal=None, rpc_factory=None, api_factory=EnrollmentAPI, progress=None):
        if journal is None:
            from .enrollment_journal import EnrollmentJournal
            journal = EnrollmentJournal()
        if rpc_factory is None:
            from .agent_rpc import AgentRPC
            rpc_factory = AgentRPC
        self.tunnel = tunnel
        self.journal = journal
        self.rpc_factory = rpc_factory
        self.api = api_factory(tunnel)
        self.progress = progress or (lambda _message: None)
        self._stop = threading.Event()
        self.record = None
        self.hub = None
        self.target = None
        self.stage = None
        self._reviewed = False

    def _guard(self):
        if self._stop.is_set():
            raise EnrollmentCancelled("Установка остановлена. Проверяем, какие действия успели завершиться.")
        if not self.tunnel.alive:
            raise EnrollmentError("SSH-соединение с Hub закрыто. Подключитесь к нему и возобновите установку.")

    def _save(self, **changes):
        if self.record is None:
            raise EnrollmentError("Запись установки ещё не создана.")
        self.record = self.journal.update(self.record["request_id"], changes, expected_revision=self.record["revision"])
        return self.record

    def _check_hub_connection(self):
        selected = _connection(self.tunnel.options)
        saved = self.record["hub_connection"]
        stable = set(saved) - {"identity", "jump_identity", "local_port"}
        if any(selected[key] != saved[key] for key in stable):
            raise EnrollmentError("Для возобновления подключитесь к тому же Hub по сохранённому SSH-маршруту.")
        # The endpoint is immutable; a relocated local private-key file may be
        # replaced by the key used for the newly verified live SSH connection.
        repaired = {**saved, **{key: selected[key] for key in ("identity", "jump_identity")}}
        if repaired != saved:
            self._save(hub_connection=repaired)

    def _rpcs(self):
        self.hub = self.rpc_factory(ConnectionOptions(**self.record["hub_connection"]), role="hub", progress=self.progress)
        self.target = self.rpc_factory(ConnectionOptions(**self.record["target_connection"]), role="target", progress=self.progress)

    def _bind_hub(self, reply):
        trust = {key: reply[key] for key in ("hub_host_key", "hub_ca_pem")}
        if self.record["hub_trust"] is not None and self.record["hub_trust"] != trust:
            raise EnrollmentError("Ключ SSH или CA центра мониторинга изменился. Автоматическое продолжение остановлено.")
        self._save(hub_trust=trust, cas={**self.record["cas"], "hub": reply["cas"]})

    def _bind_target(self, reply, *, allow_removed=False, registration=_UNSET):
        target = reply["target"]
        if target is not None and target["request_id"] != self.record["request_id"]:
            raise EnrollmentError("На сервере найдена другая установка. Она не будет изменена.")
        if self.record["target"] is not None and target is None:
            if not allow_removed:
                raise EnrollmentError("Не удалось подтвердить подготовленную установку на сервере.")
            # Keep the old public IDs for idempotent remove/revoke after a
            # successful target removal whose SSH response was lost.
            changes = {"cas": {**self.record["cas"], "target": reply["cas"]}}
            if registration is not _UNSET:
                changes["registration"] = registration
            self._save(**changes)
            return
        changes = {"target": target, "cas": {**self.record["cas"], "target": reply["cas"]}}
        if registration is not _UNSET:
            changes["registration"] = registration
        if target is not None:
            changes["phase"] = target["phase"]
        self._save(**changes)

    def _checkpoint_stage(self, descriptor):
        # Synchronous and durable BEFORE even creating the remote staging path.
        # The opaque live Stage is returned only after the upload is verified.
        self._save(stage=descriptor)

    def _ensure_stage(self):
        if self.stage is not None:
            return
        if self.record["stage"] is not None:
            try:
                self.stage = self.target.recover_stage(self.record["stage"])
                return
            except Exception as error:
                # A missing path after EOF cleanup is safe to stage again;
                # ownership/hash errors never invite overwriting that path.
                code = getattr(error, "code", None)
                if code == "STAGE_INCOMPLETE":
                    partial = self.target.recover_stage(self.record["stage"], for_cleanup=True)
                    self.target.cleanup_stage(partial)
                elif code != "STAGE_NOT_FOUND":
                    raise
                self._save(stage=None)
        self.stage = self.target.stage_target(Path(self.record["bundle"]["path"]),
            self.record["bundle"]["sha256"], checkpoint=self._checkpoint_stage)

    def _target_call(self, action, payload):
        self._ensure_stage()
        return self.target.call(action, payload, stage=self.stage)

    def _identity(self):
        target = self.record["target"]
        if target is None:
            raise EnrollmentError("Сервер ещё не подготовлен.")
        return {key: target[key] for key in ("request_id", "enrollment_id", "server_id")}

    def _target_payload(self, **extra):
        return {"protocol": 1, **self._identity(), "expected": self.record["cas"]["target"], **extra}

    def _login(self, username, password, credentials, session_token):
        if session_token is not None:
            if username is not None or password is not None or credentials is not None:
                raise EnrollmentError("Выберите один способ подтверждения прав Hub.")
            self.api.adopt_bearer(session_token)
            return
        if credentials is not None:
            if type(credentials) is not dict or set(credentials) != {"username", "password"}:
                raise EnrollmentError("Введите логин и пароль центра мониторинга.")
            username = credentials.pop("username")
            password = credentials.pop("password")
        try:
            self.api.login(username, password)
        finally:
            password = None
            if credentials is not None:
                credentials.clear()

    def prepare(self, *, target_options, name, bundle, hub_host, hub_port, local_port,
                username=None, password=None, credentials=None, session_token=None):
        self._guard()
        if self.record is not None:
            raise EnrollmentError("Установка уже подготовлена. Возобновите её или завершите очистку.")
        if not isinstance(name, str) or not 1 <= len(name) <= 80 or name != name.strip() or not name.isprintable():
            raise EnrollmentError("Введите название сервера от 1 до 80 символов.")
        selected, summary = source_bundle(bundle)
        request_id = str(uuid.uuid4())
        hub_connection = _connection(self.tunnel.options)
        target_connection = _connection(target_options)
        endpoint = _endpoint(hub_host, hub_port, local_port)
        self.progress("Подтверждаем права администратора центра мониторинга…")
        self._login(username, password, credentials, session_token)
        password = None
        if self.api.get(request_id) is not None:
            raise EnrollmentError("Идентификатор новой установки уже занят.")
        self._guard()
        # Root SSH and platform are checked with fixed local verifier code.
        self.hub = self.rpc_factory(ConnectionOptions(**hub_connection), role="hub", progress=self.progress)
        self.target = self.rpc_factory(ConnectionOptions(**target_connection), role="target", progress=self.progress)
        self.progress("Проверяем SSH-доступ к Hub и новому серверу…")
        self.hub.preflight(); target_platform = self.target.preflight()
        hub = self.hub.call("hub-preview", {"protocol": 1})
        self._guard()
        self.record = self.journal.create({"protocol": 1, "request_id": request_id, "name": name,
            "phase": "prepared", "hub_connection": hub_connection, "target_connection": target_connection,
            "hub_endpoint": endpoint, "bundle": selected, "target": None, "registration": None,
            "hub_trust": None, "hub_authorized": False, "cleanup_required": False,
            "cas": {"hub": None, "target": None}, "stage": None})
        self._bind_hub(hub)
        self.progress("Передаём проверенный временный пакет для проверки сервера…")
        self.api.verify()
        reply = self._target_call("target-preview", {"protocol": 1, "request_id": request_id})
        self._bind_target(reply)
        self._guard(); self._reviewed = True
        return {"record": self.record, "platform": reply.get("platform", target_platform),
                "source_commits": summary.commits, "hub_fingerprint": public_key_fingerprint(hub["hub_host_key"])}

    def resume(self, request_id, *, username=None, password=None, credentials=None,
               session_token=None, target_identity=_UNSET, jump_identity=_UNSET, bundle_path=None):
        self._guard()
        if self.record is not None:
            raise EnrollmentError("Сначала завершите текущую проверку установки.")
        self.record = self.journal.load(request_id)
        if self.record is None:
            raise EnrollmentError("Запись установки не найдена.")
        self._check_hub_connection()
        if target_identity is not _UNSET or jump_identity is not _UNSET:
            connection = dict(self.record["target_connection"])
            if target_identity is not _UNSET:
                connection["identity"] = target_identity
            if jump_identity is not _UNSET:
                connection["jump_identity"] = jump_identity
            connection = _connection(ConnectionOptions(**connection))
            self._save(target_connection=connection)
        selected, summary = source_bundle(bundle_path or self.record["bundle"]["path"])
        if selected["sha256"] != self.record["bundle"]["sha256"]:
            raise EnrollmentError("Сохранённый серверный пакет изменился. Возобновление остановлено.")
        if selected != self.record["bundle"]:
            self._save(bundle=selected)
        self._login(username, password, credentials, session_token); password = None
        self._rpcs()
        self.hub.preflight(); target_platform = self.target.preflight()
        self._bind_hub(self.hub.call("hub-preview", {"protocol": 1}))
        self.api.verify()
        reply = self._target_call("target-preview", {"protocol": 1, "request_id": request_id})
        target = reply["target"]
        known_target = target or self.record["target"]
        registration = self.api.get(known_target["enrollment_id"]) if known_target is not None else None
        missing_prepared_target = target is None and self.record["target"] is not None
        self._bind_target(reply, registration=registration, allow_removed=missing_prepared_target)
        self._save(cleanup_required=missing_prepared_target or registration is not None and registration["state"] == "cancelled")
        self._guard(); self._reviewed = True
        return {"record": self.record, "platform": target_platform, "source_commits": summary.commits,
                "hub_fingerprint": public_key_fingerprint(self.record["hub_trust"]["hub_host_key"])}

    def apply(self):
        self._guard()
        if not self._reviewed or self.record is None:
            raise EnrollmentError("Сначала проверьте обе машины и подтвердите результат проверки.")
        if self.record["cleanup_required"] or self.record["registration"] is not None and self.record["registration"]["state"] == "cancelled":
            raise EnrollmentError("Сначала завершите проверку и очистку незавершённой установки.")
        try:
            # Repeating prepare preserves all generated IDs and credentials.
            self.progress("Подготавливаем отдельный Agent и его защищённые данные…")
            self.api.verify()
            reply = self._target_call("target-prepare", {"protocol": 1, "request_id": self.record["request_id"],
                "expected": self.record["cas"]["target"]})
            self._bind_target(reply); self._guard()
            target = self.record["target"]
            self.progress("Настраиваем ограниченное SSH-подключение к центру мониторинга…")
            status = self.hub.call("hub-status", {"protocol": 1, "enrollment_id": target["enrollment_id"], "server_id": target["server_id"]})
            if status["authorized"]:
                if status["ssh_key_fingerprint"] != target["ssh_key_fingerprint"]:
                    raise EnrollmentError("В Hub найден другой ключ этого сервера. Установка остановлена.")
                self._save(hub_authorized=True, cas={**self.record["cas"], "hub": status["cas"]})
            else:
                self.api.verify()
                reply = self.hub.call("hub-authorize", {"protocol": 1, "enrollment_id": target["enrollment_id"],
                    "server_id": target["server_id"], "expected": self.record["cas"]["hub"],
                    "ssh_public_key": target["ssh_public_key"], "ssh_key_fingerprint": target["ssh_key_fingerprint"]})
                self._save(hub_authorized=True, cas={**self.record["cas"], "hub": reply["cas"]})
            self._guard()
            if PHASES.index(self.record["phase"]) < PHASES.index("transport_ready"):
                endpoint = self.record["hub_endpoint"]
                self.api.verify()
                reply = self._target_call("target-transport", self._target_payload(
                    hub_host=endpoint["host"], hub_port=endpoint["port"], local_port=endpoint["local_port"], **self.record["hub_trust"]))
                self._bind_target(reply); self._guard()
            target = self.record["target"]
            self.progress("Регистрируем сервер без переноса его токена…")
            registration = self.api.register(target["enrollment_id"], target["server_id"], self.record["name"], target["agent_token_sha256"])
            self._save(registration=registration); self._guard()
            # The phase is persisted before systemd starts the service. Replay
            # even on registered/active to finish a lost start response safely.
            self.api.verify()
            reply = self._target_call("target-registered", self._target_payload(registration=registration))
            self._bind_target(reply); self._guard()
            self.progress("Ждём первое измерение нового сервера…")
            deadline = time.monotonic() + 120
            while True:
                self._guard()
                registration = self.api.get(target["enrollment_id"])
                if registration is None or registration["state"] == "cancelled":
                    raise EnrollmentError("Регистрация сервера отменена или больше не подтверждается.")
                self._save(registration=registration)
                if registration["state"] == "active":
                    break
                if time.monotonic() >= deadline:
                    raise EnrollmentError("Agent ещё не прислал измерение. Сохранённую установку можно возобновить.")
                self._stop.wait(1)
            self.api.verify()
            reply = self._target_call("target-activate", self._target_payload(registration=registration))
            self._bind_target(reply)
            self._save(cleanup_required=False)
            try:
                self._clean_stage()
            except Exception:
                self._save(cleanup_required=True)
                self.progress("Сервер подключён. Временный пакет можно очистить при повторной проверке установки.")
                return self.record
            self.progress("Сервер подключён. Agent продолжит работать после закрытия Connect.")
            return self.record
        except Exception:
            # An error is never advertised as an automatic rollback.
            self._reviewed = False
            if self.record is not None and self.record["phase"] != "active":
                self._save(cleanup_required=True)
            raise

    def cancel(self):
        self._stop.set()
        for rpc in (self.hub, self.target):
            if rpc is not None:
                rpc.cancel()

    def _clean_stage(self):
        if self.stage is not None:
            self.target.cleanup_stage(self.stage)
            self.stage = None
            self._save(stage=None)

    def cleanup(self):
        """Call only after the in-flight worker returned; uses fresh RPC handles."""
        if self.record is None:
            return {"removed": True, "active": False}
        self._rpcs(); self.stage = None
        self.progress("Проверяем результат прерванной установки на обеих машинах…")
        try:
            self._bind_hub(self.hub.call("hub-preview", {"protocol": 1}))
            self.api.verify()
            status = self._target_call("target-status", {"protocol": 1, "request_id": self.record["request_id"]})
            known_target = status["target"] or self.record["target"]
            registration = self.api.get(known_target["enrollment_id"]) if known_target is not None else None
            self._bind_target(status, allow_removed=True, registration=registration)
            target = self.record["target"]
            if registration is not None and registration["state"] == "active":
                # The first sample won the race: do not erase a working Agent.
                self._save(registration=registration, cleanup_required=False)
                self.api.verify()
                reply = self._target_call("target-activate", self._target_payload(registration=registration))
                self._bind_target(reply); self._clean_stage()
                self.progress("Agent успел подключиться. Работающая установка сохранена.")
                return {"removed": False, "active": True, "record": self.record}
            if registration is not None and registration["state"] == "pending":
                try:
                    self.api.verify()
                    registration = self.api.cancel(target["enrollment_id"], registration["revision"])
                except EnrollmentAPIError as error:
                    if error.status == 409:
                        self._save(cleanup_required=True)
                        raise EnrollmentError("Состояние регистрации изменилось. Проверьте её перед повторной очисткой.") from None
                    raise
                self._save(registration=registration)
            if target is not None:
                self.progress("Удаляем только данные и службы этой незавершённой установки…")
                self.api.verify()
                self._target_call("target-remove", self._target_payload(registration=registration))
                status = self.hub.call("hub-status", {"protocol": 1, "enrollment_id": target["enrollment_id"], "server_id": target["server_id"]})
                # A durable, partially created enrollment may own an account
                # before its authorized key exists. Reconcile that ownership
                # even when the key is no longer authorized.
                if status["ssh_key_fingerprint"] is not None:
                    if status["ssh_key_fingerprint"] != target["ssh_key_fingerprint"]:
                        raise EnrollmentError("Ключ в Hub изменился. Чужое подключение не будет затронуто.")
                    self.api.verify()
                    self.hub.call("hub-revoke", {"protocol": 1, "enrollment_id": target["enrollment_id"],
                        "server_id": target["server_id"], "expected": status["cas"], "ssh_key_fingerprint": target["ssh_key_fingerprint"]})
            self._clean_stage()
            self.journal.remove(self.record["request_id"], expected_revision=self.record["revision"])
            self.record = None
            self.progress("Незавершённая установка очищена. Другие серверы и подключения сохранены.")
            return {"removed": True, "active": False}
        except Exception:
            if self.record is not None:
                self._save(cleanup_required=True)
            raise

    def close(self):
        self.api.logout()
