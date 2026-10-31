#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Root side of the Web remote-Agent enrollment socket.

Only the fixed SSH and Connect enrollment operations are accepted. The Web
gateway must first check same-origin and unrestricted admin access; this
service independently checks the same live Hub session on every request.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import threading


_DEPLOY = Path(__file__).resolve().parent
_BEARER = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_ACTIONS = frozenset({"prepare", "apply", "resume", "cleanup", "interrupt", "status", "list",
                      "vpn-source-preview", "vpn-source-apply", "vpn-source-recover",
                      "wg-control-preview", "wg-control-apply", "wg-control-recover",
                      "amnezia-provision-preview", "amnezia-provision-apply",
                      "amnezia-provision-recover"})
_MAX_REQUEST = 160 * 1024  # Two bounded private keys on a reviewed jump route.
_MAX_REPLY = 32 * 1024 - 1  # Gateway's 32 KiB limit includes the newline.
_GATEWAY_UID = 10003
_PUBLIC_WEB_LOCK = Path("/var/lib/sovagrid/.public-web.lock")


def _trusted_imports() -> None:
    """The isolated interpreter imports only the installed, root-owned tree."""
    if os.geteuid() == 0:
        if _DEPLOY != Path("/opt/sovagrid-src/sovagrid-blueprint/deploy"):
            raise RuntimeError("Web Agent service requires the managed source")
        for directory in (Path("/opt"), Path("/opt/sovagrid-src"),
                          _DEPLOY.parent, _DEPLOY):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError("Web Agent service source is not root-owned")
    sys.dont_write_bytecode = True
    if str(_DEPLOY) not in sys.path:
        sys.path.insert(0, str(_DEPLOY))


_trusted_imports()
from web_agent_local_rpc import LocalHubFacade, LocalHubRPC  # noqa: E402
from web_agent_target_ssh import PinnedTargetSSH, TargetSSHError, host_key_alias  # noqa: E402
from web_agent_jobs import ControllerBinding, JobError, WebAgentJobs  # noqa: E402
from web_vpn_source import VpnSourceError, VpnSourceJobs  # noqa: E402
from web_wireguard_control import WireguardControlError, WireguardControlJobs  # noqa: E402
from web_amnezia_provision import AmneziaProvisionError, AmneziaProvisionJobs  # noqa: E402
from sovagrid_connect.agent_enrollment import AgentEnrollment  # noqa: E402
from sovagrid_connect.core import ConnectionOptions  # noqa: E402
from sovagrid_connect.enrollment_api import EnrollmentAPI, EnrollmentAPIError  # noqa: E402


class RequestError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class Credential:
    """Short-lived request fields; the SSH broker owns its separate live copy."""

    def __init__(self, payload: dict):
        method = payload.get("method")
        password = payload.get("password")
        private_key = payload.get("private_key")
        passphrase = payload.get("passphrase")
        if (method not in ("password", "private_key") or
                not all(isinstance(value, str) for value in (password, private_key, passphrase)) or
                len(password.encode("utf-8")) > 1024 or len(passphrase.encode("utf-8")) > 1024 or
                len(private_key.encode("utf-8")) > 65536 or
                (method == "password" and (not password or private_key or passphrase)) or
                (method == "private_key" and (not private_key or password))):
            raise RequestError("INVALID_INPUT")
        self.method = method
        self.password = password
        self.private_key = private_key
        self.passphrase = passphrase

    def wipe(self) -> None:
        self.password = self.private_key = self.passphrase = ""


class RouteCredential(Credential):
    """An installer route owns two independent, short-lived SSH secrets."""

    def __init__(self, payload: dict):
        super().__init__(payload)
        self.target_host_key_blob = ""
        self.jump: dict | None = None
        if "jump" in payload:
            target_blob = payload.get("host_key_blob")
            jump = payload["jump"]
            if (not isinstance(target_blob, str) or len(target_blob) > 12000 or
                    not isinstance(jump.get("host_key_blob"), str) or
                    len(jump["host_key_blob"]) > 12000):
                raise RequestError("INVALID_INPUT")
            second = Credential(jump)
            self.target_host_key_blob = target_blob
            self.jump = {"host": jump["host"], "port": jump["port"],
                         "username": jump["username"], "fingerprint": jump["fingerprint"],
                         "host_key_blob": jump["host_key_blob"], "method": second.method,
                         "password": second.password, "private_key": second.private_key,
                         "passphrase": second.passphrase}

    def wipe(self) -> None:
        super().wipe()
        self.target_host_key_blob = ""
        if self.jump is not None:
            for key in ("password", "private_key", "passphrase"):
                self.jump[key] = ""


def _target_factory(*, target_options, fingerprint, credential, journal, progress):
    transport = PinnedTargetSSH(host=target_options.host, port=target_options.port,
        username=target_options.user, fingerprint=fingerprint, method=credential.method,
        password=credential.password, private_key=credential.private_key,
        passphrase=credential.passphrase, jump=getattr(credential, "jump", None),
        target_host_key_blob=getattr(credential, "target_host_key_blob", ""))
    transport.__enter__()
    try:
        tunnel = LocalHubFacade()

        def rpc_factory(options, *, role, progress=None):
            if role == "hub":
                return LocalHubRPC(options, role=role, progress=progress)
            if role == "target":
                return transport.target_rpc(options, progress=progress)
            raise ValueError("unsupported enrollment role")

        controller = AgentEnrollment(tunnel, journal=journal,
                                     rpc_factory=rpc_factory, progress=progress)
        return ControllerBinding(controller, transport.options, transport.close)
    except BaseException:
        transport.close()
        raise


def _authorize(token: str) -> None:
    if not isinstance(token, str) or _BEARER.fullmatch(token) is None:
        raise RequestError("AUTH_REQUIRED")
    api = EnrollmentAPI(LocalHubFacade())
    try:
        api.adopt_bearer(token)
        api.verify()
    except EnrollmentAPIError as error:
        raise RequestError("ADMIN_FORBIDDEN" if error.status == 403 else
                           "AUTH_REQUIRED" if error.status == 401 else "HUB_UNAVAILABLE") from None
    except Exception:
        raise RequestError("HUB_UNAVAILABLE") from None
    finally:
        api.logout()  # Borrowed browser sessions are never revoked here.


def _fields(payload: object, required: frozenset[str]) -> dict:
    if type(payload) is not dict or set(payload) != required:
        raise RequestError("INVALID_INPUT")
    return payload


_LOGIN = frozenset({"host", "port", "username", "method", "fingerprint",
                    "password", "private_key", "passphrase"})
_JUMP_LOGIN = _LOGIN | {"host_key_blob"}
_PREPARE = _LOGIN | {"name", "hub_host", "hub_port", "local_port"}
_RESUME = _LOGIN | {"request_id"}


def _options(payload: dict) -> ConnectionOptions:
    try:
        jump = payload.get("jump")
        extra = ({} if jump is None else {
            "jump_host": jump["host"], "jump_user": jump["username"],
            "jump_port": jump["port"],
            "jump_host_key_alias": host_key_alias(jump["fingerprint"]),
        })
        return ConnectionOptions(host=payload["host"], user=payload["username"],
                                 port=payload["port"], **extra).validated()
    except (ValueError, TypeError, OSError, TargetSSHError):
        raise RequestError("INVALID_INPUT") from None


@contextmanager
def _stable_public_web(*, expected_uid: int = 0, expected_gid: int = 0):
    """Keep direct run.sh from replacing the installed tree during a job.

    Both updaters take the enrollment lock before this public lock. Jobs take
    this shared lock first, then nonblocking enrollment admission, so neither
    a direct installer nor an updater can change the source mid-operation.
    """
    descriptor = None
    try:
        descriptor = os.open(_PUBLIC_WEB_LOCK, os.O_RDWR | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        path_info = _PUBLIC_WEB_LOCK.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or
                info.st_gid != expected_gid or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or
                (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)):
            raise RequestError("BUSY")
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except (OSError, RequestError):
        if descriptor is not None:
            os.close(descriptor)
        raise RequestError("BUSY") from None
    try:
        yield
    finally:
        os.close(descriptor)


def dispatch(jobs: WebAgentJobs, request: object, *, authorize=_authorize,
             vpn_source: VpnSourceJobs | None = None,
             wg_control: WireguardControlJobs | None = None,
             amnezia_provision: AmneziaProvisionJobs | None = None) -> dict:
    if type(request) is not dict or set(request) != {"action", "session_token", "payload"}:
        raise RequestError("INVALID_INPUT")
    action, token, payload = request["action"], request["session_token"], request["payload"]
    if not isinstance(action, str) or action not in _ACTIONS:
        raise RequestError("INVALID_INPUT")
    authorize(token)
    with _stable_public_web():
        return _dispatch_authorized(jobs, action, token, payload,
                                    vpn_source=vpn_source, wg_control=wg_control,
                                    amnezia_provision=amnezia_provision)


def _dispatch_authorized(jobs: WebAgentJobs, action: str, token: str, payload: object,
                         *, vpn_source: VpnSourceJobs | None = None,
                         wg_control: WireguardControlJobs | None = None,
                         amnezia_provision: AmneziaProvisionJobs | None = None) -> dict:
    if action.startswith("amnezia-provision-"):
        try:
            if amnezia_provision is None:
                raise RequestError("RUNTIME_UNAVAILABLE")
            operation = action.removeprefix("amnezia-provision-")
            extra = {"listen_port", "subnet", "route_mode"}
            if operation == "apply":
                extra |= {"expected_state", "confirm"}
            elif operation == "recover":
                extra = {"confirm"}
            _fields(payload, _LOGIN | extra)
            credential = Credential(payload)
            try:
                options = _options(payload)
                return amnezia_provision.execute(operation, options=options,
                    fingerprint=payload["fingerprint"], credential=credential,
                    listen_port=payload.get("listen_port"), subnet=payload.get("subnet"),
                    route_mode=payload.get("route_mode"),
                    expected_state=payload.get("expected_state"), confirm=payload.get("confirm"))
            finally:
                credential.wipe()
        finally:
            if type(payload) is dict:
                for key in ("password", "private_key", "passphrase"):
                    if key in payload:
                        payload[key] = ""
    if action.startswith("wg-control-"):
        try:
            if wg_control is None:
                raise RequestError("RUNTIME_UNAVAILABLE")
            operation = action.removeprefix("wg-control-")
            extra = {"expected", "confirm"} if operation == "apply" else \
                    {"confirm"} if operation == "recover" else set()
            _fields(payload, _LOGIN | extra)
            credential = Credential(payload)
            try:
                options = _options(payload)
                return wg_control.execute(operation, options=options,
                    fingerprint=payload["fingerprint"], credential=credential,
                    expected=payload.get("expected"), confirm=payload.get("confirm"))
            finally:
                credential.wipe()
        finally:
            if type(payload) is dict:
                for key in ("password", "private_key", "passphrase"):
                    if key in payload:
                        payload[key] = ""
    if action.startswith("vpn-source-"):
        if vpn_source is None:
            raise RequestError("RUNTIME_UNAVAILABLE")
        _fields(payload, _LOGIN | ({"expected"} if action == "vpn-source-apply" else set()))
        credential = Credential(payload)
        try:
            options = _options(payload)
            return vpn_source.execute(action.removeprefix("vpn-source-"), options=options,
                fingerprint=payload["fingerprint"], credential=credential,
                expected=payload.get("expected"))
        finally:
            credential.wipe()
            for key in ("password", "private_key", "passphrase"):
                payload[key] = ""
    if action in ("prepare", "resume"):
        try:
            jumped = type(payload) is dict and "jump" in payload
            fields = _PREPARE if action == "prepare" else _RESUME
            _fields(payload, fields | {"host_key_blob", "jump"} if jumped else fields)
            if jumped:
                _fields(payload["jump"], _JUMP_LOGIN)
            credential = RouteCredential(payload)
            try:
                options = _options(payload)
                args = {"target_options": options,
                        "reviewed_fingerprint": payload["fingerprint"],
                        "credential": credential, "session_token": token}
                if action == "prepare":
                    result = jobs.prepare(**args, name=payload["name"],
                        hub_host=payload["hub_host"], hub_port=payload["hub_port"],
                        local_port=payload["local_port"])
                else:
                    result = jobs.resume(payload["request_id"], **args)
            finally:
                credential.wipe()
        finally:
            if type(payload) is dict:
                for key in ("password", "private_key", "passphrase"):
                    if key in payload:
                        payload[key] = ""
                if type(payload.get("jump")) is dict:
                    for key in ("password", "private_key", "passphrase"):
                        if key in payload["jump"]:
                            payload["jump"][key] = ""
        return result
    if action in ("apply", "cleanup"):
        _fields(payload, frozenset({"request_id", "expected_revision"}))
        return getattr(jobs, action)(payload["request_id"], payload["expected_revision"])
    if action == "status":
        _fields(payload, frozenset({"request_id"}))
        return jobs.status(payload["request_id"])
    if action == "interrupt":
        if type(payload) is not dict or set(payload) not in (set(), {"request_id"}):
            raise RequestError("INVALID_INPUT")
        return jobs.interrupt(payload.get("request_id"))
    _fields(payload, frozenset())
    return jobs.list()


def _reply(value: dict) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raw = b'{"ok":false,"error":"OPERATION_FAILED"}'
    if len(raw) > _MAX_REPLY:
        raw = b'{"ok":false,"error":"RESPONSE_TOO_LARGE"}'
    return raw + b"\n"


def _handle(connection: socket.socket, jobs: WebAgentJobs,
            *, peer_uid=None, authorize=_authorize,
            vpn_source: VpnSourceJobs | None = None,
            wg_control: WireguardControlJobs | None = None,
            amnezia_provision: AmneziaProvisionJobs | None = None) -> None:
    with connection:
        connection.settimeout(30)
        raw = bytearray()
        try:
            if peer_uid is None:
                if not hasattr(socket, "SO_PEERCRED"):
                    raise RequestError("FORBIDDEN")
                pid, uid, _gid = struct.unpack("3i", connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if pid <= 0 or uid != _GATEWAY_UID:
                    raise RequestError("FORBIDDEN")
            elif peer_uid != _GATEWAY_UID:
                raise RequestError("FORBIDDEN")
            while b"\n" not in raw and len(raw) <= _MAX_REQUEST:
                part = connection.recv(min(4096, _MAX_REQUEST + 1 - len(raw)))
                if not part:
                    break
                raw.extend(part)
            if not raw.endswith(b"\n") or len(raw) > _MAX_REQUEST:
                raise RequestError("INVALID_INPUT")

            def unique(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError("duplicate key")
                    value[key] = item
                return value

            request = json.loads(raw, object_pairs_hook=unique)
            result = dispatch(jobs, request, authorize=authorize,
                              vpn_source=vpn_source, wg_control=wg_control,
                              amnezia_provision=amnezia_provision)
            response = {"ok": True, "result": result}
        except (JobError, RequestError, VpnSourceError, WireguardControlError,
                AmneziaProvisionError) as error:
            response = {"ok": False, "error": error.code}
            if getattr(error, "request_id", None) is not None:
                response["request_id"] = error.request_id
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError):
            response = {"ok": False, "error": "INVALID_INPUT"}
        except Exception:
            response = {"ok": False, "error": "OPERATION_FAILED"}
        finally:
            raw[:] = b"\0" * len(raw)
        try:
            connection.settimeout(5)
            connection.sendall(_reply(response))
        except OSError:
            pass


def _systemd_socket() -> socket.socket:
    if os.geteuid() != 0 or os.environ.get("LISTEN_PID") != str(os.getpid()) or \
            os.environ.get("LISTEN_FDS") != "1":
        raise RuntimeError("Web Agent service requires one systemd socket")
    listener = socket.socket(fileno=3)
    if listener.family != socket.AF_UNIX or listener.type != socket.SOCK_STREAM:
        raise RuntimeError("Unexpected Web Agent socket")
    if listener.getsockname() != "/run/sovagrid-web-agent/control.sock":
        raise RuntimeError("Unexpected Web Agent socket path")
    return listener


def serve(listener: socket.socket, jobs: WebAgentJobs,
          vpn_source: VpnSourceJobs | None = None,
          wg_control: WireguardControlJobs | None = None,
          amnezia_provision: AmneziaProvisionJobs | None = None) -> None:
    slots = threading.BoundedSemaphore(8)
    try:
        while True:
            connection, _ = listener.accept()
            if not slots.acquire(blocking=False):
                with connection:
                    try:
                        connection.sendall(_reply({"ok": False, "error": "BUSY"}))
                    except OSError:
                        pass
                continue

            def work(sock):
                try:
                    _handle(sock, jobs, vpn_source=vpn_source, wg_control=wg_control,
                            amnezia_provision=amnezia_provision)
                finally:
                    slots.release()

            threading.Thread(target=work, args=(connection,), daemon=True,
                             name="sovagrid-web-agent-request").start()
    finally:
        jobs.close()


def main() -> int:
    if os.geteuid() != 0:
        raise RuntimeError("Web Agent service requires root")
    from web_agent_bundle import ensure_managed_bundle
    bundle, digest = ensure_managed_bundle()
    jobs = WebAgentJobs(journal_root=Path("/var/lib/sovagrid/web-agent/jobs"),
                        bundle_path=bundle, bundle_sha256=digest,
                        controller_factory=_target_factory)
    serve(_systemd_socket(), jobs, VpnSourceJobs(jobs), WireguardControlJobs(jobs),
          AmneziaProvisionJobs(jobs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
