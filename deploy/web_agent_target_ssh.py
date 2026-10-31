#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Headless, host-pinned OpenSSH transport for the Web Agent installer.

This module does not install an Agent or expose an HTTP endpoint. A root-owned
worker must first verify the browser administrator and independently reviewed
host fingerprint, then keep this context alive through prepare/apply. The
credential remains in memory or a private tmpfs directory for that operation.
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import uuid


FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
KEY_TYPES = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
             "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
DENIED_PROMPT = re.compile(
    r"(?i)(?:\botp\b|\b2fa\b|\bpin\b|verification|security code|"
    r"one[- ]time|authenticator|token|код|одноразов|подтвержден)"
)
PASSWORD_PROMPT = re.compile(r"(?i)(?:\bpassword\b|пароль)")
PASSPHRASE_PROMPT = re.compile(r"(?i)\bpassphrase\b")
MAX_SECRET = 1024
MAX_SCAN = 32768
MAX_ASKPASS_REQUEST = 2048


class TargetSSHError(RuntimeError):
    """Fixed, safe-to-display failure without hostnames or secrets."""


def host_key_alias(fingerprint: str) -> str:
    """Stable journal-safe binding to the exact reviewed public key digest."""
    if not isinstance(fingerprint, str) or FINGERPRINT.fullmatch(fingerprint) is None:
        raise TargetSSHError("Неверный подтверждённый SSH-отпечаток.")
    try:
        digest = base64.b64decode(fingerprint[7:] + "=", validate=True)
    except ValueError:
        raise TargetSSHError("Неверный подтверждённый SSH-отпечаток.") from None
    if len(digest) != 32 or base64.b64encode(digest).decode("ascii").rstrip("=") != fingerprint[7:]:
        raise TargetSSHError("Неверный подтверждённый SSH-отпечаток.")
    return "sg-" + base64.b32encode(digest).decode("ascii").lower().rstrip("=")


def _write_private(path: Path, data: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _scan(host: str, port: int) -> bytes:
    try:
        result = subprocess.run(
            ["/usr/bin/ssh-keyscan", "-T", "5", "-p", str(port),
             "-t", "ed25519,ecdsa,rsa", host],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise TargetSSHError("SSH-ключ сервера не удалось получить.") from None
    if len(result.stdout) > MAX_SCAN:
        raise TargetSSHError("SSH-сервер прислал слишком много ключей.")
    return result.stdout


def reviewed_public_key(scan_output: bytes, fingerprint: str) -> tuple[str, str]:
    """Return only the scanned public key whose SHA256 was reviewed in the UI."""
    host_key_alias(fingerprint)
    if not isinstance(scan_output, bytes) or len(scan_output) > MAX_SCAN:
        raise TargetSSHError("Неверный ответ SSH-сервера.")
    matches: set[tuple[str, str]] = set()
    for line in scan_output.splitlines():
        if not line or line.startswith(b"#") or len(line) > 8192:
            continue
        parts = line.split()
        if len(parts) != 3:
            continue
        try:
            kind = parts[1].decode("ascii")
            blob = parts[2].decode("ascii")
            raw = base64.b64decode(blob, validate=True)
            if kind not in KEY_TYPES or len(raw) < 8 or len(raw) > 8192:
                continue
            inner_length = struct.unpack(">I", raw[:4])[0]
            if inner_length != len(kind) or raw[4:4 + inner_length] != kind.encode():
                continue
        except (UnicodeError, ValueError, struct.error):
            continue
        actual = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
        if actual == fingerprint:
            matches.add((kind, blob))
    if len(matches) != 1:
        raise TargetSSHError("SSH-ключ изменился или не совпал с подтверждённым отпечатком.")
    return next(iter(matches))


def reviewed_key_blob(blob: str, fingerprint: str) -> tuple[str, str]:
    """Validate a browser-reviewed public wire key without trusting its label."""
    host_key_alias(fingerprint)
    if not isinstance(blob, str) or len(blob) > 12000 or not blob.isascii():
        raise TargetSSHError("Неверный подтверждённый SSH-ключ сервера.")
    try:
        raw = base64.b64decode(blob, validate=True)
        if base64.b64encode(raw).decode("ascii") != blob or not 8 <= len(raw) <= 8192:
            raise ValueError("noncanonical wire key")
        length = struct.unpack(">I", raw[:4])[0]
        if not 4 <= length <= 96 or 4 + length > len(raw):
            raise ValueError("invalid wire type")
        kind = raw[4:4 + length].decode("ascii")
        if kind not in KEY_TYPES or length != len(kind):
            raise ValueError("unsupported wire type")
        actual = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
        if actual != fingerprint:
            raise ValueError("fingerprint changed")
    except (UnicodeError, ValueError, struct.error):
        raise TargetSSHError("SSH-ключ изменился или не совпал с подтверждённым отпечатком.") from None
    return kind, blob


def _prompt_matches(method: str, prompt: str) -> bool:
    if not isinstance(prompt, str) or not 1 <= len(prompt) <= 512 or "\x00" in prompt:
        return False
    if DENIED_PROMPT.search(prompt):
        return False
    if method == "password":
        return PASSWORD_PROMPT.search(prompt) is not None and PASSPHRASE_PROMPT.search(prompt) is None
    return PASSPHRASE_PROMPT.search(prompt) is not None and "key" in prompt.lower()


def _peer_uid(connection: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise TargetSSHError("Проверка локального SSH-запроса недоступна.")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    process, uid, _group = struct.unpack("3i", raw)
    if process <= 0:
        raise TargetSSHError("Неверный локальный SSH-процесс.")
    return uid


class AskpassBroker:
    """One recognized secret answer per SSH child; nothing secret on disk."""

    def __init__(self, path: Path, method: str, secret: str, *, peer_uid=_peer_uid):
        if method not in ("password", "private_key") or not isinstance(secret, str) or \
                len(secret.encode("utf-8")) > MAX_SECRET or "\x00" in secret or \
                "\r" in secret or "\n" in secret:
            raise TargetSSHError("Неверные данные SSH-входа.")
        self.path = path
        self.method = method
        self._secret = bytearray(secret.encode("utf-8"))
        self._peer_uid = peer_uid
        self._lock = threading.Lock()
        self._nonce: str | None = None
        self._used = True
        self._stop = threading.Event()
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._listener.bind(str(path))
            os.chmod(path, 0o600)
            self._listener.listen(2)
            self._listener.settimeout(0.2)
        except BaseException:
            self._listener.close()
            raise
        self._thread = threading.Thread(target=self._serve, daemon=True, name="sovagrid-web-agent-askpass")
        self._thread.start()

    def arm(self) -> str:
        with self._lock:
            if self._stop.is_set():
                raise TargetSSHError("SSH-транспорт уже закрыт.")
            self._nonce = uuid.uuid4().hex
            self._used = False
            return self._nonce

    def disarm(self) -> None:
        with self._lock:
            self._used = True
            self._nonce = None

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                try:
                    connection.settimeout(2)
                    if self._peer_uid(connection) != os.geteuid():
                        continue
                    data = bytearray()
                    while len(data) <= MAX_ASKPASS_REQUEST and b"\n" not in data:
                        chunk = connection.recv(min(512, MAX_ASKPASS_REQUEST + 1 - len(data)))
                        if not chunk:
                            break
                        data.extend(chunk)
                    if not data.endswith(b"\n") or len(data) > MAX_ASKPASS_REQUEST:
                        continue
                    request = json.loads(data.decode("utf-8"))
                    if not isinstance(request, dict) or set(request) != {"nonce", "prompt"}:
                        continue
                    with self._lock:
                        allowed = request["nonce"] == self._nonce and not self._used
                        if allowed:
                            # Even a rejected OTP/unknown prompt consumes this SSH child.
                            self._used = True
                    if allowed and _prompt_matches(self.method, request["prompt"]) and self._secret:
                        connection.sendall(b"OK\n")
                        connection.sendall(self._secret)
                        connection.sendall(b"\n")
                    else:
                        connection.sendall(b"DENY\n")
                except (OSError, UnicodeError, ValueError, TypeError, TargetSSHError):
                    pass

    def close(self) -> None:
        self._stop.set()
        self.disarm()
        self._listener.close()
        self._thread.join(timeout=3)
        for index in range(len(self._secret)):
            self._secret[index] = 0
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def _askpass_client(prompt: str) -> int:
    path = os.environ.get("SOVAGRID_WEB_AGENT_ASKPASS_SOCKET", "")
    nonce = os.environ.get("SOVAGRID_WEB_AGENT_ASKPASS_NONCE", "")
    if not path.startswith("/run/") or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        return 1
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(path)
            request = json.dumps({"nonce": nonce, "prompt": prompt}, ensure_ascii=False,
                                 separators=(",", ":")).encode("utf-8")
            if len(request) > MAX_ASKPASS_REQUEST - 1:
                return 1
            connection.sendall(request + b"\n")
            response = bytearray()
            while len(response) <= MAX_SECRET + 7 and b"\n" not in response:
                part = connection.recv(MAX_SECRET + 8 - len(response))
                if not part:
                    break
                response.extend(part)
            if not response.startswith(b"OK\n"):
                return 1
            while not response.endswith(b"\n") and len(response) <= MAX_SECRET + 5:
                part = connection.recv(MAX_SECRET + 6 - len(response))
                if not part:
                    break
                response.extend(part)
            secret = response[3:]
            if not secret.endswith(b"\n") or not 2 <= len(secret) <= MAX_SECRET + 1:
                return 1
            os.write(1, secret)
            for index in range(len(response)):
                response[index] = 0
            return 0
    except (OSError, UnicodeError, ValueError, TypeError):
        return 1


def _jump_proxy_client(directory: str) -> int:
    """Replace the ProxyCommand child with a separately pinned jump SSH.

    The route file contains only a validated public endpoint. The jump
    askpass capability arrives in the parent SSH environment and is never
    written to disk or passed as an argument.
    """
    try:
        folder = Path(directory)
        info = folder.lstat()
        if (not folder.is_absolute() or not stat.S_ISDIR(info.st_mode) or
                info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
            return 1
        for name, mode in (("jump_route.json", 0o600), ("ssh_config_jump", 0o600),
                           ("askpass", 0o700)):
            item = folder / name
            meta = item.lstat()
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid() or
                    stat.S_IMODE(meta.st_mode) != mode or meta.st_nlink != 1):
                return 1
        route_path = folder / "jump_route.json"
        if route_path.stat().st_size > 1024:
            return 1
        route = json.loads(route_path.read_bytes())
        if (type(route) is not dict or set(route) != {"host", "port"} or
                not isinstance(route["host"], str) or not 1 <= len(route["host"]) <= 255 or
                any(ord(char) <= 32 or ord(char) >= 127 for char in route["host"]) or
                type(route["port"]) is not int or not 1 <= route["port"] <= 65535):
            return 1
        environment = os.environ.copy()
        jump_socket = environment.pop("SOVAGRID_WEB_AGENT_JUMP_ASKPASS_SOCKET", "")
        jump_nonce = environment.pop("SOVAGRID_WEB_AGENT_JUMP_ASKPASS_NONCE", "")
        if (jump_socket != str(folder / "jump.sock") or
                re.fullmatch(r"[0-9a-f]{32}", jump_nonce) is None):
            return 1
        environment["SOVAGRID_WEB_AGENT_ASKPASS_SOCKET"] = jump_socket
        environment["SOVAGRID_WEB_AGENT_ASKPASS_NONCE"] = jump_nonce
        environment["SSH_ASKPASS"] = str(folder / "askpass")
        environment["SSH_ASKPASS_REQUIRE"] = "force"
        environment.pop("SSH_AUTH_SOCK", None)
        host = route["host"]
        destination = (f"[{host}]:{route['port']}" if ":" in host else
                       f"{host}:{route['port']}")
        argv = ["/usr/bin/ssh", "-F", str(folder / "ssh_config_jump"), "-T",
                "-o", "BatchMode=no", "-o", "ClearAllForwardings=yes",
                "-W", destination, "sovagrid-target"]
        os.execve(argv[0], argv, environment)
    except (OSError, UnicodeError, ValueError, TypeError):
        return 1
    return 1


class PinnedTargetSSH:
    """Private transport context; use its options only while it is open."""

    def __init__(self, *, host: str, port: int, username: str, fingerprint: str,
                 method: str, password: str = "", private_key: str = "", passphrase: str = "",
                 jump: dict | None = None, target_host_key_blob: str = "",
                 runtime_root: Path = Path("/run"), require_root: bool = True,
                 scanner=_scan, peer_uid=_peer_uid, python: str = "/usr/bin/python3"):
        if require_root and (os.geteuid() != 0 or runtime_root != Path("/run")):
            raise TargetSSHError("Установщик Agent должен работать на хосте Hub от root.")
        if method not in ("password", "private_key") or not isinstance(password, str) or \
                not isinstance(private_key, str) or not isinstance(passphrase, str):
            raise TargetSSHError("Неверный способ SSH-входа.")
        if method == "password":
            if not password or len(password) > MAX_SECRET or private_key or passphrase:
                raise TargetSSHError("Введите пароль SSH.")
            secret = password
        else:
            if password or not private_key or len(private_key.encode("utf-8")) > 65536 or \
                    "\x00" in private_key or len(passphrase) > MAX_SECRET:
                raise TargetSSHError("Введите приватный SSH-ключ.")
            secret = passphrase
        self.alias = host_key_alias(fingerprint)
        self.jump_alias: str | None = None
        self._jump: dict | None = None
        self._jump_secret = ""
        self._jump_private_key = ""
        if jump is not None:
            expected = {"host", "port", "username", "method", "fingerprint",
                        "password", "private_key", "passphrase", "host_key_blob"}
            if type(jump) is not dict or set(jump) != expected or not isinstance(target_host_key_blob, str):
                raise TargetSSHError("Неверный промежуточный SSH-маршрут.")
            jump_method = jump["method"]
            jump_password, jump_key, jump_phrase = (jump[name] for name in
                                                    ("password", "private_key", "passphrase"))
            if jump_method not in ("password", "private_key") or not all(
                    isinstance(value, str) for value in (jump_password, jump_key, jump_phrase)):
                raise TargetSSHError("Неверный вход на промежуточный SSH-хост.")
            if jump_method == "password":
                if (not jump_password or len(jump_password.encode("utf-8")) > MAX_SECRET or
                        jump_key or jump_phrase):
                    raise TargetSSHError("Неверный пароль промежуточного SSH-хоста.")
                self._jump_secret = jump_password
            else:
                if (jump_password or not jump_key or len(jump_key.encode("utf-8")) > 65536 or
                        "\x00" in jump_key or len(jump_phrase.encode("utf-8")) > MAX_SECRET):
                    raise TargetSSHError("Неверный приватный ключ промежуточного SSH-хоста.")
                self._jump_secret = jump_phrase
                self._jump_private_key = jump_key
            self.jump_alias = host_key_alias(jump["fingerprint"])
            reviewed_key_blob(target_host_key_blob, fingerprint)
            reviewed_key_blob(jump["host_key_blob"], jump["fingerprint"])
            self._jump = {name: jump[name] for name in
                          ("host", "port", "username", "fingerprint", "method", "host_key_blob")}
        elif target_host_key_blob:
            raise TargetSSHError("Неверный подтверждённый SSH-маршрут.")
        # The Connect validator canonicalizes DNS/IPv6, username and port.
        from sovagrid_connect.core import ConnectionOptions
        try:
            self.options = ConnectionOptions(host=host, user=username, port=port,
                host_key_alias=self.alias,
                **({} if self._jump is None else {
                    "jump_host": self._jump["host"], "jump_port": self._jump["port"],
                    "jump_user": self._jump["username"],
                    "jump_host_key_alias": self.jump_alias})).validated()
        except (ValueError, OSError):
            raise TargetSSHError("Неверный адрес, порт или пользователь SSH.") from None
        self.fingerprint = fingerprint
        self.method = method
        self._private_key = private_key
        self._secret = secret
        self._runtime_root = runtime_root
        self._scanner = scanner
        self._target_host_key_blob = target_host_key_blob
        self._peer_uid = peer_uid
        self._python = python
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._broker: AskpassBroker | None = None
        self._jump_broker: AskpassBroker | None = None
        self.config_path: Path | None = None
        self.jump_config_path: Path | None = None
        self.jump_proxy_path: Path | None = None
        self.launcher_path: Path | None = None

    @property
    def broker(self) -> AskpassBroker:
        if self._broker is None:
            raise TargetSSHError("SSH-транспорт не открыт.")
        return self._broker

    @property
    def jump_broker(self) -> AskpassBroker:
        if self._jump_broker is None:
            raise TargetSSHError("Промежуточный SSH-транспорт не открыт.")
        return self._jump_broker

    def __enter__(self) -> "PinnedTargetSSH":
        if self._temporary is not None:
            raise TargetSSHError("SSH-транспорт уже открыт.")
        try:
            root = self._runtime_root
            info = root.stat()
            if not stat.S_ISDIR(info.st_mode) or (os.geteuid() == 0 and
                    (info.st_uid != 0 or info.st_mode & 0o022)):
                raise TargetSSHError("Небезопасный временный каталог SSH.")
            self._temporary = tempfile.TemporaryDirectory(prefix="sovagrid-web-agent-", dir=root)
            folder = Path(self._temporary.name)
            os.chmod(folder, 0o700)
            if self._jump is None:
                kind, blob = reviewed_public_key(
                    self._scanner(self.options.host, self.options.port), self.fingerprint)
            else:
                kind, blob = reviewed_key_blob(self._target_host_key_blob, self.fingerprint)
                jump_kind, jump_blob = reviewed_key_blob(
                    self._jump["host_key_blob"], self._jump["fingerprint"])
                # The intermediary is directly reachable from Hub. Confirm
                # its live key before making any authenticated connection.
                scanned_kind, scanned_blob = reviewed_public_key(
                    self._scanner(self.options.jump_host, self.options.jump_port),
                    self._jump["fingerprint"])
                if (jump_kind, jump_blob) != (scanned_kind, scanned_blob):
                    raise TargetSSHError("SSH-ключ промежуточного хоста изменился.")
                jump_known_hosts = folder / "known_hosts_jump"
                _write_private(jump_known_hosts,
                               f"{self.jump_alias} {jump_kind} {jump_blob}\n".encode("ascii"))
            known_hosts = folder / "known_hosts"
            _write_private(known_hosts, f"{self.alias} {kind} {blob}\n".encode("ascii"))
            identity = None
            if self.method == "private_key":
                identity = folder / "identity"
                _write_private(identity, self._private_key.encode("utf-8"))
                from sovagrid_connect.core import ConnectionOptions
                self.options = ConnectionOptions(**{**self.options.__dict__, "identity": str(identity)}).validated()
            from sovagrid_connect.core import _ssh_config
            from dataclasses import replace
            extra = (
                "Host *\n"
                f"    UserKnownHostsFile {shlex.quote(str(known_hosts))}\n"
                "    GlobalKnownHostsFile /dev/null\n"
                "    StrictHostKeyChecking yes\n"
                "    VerifyHostKeyDNS no\n"
                "    CanonicalizeHostname no\n"
                "    IdentityAgent none\n"
                "    NumberOfPasswordPrompts 1\n"
                "    ConnectionAttempts 1\n"
                + ("    PubkeyAuthentication no\n" if self.method == "password" else
                   "    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n")
            )
            direct_options = replace(self.options, jump_host=None, jump_user=None,
                                     jump_identity=None, jump_host_key_alias=None).validated()
            if self._jump is not None:
                jump_identity = None
                if self._jump["method"] == "private_key":
                    jump_identity = folder / "identity_jump"
                    _write_private(jump_identity, self._jump_private_key.encode("utf-8"))
                    self.options = replace(self.options, jump_identity=str(jump_identity)).validated()
                jump_options = self.options.__class__(host=self.options.jump_host,
                    user=self.options.jump_user, port=self.options.jump_port,
                    host_key_alias=self.jump_alias,
                    identity=str(jump_identity) if jump_identity is not None else None).validated()
                jump_extra = extra.replace(str(known_hosts), str(jump_known_hosts))
                if self._jump["method"] != self.method:
                    jump_extra = jump_extra.replace(
                        "    PubkeyAuthentication no\n" if self.method == "password" else
                        "    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n",
                        "    PubkeyAuthentication no\n" if self._jump["method"] == "password" else
                        "    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n")
                self.jump_config_path = folder / "ssh_config_jump"
                _write_private(self.jump_config_path,
                               (jump_extra + _ssh_config(jump_options)).encode("utf-8"))
                route = json.dumps({"host": self.options.host, "port": self.options.port},
                                   sort_keys=True, separators=(",", ":")).encode("utf-8")
                _write_private(folder / "jump_route.json", route + b"\n")
                self.jump_proxy_path = folder / "jump_proxy"
                proxy = (f"#!/bin/sh\nexec {shlex.quote(self._python)} -I "
                         f"{shlex.quote(str(Path(__file__).resolve()))} --jump-proxy "
                         f"{shlex.quote(str(folder))}\n")
                _write_private(self.jump_proxy_path, proxy.encode("utf-8"), 0o700)
            self.config_path = folder / "ssh_config"
            target_config = extra + _ssh_config(direct_options)
            if self.jump_proxy_path is not None:
                target_config += ("Host sovagrid-target\n"
                                  f"    ProxyCommand {shlex.quote(str(self.jump_proxy_path))}\n")
            _write_private(self.config_path, target_config.encode("utf-8"))
            self.launcher_path = folder / "askpass"
            launcher = (f"#!/bin/sh\nexec {shlex.quote(self._python)} -I "
                f"{shlex.quote(str(Path(__file__).resolve()))} --askpass \"$@\"\n")
            _write_private(self.launcher_path, launcher.encode("utf-8"), 0o700)
            self._broker = AskpassBroker(folder / "askpass.sock", self.method, self._secret,
                                        peer_uid=self._peer_uid)
            if self._jump is not None:
                self._jump_broker = AskpassBroker(folder / "jump.sock",
                    self._jump["method"], self._jump_secret, peer_uid=self._peer_uid)
            self._secret = ""
            self._private_key = ""
            self._jump_secret = self._jump_private_key = ""
            return self
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self._jump_broker is not None:
            self._jump_broker.close()
            self._jump_broker = None
        if self._broker is not None:
            self._broker.close()
            self._broker = None
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None
        self.config_path = self.launcher_path = self.jump_config_path = self.jump_proxy_path = None
        self._secret = self._private_key = self._jump_secret = self._jump_private_key = ""
        self._target_host_key_blob = ""

    def __exit__(self, *_exc) -> None:
        self.close()

    def target_rpc(self, options, *, progress=None):
        """Return the existing checked RPC with only its SSH transport replaced."""
        from sovagrid_connect.agent_rpc import AgentRPC
        if self.config_path is None or self.launcher_path is None or options != self.options:
            raise TargetSSHError("SSH-маршрут установки изменился.")
        rpc = AgentRPC(options, role="target", progress=progress)
        rpc._installer = _HeadlessInstaller(options, self, popen=rpc._spawn)
        return rpc


class _HeadlessInstaller:
    """Only the two methods AgentRPC uses from ServerInstaller."""

    def __init__(self, options, transport: PinnedTargetSSH, *, popen):
        self.options = options
        self.transport = transport
        self._popen = popen
        self._lock = threading.Lock()
        self._process = None

    @contextmanager
    def _session(self):
        if self.transport.config_path is None or self.transport.launcher_path is None:
            raise TargetSSHError("SSH-транспорт закрыт.")
        yield str(self.transport.config_path), str(self.transport.launcher_path)

    def _ssh(self, config: str, helper: str, command: str, *, input_file=None):
        from sovagrid_connect.installer import InstallError
        if config != str(self.transport.config_path) or helper != str(self.transport.launcher_path):
            raise InstallError("Неверная конфигурация SSH.")
        nonce = self.transport.broker.arm()
        try:
            jump_nonce = self.transport.jump_broker.arm() if self.transport._jump is not None else None
        except Exception:
            self.transport.broker.disarm()
            raise
        environment = os.environ.copy()
        environment.pop("SSH_AUTH_SOCK", None)
        environment["SSH_ASKPASS"] = helper
        environment["SSH_ASKPASS_REQUIRE"] = "force"
        environment["SOVAGRID_WEB_AGENT_ASKPASS_SOCKET"] = str(self.transport.broker.path)
        environment["SOVAGRID_WEB_AGENT_ASKPASS_NONCE"] = nonce
        if jump_nonce is not None:
            environment["SOVAGRID_WEB_AGENT_JUMP_ASKPASS_SOCKET"] = str(
                self.transport.jump_broker.path)
            environment["SOVAGRID_WEB_AGENT_JUMP_ASKPASS_NONCE"] = jump_nonce
        argv = ["/usr/bin/ssh", "-F", config, "-T", "-o", "BatchMode=no",
                "-o", "ClearAllForwardings=yes", "sovagrid-target", command]
        try:
            process = self._popen(
                argv, env=environment,
                stdin=input_file if input_file is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
            )
        except Exception:
            self.transport.broker.disarm()
            if jump_nonce is not None:
                self.transport.jump_broker.disarm()
            raise InstallError("OpenSSH не удалось запустить.") from None
        with self._lock:
            self._process = process
        return process


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--askpass":
        raise SystemExit(_askpass_client(sys.argv[2]))
    if len(sys.argv) == 3 and sys.argv[1] == "--jump-proxy":
        raise SystemExit(_jump_proxy_client(sys.argv[2]))
    raise SystemExit(1)
