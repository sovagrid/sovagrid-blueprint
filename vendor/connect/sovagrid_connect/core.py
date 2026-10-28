# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Validated, temporary OpenSSH local forwarding for the SovaGrid panel."""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener


class TunnelError(RuntimeError):
    """The requested tunnel could not be created or verified."""


_USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_SAFE_CONFIG_PATH = re.compile(r"[A-Za-z0-9_./:\\-]+\Z")
_BOOTSTRAP_PASSWORD = re.compile(r"[A-Za-z0-9_-]{20,128}\Z")
_PANEL_PATH = re.compile(r"/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/){1,3}\Z")
_BOOTSTRAP_COMMAND = "head -c 257 /etc/sovagrid/admin-password"
_BOOTSTRAP_OUTPUT_LIMIT = 258
_HUB_GRANT_COMMAND = (
    "docker compose --env-file /etc/sovagrid/deploy.env "
    "-f /opt/sovagrid-src/sovagrid-blueprint/deploy/compose.yaml "
    "run --rm --no-deps -T --entrypoint python3 hub "
    "-m sovagrid_hub --db /data/hub.sqlite ssh-grant"
)
_SSH_GRANT_COMMAND = "sh -c " + shlex.quote(
    'if [ "$(id -u)" = 0 ]; then exec ' + _HUB_GRANT_COMMAND +
    '; fi; exec sudo -n ' + _HUB_GRANT_COMMAND
)
_SSH_GRANT_OUTPUT_LIMIT = 513


def _host(value: str, field: str) -> str:
    host = value.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host or any(c in host for c in "\r\n\t\x00 /\\@'\"`$;|&<>%"):
        raise ValueError(f"{field}: use a DNS name or IP address")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        ascii_host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"{field}: invalid DNS name") from exc
    if len(ascii_host) > 253 or not all(_LABEL.fullmatch(label) for label in ascii_host.split(".")):
        raise ValueError(f"{field}: invalid DNS name")
    return ascii_host


def _user(value: str, field: str) -> str:
    if not _USER.fullmatch(value):
        raise ValueError(f"{field}: invalid SSH user name")
    return value


def _port(value: int, field: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not (0 if allow_zero else 1) <= value <= 65535:
        raise ValueError(f"{field}: expected port {0 if allow_zero else 1}–65535")
    return value


def _identity(value: str | None, field: str) -> str | None:
    if not value:
        return None
    try:
        path = Path(value).expanduser().resolve()
    except RuntimeError as exc:
        raise ValueError(f"{field}: cannot expand key path") from exc
    if not path.is_file():
        raise ValueError(f"{field}: file does not exist: {path}")
    return path.as_posix()


def _config_word(value: str) -> str:
    if any(c in value for c in "\r\n\x00"):
        raise ValueError("SSH configuration value contains a control character")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


@dataclass(frozen=True)
class ConnectionOptions:
    host: str
    user: str
    port: int = 22
    jump_host: str | None = None
    jump_user: str | None = None
    jump_port: int = 22
    identity: str | None = None
    jump_identity: str | None = None
    host_key_alias: str | None = None
    jump_host_key_alias: str | None = None
    local_port: int = 0
    remote_port: int = 8766
    ssh_executable: str = "ssh"

    def validated(self) -> "ConnectionOptions":
        if self.jump_user and not self.jump_host:
            raise ValueError("jump_user requires jump_host")
        if self.jump_identity and not self.jump_host:
            raise ValueError("jump_identity requires jump_host")
        if self.jump_host_key_alias and not self.jump_host:
            raise ValueError("jump_host_key_alias requires jump_host")
        if not self.ssh_executable or any(c in self.ssh_executable for c in "\r\n\x00"):
            raise ValueError("invalid SSH executable")
        return ConnectionOptions(
            host=_host(self.host, "host"),
            user=_user(self.user, "user"),
            port=_port(self.port, "port"),
            jump_host=_host(self.jump_host, "jump_host") if self.jump_host else None,
            jump_user=_user(self.jump_user or self.user, "jump_user") if self.jump_host else None,
            jump_port=_port(self.jump_port, "jump_port"),
            identity=_identity(self.identity, "identity"),
            jump_identity=_identity(self.jump_identity, "jump_identity"),
            host_key_alias=_host(self.host_key_alias, "host_key_alias") if self.host_key_alias else None,
            jump_host_key_alias=_host(self.jump_host_key_alias, "jump_host_key_alias")
            if self.jump_host_key_alias else None,
            local_port=_port(self.local_port, "local_port", allow_zero=True),
            remote_port=_port(self.remote_port, "remote_port"),
            ssh_executable=self.ssh_executable,
        )


def _ssh_config(options: ConnectionOptions, *, batch_mode: bool = False, confirm_host_keys: bool = False) -> str:
    # One generated config is passed with -F. ProxyJump invokes its helper with
    # the same -F, so strict host key policy covers both SSH connections.
    lines = [
        "Host *",
        f"    StrictHostKeyChecking {'ask' if confirm_host_keys else 'yes'}",
        "    FingerprintHash sha256",
        "    UpdateHostKeys no",
        "    ForwardAgent no",
        "    ForwardX11 no",
        "    PermitLocalCommand no",
        "    ControlMaster no",
        "    ConnectTimeout 10",
        "    ServerAliveInterval 15",
        "    ServerAliveCountMax 3",
        "    ExitOnForwardFailure yes",
        "",
    ]
    if batch_mode:
        lines.insert(2, "    BatchMode yes")
    if options.jump_host:
        lines.extend(
            [
                "Host sovagrid-jump",
                f"    HostName {options.jump_host}",
                f"    User {options.jump_user}",
                f"    Port {options.jump_port}",
            ]
        )
        if options.jump_identity:
            lines.extend(
                [f"    IdentityFile {_config_word(options.jump_identity)}", "    IdentitiesOnly yes"]
            )
        if options.jump_host_key_alias:
            lines.append(f"    HostKeyAlias {options.jump_host_key_alias}")
        lines.append("")
    lines.extend(
        [
            "Host sovagrid-target",
            f"    HostName {options.host}",
            f"    User {options.user}",
            f"    Port {options.port}",
        ]
    )
    if options.jump_host:
        lines.append("    ProxyJump sovagrid-jump")
    if options.host_key_alias:
        lines.append(f"    HostKeyAlias {options.host_key_alias}")
    if options.identity:
        lines.extend([f"    IdentityFile {_config_word(options.identity)}", "    IdentitiesOnly yes"])
    return "\n".join(lines) + "\n"


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _require_free_port(port: int) -> None:
    # A response from an occupied loopback port is not proof that SSH owns it.
    # In particular, a fake panel could otherwise satisfy _panel_ready while
    # SSH is still waiting for a password or key passphrase.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", port))
    except OSError as exc:
        raise TunnelError(f"Local port {port} is already in use; choose another port") from exc


def _windows_short_path(path: str) -> str | None:
    if os.name != "nt":
        return None
    import ctypes

    buffer = ctypes.create_unicode_buffer(32768)
    get_short_path = ctypes.windll.kernel32.GetShortPathNameW
    get_short_path.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
    get_short_path.restype = ctypes.c_uint
    length = get_short_path(path, buffer, len(buffer))
    return buffer.value if 0 < length < len(buffer) else None


def _proxy_safe_path(path: str) -> str | None:
    # OpenSSH's ProxyJump helper builds a command string containing -F. Native
    # Windows paths contain backslashes even when every directory is safe;
    # OpenSSH accepts forward slashes for those paths.
    normalized = path.replace("\\", "/")
    return normalized if _SAFE_CONFIG_PATH.fullmatch(normalized) else None


def _safe_config_directory() -> tuple[tempfile.TemporaryDirectory[str], str]:
    candidates: list[str | None] = []
    if os.name == "posix" and os.path.isdir("/tmp") and os.access("/tmp", os.W_OK):
        candidates.append("/tmp")
    candidates.append(None)
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot")
        if system_root:
            candidates.append(os.path.join(system_root, "Temp"))
    for root in candidates:
        try:
            directory = tempfile.TemporaryDirectory(prefix="sovagrid-connect-", dir=root)
        except OSError:
            continue
        path = os.path.join(directory.name, "ssh_config")
        safe_path = _proxy_safe_path(path)
        short_directory = _windows_short_path(directory.name) if os.name == "nt" and safe_path is None else None
        if safe_path is None and short_directory:
            safe_path = _proxy_safe_path(os.path.join(short_directory, "ssh_config"))
        if safe_path:
            return directory, safe_path
        directory.cleanup()
    raise TunnelError("No safe temporary path for OpenSSH ProxyJump; set TMPDIR/TEMP to a simple path")


class Tunnel:
    """Owns the SSH child, its temporary config, and its loopback port."""

    def __init__(
        self,
        options: ConnectionOptions,
        *,
        batch_mode: bool = False,
        gui_prompts: bool = False,
        popen: Callable[..., subprocess.Popen] = subprocess.Popen,
    ) -> None:
        if batch_mode and gui_prompts:
            raise ValueError("GUI prompts require BatchMode=no")
        self.options = options.validated()
        self.batch_mode = batch_mode
        self.gui_prompts = gui_prompts
        self._popen = popen
        self._process: subprocess.Popen | None = None
        self._directory: tempfile.TemporaryDirectory[str] | None = None
        self._ssh_log: str | None = None
        self._askpass_path: str | None = None
        self._bootstrap_lock = threading.Lock()
        self._bootstrap_process: subprocess.Popen | None = None
        self.local_port: int | None = None
        self._panel_path = "/sovagrid/monitoring/"

    @property
    def url(self) -> str:
        if self.local_port is None:
            raise TunnelError("Tunnel has not started")
        return f"http://127.0.0.1:{self.local_port}/"

    @property
    def panel_url(self) -> str:
        # The origin remains separate: Hub API and one-use SSH grant requests
        # still use absolute /api/v1 paths on the same loopback listener.
        return self.url.rstrip("/") + self._panel_path

    @property
    def alive(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def _write_config(self) -> str:
        # OpenSSH turns ProxyJump into a proxy command containing the -F path.
        # Keep that path free of shell metacharacters, including spaces.
        directory, safe_path = _safe_config_directory()
        path = os.path.join(directory.name, "ssh_config")
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as config:
                config.write(_ssh_config(
                    self.options, batch_mode=self.batch_mode, confirm_host_keys=self.gui_prompts
                ))
        except BaseException:
            directory.cleanup()
            raise
        self._directory = directory
        return safe_path

    def _panel_ready(self) -> bool:
        assert self.local_port is not None
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, *_args, **_kwargs):
                return None

        opener = build_opener(ProxyHandler({}), NoRedirect())
        base = f"http://127.0.0.1:{self.local_port}"
        try:
            with opener.open(base + "/healthz", timeout=0.6) as response:
                if response.status != 200:
                    return False
                health = json.loads(response.read(512))
            if not isinstance(health, dict) or health.get("ok") is not True:
                return False
            # New Hubs advertise the active route without requiring login.
            # A 503 means initialization is still in progress. Only a 404 is
            # the old-Hub signal that permits legacy path probing.
            try:
                with opener.open(base + "/api/v1/panel-location", timeout=0.6) as response:
                    if response.status != 200 or not response.headers.get("Content-Type", "").startswith("application/json"):
                        return False
                    raw = response.read(513)
                if len(raw) > 512:
                    return False
                location = json.loads(raw)
                if not isinstance(location, dict) or set(location) != {"panel_path"}:
                    return False
                advertised = location["panel_path"]
                if (not isinstance(advertised, str) or len(advertised) > 96 or
                        _PANEL_PATH.fullmatch(advertised) is None or
                        advertised.split("/")[1] in {"api", "healthz"}):
                    return False
                paths = (advertised,)
            except HTTPError as error:
                code = error.code
                error.close()
                if code != 404:
                    return False
                paths = ("/sovagrid/monitoring/", "/")
            # A legacy Web image serves index.html for every unknown path.
            # Its apparent 200 at the new prefix is not a usable panel: the
            # relative assets would still resolve to missing files. Verify the
            # manifest at the same prefix before choosing the browser URL.
            for path in paths:
                try:
                    with opener.open(base + path, timeout=0.6) as response:
                        if response.status != 200:
                            continue
                        page = response.read(16384)
                    if b"SovaGrid" not in page:
                        continue
                    with opener.open(base + path + "manifest.webmanifest", timeout=0.6) as response:
                        if response.status != 200:
                            continue
                        manifest = json.loads(response.read(8192))
                    if isinstance(manifest, dict) and isinstance(manifest.get("name"), str) and \
                            "SovaGrid" in manifest["name"]:
                        self._panel_path = path
                        return True
                except HTTPError as error:
                    error.close()
                    continue
                except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
                    continue
            return False
        except HTTPError as error:
            error.close()
            return False
        except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
            return False

    def _forward_ready(self) -> bool:
        # OpenSSH only reports the listening forward after authenticating and
        # binding the requested port. A lookalike HTTP listener cannot supply
        # this private OpenSSH readiness signal.
        if self._ssh_log is None or self.local_port is None:
            return False
        try:
            with open(self._ssh_log, "rb") as log:
                data = log.read(131072)
        except OSError:
            return False
        marker = f"Local forwarding listening on 127.0.0.1 port {self.local_port}.".encode()
        return b"Authenticated to " in data and marker in data

    def start(self, timeout: float = 120.0) -> "Tunnel":
        if self._process is not None:
            raise TunnelError("Tunnel has already started")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        ssh = shutil.which(self.options.ssh_executable)
        if ssh is None:
            raise TunnelError("OpenSSH executable not found; install OpenSSH and add ssh to PATH")
        try:
            self.local_port = self.options.local_port or _available_port()
            _require_free_port(self.local_port)
            config = self._write_config()
            assert self._directory is not None
            self._ssh_log = os.path.join(self._directory.name, "ssh_log")
            descriptor = os.open(self._ssh_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            forwarding = f"127.0.0.1:{self.local_port}:127.0.0.1:{self.options.remote_port}"
            argv = [
                ssh,
                "-F",
                config,
                "-v",
                "-E",
                self._ssh_log,
                "-N",
                "-T",
                "-o",
                f"BatchMode={'yes' if self.batch_mode else 'no'}",
                "-o",
                "ConnectTimeout=10",
                "-L",
                forwarding,
                "sovagrid-target",
            ]
            if self.gui_prompts:
                from .askpass import helper_path

                env = os.environ.copy()
                self._askpass_path = helper_path(self._directory.name)
                env["SSH_ASKPASS"] = self._askpass_path
                env["SSH_ASKPASS_REQUIRE"] = "force"
                # SSH passes each question to a separate GUI helper. The secret
                # travels only over the helper's stdout pipe back to OpenSSH.
                self._process = self._popen(
                    argv, env=env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            else:
                # In CLI mode stderr and the controlling terminal remain attached,
                # so OpenSSH can ask for a password or key passphrase itself.
                self._process = self._popen(argv, stdin=None, stdout=subprocess.DEVNULL, stderr=None)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if self._process.poll() is not None:
                    raise TunnelError(
                        f"SSH exited before the panel was ready (code {self._process.returncode}); "
                        "check host keys, credentials, and port forwarding"
                    )
                if self._forward_ready() and self._panel_ready() and self._process.poll() is None:
                    return self
                time.sleep(0.15)
            raise TunnelError("SSH forwarding was not confirmed or the SovaGrid panel did not answer /healthz and /sovagrid/monitoring/")
        except BaseException:
            self.close()
            raise

    def wait(self, interval: float = 0.5) -> int:
        if self._process is None:
            raise TunnelError("Tunnel has not started")
        while self._process.poll() is None:
            time.sleep(interval)
        return self._process.returncode

    def read_bootstrap_password(self, timeout: float = 30.0) -> str:
        """Read the installer-generated Hub password over a separate verified SSH session.

        Only the fixed command is sent remotely. Its result travels via a pipe,
        never command arguments, environment variables, SSH logs, or a local file.
        The GUI must discard the returned value when its tunnel disconnects.
        """
        if not self.gui_prompts:
            raise TunnelError("Initial password retrieval is only available in the GUI")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        with self._bootstrap_lock:
            if not self.alive or self._directory is None:
                raise TunnelError("Connect to the panel before reading the initial password")
            if self._bootstrap_process is not None:
                raise TunnelError("Initial password retrieval is already running")
            ssh = shutil.which(self.options.ssh_executable)
            if ssh is None:
                raise TunnelError("OpenSSH executable not found")
            env = os.environ.copy()
            assert self._askpass_path is not None
            env["SSH_ASKPASS"] = self._askpass_path
            env["SSH_ASKPASS_REQUIRE"] = "force"
            argv = [
                ssh, "-F", os.path.join(self._directory.name, "ssh_config"),
                "-T", "-o", "BatchMode=no", "-o", "ConnectTimeout=10",
                "sovagrid-target", _BOOTSTRAP_COMMAND,
            ]
            try:
                process = self._popen(
                    argv, env=env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    bufsize=0,
                )
            except OSError as exc:
                raise TunnelError("Could not start SSH to read the initial password") from exc
            self._bootstrap_process = process
        result: list[bytes] = []
        read_errors: list[BaseException] = []
        read_done = threading.Event()

        def read_bounded_stdout() -> None:
            try:
                assert process.stdout is not None
                output = bytearray()
                while len(output) < _BOOTSTRAP_OUTPUT_LIMIT:
                    chunk = process.stdout.read(_BOOTSTRAP_OUTPUT_LIMIT - len(output))
                    if not chunk:
                        break
                    output.extend(chunk)
                result.append(bytes(output))
            except BaseException as exc:
                read_errors.append(exc)
            finally:
                read_done.set()

        reader = threading.Thread(target=read_bounded_stdout, daemon=True)
        reader.start()
        deadline = time.monotonic() + timeout
        try:
            if not read_done.wait(max(0, deadline - time.monotonic())):
                raise TunnelError("Timed out while reading the initial password")
            if read_errors:
                raise TunnelError("Could not read the initial password from SSH") from read_errors[0]
            output = result[0]
            if len(output) >= _BOOTSTRAP_OUTPUT_LIMIT:
                raise TunnelError("The initial password response is too large")
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                raise TunnelError("Timed out while reading the initial password") from exc
            if process.returncode != 0:
                raise TunnelError(
                    "The SSH user cannot read the initial password, or SSH authentication failed. "
                    "Use a login with access to /etc/sovagrid/admin-password (usually root)."
                )
            try:
                password = output.decode("ascii").rstrip("\r\n")
            except UnicodeDecodeError as exc:
                raise TunnelError("The initial password file has an unexpected format") from exc
            if not _BOOTSTRAP_PASSWORD.fullmatch(password):
                raise TunnelError("The initial password file has an unexpected format")
            return password
        finally:
            if process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
            reader.join(timeout=1)
            if not reader.is_alive() and process.stdout is not None:
                process.stdout.close()
            with self._bootstrap_lock:
                if self._bootstrap_process is process:
                    self._bootstrap_process = None

    def request_ssh_grant(self, timeout: float = 40.0):
        """Get a short-lived local Hub grant through the already verified SSH route.

        Docker Compose must run on the destination with root authority; the
        grant travels in a bounded private stdout pipe, never command args.
        """
        from .ssh_grant import parse_grant

        if not self.gui_prompts or not self.alive or self._directory is None:
            raise TunnelError("Connect to the panel before requesting SSH login")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        with self._bootstrap_lock:
            if self._bootstrap_process is not None:
                raise TunnelError("An SSH login request is already running")
            ssh = shutil.which(self.options.ssh_executable)
            if ssh is None:
                raise TunnelError("OpenSSH executable not found")
            env = os.environ.copy()
            assert self._askpass_path is not None
            env["SSH_ASKPASS"] = self._askpass_path
            env["SSH_ASKPASS_REQUIRE"] = "force"
            argv = [
                ssh, "-F", os.path.join(self._directory.name, "ssh_config"),
                "-T", "-o", "BatchMode=no", "-o", "ConnectTimeout=10",
                "sovagrid-target", _SSH_GRANT_COMMAND,
            ]
            try:
                process = self._popen(
                    argv, env=env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
                )
            except OSError as exc:
                raise TunnelError("Could not start SSH login request") from exc
            self._bootstrap_process = process
        result: list[bytes] = []
        read_done = threading.Event()

        def read_bounded() -> None:
            try:
                assert process.stdout is not None
                output = bytearray()
                while len(output) < _SSH_GRANT_OUTPUT_LIMIT:
                    chunk = process.stdout.read(_SSH_GRANT_OUTPUT_LIMIT - len(output))
                    if not chunk:
                        break
                    output.extend(chunk)
                result.append(bytes(output))
            finally:
                read_done.set()

        reader = threading.Thread(target=read_bounded, daemon=True)
        reader.start()
        deadline = time.monotonic() + timeout
        try:
            if not read_done.wait(max(0, deadline - time.monotonic())):
                raise TunnelError("SSH login request timed out")
            if not result or len(result[0]) >= _SSH_GRANT_OUTPUT_LIMIT:
                raise TunnelError("SSH login response is too large or unreadable")
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                raise TunnelError("SSH login request timed out") from exc
            if process.returncode != 0:
                raise TunnelError("SSH login is unavailable; use this server's Hub account")
            try:
                return parse_grant(result[0])
            except ValueError as exc:
                raise TunnelError("SSH login response is invalid") from exc
        finally:
            if process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
            reader.join(timeout=1)
            if not reader.is_alive() and process.stdout is not None:
                process.stdout.close()
            with self._bootstrap_lock:
                if self._bootstrap_process is process:
                    self._bootstrap_process = None

    def close(self) -> None:
        with self._bootstrap_lock:
            bootstrap_process = self._bootstrap_process
            self._bootstrap_process = None
        if bootstrap_process is not None and bootstrap_process.poll() is None:
            try:
                bootstrap_process.terminate()
            except ProcessLookupError:
                pass
        process = self._process
        self._process = None
        try:
            if process is not None and process.poll() is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        finally:
            if self._directory is not None:
                self._directory.cleanup()
                self._directory = None
            self._ssh_log = None
            self._askpass_path = None
            self.local_port = None

    def __enter__(self) -> "Tunnel":
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.close()
