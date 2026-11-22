# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Validate SSH route endpoints and render an isolated OpenSSH config."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import ipaddress
import json
from pathlib import Path
import re


_USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
MAX_SSH_HOPS = 16


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
class SSHJumpHost:
    """One intermediate OpenSSH endpoint with its own local key settings."""

    host: str
    user: str
    port: int = 22
    identity: str | None = None
    host_key_alias: str | None = None

    def validated(self, number: int) -> SSHJumpHost:
        name = f"SSH hop {number}"
        return SSHJumpHost(
            _host(self.host, f"{name} host"),
            _user(self.user, f"{name} user"),
            _port(self.port, f"{name} port"),
            _identity(self.identity, f"{name} identity"),
            _host(self.host_key_alias, f"{name} host key alias") if self.host_key_alias else None,
        )


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

    @property
    def ssh_hops(self) -> tuple[SSHJumpHost, ...]:
        """Expose an ordered route while preserving the existing v1 fields."""
        if not self.jump_host:
            return ()
        return (SSHJumpHost(self.jump_host, self.jump_user or self.user, self.jump_port,
                            self.jump_identity, self.jump_host_key_alias),)

    def validated(self) -> "ConnectionOptions":
        if self.jump_user and not self.jump_host:
            raise ValueError("jump_user requires jump_host")
        if self.jump_identity and not self.jump_host:
            raise ValueError("jump_identity requires jump_host")
        if self.jump_host_key_alias and not self.jump_host:
            raise ValueError("jump_host_key_alias requires jump_host")
        if not self.ssh_executable or any(c in self.ssh_executable for c in "\r\n\x00"):
            raise ValueError("invalid SSH executable")
        return replace(self,
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


@dataclass(frozen=True)
class ChainedConnectionOptions(ConnectionOptions):
    """Local OpenSSH configuration. The v1 enrollment record stays unchanged."""

    hops: tuple[SSHJumpHost, ...] = ()

    @property
    def ssh_hops(self) -> tuple[SSHJumpHost, ...]:
        return self.hops

    def validated(self) -> ChainedConnectionOptions:
        if (self.jump_host is not None or self.jump_user is not None or self.jump_identity is not None
                or self.jump_host_key_alias is not None or self.jump_port != 22):
            raise ValueError("Cannot combine an SSH chain with legacy jump fields")
        if not isinstance(self.hops, tuple) or not 2 <= len(self.hops) <= MAX_SSH_HOPS:
            raise ValueError(f"An SSH chain must contain between 2 and {MAX_SSH_HOPS} hops")
        if not all(isinstance(hop, SSHJumpHost) for hop in self.hops):
            raise ValueError("Invalid SSH chain node")
        options = super().validated()
        return replace(options, hops=tuple(hop.validated(index) for index, hop in enumerate(self.hops, 1)))


def connection_with_ssh_hops(options: ConnectionOptions, hops: tuple[SSHJumpHost, ...]) -> ConnectionOptions:
    """Use the existing options model for a direct connection or a single hop."""
    target = dict(host=options.host, user=options.user, port=options.port,
                  identity=options.identity, host_key_alias=options.host_key_alias,
                  local_port=options.local_port, remote_port=options.remote_port,
                  ssh_executable=options.ssh_executable)
    if not hops:
        return ConnectionOptions(**target)
    if len(hops) == 1:
        hop = hops[0]
        return ConnectionOptions(**target, jump_host=hop.host, jump_user=hop.user, jump_port=hop.port,
                                 jump_identity=hop.identity, jump_host_key_alias=hop.host_key_alias)
    return ChainedConnectionOptions(**target, hops=hops)


def display_ssh_endpoint(host: str, port: int) -> str:
    address = f"[{host}]" if ":" in host else host
    return f"{address}:{port}"


def describe_ssh_route(options: ConnectionOptions) -> str:
    target = f"{options.user}@{display_ssh_endpoint(options.host, options.port)}"
    hops = options.ssh_hops
    if not hops:
        return target
    return target + " через " + " → ".join(f"{hop.user}@{display_ssh_endpoint(hop.host, hop.port)}" for hop in hops)


def _host_key_alias(node: SSHJumpHost, prefix: tuple[SSHJumpHost, ...]) -> str | None:
    if node.host_key_alias or not prefix:
        return node.host_key_alias
    # An address behind a jump may refer to a different host through another
    # path. Keep trust for each network path independent of its form label.
    route = [(hop.host, hop.port, hop.user, hop.host_key_alias) for hop in prefix]
    value = json.dumps([route, node.host, node.port], separators=(",", ":")).encode("ascii")
    return "sovagrid-route-" + hashlib.sha256(value).hexdigest()


def _ssh_host_config(alias: str, node: SSHJumpHost, *, host_key_alias: str | None,
                     proxy_jump: str | None = None) -> list[str]:
    lines = [f"Host {alias}", f"    HostName {node.host}", f"    User {node.user}", f"    Port {node.port}"]
    if proxy_jump:
        lines.append(f"    ProxyJump {proxy_jump}")
    if host_key_alias:
        lines.append(f"    HostKeyAlias {host_key_alias}")
    if node.identity:
        lines.extend([f"    IdentityFile {_config_word(node.identity)}", "    IdentitiesOnly yes"])
    return lines


def _ssh_config(options: ConnectionOptions, *, batch_mode: bool = False, confirm_host_keys: bool = False) -> str:
    # One generated config is passed with -F. ProxyJump invokes its helper with
    # the same -F, so strict host key policy covers each SSH connection.
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
    hops = options.ssh_hops
    chained = len(hops) > 1
    aliases = [f"sovagrid-jump-{number}" if chained else "sovagrid-jump" for number in range(1, len(hops) + 1)]
    for index, (alias, hop) in enumerate(zip(aliases, hops)):
        host_key_alias = _host_key_alias(hop, hops[:index]) if chained else hop.host_key_alias
        lines.extend(_ssh_host_config(alias, hop, host_key_alias=host_key_alias))
        lines.append("")
    target = SSHJumpHost(options.host, options.user, options.port, options.identity, options.host_key_alias)
    host_key_alias = _host_key_alias(target, hops) if chained else target.host_key_alias
    lines.extend(_ssh_host_config("sovagrid-target", target, host_key_alias=host_key_alias,
                                  proxy_jump=",".join(aliases) or None))
    return "\n".join(lines) + "\n"
