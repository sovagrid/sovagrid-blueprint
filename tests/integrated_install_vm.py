#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Check an exact server bundle on a disposable Ubuntu GitHub Actions host."""

from __future__ import annotations

import hashlib
import grp
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import struct
import subprocess
import time
import urllib.request


SOURCE = Path("/opt/sovagrid-src")
ORIGIN = "http://127.0.0.1:8766"
SHA = re.compile(r"[0-9a-f]{64}\Z")
AGENT_SOCKET = Path("/run/sovagrid-agent-control/agent.sock")
IDLE_FIELDS = frozenset(("jobs_inflight", "file_operations", "terminal_sessions",
                         "upload_sessions", "network_checks", "probe_helpers"))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def _agent_property(name: str) -> str:
    result = subprocess.run(
        ["systemctl", "show", "-P", name, "sovagrid-agent.service"],
        check=True, capture_output=True, text=True, timeout=5)
    value = result.stdout.strip()
    require(bool(value) and "\n" not in value, "Agent systemd identity is invalid")
    return value


def _socket_line(connection: socket.socket, deadline: float, limit: int) -> bytes:
    line = bytearray()
    while len(line) < limit:
        remaining = deadline - time.monotonic()
        require(remaining > 0, "Agent quiescence handshake timed out")
        connection.settimeout(remaining)
        item = connection.recv(1)
        require(bool(item), "Agent quiescence socket closed unexpectedly")
        line.extend(item)
        if item == b"\n":
            return bytes(line)
    raise RuntimeError("Agent quiescence reply is too large")


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "Agent quiescence acknowledgment has duplicate fields")
        value[key] = item
    return value


def verify_agent_quiescence() -> None:
    """Exercise the real installed socket without changing Agent state."""
    started = time.monotonic()
    require(_agent_property("User") == "sovagrid" and
            _agent_property("Group") == "sovagrid", "Agent systemd account changed")
    uid = pwd.getpwnam("sovagrid").pw_uid
    gid = grp.getgrnam("sovagrid").gr_gid
    pid_raw = _agent_property("MainPID")
    require(pid_raw.isascii() and pid_raw.isdecimal() and int(pid_raw) > 1,
            "Agent systemd PID is invalid")
    pid = int(pid_raw)
    while True:
        try:
            parent, endpoint = AGENT_SOCKET.parent.lstat(), AGENT_SOCKET.lstat()
            break
        except FileNotFoundError:
            require(time.monotonic() - started < 8,
                    "Agent quiescence socket did not appear")
            time.sleep(0.1)
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == uid and
            stat.S_IMODE(parent.st_mode) == 0o700 and
            stat.S_ISSOCK(endpoint.st_mode) and endpoint.st_uid == uid and
            stat.S_IMODE(endpoint.st_mode) == 0o600 and endpoint.st_nlink == 1,
            "Agent quiescence socket permissions are invalid")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(str(AGENT_SOCKET))
        raw_peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                         struct.calcsize("3i"))
        require(struct.unpack("3i", raw_peer) == (pid, uid, gid),
                "Agent quiescence peer differs from systemd")
        connection.sendall(b"QUIESCE 1\n")
        raw = _socket_line(connection, time.monotonic() + 15, 512)
        try:
            response = json.loads(raw, object_pairs_hook=_unique_object)
        except (ValueError, UnicodeError) as exc:
            raise RuntimeError("Agent quiescence acknowledgment is invalid") from exc
        require(isinstance(response, dict) and
                set(response) == IDLE_FIELDS | {"protocol", "state", "pid", "epoch"} and
                type(response["protocol"]) is int and response["protocol"] == 1 and
                response["state"] == "idle" and
                type(response["pid"]) is int and response["pid"] == pid and
                isinstance(response["epoch"], str) and
                re.fullmatch(r"[0-9a-f]{32}", response["epoch"]) is not None and
                all(type(response[field]) is int and response[field] == 0
                    for field in IDLE_FIELDS),
                "Agent did not acknowledge an idle state")
        connection.sendall(b"PING 1\n")
        require(_socket_line(connection, time.monotonic() + 3, 64) ==
                b"PONG 1 " + response["epoch"].encode("ascii") + b"\n",
                "Agent quiescence heartbeat failed")
        connection.sendall(b"RELEASE 1\n")
        require(_socket_line(connection, time.monotonic() + 3, 64) == b"RELEASED 1\n",
                "Agent quiescence release failed")
    require(_agent_property("MainPID") == pid_raw,
            "Agent restarted during quiescence verification")


def request(method: str, path: str, *, body: dict | None = None,
            token: str | None = None) -> tuple[int, dict]:
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request(ORIGIN + path, data=data, headers=headers, method=method)
    with opener.open(req, timeout=10) as response:
        require(response.status in (200, 201), "Hub returned an unexpected status")
        raw = response.read(8193)
        require(len(raw) <= 8192, "Hub reply is unexpectedly large")
        return response.status, json.loads(raw)


def main() -> None:
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("RUNNER_OS") == "Linux" and os.geteuid() == 0,
            "This check runs only as root on a disposable Ubuntu CI host")
    expected = os.environ.get("SOVAGRID_EXPECTED_MANIFEST", "")
    require(SHA.fullmatch(expected) is not None, "Missing exact bundle pin")
    manifest = SOURCE / "sovagrid-bundle.json"
    require(manifest.is_file() and
            hashlib.sha256(manifest.read_bytes()).hexdigest() == expected,
            "Installed source differs from the packaged manifest")
    agent = subprocess.run(["systemctl", "is-active", "--quiet", "sovagrid-agent.service"],
                           check=False)
    require(agent.returncode == 0, "Host Agent is not active")
    verify_agent_quiescence()
    hub = subprocess.run(["docker", "compose", "--env-file", "/etc/sovagrid/deploy.env",
                          "-f", str(SOURCE / "sovagrid-blueprint/deploy/compose.yaml"),
                          "ps", "--status", "running", "--quiet", "hub"],
                         check=True, capture_output=True, text=True)
    require(bool(hub.stdout.strip()), "Hub container is not running")
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(
            ORIGIN + "/sovagrid/monitoring/", timeout=10) as response:
        require(response.status == 200 and b"SovaGrid" in response.read(131073),
                "Web panel did not load")

    password = Path("/etc/sovagrid/admin-password").read_text(encoding="utf-8").rstrip("\n")
    status, login = request("POST", "/api/v1/session",
                            body={"username": "admin", "password": password})
    require(status == 200 and isinstance(login.get("token"), str),
            "Could not authenticate to Hub")
    status, server = request("POST", "/api/v1/servers",
                             body={"name": "integrated-install-probe"}, token=login["token"])
    require(status == 201 and isinstance(server.get("id"), str) and
            isinstance(server.get("agent_token"), str), "Could not create Agent identity")
    status, proof = request("GET", f"/api/v1/servers/{server['id']}/agent-compatibility",
                            token=server["agent_token"])
    require(status == 200 and proof == {"protocol": 1, "bundle_manifest_sha256": expected},
            "Running Hub image does not report this verified server bundle")
    print("INTEGRATED_SERVER_BUNDLE_VERIFIED", flush=True)


if __name__ == "__main__":
    main()
