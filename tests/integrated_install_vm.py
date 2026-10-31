#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Check an exact server bundle on a disposable Ubuntu GitHub Actions host."""

from __future__ import annotations

import hashlib
import fcntl
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


def verify_broker_runtime_locks_after_reboot() -> None:
    """Simulate empty /run locks and inspect the real broker mount namespace."""
    service = "sovagrid-hub-backup-control.service"
    subprocess.run(["systemctl", "stop", service], check=True, timeout=20)
    held = []
    try:
        for filename in ("sovagrid-installation.lock", "sovagrid-promotion.lock"):
            target = Path("/run") / filename
            descriptor = os.open(target, os.O_RDWR | os.O_NOFOLLOW)
            held.append(descriptor)
            value = os.fstat(descriptor)
            require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and
                    (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode), value.st_size) ==
                    (0, 0, 0o600, 0), "Unsafe runtime lock in disposable VM")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for descriptor, filename in zip(held, ("sovagrid-installation.lock", "sovagrid-promotion.lock")):
            target = Path("/run") / filename
            value, observed = os.fstat(descriptor), target.lstat()
            require((value.st_dev, value.st_ino) == (observed.st_dev, observed.st_ino),
                    "Runtime lock changed before reboot simulation")
            target.unlink()
    finally:
        for descriptor in held:
            os.close(descriptor)
    subprocess.run(["systemctl", "start", service], check=True, timeout=20)
    deadline = time.monotonic() + 8
    while True:
        result = subprocess.run(["systemctl", "show", "-P", "MainPID", service],
                                check=True, capture_output=True, text=True, timeout=5)
        pid = result.stdout.strip()
        require(pid.isdecimal() and int(pid) > 0, "Broker did not restart after empty runtime locks")
        try:
            ready = b"sovagrid_hub.backup_broker" in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        except FileNotFoundError:
            ready = False
        if ready:
            break
        require(time.monotonic() < deadline, "Broker did not enter its execution namespace")
        time.sleep(0.05)
    probe = r'''
import errno, os, uuid
for name in ('sovagrid-installation.lock', 'sovagrid-promotion.lock'):
    fd = os.open('/run/' + name, os.O_RDWR | os.O_NOFOLLOW)
    os.close(fd)
name = '.sovagrid-vm-rw-' + uuid.uuid4().hex
path = '/etc/sovagrid-hub/' + name
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
os.close(fd)
os.unlink(path)
path = '/etc/' + name
try:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
except OSError as error:
    assert error.errno == errno.EROFS, 'unexpected broker root filesystem refusal'
else:
    os.close(fd)
    os.unlink(path)
    raise RuntimeError('broker root filesystem became writable')
'''
    checked = subprocess.run(["nsenter", "--target", pid, "--mount", "--",
                              "/usr/bin/python3", "-I", "-c", probe],
                             capture_output=True, check=False, timeout=15)
    require(checked.returncode == 0, "Broker runtime locks or scoped writable paths failed")
    print("INTEGRATED_BROKER_REBOOT_LOCKS_AND_SANDBOX_VERIFIED", flush=True)


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
    verify_broker_runtime_locks_after_reboot()
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
    status, revoked = request("DELETE", "/api/v1/session", token=login["token"])
    require(status == 200 and revoked.get("revoked") is True,
            "Integrated install left its administrator session open")
    print("INTEGRATED_SERVER_BUNDLE_VERIFIED", flush=True)


if __name__ == "__main__":
    main()
