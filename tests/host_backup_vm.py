# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Disposable Ubuntu VM smoke for the installed host backup broker.

Run only from the host-backup GitHub Actions job. The privileged parent sends
requests as the Hub UID, then survives the intended Hub/broker interruption.
No archive contents, password, or session token are printed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid


SOCKET = "/run/sovagrid-hub-backup/control.sock"
SELF = Path(__file__).resolve()
BASE = "http://127.0.0.1:8766"
ID = re.compile(r"[0-9a-f]{32}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_REPLY = 65536


def vm_only() -> None:
    if (sys.platform != "linux" or os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            Path("/proc/1/comm").read_text().strip() != "systemd" or
            not Path("/opt/sovagrid-src/sovagrid-bundle.json").is_file()):
        raise SystemExit("disposable Ubuntu VM fixture only")


def socket_call(raw: str) -> int:
    if os.geteuid() != 10001:
        raise SystemExit("Hub UID required")
    try:
        request = json.loads(raw)
        if not isinstance(request, dict) or len(raw) > 512:
            return 41
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(120)
            connection.connect(SOCKET)
            connection.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode())
            response = bytearray()
            while len(response) <= MAX_REPLY:
                chunk = connection.recv(min(4096, MAX_REPLY + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                if b"\n" in chunk:
                    break
        if (not response.endswith(b"\n") or response.count(b"\n") != 1 or
                len(response) > MAX_REPLY):
            return 42
        value = json.loads(response)
        if not isinstance(value, dict) or type(value.get("ok")) is not bool:
            return 42
        print(json.dumps(value, separators=(",", ":")))
        return 0
    except (OSError, TimeoutError, UnicodeError, ValueError):
        return 42


def broker(request: dict, *, uncertain: bool = False, timeout: int = 150) -> dict | None:
    command = ["sudo", "-n", "-u", "sovagrid-hub", "/usr/bin/env",
               "GITHUB_ACTIONS=true", "RUNNER_ENVIRONMENT=github-hosted",
               "/usr/bin/python3", "-I", str(SELF), "socket",
               json.dumps(request, separators=(",", ":"))]
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        if uncertain:
            return None
        raise AssertionError("broker transport unavailable") from None
    if result.returncode == 42 and uncertain:
        return None
    assert result.returncode == 0, "broker client failed"
    assert 0 < len(result.stdout) <= MAX_REPLY + 1
    value = json.loads(result.stdout)
    assert isinstance(value, dict) and value.get("ok") is True, (
        "broker refused " + str(value.get("error", "unknown")))
    return value


def http_json(path: str, *, token: str | None = None,
              payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(BASE + path, data=data, headers=headers,
                                     method="POST" if data is not None else "GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=15) as response:
        assert response.status == 200
        raw = response.read(65537)
    assert 0 < len(raw) <= 65536
    value = json.loads(raw)
    assert isinstance(value, dict)
    return value


def archive_private(identity: str) -> None:
    assert ID.fullmatch(identity)
    directory = Path("/var/lib/sovagrid-host-backups")
    info = directory.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
    assert stat.S_IMODE(info.st_mode) == 0o700
    for suffix in (".tar.gz", ".manifest.json"):
        item = directory / (identity + suffix)
        info = item.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
        assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1


def expected_running_containers(value: object) -> bool:
    return (isinstance(value, list) and len(value) == 3 and
            set(value) == {"hub", "web", "ssh-gateway"})


def run() -> None:
    assert os.geteuid() == 0
    assert Path(SOCKET).is_socket()
    assert subprocess.run(["systemctl", "is-active", "--quiet",
                           "sovagrid-hub-backup-control.service"], check=False).returncode == 0
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as outsider:
        outsider.settimeout(10)
        outsider.connect(SOCKET)
        outsider.sendall(b'{"action":"host_plan"}\n')
        denied = json.loads(outsider.makefile("rb").readline(513))
    assert denied == {"ok": False, "error": "PEER_DENIED"}
    plan = broker({"action": "host_plan"})
    assert plan is not None and set(plan) == {"ok", "manifest_sha256", "plan"}
    assert SHA.fullmatch(plan["manifest_sha256"])
    assert plan["plan"]["layout"] == "full"
    assert expected_running_containers(plan["plan"]["running_containers"])
    assert plan["plan"]["offline_ready"] is False
    print("Installed root broker returned a bounded full-host plan", flush=True)

    request_id = uuid.uuid4().hex
    started = broker({"action": "host_start", "request_id": request_id,
                      "expected_manifest_sha256": plan["manifest_sha256"]},
                     uncertain=True)
    if started is not None:
        assert started["request_id"] == request_id
        assert started["phase"] in ("accepted", "stopping", "archiving", "restarting",
                                    "complete")
    deadline = time.monotonic() + 720
    complete = None
    while time.monotonic() < deadline:
        response = broker({"action": "host_status", "request_id": request_id},
                          uncertain=True, timeout=25)
        if response is not None:
            assert response["request_id"] == request_id
            if response["phase"] == "complete":
                complete = response
                break
            assert response["phase"] not in ("failed", "recovery_required"), (
                "host snapshot did not restore its managed stack")
        time.sleep(2)
    assert complete is not None, "host snapshot did not complete within 12 minutes"
    archive = complete["archive"]
    assert isinstance(archive, dict) and ID.fullmatch(archive["id"])
    assert archive["layout"] == "full" and archive["bytes"] > 0
    archive_private(archive["id"])
    checked = broker({"action": "host_verify", "id": archive["id"]}, timeout=450)
    assert checked is not None and checked["verified"] is True
    assert checked["archive"] == archive
    operations = broker({"action": "host_operations"})
    assert operations is not None
    assert any(item["request_id"] == request_id and item["phase"] == "complete"
               for item in operations["operations"])
    print("Detached snapshot completed, private archive verified", flush=True)

    health = http_json("/healthz")
    assert health.get("ok") is True
    password = Path("/etc/sovagrid/admin-password").read_text().strip()
    assert password
    login = http_json("/api/v1/session", payload={"username": "admin", "password": password})
    token = login.get("token")
    assert isinstance(token, str) and len(token) >= 24
    listed = http_json("/api/v1/host-backups/archives", token=token)
    assert archive in listed.get("archives", [])
    api_plan = http_json("/api/v1/host-backups/plan", token=token)
    assert api_plan["manifest_sha256"] == plan["manifest_sha256"]
    assert expected_running_containers(api_plan["plan"]["running_containers"])
    forbidden = urllib.request.Request(
        BASE + "/api/v1/host-backups/archives/" + archive["id"] + "/download",
        headers={"Authorization": "Bearer " + token})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(forbidden, timeout=10) as response:
            assert response.status != 200, "private archive unexpectedly downloadable"
    except urllib.error.HTTPError as exc:
        assert exc.code in (403, 404, 405), "unexpected archive download route"
    print("Hub and Web returned HTTP 200; archive has no HTTP download route", flush=True)


if __name__ == "__main__":
    vm_only()
    if len(sys.argv) == 3 and sys.argv[1] == "socket":
        raise SystemExit(socket_call(sys.argv[2]))
    if sys.argv[1:] == ["run"]:
        run()
    else:
        raise SystemExit("usage: host_backup_vm.py run")
