#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Disposable-VM proof for the promoted local Agent's PTY and workspace."""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import grp
import select
import socket
import stat
import subprocess
import sys
import time

SOURCE = Path("/opt/sovagrid-agent-local")
WORKSPACE = Path("/var/lib/sovagrid-agent-local/files")
PROBE = WORKSPACE / ".sovagrid-local-operations-vm.txt"


def require(value: bool, reason: str) -> None:
    if not value:
        raise SystemExit("Local operations VM: " + reason)


def config() -> dict:
    return json.loads(Path("/etc/sovagrid-local/agent.json").read_text())


def agent_probe(*, existing: bool = False) -> None:
    require(os.geteuid() == pwd.getpwnam("sovagrid-local").pw_uid,
            "probe is not the local Agent")
    sys.path.insert(0, str(SOURCE))
    from sovagrid_agent.files import operate
    from sovagrid_agent.terminal import open_local_pty
    from sovagrid_agent.terminal_broker import LOCAL_SOCKET_PATH
    settings = config()
    require(operate(settings, {"action": "roots"}) == {"roots": ["workspace"]},
            "file root unavailable")
    if existing:
        require(PROBE.read_bytes() == b"local workspace VM probe\n",
                "workspace probe changed during update")
    else:
        fd = os.open(PROBE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(b"local workspace VM probe\n")
    listing = operate(settings, {"action": "list", "root": "workspace", "path": ""})
    require(any(item["name"] == PROBE.name for item in listing["entries"]),
            "file manager cannot list its workspace")
    item = operate(settings, {"action": "read", "root": "workspace", "path": PROBE.name})
    require(item["size"] == len(b"local workspace VM probe\n"),
            "file manager cannot read its workspace")
    conn, master = open_local_pty(80, 24, LOCAL_SOCKET_PATH)
    try:
        os.write(master, b"id -un; exit\n")
        output = bytearray()
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], 0.5)
            if readable:
                try:
                    output.extend(os.read(master, 4096))
                except OSError:
                    break
            if b"sovagrid-local-shell" in output:
                break
        require(b"sovagrid-local-shell" in output, "PTY did not run as isolated local shell")
    finally:
        os.close(master)
        conn.close()
    require(subprocess.run(["test", "-r", "/etc/sovagrid/agent.token"],
                           check=False).returncode != 0,
            "local Agent can read external Agent token")
    print("LOCAL_OPERATIONS_AGENT_PROBE_OK")


def root_probe(enabled: bool, *, existing: bool = False) -> None:
    require(os.geteuid() == 0, "root fixture required")
    record = json.loads(Path("/var/lib/sovagrid-promotion/local-operations.json").read_text())
    require(record == {"protocol": 1, "terminal": enabled, "files": enabled},
            "unexpected operation state")
    settings = config()
    require(settings["allow_interactive_terminal"] is enabled and
            settings["allow_file_manager"] is enabled and
            settings["allow_remote_commands"] is True, "local Agent flags incorrect")
    local = pwd.getpwnam("sovagrid-local")
    external = pwd.getpwnam("sovagrid")
    require(local.pw_uid != external.pw_uid and local.pw_gid != external.pw_gid,
            "Agents share an identity")
    if enabled:
        require(settings["terminal_socket"] ==
                "/run/sovagrid-terminal-local/control.sock" and
                settings["file_roots"] == {"workspace": str(WORKSPACE)},
                "wrong local socket or workspace")
        shell = pwd.getpwnam("sovagrid-local-shell")
        require(shell.pw_uid not in (0, local.pw_uid, external.pw_uid) and
                os.getgrouplist("sovagrid-local-shell", shell.pw_gid) == [shell.pw_gid],
                "PTY shell identity not isolated")
        home = Path("/var/lib/sovagrid-local-shell").lstat()
        workspace = WORKSPACE.lstat()
        require((home.st_uid, home.st_gid, stat.S_IMODE(home.st_mode)) ==
                (shell.pw_uid, shell.pw_gid, 0o700) and
                (workspace.st_uid, workspace.st_gid, stat.S_IMODE(workspace.st_mode)) ==
                (local.pw_uid, local.pw_gid, 0o700), "local private directories unsafe")
        endpoint = Path(settings["terminal_socket"])
        info = endpoint.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and
                info.st_gid == grp.getgrnam("sovagrid-local").gr_gid and
                stat.S_IMODE(info.st_mode) == 0o660,
                "local PTY socket permissions incorrect")
        for unit in ("sovagrid-terminal-local-control.socket",
                     "sovagrid-terminal-local-control.service"):
            require(subprocess.run(["systemctl", "is-active", "--quiet", unit],
                                   check=False).returncode == 0,
                    "local PTY broker is inactive")
            require(subprocess.run(["systemctl", "is-enabled", "--quiet", unit],
                                   check=False).returncode == 0,
                    "local PTY broker would not survive reboot")
        subprocess.run(["runuser", "-u", "sovagrid-local", "--", "python3", "-B",
                        "/opt/sovagrid-src/sovagrid-blueprint/tests/local_operations_vm.py",
                        "agent-probe-existing" if existing else "agent-probe"],
                       check=True, timeout=25)
        require(subprocess.run(["runuser", "-u", "sovagrid-local-shell", "--", "test", "-r",
                                "/etc/sovagrid-local/agent.token"],
                               check=False, timeout=10).returncode != 0,
                "PTY shell can read local Agent token")
    else:
        require("terminal_socket" not in settings and "file_roots" not in settings,
                "disabled config still grants local operations")
        require(PROBE.read_bytes() == b"local workspace VM probe\n",
                "file was lost when feature was disabled")
        for unit in ("sovagrid-terminal-local-control.socket",
                     "sovagrid-terminal-local-control.service"):
            require(subprocess.run(["systemctl", "is-active", "--quiet", unit],
                                   check=False).returncode != 0,
                    "local PTY broker remained active")
    print("LOCAL_OPERATIONS_" + ("ON" if enabled else "OFF") + "_OK")


def pending_probe() -> None:
    require(os.geteuid() == 0, "root fixture required")
    path = Path("/var/lib/sovagrid-promotion/local-operations-pending.json")
    require(not path.exists(), "pending state already exists")
    prior = {"protocol": 1, "terminal": False, "files": False}
    future = {**prior, "terminal": True}
    path.write_text(json.dumps({"protocol": 1, "previous": prior, "target": future}) + "\n")
    path.chmod(0o600)
    print("LOCAL_OPERATIONS_PENDING_SEEDED")


if __name__ == "__main__":
    if sys.argv[1:] == ["agent-probe"]:
        agent_probe()
    elif sys.argv[1:] == ["agent-probe-existing"]:
        agent_probe(existing=True)
    elif sys.argv[1:] == ["on"]:
        root_probe(True)
    elif sys.argv[1:] == ["survived"]:
        root_probe(True, existing=True)
    elif sys.argv[1:] == ["off"]:
        root_probe(False)
    elif sys.argv[1:] == ["pending"]:
        pending_probe()
    else:
        raise SystemExit("usage: local_operations_vm.py agent-probe|agent-probe-existing|on|survived|off|pending")
