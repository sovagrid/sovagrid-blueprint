#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Destructive, root-only fixture for a fresh GitHub-hosted Ubuntu VM.

Never run on a real server. The workflow verifies a published archive first,
then this fixture starts a real external Agent plus inert systemd transport
processes. No SSH keys or external servers are involved.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time


BASELINE = Path("/run/sovagrid-promotion-vm-baseline.json")
EXTERNAL_UNITS = ("sovagrid-agent.service", "sovagrid-agent-tunnel.service", "sovagrid-fixture-reverse-tunnel.service")
EXTERNAL_FILES = (
    "/etc/sovagrid/agent.json",
    "/etc/sovagrid/agent.token",
    "/etc/sovagrid/hub-ca.pem",
    "/etc/systemd/system/sovagrid-agent.service",
    "/etc/systemd/system/sovagrid-agent-tunnel.service",
    "/etc/systemd/system/sovagrid-fixture-reverse-tunnel.service",
    "/opt/sovagrid-agent-installer/source-manifest.json",
    "/var/lib/sovagrid-agent-enrollment/state.json",
    "/var/lib/sovagrid-agent/external-sentinel",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Promotion VM fixture: {message}")


def command(*args: str, quiet: bool = False) -> str:
    result = subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL if quiet else subprocess.PIPE, timeout=45)
    return result.stdout.strip()


def write(path: Path, value: bytes, *, gid: int = 0, mode: int = 0o600) -> None:
    require(not path.exists() and not path.is_symlink(), f"fixture path exists: {path}")
    path.write_bytes(value)
    os.chown(path, 0, gid)
    path.chmod(mode)


def fingerprint(path: Path) -> dict:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode), f"tracked path is not a regular file: {path}")
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}


def unit_pid(name: str) -> int:
    require(command("systemctl", "is-active", name) == "active", f"unit stopped: {name}")
    pid = int(command("systemctl", "show", "-P", "MainPID", name))
    require(pid > 1 and Path(f"/proc/{pid}").exists(), f"unit has no process: {name}")
    return pid


def snapshot() -> dict:
    source_files = sorted(Path("/opt/sovagrid-agent/sovagrid_agent").glob("*.py"))
    require(len(source_files) >= 8, "external Agent source is incomplete")
    data = Path("/var/lib/sovagrid-agent").lstat()
    return {"files": {str(path): fingerprint(path) for path in
                      (*map(Path, EXTERNAL_FILES), *source_files)},
            "agent_data": {"uid": data.st_uid, "gid": data.st_gid,
                           "mode": stat.S_IMODE(data.st_mode)},
            "pids": {name: unit_pid(name) for name in EXTERNAL_UNITS}}


def baseline_data() -> dict:
    info = BASELINE.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
            "fixture baseline is unsafe")
    return json.loads(BASELINE.read_text())


def save_baseline(value: dict) -> None:
    payload = (json.dumps(value, sort_keys=True) + "\n").encode()
    temporary = Path("/run") / (".sovagrid-promotion-vm-" + secrets.token_hex(8))
    write(temporary, payload)
    os.replace(temporary, BASELINE)


def seed(source: Path) -> None:
    for name in ("/etc/sovagrid", "/etc/sovagrid-local", "/var/lib/sovagrid",
                 "/var/lib/sovagrid-agent", "/var/lib/sovagrid-promotion", "/opt/sovagrid-src",
                 "/opt/sovagrid-agent", "/opt/sovagrid-agent-local", str(BASELINE)):
        path = Path(name)
        require(not path.exists() and not path.is_symlink(), f"VM is not pristine: {path}")
    for name in EXTERNAL_UNITS:
        require(not Path("/etc/systemd/system", name).exists(), f"unit already exists: {name}")
    require((source / "sovagrid-bundle.json").is_file(), "verified bundle was not extracted")
    require((source / "sovagrid-agent/deploy/sovagrid-agent.service").is_file(), "Agent unit missing")
    require(not command("ss", "-H", "-ltn", "( sport = :8766 or sport = :8767 )"),
            "SovaGrid loopback ports are occupied")
    command("groupadd", "--system", "sovagrid")
    command("useradd", "--system", "--gid", "sovagrid", "--home-dir",
            "/var/lib/sovagrid-agent", "--shell", "/usr/sbin/nologin", "sovagrid")
    agent_gid = grp.getgrnam("sovagrid").gr_gid
    etc = Path("/etc/sovagrid")
    etc.mkdir(mode=0o750)
    etc.chmod(0o750)
    os.chown(etc, 0, agent_gid)
    data = Path("/var/lib/sovagrid-agent")
    data.mkdir(mode=0o750)
    data.chmod(0o750)
    os.chown(data, 0, agent_gid)
    write(data / "external-sentinel", b"external Agent data must survive\n")
    Path("/opt/sovagrid-agent").mkdir(mode=0o755)
    Path("/opt/sovagrid-agent").chmod(0o755)
    shutil.copytree(source / "sovagrid-agent/sovagrid_agent",
                    "/opt/sovagrid-agent/sovagrid_agent")
    Path("/opt/sovagrid-agent-installer").mkdir(mode=0o755)
    Path("/opt/sovagrid-agent-installer").chmod(0o755)
    write(Path("/opt/sovagrid-agent-installer/source-manifest.json"), b'{"fixture":"external-agent"}\n', mode=0o644)
    Path("/var/lib/sovagrid-agent-enrollment").mkdir(mode=0o700)
    write(Path("/var/lib/sovagrid-agent-enrollment/state.json"), b'{"fixture":"enrolled"}\n')

    with tempfile.TemporaryDirectory(prefix="sovagrid-external-ca-") as folder:
        key, cert = Path(folder) / "key.pem", Path(folder) / "cert.pem"
        command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=fixture-external-hub", "-keyout", str(key), "-out", str(cert), quiet=True)
        write(etc / "hub-ca.pem", cert.read_bytes(), mode=0o644)
    config = {"hub_url": "https://127.0.0.1:9449", "server_id": "00000000-0000-4000-8000-000000000001",
              "token_file": "/etc/sovagrid/agent.token", "ca_file": "/etc/sovagrid/hub-ca.pem",
              "interval_seconds": 30, "allow_remote_commands": False}
    write(etc / "agent.json", (json.dumps(config, sort_keys=True) + "\n").encode(), gid=agent_gid, mode=0o640)
    write(etc / "agent.token", (secrets.token_urlsafe(32) + "\n").encode(), gid=agent_gid, mode=0o640)

    shutil.copyfile(source / "sovagrid-agent/deploy/sovagrid-agent.service",
                    "/etc/systemd/system/sovagrid-agent.service")
    Path("/etc/systemd/system/sovagrid-agent.service").chmod(0o644)
    for name in ("sovagrid-agent-tunnel.service", "sovagrid-fixture-reverse-tunnel.service"):
        command_line = ("/usr/bin/sh -c 'exec /usr/bin/sleep infinity # /usr/bin/ssh -R 2200:127.0.0.1:22'"
                        if name == "sovagrid-fixture-reverse-tunnel.service" else "/usr/bin/sleep infinity")
        unit = (f"[Unit]\nDescription=Fixture external transport {name}\n"
                f"[Service]\nType=simple\nExecStart={command_line}\n"
                "[Install]\nWantedBy=multi-user.target\n")
        write(Path("/etc/systemd/system", name), unit.encode(), mode=0o644)
    command("systemctl", "daemon-reload")
    for name in EXTERNAL_UNITS:
        command("systemctl", "enable", "--now", name)
    time.sleep(3)
    save_baseline({"external": snapshot()})
    print("External Agent and transport unit fixture is active; private baseline saved")


def verify_external() -> None:
    require(snapshot() == baseline_data()["external"],
            "external Agent files, data metadata, unit or process changed")
    staging = Path("/var/lib/sovagrid/local-hub-ca.pem")
    if staging.exists():
        info = staging.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
                stat.S_IMODE(info.st_mode) == 0o600, "local Hub CA staging is unsafe")
        require(staging.read_bytes() != Path("/etc/sovagrid/hub-ca.pem").read_bytes(),
                "local Hub unexpectedly reused the external CA")
    print("External Agent, CA, data and running transport PIDs are unchanged")


def verify_local(*, repeat: bool) -> None:
    verify_external()
    journal = Path("/var/lib/sovagrid-promotion/local-agent.json")
    record = json.loads(journal.read_text())
    server_id = record["server_id"]
    require(record["commands"] is False, "local commands were enabled without opt-in")
    local = pwd.getpwnam("sovagrid-local")
    external = pwd.getpwnam("sovagrid")
    require(local.pw_uid != external.pw_uid and local.pw_gid != external.pw_gid,
            "local Agent reused external identity")
    require(os.getgrouplist("sovagrid-local", local.pw_gid) == [local.pw_gid],
            "local Agent has supplementary groups")
    unit = unit_pid("sovagrid-agent-local.service")
    with Path(f"/proc/{unit}/status").open() as stream:
        status = stream.read()
    require(f"Uid:\t{local.pw_uid}\t" in status and f"Gid:\t{local.pw_gid}\t" in status,
            "local Agent process runs under the wrong identity")
    for path, uid, gid, mode in ((Path("/etc/sovagrid-local"), 0, local.pw_gid, 0o750),
                                 (Path("/var/lib/sovagrid-agent-local"), local.pw_uid, local.pw_gid, 0o700)):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
                (uid, gid, mode), f"local private directory is unsafe: {path}")
    for path in ("agent.json", "agent.token", "hub-ca.pem"):
        info = Path("/etc/sovagrid-local", path).lstat()
        require(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
                (0, local.pw_gid, 0o640), f"local Agent file is unsafe: {path}")
    require(Path("/etc/sovagrid-local/hub-ca.pem").read_bytes() ==
            Path("/var/lib/sovagrid/local-hub-ca.pem").read_bytes(), "local Agent trusts the wrong Hub CA")
    for user, target in (("sovagrid-local", "/etc/sovagrid/agent.token"),
                         ("sovagrid", "/etc/sovagrid-local/agent.token")):
        result = subprocess.run(["runuser", "-u", user, "--", "test", "-r", target], check=False, timeout=10)
        require(result.returncode != 0, f"{user} can read the other Agent's token")
    with sqlite3.connect("/var/lib/sovagrid/hub/hub.sqlite") as db:
        servers = db.execute("SELECT id FROM servers").fetchall()
        require(servers == [(server_id,)], "local Hub has duplicate or missing server enrollment")
        latest = db.execute("SELECT received_at,cpu_percent,memory_percent,details_json FROM metrics "
                            "WHERE server_id=? ORDER BY id DESC LIMIT 1", (server_id,)).fetchone()
    require(latest is not None and abs(int(time.time()) - latest[0]) < 150 and
            0 <= latest[1] <= 100 and 0 <= latest[2] <= 100 and
            isinstance(json.loads(latest[3]), dict), "local Agent has no fresh valid metric")
    state = baseline_data()
    if repeat:
        require(state.get("local_pid") == unit and state.get("local_server_id") == server_id,
                "repeated activation restarted or re-enrolled the local Agent")
    else:
        require("local_pid" not in state, "first activation was already recorded")
        state["local_pid"] = unit
        state["local_server_id"] = server_id
        save_baseline(state)
    print("Local Agent is isolated, reports a fresh metric and has one stable enrollment")


def verify_inspect(phase: str, helper: Path) -> None:
    require(phase in {"eligible", "prepared", "source_staged", "hub_installed", "activated"},
            "unsupported expected inspect phase")
    require(helper.is_file() and not helper.is_symlink(), "inspect helper is unavailable")
    payload = command("python3", str(helper), "inspect")
    value = json.loads(payload)
    keys = {"protocol", "phase", "external_agent_preserved", "baseline_sha256",
            "pinned_manifest_sha256", "source_manifest_sha256", "local_server_id", "reason_code"}
    require(isinstance(value, dict) and set(value) == keys and value["protocol"] == 1 and
            value["phase"] == phase and value["external_agent_preserved"] is True and
            value["reason_code"] is None, "inspect returned an unsafe or unexpected phase")
    if phase == "eligible":
        require(value["baseline_sha256"] is None and value["pinned_manifest_sha256"] is None and
                value["source_manifest_sha256"] is None and value["local_server_id"] is None,
                "eligible inspect unexpectedly contains a package or local Agent")
    else:
        baseline = Path("/var/lib/sovagrid-promotion/baseline.json")
        pin = json.loads(Path("/var/lib/sovagrid-promotion/bundle-pin.json").read_text())
        require(value["baseline_sha256"] == hashlib.sha256(baseline.read_bytes()).hexdigest() and
                value["pinned_manifest_sha256"] == pin["manifest_sha256"],
                "inspect lost the prepared baseline or package pin")
        if phase in {"source_staged", "hub_installed", "activated"}:
            require(value["source_manifest_sha256"] == pin["manifest_sha256"],
                    "inspect source differs from the prepared package")
        else:
            require(value["source_manifest_sha256"] is None, "prepared source should be absent")
        if phase == "activated":
            require(value["local_server_id"] == json.loads(Path(
                "/var/lib/sovagrid-promotion/local-agent.json").read_text())["server_id"],
                "inspect local server ID differs from the activation journal")
        else:
            require(value["local_server_id"] is None, "inspect exposed a premature local Agent")
    print(f"Read-only inspect confirmed {phase} with the pinned package")


def main(args: list[str]) -> None:
    os.umask(0o077)
    require(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("SOVAGRID_PROMOTION_VM_FIXTURE") == "1" and
            Path("/proc/1/comm").read_text().strip() == "systemd",
            "requires root on a disposable GitHub Actions Ubuntu VM")
    require(len(args) in (1, 2, 3),
            "usage: promotion_vm.py seed SOURCE | external | local | repeat | inspect PHASE HELPER")
    if args[0] == "seed" and len(args) == 2:
        seed(Path(args[1]))
    elif args == ["external"]:
        verify_external()
    elif args == ["local"]:
        verify_local(repeat=False)
    elif args == ["repeat"]:
        verify_local(repeat=True)
    elif args[0] == "inspect" and len(args) == 3:
        verify_inspect(args[1], Path(args[2]))
    else:
        raise SystemExit("invalid fixture operation")


if __name__ == "__main__":
    main(sys.argv[1:])
