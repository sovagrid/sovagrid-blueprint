#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Read-only postconditions for Hub-only updates on a disposable VM."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import time

import promotion_vm


BASELINE = Path("/run/sovagrid-hub-only-update-vm-baseline.json")
LOCAL_RECORD = Path("/var/lib/sovagrid-promotion/local-agent.json")
LOCAL_CONFIG = Path("/etc/sovagrid-local/agent.json")
LOCAL_TOKEN = Path("/etc/sovagrid-local/agent.token")
PIN = Path("/var/lib/sovagrid-promotion/bundle-pin.json")
SOURCE = Path("/opt/sovagrid-src")


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise SystemExit("Hub-only update VM: " + reason)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def local() -> dict:
    record = json.loads(LOCAL_RECORD.read_text())
    config = json.loads(LOCAL_CONFIG.read_text())
    require(record["commands"] is True and config["allow_remote_commands"] is True,
            "the local commands flag changed")
    require(config["server_id"] == record["server_id"], "local Agent enrollment changed")
    return {"server_id": record["server_id"], "record_sha256": sha(LOCAL_RECORD),
            "config_sha256": sha(LOCAL_CONFIG), "token_sha256": sha(LOCAL_TOKEN)}


def ready(expected_manifest: str) -> None:
    promotion_vm.verify_external()
    current = sha(SOURCE / "sovagrid-bundle.json")
    require(current == expected_manifest and json.loads(PIN.read_text())["manifest_sha256"] == current,
            "source and promotion pin differ")
    for unit in ("sovagrid-agent-local.service", "sovagrid-vpn-status.timer"):
        require(promotion_vm.command("systemctl", "is-active", unit) == "active", unit + " is down")
    result = subprocess.run(["python3", str(SOURCE / "sovagrid-blueprint/deploy/promote_agent_only.py"),
                             "inspect"], check=True, capture_output=True, text=True, timeout=60)
    state = json.loads(result.stdout)
    require(state["phase"] == "activated" and state["external_agent_preserved"] is True,
            "promotion state is not activated")
    data = local()
    require(state["local_server_id"] == data["server_id"], "local server ID changed")
    with sqlite3.connect("/var/lib/sovagrid/hub/hub.sqlite") as db:
        servers = db.execute("SELECT id,remote_commands_enabled FROM servers").fetchall()
        latest = db.execute("SELECT received_at FROM metrics WHERE server_id=? "
                            "ORDER BY id DESC LIMIT 1", (data["server_id"],)).fetchone()
    require(servers == [(data["server_id"], 1)] and latest is not None and
            abs(int(time.time()) - latest[0]) < 150, "local enrollment or metric is stale")


def initial() -> None:
    require(not BASELINE.exists() and not BASELINE.is_symlink(), "baseline already exists")
    promotion_vm.verify_external()
    data = local()
    data["manifest_sha256"] = sha(SOURCE / "sovagrid-bundle.json")
    BASELINE.write_text(json.dumps(data, sort_keys=True) + "\n")
    BASELINE.chmod(0o600)
    require(BASELINE.lstat().st_uid == 0, "baseline is not root-owned")
    print("Saved local Agent enrollment and commands flag; external PIDs remain pinned")


def verify(expected_manifest: str) -> None:
    require(len(expected_manifest) == 64, "invalid expected manifest")
    info = BASELINE.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
            "unsafe baseline")
    baseline = json.loads(BASELINE.read_text())
    ready(expected_manifest)
    data = local()
    for key in ("server_id", "record_sha256", "config_sha256", "token_sha256"):
        require(data[key] == baseline[key], key + " changed")
    worker = SOURCE / "sovagrid-blueprint/deploy/hub_only_update.py"
    result = subprocess.run(["python3", "-I", str(worker), "preview"],
                            check=True, capture_output=True, text=True, timeout=60)
    require("SG_HUB_ONLY_CURRENT_MANIFEST:" + expected_manifest in result.stdout.splitlines(),
            "updater preview disagrees with the installed source")
    print("Hub-only source, local commands and external Agent/tunnel are consistent")


def timer() -> None:
    unit = "sovagrid-hub-only-update.timer"
    require(Path("/etc/systemd/system", unit).is_file(), "timer unit was not installed")
    enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", unit], check=False, timeout=10)
    active = subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False, timeout=10)
    require(enabled.returncode != 0 and active.returncode != 0,
            "Hub-only timer started before explicit one-candidate policy")
    require(not Path("/etc/sovagrid-hub/hub-only-auto-update.json").exists(),
            "Hub-only policy appeared without opt-in")
    print("Dedicated Hub-only timer is installed, inactive and has no policy")


def main(args: list[str]) -> None:
    require(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("SOVAGRID_PROMOTION_VM_FIXTURE") == "1" and
            Path("/proc/1/comm").read_text().strip() == "systemd",
            "requires a disposable GitHub Actions Ubuntu VM")
    if args == ["initial"]:
        initial()
    elif len(args) == 2 and args[0] == "verify":
        verify(args[1])
    elif args == ["timer-inactive"]:
        timer()
    else:
        raise SystemExit("usage: hub_only_update_vm.py initial | verify SHA256 | timer-inactive")


if __name__ == "__main__":
    main(sys.argv[1:])
