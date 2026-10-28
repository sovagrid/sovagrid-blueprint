#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Disposable Ubuntu VM postconditions for the inactive signed-feed migration."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


SCRIPT = Path("/opt/sovagrid-src/sovagrid-blueprint/deploy/release_feed.py")
MARKER = Path("/var/lib/sovagrid/.release-feed-units-managed-by-run-sh")
CONFIG = Path("/etc/sovagrid/release-feed.json")
LOCK = Path("/var/lib/sovagrid/.release-feed.lock")
TIMER = "sovagrid-release-feed.timer"
UNITS = ("sovagrid-release-feed.service", TIMER)


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise SystemExit("release feed VM: " + reason)


def unit_state(unit: str) -> tuple[bool, bool]:
    enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", unit],
                             check=False, timeout=10).returncode == 0
    active = subprocess.run(["systemctl", "is-active", "--quiet", unit],
                            check=False, timeout=10).returncode == 0
    return enabled, active


def managed_file(path: Path, mode: int) -> None:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
            stat.S_IMODE(info.st_mode) == mode and info.st_nlink == 1,
            "unsafe managed file: " + str(path))


def check(mode: str) -> None:
    require(mode in ("deferred", "installed"), "unknown mode")
    require(not CONFIG.exists() and not CONFIG.is_symlink(), "opt-in was created without consent")
    require(SCRIPT.is_file(), "release feed verifier missing from installed source")
    if mode == "installed":
        managed_file(MARKER, 0o600)
        require(MARKER.read_bytes() == b"SOVAGRID_RELEASE_FEED_UNITS_V1\n", "wrong ownership marker")
        for unit in UNITS:
            managed_file(Path("/etc/systemd/system") / unit, 0o644)
        require(unit_state(TIMER) == (False, False), "signed-feed timer started without opt-in")
    else:
        for path in (MARKER, *(Path("/etc/systemd/system") / unit for unit in UNITS)):
            require(not path.exists() and not path.is_symlink(), "old worker installed unsnapshotted feed state")
    manual = {unit: unit_state(unit) for unit in ("sovagrid-auto-update.timer",
                                                 "sovagrid-hub-only-update.timer")
              if Path("/etc/systemd/system", unit).is_file()}
    lock_before = LOCK.exists()
    status = subprocess.run(["python3", "-I", str(SCRIPT), "status"],
                            check=True, capture_output=True, text=True, timeout=20)
    report = json.loads(status.stdout)
    require(report["enabled"] is False and report["key_id"] is None and
            report["timer_installed"] is (mode == "installed") and
            report["timer_enabled"] is False and report["timer_active"] is False and
            report["available_keys"] == {} and
            report["installed_manifest_sha256"] == hashlib.sha256(
                Path("/opt/sovagrid-src/sovagrid-bundle.json").read_bytes()).hexdigest() and
            re.fullmatch(r"[0-9a-f]{64}", report["state_revision"]),
            "status promised an active or trusted feed")
    again = subprocess.run(["python3", "-I", str(SCRIPT), "status"],
                           check=True, capture_output=True, text=True, timeout=20)
    require(json.loads(again.stdout)["state_revision"] == report["state_revision"] and
            LOCK.exists() == lock_before, "status changed state or created a lock")
    stale = subprocess.run(["python3", "-I", str(SCRIPT), "disable", "--expected-state", "0" * 64],
                           check=False, capture_output=True, text=True, timeout=20)
    require(stale.returncode == 40 and "SG_RELEASE_FEED_REFUSE:STATE_CHANGED" in stale.stdout,
            "stale disable did not refuse before mutation")
    malformed = subprocess.run(["python3", "-I", str(SCRIPT), "disable", "--expected-state", "bad"],
                               check=False, capture_output=True, text=True, timeout=20)
    require(malformed.returncode == 40 and
            "SG_RELEASE_FEED_REFUSE:INVALID_EXPECTED_STATE" in malformed.stdout,
            "malformed CAS did not refuse")
    promotion = Path("/var/lib/sovagrid-promotion")
    hub_only = promotion.exists() or promotion.is_symlink()
    if not hub_only:
        malformed_enable = subprocess.run(["python3", "-I", str(SCRIPT), "enable",
                                           "--expected-state", "bad"],
                                          check=False, capture_output=True, text=True, timeout=20)
        require(malformed_enable.returncode == 40 and
                "SG_RELEASE_FEED_REFUSE:INVALID_EXPECTED_STATE" in malformed_enable.stdout,
                "full-server enable accepted malformed CAS")
    attempt = subprocess.run(["python3", "-I", str(SCRIPT), "enable", "--expected-state",
                              report["state_revision"]],
                             check=False, capture_output=True, text=True, timeout=20)
    expected_refusal = "HUB_ONLY_UNSUPPORTED" if hub_only else "UNCONFIGURED_TRUST"
    require(attempt.returncode == 40 and
            "SG_RELEASE_FEED_REFUSE:" + expected_refusal in attempt.stdout,
            "enable accepted an unsupported Hub-only node or missing trust anchor")
    if mode == "installed":
        disabled = subprocess.run(["python3", "-I", str(SCRIPT), "disarm"],
                                  check=True, capture_output=True, text=True, timeout=20)
        require("SG_RELEASE_FEED:DISABLED" in disabled.stdout, "disarm did not finish")
        require(unit_state(TIMER) == (False, False), "feed timer remained active after disarm")
    require(manual == {unit: unit_state(unit) for unit in manual},
            "signed-feed controls changed the manual one-candidate timer")
    require(not CONFIG.exists() and not CONFIG.is_symlink(), "opt-in appeared during checks")
    print("Inactive signed-feed", mode, "state, refusal and manual timer isolation verified")


def legacy_guard(source: Path, outcome: str) -> None:
    """Run only run.sh's read-only preflight with the previous worker's env."""
    require(outcome in ("deferred", "refused") and source.is_file() and not source.is_symlink() and
            str(source).startswith(("/opt/sovagrid-candidates/", "/opt/sovagrid-src/")),
            "unsafe legacy guard fixture")
    script = source.read_text()
    boundary = "\nhub_only=0\n"
    require(script.count(boundary) == 1, "installer preflight boundary changed")
    preflight = script.split(boundary, 1)[0] + "\n"
    preflight += "if (( release_feed_deferred )); then printf 'SG_VM_FEED_DEFERRED\\n'; fi\n"
    env = os.environ.copy()
    # Exercise the feed guard itself. Older-worker protections for the backup
    # broker and SSH gateway precede it or follow it in run.sh; after those
    # features are installed they must not mask this specific refusal.
    env.update(SOVAGRID_PUBLIC_WEB_LOCK_HELD="1", SOVAGRID_UPDATER_TIMER_SNAPSHOT="1",
               SOVAGRID_HUB_BACKUP_BROKER_SNAPSHOT="1", SOVAGRID_SSH_GATEWAY_SNAPSHOT="1")
    env.pop("SOVAGRID_RELEASE_FEED_SNAPSHOT", None)
    result = subprocess.run(["bash", "-c", preflight], env=env, capture_output=True,
                            text=True, check=False, timeout=20)
    if outcome == "deferred":
        require(result.returncode == 0 and "SG_VM_FEED_DEFERRED" in result.stdout,
                "previous worker did not defer the first feed-unit install")
    else:
        require(result.returncode != 0 and
                "supervising updater cannot snapshot existing release-feed state" in result.stderr,
                "previous worker accepted unsnapshotted installed feed state")
    print("Previous-worker release-feed preflight", outcome, "verified")


def main(argv: list[str]) -> None:
    require(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("SOVAGRID_RELEASE_FEED_VM_FIXTURE") == "1" and
            Path("/proc/1/comm").read_text().strip() == "systemd",
            "requires a disposable GitHub Actions Ubuntu VM")
    if len(argv) == 1:
        check(argv[0])
    elif len(argv) == 3 and argv[0] == "legacy-guard":
        legacy_guard(Path(argv[1]), argv[2])
    else:
        raise SystemExit("usage: release_feed_vm.py deferred|installed | legacy-guard PATH deferred|refused")


if __name__ == "__main__":
    main(sys.argv[1:])
