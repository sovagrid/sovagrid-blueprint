#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Real systemd gate; run only on a clean disposable Ubuntu VM.

SOVAGRID_DISPOSABLE_VM=1 sudo -E python3 tests/vpn_source_maintenance_vm.py BUNDLE_ROOT
The reviewed five-repository bundle must already be unpacked under /root. This
fixture starts only management sockets; it creates no container or VPN interface.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(*args, accepted=(0,)):
    result = subprocess.run(args, capture_output=True, check=False, timeout=45,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
    require(result.returncode in accepted, "fixed VM fixture command failed")
    return result


def main():
    require(os.geteuid() == 0 and os.environ.get("SOVAGRID_DISPOSABLE_VM") == "1",
            "explicit disposable-VM acknowledgement and root are required")
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("RUNNER_OS") == "Linux", "a fresh GitHub-hosted Linux VM is required")
    require(len(sys.argv) == 2, "provide the reviewed bundle root")
    bundle = Path(sys.argv[1]).resolve()
    require(bundle.is_relative_to("/root") and bundle != Path("/root"), "unpack the reviewed bundle under /root")
    require('ID=ubuntu' in Path('/etc/os-release').read_text(), "Ubuntu is required")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(bundle / "sovagrid-blueprint/deploy"))
    from vpn_source_install import Installer, Refuse
    from vpn_source_maintenance import AMNEZIA, JOURNAL, BLOCKER
    roots = ("/opt/sovagrid-src", "/opt/sovagrid-vpn", "/var/lib/sovagrid",
             "/var/lib/sovagrid-vpn", "/etc/sovagrid-vpn", "/etc/sovagrid-vpn-routing")
    targets = (*roots, *(absolute for _, absolute, _ in AMNEZIA))
    require(not any(os.path.lexists(path) for path in targets), "VM has existing SovaGrid/VPN state")
    try:
        pwd.getpwnam("sovagrid")
    except KeyError:
        pass
    else:
        raise RuntimeError("VM already has the SovaGrid identity")
    manifest_raw = (bundle / "sovagrid-bundle.json").read_bytes()
    manifest = json.loads(manifest_raw)
    source, package = Installer.project(bundle, manifest)
    baseline = hashlib.sha256(manifest_raw).hexdigest()
    installer = Installer()
    cleanup_allowed = False
    parent_permissions = []
    try:
        # Hosted images make some /usr/local tool directories writable to the
        # runner. Give the real broker its production parent-directory contract
        # in this explicitly disposable VM, and restore that fixture change.
        for directory in ("/usr/local", "/usr/local/bin", "/usr/local/libexec",
                          "/etc/systemd/system"):
            if not os.path.lexists(directory):
                continue
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                require(stat.S_ISDIR(info.st_mode), "fixed broker parent is not a directory")
                parent_permissions.append((directory, info.st_dev, info.st_ino,
                                           info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)))
                os.fchown(fd, 0, 0)
                os.fchmod(fd, 0o755)
            finally:
                os.close(fd)
        run("/usr/sbin/useradd", "--system", "--user-group", "--no-create-home",
            "--home-dir", "/var/lib/sovagrid-agent", "--shell", "/usr/sbin/nologin", "sovagrid")
        cleanup_allowed = True
        preview = installer.preview(baseline, source, package)
        installer.apply(baseline, source, package, preview["expected"])
        Path("/var/lib/sovagrid-vpn").mkdir(mode=0o700)
        sys.path.insert(0, "/opt/sovagrid-vpn")
        from sovagrid_vpn.amnezia_install import Installer as BrokerInstaller
        BrokerInstaller().install()
        marker = Path("/etc/sovagrid-vpn/amnezia-control.enabled")
        marker.write_bytes(b"enabled\n"); marker.chmod(0o600)
        run("/usr/bin/systemctl", "enable", "--now", "sovagrid-amnezia-control.socket")
        run("/usr/bin/systemctl", "start", "sovagrid-amnezia-control.service")
        # A harmless source-only test revision also exercises every deployed
        # control-file replacement, without executing any VPN/peer command.
        candidate = {name: raw + b"\n# disposable source-maintenance candidate\n" for name, raw in source.items()}
        candidate_package = {name: raw + b"\n# disposable source-maintenance candidate\n"
                             for name, raw in package.items()}
        digest = hashlib.sha256(b"disposable-source-maintenance-v1").hexdigest()
        reviewed = installer.preview(digest, candidate, candidate_package)
        require(reviewed.get("maintenance_required") is True, "existing broker was not detected")
        try:
            installer.apply(digest, candidate, candidate_package, reviewed["expected"])
        except Refuse as error:
            require(error.code == "CONTROL_ACTIVE", "unconfirmed apply failed for another reason")
        else:
            raise RuntimeError("unconfirmed maintenance was accepted")
        result = installer.apply(digest, candidate, candidate_package, reviewed["expected"], maintenance=True)
        require(result["changed"] and not result["cleanup_required"], "maintenance did not commit")
        run("/usr/bin/systemctl", "is-active", "--quiet", "sovagrid-amnezia-control.socket")
        run("/usr/bin/systemctl", "is-active", "--quiet", "sovagrid-amnezia-control.service")
        require(marker.read_bytes() == b"enabled\n", "arm policy changed")
        before, _ = installer._state()
        # Regress the unchanged-package recovery case on real systemd: only
        # deployment files change, and interruption precedes package backup.
        second = {name: raw + b"# second deploy-only candidate\n" if name.startswith("deploy/") else raw
                  for name, raw in candidate.items()}
        second_package = dict(candidate_package)
        second_digest = hashlib.sha256(b"disposable-source-maintenance-v2").hexdigest()
        expected = installer.preview(second_digest, second, second_package)["expected"]
        pid = os.fork()
        if pid == 0:
            installer.checkpoint = lambda phase: os._exit(81) if phase == "source_switched" else None
            try:
                installer.apply(second_digest, second, second_package, expected, maintenance=True)
            except BaseException:
                os._exit(82)
            os._exit(83)
        _, status = os.waitpid(pid, 0)
        require(os.waitstatus_to_exitcode(status) == 81, "fault injection did not reach source switch")
        require(Path(JOURNAL).is_file() and Path(BLOCKER).is_file(), "durable startup guard is missing")
        # Simulate systemd activation after reboot while package files are partial.
        run("/usr/bin/systemctl", "start", "sovagrid-amnezia-control.service", accepted=(0, 1))
        require(run("/usr/bin/systemctl", "is-active", "--quiet", "sovagrid-amnezia-control.service",
                    accepted=(0, 3)).returncode == 3, "partial package was allowed to start")
        require(installer.recover()["recovered"], "interrupted maintenance was not recovered")
        after, _ = installer._state()
        require(after["source_files"] == before["source_files"] and after["package_files"] == before["package_files"],
                "recovery did not restore the previous source")
        run("/usr/bin/systemctl", "is-active", "--quiet", "sovagrid-amnezia-control.socket")
        run("/usr/bin/systemctl", "is-active", "--quiet", "sovagrid-amnezia-control.service")
        require(not Path(JOURNAL).exists() and not Path(BLOCKER).exists(), "recovery left its guard")
        require(not installer.recover()["recovered"], "recovery is not idempotent")
        print("VPN source maintenance VM gate: upgrade, explicit consent, process-exit recovery and startup fence passed")
    finally:
        if cleanup_allowed:
            # The clean-target gate above established absence of every path.
            # A failure retains the disposable VM's files for diagnosis rather
            # than deleting an incomplete transaction or an external edit.
            if not Path(JOURNAL).exists():
                if Path("/etc/systemd/system/sovagrid-amnezia-control.socket").exists():
                    run("/usr/bin/systemctl", "disable", "--now", "sovagrid-amnezia-control.socket")
                if Path("/etc/systemd/system/sovagrid-amnezia-control.service").exists():
                    run("/usr/bin/systemctl", "stop", "sovagrid-amnezia-control.service")
                for _, absolute, _ in AMNEZIA:
                    Path(absolute).unlink(missing_ok=True)
                run("/usr/bin/systemctl", "daemon-reload")
                for absolute in roots:
                    if Path(absolute).exists(): shutil.rmtree(absolute)
                run("/usr/sbin/userdel", "sovagrid")
                run("/usr/sbin/groupdel", "sovagrid", accepted=(0, 6))
                for directory, dev, ino, uid, gid, mode in reversed(parent_permissions):
                    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        info = os.fstat(fd)
                        require((info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                                 stat.S_IMODE(info.st_mode)) == (dev, ino, 0, 0, 0o755),
                                "fixed broker parent changed during fixture")
                        os.fchown(fd, uid, gid)
                        os.fchmod(fd, mode)
                    finally:
                        os.close(fd)


if __name__ == "__main__":
    main()
