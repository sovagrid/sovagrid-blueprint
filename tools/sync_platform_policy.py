#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
"""Render/check capability minima in standalone SSH/bootstrap clients."""

import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
TARGETS = (
    "sovagrid-blueprint/run.sh",
    "sovagrid-blueprint/bootstrap/run.sh",
    "sovagrid-blueprint/deploy/remote_agent.py",
    "sovagrid-blueprint/deploy/remote_update_worker.py",
    "sovagrid-blueprint/deploy/promote_agent_only.py",
    "sovagrid-blueprint/deploy/hub_only_update.py",
    "sovagrid-connect/sovagrid_connect/server_status.py",
    "sovagrid-connect/sovagrid_connect/installer.py",
    "sovagrid-connect/sovagrid_connect/agent_rpc.py",
    "sovagrid-connect/sovagrid_connect/enrollment_protocol.py",
    "sovagrid-connect/sovagrid_connect/remote_update.py",
    "sovagrid-connect/sovagrid_connect/nftables_dependency_remote.py",
    "sovagrid-apple/SovaGrid/ServerBootstrap.swift",
    "sovagrid-apple/SovaGrid/ServerDeployment.swift",
    "sovagrid-android/ssh-core/src/main/kotlin/org/sovagrid/ssh/ServerBootstrap.kt",
    "sovagrid-android/ssh-core/src/main/kotlin/org/sovagrid/ssh/ServerDeployment.kt",
    "sovagrid-web/gateway/server.js",
    "sovagrid-web/app.js",
)


def policy(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict)
        or set(data) != {"format", "hub_runtime", "managed_host", "portable_restore"}
        or type(data["format"]) is not int
        or data["format"] != 1
    ):
        raise ValueError("invalid capability contract")
    hub, host, restore = (
        data["hub_runtime"],
        data["managed_host"],
        data["portable_restore"],
    )
    expected_host = {
        "kernel",
        "python_executable",
        "python_minimum",
        "systemd_minimum",
        "systemd_states",
        "identity",
        "nologin",
        "procfs",
        "command_semantics",
        "automatic_package_adapters",
        "container_engine",
        "compose_minimum_major",
        "bash_minimum_major",
        "journal",
        "docker_executable",
        "docker_endpoint",
    }
    if not isinstance(host, dict) or set(host) != expected_host:
        raise ValueError("invalid managed host capabilities")
    if not isinstance(hub, dict) or set(hub) != {
        "python_minimum",
        "required_python_modules",
        "required_crypto",
        "filesystem_capabilities",
        "network",
    }:
        raise ValueError("invalid Hub runtime capabilities")

    def python_version(value):
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[1-9][0-9]*\.(?:0|[1-9][0-9]*)", value) is None
            or tuple(map(int, value.split("."))) < (3, 10)
        ):
            raise ValueError("Python capability is below the implemented minimum")
        return value

    python_version(hub["python_minimum"])
    python_version(host["python_minimum"])
    if (
        host["kernel"] != "linux"
        or host["python_executable"] != "/usr/bin/python3"
        or host["systemd_states"] != ["running", "degraded"]
        or host["identity"] != "posix-root-uid-and-gid-0"
        or host["nologin"] != "/usr/sbin/nologin"
        or host["procfs"]
        != ["/proc/stat", "/proc/meminfo", "/proc/net/dev", "/proc/self/fd"]
        or host["command_semantics"] != ["gnu-coreutils", "util-linux", "iproute2"]
        or host["automatic_package_adapters"] != ["apt"]
        or host["container_engine"] != "docker"
        or type(host["bash_minimum_major"]) is not int
        or host["bash_minimum_major"] != 4
        or host["journal"] != "systemd-journal-runtime"
        or host["docker_executable"] != "/usr/bin/docker"
        or host["docker_endpoint"] != "unix:///var/run/docker.sock"
        or type(host["compose_minimum_major"]) is not int
        or host["compose_minimum_major"] != 2
        or hub["required_python_modules"] != ["sqlite3", "ssl", "fcntl", "pwd"]
        or hub["required_crypto"] != ["hashlib.scrypt"]
        or hub["filesystem_capabilities"]
        != ["posix-ownership-and-modes", "O_NOFOLLOW", "dir_fd-operations"]
        or hub["network"] != ["ipv4-tcp"]
    ):
        raise ValueError("capability profile needs a runtime implementation")
    if (
        not isinstance(host["systemd_minimum"], str)
        or re.fullmatch(r"[1-9][0-9]*", host["systemd_minimum"]) is None
        or int(host["systemd_minimum"]) < 247
    ):
        raise ValueError("systemd capability is below the implemented minimum")
    if (
        not isinstance(restore, dict)
        or set(restore) != {"contract", "platform_pairs"}
        or restore["contract"] != "full/v2"
        or restore["platform_pairs"] != ["ubuntu:22.04", "ubuntu:24.04", "ubuntu:26.04"]
    ):
        raise ValueError("portable restore contract needs separate migration support")
    return data, {
        "SOVAGRID_MIN_PYTHON": host["python_minimum"],
        "SOVAGRID_MIN_SYSTEMD": host["systemd_minimum"],
    }


def synchronize(
    base, literal, *, write=False, targets=TARGETS, variable="SOVAGRID_MIN_PYTHON"
):
    assignment = re.compile(
        r"""(\b""" + re.escape(variable) + r"""\s*=\s*)(['"])([a-z0-9. :]+)(\2)"""
    )
    differences = []
    for relative in targets:
        path = Path(base) / relative
        source = path.read_text(encoding="utf-8")
        if "SOVAGRID_PLATFORM_PAIRS" in source:
            raise ValueError("obsolete OS admission list: " + relative)
        matches = list(assignment.finditer(source))
        if not matches:
            raise ValueError("missing standalone requirement: " + relative)
        replacement = assignment.sub(lambda m: m[1] + m[2] + literal + m[4], source)
        if replacement != source:
            differences.append(relative)
            if write:
                path.write_text(replacement, encoding="utf-8")
    return differences


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "sync"))
    parser.add_argument("--root", type=Path, default=ROOT.parent)
    args = parser.parse_args()
    try:
        data, minima = policy(ROOT / "platforms/requirements.json")
        changes = []
        for variable, literal in minima.items():
            changes += synchronize(
                args.root, literal, write=args.action == "sync", variable=variable
            )
        changes += synchronize(
            args.root,
            " ".join(data["portable_restore"]["platform_pairs"]),
            write=args.action == "sync",
            targets=(
                "sovagrid-blueprint/deploy/host_backup_orchestrator.py",
                "sovagrid-blueprint/run.sh",
                "sovagrid-blueprint/deploy/portable_restore_bootstrap.sh",
            ),
            variable="SOVAGRID_PORTABLE_PLATFORM_PAIRS",
        )
    except (ValueError, OSError) as error:
        parser.exit(1, str(error) + "\n")
    if changes and args.action == "check":
        parser.exit(1, "Platform policy drift: " + ", ".join(changes) + "\n")
    print(
        "Runtime capability requirements "
        + ("synchronized" if args.action == "sync" else "verified")
    )


if __name__ == "__main__":
    main()
