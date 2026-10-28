# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Read-only SSH inventory before offering a first server installation.

This probe is deliberately conservative. A partial installation is a conflict,
and a remote Agent enrolled to another Hub is never a fresh host.
"""

from __future__ import annotations

from dataclasses import dataclass
import re


KINDS = frozenset({"managed", "agent_only", "missing", "conflict", "unsupported", "unknown"})
STATUS_MARKER = re.compile(r"SG_STATUS_V1:(managed|agent_only|missing|conflict|unsupported|unknown)\Z")

# No untrusted values enter this command. A non-root account may perform the
# read-only inventory with passwordless sudo; without it the result is unknown.
# The later installer has its own root, Ubuntu and empty-host preflight.
STATUS_COMMAND = (
    "sh -c '"
    "if ! command -v python3 >/dev/null 2>&1; then printf \"SG_STATUS_V1:unsupported\\n\"; exit 0; fi; "
    "if [ \"$(id -u)\" = 0 ]; then exec python3 -; fi; "
    "if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; "
    "then exec sudo -n python3 -; fi; "
    "printf \"SG_STATUS_V1:unknown\\n\"'"
)

# The second argument exists only for local fixture tests. The SSH command
# above never passes one, so the actual probe always inspects the real host.
STATUS_SCRIPT = r'''# SOVAGRID_SSH_STATUS_V1
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path('/')

def node(path):
    target = root / path.lstrip('/')
    try:
        return target.lstat()
    except FileNotFoundError:
        return None

def present(path):
    return node(path) is not None

def regular(path):
    info = node(path)
    return info is not None and stat.S_ISREG(info.st_mode) and (root != Path('/') or info.st_uid == 0)

def directory(path):
    info = node(path)
    return info is not None and stat.S_ISDIR(info.st_mode) and (root != Path('/') or info.st_uid == 0)

def result(kind):
    print('SG_STATUS_V1:' + kind, flush=True)
    raise SystemExit(0)

try:
    if root == Path('/') and os.geteuid() != 0:
        result('unknown')
    release = root / 'etc/os-release'
    if not release.is_file():
        result('unsupported')
    raw = release.read_text(encoding='utf-8')[:8192]
    values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line and not line.startswith('#'))
    if values.get('ID', '').strip('"\'') != 'ubuntu':
        result('unsupported')
    full = directory('/opt/sovagrid-src') and regular('/opt/sovagrid-src/sovagrid-bundle.json') and \
        regular('/var/lib/sovagrid/.managed-by-run-sh')
    if full:
        result('managed')
    agent = regular('/opt/sovagrid-agent-installer/source-manifest.json') and \
        regular('/etc/systemd/system/sovagrid-agent.service') and \
        directory('/var/lib/sovagrid-agent-enrollment')
    if agent and not any(present(path) for path in (
        '/opt/sovagrid-src', '/etc/sovagrid-hub', '/var/lib/sovagrid',
        '/etc/sovagrid/.agent-unit-managed-by-run-sh',
    )):
        result('agent_only')
    reserved = (
        '/opt/sovagrid-src', '/opt/sovagrid-agent', '/opt/sovagrid-agent-installer',
        '/opt/sovagrid-vpn', '/etc/sovagrid', '/etc/sovagrid-hub',
        '/etc/sovagrid-agent-tunnel', '/etc/sovagrid-agent-tunnel-public',
        '/var/lib/sovagrid', '/var/lib/sovagrid-agent',
        '/var/lib/sovagrid-agent-enrollment', '/var/lib/sovagrid-hub-tunnels',
        '/var/lib/sovagrid-first-install',
    )
    if any(present(path) for path in reserved):
        result('conflict')
    for base in ('/etc/systemd/system', '/run/systemd/system', '/usr/local/lib/systemd/system'):
        path = root / base.lstrip('/')
        if path.is_dir() and any(entry.name.startswith('sovagrid-') for entry in path.iterdir()):
            result('conflict')
    if root == Path('/') and shutil.which('docker'):
        scan = subprocess.run(
            ['docker', 'ps', '-a', '--filter', 'label=com.docker.compose.project=sovagrid',
             '--format', '{{.ID}}'], capture_output=True, timeout=8, check=False,
        )
        if scan.returncode != 0:
            result('unknown')
        if scan.stdout.strip():
            result('conflict')
    result('missing')
except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
    result('unknown')
'''


@dataclass(frozen=True)
class ServerStatus:
    kind: str

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError("unknown server status")

    @property
    def safe_first_install(self) -> bool:
        return self.kind == "missing"


def parse_status(markers: list[str], *, returncode: int) -> ServerStatus:
    matches = [match.group(1) for marker in markers if (match := STATUS_MARKER.fullmatch(marker))]
    if returncode != 0 or len(matches) != 1:
        return ServerStatus("unknown")
    return ServerStatus(matches[0])
