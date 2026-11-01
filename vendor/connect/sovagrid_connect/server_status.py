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
_MANAGED_VPN_SOURCE_CHECK = r'''
def managed_vpn_source(root=None, owner=0):
    'Recognize only a root-owned, hash-closed Agent VPN extension; never execute it.'
    import hashlib
    import json
    import os
    from pathlib import Path
    import re
    import stat
    import time

    root = Path('/') if root is None else Path(root)
    descriptor = None
    deadline, consumed, visited = time.monotonic() + 5, 0, 0
    sha = re.compile(r'[0-9a-f]{64}\Z')
    part = re.compile(r'[A-Za-z0-9_.-]+\Z')
    stage = re.compile(r'/opt/\.sovagrid-vpn-source-[0-9a-f]{32}\Z')

    def need(value):
        if not value or time.monotonic() > deadline:
            raise ValueError('invalid managed VPN namespace')

    def checked(fd, directory=False, mode=None):
        info = os.fstat(fd)
        need(info.st_uid == owner and not info.st_mode & 0o022 and
             (stat.S_ISDIR(info.st_mode) if directory else
              stat.S_ISREG(info.st_mode) and info.st_nlink == 1))
        need(mode is None or stat.S_IMODE(info.st_mode) == mode)
        return info

    def entries(fd, limit):
        names = []
        with os.scandir(fd) as iterator:
            for entry in iterator:
                need(len(names) < limit)
                names.append(entry.name)
        return names

    def directory(path):
        fd = os.dup(descriptor)
        try:
            for name in Path(path).parts[1:]:
                need(part.fullmatch(name) is not None and name not in ('.', '..'))
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=fd)
                os.close(fd)
                fd = child
                checked(fd, directory=True)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read(fd, name, limit, *, digest=False, mode=None, attempt=0):
        nonlocal consumed
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                        dir_fd=fd)
        try:
            before = checked(child, mode=mode)
            need(before.st_size <= limit)
            data, hashing, size = [], hashlib.sha256(), 0
            while True:
                block = os.read(child, min(65536, limit + 1 - size))
                if not block:
                    break
                size += len(block)
                consumed += len(block)
                need(size <= limit and consumed <= 512 * 1024 * 1024)
                if digest:
                    hashing.update(block)
                else:
                    data.append(block)
            after = os.fstat(child)
            if before.st_nlink == 1 and after.st_nlink == 0:
                # A publisher can atomically replace its old inode while this
                # descriptor is held. Read the new file; never accept old bytes.
                current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                need(attempt < 2 and stat.S_ISREG(current.st_mode) and
                     current.st_uid == owner and current.st_nlink == 1 and not current.st_mode & 0o022 and
                     (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino))
                return read(fd, name, limit, digest=digest, mode=mode, attempt=attempt + 1)
            after = checked(child, mode=mode)
            need((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                 (after.st_size, after.st_mtime_ns, after.st_ctime_ns) and size == before.st_size)
            return hashing.hexdigest() if digest else b''.join(data)
        finally:
            os.close(child)

    def closed(path, allowed, required=()):
        fd = directory(path)
        try:
            names = set(entries(fd, 16))
            need(set(required) <= names <= set(allowed))
        except BaseException:
            os.close(fd)
            raise
        return fd, names

    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result)
            result[key] = value
        return result

    def document(raw):
        value = json.loads(raw, object_pairs_hook=unique)
        need(json.dumps(value, sort_keys=True, separators=(',', ':'),
                        ensure_ascii=False, allow_nan=False).encode() == raw)
        return value

    def hashes(value):
        need(type(value) is dict and 1 <= len(value) <= 4096)
        for name, digest in value.items():
            need(type(name) is str and len(name) <= 255 and
                 all(piece not in ('', '.', '..') and part.fullmatch(piece)
                     for piece in name.split('/')) and type(digest) is str and sha.fullmatch(digest))

    def receipt(value):
        need(type(value) is dict and set(value) == {'protocol', 'phase', 'source_manifest_sha256',
             'source_files', 'package_files', 'garbage_stage'} and type(value['protocol']) is int and
             value['protocol'] == 1 and value['phase'] == 'active' and
             type(value['source_manifest_sha256']) is str and sha.fullmatch(value['source_manifest_sha256']))
        hashes(value['source_files'])
        hashes(value['package_files'])
        required = {'LICENSE', 'NOTICE', 'ATTRIBUTION.md', 'deploy/install-amnezia-control.py',
            'deploy/install-wireguard-control.py', 'deploy/sovagrid-amnezia-provision',
            'sovagrid_vpn/amnezia_install.py', 'sovagrid_vpn/amnezia_admin.py',
            'sovagrid_vpn/amnezia_provision.py', 'sovagrid_vpn/wireguard_install.py'}
        need(required <= set(value['source_files']))
        need(value['package_files'] == {name.split('/')[1]: digest
            for name, digest in value['source_files'].items()
            if name.startswith('sovagrid_vpn/') and name.endswith('.py') and name.count('/') == 1})
        need(value['garbage_stage'] is None or type(value['garbage_stage']) is str and
             stage.fullmatch(value['garbage_stage']))

    def tree(path, expected):
        directories = {''}
        caches = set()
        for name in expected:
            parents = name.split('/')[:-1]
            directories.update('/'.join(parents[:number]) for number in range(1, len(parents) + 1))
            if name.endswith('.py'):
                caches.add('/'.join(parents + ['__pycache__']))
        found = set()

        def walk(fd, prefix=''):
            nonlocal visited
            for name in entries(fd, 4096):
                visited += 1
                need(visited <= 16384 and part.fullmatch(name) and name not in ('.', '..'))
                relative = prefix + name
                if relative in directories or relative in caches:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=fd)
                    try:
                        checked(child, directory=True)
                        walk(child, relative + '/')
                    finally:
                        os.close(child)
                elif relative in expected:
                    need(read(fd, name, 32 * 1024 * 1024, digest=True) == expected[relative])
                    found.add(relative)
                else:
                    match = re.fullmatch(r'(.*?)(?:__pycache__/)([A-Za-z0-9_.-]+)\.cpython-[0-9]+\.pyc', relative)
                    need(match is not None and match[1] + match[2] + '.py' in expected)
                    read(fd, name, 32 * 1024 * 1024, digest=True)
        fd = directory(path)
        try:
            walk(fd)
            need(found == set(expected))
        finally:
            os.close(fd)

    opened = []
    try:
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        checked(descriptor, directory=True)
        for path, allowed, required in (
            ('/opt/sovagrid-src', {'sovagrid-vpn'}, {'sovagrid-vpn'}),
            ('/opt/sovagrid-vpn', {'sovagrid_vpn'}, {'sovagrid_vpn'}),
            ('/var/lib/sovagrid', {'vpn-source', 'vpn'}, {'vpn-source'})):
            fd, _names = closed(path, allowed, required)
            opened.append(fd)
        fd, names = closed('/var/lib/sovagrid/vpn-source', {'state.json', '.lock'}, {'state.json'})
        opened.append(fd)
        checked(fd, directory=True, mode=0o700)
        raw = read(fd, 'state.json', 512 * 1024, mode=0o600)
        state = document(raw)
        receipt(state)
        if '.lock' in names:
            need(read(fd, '.lock', 0, mode=0o600) == b'')
        tree('/opt/sovagrid-src/sovagrid-vpn', state['source_files'])
        tree('/opt/sovagrid-vpn/sovagrid_vpn', state['package_files'])
        if state['garbage_stage'] is not None:
            try:
                garbage = directory(state['garbage_stage'])
            except FileNotFoundError:
                pass
            else:
                try:
                    checked(garbage, directory=True, mode=0o700)
                finally:
                    os.close(garbage)
        if 'vpn' in set(entries(opened[2], 16)):
            vpn = directory('/var/lib/sovagrid/vpn')
            opened.append(vpn)
            for name in entries(vpn, 32):
                need(name == 'status.json' or re.fullmatch(r'\.vpn-status-[A-Za-z0-9_]{8}', name))
                if name != 'status.json':
                    try:
                        temporary = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                            dir_fd=vpn)
                    except FileNotFoundError:
                        continue  # This known publisher scratch file was renamed.
                    try:
                        need(checked(temporary).st_size <= 65536)
                    finally:
                        os.close(temporary)
                    continue  # A scratch file may still contain incomplete JSON.
                value = json.loads(read(vpn, name, 65536), object_pairs_hook=unique)
                need(type(value) is dict and type(value.get('schema_version')) is int and value['schema_version'] == 1 and
                     type(value.get('collected_at')) is int and value['collected_at'] > 0)
        need(read(fd, 'state.json', 512 * 1024, mode=0o600) == raw)
        need(set(entries(opened[0], 16)) == {'sovagrid-vpn'} and
             set(entries(opened[1], 16)) == {'sovagrid_vpn'} and
             {'vpn-source'} <= set(entries(opened[2], 16)) <= {'vpn-source', 'vpn'} and
             set(entries(fd, 16)) == names)
        return True
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, AttributeError):
        return False
    finally:
        for fd in opened:
            os.close(fd)
        if descriptor is not None:
            os.close(descriptor)
'''

STATUS_SCRIPT = r'''# SOVAGRID_SSH_STATUS_V1
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
''' + _MANAGED_VPN_SOURCE_CHECK + r'''
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
        '/etc/sovagrid-hub', '/etc/sovagrid/.agent-unit-managed-by-run-sh',
    )):
        vpn = any(present(path) for path in ('/opt/sovagrid-src', '/opt/sovagrid-vpn', '/var/lib/sovagrid'))
        if not vpn or managed_vpn_source(root, owner=0 if root == Path('/') else os.getuid()):
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
