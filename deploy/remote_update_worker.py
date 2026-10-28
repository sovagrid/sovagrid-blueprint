# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
# SOVAGRID_REMOTE_UPDATE_WORKER_V1: vendored transaction engine from Connect.
import contextlib
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import shutil
import signal
import socket
import sqlite3
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request

ROOT = Path('/')
PUBLIC_OWNER = 0
BROKER_OWNER_GID = 0
COMPONENTS = {'sovagrid-blueprint', 'sovagrid-hub', 'sovagrid-web', 'sovagrid-agent', 'sovagrid-vpn'}
REQUIRED = {'sovagrid-blueprint/run.sh', 'sovagrid-blueprint/deploy/compose.yaml',
            'sovagrid-hub/Dockerfile', 'sovagrid-web/Dockerfile',
            'sovagrid-web/deploy/Caddyfile.container',
            'sovagrid-agent/deploy/sovagrid-agent.service',
            'sovagrid-vpn/deploy/sovagrid-vpn-status.service'}
LEGACY_UNITS = ('sovagrid-agent.service', 'sovagrid-vpn-status.timer',
         'sovagrid-auto-update.timer',
         'sovagrid-vpn-control.socket', 'sovagrid-vpn-control.service',
         'sovagrid-terminal-control.socket', 'sovagrid-terminal-control.service',
         'sovagrid-journal-control.socket', 'sovagrid-journal-control.service',
         'sovagrid-container-inventory.timer', 'sovagrid-container-inventory.service')
RELEASE_FEED_UNITS = LEGACY_UNITS + ('sovagrid-release-feed.timer',)
SERVICE_UNITS = ('sovagrid-service-control.socket', 'sovagrid-service-control.service')
SERVICE_ALL_UNITS = RELEASE_FEED_UNITS + SERVICE_UNITS
ROUTING_UNIT = 'sovagrid-vpn-routing.service'
ROUTING_ALL_UNITS = SERVICE_ALL_UNITS + (ROUTING_UNIT,)
BACKUP_BROKER_UNITS = ('sovagrid-hub-backup-control.socket',
                       'sovagrid-hub-backup-control.service')
UNITS = ROUTING_ALL_UNITS + BACKUP_BROKER_UNITS
BACKUP_BROKER_MARKER = '/var/lib/sovagrid/.hub-backup-broker-managed-by-run-sh'
BACKUP_BROKER_LEDGER = '/var/lib/sovagrid/backups/.broker-requests'
SSH_GATEWAY_MARKER = '/var/lib/sovagrid/.ssh-gateway-managed-by-run-sh'
SSH_GATEWAY_MARKER_CONTENT = b'SOVAGRID_SSH_GATEWAY_V1\n'
BASE_COMPOSE_SERVICES = ('hub', 'web')
SSH_GATEWAY_SERVICE = 'ssh-gateway'
LEGACY_SNAPSHOT = ('/opt/sovagrid-agent', '/opt/sovagrid-vpn', '/etc/sovagrid',
            '/etc/sovagrid-hub', '/etc/sovagrid-journal', '/var/lib/sovagrid/hub',
            '/var/lib/sovagrid/caddy', '/var/lib/sovagrid/vpn', '/var/lib/sovagrid-containers',
            '/usr/local/bin/sovagrid-vpn-ctl', '/usr/local/libexec/sovagrid-vpn-broker',
            '/etc/apparmor.d/local/wg-quick',
            '/etc/systemd/system/sovagrid-vpn-status.service',
            '/etc/systemd/system/sovagrid-auto-update.service') + \
           tuple('/etc/systemd/system/' + unit for unit in LEGACY_UNITS)
RELEASE_FEED_SNAPSHOT = LEGACY_SNAPSHOT + (
    '/var/lib/sovagrid/.release-feed-units-managed-by-run-sh',
    '/var/lib/sovagrid/release-feed-state.json',
    '/etc/systemd/system/sovagrid-release-feed.service',
    '/etc/systemd/system/sovagrid-release-feed.timer',
)
SERVICE_SNAPSHOT = RELEASE_FEED_SNAPSHOT + (
    '/etc/sovagrid-service',
    '/etc/systemd/system/sovagrid-service-control.socket',
    '/etc/systemd/system/sovagrid-service-control.service',
)
ROUTING_SNAPSHOT = SERVICE_SNAPSHOT + (
    '/etc/sovagrid-vpn-routing/policy.json',
    '/etc/sysctl.d/70-sovagrid-vpn-routing.conf',
    '/etc/systemd/system/sovagrid-vpn-routing.service',
)
HUB_BACKUP_SNAPSHOT = ROUTING_SNAPSHOT + (
    BACKUP_BROKER_MARKER,
    BACKUP_BROKER_LEDGER,
    *(f'/etc/systemd/system/{unit}' for unit in BACKUP_BROKER_UNITS),
)
SNAPSHOT = HUB_BACKUP_SNAPSHOT + (SSH_GATEWAY_MARKER,)
MAX_BACKUP = 4 * 1024**3
MAX_FAILURE_LOG = 2 * 1024**2
MAX_FAILURE_LOGS = 5
ACTIVE_CHILD = None
HUB_UID = 10001
HUB_GID = 10001
AGENT_UNIT = 'sovagrid-agent.service'
AGENT_CONTROL = '/run/sovagrid-agent-control/agent.sock'
AGENT_IDLE_FIELDS = frozenset(('jobs_inflight', 'file_operations', 'terminal_sessions',
                               'upload_sessions', 'network_checks', 'probe_helpers'))

class UpdateFailure(Exception):
    pass

def path(value):
    return ROOT / value.lstrip('/')

def emit(value):
    try:
        print(value, flush=True)
    except BrokenPipeError:
        pass

def fail(code):
    emit('SG_UPDATE_REFUSE:' + code)
    raise UpdateFailure(code)

def command(args, *, timeout=120, check=True, env=None, stdout=None):
    global ACTIVE_CHILD
    try:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout or subprocess.DEVNULL,
                                   stderr=subprocess.STDOUT if stdout is not None else subprocess.DEVNULL,
                                   env=env, start_new_session=True)
        ACTIVE_CHILD = process
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise UpdateFailure('command timed out: ' + str(args[0])) from exc
    except OSError as exc:
        raise UpdateFailure('command failed: ' + str(args[0])) from exc
    finally:
        ACTIVE_CHILD = None
    if check and code:
        raise UpdateFailure('command failed: ' + str(args[0]))
    return code

def sha256_file(value):
    digest = hashlib.sha256()
    with open(value, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()

def safe_tree(root, *, private=False):
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise UpdateFailure('unsafe source directory')
    if private and stat.S_IMODE(info.st_mode) != 0o700:
        raise UpdateFailure('unsafe candidate directory')
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            item = Path(parent) / name
            info = item.lstat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise UpdateFailure('unsafe source owner or mode')
            if name in dirs and not stat.S_ISDIR(info.st_mode):
                raise UpdateFailure('unsafe source directory type')
            if name in files and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                raise UpdateFailure('unsafe source file type')

def private_candidate_root(root):
    if (not root.is_dir() or root.is_symlink() or root.stat().st_uid != 0 or
            stat.S_IMODE(root.stat().st_mode) != 0o700):
        fail('CANDIDATE')

def validate_lock(info):
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        fail('STATE')

def source_manifest(root, *, allow_generated=False):
    safe_tree(root)
    if not allow_generated:
        for parent, dirs, files in os.walk(root, followlinks=False):
            for name in dirs:
                if stat.S_IMODE((Path(parent) / name).lstat().st_mode) != 0o755:
                    raise UpdateFailure('candidate directory mode mismatch')
            for name in files:
                item = Path(parent) / name
                mode = stat.S_IMODE(item.lstat().st_mode)
                if mode not in (0o644, 0o755) or (
                    item.relative_to(root).as_posix() == 'sovagrid-web/deploy/Caddyfile.container' and mode != 0o644
                ):
                    raise UpdateFailure('candidate file mode mismatch')
    manifest_path = root / 'sovagrid-bundle.json'
    if not manifest_path.is_file() or manifest_path.stat().st_size > 512 * 1024:
        raise UpdateFailure('missing source manifest')
    raw = manifest_path.read_bytes()
    data = json.loads(raw)
    if set(data) != {'format', 'components', 'sha256'} or type(data['format']) is not int or data['format'] != 1:
        raise UpdateFailure('unsupported source manifest')
    components, hashes = data['components'], data['sha256']
    if not isinstance(components, dict) or set(components) != COMPONENTS or not isinstance(hashes, dict):
        raise UpdateFailure('invalid source manifest')
    if not REQUIRED <= set(hashes) or {item.name for item in root.iterdir()} != COMPONENTS | {'sovagrid-bundle.json'}:
        raise UpdateFailure('incomplete source tree')
    actual = set()
    for parent, _dirs, files in os.walk(root):
        for name in files:
            item = Path(parent) / name
            relative = item.relative_to(root).as_posix()
            if relative == 'sovagrid-bundle.json':
                continue
            # The original installer imported Hub code once to create its
            # admin database. Older installs may therefore contain root-owned
            # Python bytecode that was not part of the signed-off source map.
            if allow_generated and re.fullmatch(
                r'sovagrid-[a-z]+/(?:[A-Za-z0-9_.-]+/)*__pycache__/[A-Za-z0-9_.-]+\.cpython-[0-9]+\.pyc',
                relative,
            ):
                continue
            if relative not in hashes or not re.fullmatch(r'[0-9a-f]{64}', str(hashes[relative])):
                raise UpdateFailure('unexpected source file')
            if sha256_file(item) != hashes[relative]:
                raise UpdateFailure('source hash mismatch')
            actual.add(relative)
    if actual != set(hashes):
        raise UpdateFailure('source file list mismatch')
    commits = {}
    for component, record in components.items():
        if not isinstance(record, dict) or set(record) != {'commit', 'file_count'}:
            raise UpdateFailure('invalid component version')
        commit = record['commit']
        count = sum(name.startswith(component + '/') for name in hashes)
        if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit) or type(record['file_count']) is not int or record['file_count'] != count:
            raise UpdateFailure('component version mismatch')
        commits[component] = commit
    return hashlib.sha256(raw).hexdigest(), commits

def candidate_source(digest):
    if not re.fullmatch(r'[0-9a-f]{64}', digest):
        fail('HASH')
    root = path('/opt/sovagrid-candidates') / digest
    if not root.is_dir() or root.is_symlink():
        fail('CANDIDATE')
    safe_tree(root, private=True)
    archive = root / 'bundle.tar.gz'
    if (not archive.is_file() or archive.is_symlink() or archive.stat().st_size > 64 * 1024**2 or
            archive.stat().st_size < 1 or (root / '.ready').read_text().strip() != digest or
            sha256_file(archive) != digest):
        fail('HASH')
    source = root / 'source'
    manifest_digest, commits = source_manifest(source)
    # Recheck that the staged source is exactly what was in the pinned archive.
    seen = set()
    files_seen = set()
    dirs_seen = set()
    manifest_bytes = None
    expanded = 0
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar:
            name = member.name.rstrip('/')
            if (len(seen) >= 4096 or name in seen or name.startswith('/') or '..' in name.split('/')
                    or '\\' in name or not name.isascii()):
                fail('CANDIDATE')
            seen.add(name)
            if member.isdir():
                dirs_seen.add(name)
                continue
            files_seen.add(name)
            if not member.isfile() or member.size > 32 * 1024**2:
                fail('CANDIDATE')
            expanded += member.size
            if expanded > 256 * 1024**2:
                fail('CANDIDATE')
            stream = tar.extractfile(member)
            if stream is None:
                fail('CANDIDATE')
            if name == 'sovagrid-bundle.json':
                manifest_bytes = stream.read()
            elif not (source / name).is_file() or hashlib.sha256(stream.read()).hexdigest() != sha256_file(source / name):
                fail('CANDIDATE')
    source_dirs = {str(item.relative_to(source)) for item in source.rglob('*') if item.is_dir()}
    if (manifest_bytes is None or hashlib.sha256(manifest_bytes).hexdigest() != manifest_digest or
            files_seen != set(json.loads(manifest_bytes)['sha256']) | {'sovagrid-bundle.json'} or
            not dirs_seen <= source_dirs):
        fail('CANDIDATE')
    return source, commits

def managed_routing_enabled():
    root = path('/etc/sovagrid-vpn-routing')
    policy = root / 'policy.json'
    unit = '/etc/systemd/system/' + ROUTING_UNIT
    sysctl = '/etc/sysctl.d/70-sovagrid-vpn-routing.conf'
    if not root.exists() and not root.is_symlink():
        if any(path(item).exists() or path(item).is_symlink() for item in (unit, sysctl)):
            fail('STATE')
        return False
    public_path('/etc/sovagrid-vpn-routing', directory=True, private=True)
    if not policy.exists() and not policy.is_symlink():
        if any(path(item).exists() or path(item).is_symlink() for item in (unit, sysctl)):
            fail('STATE')
        return False
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail('STATE')
            result[key] = value
        return result
    try:
        record = json.loads(public_path('/etc/sovagrid-vpn-routing/policy.json',
                                        private=True, limit=8192),
                            object_pairs_hook=unique)
    except (ValueError, UnicodeError, TypeError):
        fail('STATE')
    def valid_names(names):
        return (isinstance(names, list) and len(names) <= 64 and
                all(isinstance(name, str) and re.fullmatch(r'[a-z][a-z0-9-]{1,31}', name)
                    for name in names) and names == sorted(set(names)))
    if (not isinstance(record, dict) or set(record) != {'version', 'enabled', 'pending_remove'} or
            type(record['version']) is not int or record['version'] != 1 or
            any(not valid_names(record[field]) for field in ('enabled', 'pending_remove')) or
            record['pending_remove']):
        fail('STATE')
    enabled = bool(record['enabled'])
    if enabled:
        if any(not path(item).is_file() or path(item).is_symlink() for item in (unit, sysctl)):
            fail('STATE')
        public_path(unit, limit=4096)
        public_path(sysctl, limit=4096)
    elif any(path(item).exists() or path(item).is_symlink() for item in (unit, sysctl)):
        fail('STATE')
    return enabled

def managed_flags():
    config = json.loads(path('/etc/sovagrid/agent.json').read_text())
    if not isinstance(config, dict):
        fail('STATE')
    if config.get('allow_interactive_terminal') is True and not path('/etc/sovagrid/.terminal-unit-managed-by-run-sh').is_file():
        fail('STATE')
    if config.get('allow_systemd_journal') is True and not path('/etc/sovagrid/.journal-managed-by-run-sh').is_file():
        fail('STATE')
    container_marker = path('/etc/sovagrid/.containers-managed-by-run-sh')
    if container_marker.exists() or container_marker.is_symlink():
        info = container_marker.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            fail('STATE')
    flags = []
    expected = ['sovagrid-agent.service', 'sovagrid-vpn-status.timer']
    if managed_routing_enabled():
        expected.append(ROUTING_UNIT)
    if backup_broker_enabled():
        expected.append(BACKUP_BROKER_UNITS[0])
    feed_marker = '/var/lib/sovagrid/.release-feed-units-managed-by-run-sh'
    feed_config = '/etc/sovagrid/release-feed.json'
    feed_units = ('/etc/systemd/system/sovagrid-release-feed.service',
                  '/etc/systemd/system/sovagrid-release-feed.timer')
    if path(feed_marker).exists() or path(feed_marker).is_symlink():
        if public_path(feed_marker, private=True, limit=128) != b'SOVAGRID_RELEASE_FEED_UNITS_V1\n':
            fail('STATE')
        for unit_path in feed_units:
            if not path(unit_path).is_file() or path(unit_path).is_symlink():
                fail('STATE')
            public_path(unit_path, limit=8192)
        if path(feed_config).exists() or path(feed_config).is_symlink():
            public_path(feed_config, private=True)
            expected.append('sovagrid-release-feed.timer')
        feed_state = '/var/lib/sovagrid/release-feed-state.json'
        if path(feed_state).exists() or path(feed_state).is_symlink():
            public_path(feed_state, private=True)
    elif any(path(value).exists() or path(value).is_symlink()
             for value in (feed_config, *feed_units, '/var/lib/sovagrid/release-feed-state.json')):
        fail('STATE')
    # Socket-activated broker services normally return to inactive after a
    # request. Their enabled listening sockets are the health dependency.
    for marker, flag, units in (
        ('.vpn-control-managed-by-run-sh', '--with-wireguard', ('sovagrid-vpn-control.socket',)),
        ('.terminal-unit-managed-by-run-sh', '--with-terminal', ('sovagrid-terminal-control.socket',)),
    ):
        if path('/etc/sovagrid/' + marker).is_file():
            if flag == '--with-terminal' and config.get('allow_interactive_terminal') is not True:
                fail('STATE')
            flags.append(flag)
            expected.extend(units)
    if config.get('allow_file_manager') is True:
        roots = config.get('file_roots')
        if not isinstance(roots, dict) or roots.get('workspace') != '/var/lib/sovagrid-agent/files':
            fail('STATE')
        flags.append('--with-files')
    if path('/etc/sovagrid/.journal-managed-by-run-sh').is_file():
        groups = subprocess.run(['id', '-nG', 'sovagrid'], capture_output=True, text=True,
                                timeout=10, check=True).stdout.split()
        if 'systemd-journal' in groups or 'adm' in groups:
            fail('STATE')
        units = config.get('journal_units')
        if (config.get('allow_systemd_journal') is not True or not isinstance(units, list) or
                not 1 <= len(units) <= 16 or len(set(units)) != len(units) or
                any(not isinstance(unit, str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,96}\.service', unit) for unit in units)):
            fail('STATE')
        policy_file = path('/etc/sovagrid-journal/units.json')
        info = policy_file.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                stat.S_IMODE(info.st_mode) != 0o640):
            fail('STATE')
        policy = json.loads(policy_file.read_text())
        if policy != {'units': units}:
            fail('STATE')
        flags.append('--with-journal')
        for unit in units:
            flags += ['--journal-unit', unit]
        expected.append('sovagrid-journal-control.socket')
    if container_marker.is_file():
        directory = path('/var/lib/sovagrid-containers')
        snapshot = directory / 'snapshot.json'
        try:
            folder_info, file_info = directory.lstat(), snapshot.lstat()
        except OSError:
            fail('STATE')
        if (not stat.S_ISDIR(folder_info.st_mode) or folder_info.st_uid != 0 or
                stat.S_IMODE(folder_info.st_mode) != 0o750 or
                not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != 0 or
                file_info.st_gid != folder_info.st_gid or stat.S_IMODE(file_info.st_mode) != 0o640 or
                file_info.st_nlink != 1):
            fail('STATE')
        groups = subprocess.run(['id', '-g', 'sovagrid'], capture_output=True, text=True,
                                timeout=10, check=True).stdout.strip()
        if str(folder_info.st_gid) != groups:
            fail('STATE')
        flags.append('--with-containers')
        expected.append('sovagrid-container-inventory.timer')
    return flags, expected

def candidate_features_compatible(source, flags):
    script = (source / 'sovagrid-blueprint/run.sh').read_bytes()
    for flag in ('--with-wireguard', '--with-terminal', '--with-files', '--with-journal', '--with-containers'):
        if flag in flags and flag.encode() not in script:
            fail('COMPAT')
    if '--with-wireguard' in flags:
        for name in ('sovagrid-vpn-ctl', 'sovagrid-vpn-broker',
                     'sovagrid-vpn-control.socket', 'sovagrid-vpn-control.service'):
            if not (source / 'sovagrid-vpn/deploy' / name).is_file():
                fail('COMPAT')
    if managed_routing_enabled():
        for name in ('sovagrid-vpn/sovagrid_vpn/routing.py',
                     'sovagrid-vpn/sovagrid_vpn/managed.py'):
            if not (source / name).is_file():
                fail('COMPAT')
    if '--with-terminal' in flags:
        for name in ('sovagrid-terminal-control.socket', 'sovagrid-terminal-control.service'):
            if not (source / 'sovagrid-agent/deploy' / name).is_file():
                fail('COMPAT')
    if '--with-files' in flags and not (source / 'sovagrid-agent/sovagrid_agent/files.py').is_file():
        fail('COMPAT')
    if '--with-journal' in flags:
        if b'# SOVAGRID_JOURNAL_INSTALL_V1' not in script:
            fail('COMPAT')
        for name in ('sovagrid-journal-control.socket', 'sovagrid-journal-control.service'):
            if not (source / 'sovagrid-agent/deploy' / name).is_file():
                fail('COMPAT')
    if '--with-containers' in flags:
        if b'# SOVAGRID_CONTAINER_INVENTORY_V1' not in script:
            fail('COMPAT')
        for name in ('sovagrid_agent/containers.py', 'sovagrid_agent/container_collector.py',
                     'deploy/sovagrid-container-inventory.timer', 'deploy/sovagrid-container-inventory.service'):
            if not (source / 'sovagrid-agent' / name).is_file():
                fail('COMPAT')
    if path('/var/lib/sovagrid/.release-feed-units-managed-by-run-sh').is_file():
        if b'# SOVAGRID_RELEASE_FEED_UNITS_V1' not in script:
            fail('COMPAT')
        for name in ('release_feed.py', 'sovagrid-release-feed.service',
                     'sovagrid-release-feed.timer'):
            if not (source / 'sovagrid-blueprint/deploy' / name).is_file():
                fail('COMPAT')
    if backup_broker_enabled():
        if b'# SOVAGRID_HUB_BACKUP_BROKER_V1' not in script:
            fail('COMPAT')
        for name in ('sovagrid-blueprint/deploy/compose.backup.yaml',
                     'sovagrid-blueprint/deploy/sovagrid-hub-backup-control.socket',
                     'sovagrid-blueprint/deploy/sovagrid-hub-backup-control.service',
                     'sovagrid-hub/sovagrid_hub/backup_broker.py'):
            if not (source / name).is_file():
                fail('COMPAT')
    if ssh_gateway_managed():
        gateway_required = (
            'sovagrid-web/Dockerfile.ssh-gateway',
            'sovagrid-web/gateway/package.json',
            'sovagrid-web/gateway/package-lock.json',
            'sovagrid-web/gateway/server.js',
        )
        if (b'# SOVAGRID_SSH_GATEWAY_INSTALL_V1' not in script or
                b'# SOVAGRID_PUBLIC_SSH_REFRESH_V1' not in script or
                any(not (source / name).is_file() for name in gateway_required)):
            fail('COMPAT')
        caddy = (source / 'sovagrid-web/deploy/Caddyfile.container').read_bytes()
        if b'/api/v1/browser-ssh/' not in caddy:
            fail('COMPAT')
    # This is reached only after candidate_source verified every file against
    # the pinned archive. A downgrade must not silently discard public HTTPS.
    if path('/etc/sovagrid/public-web').exists() or path('/etc/sovagrid/public-web').is_symlink():
        public_web_overlay()
        public_required = ('sovagrid-blueprint/deploy/public_web.py',
                           'sovagrid-blueprint/deploy/public-web.site.template',
                           'sovagrid-blueprint/deploy/compose.public-web.template')
        if b'# SOVAGRID_PUBLIC_WEB_V1' not in script or any(not (source / name).is_file() for name in public_required):
            fail('COMPAT')
        caddy = (source / 'sovagrid-web/deploy/Caddyfile.container').read_bytes()
        if any(value not in caddy for value in (b'import /etc/caddy/public/global/*.options',
                                               b'import /etc/caddy/public/sites/*.caddy')):
            fail('COMPAT')
    if path('/etc/sovagrid/local-web').exists() or path('/etc/sovagrid/local-web').is_symlink():
        local_web_overlay()
        local_required = ('sovagrid-blueprint/deploy/local_web.py',
                          'sovagrid-blueprint/deploy/compose.local-web.template')
        if (b'# SOVAGRID_LOCAL_WEB_V1' not in script or
                any(not (source / name).is_file() for name in local_required) or
                b'import /etc/caddy/local/*.caddy' not in
                (source / 'sovagrid-web/deploy/Caddyfile.container').read_bytes()):
            fail('COMPAT')

def public_path(value, *, directory=False, private=False, limit=4096):
    item = path(value)
    # Check every component below ROOT, including bind-mount ancestors.
    relative = item.relative_to(ROOT)
    for index in range(1, len(relative.parts)):
        info = (ROOT / Path(*relative.parts[:index])).lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != PUBLIC_OWNER or info.st_mode & 0o022:
            fail('STATE')
    info = item.lstat()
    if info.st_uid != PUBLIC_OWNER or info.st_mode & 0o022:
        fail('STATE')
    if directory:
        if not stat.S_ISDIR(info.st_mode) or private and stat.S_IMODE(info.st_mode) != 0o700:
            fail('STATE')
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit or
            private and stat.S_IMODE(info.st_mode) != 0o600):
        fail('STATE')
    return item.read_bytes()

def backup_broker_enabled():
    marker = path(BACKUP_BROKER_MARKER)
    units = tuple(path('/etc/systemd/system/' + unit) for unit in BACKUP_BROKER_UNITS)
    ledger = path(BACKUP_BROKER_LEDGER)
    backups = path('/var/lib/sovagrid/backups')
    if marker.exists() or marker.is_symlink():
        if public_path(BACKUP_BROKER_MARKER, private=True, limit=128) != b'SOVAGRID_HUB_BACKUP_BROKER_V1\n':
            fail('STATE')
        marker_info = marker.lstat()
        if marker_info.st_gid != BROKER_OWNER_GID or marker_info.st_nlink != 1:
            fail('STATE')
        if not backups.is_dir() or backups.is_symlink():
            fail('STATE')
        public_path('/var/lib/sovagrid/backups', directory=True, private=True)
        if backups.lstat().st_gid != BROKER_OWNER_GID:
            fail('STATE')
        for item in units:
            if not item.is_file() or item.is_symlink():
                fail('STATE')
            info = item.lstat()
            if info.st_gid != BROKER_OWNER_GID or info.st_nlink != 1 or \
                    stat.S_IMODE(info.st_mode) != 0o644:
                fail('STATE')
        for unit in BACKUP_BROKER_UNITS:
            public_path('/etc/systemd/system/' + unit, limit=8192)
        if ledger.exists() or ledger.is_symlink():
            public_path(BACKUP_BROKER_LEDGER, directory=True, private=True)
            if ledger.lstat().st_gid != BROKER_OWNER_GID:
                fail('STATE')
        return True
    if any(item.exists() or item.is_symlink() for item in (*units, ledger)):
        fail('STATE')
    return False

def backup_broker_socket_ready():
    if not backup_broker_enabled():
        return
    try:
        directory = path('/run/sovagrid-hub-backup').lstat()
        endpoint = path('/run/sovagrid-hub-backup/control.sock').lstat()
    except OSError:
        fail('STATE')
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or
            stat.S_IMODE(directory.st_mode) != 0o755 or
            not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_nlink != 1 or
            (endpoint.st_uid, endpoint.st_gid, stat.S_IMODE(endpoint.st_mode)) != (0, 10001, 0o660)):
        fail('STATE')

def public_web_overlay():
    base = '/etc/sovagrid/public-web'
    if not path(base).exists() and not path(base).is_symlink():
        return None
    try:
        public_path(base, directory=True, private=True)
        if public_path(base + '/.managed', private=True) != b'SOVAGRID_PUBLIC_WEB_V1\n':
            fail('STATE')
        if not path(base + '/state.json').exists() and not path(base + '/state.json').is_symlink():
            return None
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    fail('STATE')
                result[key] = value
            return result
        def constant(_value):
            fail('STATE')
        value = json.loads(public_path(base + '/state.json', private=True), object_pairs_hook=unique, parse_constant=constant)
        legacy_config = {'mode', 'address', 'acme_environment'}
        current_config = legacy_config | {'panel_path', 'root_behavior'}
        legacy_files = {'caddy/global/public.options', 'caddy/sites/public.caddy', 'compose.yaml'}
        current_files = legacy_files | {'caddy/local/panel.caddy'}
        config = value.get('config') if isinstance(value, dict) else None
        file_hashes = value.get('sha256') if isinstance(value, dict) else None
        valid_layout = (isinstance(config, dict) and isinstance(file_hashes, dict) and
                        (set(config), set(file_hashes)) in ((legacy_config, legacy_files),
                                                             (current_config, current_files)))
        if (not isinstance(value, dict) or set(value) != {'protocol', 'generation', 'config', 'sha256'} or
                type(value['protocol']) is not int or value['protocol'] != 1 or
                not isinstance(value['generation'], str) or not re.fullmatch(r'[0-9a-f]{32}', value['generation']) or
                not valid_layout or config['mode'] not in ('ip', 'dns') or
                not isinstance(config['address'], str) or not 1 <= len(config['address']) <= 253 or
                config['acme_environment'] not in ('production', 'staging') or
                (set(config) == current_config and
                 (not isinstance(config['panel_path'], str) or len(config['panel_path']) > 96 or
                  re.fullmatch(r'/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/){1,3}',
                               config['panel_path']) is None or
                  config['panel_path'].split('/')[1] in {'api', 'healthz'} or
                  not isinstance(config['root_behavior'], str) or
                  config['root_behavior'] not in {'untouched', 'panel', 'redirect', 'not_found'}))):
            fail('STATE')
        generation = base + '/generations/' + value['generation']
        public_path(generation, directory=True, private=True)
        for name, expected in value['sha256'].items():
            if (not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected) or
                    hashlib.sha256(public_path(generation + '/' + name, limit=32768)).hexdigest() != expected):
                fail('STATE')
        return str(path(generation + '/compose.yaml'))
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        fail('STATE')

def local_web_overlay():
    """Pin the immutable loopback route before any Compose or updater action."""
    base = '/etc/sovagrid/local-web'
    if not path(base).exists() and not path(base).is_symlink():
        return None
    try:
        public_path(base, directory=True, private=True)
        if public_path(base + '/.managed', private=True) != b'SOVAGRID_LOCAL_WEB_V1\n':
            fail('STATE')
        if not path(base + '/state.json').exists() and not path(base + '/state.json').is_symlink():
            return None
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    fail('STATE')
                value[key] = item
            return value
        value = json.loads(public_path(base + '/state.json', private=True), object_pairs_hook=unique,
                           parse_constant=lambda _item: fail('STATE'))
        config = value.get('config') if isinstance(value, dict) else None
        hashes = value.get('sha256') if isinstance(value, dict) else None
        if (not isinstance(value, dict) or set(value) != {'protocol', 'generation', 'config', 'sha256'} or
                type(value['protocol']) is not int or value['protocol'] != 1 or
                not isinstance(value['generation'], str) or
                re.fullmatch(r'[0-9a-f]{32}', value['generation']) is None or
                not isinstance(config, dict) or set(config) != {'panel_path', 'root_behavior'} or
                not isinstance(config['panel_path'], str) or len(config['panel_path']) > 96 or
                re.fullmatch(r'/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/){1,3}',
                             config['panel_path']) is None or
                config['panel_path'].split('/')[1] in {'api', 'healthz'} or
                not isinstance(config['root_behavior'], str) or
                config['root_behavior'] not in {'untouched', 'panel', 'redirect', 'not_found'} or
                not isinstance(hashes, dict) or set(hashes) != {'caddy/panel.caddy', 'compose.yaml'}):
            fail('STATE')
        generation = base + '/generations/' + value['generation']
        public_path(generation, directory=True, private=True)
        for name, expected in hashes.items():
            if (not isinstance(expected, str) or re.fullmatch(r'[0-9a-f]{64}', expected) is None or
                    hashlib.sha256(public_path(generation + '/' + name, limit=32768)).hexdigest() != expected):
                fail('STATE')
        return str(path(generation + '/compose.yaml'))
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        fail('STATE')

@contextlib.contextmanager
def public_web_lock():
    import fcntl
    public_path('/var/lib/sovagrid', directory=True)
    # This directory itself is outside SNAPSHOT, so restore cannot replace the
    # held lock's inode and allow a concurrent public Web transaction.
    descriptor = os.open(path('/var/lib/sovagrid/.public-web.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        validate_lock(os.fstat(descriptor))
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def service_setup_lock():
    """Keep setup from replacing policy or units during a rollback snapshot."""
    import fcntl
    target = path('/etc/sovagrid-service-setup.lock')
    if target.is_symlink():
        raise UpdateFailure('unsafe service setup lock')
    descriptor = os.open(target, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or (info.st_uid, info.st_gid,
                stat.S_IMODE(info.st_mode), info.st_nlink) != (0, 0, 0o600, 1)):
            raise UpdateFailure('unsafe service setup lock')
        deadline = time.monotonic() + 30
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise UpdateFailure('service setup busy')
                time.sleep(0.1)
        yield
    finally:
        os.close(descriptor)

@contextlib.contextmanager
def managed_vpn_locks():
    """Freeze managed VPN state, then routing policy, during the snapshot."""
    import fcntl
    for directory in (path('/var/lib/sovagrid-vpn'), path('/etc/sovagrid-vpn-routing')):
        if directory.is_symlink():
            raise UpdateFailure('unsafe VPN lock directory')
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise UpdateFailure('unsafe VPN lock directory')
    with contextlib.ExitStack() as stack:
        for name in ('/var/lib/sovagrid-vpn/.lock', '/etc/sovagrid-vpn-routing/lock'):
            descriptor = os.open(path(name), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            stack.callback(os.close, descriptor)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or (info.st_uid, info.st_gid,
                    stat.S_IMODE(info.st_mode), info.st_nlink) != (0, 0, 0o600, 1)):
                raise UpdateFailure('unsafe VPN setup lock')
            deadline = time.monotonic() + 30
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise UpdateFailure('VPN setup busy')
                    time.sleep(0.1)
        yield


def refresh_service_units(old_source, new_source, unit_states):
    """Advance only previously installed, exact broker units with Agent code."""
    changed = False
    for name in SERVICE_UNITS:
        target = path('/etc/systemd/system/' + name)
        if not target.exists() and not target.is_symlink():
            if unit_states[name]['active'] or unit_states[name]['enabled']:
                raise UpdateFailure('service broker unit missing')
            continue
        info = target.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_gid != 0 or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o644):
            raise UpdateFailure('service broker unit changed')
        filename = 'sovagrid-agent/deploy/' + name
        before = public_path(str(old_source / filename), limit=8192)
        after = public_path(str(new_source / filename), limit=8192)
        if public_path(str(target), limit=8192) != before:
            raise UpdateFailure('service broker unit changed')
        if before == after:
            continue
        temporary = target.parent / ('.' + name + '.' + secrets.token_hex(12))
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(descriptor, 0o644)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(after)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        changed = True
    if changed:
        command(['systemctl', 'daemon-reload'], timeout=30)

def compose_args(source, *, allow_missing_backup_overlay=False):
    args = ['docker', 'compose', '--env-file', '/etc/sovagrid/deploy.env',
            '-f', str(source / 'sovagrid-blueprint/deploy/compose.yaml')]
    env = os.environ.copy()
    if path('/etc/sovagrid-hub/bot.token').is_file():
        args += ['-f', str(source / 'sovagrid-blueprint/deploy/compose.telegram.yaml')]
        env['SOVAGRID_BOT_TOKEN_FILE'] = '/etc/sovagrid-hub/bot.token'
    if backup_broker_enabled():
        overlay = source / 'sovagrid-blueprint/deploy/compose.backup.yaml'
        if overlay.is_file() and not overlay.is_symlink():
            args += ['-f', str(overlay)]
        elif not allow_missing_backup_overlay:
            fail('STATE')
    public_overlay = public_web_overlay()
    local_overlay = local_web_overlay()
    if public_overlay and local_overlay:
        fail('STATE')
    if public_overlay:
        args += ['-f', public_overlay]
    if local_overlay:
        args += ['-f', local_overlay]
    return args, env

def rollback_stop_compose_args(source, folder, snapshot, phase):
    """Stop the old project without parsing candidate-controlled overlays.

    The base Compose file contains Hub, Web and SSH gateway. Once a durable
    snapshot exists, read its deploy.env too: a failed installer may have
    damaged the live environment or either Web overlay.
    """
    env_file = path('/etc/sovagrid/deploy.env')
    if phase != 'preparing':
        if '/etc/sovagrid/deploy.env' in snapshot:
            env_file = folder / 'snapshot' / str(snapshot.index('/etc/sovagrid/deploy.env'))
        elif '/etc/sovagrid' in snapshot:
            env_file = folder / 'snapshot' / str(snapshot.index('/etc/sovagrid')) / 'deploy.env'
        else:
            raise UpdateFailure('snapshot lacks deploy environment')
    return (['docker', 'compose', '--env-file', str(env_file),
             '-f', str(source / 'sovagrid-blueprint/deploy/compose.yaml')], os.environ.copy())

def ssh_gateway_managed():
    marker = path(SSH_GATEWAY_MARKER)
    if not os.path.lexists(marker):
        return False
    parent = marker.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        fail('STATE')
    try:
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                    info.st_gid != 0 or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o600 or
                    info.st_size != len(SSH_GATEWAY_MARKER_CONTENT) or
                    stream.read(len(SSH_GATEWAY_MARKER_CONTENT) + 1) != SSH_GATEWAY_MARKER_CONTENT):
                fail('STATE')
    except OSError:
        fail('STATE')
    return True

def compose_services():
    return BASE_COMPOSE_SERVICES + ((SSH_GATEWAY_SERVICE,) if ssh_gateway_managed() else ())

def gateway_prior_state():
    """Record the exact gateway artifacts before a three-service transaction."""
    result = subprocess.run(
        ['docker', 'ps', '-a', '--no-trunc',
         '--filter', 'label=com.docker.compose.project=sovagrid',
         '--filter', 'label=com.docker.compose.service=' + SSH_GATEWAY_SERVICE,
         '--format', '{{.ID}}'], capture_output=True, text=True, timeout=10, check=True)
    ids = result.stdout.splitlines()
    if len(ids) > 4 or any(re.fullmatch(r'[0-9a-f]{64}', item) is None for item in ids):
        fail('STATE')
    if ids and not ssh_gateway_managed():
        fail('STATE')
    image = subprocess.run(
        ['docker', 'image', 'inspect', '--format', '{{.Id}}',
         'sovagrid-' + SSH_GATEWAY_SERVICE + ':local'],
        capture_output=True, text=True, timeout=10, check=False)
    if image.returncode not in (0, 1) or (image.returncode == 0 and
            re.fullmatch(r'sha256:[0-9a-f]{64}', image.stdout.strip()) is None):
        fail('STATE')
    return {'container_ids': ids, 'image': image.stdout.strip() if image.returncode == 0 else None}

def browser_ssh_route_health():
    request = urllib.request.Request(
        'http://127.0.0.1:8766/api/v1/browser-ssh/host-key', data=b'{}',
        headers={'Content-Type': 'application/json', 'Origin': 'http://127.0.0.1:8766'},
        method='POST')
    with urllib.request.urlopen(request, timeout=12) as response:
        if response.status != 200:
            raise UpdateFailure('browser SSH route failed')
        raw = response.read(513)
    if len(raw) > 512:
        raise UpdateFailure('browser SSH route reply too large')
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise UpdateFailure('browser SSH route reply invalid') from exc
    if (not isinstance(data, dict) or set(data) != {'protocol', 'port', 'key_type', 'fingerprint'} or
            data['protocol'] != 1 or type(data['port']) is not int or not 1 <= data['port'] <= 65535 or
            not isinstance(data['key_type'], str) or not data['key_type'] or
            not isinstance(data['fingerprint'], str) or
            re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', data['fingerprint']) is None):
        raise UpdateFailure('browser SSH route reply invalid')

def health(source, expected_units):
    for unit in expected_units:
        if command(['systemctl', 'is-active', '--quiet', unit], timeout=10, check=False):
            raise UpdateFailure('inactive unit: ' + unit)
    backup_broker_socket_ready()
    services = compose_services()
    for service in services:
        result = subprocess.run(['docker', 'ps', '--filter', 'label=com.docker.compose.project=sovagrid',
                                 '--filter', 'label=com.docker.compose.service=' + service, '--format', '{{.ID}}'],
                                capture_output=True, text=True, timeout=10, check=True)
        ids = result.stdout.splitlines()
        if len(ids) != 1:
            raise UpdateFailure('missing container: ' + service)
        image = subprocess.run(['docker', 'inspect', '--format', '{{.Image}}', ids[0]],
                               capture_output=True, text=True, timeout=10, check=True).stdout.strip()
        expected_image = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', 'sovagrid-' + service + ':local'],
                                        capture_output=True, text=True, timeout=10, check=True).stdout.strip()
        status = subprocess.run(['docker', 'inspect', '--format', '{{.State.Status}}', ids[0]],
                                capture_output=True, text=True, timeout=10, check=True).stdout.strip()
        if image != expected_image or status != 'running':
            raise UpdateFailure('unhealthy container: ' + service)
        if service in ('hub', SSH_GATEWAY_SERVICE):
            health_status = subprocess.run(['docker', 'inspect', '--format', '{{.State.Health.Status}}', ids[0]],
                                           capture_output=True, text=True, timeout=10, check=True).stdout.strip()
            if health_status != 'healthy':
                raise UpdateFailure('unhealthy container: ' + service)
    if SSH_GATEWAY_SERVICE not in services:
        stray = subprocess.run(['docker', 'ps', '--filter', 'label=com.docker.compose.project=sovagrid',
                                '--filter', 'label=com.docker.compose.service=' + SSH_GATEWAY_SERVICE,
                                '--format', '{{.ID}}'], capture_output=True, text=True,
                               timeout=10, check=True).stdout.strip()
        if stray:
            raise UpdateFailure('unmanaged SSH gateway container')
    with urllib.request.urlopen('http://127.0.0.1:8766/healthz', timeout=5) as response:
        if response.status != 200:
            raise UpdateFailure('web health check failed')
    if SSH_GATEWAY_SERVICE in services:
        browser_ssh_route_health()
    context = ssl.create_default_context(cafile=str(path('/etc/sovagrid/hub-ca.pem')))
    with urllib.request.urlopen('https://localhost:8767/healthz', context=context, timeout=5) as response:
        if response.status != 200:
            raise UpdateFailure('hub TLS health check failed')
    if not path('/var/lib/sovagrid/vpn/status.json').is_file():
        raise UpdateFailure('VPN inventory snapshot missing')
    if path('/etc/sovagrid/.containers-managed-by-run-sh').is_file() and \
            not path('/var/lib/sovagrid-containers/snapshot.json').is_file():
        raise UpdateFailure('container inventory snapshot missing')
    source_manifest(source, allow_generated=True)


def wait_recreated_container_health(images, *, timeout=40):
    """Wait for recreated Hub/gateway healthchecks before rollback postchecks.

    Compose `up -d` returns while a new gateway may still be `starting`.
    The installer gives that gateway 30 seconds; rollback needs the same
    bounded readiness window before its otherwise strict health() check.
    """
    targets = tuple(name for name in ('hub', SSH_GATEWAY_SERVICE) if name in images)
    deadline = time.monotonic() + timeout
    while targets:
        pending = []
        for service in targets:
            result = subprocess.run(
                ['docker', 'ps', '--filter', 'label=com.docker.compose.project=sovagrid',
                 '--filter', 'label=com.docker.compose.service=' + service,
                 '--format', '{{.ID}}'], capture_output=True, text=True, timeout=10, check=True)
            ids = result.stdout.splitlines()
            if len(ids) != 1:
                raise UpdateFailure('missing recreated container: ' + service)
            status = subprocess.run(
                ['docker', 'inspect', '--format', '{{.State.Health.Status}}', ids[0]],
                capture_output=True, text=True, timeout=10, check=True).stdout.strip()
            if status == 'healthy':
                continue
            if status not in ('starting', 'unhealthy'):
                raise UpdateFailure('invalid recreated container health: ' + service)
            pending.append(service)
        if not pending:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise UpdateFailure('recreated container health timeout: ' + ','.join(pending))
        time.sleep(min(1, remaining))

def safe_snapshot_item(item):
    if not item.exists() and not item.is_symlink():
        return 0
    total = 0
    entries = [item]
    if item.is_dir():
        entries.extend(item.rglob('*'))
    for entry in entries:
        info = entry.lstat()
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)) or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
            raise UpdateFailure('unsupported file in managed snapshot')
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
    return total

def copy_item(source, destination):
    command(['cp', '-a', '--reflink=auto', '--', str(source), str(destination)], timeout=300)

def remove_item(item):
    if item.is_symlink() or item.is_file():
        item.unlink()
    elif item.is_dir():
        shutil.rmtree(item)

def state_write(folder, state):
    temporary = folder / '.state.new'
    with temporary.open('w') as stream:
        json.dump(state, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, folder / 'state.json')
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def validate_private_install_log(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise UpdateFailure('unsafe installation log')

def secure_log_fd(fd):
    os.fchown(fd, 0, 0)
    os.fchmod(fd, 0o600)

def validate_private_log_dir(info):
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
            stat.S_IMODE(info.st_mode) != 0o700):
        raise UpdateFailure('unsafe failure log directory')

def preserve_install_log(folder):
    source = folder / 'install.log'
    try:
        info = source.lstat()
    except FileNotFoundError:
        return False
    validate_private_install_log(info)
    directory = path('/opt/sovagrid-candidates/failure-logs')
    directory.mkdir(mode=0o700, exist_ok=True)
    validate_private_log_dir(directory.lstat())
    destination = None
    try:
        for _attempt in range(3):
            candidate = directory / ('install-' + str(time.time_ns()) + '-' + secrets.token_hex(12) + '.log')
            try:
                fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                continue
            destination = candidate
            break
        else:
            raise UpdateFailure('could not allocate installation log')
        with os.fdopen(fd, 'wb') as output, source.open('rb') as input_file:
            secure_log_fd(output.fileno())
            prefix = b'[SovaGrid: only the last 2 MiB of this log were retained]\n'
            remaining = MAX_FAILURE_LOG
            if info.st_size > MAX_FAILURE_LOG:
                output.write(prefix)
                remaining -= len(prefix)
                input_file.seek(max(0, info.st_size - remaining))
            while remaining:
                block = input_file.read(min(65536, remaining))
                if not block:
                    break
                output.write(block)
                remaining -= len(block)
            output.flush()
            os.fsync(output.fileno())
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        if destination is not None:
            try:
                destination.unlink()
            except OSError:
                pass
        raise
    pattern = re.compile(r'install-[0-9]{17,25}-[0-9a-f]{24}\.log\Z')
    retained = []
    for item in directory.iterdir():
        if pattern.fullmatch(item.name):
            entry = item.lstat()
            try:
                validate_private_install_log(entry)
            except UpdateFailure:
                continue
            retained.append(item)
    cleanup_failed = False
    for old in sorted(retained, key=lambda item: item.name):
        if len(retained) <= MAX_FAILURE_LOGS:
            break
        if old != destination:
            try:
                old.unlink()
                retained.remove(old)
            except OSError:
                cleanup_failed = True
    emit('SG_APPLY_STAGE:LOG_SAVED')
    if cleanup_failed:
        emit('SG_APPLY_STAGE:CLEANUP_INCOMPLETE')
    return True

def finalize_rollback(folder):
    try:
        preserve_install_log(folder)
    except (OSError, UpdateFailure):
        emit('SG_APPLY_STAGE:LOG_UNAVAILABLE')
    try:
        shutil.rmtree(folder)
    except OSError:
        emit('SG_APPLY_STAGE:CLEANUP_INCOMPLETE')

def remove_new_gateway_on_rollback(prior_ids=()):
    """Remove only gateway containers absent from the pre-update inventory."""
    result = subprocess.run(
        ['docker', 'ps', '-a', '--no-trunc',
         '--filter', 'label=com.docker.compose.project=sovagrid',
         '--filter', 'label=com.docker.compose.service=' + SSH_GATEWAY_SERVICE,
         '--format', '{{.ID}}'], capture_output=True, text=True, timeout=10, check=True)
    ids = result.stdout.splitlines()
    if len(ids) > 4 or any(re.fullmatch(r'[0-9a-f]{64}', item) is None for item in ids):
        raise UpdateFailure('ambiguous SSH gateway container')
    prior = set(prior_ids)
    if any(re.fullmatch(r'[0-9a-f]{64}', item) is None for item in prior):
        raise UpdateFailure('invalid prior SSH gateway inventory')
    for identity in ids:
        if identity in prior:
            continue
        labels = subprocess.run(
            ['docker', 'inspect', '--format',
             '{{ index .Config.Labels "com.docker.compose.project" }}:'
             '{{ index .Config.Labels "com.docker.compose.service" }}', identity],
            capture_output=True, text=True, timeout=10, check=True).stdout.strip()
        if labels != 'sovagrid:' + SSH_GATEWAY_SERVICE:
            raise UpdateFailure('SSH gateway container labels changed')
        command(['docker', 'rm', '-f', identity], timeout=30)

def restore(folder, state):
    errors = []
    layout = state.get('snapshot_layout', 'legacy')
    if layout not in ('legacy', 'release_feed_v1', 'service_control_v1', 'routing_v1',
                      'hub_backup_broker_v1', 'ssh_gateway_v1'):
        raise UpdateFailure('unknown snapshot layout')
    snapshot = (LEGACY_SNAPSHOT if layout == 'legacy' else
                RELEASE_FEED_SNAPSHOT if layout == 'release_feed_v1' else
                SERVICE_SNAPSHOT if layout == 'service_control_v1' else
                ROUTING_SNAPSHOT if layout == 'routing_v1' else
                HUB_BACKUP_SNAPSHOT if layout == 'hub_backup_broker_v1' else SNAPSHOT)
    units = (LEGACY_UNITS if layout == 'legacy' else
             RELEASE_FEED_UNITS if layout == 'release_feed_v1' else
             SERVICE_ALL_UNITS if layout == 'service_control_v1' else
             ROUTING_ALL_UNITS if layout == 'routing_v1' else UNITS)
    source = path('/opt/sovagrid-src')
    old_source = folder / 'source-before'
    try:
        if old_source.exists():
            if source.exists() or source.is_symlink():
                os.replace(source, folder / 'source-failed')
            os.replace(old_source, source)
    except Exception as exc:
        errors.append('source: ' + str(exc))
    try:
        if layout in ('hub_backup_broker_v1', 'ssh_gateway_v1'):
            command(['systemctl', 'stop', *BACKUP_BROKER_UNITS], timeout=40, check=False)
        if layout in ('service_control_v1', 'routing_v1', 'hub_backup_broker_v1', 'ssh_gateway_v1'):
            command(['systemctl', 'stop', *reversed(SERVICE_UNITS)], timeout=40, check=False)
        args, env = rollback_stop_compose_args(source, folder, snapshot, state['phase'])
        command(args + ['stop'], timeout=120, check=False, env=env)
        if (layout == 'ssh_gateway_v1' and state['phase'] != 'preparing' and
                SSH_GATEWAY_SERVICE not in state['images'] and 'gateway_before' in state):
            remove_new_gateway_on_rollback(state['gateway_before']['container_ids'])
    except Exception as exc:
        errors.append('stop: ' + str(exc))
    # Until the complete snapshot is durable, run.sh has not started and the
    # active source has not moved. A partial snapshot must never erase state.
    if state['phase'] != 'preparing':
        for index, value in enumerate(snapshot):
            destination = path(value)
            saved = folder / 'snapshot' / str(index)
            try:
                remove_item(destination)
                if saved.exists():
                    copy_item(saved, destination)
            except Exception as exc:
                errors.append(value + ': ' + str(exc))
    try:
        for service in state['images']:
            command(['docker', 'image', 'tag', state['images'][service], 'sovagrid-' + service + ':local'])
        if (layout == 'ssh_gateway_v1' and state['phase'] != 'preparing' and
                SSH_GATEWAY_SERVICE not in state['images'] and 'gateway_before' in state):
            old_gateway_image = state['gateway_before']['image']
            if old_gateway_image:
                command(['docker', 'image', 'tag', old_gateway_image,
                         'sovagrid-' + SSH_GATEWAY_SERVICE + ':local'])
            else:
                command(['docker', 'image', 'rm', 'sovagrid-' + SSH_GATEWAY_SERVICE + ':local'],
                        check=False)
        command(['systemctl', 'daemon-reload'])
        for unit in units:
            was = state['units'].get(unit, {})
            if was.get('enabled'):
                command(['systemctl', 'enable', unit], timeout=30)
            else:
                command(['systemctl', 'disable', unit], timeout=30, check=False)
        if layout in ('hub_backup_broker_v1', 'ssh_gateway_v1') and backup_broker_enabled() and \
                state['units'][BACKUP_BROKER_UNITS[0]]['active']:
            command(['systemctl', 'start', BACKUP_BROKER_UNITS[0]], timeout=30)
        if layout in ('hub_backup_broker_v1', 'ssh_gateway_v1'):
            backup_broker_socket_ready()
        args, env = compose_args(source)
        command(args + ['up', '-d', '--no-build', '--force-recreate', *state['images']],
                timeout=240, env=env)
        wait_recreated_container_health(state['images'])
        for unit in units:
            if unit == BACKUP_BROKER_UNITS[0]:
                continue  # It was activated before the Hub container's bind mount.
            if unit == ROUTING_UNIT:
                # The updater holds the same VPN locks as routing sync. A
                # restart here would wait on those locks and deadlock.
                if state['units'].get(unit, {}).get('active') and \
                        command(['systemctl', 'is-active', '--quiet', unit], timeout=10,
                                check=False):
                    raise UpdateFailure('routing service lost activity during rollback')
                if not state['units'].get(unit, {}).get('active'):
                    command(['systemctl', 'stop', unit], timeout=30, check=False)
                continue
            if state['units'].get(unit, {}).get('active'):
                command(['systemctl', 'restart', unit], timeout=60)
            else:
                command(['systemctl', 'stop', unit], timeout=30, check=False)
        if state['phase'] != 'preparing' and path('/etc/apparmor.d/wg-quick').is_file() and \
                path('/etc/apparmor.d/local/wg-quick').is_file():
            command(['apparmor_parser', '-r', '/etc/apparmor.d/wg-quick'], timeout=30)
        health(source, state['expected_units'])
        if source_manifest(source, allow_generated=True)[0] != state['old_manifest']:
            raise UpdateFailure('old version was not restored')
    except Exception as exc:
        errors.append('restart/health: ' + str(exc))
    if errors:
        state['phase'] = 'rollback_failed'
        state['errors'] = errors
        state_write(folder, state)
        emit('SG_APPLY_STAGE:ROLLBACK_FAILED')
        return False
    state['phase'] = 'rolled_back'
    state_write(folder, state)
    emit('SG_APPLY_STAGE:ROLLED_BACK')
    return True

def inspect_state():
    if os.geteuid() != 0 or path('/etc/os-release').read_text().find('ID=ubuntu') < 0:
        fail('HOST')
    source = path('/opt/sovagrid-src')
    if source.is_symlink() or not source.is_dir():
        fail('ACTIVE')
    manifest, commits = source_manifest(source, allow_generated=True)
    for item in ('/var/lib/sovagrid/.managed-by-run-sh', '/etc/sovagrid/.agent-unit-managed-by-run-sh',
                 '/etc/sovagrid/.vpn-unit-managed-by-run-sh', '/var/lib/sovagrid/hub/hub.sqlite'):
        if not path(item).is_file() or path(item).is_symlink():
            fail('ACTIVE')
    flags, expected = managed_flags()
    health(source, expected)
    return source, manifest, commits, flags, expected

def preview():
    source, digest, commits, flags, expected = inspect_state()
    emit('SG_CURRENT_MANIFEST:' + digest)
    for name in sorted(commits):
        emit('SG_CURRENT_COMMIT:' + name + ':' + commits[name])
    emit('SG_VERSION_PREFLIGHT:OK')

def preflight(candidate_digest, expected_manifest):
    if not re.fullmatch(r'[0-9a-f]{64}', expected_manifest):
        fail('VERSION')
    source, old_manifest, old_commits, flags, _expected = inspect_state()
    if old_manifest != expected_manifest:
        fail('VERSION')
    if source.stat().st_dev != path('/opt/sovagrid-candidates').stat().st_dev:
        fail('STATE')
    staged, new_commits = candidate_source(candidate_digest)
    if new_commits == old_commits:
        fail('SAME_VERSION')
    candidate_features_compatible(staged, flags)
    emit('SG_UPDATE_PREFLIGHT:OK')

def _agent_unit_property(name):
    try:
        value = subprocess.run(['systemctl', 'show', '-P', name, AGENT_UNIT],
                               capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        fail('STATE')
    if not value or '\n' in value:
        fail('STATE')
    return value


def _agent_unit_active():
    try:
        return subprocess.run(['systemctl', 'is-active', '--quiet', AGENT_UNIT],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        fail('STATE')


def _agent_identity():
    if _agent_unit_property('User') != 'sovagrid' or _agent_unit_property('Group') != 'sovagrid':
        fail('STATE')
    try:
        uid = pwd.getpwnam('sovagrid').pw_uid
        gid = grp.getgrnam('sovagrid').gr_gid
        raw_pid = _agent_unit_property('MainPID')
        if not raw_pid.isascii() or not raw_pid.isdecimal() or str(int(raw_pid)) != raw_pid:
            fail('STATE')
        pid = int(raw_pid)
    except KeyError:
        fail('STATE')
    if pid <= 1 or uid == 0 or gid == 0 or not _agent_unit_active():
        fail('STATE')
    return pid, uid, gid


def _agent_control_path(uid):
    parent = path('/run/sovagrid-agent-control')
    endpoint = path(AGENT_CONTROL)
    try:
        directory, socket_info = parent.lstat(), endpoint.lstat()
    except FileNotFoundError:
        # An older Agent has no control socket. A timer may retry after an
        # administrator performs the one-time manual upgrade.
        fail('BUSY')
    except OSError:
        fail('STATE')
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != uid or
            stat.S_IMODE(directory.st_mode) != 0o700 or
            not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid != uid or
            stat.S_IMODE(socket_info.st_mode) != 0o600 or socket_info.st_nlink != 1 or
            socket_info.st_dev != directory.st_dev):
        fail('STATE')
    return endpoint, (socket_info.st_dev, socket_info.st_ino)


def _agent_peercred(connection):
    if sys.platform != 'linux' or not hasattr(socket, 'SO_PEERCRED'):
        fail('STATE')
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                    struct.calcsize('3i'))
        return struct.unpack('3i', raw)
    except (OSError, struct.error):
        fail('STATE')


def _agent_control_line(connection, *, limit=512, quiet=False):
    line = bytearray()
    try:
        while len(line) < limit:
            chunk = connection.recv(1)
            if not chunk:
                raise EOFError()
            line.extend(chunk)
            if chunk == b'\n':
                return bytes(line)
    except (OSError, EOFError):
        if quiet:
            raise UpdateFailure('STATE') from None
        fail('STATE')
    if quiet:
        raise UpdateFailure('STATE')
    fail('STATE')


def _agent_idle_ack(raw, pid):
    if raw == b'BUSY 1\n':
        fail('BUSY')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, TypeError):
        fail('STATE')
    if (not isinstance(value, dict) or set(value) !=
            AGENT_IDLE_FIELDS | {'protocol', 'state', 'pid', 'epoch'} or
            type(value['protocol']) is not int or value['protocol'] != 1 or
            value['state'] != 'idle' or type(value['pid']) is not int or
            value['pid'] != pid or not isinstance(value['epoch'], str) or
            re.fullmatch(r'[0-9a-f]{32}', value['epoch']) is None or
            any(type(value[name]) is not int or value[name] != 0
                for name in AGENT_IDLE_FIELDS)):
        fail('STATE')
    return value['epoch']


class _AgentIdleGuard:
    """Hold a verified Agent idle ACK until its service has stopped.

    A heartbeat thread prevents the Agent's 45-second hold timeout while
    Docker stops Hub. The root updater checks this guard again immediately
    before stopping Agent; a lost ACK fails the update before source switch.
    """

    def __init__(self, connection, *, pid, uid, gid, epoch, endpoint_identity):
        self.connection = connection
        self.pid, self.uid, self.gid = pid, uid, gid
        self.epoch = epoch
        self.endpoint_identity = endpoint_identity
        self._stop = threading.Event()
        self._mutex = threading.Lock()
        self._failed = False
        self._last_pong = time.monotonic()
        self._since = self._last_pong
        self._agent_stopping = False
        self._thread = threading.Thread(target=self._heartbeat, daemon=True,
                                        name='sovagrid-agent-idle-holder')

    def start(self):
        try:
            self._ping()
        except UpdateFailure:
            fail('STATE')
        self._thread.start()
        return self

    def _ping(self):
        self.connection.settimeout(5)
        try:
            self.connection.sendall(b'PING 1\n')
        except OSError:
            raise UpdateFailure('STATE') from None
        if (_agent_control_line(self.connection, limit=64, quiet=True) !=
                b'PONG 1 ' + self.epoch.encode('ascii') + b'\n'):
            raise UpdateFailure('STATE')
        with self._mutex:
            self._last_pong = time.monotonic()

    def _heartbeat(self):
        while not self._stop.wait(10):
            try:
                self._ping()
            except (UpdateFailure, OSError):
                with self._mutex:
                    self._failed = True
                return

    def assert_held(self):
        with self._mutex:
            failed, last_pong = self._failed, self._last_pong
        if (failed or not self._thread.is_alive() or time.monotonic() - last_pong > 25 or
                time.monotonic() - self._since > 880 or
                _agent_identity() != (self.pid, self.uid, self.gid)):
            fail('STATE')
        endpoint = path(AGENT_CONTROL)
        try:
            info = endpoint.lstat()
        except OSError:
            fail('STATE')
        if not stat.S_ISSOCK(info.st_mode) or (info.st_dev, info.st_ino) != self.endpoint_identity:
            fail('STATE')

    def begin_stop(self):
        self.assert_held()
        self._agent_stopping = True

    def confirm_stopped(self):
        if not self._agent_stopping or _agent_unit_active() or _agent_unit_property('MainPID') != '0':
            fail('STATE')

    def close(self):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=6)
        if not self._agent_stopping and not self._thread.is_alive():
            try:
                self.connection.settimeout(2)
                self.connection.sendall(b'RELEASE 1\n')
                _agent_control_line(self.connection, limit=64, quiet=True)
            except (OSError, UpdateFailure):
                pass
        self.connection.close()


@contextlib.contextmanager
def automatic_agent_quiescence():
    if sys.platform != 'linux' or os.geteuid() != 0:
        fail('STATE')
    pid, uid, gid = _agent_identity()
    endpoint, endpoint_identity = _agent_control_path(uid)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    guard = None
    try:
        connection.settimeout(5)
        try:
            connection.connect(str(endpoint))
        except (ConnectionRefusedError, FileNotFoundError):
            fail('BUSY')
        except OSError:
            fail('STATE')
        if _agent_peercred(connection) != (pid, uid, gid):
            fail('STATE')
        try:
            connection.sendall(b'QUIESCE 1\n')
        except OSError:
            fail('STATE')
        if _agent_identity() != (pid, uid, gid):
            fail('STATE')
        connection.settimeout(185)
        epoch = _agent_idle_ack(_agent_control_line(connection), pid)
        guard = _AgentIdleGuard(connection, pid=pid, uid=uid, gid=gid, epoch=epoch,
                                endpoint_identity=endpoint_identity).start()
        guard.assert_held()
        yield guard
    finally:
        if guard is not None:
            guard.close()
        else:
            connection.close()


def _automatic_idle_busy(db):
    now = int(time.time())
    # A recently expired browser session may still own an in-memory PTY.
    return bool(
        db.execute('SELECT 1 FROM sessions WHERE expires_at>? LIMIT 1', (now - 300,)).fetchone()
        or db.execute("SELECT 1 FROM jobs WHERE state IN ('queued','delivered') LIMIT 1").fetchone()
        or db.execute('SELECT 1 FROM pending_commands WHERE expires_at>? LIMIT 1', (now,)).fetchone()
    )


class _IdleBarrierHolder:
    def __init__(self, pid, release_fd, database, info):
        self.pid = pid
        self.release_fd = release_fd
        self.database = database
        self.identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid)
        self.reaped = False

    def assert_held(self):
        if self.reaped:
            fail('STATE')
        ended, _status = os.waitpid(self.pid, os.WNOHANG)
        if ended:
            self.reaped = True
            fail('STATE')
        try:
            info = self.database.lstat()
        except OSError:
            fail('STATE')
        if not stat.S_ISREG(info.st_mode) or (
                info.st_dev, info.st_ino, info.st_uid, info.st_gid) != self.identity:
            fail('STATE')

    def close(self):
        if self.release_fd is not None:
            os.close(self.release_fd)
            self.release_fd = None
        if self.reaped:
            return
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            ended, _status = os.waitpid(self.pid, os.WNOHANG)
            if ended:
                self.reaped = True
                return
            time.sleep(0.02)
        with contextlib.suppress(ProcessLookupError):
            os.kill(self.pid, signal.SIGKILL)
        os.waitpid(self.pid, 0)
        self.reaped = True


def _idle_barrier_child(database, ack_fd, release_fd):
    """Hold the SQLite reservation with the same filesystem identity as Hub."""
    status = b'S'
    sent = False
    db = None
    try:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGHUP, signal.SIG_DFL)
        if os.geteuid() == 0:
            # The parent directory is root-only. SQLite resolves its path
            # again on open, so chdir alone cannot grant UID 10001 access.
            # Chroot into the Hub-owned leaf before dropping privilege.
            os.chroot(database.parent)
            os.chdir('/')
            os.setgroups([])
            uri = 'file:/hub.sqlite?mode=rw'
        else:
            # Portable non-root fixture: only the real Ubuntu updater uses
            # chroot and the fixed Hub UID/GID.
            os.chdir(database.parent)
            uri = 'file:hub.sqlite?mode=rw'
        if os.getegid() != HUB_GID:
            os.setgid(HUB_GID)
        if os.geteuid() != HUB_UID:
            os.setuid(HUB_UID)
        db = sqlite3.connect(uri, uri=True, timeout=0,
                             isolation_level=None)
        db.execute('BEGIN IMMEDIATE')
        if _automatic_idle_busy(db):
            status = b'B'
        else:
            status = b'R'
        os.write(ack_fd, status)
        sent = True
        if status == b'R':
            # EOF releases the lock even if the root parent exits abruptly.
            os.read(release_fd, 1)
    except sqlite3.OperationalError as exc:
        if 'locked' in str(exc).lower() or 'busy' in str(exc).lower():
            status = b'B'
    except (OSError, sqlite3.Error):
        pass
    finally:
        if db is not None:
            with contextlib.suppress(sqlite3.Error):
                db.rollback()
            with contextlib.suppress(sqlite3.Error):
                db.close()
        if not sent:
            with contextlib.suppress(OSError):
                os.write(ack_fd, status)
        with contextlib.suppress(OSError):
            os.close(ack_fd)
        with contextlib.suppress(OSError):
            os.close(release_fd)
        os._exit(0)


@contextlib.contextmanager
def automatic_idle_barrier():
    """Serialize the final idle read with Hub writes until its container stops.

    Hub uses BEGIN IMMEDIATE for login, jobs and agent writes. With the same
    writer reservation, no new work can commit after this final idle check.
    The caller must release the barrier as soon as Hub is confirmed stopped,
    before copying or restoring the database.
    """
    database = path('/var/lib/sovagrid/hub/hub.sqlite')
    try:
        info = database.lstat()
        directory = database.parent.lstat()
    except OSError:
        fail('STATE')
    if not (stat.S_ISREG(info.st_mode) and info.st_uid == HUB_UID and info.st_gid == HUB_GID
            and stat.S_ISDIR(directory.st_mode) and directory.st_uid == HUB_UID
            and directory.st_gid == HUB_GID):
        fail('STATE')
    try:
        ack_read, ack_write = os.pipe()
    except OSError:
        fail('STATE')
    try:
        release_read, release_write = os.pipe()
    except OSError:
        os.close(ack_read)
        os.close(ack_write)
        fail('STATE')
    try:
        pid = os.fork()
    except OSError:
        for fd in (ack_read, ack_write, release_read, release_write):
            os.close(fd)
        fail('STATE')
    if pid == 0:
        os.close(ack_read)
        os.close(release_write)
        _idle_barrier_child(database, ack_write, release_read)
    os.close(ack_write)
    os.close(release_read)
    holder = _IdleBarrierHolder(pid, release_write, database, info)
    try:
        ready, _, _ = select.select([ack_read], [], [], 5)
        if not ready:
            fail('STATE')
        status = os.read(ack_read, 1)
        if status == b'B':
            fail('BUSY')
        if status != b'R':
            fail('STATE')
        holder.assert_held()
        yield holder
    finally:
        os.close(ack_read)
        holder.close()

def apply(candidate_digest, expected_manifest, *, automatic=False):
    import fcntl
    if not re.fullmatch(r'[0-9a-f]{64}', expected_manifest):
        fail('VERSION')
    candidate_root = path('/opt/sovagrid-candidates')
    private_candidate_root(candidate_root)
    lock_path = candidate_root / '.lock'
    lock = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock, 'rb') as lock_file, contextlib.ExitStack() as operation_locks:
        validate_lock(os.fstat(lock_file.fileno()))
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        # Older Connect versions also take candidate before run.sh's public
        # lock. Preserve that order across versions to avoid a lock cycle.
        operation_locks.enter_context(public_web_lock())
        operation_locks.enter_context(service_setup_lock())
        operation_locks.enter_context(managed_vpn_locks())
        transactions = candidate_root / 'transactions'
        transactions.mkdir(mode=0o700, exist_ok=True)
        private_candidate_root(transactions)
        for pending in sorted(transactions.iterdir()):
            if not pending.is_dir() or pending.is_symlink():
                fail('STATE')
            state = json.loads((pending / 'state.json').read_text())
            if state['phase'] not in ('committed', 'rolled_back'):
                emit('SG_APPLY_STAGE:RECOVERING')
                if not restore(pending, state):
                    fail('RECOVERY')
                finalize_rollback(pending)
                fail('RECOVERED')
        source, old_manifest, old_commits, flags, expected_units = inspect_state()
        if old_manifest != expected_manifest:
            fail('VERSION')
        if source.stat().st_dev != candidate_root.stat().st_dev:
            fail('STATE')
        staged, new_commits = candidate_source(candidate_digest)
        if new_commits == old_commits:
            fail('SAME_VERSION')
        candidate_features_compatible(staged, flags)
        emit('SG_APPLY_STAGE:VERIFIED')
        total = sum(safe_snapshot_item(path(value)) for value in SNAPSHOT)
        free = shutil.disk_usage(candidate_root).free
        if total > MAX_BACKUP or free < total * 2 + 512 * 1024**2:
            fail('SPACE')
        gateway_before = gateway_prior_state()
        images = {}
        for service in compose_services():
            result = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', 'sovagrid-' + service + ':local'],
                                    capture_output=True, text=True, timeout=10, check=True)
            images[service] = result.stdout.strip()
        unit_states = {unit: {
            'active': command(['systemctl', 'is-active', '--quiet', unit], timeout=10, check=False) == 0,
            'enabled': command(['systemctl', 'is-enabled', '--quiet', unit], timeout=10, check=False) == 0,
        } for unit in UNITS}
        # Stop admitting Agent work before reserving Hub's writer. Reversing
        # that order could deadlock an in-flight Agent result against SQLite.
        agent_admission = contextlib.ExitStack()
        operation_locks.callback(agent_admission.close)
        agent_guard = agent_admission.enter_context(automatic_agent_quiescence()) if automatic else None
        # Reserve Hub's SQLite writer before any service stops. Login, jobs,
        # Telegram confirmations and Agent writes all serialize on this DB.
        # Keep the reservation until the Hub container is confirmed stopped.
        admission = contextlib.ExitStack()
        operation_locks.callback(admission.close)
        barrier = admission.enter_context(automatic_idle_barrier()) if automatic else None
        folder = transactions / (str(time.time_ns()) + '-' + candidate_digest[:12])
        created = False
        try:
            folder.mkdir(mode=0o700)
            created = True
            state = {'phase': 'preparing', 'old_manifest': old_manifest, 'candidate': candidate_digest,
                     'snapshot_layout': 'ssh_gateway_v1',
                     'images': images, 'units': unit_states, 'expected_units': expected_units,
                     'gateway_before': gateway_before}
            state_write(folder, state)
        except BaseException:
            admission.close()
            agent_admission.close()
            if created:
                with contextlib.suppress(OSError):
                    shutil.rmtree(folder)
            raise
        try:
            for service in images:
                command(['docker', 'image', 'tag', images[service], 'sovagrid-' + service + ':rollback-' + candidate_digest[:12]])
            if automatic:
                args, env = compose_args(source)
                # Stop Hub first and release the writer as soon as Docker
                # confirms it exited. The remaining services can stop without
                # delaying Hub writes through this reservation.
                command(args + ['stop', '--timeout', '30', 'hub'], timeout=45, env=env)
                running = subprocess.run(
                    ['docker', 'ps', '--quiet', '--filter', 'label=com.docker.compose.project=sovagrid',
                     '--filter', 'label=com.docker.compose.service=hub'],
                    capture_output=True, text=True, timeout=10, check=True,
                ).stdout.strip()
                if running:
                    raise UpdateFailure('container did not stop: hub')
                barrier.assert_held()
                agent_guard.assert_held()
                admission.close()
                # The Hub is down, so no new relay or command can be handed
                # to this Agent. Stop it while the Agent idle ACK still holds.
                agent_guard.begin_stop()
                command(['systemctl', 'stop', AGENT_UNIT], timeout=40)
                agent_guard.confirm_stopped()
                agent_admission.close()
            command(['systemctl', 'stop', *BACKUP_BROKER_UNITS], timeout=40, check=False)
            remaining_units = tuple(unit for unit in reversed(SERVICE_UNITS)
                                    if not automatic or unit != AGENT_UNIT)
            command(['systemctl', 'stop', *remaining_units], timeout=40, check=False)
            if not automatic:
                args, env = compose_args(source)
            command(args + ['stop'], timeout=120, env=env)
            for service in images:
                running = subprocess.run(
                    ['docker', 'ps', '--quiet', '--filter', 'label=com.docker.compose.project=sovagrid',
                     '--filter', 'label=com.docker.compose.service=' + service],
                    capture_output=True, text=True, timeout=10, check=True,
                ).stdout.strip()
                if running:
                    raise UpdateFailure('container did not stop: ' + service)
            admission.close()
            agent_admission.close()
            emit('SG_APPLY_STAGE:STOPPED')
            (folder / 'snapshot').mkdir(mode=0o700)
            for index, value in enumerate(SNAPSHOT):
                item = path(value)
                if item.exists():
                    copy_item(item, folder / 'snapshot' / str(index))
            new_source = folder / 'source-new'
            copy_item(staged, new_source)
            pinned_manifest = source_manifest(staged)[0]
            if source_manifest(new_source) != (pinned_manifest, new_commits):
                raise UpdateFailure('candidate changed during copy')
            state['phase'] = 'backed_up'
            state_write(folder, state)
            if source_manifest(source, allow_generated=True)[0] != old_manifest:
                raise UpdateFailure('installed source changed before switch')
            os.replace(source, folder / 'source-before')
            os.replace(new_source, source)
            state['phase'] = 'running'
            state_write(folder, state)
            emit('SG_APPLY_STAGE:INSTALLING')
            with (folder / 'install.log').open('wb') as output:
                os.chmod(output.fileno(), 0o600)
                install_env = os.environ.copy()
                # The supervisor holds the same lock throughout source switch,
                # installation and rollback; a nested run.sh must not deadlock.
                install_env['SOVAGRID_PUBLIC_WEB_LOCK_HELD'] = '1'
                install_env['SOVAGRID_UPDATER_TIMER_SNAPSHOT'] = '1'
                install_env['SOVAGRID_RELEASE_FEED_SNAPSHOT'] = '1'
                install_env['SOVAGRID_HUB_BACKUP_BROKER_SNAPSHOT'] = '1'
                install_env['SOVAGRID_SSH_GATEWAY_SNAPSHOT'] = '1'
                command(['bash', str(source / 'sovagrid-blueprint/run.sh'), *flags], timeout=2700, stdout=output, env=install_env)
            refresh_service_units(folder / 'source-before', source, unit_states)
            emit('SG_APPLY_STAGE:CHECKING')
            health(source, expected_units)
            for unit in SERVICE_UNITS:
                old = unit_states[unit]
                command(['systemctl', 'enable' if old['enabled'] else 'disable', unit],
                        timeout=30, check=old['enabled'])
                command(['systemctl', 'restart' if old['active'] else 'stop', unit],
                        timeout=60, check=old['active'])
            for state_name, action in (('active', 'is-active'), ('enabled', 'is-enabled')):
                observed = command(['systemctl', action, '--quiet', ROUTING_UNIT],
                                   timeout=10, check=False) == 0
                if observed != unit_states[ROUTING_UNIT][state_name]:
                    raise UpdateFailure('routing service state changed during update')
            if source_manifest(source, allow_generated=True)[1] != new_commits or managed_flags()[0] != flags:
                raise UpdateFailure('version or features changed after installation')
            state['phase'] = 'committed'
            state_write(folder, state)
            emit('SG_APPLY_STAGE:DONE')
        except BaseException:
            # Preparing transactions have not copied or swapped the database.
            # Release the writer reservation before rollback can restart Hub.
            admission.close()
            agent_admission.close()
            emit('SG_APPLY_STAGE:ROLLBACK')
            if restore(folder, state):
                finalize_rollback(folder)
                raise UpdateFailure('update failed and was rolled back')
            raise UpdateFailure('update failed; rollback needs recovery')
        # Cleanup is deliberately outside the rollback branch: a failed
        # cleanup must never undo a healthy committed deployment.
        try:
            shutil.rmtree(folder)
            for service in images:
                command(['docker', 'image', 'rm', 'sovagrid-' + service + ':rollback-' + candidate_digest[:12]],
                        timeout=30, check=False)
        except (OSError, UpdateFailure):
            pass

def interrupted(_number, _frame):
    if ACTIVE_CHILD is not None and ACTIVE_CHILD.poll() is None:
        try:
            os.killpg(ACTIVE_CHILD.pid, signal.SIGTERM)
            ACTIVE_CHILD.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(ACTIVE_CHILD.pid, signal.SIGKILL)
                ACTIVE_CHILD.wait()
            except OSError:
                pass
    raise UpdateFailure('interrupted')

if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    try:
        if len(sys.argv) == 2 and sys.argv[1] == 'preview':
            preview()
        elif len(sys.argv) == 4 and sys.argv[1] == 'preflight':
            preflight(sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 4 and sys.argv[1] == 'apply':
            apply(sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 4 and sys.argv[1] == 'apply-auto':
            apply(sys.argv[2], sys.argv[3], automatic=True)
        else:
            fail('ARGS')
    except UpdateFailure:
        sys.exit(40)
    except Exception:
        emit('SG_UPDATE_REFUSE:UNEXPECTED')
        sys.exit(41)
