# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Fixed root-side programs for the opt-in Agent-only promotion wizard.

Only a locally pinned, fully verified bundle may supply the promotion helper.
The archive is sent on stdin; it is never interpolated into a shell command.
Remote stdout contains fixed markers, while detailed logs remain root-only.
"""

STAGE_SCRIPT = r'''
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

SOURCE = Path('/opt/sovagrid-src')
HELPER = 'sovagrid-blueprint/deploy/promote_agent_only.py'
COMPONENTS = {'sovagrid-blueprint', 'sovagrid-hub', 'sovagrid-web', 'sovagrid-agent', 'sovagrid-vpn'}
REQUIRED = {HELPER, 'sovagrid-blueprint/run.sh', 'sovagrid-blueprint/deploy/compose.yaml',
            'sovagrid-hub/Dockerfile', 'sovagrid-web/Dockerfile',
            'sovagrid-web/deploy/Caddyfile.container',
            'sovagrid-agent/deploy/sovagrid-agent.service',
            'sovagrid-vpn/deploy/sovagrid-vpn-status.service'}
archive_path = None
stage = None

def need(value):
    if not value:
        raise RuntimeError('refused')

def lock():
    path = Path('/run/sovagrid-promotion.lock')
    need(not path.is_symlink())
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd

def inspect(helper):
    reply = subprocess.run(['python3', str(helper), 'inspect'], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           check=False, timeout=40, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    need(reply.returncode == 0 and len(reply.stdout) <= 4096)
    value = json.loads(reply.stdout)
    need(isinstance(value, dict) and value.get('protocol') == 1 and
         value.get('phase') == 'prepared' and value.get('external_agent_preserved') is True and
         value.get('pinned_manifest_sha256') == expected_manifest)

try:
    need(os.geteuid() == 0 and len(sys.argv) == 3)
    expected_archive, expected_manifest = sys.argv[1:]
    need(re.fullmatch(r'[0-9a-f]{64}', expected_archive) and
         re.fullmatch(r'[0-9a-f]{64}', expected_manifest))
    lock_fd = lock()
    need(not os.path.lexists(SOURCE))
    fd, archive_path = tempfile.mkstemp(prefix='.sovagrid-promotion-archive-', dir='/opt')
    digest = hashlib.sha256()
    count = 0
    with os.fdopen(fd, 'wb') as stream:
        while True:
            chunk = sys.stdin.buffer.read(128 * 1024)
            if not chunk:
                break
            count += len(chunk)
            need(count <= 64 * 1024 * 1024)
            digest.update(chunk)
            stream.write(chunk)
        stream.flush()
        os.fsync(stream.fileno())
    need(count > 0 and digest.hexdigest() == expected_archive)
    stage = Path(tempfile.mkdtemp(prefix='.sovagrid-promotion-source-', dir='/opt'))
    hashes = {}
    names = set()
    expanded = 0
    with tarfile.open(archive_path, 'r:gz') as archive:
        need(not archive.pax_headers)
        for member in archive:
            name = member.name.rstrip('/') if member.isdir() else member.name
            pure = PurePosixPath(name)
            need(len(name) <= 240 and name.isascii() and not name.startswith('/') and
                 pure.parts and not any(part in ('', '.', '..') or
                 re.fullmatch(r'[A-Za-z0-9_.@-]+', part) is None for part in pure.parts) and
                 '/'.join(pure.parts) == name and name not in names)
            names.add(name)
            target = stage / name
            if member.isdir():
                need(member.mode == 0o755)
                target.mkdir(parents=True, exist_ok=True, mode=0o755)
                target.chmod(0o755)
                continue
            need(member.isfile() and member.mode in (0o644, 0o755) and
                 0 <= member.size <= 32 * 1024 * 1024)
            expanded += member.size
            need(expanded <= 256 * 1024 * 1024 and len(hashes) < 4096)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            source = archive.extractfile(member)
            need(source is not None)
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 getattr(os, 'O_NOFOLLOW', 0), member.mode)
            file_hash = hashlib.sha256()
            with os.fdopen(descriptor, 'wb') as output:
                remaining = member.size
                while remaining:
                    part = source.read(min(128 * 1024, remaining))
                    need(part)
                    output.write(part)
                    file_hash.update(part)
                    remaining -= len(part)
                os.fchmod(output.fileno(), member.mode)
            hashes[name] = file_hash.hexdigest()
    need({p.name for p in stage.iterdir()} == COMPONENTS | {'sovagrid-bundle.json'})
    need(REQUIRED <= hashes.keys() and hashes.get('sovagrid-bundle.json') == expected_manifest)
    manifest = json.loads((stage / 'sovagrid-bundle.json').read_bytes())
    need(isinstance(manifest, dict) and manifest.get('format') == 1 and
         set(manifest.get('components', {})) == COMPONENTS and
         manifest.get('sha256') == {name: value for name, value in hashes.items()
                                    if name != 'sovagrid-bundle.json'})
    inspect(stage / HELPER)
    need(not os.path.lexists(SOURCE))
    # Linux renameat2 with NOREPLACE prevents another root process's source
    # directory from being silently replaced between checks.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    need(rename(-100, os.fsencode(stage), -100, os.fsencode(SOURCE), 1) == 0)
    stage = None
    print('SG_PROMOTION_STAGE:DONE', flush=True)
except Exception:
    print('SG_PROMOTION_REFUSE:STAGE', flush=True)
    raise SystemExit(1)
finally:
    if archive_path is not None:
        try:
            os.unlink(archive_path)
        except OSError:
            pass
    if stage is not None:
        shutil.rmtree(stage, ignore_errors=True)
'''


ACTION_SCRIPT = r'''
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SOURCE = Path('/opt/sovagrid-src')
HELPER = SOURCE / 'sovagrid-blueprint/deploy/promote_agent_only.py'
RUN = SOURCE / 'sovagrid-blueprint/run.sh'
LOG_DIR = Path('/var/lib/sovagrid-promotion')

def need(value):
    if not value:
        raise RuntimeError('refused')

def inspect():
    reply = subprocess.run(['python3', str(HELPER), 'inspect'], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           check=False, timeout=40, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    need(reply.returncode == 0 and len(reply.stdout) <= 4096)
    state = json.loads(reply.stdout)
    need(isinstance(state, dict) and state.get('protocol') == 1 and
         state.get('external_agent_preserved') is True and
         state.get('pinned_manifest_sha256') == expected_manifest and
         state.get('source_manifest_sha256') == expected_manifest)
    return state['phase']

def private_log(name):
    info = LOG_DIR.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
    path = LOG_DIR / name
    if os.path.lexists(path):
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600)
    return fd

try:
    need(os.geteuid() == 0 and len(sys.argv) == 3)
    action, expected_manifest = sys.argv[1:]
    need(action in ('hub', 'activate') and re.fullmatch(r'[0-9a-f]{64}', expected_manifest))
    lock = Path('/run/sovagrid-promotion.lock')
    need(not lock.is_symlink())
    lock_fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    info = os.fstat(lock_fd)
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    source_info = SOURCE.lstat()
    need(stat.S_ISDIR(source_info.st_mode) and source_info.st_uid == 0 and
         not source_info.st_mode & 0o022)
    manifest = SOURCE / 'sovagrid-bundle.json'
    manifest_info = manifest.lstat()
    need(stat.S_ISREG(manifest_info.st_mode) and manifest_info.st_uid == 0 and
         not manifest_info.st_mode & 0o022 and 0 < manifest_info.st_size <= 512 * 1024)
    manifest_raw = manifest.read_bytes()
    need(hashlib.sha256(manifest_raw).hexdigest() == expected_manifest)
    hashes = json.loads(manifest_raw).get('sha256')
    need(isinstance(hashes, dict))
    for file in (HELPER, RUN):
        info = file.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
             not info.st_mode & 0o022 and 0 < info.st_size <= 8 * 1024 * 1024)
        relative = file.relative_to(SOURCE).as_posix()
        need(hashlib.sha256(file.read_bytes()).hexdigest() == hashes.get(relative))
    before = inspect()
    if action == 'hub':
        need(before == 'source_staged')
        command = ['bash', str(RUN), '--hub-only']
        log_name = 'hub-install.log'
        expected_after = 'hub_installed'
        marker = 'SG_PROMOTION_HUB:DONE'
    else:
        need(before == 'hub_installed')
        command = ['python3', str(HELPER), 'activate']
        log_name = 'local-agent-activation.log'
        expected_after = 'activated'
        marker = 'SG_PROMOTION_AGENT:DONE'
    fd = private_log(log_name)
    with os.fdopen(fd, 'wb') as output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,
                                   env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        remaining = 2 * 1024 * 1024
        truncated = False
        with process.stdout:
            while True:
                chunk = process.stdout.read(64 * 1024)
                if not chunk:
                    break
                kept = chunk[:remaining]
                if kept:
                    output.write(kept)
                    remaining -= len(kept)
                if len(chunk) > len(kept):
                    truncated = True
        if truncated:
            output.write(b'\n[installation output truncated after 2 MiB]\n')
        output.flush()
        os.fsync(output.fileno())
        returncode = process.wait()
    need(returncode == 0 and inspect() == expected_after)
    print(marker, flush=True)
except Exception:
    print('SG_PROMOTION_REFUSE:ACTION', flush=True)
    raise SystemExit(1)
'''
