# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Read-only proof of the exact root-run Hub backup source and data layout."""

SCRIPT = r'''
import hashlib, json, os, pathlib, pwd, re, stat, sys

ROOT = pathlib.Path('/opt/sovagrid-src')
SOURCE = ROOT / 'sovagrid-hub'
DATA_ROOT = pathlib.Path('/var/lib/sovagrid')
SHA = re.compile(r'[0-9a-f]{64}\Z')
CACHE_NAME = re.compile(r'([A-Za-z0-9_]+)\.cpython-[0-9]{2,3}(?:\.opt-[0-9])?\.pyc\Z')

def need(ok):
    if not ok:
        raise ValueError('SOURCE_UNVERIFIED')

def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value)
        value[key] = item
    return value

def directory(path, uid, gid, mode):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and info.st_gid == gid and
         stat.S_IMODE(info.st_mode) == mode)

def regular(path, uid, gid, modes, maximum, *, read=True):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_gid == gid and
         info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in modes and
         0 < info.st_size <= maximum)
    if not read:
        return None
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        actual = os.fstat(fd)
        need((actual.st_dev, actual.st_ino, actual.st_size) ==
             (info.st_dev, info.st_ino, info.st_size))
        chunks = []
        remaining = maximum + 1
        while remaining:
            block = os.read(fd, min(65536, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b''.join(chunks)
        need(len(data) == info.st_size)
        return data
    finally:
        os.close(fd)

def checked_component(manifest):
    prefix = 'sovagrid-hub/'
    hashes = manifest['sha256']
    expected = {}
    for key, digest in hashes.items():
        if not isinstance(key, str) or not key.startswith(prefix):
            continue
        relative = key[len(prefix):]
        parts = relative.split('/')
        need(1 <= len(parts) <= 8 and all(part and part not in ('.', '..') for part in parts) and
             re.fullmatch(r'[A-Za-z0-9_.-]+', ''.join(parts)) is not None and
             isinstance(digest, str) and SHA.fullmatch(digest) is not None)
        expected[relative] = digest
    need(8 <= len(expected) <= 256 and
         'sovagrid_hub/backup.py' in expected and
         'sovagrid_hub/amnezia_actions.py' in expected and
         'sovagrid_hub/service_actions.py' in expected)
    seen = set()
    stack = [(SOURCE, '')]
    directories = 0
    total = 0
    cache_count = 0
    while stack:
        directory_path, parent = stack.pop()
        directory_info = directory_path.lstat()
        need(stat.S_ISDIR(directory_info.st_mode) and directory_info.st_uid == 0 and
             directory_info.st_gid == 0 and not directory_info.st_mode & 0o022)
        directories += 1
        need(directories <= 64)
        for child in directory_path.iterdir():
            relative = parent + child.name
            info = child.lstat()
            if stat.S_ISDIR(info.st_mode):
                stack.append((child, relative + '/'))
                continue
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
                 info.st_nlink == 1 and not info.st_mode & 0o022)
            if child.name.endswith('.pyc') and parent.endswith('__pycache__/'):
                match = CACHE_NAME.fullmatch(child.name)
                source_name = parent[:-len('__pycache__/')] + match.group(1) + '.py' if match else None
                need(source_name in expected and 0 < info.st_size <= 1048576)
                cache_count += 1
                total += info.st_size
                need(cache_count <= 256 and total <= 16 * 1024**2)
                continue
            need(relative in expected and relative not in seen)
            data = regular(child, 0, 0, {0o644, 0o755}, 1048576)
            need(hashlib.sha256(data).hexdigest() == expected[relative])
            seen.add(relative)
            total += len(data)
            need(total <= 16 * 1024**2)
    need(seen == set(expected))

def check(expected, source_only=False):
    need(os.geteuid() == 0 and SHA.fullmatch(expected) is not None)
    for path in (pathlib.Path('/opt'), ROOT):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
             not info.st_mode & 0o022)
    raw = regular(ROOT / 'sovagrid-bundle.json', 0, 0, {0o644}, 524288)
    need(hashlib.sha256(raw).hexdigest() == expected)
    manifest = json.loads(raw, object_pairs_hook=unique)
    need(isinstance(manifest, dict) and set(manifest) == {'format', 'components', 'sha256'} and
         type(manifest['format']) is int and manifest['format'] == 1 and
         isinstance(manifest['sha256'], dict))
    checked_component(manifest)
    if source_only:
        return {'protocol': 1, 'manifest_sha256': expected, 'source_verified': True}
    account = pwd.getpwnam('sovagrid-hub')
    need((account.pw_uid, account.pw_gid) == (10001, 10001))
    directory(DATA_ROOT, 0, 0, 0o700)
    directory(DATA_ROOT / 'hub', 10001, 10001, 0o700)
    regular(DATA_ROOT / 'hub/hub.sqlite', 10001, 10001, {0o600}, 4 * 1024**3,
            read=False)
    backups = DATA_ROOT / 'backups'
    present = os.path.lexists(backups)
    if present:
        directory(backups, 0, 0, 0o700)
    return {'protocol': 1, 'manifest_sha256': expected, 'backups_present': present}

try:
    need(len(sys.argv) in (2, 3) and
         (len(sys.argv) == 2 or sys.argv[2] == 'source-only'))
    print(json.dumps(check(sys.argv[1], len(sys.argv) == 3),
                     sort_keys=True, separators=(',', ':')))
except (OSError, KeyError, ValueError, TypeError, UnicodeError):
    print('SG_HUB_BACKUP_SOURCE_REFUSE:UNVERIFIED')
    raise SystemExit(40)
'''
