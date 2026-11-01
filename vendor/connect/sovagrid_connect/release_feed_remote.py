# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Exact-source preflight before reviewing or changing the signed feed."""

SOURCE_PROOF = r'''
import hashlib, json, os, pathlib, re, stat, subprocess, sys

ROOT = pathlib.Path('/opt/sovagrid-src')
DEPLOY = ROOT / 'sovagrid-blueprint/deploy'
UNITS = pathlib.Path('/etc/systemd/system')
MARKER = pathlib.Path('/var/lib/sovagrid/.release-feed-units-managed-by-run-sh')
SHA = re.compile(r'[0-9a-f]{64}\Z')
SAFE = re.compile(r'(?!\.{1,2}(?:/|\Z))[A-Za-z0-9_.@-]+'
                  r'(?:/(?!\.{1,2}(?:/|\Z))[A-Za-z0-9_.@-]+)*\Z')
GENERATED = re.compile(r'sovagrid-[a-z]+/(?:[A-Za-z0-9_.-]+/)*__pycache__/[A-Za-z0-9_.-]+\.cpython-[0-9]+\.pyc\Z')
COMPONENTS = {'sovagrid-blueprint', 'sovagrid-hub', 'sovagrid-web', 'sovagrid-agent', 'sovagrid-vpn'}
REQUIRED = {'sovagrid-blueprint/deploy/release_feed.py',
            'sovagrid-blueprint/deploy/remote_update_worker.py',
            'sovagrid-blueprint/deploy/auto_update.py',
            'sovagrid-blueprint/deploy/sovagrid-release-feed.service',
            'sovagrid-blueprint/deploy/sovagrid-release-feed.timer',
            'sovagrid-blueprint/run.sh'}

class Refused(Exception):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'JSON')
        result[key] = value
    return result

def checked_dir(path):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
         'SOURCE_OWNER')

def checked_file(path, modes, limit):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) in modes and 0 <= info.st_size <= limit,
         'SOURCE_FILE')
    return path.read_bytes()

def source(expected):
    need(os.geteuid() == 0 and SHA.fullmatch(expected) is not None, 'ROOT_OR_DIGEST')
    checked_dir(pathlib.Path('/opt'))
    checked_dir(ROOT)
    raw = checked_file(ROOT / 'sovagrid-bundle.json', {0o644}, 524288)
    need(hashlib.sha256(raw).hexdigest() == expected, 'SOURCE_MANIFEST')
    manifest = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    need(isinstance(manifest, dict) and set(manifest) == {'format', 'components', 'sha256'} and
         type(manifest['format']) is int and manifest['format'] == 1 and
         isinstance(manifest['components'], dict) and
         set(manifest['components']) == COMPONENTS and
         isinstance(manifest['sha256'], dict), 'SOURCE_MANIFEST')
    hashes = manifest['sha256']
    need(REQUIRED <= set(hashes) and len(hashes) <= 4096 and
         {path.name for path in ROOT.iterdir()} == COMPONENTS | {'sovagrid-bundle.json'},
         'SOURCE_MANIFEST')
    actual = set()
    total = 0
    for parent, dirs, files in os.walk(ROOT, followlinks=False):
        checked_dir(pathlib.Path(parent))
        for name in dirs:
            checked_dir(pathlib.Path(parent) / name)
        for name in files:
            item = pathlib.Path(parent) / name
            relative = item.relative_to(ROOT).as_posix()
            if relative == 'sovagrid-bundle.json':
                continue
            if GENERATED.fullmatch(relative):
                checked_file(item, {0o644}, 1048576)
                continue
            need(SAFE.fullmatch(relative) is not None and relative in hashes and
                 isinstance(hashes[relative], str) and SHA.fullmatch(hashes[relative]) is not None,
                 'SOURCE_FILE_LIST')
            info = item.lstat()
            total += info.st_size
            need(total <= 256 * 1024 * 1024, 'SOURCE_SIZE')
            value = checked_file(item, {0o644, 0o755}, 32 * 1024 * 1024)
            need(hashlib.sha256(value).hexdigest() == hashes[relative], 'SOURCE_HASH')
            actual.add(relative)
    need(actual == set(hashes), 'SOURCE_FILE_LIST')
    for name, record in manifest['components'].items():
        need(isinstance(record, dict) and set(record) == {'commit', 'file_count'} and
             isinstance(record['commit'], str) and
             re.fullmatch(r'[0-9a-f]{40}', record['commit']) is not None and
             type(record['file_count']) is int and
             record['file_count'] == sum(path.startswith(name + '/') for path in hashes),
             'SOURCE_MANIFEST')
    return hashes

'''

FEED_PROOF = r'''
def units(hashes):
    checked_dir(UNITS)
    names = ('sovagrid-release-feed.service', 'sovagrid-release-feed.timer')
    if not MARKER.exists() and not MARKER.is_symlink():
        need(all(not (UNITS / name).exists() and not (UNITS / name).is_symlink()
                 for name in names), 'UNMANAGED_UNIT')
        return False
    need(checked_file(MARKER, {0o600}, 128) == b'SOVAGRID_RELEASE_FEED_UNITS_V1\n',
         'UNIT_MARKER')
    for name in names:
        relative = 'sovagrid-blueprint/deploy/' + name
        installed = checked_file(UNITS / name, {0o644}, 32768)
        need(installed == checked_file(ROOT / relative, {0o644}, 32768) and
             hashlib.sha256(installed).hexdigest() == hashes[relative], 'UNIT_CONTENT')
    return True

def feed_status(expected):
    hashes = source(expected)
    installed = units(hashes)
    result = subprocess.run(['/usr/bin/python3', '-I', str(DEPLOY / 'release_feed.py'),
                             'status'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=30, check=False,
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                                 'PYTHONDONTWRITEBYTECODE': '1'})
    need(result.returncode == 0 and len(result.stdout) <= 4096, 'FEED_STATUS')
    report = json.loads(result.stdout.decode('utf-8'), object_pairs_hook=unique)
    need(isinstance(report, dict) and
         set(report) == {'format', 'channel', 'enabled', 'key_id', 'available_keys',
                         'timer_installed', 'timer_enabled', 'timer_active',
                         'manual_candidate_active', 'installed_manifest_sha256',
                         'state_revision', 'ledger'} and
         type(report['format']) is int and report['format'] == 1 and
         report['channel'] == 'stable' and report['timer_installed'] is installed,
         'FEED_STATUS')
    need(type(report['timer_enabled']) is bool and
         type(report['timer_active']) is bool and
         (not report['timer_active'] or installed) and
         report['installed_manifest_sha256'] == expected and
         isinstance(report['state_revision'], str) and
         SHA.fullmatch(report['state_revision']) is not None,
         'FEED_STATUS')
    return {'protocol': 1, 'source_manifest_sha256': expected,
            'units_verified': installed, 'feed': report}

'''

SCRIPT = SOURCE_PROOF + FEED_PROOF + r'''
def status(expected):
    print(json.dumps(feed_status(expected), sort_keys=True, separators=(',', ':')))

try:
    need(len(sys.argv) == 3 and sys.argv[1] == 'status', 'ARGS')
    status(sys.argv[2])
except (Refused, OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
    code = str(exc) if isinstance(exc, Refused) else 'UNVERIFIED'
    print('SG_RELEASE_FEED_CLIENT_REFUSE:' + code)
    raise SystemExit(40)
'''

MUTATION_SCRIPT = SOURCE_PROOF + FEED_PROOF + r'''
KEY_ID = re.compile(r'[a-z0-9][a-z0-9_-]{0,63}\Z')

def mutate(expected, action, revision, key_id):
    need(SHA.fullmatch(revision) is not None and action in ('enable', 'disable'), 'ARGS')
    current = feed_status(expected)
    report = current['feed']
    need(report['state_revision'] == revision, 'STATE_CHANGED')
    if action == 'enable':
        need(current['units_verified'], 'TIMER_NOT_INSTALLED')
        need(not report['enabled'], 'STATE_CHANGED')
        need(KEY_ID.fullmatch(key_id) is not None and
             key_id in report['available_keys'], 'UNCONFIGURED_TRUST')
        args = ['enable', key_id]
        success = ('SG_RELEASE_FEED:ENABLED:' + key_id + '\n').encode()
    else:
        need(key_id == '-' and report['enabled'], 'STATE_CHANGED')
        args = ['disable']
        success = b'SG_RELEASE_FEED:DISABLED\n'
    result = subprocess.run(['/usr/bin/python3', '-I', str(DEPLOY / 'release_feed.py'),
                             *args, '--expected-state', revision],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=120, check=False,
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                                 'PYTHONDONTWRITEBYTECODE': '1'})
    need(len(result.stdout) <= 256, 'UNVERIFIED_RESULT')
    if result.returncode != 0:
        if result.stdout == b'SG_RELEASE_FEED_REFUSE:STATE_CHANGED\n':
            raise Refused('STATE_CHANGED')
        raise Refused('SERVER_REFUSED')
    need(result.stdout == success, 'UNVERIFIED_RESULT')
    print('SG_RELEASE_FEED_CLIENT_APPLIED:' + action)

try:
    need(len(sys.argv) == 6 and sys.argv[1] == 'mutate', 'ARGS')
    mutate(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
except (Refused, OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
    code = str(exc) if isinstance(exc, Refused) else 'UNVERIFIED'
    print('SG_RELEASE_FEED_CLIENT_REFUSE:' + code)
    raise SystemExit(40)
'''
