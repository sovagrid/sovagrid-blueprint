# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Resume checked file removal after the Hub and all its Agents have stopped."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import tempfile

import promote_agent_only as promotion
import remote_update_worker as installed

STATE = Path('/var/lib/.sovagrid-uninstall-recovery.json')
MOUNTINFO = Path('/proc/self/mountinfo')


class RecoveryError(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise RecoveryError(message)


def identity(path):
    info = path.lstat()
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode]


def entry(path):
    return {'path': str(path), 'identity': identity(path)}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(units, roots, retained, backups, external):
    suffix = secrets.token_hex(12)
    moves = [(path, backups.parent.parent / f'sovagrid-workspaces-retained-{suffix}' / path.name)
             for path in retained]
    if os.path.lexists(backups):
        moves.append((backups, backups.parent.parent / f'sovagrid-backups-retained-{suffix}' / backups.name))
    state = {'version': 1, 'external': external,
             'units': [{**entry(path), 'sha256': digest(path)} for path in units],
             'roots': [entry(path) for path in roots],
             'retained': [{**entry(path), 'destination': str(destination)} for path, destination in moves]}
    descriptor, temporary = tempfile.mkstemp(prefix='.sovagrid-uninstall-', dir=STATE.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(json.dumps(state, sort_keys=True).encode())
            stream.flush()
            os.fsync(stream.fileno())
        require(not os.path.lexists(STATE), 'Уже существует журнал удаления')
        os.replace(temporary, STATE)
        sync_state_directory()
    finally:
        Path(temporary).unlink(missing_ok=True)
    return state


def sync_state_directory():
    descriptor = os.open(STATE.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_state():
    raw = installed.public_path(str(STATE), private=True, limit=1024 * 1024)
    state = json.loads(raw)
    require(type(state) is dict and state.get('version') == 1 and
            set(state) == {'version', 'external', 'units', 'roots', 'retained'},
            'Неверный журнал удаления')
    return state


def existing(record, *, key='path'):
    path = Path(record[key])
    require(path.is_absolute() and path != Path('/') and '..' not in path.parts,
            'Небезопасный путь в журнале удаления')
    if not os.path.lexists(path):
        return None
    require(identity(path) == record['identity'], f'Ресурс изменился после остановки Hub: {path}')
    return path


def recheck_external(external):
    if external is not None:
        actual = promotion.capture_external(check_runtime=False)
        require(json.dumps(actual, sort_keys=True) == json.dumps(external, sort_keys=True),
                'Исходный Agent или его SSH-туннель изменились')


def complete(state, execute):
    recheck_external(state['external'])
    units = []
    for record in state['units']:
        path = existing(record)
        if path is not None:
            require(digest(path) == record['sha256'], f'Служба изменилась: {path}')
            if '@.' not in path.name:
                active = execute('systemctl', 'show', '-P', 'ActiveState', path.name).decode().strip()
                require(active in ('inactive', 'failed'), f'Служба запустилась после остановки Hub: {path.name}')
            units.append(path)
    roots = [path for record in state['roots'] if (path := existing(record)) is not None]
    mounts = [Path(line.split()[4].replace('\\040', ' '))
              for line in MOUNTINFO.read_text().splitlines()]
    retain = [Path(record['path']) for record in state['retained']]
    require(not any(mount.is_relative_to(root) for mount in mounts for root in (*roots, *retain)),
            'Точка монтирования в каталоге SovaGrid появилась после остановки Hub')
    for record in state['retained']:
        origin = existing(record)
        destination = Path(record['destination'])
        if origin is None:
            require(existing(record, key='destination') is not None, 'Сохраняемый каталог исчез')
        else:
            require(not os.path.lexists(destination), f'Путь сохранения уже занят: {destination}')
            destination.parent.mkdir(mode=0o700, exist_ok=True)
            directory = destination.parent.lstat()
            require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == os.geteuid() and
                    stat.S_IMODE(directory.st_mode) == 0o700, 'Небезопасный каталог сохранения')
            origin.rename(destination)
        print(f'Данные сохранены в {destination}')
    for unit in units:
        unit.unlink()
    execute('systemctl', 'daemon-reload')
    for root in roots:
        if stat.S_ISDIR(root.lstat().st_mode):
            shutil.rmtree(root)
        else:
            root.unlink()
    recheck_external(state['external'])
    STATE.unlink()
    sync_state_directory()
