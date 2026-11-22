#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Review and remove a managed Hub installation and its enrolled Agents."""
from __future__ import annotations

import argparse
import ast
import base64
from contextlib import ExitStack, closing
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import sqlite3
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import remote_agent as enrollment
import remote_update_worker as installed
import managed_monitoring as monitoring
import uninstall_agent as agent_uninstall
import uninstall_hub_only as hub_only
import uninstall_recovery as recovery
from web_agent_jobs import _vendor

SOURCE = Path('/opt/sovagrid-src')
DATA = Path('/var/lib/sovagrid')
DB = DATA / 'hub/hub.sqlite'
MARKER = DATA / '.managed-by-run-sh'
WEB_JOBS = DATA / 'web-agent/jobs'
BACKUPS = DATA / 'backups'
DOCKER = ('docker', '--host', 'unix:///var/run/docker.sock')
UNITS = Path('/etc/systemd/system')
UNIT = re.compile(r'sovagrid-[a-z0-9@.-]+\.(?:service|socket|timer)\Z')
VPN_CODE = Path('/opt/sovagrid-vpn')
ROUTING_POLICY = '/etc/sovagrid-vpn-routing/policy.json'
ROUTING_SYSCTL = '/etc/sysctl.d/70-sovagrid-vpn-routing.conf'
ROUTING_UNIT = '/etc/systemd/system/' + installed.ROUTING_UNIT
ROUTING_MODULES = ('__init__.py', 'managed.py', 'proposal.py', 'routing.py')
ALIAS = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}\Z')
COMPOSE_SERVICES = frozenset({'hub', 'web', 'ssh-gateway', 'prometheus'})
# User files, backups, exported images and WireGuard data remain on disk.
RUNTIME = (
    '/etc/sovagrid-journal', '/etc/sovagrid-hub', '/etc/sovagrid',
    '/opt/sovagrid-agent', '/opt/sovagrid-vpn', '/opt/sovagrid-candidates',
    '/var/lib/sovagrid-containers', '/var/lib/sovagrid-monitoring',
    '/var/lib/sovagrid-host-backup-operations', '/var/cache/sovagrid-web-restores',
)


class UninstallError(RuntimeError):
    pass


def need(condition, description):
    if not condition:
        raise UninstallError(description)


def execute(*argv, timeout=60):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False, timeout=timeout)
    need(result.returncode == 0, f'Ошибка команды {argv[0]} {argv[1]}')
    return result.stdout


@dataclass(frozen=True)
class Agent:
    enrollment_id: str
    server_id: str
    ssh_key_fingerprint: str
    name: str

    def payload(self):
        return {field: getattr(self, field) for field in
                ('enrollment_id', 'server_id', 'ssh_key_fingerprint')}


def installed_agents(db, ledger, *, local_id=None):
    """Require agreement between the Hub database and the root tunnel ledger."""
    state = ledger.hub_state()
    if state:
        ledger.check_owned_files(state)
    entries = state['enrollments'] if state else {}
    registered = db.execute('''
        SELECT e.id, e.server_id, e.name, s.last_seen FROM agent_enrollments e
        LEFT JOIN servers s ON s.id = e.server_id WHERE e.cancelled_at IS NULL ORDER BY e.id
    ''').fetchall()
    registered_ids = {row[0] for row in registered}
    tracked_servers = {row[1] for row in registered}
    reporters = {row[0] for row in db.execute('SELECT id FROM servers WHERE last_seen IS NOT NULL')}
    unowned = sorted(reporters - tracked_servers - {local_id})
    need(not unowned, 'Есть Agent без подтверждённой установки этим Hub: ' + ', '.join(unowned))
    need(all(entry['revoked'] for identity, entry in entries.items() if identity not in registered_ids),
         'Есть незавершённая установка Agent. Завершите или отмените её в панели.')
    result = []
    for identity, server, name, last_seen in registered:
        entry = entries.get(identity)
        need(last_seen is not None and entry and entry['server_id'] == server,
             'Не удалось подтвердить зарегистрированный Agent. Восстановите установку в панели.')
        enrollment.canonical_uuid(identity)
        enrollment.canonical_uuid(server)
        result.append(Agent(identity, server, entry['ssh_key_fingerprint'], name))
    return result


def ssh_user():
    user = pwd.getpwnam(os.environ.get('SUDO_USER') or 'root')
    return {'user': user.pw_uid, 'group': user.pw_gid,
            'extra_groups': os.getgrouplist(user.pw_name, user.pw_gid),
            'env': {**os.environ, 'HOME': user.pw_dir, 'USER': user.pw_name,
                    'LOGNAME': user.pw_name, 'SSH_ASKPASS_REQUIRE': 'never'}}


def agent_rpc(agent, route, action, revision=None):
    need(ALIAS.fullmatch(route), 'Укажите имя SSH-профиля из ~/.ssh/config')
    request = agent.payload()
    if revision is not None:
        request['expected_revision'] = revision
    encoded = base64.urlsafe_b64encode(json.dumps(request).encode()).decode().rstrip('=')
    root_command = (f'/usr/bin/python3 -B -I - {action} {encoded}')
    command = f'if [ "$(id -u)" = 0 ]; then exec {root_command}; else exec sudo -n {root_command}; fi'
    script = agent_uninstall.ssh_program()
    result = subprocess.run(
        ['ssh', '-T', '-o', 'StrictHostKeyChecking=yes', '-o', 'ClearAllForwardings=yes',
         '-o', 'ForwardAgent=no', '-o', 'ConnectTimeout=10', '--', route, command],
        input=script, stdout=subprocess.PIPE, timeout=150, check=False, **ssh_user(),
    )
    need(result.returncode == 0 and len(result.stdout) <= 4096,
         f'SSH-профиль {route} не подтвердил удаление. Проверьте связь и права установки.')
    reply = json.loads(result.stdout, object_pairs_hook=enrollment.unique_object)
    need(set(reply) == {'enrollment_id', 'server_id', 'state', 'revision'} and
         reply['enrollment_id'] == agent.enrollment_id and reply['server_id'] == agent.server_id and
         reply['state'] in ({'ready', 'removed'} if action == 'preview' else {'removed'}) and
         enrollment.SHA.fullmatch(reply['revision']) and
         (revision is None or reply['revision'] == revision),
         f'SSH-профиль {route} не подтвердил ожидаемый Agent')
    return reply


def reviewed_units(manifest, layout=None):
    tracked = {}
    for name, digest in manifest['sha256'].items():
        candidate = Path(name)
        if candidate.parent.name == 'deploy' and UNIT.fullmatch(candidate.name):
            tracked.setdefault(candidate.name, set()).add(digest)
    if layout is not None and layout.local_id is not None:
        local = hub_only.promotion
        tracked[local.LOCAL_UNIT.name] = {hashlib.sha256(local.UNIT_TEXT.encode()).hexdigest()}
    result = []
    for path in sorted(UNITS.glob('sovagrid-*')):
        if not UNIT.fullmatch(path.name):
            continue
        if path.name == installed.ROUTING_UNIT:
            # Routing remains independent of the Hub, including a unit with
            # this name installed by the server administrator.
            continue
        if layout is not None and path.name not in layout.allowed_units:
            continue
        data = path.lstat()
        known = tracked.get(path.name, set())
        need(stat.S_ISREG(data.st_mode) and data.st_uid == 0 and data.st_nlink == 1 and
             not data.st_mode & 0o022 and
             hashlib.sha256(path.read_bytes()).hexdigest() in known,
             f'Служба {path.name} не совпадает с установленным пакетом')
        if '@.' in path.name:
            # systemctl show requires an instance name. The template itself
            # is never stopped as a unit, and its jobs are checked separately.
            instance = path.name.replace('@.', '@uninstall-review.')
        else:
            instance = path.name
        effective = execute('systemctl', 'show', '-p', 'FragmentPath', '-p', 'DropInPaths',
                            instance).decode().splitlines()
        need(set(effective) == {f'FragmentPath={path}', 'DropInPaths='},
             f'Для {path.name} есть дополнительные настройки systemd')
        result.append(path)
    return result


def reviewed_routing(manifest):
    if not os.path.lexists(ROUTING_POLICY):
        return None
    # A completed ownership record identifies the optional SovaGrid boot
    # routing service. The updater already validates the private policy.
    policy = installed.public_path(ROUTING_POLICY, private=True, limit=8192)
    if json.loads(policy) == {'version': 1, 'enabled': [], 'pending_remove': []}:
        return None
    need(installed.managed_routing_enabled(), 'Политика маршрутизации WireGuard не подтверждена')
    sources = {}
    for name in ROUTING_MODULES:
        relative = 'sovagrid_vpn/' + name
        selected = installed.public_path(str(VPN_CODE / relative), limit=512 * 1024)
        expected = manifest['sha256'].get('sovagrid-vpn/' + relative)
        need(hashlib.sha256(selected).hexdigest() == expected,
             f'Код маршрутизации WireGuard отличается от установленного пакета: {name}')
        sources[name] = selected
    # The unit and sysctl are emitted by routing.py and do not have their
    # own files in the release manifest. Extract the reviewed literals
    # without importing or executing any VPN code.
    constants = {}
    for node in ast.parse(sources['routing.py']).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, = node.targets
            if isinstance(target, ast.Name) and target.id in {'UNIT_CONTENT', 'SYSCTL_CONTENT'}:
                constants[target.id] = ast.literal_eval(node.value)
    unit = installed.public_path(ROUTING_UNIT, limit=4096)
    sysctl = installed.public_path(ROUTING_SYSCTL, limit=4096)
    need(unit == constants.get('UNIT_CONTENT') and sysctl == constants.get('SYSCTL_CONTENT'),
         'Служба маршрутизации WireGuard или sysctl отличается от установленного пакета')
    return policy, unit, sysctl


def reviewed_containers(roots):
    identifiers = execute(*DOCKER, 'ps', '-aq').decode().splitlines()
    if not identifiers:
        return []
    objects = json.loads(execute(*DOCKER, 'inspect', *identifiers))
    collector = monitoring._collector_details(monitoring._token_hash())
    collector_id = collector['Id'] if collector else None
    result = []
    for item in objects:
        labels = item['Config']['Labels'] or {}
        if item['Id'] == collector_id:
            need(labels.get('com.docker.compose.project.working_dir') == str(SOURCE / 'sovagrid-blueprint/deploy')
                 and item['Config']['Image'] == monitoring.IMAGE,
                 'Параметры управляемого Prometheus изменились')
            result.append(item['Id'])
        elif labels.get('com.docker.compose.project') == 'sovagrid':
            service = labels.get('com.docker.compose.service')
            working = labels.get('com.docker.compose.project.working_dir', '')
            need(service in COMPOSE_SERVICES and Path(working) == SOURCE / 'sovagrid-blueprint/deploy',
                 'Проект Docker sovagrid содержит неопознанный контейнер')
            result.append(item['Id'])
        else:
            for mount in item['Mounts']:
                origin = Path(mount['Source'])
                need(not any(origin.is_relative_to(root) for root in roots),
                     'Другой контейнер использует файлы SovaGrid')
    return sorted(result)


def reviewed_network(containers):
    ids = execute(*DOCKER, 'network', 'ls', '-q', '--filter',
                  'label=com.docker.compose.project=sovagrid').decode().splitlines()
    if not ids:
        return None
    need(len(ids) == 1, 'У проекта sovagrid несколько сетей')
    network, = json.loads(execute(*DOCKER, 'network', 'inspect', ids[0]))
    need(network['Name'] == 'sovagrid_private' and
         network['Labels'].get('com.docker.compose.network') == 'private' and
         set(network['Containers'] or {}) <= set(containers),
         'Другой контейнер использует сеть SovaGrid')
    return network['Id']


def runtime_roots(layout=None, *, keep_routing=False):
    paths = [Path(name) for name in RUNTIME]
    if layout is not None:
        paths = [path for path in paths if path not in {
            hub_only.SHARED_CONFIG, Path('/opt/sovagrid-agent'), Path('/etc/sovagrid-journal'),
            Path('/var/lib/sovagrid-containers'),
        }]
        paths.extend(layout.extra_paths)
    if keep_routing:
        paths.remove(VPN_CODE)
    paths.extend((Path(enrollment.HUB_STATE_DIR), DATA, SOURCE))
    roots = []
    mounts = [Path(re.sub(r'\\([0-7]{3})', lambda token: chr(int(token[1], 8)), line.split()[4]))
              for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    for path in [*paths, *(layout.retained_paths if layout is not None else ())]:
        if not os.path.lexists(path):
            continue
        info = path.lstat()
        need(not any(mount.is_relative_to(path) for mount in mounts),
             f'Точка монтирования внутри пути {path}')
        if path in paths:
            # Shared configuration files are explicitly enumerated by the
            # layout. Existing full-install roots must still be directories.
            if layout is not None and path in layout.regular_paths:
                kind_ok = stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            else:
                kind_ok = stat.S_ISDIR(info.st_mode)
            need(kind_ok and info.st_uid == 0 and not info.st_mode & 0o022,
                 f'Небезопасный путь {path}')
            roots.append(path)
        else:
            need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700,
                 f'Небезопасный рабочий каталог {path}')
    if os.path.lexists(BACKUPS):
        data = BACKUPS.lstat()
        need(stat.S_ISDIR(data.st_mode) and data.st_uid == 0 and
             stat.S_IMODE(data.st_mode) == 0o700, 'Небезопасный каталог резервных копий')
    return roots


def root_identities(roots):
    identities = []
    for path in roots:
        data = path.lstat()
        identities.append((path, data.st_dev, data.st_ino))
    return identities


def stop_local(units, containers, network, ledger, agents):
    # Stop the specific authorizations only after all remote removals are proven.
    state = ledger.hub_state()
    if state:
        for agent in agents:
            ledger.hub_revoke({**agent.payload(), 'expected': ledger.cas('hub')})
    for unit in ('.timer', '.socket', '.service'):
        names = [path.name for path in units if path.name.endswith(unit) and '@.' not in path.name]
        if names:
            execute('systemctl', 'stop', *names)
            execute('systemctl', 'disable', *names)
    if containers:
        # The managed collector shares Hub's network namespace. Remove it
        # before its owner so Docker never sees a stale container dependency.
        collector = monitoring._collector_details(monitoring._token_hash())
        if collector is not None:
            identifier = collector['Id']
            need(identifier in containers, 'Управляемый Prometheus изменился после проверки')
            execute(*DOCKER, 'rm', '--force', identifier, timeout=120)
            containers = [item for item in containers if item != identifier]
        if containers:
            execute(*DOCKER, 'rm', '--force', *containers, timeout=120)
    if network:
        execute(*DOCKER, 'network', 'rm', network)
    if state is not None:
        with ledger.locked('hub'):
            state = ledger.hub_state()
            need(all(item['revoked'] for item in state['enrollments'].values()) and not state['accounts'],
                 'Не все SSH-разрешения отозваны')
            ledger.check_owned_files(state)
            policy = enrollment.POLICY_PATH
            if policy in state['owned_files']:
                ledger.unlink_owned('hub', state, policy)
                execute('/usr/sbin/sshd', '-t')
                execute('systemctl', 'reload', ledger.ssh_service())
            keys = Path('/etc/ssh/sovagrid-tunnels')
            if str(keys) in state['owned_directories'] and keys.exists():
                keys.rmdir()


def remove_local(units, roots, retained=(), *, external=None):
    state = recovery.prepare(units, roots, retained, BACKUPS, external)
    recovery.complete(state, execute)


def resume_local(plan):
    state = recovery.read_state()
    print('Hub уже остановлен. Осталось завершить удаление его локальных файлов.')
    print('Пути: ' + ', '.join(record['path'] for record in state['roots']))
    if plan:
        return 0
    with (open('/dev/tty', encoding='utf-8') as reader,
          open('/dev/tty', 'w', encoding='utf-8') as writer):
        writer.write('Для продолжения введите REMOVE SOVAGRID: ')
        writer.flush()
        if reader.readline().strip() != 'REMOVE SOVAGRID':
            return 0
    recovery.complete(state, execute)
    print('Удаление SovaGrid завершено.')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', action='store_true', help='только проверить и показать список')
    parser.add_argument('--route', action='append', default=[], metavar='SERVER_ID=SSH_PROFILE',
                        help='профиль OpenSSH с проверенными ключами и правами установки')
    args = parser.parse_args(argv)
    try:
        need(os.geteuid() == 0, 'Запустите удаление через sudo')
        need(not os.path.lexists('/var/lib/.sovagrid-host-restore-in-progress'),
             'Сначала завершите восстановление Hub')
        routes = {}
        for value in args.route:
            server, separator, alias = value.partition('=')
            need(separator and ALIAS.fullmatch(alias) and server not in routes, 'Неверный --route')
            routes[enrollment.canonical_uuid(server)] = alias
        with ExitStack() as stack:
            stack.enter_context(installed.installation_lock())
            if os.path.lexists(recovery.STATE):
                need(not routes, 'На этом этапе нужны только локальные файлы. Уберите --route.')
                return resume_local(args.plan)
            installed.public_path(str(MARKER), private=True)
            shared = hub_only.is_hub_only()
            if shared:
                stack.callback(os.close, hub_only.updates._lock(hub_only.updates.PROMOTION_LOCK))
            manifest_digest, _commits = installed.source_manifest(SOURCE, allow_generated=True)
            # Shares the lock used by Web Agent mutations; even during the review
            # a new pending install must not leave the fleet inventory incomplete.
            stack.enter_context(installed.web_agent_snapshot_lock())
            if shared:
                stack.enter_context(installed.public_web_lock())
                stack.enter_context(installed.service_setup_lock())
            return uninstall(args.plan, routes, manifest_digest=manifest_digest if shared else None)
    except (OSError, KeyError, TypeError, ValueError, sqlite3.Error, subprocess.SubprocessError,
            UninstallError, enrollment.Refuse, installed.UpdateFailure, monitoring.MonitoringError,
            hub_only.promotion.PromotionError, hub_only.updates.Refused,
            hub_only.updates.common.UpdateFailure, recovery.RecoveryError) as error:
        print(f'SovaGrid: {error}', file=sys.stderr)
        return 1


def uninstall(plan, routes, *, manifest_digest=None):
    ledger = enrollment.Enrollment(executable=str(SOURCE / enrollment.SELF_NAME))
    manifest = json.loads((SOURCE / 'sovagrid-bundle.json').read_bytes())
    layout = hub_only.inspect(manifest, manifest_digest) if manifest_digest is not None else None
    routing = reviewed_routing(manifest)
    roots = runtime_roots(layout, keep_routing=routing is not None)
    retained = layout.retained_paths if layout is not None else ()
    identities = root_identities([*roots, *retained])
    units = reviewed_units(manifest, layout)
    containers = reviewed_containers([*roots, *retained])
    network = reviewed_network(containers)
    if layout is None:
        local_config = installed.public_path('/etc/sovagrid/agent.json', limit=65536)
        local_id = enrollment.canonical_uuid(json.loads(local_config)['server_id'])
    else:
        local_id = layout.local_id
    if WEB_JOBS.exists():
        _options, journal, journal_error = _vendor()
        try:
            need(not any(record['phase'] != 'active' or record['cleanup_required']
                         for record in journal(WEB_JOBS).list()),
                 'Есть незавершённая установка Agent. Завершите или отмените её в панели.')
        except journal_error:
            raise UninstallError('Журнал установок Agent недоступен') from None
    with closing(sqlite3.connect(f'{DB.as_uri()}?mode=ro', uri=True)) as database:
        agents = installed_agents(database, ledger, local_id=local_id)
    needed = {agent.server_id for agent in agents}
    need(routes.keys() <= needed, 'Профиль задан для неизвестного или чужого сервера')
    mode = 'Hub-only' if layout is not None else 'Hub'
    print(f'{mode}: служб {len(units)}, контейнеров {len(containers)}, удалённых Agent {len(agents)}.')
    print('Удаляемые службы: ' + (', '.join(path.name for path in units) or 'нет'))
    print('Удаляемые каталоги: ' + ', '.join(map(str, roots)))
    print(f'Копии из {BACKUPS} будут перенесены в отдельный каталог рядом. '
          'Пользовательские файлы, выгрузки и конфигурация WireGuard сохраняются.')
    if routing is not None:
        print('Служба маршрутизации WireGuard, её политика, sysctl и код сохраняются.')
    for agent in agents:
        name = json.dumps(agent.name, ensure_ascii=False)
        print(f'Agent {name} ({agent.server_id})')
    if plan:
        return 0
    with (open('/dev/tty', encoding='utf-8') as reader,
          open('/dev/tty', 'w', encoding='utf-8') as writer):
        reviewed = []
        for agent in agents:
            route = routes.get(agent.server_id)
            if not route:
                writer.write(f'SSH-профиль для {agent.server_id}: ')
                writer.flush()
                route = reader.readline().strip()
            reviewed.append((agent, route, agent_rpc(agent, route, 'preview')))
        writer.write('Удалить Hub и перечисленные Agent? Введите REMOVE SOVAGRID: ')
        writer.flush()
        if reader.readline().strip() != 'REMOVE SOVAGRID':
            print('Удаление отменено.')
            return 0
    # Keep writes out of the Hub between revalidating the roster and stopping
    # the backend. Existing database files remain in place if any target fails.
    def check_local(database):
        if layout is not None:
            layout_matches = hub_only.inspect(manifest, manifest_digest) == layout
        else:
            layout_matches = local_config == installed.public_path('/etc/sovagrid/agent.json', limit=65536)
        need(layout_matches and reviewed_routing(manifest) == routing and
             agents == installed_agents(database, ledger, local_id=local_id) and
             identities == root_identities([*runtime_roots(layout, keep_routing=routing is not None), *retained]) and
             units == reviewed_units(manifest, layout) and
             containers == reviewed_containers([*roots, *retained]) and
             network == reviewed_network(containers),
             'Состав установки изменился. Получите новый план.')

    with closing(sqlite3.connect(f'{DB.as_uri()}?mode=rw', uri=True, timeout=3)) as database:
        database.execute('BEGIN IMMEDIATE')
        check_local(database)
        for agent, route, result in reviewed:
            if result['state'] == 'ready':
                agent_rpc(agent, route, 'apply', result['revision'])
            else:
                need(agent_rpc(agent, route, 'preview') == result, 'Подтверждение удаления изменилось')
        check_local(database)
        stop_local(units, containers, network, ledger, agents)
    need(reviewed_routing(manifest) == routing and
         identities == root_identities([*runtime_roots(layout, keep_routing=routing is not None), *retained]),
         'Каталоги установки изменились после остановки Hub')
    if layout is not None:
        layout.recheck_external()
    if layout is None:
        remove_local(units, roots, retained)
    else:
        remove_local(units, roots, retained, external=layout.external)
    if layout is not None:
        layout.recheck_external()
    print('Hub и управляемые Agent удалены. Пользовательские файлы и резервные копии сохранены.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
