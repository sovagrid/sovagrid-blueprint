#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Select the appropriate uninstaller for the managed layout on this host."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from uninstall_agent import AgentRemoval, MAX_STATE, Refused, STATE, read_json
import uninstall_hub as hub

_HUB_MARKER = '/var/lib/sovagrid/.managed-by-run-sh'
_HUB_PATHS = (
    '/opt/sovagrid-src', '/etc/sovagrid-hub', _HUB_MARKER,
    '/var/lib/sovagrid-promotion', str(hub.recovery.STATE),
)
# Workspaces, backups and WireGuard configuration can remain after uninstall.
_RUNTIME_PATHS = (
    *(path for path in hub.RUNTIME if path not in ('/etc/sovagrid', str(hub.VPN_CODE))),
    '/var/lib/sovagrid', hub.enrollment.HUB_STATE_DIR,
    '/etc/sovagrid/agent.json', '/etc/sovagrid/deploy.env', '/etc/sovagrid/hub-ca.pem',
    hub.VPN_CONTROL_MARKER,
    '/etc/sovagrid-local', '/opt/sovagrid-agent-local',
    '/var/lib/.sovagrid-host-restore-in-progress',
)


def runtime_remnants():
    paths = [path for path in _RUNTIME_PATHS if os.path.lexists(path)]
    if os.path.lexists(hub.VPN_CODE) and not os.path.lexists(hub.ROUTING_POLICY):
        paths.append(str(hub.VPN_CODE))
    units = set()
    for action in ('list-unit-files', 'list-units'):
        arguments = ('--all', '--plain') if action == 'list-units' else ()
        rows = hub.execute('systemctl', action, *arguments, '--no-legend', '--no-pager',
                           timeout=10).decode().splitlines()
        for row in rows:
            fields = row.split()
            if not fields or not fields[0].startswith('sovagrid-') or fields[0] == hub.installed.ROUTING_UNIT:
                continue
            if action == 'list-unit-files' or fields[1:3] != ['not-found', 'inactive']:
                units.add(fields[0])
    paths.extend(sorted(units))
    if os.path.lexists('/var/run/docker.sock'):
        command = [*hub.DOCKER, 'ps', '-a', '--format', '{{.Names}}\t{{.Label "com.docker.compose.project"}}']
        # The host has to be local even when the operator has configured Docker contexts.
        env = {key: value for key, value in os.environ.items() if key not in ('DOCKER_HOST', 'DOCKER_CONTEXT')}
        for row in subprocess.check_output(command, timeout=10, env=env, text=True).splitlines():
            name, _, project = row.partition('\t')
            if project in ('sovagrid', 'sovagrid-monitoring'):
                paths.append(name)
    return paths


def ensure_no_runtime():
    remnants = runtime_remnants()
    if remnants:
        raise Refused('Найдены следы установки без журнала управляемого Hub. Проверьте: ' + ', '.join(remnants))


def cleanup_old_programs(*, plan):
    source = Path(__file__).resolve().parents[2]
    try:
        hub.installed.source_manifest(source)
        manifest = json.loads((source / 'sovagrid-bundle.json').read_bytes())
    except (OSError, ValueError, hub.installed.UpdateFailure) as error:
        raise Refused('Остались программы управления VPN. Повторите проверку через проверенный run.sh.') from error
    with hub.installed.installation_lock():
        def recheck_layout():
            ensure_no_runtime()
            if any(os.path.lexists(path) for path in (*_HUB_PATHS, STATE, hub.VPN_CODE)):
                raise Refused('Остались файлы Hub, Agent или маршрутизации VPN. Проверьте состав установки.')

        recheck_layout()
        programs = hub.reviewed_vpn_programs(manifest)
        if not programs:
            print('SovaGrid: Программы управления VPN уже удалены.')
            return 0
        identities = hub.root_identities(programs)
        print('SovaGrid: Остались проверенные программы управления VPN. Можно удалить: ' +
              ', '.join(map(str, programs)))
        if plan:
            return 0
        with (open('/dev/tty', encoding='utf-8') as reader,
              open('/dev/tty', 'w', encoding='utf-8') as writer):
            writer.write('Для удаления введите REMOVE SOVAGRID: ')
            writer.flush()
            if reader.readline().strip() != 'REMOVE SOVAGRID':
                print('Удаление отменено.')
                return 0
        recheck_layout()
        if hub.root_identities(hub.reviewed_vpn_programs(manifest)) != identities:
            raise Refused('Состав установки изменился. Получите новый план.')
        for path in programs:
            path.unlink()
    print('SovaGrid: Программы управления VPN удалены. Данные и конфигурация WireGuard сохранены.')
    return 0


def agent_only(argv):
    parser = argparse.ArgumentParser(description='Удалить управляемый Agent с этого сервера')
    parser.add_argument('--plan', action='store_true', help='проверить Agent и показать план удаления')
    if argv == ['--help']:
        parser.print_help()
        return 0
    args = parser.parse_args(argv)
    if not os.path.lexists(STATE):
        raise Refused('Управляемый Hub или Agent на этой машине не найден')
    remover = AgentRemoval()
    state = read_json(remover.read(STATE, mode=0o600, limit=MAX_STATE))
    request = {name: state['identity'][name] for name in ('enrollment_id', 'server_id')}
    operation = state.get('uninstallation') or {}
    request['ssh_key_fingerprint'] = operation.get('fingerprint') or state['ssh_key_fingerprint']
    review = remover.run('preview', request)
    if review['state'] == 'removed':
        print('SovaGrid: Agent уже удалён.')
        return 0
    print(f'SovaGrid: будет удалён Agent {request["server_id"]}. Рабочие файлы сохранятся.')
    if args.plan:
        return 0
    with (open('/dev/tty', encoding='utf-8') as reader,
          open('/dev/tty', 'w', encoding='utf-8') as writer):
        writer.write('Для удаления введите REMOVE SOVAGRID: ')
        writer.flush()
        if reader.readline().strip() != 'REMOVE SOVAGRID':
            print('Удаление отменено.')
            return 0
    remover.run('apply', {**request, 'expected_revision': review['revision']})
    print('SovaGrid: Agent удалён. Его запись ещё доступна администратору в Hub.')
    return 0


def main(argv):
    try:
        if os.geteuid() != 0:
            raise Refused('Запустите удаление через sudo')
        hub_paths = [path for path in _HUB_PATHS if os.path.lexists(path)]
        agent_present = os.path.lexists(STATE)
        agent_mode = '--agent-only' in argv
        if agent_mode:
            if hub_paths or argv.count('--agent-only') != 1:
                raise Refused('Удаление отдельного Agent доступно на хосте без Hub')
            argv = [arg for arg in argv if arg != '--agent-only']
            if agent_present or argv == ['--help']:
                return agent_only(argv)
        if hub_paths:
            if _HUB_MARKER not in hub_paths and str(hub.recovery.STATE) not in hub_paths:
                raise Refused('Найдены следы установки без журнала управляемого Hub. Проверьте: ' + ', '.join(hub_paths))
            return hub.main(argv)
        if agent_present:
            raise Refused('На хосте есть только Agent. Для его удаления укажите --uninstall --agent-only')
        if argv not in ([], ['--plan']):
            raise Refused('Для проверки удалённой установки доступны --uninstall и --uninstall --plan')
        ensure_no_runtime()
        if any(os.path.lexists(path) for path in hub.hub_only.VPN_PROGRAMS):
            if agent_mode:
                raise Refused('На хосте остались программы управления VPN. Запустите --uninstall --plan.')
            return cleanup_old_programs(plan=argv == ['--plan'])
        print('SovaGrid: Установка уже удалена или не выполнялась. Сохранённые данные оставлены на месте.')
        return 0
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError, Refused,
            hub.UninstallError, hub.installed.UpdateFailure) as error:
        print(f'SovaGrid: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
