#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Select the appropriate uninstaller for the managed layout on this host."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from uninstall_agent import AgentRemoval, MAX_STATE, Refused, STATE, read_json

_HUB_PATHS = (
    '/opt/sovagrid-src', '/etc/sovagrid-hub', '/var/lib/sovagrid/.managed-by-run-sh',
    '/var/lib/sovagrid-promotion', '/var/lib/.sovagrid-uninstall-recovery.json',
)


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
        hub_present = any(os.path.lexists(path) for path in _HUB_PATHS)
        if '--agent-only' in argv:
            if hub_present or argv.count('--agent-only') != 1:
                raise Refused('Удаление отдельного Agent доступно на хосте без Hub')
            return agent_only([arg for arg in argv if arg != '--agent-only'])
        if hub_present:
            from uninstall_hub import main as hub_main
            return hub_main(argv)
        if os.path.lexists(STATE):
            raise Refused('На хосте есть только Agent. Для его удаления укажите --uninstall --agent-only')
        raise Refused('Управляемый Hub на этой машине не найден')
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError, Refused) as error:
        print(f'SovaGrid: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
