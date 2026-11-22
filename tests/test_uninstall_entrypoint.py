# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Exercise ordinary run.sh's local uninstall layout selection."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import nullcontext
from unittest.mock import MagicMock, Mock, patch

from deploy import uninstall


class UninstallEntryPointTest(unittest.TestCase):
    def test_hub_layout_wins_over_existing_agent(self):
        with (patch.object(uninstall.os, 'geteuid', return_value=0),
              patch.object(uninstall.os.path, 'lexists', return_value=True),
              patch('uninstall_hub.main', return_value=0) as hub,
              patch.object(uninstall, 'agent_only') as agent):
            self.assertEqual(uninstall.main(['--plan']), 0)
        hub.assert_called_once_with(['--plan'])
        agent.assert_not_called()

    def test_agent_plan_is_read_only(self):
        remover = Mock()
        identity = {'enrollment_id': 'test-enrollment', 'server_id': 'test-agent'}
        request = {**identity, 'ssh_key_fingerprint': 'test-pin'}
        remover.read.return_value = json.dumps({'identity': identity, 'ssh_key_fingerprint': 'test-pin'}).encode()
        remover.run.return_value = {'state': 'ready'}
        with (patch.object(uninstall.os, 'geteuid', return_value=0),
              patch.object(uninstall.os.path, 'lexists', side_effect=lambda name: name == uninstall.STATE),
              patch.object(uninstall, 'AgentRemoval', return_value=remover),
              patch('builtins.print')):
            self.assertEqual(uninstall.main(['--agent-only', '--plan']), 0)
        remover.run.assert_called_once_with('preview', request)

    def test_repeating_hub_removal_does_not_remove_an_independent_agent(self):
        with (patch.object(uninstall.os, 'geteuid', return_value=0),
              patch.object(uninstall.os.path, 'lexists', side_effect=lambda name: name == uninstall.STATE),
              patch.object(uninstall, 'AgentRemoval') as remover,
              patch('builtins.print')):
            self.assertEqual(uninstall.main([]), 1)
        remover.assert_not_called()

    def test_removed_hub_with_retained_data_returns_success(self):
        retained = {'/var/lib/sovagrid-agent', '/var/lib/sovagrid-shell', '/var/lib/sovagrid-vpn'}
        with (patch.object(uninstall.os, 'geteuid', return_value=0),
              patch.object(uninstall.os.path, 'lexists', side_effect=lambda name: name in retained),
              patch.object(uninstall, 'AgentRemoval') as remover,
              patch.object(uninstall.hub, 'execute', return_value=b''),
              patch('builtins.print') as output):
            self.assertEqual(uninstall.main(['--plan']), 0)
        remover.assert_not_called()
        self.assertIn('уже удалена', output.call_args.args[0])

    def test_live_runtime_without_manifest_is_reported_and_not_removed(self):
        with (patch.object(uninstall.os, 'geteuid', return_value=0),
              patch.object(uninstall.os.path, 'lexists', return_value=False),
              patch.object(uninstall.hub, 'execute', side_effect=[
                  b'sovagrid-vpn-routing.service enabled enabled\n',
                  b'sovagrid-hub.service not-found inactive dead old\n'
                  b'sovagrid-agent.service loaded active running agent\n',
              ]),
              patch.object(uninstall, 'cleanup_old_programs') as cleanup,
              patch('builtins.print') as output):
            self.assertEqual(uninstall.main([]), 1)
        cleanup.assert_not_called()
        self.assertIn('sovagrid-agent.service', output.call_args.args[0])
        self.assertNotIn('sovagrid-hub.service', output.call_args.args[0])
        self.assertNotIn('sovagrid-vpn-routing.service', output.call_args.args[0])

    def test_docker_probe_checks_only_local_sovagrid_projects(self):
        docker_rows = 'ordinary\tother\nold-hub\tsovagrid\nold-metrics\tsovagrid-monitoring\n'
        with (patch.object(uninstall.os.path, 'lexists',
                           side_effect=lambda name: name == '/var/run/docker.sock'),
              patch.object(uninstall.hub, 'execute', return_value=b''),
              patch.object(uninstall.subprocess, 'check_output', return_value=docker_rows) as docker,
              patch.dict(os.environ, {'DOCKER_HOST': 'tcp://remote', 'DOCKER_CONTEXT': 'remote'})):
            self.assertEqual(uninstall.runtime_remnants(), ['old-hub', 'old-metrics'])
        self.assertNotIn('DOCKER_HOST', docker.call_args.kwargs['env'])
        self.assertNotIn('DOCKER_CONTEXT', docker.call_args.kwargs['env'])
        self.assertIn('unix:///var/run/docker.sock', docker.call_args.args[0])

    def test_orphan_helpers_are_planned_and_removal_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as temp:
            paths = tuple(Path(temp) / name for name in ('sovagrid-vpn-ctl', 'sovagrid-vpn-broker'))
            for path in paths:
                path.write_text('reviewed')
            terminal = MagicMock()
            terminal.__enter__.return_value = terminal
            terminal.readline.side_effect = ['cancel\n', 'REMOVE SOVAGRID\n']
            with (patch.object(uninstall, 'runtime_remnants', return_value=[]),
                  patch.object(uninstall.hub.installed, 'source_manifest') as source,
                  patch.object(Path, 'read_bytes', return_value=b'{"sha256": {}}'),
                  patch.object(uninstall.hub.installed, 'installation_lock', side_effect=nullcontext),
                  patch.object(uninstall.hub, 'reviewed_vpn_programs', return_value=paths),
                  patch('builtins.open', return_value=terminal) as opened,
                  patch('builtins.print')):
                self.assertEqual(uninstall.cleanup_old_programs(plan=True), 0)
                opened.assert_not_called()
                self.assertEqual(uninstall.cleanup_old_programs(plan=False), 0)
                self.assertTrue(all(path.exists() for path in paths))
                self.assertEqual(uninstall.cleanup_old_programs(plan=False), 0)
                self.assertTrue(all(not path.exists() for path in paths))
        self.assertEqual(source.call_count, 3)
