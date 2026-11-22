# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Exercise ordinary run.sh's local uninstall layout selection."""
import json
import unittest
from unittest.mock import Mock, patch

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

    def test_unknown_layout_does_not_attempt_a_removal(self):
        with (patch.object(uninstall.os, 'geteuid', return_value=0),
              patch.object(uninstall.os.path, 'lexists', return_value=False),
              patch.object(uninstall, 'AgentRemoval') as remover,
              patch('builtins.print')):
            self.assertEqual(uninstall.main(['--plan']), 1)
        remover.assert_not_called()
