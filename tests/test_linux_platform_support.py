# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Linux capability admission, package-manager independence and fixed SSH units."""
import contextlib
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

DEPLOY = Path(__file__).resolve().parents[1] / 'deploy'


def load(name):
    spec = importlib.util.spec_from_file_location('platform_test_' + name, DEPLOY / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def runtime_command(argv, **kwargs):
    if argv[0] == '/usr/bin/python3': return SimpleNamespace(returncode=0, stdout=b'')
    if 'is-system-running' in argv: return SimpleNamespace(returncode=1, stdout=b'degraded\n')
    return SimpleNamespace(returncode=0, stdout=b'257.7-1\n')


class LinuxPlatformTests(unittest.TestCase):
    def test_enrollment_accepts_capable_distributions_without_release_allowlist(self):
        helper = load('remote_agent')
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(helper.sys, 'platform', 'linux'):
            root = Path(directory)
            release = root / 'usr/lib/os-release'
            release.parent.mkdir(parents=True)
            (root / 'run/systemd/system').mkdir(parents=True)
            (root / 'proc/self').mkdir(parents=True)
            def command(argv, **kwargs):
                result = runtime_command(argv)
                return result.returncode, result.stdout
            commands = SimpleNamespace(run=mock.Mock(side_effect=command))
            enrollment = helper.Enrollment(root=root, owner=os.getuid(), commands=commands)
            for distribution, version in (('ubuntu', '20.04'), ('ubuntu', '99.04'), ('debian', '13'),
                                          ('fedora', '44'), ('opensuse-tumbleweed', '20261101'), ('custom', 'v1')):
                release.write_text(f'ID={distribution}\nVERSION_ID="{version}"\n')
                record = enrollment.platform()
                self.assertEqual(set(record), {'python_version', 'systemd_version'} |
                                 ({'ubuntu_version'} if distribution == 'ubuntu' else {'distribution', 'version'}))
                self.assertEqual(record.get('ubuntu_version', record.get('version')), version)
            release.write_text('ID=arch\n')
            self.assertEqual(enrollment.platform()['version'], 'rolling')
            release.unlink()
            self.assertEqual(enrollment.platform()['distribution'], 'linux')
            self.assertEqual(enrollment.platform()['version'], 'unknown')
            (root / 'proc/self').rmdir()
            with self.assertRaises(helper.Refuse) as caught: enrollment.platform()
            self.assertEqual(caught.exception.code, 'UNSUPPORTED_PLATFORM')

    def test_update_and_promotion_runtime_checks_use_actual_capabilities(self):
        for name in ('remote_update_worker', 'promote_agent_only', 'hub_only_update'):
            module = load(name)
            with mock.patch.object(module.sys, 'platform', 'linux'), mock.patch.object(Path, 'is_dir', return_value=True), \
                    mock.patch.object(module.subprocess, 'run', side_effect=runtime_command), \
                    mock.patch.object(Path, 'read_text', side_effect=AssertionError('OS metadata is not admission')):
                self.assertTrue(module.runtime_supported(), name)
                with mock.patch.object(module.sys, 'version_info', (3, 9)):
                    self.assertFalse(module.runtime_supported(), name)
                with mock.patch.object(module.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'offline\n')):
                    self.assertFalse(module.runtime_supported(), name)
                with mock.patch.object(module.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout=b'')):
                    self.assertFalse(module.runtime_supported(), name)
            with mock.patch.object(module.sys, 'platform', 'darwin'):
                self.assertFalse(module.runtime_supported(), name)

    def test_preinstalled_dependencies_never_require_apt(self):
        helper = load('remote_agent')
        with tempfile.TemporaryDirectory() as directory:
            commands = SimpleNamespace(run=mock.Mock())
            enrollment = helper.Enrollment(root=Path(directory), owner=os.getuid(), commands=commands)
            with mock.patch.object(enrollment, 'dependencies_present', return_value=True): enrollment.prerequisites()
            commands.run.assert_not_called()
            with mock.patch.object(enrollment, 'dependencies_present', return_value=False):
                with self.assertRaises(helper.Refuse) as caught: enrollment.prerequisites()
            self.assertEqual(caught.exception.code, 'UNSUPPORTED_DEPENDENCIES')
            commands.run.assert_not_called()
            for tool in ('apt-get', 'dpkg-query'):
                path = Path(directory) / 'usr/bin' / tool
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture')
                path.chmod(0o755)
            with mock.patch.object(enrollment, 'dependencies_present', side_effect=[False, True]): enrollment.prerequisites()
            self.assertEqual(len(commands.run.call_args_list), 2)
            self.assertTrue(all(call.args[0][0] == '/usr/bin/apt-get' for call in commands.run.call_args_list))

    def test_loaded_sshd_fallback_is_selected_and_used_for_reload(self):
        helper = load('remote_agent')
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            def command(argv, **kwargs):
                calls.append(argv)
                if '--property=LoadState' in argv:
                    return (0, b'loaded\n') if argv[-1] == 'sshd.service' else (0, b'not-found\n')
                return 0, b''
            enrollment = helper.Enrollment(root=Path(directory), owner=os.getuid(), commands=SimpleNamespace(run=command))
            self.assertEqual(enrollment.ssh_service(), 'sshd.service')
            enrollment.files.mkdir('/etc/ssh/sshd_config.d', 0o755)
            eid, sid = str(uuid.uuid4()), str(uuid.uuid4())
            entry = dict(enrollment_id=eid, server_id=sid, username=helper.username(sid), ssh_public_key='fixture',
                         ssh_key_fingerprint='fixture', revoked=False)
            state = {'enrollments': {eid: entry}}
            request = {**entry, 'expected': {}}
            with mock.patch.object(enrollment, 'locked', return_value=contextlib.nullcontext()), \
                    mock.patch.object(enrollment, 'check_cas'), mock.patch.object(enrollment, 'hub_state', return_value=state), \
                    mock.patch.object(enrollment, 'effective', return_value={}), mock.patch.object(enrollment, 'hub_group'), \
                    mock.patch.object(enrollment, 'account'), mock.patch.object(enrollment, 'owned_directory'), \
                    mock.patch.object(enrollment, 'owned_write'), mock.patch.object(enrollment, 'enforce_tunnel_policy'), \
                    mock.patch.object(enrollment, 'cas', return_value={}):
                self.assertTrue(enrollment.hub_authorize(request)['authorized'])
            self.assertIn(['/usr/bin/systemctl', 'reload', 'sshd.service'], calls)
            self.assertNotIn(['/usr/bin/systemctl', 'reload', 'ssh.service'], calls)
            self.assertTrue(all(call[-1] in ('ssh.service', 'sshd.service') for call in calls if '--property=LoadState' in call))

    def test_no_loaded_ssh_unit_refuses_before_hub_transport_mutation(self):
        helper = load('remote_agent')
        with tempfile.TemporaryDirectory() as directory:
            enrollment = helper.Enrollment(root=Path(directory), owner=os.getuid(),
                commands=SimpleNamespace(run=mock.Mock(return_value=(0, b'not-found\n'))))
            eid, sid = str(uuid.uuid4()), str(uuid.uuid4())
            entry = dict(enrollment_id=eid, server_id=sid, username=helper.username(sid), ssh_public_key='fixture',
                         ssh_key_fingerprint='fixture', revoked=False)
            with mock.patch.object(enrollment, 'locked', return_value=contextlib.nullcontext()), \
                    mock.patch.object(enrollment, 'check_cas'), \
                    mock.patch.object(enrollment, 'hub_state', return_value={'enrollments': {eid: entry}}), \
                    mock.patch.object(enrollment, 'account') as account, mock.patch.object(enrollment, 'owned_write') as write:
                with self.assertRaises(helper.Refuse) as caught: enrollment.hub_authorize({**entry, 'expected': {}})
            self.assertEqual(caught.exception.code, 'SSH_RELOAD_FAILED')
            account.assert_not_called()
            write.assert_not_called()


if __name__ == '__main__': unittest.main()
