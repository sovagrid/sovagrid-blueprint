# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
from contextlib import nullcontext
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vendor/connect'))
sys.path.insert(0, str(ROOT / 'deploy'))
import web_agent_features as module
import host_backup
from sovagrid_connect.agent_rpc import Stage
from sovagrid_connect.core import ConnectionOptions

SERVER = '11111111-1111-4111-8111-111111111111'
ENROLL = '22222222-2222-4222-8222-222222222222'
CURRENT = {'commands': False, 'terminal': False, 'files': False}
DESIRED = {'commands': True, 'terminal': True, 'files': True}
IDENTITY = {'request_id': '33333333-3333-4333-8333-333333333333',
            'server_id': SERVER, 'enrollment_id': ENROLL, 'agent_token_sha256': 'c' * 64}


class RPC:
    def __init__(self):
        self._owner, self._stages, self.applies = object(), {}, 0
        self.current = dict(CURRENT)
        self.fail_apply = False

    def stage_target(self, _bundle, _sha, *, checkpoint):
        stage = Stage('/var/tmp/sovagrid-agent-enroll.' + 'a' * 32,
            'a' * 64, 'b' * 64, 'd' * 64, 'a' * 32, self._owner)
        self._stages[stage.stage_id] = stage
        checkpoint(stage.descriptor())
        return stage

    def cleanup_stage(self, _stage):
        pass

    def call(self, action, payload, *, stage):
        operation = action.removeprefix('target-features-')
        if operation == 'apply':
            if self.fail_apply:
                raise module.RPCError('SSH_FAILED')
            self.applies += 1
            self.current = dict(payload['features'])
        result = {'protocol': 1, 'identity': dict(IDENTITY),
            'source_manifest_sha256': stage.source_manifest_sha256,
            'current': dict(self.current), 'pending_features': None, 'recovery_required': False,
            'services': {'agent': True, 'tunnel': True},
            'expected': {key: ('e' if self.current['commands'] else 'f') * 64
                for key in ('source_manifest_sha256', 'features_sha256', 'policy_sha256', 'state_sha256')}}
        if operation in ('preview', 'apply'):
            result.update(desired=dict(payload['features']), changed=result['current'] != payload['features'])
        if operation == 'apply': result['applied'] = True
        return result


class API:
    def __init__(self, events):
        self.events = events
        self.policy = {key: IDENTITY[key] for key in ('server_id', 'enrollment_id', 'agent_token_sha256')}
        self.policy.update(enabled=False, revision=0)
        self.seen = 1

    def adopt_bearer(self, _token): pass
    def verify(self): pass
    def logout(self): pass

    def management(self, _server):
        return dict(self.policy)

    def set_management(self, expected, enabled):
        if expected != self.policy:
            raise module.EnrollmentAPIError('changed', 409)
        self.events.append(('gate', enabled))
        self.policy.update(enabled=enabled, revision=self.policy['revision'] + int(enabled != self.policy['enabled']))
        return dict(self.policy)

    def get(self, _enrollment):
        self.seen += 1
        return {'id': ENROLL, 'server_id': SERVER, 'name': 'QA target', 'state': 'active', 'last_seen': self.seen}


class FeatureWebTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.rpc, self.events = RPC(), []
        self.api = API(self.events)
        jobs = SimpleNamespace(_bundle_path=self.root / ('source-' + 'a' * 64 + '.tar.gz'),
            _bundle_sha256='a' * 64, _exclusive=nullcontext, _bundle=lambda: self.root / 'bundle.tar.gz')
        outer = self

        class Transport:
            def __init__(self, **kwargs):
                self.options = ConnectionOptions(host=kwargs['host'], user=kwargs['username'], port=kwargs['port'])
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def target_rpc(self, _options): return outer.rpc

        self.jobs = module.AgentFeatureJobs(jobs, transport_factory=Transport, api_factory=lambda _: self.api)
        self.arguments = {'server_id': SERVER, 'options': ConnectionOptions(host='qa.example', user='root'),
            'fingerprint': 'SHA256:' + 'A' * 43,
            'credential': SimpleNamespace(method='password', password='never-persist-me', private_key='', passphrase=''),
            'session_token': 't' * 43}

    def plan(self):
        return self.jobs.execute('preview', features=DESIRED, **self.arguments)

    def test_current_read_is_not_a_mutation_plan_and_writes_no_credentials(self):
        result = self.jobs.execute('preview', features=None, **self.arguments)
        self.assertEqual(result['current'], CURRENT)
        self.assertIsNone(result['review_sha256'])
        self.assertFalse(result['can_apply'])
        self.assertFalse(result['activation_writes'])
        self.assertEqual(self.events, [])
        self.assertEqual(self.rpc.applies, 0)
        self.assertFalse((self.root / 'agent-features-stage.json').exists())

    def test_wrong_review_and_wrong_agent_identity_never_change_the_gate(self):
        plan = self.plan()
        with self.assertRaises(module.AgentFeatureError) as error:
            self.jobs.execute('apply', features=DESIRED, expected_review_sha256='0' * 64,
                confirm=True, **self.arguments)
        self.assertEqual(error.exception.code, 'STALE_PREVIEW')
        self.assertEqual(self.events, [])
        self.api.policy['agent_token_sha256'] = '0' * 64
        with self.assertRaises(module.AgentFeatureError) as error:
            self.jobs.execute('apply', features=DESIRED, expected_review_sha256=plan['review_sha256'],
                confirm=True, **self.arguments)
        self.assertEqual(error.exception.code, 'AGENT_NOT_ENROLLED')
        self.assertEqual(self.events, [])

    def test_apply_rechecks_plan_closes_gate_and_confirms_a_new_metric(self):
        plan = self.plan()
        result = self.jobs.execute('apply', features=DESIRED, expected_review_sha256=plan['review_sha256'],
            confirm=True, **self.arguments)
        self.assertEqual(self.events, [('gate', False), ('gate', True)])
        self.assertEqual(self.rpc.applies, 1)
        self.assertEqual(result['current'], DESIRED)
        self.assertTrue(result['fresh_metric_verified'])
        self.assertTrue(result['hub_enabled'])
        self.assertFalse((self.root / 'agent-features-stage.json').exists())

    def test_revocation_after_closing_gate_blocks_target_apply(self):
        plan = self.plan()
        def authorize():
            if self.events:
                raise module.AgentFeatureError('ADMIN_FORBIDDEN')
        with self.assertRaises(module.AgentFeatureError) as error:
            self.jobs.execute('apply', features=DESIRED, expected_review_sha256=plan['review_sha256'],
                confirm=True, authorize=authorize, **self.arguments)
        self.assertEqual(error.exception.code, 'ADMIN_FORBIDDEN')
        self.assertEqual(self.events, [('gate', False)])
        self.assertEqual(self.rpc.applies, 0)
        self.assertFalse(self.api.policy['enabled'])

    def test_uncertain_target_apply_keeps_the_gate_closed(self):
        plan = self.plan()
        self.rpc.fail_apply = True
        with self.assertRaises(module.AgentFeatureError) as error:
            self.jobs.execute('apply', features=DESIRED, expected_review_sha256=plan['review_sha256'],
                confirm=True, **self.arguments)
        self.assertEqual(error.exception.code, 'APPLY_UNCERTAIN')
        self.assertEqual(self.events, [('gate', False)])
        self.assertFalse(self.api.policy['enabled'])

    def test_revocation_after_target_change_never_reopens_the_gate(self):
        plan = self.plan()
        checks = 0
        def authorize():
            nonlocal checks
            checks += 1
            if checks == 3:
                raise module.AgentFeatureError('ADMIN_FORBIDDEN')
        with self.assertRaises(module.AgentFeatureError):
            self.jobs.execute('apply', features=DESIRED, expected_review_sha256=plan['review_sha256'],
                confirm=True, authorize=authorize, **self.arguments)
        self.assertEqual(self.rpc.applies, 1)
        self.assertEqual(self.events, [('gate', False)])

    def test_backup_inventory_accepts_only_the_bounded_private_stage_record(self):
        path = host_backup.WEB_AGENT_DIR + '/agent-features-stage.json'
        source = host_backup._web_agent_source(path)
        self.assertTrue(source.private)
        self.assertEqual(source.exact_mode, 0o600)
        self.assertEqual(host_backup._web_agent_limit(path), 4096)
        with self.assertRaises(host_backup.Refused):
            host_backup._web_agent_source(host_backup.WEB_AGENT_DIR + '/agent-features-password.json')

    def test_generic_commands_require_an_explicit_valid_feature_plan(self):
        for features in ({'commands': False, 'terminal': True, 'files': False},
                         {'commands': 1, 'terminal': False, 'files': False}, {'commands': True}):
            with self.assertRaises(module.AgentFeatureError):
                self.jobs.execute('preview', features=features, **self.arguments)
        self.assertEqual(self.events, [])
