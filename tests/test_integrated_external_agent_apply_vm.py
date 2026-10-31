# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Local contract checks for the opt-in disposable Ubuntu VM fixture."""

from __future__ import annotations

from pathlib import Path
import re
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

if __package__:
    from . import integrated_external_agent_apply_vm as fixture
else:
    import integrated_external_agent_apply_vm as fixture


class FixtureContractTests(unittest.TestCase):
    def test_lease_answers_match_production_parser(self):
        import importlib.util

        path = Path(__file__).resolve().parents[1] / "deploy/external_agent_update.py"
        spec = importlib.util.spec_from_file_location("sovagrid_vm_contract_planner", path)
        assert spec and spec.loader
        planner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(planner)

        server = SimpleNamespace(
            lock=threading.Lock(), manifest_sha256="a" * 64,
            epoch="b" * 32, lease_token=None, lease_expires=0,
            max_until=0, counters={"lease_acquire": 0,
                                   "lease_renew": 0, "lease_release": 0,
                                   "lease_expires_at": 0}, save=lambda: None,
            base="/api/v1/servers/00000000-0000-4000-8000-000000000001")
        handler = fixture.FixtureHandler.__new__(fixture.FixtureHandler)
        handler.server = server
        replies = []
        handler.reply = lambda code, value: replies.append((code, value))
        handler.path = server.base + "/agent-maintenance/lease"
        handler.maintenance({"bundle_manifest_sha256": server.manifest_sha256})
        self.assertEqual(replies[-1][0], 201)
        acquired = planner._lease_reply(replies[-1][1], acquired=True)
        self.assertTrue(re.fullmatch(r"[A-Za-z0-9_-]{43}", acquired["lease_token"]))

        handler.maintenance({"bundle_manifest_sha256": server.manifest_sha256})
        self.assertEqual(replies[-1][0], 409)
        handler.path = server.base + "/agent-maintenance/lease/renew"
        handler.maintenance({"lease_token": acquired["lease_token"]})
        self.assertEqual(replies[-1][0], 200)
        planner._lease_reply(replies[-1][1], acquired=False,
                             epoch=acquired["hub_epoch"],
                             max_until=acquired["max_until"],
                             expires_at=acquired["expires_at"])
        handler.path = server.base + "/agent-maintenance/lease/release"
        handler.maintenance({"lease_token": acquired["lease_token"]})
        self.assertEqual(replies[-1], (200, {"released": True}))

    def test_fixture_refuses_non_disposable_host_before_any_action(self):
        with mock.patch.object(fixture.os, "geteuid", return_value=0), \
             mock.patch.dict(fixture.os.environ,
                             {"GITHUB_ACTIONS": "false",
                              "RUNNER_ENVIRONMENT": "github-hosted",
                              "SOVAGRID_EXTERNAL_APPLY_VM_FIXTURE": "1"}), \
             mock.patch.object(fixture, "seed") as seed, \
             self.assertRaisesRegex(SystemExit, "requires explicit opt-in"):
            fixture.main(["seed", "/some/source"])
        seed.assert_not_called()

    def test_workflow_keeps_trial_manual_and_default_off(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/hub-only-update-vm.yml").read_text()
        self.assertIn("external_agent_apply:\n", workflow)
        self.assertIn("default: false", workflow)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.external_agent_apply",
                      workflow)
        self.assertIn(f"OLD_AGENT_COMMIT: {fixture.BASELINE_AGENT_COMMIT}", workflow)
        self.assertIn('"$RUNNER_TEMP/sovagrid-old-agent-source"', workflow)
        for component, commit in fixture.EXPECTED_TRIAL_COMPONENTS.items():
            label = component.removeprefix("sovagrid-").upper() + "_COMMIT"
            with self.subTest(component=component):
                self.assertIn(f"{label}: {commit}", workflow)
        self.assertLess(workflow.index("Stage and preflight the exact candidate"),
                        workflow.index("Exercise external Agent apply and boot recovery"))


if __name__ == "__main__":
    unittest.main()
