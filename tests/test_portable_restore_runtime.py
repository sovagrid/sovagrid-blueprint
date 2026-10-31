# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Resource-plan persistence, phase ordering, and the closed public apply gate."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
import unittest
from unittest.mock import patch

from deploy import host_restore as restore
from deploy import portable_restore_apply as core
from deploy import portable_restore_runtime as runtime
from tests import test_portable_restore_resource_plan as fixtures


class RuntimePlanTest(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ResourcePlanTest(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.inputs = self.fixture.inputs()
        self.plan = core.build_resource_plan(self.inputs)
        self.stage = self.fixture.staged.parent
        self.stage.chmod(0o700)
        self.fd = os.open(self.stage, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        if not sys.platform.startswith("linux"):
            patcher = patch.object(core, "_rename_noreplace", self.rename)
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def rename(fd, source, target):
        try:
            os.stat(target, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            os.rename(source, target, src_dir_fd=fd, dst_dir_fd=fd)
        else:
            raise core.Refused("RESTORE_TARGET_EXISTS")

    def test_private_plan_and_label_override_are_hash_bound_and_idempotent(self):
        runtime.persist(restore, core, self.fd, self.plan)
        runtime.persist(restore, core, self.fd, self.plan)
        loaded = runtime.load(restore, core, self.fd, self.plan["id"], self.plan["bindings"])
        self.assertEqual(loaded, self.plan)
        plan_file = self.stage / (".apply-plan-" + self.plan["id"] + ".json")
        self.assertEqual(stat.S_IMODE(plan_file.stat().st_mode), 0o600)
        self.assertNotIn(b"test-only-token", plan_file.read_bytes())
        override = json.loads((self.stage / (".apply-compose-" + self.plan["id"] + ".json")).read_bytes())
        self.assertEqual(override["services"]["hub"]["labels"]["org.sovagrid.restore"], self.plan["id"])
        self.assertEqual(override["networks"]["private"]["labels"]["org.sovagrid.restore-review"],
                         self.plan["bindings"]["apply_review_sha256"])

    def test_corrupted_plan_is_rejected_before_runtime_adapter_is_constructed(self):
        runtime.persist(restore, core, self.fd, self.plan)
        target = self.stage / (".apply-plan-" + self.plan["id"] + ".json")
        changed = json.loads(target.read_bytes())
        changed["resources"][0]["entries"][""]["uid"] = 123
        target.write_text(json.dumps(changed))
        with self.assertRaisesRegex(core.Refused, "RESTORE_PLAN_CHANGED"):
            runtime.load(restore, core, self.fd, self.plan["id"], self.plan["bindings"])

    def test_runtime_step_order_prepares_parents_sockets_and_consumers_before_timers(self):
        journal = core.Journal(self.fd, self.plan["id"], uid=os.getuid(), gid=os.getgid())
        driver = runtime.Runtime(restore, core, self.plan, journal, inputs=self.inputs)
        steps = driver.steps()
        compose_index = next(index for index, step in enumerate(steps) if step["kind"] == "compose")
        socket_index = next(index for index, step in enumerate(steps) if step["kind"] == "service" and step["resource"].endswith(".socket"))
        agent_index = next(index for index, step in enumerate(steps) if step["kind"] == "service" and step["resource"] == "sovagrid-agent.service")
        timer_index = next(index for index, step in enumerate(steps) if step["kind"] == "service" and step["resource"].endswith(".timer"))
        self.assertLess(socket_index, compose_index)
        self.assertLess(compose_index, agent_index)
        self.assertLess(agent_index, timer_index)
        reload_index = next(index for index, step in enumerate(steps) if step["kind"] == "reload")
        self.assertTrue(all(index < reload_index for index, step in enumerate(steps) if step["kind"] == "publish"))
        self.assertLess(len(steps), core.MAX_STEPS)
        published = [step["resource"] for step in steps if step["kind"] == "publish"]
        self.assertLess(published.index("/run/sovagrid-web-agent"), published.index("/etc/sovagrid"))

    def test_public_apply_gate_cannot_be_bypassed_by_the_cli(self):
        runtime.persist(restore, core, self.fd, self.plan)
        # A public command must not enable an unvalidated VM adapter just
        # because the source version was changed to 1.0.0.
        with (patch.object(restore, "_require_root"),
              patch.object(restore, "_sibling", return_value=core),
              patch.object(core, "APPLY_ENABLED", False),
              patch("sys.stdout", new_callable=io.StringIO) as output):
            self.assertEqual(restore.main(["portable-apply", self.plan["id"], "a" * 64]), 40)
        self.assertEqual(json.loads(output.getvalue())["error"], "APPLY_NOT_IMPLEMENTED")
        self.assertFalse((self.fixture.root / "etc/sovagrid").exists())

    def test_health_checks_static_roots_without_rejecting_normal_database_writes(self):
        journal = core.Journal(self.fd, self.plan["id"], uid=os.getuid(), gid=os.getgid())
        driver = runtime.Runtime(restore, core, self.plan, journal, inputs=self.inputs)
        value = {"steps": [
            {"kind": "compose", "state": "done", "proof": {}},
            {"kind": "queue", "state": "done", "proof": {}},
            {"kind": "publish", "resource": "/var/lib/sovagrid", "proof": {}},
            {"kind": "publish", "resource": "/etc/sovagrid", "proof": {}}]}
        with (patch.object(self.inputs, "unchanged") as unchanged,
              patch.object(driver.compose, "health"),
              patch.object(driver, "_socket_health"),
              patch.object(driver.publisher, "verify") as verify):
            driver.health(value)
        unchanged.assert_called_once_with(hash_contents=True)
        self.assertEqual([call.args[0]["resource"] for call in verify.call_args_list], ["/etc/sovagrid"])

    def test_queue_quarantine_is_journaled_before_any_possible_activation(self):
        journal = core.Journal(self.fd, self.plan["id"], uid=os.getuid(), gid=os.getgid())
        driver = runtime.Runtime(restore, core, self.plan, journal, inputs=self.inputs)
        steps = driver.steps()
        queue = next(index for index, step in enumerate(steps) if step["kind"] == "queue")
        self.assertTrue(all(index < queue for index, step in enumerate(steps) if step["kind"] == "publish"))
        self.assertTrue(all(index > queue for index, step in enumerate(steps)
                            if step["kind"] in ("reload", "enablement", "service", "compose")))
        self.assertEqual(steps[queue]["resource"], "/var/lib/sovagrid/hub/hub.sqlite")

    def test_health_cannot_commit_an_unquarantined_queue(self):
        journal = core.Journal(self.fd, self.plan["id"], uid=os.getuid(), gid=os.getgid())
        driver = runtime.Runtime(restore, core, self.plan, journal, inputs=self.inputs)
        with (patch.object(self.inputs, "unchanged"), patch.object(driver.compose, "health") as health):
            with self.assertRaisesRegex(core.Refused, "RESTORE_QUEUE_NOT_QUARANTINED"):
                driver.health({"steps": [{"kind": "compose", "state": "done", "proof": {}}]})
            health.assert_not_called()


if __name__ == "__main__":
    unittest.main()
