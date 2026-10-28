# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""A recreated gateway may still be starting when Compose returns."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import types
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "deploy/remote_update_worker.py"
spec = importlib.util.spec_from_file_location("sovagrid_rollback_health_test", SOURCE)
assert spec and spec.loader
update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update)


class RollbackHealthWaitTests(unittest.TestCase):
    def test_starting_gateway_becomes_healthy_before_strict_postcheck(self) -> None:
        statuses = iter(("healthy", "starting", "healthy", "healthy"))
        calls = []

        def docker(args, **_kwargs):
            calls.append(args)
            if args[:2] == ["docker", "ps"]:
                return types.SimpleNamespace(stdout="abc123def456\n")
            self.assertEqual(args[:2], ["docker", "inspect"])
            return types.SimpleNamespace(stdout=next(statuses) + "\n")

        with mock.patch.object(update.subprocess, "run", side_effect=docker), \
             mock.patch.object(update.time, "sleep") as sleep:
            update.wait_recreated_container_health({"hub": "old-hub", "web": "old-web",
                                                    "ssh-gateway": "old-gateway"})
        sleep.assert_called_once()
        self.assertEqual(len(calls), 8)

    def test_starting_gateway_has_a_bounded_timeout(self) -> None:
        def docker(args, **_kwargs):
            return types.SimpleNamespace(stdout=("abc123def456\n" if args[:2] == ["docker", "ps"]
                                                 else "starting\n"))

        with mock.patch.object(update.subprocess, "run", side_effect=docker), \
             mock.patch.object(update.time, "monotonic", side_effect=(0, 41)), \
             mock.patch.object(update.time, "sleep") as sleep, \
             self.assertRaisesRegex(update.UpdateFailure, "health timeout: ssh-gateway"):
            update.wait_recreated_container_health({"ssh-gateway": "old-gateway"}, timeout=40)
        sleep.assert_not_called()

    def test_missing_recreated_hub_is_not_accepted_as_starting(self) -> None:
        with mock.patch.object(update.subprocess, "run",
                               return_value=types.SimpleNamespace(stdout="")), \
             mock.patch.object(update.time, "sleep") as sleep, \
             self.assertRaisesRegex(update.UpdateFailure, "missing recreated container: hub"):
            update.wait_recreated_container_health({"hub": "old-hub"})
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
