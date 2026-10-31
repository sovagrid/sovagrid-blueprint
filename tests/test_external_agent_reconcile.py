# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""An uncertain external Agent operation needs proof, never a replay."""

from __future__ import annotations

import contextlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "deploy/external_agent_update.py"
spec = importlib.util.spec_from_file_location("sovagrid_external_reconcile_test", SCRIPT)
assert spec and spec.loader
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)

REQUEST_ID = "9c941101-2acb-4e59-877c-136d3f43f1d8"
OTHER_ID = "f3a1a600-fca8-491c-a978-51d5628726fa"
NEW = "a" * 64
OLD = "b" * 64
BASELINE = "c" * 64


class ReconcileTests(unittest.TestCase):
    def test_worker_must_be_inactive_without_a_queued_job(self):
        fields = {"Id": "sovagrid-external-agent-apply@" + REQUEST_ID + ".service",
                  "ActiveState": "inactive", "MainPID": "0", "Job": "0",
                  "ControlGroup": "", "FragmentPath": updater.update.EXTERNAL_APPLY_UNIT,
                  "NeedDaemonReload": "no"}

        def run(*_args, **_kwargs):
            raw = "\n".join(key + "=" + value for key, value in fields.items()) + "\n"
            return subprocess.CompletedProcess([], 0, raw.encode(), b"")

        with mock.patch.object(updater.subprocess, "run", side_effect=run), \
             mock.patch.object(updater.promotion, "_read_regular", return_value=b"unit"):
            updater._operation_unit_quiescent(REQUEST_ID)
            fields["ControlGroup"] = (
                "/system.slice/sovagrid-external-agent-apply@" + REQUEST_ID + ".service")
            with mock.patch.object(updater, "_cgroup_empty", return_value=True):
                updater._operation_unit_quiescent(REQUEST_ID)
            with mock.patch.object(updater, "_cgroup_empty", return_value=False), \
                 self.assertRaisesRegex(updater.Refused, "OPERATION_WORKER_BUSY"):
                updater._operation_unit_quiescent(REQUEST_ID)
            fields["ControlGroup"] = ""
            for key, value in (("ActiveState", "activating"),
                               ("MainPID", "17"), ("Job", "31"),
                               ("NeedDaemonReload", "yes")):
                original = fields[key]
                fields[key] = value
                with self.subTest(key=key), self.assertRaisesRegex(
                        updater.Refused, "OPERATION_WORKER_BUSY"):
                    updater._operation_unit_quiescent(REQUEST_ID)
                fields[key] = original

    def test_later_completed_operation_makes_source_ambiguous(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for identifier in (REQUEST_ID, OTHER_ID):
                (root / identifier).mkdir()
            request = {"current_hub_manifest_sha256": NEW,
                       "external_agent_manifest_sha256": OLD}
            uncertain = {"phase": "uncertain", "created_at": 100,
                         "updated_at": 110}
            earlier = {"phase": "complete", "created_at": 50,
                       "updated_at": 80}
            status = {REQUEST_ID: uncertain, OTHER_ID: earlier}
            with mock.patch.object(updater.operation, "OPERATIONS", root), \
                 mock.patch.object(updater.operation, "_record_dir",
                                   side_effect=lambda name: root / name), \
                 mock.patch.object(updater.operation, "_request",
                                   return_value=request), \
                 mock.patch.object(updater.operation, "_status",
                                   side_effect=lambda _path, name: status[name]):
                self.assertEqual(updater._only_uncertain_operation(REQUEST_ID), request)
                earlier["updated_at"] = 100
                with self.assertRaisesRegex(updater.Refused, "OPERATION_AMBIGUOUS"):
                    updater._only_uncertain_operation(REQUEST_ID)
                earlier["updated_at"] = 80
                earlier["phase"] = "uncertain"
                with self.assertRaisesRegex(updater.Refused, "OPERATION_AMBIGUOUS"):
                    updater._only_uncertain_operation(REQUEST_ID)

    def _reconcile(self, external: str, *, journal=None,
                   worker_busy: bool = False):
        request = {"current_hub_manifest_sha256": NEW,
                   "external_agent_manifest_sha256": OLD}
        promoted = {"phase": "activated", "external_agent_preserved": True,
                    "baseline_sha256": BASELINE}
        enrollment = mock.Mock()
        enrollment.locked.return_value = contextlib.nullcontext()
        enrollment.files.inspect.return_value = None
        transaction = mock.Mock()
        transaction._load_journal.return_value = journal
        transaction._load_committed_marker.return_value = None
        transitions = []
        worker = (updater.Refused("OPERATION_WORKER_BUSY") if worker_busy else None)
        with mock.patch.object(updater.os, "geteuid", return_value=0), \
             mock.patch.object(updater.os, "getegid", return_value=0), \
             mock.patch.object(updater.sys, "platform", "linux"), \
             mock.patch.object(updater, "_exclusive_lock", return_value=99), \
             mock.patch.object(updater.os, "close"), \
             mock.patch.object(updater.remote, "Enrollment", return_value=enrollment), \
             mock.patch.object(updater.recovery, "Recovery", return_value=transaction), \
             mock.patch.object(updater, "_only_uncertain_operation", return_value=request), \
             mock.patch.object(updater, "_operation_unit_quiescent", side_effect=worker), \
             mock.patch.object(updater.update, "inspect",
                               return_value=(NEW, promoted, {}, BASELINE)) as inspect, \
             mock.patch.object(updater, "_external_snapshot_locked",
                               return_value=(external, {}, {})), \
             mock.patch.object(updater, "_external_unit_properties", return_value={
                 "ActiveState": "active", "SubState": "running", "MainPID": "123"}), \
             mock.patch.object(updater, "_proc_start_ticks", return_value=456), \
             mock.patch.object(updater.promotion, "capture_external",
                               return_value={"verified": True}), \
             mock.patch.object(updater.promotion, "_private_json",
                               return_value={"verified": True}), \
             mock.patch.object(updater.os.path, "lexists", return_value=False), \
             mock.patch.object(updater.operation, "_record_dir",
                               return_value=Path("/unused")), \
             mock.patch.object(updater.operation, "_transition",
                               side_effect=lambda *args: transitions.append(args)):
            if journal is not None:
                with self.assertRaisesRegex(updater.Refused,
                                            "OPERATION_RECOVERY_PENDING"):
                    updater.reconcile(REQUEST_ID)
            elif worker_busy:
                with self.assertRaisesRegex(updater.Refused,
                                            "OPERATION_WORKER_BUSY"):
                    updater.reconcile(REQUEST_ID)
            elif external not in (NEW, OLD):
                with self.assertRaisesRegex(updater.Refused,
                                            "OPERATION_SOURCE_CHANGED"):
                    updater.reconcile(REQUEST_ID)
            else:
                result = updater.reconcile(REQUEST_ID)
                self.assertEqual(result["phase"],
                                 "complete" if external == NEW else "failed")
                self.assertEqual(inspect.call_args.kwargs,
                                 {"read_only_uncertain": True})
            return transitions

    def test_proven_new_source_closes_complete(self):
        transitions = self._reconcile(NEW)
        self.assertEqual(transitions[0][3:], ("complete", None))

    def test_proven_old_source_closes_failed(self):
        transitions = self._reconcile(OLD)
        self.assertEqual(transitions[0][3:], ("failed", "RECONCILED_ROLLBACK"))

    def test_journal_worker_or_unknown_source_never_transitions(self):
        self.assertEqual(self._reconcile(NEW, journal={"phase": "committed"}), [])
        self.assertEqual(self._reconcile(NEW, worker_busy=True), [])
        self.assertEqual(self._reconcile("d" * 64), [])


if __name__ == "__main__":
    unittest.main()
