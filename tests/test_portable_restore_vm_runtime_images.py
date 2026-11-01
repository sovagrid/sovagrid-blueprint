# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Cleanup uses content-verified engine IDs, including manifest-based daemons."""
from contextlib import contextmanager
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests.test_portable_restore_vm_guard import vm


class RestoredImageCleanupTest(unittest.TestCase):
    def setUp(self):
        self.identity = "a" * 32
        self.config = "sha256:" + "b" * 64
        self.manifest = "sha256:" + "c" * 64
        self.receipt = {"host_archive_id": self.identity, "source_manifest_sha256": "d" * 64,
            "host_archive_sha256": "e" * 64, "images_sha256": "f" * 64,
            "exported_configs": {"hub": self.config}, "rootfs_sha256": {"hub": "1" * 64}}
        self.bindings = {key: self.receipt[key] for key in
                         ("source_manifest_sha256", "host_archive_sha256", "images_sha256")}
        self.step = {"kind": "compose", "state": "done", "proof": {"runtime_images": {"hub": self.manifest}}}
        self.value = {"id": self.identity, "phase": "committed", "bindings": self.bindings, "steps": [self.step]}
        self.plan = {"images": {"hub": {"config": self.config, "rootfs_sha256": "1" * 64,
            "platform": {"os": "linux", "architecture": "arm64"}, "runtime_ids": [self.config, self.manifest]}}}
        self.verify = Mock()
        self.resolved = Mock(return_value={"hub": self.manifest})
        self.driver = SimpleNamespace(compose=SimpleNamespace(verify=self.verify),
            images=SimpleNamespace(resolved=self.resolved))
        self.runtime = SimpleNamespace(load=Mock(return_value=self.plan), Runtime=Mock(return_value=self.driver))
        @contextmanager
        def locks(_restore):
            yield 123, None
        self.core = SimpleNamespace(transaction_locks=locks, Journal=Mock(return_value=SimpleNamespace(read=lambda: self.value)))
        self.restore = SimpleNamespace(backup=SimpleNamespace(ROOT_UID=0, ROOT_GID=0))

    def run_cleanup_ids(self, receipt=None):
        with patch.object(vm, "load", return_value=self.runtime):
            return vm.restored_runtime_images(Path("/verified"), self.restore, self.core,
                self.identity, receipt or self.receipt)

    def test_manifest_id_is_returned_only_after_actual_compose_and_content_verification(self):
        self.assertEqual(self.run_cleanup_ids(), {"hub": self.manifest})
        self.assertNotEqual(self.manifest, self.receipt["exported_configs"]["hub"])
        self.verify.assert_called_once_with(self.step, self.step["proof"])
        self.resolved.assert_called_once_with(self.plan["images"])
        self.runtime.load.assert_called_once_with(self.restore, self.core, 123, self.identity, self.bindings)

    def test_uncommitted_or_mismatched_receipt_is_refused_before_daemon_verification(self):
        self.value["phase"] = "recovery_required"
        with self.assertRaisesRegex(RuntimeError, "not committed"):
            self.run_cleanup_ids()
        self.value["phase"] = "committed"
        receipt = copy.deepcopy(self.receipt); receipt["source_manifest_sha256"] = "2" * 64
        with self.assertRaisesRegex(RuntimeError, "differs from committed inputs"):
            self.run_cleanup_ids(receipt)
        receipt = copy.deepcopy(self.receipt); receipt["exported_configs"]["hub"] = "sha256:" + "3" * 64
        with self.assertRaisesRegex(RuntimeError, "content differs from receipt"):
            self.run_cleanup_ids(receipt)
        self.verify.assert_not_called(); self.resolved.assert_not_called()

    def test_foreign_daemon_content_or_proof_id_mismatch_is_not_accepted_for_cleanup(self):
        self.verify.side_effect = RuntimeError("foreign Compose state")
        with self.assertRaisesRegex(RuntimeError, "foreign Compose state"):
            self.run_cleanup_ids()
        self.resolved.assert_not_called()
        self.verify.side_effect = None
        self.resolved.return_value = {"hub": "sha256:" + "4" * 64}
        with self.assertRaisesRegex(RuntimeError, "daemon image IDs differ"):
            self.run_cleanup_ids()


class OfflineSqlWitnessGuardTest(unittest.TestCase):
    def test_disposable_guard_precedes_any_directory_or_database_access(self):
        with patch.object(vm, "guard", side_effect=RuntimeError("disposable VM required")), patch.object(vm, "fixture_module") as fixture:
            with self.assertRaisesRegex(RuntimeError, "disposable VM required"):
                vm.hub_sql_read_offline(Path("/unused"), None, None, "a" * 32, "SELECT 1", [])
            fixture.assert_not_called()

    def test_only_exact_producer_queries_and_parameters_reach_source_verification(self):
        fixture = SimpleNamespace(ledger=lambda: {"sentinel": {"job": "known-job", "pending": "known-pending"}})
        with patch.object(vm, "guard"), patch.object(vm, "fixture_module", return_value=fixture), patch.object(vm, "verified_bundle") as verify:
            for query, parameters in (("DELETE FROM jobs", []),
                    ("SELECT state,command='',server_id FROM jobs WHERE id=?", ["another-job"]),
                    ("SELECT value FROM sovagrid_restore_ci_writeproof WHERE id=1;SELECT 2", [])):
                with self.subTest(query=query), self.assertRaisesRegex(RuntimeError, "invalid fixed offline"):
                    vm.hub_sql_read_offline(Path("/unused"), None, None, "a" * 32, query, parameters)
            verify.assert_not_called()

    def test_non_fenced_phase_refuses_before_loading_plan_or_opening_database(self):
        fixture = SimpleNamespace(ledger=lambda: {"sentinel": {"job": "known-job", "pending": "known-pending"}})
        @contextmanager
        def locks(_restore):
            yield 123, None
        core = SimpleNamespace(transaction_locks=locks,
            Journal=lambda *_args: SimpleNamespace(read=lambda: {"id": "a" * 32, "phase": "committed"}))
        with patch.object(vm, "guard"), patch.object(vm, "fixture_module", return_value=fixture), patch.object(vm, "verified_bundle"), patch.object(vm, "load") as load:
            with self.assertRaisesRegex(RuntimeError, "not fenced"):
                vm.hub_sql_read_offline(Path("/unused"), None, core, "a" * 32,
                    "SELECT value FROM sovagrid_restore_ci_writeproof WHERE id=1", [])
            load.assert_not_called()
