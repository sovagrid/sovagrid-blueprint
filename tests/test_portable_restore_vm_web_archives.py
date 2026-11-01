# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Only a proven completed enrollment runner may disappear after restore."""

import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid


spec = importlib.util.spec_from_file_location("portable_restore_web_archives_vm",
    Path(__file__).with_name("portable_restore_apply_vm.py"))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
fixture = vm.fixture_module()


class WebArchiveProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "web-agent/jobs").mkdir(parents=True)
        self.old, self.old_manifest = self.archive(b"old producer")
        self.request = str(uuid.uuid4())
        self.journal = "web-agent/jobs/" + self.request + ".json"
        self.job = {"request_id": self.request, "phase": "active", "cleanup_required": False,
                    "bundle": {"path": "/var/lib/sovagrid/" + self.old, "sha256": Path(self.old).name[7:-7]}}
        self.write_job()
        self.before = self.inventory()
        self.current, self.target = self.archive(b"new producer")
        self.actual = self.inventory()
        self.value = {"initial_manifest_sha256": self.old_manifest, "manifest_sha256": self.target,
                      "trees": {"/var/lib/sovagrid": copy.deepcopy(self.actual)}}
        self.real_fstat = os.fstat

    def archive(self, content):
        names = {component + "/fixture": hashlib.sha256(content).hexdigest() for component in fixture.COMPONENTS}
        manifest = json.dumps({"format": 1, "components": sorted(fixture.COMPONENTS), "sha256": names}).encode()
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            for name, raw in [("sovagrid-bundle.json", manifest)] + [(name, content) for name in names]:
                item = tarfile.TarInfo(name)
                item.size = len(raw)
                archive.addfile(item, io.BytesIO(raw))
        raw = data.getvalue()
        name = "web-agent/source-" + hashlib.sha256(raw).hexdigest() + ".tar.gz"
        (self.root / name).write_bytes(raw)
        (self.root / name).chmod(0o600)
        return name, hashlib.sha256(manifest).hexdigest()

    def write_job(self):
        (self.root / self.journal).write_text(json.dumps(self.job))
        (self.root / self.journal).chmod(0o600)

    def inventory(self):
        records = fixture.inventory(self.root)
        for record in records.values():
            record.update(uid=0, gid=0)
        return records

    def root_fstat(self, fd):
        info = self.real_fstat(fd)
        fields = {key: getattr(info, key) for key in dir(info) if key.startswith("st_")}
        return SimpleNamespace(**dict(fields, st_uid=0, st_gid=0))

    def seal(self):
        with patch.object(vm.os, "fstat", side_effect=self.root_fstat):
            proof = vm.seal_web_bundle_retirements(fixture, self.before, self.actual,
                self.old_manifest, self.target, root=self.root)
        self.value["web_bundle_retirements"] = proof
        return proof

    def entries(self):
        return {name: {key: value for key, value in record.items() if key not in ("dev", "ino")}
                for name, record in self.value["trees"]["/var/lib/sovagrid"].items()}

    def retired(self, actual=None, entries=None):
        actual = self.inventory() if actual is None else actual
        with patch.object(vm.os, "fstat", side_effect=self.root_fstat), \
                patch.object(vm, "expected_manifest", return_value=self.target):
            return vm.retired_web_bundles(fixture, self.value, self.entries() if entries is None else entries,
                actual, root=self.root)

    def test_completed_old_runner_has_exact_producer_proof_and_only_its_absence_is_optional(self):
        proof = self.seal()
        self.assertEqual(proof["archives"], {self.old: [self.journal]})
        self.assertEqual(proof["current"], self.current)
        self.assertEqual(self.retired(), set())
        (self.root / self.old).unlink()
        self.assertEqual(self.retired(), {self.old})

    def test_no_seal_cannot_authorize_any_missing_source_archive(self):
        (self.root / self.old).unlink()
        self.assertEqual(self.retired(), set())

    def test_pending_enrollment_or_cleanup_does_not_produce_retirement_permission(self):
        for phase, cleanup in (("prepared", False), ("active", True)):
            with self.subTest(phase=phase, cleanup=cleanup):
                self.job.update(phase=phase, cleanup_required=cleanup)
                self.write_job()
                self.before[self.journal] = self.inventory()[self.journal]
                self.actual[self.journal] = self.before[self.journal]
                self.assertEqual(self.seal()["archives"], {})

    def test_any_changed_producer_journal_refuses_transition_retirement_seal(self):
        self.job["cleanup_required"] = True
        self.write_job()
        self.actual = self.inventory()
        with self.assertRaisesRegex(RuntimeError, "journal changed during transition"):
            self.seal()

    def test_changed_old_archive_cannot_be_sealed_even_with_unchanged_completed_job(self):
        self.actual[self.old]["ino"] += 1
        with self.assertRaisesRegex(RuntimeError, "old producer Web archive changed"):
            self.seal()

    def test_restore_history_pin_prevents_retirement_exception(self):
        self.actual["web-agent/restores/operations/" + "a" * 32] = {"kind": "dir"}
        with self.assertRaisesRegex(RuntimeError, "restore history"):
            self.seal()

    def test_absent_changed_or_unpinned_current_archive_is_refused(self):
        self.seal()
        (self.root / self.old).unlink()
        actual = self.inventory()
        for mutation in ("missing", "bytes", "unsealed"):
            candidate, entries = copy.deepcopy(actual), self.entries()
            with self.subTest(mutation=mutation):
                if mutation == "missing":
                    del candidate[self.current]
                elif mutation == "bytes":
                    candidate[self.current]["sha256"] = "f" * 64
                else:
                    del entries[self.current]
                with self.assertRaisesRegex(RuntimeError, "current Web archive"):
                    self.retired(candidate, entries)

    def test_changed_missing_or_pending_cleanup_journal_cannot_authorize_missing_archive(self):
        self.seal()
        (self.root / self.old).unlink()
        actual = self.inventory()
        for mutation in ("missing", "bytes", "metadata", "pending"):
            candidate = copy.deepcopy(actual)
            with self.subTest(mutation=mutation):
                if mutation == "missing":
                    del candidate[self.journal]
                elif mutation == "bytes":
                    candidate[self.journal]["sha256"] = "f" * 64
                elif mutation == "metadata":
                    candidate[self.journal]["mode"] = 0o644
                else:
                    self.job["cleanup_required"] = True
                    self.write_job()
                with self.assertRaisesRegex(RuntimeError, "(still needed|journal.*changed)"):
                    self.retired(candidate)

    def test_journal_symlink_and_same_byte_inode_replacement_are_refused(self):
        self.seal()
        (self.root / self.old).unlink()
        actual = self.inventory()
        path = self.root / self.journal
        raw = path.read_bytes()
        path.unlink()
        path.write_bytes(raw)
        path.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "journal identity changed"):
            self.retired(actual)
        path.unlink()
        path.symlink_to(self.root / self.current)
        with self.assertRaises(OSError):
            self.retired(actual)

    def test_unknown_archive_and_mismatched_plan_metadata_are_never_optional(self):
        self.seal()
        for mutation in ("unknown", "metadata", "digest", "old-manifest", "target-manifest"):
            value = copy.deepcopy(self.value)
            entries = self.entries()
            with self.subTest(mutation=mutation):
                if mutation == "unknown":
                    value["web_bundle_retirements"]["archives"]["web-agent/source-" + "f" * 64 + ".tar.gz"] = [self.journal]
                elif mutation == "metadata":
                    entries[self.old]["mode"] = 0o644
                elif mutation == "digest":
                    entries[self.old]["sha256"] = "f" * 64
                elif mutation == "old-manifest":
                    value["web_bundle_retirements"]["old_manifest_sha256"] = "f" * 64
                else:
                    value["web_bundle_retirements"]["target_manifest_sha256"] = "f" * 64
                with patch.object(self, "value", value), self.assertRaises(RuntimeError):
                    self.retired(entries=entries)

    def restored(self):
        identity = "a" * 32
        actual = self.inventory()
        entries = self.entries()
        root = actual[""]
        plan = {"resources": [{"target": "/var/lib/sovagrid", "entries": entries}], "unit_states": {}}
        transaction = {"phase": "committed", "id": identity, "steps": [{"kind": "publish", "state": "done",
            "resource": "/var/lib/sovagrid", "proof": {"resource": {"device": root["dev"], "inode": root["ino"]}}}]}
        restore = SimpleNamespace(STAGING=self.root / "staging")
        core = SimpleNamespace(host_status=lambda *args: {"phase": "committed"})
        retired = vm.retired_web_bundles
        def read(path, **kwargs):
            return plan if path.name.startswith(".apply-plan-") else transaction
        with (patch.object(vm, "fixture_module", return_value=fixture),
              patch.object(fixture, "ledger", return_value=self.value), patch.object(fixture, "source_pin"),
              patch.object(fixture, "inventory", return_value=actual), patch.object(fixture, "unit_inventory", return_value={}),
              patch.object(fixture, "save") as save, patch.object(vm, "api", return_value=(restore, core, None)),
              patch.object(vm, "private_json", side_effect=read), patch.object(vm, "expected_manifest", return_value=self.target),
              patch.object(vm, "ROOTS", {"/var/lib/sovagrid"}), patch.object(vm.os.path, "lexists", return_value=True),
              patch.object(vm.os, "fstat", side_effect=self.root_fstat),
              patch.object(vm, "retired_web_bundles", side_effect=lambda *args: retired(*args, root=self.root))):
            vm.record_restored(Path("/verified/source"), identity)
        return copy.deepcopy(save.call_args.args[0])

    def test_restored_ledger_advances_only_after_exact_gc_and_next_cleanup_comparison_passes(self):
        self.seal()
        (self.root / self.old).unlink()
        value = self.restored()
        sealed = value["trees"]["/var/lib/sovagrid"]
        self.assertNotIn(self.old, sealed)
        self.assertIn(self.current, sealed)
        actual = self.inventory()
        with patch.object(fixture, "inventory", return_value=actual):
            self.assertEqual(fixture.compare("/var/lib/sovagrid", sealed), actual)
        actual["unrelated-private-data"] = copy.deepcopy(actual[self.current])
        with patch.object(fixture, "inventory", return_value=actual), self.assertRaisesRegex(RuntimeError, "unknown descendant"):
            fixture.compare("/var/lib/sovagrid", sealed)

    def test_record_restored_still_refuses_unrelated_missing_file_or_present_archive_mutation(self):
        (self.root / "owned-setting").write_bytes(b"must survive")
        self.actual = self.inventory()
        self.value["trees"]["/var/lib/sovagrid"] = copy.deepcopy(self.actual)
        self.seal()
        (self.root / "owned-setting").unlink()
        with self.assertRaisesRegex(RuntimeError, "lost a declared descendant"):
            self.restored()
        (self.root / "owned-setting").write_bytes(b"must survive")
        (self.root / self.old).write_bytes(b"mutated present archive is never optional")
        with self.assertRaisesRegex(RuntimeError, "changed before provenance seal"):
            self.restored()


if __name__ == "__main__":
    unittest.main()
