# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Filesystem interruption tests for the external Agent transaction primitive."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
spec = importlib.util.spec_from_file_location("sovagrid_external_recovery_test",
                                              DEPLOY / "external_agent_recovery.py")
assert spec and spec.loader
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
remote_spec = importlib.util.spec_from_file_location("sovagrid_remote_recovery_test",
                                                     DEPLOY / "remote_agent.py")
assert remote_spec and remote_spec.loader
remote = importlib.util.module_from_spec(remote_spec)
remote_spec.loader.exec_module(remote)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class InterruptedRecoveryTests(unittest.TestCase):
    def setUp(self):
        self._new_fixture()

    def _new_fixture(self):
        if hasattr(self, "temp"):
            self.temp.cleanup()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.files = remote.Files(self.root, owner=self.uid)
        self.worker = recovery.Recovery(self.files, owner=self.uid, group=self.gid)
        self.old_tree_data = {
            "LICENSE": b"license\n", "NOTICE": b"notice\n",
            "ATTRIBUTION.md": b"attribution\n",
            "deploy/sovagrid-agent.service": b"[Service]\nold\n",
            "sovagrid_agent/__main__.py": b"print('old')\n",
        }
        self.new_tree_data = {**self.old_tree_data,
                              "sovagrid_agent/__main__.py": b"print('new')\n",
                              "sovagrid_agent/new_metric.py": b"VALUE = 1\n",
                              "sovagrid_agent/plugins/extension.py": b"ENABLED = True\n"}
        self.old_tree = {name: sha(data) for name, data in self.old_tree_data.items()}
        self.new_tree = {name: sha(data) for name, data in self.new_tree_data.items()}
        self._tree(recovery.AGENT, self.old_tree_data)
        self._tree("/opt/candidate-agent", self.new_tree_data)
        self.guards = {
            "/etc/sovagrid/agent.token": (b"token secret\n", 0o640),
            "/etc/sovagrid/hub-ca.pem": (b"CA\n", 0o644),
            "/etc/sovagrid-agent-tunnel/id_ed25519": (b"private SSH key\n", 0o600),
            "/etc/sovagrid-agent-tunnel-public/known_hosts": (b"host pin\n", 0o644),
            "/etc/systemd/system/sovagrid-agent-tunnel.service": (b"tunnel unit\n", 0o644),
            "/etc/systemd/system/sovagrid-fixture-reverse-tunnel.service": (b"fixture reverse tunnel\n", 0o644),
            recovery.TRIAL_DROPIN: ((DEPLOY / "sovagrid-external-agent-trial.conf").read_bytes(),
                                    0o644),
        }
        for path, (data, mode) in self.guards.items():
            self._file(path, data, mode)
        self.old_meta, self.new_meta = self._metadata()
        for name, mode, _limit in recovery.META:
            self._file(name, self.old_meta[name], mode)

    def _file(self, absolute, data, mode=0o644):
        path = self.files.path(absolute)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def _tree(self, absolute, data):
        root = self.files.path(absolute)
        root.mkdir(parents=True, exist_ok=True)
        root.chmod(0o755)
        for relative, raw in data.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o644)

    def _metadata(self):
        helper, unit, manifest, state, baseline = (entry[0] for entry in recovery.META)
        old = {helper: b"# original helper\n", unit: self.old_tree_data["deploy/sovagrid-agent.service"]}
        new = {helper: b"# candidate helper\n", unit: self.new_tree_data["deploy/sovagrid-agent.service"]}

        def version(payloads, tree):
            hashes = {"sovagrid-blueprint/deploy/remote_agent.py": sha(payloads[helper]),
                      "sovagrid-agent/deploy/sovagrid-agent.service": sha(payloads[unit]),
                      **{"sovagrid-agent/" + name: digest for name, digest in tree.items()}}
            payloads[manifest] = encode({"format": 1, "components": {}, "sha256": hashes})
            source_files = {helper: sha(payloads[helper]),
                            **{recovery.AGENT + "/" + name: digest for name, digest in tree.items()}}
            owned = {**source_files, unit: sha(payloads[unit]), manifest: sha(payloads[manifest]),
                     "/etc/sovagrid/agent.token": sha(self.guards["/etc/sovagrid/agent.token"][0]),
                     "/etc/sovagrid/hub-ca.pem": sha(self.guards["/etc/sovagrid/hub-ca.pem"][0])}
            file_metadata = {path: {"mode": 0o644, "gid": self.gid} for path in owned}
            source_dirs = ({"/opt/sovagrid-agent/sovagrid_agent/plugins": 0o755}
                           if "sovagrid_agent/plugins/extension.py" in tree else {})
            payloads[state] = encode({"protocol": 1, "kind": "target", "phase": "active",
                                      "removed": False, "pending_writes": {},
                                      "identity": {"request_id": "same", "server_id": "same",
                                                   "enrollment_id": "same"},
                                      "agent_token_sha256": sha(self.guards["/etc/sovagrid/agent.token"][0]),
                                      "ssh_public_key": "ssh-ed25519 same",
                                      "ssh_key_fingerprint": "same", "transport": {"host": "same"},
                                      "local_port": 2200, "accounts": {},
                                      "owned_directories": source_dirs,
                                      "source_manifest_sha256": sha(payloads[manifest]),
                                      "source_files": source_files, "owned_files": owned,
                                      "file_metadata": file_metadata})
            records = {path: {"sha256": sha(payloads[path]), "uid": self.uid,
                              "gid": self.gid, "mode": mode}
                       for path, mode in ((unit, 0o644), (manifest, 0o644), (state, 0o600))}
            records["/etc/sovagrid/agent.token"] = {"sha256": sha(self.guards["/etc/sovagrid/agent.token"][0]),
                                                       "uid": self.uid, "gid": self.gid, "mode": 0o640}
            reverse_unit = "/etc/systemd/system/sovagrid-fixture-reverse-tunnel.service"
            records[reverse_unit] = {"sha256": sha(self.guards[reverse_unit][0]),
                                     "uid": self.uid, "gid": self.gid, "mode": 0o644}
            payloads[baseline] = encode({"protocol": 1, "files": records,
                                         "agent_data": {"uid": self.uid, "gid": self.gid, "mode": 0o755},
                                         "units": {"agent": True, "tunnel": True,
                                                   "sovagrid-fixture-reverse-tunnel.service": True}})
            return payloads

        return version(old, self.old_tree), version(new, self.new_tree)

    def prepare(self):
        return self.worker.prepare(candidate_tree="/opt/candidate-agent",
                                   old_tree=self.old_tree, new_tree=self.new_tree,
                                   new_meta=self.new_meta)

    def prepare_with_checkpoint(self, checkpoint):
        return self.worker.prepare(candidate_tree="/opt/candidate-agent",
                                   old_tree=self.old_tree, new_tree=self.new_tree,
                                   new_meta=self.new_meta, checkpoint=checkpoint)

    def switch(self, checkpoint=None, *, remote_gate=True, agent_gate=True):
        return self.worker._switch_under_quiescence(
            agent_stopped=lambda: True, remote_lease_active=lambda: remote_gate,
            agent_idle_ack=lambda: agent_gate, checkpoint=checkpoint)

    def assert_old(self):
        self.worker._tree(recovery.AGENT, self.old_tree)
        for name, _mode, _limit in recovery.META:
            self.assertEqual(self.files.path(name).read_bytes(), self.old_meta[name])
        for name, (data, mode) in self.guards.items():
            self.assertEqual(self.files.path(name).read_bytes(), data)
            self.assertEqual(self.files.path(name).stat().st_mode & 0o777, mode)

    def assert_new(self):
        self.worker._tree(recovery.AGENT, self.new_tree)
        for name, _mode, _limit in recovery.META:
            self.assertEqual(self.files.path(name).read_bytes(), self.new_meta[name])
        for name, (data, mode) in self.guards.items():
            self.assertEqual(self.files.path(name).read_bytes(), data)
            self.assertEqual(self.files.path(name).stat().st_mode & 0o777, mode)

    def trial(self):
        self.worker.begin_trial(agent_stopped=lambda: True,
                                remote_lease_active=lambda: True,
                                supervisor_active=lambda: True,
                                agent_idle_proven=lambda: True)

    def commit_trial(self):
        self.worker.commit_trial(agent_running=lambda: True,
                                 agent_healthy=lambda: True,
                                 remote_lease_active=lambda: True,
                                 supervisor_active=lambda: True,
                                 agent_idle_proven=lambda: True)

    def test_interruption_after_each_switch_step_restores_original(self):
        for stop_at in ("tree", *("meta-" + str(i) for i in range(len(recovery.META))), None):
            with self.subTest(stop_at=stop_at):
                self._new_fixture()
                self.prepare()

                def interrupted(point):
                    if point == stop_at:
                        raise RuntimeError("power loss")

                if stop_at is None:
                    self.switch()
                else:
                    with self.assertRaisesRegex(RuntimeError, "power loss"):
                        self.switch(interrupted)
                self.assertTrue(self.worker.recover_pending(agent_stopped=lambda: True))
                self.assert_old()
                self.assertFalse(self.worker.recover_pending(agent_stopped=lambda: True))

    def test_sigkill_during_prepare_has_safe_cleanup_and_retry(self):
        steps = ("txn-created", "prepare-marker", "old-tree", "new-tree",
                 *("meta-" + str(i) for i in range(len(recovery.META))),
                 "journal", "marker-removed")
        for stop_at in steps:
            with self.subTest(stop_at=stop_at):
                self._new_fixture()

                def interrupted(point):
                    if point == stop_at:
                        raise RuntimeError("power loss")

                with self.assertRaisesRegex(RuntimeError, "power loss"):
                    self.prepare_with_checkpoint(interrupted)
                self.assert_old()
                self.assertTrue(self.worker.recover_pending(agent_stopped=lambda: True))
                self.assertFalse(self.files.path(recovery.TXN).exists())
                self.assertFalse(self.worker.recover_pending(agent_stopped=lambda: True))
                self.prepare()
                self.assertTrue(self.worker.recover_pending(agent_stopped=lambda: True))
                self.assert_old()

    def test_prepare_retries_after_verified_prejournal_orphan(self):
        def interrupted(point):
            if point == "new-tree":
                raise RuntimeError("power loss")

        with self.assertRaisesRegex(RuntimeError, "power loss"):
            self.prepare_with_checkpoint(interrupted)
        self.assertTrue(self.files.path(recovery.PREPARING).exists())
        self.prepare()
        self.assertFalse(self.files.path(recovery.PREPARING).exists())
        self.assertTrue(self.files.path(recovery.JOURNAL).exists())
        self.assertTrue(self.worker.recover_pending(agent_stopped=lambda: True))
        self.assert_old()

    def test_interrupted_recovery_is_idempotent(self):
        for stop_at in ("tree", *("meta-" + str(i) for i in range(len(recovery.META)))):
            with self.subTest(stop_at=stop_at):
                self._new_fixture()
                self.prepare()
                self.switch()

                def interrupted(point):
                    if point == stop_at:
                        raise RuntimeError("power loss")

                with self.assertRaisesRegex(RuntimeError, "power loss"):
                    self.worker.recover_pending(agent_stopped=lambda: True,
                                                checkpoint=interrupted)
                self.assertTrue(self.worker.recover_pending(agent_stopped=lambda: True))
                self.assert_old()

    def test_missing_lease_or_idle_ack_cannot_switch(self):
        self.prepare()
        for remote_gate, agent_gate in ((False, True), (True, False)):
            with self.subTest(remote_gate=remote_gate, agent_gate=agent_gate), \
                 self.assertRaisesRegex(recovery.RecoveryError, "QUIESCENCE_REQUIRED"):
                self.switch(remote_gate=remote_gate, agent_gate=agent_gate)
            self.assert_old()
        self.assertTrue(self.worker.recover_pending(agent_stopped=lambda: True))

    def test_trial_requires_every_live_gate_and_default_boot_recovers_old(self):
        self.prepare()
        self.switch()
        callbacks = dict(agent_stopped=lambda: True,
                         remote_lease_active=lambda: True,
                         supervisor_active=lambda: True,
                         agent_idle_proven=lambda: True)
        for missing in callbacks:
            with self.subTest(missing=missing):
                invalid = {**callbacks, missing: lambda: False}
                with self.assertRaisesRegex(recovery.RecoveryError, "TRIAL_GATE_REQUIRED"):
                    self.worker.begin_trial(**invalid)
                self.assertEqual(self.worker._load_journal()["phase"], "switched")
        self.trial()
        self.assertEqual(self.worker._load_journal()["phase"], "trial")
        self.assertFalse(self.worker.recover_pending(
            agent_stopped=lambda: True, trial_authorized=lambda: True))
        self.assert_new()
        self.assertTrue(self.worker.recover_pending(agent_stopped=lambda: True))
        self.assert_old()

    def test_trial_commit_requires_health_and_idle_proof(self):
        self.prepare()
        self.switch()
        self.trial()
        callbacks = dict(agent_running=lambda: True, agent_healthy=lambda: True,
                         remote_lease_active=lambda: True,
                         supervisor_active=lambda: True,
                         agent_idle_proven=lambda: True)
        for missing in callbacks:
            with self.subTest(missing=missing):
                invalid = {**callbacks, missing: lambda: False}
                with self.assertRaisesRegex(recovery.RecoveryError, "COMMIT_GATE_REQUIRED"):
                    self.worker.commit_trial(**invalid)
                self.assertEqual(self.worker._load_journal()["phase"], "trial")
        self.commit_trial()
        self.assertEqual(self.worker._load_journal()["phase"], "committed")
        self.assertTrue(self.worker.recover_pending(agent_stopped=lambda: False))
        self.assert_new()
        self.assertFalse(self.worker.recover_pending(agent_stopped=lambda: True))

    def test_committed_cleanup_crashes_preserve_new_source(self):
        for stop_at in ("committed-marker", "committed-journal-removed"):
            with self.subTest(stop_at=stop_at):
                self._new_fixture()
                self.prepare()
                self.switch()
                self.trial()
                self.commit_trial()

                def interrupted(point):
                    if point == stop_at:
                        raise RuntimeError("power loss")

                with self.assertRaisesRegex(RuntimeError, "power loss"):
                    self.worker.finalize_committed(checkpoint=interrupted)
                self.assert_new()
                self.assertTrue(self.worker.recover_pending(agent_stopped=lambda: True))
                self.assert_new()
                self.assertFalse(self.files.path(recovery.TXN).exists())
                self.assertFalse(self.files.path(recovery.COMMITTED).exists())
                self.assertFalse(self.worker.recover_pending(agent_stopped=lambda: True))

    def test_partial_committed_scratch_cleanup_is_retried(self):
        self.prepare()
        self.switch()
        self.trial()
        self.commit_trial()

        def interrupted(point):
            if point == "committed-journal-removed":
                raise RuntimeError("power loss")

        with self.assertRaisesRegex(RuntimeError, "power loss"):
            self.worker.finalize_committed(checkpoint=interrupted)
        self.assertTrue(self.files.path(recovery.COMMITTED).exists())
        shutil.rmtree(self.files.path(recovery.NEW_META))
        self.assertTrue(self.worker.recover_pending(agent_stopped=lambda: True))
        self.assert_new()
        self.assertFalse(self.files.path(recovery.TXN).exists())

    def test_committed_marker_and_installed_source_must_agree(self):
        self.prepare()
        self.switch()
        self.trial()
        self.commit_trial()

        def interrupted(point):
            if point == "committed-journal-removed":
                raise RuntimeError("power loss")

        with self.assertRaisesRegex(RuntimeError, "power loss"):
            self.worker.finalize_committed(checkpoint=interrupted)
        source = recovery.AGENT + "/sovagrid_agent/__main__.py"
        self._file(source, b"tampered\n", 0o644)
        with self.assertRaisesRegex(recovery.RecoveryError, "TREE_CHANGED"):
            self.worker.recover_pending(agent_stopped=lambda: True)
        self._file(source, self.new_tree_data["sovagrid_agent/__main__.py"], 0o644)
        self.assertTrue(self.worker.recover_pending(agent_stopped=lambda: True))
        self.assert_new()

    def test_committed_cleanup_rejects_corrupt_new_tree_or_guard(self):
        self.prepare()
        self.switch()
        self.trial()
        self.commit_trial()
        source = recovery.AGENT + "/sovagrid_agent/__main__.py"
        self._file(source, b"tampered\n", 0o644)
        with self.assertRaisesRegex(recovery.RecoveryError, "TREE_CHANGED"):
            self.worker.recover_pending(agent_stopped=lambda: True)
        self._file(source, self.new_tree_data["sovagrid_agent/__main__.py"], 0o644)
        token = "/etc/sovagrid/agent.token"
        self._file(token, b"tampered token\n", 0o640)
        with self.assertRaisesRegex(recovery.RecoveryError, "GUARD_CHANGED"):
            self.worker.recover_pending(agent_stopped=lambda: True)
        self._file(token, self.guards[token][0], 0o640)
        self.assertTrue(self.worker.recover_pending(agent_stopped=lambda: True))
        self.assert_new()

    def test_additive_directory_is_atomically_installed_and_removed_on_rollback(self):
        new_path = self.files.path(recovery.AGENT + "/sovagrid_agent/plugins/extension.py")
        self.assertFalse(new_path.exists())
        self.prepare()
        self.switch()
        self.assertEqual(new_path.read_bytes(), b"ENABLED = True\n")
        self.worker._tree(recovery.AGENT, self.new_tree)
        self.assertTrue(self.worker.recover_pending(agent_stopped=lambda: True))
        self.assertFalse(new_path.exists())
        self.assert_old()

    def test_changed_credential_or_foreign_unit_blocks_recovery(self):
        self.prepare()
        self.switch()
        token = "/etc/sovagrid/agent.token"
        self._file(token, b"replaced token\n", 0o640)
        with self.assertRaisesRegex(recovery.RecoveryError, "GUARD_CHANGED"):
            self.worker.recover_pending(agent_stopped=lambda: True)
        self._file(token, self.guards[token][0], 0o640)
        unit = recovery.META[1][0]
        self._file(unit, b"foreign unit\n", 0o644)
        with self.assertRaisesRegex(recovery.RecoveryError, "META_CHANGED"):
            self.worker.recover_pending(agent_stopped=lambda: True)
        self._file(unit, self.new_meta[unit], 0o644)
        self.assertTrue(self.worker.recover_pending(agent_stopped=lambda: True))
        self.assert_old()

    def test_changed_identity_is_rejected_before_journal(self):
        path = recovery.META[3][0]
        state = json.loads(self.new_meta[path])
        state["ssh_public_key"] = "changed"
        self.new_meta[path] = encode(state)
        baseline = recovery.META[4][0]
        record = json.loads(self.new_meta[baseline])
        record["files"][path]["sha256"] = sha(self.new_meta[path])
        self.new_meta[baseline] = encode(record)
        with self.assertRaisesRegex(recovery.RecoveryError, "IDENTITY_CHANGED"):
            self.prepare()
        self.assertFalse(self.files.path(recovery.JOURNAL).exists())
        self.assert_old()

    def test_running_agent_or_corrupt_journal_blocks_recovery(self):
        self.prepare()
        self.switch()
        with self.assertRaisesRegex(recovery.RecoveryError, "AGENT_RUNNING"):
            self.worker.recover_pending(agent_stopped=lambda: False)
        self.worker._tree(recovery.AGENT, self.new_tree)
        journal = self.files.path(recovery.JOURNAL)
        saved = journal.read_bytes()
        journal.write_bytes(b'{"protocol":1,"protocol":1}')
        with self.assertRaisesRegex(recovery.RecoveryError, "JOURNAL_INVALID"):
            self.worker.recover_pending(agent_stopped=lambda: True)
        self.worker._tree(recovery.AGENT, self.new_tree)
        journal.write_bytes(saved)
        self.assertTrue(self.worker.recover_pending(agent_stopped=lambda: True))
        self.assert_old()

    def test_missing_journal_after_switch_is_not_mistaken_for_preparation(self):
        self.prepare()
        self.switch()
        self.files.path(recovery.JOURNAL).unlink()
        with self.assertRaisesRegex(recovery.RecoveryError, "ORPHAN_REQUIRES_REVIEW"):
            self.worker.recover_pending(agent_stopped=lambda: True)
        self.worker._tree(recovery.AGENT, self.new_tree)

    def test_boot_unit_requires_successful_recovery_before_agent(self):
        unit = (DEPLOY / "sovagrid-external-agent-recovery.service").read_text()
        self.assertIn("Before=sovagrid-agent.service", unit)
        self.assertIn("RequiredBy=sovagrid-agent.service", unit)
        self.assertIn("external_agent_update.py recover", unit)
        dropin = (DEPLOY / "sovagrid-external-agent-trial.conf").read_text()
        self.assertIn("ExecStartPre=+/usr/bin/python3 -I", dropin)
        self.assertIn("external_agent_update.py trial-start-guard", dropin)
        self.assertIn("Environment=SOVAGRID_EXTERNAL_TRIAL_GATE=1", dropin)
        self.assertIn("EnvironmentFile=-/run/sovagrid-external-agent-trial/epoch.env", dropin)

    def test_loaded_trial_guard_requires_agent_runtime_gate(self):
        planner_spec = importlib.util.spec_from_file_location(
            "sovagrid_external_trial_loaded_test", DEPLOY / "external_agent_update.py")
        assert planner_spec and planner_spec.loader
        planner = importlib.util.module_from_spec(planner_spec)
        planner_spec.loader.exec_module(planner)
        prestart = ("argv[]=/usr/bin/python3 -I /opt/sovagrid-src/sovagrid-blueprint/"
                    "deploy/external_agent_update.py trial-start-guard ;")
        def loaded(environment, reload="no", epoch_file=True):
            body = (f"NeedDaemonReload={reload}\nExecStartPre={prestart}\n"
                    f"Environment={environment}\nEnvironmentFiles="
                    f"{'/run/sovagrid-external-agent-trial/epoch.env (ignore_errors=yes)' if epoch_file else ''}\n").encode()
            return mock.Mock(returncode=0, stdout=body)
        with mock.patch.object(planner.subprocess, "run", return_value=loaded("SOVAGRID_EXTERNAL_TRIAL_GATE=1")):
            self.assertTrue(planner._systemd_trial_guard_loaded())
        for environment, reload, epoch_file in (
                ("", "no", True), ("SOVAGRID_EXTERNAL_TRIAL_GATE=0", "no", True),
                ("SOVAGRID_EXTERNAL_TRIAL_GATE=1", "yes", True),
                ("OTHER=1 SOVAGRID_EXTERNAL_TRIAL_GATE=1", "no", True),
                ("SOVAGRID_EXTERNAL_TRIAL_GATE=1", "no", False)):
            with self.subTest(environment=environment, reload=reload, epoch_file=epoch_file), \
                 mock.patch.object(planner.subprocess, "run", return_value=loaded(environment, reload, epoch_file)):
                self.assertFalse(planner._systemd_trial_guard_loaded())

    def test_trial_start_cli_stays_closed_before_fd_watchdog(self):
        planner_spec = importlib.util.spec_from_file_location(
            "sovagrid_external_trial_guard_cli_test", DEPLOY / "external_agent_update.py")
        assert planner_spec and planner_spec.loader
        planner = importlib.util.module_from_spec(planner_spec)
        planner_spec.loader.exec_module(planner)
        enrollment = mock.MagicMock()
        enrollment.locked.return_value = contextlib.nullcontext()
        transaction = mock.MagicMock()
        transaction._load_journal.return_value = {"phase": "trial"}
        transaction.verify_trial_state.return_value = "a" * 64
        with mock.patch.object(planner.os, "geteuid", return_value=0), \
             mock.patch.object(planner.remote, "Enrollment", return_value=enrollment), \
             mock.patch.object(planner.recovery, "Recovery", return_value=transaction), \
             mock.patch.object(planner.update, "_lock",
                               side_effect=lambda _path: os.open(os.devnull, os.O_RDONLY)), \
             mock.patch.object(planner, "_systemd_trial_guard_loaded", return_value=True), \
             mock.patch.object(planner.recovery, "probe_trial_gate") as probe:
            with self.assertRaisesRegex(planner.Refused, "TRIAL_RUNTIME_NOT_READY"):
                planner.trial_start_guard()
            probe.assert_not_called()
            transaction._load_journal.return_value = None
            transaction._load_committed_marker.return_value = None
            transaction.files.inspect.return_value = None
            self.assertEqual(planner.trial_start_guard(),
                             {"protocol": 1, "trial": False, "allowed": True})


class LiveTrialGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "private-run"
        self.directory.mkdir(mode=0o700)
        self.directory.chmod(0o700)
        self.path = str(self.directory / "trial.sock")
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.digest = "a" * 64

    def probe(self, operation, digest=None):
        return recovery.probe_trial_gate(operation, digest or self.digest,
                                         path=self.path, owner=self.uid,
                                         group=self.gid)

    def test_live_gate_is_digest_bound_single_use_and_ordered(self):
        flags = {"lease": True, "ack": True}
        server = recovery.TrialGateServer(
            self.digest, lease_active=lambda: flags["lease"],
            agent_idle_proven=lambda: flags["ack"], path=self.path,
            owner=self.uid, group=self.gid)
        with mock.patch.object(recovery, "_linux_peer",
                               return_value=(os.getpid(), self.uid, self.gid)):
            server.start()
            self.addCleanup(server.close)
            self.assertFalse(self.probe("start"))
            self.assertFalse(self.probe("recover", "b" * 64))
            flags["lease"] = False
            self.assertFalse(self.probe("recover"))
            flags["lease"] = True
            self.assertTrue(self.probe("recover"))
            self.assertFalse(self.probe("recover"))
            flags["ack"] = False
            self.assertFalse(self.probe("start"))
            flags["ack"] = True
            self.assertTrue(self.probe("start"))
            self.assertFalse(self.probe("start"))
            server.close()
            self.assertFalse(self.probe("recover"))

    def test_stale_or_untrusted_socket_never_authorizes(self):
        self.assertFalse(self.probe("recover"))
        other = self.directory / "other"
        other.write_text("not a socket")
        Path(self.path).symlink_to(other)
        self.assertFalse(self.probe("recover"))

    def test_peer_pid_mismatch_cannot_authorize(self):
        server = recovery.TrialGateServer(
            self.digest, lease_active=lambda: True,
            agent_idle_proven=lambda: True, path=self.path,
            owner=self.uid, group=self.gid)
        with mock.patch.object(recovery, "_linux_peer",
                               return_value=(os.getpid() + 1, self.uid, self.gid)):
            server.start()
            self.addCleanup(server.close)
            self.assertFalse(self.probe("recover"))

    def test_recovery_refusal_has_bounded_explicit_code(self):
        planner_spec = importlib.util.spec_from_file_location(
            "sovagrid_external_recovery_cli_test", DEPLOY / "external_agent_update.py")
        assert planner_spec and planner_spec.loader
        planner = importlib.util.module_from_spec(planner_spec)
        planner_spec.loader.exec_module(planner)
        stderr = io.StringIO()
        with mock.patch.object(planner, "recover_pending",
                               side_effect=planner.recovery.RecoveryError("ORPHAN_REQUIRES_REVIEW")), \
             contextlib.redirect_stderr(stderr):
            self.assertEqual(planner.main(["recover"]), 40)
        self.assertEqual(stderr.getvalue(),
                         "SG_EXTERNAL_AGENT_UPDATE_REFUSE:ORPHAN_REQUIRES_REVIEW\n")


if __name__ == "__main__":
    unittest.main()
