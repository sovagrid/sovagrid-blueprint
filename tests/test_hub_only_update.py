# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""One-candidate policy and local-only snapshot boundaries."""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


DEPLOY = Path(__file__).resolve().parents[1] / "deploy"


def module(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, DEPLOY / file)
    assert spec and spec.loader
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


auto = module("sovagrid_hub_only_auto_update_test", "hub_only_auto_update.py")
update = module("sovagrid_hub_only_update_test", "hub_only_update.py")
ARCHIVE = "a" * 64
CURRENT = "b" * 64


class HubOnlyUpdatePolicy(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for name, value in (("POLICY", root / "policy.json"),
                            ("STATUS", root / "status.json"),
                            ("LOCK", root / ".lock"),
                            ("ROOT_UID", os.geteuid()),
                            ("require_root", lambda: None)):
            patcher = mock.patch.object(auto, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def result(line: str, code: int = 0) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], code, line + "\n", "")

    def arm(self) -> None:
        with mock.patch.object(auto, "worker", return_value=self.result("SG_HUB_ONLY_CANDIDATE:OK")), \
             mock.patch.object(auto.subprocess, "run", return_value=self.result("")):
            auto.arm(ARCHIVE, CURRENT)

    def test_only_one_exact_candidate_can_be_armed(self) -> None:
        self.arm()
        policy = auto.load_policy()
        assert policy is not None
        self.assertEqual((policy["archive_sha256"], policy["expected_current_manifest"]),
                         (ARCHIVE, CURRENT))
        self.assertEqual(auto.POLICY.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(auto.Refused, "ALREADY_ARMED"):
            auto.arm("c" * 64, CURRENT)

    def test_rollback_failure_disarms_automatic_retry(self) -> None:
        self.arm()
        with mock.patch.object(auto, "worker", return_value=self.result(
                "SG_HUB_ONLY_STAGE:ROLLBACK_FAILED\nSG_HUB_ONLY_REFUSE:ROLLBACK_FAILED", 40)):
            with self.assertRaisesRegex(auto.Refused, "UPDATE_FAILED"):
                auto.tick()
        self.assertFalse(auto.POLICY.exists())
        self.assertEqual(json.loads(auto.STATUS.read_text())["state"], "needs_attention")

    def test_busy_worker_keeps_exact_candidate_for_later(self) -> None:
        self.arm()
        with mock.patch.object(auto, "worker", return_value=self.result("SG_HUB_ONLY_REFUSE:BUSY", 40)):
            auto.tick()
        self.assertEqual(auto.load_policy()["archive_sha256"], ARCHIVE)
        self.assertEqual(json.loads(auto.STATUS.read_text())["state"], "deferred_busy")

    def test_sqlite_busy_is_reported_as_hub_only_busy(self) -> None:
        # A raw common worker error would become UNEXPECTED in main() and
        # disarm the one-candidate timer instead of deferring it.
        with mock.patch.object(update.common, "automatic_idle_barrier",
                               side_effect=update.common.UpdateFailure("BUSY")):
            with contextlib.ExitStack() as admission, \
                 self.assertRaisesRegex(update.Refused, "BUSY"):
                update._automatic_barrier(admission)

    def test_auto_apply_releases_writer_after_hub_stop_before_local_stop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            candidates = root / "candidates"
            candidates.mkdir()
            (candidates / "transactions").mkdir()
            staged = candidates / "staged"
            staged.mkdir()
            db_path = root / "var/lib/sovagrid/hub/hub.sqlite"
            db_path.parent.mkdir(parents=True)
            with contextlib.closing(sqlite3.connect(db_path)) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("CREATE TABLE sessions(expires_at INTEGER)")
                db.execute("CREATE TABLE jobs(state TEXT)")
                db.execute("CREATE TABLE pending_commands(expires_at INTEGER)")
            events = []

            def command(argv, **_kwargs):
                if argv[:2] == ["docker", "compose"] and argv[-4:] == ["stop", "--timeout", "30", "hub"]:
                    events.append("hub_stopped")
                if argv[:2] == ["systemctl", "stop"]:
                    with contextlib.closing(sqlite3.connect(db_path, timeout=0, isolation_level=None)) as writer:
                        writer.execute("BEGIN IMMEDIATE")
                        writer.rollback()
                    events.append("writer_released")
                    raise update.common.UpdateFailure("local stop failed")
                return 0

            def docker(argv, **_kwargs):
                if argv[:3] == ["docker", "image", "inspect"]:
                    return types.SimpleNamespace(stdout="sha256:" + ARCHIVE + "\n")
                if argv[:2] == ["docker", "ps"]:
                    return types.SimpleNamespace(stdout="")
                self.fail(f"Unexpected Docker command: {argv}")

            def lock(_path):
                return os.open(os.devnull, os.O_RDONLY)

            class RootCheckProxy:
                def geteuid(self):
                    return 0

                def __getattr__(self, name):
                    return getattr(os, name)

            patches = (
                mock.patch.object(update, "CANDIDATES", candidates),
                mock.patch.object(update, "TRANSACTIONS", candidates / "transactions"),
                mock.patch.object(update, "SOURCE", source),
                mock.patch.object(update, "_private_dir"),
                mock.patch.object(update, "_lock", side_effect=lock),
                mock.patch.object(update, "_recover_pending"),
                mock.patch.object(update, "inspect", return_value=(CURRENT, {"local_server_id": "local"},
                                                                   {"hub": "old"}, ARCHIVE)),
                mock.patch.object(update, "_candidate", return_value=(staged, {"hub": "new"})),
                mock.patch.object(update, "_snapshot_size", return_value=0),
                mock.patch.object(update, "_unit_state", return_value={"active": False, "enabled": False}),
                mock.patch.object(update, "_external_runtime", return_value={}),
                mock.patch.object(update, "_hash_file", return_value=ARCHIVE),
                mock.patch.object(update, "_state"),
                mock.patch.object(update, "_restore", return_value=True),
                mock.patch.object(update.common, "ROOT", root),
                mock.patch.object(update.common, "HUB_UID", os.getuid()),
                mock.patch.object(update.common, "HUB_GID", os.getgid()),
                mock.patch.object(update.common, "public_web_lock", side_effect=contextlib.nullcontext),
                mock.patch.object(update.common, "managed_vpn_locks", side_effect=contextlib.nullcontext),
                mock.patch.object(update.common, "gateway_prior_state", return_value={}),
                mock.patch.object(update.common, "compose_services", return_value=("hub",)),
                mock.patch.object(update.common, "compose_args", return_value=(["docker", "compose"], {})),
                mock.patch.object(update.common, "source_manifest", return_value=("c" * 64, {"hub": "new"})),
                mock.patch.object(update.common, "command", side_effect=command),
                mock.patch.object(update.promotion, "_service_setup_lock",
                                  side_effect=lambda: os.open(os.devnull, os.O_RDONLY)),
                mock.patch.object(update, "os", RootCheckProxy()),
                mock.patch.object(update.subprocess, "run", side_effect=docker),
            )
            with contextlib.ExitStack() as stack:
                for patcher in patches:
                    stack.enter_context(patcher)
                with self.assertRaisesRegex(update.Refused, "ROLLED_BACK"):
                    update.apply(ARCHIVE, CURRENT, automatic=True)
            self.assertEqual(events, ["hub_stopped", "writer_released"])

    def test_hub_only_snapshot_excludes_external_agent_and_transport(self) -> None:
        external = ("/opt/sovagrid-agent", "/var/lib/sovagrid-agent", "/etc/sovagrid/agent.json",
                    "/etc/sovagrid/agent.token", "/etc/sovagrid/hub-ca.pem",
                    "/etc/systemd/system/sovagrid-agent.service",
                    "/etc/systemd/system/sovagrid-agent-tunnel.service",
                    "/etc/systemd/system/sovagrid-fixture-reverse-tunnel.service")
        for path in external:
            self.assertNotIn(path, update.SNAPSHOT)
        self.assertIn("/var/lib/sovagrid-promotion/local-agent.json", update.SNAPSHOT)
        self.assertIn("/etc/sovagrid-local", update.SNAPSHOT)
        self.assertNotIn("sovagrid-agent.service", update.UNITS)
        self.assertNotIn("sovagrid-agent-tunnel.service", update.UNITS)

    def test_external_writer_snapshot_is_versioned_without_external_agent_tree(self) -> None:
        self.assertNotIn(update.EXTERNAL_APPLY_UNIT, update.WEB_AGENT_SNAPSHOT)
        self.assertNotIn(update.EXTERNAL_APPLY_LEDGER, update.WEB_AGENT_SNAPSHOT)
        for path in (update.EXTERNAL_APPLY_MARKER, update.EXTERNAL_APPLY_UNIT,
                     update.EXTERNAL_APPLY_LEDGER):
            self.assertIn(path, update.SNAPSHOT)
        self.assertNotIn("/opt/sovagrid-agent", update.SNAPSHOT)
        self.assertNotIn("sovagrid-external-agent-apply@.service", update.UNITS)

    def test_writer_unit_keeps_atomic_exchange_paths_on_same_filesystem(self) -> None:
        unit = (DEPLOY / "sovagrid-external-agent-apply@.service").read_text()
        self.assertIn("ProtectSystem=full", unit)
        self.assertIn("ReadWritePaths=/etc/systemd/system", unit)
        self.assertNotIn("ReadWritePaths=/opt/sovagrid-agent", unit)
        self.assertNotIn("ReadWritePaths=/var/lib/sovagrid-external-agent-update", unit)
        self.assertIn("OnFailure=sovagrid-external-agent-recovery.service", unit)

    def test_hub_update_refuses_a_pending_external_agent_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker, unit, ledger = root / "marker", root / "unit", root / "operations"
            marker.write_text("SOVAGRID_EXTERNAL_AGENT_APPLY_UNIT_V1\n")
            unit.write_text("fixed unit\n")
            ledger.mkdir()
            request_id = "9c941101-2acb-4e59-877c-136d3f43f1d8"
            operation = ledger / request_id
            operation.mkdir()
            status = {"format": 1, "request_id": request_id, "phase": "running",
                      "created_at": 1, "updated_at": 1, "error": None}
            (operation / "status.json").write_text(
                json.dumps(status, sort_keys=True, separators=(",", ":")) + "\n")
            def public_path(path, **_kwargs):
                return Path(path).read_bytes()
            apply_state = ["activating"]
            def systemctl_show(command, **_kwargs):
                state = "inactive" if "-recovery.service" in command[-1] else apply_state[0]
                return subprocess.CompletedProcess(command, 0, state + "\n", "")
            with mock.patch.object(update, "EXTERNAL_APPLY_MARKER", str(marker)), \
                 mock.patch.object(update, "EXTERNAL_APPLY_UNIT", str(unit)), \
                 mock.patch.object(update, "EXTERNAL_APPLY_LEDGER", str(ledger)), \
                 mock.patch.object(update, "_private_dir"), \
                 mock.patch.object(update.common, "public_path", side_effect=public_path), \
                 mock.patch.object(update.subprocess, "run", side_effect=systemctl_show):
                with self.assertRaisesRegex(update.Refused, "EXTERNAL_APPLY_BUSY"):
                    update._external_apply_idle()
                status["phase"] = "complete"
                (operation / "status.json").write_text(
                    json.dumps(status, sort_keys=True, separators=(",", ":")) + "\n")
                with self.assertRaisesRegex(update.Refused, "EXTERNAL_APPLY_BUSY"):
                    update._external_apply_idle()
                apply_state[0] = "inactive"
                update._external_apply_idle()

    @staticmethod
    def external_runtime(pid: int = 101) -> dict[str, dict]:
        return {unit: {"active": True, "enabled": True, "pid": pid}
                for unit in update.promotion.UNITS}

    def test_external_pid_drift_is_diagnosed_without_rejecting_live_units(self) -> None:
        before = self.external_runtime(101)
        after = self.external_runtime(202)
        emitted = []
        with mock.patch.object(update, "_external_runtime", return_value=after), \
             mock.patch.object(update, "emit", side_effect=emitted.append):
            update._check_external_runtime(before)
        self.assertEqual(emitted, ["SG_HUB_ONLY_EXTERNAL_PID_CHANGED:" + unit
                                   for unit in update.promotion.UNITS])

    def test_external_unit_policy_or_liveness_change_still_refused(self) -> None:
        before = self.external_runtime()
        for field in ("active", "enabled"):
            after = self.external_runtime(202)
            after[update.promotion.UNITS[0]][field] = False
            with self.subTest(field=field), \
                 mock.patch.object(update, "_external_runtime", return_value=after), \
                 self.assertRaisesRegex(update.Refused, "EXTERNAL_RUNTIME"):
                update._check_external_runtime(before)
        with mock.patch.object(update, "_unit_state", return_value={"active": True, "enabled": True}), \
             mock.patch.object(update.subprocess, "run", return_value=types.SimpleNamespace(stdout="0\n")), \
             self.assertRaisesRegex(update.Refused, "EXTERNAL_RUNTIME"):
            update._external_runtime()

    def test_rollback_accepts_external_restart_after_restoring_local_hub(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            before = self.external_runtime(101)
            after = self.external_runtime(202)
            units = {unit: {"active": True, "enabled": True} for unit in update.UNITS}
            state = {"phase": "preparing", "snapshot_layout": "local_web_v1",
                     "old_manifest": CURRENT, "baseline_sha256": ARCHIVE,
                     "local_record_sha256": ARCHIVE, "local_config_sha256": ARCHIVE,
                     "external_runtime": before, "images": {"hub": "sha256:" + ARCHIVE,
                                                      "web": "sha256:" + ARCHIVE},
                     "units": units}
            emitted = []
            with mock.patch.object(update, "_external_runtime", return_value=after), \
                 mock.patch.object(update, "_unit_state", side_effect=lambda unit: units[unit]), \
                 mock.patch.object(update, "_hash_file", return_value=ARCHIVE), \
                 mock.patch.object(update, "inspect", return_value=(CURRENT, {}, {}, ARCHIVE)), \
                 mock.patch.object(update, "_state"), \
                 mock.patch.object(update, "emit", side_effect=emitted.append), \
                 mock.patch.object(update.common, "command", return_value=0), \
                 mock.patch.object(update.common, "rollback_stop_compose_args",
                                   return_value=(["docker", "compose"], {})), \
                 mock.patch.object(update.common, "compose_args", return_value=(["docker", "compose"], {})), \
                 mock.patch.object(update.common, "wait_recreated_container_health"), \
                 mock.patch.object(update.common, "backup_broker_enabled", return_value=False):
                self.assertTrue(update._restore(folder, state))
            self.assertEqual(state["phase"], "rolled_back")
            self.assertIn("SG_HUB_ONLY_EXTERNAL_PID_CHANGED:" + update.promotion.UNITS[0], emitted)

    def test_candidate_preflight_uses_pinned_digest_and_installed_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate"
            candidate.mkdir()
            for name in update.REQUIRED_CANDIDATE:
                file = candidate / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text("helper fixture")
            (candidate / "sovagrid-blueprint/run.sh").write_bytes(
                b"#!/bin/bash\n# --hub-only\n# local-hub-ca.pem\n")
            with mock.patch.object(update, "CANDIDATES", root), \
                 mock.patch.object(update, "SOURCE", root), \
                 mock.patch.object(update.common, "candidate_source",
                                   return_value=(candidate, {"sovagrid-blueprint": "new"})):
                self.assertEqual(update._candidate(ARCHIVE, {"sovagrid-blueprint": "old"})[0],
                                 candidate)
                with self.assertRaisesRegex(update.Refused, "HASH"):
                    update._candidate("bad", {"sovagrid-blueprint": "old"})

    def test_managed_ssh_gateway_requires_complete_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate"
            candidate.mkdir()
            for name in update.REQUIRED_CANDIDATE:
                file = candidate / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text("helper fixture")
            script = candidate / "sovagrid-blueprint/run.sh"
            script.write_bytes(b"#!/bin/bash\n# --hub-only\n# local-hub-ca.pem\n")
            with mock.patch.object(update, "CANDIDATES", root), \
                 mock.patch.object(update, "SOURCE", root), \
                 mock.patch.object(update.common, "ssh_gateway_managed", return_value=True), \
                 mock.patch.object(update.common, "candidate_source",
                                   return_value=(candidate, {"sovagrid-blueprint": "new"})):
                with self.assertRaisesRegex(update.Refused, "CANDIDATE_INCOMPATIBLE"):
                    update._candidate(ARCHIVE, {"sovagrid-blueprint": "old"})
                script.write_bytes(script.read_bytes() + b"# SOVAGRID_SSH_GATEWAY_INSTALL_V1\n")
                for name in ("sovagrid-web/Dockerfile.ssh-gateway",
                             "sovagrid-web/gateway/package.json",
                             "sovagrid-web/gateway/package-lock.json",
                             "sovagrid-web/gateway/server.js"):
                    file = candidate / name
                    file.parent.mkdir(parents=True, exist_ok=True)
                    file.write_text("fixture")
                caddy = candidate / "sovagrid-web/deploy/Caddyfile.container"
                caddy.parent.mkdir(parents=True, exist_ok=True)
                caddy.write_text(":8080 { respond 'old' }\n")
                with self.assertRaisesRegex(update.Refused, "CANDIDATE_INCOMPATIBLE"):
                    update._candidate(ARCHIVE, {"sovagrid-blueprint": "old"})
                caddy.write_text("handle /api/v1/browser-ssh/* { reverse_proxy ssh-gateway:8768 }\n")
                with self.assertRaisesRegex(update.Refused, "CANDIDATE_INCOMPATIBLE"):
                    update._candidate(ARCHIVE, {"sovagrid-blueprint": "old"})
                script.write_bytes(script.read_bytes() + b"# SOVAGRID_PUBLIC_SSH_REFRESH_V1\n")
                self.assertEqual(update._candidate(ARCHIVE, {"sovagrid-blueprint": "old"})[0],
                                 candidate)

    def test_unmanaged_stopped_gateway_is_not_taken_over_by_update(self) -> None:
        common = update.common
        identity = "a" * 64
        def docker(args, **_kwargs):
            if args[:2] == ["docker", "ps"]:
                self.assertIn("-a", args)
                return types.SimpleNamespace(stdout=identity + "\n", returncode=0)
            self.fail(f"Unexpected Docker command: {args}")
        with mock.patch.object(common, "ssh_gateway_managed", return_value=False), \
             mock.patch.object(common.subprocess, "run", side_effect=docker):
            with self.assertRaises(common.UpdateFailure):
                common.gateway_prior_state()

    def test_staged_helper_import_does_not_modify_candidate_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            for filename in ("hub_only_update.py", "remote_update_worker.py", "promote_agent_only.py",
                             "local_operations.py", "local_container_inventory.py"):
                shutil.copyfile(DEPLOY / filename, source / filename)
            result = subprocess.run([sys.executable, "-I", str(source / "hub_only_update.py"), "preview"],
                                    capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 40)
            self.assertIn("SG_HUB_ONLY_REFUSE:ROOT", result.stdout)
            self.assertFalse(list(source.rglob("__pycache__")))

    def test_hub_only_timer_requires_explicit_policy(self) -> None:
        timer = (DEPLOY / "sovagrid-hub-only-update.timer").read_text()
        service = (DEPLOY / "sovagrid-hub-only-update.service").read_text()
        installer = (DEPLOY.parent / "run.sh").read_text()
        self.assertIn("ConditionPathExists=/etc/sovagrid-hub/hub-only-auto-update.json", service)
        self.assertIn("OnActiveSec=10min", timer)
        branch = installer[installer.index("if (( hub_only )); then\n  for auto_unit in "):]
        self.assertNotIn("systemctl enable --now sovagrid-hub-only-update.timer", branch)


if __name__ == "__main__":
    unittest.main()
