# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Rootless journal and interruption tests for managed host snapshots."""

from contextlib import contextmanager, nullcontext
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import call, patch

from deploy import host_backup_orchestrator as operation


REAL_SPAWN = operation._spawn
REQUEST = "a" * 32
MANIFEST = "b" * 64
UNIT = "sovagrid-vpn-control.socket"
PLAN = {"ok": True, "protocol": "sovagrid-host-backup-v1", "layout": "full",
        "active_units": [UNIT], "running_containers": ["hub", "web"],
        "offline_ready": False}
GATEWAY_PLAN = {**PLAN, "running_containers": ["hub", "web", "ssh-gateway"]}
GATEWAY_IDS = {"hub": "c" * 64, "web": "d" * 64, "ssh-gateway": "f" * 64}
PORTABLE_IMAGES = {
    "hub": {"container_id": "c" * 64, "image_id": "sha256:" + "1" * 64,
            "rootfs_sha256": "5" * 64},
    "web": {"container_id": "d" * 64, "image_id": "sha256:" + "2" * 64,
            "rootfs_sha256": "6" * 64},
}


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state_dir = Path(temporary.name) / "operations"
        patches = (
            patch.object(operation, "STATE_DIR", self.state_dir),
            patch.object(operation, "_require_root"),
            patch.object(operation.backup, "_source_manifest", return_value=MANIFEST),
            patch.object(operation.backup, "plan", return_value=PLAN),
            patch.object(operation.backup, "list_archives", return_value={"archives": []}),
            patch.object(operation, "_container_ids", return_value={"hub": "c" * 64,
                                                                "web": "d" * 64}),
            patch.object(operation, "_unit_hashes", return_value={UNIT: "e" * 64}),
            patch.object(operation.backup, "_locks", return_value=nullcontext()),
            patch.object(operation, "_spawn"),
        )
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def _start(self):
        return operation.start(REQUEST, MANIFEST)

    def test_start_is_idempotent_and_list_finds_operation_from_another_client(self):
        first = self._start()
        self.assertEqual(first["phase"], "accepted")
        self.assertIsNone(first["archive"])
        self.assertEqual(operation.status(REQUEST), first)
        self.assertEqual(operation.list_operations()["operations"], [first])
        self.assertEqual(self._start(), first)
        operation._spawn.assert_called_once_with("run", REQUEST)
        stored = operation._record(REQUEST)
        self.assertEqual(stored["expected_manifest_sha256"], MANIFEST)
        self.assertRegex(stored["archive_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(stored["container_ids"], {"hub": "c" * 64, "web": "d" * 64})

    def test_corrupted_journal_types_return_stable_error(self):
        self._start()
        original = operation._record(REQUEST)
        for key in ("phase", "active_units", "running_containers"):
            with self.subTest(key=key):
                damaged = {**original, key: [{}]}
                operation._private_write(operation._record_path(REQUEST),
                                         (json.dumps(damaged) + "\n").encode())
                with self.assertRaisesRegex(operation.Refused, "INVALID_STATE"):
                    operation.status(REQUEST)

    def test_worker_passes_pinned_archive_id_and_restores_stack(self):
        self._start()
        archive_id = operation._record(REQUEST)["archive_id"]
        archive = {"id": archive_id, "created_at": "2026-10-27T00:00:00+00:00",
                   "layout": "full", "bytes": 512, "files": 3}
        with patch.object(operation, "_stop") as stop, patch.object(
                operation, "_restart") as restart, patch.object(
                operation.backup, "_create_locked", return_value={"archive": archive}) as create:
            operation._worker(REQUEST, recovery=False)
        stop.assert_called_once()
        create.assert_called_once_with(identity=archive_id)
        restart.assert_called_once()
        self.assertEqual(operation.status(REQUEST)["phase"], "complete")
        self.assertEqual(operation.status(REQUEST)["archive"], archive)
        self.assertIsNone(operation._active())

    def test_portable_operation_pairs_pinned_archive_and_exact_images(self):
        with patch.object(operation, "_portable_images", return_value=PORTABLE_IMAGES):
            accepted = operation.start(REQUEST, MANIFEST, portable=True)
            self.assertEqual(accepted["phase"], "accepted")
            self.assertEqual(operation.start(REQUEST, MANIFEST, portable=True), accepted)
            with self.assertRaisesRegex(operation.Refused, "ID_CONFLICT"):
                operation.start(REQUEST, MANIFEST)
            self.assertNotIn("image_receipt", accepted)  # Legacy status shape.
            archive_id = operation._record(REQUEST)["archive_id"]
            archive = {"id": archive_id, "created_at": "2026-10-27T00:00:00+00:00",
                       "layout": "full", "bytes": 512, "files": 3}
            artifact = {"id": archive_id, "host_archive_sha256": "3" * 64,
                        "source_manifest_sha256": MANIFEST, "layout": "full",
                        "sha256": "4" * 64,
                        "images": {key: item["image_id"]
                                   for key, item in PORTABLE_IMAGES.items()},
                        "container_ids": {"hub": "c" * 64, "web": "d" * 64},
                        "exported_configs": {"hub": "sha256:" + "7" * 64,
                                             "web": "sha256:" + "8" * 64},
                        "rootfs_sha256": {key: item["rootfs_sha256"]
                                           for key, item in PORTABLE_IMAGES.items()}}
            with patch.object(operation, "_stop"), patch.object(operation, "_restart"), \
                 patch.object(operation.backup, "_create_locked",
                              return_value={"archive": archive}), \
                 patch.object(operation.backup, "_record",
                              return_value={"sha256": "3" * 64}), \
                 patch.object(operation.images, "_create_locked",
                              return_value=artifact) as export, \
                 patch.object(operation.images, "_publish_portable_receipt_locked") as publish:
                operation._worker(REQUEST, recovery=False)
        export.assert_called_once_with(archive_id, expected_installed=PORTABLE_IMAGES)
        publish.assert_called_once()
        self.assertEqual(publish.call_args.args[0], archive_id)
        self.assertEqual(publish.call_args.args[1]["images_sha256"], "4" * 64)
        self.assertEqual(operation.status(REQUEST)["phase"], "complete")
        receipt = operation.portable_status(REQUEST)["image_receipt"]
        self.assertEqual(receipt["host_archive_sha256"], "3" * 64)
        self.assertEqual(receipt["images_sha256"], "4" * 64)
        self.assertEqual(receipt["container_ids"], artifact["container_ids"])
        self.assertEqual(receipt["rootfs_sha256"], artifact["rootfs_sha256"])
        self.assertEqual(receipt["exported_configs"], artifact["exported_configs"])
        damaged = operation._record(REQUEST)
        damaged["image_receipt"] = None
        operation._private_write(operation._record_path(REQUEST),
                                 (json.dumps(damaged) + "\n").encode())
        with self.assertRaisesRegex(operation.Refused, "INVALID_STATE"):
            operation.portable_status(REQUEST)
        self.assertIsNone(operation._active())

    def test_portable_export_failure_never_reports_complete(self):
        with patch.object(operation, "_portable_images", return_value=PORTABLE_IMAGES):
            operation.start(REQUEST, MANIFEST, portable=True)
            archive_id = operation._record(REQUEST)["archive_id"]
            archive = {"id": archive_id, "created_at": "2026-10-27T00:00:00+00:00",
                       "layout": "full", "bytes": 512, "files": 3}
            with patch.object(operation, "_stop"), patch.object(operation, "_restart") as restart, \
                 patch.object(operation.backup, "_create_locked",
                              return_value={"archive": archive}), \
                 patch.object(operation.images, "_create_locked",
                              side_effect=RuntimeError("private docker error")):
                operation._worker(REQUEST, recovery=False)
        restart.assert_called_once()
        state = operation.portable_status(REQUEST)
        self.assertEqual((state["phase"], state["error"]), ("failed", "IMAGES_FAILED"))
        self.assertIsNone(state["image_receipt"])
        self.assertNotIn("private docker error", str(state))

    def test_portable_receipt_write_failure_never_reports_complete(self):
        with patch.object(operation, "_portable_images", return_value=PORTABLE_IMAGES):
            operation.start(REQUEST, MANIFEST, portable=True)
            archive_id = operation._record(REQUEST)["archive_id"]
            archive = {"id": archive_id, "created_at": "2026-10-27T00:00:00+00:00",
                       "layout": "full", "bytes": 512, "files": 3}
            artifact = {"id": archive_id, "host_archive_sha256": "3" * 64,
                        "source_manifest_sha256": MANIFEST, "layout": "full",
                        "sha256": "4" * 64,
                        "images": {key: item["image_id"]
                                   for key, item in PORTABLE_IMAGES.items()},
                        "container_ids": {"hub": "c" * 64, "web": "d" * 64},
                        "exported_configs": {"hub": "sha256:" + "7" * 64,
                                             "web": "sha256:" + "8" * 64},
                        "rootfs_sha256": {key: item["rootfs_sha256"]
                                           for key, item in PORTABLE_IMAGES.items()}}
            with patch.object(operation, "_stop"), patch.object(operation, "_restart"), \
                 patch.object(operation.backup, "_create_locked",
                              return_value={"archive": archive}), \
                 patch.object(operation.backup, "_record",
                              return_value={"sha256": "3" * 64}), \
                 patch.object(operation.images, "_create_locked", return_value=artifact), \
                 patch.object(operation.images, "_publish_portable_receipt_locked",
                              side_effect=OSError("private disk path")):
                operation._worker(REQUEST, recovery=False)
        state = operation.portable_status(REQUEST)
        self.assertEqual((state["phase"], state["error"]), ("failed", "IMAGES_FAILED"))
        self.assertIsNone(state["image_receipt"])
        self.assertNotIn("private disk path", str(state))

    def test_portable_image_drift_blocks_stop(self):
        with patch.object(operation, "_portable_images", return_value=PORTABLE_IMAGES):
            operation.start(REQUEST, MANIFEST, portable=True)
        changed = {**PORTABLE_IMAGES, "web": {**PORTABLE_IMAGES["web"],
                                            "rootfs_sha256": "9" * 64}}
        with patch.object(operation, "_portable_images", return_value=changed), \
             patch.object(operation, "_stop") as stop, \
             patch.object(operation.images, "_create_locked") as export:
            operation._worker(REQUEST, recovery=False)
        stop.assert_not_called()
        export.assert_not_called()
        self.assertEqual(operation.portable_status(REQUEST)["error"], "IMAGE_CHANGED")

    def test_portable_recovery_never_reexports_images(self):
        with patch.object(operation, "_portable_images", return_value=PORTABLE_IMAGES):
            operation.start(REQUEST, MANIFEST, portable=True)
        value = operation._record(REQUEST)
        operation._phase(value, "restarting")
        with patch.object(operation.subprocess, "run") as run:
            run.return_value.returncode = 3
            operation.recover(REQUEST)
        with patch.object(operation, "_reconcile_archive", return_value=None), \
             patch.object(operation, "_restart"), \
             patch.object(operation.images, "_create_locked") as export:
            operation._worker(REQUEST, recovery=True)
        export.assert_not_called()
        state = operation.portable_status(REQUEST)
        self.assertEqual(state["phase"], "recovered")
        self.assertIsNone(state["image_receipt"])

    def test_portable_start_requires_running_managed_stack(self):
        with patch.object(operation.backup, "plan", return_value={
                **PLAN, "running_containers": []}), patch.object(
                operation, "_portable_images") as inspect:
            with self.assertRaisesRegex(operation.Refused, "STACK_NOT_READY"):
                operation.start(REQUEST, MANIFEST, portable=True)
        inspect.assert_not_called()
        self.assertEqual(operation.list_operations()["operations"], [])

    def test_worker_holds_enrollment_lock_while_stopping_and_archiving(self):
        self._start()
        held = []

        @contextmanager
        def enrollment_lock():
            held.append(True)
            try:
                yield
            finally:
                held.pop()

        def check_stop(_value):
            self.assertEqual(held, [True])

        def check_archive(*, identity):
            self.assertEqual(held, [True])
            return {"archive": {"id": identity, "created_at": "2026-10-27T00:00:00+00:00",
                                "layout": "full", "bytes": 512, "files": 3}}

        with patch.object(operation.update, "web_agent_snapshot_lock", side_effect=enrollment_lock), patch.object(
                operation, "_stop", side_effect=check_stop), patch.object(
                operation, "_restart", side_effect=check_stop), patch.object(
                operation.backup, "_create_locked", side_effect=check_archive):
            operation._worker(REQUEST, recovery=False)
        self.assertEqual(held, [])
        self.assertEqual(operation.status(REQUEST)["phase"], "complete")

    def test_busy_enrollment_lock_refuses_backup_before_stop(self):
        self._start()
        with patch.object(operation.update, "web_agent_snapshot_lock",
                          side_effect=operation.update.UpdateFailure("BUSY")), patch.object(
                operation, "_stop") as stop:
            operation._worker(REQUEST, recovery=False)
        stop.assert_not_called()
        self.assertEqual(operation.status(REQUEST)["phase"], "failed")
        self.assertEqual(operation.status(REQUEST)["error"], "BUSY")

    def test_detached_worker_waits_for_start_to_release_operation_lock(self):
        worker = None
        archive = None

        def launch(_action, identity):
            nonlocal worker
            worker = threading.Thread(target=operation._worker, args=(identity,),
                                      kwargs={"recovery": False})
            worker.start()
            time.sleep(0.05)
            self.assertTrue(worker.is_alive())

        def create(*, identity):
            nonlocal archive
            archive = {"id": identity, "created_at": "2026-10-27T00:00:00+00:00",
                       "layout": "full", "bytes": 512, "files": 3}
            return {"archive": archive}

        with patch.object(operation, "_spawn", side_effect=launch), patch.object(
                operation, "_stop"), patch.object(operation, "_restart"), patch.object(
                operation.backup, "_create_locked", side_effect=create):
            accepted = self._start()
            self.assertEqual(accepted["phase"], "accepted")
            assert worker is not None
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
        self.assertEqual(operation.status(REQUEST)["phase"], "complete")
        self.assertEqual(operation.status(REQUEST)["archive"], archive)

    def test_unexpected_archive_exception_still_restarts(self):
        self._start()
        with patch.object(operation, "_stop"), patch.object(
                operation, "_restart") as restart, patch.object(
                operation.backup, "_create_locked", side_effect=RuntimeError("sensitive detail")), patch.object(
                operation, "_reconcile_archive", return_value=None):
            operation._worker(REQUEST, recovery=False)
        restart.assert_called_once()
        result = operation.status(REQUEST)
        self.assertEqual(result["phase"], "failed")
        self.assertEqual(result["error"], "ARCHIVE_FAILED")
        self.assertNotIn("sensitive detail", str(result))
        self.assertIsNone(operation._active())

    def test_stop_failure_still_restarts_original_stack(self):
        self._start()
        with patch.object(operation, "_stop", side_effect=RuntimeError("stop failed")), patch.object(
                operation, "_restart") as restart, patch.object(
                operation, "_reconcile_archive", return_value=None):
            operation._worker(REQUEST, recovery=False)
        restart.assert_called_once()
        self.assertEqual(operation.status(REQUEST)["phase"], "failed")

    def test_reconcile_removes_only_pinned_incomplete_files(self):
        self._start()
        value = operation._record(REQUEST)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            partial = output / ("." + value["archive_id"] + ".tar.gz.tmp")
            partial.write_bytes(b"private partial")
            partial.chmod(0o600)
            another = output / ("f" * 32 + ".tar.gz")
            another.write_bytes(b"unrelated archive")
            another.chmod(0o600)
            with patch.object(operation.backup, "OUTPUT", output), patch.object(
                    operation.backup, "_output", return_value=output), patch.object(
                    operation.backup, "_sync"):
                self.assertIsNone(operation._reconcile_archive(value))
            self.assertFalse(partial.exists())
            self.assertEqual(another.read_bytes(), b"unrelated archive")

    def test_reconcile_recovers_exact_prepinned_published_archive(self):
        self._start()
        value = operation._record(REQUEST)
        summary = {"id": value["archive_id"], "created_at": "2026-10-27T00:00:00+00:00",
                   "layout": "full", "bytes": 512, "files": 3}
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            for suffix in (".tar.gz", ".manifest.json"):
                item = output / (value["archive_id"] + suffix)
                item.write_bytes(b"safe")
                item.chmod(0o600)
            with patch.object(operation.backup, "OUTPUT", output), patch.object(
                    operation.backup, "_output", return_value=output), patch.object(
                    operation.backup, "_sync"), patch.object(
                    operation.backup, "verify", return_value={"archive": summary}) as verify:
                self.assertEqual(operation._reconcile_archive(value), summary)
            verify.assert_called_once_with(value["archive_id"])

    def test_recover_never_repeats_archive_after_worker_interruption(self):
        self._start()
        value = operation._record(REQUEST)
        operation._phase(value, "archiving")
        with patch.object(operation.subprocess, "run") as run:
            run.return_value.returncode = 3  # transient worker has exited
            result = operation.recover(REQUEST)
        self.assertEqual(result["phase"], "recovery_requested")
        operation._spawn.assert_any_call("recover-run", REQUEST)
        archive = {"id": value["archive_id"], "created_at": "2026-10-27T00:00:00+00:00",
                   "layout": "full", "bytes": 512, "files": 3}
        with patch.object(operation, "_reconcile_archive", return_value=archive), patch.object(
                operation, "_restart") as restart, patch.object(
                operation.backup, "_create_locked") as create:
            operation._worker(REQUEST, recovery=True)
        restart.assert_called_once()
        create.assert_not_called()
        self.assertEqual(operation.status(REQUEST)["phase"], "recovered")
        self.assertEqual(operation.status(REQUEST)["archive"], archive)
        self.assertIsNone(operation._active())

    def test_source_drift_prevents_stop(self):
        self._start()
        with patch.object(operation.backup, "_source_manifest", return_value="f" * 64), patch.object(
                operation, "_stop") as stop:
            operation._worker(REQUEST, recovery=False)
        stop.assert_not_called()
        self.assertEqual(operation.status(REQUEST)["phase"], "failed")
        self.assertEqual(operation.status(REQUEST)["error"], "SOURCE_CHANGED")

    def test_restart_allows_timer_to_activate_known_oneshot_writer(self):
        self._start()
        value = operation._record(REQUEST)

        def capture(args, **_kwargs):
            if "{{.Id}}" in args:
                return "c" * 64 if "c" * 64 in args else "d" * 64
            if "{{.State.Running}}" in args:
                return "true"
            raise AssertionError(args)

        after = {**PLAN, "active_units": [UNIT, "sovagrid-vpn-status.service"]}
        with patch.object(operation.backup, "plan", return_value=after), patch.object(
                operation, "_capture", side_effect=capture), patch.object(
                operation, "_command"), patch.object(operation, "_ready"), patch.object(
                operation.subprocess, "run") as run:
            run.return_value.returncode = 0
            operation._restart(value)

    def test_active_transient_writer_is_not_interrupted(self):
        with patch.object(operation.backup, "plan", return_value={
                **PLAN, "active_units": ["sovagrid-auto-update.service"]}):
            with self.assertRaisesRegex(operation.Refused, "BUSY"):
                self._start()
        self.assertEqual(operation.list_operations()["operations"], [])

    def test_partially_running_compose_stack_is_refused_before_stop(self):
        for services in (["hub"], ["hub", "ssh-gateway"], ["web", "ssh-gateway"]):
            with self.subTest(services=services), patch.object(
                    operation.backup, "plan", return_value={
                        **PLAN, "running_containers": services}):
                with self.assertRaisesRegex(operation.Refused, "DEGRADED_CONTAINERS"):
                    self._start()
        self.assertEqual(operation.list_operations()["operations"], [])

    def test_gateway_journal_stops_and_restarts_exact_original_instances(self):
        self.assertEqual(operation.backup.SSH_GATEWAY_MARKER,
                         operation.update.SSH_GATEWAY_MARKER)
        self.assertEqual(operation.backup.SSH_GATEWAY_MARKER_CONTENT,
                         operation.update.SSH_GATEWAY_MARKER_CONTENT)
        with patch.object(operation.backup, "plan", return_value=GATEWAY_PLAN), patch.object(
                operation, "_container_ids", return_value=GATEWAY_IDS):
            self._start()
        value = operation._record(REQUEST)
        self.assertEqual(value["running_containers"], ["hub", "web", "ssh-gateway"])
        self.assertEqual(value["container_ids"], GATEWAY_IDS)
        offline = {**PLAN, "running_containers": [], "active_units": [],
                   "offline_ready": True}
        with patch.object(operation.backup, "plan", return_value=offline), patch.object(
                operation, "_compose_stop") as stop, patch.object(operation, "_command"):
            operation._stop(value)
        stop.assert_called_once_with(["hub", "web", "ssh-gateway"])

        def capture(args, **_kwargs):
            if "{{.Id}}" in args:
                return args[-1]
            if "{{.State.Running}}" in args:
                return "false"
            if args[:3] == ["docker", "ps", "--quiet"]:
                return ""
            raise AssertionError(args)

        with patch.object(operation.backup, "plan", side_effect=[offline, GATEWAY_PLAN]), \
             patch.object(operation, "_container_ids", return_value=GATEWAY_IDS), \
             patch.object(operation, "_capture", side_effect=capture), \
             patch.object(operation, "_command") as command, \
             patch.object(operation, "_ready") as ready, \
             patch.object(operation.subprocess, "run") as run:
            run.return_value.returncode = 0
            operation._restart(value)
        starts = [entry for entry in command.call_args_list
                  if entry.args[0][:2] == ["docker", "start"]]
        self.assertEqual(starts, [call(["docker", "start", GATEWAY_IDS[service]],
                                        timeout=90)
                                  for service in operation.START_ORDER])
        ready.assert_called_once_with(value)

    def test_readiness_checks_gateway_health_only_when_previously_running(self):
        with patch.object(operation.backup, "plan", return_value=GATEWAY_PLAN), patch.object(
                operation, "_container_ids", return_value=GATEWAY_IDS):
            self._start()
        value = operation._record(REQUEST)
        with patch.object(operation, "_capture", return_value="healthy") as capture, \
             patch.object(operation.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.status = 200
            operation._ready(value)
        inspected = [entry.args[0][-1] for entry in capture.call_args_list]
        self.assertEqual(inspected, [GATEWAY_IDS["hub"], GATEWAY_IDS["ssh-gateway"]])

    def test_gateway_identity_drift_blocks_every_container_start(self):
        with patch.object(operation.backup, "plan", return_value=GATEWAY_PLAN), patch.object(
                operation, "_container_ids", return_value=GATEWAY_IDS):
            self._start()
        value = operation._record(REQUEST)
        offline = {**PLAN, "running_containers": [], "active_units": [],
                   "offline_ready": True}

        def capture(args, **_kwargs):
            if "{{.Id}}" in args:
                return "e" * 64 if args[-1] == GATEWAY_IDS["ssh-gateway"] else args[-1]
            if "{{.State.Running}}" in args:
                return "false"
            if args[:3] == ["docker", "ps", "--quiet"]:
                return ""
            raise AssertionError(args)

        with patch.object(operation.backup, "plan", return_value=offline), \
             patch.object(operation, "_capture", side_effect=capture), \
             patch.object(operation, "_command") as command:
            with self.assertRaisesRegex(operation.Refused, "CONTAINER_CHANGED"):
                operation._restart(value)
        command.assert_not_called()

    def test_spawn_unit_does_not_match_sovagrid_writer_wildcard(self):
        with patch.object(operation.subprocess, "run") as run:
            run.return_value.returncode = 0
            REAL_SPAWN("run", REQUEST)
            unit = run.call_args.args[0][3]
            self.assertEqual(unit, "--unit=sg-host-backup-" + REQUEST)
            REAL_SPAWN("recover-run", REQUEST)
            recovery_unit = run.call_args.args[0][3]
            self.assertEqual(recovery_unit, "--unit=sg-host-backup-recover-" + REQUEST)
            REAL_SPAWN("run", REQUEST, portable=True)
            self.assertIn("--property=RuntimeMaxSec=2700", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
