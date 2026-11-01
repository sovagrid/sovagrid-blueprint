# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deploy import portable_restore_apply as core
from deploy import portable_restore_retry as retry
from deploy import portable_restore_target as target

OP, ARCHIVE, REVIEW = "a" * 32, "b" * 32, "c" * 64


class PreviewContractTest(unittest.TestCase):
    def test_backend_gate_and_physical_readiness_are_independent_and_bound(self):
        base = {"apply_review_sha256": "a" * 64}
        plan = {"bindings": {"resource_manifest_sha256": "b" * 64}}
        with patch.object(core, "APPLY_ENABLED", False):
            disabled = core._full_preview(base, plan, [])
        self.assertTrue(disabled["target_ready"])
        self.assertFalse(disabled["backend_supported"])
        self.assertFalse(disabled["apply_available"])
        self.assertEqual(disabled["blockers"], ["APPLY_NOT_IMPLEMENTED"])
        with patch.object(core, "APPLY_ENABLED", True):
            ready = core._full_preview(base, plan, [])
            blocked = core._full_preview(base, None, ["PUBLIC_ENDPOINT_MISMATCH", "RESTORE_ROUTING_STATE_UNSUPPORTED"])
            next_attempt = core._full_preview(base, plan, [], attempt_revision="d" * 32)
        self.assertTrue(ready["apply_available"])
        self.assertEqual(ready["blockers"], [])
        self.assertFalse(blocked["target_ready"])
        self.assertIn("PUBLIC_ENDPOINT_MISMATCH", blocked["blockers"])
        self.assertNotEqual(ready["apply_review_sha256"], disabled["apply_review_sha256"])
        self.assertNotEqual(ready["apply_review_sha256"], next_attempt["apply_review_sha256"])
        self.assertEqual(ready["policy"]["queued_jobs"], "cancel")


class TargetWorkerTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.receiver = SimpleNamespace(verified_runner=lambda identity: self.root / "runner",
            request_status=lambda identity: {"registered": True, "request_sha256": "d" * 64})
        self.request = {"operation_id": OP, "archive_id": ARCHIVE}
        @contextmanager
        def context(identity):
            self.assertEqual(identity, OP)
            yield self.receiver, None, core, self.request, self.fd
        patches = [patch.object(target, "_context", side_effect=context),
                   patch.object(target, "ROOT_UID", os.getuid()), patch.object(target, "ROOT_GID", os.getgid()),
                   patch.object(core, "APPLY_ENABLED", True), patch.object(core, "host_status", side_effect=core.Refused("RESTORE_NOT_FOUND")),
                   patch.object(core, "host_retry_status", return_value=None),
                   patch.object(core, "preview_host", return_value={"apply_available": True, "apply_review_sha256": REVIEW})]
        for item in patches:
            item.start(); self.addCleanup(item.stop)

    def test_durable_intent_precedes_detach_and_uncertain_start_never_repeats(self):
        starts = []
        def tool(args, **kwargs):
            if args[0].endswith("systemd-run"):
                state = json.loads((self.root / target.CONTROL).read_bytes())
                self.assertEqual(state["phase"], "accepted")
                self.assertIn(str(self.root / "runner/sovagrid-blueprint/deploy/portable_restore_target.py"), args)
                self.assertNotIn("bash", args)
                starts.append(args)
                raise target.Refused("RESTORE_WORKER_START_UNCERTAIN")
            return "inactive"
        with patch.object(target, "_tool", side_effect=tool):
            with self.assertRaisesRegex(target.Refused, "START_UNCERTAIN"):
                target.launch(OP, "apply", REVIEW)
            answer = target.launch(OP, "apply", REVIEW)
        self.assertEqual(len(starts), 1)
        self.assertEqual(answer["phase"], "accepted")

    def test_disabled_gate_starts_no_worker_and_persists_no_intent(self):
        with patch.object(core, "APPLY_ENABLED", False), patch.object(target, "_tool") as tool:
            with self.assertRaisesRegex(target.Refused, "APPLY_NOT_IMPLEMENTED"):
                target.launch(OP, "apply", REVIEW)
            tool.assert_not_called()
        self.assertFalse((self.root / target.CONTROL).exists())

    def test_worker_may_finish_before_systemd_run_acknowledges_without_lock_failure(self):
        starts = []
        def tool(args, **kwargs):
            if args[0].endswith("systemd-run"):
                state = json.loads((self.root / target.CONTROL).read_bytes())
                self.assertEqual(state["phase"], "accepted")
                starts.append(args)
                # Deterministically take both real flock locks in the worker
                # while launch is still on the stack, as Type=exec permits.
                target.worker(OP, "apply", state["worker_nonce"])
            return "inactive"
        with patch.object(target, "_tool", side_effect=tool), patch.object(core, "apply_host") as apply:
            target.launch(OP, "apply", REVIEW)
            target.launch(OP, "apply", REVIEW)  # A delayed duplicate is status only.
        apply.assert_called_once_with(None, ARCHIVE, REVIEW)
        self.assertEqual(len(starts), 1)
        state = json.loads((self.root / target.CONTROL).read_bytes())
        self.assertEqual(state["phase"], "finished")
        self.assertIsNone(state["error"])

    def test_stale_worker_nonce_cannot_apply_and_errors_never_persist_raw_details(self):
        with patch.object(target, "_tool", return_value=""):
            target.launch(OP, "apply", REVIEW)
        state = json.loads((self.root / target.CONTROL).read_bytes())
        with patch.object(core, "apply_host") as apply:
            with self.assertRaisesRegex(target.Refused, "STALE_TARGET_WORKER"):
                target.worker(OP, "apply", "e" * 32)
            apply.assert_not_called()
        def fail(*args):
            self.assertEqual(json.loads((self.root / target.CONTROL).read_bytes())["phase"], "running")
            raise RuntimeError("a private credential must never enter the journal")
        with patch.object(core, "apply_host", side_effect=fail):
            target.worker(OP, "apply", state["worker_nonce"])
        raw = (self.root / target.CONTROL).read_bytes()
        self.assertNotIn(b"private credential", raw)
        self.assertEqual(json.loads(raw)["error"], "RESTORE_WORKER_FAILED")

    def test_frames_reject_arbitrary_command_or_path_before_opening_context(self):
        with patch.object(target, "_context") as context:
            for frame in ({"action": "start", "apply_review_sha256": REVIEW, "command": "true"},
                          {"action": "preview", "path": "/anything"}, {"action": "shell"}):
                with self.assertRaisesRegex(target.Refused, "INVALID_TARGET_ACTION"):
                    target.dispatch_frame(OP, frame)
            context.assert_not_called()

    def test_interrupted_retry_exposes_its_terminal_review_after_live_journal_moved(self):
        retry_state = {"phase": "archiving", "terminal_sha256": REVIEW, "history_id": "e" * 32}
        with patch.object(core, "host_retry_status", return_value=retry_state):
            answer = target.status(OP)
        self.assertEqual(answer["phase"], "retry_required")
        self.assertTrue(answer["retry_available"])
        self.assertTrue(answer["retry_in_progress"])
        self.assertEqual(answer["terminal_sha256"], REVIEW)

    def test_status_reopens_a_control_record_atomically_replaced_by_worker(self):
        with patch.object(target, "_tool", return_value="inactive"):
            target.launch(OP, "apply", REVIEW)
        state = json.loads((self.root / target.CONTROL).read_bytes())
        state["phase"] = "running"
        read = os.read
        replaced = False
        def changing(descriptor, length):
            nonlocal replaced
            raw = read(descriptor, length)
            if not replaced:
                replaced = True
                with target._lock(core, self.fd, ".control.lock"):
                    target._save(core, self.fd, state)
            return raw
        with patch.object(core.os, "read", side_effect=changing):
            answer = target._control(core, self.fd, OP, "d" * 64)
        self.assertEqual(answer["phase"], "running")
        self.assertEqual(answer["worker_nonce"], state["worker_nonce"])


class RetryTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / "stage"
        self.stage.mkdir(mode=0o700)
        (self.root / "var/lib").mkdir(parents=True)
        self.fd = os.open(self.stage, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.journal = core.Journal(self.fd, ARCHIVE, uid=os.getuid(), gid=os.getgid())
        self.restore = SimpleNamespace(_require_root=lambda: None,
            STAGING=self.stage,
            backup=SimpleNamespace(ROOT=self.root, ROOT_UID=os.getuid(), ROOT_GID=os.getgid(),
                _safe_open=lambda path, directory=False: os.open(path, os.O_RDONLY | os.O_NOFOLLOW |
                    (os.O_DIRECTORY if directory else 0))),
            portable_clean_plan=lambda identity: {"target_empty": True, "target_ready": True})
        @contextmanager
        def locks(restore): yield self.fd, None
        def rename(fd, source, destination):
            with self.assertRaises(FileNotFoundError): os.stat(destination, dir_fd=fd, follow_symlinks=False)
            os.rename(source, destination, src_dir_fd=fd, dst_dir_fd=fd)
        for item in (patch.object(core, "transaction_locks", side_effect=locks),
                     patch.object(core, "_rename_noreplace", side_effect=rename)):
            item.start(); self.addCleanup(item.stop)
        class Driver:
            def prepare(self, step): return {"absent": True}
            def execute(self, step, proof): pass
            def verify(self, step, proof): pass
            def undo(self, step, proof): pass
            def health(self, value): raise core.Refused("TEST_HEALTH_FAILURE")
        bindings = {name: hashlib.sha256(name.encode()).hexdigest() for name in core.BINDINGS}
        core.run(self.journal, Driver(), bindings, [{"kind": "group", "resource": "test", "desired": {}}])
        self.terminal = core.status(self.journal)["terminal_sha256"]

    def test_explicit_retry_archives_exact_terminal_inode_and_requires_new_review(self):
        before = (self.stage / self.journal.name).read_bytes()
        answer = retry.retry(self.restore, core, ARCHIVE, self.terminal)
        self.assertTrue(answer["retry_ready"])
        self.assertIsNone(self.journal.read())
        archive = self.stage / (".history-" + ARCHIVE + "-" + answer["history_id"] + "-journal.json")
        self.assertEqual(archive.read_bytes(), before)
        self.assertEqual(retry.retry(self.restore, core, ARCHIVE, self.terminal), answer)

    def test_changed_or_nonempty_target_refuses_without_archiving(self):
        with self.assertRaisesRegex(core.Refused, "RESTORE_RETRY_NOT_TERMINAL"):
            retry.retry(self.restore, core, ARCHIVE, "f" * 64)
        self.restore.portable_clean_plan = lambda identity: {"target_empty": False, "target_ready": False}
        with self.assertRaisesRegex(core.Refused, "RESTORE_TARGET_NOT_READY"):
            retry.retry(self.restore, core, ARCHIVE, self.terminal)
        self.assertIsNotNone(self.journal.read())

    def test_process_death_after_archive_rename_resumes_without_deleting_history(self):
        real = core._rename_noreplace
        class Death(BaseException): pass
        def interrupt(fd, source, destination):
            real(fd, source, destination)
            if destination.endswith("-journal.json"): raise Death()
        with patch.object(core, "_rename_noreplace", side_effect=interrupt):
            with self.assertRaises(Death): retry.retry(self.restore, core, ARCHIVE, self.terminal)
        self.assertIsNone(self.journal.read())
        partial = retry.inspect(self.restore, core, ARCHIVE)
        self.assertEqual(partial["phase"], "archiving")
        self.assertEqual(partial["terminal_sha256"], self.terminal)
        answer = retry.retry(self.restore, core, ARCHIVE, self.terminal)
        self.assertTrue(answer["retry_ready"])
        self.assertEqual(len(list(self.stage.glob(".history-*-journal.json"))), 1)

    def test_corrupt_retry_envelope_refuses_read_and_retry_without_moving_journal(self):
        path = self.stage / (".retry-" + ARCHIVE + ".json")
        path.write_bytes(b"[]\n")
        path.chmod(0o600)
        before = (self.stage / self.journal.name).read_bytes()
        with self.assertRaisesRegex(core.Refused, "INVALID_RESTORE_RETRY"):
            retry.inspect(self.restore, core, ARCHIVE)
        with self.assertRaisesRegex(core.Refused, "INVALID_RESTORE_RETRY"):
            retry.retry(self.restore, core, ARCHIVE, self.terminal)
        self.assertEqual((self.stage / self.journal.name).read_bytes(), before)


if __name__ == "__main__": unittest.main()
