# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Host-side enrollment coordination tests; no network or personal servers."""

from __future__ import annotations

from dataclasses import asdict
import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vendor/connect"))
sys.path.insert(0, str(ROOT / "deploy"))

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect import enrollment_journal
from sovagrid_connect.enrollment_protocol import public_key_fingerprint
from web_agent_jobs import ControllerBinding, JobError, WebAgentJobs
import web_agent_jobs


BEARER = "b" * 43


def ssh_key() -> tuple[str, str]:
    kind = b"ssh-ed25519"
    raw = struct.pack(">I", len(kind)) + kind + struct.pack(">I", 32) + bytes(range(32))
    public = "ssh-ed25519 " + base64.b64encode(raw).decode("ascii")
    return public, public_key_fingerprint(public)


PUBLIC_KEY, FINGERPRINT = ssh_key()


class Credential:
    def __init__(self, secret="test-only-ssh-secret"):
        self.secret = bytearray(secret.encode())
        self.wiped = False

    def wipe(self):
        self.secret[:] = b"\0" * len(self.secret)
        self.wiped = True


class FakeController:
    """Writes valid Connect checkpoints with the same public lifecycle."""

    def __init__(self, journal, target_options, *, stall=None, fail_apply=False):
        self.journal = journal
        self.options = target_options
        self.record = None
        self.stall = stall
        self.entered = threading.Event()
        self.cancelled = threading.Event()
        self.closed = False
        self.fail_apply = fail_apply
        self.resumed_bundle = None

    @staticmethod
    def _connection(options):
        values = asdict(options.validated())
        values.pop("ssh_executable")
        return values

    def _preview(self):
        return {"record": self.record, "hub_fingerprint": FINGERPRINT,
                "platform": {"ubuntu_version": "24.04"}, "source_commits": {}}

    def prepare(self, *, target_options, name, bundle, hub_host, hub_port,
                local_port, session_token):
        assert session_token == BEARER
        assert target_options == self.options
        request_id = str(uuid.uuid4())
        self.record = self.journal.create({
            "protocol": 1, "request_id": request_id, "name": name,
            "phase": "prepared", "hub_connection": self._connection(
                ConnectionOptions(host="hub.example", user="root", local_port=18766)),
            "target_connection": self._connection(self.options),
            "hub_endpoint": {"host": hub_host, "port": hub_port, "local_port": local_port},
            "bundle": {"path": str(bundle), "sha256": hashlib.sha256(Path(bundle).read_bytes()).hexdigest()},
            "target": None, "registration": None, "hub_trust": None,
            "hub_authorized": False, "cleanup_required": False,
            "cas": {"hub": None, "target": None}, "stage": None,
        })
        self.entered.set()
        if self.stall is not None:
            while not self.stall.wait(0.01):
                if self.cancelled.is_set():
                    raise RuntimeError("private-ssh-secret should never leave the coordinator")
        return self._preview()

    def resume(self, request_id, *, session_token, target_identity, jump_identity, bundle_path):
        assert session_token == BEARER
        assert Path(bundle_path).exists()
        self.resumed_bundle = Path(bundle_path)
        self.record = self.journal.load(request_id)
        assert self.record is not None
        connection = dict(self.record["target_connection"])
        connection["identity"] = target_identity
        connection["jump_identity"] = jump_identity
        if connection != self.record["target_connection"]:
            self.record = self.journal.update(request_id, {"target_connection": connection},
                                              expected_revision=self.record["revision"])
        return self._preview()

    def apply(self):
        assert self.record is not None
        if self.fail_apply:
            self.record = self.journal.update(self.record["request_id"],
                {"cleanup_required": True}, expected_revision=self.record["revision"])
            raise RuntimeError("borrowed-bearer-should-not-appear-in-status")
        enrollment_id = str(uuid.uuid4())
        server_id = str(uuid.uuid4())
        target = {"request_id": self.record["request_id"], "enrollment_id": enrollment_id,
                  "server_id": server_id, "phase": "active",
                  "agent_token_sha256": "a" * 64, "ssh_public_key": PUBLIC_KEY,
                  "ssh_key_fingerprint": FINGERPRINT,
                  "local_port": self.record["hub_endpoint"]["local_port"]}
        registration = {"id": enrollment_id, "server_id": server_id,
                        "name": self.record["name"], "state": "active",
                        "revision": 1, "created_at": 100, "last_seen": 101}
        self.record = self.journal.update(self.record["request_id"],
            {"phase": "active", "target": target, "registration": registration},
            expected_revision=self.record["revision"])
        return self.record

    def cleanup(self):
        assert self.record is not None
        self.journal.remove(self.record["request_id"], expected_revision=self.record["revision"])
        self.record = None
        return {"removed": True, "active": False}

    def cancel(self):
        self.cancelled.set()

    def close(self):
        self.closed = True


class JobsTests(unittest.TestCase):
    def setUp(self):
        # macOS /tmp is a symlink; Connect's journal intentionally rejects it.
        trusted_tmp = "/private/tmp" if Path("/private/tmp").is_dir() else "/tmp"
        self.directory = tempfile.TemporaryDirectory(dir=trusted_tmp)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        contents = b"fixture bundle, not a real installer"
        self.sha = hashlib.sha256(contents).hexdigest()
        self.bundle = self.root / f"source-{self.sha}.tar.gz"
        self.bundle.write_bytes(contents)
        self.bundle.chmod(0o600)
        self.created = []
        self.controller_created = threading.Event()
        self.fail_apply = False
        self.stall = None

    def factory(self, *, target_options, fingerprint, credential, journal, progress):
        self.assertEqual(fingerprint, FINGERPRINT)
        self.assertTrue(callable(progress))
        self.assertIsInstance(credential, Credential)
        controller = FakeController(journal, target_options, stall=self.stall,
                                    fail_apply=self.fail_apply)
        self.created.append(controller)
        self.controller_created.set()
        return ControllerBinding(controller=controller, target_options=target_options,
                                 close_transport=lambda: None)

    def jobs(self):
        jobs = WebAgentJobs(journal_root=self.root / "journal", bundle_path=self.bundle,
                            bundle_sha256=self.sha, controller_factory=self.factory,
                            root_check=lambda: True)
        self.addCleanup(jobs.close)
        return jobs

    def options(self, alias=None):
        return ConnectionOptions(host="target.example", user="root", host_key_alias=alias)

    def prepare(self, jobs, credential=None):
        return jobs.prepare(target_options=self.options(), reviewed_fingerprint=FINGERPRINT,
            credential=credential or Credential(), session_token=BEARER,
            name="test target", hub_host="192.0.2.40", hub_port=22, local_port=18767)

    def assert_secretless(self, jobs):
        status = json.dumps(jobs.list(), sort_keys=True)
        raw = "".join(path.read_text() for path in (self.root / "journal").glob("*.json"))
        for secret in (BEARER, "test-only-ssh-secret", "borrowed-bearer-should-not-appear-in-status"):
            self.assertNotIn(secret, status + raw)

    def test_prepare_review_apply_and_secretless_checkpoint(self):
        jobs = self.jobs()
        credential = Credential()
        review = self.prepare(jobs, credential)
        self.assertEqual(review["phase"], "prepared")
        self.assertTrue(review["writes"])
        self.assertFalse(review["activation_writes"])
        self.assertEqual(review["revision"], 1)
        self.assertEqual(jobs.status(review["request_id"])["request_id"], review["request_id"])
        self.assert_secretless(jobs)
        active = jobs.apply(review["request_id"], review["revision"])
        self.assertEqual(active["phase"], "active")
        self.assertFalse(active["recoverable"])
        self.assertTrue(credential.wiped)
        self.assertTrue(self.created[0].closed)
        self.assert_secretless(jobs)

    def test_restart_requires_fresh_review_and_credential(self):
        first = self.jobs()
        old = Credential()
        review = self.prepare(first, old)
        first.close()
        self.assertTrue(old.wiped)
        second = self.jobs()
        self.assertTrue(second.status(review["request_id"])["recoverable"])
        with self.assertRaises(JobError) as raised:
            second.apply(review["request_id"], review["revision"])
        self.assertEqual(raised.exception.code, "RESUME_REQUIRED")
        wrong = Credential()
        with self.assertRaises(JobError) as raised:
            second.resume(review["request_id"], target_options=self.options(),
                reviewed_fingerprint="SHA256:" + "A" * 43,
                credential=wrong, session_token=BEARER)
        self.assertEqual(raised.exception.code, "HOST_KEY_MISMATCH")
        self.assertTrue(wrong.wiped)
        self.assertEqual(len(self.created), 1)  # Wrong host key did not start SSH.
        fresh = Credential()
        resumed = second.resume(review["request_id"], target_options=self.options(),
            reviewed_fingerprint=FINGERPRINT, credential=fresh, session_token=BEARER)
        self.assertEqual(resumed["request_id"], review["request_id"])
        self.assertEqual(resumed["revision"], review["revision"])
        second.apply(resumed["request_id"], resumed["revision"])
        self.assertTrue(fresh.wiped)
        self.assert_secretless(second)

    def test_failed_apply_is_recoverable_and_cleanup_is_explicit(self):
        self.fail_apply = True
        jobs = self.jobs()
        credential = Credential()
        review = self.prepare(jobs, credential)
        with self.assertRaises(JobError) as raised:
            jobs.apply(review["request_id"], review["revision"])
        self.assertEqual(raised.exception.code, "APPLY_UNCERTAIN")
        self.assertTrue(credential.wiped)
        checkpoint = jobs.status(review["request_id"])
        self.assertTrue(checkpoint["cleanup_required"])
        self.assertGreater(checkpoint["revision"], review["revision"])
        self.assert_secretless(jobs)
        cleanup_credential = Credential()
        resumed = jobs.resume(review["request_id"], target_options=self.options(),
            reviewed_fingerprint=FINGERPRINT, credential=cleanup_credential,
            session_token=BEARER)
        outcome = jobs.cleanup(resumed["request_id"], resumed["revision"])
        self.assertTrue(outcome["removed"])
        self.assertTrue(cleanup_credential.wiped)
        self.assertEqual(jobs.list(), [])

    def test_interrupt_and_other_coordinator_cannot_mutate_concurrently(self):
        self.stall = threading.Event()
        first = self.jobs()
        second = self.jobs()
        result = {}
        def run_prepare():
            try:
                result["review"] = self.prepare(first)
            except JobError as error:
                result["error"] = error
        worker = threading.Thread(target=run_prepare)
        worker.start()
        self.assertTrue(self.controller_created.wait(3))
        self.assertTrue(self.created[0].entered.wait(3))
        other_credential = Credential()
        with self.assertRaises(JobError) as raised:
            self.prepare(second, other_credential)
        self.assertEqual(raised.exception.code, "BUSY")
        self.assertTrue(other_credential.wiped)
        self.assertTrue(first.interrupt()["cancel_requested"])
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result["error"].code, "PREPARE_UNCERTAIN")
        request_id = result["error"].request_id
        self.assertEqual(first.status(request_id)["phase"], "prepared")
        first.close()
        self.assert_secretless(second)

    def test_cas_and_bundle_pin_fail_closed(self):
        jobs = self.jobs()
        review = self.prepare(jobs)
        with self.assertRaises(JobError) as raised:
            jobs.apply(review["request_id"], review["revision"] + 1)
        self.assertEqual(raised.exception.code, "STALE_REVISION")
        jobs.close()
        self.bundle.write_bytes(b"replaced")
        new_jobs = self.jobs()
        credential = Credential()
        with self.assertRaises(JobError) as raised:
            new_jobs.resume(review["request_id"], target_options=self.options(),
                reviewed_fingerprint=FINGERPRINT, credential=credential,
                session_token=BEARER)
        self.assertEqual(raised.exception.code, "SOURCE_UNTRUSTED")
        self.assertTrue(credential.wiped)
        self.assert_secretless(new_jobs)

    def test_invalid_factory_binding_closes_transport_and_wipes_secret(self):
        closed = []
        def invalid_factory(*, target_options, fingerprint, credential, journal, progress):
            controller = FakeController(journal, target_options)
            closed.append(controller)
            changed = ConnectionOptions(**{**asdict(target_options), "port": 2222})
            return ControllerBinding(controller=controller, target_options=changed,
                                     close_transport=lambda: closed.append("transport closed"))
        jobs = WebAgentJobs(journal_root=self.root / "journal", bundle_path=self.bundle,
            bundle_sha256=self.sha, controller_factory=invalid_factory, root_check=lambda: True)
        self.addCleanup(jobs.close)
        credential = Credential()
        with self.assertRaises(JobError) as raised:
            self.prepare(jobs, credential)
        self.assertEqual(raised.exception.code, "INVALID_FACTORY")
        self.assertTrue(credential.wiped)
        self.assertTrue(closed[0].closed)
        self.assertEqual(closed[1], "transport closed")
        self.assertEqual(jobs.list(), [])

    def test_idle_lease_expires_and_drops_live_secret(self):
        now = [100.0]
        jobs = WebAgentJobs(journal_root=self.root / "journal", bundle_path=self.bundle,
            bundle_sha256=self.sha, controller_factory=self.factory,
            root_check=lambda: True, monotonic=lambda: now[0])
        self.addCleanup(jobs.close)
        credential = Credential()
        review = self.prepare(jobs, credential)
        now[0] += 601
        jobs._expire_live(jobs._live)
        self.assertTrue(credential.wiped)
        self.assertTrue(self.created[0].closed)
        with self.assertRaises(JobError) as raised:
            jobs.apply(review["request_id"], review["revision"])
        self.assertEqual(raised.exception.code, "RESUME_REQUIRED")
        self.assertTrue(jobs.status(review["request_id"])["recoverable"])

    def test_pending_job_resumes_with_old_content_addressed_bundle_after_update(self):
        first = self.jobs()
        review = self.prepare(first)
        first.close()
        old_bundle = self.bundle
        new_bytes = b"updated source bundle fixture"
        new_sha = hashlib.sha256(new_bytes).hexdigest()
        new_bundle = self.root / f"source-{new_sha}.tar.gz"
        new_bundle.write_bytes(new_bytes)
        new_bundle.chmod(0o600)
        second = WebAgentJobs(journal_root=self.root / "journal", bundle_path=new_bundle,
            bundle_sha256=new_sha, controller_factory=self.factory, root_check=lambda: True)
        self.addCleanup(second.close)
        self.assertEqual(second.status(review["request_id"])["phase"], "prepared")
        resumed = second.resume(review["request_id"], target_options=self.options(),
            reviewed_fingerprint=FINGERPRINT, credential=Credential(), session_token=BEARER)
        self.assertEqual(self.created[-1].resumed_bundle, old_bundle)
        self.assertTrue(second.cleanup(resumed["request_id"], resumed["revision"])["removed"])
        self.assertTrue(old_bundle.exists())  # A separate safe GC may remove it later.

    def test_resume_rejects_journal_bundle_outside_private_directory(self):
        first = self.jobs()
        review = self.prepare(first)
        first.close()
        outside = self.root.parent / f"source-{self.sha}.tar.gz"
        record = first.journal.load(review["request_id"])
        first.journal.update(review["request_id"],
            {"bundle": {"path": str(outside), "sha256": self.sha}},
            expected_revision=record["revision"])
        second = self.jobs()
        credential = Credential()
        with self.assertRaises(JobError) as raised:
            second.resume(review["request_id"], target_options=self.options(),
                reviewed_fingerprint=FINGERPRINT, credential=credential, session_token=BEARER)
        self.assertEqual(raised.exception.code, "SOURCE_UNTRUSTED")
        self.assertTrue(credential.wiped)

    def test_completed_enrollments_archive_before_pruning_and_never_prune_pending(self):
        with patch.object(enrollment_journal, "MAX_RECORDS", 4):
            jobs = self.jobs()
            completed = []
            for _ in range(6):
                prepared = self.prepare(jobs)
                completed.append(jobs.apply(prepared["request_id"], prepared["revision"]))
            archive = self.root / "completed-enrollments.jsonl"
            self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(jobs.list()), 3)
            verification = jobs.verify_completed_archive()
            self.assertEqual(verification["records"], 3)
            archived_ids = [json.loads(line)["record"]["request_id"]
                            for line in archive.read_text().splitlines()]
            self.assertEqual(len(set(archived_ids)), 3)
            self.assertEqual(set(archived_ids) | {row["request_id"] for row in jobs.list()},
                             {row["request_id"] for row in completed})
            for request_id in archived_ids:
                with self.assertRaises(JobError) as error:
                    jobs.status(request_id)
                self.assertEqual(error.exception.code, "NOT_FOUND")
            pending = self.prepare(jobs)
            with self.assertRaises(JobError) as error:
                self.prepare(jobs)
            self.assertEqual(error.exception.code, "RECOVERY_REQUIRED")
            self.assertEqual(error.exception.request_id, pending["request_id"])
            self.assertEqual(jobs.verify_completed_archive()["records"], 4)
            self.assert_secretless(jobs)
            self.assertNotIn(BEARER, archive.read_text())

    def test_crash_after_durable_archive_retries_without_duplicate(self):
        with patch.object(enrollment_journal, "MAX_RECORDS", 4):
            jobs = self.jobs()
            for _ in range(3):
                prepared = self.prepare(jobs)
                jobs.apply(prepared["request_id"], prepared["revision"])
            with patch.object(jobs.journal, "remove", side_effect=enrollment_journal.EnrollmentJournalError("interrupted")):
                with self.assertRaises(JobError) as error:
                    self.prepare(jobs)
            self.assertEqual(error.exception.code, "JOURNAL_UNAVAILABLE")
            self.assertEqual(jobs.verify_completed_archive()["records"], 1)
            self.assertEqual(len(jobs.list()), 3)
            prepared = self.prepare(jobs)
            self.assertEqual(prepared["phase"], "prepared")
            self.assertEqual(jobs.verify_completed_archive()["records"], 1)
            self.assertEqual(len(jobs.list()), 3)

    def test_archive_capacity_refuses_new_prepare_without_remote_writes(self):
        with patch.object(enrollment_journal, "MAX_RECORDS", 4):
            jobs = self.jobs()
            for _ in range(4):
                prepared = self.prepare(jobs)
                jobs.apply(prepared["request_id"], prepared["revision"])
            archive = self.root / "completed-enrollments.jsonl"
            before = archive.read_bytes()
            controllers = len(self.created)
            credential = Credential()
            with patch.object(web_agent_jobs, "_ARCHIVE_MAX_BYTES", len(before) + 1):
                with self.assertRaises(JobError) as error:
                    self.prepare(jobs, credential)
            self.assertEqual(error.exception.code, "ARCHIVE_FULL")
            self.assertTrue(credential.wiped)
            self.assertEqual(len(self.created), controllers)
            self.assertEqual(len(jobs.list()), 3)
            self.assertEqual(archive.read_bytes(), before)

    def test_archive_tamper_fails_closed_and_incomplete_append_recovers(self):
        with patch.object(enrollment_journal, "MAX_RECORDS", 4):
            jobs = self.jobs()
            for _ in range(4):
                prepared = self.prepare(jobs)
                jobs.apply(prepared["request_id"], prepared["revision"])
            archive = self.root / "completed-enrollments.jsonl"
            self.assertEqual(jobs.verify_completed_archive()["records"], 1)
            with archive.open("ab") as stream:
                stream.write(b'{"partial":')
                stream.flush(); os.fsync(stream.fileno())
            for _ in range(2):
                prepared = self.prepare(jobs)
                jobs.apply(prepared["request_id"], prepared["revision"])
            self.assertEqual(jobs.verify_completed_archive()["records"], 3)
            raw = archive.read_bytes()
            archive.write_bytes(raw.replace(b'"active"', b'"broken"', 1))
            with self.assertRaises(JobError) as error:
                jobs.verify_completed_archive()
            self.assertEqual(error.exception.code, "ARCHIVE_UNSAFE")


if __name__ == "__main__":
    unittest.main()
