# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Bounded real cache writes and durable, credential-free Web orchestration."""
from copy import deepcopy
from contextlib import nullcontext
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
sys.path.insert(0, str(ROOT / "vendor/connect"))
from web_restore import (BrowserImports, CHUNK, ORDER, PrivateStore, PROTOCOL,
                         RestoreError, TARGET, WebRestoreJobs, canonical, digest)
from sovagrid_connect.core import ConnectionOptions


SOURCE, ARCHIVE, OP = "a" * 32, "b" * 32, "c" * 32
FINGERPRINT = "SHA256:" + "A" * 43


def metadata(data):
    return {part: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} for part, raw in data.items()}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = PrivateStore(self.root / "metadata", os.getuid(), os.getgid())
        self.spool = PrivateStore(self.root / "cache", os.getuid(), os.getgid())
        self.imports = BrowserImports(self.store, self.spool)
        self.data = {part: (part.encode() + b"\0\xff\n") * 10 for part in ORDER}
        self.data["host"] = bytes(range(256)) * (CHUNK // 256) + b"final tail"
        self.request = {"source_id": SOURCE, "archive_id": ARCHIVE, "artifacts": metadata(self.data)}
        self.imports.init(self.request)

    def chunk(self, part, offset=0, length=None):
        raw = self.data[part][offset:offset + (length or CHUNK)]
        return {"source_id": SOURCE, "part": part, "offset": offset, "length": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()}, raw

    def upload(self):
        for part, raw in self.data.items():
            for offset in range(0, len(raw), CHUNK):
                request, block = self.chunk(part, offset)
                self.imports.receive(request, block)

    def test_real_four_mib_chunks_resume_and_duplicate_ack_without_copying_bytes_into_state(self):
        request, block = self.chunk("host")
        first = self.imports.receive(request, block)
        self.assertEqual(first["artifacts"]["host"]["received"], CHUNK)
        self.assertEqual(self.imports.receive(request, block), first)
        self.upload()
        state = self.imports.status(SOURCE)
        self.assertTrue(state["complete"])
        archive, actual, paths = self.imports.paths(SOURCE)
        self.assertEqual(archive, ARCHIVE)
        self.assertEqual(actual, self.request["artifacts"])
        for part, path in paths.items():
            self.assertEqual(path.read_bytes(), self.data[part])
            self.assertTrue(path.is_relative_to(self.spool.root))
        self.assertLess(sum(p.stat().st_size for p in self.store.root.rglob("*") if p.is_file()), 10000)
        self.assertNotIn("final tail", (self.store.root / "imports" / SOURCE / "state.json").read_text())

    def test_process_loss_after_fsynced_bytes_resumes_the_exact_pending_chunk(self):
        original = self.store.write
        failed = False

        def crash(folder, state, **kwargs):
            nonlocal failed
            if state.get("files", {}).get("host", {}).get("received") == CHUNK and not failed:
                failed = True
                raise OSError("injected crash before ack publication")
            return original(folder, state, **kwargs)

        request, block = self.chunk("host")
        with patch.object(self.store, "write", crash), self.assertRaises(OSError):
            self.imports.receive(request, block)
        before = self.imports.status(SOURCE)
        self.assertEqual(before["artifacts"]["host"]["received"], 0)
        self.assertEqual(before["pending_chunk"]["sha256"], request["sha256"])
        after = BrowserImports(self.store, self.spool).receive(request, block)
        self.assertEqual(after["artifacts"]["host"]["received"], CHUNK)
        self.assertIsNone(after["pending_chunk"])

    def test_lost_excluded_cache_can_be_reuploaded_using_the_durable_hashes(self):
        self.upload()
        shutil.rmtree(self.spool.root)
        status = self.imports.status(SOURCE)
        self.assertFalse(status["complete"])
        self.assertTrue(all(item["received"] == 0 for item in status["artifacts"].values()))
        self.upload()
        self.assertTrue(self.imports.status(SOURCE)["complete"])

    def test_space_reservation_uses_the_bulk_cache_filesystem(self):
        source = "d" * 32
        with patch("web_restore.os.statvfs", return_value=type("Space", (), {"f_bavail": 0, "f_frsize": 4096})()) as space:
            with self.assertRaisesRegex(RestoreError, "INSUFFICIENT_SPACE"):
                self.imports.init({**self.request, "source_id": source})
        self.assertEqual(space.call_args.args, (self.spool.root,))

    def test_changed_input_and_offsets_refuse_before_overwriting_a_received_prefix(self):
        request, block = self.chunk("host")
        self.imports.receive(request, block)
        changed = {**request, "sha256": hashlib.sha256(b"x" * len(block)).hexdigest()}
        with self.assertRaises(RestoreError):
            self.imports.receive(changed, b"x" * len(block))
        with self.assertRaises(RestoreError):
            self.imports.receive({**request, "offset": True}, block)
        path = self.spool.root / "imports" / SOURCE / (ARCHIVE + ".tar.gz")
        self.assertEqual(path.read_bytes(), block)

    def test_delete_removes_only_the_explicit_import_cache_and_metadata(self):
        self.upload()
        result = self.imports.delete(SOURCE)
        self.assertTrue(result["deleted"])
        self.assertFalse((self.spool.root / "imports" / SOURCE).exists())
        self.assertFalse((self.store.root / "imports" / SOURCE).exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "requires symlinks")
    def test_symlink_at_a_fixed_cache_filename_never_modifies_its_target(self):
        original = self.root / "original"
        original.write_bytes(b"foreign private contents")
        path = self.spool.root / "imports" / SOURCE / (ARCHIVE + ".tar.gz")
        path.symlink_to(original)
        request, block = self.chunk("host")
        with self.assertRaises((OSError, RestoreError)):
            self.imports.receive(request, block)
        self.assertEqual(original.read_bytes(), b"foreign private contents")


class FakeCredential:
    method, password, private_key, passphrase = "password", "private-test-secret", "", ""
    jump = None
    target_host_key_blob = ""


def target(record, phase="review", available=True):
    request = record["request"]
    return {"ok": True, "protocol": TARGET, "operation_id": record["operation_id"],
            "archive_id": request["archive_id"], "request_sha256": digest(request), "registered": True,
            "phase": phase, "backend_supported": True, "target_ready": available,
            "apply_available": available, "blockers": [], "apply_review_sha256": "e" * 64 if available else None,
            "worker_active": phase == "accepted", "retry_available": phase == "rolled_back", "error": None}


class JobTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = PrivateStore(self.root / "state", os.getuid(), os.getgid())
        self.spool = PrivateStore(self.root / "spool", os.getuid(), os.getgid())
        self.bundle = self.root / "runner.tar.gz"
        with tarfile.open(self.bundle, "w:gz") as archive:
            raw = b'{"format":1}\n'; item = tarfile.TarInfo("sovagrid-bundle.json"); item.size = len(raw)
            archive.addfile(item, io.BytesIO(raw))
        self.calls, self.transports = [], []
        self.fail_start = False
        owner = self

        class Transport:
            def __init__(self, **kwargs):
                self.kwargs = kwargs; owner.transports.append(self)
            def __enter__(self): return self
            def __exit__(self, *args): self.close()
            def close(self): self.kwargs = {}
            def restore_controller(self, **kwargs):
                class Controller:
                    def prepare(self, folder, runner, *, record):
                        owner.calls.append(("prepare", record["operation_id"]))
                        kwargs["store"].save(record)
                        kwargs["progress"]("Передача копии")
                        return record, target(record)
                    def action(self, record, action, **values):
                        owner.calls.append((action, values))
                        if action == "start" and owner.fail_start:
                            owner.fail_start = False
                            raise OSError("lost acknowledgment")
                        return target(record, "accepted", False)
                    def cancel(self): pass
                return Controller()

        self.meta = {part: {"bytes": 1, "sha256": "f" * 64} for part in ORDER}
        self.jobs = WebRestoreJobs(self.bundle, hashlib.sha256(self.bundle.read_bytes()).hexdigest(),
            store=self.store, spool=self.spool, transport_factory=Transport,
            source_resolver=lambda _id: (ARCHIVE, deepcopy(self.meta), {}))
        self.options = ConnectionOptions("server.example.com", user="ubuntu").validated()
        self.authorized = []

    def args(self):
        return {"options": self.options, "fingerprint": FINGERPRINT, "credential": FakeCredential(),
                "authorize": lambda: self.authorized.append(True)}

    def prepared(self):
        self.jobs.prepare(OP, {"kind": "backup", "id": SOURCE}, **self.args())
        deadline = time.monotonic() + 3
        while self.jobs.status(OP)["worker_active"] and time.monotonic() < deadline:
            time.sleep(.005)
        value = self.jobs.status(OP)
        self.assertFalse(value["worker_active"])
        self.assertEqual(value["phase"], "review", value)
        return value

    def test_background_prepare_persists_only_pins_and_metadata_and_rechecks_role(self):
        value = self.prepared()
        self.assertEqual(value["route"]["host"], "server.example.com")
        self.assertTrue(value["target"]["apply_available"])
        self.assertGreaterEqual(len(self.authorized), 3)
        raw = (self.store.root / "operations" / OP / "state.json").read_bytes()
        self.assertNotIn(b"private-test-secret", raw)
        self.assertNotIn(b'"password"', raw)
        self.assertNotIn(b'"session_token"', raw)
        self.assertEqual(self.transports[0].kwargs, {})

    def test_lost_start_reply_is_followed_by_status_and_never_repeats_forward_apply(self):
        value = self.prepared(); self.fail_start = True
        args = {**self.args(), "expected_revision": value["expected_revision"], "apply_review_sha256": "e" * 64}
        with self.assertRaisesRegex(RestoreError, "RESTORE_RESPONSE_UNCERTAIN"):
            self.jobs.control(OP, "start", **args)
        result = self.jobs.control(OP, "start", **args)
        self.assertEqual(result["target"]["phase"], "accepted")
        self.assertEqual(sum(name == "start" for name, _ in self.calls), 1)
        self.assertEqual(self.calls[-1][0], "operation-status")

    def test_route_or_review_change_refuses_without_a_remote_action(self):
        value = self.prepared(); before = len(self.calls)
        args = self.args(); args["options"] = ConnectionOptions("other.example.com", user="ubuntu")
        with self.assertRaisesRegex(RestoreError, "TARGET_CHANGED"):
            self.jobs.control(OP, "inspect", **args)
        with self.assertRaisesRegex(RestoreError, "STALE_REVISION"):
            self.jobs.control(OP, "start", **self.args(), expected_revision="0" * 64, apply_review_sha256="e" * 64)
        self.assertEqual(len(self.calls), before)

    def test_status_and_recovery_do_not_need_the_source_backup_to_still_exist(self):
        self.prepared()
        self.jobs.source_resolver = lambda _id: (_ for _ in ()).throw(OSError("source was removed"))
        result = self.jobs.control(OP, "inspect", **self.args())
        self.assertEqual(result["target"]["phase"], "accepted")

    def test_restored_inactive_worker_is_reported_as_resume_required(self):
        self.prepared()
        folder = self.store.folder("operations", OP)
        state = self.store.read(folder); state["phase"] = "preparing"; self.store.write(folder, state)
        self.assertEqual(self.jobs.status(OP)["phase"], "resume_required")

    def test_unadvertised_directory_does_not_break_history_and_capacity_refuses_before_source_read(self):
        self.prepared()
        for number in range(127):
            self.store.folder("operations", f"{number:032x}", True)
        self.assertEqual(len(self.jobs.list()["operations"]), 1)
        self.jobs.source_resolver = lambda _id: self.fail("capacity failure read source bytes")
        with self.assertRaisesRegex(RestoreError, "ARCHIVE_FULL"):
            self.jobs.prepare("d" * 32, {"kind": "backup", "id": SOURCE}, **self.args())
        self.assertFalse((self.store.root / "operations" / ("d" * 32)).exists())

    def test_explicit_cache_removal_after_failed_prepare_preserves_the_remote_operation_record(self):
        self.prepared()
        imported = {"source_id": SOURCE, "archive_id": ARCHIVE, "artifacts": self.meta}
        self.jobs.imports.init(imported)
        folder = self.store.folder("operations", OP)
        state = self.store.read(folder)
        state.update(source={"kind": "upload", "id": SOURCE}, target=None, phase="resume_required")
        self.store.write(folder, state)
        self.assertTrue(self.jobs.delete_import(SOURCE)["deleted"])
        self.assertTrue((folder / "state.json").exists())
        self.assertEqual(self.jobs.status(OP)["phase"], "resume_required")


class SocketFrameTests(unittest.TestCase):
    setUp = StoreTests.setUp
    chunk = StoreTests.chunk

    def exchange(self, header, raw=b"", *, allowed=True):
        import web_agent_service as service
        left, right = socket.socketpair()
        calls = []

        def authorize(token):
            calls.append(token)
            if not allowed:
                raise service.RequestError("AUTH_REQUIRED")

        class Restore:
            imports = self.imports

        thread = threading.Thread(target=lambda: service._handle(left, None, peer_uid=10003,
            authorize=authorize, restore=Restore()), daemon=True)
        with patch.object(service, "_stable_public_web", nullcontext):
            thread.start()
            with right:
                right.settimeout(5)
                right.sendall(canonical(header) + raw)
                right.shutdown(socket.SHUT_WR)
                incoming = bytearray()
                while not incoming.endswith(b"\n"):
                    block = right.recv(4096)
                    if not block: break
                    incoming.extend(block)
            thread.join(5)
        self.assertFalse(thread.is_alive())
        return json.loads(incoming), calls

    def test_actual_service_header_and_binary_share_one_socket_without_json_expansion(self):
        request, raw = self.chunk("host")
        response, calls = self.exchange({"action": "restore-import-chunk", "session_token": "t" * 43,
                                         "payload": request}, raw)
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["result"]["artifacts"]["host"]["received"], CHUNK)
        self.assertEqual(len(calls), 2)

    def test_revoked_caller_is_refused_before_any_binary_write(self):
        request, raw = self.chunk("host")
        response, calls = self.exchange({"action": "restore-import-chunk", "session_token": "t" * 43,
                                         "payload": request}, allowed=False)
        self.assertEqual(response, {"ok": False, "error": "AUTH_REQUIRED"})
        self.assertEqual(self.imports.status(SOURCE)["artifacts"]["host"]["received"], 0)


class RunnerPinRetentionTests(unittest.TestCase):
    def test_old_runner_pin_is_retained_from_small_durable_restore_metadata(self):
        import web_agent_bundle as bundle
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            operations = root / "restores" / "operations"
            operations.mkdir(parents=True, mode=0o700)
            operations.parent.chmod(0o700)
            folder = operations / OP; folder.mkdir(mode=0o700)
            state = {"protocol": PROTOCOL, "operation_id": OP,
                     "record": {"operation_id": OP, "runner_path": str(root / ("source-" + "f" * 64 + ".tar.gz")),
                                "request": {"operation_id": OP, "runner_archive_sha256": "f" * 64}}}
            path = folder / "state.json"; path.write_bytes(canonical(state)); path.chmod(0o600)
            self.assertEqual(bundle._restore_bundle_pins(root, os.getuid()), {root / ("source-" + "f" * 64 + ".tar.gz")})
            state["record"]["runner_path"] = "/somewhere/else"
            path.write_bytes(canonical(state))
            self.assertIsNone(bundle._restore_bundle_pins(root, os.getuid()))


if __name__ == "__main__":
    unittest.main()
