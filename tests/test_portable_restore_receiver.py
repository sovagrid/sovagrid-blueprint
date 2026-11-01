# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Real private files, interrupted streams and closed restore registration."""
from contextlib import ExitStack
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deploy import portable_restore_receiver as receiver
from deploy import host_restore as restore
from deploy import host_image_export as images
from tests import test_host_restore as host_fixture
from tests.test_host_image_export import image_archive


OP, ARCHIVE = "a" * 32, "b" * 32


class PowerLoss(BaseException):
    pass


class ReceiverTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ("root", "root/.sovagrid-restore", "root/.sovagrid-restore/" + OP):
            target = self.root / name
            target.mkdir(mode=0o700)
            target.chmod(0o700)
        for name in ("run", "var", "var/lib"):
            target = self.root / name
            target.mkdir(mode=0o755)
            target.chmod(0o755)
        self.operation = self.root / "root/.sovagrid-restore" / OP
        self.runner = self.operation / "runner"
        self.runner.mkdir(mode=0o755)
        self.runner.chmod(0o755)
        hashes, components = {}, {}
        for name in sorted(receiver.COMPONENTS):
            folder = self.runner / name
            folder.mkdir(mode=0o755)
            folder.chmod(0o755)
            raw = (name + " trusted runner fixture\n").encode()
            (folder / "README").write_bytes(raw)
            (folder / "README").chmod(0o644)
            hashes[name + "/README"] = hashlib.sha256(raw).hexdigest()
            components[name] = {"commit": "c" * 40, "file_count": 1}
        raw = receiver._canonical({"format": 1, "components": components, "sha256": hashes})
        manifest = self.runner / "sovagrid-bundle.json"
        manifest.write_bytes(raw)
        manifest.chmod(0o644)
        self.runner_record = {"protocol": "sovagrid-portable-restore-runner-v1", "operation_id": OP,
            "runner_bytes": 1024, "runner_archive_sha256": "d" * 64,
            "runner_manifest_sha256": hashlib.sha256(raw).hexdigest(), "dependencies_ready": True}
        self.write_json(self.operation / "runner.json", self.runner_record)
        for context in (patch.object(receiver, "ROOT", self.root),
                        patch.object(receiver, "UID", os.getuid()), patch.object(receiver, "GID", os.getgid())):
            context.start()
            self.addCleanup(context.stop)
        if not sys.platform.startswith("linux"):
            context = patch.object(receiver, "_rename", side_effect=self.rename)
            context.start()
            self.addCleanup(context.stop)
        self.payloads = {part: (part + "\x00\xff fixture\n").encode("latin1") for part in receiver.ORDER}
        self.request = self.make_request(self.payloads)

    @staticmethod
    def rename(source_fd, source, target_fd, target):
        try:
            os.stat(target, dir_fd=target_fd, follow_symlinks=False)
        except FileNotFoundError:
            os.rename(source, target, src_dir_fd=source_fd, dst_dir_fd=target_fd)
        else:
            raise receiver.Refused("RECEIVER_DESTINATION_EXISTS")

    @staticmethod
    def write_json(path, value):
        path.write_bytes(receiver._canonical(value))
        path.chmod(0o600)

    def make_request(self, payloads):
        return {"protocol": receiver.PROTOCOL, "operation_id": OP, "archive_id": ARCHIVE,
            "runner_archive_sha256": self.runner_record["runner_archive_sha256"],
            "runner_manifest_sha256": self.runner_record["runner_manifest_sha256"],
            "artifacts": {part: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                          for part, raw in payloads.items()}}

    def upload(self):
        receiver.initialize(OP, self.request)
        for part, raw in self.payloads.items():
            receiver.receive(OP, part, 0, len(raw), hashlib.sha256(raw).hexdigest(), raw)

    def test_runner_is_hash_verified_before_loading_any_backup_parser(self):
        self.assertEqual(receiver.verified_runner(OP), self.runner)
        selected = self.runner / "sovagrid-hub/README"
        selected.write_bytes(b"changed source")
        with self.assertRaisesRegex(receiver.Refused, "RUNNER_HASH_MISMATCH"):
            receiver.verified_runner(OP)
        self.assertFalse((self.operation / "request.json").exists())

    def test_runner_unknown_files_links_and_writable_sources_are_refused(self):
        selected = self.runner / "sovagrid-hub/README"
        unknown = self.runner / "unexpected"
        unknown.write_bytes(b"unknown")
        unknown.chmod(0o644)
        with self.assertRaisesRegex(receiver.Refused, "INVALID_RUNNER"):
            receiver.verified_runner(OP)
        unknown.unlink()
        selected.chmod(0o666)
        with self.assertRaisesRegex(receiver.Refused, "INVALID_RUNNER"):
            receiver.verified_runner(OP)
        selected.chmod(0o644)
        unknown.symlink_to(selected)
        with self.assertRaisesRegex(receiver.Refused, "INVALID_RUNNER"):
            receiver.verified_runner(OP)

    def test_request_is_immutable_bounded_and_bound_to_independent_runner(self):
        first = receiver.initialize(OP, self.request)
        self.assertEqual(receiver.initialize(OP, self.request), first)
        self.assertEqual(first["request_sha256"], hashlib.sha256(receiver._canonical(self.request)).hexdigest())
        for mutate in (lambda item: item.update(archive_id="c" * 32),
                       lambda item: item.update(runner_manifest_sha256="e" * 64),
                       lambda item: item["artifacts"]["host"].update(bytes=True),
                       lambda item: item["artifacts"]["host"].update(bytes=8 * 1024**3 + 1),
                       lambda item: item.update(password="must-not-persist")):
            changed = copy.deepcopy(self.request)
            mutate(changed)
            with self.assertRaises(receiver.Refused):
                receiver.initialize(OP, changed)
        self.assertEqual(json.loads((self.operation / "request.json").read_bytes()), self.request)
        self.assertNotIn(b"must-not-persist", (self.operation / "request.json").read_bytes())

    def test_one_authenticated_framed_stream_preserves_binary_and_following_frames(self):
        raw = b'\x00\xff\n{"action":"start"}\nlast byte'
        self.payloads["host"] = raw
        self.request = self.make_request(self.payloads)
        frames = (receiver._canonical({"action": "init", "request": self.request}) +
                  receiver._canonical({"action": "receive", "part": "host", "offset": 0,
                    "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}) + raw +
                  receiver._canonical({"action": "status"}))
        output = io.BytesIO()
        receiver.serve(OP, io.BytesIO(frames), output)
        replies = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(replies), 3)
        self.assertTrue(all(reply["ok"] for reply in replies))
        self.assertEqual(replies[-1]["artifacts"]["host"]["received"], len(raw))
        self.assertEqual((self.operation / "parts/host.data").read_bytes(), raw)

    def test_partial_write_and_lost_ack_resume_only_the_same_chunk_and_inode(self):
        receiver.initialize(OP, self.request)
        part, raw = "host", self.payloads["host"]
        original = receiver._write_all
        def fail(fd, data, offset=None):
            if offset is not None:
                os.pwrite(fd, data[:5], offset)
                os.fsync(fd)
                raise PowerLoss()
            return original(fd, data, offset)
        with patch.object(receiver, "_write_all", side_effect=fail), self.assertRaises(PowerLoss):
            receiver.receive(OP, part, 0, len(raw), hashlib.sha256(raw).hexdigest(), raw)
        path = self.operation / "parts/host.data"
        inode = path.stat().st_ino
        pending = receiver.request_status(OP)
        self.assertEqual(pending["pending_chunk"]["length"], len(raw))
        self.assertEqual(pending["artifacts"][part]["received"], 0)
        done = receiver.receive(OP, part, 0, len(raw), hashlib.sha256(raw).hexdigest(), raw)
        self.assertTrue(done["artifacts"][part]["complete"])
        self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(receiver.receive(OP, part, 0, len(raw), hashlib.sha256(raw).hexdigest(), raw), done)

    def test_invalid_framing_returns_one_bounded_error_and_stops_the_stream(self):
        for frame in (b'{"action":"status","action":"start"}\n',
                      b'{"action":"receive","part":"host","offset":0,"length":4194305,"sha256":"' +
                      b"e" * 64 + b'"}\n', b"[" * 1200 + b"]" * 1200 + b"\n",
                      b"x" * (receiver.MAX_FRAME + 1) + b"\n"):
            with self.subTest(prefix=frame[:30]):
                output = io.BytesIO()
                with patch.object(receiver, "request_status") as status:
                    receiver.serve(OP, io.BytesIO(frame + receiver._canonical({"action": "status"})), output)
                status.assert_not_called()
                replies = output.getvalue().splitlines()
                self.assertEqual(len(replies), 1)
                value = json.loads(replies[0])
                self.assertFalse(value["ok"])
                self.assertEqual(value["operation_id"], OP)
                self.assertRegex(value["error"], r"^[A-Z][A-Z0-9_]{0,63}$")

    def test_dependency_failure_cannot_claim_ready_or_expose_private_error(self):
        self.runner_record["dependencies_ready"] = False
        self.write_json(self.operation / "runner.json", self.runner_record)
        for result in (SimpleNamespace(returncode=1),
                       subprocess.TimeoutExpired(["private credential"], 1800)):
            with self.subTest(timeout=isinstance(result, Exception)):
                kwargs = {"side_effect": result} if isinstance(result, Exception) else {"return_value": result}
                with patch.object(receiver.subprocess, "run", **kwargs) as run:
                    with self.assertRaisesRegex(receiver.Refused, "^DEPENDENCIES_FAILED$"):
                        receiver.dependencies(OP)
                args = run.call_args.args[0]
                self.assertEqual(args[:2], ["/bin/bash", str(self.runner / "sovagrid-blueprint/run.sh")])
                self.assertNotIn("receipt.json", " ".join(args))
                self.assertFalse(json.loads((self.operation / "runner.json").read_bytes())["dependencies_ready"])

    def test_pending_or_acknowledged_foreign_same_byte_replacement_is_preserved(self):
        self.upload()
        path = self.operation / "parts/host.data"
        path.rename(path.with_suffix(".original"))
        path.write_bytes(self.payloads["host"])
        path.chmod(0o600)
        with self.assertRaisesRegex(receiver.Refused, "RECEIVER_PART_CHANGED"):
            receiver.request_status(OP)
        self.assertEqual(path.read_bytes(), self.payloads["host"])

    def test_invalid_chunks_and_changed_offsets_do_not_advance_state(self):
        receiver.initialize(OP, self.request)
        raw = self.payloads["host"]
        for part, offset, length, digest, data in (
                ("../../outside", 0, len(raw), hashlib.sha256(raw).hexdigest(), raw),
                ("host", True, len(raw), hashlib.sha256(raw).hexdigest(), raw),
                ("host", 1, len(raw), hashlib.sha256(raw).hexdigest(), raw),
                ("host", 0, len(raw), "e" * 64, raw),
                ("host", 0, receiver.MAX_CHUNK + 1, "e" * 64, raw)):
            with self.subTest(part=part, offset=offset), self.assertRaises(receiver.Refused):
                receiver.receive(OP, part, offset, length, digest, data)
        self.assertEqual(receiver.request_status(OP)["artifacts"]["host"]["received"], 0)

    def test_registration_partial_copy_recovers_and_idempotently_preserves_inode(self):
        self.upload()
        original = receiver._write_all
        def fail(fd, raw, offset=None):
            if offset is not None:
                os.pwrite(fd, raw[:3], offset)
                os.fsync(fd)
                raise PowerLoss()
            return original(fd, raw, offset)
        with patch.object(receiver, "_verify_uploaded"), patch.object(receiver, "_verify_registration"):
            with patch.object(receiver, "_write_all", side_effect=fail), self.assertRaises(PowerLoss):
                receiver.register(OP)
            self.assertFalse(receiver.request_status(OP)["registered"])
            result = receiver.register(OP)
            self.assertTrue(result["registered"])
            before = {}
            for part, (folder, name) in receiver._targets(self.request).items():
                path = self.root / str(folder).lstrip("/") / name
                self.assertEqual(path.read_bytes(), self.payloads[part])
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                before[part] = path.stat().st_ino
            self.assertTrue(receiver.register(OP)["registered"])
            for part, (folder, name) in receiver._targets(self.request).items():
                path = self.root / str(folder).lstrip("/") / name
                self.assertEqual(path.stat().st_ino, before[part])

    def test_registration_refuses_even_equal_foreign_files_before_overwrite(self):
        self.upload()
        destination = self.root / "var/lib/sovagrid-host-backups"
        destination.mkdir(mode=0o700)
        path = destination / (ARCHIVE + ".tar.gz")
        path.write_bytes(self.payloads["host"])
        path.chmod(0o600)
        original_inode = path.stat().st_ino
        with patch.object(receiver, "_verify_uploaded"), self.assertRaisesRegex(receiver.Refused, "DESTINATION_EXISTS"):
            receiver.register(OP)
        self.assertEqual(path.stat().st_ino, original_inode)
        self.assertEqual(path.read_bytes(), self.payloads["host"])

    def test_installation_fence_blocks_new_data_but_keeps_status_readable(self):
        receiver.initialize(OP, self.request)
        fence = self.root / "var/lib/.sovagrid-host-restore-in-progress"
        fence.write_bytes(b"preserve active operation")
        raw = self.payloads["host"]
        with self.assertRaisesRegex(receiver.Refused, "RESTORE_RECOVERY_REQUIRED"):
            receiver.receive(OP, "host", 0, len(raw), hashlib.sha256(raw).hexdigest(), raw)
        self.assertEqual(receiver.request_status(OP)["artifacts"]["host"]["received"], 0)

    def test_real_host_image_and_receipt_parsers_verify_before_registration(self):
        fixture = host_fixture.RestoreInspectionTest(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        entries = fixture.entries
        host_raw = host_fixture.make_archive(entries)
        image_raw, ids = image_archive()
        roots = {name: images._rootfs_digest(["sha256:" + hashlib.sha256(
            (name + " layer contents\n").encode()).hexdigest()]) for name in ids}
        host = {"protocol": restore.backup.PROTOCOL, "id": ARCHIVE,
                "created_at": "2026-10-27T00:00:00+00:00", "layout": "full", "files": len(entries),
                "bytes": len(host_raw), "sha256": hashlib.sha256(host_raw).hexdigest(),
                "source_manifest_sha256": fixture.source_sha}
        metadata = {"protocol": images.PROTOCOL, "id": ARCHIVE, "created_at": host["created_at"],
            "layout": "full", "bytes": len(image_raw), "sha256": hashlib.sha256(image_raw).hexdigest(),
            "files": 5, "host_archive_sha256": host["sha256"], "source_manifest_sha256": fixture.source_sha,
            "images": ids, "exported_configs": ids,
            "container_ids": {name: ("1" if name == "hub" else "2") * 64 for name in ids}, "rootfs_sha256": roots}
        receipt = {"protocol": images.PORTABLE_RECEIPT, "host_archive_id": ARCHIVE,
            "host_archive_sha256": host["sha256"], "source_manifest_sha256": fixture.source_sha,
            "images_sha256": metadata["sha256"], "active_units": [], "unit_hashes": {}, "unit_states": {},
            **{key: metadata[key] for key in ("images", "container_ids", "exported_configs", "rootfs_sha256")}}
        self.payloads = {"host_manifest": receiver._canonical(host), "host": host_raw,
            "images_manifest": receiver._canonical(metadata), "images": image_raw,
            "receipt": receiver._canonical(receipt)}
        self.request = self.make_request(self.payloads)
        self.upload()
        with ExitStack() as stack:
            for module in (restore, images.restore):
                stack.enter_context(patch.object(module, "_required", return_value={
                    "/opt/sovagrid-src", "/opt/sovagrid-src/sovagrid-bundle.json"}))
                stack.enter_context(patch.object(module.backup, "_sources", return_value=fixture.sources))
                for name, value in (("ROOT", self.root), ("ROOT_UID", os.getuid()), ("ROOT_GID", os.getgid())):
                    stack.enter_context(patch.object(module.backup, name, value))
            stack.enter_context(patch.object(receiver, "_module", side_effect=lambda name: {
                "host_restore": restore}[name]))
            stack.enter_context(patch.object(restore, "_portable_export_module", return_value=images))
            result = receiver.register(OP)
            self.assertTrue(result["registered"])
            self.assertTrue(receiver.request_status(OP)["registered"])


if __name__ == "__main__":
    unittest.main()
