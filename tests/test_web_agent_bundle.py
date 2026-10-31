# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Rebuild the installed five-component source tree without a live server."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vendor/connect"))
sys.path.insert(0, str(ROOT / "deploy"))

from sovagrid_connect.agent_enrollment import source_bundle
from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.enrollment_journal import EnrollmentJournal
from web_agent_bundle import BundleError, COMPONENTS, REQUIRED, ensure_managed_bundle


class BundleTests(unittest.TestCase):
    def setUp(self):
        trusted_tmp = "/private/tmp" if Path("/private/tmp").is_dir() else "/tmp"
        self.directory = tempfile.TemporaryDirectory(dir=trusted_tmp)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o755)
        self.output = self.root / "private" / "source.tar.gz"
        self.files = {}
        for name in sorted(REQUIRED):
            content = (b"SOVAGRID_REMOTE_AGENT_HELPER_V1\n" if name.endswith("remote_agent.py")
                       else ("fixture: " + name + "\n").encode())
            self.files[name] = content
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            path.write_bytes(content)
            path.chmod(0o755 if name.endswith("run.sh") else 0o644)
        self.write_manifest()

    def write_manifest(self):
        manifest = {"format": 1,
                    "components": {name: {"commit": "a" * 40,
                                          "file_count": sum(path.startswith(name + "/")
                                                            for path in self.files)}
                                   for name in sorted(COMPONENTS)},
                    "sha256": {name: hashlib.sha256(content).hexdigest()
                               for name, content in sorted(self.files.items())}}
        (self.source / "sovagrid-bundle.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
        (self.source / "sovagrid-bundle.json").chmod(0o644)

    def ensure(self):
        return ensure_managed_bundle(source_root=self.source, output_path=self.output,
                                     expected_uid=os.geteuid(), require_root=False)

    def pending_journal(self, path: Path, digest: str):
        journal = EnrollmentJournal(self.output.parent / "jobs")
        request_id = str(uuid.uuid4())
        connection = asdict(ConnectionOptions(host="example.invalid", user="root").validated())
        connection.pop("ssh_executable")
        record = journal.create({"protocol": 1, "request_id": request_id, "name": "fixture",
            "phase": "prepared", "hub_connection": connection,
            "target_connection": connection,
            "hub_endpoint": {"host": "192.0.2.40", "port": 22, "local_port": 18767},
            "bundle": {"path": str(path), "sha256": digest},
            "target": None, "registration": None, "hub_trust": None,
            "hub_authorized": False, "cleanup_required": False,
            "cas": {"hub": None, "target": None}, "stage": None})
        return journal, record

    def test_reproducible_private_bundle_matches_connect(self):
        path, digest = self.ensure()
        self.assertEqual(path, self.output.parent / f"source-{digest}.tar.gz")
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        _, summary = source_bundle(path)
        self.assertEqual(set(summary.commits), COMPONENTS)
        first_bytes = path.read_bytes()
        self.assertEqual(self.ensure(), (path, digest))
        path.unlink()
        rebuilt, rebuilt_sha = self.ensure()
        self.assertEqual(rebuilt.read_bytes(), first_bytes)
        self.assertEqual(rebuilt_sha, digest)

    def test_systemd_template_path_round_trip(self):
        name = "sovagrid-blueprint/deploy/sovagrid-external-agent-apply@.service"
        self.files[name] = b"[Unit]\nDescription=fixture\n"
        (self.source / name).write_bytes(self.files[name])
        self.write_manifest()
        path, _ = self.ensure()
        with tarfile.open(path, "r:gz") as archive:
            self.assertEqual(archive.extractfile(name).read(), self.files[name])
        _, summary = source_bundle(path)
        self.assertEqual(set(summary.commits), COMPONENTS)

    def test_generated_bytecode_is_not_exported(self):
        generated = self.source / "sovagrid-blueprint" / "deploy" / "__pycache__"
        generated.mkdir()
        (generated / "remote_agent.cpython-315.pyc").write_bytes(b"generated")
        path, _ = self.ensure()
        with tarfile.open(path, "r:gz") as archive:
            self.assertNotIn("__pycache__", " ".join(archive.getnames()))

    def test_tampered_source_keeps_previous_bundle(self):
        path, digest = self.ensure()
        before = path.read_bytes()
        (self.source / "sovagrid-agent/deploy/sovagrid-agent.service").write_bytes(b"modified")
        with self.assertRaises(BundleError) as raised:
            self.ensure()
        self.assertEqual(str(raised.exception), "SOURCE_UNTRUSTED")
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_new_source_keeps_old_archive_for_pending_enrollment(self):
        old_path, old_digest = self.ensure()
        journal, pending = self.pending_journal(old_path, old_digest)
        name = "sovagrid-web/Dockerfile"
        self.files[name] = b"new release fixture\n"
        (self.source / name).write_bytes(self.files[name])
        self.write_manifest()
        new_path, new_digest = self.ensure()
        self.assertNotEqual(new_digest, old_digest)
        self.assertNotEqual(new_path, old_path)
        self.assertTrue(old_path.is_file())
        self.assertEqual(hashlib.sha256(old_path.read_bytes()).hexdigest(), old_digest)
        self.assertEqual(hashlib.sha256(new_path.read_bytes()).hexdigest(), new_digest)
        journal.remove(pending["request_id"], expected_revision=pending["revision"])
        self.assertEqual(self.ensure(), (new_path, new_digest))
        self.assertFalse(old_path.exists())

    def test_unlisted_file_and_symlink_are_rejected(self):
        extra = self.source / "sovagrid-web" / "unexpected.txt"
        extra.write_bytes(b"unlisted")
        with self.assertRaises(BundleError):
            self.ensure()
        extra.unlink()
        target = self.source / "sovagrid-hub/Dockerfile"
        target.unlink()
        target.symlink_to(self.source / "sovagrid-web/Dockerfile")
        with self.assertRaises(BundleError):
            self.ensure()

    def test_invalid_helper_marker_and_unsafe_output_are_rejected(self):
        helper_name = "sovagrid-blueprint/deploy/remote_agent.py"
        helper = self.source / helper_name
        helper.write_bytes(b"no installer marker")
        self.files[helper_name] = helper.read_bytes()
        self.write_manifest()
        with self.assertRaises(BundleError) as raised:
            self.ensure()
        self.assertEqual(str(raised.exception), "BUNDLE_INVALID")
        helper.write_bytes(b"SOVAGRID_REMOTE_AGENT_HELPER_V1\n")
        self.files[helper_name] = helper.read_bytes()
        self.write_manifest()
        valid_path, _ = self.ensure()
        valid_path.unlink()
        valid_path.symlink_to(self.source / "sovagrid-bundle.json")
        with self.assertRaises(BundleError) as raised:
            self.ensure()
        self.assertEqual(str(raised.exception), "OUTPUT_UNSAFE")

    def test_second_builder_fails_fast_while_lock_is_held(self):
        self.ensure()
        with (self.output.parent / ".bundle.lock").open("rb+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                with self.assertRaises(BundleError) as raised:
                    self.ensure()
                self.assertEqual(str(raised.exception), "BUSY")
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


if __name__ == "__main__":
    unittest.main()
