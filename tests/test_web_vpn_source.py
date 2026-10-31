# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Pinned source SSH bridge with a disposable fake transport."""

from __future__ import annotations

from contextlib import nullcontext
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vendor/connect"))
sys.path.insert(0, str(ROOT / "deploy"))
import host_backup
import web_vpn_source as module


FINGERPRINT = "SHA256:" + "A" * 43
SHA = "a" * 64
MANIFEST = "b" * 64
CANDIDATE = "c" * 64


class FakeJobs:
    def __init__(self, directory):
        self._bundle_path = directory / ("source-" + SHA + ".tar.gz")
        self._bundle_sha256 = SHA

    def _exclusive(self):
        return nullcontext()

    def _bundle(self):
        return self._bundle_path


class FakeRPC:
    fail_cleanup_once = False

    def __init__(self):
        self._owner = object()
        self._stages = {}
        self.cleaned = []

    def stage_target(self, bundle, digest, *, checkpoint):
        stage = module.Stage("/var/tmp/sovagrid-agent-enroll." + "e" * 32,
                             SHA, MANIFEST, "d" * 64, "e" * 32, self._owner)
        self._stages[stage.stage_id] = stage
        checkpoint(stage.descriptor())
        return stage

    def _exchange(self, bootstrap, chunks, timeout):
        request = json.loads(b"".join(chunks))
        assert request["source_manifest_sha256"] == MANIFEST
        assert "vpn_source_install.py" in bootstrap
        compile(bootstrap, "<remote-vpn-source>", "exec")
        result = {"protocol": 1, "change": "install", "source_manifest_sha256": MANIFEST,
                  "candidate_sha256": CANDIDATE, "installed_sha256": "0" * 64,
                  "state_sha256": "0" * 64, "cleanup_required": False,
                  "expected": {"source_manifest_sha256": MANIFEST, "candidate_sha256": CANDIDATE,
                               "installed_sha256": "0" * 64, "state_sha256": "0" * 64}}
        return module._canonical({"protocol": 1, "ok": True, "result": result}), 0

    def cleanup_stage(self, stage):
        if type(self).fail_cleanup_once:
            type(self).fail_cleanup_once = False
            raise OSError("simulated SSH interruption")
        self.cleaned.append(stage.stage_id)
        self._stages.pop(stage.stage_id, None)


class FakeTransport:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.rpc = FakeRPC()
        self.options = SimpleNamespace(host=kwargs["host"], port=kwargs["port"],
                                       user=kwargs["username"])
        type(self).instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def target_rpc(self, _options):
        return self.rpc


class WebVpnSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.directory.chmod(0o700)
        self.jobs = FakeJobs(self.directory)
        self.bridge = module.VpnSourceJobs(self.jobs,
            journal_path=self.directory / "vpn-source-stage.json",
            transport_factory=FakeTransport)
        self.options = SimpleNamespace(host="target.example", port=2222, user="root")
        self.credential = SimpleNamespace(method="password", password="test-secret",
                                          private_key="", passphrase="")
        FakeTransport.instances.clear()
        FakeRPC.fail_cleanup_once = False

    def _preview(self):
        return self.bridge.execute("preview", options=self.options,
            fingerprint=FINGERPRINT, credential=self.credential)

    def test_preview_returns_only_pins_and_cleans_stage(self):
        result = self._preview()
        self.assertEqual(result["host"], "target.example")
        self.assertEqual(result["port"], 2222)
        self.assertEqual(result["host_key_fingerprint"], FINGERPRINT)
        self.assertEqual(result["expected"]["source_manifest_sha256"], MANIFEST)
        self.assertTrue(result["temporary_writes"])
        self.assertFalse(result["activation_writes"])
        self.assertFalse((self.directory / "vpn-source-stage.json").exists())
        self.assertEqual(FakeTransport.instances[0].rpc.cleaned, ["e" * 32])

    def test_failed_stage_cleanup_is_recovered_by_next_same_target_request(self):
        FakeRPC.fail_cleanup_once = True
        with self.assertRaises(module.VpnSourceError) as error:
            self._preview()
        self.assertEqual(error.exception.code, "STAGE_CLEANUP_REQUIRED")
        self.assertTrue((self.directory / "vpn-source-stage.json").exists())
        result = self._preview()
        self.assertEqual(result["change"], "install")
        self.assertFalse((self.directory / "vpn-source-stage.json").exists())
        self.assertEqual(FakeTransport.instances[1].rpc.cleaned, ["e" * 32, "e" * 32])

    def test_apply_requires_reviewed_cas_before_ssh(self):
        with self.assertRaises(module.VpnSourceError) as error:
            self.bridge.execute("apply", options=self.options, fingerprint=FINGERPRINT,
                                credential=self.credential, expected={})
        self.assertEqual(error.exception.code, "INVALID_REQUEST")
        self.assertEqual(FakeTransport.instances, [])

    def test_backup_accepts_only_bounded_private_stage_journal(self):
        path = host_backup.WEB_AGENT_DIR + "/vpn-source-stage.json"
        self.assertEqual(host_backup._web_agent_source(path).exact_mode, 0o600)
        self.assertEqual(host_backup._web_agent_limit(path), 4096)
        temporary = SimpleNamespace(st_mode=0o100600, st_uid=0, st_gid=0,
                                    st_nlink=1, st_size=4096)
        self.assertTrue(host_backup._skip_web_agent_temp(host_backup.WEB_AGENT_DIR,
                        ".vpn-stage-" + "a" * 32, temporary))
        oversized = SimpleNamespace(**{**vars(temporary), "st_size": 4097})
        with self.assertRaises(host_backup.Refused):
            host_backup._skip_web_agent_temp(host_backup.WEB_AGENT_DIR,
                                             ".vpn-stage-" + "a" * 32, oversized)


if __name__ == "__main__":
    unittest.main()
