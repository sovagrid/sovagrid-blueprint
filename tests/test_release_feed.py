# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Offline checks for the dormant Ed25519 release feed."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "release_feed.py"
spec = importlib.util.spec_from_file_location("sovagrid_release_feed", SCRIPT)
assert spec and spec.loader
feed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feed)
DEFAULT_ANCHORS = dict(feed.TRUST_ANCHORS)
FROM = "a" * 64
TO = "b" * 64
FINAL = "c" * 64


class SignedFeed(unittest.TestCase):
    def test_archive_member_allows_systemd_template_but_rejects_traversal(self) -> None:
        template = tarfile.TarInfo("sovagrid-blueprint/deploy/sovagrid-external-agent-apply@.service")
        self.assertEqual(feed._member_name(template), template.name)
        with self.assertRaisesRegex(feed.Refused, "UNSAFE_ARCHIVE_MEMBER"):
            feed._member_name(tarfile.TarInfo("sovagrid-blueprint/deploy/../escape@.service"))

    @classmethod
    def setUpClass(cls) -> None:
        cls.keys = tempfile.TemporaryDirectory()
        openssl = shutil.which("openssl")
        assert openssl
        cls.openssl = openssl
        cls.private = Path(cls.keys.name) / "private.pem"
        public = Path(cls.keys.name) / "public.der"
        subprocess.run([openssl, "genpkey", "-algorithm", "Ed25519", "-out", str(cls.private)], check=True)
        subprocess.run([openssl, "pkey", "-in", str(cls.private), "-pubout", "-outform", "DER",
                        "-out", str(public)], check=True)
        der = public.read_bytes()
        assert der.startswith(feed.ED25519_SPKI_PREFIX) and len(der) == 44
        cls.public = der[len(feed.ED25519_SPKI_PREFIX):]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.keys.cleanup()

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        root.chmod(0o700)
        patchers = [
            mock.patch.object(feed, "ROOT_UID", os.geteuid()),
            mock.patch.object(feed, "OPENSSL", self.openssl),
            mock.patch.object(feed, "TRUST_ANCHORS", {"fixture-key": self.public}),
            mock.patch.object(feed, "CONFIG", root / "release-feed.json"),
            mock.patch.object(feed, "STATE", root / "release-feed-state.json"),
            mock.patch.object(feed, "LOCK", root / ".release-feed.lock"),
            mock.patch.object(feed, "CANDIDATES", root / "candidates"),
            mock.patch.object(feed, "SYSTEMD_UNITS", root / "units"),
            mock.patch.object(feed, "MANAGED_MARKER", root / ".release-feed-units-managed-by-run-sh"),
            mock.patch.object(feed, "INSTALLED_MANIFEST", root / "sovagrid-bundle.json"),
            mock.patch.object(feed, "MANUAL_POLICY", root / "auto-update.json"),
            mock.patch.object(feed, "HUB_ONLY_MANUAL_POLICY", root / "hub-only-auto-update.json"),
            mock.patch.object(feed, "PROMOTION_STATE_DIR", root / "promotion"),
            mock.patch.object(feed, "HUB_ONLY_ARTIFACTS", (root / "agent-local", root / "hub-only.service")),
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.now = int(time.time())
        self.ledger = {"format": 1, "highest_sequence": 0,
                       "highest_version": "0.0.0", "last_seen_at": 0}
        self.release = {"sequence": 1, "version": "0.3.10", "from_manifest_sha256": FROM,
                        "to_manifest_sha256": TO, "archive_sha256": "d" * 64,
                        "archive_size": 100}
        self.manifest = {"format": 1, "channel": "stable", "key_id": "fixture-key",
                         "issued_at": self.now - 60, "expires_at": self.now + 3600,
                         "releases": [self.release]}
        feed.CONFIG.write_text(json.dumps({"format": 1, "enabled": True, "channel": "stable",
                                               "key_id": "fixture-key"}))
        feed.CONFIG.chmod(0o600)
        feed.INSTALLED_MANIFEST.write_bytes(b'{"fixture":"installed"}\n')

    def sign(self, value: dict | None = None) -> tuple[bytes, bytes]:
        raw = (json.dumps(self.manifest if value is None else value, sort_keys=True,
                          separators=(",", ":")) + "\n").encode()
        source = Path(self.directory.name) / "sign-input"
        signature = Path(self.directory.name) / "sign-output"
        source.write_bytes(raw)
        subprocess.run([self.openssl, "pkeyutl", "-sign", "-rawin", "-inkey", str(self.private),
                        "-in", str(source), "-out", str(signature)], check=True)
        return raw, signature.read_bytes()

    def test_valid_chain_and_real_signature(self) -> None:
        self.manifest["releases"].append({**self.release, "sequence": 2, "version": "0.3.11",
                                          "from_manifest_sha256": TO, "to_manifest_sha256": FINAL})
        raw, signature = self.sign()
        value = feed.validate_manifest(raw, signature, "fixture-key", self.ledger, self.now)
        self.assertEqual(feed.select_release(value, FROM, self.ledger)["version"], "0.3.10")
        self.assertEqual(feed.select_release(value, TO, {**self.ledger, "highest_sequence": 1,
                                                        "highest_version": "0.3.10"})["version"], "0.3.11")

    def test_two_release_cycle_is_rejected_before_selection(self) -> None:
        self.manifest["releases"].append({**self.release, "sequence": 2, "version": "0.3.11",
                                          "from_manifest_sha256": TO, "to_manifest_sha256": FROM})
        raw, signature = self.sign()
        with self.assertRaisesRegex(feed.Refused, "INVALID_RELEASE_ORDER"):
            feed.validate_manifest(raw, signature, "fixture-key", self.ledger, self.now)

    def test_tampering_or_wrong_key_fails_before_use(self) -> None:
        raw, signature = self.sign()
        with self.assertRaisesRegex(feed.Refused, "INVALID_SIGNATURE"):
            feed.validate_manifest(raw.replace(b"0.3.10", b"0.3.09"), signature,
                                   "fixture-key", self.ledger, self.now)
        with self.assertRaisesRegex(feed.Refused, "INVALID_SIGNATURE"):
            feed.validate_manifest(raw, bytes(64), "fixture-key", self.ledger, self.now)
        with self.assertRaisesRegex(feed.Refused, "UNCONFIGURED_TRUST"):
            feed.validate_manifest(raw, signature, "unknown", self.ledger, self.now)

    def test_expiry_clock_rollback_and_duplicate_json(self) -> None:
        self.manifest["expires_at"] = self.now
        raw, signature = self.sign()
        with self.assertRaisesRegex(feed.Refused, "INVALID_MANIFEST_TIME"):
            feed.validate_manifest(raw, signature, "fixture-key", self.ledger, self.now)
        self.manifest["expires_at"] = self.now + 3600
        raw, signature = self.sign()
        with self.assertRaisesRegex(feed.Refused, "INVALID_MANIFEST_TIME"):
            feed.validate_manifest(raw, signature, "fixture-key",
                                   {**self.ledger, "last_seen_at": self.now + 301}, self.now)
        self.assertRaisesRegex(feed.Refused, "DUPLICATE_JSON_KEY", feed._json,
                               b'{"format":1,"format":1}')

    def test_valid_document_may_predate_last_poll(self) -> None:
        self.manifest["issued_at"] = self.now - 5 * 86400
        self.manifest["expires_at"] = self.now + 86400
        raw, signature = self.sign()
        seen = {**self.ledger, "last_seen_at": self.now}
        self.assertEqual(feed.validate_manifest(raw, signature, "fixture-key", seen, self.now)["channel"],
                         "stable")

    def test_signed_feed_issued_at_cannot_move_backward_after_valid_poll(self) -> None:
        prior = {**self.ledger, "highest_sequence": 1, "highest_version": "0.3.10"}
        feed._atomic_private(feed.STATE, prior)
        raw, signature = self.sign()
        with mock.patch.object(feed, "fetch_small", side_effect=[raw, signature]), \
             mock.patch.object(feed, "current_manifest", return_value=TO), \
             mock.patch.object(feed, "existing_policy", return_value=False):
            feed.poll()
        persisted = feed.state()
        self.assertEqual(persisted["highest_issued_at"], self.manifest["issued_at"])
        self.assertGreaterEqual(persisted["last_seen_at"], self.now)
        self.manifest["issued_at"] -= 1
        old_raw, old_signature = self.sign()
        with self.assertRaisesRegex(feed.Refused, "INVALID_MANIFEST_TIME"):
            feed.validate_manifest(old_raw, old_signature, "fixture-key", persisted, self.now)

    def test_local_status_enable_disable_contract(self) -> None:
        feed.CONFIG.unlink()
        feed.SYSTEMD_UNITS.mkdir(mode=0o755)
        for name in (feed.TIMER, feed.SERVICE):
            (feed.SYSTEMD_UNITS / name).write_text("[Unit]\n")
            (feed.SYSTEMD_UNITS / name).chmod(0o644)
        feed.MANAGED_MARKER.write_bytes(feed.MANAGED_MARKER_CONTENT)
        feed.MANAGED_MARKER.chmod(0o600)
        raw, signature = self.sign()
        enabled = subprocess.CompletedProcess([], 0, "", "")
        output = io.StringIO()
        with mock.patch.object(feed, "_systemctl", return_value=enabled), \
             contextlib.redirect_stdout(output):
            feed.status()
        report = json.loads(output.getvalue())
        self.assertFalse(report["enabled"])
        self.assertFalse(feed.LOCK.exists())
        self.assertTrue(report["timer_installed"])
        self.assertRegex(report["state_revision"], r"^[0-9a-f]{64}$")
        self.assertEqual(report["installed_manifest_sha256"],
                         hashlib.sha256(feed.INSTALLED_MANIFEST.read_bytes()).hexdigest())
        self.assertEqual(report["available_keys"]["fixture-key"],
                         hashlib.sha256(feed.ED25519_SPKI_PREFIX + self.public).hexdigest())
        with mock.patch.object(feed, "fetch_small", side_effect=[raw, signature]), \
             mock.patch.object(feed, "current_manifest", return_value=FROM), \
             mock.patch.object(feed, "_systemctl", return_value=enabled) as systemctl:
            feed.enable(expected_state=report["state_revision"])
        self.assertEqual(feed.configuration()["key_id"], "fixture-key")
        self.assertEqual(feed.CONFIG.stat().st_mode & 0o777, 0o600)
        systemctl.assert_any_call("enable", "--now", feed.TIMER)
        self.assertEqual(feed.state()["highest_issued_at"], self.manifest["issued_at"])
        with mock.patch.object(feed, "_systemctl", return_value=enabled) as systemctl:
            after_enable = feed._snapshot()["state_revision"]
            self.assertNotEqual(report["state_revision"], after_enable)
            feed.disable(expected_state=after_enable)
        systemctl.assert_any_call("disable", "--now", feed.TIMER)
        self.assertFalse(feed.CONFIG.exists())
        self.assertEqual(feed.state()["highest_issued_at"], self.manifest["issued_at"])

    def test_removed_trust_key_keeps_reviewed_disable_available(self) -> None:
        inactive = subprocess.CompletedProcess([], 1, "", "")
        with mock.patch.object(feed, "TRUST_ANCHORS", {}), \
             mock.patch.object(feed, "_systemctl", return_value=inactive), \
             mock.patch.object(feed, "fetch_small") as fetch:
            reviewed = feed._snapshot()
            self.assertTrue(reviewed["enabled"])
            self.assertEqual(reviewed["key_id"], "fixture-key")
            self.assertEqual(reviewed["available_keys"], {})
            with self.assertRaisesRegex(feed.Refused, "UNCONFIGURED_TRUST"):
                feed.poll()
            fetch.assert_not_called()
            feed.disable(expected_state=reviewed["state_revision"])
        self.assertFalse(feed.CONFIG.exists())

    def test_promoted_home_refuses_enable_before_network_or_state_change(self) -> None:
        feed.CONFIG.unlink()
        for footprint in ("directory", "broken_symlink", "orphan_agent"):
            with self.subTest(footprint=footprint):
                if footprint == "directory":
                    feed.PROMOTION_STATE_DIR.mkdir(mode=0o700)
                elif footprint == "broken_symlink":
                    feed.PROMOTION_STATE_DIR.symlink_to(feed.PROMOTION_STATE_DIR.parent / "missing")
                else:
                    feed.HUB_ONLY_ARTIFACTS[0].write_text("partial hub-only installation")
                try:
                    with mock.patch.object(feed, "fetch_small") as fetch, \
                         mock.patch.object(feed, "_systemctl") as systemctl, \
                         mock.patch.object(feed, "stage_candidate") as stage, \
                         mock.patch.object(feed, "arm_candidate") as arm:
                        with self.assertRaisesRegex(feed.Refused, "HUB_ONLY_UNSUPPORTED"):
                            feed.enable("fixture-key")
                    fetch.assert_not_called()
                    systemctl.assert_not_called()
                    stage.assert_not_called()
                    arm.assert_not_called()
                    self.assertFalse(feed.CONFIG.exists())
                    self.assertFalse(feed.STATE.exists())
                finally:
                    if footprint == "directory":
                        feed.PROMOTION_STATE_DIR.rmdir()
                    elif footprint == "broken_symlink":
                        feed.PROMOTION_STATE_DIR.unlink()
                    else:
                        feed.HUB_ONLY_ARTIFACTS[0].unlink()

    def test_promoted_home_refuses_poll_but_status_and_disable_work(self) -> None:
        feed.PROMOTION_STATE_DIR.mkdir(mode=0o700)
        initial_config = feed.CONFIG.read_bytes()
        feed._atomic_private(feed.STATE, self.ledger)
        initial_state = feed.STATE.read_bytes()
        with mock.patch.object(feed, "fetch_small") as fetch, \
             mock.patch.object(feed, "_systemctl") as systemctl, \
             mock.patch.object(feed, "stage_candidate") as stage, \
             mock.patch.object(feed, "arm_candidate") as arm:
            with self.assertRaisesRegex(feed.Refused, "HUB_ONLY_UNSUPPORTED"):
                feed.poll()
        fetch.assert_not_called()
        systemctl.assert_not_called()
        stage.assert_not_called()
        arm.assert_not_called()
        self.assertEqual(feed.CONFIG.read_bytes(), initial_config)
        self.assertEqual(feed.STATE.read_bytes(), initial_state)
        inactive = subprocess.CompletedProcess([], 1, "", "")
        with mock.patch.object(feed, "_systemctl", return_value=inactive):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                feed.status()
            report = json.loads(output.getvalue())
            self.assertTrue(report["enabled"])
            feed.disable(expected_state=report["state_revision"])
        self.assertFalse(feed.CONFIG.exists())
        self.assertEqual(feed.STATE.read_bytes(), initial_state)

    def test_promotion_appearing_during_fetch_or_stage_cannot_arm_update(self) -> None:
        raw, signature = self.sign()
        original_config = feed.CONFIG.read_bytes()
        for phase in ("fetch", "stage"):
            with self.subTest(phase=phase):
                responses = iter((raw, signature))

                def fetch(*_args):
                    if phase == "fetch":
                        feed.PROMOTION_STATE_DIR.mkdir(mode=0o700, exist_ok=True)
                    return next(responses)

                def stage(*_args):
                    feed.PROMOTION_STATE_DIR.mkdir(mode=0o700)

                try:
                    with mock.patch.object(feed, "fetch_small", side_effect=fetch), \
                         mock.patch.object(feed, "current_manifest", return_value=FROM), \
                         mock.patch.object(feed, "existing_policy", return_value=False), \
                         mock.patch.object(feed, "stage_candidate", side_effect=stage) as staged, \
                         mock.patch.object(feed, "arm_candidate") as armed:
                        with self.assertRaisesRegex(feed.Refused, "HUB_ONLY_UNSUPPORTED"):
                            feed.poll()
                    if phase == "fetch":
                        staged.assert_not_called()
                    else:
                        staged.assert_called_once()
                    armed.assert_not_called()
                    self.assertEqual(feed.CONFIG.read_bytes(), original_config)
                    self.assertFalse(feed.STATE.exists())
                finally:
                    feed.PROMOTION_STATE_DIR.rmdir()

    def test_reviewed_cas_rejects_stale_and_malformed_state_before_mutation(self) -> None:
        feed.CONFIG.unlink()
        feed.SYSTEMD_UNITS.mkdir(mode=0o755)
        for name in (feed.TIMER, feed.SERVICE):
            (feed.SYSTEMD_UNITS / name).write_text("[Unit]\n")
        feed.MANAGED_MARKER.write_bytes(feed.MANAGED_MARKER_CONTENT)
        feed.MANAGED_MARKER.chmod(0o600)
        inactive = subprocess.CompletedProcess([], 1, "", "")
        with mock.patch.object(feed, "_systemctl", return_value=inactive):
            reviewed = feed._snapshot()["state_revision"]
        feed._atomic_private(feed.STATE, {**feed.empty_state(), "last_seen_at": 1})
        with mock.patch.object(feed, "fetch_small") as fetch, \
             mock.patch.object(feed, "_systemctl", return_value=inactive) as systemctl:
            with self.assertRaisesRegex(feed.Refused, "STATE_CHANGED"):
                feed.enable(expected_state=reviewed)
            self.assertEqual(feed.main(["enable", "fixture-key", "--expected-state", "bad"]), 40)
        fetch.assert_not_called()
        self.assertFalse(feed.CONFIG.exists())
        self.assertNotIn(mock.call("enable", "--now", feed.TIMER), systemctl.call_args_list)

        feed.CONFIG.write_text(json.dumps({"format": 1, "enabled": True, "channel": "stable",
                                                "key_id": "fixture-key"}))
        feed.CONFIG.chmod(0o600)
        with mock.patch.object(feed, "_systemctl", return_value=inactive):
            reviewed = feed._snapshot()["state_revision"]
        feed.MANUAL_POLICY.write_bytes(b'{"new":"manual candidate"}\n')
        feed.MANUAL_POLICY.chmod(0o600)
        with mock.patch.object(feed, "_systemctl", return_value=inactive) as systemctl:
            with self.assertRaisesRegex(feed.Refused, "STATE_CHANGED"):
                feed.disable(expected_state=reviewed)
            self.assertEqual(feed.main(["disable", "--expected-state", "BAD"]), 40)
        self.assertTrue(feed.CONFIG.exists())
        self.assertNotIn(mock.call("disable", "--now", feed.TIMER), systemctl.call_args_list)

    def test_status_revision_covers_exact_bytes_timer_and_trust_without_writes(self) -> None:
        feed.SYSTEMD_UNITS.mkdir(mode=0o755)
        for name in (feed.TIMER, feed.SERVICE):
            (feed.SYSTEMD_UNITS / name).write_text("[Unit]\n")
        feed.MANAGED_MARKER.write_bytes(feed.MANAGED_MARKER_CONTENT)
        feed.MANAGED_MARKER.chmod(0o600)
        inactive = subprocess.CompletedProcess([], 1, "", "")
        active = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(feed, "_systemctl", return_value=inactive):
            initial = feed._snapshot()
            self.assertEqual(feed._snapshot()["state_revision"], initial["state_revision"])
        self.assertFalse(feed.LOCK.exists())
        self.assertFalse(initial["timer_enabled"])
        self.assertFalse(initial["timer_active"])
        self.assertEqual(initial["manual_candidate_active"], False)
        with mock.patch.object(feed, "_systemctl", return_value=active):
            self.assertNotEqual(feed._snapshot()["state_revision"], initial["state_revision"])
        feed.CONFIG.write_bytes(feed.CONFIG.read_bytes() + b"\n")
        with mock.patch.object(feed, "_systemctl", return_value=inactive):
            changed_config = feed._snapshot()["state_revision"]
        self.assertNotEqual(changed_config, initial["state_revision"])
        feed.STATE.write_bytes(b'{"format":1,"highest_sequence":0,"highest_version":"0.0.0",'
                               b'"highest_issued_at":0,"last_seen_at":0}\n')
        feed.STATE.chmod(0o600)
        with mock.patch.object(feed, "_systemctl", return_value=inactive):
            changed_ledger = feed._snapshot()["state_revision"]
        self.assertNotEqual(changed_ledger, changed_config)
        feed.INSTALLED_MANIFEST.write_bytes(b'{"fixture":"new installed version"}\n')
        with mock.patch.object(feed, "_systemctl", return_value=inactive):
            changed_manifest = feed._snapshot()["state_revision"]
        self.assertNotEqual(changed_manifest, changed_ledger)
        (feed.SYSTEMD_UNITS / feed.SERVICE).write_text("[Unit]\nDescription=Changed\n")
        with mock.patch.object(feed, "_systemctl", return_value=inactive):
            changed_unit = feed._snapshot()["state_revision"]
        self.assertNotEqual(changed_unit, changed_manifest)
        with mock.patch.object(feed, "_systemctl", return_value=inactive), \
             mock.patch.object(feed, "TRUST_ANCHORS", {"fixture-key": bytes(32)}):
            self.assertNotEqual(feed._snapshot()["state_revision"], changed_unit)
        feed.HUB_ONLY_MANUAL_POLICY.write_bytes(b'{"manual":"hub-only"}\n')
        feed.HUB_ONLY_MANUAL_POLICY.chmod(0o600)
        with mock.patch.object(feed, "_systemctl", return_value=inactive):
            hub_only_manual = feed._snapshot()
        self.assertTrue(hub_only_manual["manual_candidate_active"])
        self.assertNotEqual(hub_only_manual["state_revision"], changed_unit)
        self.assertTrue(feed.existing_policy())

    def test_enable_refuses_missing_unit_and_rolls_back_failed_timer(self) -> None:
        feed.CONFIG.unlink()
        raw, signature = self.sign()
        with mock.patch.object(feed, "fetch_small") as fetch:
            with self.assertRaisesRegex(feed.Refused, "TIMER_NOT_INSTALLED"):
                feed.enable()
        fetch.assert_not_called()
        feed.SYSTEMD_UNITS.mkdir(mode=0o755)
        for name in (feed.TIMER, feed.SERVICE):
            (feed.SYSTEMD_UNITS / name).write_text("[Unit]\n")
        with self.assertRaisesRegex(feed.Refused, "TIMER_NOT_INSTALLED"):
            feed.enable()
        feed.MANAGED_MARKER.write_bytes(feed.MANAGED_MARKER_CONTENT)
        feed.MANAGED_MARKER.chmod(0o600)
        failed = subprocess.CompletedProcess([], 1, "", "")
        with mock.patch.object(feed, "fetch_small", side_effect=[raw, signature]), \
             mock.patch.object(feed, "current_manifest", return_value=FROM), \
             mock.patch.object(feed, "_systemctl", return_value=failed):
            with self.assertRaisesRegex(feed.Refused, "TIMER_UNAVAILABLE"):
                feed.enable()
        self.assertFalse(feed.CONFIG.exists())

    def test_disable_removes_opt_in_even_when_systemctl_fails(self) -> None:
        feed.SYSTEMD_UNITS.mkdir(mode=0o755)
        (feed.SYSTEMD_UNITS / feed.TIMER).write_text("[Unit]\n")
        failed = subprocess.CompletedProcess([], 1, "", "")
        with mock.patch.object(feed, "_systemctl", return_value=failed):
            with self.assertRaisesRegex(feed.Refused, "TIMER_UNAVAILABLE"):
                feed.disable()
        self.assertFalse(feed.CONFIG.exists())

    def test_disarm_alias_uses_same_fail_closed_disable_path(self) -> None:
        with mock.patch.object(feed, "disable") as disable:
            self.assertEqual(feed.main(["disarm"]), 0)
        disable.assert_called_once_with()

    def test_cli_passes_reviewed_revision_to_mutations(self) -> None:
        reviewed = "a" * 64
        with mock.patch.object(feed, "enable") as enable, \
             mock.patch.object(feed, "disable") as disable:
            self.assertEqual(feed.main(["enable", "fixture-key", "--expected-state", reviewed]), 0)
            enable.assert_called_once_with("fixture-key", expected_state=reviewed)
            self.assertEqual(feed.main(["disable", "--expected-state", reviewed]), 0)
            disable.assert_called_once_with(expected_state=reviewed)

    def test_no_url_or_command_fields_and_release_order(self) -> None:
        self.manifest["releases"][0]["url"] = "https://example.test/x"
        raw, signature = self.sign()
        with self.assertRaisesRegex(feed.Refused, "INVALID_RELEASE"):
            feed.validate_manifest(raw, signature, "fixture-key", self.ledger, self.now)
        del self.manifest["releases"][0]["url"]
        self.manifest["releases"].append({**self.release, "sequence": 2, "version": "0.3.11",
                                          "from_manifest_sha256": FINAL})
        raw, signature = self.sign()
        with self.assertRaisesRegex(feed.Refused, "INVALID_RELEASE_ORDER"):
            feed.validate_manifest(raw, signature, "fixture-key", self.ledger, self.now)

    def test_replay_and_downgrade_rejected(self) -> None:
        raw, signature = self.sign()
        manifest = feed.validate_manifest(raw, signature, "fixture-key", self.ledger, self.now)
        prior = {**self.ledger, "highest_sequence": 1, "highest_version": "0.3.10"}
        with self.assertRaisesRegex(feed.Refused, "REPLAY_OR_DOWNGRADE"):
            feed.select_release(manifest, FROM, prior)
        self.assertIsNone(feed.select_release(manifest, TO, prior))
        later = {**prior, "highest_sequence": 2, "highest_version": "0.3.11"}
        with self.assertRaisesRegex(feed.Refused, "REPLAY_OR_DOWNGRADE"):
            feed.select_release(manifest, TO, later)

    def test_url_validation_rejects_redirect_to_other_host_or_http(self) -> None:
        self.assertEqual(feed.FEED_URL,
                         "https://raw.githubusercontent.com/sovagrid/sovagrid-update-feed/main/stable.json")
        for url in ("http://github.com/a", "https://127.0.0.1/a",
                    "https://github.com:444/a", "https://user:secret@github.com/a",
                    "https://github.com/a?token=x"):
            with self.subTest(url=url), self.assertRaisesRegex(feed.Refused, "UNSAFE_URL"):
                feed._validate_url(url, feed.ARCHIVE_HOSTS)
        handler = feed._SafeRedirect(feed.ARCHIVE_HOSTS)
        with self.assertRaisesRegex(feed.Refused, "UNSAFE_URL"):
            handler.redirect_request(None, None, 302, "", {}, "https://evil.example/a")
        feed._validate_url("https://release-assets.githubusercontent.com/object?github-signed=1",
                           feed.ARCHIVE_HOSTS, allow_cdn_query=True)
        self.assertEqual(feed.archive_url("0.3.10"),
                         "https://github.com/sovagrid/sovagrid-blueprint/releases/download/"
                         "server-v0.3.10/SovaGrid-server-source.tar.gz")
        with self.assertRaises(feed.Refused):
            feed.archive_url("../malicious")

    def test_private_opt_in_config_and_state(self) -> None:
        self.assertEqual(set(DEFAULT_ANCHORS), {"sovagrid-2026-10"})
        self.assertEqual(hashlib.sha256(feed.ED25519_SPKI_PREFIX +
                                        DEFAULT_ANCHORS["sovagrid-2026-10"]).hexdigest(),
                         "abb6ed34e70fc1dd33d393987fb6067b4a69120eb3a5e00681f209e3666444bf")
        installer = (SCRIPT.parents[1] / "run.sh").read_text()
        self.assertIn("install_release_feed_units", installer)
        self.assertNotIn("systemctl enable --now sovagrid-release-feed.timer", installer)
        service = (SCRIPT.parent / "sovagrid-release-feed.service").read_text()
        self.assertIn("ConditionPathExists=/etc/sovagrid/release-feed.json", service)
        self.assertEqual(feed.configuration()["key_id"], "fixture-key")
        feed.CONFIG.chmod(0o644)
        with self.assertRaisesRegex(feed.Refused, "UNSAFE_FILE"):
            feed.configuration()
        feed.CONFIG.chmod(0o600)
        with mock.patch.object(feed, "TRUST_ANCHORS", {}):
            with self.assertRaisesRegex(feed.Refused, "UNCONFIGURED_TRUST"):
                feed.configuration()
        feed._atomic_private(feed.STATE, {**self.ledger, "highest_sequence": 3})
        self.assertEqual(feed.state()["highest_sequence"], 3)
        self.assertEqual(feed.STATE.stat().st_mode & 0o777, 0o600)

    @staticmethod
    def archive(*, symlink: bool = False) -> tuple[bytes, str]:
        source_manifest = b'{"fixture":"test"}\n'
        target_sha = hashlib.sha256(source_manifest).hexdigest()
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as tar:
            directory = tarfile.TarInfo("sovagrid-blueprint/")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            tar.addfile(directory)
            entry = tarfile.TarInfo("sovagrid-blueprint/test.txt")
            entry.mode = 0o644
            if symlink:
                entry.type = tarfile.SYMTYPE
                entry.linkname = "/etc/shadow"
                tar.addfile(entry)
            else:
                entry.size = 4
                tar.addfile(entry, io.BytesIO(b"test"))
            manifest = tarfile.TarInfo("sovagrid-bundle.json")
            manifest.mode = 0o644
            manifest.size = len(source_manifest)
            tar.addfile(manifest, io.BytesIO(source_manifest))
        return output.getvalue(), target_sha

    def test_archive_boundaries_and_candidate_staging(self) -> None:
        archive, target_sha = self.archive()
        release = {**self.release, "archive_size": len(archive),
                   "archive_sha256": hashlib.sha256(archive).hexdigest(),
                   "to_manifest_sha256": target_sha}
        feed.CANDIDATES.mkdir(mode=0o700)

        class Response(io.BytesIO):
            pass

        with mock.patch.object(feed, "_open", side_effect=lambda *_: contextlib.nullcontext(Response(archive))), \
             mock.patch.object(feed, "_worker", return_value=subprocess.CompletedProcess([], 0,
                              "SG_UPDATE_PREFLIGHT:OK\n", "")) as worker:
            old_umask = os.umask(0o077)
            try:
                feed.stage_candidate(release, FROM)
            finally:
                os.umask(old_umask)
        root = feed.CANDIDATES / release["archive_sha256"]
        self.assertEqual((root / "bundle.tar.gz").read_bytes(), archive)
        self.assertEqual((root / ".ready").read_text().strip(), release["archive_sha256"])
        self.assertEqual((root / "source/sovagrid-bundle.json").read_bytes(), b'{"fixture":"test"}\n')
        self.assertEqual((root / "source").stat().st_mode & 0o777, 0o755)
        self.assertEqual((root / "source/sovagrid-blueprint").stat().st_mode & 0o777, 0o755)
        self.assertEqual((root / "source/sovagrid-blueprint/test.txt").stat().st_mode & 0o777, 0o644)
        worker.assert_called_once_with("preflight", release["archive_sha256"], FROM)

        bad_archive, _ = self.archive(symlink=True)
        bad_path = Path(self.directory.name) / "bad.tar.gz"
        bad_path.write_bytes(bad_archive)
        with self.assertRaisesRegex(feed.Refused, "UNSAFE_ARCHIVE_MEMBER"):
            feed.unpack_archive(bad_path, Path(self.directory.name) / "unsafe", target_sha)

    def test_poll_only_arms_after_verified_feed_and_persists_sequence(self) -> None:
        raw, signature = self.sign()
        with mock.patch.object(feed, "fetch_small", side_effect=[raw, signature]), \
             mock.patch.object(feed, "current_manifest", return_value=FROM), \
             mock.patch.object(feed, "existing_policy", return_value=False), \
             mock.patch.object(feed, "stage_candidate") as stage, \
             mock.patch.object(feed, "arm_candidate") as arm:
            feed.poll()
        stage.assert_called_once_with(self.release, FROM)
        arm.assert_called_once_with(self.release, FROM)
        self.assertEqual(feed.state()["highest_sequence"], 1)
        with mock.patch.object(feed, "fetch_small", side_effect=[raw, signature]), \
             mock.patch.object(feed, "current_manifest", return_value=FROM), \
             mock.patch.object(feed, "existing_policy", return_value=False), \
             mock.patch.object(feed, "arm_candidate") as arm:
            with self.assertRaisesRegex(feed.Refused, "REPLAY_OR_DOWNGRADE"):
                feed.poll()
        arm.assert_not_called()

    def test_existing_manual_policy_blocks_feed_before_network(self) -> None:
        with mock.patch.object(feed, "existing_policy", return_value=True), \
             mock.patch.object(feed, "fetch_small") as fetch, \
             mock.patch.object(feed, "arm_candidate") as arm:
            feed.poll()
        fetch.assert_not_called()
        arm.assert_not_called()

    def test_failed_arm_consumes_sequence_fail_closed(self) -> None:
        raw, signature = self.sign()
        with mock.patch.object(feed, "fetch_small", side_effect=[raw, signature]), \
             mock.patch.object(feed, "current_manifest", return_value=FROM), \
             mock.patch.object(feed, "existing_policy", return_value=False), \
             mock.patch.object(feed, "stage_candidate"), \
             mock.patch.object(feed, "arm_candidate", side_effect=feed.Refused("AUTO_UPDATE_REFUSED")):
            with self.assertRaisesRegex(feed.Refused, "AUTO_UPDATE_REFUSED"):
                feed.poll()
        self.assertEqual(feed.state()["highest_sequence"], 1)


if __name__ == "__main__":
    unittest.main()
