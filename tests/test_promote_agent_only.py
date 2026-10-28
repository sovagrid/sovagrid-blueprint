# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Offline safety checks for the opt-in external-Agent promotion helper."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.error import URLError


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("promotion", ROOT / "deploy/promote_agent_only.py")
promotion = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(promotion)


class PromotionTests(unittest.TestCase):
    def test_discovers_reverse_ssh_unit_without_host_specific_name(self):
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch.object(promotion, "ROOT_UID", os.geteuid()):
            directory = Path(folder)
            reverse = directory / "fixture-reverse.service"
            reverse.write_text("[Service]\nExecStart=/usr/bin/autossh -N -R 2200:127.0.0.1:22 relay.example\n")
            ordinary = directory / "ordinary.service"
            ordinary.write_text("[Service]\nExecStart=/usr/bin/sleep infinity\n")
            (directory / "alias.service").symlink_to(reverse)
            found = promotion._additional_reverse_tunnels(directory)
            self.assertEqual(set(found), {reverse.name})
            self.assertEqual(found[reverse.name], reverse.read_bytes())

    def test_legacy_absent_optional_unit_does_not_block_existing_baseline(self):
        current = {"protocol": 1, "files": {}, "agent_data": {},
                   "units": {"sovagrid-agent.service": True,
                             "sovagrid-agent-tunnel.service": True}}
        legacy = {**current, "units": {**current["units"], "old-optional.service": False}}
        self.assertTrue(promotion._external_matches(current, legacy))
        active = {**legacy, "units": {**current["units"], "old-optional.service": True}}
        self.assertFalse(promotion._external_matches(current, active))

    def test_prepare_is_explicit_and_refuses_changed_external_agent(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            snapshot = {"protocol": 1, "files": {"agent": "pinned"}}
            with mock.patch.object(promotion, "SOURCE", base / "source"), \
                 mock.patch.object(promotion, "MANAGED_MARKER", base / "managed"), \
                 mock.patch.object(promotion, "LOCAL", base / "local"), \
                 mock.patch.object(promotion, "BASELINE", base / "baseline"), \
                 mock.patch.object(promotion, "capture_external", return_value=snapshot), \
                 mock.patch.object(promotion, "_save_private") as save:
                self.assertTrue(promotion.prepare()["prepared"])
                save.assert_called_once_with(base / "baseline", snapshot)
                (base / "baseline").write_text("fixture")
                with mock.patch.object(promotion, "_private_json", return_value=snapshot):
                    self.assertTrue(promotion.prepare()["external_agent_preserved"])
                with mock.patch.object(promotion, "_private_json", return_value={"changed": True}):
                    with self.assertRaises(promotion.PromotionError):
                        promotion.prepare()

    def test_promotion_copy_checks_every_agent_file_and_refuses_tampering(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            source = base / "source"
            (source / "sovagrid-agent/sovagrid_agent").mkdir(parents=True)
            hashes = {}
            for index in range(8):
                path = source / "sovagrid-agent/sovagrid_agent" / f"part{index}.py"
                path.write_text(f"VALUE = {index}\n")
                hashes[str(path.relative_to(source))] = hashlib.sha256(path.read_bytes()).hexdigest()
            for name in ("LICENSE", "ATTRIBUTION.md", "NOTICE"):
                path = source / "sovagrid-agent" / name
                path.write_text("fixture " + name)
                hashes[str(path.relative_to(source))] = hashlib.sha256(path.read_bytes()).hexdigest()
            (source / "sovagrid-bundle.json").write_text(json.dumps({"sha256": hashes}))
            target = base / "agent-local"
            with mock.patch.object(promotion, "SOURCE", source), \
                 mock.patch.object(promotion, "LOCAL_SOURCE", target), \
                 mock.patch.object(promotion, "ROOT_UID", os.getuid()), \
                 mock.patch.object(promotion, "_read_regular", side_effect=lambda path, *args: path.read_bytes()):
                files, expected = promotion._agent_source_files()
                promotion._install_agent_source(files, expected)
                promotion._verify_local_source(files, expected)
                (target / "sovagrid_agent/part0.py").write_text("tampered")
                with self.assertRaises(promotion.PromotionError):
                    promotion._verify_local_source(files, expected)

    def test_local_agent_config_uses_distinct_token_and_disables_shared_brokers(self):
        saved = {"server_id": "00000000-0000-4000-8000-000000000001", "commands": False}
        config = json.loads(promotion._config_bytes(saved))
        self.assertEqual(config["hub_url"], "https://localhost:8767")
        self.assertEqual(config["token_file"], "/etc/sovagrid-local/agent.token")
        self.assertEqual(config["ca_file"], "/etc/sovagrid-local/hub-ca.pem")
        self.assertFalse(config["allow_remote_commands"])
        self.assertFalse(config["allow_interactive_terminal"])
        self.assertFalse(config["allow_file_manager"])
        enabled = json.loads(promotion._config_bytes({**saved, "commands": True}))
        self.assertTrue(enabled["allow_remote_commands"])
        self.assertNotIn("agent_token", config)
        self.assertIn("User=sovagrid-local\nGroup=sovagrid-local", promotion.UNIT_TEXT)
        self.assertIn("ReadWritePaths=/var/lib/sovagrid-agent-local", promotion.UNIT_TEXT)
        self.assertNotIn("ReadWritePaths=/var/lib/sovagrid-agent\n", promotion.UNIT_TEXT)
        self.assertNotIn("--config /etc/sovagrid/agent.json", promotion.UNIT_TEXT)

    def test_local_uid_has_no_external_agent_group_or_identity(self):
        local_group = SimpleNamespace(gr_gid=1005, gr_mem=[])
        external_group = SimpleNamespace(gr_gid=999, gr_mem=[])
        local_user = SimpleNamespace(pw_uid=1005, pw_gid=1005,
                                     pw_dir="/var/lib/sovagrid-agent-local",
                                     pw_shell="/usr/sbin/nologin")
        external_user = SimpleNamespace(pw_uid=999)
        with mock.patch.object(promotion.grp, "getgrnam", side_effect=lambda name:
                               local_group if name == "sovagrid-local" else external_group), \
             mock.patch.object(promotion.pwd, "getpwnam", side_effect=lambda name:
                               local_user if name == "sovagrid-local" else external_user), \
             mock.patch.object(promotion.os, "getgrouplist", return_value=[1005]):
            self.assertEqual(promotion._local_identity(), (1005, 1005))
        with mock.patch.object(promotion.grp, "getgrnam", side_effect=lambda name:
                               local_group if name == "sovagrid-local" else external_group), \
             mock.patch.object(promotion.pwd, "getpwnam", side_effect=lambda name:
                               local_user if name == "sovagrid-local" else external_user), \
             mock.patch.object(promotion.os, "getgrouplist", return_value=[1005, 999]):
            with self.assertRaises(promotion.PromotionError):
                promotion._local_identity()
        same_gid = SimpleNamespace(gr_gid=999, gr_mem=[])
        with mock.patch.object(promotion.grp, "getgrnam", side_effect=lambda name:
                               same_gid if name == "sovagrid-local" else external_group), \
             mock.patch.object(promotion.pwd, "getpwnam", side_effect=lambda name:
                               local_user if name == "sovagrid-local" else external_user), \
             mock.patch.object(promotion.os, "getgrouplist", return_value=[1005]):
            with self.assertRaises(promotion.PromotionError):
                promotion._local_identity()

    def test_activation_refuses_changed_external_state_before_hub_action(self):
        with tempfile.TemporaryDirectory() as folder:
            baseline = Path(folder) / "baseline.json"
            baseline.write_text("fixture")
            with mock.patch.object(promotion, "BASELINE", baseline), \
                 mock.patch.object(promotion, "capture_external", return_value={"changed": True}), \
                 mock.patch.object(promotion, "_private_json", return_value={"changed": False}), \
                 mock.patch.object(promotion, "_with_admin") as admin:
                with self.assertRaises(promotion.PromotionError):
                    promotion.activate()
                admin.assert_not_called()

    def test_host_root_grant_stays_out_of_command_arguments(self):
        grant = "a" * 43
        response = json.dumps({"protocol": 1, "grant": grant,
                               "expires_at": 1800000000, "username": "admin"}).encode()
        calls = []

        def api(method, path, *, bearer=None, body=None):
            calls.append((method, path, bearer, body))
            if path.endswith("ssh-grant"):
                return 200, {"token": "private-session"}
            return 200, {"revoked": True}

        with mock.patch.object(promotion.subprocess, "run", return_value=SimpleNamespace(
            returncode=0, stdout=response)) as run, mock.patch.object(promotion, "_http", side_effect=api):
            result = promotion._with_admin(lambda bearer: ("admin-operation", bearer))
        self.assertEqual(result, ("admin-operation", "private-session"))
        self.assertNotIn(grant, " ".join(run.call_args.args[0]))
        self.assertEqual(calls[0], ("POST", "/api/v1/session/ssh-grant", None, {"grant": grant}))
        self.assertEqual(calls[-1][:3], ("DELETE", "/api/v1/session", "private-session"))

    def test_hub_only_does_not_install_over_external_agent_layout(self):
        script = (ROOT / "run.sh").read_text()
        self.assertEqual(subprocess.run(["bash", "-n", str(ROOT / "run.sh")], check=False).returncode, 0)
        self.assertIn("if (( ! hub_only )); then\n  install -d -o sovagrid -g sovagrid -m 0700 /var/lib/sovagrid-agent\nfi", script)
        self.assertIn("if (( ! hub_only )); then\n  install -d -o root -g root -m 0755 /opt/sovagrid-agent", script)
        self.assertIn('if (( ! hub_only )); then notice_repos+=(sovagrid-agent); fi', script)
        self.assertIn('if (( hub_only )); then\n  # The existing external Agent may trust', script)
        self.assertIn('ca_target=/var/lib/sovagrid/local-hub-ca.pem', script)
        self.assertIn('ca_target=/etc/sovagrid/hub-ca.pem', script)
        self.assertIn('context = ssl.create_default_context(cafile=sys.argv[1])', script)
        self.assertEqual(str(promotion.LOCAL_HUB_CA_STAGING), '/var/lib/sovagrid/local-hub-ca.pem')
        self.assertIn('/etc/sovagrid/hub-ca.pem', promotion.OPTIONAL_CRITICAL)

    def test_prepare_pins_one_manifest_and_rejects_a_changed_choice(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            state = base / "state"
            digest = "a" * 64
            paths = {"SOURCE": base / "source", "MANAGED_MARKER": base / "managed",
                     "LOCAL": base / "local", "BASELINE": state / "baseline.json",
                     "PIN": state / "bundle-pin.json", "STATE_DIR": state}
            previous_umask = os.umask(0o077)
            try:
                with mock.patch.multiple(promotion, **paths), \
                     mock.patch.object(promotion, "ROOT_UID", os.getuid()), \
                     mock.patch.object(promotion, "capture_external", return_value={"protocol": 1, "fixture": True}):
                    self.assertTrue(promotion.prepare(manifest_sha256=digest)["prepared"])
                    self.assertEqual(promotion._pin(), digest)
                    self.assertTrue(promotion.prepare(manifest_sha256=digest)["prepared"])
                    with self.assertRaises(promotion.PromotionError):
                        promotion.prepare(manifest_sha256="b" * 64)
            finally:
                os.umask(previous_umask)

    def test_inspect_exact_resume_phases_and_network_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            source = base / "source"
            baseline = base / "baseline.json"
            pin = base / "pin.json"
            marker = base / "managed"
            local = base / "local.json"
            external = {"protocol": 1, "fixture": "external"}
            paths = {"SOURCE": source, "BASELINE": baseline, "PIN": pin,
                     "MANAGED_MARKER": marker, "LOCAL": local,
                     "AGENT_MARKER": base / "adopted"}
            with mock.patch.multiple(promotion, **paths), \
                 mock.patch.object(promotion, "ROOT_UID", os.getuid()), \
                 mock.patch.object(promotion, "capture_external", return_value=external) as capture, \
                 mock.patch.object(promotion, "_hub_footprint", return_value=False), \
                 mock.patch.object(promotion, "_local_artifacts", return_value=False):
                eligible = promotion.inspect()
                self.assertEqual(eligible["phase"], "eligible")
                self.assertEqual(set(eligible), {"protocol", "phase", "external_agent_preserved",
                                                 "baseline_sha256", "pinned_manifest_sha256",
                                                 "source_manifest_sha256", "local_server_id", "reason_code"})
                baseline.write_text(json.dumps(external))
                baseline.chmod(0o600)
                pin.write_text(json.dumps({"protocol": 1, "manifest_sha256": "a" * 64}))
                pin.chmod(0o600)
                self.assertEqual(promotion.inspect()["phase"], "prepared")
                source.mkdir(mode=0o755)
                source.chmod(0o755)
                component = source / "sovagrid-agent"
                component.mkdir(mode=0o755)
                component.chmod(0o755)
                content = component / "sample.py"
                content.write_bytes(b"VALUE = 1\n")
                content.chmod(0o644)
                manifest = {"format": 1, "sha256": {"sovagrid-agent/sample.py":
                            hashlib.sha256(content.read_bytes()).hexdigest()}}
                manifest_path = source / "sovagrid-bundle.json"
                manifest_path.write_text(json.dumps(manifest))
                manifest_path.chmod(0o644)
                source_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
                pin.write_text(json.dumps({"protocol": 1, "manifest_sha256": source_digest}))
                self.assertEqual(promotion.inspect()["phase"], "source_staged")
                content.write_bytes(b"tampered\n")
                self.assertEqual(promotion.inspect()["reason_code"], "SOURCE_INVALID")
                content.write_bytes(b"VALUE = 1\n")
                pin.write_text(json.dumps({"protocol": 1, "manifest_sha256": "c" * 64}))
                self.assertEqual(promotion.inspect()["reason_code"], "SOURCE_MISMATCH")
                pin.write_text(json.dumps({"protocol": 1, "manifest_sha256": source_digest}))
                marker.write_bytes(b"managed\n")
                marker.chmod(0o600)
                with mock.patch.object(promotion, "_local_hub_ready", return_value=True):
                    self.assertEqual(promotion.inspect()["phase"], "hub_installed")
                    local.write_bytes(b"local\n")
                    with mock.patch.object(promotion, "_local_record", return_value="00000000-0000-4000-8000-000000000001"):
                        active = promotion.inspect()
                    self.assertEqual(active["phase"], "activated")
                    self.assertEqual(active["local_server_id"], "00000000-0000-4000-8000-000000000001")
                with mock.patch.object(promotion, "_local_hub_ready", side_effect=URLError("down")):
                    failed = promotion.inspect()
                self.assertEqual((failed["phase"], failed["reason_code"]), ("unknown", "HUB_PARTIAL"))
                capture.return_value = {"protocol": 1, "fixture": "changed"}
                changed = promotion.inspect()
                self.assertEqual((changed["phase"], changed["reason_code"]),
                                 ("external_changed", "EXTERNAL_CHANGED"))

    def test_activate_refuses_pinned_source_mismatch_before_local_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            source = base / "source"
            source.mkdir(mode=0o755)
            source.chmod(0o755)
            (source / "sovagrid-bundle.json").write_text(json.dumps({"format": 1, "sha256": {}}))
            marker = base / "managed"
            marker.write_bytes(b"managed\n")
            marker.chmod(0o600)
            baseline = base / "baseline.json"
            baseline.write_text(json.dumps({"protocol": 1, "fixture": True}))
            baseline.chmod(0o600)
            with mock.patch.object(promotion, "SOURCE", source), \
                 mock.patch.object(promotion, "MANAGED_MARKER", marker), \
                 mock.patch.object(promotion, "BASELINE", baseline), \
                 mock.patch.object(promotion, "ROOT_UID", os.getuid()), \
                 mock.patch.object(promotion, "capture_external", return_value={"protocol": 1, "fixture": True}), \
                 mock.patch.object(promotion, "_source_manifest_sha256", return_value="b" * 64), \
                 mock.patch.object(promotion, "_pin", return_value="a" * 64), \
                 mock.patch.object(promotion, "_ensure_local_private_paths") as local_paths:
                with self.assertRaises(promotion.PromotionError):
                    promotion.activate()
                local_paths.assert_not_called()


if __name__ == "__main__":
    unittest.main()
