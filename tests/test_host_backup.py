# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Offline host archive boundaries, refusal, and private publication."""

from __future__ import annotations

from contextlib import nullcontext
import fcntl
import importlib.util
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
import tarfile
from unittest.mock import patch


FILE = Path(__file__).resolve().parents[1] / "deploy" / "host_backup.py"
SPEC = importlib.util.spec_from_file_location("host_backup_under_test", FILE)
assert SPEC and SPEC.loader
backup = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = backup
SPEC.loader.exec_module(backup)


class HostBackupTest(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        (self.root / "run").mkdir()
        self.uid, self.gid = os.geteuid(), os.getegid()
        for name, value in (("ROOT", self.root), ("ROOT_UID", self.uid),
                            ("ROOT_GID", self.gid), ("HUB_UID", self.uid),
                            ("HUB_GID", self.gid),
                            ("WEB_UID", self.uid), ("WEB_GID", self.gid)):
            patcher = patch.object(backup, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.hub = self.root / "var/lib/sovagrid/hub"
        self.hub.mkdir(parents=True, mode=0o700)
        self.hub.chmod(0o700)
        self.database = self.hub / "hub.sqlite"
        self.database.write_bytes(b"offline sqlite placeholder")
        self.database.chmod(0o600)
        self.caddy = self.root / "var/lib/sovagrid/caddy"
        self.caddy.mkdir(mode=0o700)
        self.caddy.chmod(0o700)
        authority = self.caddy / "caddy/pki/authorities/local"
        authority.mkdir(parents=True)
        for name in ("root.crt", "root.key"):
            target = authority / name
            target.write_bytes(b"private fixture")
            target.chmod(0o600)
        self.config = self.root / "etc/sovagrid"
        self.config.mkdir(parents=True)
        self.password = self.config / "admin-password"
        self.password.write_bytes(b"never display this value")
        self.password.chmod(0o600)
        for name in ("agent.json", "agent.token", "hub-ca.pem"):
            target = self.config / name
            target.write_bytes(b"fixture")
            target.chmod(0o644 if name == "hub-ca.pem" else 0o640)
        (self.root / "opt/sovagrid-agent").mkdir(parents=True)
        self.sources = (
            backup.Source("/var/lib/sovagrid/hub", self.uid, "dir", True,
                          True, 0o700, self.gid),
            backup.Source("/var/lib/sovagrid/caddy", self.uid, "dir", True,
                          True, 0o700, self.gid),
            backup.Source("/etc/sovagrid/admin-password", self.uid, "file", True,
                          True, 0o600, self.gid),
            backup.Source("/etc/sovagrid/agent.json", self.uid, private=True,
                          exact_mode=0o640),
            backup.Source("/etc/sovagrid/agent.token", self.uid, private=True,
                          exact_mode=0o640),
            backup.Source("/etc/sovagrid/hub-ca.pem", self.uid),
            backup.Source("/opt/sovagrid-agent", self.uid, "dir"),
        )

    def archive(self) -> dict:
        with patch.object(backup, "_locks", return_value=nullcontext()), \
             patch.object(backup, "_require_offline"), \
             patch.object(backup, "_layout", return_value="full"), \
             patch.object(backup, "_source_manifest", return_value=None), \
             patch.object(backup, "_sources", return_value=self.sources), \
             patch.object(backup.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=self.gid)):
            return backup.create()["archive"]

    def test_direct_hub_backup_refuses_collector_lock_contention(self) -> None:
        lock = self.root / "run/sovagrid-promotion.lock"
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(backup, "_layout", return_value="hub-only"), \
                 self.assertRaisesRegex(backup.Refused, "BUSY"):
                with backup._promotion_lock():
                    self.fail("collector lock was ignored")
        finally:
            os.close(fd)

    def test_private_archive_round_trip_without_public_paths(self) -> None:
        self.assertEqual(backup.list_archives()["archives"], [])
        result = self.archive()
        self.assertEqual(result["layout"], "full")
        self.assertGreaterEqual(result["files"], 10)
        self.assertEqual(set(result), {"id", "created_at", "layout", "bytes", "files"})
        self.assertNotIn("password", str(result))
        output = self.root / "var/lib/sovagrid-host-backups"
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        for suffix in (".tar.gz", ".manifest.json"):
            self.assertEqual((output / (result["id"] + suffix)).stat().st_mode & 0o777,
                             0o600)
        self.assertEqual(backup.verify(result["id"])["verified"], True)
        self.assertEqual(backup.list_archives()["archives"], [result])

    def test_hub_only_archive_does_not_adopt_external_agent(self) -> None:
        local_sources = self.sources[:3]
        with patch.object(backup, "_locks", return_value=nullcontext()), \
             patch.object(backup, "_require_offline"), \
             patch.object(backup, "_layout", return_value="hub-only"), \
             patch.object(backup, "_source_manifest", return_value=None), \
             patch.object(backup, "_sources", return_value=local_sources):
            result = backup.create()["archive"]
        self.assertEqual(result["layout"], "hub-only")
        archive = (self.root / "var/lib/sovagrid-host-backups" /
                   (result["id"] + ".tar.gz"))
        with tarfile.open(archive, "r:gz") as stream:
            names = set(stream.getnames())
        self.assertFalse(any(name.startswith("etc/sovagrid/agent") for name in names))
        self.assertIn("etc/sovagrid/admin-password", names)
        self.assertTrue(backup.verify(result["id"])["verified"])

    def test_list_is_newest_first(self) -> None:
        first = self.archive()
        time.sleep(0.002)
        second = self.archive()
        self.assertEqual([item["id"] for item in backup.list_archives()["archives"]],
                         [second["id"], first["id"]])

    def test_prepinned_archive_id_is_used_once_for_journaled_operation(self) -> None:
        identity = "f" * 32
        with patch.object(backup, "_require_offline"), patch.object(
                backup, "_layout", return_value="full"), patch.object(
                backup, "_source_manifest", return_value=None), patch.object(
                backup, "_sources", return_value=self.sources), patch.object(
                backup.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=self.gid)):
            result = backup._create_locked(identity=identity)["archive"]
            self.assertEqual(result["id"], identity)
            with self.assertRaisesRegex(backup.Refused, "ID_CONFLICT"):
                backup._create_locked(identity=identity)
            with self.assertRaisesRegex(backup.Refused, "INVALID_ID"):
                backup._create_locked(identity="../unsafe")
        self.assertTrue(backup.verify(identity)["verified"])

    def test_symlink_and_hardlink_sources_refused_before_writing(self) -> None:
        alias = self.hub / "unexpected"
        alias.symlink_to(self.password)
        with self.assertRaises(backup.Refused):
            self.archive()
        alias.unlink()
        os.link(self.password, alias)
        with self.assertRaises(backup.Refused):
            self.archive()
        self.assertFalse((self.root / "var/lib/sovagrid-host-backups").exists())

    def test_private_bootstrap_password_mode_enforced(self) -> None:
        self.password.chmod(0o644)
        with self.assertRaisesRegex(backup.Refused, "UNSAFE_SOURCE"):
            self.archive()

    def test_publish_failure_removes_orphan_archive(self) -> None:
        real_replace = os.replace

        def fail_manifest(source, target):
            if str(target).endswith(".manifest.json"):
                raise OSError("simulated write failure")
            return real_replace(source, target)

        with patch.object(backup.os, "replace", side_effect=fail_manifest):
            with self.assertRaises(OSError):
                self.archive()
        self.assertEqual(list((self.root / "var/lib/sovagrid-host-backups").iterdir()), [])

    def test_missing_verify_and_invalid_id_are_bounded(self) -> None:
        with self.assertRaisesRegex(backup.Refused, "NOT_FOUND"):
            backup.verify("a" * 32)
        with self.assertRaisesRegex(backup.Refused, "INVALID_ID"):
            backup.verify("../../etc/shadow")

    def test_corrupt_archive_and_orphan_are_detected(self) -> None:
        result = self.archive()
        output = self.root / "var/lib/sovagrid-host-backups"
        archive = output / (result["id"] + ".tar.gz")
        with archive.open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(backup.Refused, "ARCHIVE_CHANGED"):
            backup.verify(result["id"])
        archive.unlink()
        with self.assertRaisesRegex(backup.Refused, "INCOMPLETE_ARCHIVE"):
            backup.list_archives()

    def test_full_and_hub_only_sources_do_not_adopt_external_home_agent(self) -> None:
        full = {item.path for item in backup.CORE + backup.FULL}
        local = {item.path for item in backup.CORE + backup.HUB_ONLY}
        self.assertIn("/etc/sovagrid/agent.token", full)
        self.assertIn("/etc/sovagrid-local", local)
        self.assertNotIn("/etc/sovagrid/agent.token", local)
        self.assertNotIn("/etc/sovagrid/hub-ca.pem", local)
        self.assertNotIn("/var/lib/sovagrid-agent/files", full)
        self.assertNotIn("/var/lib/sovagrid-agent-local/files", local)
        self.assertNotIn("/var/lib/sovagrid-vpn", local)
        self.assertNotIn("/etc/sovagrid-vpn", local)
        self.assertNotIn("/root/.ssh", full | local)
        self.assertNotIn("sovagrid-agent.service", backup.WRITERS["hub-only"])
        self.assertNotIn("sovagrid-agent-tunnel.service", backup.WRITERS["hub-only"])
        self.assertNotIn("sovagrid-vpn-routing.service", backup.WRITERS["full"])

    def test_plan_preserves_transport_and_blocks_only_managed_writer(self) -> None:
        unit = self.root / "etc/systemd/system/sovagrid-vpn-status.timer"
        unit.parent.mkdir(parents=True)
        unit.write_text("[Timer]\n")
        unit.chmod(0o644)

        def run(args):
            if args[0] == "systemctl":
                return ("sovagrid-agent-tunnel.service loaded active running external\n"
                        "sovagrid-agent.service loaded active running external\n"
                        "sovagrid-vpn-routing.service loaded active exited route\n"
                        "sovagrid-vpn-status.timer loaded active waiting writer\n")
            return ""

        with patch.object(backup, "_layout", return_value="hub-only"), \
             patch.object(backup, "_run", side_effect=run):
            planned = backup.plan()
            self.assertEqual(planned["active_units"], ["sovagrid-vpn-status.timer"])
            self.assertFalse(planned["offline_ready"])
            with self.assertRaisesRegex(backup.Refused, "SERVICES_RUNNING"):
                backup._require_offline("hub-only")

    def test_optional_gateway_is_managed_without_accepting_foreign_containers(self) -> None:
        identities = {"hub": "a" * 12, "web": "b" * 12,
                      "ssh-gateway": "c" * 12}

        def run(args):
            if args[0] == "systemctl":
                return ""
            service = next((item.rsplit("=", 1)[1] for item in args
                            if item.startswith("label=com.docker.compose.service=")), None)
            if service is not None:
                return identities.get(service, "")
            return "\n".join(identities.values())

        with patch.object(backup, "_layout", return_value="hub-only"), patch.object(
                backup, "_run", side_effect=run):
            del identities["ssh-gateway"]
            self.assertEqual(backup.plan()["running_containers"], ["hub", "web"])
            identities["ssh-gateway"] = "c" * 12
            with self.assertRaisesRegex(backup.Refused, "UNMANAGED_GATEWAY"):
                backup.plan()
            marker = backup._host(backup.SSH_GATEWAY_MARKER)
            marker.write_bytes(backup.SSH_GATEWAY_MARKER_CONTENT)
            marker.chmod(0o600)
            self.assertEqual(backup.plan()["running_containers"],
                             ["hub", "web", "ssh-gateway"])
            marker.write_bytes(b"wrong marker content\n")
            with self.assertRaisesRegex(backup.Refused, "UNSAFE_GATEWAY_MARKER"):
                backup.plan()
            marker.write_bytes(backup.SSH_GATEWAY_MARKER_CONTENT)
            marker.chmod(0o644)
            with self.assertRaisesRegex(backup.Refused, "UNSAFE_GATEWAY_MARKER"):
                backup.plan()
            marker.chmod(0o600)
            marker.unlink()
            marker.symlink_to(self.password)
            with self.assertRaisesRegex(backup.Refused, "UNSAFE_GATEWAY_MARKER"):
                backup.plan()
            marker.unlink()
            marker.write_bytes(backup.SSH_GATEWAY_MARKER_CONTENT)
            marker.chmod(0o600)
            identities["foreign"] = "d" * 12
            with self.assertRaisesRegex(backup.Refused, "CONTAINER_AMBIGUOUS"):
                backup.plan()
            del identities["foreign"]
            identities["ssh-gateway"] = "c" * 12 + "\n" + "d" * 12
            with self.assertRaisesRegex(backup.Refused, "CONTAINER_AMBIGUOUS"):
                backup.plan()

    def test_source_digest_is_bounded_and_requires_installed_generation(self) -> None:
        with patch.object(backup, "_require_root"), patch.object(
                backup, "_source_manifest", return_value="b" * 64):
            self.assertEqual(backup.source()["manifest_sha256"], "b" * 64)
        with patch.object(backup, "_require_root"), patch.object(
                backup, "_source_manifest", return_value=None):
            with self.assertRaisesRegex(backup.Refused, "SOURCE_UNAVAILABLE"):
                backup.source()

    def test_unknown_active_unit_is_not_silently_ignored(self) -> None:
        def run(args):
            return ("sovagrid-new-writer.service loaded active running unknown\n"
                    if args[0] == "systemctl" else "")
        with patch.object(backup, "_layout", return_value="hub-only"), \
             patch.object(backup, "_run", side_effect=run):
            with self.assertRaisesRegex(backup.Refused, "UNKNOWN_ACTIVE_UNIT"):
                backup.plan()

    def test_size_limit_rejects_unbounded_source(self) -> None:
        with patch.object(backup, "MAX_FILE_BYTES", 3):
            with self.assertRaisesRegex(backup.Refused, "SIZE_LIMIT"):
                backup._scan(self.sources, deadline=time.monotonic() + 2)


if __name__ == "__main__":
    unittest.main()
