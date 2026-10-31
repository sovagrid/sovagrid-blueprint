# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Malicious-but-hashable host archive entries must fail restore inspection."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deploy import host_restore as restore


COMPONENTS = tuple(sorted(restore.COMPONENTS))
ROOT = "opt/sovagrid-src"


def fixture_entries():
    names = set(restore.REQUIRED_BUNDLE) | {component + "/README"
                                            for component in COMPONENTS}
    files = {name: (name + "\n").encode() for name in names}
    bundle = {"format": 1,
              "components": {component: {"commit": "a" * 40,
                                        "file_count": sum(name.startswith(component + "/")
                                                          for name in names)}
                             for component in COMPONENTS},
              "sha256": {name: hashlib.sha256(raw).hexdigest()
                         for name, raw in files.items()}}
    bundle_raw = (json.dumps(bundle, sort_keys=True, indent=2) + "\n").encode()
    entries = [(ROOT, "dir", b"", 0, 0, 0o755)]
    for component in COMPONENTS:
        entries.append((ROOT + "/" + component, "dir", b"", 0, 0, 0o755))
        directories = set()
        for name in files:
            if not name.startswith(component + "/"):
                continue
            parts = name.split("/")
            directories.update("/".join(parts[:depth])
                               for depth in range(2, len(parts)))
        for directory in sorted(directories, key=lambda item: (item.count("/"), item)):
            entries.append((ROOT + "/" + directory, "dir", b"", 0, 0, 0o755))
        for name in sorted(files):
            if name.startswith(component + "/"):
                entries.append((ROOT + "/" + name, "file", files[name], 0, 0, 0o644))
    entries.append((ROOT + "/sovagrid-bundle.json", "file",
                    bundle_raw, 0, 0, 0o644))
    return entries, hashlib.sha256(bundle_raw).hexdigest()


def make_archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, kind, contents, uid, gid, mode in entries:
            member = tarfile.TarInfo(name + ("/" if kind == "dir" else ""))
            member.uid, member.gid, member.mode = uid, gid, mode
            member.mtime = 1_700_000_000
            member.type = {"dir": tarfile.DIRTYPE, "file": tarfile.REGTYPE,
                           "symlink": tarfile.SYMTYPE,
                           "hardlink": tarfile.LNKTYPE}[kind]
            member.size = len(contents) if kind == "file" else 0
            archive.addfile(member, io.BytesIO(contents) if kind == "file" else None)
    return output.getvalue()


class RestoreInspectionTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.sources = (restore.backup.Source("/opt/sovagrid-src", kind="dir"),)
        self.entries, self.source_sha = fixture_entries()
        required = {"/opt/sovagrid-src", "/opt/sovagrid-src/sovagrid-bundle.json"}
        self.real_required = restore._required
        patcher = patch.object(restore, "_required", return_value=required)
        patcher.start()
        self.addCleanup(patcher.stop)

    def inspect(self, entries=None, *, source_sha=None):
        selected = self.entries if entries is None else entries
        content = make_archive(selected)
        path = self.folder / "archive.tar.gz"
        path.write_bytes(content)
        manifest = {"id": "a" * 32, "created_at": "2026-10-27T00:00:00+00:00",
                    "files": len(selected), "bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(), "layout": "full",
                    "source_manifest_sha256": self.source_sha if source_sha is None
                    else source_sha}
        fd = os.open(path, os.O_RDONLY)
        try:
            restore._hash_archive(fd, manifest, deadline=time.monotonic() + 10)
            return restore._inspect_tar(
                fd, manifest, self.sources, deadline=time.monotonic() + 10)
        finally:
            os.close(fd)

    def test_exact_archive_and_embedded_bundle_are_verified_without_extraction(self):
        result = self.inspect()
        self.assertEqual(result["entries"], len(self.entries))
        self.assertEqual(result["generated_bytecode_files"], 0)
        self.assertEqual(result["source_manifest_sha256"], self.source_sha)

    def test_digest_of_archive_alone_cannot_authorize_unsafe_member(self):
        attacks = (
            ("traversal", ("etc/../root/.ssh/id", "file", b"x", 0, 0, 0o600)),
            ("foreign_path", ("root/.ssh/id", "file", b"x", 0, 0, 0o600)),
            ("symlink", (ROOT + "/sovagrid-hub/link", "symlink", b"", 0, 0, 0o644)),
            ("hardlink", (ROOT + "/sovagrid-hub/link", "hardlink", b"", 0, 0, 0o644)),
            ("world_writable", (ROOT + "/sovagrid-hub/README", "file", b"x", 0, 0, 0o666)),
            ("wrong_owner", (ROOT + "/sovagrid-hub/README", "file", b"x", 10001, 0, 0o644)),
        )
        for label, item in attacks:
            with self.subTest(label=label):
                selected = list(self.entries)
                if label in ("world_writable", "wrong_owner"):
                    selected = [item if original[0] == item[0] else original
                                for original in selected]
                else:
                    selected.append(item)
                # The test's tar is otherwise well formed and its own SHA can
                # be updated by an attacker; metadata validation still refuses.
                with self.assertRaises(restore.Refused):
                    self.inspect(selected)

    def test_duplicate_and_missing_source_member_are_refused(self):
        with self.assertRaisesRegex(restore.Refused, "INVALID_ARCHIVE"):
            self.inspect(self.entries + [self.entries[-1]])
        with self.assertRaisesRegex(restore.Refused, "INVALID_ARCHIVE"):
            self.inspect(self.entries[:-1])

    def test_extra_source_tree_entries_are_refused(self):
        attacks = (
            (ROOT + "/evil", "dir", b"", 0, 0, 0o755),
            (ROOT + "/sovagrid-hub/empty", "dir", b"", 0, 0, 0o755),
            (ROOT + "/sovagrid-hub/unlisted.txt", "file", b"x", 0, 0, 0o644),
        )
        for entry in attacks:
            with self.subTest(path=entry[0]):
                with self.assertRaises(restore.Refused):
                    self.inspect(self.entries + [entry])

    def test_child_of_regular_file_is_refused(self):
        selected = [(name, "file" if name == ROOT + "/sovagrid-hub" else kind,
                     raw, uid, gid, mode)
                    for name, kind, raw, uid, gid, mode in self.entries]
        with self.assertRaisesRegex(restore.Refused, "INVALID_ARCHIVE"):
            self.inspect(selected)

    def test_parent_directory_must_precede_child_in_archive(self):
        selected = self.entries[1:] + self.entries[:1]
        with self.assertRaisesRegex(restore.Refused, "INVALID_ARCHIVE"):
            self.inspect(selected)

    def test_direct_child_allowlist_matches_archive_creator(self):
        syntax = ast.parse(Path(restore.backup.__file__).read_text())
        scanner = next(node for node in syntax.body
                       if isinstance(node, ast.FunctionDef) and node.name == "_scan")
        assignment = next(node for node in ast.walk(scanner)
                          if isinstance(node, ast.Assign) and
                          any(isinstance(target, ast.Name) and target.id == "allowed"
                              for target in node.targets))
        self.assertIsInstance(assignment.value, ast.Call)
        creator_allowlist = ast.literal_eval(assignment.value.func.value)
        self.assertEqual({path: set(names) for path, names in restore.DIRECT_FILES.items()},
                         creator_allowlist)

    def test_required_bundle_files_match_installed_updater_schema(self):
        updater = Path(restore.backup.__file__).with_name("remote_update_worker.py")
        syntax = ast.parse(updater.read_text())
        assignment = next(node for node in syntax.body
                          if isinstance(node, ast.Assign) and
                          any(isinstance(target, ast.Name) and target.id == "REQUIRED"
                              for target in node.targets))
        self.assertEqual(set(restore.REQUIRED_BUNDLE), ast.literal_eval(assignment.value))

    def test_optional_managed_state_from_multiple_features_is_accepted(self):
        roots = ("/var/lib/sovagrid/hub", "/etc/sovagrid-vpn",
                 "/etc/sovagrid-service", "/var/lib/sovagrid/vpn",
                 "/var/lib/sovagrid-containers")
        candidates = restore.backup.CORE + restore.backup.FULL
        self.sources += tuple(next(source for source in candidates if source.path == root)
                              for root in roots)
        optional = [
            ("var/lib/sovagrid/hub", "dir", b"", 10001, 10001, 0o700),
            ("var/lib/sovagrid/hub/hub.sqlite", "file", b"SQLite", 10001, 10001, 0o600),
            ("var/lib/sovagrid/hub/hub.sqlite-wal", "file", b"WAL", 10001, 10001, 0o600),
            ("etc/sovagrid-vpn", "dir", b"", 0, 0, 0o700),
            ("etc/sovagrid-vpn/amnezia-control.enabled", "file", b"yes", 0, 0, 0o600),
            ("etc/sovagrid-service", "dir", b"", 0, 0, 0o700),
            ("etc/sovagrid-service/units.json", "file", b"{}", 0, 0, 0o600),
            ("var/lib/sovagrid/vpn", "dir", b"", 0, 10001, 0o750),
            ("var/lib/sovagrid/vpn/status.json", "file", b"{}", 0, 10001, 0o640),
            ("var/lib/sovagrid-containers", "dir", b"", 0, 0, 0o700),
            ("var/lib/sovagrid-containers/snapshot.json", "file", b"{}", 0, 0, 0o644),
        ]
        self.assertEqual(self.inspect(self.entries + optional)["entries"],
                         len(self.entries) + len(optional))
        foreign = ("var/lib/sovagrid/hub/foreign", "file", b"x", 10001, 10001, 0o600)
        with self.assertRaisesRegex(restore.Refused, "UNEXPECTED_PATH"):
            self.inspect(self.entries + optional + [foreign])

    def test_gateway_marker_is_optional_but_must_be_exact_when_archived(self):
        marker = restore.backup.SSH_GATEWAY_MARKER
        self.assertIn(marker, {source.path for source in restore.backup.CORE})
        self.sources += (next(source for source in restore.backup.CORE
                              if source.path == marker),)
        entry = (marker.lstrip("/"), "file",
                 restore.backup.SSH_GATEWAY_MARKER_CONTENT, 0, 0, 0o600)
        self.assertEqual(self.inspect(self.entries + [entry])["entries"],
                         len(self.entries) + 1)
        bad = (entry[0], entry[1], b"unmanaged gateway\n", 0, 0, 0o600)
        with self.assertRaisesRegex(restore.Refused, "INVALID_ARCHIVE"):
            self.inspect(self.entries + [bad])

    def test_web_agent_recovery_state_is_private_and_content_addressed(self):
        backup = restore.backup
        self.sources += tuple(next(source for source in backup.CORE
                                   if source.path == path)
                              for path in (backup.WEB_AGENT_MARKER,
                                           backup.WEB_AGENT_DIR))
        self.sources += tuple(backup.Source(path, exact_mode=0o644, gid=0)
                              for path in backup.WEB_AGENT_UNIT_PATHS)
        raw = b"pinned source bundle\n"
        digest = hashlib.sha256(raw).hexdigest()
        prefix = backup.WEB_AGENT_DIR.lstrip("/")
        entries = [
            (backup.WEB_AGENT_MARKER.lstrip("/"), "file",
             backup.WEB_AGENT_MARKER_CONTENT, 0, 0, 0o600),
            (prefix, "dir", b"", 0, 0, 0o700),
            (prefix + "/jobs", "dir", b"", 0, 0, 0o700),
            (prefix + "/.bundle.lock", "file", b"", 0, 0, 0o600),
            (prefix + "/source-" + digest + ".tar.gz", "file", raw, 0, 0, 0o600),
            (prefix + "/jobs/" + "a" * 32 + ".json", "file",
             b'{"phase":"prepared"}\n', 0, 0, 0o600),
            (prefix + "/completed-enrollments.jsonl", "file",
             b'{"event":"complete"}\n', 0, 0, 0o600),
            *((path.lstrip("/"), "file", b"[Unit]\n", 0, 0, 0o644)
              for path in backup.WEB_AGENT_UNIT_PATHS),
        ]
        present = {"/" + item[0] for item in entries}
        self.assertTrue(backup._web_agent_required(present) <= present)
        self.assertEqual(self.inspect(self.entries + entries)["entries"],
                         len(self.entries) + len(entries))
        for label, needle, replacement in (
                ("marker", backup.WEB_AGENT_MARKER.lstrip("/"), b"wrong marker\n"),
                ("bundle", prefix + "/source-" + digest + ".tar.gz", b"wrong bytes")):
            with self.subTest(label=label):
                altered = [(name, kind, replacement if name == needle else contents,
                            uid, gid, mode)
                           for name, kind, contents, uid, gid, mode in entries]
                with self.assertRaisesRegex(restore.Refused, "INVALID_ARCHIVE"):
                    self.inspect(self.entries + altered)
        for path in (prefix + "/credentials", prefix + "/jobs/foreign.json"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(restore.Refused, "UNEXPECTED_PATH"):
                    self.inspect(self.entries + entries +
                                 [(path, "file", b"secret", 0, 0, 0o600)])
        bad_mode = [(name, kind, contents, uid, gid,
                     0o644 if name == prefix + "/completed-enrollments.jsonl" else mode)
                    for name, kind, contents, uid, gid, mode in entries]
        with self.assertRaisesRegex(restore.Refused, "INVALID_ARCHIVE"):
            self.inspect(self.entries + bad_mode)
        with self.assertRaisesRegex(restore.Refused, "INVALID_ARCHIVE"):
            self.real_required("full", present - {backup.WEB_AGENT_MARKER})
        with self.assertRaisesRegex(restore.Refused, "INVALID_ARCHIVE"):
            self.real_required("full", present - {backup.WEB_AGENT_JOBS})

    def test_local_panel_generation_is_in_full_and_hub_only_archives(self):
        source = next(item for item in restore.backup.CORE
                      if item.path == "/etc/sovagrid/local-web")
        self.assertEqual((source.kind, source.private, source.exact_mode, source.gid),
                         ("dir", True, 0o700, 0))
        self.sources += (source,)
        generation = "a" * 32
        prefix = "etc/sovagrid/local-web"
        entries = [
            (prefix, "dir", b"", 0, 0, 0o700),
            (prefix + "/.managed", "file", b"SOVAGRID_LOCAL_WEB_V1\n", 0, 0, 0o600),
            (prefix + "/generations", "dir", b"", 0, 0, 0o700),
            (prefix + "/generations/" + generation, "dir", b"", 0, 0, 0o700),
            (prefix + "/generations/" + generation + "/caddy", "dir", b"", 0, 0, 0o755),
            (prefix + "/generations/" + generation + "/caddy/panel.caddy",
             "file", b"# route\n", 0, 0, 0o644),
            (prefix + "/generations/" + generation + "/compose.yaml",
             "file", b"services: {}\n", 0, 0, 0o644),
            (prefix + "/state.json", "file", b"{}\n", 0, 0, 0o600),
        ]
        self.assertEqual(self.inspect(self.entries + entries)["entries"],
                         len(self.entries) + len(entries))

    def test_required_caddy_ca_matches_current_archive_creator(self):
        required = self.real_required("full", set())
        self.assertIn("/var/lib/sovagrid/caddy/caddy/pki/authorities/local/root.crt",
                      required)
        self.assertIn("/var/lib/sovagrid/caddy/caddy/pki/authorities/local/root.key",
                      required)

    def test_known_private_file_checks_owner_group_and_mode(self):
        source = restore.backup.CORE[0]
        member = tarfile.TarInfo("var/lib/sovagrid/hub/hub.sqlite")
        member.type = tarfile.REGTYPE
        member.uid, member.gid, member.mode = 10001, 10001, 0o600
        parent = {"/var/lib/sovagrid/hub"}
        restore._check_member("/var/lib/sovagrid/hub/hub.sqlite", member,
                              False, (source,), parent)
        for uid, gid, mode in ((0, 10001, 0o600),
                               (10001, 0, 0o600),
                               (10001, 10001, 0o644)):
            member.uid, member.gid, member.mode = uid, gid, mode
            with self.subTest(uid=uid, gid=gid, mode=mode):
                with self.assertRaisesRegex(restore.Refused, "INVALID_ARCHIVE"):
                    restore._check_member("/var/lib/sovagrid/hub/hub.sqlite",
                                          member, False, (source,), parent)

    def test_vpn_routing_lock_requires_exact_private_metadata(self):
        source = next(item for item in restore.backup.CORE
                      if item.path == "/etc/sovagrid-vpn-routing")
        member = tarfile.TarInfo("etc/sovagrid-vpn-routing/lock")
        member.type = tarfile.REGTYPE
        member.uid, member.gid, member.mode, member.size = 0, 0, 0o600, 0
        directory = {"/etc/sovagrid-vpn-routing"}
        restore._check_member("/etc/sovagrid-vpn-routing/lock", member,
                              False, (source,), directory)
        for uid, gid, mode, size in ((1, 0, 0o600, 0), (0, 1, 0o600, 0),
                                    (0, 0, 0o640, 0), (0, 0, 0o600, 1)):
            with self.subTest(uid=uid, gid=gid, mode=mode, size=size):
                member.uid, member.gid, member.mode, member.size = uid, gid, mode, size
                with self.assertRaisesRegex(restore.Refused, "INVALID_ARCHIVE"):
                    restore._check_member("/etc/sovagrid-vpn-routing/lock", member,
                                          False, (source,), directory)

    def test_agent_group_is_checked_from_archive_on_clean_target(self):
        full = restore.backup.CORE + restore.backup.FULL
        self.sources += tuple(next(source for source in full if source.path == path)
                              for path in ("/etc/sovagrid/agent.json",
                                           "/etc/sovagrid/agent.token"))
        entries = self.entries + [
            ("etc/sovagrid/agent.json", "file", b"{}", 0, 20042, 0o640),
            ("etc/sovagrid/agent.token", "file", b"secret", 0, 20042, 0o640),
        ]
        with patch.object(restore.backup.grp, "getgrnam", side_effect=KeyError):
            self.assertEqual(self.inspect(entries)["entries"], len(entries))
            for wrong in ((0, 0o640), (20043, 0o640), (20042, 0o600)):
                with self.subTest(wrong=wrong):
                    damaged = entries[:-1] + [(entries[-1][0], "file", b"secret", 0,
                                               wrong[0], wrong[1])]
                    with self.assertRaisesRegex(restore.Refused, "INVALID_ARCHIVE"):
                        self.inspect(damaged)

    def test_local_agent_group_must_match_all_three_archived_files(self):
        local = next(source for source in restore.backup.HUB_ONLY
                     if source.path == "/etc/sovagrid-local")
        self.sources += (local,)
        entries = self.entries + [
            ("etc/sovagrid-local", "dir", b"", 0, 0, 0o700),
            ("etc/sovagrid-local/agent.json", "file", b"{}", 0, 20043, 0o640),
            ("etc/sovagrid-local/agent.token", "file", b"secret", 0, 20043, 0o640),
            ("etc/sovagrid-local/hub-ca.pem", "file", b"CA", 0, 20043, 0o640),
        ]
        with patch.object(restore.backup.grp, "getgrnam", side_effect=KeyError):
            self.assertEqual(self.inspect(entries)["entries"], len(entries))
            damaged = entries[:-1] + [(entries[-1][0], "file", b"CA", 0, 20044,
                                       0o640)]
            with self.assertRaisesRegex(restore.Refused, "INVALID_ARCHIVE"):
                self.inspect(damaged)

    def test_bundle_sha_and_file_map_must_match_archived_contents(self):
        with self.assertRaisesRegex(restore.Refused, "INVALID_BUNDLE"):
            self.inspect(source_sha="b" * 64)
        selected = [(name, kind, b"changed" if name.endswith("sovagrid-hub/README")
                     else raw, uid, gid, mode)
                    for name, kind, raw, uid, gid, mode in self.entries]
        with self.assertRaisesRegex(restore.Refused, "INVALID_BUNDLE"):
            self.inspect(selected)
        bundle = json.loads(self.entries[-1][2])
        bundle["sha256"]["sovagrid-hub/unlisted"] = "f" * 64
        bundle["components"]["sovagrid-hub"]["file_count"] += 1
        raw = json.dumps(bundle, sort_keys=True).encode()
        selected = self.entries[:-1] + [(ROOT + "/sovagrid-bundle.json", "file",
                                         raw, 0, 0, 0o644)]
        with self.assertRaisesRegex(restore.Refused, "INVALID_BUNDLE"):
            self.inspect(selected, source_sha=hashlib.sha256(raw).hexdigest())

    def test_required_same_host_state_is_exact_and_apply_is_absent(self):
        self.assertIn("/var/lib/sovagrid/hub/hub.sqlite",
                      self.real_required("full", set()))
        self.assertIn("/etc/sovagrid-local/agent.token",
                      self.real_required("hub-only", {"/etc/sovagrid-local/agent.json"}))
        self.assertFalse(hasattr(restore, "apply"))
        with patch.object(restore.os, "geteuid", return_value=501):
            with self.assertRaisesRegex(restore.Refused, "ROOT_REQUIRED"):
                restore.verify("a" * 32)

    def test_plan_reports_layout_and_source_mismatch_without_apply(self):
        verified = {"ok": True, "archive": {"layout": "full"},
                    "source_manifest_sha256": "a" * 64}
        with (patch.object(restore, "verify", return_value=verified),
              patch.object(restore.backup, "plan", return_value={
                  "layout": "hub-only", "running_containers": ["hub", "web", "ssh-gateway"],
                  "active_units": [], "offline_ready": False}),
              patch.object(restore.backup, "_source_manifest", return_value="b" * 64)):
            result = restore.plan("a" * 32)
        self.assertFalse(result["apply_available"])
        self.assertEqual(result["target_running_containers"],
                         ["hub", "web", "ssh-gateway"])
        self.assertEqual(result["blockers"], ["APPLY_NOT_IMPLEMENTED",
                                              "LAYOUT_MISMATCH", "SOURCE_MISMATCH"])
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(restore.main(["apply", "a" * 32]), 40)
        self.assertEqual(json.loads(output.getvalue())["error"], "USAGE")

    def test_plan_flags_degraded_gateway_host_without_starting_containers(self):
        verified = {"ok": True, "archive": {"layout": "full"},
                    "source_manifest_sha256": "a" * 64}
        with (patch.object(restore, "verify", return_value=verified),
              patch.object(restore.backup, "plan", return_value={
                  "layout": "full", "running_containers": ["hub", "ssh-gateway"],
                  "active_units": [], "offline_ready": False}),
              patch.object(restore.backup, "_source_manifest", return_value="a" * 64)):
            result = restore.plan("a" * 32)
        self.assertEqual(result["blockers"], ["APPLY_NOT_IMPLEMENTED",
                                              "TARGET_STACK_DEGRADED"])

    def test_plan_accepts_legacy_hub_web_target_without_gateway(self):
        verified = {"ok": True, "archive": {"layout": "hub-only"},
                    "source_manifest_sha256": "a" * 64}
        with (patch.object(restore, "verify", return_value=verified),
              patch.object(restore.backup, "plan", return_value={
                  "layout": "hub-only", "running_containers": ["hub", "web"],
                  "active_units": [], "offline_ready": False}),
              patch.object(restore.backup, "_source_manifest", return_value="a" * 64)):
            result = restore.plan("a" * 32)
        self.assertEqual(result["blockers"], ["APPLY_NOT_IMPLEMENTED"])
        self.assertTrue(result["same_layout"])
        self.assertTrue(result["same_source"])

    def test_archive_hash_pin_rejects_modified_compressed_bytes(self):
        content = make_archive(self.entries)
        path = self.folder / "pinned.tar.gz"
        path.write_bytes(content)
        manifest = {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        fd = os.open(path, os.O_RDONLY)
        try:
            restore._hash_archive(fd, manifest, deadline=time.monotonic() + 10)
            altered = bytearray(content)
            altered[-1] ^= 1
            path.write_bytes(altered)
            with self.assertRaisesRegex(restore.Refused, "ARCHIVE_CHANGED"):
                restore._hash_archive(fd, manifest, deadline=time.monotonic() + 10)
        finally:
            os.close(fd)

    def test_clean_target_plan_verifies_archive_without_extracting(self):
        content = make_archive(self.entries)
        archive = self.folder / "copied-host.tar.gz"
        archive.write_bytes(content)
        target = self.folder / "clean-root"
        target.mkdir()
        manifest = {"id": "a" * 32, "created_at": "2026-10-27T00:00:00+00:00",
                    "files": len(self.entries), "bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(), "layout": "full",
                    "source_manifest_sha256": self.source_sha}
        def archive_fd(_identity):
            return os.open(archive, os.O_RDONLY), manifest
        with (patch.object(restore, "_archive_fd", side_effect=archive_fd),
              patch.object(restore, "_require_root"),
              patch.object(restore.backup, "_sources", return_value=self.sources),
              patch.object(restore.backup, "ROOT", target),
              patch.object(restore.backup, "ROOT_UID", os.geteuid()),
              patch.object(restore, "_identity_conflicts", return_value=0)):
            clean = restore.clean_plan("a" * 32)
            self.assertTrue(clean["verified"])
            self.assertTrue(clean["target_empty"])
            self.assertFalse(clean["apply_available"])
            self.assertEqual(clean["target_conflicts"], 0)
            self.assertEqual(clean["target_unsafe_paths"], 0)
            self.assertEqual(clean["target_identity_conflicts"], 0)
            self.assertEqual(clean["blockers"], ["APPLY_NOT_IMPLEMENTED",
                                                  "DOCKER_IMAGES_NOT_INCLUDED"])
            self.assertEqual(list(target.iterdir()), [])

            # A copied image sidecar is backup input, not installed state.
            image_sidecar = target / "var/lib/sovagrid-host-image-exports"
            image_sidecar.mkdir(parents=True)
            with_sidecar = restore.clean_plan("a" * 32)
            self.assertTrue(with_sidecar["target_empty"])
            image_sidecar.rmdir()

            managed = target / "var/lib/sovagrid"
            managed.mkdir(parents=True)
            occupied = restore.clean_plan("a" * 32)
            self.assertFalse(occupied["target_empty"])
            self.assertGreater(occupied["target_conflicts"], 0)
            self.assertIn("TARGET_STATE_PRESENT", occupied["blockers"])

            managed.rmdir()
            (target / "etc").symlink_to(self.folder)
            unsafe = restore.clean_plan("a" * 32)
            self.assertFalse(unsafe["target_empty"])
            self.assertGreater(unsafe["target_unsafe_paths"], 0)
            self.assertIn("TARGET_PATH_UNSAFE", unsafe["blockers"])

            (target / "etc").unlink()
            future = target / "etc/systemd/system/sovagrid-future.service"
            future.parent.mkdir(parents=True)
            future.write_text("[Unit]\nDescription=unknown\n")
            unknown = restore.clean_plan("a" * 32)
            self.assertFalse(unknown["target_empty"])
            self.assertIn("TARGET_STATE_PRESENT", unknown["blockers"])

    def test_clean_target_identity_collision_blocks_restore(self):
        target = self.folder / "identity-root"
        target.mkdir()
        sample = {"ok": True, "protocol": restore.PROTOCOL, "verified": True,
                  "archive": {"layout": "full"},
                  "identities": {"users": {"sovagrid-hub": 10001},
                                 "groups": {"sovagrid-hub": 10001}}}
        with (patch.object(restore, "verify", return_value=sample),
              patch.object(restore.backup, "_sources", return_value=()),
              patch.object(restore.backup, "ROOT", target),
              patch.object(restore.backup, "ROOT_UID", os.geteuid()),
              patch.object(restore, "_identity_conflicts", return_value=1)):
            result = restore.clean_plan("a" * 32)
        self.assertFalse(result["target_empty"])
        self.assertEqual(result["target_identity_conflicts"], 1)
        self.assertIn("TARGET_IDENTITY_CONFLICT", result["blockers"])

    def test_identity_plan_uses_archived_dynamic_gid_and_checks_nss(self):
        present = {"/etc/sovagrid/agent.json", "/etc/sovagrid/agent.token",
                   restore.backup.WEB_AGENT_MARKER,
                   "/etc/sovagrid/.terminal-unit-managed-by-run-sh"}
        identities = restore._identities(present, {
            "/etc/sovagrid/agent.json": 12345,
            "/etc/sovagrid/agent.token": 12345,
        })
        self.assertEqual(identities["groups"]["sovagrid"], 12345)
        self.assertEqual(identities["groups"]["sovagrid-web-agent"], 10005)
        self.assertEqual(identities["users"]["sovagrid-shell"], 10003)

        def missing(_value):
            raise KeyError

        with (patch.object(restore.pwd, "getpwnam", side_effect=missing),
              patch.object(restore.pwd, "getpwuid", side_effect=missing),
              patch.object(restore.grp, "getgrnam", side_effect=missing),
              patch.object(restore.grp, "getgrgid", side_effect=missing)):
            self.assertEqual(restore._identity_conflicts(identities), 0)

        # An existing unrelated group at the archived Agent GID cannot be
        # silently reused, even when all SovaGrid names are still free.
        def group_gid(gid):
            if gid == 12345:
                return SimpleNamespace(gr_name="other-service")
            raise KeyError

        with (patch.object(restore.pwd, "getpwnam", side_effect=missing),
              patch.object(restore.pwd, "getpwuid", side_effect=missing),
              patch.object(restore.grp, "getgrnam", side_effect=missing),
              patch.object(restore.grp, "getgrgid", side_effect=group_gid)):
            self.assertEqual(restore._identity_conflicts(identities), 1)

    def test_hub_only_local_agent_gid_belongs_to_local_group(self):
        identities = restore._identities({"/etc/sovagrid-local/agent.json"}, {
            "/etc/sovagrid-local/agent.json": 12346,
        })
        self.assertEqual(identities["groups"]["sovagrid-local"], 12346)
        self.assertNotIn("sovagrid", identities["groups"])

        def missing(_value):
            raise KeyError

        def group_gid(gid):
            if gid == 12346:
                return SimpleNamespace(gr_name="foreign-group")
            raise KeyError

        with (patch.object(restore.pwd, "getpwnam", side_effect=missing),
              patch.object(restore.pwd, "getpwuid", side_effect=missing),
              patch.object(restore.grp, "getgrnam", side_effect=missing),
              patch.object(restore.grp, "getgrgid", side_effect=group_gid)):
            self.assertEqual(restore._identity_conflicts(identities), 1)

        def local_user(name):
            if name == "sovagrid-local":
                return SimpleNamespace(pw_uid=12347, pw_gid=22222)
            raise KeyError

        with (patch.object(restore.pwd, "getpwnam", side_effect=local_user),
              patch.object(restore.pwd, "getpwuid", side_effect=missing),
              patch.object(restore.grp, "getgrnam", side_effect=missing),
              patch.object(restore.grp, "getgrgid", side_effect=missing)):
            self.assertEqual(restore._identity_conflicts(identities), 1)

    def test_clean_plan_cli_never_exposes_paths_or_enables_apply(self):
        sample = {"ok": True, "protocol": restore.PROTOCOL, "verified": True,
                  "archive": {"id": "a" * 32}, "target_kind": "clean",
                  "target_empty": False, "target_conflicts": 2,
                  "target_unsafe_paths": 0, "apply_available": False,
                  "blockers": ["APPLY_NOT_IMPLEMENTED", "TARGET_STATE_PRESENT"]}
        with (patch.object(restore, "clean_plan", return_value=sample),
              patch("sys.stdout", new_callable=io.StringIO) as output):
            self.assertEqual(restore.main(["clean-plan", "a" * 32]), 0)
        self.assertEqual(json.loads(output.getvalue()), sample)
        self.assertNotIn("/var/lib", output.getvalue())

    def _stage_fixture(self):
        content = make_archive(self.entries)
        archive = self.folder / "stage-archive.tar.gz"
        archive.write_bytes(content)
        target = self.folder / "stage-clean-root"
        (target / "var/lib").mkdir(parents=True)
        manifest = {"id": "a" * 32, "created_at": "2026-10-27T00:00:00+00:00",
                    "files": len(self.entries), "bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(), "layout": "full",
                    "source_manifest_sha256": self.source_sha}
        return archive, target, manifest

    def test_private_staging_is_atomic_and_does_not_install_files(self):
        archive, target, manifest = self._stage_fixture()
        def archive_fd(_identity):
            return os.open(archive, os.O_RDONLY), manifest
        with (patch.object(restore, "_archive_fd", side_effect=archive_fd),
              patch.object(restore, "_require_root"),
              patch.object(restore.backup, "_sources", return_value=self.sources),
              patch.object(restore.backup, "ROOT", target),
              patch.object(restore.backup, "ROOT_UID", os.geteuid()),
              patch.object(restore.backup, "ROOT_GID", os.getegid())):
            result = restore.stage("a" * 32)
            self.assertTrue(result["staged"])
            self.assertFalse(result["apply_available"])
            self.assertIn("DOCKER_IMAGES_NOT_INCLUDED", result["blockers"])
            staged = target / "var/lib/.sovagrid-host-restore-staging" / ("a" * 32)
            self.assertEqual((staged / "opt/sovagrid-src/sovagrid-hub/README").read_bytes(),
                             b"sovagrid-hub/README\n")
            self.assertEqual(stat.S_IMODE((staged / "opt/sovagrid-src/sovagrid-hub/README")
                                           .stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o700)
            receipt = json.loads((staged / "receipt.json").read_text())
            self.assertEqual(receipt["archive_sha256"], manifest["sha256"])
            self.assertEqual(restore.stage_status("a" * 32)["verified"], True)
            self.assertFalse((target / "opt").exists())
            self.assertFalse((target / "etc").exists())
            with self.assertRaisesRegex(restore.Refused, "STAGE_EXISTS"):
                restore.stage("a" * 32)
            self.assertEqual([item.name for item in staged.parent.iterdir()],
                             ["a" * 32])
            sample = staged / "opt/sovagrid-src/sovagrid-hub/README"
            sample.write_bytes(b"tampered\n")
            with self.assertRaisesRegex(restore.Refused, "STAGE_CHANGED"):
                restore.stage_status("a" * 32)
            sample.write_bytes(b"sovagrid-hub/README\n")
            extra = staged / "foreign-file"
            extra.write_bytes(b"x")
            extra.chmod(0o600)
            with self.assertRaisesRegex(restore.Refused, "STAGE_CHANGED"):
                restore.stage_status("a" * 32)

    def test_staging_refuses_occupied_target_before_creating_stage_root(self):
        archive, target, manifest = self._stage_fixture()
        (target / "etc/sovagrid").mkdir(parents=True)
        def archive_fd(_identity):
            return os.open(archive, os.O_RDONLY), manifest
        with (patch.object(restore, "_archive_fd", side_effect=archive_fd),
              patch.object(restore, "_require_root"),
              patch.object(restore.backup, "_sources", return_value=self.sources),
              patch.object(restore.backup, "ROOT", target),
              patch.object(restore.backup, "ROOT_UID", os.geteuid())):
            with self.assertRaisesRegex(restore.Refused, "TARGET_NOT_CLEAN"):
                restore.stage("a" * 32)
        self.assertFalse((target / "var/lib/.sovagrid-host-restore-staging").exists())

    def test_changed_archive_during_materialization_cleans_incomplete_stage(self):
        archive, target, manifest = self._stage_fixture()
        def archive_fd(_identity):
            return os.open(archive, os.O_RDONLY), manifest
        original = restore._materialize
        def tamper(*args, **kwargs):
            original(*args, **kwargs)
            with archive.open("ab") as stream:
                stream.write(b"changed")
        with (patch.object(restore, "_archive_fd", side_effect=archive_fd),
              patch.object(restore, "_require_root"),
              patch.object(restore.backup, "_sources", return_value=self.sources),
              patch.object(restore.backup, "ROOT", target),
              patch.object(restore.backup, "ROOT_UID", os.geteuid()),
              patch.object(restore.backup, "ROOT_GID", os.getegid()),
              patch.object(restore, "_materialize", side_effect=tamper)):
            with self.assertRaisesRegex(restore.Refused, "ARCHIVE_CHANGED"):
                restore.stage("a" * 32)
        stage_root = target / "var/lib/.sovagrid-host-restore-staging"
        self.assertEqual(list(stage_root.iterdir()), [])
        self.assertFalse((target / "opt").exists())


if __name__ == "__main__":
    unittest.main()
