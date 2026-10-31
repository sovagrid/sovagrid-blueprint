# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""External Agent update planning preserves enrollment and refuses unsafe sources."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
spec = importlib.util.spec_from_file_location("sovagrid_external_agent_preflight_test",
                                              DEPLOY / "external_agent_update.py")
assert spec and spec.loader
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)

OLD = "a" * 64
NEW = "b" * 64
ARCHIVE = "c" * 64
BASELINE = "d" * 64


def bundle(main_hash: str) -> dict:
    return {"format": 1, "components": {}, "sha256": {
        planner.remote.SELF_NAME: "1" * 64,
        "sovagrid-agent/LICENSE": "2" * 64,
        "sovagrid-agent/NOTICE": "3" * 64,
        "sovagrid-agent/ATTRIBUTION.md": "4" * 64,
        "sovagrid-agent/deploy/sovagrid-agent.service": "5" * 64,
        "sovagrid-agent/sovagrid_agent/agent.py": "9" * 64,
        "sovagrid-agent/sovagrid_agent/trial_gate.py": "8" * 64,
        "sovagrid-agent/sovagrid_agent/__main__.py": main_hash,
    }}


def enrolled(before: dict) -> dict:
    source_files = planner.remote.Enrollment.installed_projection(before)
    owned = {**source_files, planner.MANIFEST_FILE: OLD,
             planner.AGENT_UNIT_FILE: before["sha256"]["sovagrid-agent/deploy/sovagrid-agent.service"],
             "/etc/sovagrid/agent.token": "9" * 64,
             "/etc/sovagrid/hub-ca.pem": "8" * 64}
    return {"protocol": 1, "kind": "target", "phase": "active", "removed": False,
            "identity": {"request_id": "request", "server_id": "server", "enrollment_id": "enrollment"},
            "source_manifest_sha256": OLD, "source_files": source_files,
            "owned_files": owned, "file_metadata": {path: {"mode": 0o644, "gid": 0} for path in owned},
            "owned_directories": {},
            "pending_writes": {}, "agent_token_sha256": "9" * 64,
            "ssh_public_key": "ssh-ed25519 fixture", "ssh_key_fingerprint": "fixture",
            "transport": {"hub_host": "example.invalid"}, "local_port": 2200}


class StateProjectionTests(unittest.TestCase):
    def setUp(self):
        self.before = bundle("6" * 64)
        self.after = bundle("7" * 64)
        self.state = enrolled(self.before)

    def test_only_source_ownership_changes_and_identity_is_preserved(self):
        original = copy.deepcopy(self.state)
        projected = planner._project_target_state(self.state, self.before, self.after, NEW)
        self.assertEqual(self.state, original)
        self.assertEqual(projected["source_manifest_sha256"], NEW)
        self.assertEqual(projected["source_files"], planner.remote.Enrollment.installed_projection(self.after))
        self.assertEqual(projected["owned_files"][planner.MANIFEST_FILE], NEW)
        self.assertEqual(projected["owned_files"]["/etc/sovagrid/agent.token"], "9" * 64)
        self.assertEqual(projected["owned_files"]["/etc/sovagrid/hub-ca.pem"], "8" * 64)
        for key in ("identity", "agent_token_sha256", "transport", "local_port",
                    "ssh_public_key", "ssh_key_fingerprint"):
            self.assertEqual(projected[key], original[key])

    def test_pending_or_unowned_source_refuses(self):
        self.state["pending_writes"] = {"/etc/sovagrid/agent.json": {"new": "8" * 64}}
        with self.assertRaisesRegex(planner.Refused, "EXTERNAL_ENROLLMENT"):
            planner._project_target_state(self.state, self.before, self.after, NEW)
        self.state["pending_writes"] = {}
        self.state["owned_files"][planner.remote.TARGET_HELPER] = "0" * 64
        with self.assertRaisesRegex(planner.Refused, "EXTERNAL_ENROLLMENT"):
            planner._project_target_state(self.state, self.before, self.after, NEW)

    def test_additive_source_is_owned_without_changing_existing_identity(self):
        added = "sovagrid-agent/sovagrid_agent/plugins/extension.py"
        self.after["sha256"][added] = "e" * 64
        projected = planner._project_target_state(self.state, self.before, self.after, NEW)
        path = "/opt/sovagrid-agent/sovagrid_agent/plugins/extension.py"
        self.assertEqual(projected["source_files"][path], "e" * 64)
        self.assertEqual(projected["owned_files"][path], "e" * 64)
        self.assertEqual(projected["file_metadata"][path], {"mode": 0o644, "gid": 0})
        self.assertEqual(projected["owned_directories"]["/opt/sovagrid-agent/sovagrid_agent/plugins"], 0o755)
        self.assertEqual(projected["identity"], self.state["identity"])

    def test_old_installed_file_removal_remains_closed(self):
        optional = "sovagrid-agent/README.md"
        self.before["sha256"][optional] = "f" * 64
        state = enrolled(self.before)
        with self.assertRaisesRegex(planner.Refused, "EXTERNAL_ENROLLMENT"):
            planner._project_target_state(state, self.before, self.after, NEW)


class CandidateAndTreeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = {
            planner.remote.SELF_NAME: b"# helper\n",
            "sovagrid-agent/LICENSE": b"license\n",
            "sovagrid-agent/NOTICE": b"notice\n",
            "sovagrid-agent/ATTRIBUTION.md": b"attribution\n",
            "sovagrid-agent/deploy/sovagrid-agent.service": b"[Service]\n",
            "sovagrid-agent/sovagrid_agent/trial_gate.py": b"# watchdog\n",
            "sovagrid-agent/sovagrid_agent/__main__.py": b"print('agent')\n",
        }
        for relative, raw in self.data.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.manifest = {"format": 1, "components": {}, "sha256": {
            path: hashlib.sha256(raw).hexdigest() for path, raw in self.data.items()}}

    def test_candidate_source_is_checked_and_python_syntax_is_compiled_without_execution(self):
        with mock.patch.object(planner.promotion, "_read_regular",
                               side_effect=lambda path, _limit: path.read_bytes()):
            projection = planner._candidate_agent_files(self.root, self.manifest)
        self.assertEqual(projection[planner.remote.TARGET_HELPER],
                         self.manifest["sha256"][planner.remote.SELF_NAME])
        self.assertEqual(len(projection), 7)
        self.data["sovagrid-agent/sovagrid_agent/__main__.py"] = b"def broken(:\n"
        path = self.root / "sovagrid-agent/sovagrid_agent/__main__.py"
        path.write_bytes(self.data["sovagrid-agent/sovagrid_agent/__main__.py"])
        self.manifest["sha256"]["sovagrid-agent/sovagrid_agent/__main__.py"] = hashlib.sha256(path.read_bytes()).hexdigest()
        with mock.patch.object(planner.promotion, "_read_regular",
                               side_effect=lambda path, _limit: path.read_bytes()), \
             self.assertRaisesRegex(planner.Refused, "CANDIDATE_PYTHON_INVALID"):
            planner._candidate_agent_files(self.root, self.manifest)

    def test_untracked_or_symlinked_installed_source_refuses(self):
        source = self.root / "sovagrid-agent"
        projection = planner.remote.Enrollment.installed_projection(self.manifest)
        planner._installed_agent_tree(projection, root=source, owner=os.geteuid())
        empty = source / "personal"
        empty.mkdir()
        with self.assertRaisesRegex(planner.Refused, "EXTERNAL_SOURCE"):
            planner._installed_agent_tree(projection, root=source, owner=os.geteuid())
        empty.rmdir()
        extra = source / "user-notes.txt"
        extra.write_text("keep me", encoding="utf-8")
        with self.assertRaisesRegex(planner.Refused, "EXTERNAL_SOURCE"):
            planner._installed_agent_tree(projection, root=source, owner=os.geteuid())
        extra.unlink()
        path = source / "sovagrid_agent/__main__.py"
        path.unlink()
        path.symlink_to(source / "LICENSE")
        with self.assertRaisesRegex(planner.Refused, "EXTERNAL_SOURCE"):
            planner._installed_agent_tree(projection, root=source, owner=os.geteuid())


class PreflightContractTests(unittest.TestCase):
    def test_preflight_remains_read_only_and_blocks_apply_without_remote_lease(self):
        before, after = bundle("6" * 64), bundle("7" * 64)
        state = enrolled(before)
        previous = {"protocol": 1, "current_hub_manifest_sha256": NEW,
                    "candidate_manifest_sha256": NEW, "external_agent_manifest_sha256": OLD,
                    "source_paths_to_change": [], "apply_supported": False,
                    "apply_blockers": ["EXTERNAL_AGENT_TRANSACTION_MISSING"]}
        promoted = {"phase": "activated", "baseline_sha256": BASELINE}
        patches = [
            mock.patch.object(planner, "preview", return_value=previous),
            mock.patch.object(planner, "_promotion_lock", return_value=contextlib.nullcontext()),
            mock.patch.object(planner.update, "inspect", return_value=(NEW, promoted, {}, BASELINE)),
            mock.patch.object(planner, "_external_snapshot", return_value=(OLD, before, state)),
            mock.patch.object(planner.common, "candidate_source", return_value=(Path("/candidate"), {})),
            mock.patch.object(planner, "_manifest", return_value=(NEW, after)),
            mock.patch.object(planner, "_candidate_agent_files",
                              return_value=planner.remote.Enrollment.installed_projection(after)),
            mock.patch.object(planner, "_installed_agent_tree"),
            mock.patch.object(planner.promotion, "capture_external", return_value={"proof": True}),
            mock.patch.object(planner.promotion, "_private_json", return_value={"proof": True}),
            mock.patch.object(planner.update, "_hash_file", return_value=BASELINE),
        ]
        with contextlib.ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            result = planner.preflight(ARCHIVE, NEW)
        self.assertTrue(result["apply_supported"])
        self.assertEqual(result["candidate_agent_file_count"], 8)
        self.assertEqual(result["apply_blockers"], [])
        self.assertEqual(result["live_gates_pending"],
                         ["ORIGINAL_HUB_AGENT_UPDATE_LEASE", "AGENT_IDLE_ACK",
                          "TRIAL_FD_WATCHDOG"])
        self.assertNotIn("agent.token", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
