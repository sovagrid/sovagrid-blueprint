# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Check the restore bootstrap's early, read-only refusal paths."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "run.sh"


def function_body(source: str, name: str, following: str) -> str:
    start = source.index(f"{name}() {{\n")
    end = source.index(f"\n{following}", start)
    return source[start:end]


def tree_snapshot(root: Path) -> tuple[tuple[str, str, bytes], ...]:
    entries = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            entries.append((relative, "link", os.readlink(path).encode()))
        elif path.is_dir():
            entries.append((relative, "dir", b""))
        else:
            entries.append((relative, "file", path.read_bytes()))
    return tuple(entries)


@unittest.skipUnless(shutil.which("bash"), "Bash is unavailable")
class RestoreDependencyBootstrapTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.target_guard = function_body(cls.source, "restore_target_empty",
                                         "restore_source_and_target_verified() {")
        cls.bootstrap = function_body(cls.source, "restore_dependencies_only",
                                      "if [[ ${1:-} == --restore-dependencies-only ]]; then")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "target"
        for directory in ("etc/systemd/system", "opt", "var/lib", "usr/local/bin",
                          "usr/local/libexec"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        self.bin = Path(self.temporary.name) / "bin"
        self.bin.mkdir()
        getent = self.bin / "getent"
        getent.write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  passwd) printf 'root:x:0:0:root:/root:/bin/sh\\n'; "
            "[ \"${TEST_RESTORE_IDENTITY:-0}\" != 1 ] || "
            "printf 'sovagrid-agent:x:1001:1001::/var/empty:/usr/sbin/nologin\\n' ;;\n"
            "  group) printf 'root:x:0:\\n' ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        getent.chmod(0o755)

    def run_guard(self, *, identity: bool = False) -> subprocess.CompletedProcess[str]:
        script = (
            "set -euo pipefail\n"
            "die() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
            f"{self.target_guard}\n"
            f"restore_target_empty {shlex.quote(str(self.root))}\n"
        )
        env = os.environ.copy()
        env["PATH"] = str(self.bin) + os.pathsep + env.get("PATH", "")
        env["TEST_RESTORE_IDENTITY"] = "1" if identity else "0"
        return subprocess.run(["bash", "-c", script], env=env,
                              capture_output=True, text=True, check=False)

    def test_clean_target_is_only_inspected(self) -> None:
        before = tree_snapshot(self.root)
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(tree_snapshot(self.root), before)

    def test_existing_state_is_rejected_without_changes(self) -> None:
        (self.root / "etc/sovagrid-hub").mkdir()
        before = tree_snapshot(self.root)
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already has SovaGrid state", result.stderr)
        self.assertEqual(tree_snapshot(self.root), before)

    def test_unsafe_archive_input_is_rejected_without_changes(self) -> None:
        (self.root / "var/lib/sovagrid-host-backups").symlink_to(self.bin)
        before = tree_snapshot(self.root)
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("input or staging directory is unsafe", result.stderr)
        self.assertEqual(tree_snapshot(self.root), before)

    def test_existing_identity_is_rejected_without_changes(self) -> None:
        before = tree_snapshot(self.root)
        result = self.run_guard(identity=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already has SovaGrid identities", result.stderr)
        self.assertEqual(tree_snapshot(self.root), before)

    def test_unsupported_ubuntu_release_stops_before_dependency_install(self) -> None:
        marker = Path(self.temporary.name) / "apt-called"
        apt = self.bin / "apt-get"
        apt.write_text(f"#!/bin/sh\nprintf x > {shlex.quote(str(marker))}\n", encoding="utf-8")
        apt.chmod(0o755)
        script = (
            "set -euo pipefail\n"
            "die() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
            f"{self.bootstrap}\n"
            "VERSION_ID=20.04\n"
            f"restore_dependencies_only {'0' * 64}\n"
        )
        env = os.environ.copy()
        env["PATH"] = str(self.bin) + os.pathsep + env.get("PATH", "")
        before = tree_snapshot(self.root)
        result = subprocess.run(["bash", "-c", script], env=env,
                                capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires Ubuntu 22.04", result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(tree_snapshot(self.root), before)

    def test_bootstrap_is_before_normal_install_state_changes(self) -> None:
        source = self.source
        self.assertLess(source.index("if [[ ${1:-} == --restore-dependencies-only ]]; then"),
                        source.index("backup_broker_marker=/var/lib/sovagrid/"))
        self.assertLess(source.index("restore_target_empty /"),
                        source.index("install_core_dependencies\n", source.index("restore_dependencies_only() {")))

    def test_full_source_hashing_precedes_candidate_import(self) -> None:
        source = self.source
        start = source.index("\n", source.index("python3 -B -I - \"$1\" \"$2\" <<'PY'")) + 1
        end = source.index("\nPY\n", start)
        verifier = source[start:end]
        compile(verifier, "restore-source-verifier", "exec")
        self.assertLess(verifier.index("if seen != set(hashes):"),
                        verifier.index("spec.loader.exec_module(module)"))

    def test_stdlib_verifier_refuses_tampered_candidate_without_import(self) -> None:
        source = self.source
        start = source.index("\n", source.index("python3 -B -I - \"$1\" \"$2\" <<'PY'")) + 1
        end = source.index("\nPY\n", start)
        module = ast.parse(source[start:end])
        selected = [node for node in module.body
                    if isinstance(node, (ast.Import, ast.ImportFrom)) or
                    isinstance(node, ast.FunctionDef) and
                    node.name in ("reject", "verify_reviewed_source")]
        scope: dict[str, object] = {}
        exec(compile(ast.Module(body=selected, type_ignores=[]),
                     "restore-source-verifier", "exec"), scope)
        verify = scope["verify_reviewed_source"]

        anchor = Path(self.temporary.name) / "private"
        anchor.mkdir(mode=0o700)
        anchor.chmod(0o700)
        bundle = anchor / "bundle"
        bundle.mkdir(mode=0o755)
        bundle.chmod(0o755)
        components = ("sovagrid-blueprint", "sovagrid-hub", "sovagrid-web",
                      "sovagrid-agent", "sovagrid-vpn")
        files = {f"{component}/README": b"reviewed\n" for component in components}
        worker_name = "sovagrid-blueprint/deploy/remote_update_worker.py"
        files[worker_name] = b"raise RuntimeError('candidate code executed')\n"
        for relative, content in files.items():
            path = bundle / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.parent.chmod(0o755)
            path.write_bytes(content)
            path.chmod(0o644)
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        manifest = {
            "format": 1,
            "components": {component: {"commit": "a" * 40,
                                       "file_count": sum(name.startswith(component + "/")
                                                         for name in files)}
                           for component in components},
            "sha256": hashes,
        }
        raw = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
        manifest_path = bundle / "sovagrid-bundle.json"
        manifest_path.write_bytes(raw)
        manifest_path.chmod(0o644)
        digest = hashlib.sha256(raw).hexdigest()
        verify(bundle, digest, anchor=anchor, owner_uid=os.getuid())

        marker = Path(self.temporary.name) / "candidate-imported"
        worker = bundle / worker_name
        worker.write_text(f"open({str(marker)!r}, 'w').write('executed')\n", encoding="utf-8")
        with self.assertRaises(SystemExit):
            verify(bundle, digest, anchor=anchor, owner_uid=os.getuid())
        self.assertFalse(marker.exists())

    def test_docker_image_guard_recognizes_namespace_repository(self) -> None:
        line = next(line for line in self.source.splitlines()
                    if "restore target has SovaGrid images" in line)
        script = (
            "die() { exit 1; }\n"
            "inventory=$1\n"
            f"{line}\n"
        )
        for repository in ("sovagrid", "sovagrid/hub", "registry.test/sovagrid_hub"):
            with self.subTest(repository=repository):
                result = subprocess.run(["bash", "-c", script, "sovagrid", repository],
                                        capture_output=True, text=True, check=False)
                self.assertNotEqual(result.returncode, 0)
        result = subprocess.run(["bash", "-c", script, "sovagrid", "unrelated/image"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
