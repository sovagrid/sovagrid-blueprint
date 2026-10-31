# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""A restore/installer lock must cover source switch and survive child exec."""

import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def workers():
    server = {"__name__": "installation_lock_fixture"}
    exec(compile((ROOT / "deploy/remote_update_worker.py").read_text(),
                 "server_worker", "exec"), server)
    yield "server", server
    connect = ROOT.parent / "sovagrid-connect/sovagrid_connect/remote_update.py"
    if connect.is_file():
        package = {"__name__": "connect_worker_fixture"}
        exec(compile(connect.read_text(), str(connect), "exec"), package)
        embedded = {"__name__": "installation_lock_fixture"}
        exec(compile(package["REMOTE_SCRIPT"], "connect_worker", "exec"), embedded)
        yield "connect", embedded


class InstallationLockTests(unittest.TestCase):
    def fixture(self, code, directory):
        code["ROOT"] = Path(directory)
        (Path(directory) / "run").mkdir()

        def validate(info):
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                    stat.S_IMODE(info.st_mode) != 0o600):
                code["fail"]("STATE")

        code["validate_lock"] = validate
        return Path(directory) / "run/sovagrid-installation.lock"

    def test_busy_lock_refuses_before_transaction_then_can_be_reused(self):
        for name, code in workers():
            with self.subTest(worker=name), tempfile.TemporaryDirectory() as directory:
                lock = self.fixture(code, directory)
                with code["installation_lock"]():
                    code["_apply_locked"] = lambda *a, **k: self.fail("transaction reached while busy")
                    with self.assertRaisesRegex(code["UpdateFailure"], "BUSY"):
                        code["apply"]("a" * 64, "b" * 64)
                with code["installation_lock"]():
                    self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)

    def test_symlink_hardlink_and_weak_permissions_are_refused(self):
        for name, code in workers():
            for kind in ("symlink", "hardlink", "mode"):
                with self.subTest(worker=name, kind=kind), tempfile.TemporaryDirectory() as directory:
                    lock = self.fixture(code, directory)
                    target = Path(directory) / "original"
                    target.write_bytes(b"do not change\n")
                    target.chmod(0o600)
                    if kind == "symlink":
                        lock.symlink_to(target)
                    elif kind == "hardlink":
                        os.link(target, lock)
                    else:
                        lock.write_bytes(b"")
                        lock.chmod(0o644)
                    with self.assertRaises((OSError, code["UpdateFailure"])):
                        with code["installation_lock"]():
                            self.fail("unsafe lock admitted")
                    self.assertEqual(target.read_bytes(), b"do not change\n")

    def test_only_installer_child_inherits_the_held_descriptor(self):
        child = (
            "import fcntl, os, sys; "
            "fd=int(os.environ['SOVAGRID_INSTALLATION_LOCK_FD']); "
            "assert os.fstat(fd).st_ino == os.stat(sys.argv[1]).st_ino; "
            "fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); "
            "other=os.open(sys.argv[1], os.O_RDWR); "
            "\ntry: fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)"
            "\nexcept BlockingIOError: print('held')"
            "\nelse: raise RuntimeError('lock lost during exec')"
        )
        for name, code in workers():
            with self.subTest(worker=name), tempfile.TemporaryDirectory() as directory:
                lock = self.fixture(code, directory)
                with code["installation_lock"]() as descriptor:
                    environment = dict(os.environ, SOVAGRID_INSTALLATION_LOCK_FD=str(descriptor))
                    with tempfile.TemporaryFile() as output:
                        code["command"]([sys.executable, "-I", "-c", child, str(lock)],
                                        env=environment, pass_fds=(descriptor,), stdout=output)
                        output.seek(0)
                        self.assertEqual(output.read(), b"held\n")
                with code["installation_lock"]():
                    pass

    def test_restore_fence_blocks_updates_after_a_crash_without_consuming_it(self):
        for name, code in workers():
            for dangling in (False, True):
                with self.subTest(worker=name, dangling=dangling), tempfile.TemporaryDirectory() as directory:
                    self.fixture(code, directory)
                    fence = Path(directory) / "var/lib/.sovagrid-host-restore-in-progress"
                    fence.parent.mkdir(parents=True)
                    if dangling:
                        fence.symlink_to("missing-journal")
                    else:
                        fence.write_bytes(b"unfinished restore\n")
                    code["_apply_locked"] = lambda *a, **k: self.fail("update touched an unfinished restore")
                    with self.assertRaisesRegex(code["UpdateFailure"], "RESTORE_RECOVERY"):
                        code["apply"]("a" * 64, "b" * 64)
                    self.assertTrue(fence.is_symlink() if dangling else fence.is_file())

    def test_full_worker_rejects_every_hub_only_footprint_before_inspection_or_mutation(self):
        for name, code in workers():
            for footprint in code["HUB_ONLY_FOOTPRINTS"]:
                for dangling in (False, True):
                    with self.subTest(worker=name, footprint=footprint, dangling=dangling), \
                            tempfile.TemporaryDirectory() as directory:
                        self.fixture(code, directory)
                        artifact = Path(directory) / footprint.lstrip("/")
                        artifact.parent.mkdir(parents=True, exist_ok=True)
                        if dangling:
                            artifact.symlink_to("missing-promotion-state")
                        else:
                            artifact.mkdir()
                        code["inspect_state"] = lambda: self.fail("full worker inspected a promoted installation")
                        code["_apply_locked"] = lambda *a, **k: self.fail("full worker mutated a promoted installation")
                        operations = [code["preview"], lambda: code["apply"]("a" * 64, "b" * 64)]
                        if "preflight" in code:
                            operations.append(lambda: code["preflight"]("a" * 64, "b" * 64))
                        for operation in operations:
                            with self.assertRaisesRegex(code["UpdateFailure"], "HUB_ONLY_LAYOUT"):
                                operation()
                        self.assertFalse((Path(directory) / "opt/sovagrid-candidates").exists())

    def test_installers_lock_before_dependency_or_managed_state_mutations(self):
        source = (ROOT / "run.sh").read_text()
        restore = source.split("restore_dependencies_only() {", 1)[1]
        self.assertLess(restore.index("\n  installation_lock\n"),
                        restore.index("\n  install_core_dependencies restore\n"))
        ordinary = source.split("\ninstallation_lock\n", 1)[1]
        self.assertIn("\ninstall_core_dependencies\n", ordinary)
        self.assertIn("backup_broker_marker=", ordinary)
        self.assertLess(ordinary.index('exec 9>>"$candidate_root/.lock"'),
                        ordinary.index("\ninstall_core_dependencies\n"))
        self.assertLess(ordinary.index('exec 9>>"$candidate_root/.lock"'),
                        ordinary.index("    useradd --system"))


if __name__ == "__main__":
    unittest.main()
