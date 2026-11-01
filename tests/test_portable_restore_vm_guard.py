# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""A destructive VM helper must reject a developer/private host before reads."""

import importlib.util
from contextlib import contextmanager
import os
from pathlib import Path
import hashlib
import json
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deploy import portable_restore_apply as core
from deploy import portable_restore_receiver as receiver


spec = importlib.util.spec_from_file_location("portable_restore_vm_guard_fixture",
    Path(__file__).with_name("portable_restore_apply_vm.py"))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
fixture = vm.fixture_module()


class VmGuardTest(unittest.TestCase):
    @contextmanager
    def public_inputs_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = "d" * 32
            host = root / "var/lib/sovagrid-host-backups"
            images = root / "var/lib/sovagrid-host-image-exports" / identity
            host.mkdir(parents=True, mode=0o700)
            images.mkdir(parents=True, mode=0o700)
            images.parent.chmod(0o700)
            originals = {"host_manifest": host / (identity + ".manifest.json"),
                         "host": host / (identity + ".tar.gz"),
                         "images_manifest": images / "manifest.json", "images": images / "images.tar",
                         "receipt": images / "receipt.json"}
            for part, path in originals.items():
                path.write_bytes(part.encode() + b"\x00\xff\n")
                path.chmod(0o600)
            exporter = SimpleNamespace(verify=lambda *args, **kwargs: {
                "receipt": {"protocol": "sovagrid-portable-host-receipt-v2"}})
            restore = SimpleNamespace(_sibling=lambda *args: exporter)
            mappings = {"/var/lib/sovagrid-host-backups": host,
                        "/var/lib/sovagrid-host-image-exports": images.parent}
            def mapped(value):
                return mappings.get(str(value), Path(value))
            with (patch.object(vm, "Path", side_effect=mapped),
                  patch.object(receiver, "_safe_open", side_effect=lambda path, **kwargs:
                      os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)),
                  patch.object(receiver, "UID", os.getuid()), patch.object(receiver, "GID", os.getgid())):
                yield root, identity, host, images, originals, restore, exporter

    def test_public_inputs_preserve_all_five_originals_and_hold_verified_descriptors(self):
        with self.public_inputs_fixture() as (root, identity, host, images, paths, restore, _exporter):
            expected = {part: path.read_bytes() for part, path in paths.items()}
            before = {part: (path.stat().st_dev, path.stat().st_ino) for part, path in paths.items()}
            with vm.public_restore_inputs(restore, receiver, identity) as (files, artifacts, fingerprints):
                self.assertEqual(set(files), set(expected))
                self.assertTrue(all(not path.exists() for path in paths.values()))
                for part, fd in files.items():
                    info = os.fstat(fd)
                    self.assertEqual((info.st_dev, info.st_ino), before[part])
                    self.assertEqual(os.pread(fd, info.st_size, 0), expected[part])
                    self.assertEqual(artifacts[part], {"bytes": len(expected[part]),
                        "sha256": hashlib.sha256(expected[part]).hexdigest()})
                    self.assertEqual(receiver._fingerprint(info), fingerprints[part])
            private, = (root / "var/lib").glob(".sovagrid-public-restore-ci-*")
            self.assertEqual({str(path.relative_to(private)): path.read_bytes()
                for path in private.rglob("*") if path.is_file()}, {
                    "host_manifest": expected["host_manifest"], "host": expected["host"],
                    "images/manifest.json": expected["images_manifest"],
                    "images/images.tar": expected["images"], "images/receipt.json": expected["receipt"]})
            self.assertEqual(list(host.iterdir()), [])
            self.assertFalse(images.exists())

    def test_public_input_quarantine_refuses_foreign_image_descendants_without_moving_anything(self):
        with self.public_inputs_fixture() as (root, identity, _host, images, paths, restore, _exporter):
            foreign = images / "foreign-data"
            foreign.write_bytes(b"preserve")
            with self.assertRaisesRegex(RuntimeError, "foreign descendants"):
                with vm.public_restore_inputs(restore, receiver, identity):
                    self.fail("foreign input was adopted")
            self.assertTrue(all(path.exists() for path in paths.values()))
            self.assertEqual(foreign.read_bytes(), b"preserve")
            self.assertEqual(list((root / "var/lib").glob(".sovagrid-public-restore-ci-*")), [])

    def test_public_input_changed_after_full_verification_is_preserved_and_never_renamed(self):
        with self.public_inputs_fixture() as (_root, identity, _host, _images, paths, restore, exporter):
            def changed(*args, **kwargs):
                paths["host_manifest"].write_bytes(b"changed-after-verify")
                return {"receipt": {"protocol": "sovagrid-portable-host-receipt-v2"}}
            exporter.verify = changed
            with self.assertRaisesRegex(RuntimeError, "changed before rename"):
                with vm.public_restore_inputs(restore, receiver, identity):
                    self.fail("changed input was adopted")
            self.assertTrue(all(path.exists() for path in paths.values()))
            self.assertEqual(paths["host_manifest"].read_bytes(), b"changed-after-verify")

    def test_vm_preview_and_child_use_same_enabled_core_without_changing_production_gate(self):
        base = {"apply_review_sha256": "a" * 64}
        resources = {"bindings": {"resource_manifest_sha256": "b" * 64}}
        runtime = SimpleNamespace()
        restore = SimpleNamespace(_sibling=lambda filename, name: None)
        def preview(identity):
            bound = restore._sibling("portable_restore_apply.py", "preview_core")
            self.assertIs(bound, core)
            return bound._full_preview(base, resources, [])
        restore.portable_clean_plan = lambda identity: {"target_empty": True, "target_ready": core.APPLY_ENABLED,
                                                       "blockers": [] if core.APPLY_ENABLED else ["APPLY_NOT_IMPLEMENTED"],
                                                       "review_sha256": "c" * 64}
        restore.portable_stage = lambda identity, review: self.assertTrue(core.APPLY_ENABLED)
        restore.portable_apply_preview = preview
        def child(restored, bound, actual_runtime, identity, review, mode):
            self.assertIs(restored, restore)
            self.assertIs(bound, core)
            self.assertIs(restore._sibling("portable_restore_runtime.py", "runtime"), runtime)
            self.assertEqual(preview(identity)["apply_review_sha256"], review)
        with (patch.object(vm, "guard"), patch.object(vm, "verified_bundle") as verify,
              patch.object(vm, "api", return_value=(restore, core, runtime)) as api,
              patch.object(vm, "_enabled_child", side_effect=child), patch.object(core, "APPLY_ENABLED", False)):
            review = vm.stage(Path("/unused"), "d" * 32)
            self.assertFalse(core.APPLY_ENABLED)
            vm.child("d" * 32, review, "success")
            self.assertFalse(core.APPLY_ENABLED)
            self.assertEqual(verify.call_count, 2)
            self.assertEqual(api.call_count, 2)

    def test_vm_enable_refuses_unverified_bytes_and_retains_an_open_production_gate(self):
        with (patch.object(vm, "guard"), patch.object(vm, "verified_bundle", side_effect=RuntimeError("pin mismatch")),
              patch.object(vm, "api") as api):
            with self.assertRaisesRegex(RuntimeError, "pin mismatch"):
                with vm.enabled_vm_api(Path("/unused")): self.fail("unverified API enabled")
            api.assert_not_called()
        with (patch.object(vm, "guard"), patch.object(vm, "verified_bundle"),
              patch.object(vm, "api", return_value=(SimpleNamespace(_sibling=lambda *args: None), core, None)),
              patch.object(core, "APPLY_ENABLED", True)):
            with vm.enabled_vm_api(Path("/unused")) as (_restore, bound, _runtime):
                self.assertIs(bound, core)
                self.assertIs(core.APPLY_ENABLED, True)
            self.assertIs(core.APPLY_ENABLED, True)

    def test_same_byte_unit_and_external_template_replacements_refuse_before_cleanup(self):
        for name in ("sovagrid-agent.service", "sovagrid-external-agent-apply@.service"):
            with self.subTest(unit=name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                unit = directory / name
                unit.write_bytes(b"[Service]\nExecStart=/usr/bin/true\n")
                unit.chmod(0o644)
                original_inventory = fixture.unit_inventory
                sealed = original_inventory(root=directory, uid=os.getuid(), gid=os.getgid())
                replacement = directory / "replacement"
                replacement.write_bytes(unit.read_bytes())
                replacement.chmod(0o644)
                os.replace(replacement, unit)
                value = {"manifest_sha256": "a" * 64, "trees": {}, "units": sealed}
                with (patch.object(vm, "api", return_value=(None, None, None)),
                      patch.object(vm, "fixture_module", return_value=fixture),
                      patch.object(fixture, "ledger", return_value=value), patch.object(fixture, "source_pin"),
                      patch.object(vm, "expected_manifest", return_value="a" * 64),
                      patch.object(vm, "ROOTS", set()), patch.object(vm, "command") as command,
                      patch.object(fixture, "unit_inventory", side_effect=lambda **kwargs:
                          original_inventory(root=directory, uid=os.getuid(), gid=os.getgid()))):
                    with self.assertRaisesRegex(RuntimeError, "producer-owned fixture unit changed"):
                        vm.uninstall(directory, "b" * 32, {})
                    command.assert_not_called()
                self.assertEqual(unit.read_bytes(), b"[Service]\nExecStart=/usr/bin/true\n")

    def test_descendant_inserted_before_fresh_proof_is_not_adopted_after_rename(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            live = root / "managed"
            live.mkdir()
            (live / "owned").write_bytes(b"fixture")
            sealed = fixture.inventory(live)
            fixture.compare(str(live), sealed)  # The initial ownership check passes.
            (live / "injected-private-data").write_bytes(b"preserve after rename")
            parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                info = os.fstat(parent)
                proof = {"parent": [info.st_dev, info.st_ino], "resource": core.tree_proof(parent, "managed")}
                identity, shadow = "a" * 32, ".sovagrid-restore-" + "a" * 32 + "-0"
                step = {"kind": "publish", "resource": "/managed", "desired": {
                    "shadow": shadow, "sha256": proof["resource"]["sha256"]}}
                def rename(fd, source, destination):
                    with self.assertRaises(FileNotFoundError):
                        os.stat(destination, dir_fd=fd, follow_symlinks=False)
                    os.rename(source, destination, src_dir_fd=fd, dst_dir_fd=fd)
                with patch.object(core, "_rename_noreplace", side_effect=rename):
                    core.Publisher(root, identity, {"/managed"}, uid=os.getuid()).undo(step, proof)
                with patch.object(vm.shutil, "rmtree") as remove:
                    with self.assertRaisesRegex(RuntimeError, "unknown descendant"):
                        vm.remove_quarantined(fixture, core, parent, shadow, "/managed", proof, sealed)
                    remove.assert_not_called()
                self.assertEqual((root / shadow / "injected-private-data").read_bytes(), b"preserve after rename")
            finally:
                os.close(parent)

    def test_renamed_tree_keeps_only_original_logical_path_mutable_exceptions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, shadow = Path(temporary), ".sovagrid-restore-" + "a" * 32 + "-0"
            live = root / "managed"
            (live / "hub").mkdir(parents=True)
            database = live / "hub/hub.sqlite"
            database.write_bytes(b"before known Hub writes")
            sealed = fixture.inventory(live)
            database.write_bytes(b"after known Hub writes")
            parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                info = os.fstat(parent)
                proof = {"parent": [info.st_dev, info.st_ino], "resource": core.tree_proof(parent, "managed")}
                os.rename("managed", shadow, src_dir_fd=parent, dst_dir_fd=parent)
                vm.remove_quarantined(fixture, core, parent, shadow, "/var/lib/sovagrid", proof, sealed)
                self.assertFalse((root / shadow).exists())
            finally:
                os.close(parent)

    def test_missing_artifact_pin_is_refused_before_copy_or_installed_import(self):
        with (patch.dict(os.environ, {}, clear=True), patch.object(vm, "guard"),
              patch.object(vm, "fixture_module") as module, patch.object(vm.shutil, "copytree") as copy):
            with self.assertRaisesRegex(RuntimeError, "artifact-pinned source manifest"):
                vm.run()
            module.assert_not_called()
            copy.assert_not_called()

    def test_foreign_descendants_are_refused_before_any_cleanup_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "managed"
            root.mkdir()
            (root / "owned").write_bytes(b"fixture")
            value = {"manifest_sha256": "a" * 64, "trees": {str(root): fixture.inventory(root)}}
            (root / "foreign-directory").mkdir()
            (root / "foreign-directory/personal-data").write_bytes(b"preserve")
            with (patch.object(vm, "api", return_value=(None, None, None)),
                  patch.object(vm, "fixture_module", return_value=fixture),
                  patch.object(fixture, "ledger", return_value=value), patch.object(fixture, "source_pin"),
                  patch.object(vm, "expected_manifest", return_value="a" * 64),
                  patch.object(vm, "ROOTS", {str(root)}), patch.object(vm, "command") as command):
                with self.assertRaisesRegex(RuntimeError, "unknown descendant"):
                    vm.uninstall(Path(temporary), "b" * 32, {})
                command.assert_not_called()
            self.assertEqual((root / "foreign-directory/personal-data").read_bytes(), b"preserve")

    def test_initial_critical_roots_have_closed_descendant_sets(self):
        for root, foreign in (("/var/lib/sovagrid", "hub/foreign.txt"),
                              ("/var/lib/sovagrid-agent", "files/personal-data"),
                              ("/opt/sovagrid-candidates", "somebody-elses-candidate/data")):
            with self.subTest(root=root):
                with self.assertRaisesRegex(RuntimeError, "unknown initial"):
                    vm.initial_names(root, {"": {}, foreign: {}}, Path("/unused"))

    def test_installer_notices_are_pinned_without_adopting_other_code_descendants(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            for component in ("sovagrid-agent", "sovagrid-vpn"):
                folder = source / component
                folder.mkdir()
                records = {"": {}}
                for name in ("LICENSE", "ATTRIBUTION.md", "NOTICE"):
                    raw = (component + "/" + name + "\n").encode()
                    (folder / name).write_bytes(raw)
                    records[name] = {"sha256": hashlib.sha256(raw).hexdigest()}
                vm.initial_names("/opt/" + component, records, source)
                records["NOTICE"] = {"sha256": "0" * 64}
                with self.assertRaisesRegex(RuntimeError, "installed code is foreign"):
                    vm.initial_names("/opt/" + component, records, source)
                records.pop("NOTICE")
                records["unknown-file"] = {}
                with self.assertRaisesRegex(RuntimeError, "unknown installed code descendant"):
                    vm.initial_names("/opt/" + component, records, source)

    def test_machine_properties_use_machinectl_individual_property_filters(self):
        name = "sovagrid-ci-target-012345abcdef"
        values = {"Name": name, "Leader": "123", "RootDirectory": "/var/lib/machines/" + name,
                  "Service": "systemd-nspawn", "Class": "container",
                  "Unit": "sg-ci-nspawn-target-012345abcdef.service"}
        def machinectl(*args):
            self.assertEqual(args[:3], ("machinectl", "show", name))
            # machinectl treats each filter as one literal property name.
            filters = [arg.removeprefix("--property=") for arg in args[3:]]
            return "\n".join(key + "=" + value for key, value in values.items() if key in filters)
        with patch.object(vm, "text", side_effect=machinectl):
            self.assertEqual(vm.guest_properties(name), values)

    def test_source_manifest_pin_is_known_and_all_bytes_are_checked_before_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            hashes = {}
            for component in fixture.COMPONENTS:
                (root / component).mkdir()
                (root / component / "main.py").write_bytes(b"pass\n")
                hashes[component + "/main.py"] = hashlib.sha256(b"pass\n").hexdigest()
            raw = json.dumps({"format": 1, "components": {name: {} for name in fixture.COMPONENTS}, "sha256": hashes}).encode()
            (root / "sovagrid-bundle.json").write_bytes(raw)
            expected = hashlib.sha256(raw).hexdigest()
            # The source verifier requires root-owned bytes in production.
            with patch.object(fixture, "inventory", wraps=fixture.inventory):
                with self.assertRaisesRegex(RuntimeError, "artifact manifest pin mismatch"):
                    fixture.source_pin(root, "a" * 64)
            source = root / "sovagrid-blueprint/main.py"
            source.write_bytes(b"unreviewed code\n")
            with patch.object(fixture, "inventory", return_value={"": {"kind": "dir", "uid": 0, "gid": 0, "mode": 0o755},
                    "sovagrid-blueprint/main.py": {"kind": "file", "uid": 0, "gid": 0, "mode": 0o644,
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}}):
                with self.assertRaisesRegex(RuntimeError, "pinned source bytes changed"):
                    fixture.source_pin(root, expected)

    def test_independent_verifier_rejects_even_manifest_named_module_bytecode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = json.dumps({"format": 1, "components": {name: {} for name in fixture.COMPONENTS},
                              "sha256": {"sovagrid-blueprint/main.py": "a" * 64}}).encode()
            (root / "sovagrid-bundle.json").write_bytes(raw)
            cache = {"": {"kind": "dir", "uid": 0, "gid": 0, "mode": 0o755},
                     "sovagrid-blueprint/__pycache__": {"kind": "dir", "uid": 0, "gid": 0, "mode": 0o755}}
            with patch.object(fixture, "inventory", return_value=cache):
                with self.assertRaisesRegex(RuntimeError, "unexpected pinned source directory"):
                    fixture.source_pin(root, hashlib.sha256(raw).hexdigest())

    def test_guest_provenance_mismatch_precedes_poweroff_and_image_retag(self):
        state = {"container": "sovagrid-ci-target-123456abcdef", "image": "sovagrid-ci-target:123456abcdef"}
        provenance = {"guests": {state["container"]: {"leader": "known"}}}
        with (patch.dict(os.environ, {"RUNNER_TEMP": "/tmp"}),
              patch.object(vm, "fixture_module", return_value=fixture),
              patch.object(fixture, "ledger", return_value=provenance),
              patch.object(vm, "private_json", return_value=state),
              patch.object(vm.Path, "is_dir", return_value=True), patch.object(vm.Path, "is_symlink", return_value=False),
              patch.object(vm, "guest_identity", return_value={"leader": "foreign"}),
              patch.object(vm, "command") as command):
            with self.assertRaisesRegex(RuntimeError, "guest identity changed before poweroff"):
                vm.stop_ci_guests_and_retag(Path("/unused"))
            command.assert_not_called()

    def test_cleanup_accounts_require_exact_home_gecos_uid_groups_and_empty_group_members(self):
        inspected = {"identities": {"users": {"sovagrid-hub": 10001},
                                   "groups": {"sovagrid-hub": 10001, "sovagrid": 997}}}
        provenance = {"trees": {"/var/lib/sovagrid-agent": {"": {"uid": 997}}}}
        core = SimpleNamespace(Identities=SimpleNamespace(_locked_password=lambda *args, **kwargs: True))
        for changed in ("home", "gecos", "uid", "supplementary", "members"):
            users = {"sovagrid-hub": vm.pwd.struct_passwd(("sovagrid-hub", "x", 10001, 10001, "", "/nonexistent", "/usr/sbin/nologin")),
                     "sovagrid": vm.pwd.struct_passwd(("sovagrid", "x", 997, 997, "", "/var/lib/sovagrid-agent", "/usr/sbin/nologin"))}
            fields = list(users["sovagrid"])
            if changed == "home": fields[5] = "/home/personal"
            if changed == "gecos": fields[4] = "Somebody else's account"
            if changed == "uid": fields[2] = 998
            users["sovagrid"] = vm.pwd.struct_passwd(fields)
            groups = {name: vm.grp.struct_group((name, "x", gid, ["foreign"] if changed == "members" else []))
                      for name, gid in inspected["identities"]["groups"].items()}
            with (self.subTest(changed=changed), patch.object(vm.pwd, "getpwnam", side_effect=users.__getitem__),
                  patch.object(vm.grp, "getgrnam", side_effect=groups.__getitem__),
                  patch.object(vm.os, "getgrouplist", side_effect=lambda name, gid: [gid, 27] if changed == "supplementary" else [gid])):
                with self.assertRaisesRegex(RuntimeError, "unknown CI (service account|group)"):
                    vm.identity_snapshot(inspected, core, provenance=provenance)

    def test_every_disposable_host_condition_is_required_before_any_system_read(self):
        good = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux", "SOVAGRID_PORTABLE_RESTORE_DISPOSABLE": "1"}
        for missing in (*good, "root"):
            environment = dict(good)
            if missing != "root":
                environment.pop(missing)
            with self.subTest(missing=missing):
                with (patch.dict(os.environ, environment, clear=True),
                      patch.object(vm.os, "geteuid", return_value=1000 if missing == "root" else 0),
                      patch.object(vm.Path, "read_text") as read,
                      patch.object(vm.subprocess, "run") as command):
                    with self.assertRaisesRegex(RuntimeError, "requires explicit disposable"):
                        vm.guard()
                    read.assert_not_called()
                    command.assert_not_called()

    def test_self_hosted_runner_is_refused_even_with_the_explicit_flag(self):
        environment = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted",
                       "RUNNER_OS": "Linux", "SOVAGRID_PORTABLE_RESTORE_DISPOSABLE": "1"}
        with patch.dict(os.environ, environment, clear=True), patch.object(vm.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "requires explicit disposable"):
                vm.guard()


if __name__ == "__main__":
    unittest.main()
