# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Offline, disposable fixtures for exact-image export and verification."""

from __future__ import annotations

from contextlib import nullcontext
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

from deploy import host_image_export as images


IDENTITY = "a" * 32
SOURCE = "b" * 64


def image_archive(services=("hub", "web"), *, changed_layer=None,
                  changed_config=None, extra=None, tags=None,
                  platform=("linux", "amd64")):
    entries = []
    manifest = []
    identities = {}
    for service in services:
        layer = (service + " layer contents\n").encode()
        layer_digest = hashlib.sha256(layer).hexdigest()
        config = {"rootfs": {"type": "layers",
                              "diff_ids": ["sha256:" + layer_digest]},
                  "architecture": platform[1], "os": platform[0]}
        raw = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        image_id = "sha256:" + hashlib.sha256(raw).hexdigest()
        identities[service] = image_id
        config_name = image_id[7:] + ".json"
        layer_name = hashlib.sha256(service.encode()).hexdigest() + "/layer.tar"
        entries.append((config_name, raw + (b"x" if changed_config == service else b"")))
        entries.append((layer_name, layer + (b"x" if changed_layer == service else b"")))
        manifest.append({"Config": config_name,
                         "RepoTags": (["sovagrid-" + service + ":local"] if tags is None
                                      else tags.get(service)), "Layers": [layer_name]})
    entries.append(("manifest.json", json.dumps(manifest, sort_keys=True).encode()))
    if extra is not None:
        entries.append(extra)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for entry in entries:
            name, content = entry[:2]
            kind = entry[2] if len(entry) == 3 else "file"
            member = tarfile.TarInfo(name)
            member.uid, member.gid, member.mode = 0, 0, 0o644
            member.mtime = 1_700_000_000
            if kind in ("symlink", "hardlink"):
                member.type = (tarfile.SYMTYPE if kind == "symlink"
                               else tarfile.LNKTYPE)
                member.linkname = "manifest.json"
                archive.addfile(member)
            else:
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
    return output.getvalue(), identities


def oci_image_archive(services=("hub", "web"), *, extra=None,
                      foreign_tag=False, wrong_diff=False, attestation=True,
                      bad_descriptor=False):
    blobs = {}
    docker_manifest = []
    top = []

    def blob(raw):
        digest = hashlib.sha256(raw).hexdigest()
        blobs[digest] = raw
        return {"mediaType": "", "digest": "sha256:" + digest, "size": len(raw)}

    def json_blob(value):
        return blob(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())

    ids = {}
    for service in services:
        layer = (service + " OCI layer\n").encode()
        packed = gzip.compress(layer, mtime=0)
        layer_descriptor = blob(packed)
        layer_descriptor["mediaType"] = images.OCI_GZIP_LAYER
        diff_id = hashlib.sha256(layer + (b"changed" if wrong_diff else b"")).hexdigest()
        config = {"os": "linux", "architecture": "amd64",
                  "rootfs": {"type": "layers", "diff_ids": ["sha256:" + diff_id]}}
        config_descriptor = json_blob(config)
        config_descriptor["mediaType"] = images.OCI_CONFIG
        ids[service] = config_descriptor["digest"]
        manifest = {"schemaVersion": 2, "mediaType": images.OCI_MANIFEST,
                    "config": config_descriptor, "layers": [layer_descriptor]}
        primary = json_blob(manifest)
        primary["mediaType"] = images.OCI_MANIFEST
        primary["platform"] = {"os": "linux", "architecture": "amd64"}
        if bad_descriptor and service == "hub":
            primary["size"] += 1
        nested = [primary]
        if attestation:
            empty = blob(b"{}")
            statement = json_blob({"_type": "https://in-toto.io/Statement/v1"})
            statement["mediaType"] = "application/vnd.in-toto+json"
            statement["annotations"] = {
                "in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"}
            att_manifest = {
                "schemaVersion": 2, "mediaType": images.OCI_MANIFEST,
                "artifactType": "application/vnd.docker.attestation.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.empty.v1+json",
                           **{key: empty[key] for key in ("digest", "size")},
                           "data": "e30="},
                "layers": [statement],
                "subject": {key: primary[key] for key in ("mediaType", "digest", "size")}}
            att = json_blob(att_manifest)
            att["mediaType"] = images.OCI_MANIFEST
            att["platform"] = {"os": "unknown", "architecture": "unknown"}
            att["annotations"] = {
                "vnd.docker.reference.digest": primary["digest"],
                "vnd.docker.reference.type": "attestation-manifest"}
            nested.append(att)
        nested_index = json_blob({"schemaVersion": 2, "mediaType": images.OCI_INDEX,
                                  "manifests": nested})
        nested_index["mediaType"] = images.OCI_INDEX
        nested_index["annotations"] = {
            "io.containerd.image.name": "docker.io/library/sovagrid-" + service + ":local",
            "org.opencontainers.image.ref.name": "local"}
        top.append(nested_index)
        docker_manifest.append({"Config": "blobs/sha256/" + ids[service][7:],
                                "RepoTags": ["foreign:latest"] if foreign_tag and service == "hub"
                                            else ["sovagrid-" + service + ":local"],
                                "Layers": ["blobs/sha256/" + layer_descriptor["digest"][7:]]})
    entries = [("index.json", json.dumps({"schemaVersion": 2,
                    "mediaType": images.OCI_INDEX, "manifests": top}).encode()),
               ("manifest.json", json.dumps(docker_manifest).encode()),
               ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}')]
    entries.extend(("blobs/sha256/" + digest, raw) for digest, raw in blobs.items())
    if extra is not None:
        entries.append(extra)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in ("blobs", "blobs/sha256"):
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            archive.addfile(member)
        for name, raw in entries:
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return output.getvalue(), ids


class ImageExportTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)

    def test_export_is_pinned_to_the_local_docker_socket(self):
        self.assertEqual(images.DOCKER,
                         ("/usr/bin/docker", "--host", "unix:///run/docker.sock"))

    def inspect(self, raw, identities, **kwargs):
        path = self.path / "inspect.tar"
        path.write_bytes(raw)
        fd = os.open(path, os.O_RDONLY)
        try:
            return images._inspect_image_tar(fd, identities,
                                             deadline=time.monotonic() + 10,
                                             **kwargs)
        finally:
            os.close(fd)

    def test_docker_save_payload_binds_config_and_layers_to_exact_ids(self):
        raw, ids = image_archive(("hub", "web", "ssh-gateway"))
        self.assertGreater(self.inspect(raw, ids), 0)
        wrong_config, _ = image_archive(changed_config="hub")
        with self.assertRaisesRegex(images.Refused, "IMAGE_ID_MISMATCH"):
            self.inspect(wrong_config, {key: ids[key] for key in ("hub", "web")})
        wrong_layer, _ = image_archive(changed_layer="web")
        with self.assertRaisesRegex(images.Refused, "LAYER_DIGEST_MISMATCH"):
            self.inspect(wrong_layer, {key: ids[key] for key in ("hub", "web")})
        traversal, _ = image_archive(extra=("../outside", b"x"))
        with self.assertRaisesRegex(images.Refused, "INVALID_IMAGE_ARCHIVE"):
            self.inspect(traversal, {key: ids[key] for key in ("hub", "web")})
        for attack in (("manifest.json", b"{}"),
                       ("foreign-link", b"", "symlink"),
                       ("foreign-link", b"", "hardlink")):
            with self.subTest(attack=attack):
                damaged, _ = image_archive(extra=attack)
                with self.assertRaisesRegex(images.Refused, "INVALID_IMAGE_ARCHIVE"):
                    self.inspect(damaged, {key: ids[key] for key in ("hub", "web")})

    def test_rejects_foreign_tags_unreferenced_members_and_platforms(self):
        for payload in (
            image_archive(tags={"hub": ["foreign:latest"], "web": None}),
            image_archive(tags={"hub": None, "web": None}),
            image_archive(extra=("foreign.txt", b"payload")),
            image_archive(extra=("repositories", b'{"foreign":{"latest":"bad"}}')),
            image_archive(platform=("windows", "amd64")),
            image_archive(platform=("linux", "mips64")),
        ):
            with self.subTest(payload=hashlib.sha256(payload[0]).hexdigest()[:8]):
                with self.assertRaisesRegex(images.Refused, "INVALID_IMAGE_ARCHIVE"):
                    self.inspect(*payload)

    def test_oci_docker_save_validates_nested_indexes_and_compressed_diff_ids(self):
        raw, ids = oci_image_archive(("hub", "web", "ssh-gateway"))
        self.assertGreater(self.inspect(raw, ids), 0)
        path = self.path / "oci-platforms.tar"
        path.write_bytes(raw)
        fd = os.open(path, os.O_RDONLY)
        try:
            platforms = {}
            images._inspect_image_tar(fd, ids, deadline=time.monotonic() + 10,
                                      platforms=platforms)
            self.assertEqual(platforms, {service: {"os": "linux",
                                                 "architecture": "amd64"}
                                         for service in ids})
        finally:
            os.close(fd)
        without_attestation, ids = oci_image_archive(attestation=False)
        self.assertGreater(self.inspect(without_attestation, ids), 0)
        for payload in (oci_image_archive(foreign_tag=True),
                        oci_image_archive(wrong_diff=True),
                        oci_image_archive(extra=("blobs/sha256/" +
                                                 hashlib.sha256(b"unreferenced").hexdigest(),
                                                 b"unreferenced"))):
            with self.subTest(payload=hashlib.sha256(payload[0]).hexdigest()[:8]):
                with self.assertRaises(images.Refused):
                    self.inspect(*payload)

    def test_oci_export_config_may_differ_from_pinned_daemon_image_id(self):
        raw, exported = oci_image_archive()
        source = {"hub": "sha256:" + "1" * 64,
                  "web": "sha256:" + "2" * 64}
        rootfs = {service: images._rootfs_digest([
            "sha256:" + hashlib.sha256((service + " OCI layer\n").encode()).hexdigest()])
            for service in source}
        captured = {}
        self.assertGreater(self.inspect(raw, source, source_rootfs=rootfs,
                                        exported_configs=captured), 0)
        self.assertEqual(captured, exported)
        with self.assertRaisesRegex(images.Refused, "ROOTFS_MISMATCH"):
            self.inspect(raw, source, source_rootfs={**rootfs, "web": "0" * 64})
        malformed, _ = oci_image_archive(bad_descriptor=True)
        with self.assertRaisesRegex(images.Refused, "INVALID_IMAGE_ARCHIVE"):
            self.inspect(malformed, source, source_rootfs=rootfs)

    def test_unreferenced_legacy_metadata_cannot_exhaust_capture_memory(self):
        foreign = hashlib.sha256(b"unreferenced layer").hexdigest()
        archive, ids = image_archive(extra=(foreign + "/json", b"x" * 1024))
        with patch.object(images, "MAX_CAPTURED_METADATA", 1024):
            with self.assertRaisesRegex(images.Refused, "INVALID_IMAGE_ARCHIVE"):
                self.inspect(archive, ids)

    def test_accepts_only_referenced_legacy_layer_metadata(self):
        root = hashlib.sha256(b"hub").hexdigest()
        repositories = {"sovagrid-" + service: {
            "local": hashlib.sha256(service.encode()).hexdigest()}
            for service in ("hub", "web")}
        archive, ids = image_archive(extra=("repositories", json.dumps(repositories).encode()))
        self.assertGreater(self.inspect(archive, ids), 0)
        for name, raw in ((root + "/VERSION", b"1.0\n"),
                          (root + "/json", b'{"id":"legacy"}')):
            archive, ids = image_archive(extra=(name, raw))
            self.assertGreater(self.inspect(archive, ids), 0)
        for name, raw in ((root + "/VERSION", b"2.0\n"),
                          (root + "/json", b"not-json"),
                          ("f" * 64 + "/VERSION", b"1.0\n")):
            archive, ids = image_archive(extra=(name, raw))
            with self.subTest(name=name):
                with self.assertRaisesRegex(images.Refused, "INVALID_IMAGE_ARCHIVE"):
                    self.inspect(archive, ids)

    def _export_fixture(self, *, oci=False):
        if oci:
            raw, _exported = oci_image_archive()
            ids = {"hub": "sha256:" + "1" * 64,
                   "web": "sha256:" + "2" * 64}
        else:
            raw, ids = image_archive()
        docker_tar = self.path / "docker-save.tar"
        docker_tar.write_bytes(raw)
        docker_script = self.path / "fake-docker-save.py"
        docker_script.write_text(
            "import os,sys\n"
            "assert sys.argv[1:3] == ['image','save']\n"
            "assert sys.argv[3:] == ['sovagrid-hub:local','sovagrid-web:local']\n"
            "with open(os.environ['SOVAGRID_FAKE_DOCKER_SAVE'], 'rb') as source:\n"
            "  while chunk := source.read(65536):\n"
            "    os.write(1, chunk)\n")
        host_raw = b"verified host archive fixture"
        host_tar = self.path / "host.tar.gz"
        host_tar.write_bytes(host_raw)
        host_manifest = {"id": IDENTITY, "bytes": len(host_raw),
                         "sha256": hashlib.sha256(host_raw).hexdigest(),
                         "layout": "full", "source_manifest_sha256": SOURCE}
        target = self.path / "clean-root"
        (target / "var/lib").mkdir(parents=True)
        installed = {service: {"container_id": ("1" if service == "hub" else "2") * 64,
                               "image_id": identity,
                               "rootfs_sha256": images._rootfs_digest([
                                   "sha256:" + hashlib.sha256(
                                       (service + (" OCI layer\n" if oci else
                                                   " layer contents\n")).encode()).hexdigest()])}
                     for service, identity in ids.items()}
        return docker_tar, docker_script, host_tar, host_manifest, target, installed

    def _patch_environment(self, docker_tar, docker_script, host_tar,
                           host_manifest, target, installed):
        def archive_fd(_identity):
            return os.open(host_tar, os.O_RDONLY), host_manifest
        return (
            patch.object(images.restore, "_archive_fd", side_effect=archive_fd),
            patch.object(images.restore, "_inspect_tar", return_value={}),
            patch.object(images.backup, "_sources", return_value=()),
            patch.object(images.backup, "_require_root"),
            patch.object(images.backup, "_locks", side_effect=lambda: nullcontext()),
            patch.object(images.backup, "_layout", return_value="full"),
            patch.object(images.backup, "_source_manifest", return_value=SOURCE),
            patch.object(images, "_installed_images", return_value=installed),
            patch.object(images.backup, "ROOT", target),
            patch.object(images.backup, "ROOT_UID", os.geteuid()),
            patch.object(images.backup, "ROOT_GID", os.getegid()),
            patch.object(images, "DOCKER", (sys.executable, str(docker_script))),
            patch.dict(os.environ, {"SOVAGRID_FAKE_DOCKER_SAVE": str(docker_tar)}),
        )

    def test_create_and_verify_publish_only_private_atomic_artifact(self):
        fixture = self._export_fixture()
        docker_tar, docker_script, host_tar, host_manifest, target, installed = fixture
        patches = self._patch_environment(*fixture)
        for context in patches:
            context.start()
            self.addCleanup(context.stop)
        result = images.create(IDENTITY)
        self.assertEqual(result["image_count"], 2)
        self.assertFalse(result["apply_available"])
        artifact = target / "var/lib/sovagrid-host-image-exports" / IDENTITY
        self.assertEqual((artifact / "images.tar").read_bytes(), docker_tar.read_bytes())
        self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((artifact / "images.tar").stat().st_mode), 0o600)
        record = json.loads((artifact / "manifest.json").read_text())
        self.assertEqual(record["host_archive_sha256"], host_manifest["sha256"])
        self.assertEqual(set(record["images"]), set(installed))
        self.assertEqual(record["rootfs_sha256"], {
            service: item["rootfs_sha256"] for service, item in installed.items()})
        self.assertEqual(record["exported_configs"], record["images"])
        self.assertEqual(images.verify(IDENTITY)["verified"], True)
        self.assertEqual(list(artifact.parent.iterdir()), [artifact])
        self.assertFalse((target / "opt").exists())
        self.assertFalse((target / "etc").exists())
        with self.assertRaisesRegex(images.Refused, "EXISTS"):
            images.create(IDENTITY)
        with (artifact / "images.tar").open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(images.Refused, "UNSAFE_ARTIFACT"):
            images.verify(IDENTITY)

    def test_portable_receipt_survives_without_source_operation_ledger(self):
        fixture = self._export_fixture()
        *_, target, installed = fixture
        for context in self._patch_environment(*fixture):
            context.start()
            self.addCleanup(context.stop)
        images.create(IDENTITY)
        artifact = target / "var/lib/sovagrid-host-image-exports" / IDENTITY
        record = json.loads((artifact / "manifest.json").read_text())
        with self.assertRaisesRegex(images.Refused, "RECEIPT_NOT_FOUND"):
            images.verify(IDENTITY, require_receipt=True)
        receipt = {"protocol": images.PORTABLE_RECEIPT,
                   "host_archive_id": IDENTITY,
                   "host_archive_sha256": record["host_archive_sha256"],
                   "source_manifest_sha256": record["source_manifest_sha256"],
                   "images_sha256": record["sha256"],
                   "images": record["images"],
                   "container_ids": record["container_ids"],
                   "exported_configs": record["exported_configs"],
                   "rootfs_sha256": record["rootfs_sha256"],
                   "active_units": ["sovagrid-vpn-control.socket"],
                   "unit_hashes": {"sovagrid-vpn-control.socket": "e" * 64}}
        bad = {**receipt, "images_sha256": "0" * 64}
        with self.assertRaisesRegex(images.Refused, "INVALID_RECEIPT"):
            images._publish_portable_receipt_locked(IDENTITY, bad)
        self.assertFalse((artifact / "receipt.json").exists())
        with patch.object(images, "_write_all", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                images._publish_portable_receipt_locked(IDENTITY, receipt)
        self.assertFalse((artifact / "receipt.json").exists())
        self.assertEqual(list(artifact.parent.iterdir()), [artifact])
        images._publish_portable_receipt_locked(IDENTITY, receipt)
        receipt_path = artifact / "receipt.json"
        self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
        checked = images.verify(IDENTITY, require_receipt=True)
        self.assertEqual(checked["receipt"], receipt)
        self.assertEqual(checked["platforms"], {service: {"os": "linux",
                            "architecture": "amd64"} for service in installed})
        self.assertEqual(set(artifact.iterdir()), {artifact / name for name in
                                                  ("images.tar", "manifest.json",
                                                   "receipt.json")})
        with self.assertRaisesRegex(images.Refused, "EXISTS"):
            images._publish_portable_receipt_locked(IDENTITY, receipt)
        receipt_path.write_text(json.dumps({**receipt, "active_units": []}))
        with self.assertRaisesRegex(images.Refused, "INVALID_RECEIPT"):
            images.verify(IDENTITY)

    def test_oci_create_and_verify_portable_preserve_original_daemon_ids(self):
        fixture = self._export_fixture(oci=True)
        *_, target, installed = fixture
        for context in self._patch_environment(*fixture):
            context.start()
            self.addCleanup(context.stop)
        images.create(IDENTITY)
        artifact = target / "var/lib/sovagrid-host-image-exports" / IDENTITY
        record = json.loads((artifact / "manifest.json").read_text())
        self.assertEqual(record["images"], {service: item["image_id"]
                                            for service, item in installed.items()})
        self.assertTrue(all(record["images"][service] != record["exported_configs"][service]
                            for service in installed))
        receipt = {"protocol": images.PORTABLE_RECEIPT,
                   "host_archive_id": IDENTITY,
                   "host_archive_sha256": record["host_archive_sha256"],
                   "source_manifest_sha256": record["source_manifest_sha256"],
                   "images_sha256": record["sha256"],
                   "images": record["images"],
                   "container_ids": record["container_ids"],
                   "exported_configs": record["exported_configs"],
                   "rootfs_sha256": record["rootfs_sha256"],
                   "active_units": [], "unit_hashes": {}}
        images._publish_portable_receipt_locked(IDENTITY, receipt)
        checked = images.verify(IDENTITY, require_receipt=True)
        self.assertEqual(checked["receipt"], receipt)
        self.assertEqual(set(checked["platforms"]), set(installed))

    def test_bounded_export_rejects_large_stream_and_cleans_temp(self):
        fixture = self._export_fixture()
        *_, target, _installed = fixture
        patches = self._patch_environment(*fixture)
        for context in patches:
            context.start()
            self.addCleanup(context.stop)
        with patch.object(images, "MAX_IMAGE_BYTES", 1024):
            with self.assertRaisesRegex(images.Refused, "SIZE_LIMIT"):
                images.create(IDENTITY)
        output = target / "var/lib/sovagrid-host-image-exports"
        self.assertEqual(list(output.iterdir()), [])
        self.assertFalse((target / "opt").exists())

    def test_running_container_image_must_equal_local_tag(self):
        first = "sha256:" + "a" * 64
        second = "sha256:" + "b" * 64
        responses = {
            ("ps", "--quiet", "--filter", "label=com.docker.compose.project=sovagrid",
             "--filter", "label=com.docker.compose.service=hub"): "1" * 12,
            ("ps", "--quiet", "--filter", "label=com.docker.compose.project=sovagrid",
             "--filter", "label=com.docker.compose.service=web"): "2" * 12,
            ("inspect", "--format", "{{.Id}}", "1" * 12): "1" * 64,
            ("inspect", "--format", "{{.Id}}", "2" * 12): "2" * 64,
            ("inspect", "--format", "{{.Image}}", "1" * 12): first,
            ("inspect", "--format", "{{.Image}}", "2" * 12): second,
            ("image", "inspect", "--format", "{{.Id}}", "sovagrid-hub:local"): first,
            ("image", "inspect", "--format", "{{.Id}}", "sovagrid-web:local"): second,
            ("image", "inspect", "--format", "{{json .RootFS.Layers}}",
             "sovagrid-hub:local"): json.dumps(["sha256:" + "3" * 64]),
            ("image", "inspect", "--format", "{{json .RootFS.Layers}}",
             "sovagrid-web:local"): json.dumps(["sha256:" + "4" * 64]),
        }
        with (patch.object(images.backup, "plan", return_value={
                "layout": "full", "running_containers": ["hub", "web"]}),
              patch.object(images.backup, "_gateway_marker", return_value=False),
              patch.object(images, "_capture",
                           side_effect=lambda args, **kwargs: responses[tuple(args)])):
            installed = images._installed_images("full")
            self.assertEqual(set(installed), {"hub", "web"})
            self.assertEqual(installed["hub"]["rootfs_sha256"],
                             images._rootfs_digest(["sha256:" + "3" * 64]))
            responses[("image", "inspect", "--format", "{{.Id}}",
                       "sovagrid-web:local")] = first
            with self.assertRaisesRegex(images.Refused, "IMAGE_CHANGED"):
                images._installed_images("full")


if __name__ == "__main__":
    unittest.main()
