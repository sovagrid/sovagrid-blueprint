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
from types import SimpleNamespace
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
                      bad_descriptor=False, direct_manifest=False,
                      layer_media_type=None, architecture="amd64",
                      legacy_attestation=False, bad_attestation_config=False,
                      predicate="https://slsa.dev/provenance/v1",
                      manifest_media_type=None, config_media_type=None):
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
        packed = (layer if layer_media_type in (images.OCI_RAW_LAYER, images.DOCKER_RAW_LAYER)
                  else gzip.compress(layer, mtime=0))
        layer_descriptor = blob(packed)
        layer_descriptor["mediaType"] = layer_media_type or images.OCI_GZIP_LAYER
        diff_id = hashlib.sha256(layer + (b"changed" if wrong_diff else b"")).hexdigest()
        config = {"os": "linux", "architecture": architecture,
                  "rootfs": {"type": "layers", "diff_ids": ["sha256:" + diff_id]}}
        config_descriptor = json_blob(config)
        manifest_type = manifest_media_type or images.OCI_MANIFEST
        config_descriptor["mediaType"] = config_media_type or (
            images.DOCKER_CONFIG if manifest_type == images.DOCKER_MANIFEST else images.OCI_CONFIG)
        ids[service] = config_descriptor["digest"]
        manifest = {"schemaVersion": 2, "mediaType": manifest_type,
                    "config": config_descriptor, "layers": [layer_descriptor]}
        primary = json_blob(manifest)
        primary["mediaType"] = manifest_type
        primary["platform"] = {"os": "linux", "architecture": architecture}
        if bad_descriptor and service == "hub":
            primary["size"] += 1
        nested = [primary]
        if attestation:
            empty = blob(b"{}")
            statement = json_blob({"_type": "https://in-toto.io/Statement/v1"})
            statement["mediaType"] = "application/vnd.in-toto+json"
            statement["annotations"] = {
                "in-toto.io/predicate-type": predicate}
            if legacy_attestation:
                # Real BuildKit --provenance=mode=min defaults to an ordinary
                # non-runnable config, rather than the optional OCI artifact.
                blobs.pop(empty["digest"][7:])
                config = {"architecture": "unknown", "os": "unknown", "config": {},
                          "rootfs": {"type": "layers", "diff_ids": [statement["digest"]]}}
                if bad_attestation_config:
                    config["config"] = {"Entrypoint": ["/untrusted"]}
                att_config = json_blob(config)
                att_config["mediaType"] = images.OCI_CONFIG
                att_manifest = {"schemaVersion": 2, "mediaType": images.OCI_MANIFEST,
                                "config": att_config, "layers": [statement]}
            else:
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
        if direct_manifest:
            assert not attestation
            nested_index = {key: primary[key] for key in ("mediaType", "digest", "size")}
        else:
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


def oci_daemon_ids(raw):
    """Containerd reports the named top descriptor as the daemon image ID."""
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        top = json.load(archive.extractfile("index.json"))
    return {item["annotations"]["io.containerd.image.name"].removeprefix(
                "docker.io/library/sovagrid-").removesuffix(":local"): item["digest"]
            for item in top["manifests"]}


class ImageExportTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)

    def test_export_is_pinned_to_the_local_docker_socket(self):
        self.assertEqual(images.DOCKER,
                         ("/usr/bin/docker", "--host", "unix:///run/docker.sock"))

    def test_anonymous_export_checks_available_blocks_via_the_held_output_fd(self):
        script = self.path / "stream.py"
        payload = b"anonymous docker stream\x00\xff"
        script.write_text("import os\nos.write(1," + repr(payload) + ")\n")
        for blocks in (0, images.MIN_FREE // 4096 + 2):
            with self.subTest(blocks=blocks):
                descriptor, name = tempfile.mkstemp(dir=self.path)
                os.unlink(name)
                try:
                    self.assertEqual(os.fstat(descriptor).st_nlink, 0)
                    with (patch.object(images, "DOCKER", (sys.executable, str(script))),
                          patch.object(images.os, "fstatvfs", return_value=SimpleNamespace(
                              f_bavail=blocks, f_frsize=4096)) as space,
                          patch.object(images.shutil, "disk_usage", side_effect=AssertionError(
                              "anonymous export must not resolve a filesystem path"))):
                        if blocks == 0:
                            with self.assertRaisesRegex(images.Refused, "DISK_SPACE"):
                                images._save_images([], descriptor, descriptor,
                                                    deadline=time.monotonic() + 10)
                            self.assertEqual(os.fstat(descriptor).st_size, 0)
                        else:
                            self.assertEqual(images._save_images([], descriptor, descriptor,
                                deadline=time.monotonic() + 10),
                                (len(payload), hashlib.sha256(payload).hexdigest()))
                            self.assertEqual(os.pread(descriptor, len(payload), 0), payload)
                    space.assert_called_once_with(descriptor)
                finally:
                    os.close(descriptor)

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
        source = oci_daemon_ids(raw)
        rootfs = {service: images._rootfs_digest([
            "sha256:" + hashlib.sha256((service + " OCI layer\n").encode()).hexdigest()])
            for service in source}
        captured = {}
        self.assertGreater(self.inspect(raw, source, source_rootfs=rootfs,
                                        exported_configs=captured), 0)
        self.assertEqual(captured, exported)
        with self.assertRaisesRegex(images.Refused, "IMAGE_ID_MISMATCH"):
            self.inspect(raw, {**source, "web": "sha256:" + "2" * 64}, source_rootfs=rootfs)
        with self.assertRaisesRegex(images.Refused, "ROOTFS_MISMATCH"):
            self.inspect(raw, source, source_rootfs={**rootfs, "web": "0" * 64})
        malformed, _ = oci_image_archive(bad_descriptor=True)
        with self.assertRaisesRegex(images.Refused, "INVALID_IMAGE_ARCHIVE"):
            self.inspect(malformed, source, source_rootfs=rootfs)

    def test_real_containerd_direct_manifest_and_docker_gzip_layer_shape(self):
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture):
                raw, ids = oci_image_archive(("hub", "web", "ssh-gateway"),
                    attestation=False, direct_manifest=True,
                    layer_media_type=images.DOCKER_GZIP_LAYER, architecture=architecture)
                self.assertGreater(self.inspect(raw, ids), 0)
        for options in ({"foreign_tag": True}, {"wrong_diff": True},
                        {"architecture": "riscv64"}, {"layer_media_type": "application/unknown"}):
            with self.subTest(options=options), self.assertRaises(images.Refused):
                self.inspect(*oci_image_archive(attestation=False, direct_manifest=True,
                                                **options))

    def test_real_buildkit_legacy_attestation_config_stays_non_runnable_and_hash_bound(self):
        for predicate in ("https://slsa.dev/provenance/v0.2", "https://slsa.dev/provenance/v1"):
            with self.subTest(predicate=predicate):
                self.assertGreater(self.inspect(*oci_image_archive(
                    legacy_attestation=True, predicate=predicate)), 0)
        for options in ({"bad_attestation_config": True}, {"wrong_diff": True},
                        {"predicate": "https://untrusted.invalid/predicate"},
                        {"extra": ("blobs/sha256/" + hashlib.sha256(b"foreign").hexdigest(), b"foreign")}):
            with self.subTest(options=options), self.assertRaises(images.Refused):
                self.inspect(*oci_image_archive(legacy_attestation=True, **options))

    def test_real_containerd_reexport_of_legacy_docker_manifest_has_exact_media_pair(self):
        options = {"attestation": False, "direct_manifest": True,
                   "manifest_media_type": images.DOCKER_MANIFEST,
                   "layer_media_type": images.DOCKER_GZIP_LAYER}
        raw, configs = oci_image_archive(**options)
        source = oci_daemon_ids(raw)
        runtime = {}
        self.assertGreater(self.inspect(raw, source, runtime_ids=runtime), 0)
        self.assertEqual(runtime, {service: sorted((source[service], configs[service]))
                                   for service in configs})
        for changes in ({"config_media_type": images.OCI_CONFIG},
                        {"layer_media_type": images.OCI_GZIP_LAYER},
                        {"manifest_media_type": "application/unknown"}):
            with self.subTest(changes=changes), self.assertRaises(images.Refused):
                self.inspect(*oci_image_archive(**{**options, **changes}))

    def test_uncompressed_oci_and_docker_layers_bind_the_raw_bytes_to_diff_id(self):
        for manifest_type, layer_type in ((images.OCI_MANIFEST, images.OCI_RAW_LAYER),
                                         (images.OCI_MANIFEST, images.DOCKER_RAW_LAYER),
                                         (images.DOCKER_MANIFEST, images.DOCKER_RAW_LAYER)):
            options = {"attestation": False, "direct_manifest": True,
                       "manifest_media_type": manifest_type, "layer_media_type": layer_type}
            with self.subTest(manifest=manifest_type, layer=layer_type):
                raw, configs = oci_image_archive(**options)
                self.assertGreater(self.inspect(raw, oci_daemon_ids(raw)), 0)
                with self.assertRaisesRegex(images.Refused, "LAYER_DIGEST_MISMATCH"):
                    self.inspect(*oci_image_archive(**options, wrong_diff=True))

    def test_runtime_ids_are_only_this_services_verified_runnable_dag(self):
        for options, count in (({"attestation": False, "direct_manifest": True}, 2),
                               ({"attestation": False}, 3),
                               ({"legacy_attestation": True}, 3), ({}, 3)):
            with self.subTest(options=options):
                raw, configs = oci_image_archive(**options)
                source = oci_daemon_ids(raw)
                runtime = {}
                self.assertGreater(self.inspect(raw, source, runtime_ids=runtime), 0)
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                    top = json.load(archive.extractfile("index.json"))
                    for descriptor in top["manifests"]:
                        service = descriptor["annotations"]["io.containerd.image.name"].removeprefix(
                            "docker.io/library/sovagrid-").removesuffix(":local")
                        value = json.load(archive.extractfile("blobs/sha256/" + descriptor["digest"][7:]))
                        expected = {configs[service], descriptor["digest"]}
                        if "manifests" in value:
                            expected.add(value["manifests"][0]["digest"])
                            if len(value["manifests"]) == 2:
                                self.assertNotIn(value["manifests"][1]["digest"], runtime[service])
                        self.assertEqual(runtime[service], sorted(expected))
                        self.assertEqual(len(runtime[service]), count)
                with self.assertRaisesRegex(images.Refused, "IMAGE_ID_MISMATCH"):
                    self.inspect(raw, {**source, "web": source["hub"]})
        raw, configs = image_archive()
        runtime = {}
        self.inspect(raw, configs, runtime_ids=runtime)
        self.assertEqual(runtime, {service: [digest] for service, digest in configs.items()})

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
            ids = oci_daemon_ids(raw)
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
        receipt = {"protocol": images.PORTABLE_RECEIPT_V1,
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
        receipt = {"protocol": images.PORTABLE_RECEIPT_V1,
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

    def test_v2_receipt_validates_all_managed_unit_states(self):
        record = {"layout": "full", "host_archive_sha256": "a" * 64,
                  "source_manifest_sha256": "b" * 64, "sha256": "c" * 64,
                  "images": {}, "container_ids": {}, "exported_configs": {},
                  "rootfs_sha256": {}}
        unit = "sovagrid-vpn-control.socket"
        states = {
            unit: {"active": True, "enablement": "enabled", "sha256": "d" * 64},
            "sovagrid-agent.service": {"active": True,
                                       "enablement": "disabled", "sha256": "e" * 64}}
        receipt = {"protocol": images.PORTABLE_RECEIPT,
                   "host_archive_id": IDENTITY,
                   "host_archive_sha256": record["host_archive_sha256"],
                   "source_manifest_sha256": record["source_manifest_sha256"],
                   "images_sha256": record["sha256"], "images": {},
                   "container_ids": {}, "exported_configs": {},
                   "rootfs_sha256": {}, "active_units": [unit],
                   "unit_hashes": {unit: "d" * 64}, "unit_states": states}
        self.assertTrue(images._valid_portable_receipt(receipt, IDENTITY, record))
        amnezia = "sovagrid-amnezia-control.socket"
        with_amnezia = {**receipt,
                        "active_units": [unit, amnezia],
                        "unit_hashes": {unit: "d" * 64, amnezia: "f" * 64},
                        "unit_states": {**states, amnezia: {
                            "active": True, "enablement": "enabled",
                            "sha256": "f" * 64}}}
        self.assertTrue(images._valid_portable_receipt(
            with_amnezia, IDENTITY, record))
        legacy = {key: value for key, value in receipt.items()
                  if key != "unit_states"}
        legacy["protocol"] = images.PORTABLE_RECEIPT_V1
        self.assertTrue(images._valid_portable_receipt(legacy, IDENTITY, record))
        for changed in (
                {**states, "sovagrid-foreign.service": {"active": False,
                    "enablement": "disabled", "sha256": "f" * 64}},
                {**states, unit: {"active": True, "enablement": "enabled",
                                  "sha256": "f" * 64}},
                {**states, unit: {"active": False, "enablement": "enabled",
                                  "sha256": "d" * 64}},
                {**states, unit: {"active": True, "enablement": [],
                                  "sha256": "d" * 64}}):
            with self.subTest(states=changed):
                self.assertFalse(images._valid_portable_receipt(
                    {**receipt, "unit_states": changed}, IDENTITY, record))

    def test_v2_receipt_verify_binds_unit_hashes_to_host_archive_bytes(self):
        fixture = self._export_fixture()
        *_, target, _installed = fixture
        for context in self._patch_environment(*fixture):
            context.start()
            self.addCleanup(context.stop)
        images.backup._sources.return_value = (
            images.backup.Source("/etc/systemd/system/sovagrid-agent.service"),)
        with self.assertRaisesRegex(images.Refused, "HOST_ARCHIVE_CHANGED"):
            images._create_locked(IDENTITY, expected_unit_hashes={
                "sovagrid-agent.service": "e" * 64})
        images.create(IDENTITY)
        artifact = target / "var/lib/sovagrid-host-image-exports" / IDENTITY
        record = json.loads((artifact / "manifest.json").read_text())
        receipt = {"protocol": images.PORTABLE_RECEIPT,
                   "host_archive_id": IDENTITY,
                   "host_archive_sha256": record["host_archive_sha256"],
                   "source_manifest_sha256": record["source_manifest_sha256"],
                   "images_sha256": record["sha256"],
                   "images": record["images"],
                   "container_ids": record["container_ids"],
                   "exported_configs": record["exported_configs"],
                   "rootfs_sha256": record["rootfs_sha256"],
                   "active_units": [], "unit_hashes": {}, "unit_states": {}}
        images._publish_portable_receipt_locked(IDENTITY, receipt)
        self.assertEqual(images.verify(IDENTITY, require_receipt=True)["receipt"], receipt)
        receipt["unit_states"] = {"sovagrid-agent.service": {
            "active": False, "enablement": "disabled", "sha256": "e" * 64}}
        self.assertTrue(images._valid_portable_receipt(receipt, IDENTITY, record))
        (artifact / "receipt.json").write_text(json.dumps(receipt) + "\n")
        with self.assertRaisesRegex(images.Refused, "INVALID_RECEIPT"):
            images.verify(IDENTITY, require_receipt=True)

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
