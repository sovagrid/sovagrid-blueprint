# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Offline, disposable fixtures for exact-image export and verification."""

from __future__ import annotations

from contextlib import nullcontext
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
                  changed_config=None, extra=None):
    entries = []
    manifest = []
    identities = {}
    for service in services:
        layer = (service + " layer contents\n").encode()
        layer_digest = hashlib.sha256(layer).hexdigest()
        config = {"rootfs": {"type": "layers",
                              "diff_ids": ["sha256:" + layer_digest]},
                  "architecture": "amd64", "os": "linux"}
        raw = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        image_id = "sha256:" + hashlib.sha256(raw).hexdigest()
        identities[service] = image_id
        config_name = image_id[7:] + ".json"
        layer_name = hashlib.sha256(service.encode()).hexdigest() + "/layer.tar"
        entries.append((config_name, raw + (b"x" if changed_config == service else b"")))
        entries.append((layer_name, layer + (b"x" if changed_layer == service else b"")))
        manifest.append({"Config": config_name, "RepoTags": ["sovagrid-" + service +
                          ":local"], "Layers": [layer_name]})
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


class ImageExportTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)

    def test_export_is_pinned_to_the_local_docker_socket(self):
        self.assertEqual(images.DOCKER,
                         ("/usr/bin/docker", "--host", "unix:///run/docker.sock"))

    def inspect(self, raw, identities):
        path = self.path / "inspect.tar"
        path.write_bytes(raw)
        fd = os.open(path, os.O_RDONLY)
        try:
            return images._inspect_image_tar(fd, identities,
                                             deadline=time.monotonic() + 10)
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

    def _export_fixture(self):
        raw, ids = image_archive()
        docker_tar = self.path / "docker-save.tar"
        docker_tar.write_bytes(raw)
        docker_script = self.path / "fake-docker-save.py"
        docker_script.write_text(
            "import os,sys\n"
            "assert sys.argv[1:3] == ['image','save']\n"
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
                               "image_id": identity}
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
        }
        with (patch.object(images.backup, "plan", return_value={
                "layout": "full", "running_containers": ["hub", "web"]}),
              patch.object(images.backup, "_gateway_marker", return_value=False),
              patch.object(images, "_capture", side_effect=lambda args: responses[tuple(args)])):
            self.assertEqual(set(images._installed_images("full")), {"hub", "web"})
            responses[("image", "inspect", "--format", "{{.Id}}",
                       "sovagrid-web:local")] = first
            with self.assertRaisesRegex(images.Refused, "IMAGE_CHANGED"):
                images._installed_images("full")


if __name__ == "__main__":
    unittest.main()
