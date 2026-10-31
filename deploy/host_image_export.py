#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Root-only, bounded Docker image export bound to one verified host archive.

This exports opaque Docker images for later offline recovery. It never invokes
docker load, writes live SovaGrid paths, or enables host restore apply.
"""

from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import uuid
import zlib


sys.dont_write_bytecode = True


def _sibling(filename: str, name: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise RuntimeError("SovaGrid archive validator unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


restore = _sibling("host_restore.py", "_sovagrid_host_images_restore")
backup = restore.backup
PROTOCOL = "sovagrid-host-images-v1"
PORTABLE_RECEIPT = "sovagrid-portable-host-receipt-v1"
OUTPUT = Path("/var/lib/sovagrid-host-image-exports")
# Pin the local daemon. A caller's Docker context must not redirect an export
# to a remote host with identically named Compose services.
DOCKER = ("/usr/bin/docker", "--host", "unix:///run/docker.sock")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
SHORT_ID = re.compile(r"[0-9a-f]{12,64}\Z")
LAYER_PATH = re.compile(r"[0-9a-f]{64}/layer\.tar\Z")
OCI_BLOB = re.compile(r"blobs/sha256/([0-9a-f]{64})\Z")
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_GZIP_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
MAX_IMAGE_BYTES = 8 * 1024**3
MAX_IMAGE_FILES = 20_000
MAX_IMAGE_SECONDS = 1200
MAX_IMAGE_MANIFEST = 4096
MAX_PORTABLE_RECEIPT = 8192
MAX_DOCKER_MANIFEST = 256 * 1024
MAX_CONFIG = 16 * 1024**2
MAX_LEGACY_METADATA = 1024**2
MAX_CAPTURED_METADATA = 64 * 1024**2
MAX_ROOTFS_LAYERS = 128
MIN_FREE = backup.MIN_FREE


class Refused(RuntimeError):
    """Stable refusal code without command output or private paths."""


def _id(value: str) -> str:
    if not isinstance(value, str) or backup.ID.fullmatch(value) is None:
        raise Refused("INVALID_ID")
    return value


def _sha(value: object) -> bool:
    return isinstance(value, str) and IMAGE_ID.fullmatch(value) is not None


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused("INVALID_IMAGE_ARCHIVE")
        result[key] = value
    return result


def _verified_host(identity: str, *, deadline: float) -> tuple[int, dict, tuple]:
    """Pin the host archive FD throughout export, including its source bundle."""
    fd, manifest = restore._archive_fd(identity)
    try:
        before = restore._hash_archive(fd, manifest, deadline=deadline)
        restore._inspect_tar(fd, manifest, backup._sources(manifest["layout"]),
                             deadline=deadline)
        if restore._fingerprint(os.fstat(fd)) != before:
            raise Refused("HOST_ARCHIVE_CHANGED")
        return fd, manifest, before
    except BaseException:
        os.close(fd)
        raise


def _capture(args: list[str], *, maximum: int = 4096) -> str:
    try:
        result = subprocess.run([*DOCKER, *args], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused("DOCKER_UNAVAILABLE") from exc
    if result.returncode or len(result.stdout) > maximum:
        raise Refused("DOCKER_UNAVAILABLE")
    return result.stdout.strip()


def _rootfs_digest(layers: object) -> str:
    """Canonical, bounded digest of Docker's ordered RootFS.Layers vector."""
    if (not isinstance(layers, list) or
            not 1 <= len(layers) <= MAX_ROOTFS_LAYERS or
            any(not _sha(layer) for layer in layers)):
        raise Refused("INVALID_ROOTFS")
    return hashlib.sha256("\n".join(layers).encode("ascii")).hexdigest()


def _installed_images(layout: str) -> dict[str, dict[str, str]]:
    """Require each running managed container to use its local tagged image."""
    state = backup.plan()
    if state["layout"] != layout:
        raise Refused("LAYOUT_CHANGED")
    services = list(backup.COMPOSE_SERVICES[:2])
    if backup._gateway_marker():
        services.append("ssh-gateway")
    if state["running_containers"] != services:
        raise Refused("STACK_NOT_READY")
    result = {}
    for service in services:
        ids = _capture(["ps", "--quiet", "--filter",
                        "label=com.docker.compose.project=sovagrid", "--filter",
                        "label=com.docker.compose.service=" + service]).splitlines()
        if len(ids) != 1 or SHORT_ID.fullmatch(ids[0]) is None:
            raise Refused("CONTAINER_CHANGED")
        container_id = _capture(["inspect", "--format", "{{.Id}}", ids[0]])
        container_image = _capture(["inspect", "--format", "{{.Image}}", ids[0]])
        tag_image = _capture(["image", "inspect", "--format", "{{.Id}}",
                              "sovagrid-" + service + ":local"])
        if (CONTAINER_ID.fullmatch(container_id) is None or
                not _sha(container_image) or not _sha(tag_image) or
                container_image != tag_image):
            raise Refused("IMAGE_CHANGED")
        try:
            rootfs = json.loads(_capture(["image", "inspect", "--format",
                                           "{{json .RootFS.Layers}}",
                                           "sovagrid-" + service + ":local"],
                                          maximum=16_384))
        except (UnicodeError, ValueError) as exc:
            raise Refused("INVALID_ROOTFS") from exc
        result[service] = {"container_id": container_id, "image_id": tag_image,
                           "rootfs_sha256": _rootfs_digest(rootfs)}
    if len({value["image_id"] for value in result.values()}) != len(result):
        raise Refused("IMAGE_AMBIGUOUS")
    return result


def _output(*, create: bool) -> tuple[Path, int]:
    present, unsafe = restore._target_path("/var/lib")
    if not present or unsafe:
        raise Refused("UNSAFE_OUTPUT")
    parent_fd = backup._safe_open(Path("/var/lib"), directory=True)
    try:
        parent = os.fstat(parent_fd)
        if parent.st_uid != backup.ROOT_UID or stat.S_IMODE(parent.st_mode) & 0o022:
            raise Refused("UNSAFE_OUTPUT")
        created = False
        if create:
            try:
                os.mkdir(OUTPUT.name, 0o700, dir_fd=parent_fd)
                created = True
            except FileExistsError:
                pass
        try:
            fd = os.open(OUTPUT.name, os.O_RDONLY | os.O_DIRECTORY |
                         os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        except FileNotFoundError as exc:
            raise Refused("NOT_FOUND") from exc
        try:
            if created:
                info = os.fstat(fd)
                if (info.st_uid, info.st_gid) != (backup.ROOT_UID, backup.ROOT_GID):
                    os.fchown(fd, backup.ROOT_UID, backup.ROOT_GID)
                os.fchmod(fd, 0o700)
                os.fsync(fd)
                os.fsync(parent_fd)
            info = os.fstat(fd)
            if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (
                    backup.ROOT_UID, backup.ROOT_GID, 0o700):
                raise Refused("UNSAFE_OUTPUT")
            return backup._host(OUTPUT), fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent_fd)


def _private_new(parent_fd: int, name: str, *, read_write: bool = False) -> int:
    fd = os.open(name, (os.O_RDWR if read_write else os.O_WRONLY) |
                 os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                 os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        if (info.st_uid, info.st_gid) != (backup.ROOT_UID, backup.ROOT_GID):
            os.fchown(fd, backup.ROOT_UID, backup.ROOT_GID)
        os.fchmod(fd, 0o600)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _write_all(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise Refused("IO_ERROR")
        view = view[count:]


def _save_images(refs: list[str], fd: int, destination: Path, *, deadline: float) -> tuple[int, str]:
    """Stream Docker stdout with time, byte and free-space limits."""
    try:
        process = subprocess.Popen([*DOCKER, "image", "save", *refs],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, close_fds=True)
    except OSError as exc:
        raise Refused("DOCKER_UNAVAILABLE") from exc
    digest = hashlib.sha256()
    total = 0
    try:
        if process.stdout is None:
            raise Refused("DOCKER_SAVE_FAILED")
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                if time.monotonic() > deadline:
                    raise Refused("TIME_LIMIT")
                ready = selector.select(timeout=min(1, max(0, deadline - time.monotonic())))
                if not ready:
                    continue
                block = os.read(process.stdout.fileno(), 1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > MAX_IMAGE_BYTES:
                    raise Refused("SIZE_LIMIT")
                if shutil.disk_usage(destination).free < len(block) + MIN_FREE:
                    raise Refused("DISK_SPACE")
                _write_all(fd, block)
                digest.update(block)
        remaining = max(0.1, deadline - time.monotonic())
        try:
            code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise Refused("TIME_LIMIT") from exc
        if code or total == 0:
            raise Refused("DOCKER_SAVE_FAILED")
        os.fsync(fd)
        return total, digest.hexdigest()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if process.stdout is not None:
            process.stdout.close()


def _member_name(member: tarfile.TarInfo) -> tuple[str, bool]:
    if not (member.isfile() or member.isdir()) or member.linkname:
        raise Refused("INVALID_IMAGE_ARCHIVE")
    name = member.name.rstrip("/")
    parts = name.split("/")
    try:
        raw = name.encode("utf-8")
    except UnicodeError as exc:
        raise Refused("INVALID_IMAGE_ARCHIVE") from exc
    if (not name or name.startswith("/") or name.endswith("/") or
            member.name.endswith("//") or len(raw) > 4096 or
            any(part in ("", ".", "..") or len(part.encode("utf-8")) > 255
                for part in parts) or
            (member.isfile() and name != member.name) or
            type(member.size) is not int or member.size < 0 or
            member.size > MAX_IMAGE_BYTES or (member.isdir() and member.size != 0)):
        raise Refused("INVALID_IMAGE_ARCHIVE")
    return name, member.isdir()


def _parse_json(raw: bytes) -> object:
    try:
        return json.loads(raw, object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise Refused("INVALID_IMAGE_ARCHIVE") from exc


def _oci_blob(descriptor: object, files: dict, *, media_type: str) -> str:
    if (not isinstance(descriptor, dict) or
            set(descriptor) != {"mediaType", "digest", "size"} or
            descriptor["mediaType"] != media_type or
            not _sha(descriptor["digest"]) or
            type(descriptor["size"]) is not int):
        raise Refused("INVALID_IMAGE_ARCHIVE")
    name = "blobs/sha256/" + descriptor["digest"][7:]
    if name not in files or files[name][0] != descriptor["size"]:
        raise Refused("INVALID_IMAGE_ARCHIVE")
    return name


def _oci_json(fd: int, name: str, files: dict, offsets: dict,
              metadata: list[int], *, limit: int = MAX_CONFIG) -> object:
    size = files[name][0]
    metadata[0] += size
    if size > limit or metadata[0] > MAX_CAPTURED_METADATA:
        raise Refused("INVALID_IMAGE_ARCHIVE")
    raw = os.pread(fd, size, offsets[name])
    if len(raw) != size:
        raise Refused("INVALID_IMAGE_ARCHIVE")
    return _parse_json(raw)


def _oci_diff_id(fd: int, name: str, files: dict, offsets: dict,
                 expanded: list[int], *, deadline: float) -> str:
    """Hash an OCI gzip layer's uncompressed tar with a strict output cap."""
    remaining = files[name][0]
    position = offsets[name]
    decoder = zlib.decompressobj(31)
    digest = hashlib.sha256()
    while remaining:
        if time.monotonic() > deadline:
            raise Refused("TIME_LIMIT")
        block = os.pread(fd, min(1024 * 1024, remaining), position)
        if not block:
            raise Refused("INVALID_IMAGE_ARCHIVE")
        position += len(block)
        remaining -= len(block)
        pending = block
        while pending:
            if time.monotonic() > deadline:
                raise Refused("TIME_LIMIT")
            before_pending = len(pending)
            try:
                plain = decoder.decompress(pending, 1024 * 1024)
            except zlib.error as exc:
                raise Refused("INVALID_IMAGE_ARCHIVE") from exc
            expanded[0] += len(plain)
            if expanded[0] > MAX_IMAGE_BYTES:
                raise Refused("SIZE_LIMIT")
            digest.update(plain)
            pending = decoder.unconsumed_tail
            if len(pending) == before_pending and not plain and not decoder.eof:
                raise Refused("INVALID_IMAGE_ARCHIVE")
            if decoder.eof:
                if pending or decoder.unused_data or remaining:
                    raise Refused("INVALID_IMAGE_ARCHIVE")
                break
        if decoder.eof:
            break
    if not decoder.eof:
        raise Refused("INVALID_IMAGE_ARCHIVE")
    return digest.hexdigest()


def _inspect_oci_tar(fd: int, image_ids: dict[str, str], files: dict,
                     offsets: dict, seen: set[str], captured: dict,
                     *, deadline: float, platforms: dict | None = None,
                     source_rootfs: dict | None = None,
                     exported_configs: dict | None = None) -> int:
    if (set(seen) - set(files) != {"blobs", "blobs/sha256"} or
            not {"index.json", "manifest.json", "oci-layout"} <= set(files)):
        raise Refused("INVALID_IMAGE_ARCHIVE")
    for name, (_size, digest) in files.items():
        match = OCI_BLOB.fullmatch(name)
        if name not in ("index.json", "manifest.json", "oci-layout") and not match:
            raise Refused("INVALID_IMAGE_ARCHIVE")
        if match and match.group(1) != digest:
            raise Refused("INVALID_IMAGE_ARCHIVE")
    if _parse_json(captured["oci-layout"]) != {"imageLayoutVersion": "1.0.0"}:
        raise Refused("INVALID_IMAGE_ARCHIVE")
    index = _parse_json(captured["index.json"])
    docker_manifest = _parse_json(captured["manifest.json"])
    if (not isinstance(index, dict) or set(index) !=
            {"schemaVersion", "mediaType", "manifests"} or
            index["schemaVersion"] != 2 or index["mediaType"] != OCI_INDEX or
            not isinstance(index["manifests"], list) or
            len(index["manifests"]) != len(image_ids) or
            not isinstance(docker_manifest, list) or
            len(docker_manifest) != len(image_ids)):
        raise Refused("INVALID_IMAGE_ARCHIVE")
    metadata = [sum(len(raw) for raw in captured.values())]
    expanded = [0]
    referenced = {"index.json", "manifest.json", "oci-layout"}
    services = set()
    for top in index["manifests"]:
        if (not isinstance(top, dict) or set(top) !=
                {"mediaType", "digest", "size", "annotations"} or
                not isinstance(top["annotations"], dict) or
                set(top["annotations"]) !=
                {"io.containerd.image.name", "org.opencontainers.image.ref.name"} or
                top["annotations"]["org.opencontainers.image.ref.name"] != "local"):
            raise Refused("INVALID_IMAGE_ARCHIVE")
        names = [service for service in image_ids if
                 top["annotations"]["io.containerd.image.name"] ==
                 "docker.io/library/sovagrid-" + service + ":local"]
        if len(names) != 1 or names[0] in services:
            raise Refused("INVALID_IMAGE_ARCHIVE")
        service = names[0]
        services.add(service)
        top_name = _oci_blob({key: top[key] for key in ("mediaType", "digest", "size")},
                             files, media_type=OCI_INDEX)
        referenced.add(top_name)
        nested = _oci_json(fd, top_name, files, offsets, metadata)
        if (not isinstance(nested, dict) or set(nested) !=
                {"schemaVersion", "mediaType", "manifests"} or
                nested["schemaVersion"] != 2 or nested["mediaType"] != OCI_INDEX or
                not isinstance(nested["manifests"], list) or
                len(nested["manifests"]) not in (1, 2)):
            raise Refused("INVALID_IMAGE_ARCHIVE")
        primary = nested["manifests"][0]
        if (not isinstance(primary, dict) or set(primary) !=
                {"mediaType", "digest", "size", "platform"} or
                not isinstance(primary["platform"], dict) or
                set(primary["platform"]) != {"os", "architecture"} or
                primary["platform"]["os"] != "linux" or
                primary["platform"]["architecture"] not in ("amd64", "arm64")):
            raise Refused("INVALID_IMAGE_ARCHIVE")
        primary_name = _oci_blob({key: primary[key] for key in
                                  ("mediaType", "digest", "size")},
                                 files, media_type=OCI_MANIFEST)
        referenced.add(primary_name)
        manifest = _oci_json(fd, primary_name, files, offsets, metadata)
        if (not isinstance(manifest, dict) or set(manifest) !=
                {"schemaVersion", "mediaType", "config", "layers"} or
                manifest["schemaVersion"] != 2 or
                manifest["mediaType"] != OCI_MANIFEST or
                not isinstance(manifest["layers"], list) or
                not 1 <= len(manifest["layers"]) <= MAX_IMAGE_FILES):
            raise Refused("INVALID_IMAGE_ARCHIVE")
        config_name = _oci_blob(manifest["config"], files, media_type=OCI_CONFIG)
        if source_rootfs is None and config_name != (
                "blobs/sha256/" + image_ids[service][7:]):
            raise Refused("IMAGE_ID_MISMATCH")
        referenced.add(config_name)
        config = _oci_json(fd, config_name, files, offsets, metadata)
        if (not isinstance(config, dict) or config.get("os") != "linux" or
                config.get("architecture") != primary["platform"]["architecture"] or
                not isinstance(config.get("rootfs"), dict) or
                config["rootfs"].get("type") != "layers" or
                not isinstance(config["rootfs"].get("diff_ids"), list) or
                len(config["rootfs"]["diff_ids"]) != len(manifest["layers"])):
            raise Refused("INVALID_IMAGE_ARCHIVE")
        if (source_rootfs is not None and
                _rootfs_digest(config["rootfs"]["diff_ids"]) !=
                source_rootfs.get(service)):
            raise Refused("ROOTFS_MISMATCH")
        if exported_configs is not None:
            exported_configs[service] = "sha256:" + config_name.rsplit("/", 1)[1]
        if platforms is not None:
            platforms[service] = {"os": "linux",
                                  "architecture": config["architecture"]}
        layer_names = []
        for descriptor, diff_id in zip(manifest["layers"], config["rootfs"]["diff_ids"]):
            name = _oci_blob(descriptor, files, media_type=OCI_GZIP_LAYER)
            if not _sha(diff_id) or _oci_diff_id(fd, name, files, offsets, expanded,
                                                 deadline=deadline) != diff_id[7:]:
                raise Refused("LAYER_DIGEST_MISMATCH")
            referenced.add(name)
            layer_names.append(name)
        matching = [item for item in docker_manifest if isinstance(item, dict) and
                    item.get("RepoTags") == ["sovagrid-" + service + ":local"]]
        if (len(matching) != 1 or set(matching[0]) !=
                {"Config", "RepoTags", "Layers"} or
                matching[0]["Config"] != config_name or
                matching[0]["Layers"] != layer_names):
            raise Refused("INVALID_IMAGE_ARCHIVE")
        if len(nested["manifests"]) == 2:
            att = nested["manifests"][1]
            if (not isinstance(att, dict) or set(att) !=
                    {"mediaType", "digest", "size", "platform", "annotations"} or
                    att["platform"] != {"os": "unknown", "architecture": "unknown"} or
                    att["annotations"] != {
                        "vnd.docker.reference.digest": primary["digest"],
                        "vnd.docker.reference.type": "attestation-manifest"}):
                raise Refused("INVALID_IMAGE_ARCHIVE")
            att_name = _oci_blob({key: att[key] for key in
                                  ("mediaType", "digest", "size")},
                                 files, media_type=OCI_MANIFEST)
            referenced.add(att_name)
            att_manifest = _oci_json(fd, att_name, files, offsets, metadata)
            if (not isinstance(att_manifest, dict) or set(att_manifest) !=
                    {"schemaVersion", "mediaType", "artifactType", "config",
                     "layers", "subject"} or
                    att_manifest["schemaVersion"] != 2 or
                    att_manifest["mediaType"] != OCI_MANIFEST or
                    att_manifest["artifactType"] !=
                    "application/vnd.docker.attestation.manifest.v1+json" or
                    att_manifest["subject"] != {key: primary[key] for key in
                                               ("mediaType", "digest", "size")} or
                    not isinstance(att_manifest["config"], dict) or
                    set(att_manifest["config"]) !=
                    {"mediaType", "digest", "size", "data"} or
                    att_manifest["config"]["mediaType"] !=
                    "application/vnd.oci.empty.v1+json" or
                    not isinstance(att_manifest["layers"], list) or
                    len(att_manifest["layers"]) != 1):
                raise Refused("INVALID_IMAGE_ARCHIVE")
            empty = att_manifest["config"]
            if (empty["data"] != "e30=" or empty["size"] != 2 or
                    empty["digest"] != "sha256:" + hashlib.sha256(b"{}").hexdigest()):
                raise Refused("INVALID_IMAGE_ARCHIVE")
            empty_name = "blobs/sha256/" + empty["digest"][7:]
            if empty_name in files:
                if files[empty_name][0] != 2:
                    raise Refused("INVALID_IMAGE_ARCHIVE")
                referenced.add(empty_name)
            att_layer = att_manifest["layers"][0]
            if (not isinstance(att_layer, dict) or set(att_layer) !=
                    {"mediaType", "digest", "size", "annotations"} or
                    att_layer["annotations"] != {
                        "in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"}):
                raise Refused("INVALID_IMAGE_ARCHIVE")
            att_layer_name = _oci_blob({key: att_layer[key] for key in
                                        ("mediaType", "digest", "size")},
                                       files, media_type="application/vnd.in-toto+json")
            referenced.add(att_layer_name)
            _oci_json(fd, att_layer_name, files, offsets, metadata,
                      limit=MAX_LEGACY_METADATA)
    if services != set(image_ids) or set(files) != referenced:
        raise Refused("INVALID_IMAGE_ARCHIVE")
    return len(seen)


def _inspect_image_tar(fd: int, image_ids: dict[str, str], *, deadline: float,
                       platforms: dict | None = None,
                       source_rootfs: dict | None = None,
                       exported_configs: dict | None = None) -> int:
    """Validate exact Docker-save members before any later docker-load design."""
    os.lseek(fd, 0, os.SEEK_SET)
    seen: set[str] = set()
    files: dict[str, tuple[int, str]] = {}
    capture_names = {identity[7:] + ".json" for identity in image_ids.values()}
    capture_names.update(("manifest.json", "repositories", "index.json", "oci-layout"))
    captured: dict[str, bytes] = {}
    offsets: dict[str, int] = {}
    total = 0
    captured_total = 0
    try:
        with os.fdopen(os.dup(fd), "rb") as stream:
            with tarfile.open(fileobj=stream, mode="r|") as archive:
                for member in archive:
                    if time.monotonic() > deadline:
                        raise Refused("TIME_LIMIT")
                    name, directory = _member_name(member)
                    if name in seen or len(seen) >= MAX_IMAGE_FILES:
                        raise Refused("INVALID_IMAGE_ARCHIVE")
                    seen.add(name)
                    if directory:
                        continue
                    total += member.size
                    if total > MAX_IMAGE_BYTES:
                        raise Refused("SIZE_LIMIT")
                    legacy_version = re.fullmatch(r"[0-9a-f]{64}/VERSION", name) is not None
                    legacy_json = re.fullmatch(r"[0-9a-f]{64}/json", name) is not None
                    maximum = (MAX_DOCKER_MANIFEST if name in ("manifest.json", "repositories",
                                                              "index.json") else
                               64 if name == "oci-layout" else
                               32 if legacy_version else MAX_CONFIG if name in capture_names else
                               MAX_LEGACY_METADATA if legacy_json else 0)
                    if maximum and member.size > maximum:
                        raise Refused("INVALID_IMAGE_ARCHIVE")
                    if name in capture_names or legacy_version or legacy_json:
                        captured_total += member.size
                        if captured_total > MAX_CAPTURED_METADATA:
                            raise Refused("INVALID_IMAGE_ARCHIVE")
                    reader = archive.extractfile(member)
                    if reader is None:
                        raise Refused("INVALID_IMAGE_ARCHIVE")
                    digest = hashlib.sha256()
                    capture = bytearray() if name in capture_names or legacy_version or legacy_json else None
                    remaining = member.size
                    while remaining:
                        if time.monotonic() > deadline:
                            raise Refused("TIME_LIMIT")
                        block = reader.read(min(1024 * 1024, remaining))
                        if not block:
                            raise Refused("INVALID_IMAGE_ARCHIVE")
                        digest.update(block)
                        if capture is not None:
                            capture.extend(block)
                        remaining -= len(block)
                    files[name] = (member.size, digest.hexdigest())
                    offsets[name] = member.offset_data
                    if capture is not None:
                        captured[name] = bytes(capture)
    except (tarfile.TarError, EOFError, OSError, ValueError, OverflowError) as exc:
        raise Refused("INVALID_IMAGE_ARCHIVE") from exc
    if "index.json" in files or "oci-layout" in files:
        return _inspect_oci_tar(fd, image_ids, files, offsets, seen, captured,
                                deadline=deadline, platforms=platforms,
                                source_rootfs=source_rootfs,
                                exported_configs=exported_configs)
    listing = _parse_json(captured.get("manifest.json", b""))
    if not isinstance(listing, list) or len(listing) != len(image_ids):
        raise Refused("INVALID_IMAGE_ARCHIVE")
    expected_configs = {identity[7:] + ".json" for identity in image_ids.values()}
    config_services = {identity[7:] + ".json": service
                       for service, identity in image_ids.items()}
    found_configs = set()
    referenced_layers: set[str] = set()
    repository_tags: dict[str, dict[str, str]] = {}
    for item in listing:
        if (not isinstance(item, dict) or set(item) != {"Config", "RepoTags", "Layers"} or
                not isinstance(item["Config"], str) or
                item["Config"] not in expected_configs or
                not isinstance(item["Layers"], list) or
                not 1 <= len(item["Layers"]) <= MAX_IMAGE_FILES or
                any(not isinstance(layer, str) for layer in item["Layers"]) or
                len(set(item["Layers"])) != len(item["Layers"]) or
                any(LAYER_PATH.fullmatch(layer) is None or layer not in files
                    for layer in item["Layers"]) or
                item["RepoTags"] !=
                ["sovagrid-" + config_services[item["Config"]] + ":local"]):
            raise Refused("INVALID_IMAGE_ARCHIVE")
        config_name = item["Config"]
        if config_name in found_configs or config_name not in captured:
            raise Refused("INVALID_IMAGE_ARCHIVE")
        found_configs.add(config_name)
        referenced_layers.update(item["Layers"])
        service = config_services[config_name]
        repository_tags["sovagrid-" + service] = {
            "local": item["Layers"][-1].split("/", 1)[0]}
        if files[config_name][1] != config_name[:-5]:
            raise Refused("IMAGE_ID_MISMATCH")
        config = _parse_json(captured[config_name])
        if (not isinstance(config, dict) or config.get("os") != "linux" or
                config.get("architecture") not in ("amd64", "arm64") or
                not isinstance(config.get("rootfs"), dict) or
                config["rootfs"].get("type") != "layers" or
                not isinstance(config["rootfs"].get("diff_ids"), list)):
            raise Refused("INVALID_IMAGE_ARCHIVE")
        if platforms is not None:
            platforms[service] = {"os": "linux",
                                  "architecture": config["architecture"]}
        differences = config["rootfs"]["diff_ids"]
        if (source_rootfs is not None and
                _rootfs_digest(differences) != source_rootfs.get(service)):
            raise Refused("ROOTFS_MISMATCH")
        if exported_configs is not None:
            exported_configs[service] = "sha256:" + config_name[:-5]
        if (len(differences) != len(item["Layers"]) or
                any(not _sha(difference) or
                    files[layer][1] != difference[7:]
                    for layer, difference in zip(item["Layers"], differences))):
            raise Refused("LAYER_DIGEST_MISMATCH")
    if found_configs != expected_configs:
        raise Refused("INVALID_IMAGE_ARCHIVE")
    # Docker's legacy layer metadata is allowed only beside a referenced
    # layer. Unreferenced files and repositories could affect a later load.
    layer_roots = {name.split("/", 1)[0] for name in referenced_layers}
    allowed_files = {"manifest.json", *expected_configs, *referenced_layers}
    for root in layer_roots:
        allowed_files.update((root + "/json", root + "/VERSION"))
    if "repositories" in files:
        repositories = _parse_json(captured["repositories"])
        if repositories != repository_tags:
            raise Refused("INVALID_IMAGE_ARCHIVE")
        allowed_files.add("repositories")
    if set(files) - allowed_files or any(name not in layer_roots for name in seen - set(files)):
        raise Refused("INVALID_IMAGE_ARCHIVE")
    for root in layer_roots:
        version = root + "/VERSION"
        if version in files and captured.get(version) != b"1.0\n":
            raise Refused("INVALID_IMAGE_ARCHIVE")
        metadata = root + "/json"
        if metadata in files and not isinstance(_parse_json(captured[metadata]), dict):
            raise Refused("INVALID_IMAGE_ARCHIVE")
    return len(seen)


def _read_exact(fd: int, limit: int) -> bytes:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= limit:
        raise Refused("UNSAFE_ARTIFACT")
    raw = bytearray()
    while len(raw) < info.st_size:
        block = os.read(fd, min(1024 * 1024, info.st_size - len(raw)))
        if not block:
            raise Refused("UNSAFE_ARTIFACT")
        raw.extend(block)
    if restore._fingerprint(os.fstat(fd)) != restore._fingerprint(info):
        raise Refused("ARTIFACT_CHANGED")
    return bytes(raw)


def _manifest(fd: int, identity: str) -> dict:
    info = os.fstat(fd)
    if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (
            backup.ROOT_UID, backup.ROOT_GID, 0o600):
        raise Refused("UNSAFE_ARTIFACT")
    try:
        value = _parse_json(_read_exact(fd, MAX_IMAGE_MANIFEST))
    except Refused as exc:
        if str(exc) == "INVALID_IMAGE_ARCHIVE":
            raise Refused("INVALID_MANIFEST") from exc
        raise
    services = set(backup.COMPOSE_SERVICES[:2])
    valid_services = (services, services | {"ssh-gateway"})
    if (not isinstance(value, dict) or set(value) != {
            "protocol", "id", "host_archive_sha256", "source_manifest_sha256",
            "layout", "created_at", "bytes", "sha256", "files", "images",
            "container_ids", "exported_configs", "rootfs_sha256"} or
            value["protocol"] != PROTOCOL or
            value["id"] != identity or value["layout"] not in ("full", "hub-only") or
            not isinstance(value["created_at"], str) or
            len(value["created_at"]) > 40 or
            not value["created_at"].endswith("+00:00") or
            type(value["bytes"]) is not int or not 0 < value["bytes"] <= MAX_IMAGE_BYTES or
            type(value["files"]) is not int or not 0 < value["files"] <= MAX_IMAGE_FILES or
            not isinstance(value["sha256"], str)):
        raise Refused("INVALID_MANIFEST")
    if (not isinstance(value["sha256"], str) or
            re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None or
            not isinstance(value["host_archive_sha256"], str) or
            re.fullmatch(r"[0-9a-f]{64}", value["host_archive_sha256"]) is None or
            not isinstance(value["source_manifest_sha256"], str) or
            re.fullmatch(r"[0-9a-f]{64}", value["source_manifest_sha256"]) is None or
            not isinstance(value["images"], dict) or
            set(value["images"]) not in valid_services or
            any(not _sha(item) for item in value["images"].values()) or
            len(set(value["images"].values())) != len(value["images"]) or
            not isinstance(value["container_ids"], dict) or
            set(value["container_ids"]) != set(value["images"]) or
            any(not isinstance(item, str) or CONTAINER_ID.fullmatch(item) is None
                for item in value["container_ids"].values()) or
            not isinstance(value["exported_configs"], dict) or
            set(value["exported_configs"]) != set(value["images"]) or
            any(not _sha(item) for item in value["exported_configs"].values()) or
            len(set(value["exported_configs"].values())) != len(value["images"]) or
            not isinstance(value["rootfs_sha256"], dict) or
            set(value["rootfs_sha256"]) != set(value["images"]) or
            any(not isinstance(item, str) or
                re.fullmatch(r"[0-9a-f]{64}", item) is None
                for item in value["rootfs_sha256"].values())):
        raise Refused("INVALID_MANIFEST")
    return value


def _artifact(identity: str) -> tuple[Path, int, int, dict]:
    folder, root_fd = _output(create=False)
    try:
        try:
            artifact_fd = os.open(identity, os.O_RDONLY | os.O_DIRECTORY |
                                  os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
        except FileNotFoundError as exc:
            raise Refused("NOT_FOUND") from exc
        try:
            info = os.fstat(artifact_fd)
            if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (
                    backup.ROOT_UID, backup.ROOT_GID, 0o700):
                raise Refused("UNSAFE_ARTIFACT")
            with os.scandir(artifact_fd) as entries:
                names = {entry.name for entry in entries}
                if names not in ({"images.tar", "manifest.json"},
                                 {"images.tar", "manifest.json", "receipt.json"}):
                    raise Refused("UNSAFE_ARTIFACT")
            manifest_fd = os.open("manifest.json", os.O_RDONLY | os.O_NOFOLLOW |
                                  os.O_CLOEXEC, dir_fd=artifact_fd)
            try:
                record = _manifest(manifest_fd, identity)
            finally:
                os.close(manifest_fd)
            tar_fd = os.open("images.tar", os.O_RDONLY | os.O_NOFOLLOW |
                             os.O_CLOEXEC, dir_fd=artifact_fd)
            info = os.fstat(tar_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (
                        backup.ROOT_UID, backup.ROOT_GID, 0o600) or
                    info.st_size != record["bytes"]):
                os.close(tar_fd)
                raise Refused("UNSAFE_ARTIFACT")
            return folder / identity, artifact_fd, tar_fd, record
        except BaseException:
            os.close(artifact_fd)
            raise
    finally:
        os.close(root_fd)


def _hash_tar(fd: int, record: dict, *, deadline: float) -> tuple:
    before = restore._fingerprint(os.fstat(fd))
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while True:
        if time.monotonic() > deadline:
            raise Refused("TIME_LIMIT")
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        total += len(block)
        if total > MAX_IMAGE_BYTES:
            raise Refused("SIZE_LIMIT")
        digest.update(block)
    if (total != record["bytes"] or digest.hexdigest() != record["sha256"] or
            restore._fingerprint(os.fstat(fd)) != before):
        raise Refused("ARTIFACT_CHANGED")
    return before


def _valid_portable_receipt(value: object, identity: str, record: dict) -> bool:
    if not isinstance(value, dict) or set(value) != {
            "protocol", "host_archive_id", "host_archive_sha256",
            "source_manifest_sha256", "images_sha256", "images",
            "container_ids", "exported_configs", "rootfs_sha256",
            "active_units", "unit_hashes"}:
        return False
    units = value["active_units"]
    hashes = value["unit_hashes"]
    allowed = backup.WRITERS[record["layout"]] | (
        backup.AMNEZIA_WRITERS if record["layout"] == "full" else frozenset())
    return (value["protocol"] == PORTABLE_RECEIPT and
            value["host_archive_id"] == identity and
            value["host_archive_sha256"] == record["host_archive_sha256"] and
            value["source_manifest_sha256"] == record["source_manifest_sha256"] and
            value["images_sha256"] == record["sha256"] and
            value["images"] == record["images"] and
            value["container_ids"] == record["container_ids"] and
            value["exported_configs"] == record["exported_configs"] and
            value["rootfs_sha256"] == record["rootfs_sha256"] and
            isinstance(units, list) and len(units) <= 32 and
            all(isinstance(unit, str) and unit in allowed for unit in units) and
            len(set(units)) == len(units) and
            isinstance(hashes, dict) and set(hashes) == set(units) and
            all(isinstance(digest, str) and
                re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                for digest in hashes.values()))


def _read_portable_receipt(directory_fd: int, identity: str,
                           record: dict, *, required: bool) -> dict | None:
    try:
        fd = os.open("receipt.json", os.O_RDONLY | os.O_NOFOLLOW |
                     os.O_CLOEXEC, dir_fd=directory_fd)
    except FileNotFoundError as exc:
        if required:
            raise Refused("RECEIPT_NOT_FOUND") from exc
        return None
    try:
        info = os.fstat(fd)
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (
                backup.ROOT_UID, backup.ROOT_GID, 0o600):
            raise Refused("UNSAFE_RECEIPT")
        try:
            value = _parse_json(_read_exact(fd, MAX_PORTABLE_RECEIPT))
        except Refused as exc:
            if str(exc) == "INVALID_IMAGE_ARCHIVE":
                raise Refused("INVALID_RECEIPT") from exc
            raise
        if not _valid_portable_receipt(value, identity, record):
            raise Refused("INVALID_RECEIPT")
        return value
    finally:
        os.close(fd)


def _publish_portable_receipt_locked(identity: str, receipt: dict) -> None:
    """Atomically add a root-only receipt to a just-created image artifact.

    The caller holds the host operation/update locks. A crash before rename
    leaves only an ignored temporary in the closed export root; a crash after
    rename cannot make the operation journal claim completion by itself.
    """
    backup._require_root()
    identity = _id(identity)
    folder, root_fd = _output(create=False)
    directory_fd = -1
    tar_fd = -1
    temp_name: str | None = None
    try:
        try:
            fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused("BUSY") from exc
        _folder, directory_fd, tar_fd, record = _artifact(identity)
        if not _valid_portable_receipt(receipt, identity, record):
            raise Refused("INVALID_RECEIPT")
        _hash_tar(tar_fd, record, deadline=time.monotonic() + MAX_IMAGE_SECONDS)
        if os.path.lexists(folder / identity / "receipt.json"):
            raise Refused("EXISTS")
        raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) +
               "\n").encode("ascii")
        if not 0 < len(raw) <= MAX_PORTABLE_RECEIPT:
            raise Refused("INVALID_RECEIPT")
        temp_name = "." + identity + ".receipt." + uuid.uuid4().hex + ".tmp"
        fd = _private_new(root_fd, temp_name)
        try:
            _write_all(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(temp_name, "receipt.json", src_dir_fd=root_fd,
                  dst_dir_fd=directory_fd)
        temp_name = None
        os.fsync(directory_fd)
        os.fsync(root_fd)
    finally:
        if temp_name is not None:
            os.unlink(temp_name, dir_fd=root_fd)
        if tar_fd >= 0:
            os.close(tar_fd)
        if directory_fd >= 0:
            os.close(directory_fd)
        os.close(root_fd)


def verify(identity: str, *, require_receipt: bool = False) -> dict:
    backup._require_root()
    identity = _id(identity)
    deadline = time.monotonic() + 2 * backup.MAX_SECONDS
    host_fd, host, _before = _verified_host(identity, deadline=deadline)
    os.close(host_fd)
    folder, directory_fd, tar_fd, record = _artifact(identity)
    try:
        if (record["host_archive_sha256"] != host["sha256"] or
                record["source_manifest_sha256"] != host["source_manifest_sha256"] or
                record["layout"] != host["layout"]):
            raise Refused("HOST_ARCHIVE_MISMATCH")
        deadline = time.monotonic() + MAX_IMAGE_SECONDS
        before = _hash_tar(tar_fd, record, deadline=deadline)
        platforms: dict[str, dict[str, str]] = {}
        exported_configs: dict[str, str] = {}
        count = _inspect_image_tar(tar_fd, record["images"], deadline=deadline,
                                   platforms=platforms,
                                   source_rootfs=record["rootfs_sha256"],
                                   exported_configs=exported_configs)
        if (count != record["files"] or
                exported_configs != record["exported_configs"] or
                restore._fingerprint(os.fstat(tar_fd)) != before):
            raise Refused("ARTIFACT_CHANGED")
        receipt = _read_portable_receipt(directory_fd, identity, record,
                                         required=require_receipt)
        result = {"ok": True, "protocol": PROTOCOL, "id": identity,
                  "verified": True, "image_count": len(record["images"]),
                  "bytes": record["bytes"], "apply_available": False}
        if require_receipt:
            result["receipt"] = receipt
            result["platforms"] = platforms
        return result
    finally:
        os.close(tar_fd)
        os.close(directory_fd)


def _create_locked(identity: str, *, expected_installed: dict | None = None) -> dict:
    """Create a paired artifact while the caller owns candidate/public locks."""
    backup._require_root()
    identity = _id(identity)
    deadline = time.monotonic() + 2 * backup.MAX_SECONDS
    host_fd, host, before = _verified_host(identity, deadline=deadline)
    try:
        if backup._layout() != host["layout"] or (
                backup._source_manifest() != host["source_manifest_sha256"]):
            raise Refused("SOURCE_CHANGED")
        installed = _installed_images(host["layout"])
        if expected_installed is not None and installed != expected_installed:
            raise Refused("IMAGE_CHANGED")
        folder, root_fd = _output(create=True)
        temporary: Path | None = None
        try:
            try:
                fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Refused("BUSY") from exc
            if os.path.lexists(folder / identity):
                raise Refused("EXISTS")
            if shutil.disk_usage(folder).free < MIN_FREE:
                raise Refused("DISK_SPACE")
            temp_name = "." + identity + "." + uuid.uuid4().hex + ".tmp"
            os.mkdir(temp_name, 0o700, dir_fd=root_fd)
            temporary = folder / temp_name
            temp_fd = os.open(temp_name, os.O_RDONLY | os.O_DIRECTORY |
                              os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
            try:
                info = os.fstat(temp_fd)
                if (info.st_uid, info.st_gid) != (backup.ROOT_UID, backup.ROOT_GID):
                    os.fchown(temp_fd, backup.ROOT_UID, backup.ROOT_GID)
                os.fchmod(temp_fd, 0o700)
                tar_fd = _private_new(temp_fd, "images.tar", read_write=True)
                try:
                    deadline = time.monotonic() + MAX_IMAGE_SECONDS
                    refs = ["sovagrid-" + service + ":local" for service in installed]
                    size, digest = _save_images(refs, tar_fd, folder,
                                                deadline=deadline)
                    tar_info = os.fstat(tar_fd)
                    if tar_info.st_size != size:
                        raise Refused("ARTIFACT_CHANGED")
                    tar_before = _hash_tar(tar_fd, {"bytes": size, "sha256": digest},
                                           deadline=deadline)
                    exported_configs: dict[str, str] = {}
                    count = _inspect_image_tar(tar_fd, {
                        service: value["image_id"] for service, value in installed.items()},
                        deadline=deadline,
                        source_rootfs={service: value["rootfs_sha256"]
                                       for service, value in installed.items()},
                        exported_configs=exported_configs)
                    if restore._fingerprint(os.fstat(tar_fd)) != tar_before:
                        raise Refused("ARTIFACT_CHANGED")
                finally:
                    os.close(tar_fd)
                if (installed != _installed_images(host["layout"]) or
                        backup._layout() != host["layout"] or
                        backup._source_manifest() != host["source_manifest_sha256"]):
                    raise Refused("IMAGE_CHANGED")
                restore._hash_archive(host_fd, host, deadline=time.monotonic() +
                                      2 * backup.MAX_SECONDS)
                if restore._fingerprint(os.fstat(host_fd)) != before:
                    raise Refused("HOST_ARCHIVE_CHANGED")
                record = {"protocol": PROTOCOL, "id": identity,
                          "host_archive_sha256": host["sha256"],
                          "source_manifest_sha256": host["source_manifest_sha256"],
                          "layout": host["layout"],
                          "created_at": datetime.now(timezone.utc).isoformat(),
                          "bytes": size, "sha256": digest, "files": count,
                          "images": {service: value["image_id"]
                                     for service, value in installed.items()},
                          "container_ids": {service: value["container_id"]
                                            for service, value in installed.items()},
                          "exported_configs": exported_configs,
                          "rootfs_sha256": {service: value["rootfs_sha256"]
                                            for service, value in installed.items()}}
                raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) +
                       "\n").encode()
                if len(raw) > MAX_IMAGE_MANIFEST:
                    raise Refused("INVALID_MANIFEST")
                manifest_fd = _private_new(temp_fd, "manifest.json")
                try:
                    _write_all(manifest_fd, raw)
                    os.fsync(manifest_fd)
                finally:
                    os.close(manifest_fd)
                os.fsync(temp_fd)
            finally:
                os.close(temp_fd)
            if os.path.lexists(folder / identity):
                raise Refused("EXISTS")
            os.rename(temp_name, identity, src_dir_fd=root_fd, dst_dir_fd=root_fd)
            temporary = None
            os.fsync(root_fd)
            return record
        finally:
            if temporary is not None:
                shutil.rmtree(temporary)
            os.close(root_fd)
    finally:
        os.close(host_fd)


def create(identity: str) -> dict:
    backup._require_root()
    identity = _id(identity)
    with backup._locks():
        record = _create_locked(identity)
    return {"ok": True, "protocol": PROTOCOL, "id": identity,
            "image_count": len(record["images"]), "bytes": record["bytes"],
            "apply_available": False}

def main(argv: list[str]) -> int:
    try:
        if len(argv) != 2 or argv[0] not in ("create", "verify", "verify-portable"):
            raise Refused("USAGE")
        result = (create(argv[1]) if argv[0] == "create" else
                  verify(argv[1], require_receipt=argv[0] == "verify-portable"))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (Refused, restore.Refused, backup.Refused, OSError, ValueError,
            TypeError) as exc:
        code = str(exc) if isinstance(exc, (Refused, restore.Refused,
                                            backup.Refused)) else "IO_ERROR"
        print(json.dumps({"ok": False, "protocol": PROTOCOL, "error": code},
                         separators=(",", ":")))
        return 40


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
