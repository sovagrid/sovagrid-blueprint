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
OUTPUT = Path("/var/lib/sovagrid-host-image-exports")
# Pin the local daemon. A caller's Docker context must not redirect an export
# to a remote host with identically named Compose services.
DOCKER = ("/usr/bin/docker", "--host", "unix:///run/docker.sock")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
SHORT_ID = re.compile(r"[0-9a-f]{12,64}\Z")
LAYER_PATH = re.compile(r"[0-9a-f]{64}/layer\.tar\Z")
MAX_IMAGE_BYTES = 8 * 1024**3
MAX_IMAGE_FILES = 20_000
MAX_IMAGE_SECONDS = 1200
MAX_IMAGE_MANIFEST = 4096
MAX_DOCKER_MANIFEST = 256 * 1024
MAX_CONFIG = 16 * 1024**2
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


def _capture(args: list[str]) -> str:
    try:
        result = subprocess.run([*DOCKER, *args], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused("DOCKER_UNAVAILABLE") from exc
    if result.returncode or len(result.stdout) > 4096:
        raise Refused("DOCKER_UNAVAILABLE")
    return result.stdout.strip()


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
        result[service] = {"container_id": container_id, "image_id": tag_image}
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


def _save_images(ids: list[str], fd: int, destination: Path, *, deadline: float) -> tuple[int, str]:
    """Stream Docker stdout with time, byte and free-space limits."""
    try:
        process = subprocess.Popen([*DOCKER, "image", "save", *ids],
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


def _inspect_image_tar(fd: int, image_ids: dict[str, str], *, deadline: float) -> int:
    """Validate Docker save manifest, image config digests and layer diff IDs."""
    os.lseek(fd, 0, os.SEEK_SET)
    seen: set[str] = set()
    files: dict[str, tuple[int, str]] = {}
    capture_names = {identity[7:] + ".json" for identity in image_ids.values()}
    capture_names.add("manifest.json")
    captured: dict[str, bytes] = {}
    total = 0
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
                    maximum = (MAX_DOCKER_MANIFEST if name == "manifest.json" else
                               MAX_CONFIG if name in capture_names else 0)
                    if maximum and member.size > maximum:
                        raise Refused("INVALID_IMAGE_ARCHIVE")
                    reader = archive.extractfile(member)
                    if reader is None:
                        raise Refused("INVALID_IMAGE_ARCHIVE")
                    digest = hashlib.sha256()
                    capture = bytearray() if name in capture_names else None
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
                    if capture is not None:
                        captured[name] = bytes(capture)
    except (tarfile.TarError, EOFError, OSError, ValueError, OverflowError) as exc:
        raise Refused("INVALID_IMAGE_ARCHIVE") from exc
    listing = _parse_json(captured.get("manifest.json", b""))
    if not isinstance(listing, list) or len(listing) != len(image_ids):
        raise Refused("INVALID_IMAGE_ARCHIVE")
    expected_configs = {identity[7:] + ".json" for identity in image_ids.values()}
    found_configs = set()
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
                (item["RepoTags"] is not None and
                 (not isinstance(item["RepoTags"], list) or
                  any(not isinstance(tag, str) or len(tag) > 256
                      for tag in item["RepoTags"])))):
            raise Refused("INVALID_IMAGE_ARCHIVE")
        config_name = item["Config"]
        if config_name in found_configs or config_name not in captured:
            raise Refused("INVALID_IMAGE_ARCHIVE")
        found_configs.add(config_name)
        if files[config_name][1] != config_name[:-5]:
            raise Refused("IMAGE_ID_MISMATCH")
        config = _parse_json(captured[config_name])
        if (not isinstance(config, dict) or not isinstance(config.get("rootfs"), dict) or
                config["rootfs"].get("type") != "layers" or
                not isinstance(config["rootfs"].get("diff_ids"), list)):
            raise Refused("INVALID_IMAGE_ARCHIVE")
        differences = config["rootfs"]["diff_ids"]
        if (len(differences) != len(item["Layers"]) or
                any(not _sha(difference) or
                    files[layer][1] != difference[7:]
                    for layer, difference in zip(item["Layers"], differences))):
            raise Refused("LAYER_DIGEST_MISMATCH")
    if found_configs != expected_configs:
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
            "container_ids"} or value["protocol"] != PROTOCOL or
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
                for item in value["container_ids"].values())):
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
                if {entry.name for entry in entries} != {"images.tar", "manifest.json"}:
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


def verify(identity: str) -> dict:
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
        count = _inspect_image_tar(tar_fd, record["images"], deadline=deadline)
        if count != record["files"] or restore._fingerprint(os.fstat(tar_fd)) != before:
            raise Refused("ARTIFACT_CHANGED")
        return {"ok": True, "protocol": PROTOCOL, "id": identity,
                "verified": True, "image_count": len(record["images"]),
                "bytes": record["bytes"], "apply_available": False}
    finally:
        os.close(tar_fd)
        os.close(directory_fd)


def create(identity: str) -> dict:
    backup._require_root()
    identity = _id(identity)
    with backup._locks():
        deadline = time.monotonic() + 2 * backup.MAX_SECONDS
        host_fd, host, before = _verified_host(identity, deadline=deadline)
        try:
            if backup._layout() != host["layout"] or (
                    backup._source_manifest() != host["source_manifest_sha256"]):
                raise Refused("SOURCE_CHANGED")
            installed = _installed_images(host["layout"])
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
                        ids = [value["image_id"] for value in installed.values()]
                        size, digest = _save_images(ids, tar_fd, folder,
                                                    deadline=deadline)
                        tar_info = os.fstat(tar_fd)
                        if tar_info.st_size != size:
                            raise Refused("ARTIFACT_CHANGED")
                        tar_before = _hash_tar(tar_fd, {"bytes": size, "sha256": digest},
                                               deadline=deadline)
                        count = _inspect_image_tar(tar_fd, {
                            service: value["image_id"] for service, value in installed.items()},
                            deadline=deadline)
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
                return {"ok": True, "protocol": PROTOCOL, "id": identity,
                        "image_count": len(installed), "bytes": size,
                        "apply_available": False}
            finally:
                if temporary is not None:
                    shutil.rmtree(temporary)
                os.close(root_fd)
        finally:
            os.close(host_fd)


def main(argv: list[str]) -> int:
    try:
        if len(argv) != 2 or argv[0] not in ("create", "verify"):
            raise Refused("USAGE")
        result = create(argv[1]) if argv[0] == "create" else verify(argv[1])
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
