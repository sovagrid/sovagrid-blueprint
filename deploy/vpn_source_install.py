#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Prepare the verified VPN source on an Agent-only Ubuntu target.

This helper is executed from an already pinned, verified Connect bundle. It
copies source code only; it never invokes Docker, systemd, or a VPN installer.
The two trees required by the VPN installers are replaced with a durable
rollback journal, so an interrupted copy cannot silently adopt foreign files.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import uuid


PROTOCOL = 1
MAX_RPC = 32768
MAX_FILE = 32 * 1024 * 1024
MAX_FILES = 4096
MAX_TOTAL = 256 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")
STAGE = re.compile(r"/opt/\.sovagrid-vpn-source-[0-9a-f]{32}\Z")
BYTECODE = re.compile(r"(?:[A-Za-z0-9_.-]+/)*__pycache__/[A-Za-z0-9_.-]+\.cpython-[0-9]+\.pyc\Z")
SOURCE_DEST = "/opt/sovagrid-src/sovagrid-vpn"
PACKAGE_DEST = "/opt/sovagrid-vpn/sovagrid_vpn"
STATE_DIR = "/var/lib/sovagrid/vpn-source"
STATE_FILE = STATE_DIR + "/state.json"
LOCK_FILE = STATE_DIR + "/.lock"
ZERO_SHA = "0" * 64


class Refuse(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def need(condition: bool, code: str = "SOURCE_UNTRUSTED") -> None:
    if not condition:
        raise Refuse(code)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "STATE_CONFLICT")
        result[key] = value
    return result


def valid_hashes(value: object) -> dict[str, str]:
    need(type(value) is dict and 1 <= len(value) <= MAX_FILES, "STATE_CONFLICT")
    for name, expected in value.items():
        need(type(name) is str and 1 <= len(name) <= 255 and
             all(part not in ("", ".", "..") and NAME.fullmatch(part)
                 for part in name.split("/")) and
             type(expected) is str and SHA.fullmatch(expected) is not None,
             "STATE_CONFLICT")
    return value


class Installer:
    """Fixed-path target transaction; root/owner injection is for isolated tests."""

    def __init__(self, *, root: Path = Path("/"), owner: int = 0):
        self.root = Path(root)
        self.owner = owner
        need(self.root.is_absolute() and ".." not in self.root.parts, "INVALID_REQUEST")

    def at(self, absolute: str) -> Path:
        need(absolute.startswith("/") and ".." not in Path(absolute).parts,
             "INVALID_REQUEST")
        return self.root / absolute.lstrip("/")

    def _inspect(self, absolute: str, *, directory: bool = False,
                 absent: bool = False, private: bool = False):
        path = self.at(absolute)
        current = self.root
        for part in path.relative_to(self.root).parts:
            current /= part
            try:
                info = current.lstat()
            except FileNotFoundError:
                if absent:
                    return None
                raise Refuse("STATE_CONFLICT") from None
            need(info.st_uid == self.owner and not stat.S_ISLNK(info.st_mode) and
                 not info.st_mode & 0o022, "OWNERSHIP_CONFLICT")
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) if directory else
             stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
             "OWNERSHIP_CONFLICT")
        if private:
            need(stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600),
                 "OWNERSHIP_CONFLICT")
        return info

    def _read(self, absolute: str, *, limit: int = MAX_FILE,
              private: bool = False) -> bytes:
        before = self._inspect(absolute, private=private)
        need(before.st_size <= limit, "STATE_CONFLICT")
        fd = os.open(self.at(absolute), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            current = os.fstat(fd)
            need((before.st_dev, before.st_ino) == (current.st_dev, current.st_ino),
                 "STATE_CONFLICT")
            raw = os.read(fd, limit + 1)
            need(len(raw) == before.st_size, "STATE_CONFLICT")
            return raw
        finally:
            os.close(fd)

    def _mkdir(self, absolute: str, mode: int) -> None:
        parent = str(Path(absolute).parent)
        if self._inspect(parent, directory=True, absent=True) is None:
            self._mkdir(parent, 0o700 if parent.startswith("/var/lib/sovagrid") else 0o755)
        if self._inspect(absolute, directory=True, absent=True) is None:
            path = self.at(absolute)
            path.mkdir(mode=mode)
            os.chmod(path, mode)
            self._fsync_dir(parent)
        info = self._inspect(absolute, directory=True)
        need(stat.S_IMODE(info.st_mode) == mode, "OWNERSHIP_CONFLICT")

    def _fsync_dir(self, absolute: str) -> None:
        fd = os.open(self.at(absolute), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _write(self, absolute: str, raw: bytes, mode: int = 0o600) -> None:
        parent = str(Path(absolute).parent)
        self._inspect(parent, directory=True)
        old = self._inspect(absolute, absent=True)
        if old is not None:
            need(old.st_nlink == 1, "OWNERSHIP_CONFLICT")
        temporary = self.at(parent) / (".sg-vpn-" + uuid.uuid4().hex)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), mode)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.at(absolute))
            self._fsync_dir(parent)
        finally:
            if os.path.lexists(temporary):
                temporary.unlink()

    def _tree(self, absolute: str) -> dict[str, str]:
        self._inspect(absolute, directory=True)
        base = self.at(absolute)
        hashes = {}
        total = 0
        visited = 0
        for parent, dirs, files in os.walk(base, followlinks=False):
            for name in dirs:
                relative = (Path(parent) / name).relative_to(self.root).as_posix()
                self._inspect("/" + relative, directory=True)
            for name in files:
                relative = (Path(parent) / name).relative_to(base).as_posix()
                visited += 1
                need(visited <= MAX_FILES and all(NAME.fullmatch(part) for part in relative.split("/")),
                     "STATE_CONFLICT")
                raw = self._read(absolute + "/" + relative)
                total += len(raw)
                need(total <= MAX_TOTAL, "STATE_CONFLICT")
                if BYTECODE.fullmatch(relative):
                    continue  # Python's own cache is neither source nor a managed file.
                hashes[relative] = digest(raw)
        return hashes

    @staticmethod
    def _validate_state(value: object) -> dict:
        need(type(value) is dict and value.get("protocol") == PROTOCOL and
             value.get("phase") in ("active", "pending"), "STATE_CONFLICT")
        if value["phase"] == "active":
            need(set(value) == {"protocol", "phase", "source_manifest_sha256",
                                "source_files", "package_files", "garbage_stage"}, "STATE_CONFLICT")
            need(type(value["source_manifest_sha256"]) is str and
                 SHA.fullmatch(value["source_manifest_sha256"]), "STATE_CONFLICT")
            valid_hashes(value["source_files"]); valid_hashes(value["package_files"])
            need(value["garbage_stage"] is None or
                 type(value["garbage_stage"]) is str and STAGE.fullmatch(value["garbage_stage"]),
                 "STATE_CONFLICT")
        else:
            need(set(value) == {"protocol", "phase", "source_manifest_sha256", "source_files",
                                "package_files", "previous", "stage"}, "STATE_CONFLICT")
            need(type(value["source_manifest_sha256"]) is str and
                 SHA.fullmatch(value["source_manifest_sha256"]), "STATE_CONFLICT")
            valid_hashes(value["source_files"]); valid_hashes(value["package_files"])
            need(type(value["stage"]) is str and STAGE.fullmatch(value["stage"]), "STATE_CONFLICT")
            if value["previous"] is not None:
                need(type(value["previous"]) is dict and value["previous"].get("phase") == "active",
                     "STATE_CONFLICT")
                Installer._validate_state(value["previous"])
        return value

    def _state(self) -> tuple[dict | None, str]:
        if self._inspect(STATE_DIR, directory=True, absent=True) is not None:
            self._inspect(STATE_DIR, directory=True, private=True)
            need({entry.name for entry in self.at(STATE_DIR).iterdir()} <=
                 {".lock", "state.json"}, "OWNERSHIP_CONFLICT")
            if os.path.lexists(self.at(LOCK_FILE)):
                self._inspect(LOCK_FILE, private=True)
        if self._inspect(STATE_FILE, absent=True) is None:
            return None, ZERO_SHA
        raw = self._read(STATE_FILE, limit=512 * 1024, private=True)
        try:
            value = json.loads(raw, object_pairs_hook=unique_object)
            self._validate_state(value)
            need(canonical(value) == raw, "STATE_CONFLICT")
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise Refuse("STATE_CONFLICT") from None
        return value, digest(raw)

    def _save_state(self, value: dict) -> None:
        self._validate_state(value)
        self._write(STATE_FILE, canonical(value))

    @staticmethod
    def project(source_root: Path, manifest: dict) -> tuple[dict[str, bytes], dict[str, bytes]]:
        hashes = manifest["sha256"]
        component = {key[len("sovagrid-vpn/"):]: expected for key, expected in hashes.items()
                     if key.startswith("sovagrid-vpn/")}
        valid_hashes(component)
        required = {"deploy/install-amnezia-control.py", "deploy/sovagrid-amnezia-ctl",
                    "deploy/sovagrid-amnezia-broker", "deploy/sovagrid-amnezia-control.service",
                    "deploy/sovagrid-amnezia-control.socket", "sovagrid_vpn/amnezia_install.py",
                    "sovagrid_vpn/amnezia_admin.py"}
        required.update({"deploy/sovagrid-amnezia-provision",
                         "sovagrid_vpn/amnezia_provision.py"})
        need(required <= set(component), "SOURCE_UNTRUSTED")
        source = {}
        package = {}
        total = 0
        for relative, expected in component.items():
            path = source_root / "sovagrid-vpn" / relative
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                 not info.st_mode & 0o022 and info.st_size <= MAX_FILE, "SOURCE_UNTRUSTED")
            raw = path.read_bytes()
            total += len(raw)
            need(total <= MAX_TOTAL and digest(raw) == expected, "SOURCE_CHANGED")
            source[relative] = raw
            if (relative.startswith("sovagrid_vpn/") and relative.endswith(".py") and
                    relative.count("/") == 1):
                package[relative.split("/", 1)[1]] = raw
        need(package and len(package) == sum(name.startswith("sovagrid_vpn/") and
             name.endswith(".py") and name.count("/") == 1 for name in component),
             "SOURCE_UNTRUSTED")
        return source, package

    @staticmethod
    def _hashmap(files: dict[str, bytes]) -> dict[str, str]:
        return {name: digest(raw) for name, raw in files.items()}

    def _active_files(self, state: dict | None) -> str:
        for destination, key in ((SOURCE_DEST, "source_files"), (PACKAGE_DEST, "package_files")):
            info = self._inspect(destination, directory=True, absent=True)
            if state is None:
                need(info is None, "OWNERSHIP_CONFLICT")
            else:
                need(info is not None and self._tree(destination) == state[key], "STATE_CONFLICT")
        return digest(canonical({"source": state["source_files"],
                                 "package": state["package_files"]})) if state else ZERO_SHA

    def preview(self, source_manifest_sha256: str,
                source: dict[str, bytes], package: dict[str, bytes]) -> dict:
        need(type(source_manifest_sha256) is str and SHA.fullmatch(source_manifest_sha256),
             "INVALID_REQUEST")
        state, state_sha = self._state()
        need(state is None or state["phase"] == "active", "RECOVERY_REQUIRED")
        installed_sha = self._active_files(state)
        source_files, package_files = self._hashmap(source), self._hashmap(package)
        valid_hashes(source_files); valid_hashes(package_files)
        candidate_sha = digest(canonical({"source": source_files, "package": package_files}))
        change = "install" if state is None else "current" if installed_sha == candidate_sha else "update"
        # The package may be in use by an armed broker; source-only updates do
        # not attempt to restart it or claim compatibility across versions.
        if change == "update":
            for marker in ("/etc/sovagrid-vpn/amnezia-control.enabled",
                           "/etc/sovagrid-vpn/amnezia-wireguard-control.enabled",
                           "/etc/sovagrid-vpn/amnezia-awg-settings.enabled",
                           "/etc/systemd/system/sovagrid-amnezia-control.service",
                           "/etc/systemd/system/sovagrid-vpn-control.service"):
                need(not os.path.lexists(self.at(marker)), "CONTROL_ACTIVE")
        expected = {"source_manifest_sha256": source_manifest_sha256,
                    "installed_sha256": installed_sha, "state_sha256": state_sha,
                    "candidate_sha256": candidate_sha}
        return {"protocol": PROTOCOL, "change": change,
                "source_manifest_sha256": source_manifest_sha256,
                "candidate_sha256": candidate_sha, "installed_sha256": installed_sha,
                "state_sha256": state_sha,
                "cleanup_required": bool(state and state["garbage_stage"]),
                "expected": expected}

    @contextmanager
    def _lock(self):
        self._mkdir(STATE_DIR, 0o700)
        path = self.at(LOCK_FILE)
        if not os.path.lexists(path):
            try:
                fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.fchmod(fd, 0o600)
                os.close(fd)
                self._fsync_dir(STATE_DIR)
            except FileExistsError:
                pass
        self._inspect(LOCK_FILE, private=True)
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except BlockingIOError:
            raise Refuse("BUSY") from None
        finally:
            os.close(fd)

    def _write_tree(self, absolute: str, files: dict[str, bytes]) -> None:
        self._mkdir(absolute, 0o755)
        for relative, raw in sorted(files.items()):
            parts = relative.split("/")
            for depth in range(1, len(parts)):
                self._mkdir(absolute + "/" + "/".join(parts[:depth]), 0o755)
            self._write(absolute + "/" + relative, raw, mode=0o644)

    def _rename(self, old: str, new: str) -> None:
        need(not os.path.lexists(self.at(new)), "STATE_CONFLICT")
        os.rename(self.at(old), self.at(new))
        self._fsync_dir(str(Path(old).parent))
        if Path(old).parent != Path(new).parent:
            self._fsync_dir(str(Path(new).parent))

    def _remove_stage(self, stage: str) -> None:
        need(STAGE.fullmatch(stage) is not None, "STATE_CONFLICT")
        if self._inspect(stage, directory=True, absent=True) is None:
            return
        # rmtree is fd-based on supported Linux; inspect first to refuse
        # replaced symlinks or untrusted files rather than deleting them.
        need(shutil.rmtree.avoids_symlink_attacks, "STATE_CONFLICT")
        for parent, dirs, files in os.walk(self.at(stage), followlinks=False):
            self._inspect("/" + Path(parent).relative_to(self.root).as_posix(), directory=True)
            for name in dirs:
                self._inspect("/" + (Path(parent) / name).relative_to(self.root).as_posix(), directory=True)
            for name in files:
                self._inspect("/" + (Path(parent) / name).relative_to(self.root).as_posix())
        shutil.rmtree(self.at(stage))
        self._fsync_dir("/opt")

    def _rollback(self, pending: dict) -> None:
        need(pending["phase"] == "pending", "STATE_CONFLICT")
        stage = pending["stage"]
        previous = pending["previous"]
        for destination, key, old_name, discard in (
                (SOURCE_DEST, "source_files", "old_source", "discard_source"),
                (PACKAGE_DEST, "package_files", "old_package", "discard_package")):
            old = stage + "/" + old_name
            discarded = stage + "/" + discard
            current = self._inspect(destination, directory=True, absent=True)
            backup = self._inspect(old, directory=True, absent=True) if self._inspect(
                stage, directory=True, absent=True) is not None else None
            if current is not None:
                actual = self._tree(destination)
                if actual == pending[key]:
                    need(self._inspect(discarded, directory=True, absent=True) is None,
                         "STATE_CONFLICT")
                    self._rename(destination, discarded)
                else:
                    need(previous is not None and backup is None and
                         actual == previous[key], "STATE_CONFLICT")
            if backup is not None:
                need(previous is not None and self._tree(old) == previous[key] and
                     self._inspect(destination, directory=True, absent=True) is None,
                     "STATE_CONFLICT")
                self._rename(old, destination)
            elif previous is None:
                need(self._inspect(destination, directory=True, absent=True) is None,
                     "STATE_CONFLICT")
        if previous is not None:
            self._active_files(previous)
            old = {**previous, "garbage_stage": stage}
            self._save_state(old)
        self._remove_stage(stage)
        if previous is None:
            self._inspect(STATE_FILE)
            self.at(STATE_FILE).unlink()
            self._fsync_dir(STATE_DIR)
        else:
            self._save_state({**previous, "garbage_stage": None})

    def recover(self) -> dict:
        with self._lock():
            state, _ = self._state()
            if state is None:
                return {"protocol": PROTOCOL, "recovered": False}
            if state["phase"] == "pending":
                self._rollback(state)
                return {"protocol": PROTOCOL, "recovered": True}
            if state["garbage_stage"]:
                self._active_files(state)
                self._remove_stage(state["garbage_stage"])
                self._save_state({**state, "garbage_stage": None})
                return {"protocol": PROTOCOL, "recovered": True}
            self._active_files(state)
            return {"protocol": PROTOCOL, "recovered": False}

    def apply(self, source_manifest_sha256: str, source: dict[str, bytes],
              package: dict[str, bytes], expected: dict) -> dict:
        need(type(expected) is dict and set(expected) == {"source_manifest_sha256",
             "installed_sha256", "state_sha256", "candidate_sha256"} and
             all(type(value) is str and SHA.fullmatch(value) for value in expected.values()),
             "INVALID_REQUEST")
        with self._lock():
            preview = self.preview(source_manifest_sha256, source, package)
            need(preview["expected"] == expected, "STALE_PREVIEW")
            if preview["cleanup_required"]:
                state, _ = self._state()
                need(state is not None and state["phase"] == "active", "STATE_CONFLICT")
                self._remove_stage(state["garbage_stage"])
                self._save_state({**state, "garbage_stage": None})
            if preview["change"] == "current":
                return {"protocol": PROTOCOL, "installed": True, "changed": False,
                        "source_manifest_sha256": source_manifest_sha256,
                        "candidate_sha256": preview["candidate_sha256"],
                        "cleanup_required": False}
            previous, _ = self._state()
            stage = "/opt/.sovagrid-vpn-source-" + uuid.uuid4().hex
            pending = {"protocol": PROTOCOL, "phase": "pending", "stage": stage,
                       "source_manifest_sha256": source_manifest_sha256,
                       "source_files": self._hashmap(source),
                       "package_files": self._hashmap(package), "previous": previous}
            self._save_state(pending)
            try:
                self._mkdir(stage, 0o700)
                self._write_tree(stage + "/new_source", source)
                self._write_tree(stage + "/new_package", package)
                need(self._tree(stage + "/new_source") == pending["source_files"] and
                     self._tree(stage + "/new_package") == pending["package_files"],
                     "SOURCE_CHANGED")
                self._mkdir("/opt/sovagrid-src", 0o755)
                self._mkdir("/opt/sovagrid-vpn", 0o755)
                if previous is not None:
                    self._rename(SOURCE_DEST, stage + "/old_source")
                self._rename(stage + "/new_source", SOURCE_DEST)
                if previous is not None:
                    self._rename(PACKAGE_DEST, stage + "/old_package")
                self._rename(stage + "/new_package", PACKAGE_DEST)
                need(self._tree(SOURCE_DEST) == pending["source_files"] and
                     self._tree(PACKAGE_DEST) == pending["package_files"],
                     "STATE_CONFLICT")
                active = {"protocol": PROTOCOL, "phase": "active",
                          "source_manifest_sha256": source_manifest_sha256,
                          "source_files": pending["source_files"],
                          "package_files": pending["package_files"],
                          "garbage_stage": stage}
                self._save_state(active)
            except BaseException:
                try:
                    self._rollback(pending)
                except Exception:
                    raise Refuse("RECOVERY_REQUIRED") from None
                raise
            try:
                self._remove_stage(stage)
                self._save_state({**active, "garbage_stage": None})
            except Exception:
                return {"protocol": PROTOCOL, "installed": True, "changed": True,
                        "source_manifest_sha256": source_manifest_sha256,
                        "candidate_sha256": preview["candidate_sha256"],
                        "cleanup_required": True}
            return {"protocol": PROTOCOL, "installed": True, "changed": True,
                    "source_manifest_sha256": source_manifest_sha256,
                    "candidate_sha256": preview["candidate_sha256"],
                    "cleanup_required": False}


def _staged_source() -> tuple[Path, str, dict[str, bytes], dict[str, bytes]]:
    source_root = Path(__file__).resolve().parents[2]
    need(re.fullmatch(r"/var/tmp/sovagrid-agent-enroll\.[A-Za-z0-9_-]{8,32}/source",
                      str(source_root)) is not None, "SOURCE_UNTRUSTED")
    helper = source_root / "sovagrid-blueprint/deploy/remote_agent.py"
    spec = importlib.util.spec_from_file_location("sovagrid_remote_agent_source", helper)
    need(spec is not None and spec.loader is not None, "SOURCE_UNTRUSTED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source_sha, manifest = module.Source(module.Files(), str(source_root)).verify()
    source, package = Installer.project(source_root, manifest)
    return source_root, source_sha, source, package


def main() -> int:
    os.umask(0o077)
    try:
        need(os.geteuid() == 0, "ROOT_REQUIRED")
        raw = sys.stdin.buffer.read(MAX_RPC + 1)
        need(len(raw) <= MAX_RPC, "INVALID_REQUEST")
        request = json.loads(raw, object_pairs_hook=unique_object)
        need(type(request) is dict and request.get("protocol") == PROTOCOL and
             request.get("action") in ("preview", "apply", "recover"), "INVALID_REQUEST")
        expected_fields = {"protocol", "action", "source_manifest_sha256"}
        if request["action"] == "apply":
            expected_fields.add("expected")
        need(set(request) == expected_fields and
             type(request["source_manifest_sha256"]) is str and
             SHA.fullmatch(request["source_manifest_sha256"]), "INVALID_REQUEST")
        _root, source_sha, source, package = _staged_source()
        need(source_sha == request["source_manifest_sha256"], "SOURCE_CHANGED")
        installer = Installer()
        if request["action"] == "preview":
            result = installer.preview(source_sha, source, package)
        elif request["action"] == "apply":
            result = installer.apply(source_sha, source, package, request["expected"])
        else:
            result = installer.recover()
        response = {"protocol": PROTOCOL, "ok": True, "result": result}
        need(len(canonical(response)) <= MAX_RPC, "INTERNAL_ERROR")
        sys.stdout.buffer.write(canonical(response) + b"\n")
        return 0
    except Refuse as error:
        response = {"protocol": PROTOCOL, "ok": False, "error": error.code}
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        response = {"protocol": PROTOCOL, "ok": False, "error": "OPERATION_FAILED"}
    except Exception:
        response = {"protocol": PROTOCOL, "ok": False, "error": "OPERATION_FAILED"}
    sys.stdout.buffer.write(canonical(response) + b"\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
