#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Reviewed local removal of an enrolled Agent. Run over a verified root SSH route."""
from __future__ import annotations

import base64
import binascii
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import types
import uuid


JOURNAL = "/var/lib/sovagrid-agent-enrollment"
STATE = JOURNAL + "/state.json"
INSTALLER = "/opt/sovagrid-agent-installer"
HELPER = INSTALLER + "/remote_agent.py"
MANIFEST = INSTALLER + "/source-manifest.json"
SOURCE_ENTRY = "sovagrid-blueprint/deploy/remote_agent.py"
OWNER_ACCOUNTS = {"sovagrid", "sovagrid-tunnel"}
UNITS = ("sovagrid-agent.service", "sovagrid-agent-tunnel.service")
UNIT_PATHS = {unit: "/etc/systemd/system/" + unit for unit in UNITS}
CORE_FILES = {*UNIT_PATHS.values(), "/etc/systemd/system/sovagrid-agent.service.d/10-tunnel.conf",
              "/etc/sovagrid/agent.json", "/etc/sovagrid/agent.token", "/etc/sovagrid/hub-ca.pem",
              "/etc/sovagrid-agent-tunnel/id_ed25519", "/etc/sovagrid-agent-tunnel/id_ed25519.pub",
              "/etc/sovagrid-agent-tunnel-public/known_hosts", MANIFEST}
CORE_DIRECTORIES = {INSTALLER, "/opt/sovagrid-agent", "/etc/sovagrid", "/etc/sovagrid-agent-tunnel",
                    "/etc/sovagrid-agent-tunnel-public", "/var/lib/sovagrid-agent",
                    "/var/empty/sovagrid-tunnel", "/etc/systemd/system/sovagrid-agent.service.d"}
UNSUPPORTED = (JOURNAL + "/features.json", "/opt/sovagrid-src", "/opt/sovagrid-agent-local",
               "/etc/sovagrid-hub", "/etc/sovagrid-local", "/var/lib/sovagrid-promotion",
               "/var/lib/sovagrid-hub-tunnels", "/var/lib/.sovagrid-host-restore-in-progress",
               "/var/lib/sovagrid-shell", "/var/lib/sovagrid-agent/files",
               "/etc/systemd/system/sovagrid-agent-local.service")
SHA = re.compile(r"[0-9a-f]{64}\Z")
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
REQUEST_FIELDS = {"enrollment_id", "server_id", "ssh_key_fingerprint"}
MAX_REQUEST = 1024
MAX_STATE = 4 * 1024**2


class Refused(Exception):
    pass


def require(value, code="INVALID_REQUEST"):
    if not value:
        raise Refused(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def read_json(raw):
    value = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(value, dict))
    return value


def encode(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_request(action, value):
    require(action in ("preview", "apply"))
    fields = REQUEST_FIELDS | ({"expected_revision"} if action == "apply" else set())
    require(isinstance(value, dict) and set(value) == fields)
    for key in ("enrollment_id", "server_id"):
        require(isinstance(value[key], str) and str(uuid.UUID(value[key])) == value[key])
    require(isinstance(value["ssh_key_fingerprint"], str) and FINGERPRINT.fullmatch(value["ssh_key_fingerprint"]))
    if action == "apply":
        require(isinstance(value["expected_revision"], str) and SHA.fullmatch(value["expected_revision"]))


class AgentRemoval:
    def __init__(self, root=Path("/"), *, owner=0):
        self.root = root
        self.owner = owner

    def path(self, absolute):
        return self.root / absolute.lstrip("/")

    def inspect(self, absolute, *, directory=False, mode=None, missing=False):
        relative = Path(absolute)
        require(relative.is_absolute() and ".." not in relative.parts, "OWNERSHIP_CONFLICT")
        path = self.root
        try:
            for part in relative.parts[1:]:
                path /= part
                info = path.lstat()
                require(info.st_uid == self.owner and not info.st_mode & 0o022
                        and not stat.S_ISLNK(info.st_mode), "OWNERSHIP_CONFLICT")
        except FileNotFoundError:
            require(missing, "STATE_CONFLICT")
            return None
        require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "OWNERSHIP_CONFLICT")
        require(mode is None or stat.S_IMODE(info.st_mode) == mode, "OWNERSHIP_CONFLICT")
        return info

    def read(self, path, *, mode, limit, missing=False):
        info = self.inspect(path, mode=mode, missing=missing)
        if info is None:
            return None
        require(info.st_size <= limit, "STATE_CONFLICT")
        fd = os.open(self.path(path), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            current = os.fstat(stream.fileno())
            require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), "OWNERSHIP_CONFLICT")
            raw = stream.read(limit + 1)
            require(len(raw) <= limit, "STATE_CONFLICT")
            return raw

    @contextlib.contextmanager
    def lock(self, action):
        self.inspect(JOURNAL, directory=True, mode=0o700)
        path = JOURNAL + "/lock"
        expected = self.inspect(path, mode=0o600)
        shared = action == "preview"
        fd = os.open(self.path(path), (os.O_RDONLY if shared else os.O_RDWR) | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            require((info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino), "OWNERSHIP_CONFLICT")
            try:
                fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refused("BUSY") from None
            yield
        finally:
            os.close(fd)

    def load_helper(self, state):
        manifest_raw = self.read(MANIFEST, mode=0o644, limit=512 * 1024)
        require(digest(manifest_raw) == state.get("source_manifest_sha256"), "SOURCE_CHANGED")
        manifest = read_json(manifest_raw)
        helper_raw = self.read(HELPER, mode=0o644, limit=1024 * 1024)
        expected = manifest.get("sha256", {}).get(SOURCE_ENTRY)
        require(digest(helper_raw) == expected == state["source_files"].get(HELPER), "SOURCE_CHANGED")
        helper = types.ModuleType("sovagrid_verified_installed_enrollment")
        helper.__file__ = str(self.path(HELPER))
        exec(compile(helper_raw, helper.__file__, "exec"), helper.__dict__)
        return helper

    def assert_supported(self):
        for path in UNSUPPORTED:
            item = self.path(path)
            require(not item.exists() and not item.is_symlink(), "UNSUPPORTED_INSTALLATION")

    def known_resources(self, enrollment, state, *, complete):
        source_files = state["source_files"]
        allowed_files = set(source_files) | CORE_FILES
        allowed_dirs = set(CORE_DIRECTORIES)
        for path in source_files:
            require(path == HELPER or path.startswith("/opt/sovagrid-agent/"), "OWNERSHIP_CONFLICT")
            allowed_dirs.update(str(parent) for parent in Path(path).parents
                                if str(parent).startswith("/opt/sovagrid-agent/"))
        files = set(state["owned_files"])
        directories = set(state["owned_directories"])
        accounts = set(state["accounts"])
        require(not state["pending_writes"] and files <= allowed_files and directories <= allowed_dirs
                and accounts <= OWNER_ACCOUNTS, "OWNERSHIP_CONFLICT")
        if complete:
            require(files == allowed_files and CORE_DIRECTORIES <= directories
                    and accounts == OWNER_ACCOUNTS, "OWNERSHIP_CONFLICT")
        enrollment.check_owned_files(state)
        for path, mode in state["owned_directories"].items():
            info = enrollment.files.inspect(path, directory=True, missing=not complete)
            if info is not None:
                require(stat.S_IMODE(info.st_mode) == mode, "OWNERSHIP_CONFLICT")
                children = {path + "/" + child.name for child in self.path(path).iterdir()}
                require(children <= files | directories, "UNOWNED_DATA")
        for name, account in state["accounts"].items():
            for key in ("uid", "gid"):
                require(type(account.get(key)) is int and account[key] > 0, "OWNERSHIP_CONFLICT")
            entry = enrollment.reconcile_account("target", state, name)
            require(entry is not None or not complete, "OWNERSHIP_CONFLICT")

    def expected_revision(self, enrollment, state):
        request_id = state["identity"]["request_id"]
        require(enrollment.target_state(request_id, required=True) == state, "STATE_CONFLICT")
        enrollment.verify_installed_files(state)
        enrollment.verify_credentials(state)
        self.known_resources(enrollment, state, complete=True)
        for unit in UNITS:
            enrollment.check_loaded_unit(unit, state)
        return digest(encode({"kind": "sovagrid-agent-removal-v1", "identity": state["identity"],
                              "pin": state["ssh_key_fingerprint"], "cas": enrollment.cas("target")}))

    def remove_runtime(self, enrollment, state):
        self.known_resources(enrollment, state, complete=False)
        operation = state["uninstallation"]
        if operation["step"] == "stop":
            for unit in UNITS:
                enrollment.check_loaded_unit(unit, state)
                enrollment.commands.run(["/usr/bin/systemctl", "disable", "--now", unit])
            operation["step"] = "runtime"
            enrollment.save_state("target", state)
        require(not any(enrollment.services().values()), "CLEANUP_REQUIRED")
        self.known_resources(enrollment, state, complete=False)
        for name, account in list(state["accounts"].items()):
            require(not enrollment.process_snapshot(account["uid"]), "CLEANUP_REQUIRED")
            enrollment.remove_account("target", state, name)
        for path in sorted(set(state["owned_files"]) - {HELPER, MANIFEST}, key=lambda path: (-len(path), path)):
            enrollment.unlink_owned("target", state, path)
        for path in sorted(set(state["owned_directories"]) - {INSTALLER}, key=lambda path: (-len(path), path)):
            if enrollment.files.inspect(path, directory=True, missing=True) is not None:
                self.path(path).rmdir()
            state["owned_directories"].pop(path)
            enrollment.save_state("target", state)
        enrollment.commands.run(["/usr/bin/systemctl", "daemon-reload"])
        operation["step"] = "installer"
        enrollment.save_state("target", state)

    def finish(self, state):
        require(set(state["owned_files"]) == {HELPER, MANIFEST}
                and set(state["owned_directories"]) == {INSTALLER} and not state["accounts"]
                and not state["pending_writes"], "STATE_CONFLICT")
        if self.inspect(INSTALLER, directory=True, mode=state["owned_directories"][INSTALLER],
                        missing=True) is not None:
            require({path.name for path in self.path(INSTALLER).iterdir()}
                    <= {Path(HELPER).name, Path(MANIFEST).name}, "UNOWNED_DATA")
        owned = []
        for path in (HELPER, MANIFEST):
            raw = self.read(path, mode=0o644, limit=1024 * 1024, missing=True)
            if raw is not None:
                info = self.inspect(path, mode=0o644)
                require(digest(raw) == state["owned_files"][path]
                        and state["file_metadata"][path] == {"mode": 0o644, "gid": info.st_gid},
                        "OWNERSHIP_CONFLICT")
                owned.append(path)
        for path in owned:
            self.path(path).unlink()
        with contextlib.suppress(FileNotFoundError):
            self.path(INSTALLER).rmdir()
        state["uninstallation"]["step"] = "removed"
        state.update(removed=True, source_files={}, owned_files={}, file_metadata={}, owned_directories={},
                     pending_writes={}, accounts={}, agent_token_sha256=None, ssh_public_key=None,
                     ssh_key_fingerprint=None, phase="prepared", local_port=None, transport=None)
        journal = self.path(JOURNAL)
        fd, temporary = tempfile.mkstemp(prefix=".removal-", dir=journal)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encode(state) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path(STATE))
            directory = os.open(journal, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)

    def run(self, action, request):
        validate_request(action, request)
        with self.lock(action):
            state = read_json(self.read(STATE, mode=0o600, limit=MAX_STATE))
            require(state.get("kind") == "target" and type(state.get("protocol")) is int
                    and state["protocol"] == 1, "STATE_CONFLICT")
            identity = {key: request[key] for key in ("enrollment_id", "server_id")}
            require(all(state["identity"].get(key) == value for key, value in identity.items()), "WRONG_AGENT")
            operation = state.get("uninstallation")
            if operation is not None:
                require(operation["fingerprint"] == request["ssh_key_fingerprint"]
                        and SHA.fullmatch(operation["revision"])
                        and operation["step"] in ("stop", "runtime", "installer", "removed"), "WRONG_AGENT")
                revision = operation["revision"]
                if operation["step"] == "removed":
                    require(state.get("removed") is True, "STATE_CONFLICT")
                    if action == "apply":
                        require(hmac.compare_digest(revision, request["expected_revision"]), "STALE_PREVIEW")
                    return {**identity, "state": "removed", "revision": revision}
                require(state["phase"] == "uninstalling" and not state.get("removed"), "STATE_CONFLICT")
            else:
                require(state["phase"] == "active" and not state.get("removed")
                        and not state.get("cleanup_started"), "NOT_ACTIVE")
                require(state.get("ssh_key_fingerprint") == request["ssh_key_fingerprint"], "WRONG_AGENT")
            self.assert_supported()
            if operation is None or operation["step"] in ("stop", "runtime"):
                helper = self.load_helper(state)
                enrollment = helper.Enrollment(root=self.root, owner=self.owner, executable=HELPER)
                try:
                    if operation is None:
                        revision = self.expected_revision(enrollment, state)
                    if action == "apply":
                        require(hmac.compare_digest(revision, request["expected_revision"]), "STALE_PREVIEW")
                        if operation is None:
                            state["phase"] = "uninstalling"
                            state["uninstallation"] = {"step": "stop", "revision": revision,
                                                       "fingerprint": request["ssh_key_fingerprint"]}
                            enrollment.save_state("target", state)
                        self.remove_runtime(enrollment, state)
                except helper.Refuse as error:
                    raise Refused(error.code) from None
            if action == "preview":
                return {**identity, "state": "ready", "revision": revision}
            require(hmac.compare_digest(revision, request["expected_revision"]), "STALE_PREVIEW")
            self.finish(state)
            return {**identity, "state": "removed", "revision": revision}


def main():
    os.umask(0o077)
    try:
        require(os.geteuid() == 0, "ROOT_REQUIRED")
        require(2 <= len(sys.argv) <= 3)
        if len(sys.argv) == 3:
            token = sys.argv[2]
            require(1 <= len(token) <= MAX_REQUEST and re.fullmatch(r"[A-Za-z0-9_-]+", token))
            raw = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
        else:
            require(sys.argv[0] != "-")
            raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        require(0 < len(raw) <= MAX_REQUEST)
        result = AgentRemoval().run(sys.argv[1], read_json(raw))
    except Refused as error:
        result = {"error": str(error)}
    except (ValueError, TypeError, KeyError, binascii.Error, UnicodeError):
        result = {"error": "INVALID_REQUEST"}
    except OSError:
        result = {"error": "CLEANUP_REQUIRED"}
    print(encode(result).decode("ascii"), flush=True)
    return int("error" in result)


if __name__ == "__main__":
    sys.exit(main())
