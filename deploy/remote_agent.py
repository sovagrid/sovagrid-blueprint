#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""SOVAGRID_REMOTE_AGENT_HELPER_V1: bounded root enrollment RPC.

Agent token and SSH private key are generated on the target and never emitted.
The Hub boundary accepts only public keys from verified managed installed source.
"""
from __future__ import annotations

import base64
import contextlib
import fcntl
import grp
import glob
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import shlex
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

PROTOCOL = 1
MAX_RPC = 32768
MAX_STATE = 4 * 1024**2
MAX_HUB_ENROLLMENTS = 2048
MAX_HUB_ACTIVE_ENROLLMENTS = 256
HUB_UID_MIN = 100
HUB_UID_MAX = 999
SELF_NAME = "sovagrid-blueprint/deploy/remote_agent.py"
TARGET_HELPER = "/opt/sovagrid-agent-installer/remote_agent.py"
COMPONENTS = {"sovagrid-blueprint", "sovagrid-agent", "sovagrid-hub", "sovagrid-web", "sovagrid-vpn"}
REQUIRED_SOURCE = {SELF_NAME, "sovagrid-blueprint/run.sh", "sovagrid-blueprint/deploy/compose.yaml",
                   "sovagrid-hub/Dockerfile", "sovagrid-web/Dockerfile", "sovagrid-web/deploy/Caddyfile.container",
                   "sovagrid-agent/deploy/sovagrid-agent.service", "sovagrid-vpn/deploy/sovagrid-vpn-status.service"}
PHASES = ("prepared", "transport_ready", "registered", "active")
ACTIONS = {"target-preview", "target-prepare", "target-transport", "target-registered",
           "target-activate", "target-status", "target-remove", "hub-preview", "hub-authorize",
           "hub-status", "hub-revoke", "target-features-status", "target-features-preview", "target-features-apply"}
FEATURE_ACTIONS = {"target-features-status", "target-features-preview", "target-features-apply"}
CAS_FIELDS = {"source_manifest_sha256", "features_sha256", "policy_sha256", "state_sha256"}
SHA = re.compile(r"[0-9a-f]{64}\Z")
STAGE = re.compile(r"/var/tmp/sovagrid-agent-enroll\.[A-Za-z0-9_-]{8,32}/source\Z")


class Refuse(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code="INVALID_REQUEST"):
    if not condition:
        raise Refuse(code)


def valid_manifest_source_name(name):
    """Use the same path grammar for packaging and installed source checks."""
    return (isinstance(name, str) and len(name) <= 240
            and re.fullmatch(r"[A-Za-z0-9_.@-]+(?:/[A-Za-z0-9_.@-]+)*", name) is not None
            and all(part not in (".", "..") for part in name.split("/")))


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical_uuid(value):
    try:
        require(isinstance(value, str) and str(uuid.UUID(value)) == value)
    except (ValueError, AttributeError):
        raise Refuse("INVALID_REQUEST") from None
    return value


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def exact(value, fields):
    require(isinstance(value, dict) and set(value) == set(fields))
    return value


def public_key(value):
    require(isinstance(value, str) and len(value) <= 128 and value.count(" ") == 1)
    kind, blob = value.split(" ")
    require(kind == "ssh-ed25519")
    try:
        raw = base64.b64decode(blob, validate=True)
    except ValueError:
        raise Refuse("INVALID_REQUEST") from None
    expected = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)
    require(len(raw) == len(expected) + 32 and raw.startswith(expected)
            and base64.b64encode(raw).decode("ascii") == blob)
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return value, fingerprint


def username(server_id):
    return "sgt_" + base64.b32encode(uuid.UUID(canonical_uuid(server_id)).bytes).decode("ascii").lower().rstrip("=")


def public_ca(value):
    require(isinstance(value, str) and value.isascii() and 1 <= len(value) <= 16384)
    pattern = r"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/\r\n=]+-----END CERTIFICATE-----"
    certificates = re.findall(pattern, value)
    require(1 <= len(certificates) <= 16 and not re.sub(pattern, "", value).strip(" \t\r\n"))
    # Reject combined certificate/private-key PEM files rather than copying
    # accidentally misplaced CA signing material to a target or GUI reply.
    try:
        ssl.create_default_context(cadata=value)
    except (ValueError, ssl.SSLError):
        raise Refuse("INVALID_REQUEST") from None
    return value


def validate_registration(value, identity, *, states):
    exact(value, {"id", "server_id", "name", "state", "revision", "created_at", "last_seen"})
    require(value["id"] == identity["enrollment_id"] and value["server_id"] == identity["server_id"])
    require(isinstance(value["name"], str) and 1 <= len(value["name"]) <= 80
            and value["state"] in states and integer(value["revision"], 1, 2)
            and integer(value["created_at"], 1, 253402300799)
            and (value["last_seen"] is None or integer(value["last_seen"], 1, 253402300799)))
    require((value["state"] == "active") == (value["last_seen"] is not None))
    require(value["revision"] == (2 if value["state"] == "cancelled" else 1))
    return value


def validate_request(action, value):
    require(action in ACTIONS)
    if action in FEATURE_ACTIONS:
        fields = {"protocol", "server_id"}
        if action != "target-features-status":
            fields.add("features")
        if action == "target-features-apply":
            fields |= {"expected", "enrollment_id", "agent_token_sha256"}
        exact(value, fields)
        require(type(value["protocol"]) is int and value["protocol"] == 1)
        canonical_uuid(value["server_id"])
        if "features" in value:
            exact(value["features"], {"commands", "terminal", "files"})
            require(all(type(item) is bool for item in value["features"].values()))
            require(value["features"]["commands"] or not (value["features"]["terminal"] or value["features"]["files"]))
        if "expected" in value:
            exact(value["expected"], CAS_FIELDS)
            require(all(isinstance(item, str) and SHA.fullmatch(item) for item in value["expected"].values()))
            canonical_uuid(value["enrollment_id"])
            require(isinstance(value["agent_token_sha256"], str) and SHA.fullmatch(value["agent_token_sha256"]))
        return value
    common = {"protocol"}
    if action.startswith("target-"):
        common.add("request_id")
    if action in ("hub-status", "hub-authorize", "hub-revoke") or action.startswith("target-") and action not in ("target-preview", "target-prepare", "target-status"):
        common |= {"enrollment_id", "server_id"}
    if action not in ("target-preview", "target-status", "hub-preview", "hub-status"):
        common.add("expected")
    extras = {
        "target-transport": {"hub_host", "hub_port", "local_port", "hub_host_key", "hub_ca_pem"},
        "target-registered": {"registration"}, "target-activate": {"registration"},
        "target-remove": {"registration"},
        "hub-authorize": {"ssh_public_key", "ssh_key_fingerprint"},
        "hub-revoke": {"ssh_key_fingerprint"},
    }
    exact(value, common | extras.get(action, set()))
    require(type(value["protocol"]) is int and value["protocol"] == 1)
    for field in ("request_id", "enrollment_id", "server_id"):
        if field in value:
            canonical_uuid(value[field])
    if "expected" in value:
        exact(value["expected"], CAS_FIELDS)
        require(all(isinstance(item, str) and SHA.fullmatch(item) for item in value["expected"].values()))
    if action == "target-transport":
        require(isinstance(value["hub_host"], str))
        try:
            address = ipaddress.ip_address(value["hub_host"])
        except (ValueError, TypeError):
            raise Refuse("INVALID_REQUEST") from None
        effective = getattr(address, "ipv4_mapped", None) or address
        require(not (effective.is_loopback or effective.is_unspecified or effective.is_multicast
                     or "%" in value["hub_host"]))
        require(integer(value["hub_port"], 1, 65535) and integer(value["local_port"], 1024, 65535))
        public_key(value["hub_host_key"])
        public_ca(value["hub_ca_pem"])
    if "ssh_public_key" in value:
        _, fingerprint = public_key(value["ssh_public_key"])
        require(value["ssh_key_fingerprint"] == fingerprint)
    if "ssh_key_fingerprint" in value:
        require(isinstance(value["ssh_key_fingerprint"], str)
                and re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", value["ssh_key_fingerprint"]))
    if "registration" in value and value["registration"] is not None:
        states = {"cancelled"} if action == "target-remove" else {"active"} if action == "target-activate" else {"pending", "active"}
        validate_registration(value["registration"], value, states=states)
    elif "registration" in value:
        require(action == "target-remove")
    return value


class Files:
    """Path operations are always rooted in fixed paths; root is injectable only by tests."""
    def __init__(self, root=Path("/"), *, owner=0):
        self.root = Path(root)
        self.owner = owner

    def path(self, absolute):
        require(isinstance(absolute, str) and absolute.startswith("/") and ".." not in Path(absolute).parts)
        return self.root / absolute.lstrip("/")

    def inspect(self, absolute, *, directory=False, private=False, missing=False):
        item = self.path(absolute)
        try:
            # Check every existing component; resolve() would conceal symlinks.
            relative = item.relative_to(self.root)
            current = self.root
            for component in relative.parts:
                current /= component
                info = current.lstat()
                public_sticky = (str(current.relative_to(self.root)) in ("tmp", "var/tmp")
                                 and stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX)
                require(info.st_uid == self.owner and (not info.st_mode & 0o022 or public_sticky),
                        "OWNERSHIP_CONFLICT")
                require(not stat.S_ISLNK(info.st_mode), "OWNERSHIP_CONFLICT")
            info = item.lstat()
        except FileNotFoundError:
            if missing:
                return None
            raise Refuse("STATE_CONFLICT") from None
        require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "OWNERSHIP_CONFLICT")
        if private:
            require(stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600), "OWNERSHIP_CONFLICT")
        return info

    def read(self, absolute, *, limit=MAX_RPC, private=False, missing=False):
        info = self.inspect(absolute, private=private, missing=missing)
        if info is None:
            return None
        require(info.st_size <= limit, "STATE_CONFLICT")
        fd = os.open(self.path(absolute), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            current = os.fstat(fd)
            require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), "STATE_CONFLICT")
            data = os.read(fd, limit + 1)
            require(len(data) <= limit, "STATE_CONFLICT")
            return data
        finally:
            os.close(fd)

    def mkdir(self, absolute, mode=0o700):
        item = self.path(absolute)
        parent = str(Path(absolute).parent)
        if not self.path(parent).exists():
            self.mkdir(parent, 0o755)
        self.inspect(parent, directory=True)
        try:
            item.mkdir(mode=mode)
        except FileExistsError:
            pass
        else:
            # main() deliberately uses umask077. Set the intended mode only
            # on a directory we just created; never repair/adopt an old path.
            fd = os.open(item, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                require(os.fstat(fd).st_uid == self.owner, "OWNERSHIP_CONFLICT")
                os.fchmod(fd, mode)
            finally:
                os.close(fd)
        self.inspect(absolute, directory=True)
        require(stat.S_IMODE(item.lstat().st_mode) == mode, "OWNERSHIP_CONFLICT")

    def write(self, absolute, data, *, mode=0o600, gid=None):
        require(isinstance(data, bytes), "STATE_CONFLICT")
        parent = str(Path(absolute).parent)
        self.inspect(parent, directory=True)
        self.inspect(absolute, missing=True)
        fd, temporary = tempfile.mkstemp(prefix=".enroll-", dir=self.path(parent))
        try:
            os.fchmod(fd, mode)
            if gid is not None:
                os.fchown(fd, self.owner, gid)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, self.path(absolute))
            directory = os.open(self.path(parent), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)


class Source:
    def __init__(self, files, source):
        self.files = files
        self.source = str(source).rstrip("/")

    def verify(self):
        self.files.inspect(self.source, directory=True)
        raw = self.files.read(self.source + "/sovagrid-bundle.json", limit=512 * 1024)
        try:
            manifest = json.loads(raw, object_pairs_hook=unique_object)
        except (ValueError, UnicodeError):
            raise Refuse("SOURCE_UNTRUSTED") from None
        exact(manifest, {"format", "components", "sha256"})
        require(type(manifest["format"]) is int and manifest["format"] == 1
                and isinstance(manifest["components"], dict) and set(manifest["components"]) == COMPONENTS
                and isinstance(manifest["sha256"], dict) and REQUIRED_SOURCE <= set(manifest["sha256"]), "SOURCE_UNTRUSTED")
        require({item.name for item in self.files.path(self.source).iterdir()} == COMPONENTS | {"sovagrid-bundle.json"},
                "SOURCE_UNTRUSTED")
        require(1 <= len(manifest["sha256"]) <= 4096, "SOURCE_UNTRUSTED")
        expanded = 0
        for name, expected in manifest["sha256"].items():
            require(valid_manifest_source_name(name)
                    and name.split("/")[0] in COMPONENTS
                    and isinstance(expected, str) and SHA.fullmatch(expected), "SOURCE_UNTRUSTED")
            data = self.files.read(self.source + "/" + name, limit=32 * 1024**2)
            expanded += len(data)
            require(expanded <= 256 * 1024**2, "SOURCE_UNTRUSTED")
            require(digest(data) == expected, "SOURCE_CHANGED")
        actual = set()
        for parent, dirs, names in os.walk(self.files.path(self.source), followlinks=False):
            for name in dirs:
                absolute = "/" + str((Path(parent) / name).relative_to(self.files.root))
                self.files.inspect(absolute, directory=True)
            for name in names:
                relative = (Path(parent) / name).relative_to(self.files.path(self.source)).as_posix()
                if relative != "sovagrid-bundle.json":
                    actual.add(relative)
        require(actual == set(manifest["sha256"]), "SOURCE_UNTRUSTED")
        for component, record in manifest["components"].items():
            exact(record, {"commit", "file_count"})
            require(isinstance(record["commit"], str) and re.fullmatch(r"[0-9a-f]{40}", record["commit"])
                    and integer(record["file_count"], 1, 4096)
                    and record["file_count"] == sum(name.startswith(component + "/") for name in actual), "SOURCE_UNTRUSTED")
        require(b"SOVAGRID_REMOTE_AGENT_HELPER_V1" in self.files.read(self.source + "/" + SELF_NAME, limit=1024 * 1024),
                "SOURCE_UNTRUSTED")
        return digest(raw), manifest


class Commands:
    """Fixed argv only; command output is private implementation data, never RPC errors."""
    def run(self, argv, *, timeout=20, input_data=None, limit=32768, check=True, user=None, group=None, capture=True):
        import selectors
        require(isinstance(argv, list) and argv and all(isinstance(item, str) for item in argv), "INTERNAL_ERROR")
        options = {}
        if user is not None:
            require(integer(user, 1, 2**31 - 1) and integer(group, 1, 2**31 - 1), "INTERNAL_ERROR")
            options.update(user=user, group=group, extra_groups=[])
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
                                start_new_session=True, bufsize=0,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
                                     "DEBIAN_FRONTEND": "noninteractive", "PYTHONDONTWRITEBYTECODE": "1"}, **options)
        selector = selectors.DefaultSelector()
        data = bytearray()
        deadline = time.monotonic() + timeout
        completed = False
        try:
            if input_data is not None:
                require(isinstance(input_data, bytes) and len(input_data) <= 4096, "INTERNAL_ERROR")
                proc.stdin.write(input_data); proc.stdin.close()
            if not capture:
                try:
                    code = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    raise Refuse("SERVICE_FAILED") from None
                require(not check or code == 0, "SERVICE_FAILED")
                completed = True
                return code, b""
            os.set_blocking(proc.stdout.fileno(), False)
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map() or proc.poll() is None:
                remaining = deadline - time.monotonic()
                require(remaining > 0, "SERVICE_FAILED")
                if selector.get_map():
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fd, limit - len(data) + 1)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            require(len(data) + len(chunk) <= limit, "SERVICE_FAILED")
                            data.extend(chunk)
                else:
                    time.sleep(min(remaining, 0.02))
            code = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
            require(not check or code == 0, "SERVICE_FAILED")
            completed = True
            return code, bytes(data)
        finally:
            selector.close()
            if not completed or proc.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
            if proc.poll() is None:
                proc.wait(timeout=5)
            for stream in (proc.stdin, proc.stdout):
                if stream is not None:
                    with contextlib.suppress(OSError):
                        stream.close()


TARGET_STATE_DIR = "/var/lib/sovagrid-agent-enrollment"
HUB_STATE_DIR = "/var/lib/sovagrid-hub-tunnels"
TARGET_STATE = TARGET_STATE_DIR + "/state.json"
HUB_STATE = HUB_STATE_DIR + "/state.json"
POLICY_PATH = "/etc/ssh/sshd_config.d/10-sovagrid-tunnels.conf"
HUB_GROUP = "sovagrid-tunnel"
POLICY = b'''# SOVAGRID_REMOTE_AGENT_HELPER_V1 - managed restricted transport accounts
Match Group sovagrid-tunnel
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AuthorizedKeysFile /etc/ssh/sovagrid-tunnels/%u
    AuthorizedKeysCommand none
    PubkeyAcceptedAlgorithms ssh-ed25519
    MaxSessions 0
    AllowTcpForwarding local
    PermitOpen 127.0.0.1:8767
    PermitListen none
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
    PermitTunnel no
    PermitUserRC no
    ForceCommand /bin/false
Match all
'''


class Enrollment:
    def __init__(self, *, root=Path("/"), owner=0, executable=None, commands=None):
        self.files = Files(root, owner=owner)
        self.commands = commands or Commands()
        self.executable = executable or str(Path(__file__).absolute())
        self._source = None

    def load_json(self, path, *, missing=False, limit=MAX_RPC):
        data = self.files.read(path, private=True, missing=missing, limit=limit)
        if data is None:
            return None
        try:
            value = json.loads(data, object_pairs_hook=unique_object)
        except (ValueError, UnicodeError):
            raise Refuse("STATE_CONFLICT") from None
        require(isinstance(value, dict), "STATE_CONFLICT")
        return value

    def load_state(self, side):
        state = self.load_json(HUB_STATE if side == "hub" else TARGET_STATE, missing=True, limit=MAX_STATE)
        if state is not None:
            require(state.get("protocol") == 1 and type(state.get("protocol")) is int,
                    "STATE_CONFLICT")
        return state

    @contextlib.contextmanager
    def locked(self, side, *, readonly=False):
        directory = HUB_STATE_DIR if side == "hub" else TARGET_STATE_DIR
        if readonly:
            self.files.inspect(directory, directory=True, private=True)
        else:
            self.files.mkdir(directory, 0o700)
        path = directory + "/lock"
        self.files.inspect(path, private=True, missing=not readonly)
        flags = os.O_NOFOLLOW | (os.O_RDONLY if readonly else os.O_CREAT | os.O_RDWR)
        fd = os.open(self.files.path(path), flags, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid == self.files.owner and stat.S_IMODE(info.st_mode) == 0o600,
                    "OWNERSHIP_CONFLICT")
            # Never wait indefinitely behind another installer.
            try:
                fcntl.flock(fd, (fcntl.LOCK_SH if readonly else fcntl.LOCK_EX) | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refuse("STATE_CONFLICT") from None
            yield
        finally:
            os.close(fd)

    def save_state(self, side, state):
        raw = encode(state) + b"\n"
        require(len(raw) <= MAX_STATE, "STATE_CONFLICT")
        self.files.write(HUB_STATE if side == "hub" else TARGET_STATE, raw)

    def source(self, side):
        if side == "hub":
            require(self.executable == "/opt/sovagrid-src/" + SELF_NAME, "SOURCE_UNTRUSTED")
            source = "/opt/sovagrid-src"
            for marker in ("/var/lib/sovagrid/.managed-by-run-sh",):
                self.files.inspect(marker, private=True)
            return Source(self.files, source).verify()
        if self.executable == TARGET_HELPER:
            state = self.load_state("target")
            require(state is not None, "SOURCE_UNTRUSTED")
            raw = self.files.read("/opt/sovagrid-agent-installer/source-manifest.json", limit=512 * 1024)
            require(digest(raw) == state.get("source_manifest_sha256"), "SOURCE_CHANGED")
            manifest = json.loads(raw, object_pairs_hook=unique_object)
            require(digest(self.files.read(TARGET_HELPER, limit=1024 * 1024)) == manifest["sha256"].get(SELF_NAME),
                    "SOURCE_CHANGED")
            expected_files = self.installed_projection(manifest)
            require(isinstance(state.get("source_files"), dict)
                    and state["source_files"] == expected_files, "STATE_CONFLICT")
            for path, expected in expected_files.items():
                require(digest(self.files.read(path, limit=32 * 1024**2)) == expected, "SOURCE_CHANGED")
            return digest(raw), manifest
        path = Path(self.executable)
        require(path.as_posix().endswith("/" + SELF_NAME), "SOURCE_UNTRUSTED")
        source = path.parents[2].as_posix()
        require(STAGE.fullmatch(source), "SOURCE_UNTRUSTED")
        self.files.inspect(str(path.parents[3]), directory=True, private=True)
        return Source(self.files, source).verify()

    @staticmethod
    def installed_projection(manifest):
        require(isinstance(manifest, dict) and isinstance(manifest.get("sha256"), dict)
                and SELF_NAME in manifest["sha256"], "SOURCE_UNTRUSTED")
        projection = {TARGET_HELPER: manifest["sha256"][SELF_NAME]}
        legal = {"LICENSE", "NOTICE", "ATTRIBUTION.md", "README.md", "THIRD_PARTY_NOTICES.txt",
                 "deploy/sovagrid-agent.service"}
        for name, expected in manifest["sha256"].items():
            if not name.startswith("sovagrid-agent/"):
                continue
            relative = name[len("sovagrid-agent/"):]
            if (relative in legal or (relative.startswith("sovagrid_agent/") and relative.endswith(".py")
                                     and "__pycache__" not in relative.split("/"))):
                require(isinstance(expected, str) and SHA.fullmatch(expected)
                        and ".." not in relative.split("/") and not relative.startswith("/"), "SOURCE_UNTRUSTED")
                projection["/opt/sovagrid-agent/" + relative] = expected
        require({"/opt/sovagrid-agent/sovagrid_agent/__main__.py", "/opt/sovagrid-agent/LICENSE",
                 "/opt/sovagrid-agent/NOTICE", "/opt/sovagrid-agent/ATTRIBUTION.md",
                 "/opt/sovagrid-agent/deploy/sovagrid-agent.service"} <= set(projection), "SOURCE_UNTRUSTED")
        return projection

    def platform(self):
        # Ubuntu commonly makes /etc/os-release a symlink. Read the fixed
        # canonical vendor file instead of following an arbitrary link.
        release_path = "/usr/lib/os-release" if self.files.path("/usr/lib/os-release").exists() else "/etc/os-release"
        raw = self.files.read(release_path, limit=8192).decode("utf-8")
        values = {}
        for line in raw.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip('"')
        require(values.get("ID") == "ubuntu" and values.get("VERSION_ID") in ("22.04", "24.04", "26.04"),
                "UNSUPPORTED_PLATFORM")
        require(sys.version_info >= (3, 10) and self.files.path("/run/systemd/system").is_dir(), "UNSUPPORTED_SYSTEMD")
        _, raw_version = self.commands.run(["/usr/bin/systemctl", "--version"])
        match = re.match(rb"systemd ([0-9]+)", raw_version)
        require(match is not None and int(match.group(1)) >= 247, "UNSUPPORTED_SYSTEMD")
        return {"ubuntu_version": values["VERSION_ID"], "python_version": platform.python_version(),
                "systemd_version": match.group(1).decode("ascii")}

    def features(self, side):
        paths = ("/etc/sovagrid/.agent-unit-managed-by-run-sh",
                 "/etc/sovagrid/.terminal-unit-managed-by-run-sh",
                 "/etc/sovagrid/.journal-managed-by-run-sh",
                 "/etc/sovagrid/.vpn-unit-managed-by-run-sh",
                 "/etc/sovagrid/.vpn-control-managed-by-run-sh",
                 "/etc/sovagrid/agent.json")
        if side == "hub":
            paths += ("/etc/sovagrid/hub-ca.pem", "/etc/ssh/ssh_host_ed25519_key.pub")
        result = {}
        for path in paths:
            value = self.files.read(path, missing=True)
            result[path] = digest(value) if value is not None else None
        return result

    def policy_snapshot(self, side):
        if side == "target":
            state = self.load_state("target")
            return state.get("transport") if state else None
        entries = {}
        total = 0
        def visit(path, stack=()):
            nonlocal total
            require(path not in stack and len(stack) < 16 and len(entries) < 256,
                    "SSH_POLICY_CONFLICT")
            if path in entries:
                return
            raw = self.files.read(path, limit=512 * 1024)
            total += len(raw)
            require(total <= 2 * 1024**2, "SSH_POLICY_CONFLICT")
            entries[path] = digest(raw)
            try:
                lines = raw.decode("utf-8").splitlines()
                for line in lines:
                    parts = shlex.split(line, comments=True, posix=True)
                    if parts and parts[0].lower() == "match":
                        criteria = parts[1:]
                        if len(criteria) == 1 and criteria[0].lower() == "all":
                            continue
                        # User/Group matching is deterministic for our dedicated
                        # account. Address/Host/LocalPort/etc can change policy
                        # for the real Agent while a desktop -T -C probe passes;
                        # first increment refuses these ambiguous configurations.
                        require(criteria and len(criteria) % 2 == 0
                                and all(criteria[index].lower() in ("user", "group")
                                        for index in range(0, len(criteria), 2)), "SSH_POLICY_CONFLICT")
                    if not parts or parts[0].lower() != "include":
                        continue
                    require(1 <= len(parts[1:]) <= 32, "SSH_POLICY_CONFLICT")
                    for pattern in parts[1:]:
                        absolute = pattern if pattern.startswith("/") else "/etc/ssh/" + pattern
                        require(".." not in Path(absolute).parts, "SSH_POLICY_CONFLICT")
                        # Track matching names too: a new file in a wildcard
                        # Include changes the snapshot even before sshd -T.
                        matches = sorted(glob.glob(str(self.files.path(absolute))))
                        entries["glob:" + absolute] = digest(encode(matches))
                        for match in matches:
                            child = "/" + str(Path(match).relative_to(self.files.root))
                            visit(child, stack + (path,))
            except (ValueError, UnicodeError):
                raise Refuse("SSH_POLICY_CONFLICT") from None
        visit("/etc/ssh/sshd_config")
        # Bind the managed fragment even if an existing global config fails
        # to include it; authorize later explicitly proves effective policy.
        raw = self.files.read(POLICY_PATH, limit=512 * 1024, missing=True)
        entries[POLICY_PATH] = digest(raw) if raw is not None else None
        # Capture nested Includes/defaults without returning the configuration.
        _, effective = self.commands.run(["/usr/sbin/sshd", "-T"])
        entries["effective"] = digest(effective)
        return entries

    def cas(self, side):
        source_sha, _ = self.source(side)
        state = self.load_state(side)
        owned = {}
        directories = {}
        accounts = {}
        group_state = None
        if side == "hub":
            try:
                group = grp.getgrnam(HUB_GROUP)
                group_state = {"name": group.gr_name, "gid": group.gr_gid, "members": sorted(group.gr_mem)}
            except KeyError:
                pass
        if state is not None:
            for path in state.get("owned_directories", {}):
                info = self.files.inspect(path, directory=True, missing=True)
                directories[path] = ({"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}
                                     if info is not None else None)
            for name in state.get("accounts", {}):
                try:
                    item = pwd.getpwnam(name)
                    accounts[name] = {"uid": item.pw_uid, "gid": item.pw_gid, "home": item.pw_dir,
                                      "comment": item.pw_gecos, "shell": item.pw_shell,
                                      "groups": sorted(os.getgrouplist(name, item.pw_gid))}
                    if side == "hub":
                        _, expiry = self.commands.run(["/usr/bin/chage", "--list", name], limit=4096)
                        accounts[name]["expiry_sha256"] = digest(expiry)
                except KeyError:
                    accounts[name] = None
            for path, expected in state.get("owned_files", {}).items():
                require(isinstance(path, str) and path.startswith("/") and isinstance(expected, str) and SHA.fullmatch(expected),
                        "STATE_CONFLICT")
                raw = self.files.read(path, limit=32 * 1024**2, missing=True)
                if raw is None:
                    owned[path] = None
                else:
                    info = self.files.inspect(path)
                    owned[path] = {"sha256": digest(raw), "mode": stat.S_IMODE(info.st_mode),
                                   "uid": info.st_uid, "gid": info.st_gid}
        return {"source_manifest_sha256": source_sha,
                "features_sha256": digest(encode(self.features(side))),
                "policy_sha256": digest(encode(self.policy_snapshot(side))),
                "state_sha256": digest(encode({"manifest": state, "files": owned, "directories": directories,
                                               "accounts": accounts, "group": group_state}))}

    def check_cas(self, side, expected):
        require(self.cas(side) == expected, "STALE_PREVIEW")

    def target_state(self, request_id, *, required=False):
        state = self.load_state("target")
        if state is None:
            require(not required, "STATE_CONFLICT")
            return None
        require(state.get("kind") == "target" and isinstance(state.get("identity"), dict)
                and state.get("phase") in PHASES and isinstance(state.get("owned_files"), dict)
                and isinstance(state.get("source_files"), dict), "STATE_CONFLICT")
        for field in ("request_id", "enrollment_id", "server_id"):
            canonical_uuid(state["identity"].get(field))
        if state.get("removed"):
            # A finished tombstone is not a live Agent. It can permit a new
            # explicitly requested enrollment only after proving resources are
            # gone; an old request cannot adopt or remove its replacement.
            require(not state["owned_files"] and not state["source_files"]
                    and not state.get("accounts") and not state.get("owned_directories")
                    and not state.get("pending_writes")
                    and all(state.get(key) is None for key in ("agent_token_sha256", "ssh_public_key", "ssh_key_fingerprint")),
                    "STATE_CONFLICT")
            self.target_conflicts(None)
            require(not required, "STATE_CONFLICT")
            return None
        require(state["identity"].get("request_id") == request_id, "STATE_CONFLICT")
        return state

    @staticmethod
    def public_target(state):
        if state is None:
            return None
        result = {**state["identity"], "phase": state["phase"], "local_port": state.get("local_port")}
        for key in ("agent_token_sha256", "ssh_public_key", "ssh_key_fingerprint"):
            result[key] = state.get(key)
        return result

    def target_conflicts(self, state):
        if state is not None:
            return
        for absolute in ("/opt/sovagrid-agent", "/opt/sovagrid-agent-installer", "/etc/sovagrid",
                         "/etc/sovagrid-agent-tunnel", "/etc/sovagrid-agent-tunnel-public", "/var/lib/sovagrid-agent",
                         "/etc/systemd/system/sovagrid-agent.service",
                         "/etc/systemd/system/sovagrid-agent-tunnel.service"):
            require(not self.files.path(absolute).exists() and not self.files.path(absolute).is_symlink(),
                    "EXISTING_AGENT")
        for directory in ("/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system",
                          "/usr/lib/systemd/system", "/lib/systemd/system"):
            for unit in ("sovagrid-agent.service", "sovagrid-agent-tunnel.service"):
                for suffix in ("", ".d"):
                    path = self.files.path(directory + "/" + unit + suffix)
                    require(not path.exists() and not path.is_symlink(), "EXISTING_AGENT")
        for name in ("sovagrid", "sovagrid-tunnel"):
            for lookup in (pwd.getpwnam, grp.getgrnam):
                try:
                    lookup(name)
                except KeyError:
                    pass
                else:
                    raise Refuse("OWNERSHIP_CONFLICT")

    def hub_trust(self):
        _, effective = self.commands.run(["/usr/sbin/sshd", "-T"])
        enabled = {line.split(maxsplit=1)[1] for line in effective.decode("utf-8").splitlines()
                   if line.startswith("hostkey ")}
        key_path = "/etc/ssh/ssh_host_ed25519_key"
        require(key_path in enabled, "SSH_POLICY_CONFLICT")
        raw_key = self.files.read(key_path + ".pub", limit=1024).decode("ascii").strip().split()
        require(len(raw_key) >= 2, "SSH_POLICY_CONFLICT")
        key, _ = public_key(" ".join(raw_key[:2]))
        ca = self.files.read("/etc/sovagrid/hub-ca.pem", limit=16384).decode("ascii")
        try:
            public_ca(ca)
        except Refuse:
            raise Refuse("TLS_VERIFY_FAILED") from None
        return {"hub_host_key": key, "hub_ca_pem": ca}

    def preview(self, side, value):
        # This entire path is deliberately read-only: no mkdir/flock/apt or
        # SSH reload. Mutations recompute its snapshot after taking the lock.
        if side == "target":
            state = self.target_state(value["request_id"])
            self.target_conflicts(state)
            system = self.platform()
            return {"cas": self.cas(side), "target": self.public_target(state), "platform": system}
        state = self.hub_state()
        if state is None:
            require(not self.files.path(POLICY_PATH).exists()
                    and not self.files.path("/etc/ssh/sovagrid-tunnels").exists(), "OWNERSHIP_CONFLICT")
            try:
                grp.getgrnam(HUB_GROUP)
            except KeyError:
                pass
            else:
                raise Refuse("OWNERSHIP_CONFLICT")
        return {"cas": self.cas(side), "helper_v1": True, **self.hub_trust()}

    def owned_directory(self, side, state, path, mode=0o755):
        directories = state.setdefault("owned_directories", {})
        if path not in directories:
            require(not self.files.path(path).exists() and not self.files.path(path).is_symlink(), "OWNERSHIP_CONFLICT")
            directories[path] = mode
            self.save_state(side, state)  # Intent survives disconnect before mkdir.
        require(directories[path] == mode, "STATE_CONFLICT")
        self.files.mkdir(path, mode)

    def owned_write(self, side, state, path, data, *, mode=0o600, gid=None):
        current = self.files.read(path, limit=32 * 1024**2, missing=True)
        old = digest(current) if current is not None else None
        new = digest(data)
        owned = state.setdefault("owned_files", {})
        pending = state.setdefault("pending_writes", {})
        if path in pending:
            intent = pending[path]
            require(intent.get("new") == new and old in (intent.get("old"), new), "OWNERSHIP_CONFLICT")
        else:
            require((path not in owned and current is None) or owned.get(path) == old, "OWNERSHIP_CONFLICT")
            pending[path] = {"old": old, "new": new, "mode": mode, "gid": gid}
            self.save_state(side, state)
        if old != new:
            self.files.write(path, data, mode=mode, gid=gid)
        info = self.files.inspect(path)
        require(stat.S_IMODE(info.st_mode) == mode and (gid is None or info.st_gid == gid), "OWNERSHIP_CONFLICT")
        owned[path] = new
        state.setdefault("file_metadata", {})[path] = {"mode": stat.S_IMODE(info.st_mode), "gid": info.st_gid}
        del pending[path]
        self.save_state(side, state)

    def account(self, side, state, name, *, role, group_name=None, enrollment_id=None):
        accounts = state.setdefault("accounts", {})
        home = "/var/lib/sovagrid-agent" if role == "agent" else "/var/empty/" + name
        operation = enrollment_id or state["identity"]["enrollment_id"]
        comment = "sovagrid-" + operation + "-" + role
        if name not in accounts:
            try:
                pwd.getpwnam(name)
            except KeyError:
                pass
            else:
                raise Refuse("OWNERSHIP_CONFLICT")
            # The stable full operation comment plus durable intent allows a
            # retry after useradd succeeded but its response was lost.
            record = {"uid": None, "gid": None, "home": home, "comment": comment}
            if side == "hub":
                reserved = set()
                for other in accounts.values():
                    require(isinstance(other, dict) and integer(other.get("requested_uid"), HUB_UID_MIN, HUB_UID_MAX),
                            "STATE_CONFLICT")
                    reserved.add(other["requested_uid"])
                selected = None
                for candidate in range(HUB_UID_MAX, HUB_UID_MIN - 1, -1):
                    if candidate in reserved:
                        continue
                    try:
                        pwd.getpwuid(candidate)
                    except KeyError:
                        selected = candidate
                        break
                require(selected is not None, "OWNERSHIP_CONFLICT")
                record["requested_uid"] = selected
            accounts[name] = record
            self.save_state(side, state)
        record = accounts[name]
        require(record.get("comment") == comment and record.get("home") == home, "STATE_CONFLICT")
        if side == "hub":
            require(integer(record.get("requested_uid"), HUB_UID_MIN, HUB_UID_MAX)
                    and record.get("uid") in (None, record["requested_uid"]), "STATE_CONFLICT")
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            require(record.get("uid") is None, "OWNERSHIP_CONFLICT")
            args = ["/usr/sbin/useradd"]
            if side == "hub":
                # useradd --system ignores --expiredate on supported Ubuntu.
                # Keep a system-range UID but atomically create it expired.
                try:
                    pwd.getpwuid(record["requested_uid"])
                except KeyError:
                    pass
                else:
                    raise Refuse("OWNERSHIP_CONFLICT")
                args += ["--uid", str(record["requested_uid"])]
            else:
                args += ["--system"]
            args += ["--no-create-home", "--home-dir", home,
                    "--shell", "/usr/sbin/nologin", "--password", "*NP*", "--expiredate",
                    "1970-01-02" if role == "hub-tunnel" else "", "--comment", comment]
            args += ["--gid", group_name] if group_name else ["--user-group"]
            self.commands.run(args + [name], capture=False)
            entry = pwd.getpwnam(name)
        require(entry.pw_uid != 0 and entry.pw_gecos == comment and entry.pw_dir == home
                and entry.pw_shell == "/usr/sbin/nologin"
                and (record.get("uid") is None or entry.pw_uid == record["uid"])
                and (record.get("gid") is None or entry.pw_gid == record["gid"]), "OWNERSHIP_CONFLICT")
        require(set(os.getgrouplist(name, entry.pw_gid)) == {entry.pw_gid}, "OWNERSHIP_CONFLICT")
        if side == "hub":
            require(entry.pw_uid == record["requested_uid"] and group_name == HUB_GROUP
                    and isinstance(state.get("group"), dict) and entry.pw_gid == state["group"].get("gid"),
                    "OWNERSHIP_CONFLICT")
        record.update(uid=entry.pw_uid, gid=entry.pw_gid)
        self.save_state(side, state)
        return entry

    def prerequisites(self):
        args = ["/usr/bin/dpkg-query", "-W", "-f=${Status}\\n", "python3", "ca-certificates", "openssh-client"]
        code, output = self.commands.run(args, check=False)
        if code != 0 or output.decode("ascii", "replace").splitlines() != ["install ok installed"] * 3:
            self.commands.run(["/usr/bin/apt-get", "-o", "DPkg::Lock::Timeout=30", "update"], timeout=180, capture=False)
            self.commands.run(["/usr/bin/apt-get", "-o", "DPkg::Lock::Timeout=30", "install", "-y", "--no-install-recommends",
                               "python3", "ca-certificates", "openssh-client"], timeout=180, capture=False)

    def verify_credentials(self, state):
        token_info = self.files.inspect("/etc/sovagrid/agent.token")
        require(stat.S_IMODE(token_info.st_mode) == 0o640
                and token_info.st_gid == state["accounts"]["sovagrid"]["gid"], "KEY_CONFLICT")
        token = self.files.read("/etc/sovagrid/agent.token", limit=256)
        require(re.fullmatch(rb"[A-Za-z0-9_-]{43}\n", token)
                and digest(token.rstrip(b"\n")) == state.get("agent_token_sha256"), "KEY_CONFLICT")
        private = "/etc/sovagrid-agent-tunnel/id_ed25519"
        self.files.inspect(private, private=True)
        self.files.inspect(private + ".pub")
        _, derived = self.commands.run(["/usr/bin/ssh-keygen", "-y", "-P", "", "-f", private])
        parts = derived.decode("ascii").strip().split()
        require(len(parts) in (2, 3), "KEY_CONFLICT")
        if len(parts) == 3:
            require(parts[2] == "sovagrid:" + state["identity"]["enrollment_id"], "KEY_CONFLICT")
        key, fingerprint = public_key(" ".join(parts[:2]))
        stored = self.files.read(private + ".pub", limit=1024).decode("ascii").strip().split()
        require(len(stored) == 3 and stored[2] == "sovagrid:" + state["identity"]["enrollment_id"]
                and " ".join(stored[:2]) == key
                and key == state.get("ssh_public_key") and fingerprint == state.get("ssh_key_fingerprint"), "KEY_CONFLICT")

    def cleanup_keygen_scratch(self, state):
        scratch = TARGET_STATE_DIR + "/keygen-" + state["identity"]["enrollment_id"]
        if scratch not in state.get("owned_directories", {}):
            return
        if self.files.inspect(scratch, directory=True, private=True, missing=True) is not None:
            allowed = {"id_ed25519", "id_ed25519.pub"}
            require({path.name for path in self.files.path(scratch).iterdir()} <= allowed, "CLEANUP_REQUIRED")
            for name in allowed:
                path = scratch + "/" + name
                raw = self.files.read(path, limit=16384, missing=True)
                if raw is not None:
                    expected = state.get("keygen_outputs", {}).get(path)
                    require(expected is None or digest(raw) == expected, "OWNERSHIP_CONFLICT")
                    # Only the fixed two files in this operation's root0700
                    # scratch are eligible when killed before hashing them.
                    self.files.path(path).unlink()
            self.files.path(scratch).rmdir()
        state["owned_directories"].pop(scratch, None)
        state.pop("keygen_outputs", None)
        self.save_state("target", state)

    def verify_installed_files(self, state):
        for path, expected in state["source_files"].items():
            require(digest(self.files.read(path, limit=32 * 1024**2)) == expected
                    and stat.S_IMODE(self.files.inspect(path).st_mode) == 0o644, "SOURCE_CHANGED")
        for path, mode in state.get("owned_directories", {}).items():
            info = self.files.inspect(path, directory=True)
            require(stat.S_IMODE(info.st_mode) == mode, "OWNERSHIP_CONFLICT")

    def finish_pending(self, side, state):
        for path, intent in list(state.get("pending_writes", {}).items()):
            raw = self.files.read(path, limit=32 * 1024**2, missing=True)
            require(raw is not None and digest(raw) == intent["new"], "STATE_CONFLICT")
            info = self.files.inspect(path)
            require(stat.S_IMODE(info.st_mode) == intent["mode"]
                    and (intent["gid"] is None or info.st_gid == intent["gid"]), "OWNERSHIP_CONFLICT")
            state["owned_files"][path] = intent["new"]
            state.setdefault("file_metadata", {})[path] = {"mode": stat.S_IMODE(info.st_mode), "gid": info.st_gid}
            del state["pending_writes"][path]
            self.save_state(side, state)

    def target_prepare(self, value):
        self.platform()
        with self.locked("target"):
            self.check_cas("target", value["expected"])
            state = self.target_state(value["request_id"])
            self.target_conflicts(state)
            source_sha, manifest = self.source("target")
            projection = self.installed_projection(manifest)
            if state is None:
                state = {"protocol": 1, "kind": "target", "identity": {"request_id": value["request_id"],
                         "enrollment_id": str(uuid.uuid4()), "server_id": str(uuid.uuid4())},
                         "phase": "prepared", "created_at": int(time.time()),
                         "source_manifest_sha256": source_sha, "source_files": {}, "owned_files": {},
                         "owned_directories": {}, "pending_writes": {}, "accounts": {},
                         "agent_token_sha256": None, "ssh_public_key": None, "ssh_key_fingerprint": None,
                         "local_port": None, "transport": None}
                self.save_state("target", state)
            require(state["source_manifest_sha256"] == source_sha, "SOURCE_CHANGED")
            if (state["phase"] != "prepared" or (state.get("source_files") == projection
                    and all(state.get(key) is not None for key in ("agent_token_sha256", "ssh_public_key", "ssh_key_fingerprint")))):
                self.verify_installed_files(state)
                self.verify_credentials(state)
                self.finish_pending("target", state)
                self.cleanup_keygen_scratch(state)
                return {"cas": self.cas("target"), "target": self.public_target(state)}
            self.prerequisites()
            agent = self.account("target", state, "sovagrid", role="agent")
            self.account("target", state, "sovagrid-tunnel", role="tunnel")
            for path, mode in (("/etc/sovagrid", 0o750), ("/etc/sovagrid-agent-tunnel", 0o700),
                               ("/etc/sovagrid-agent-tunnel-public", 0o755), ("/opt/sovagrid-agent", 0o755), ("/opt/sovagrid-agent-installer", 0o755),
                               ("/var/lib/sovagrid-agent", 0o755), ("/var/empty/sovagrid-tunnel", 0o755)):
                self.owned_directory("target", state, path, mode)
            os.chown(self.files.path("/etc/sovagrid"), self.files.owner, agent.pw_gid)
            # Copy only Agent runtime/legal files plus this helper. Other
            # verified bundle components are never installed or executed.
            source_root = Path(self.executable).parents[2].as_posix() if self.executable != TARGET_HELPER else None
            for destination, expected in projection.items():
                if self.executable == TARGET_HELPER:
                    require(state.get("source_files") == projection, "SOURCE_CHANGED")
                    data = self.files.read(destination, limit=32 * 1024**2)
                else:
                    relative = SELF_NAME if destination == TARGET_HELPER else "sovagrid-agent/" + destination[len("/opt/sovagrid-agent/"):]
                    data = self.files.read(source_root + "/" + relative, limit=32 * 1024**2)
                require(digest(data) == expected, "SOURCE_CHANGED")
                parent = str(Path(destination).parent)
                if not self.files.path(parent).exists():
                    self.owned_directory("target", state, parent, 0o755)
                self.owned_write("target", state, destination, data, mode=0o644)
            manifest_raw = (self.files.read(source_root + "/sovagrid-bundle.json", limit=512 * 1024) if source_root
                            else self.files.read("/opt/sovagrid-agent-installer/source-manifest.json", limit=512 * 1024))
            self.owned_write("target", state, "/opt/sovagrid-agent-installer/source-manifest.json", manifest_raw, mode=0o644)
            state["source_files"] = projection
            self.save_state("target", state)
            token_path = "/etc/sovagrid/agent.token"
            if state["agent_token_sha256"] is None:
                require(not self.files.path(token_path).exists() and token_path not in state["pending_writes"], "KEY_CONFLICT")
                token = secrets.token_urlsafe(32).encode("ascii")
                state["agent_token_sha256"] = digest(token)
                self.save_state("target", state)
                self.owned_write("target", state, token_path, token + b"\n", mode=0o640, gid=agent.pw_gid)
                token = b""
            private = "/etc/sovagrid-agent-tunnel/id_ed25519"
            if state["ssh_public_key"] is None:
                scratch = TARGET_STATE_DIR + "/keygen-" + state["identity"]["enrollment_id"]
                self.owned_directory("target", state, scratch, 0o700)
                temporary = scratch + "/id_ed25519"
                if not state.get("key_generation_started"):
                    require(not self.files.path(temporary).exists() and not self.files.path(temporary + ".pub").exists(), "KEY_CONFLICT")
                    state["key_generation_started"] = True
                    self.save_state("target", state)
                    self.commands.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                                       "sovagrid:" + state["identity"]["enrollment_id"], "-f", temporary], capture=False)
                # A completed scratch pair is reused after interruption; a
                # missing/corrupt half is never replaced with a new identity.
                private_data = self.files.read(temporary, limit=16384, private=True)
                public_data = self.files.read(temporary + ".pub", limit=1024)
                stored = public_data.decode("ascii").strip().split()
                require(len(stored) == 3 and stored[2] == "sovagrid:" + state["identity"]["enrollment_id"], "KEY_CONFLICT")
                key, fingerprint = public_key(" ".join(stored[:2]))
                _, derived = self.commands.run(["/usr/bin/ssh-keygen", "-y", "-P", "", "-f", temporary])
                require(" ".join(derived.decode("ascii").strip().split()[:2]) == key, "KEY_CONFLICT")
                state["keygen_outputs"] = {temporary: digest(private_data), temporary + ".pub": digest(public_data)}
                self.save_state("target", state)
                self.owned_write("target", state, private, private_data, mode=0o600)
                private_data = b""
                self.owned_write("target", state, private + ".pub", public_data, mode=0o644)
                state.update(ssh_public_key=key, ssh_key_fingerprint=fingerprint)
                self.save_state("target", state)
            self.cleanup_keygen_scratch(state)
            self.verify_credentials(state)
            return {"cas": self.cas("target"), "target": self.public_target(state)}

    def services(self):
        result = {}
        for key, unit in (("tunnel", "sovagrid-agent-tunnel.service"), ("agent", "sovagrid-agent.service")):
            code, _ = self.commands.run(["/usr/bin/systemctl", "is-active", "--quiet", unit], check=False)
            result[key] = code == 0
        return result

    @staticmethod
    def same_identity(state, value):
        require(all(state["identity"][key] == value[key] for key in ("request_id", "enrollment_id", "server_id")),
                "STATE_CONFLICT")

    def tls_ready(self, local_port, *, attempts=5):
        last = "TLS_UNAVAILABLE"
        for attempt in range(attempts):
            try:
                code, raw = self.commands.run(["/usr/bin/python3", "-I", TARGET_HELPER, "_tls-health"],
                                              input_data=encode({"protocol": 1, "local_port": local_port}),
                                              timeout=5, limit=4096, check=False)
                value = json.loads(raw, object_pairs_hook=unique_object)
                if code == 0 and value == {"ok": True}:
                    return True
                if isinstance(value, dict) and value.get("error") == "TLS_VERIFY_FAILED":
                    raise Refuse("TLS_VERIFY_FAILED")
            except (ValueError, Refuse) as exc:
                if isinstance(exc, Refuse) and exc.code == "TLS_VERIFY_FAILED":
                    raise
                last = "TLS_UNAVAILABLE"
            if attempt + 1 < attempts:
                time.sleep(0.2)
        raise Refuse(last)

    def check_loaded_unit(self, unit, state):
        # systemd merges drop-ins from /run and vendor directories even when
        # our main file lives in /etc. Never start a foreign override as root.
        self.check_owned_files(state)
        _, raw = self.commands.run(["/usr/bin/systemctl", "show", unit,
                                     "--property=FragmentPath,DropInPaths,User,Group,LoadState"])
        values = dict(line.split("=", 1) for line in raw.decode("utf-8").splitlines() if "=" in line)
        expected_user = "sovagrid-tunnel" if unit == "sovagrid-agent-tunnel.service" else "sovagrid"
        expected_dropins = ({"/etc/systemd/system/sovagrid-agent.service.d/10-tunnel.conf"}
                            if unit == "sovagrid-agent.service" else set())
        require(values.get("FragmentPath") == "/etc/systemd/system/" + unit
                and set(shlex.split(values.get("DropInPaths", ""))) == expected_dropins
                and values.get("User") == expected_user and values.get("Group") == expected_user
                and values.get("LoadState") == "loaded", "OWNERSHIP_CONFLICT")

    def target_transport(self, value):
        self.platform()
        with self.locked("target"):
            self.check_cas("target", value["expected"])
            state = self.target_state(value["request_id"], required=True)
            self.same_identity(state, value)
            self.verify_credentials(state)
            transport = {key: value[key] for key in ("hub_host", "hub_port", "local_port", "hub_host_key", "hub_ca_pem")}
            require(state.get("transport") in (None, transport), "STATE_CONFLICT")
            current_services = self.services()
            if not current_services["tunnel"]:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                    try:
                        listener.bind(("127.0.0.1", value["local_port"]))
                    except OSError:
                        raise Refuse("PORT_BUSY") from None
            state["transport"] = transport
            state["local_port"] = value["local_port"]
            self.save_state("target", state)
            alias = "sovagrid-hub-" + digest(encode({key: transport[key] for key in ("hub_host", "hub_port")}))[:24]
            pin = (alias + " " + value["hub_host_key"] + "\n").encode("ascii")
            # Known_hosts/CA are public; the private key remains root-only and
            # is copied by systemd into this service UID's credential directory.
            self.owned_write("target", state, "/etc/sovagrid-agent-tunnel-public/known_hosts", pin, mode=0o644)
            self.owned_write("target", state, "/etc/sovagrid/hub-ca.pem", value["hub_ca_pem"].encode("ascii"), mode=0o644)
            # All substitutions below are fixed paths, canonical derived names,
            # literal IP addresses or validated decimal ports; no shell is used.
            ssh = ["/usr/bin/ssh", "-F", "/dev/null", "-nNT", "-o", "BatchMode=yes",
                   "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=yes",
                   "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "HostKeyAlias=" + alias,
                   "-o", "UserKnownHostsFile=/etc/sovagrid-agent-tunnel-public/known_hosts",
                   "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
                   "-o", "ExitOnForwardFailure=yes", "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
                   "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", "-i", "%d/ssh-key",
                   "-L", f"127.0.0.1:{value['local_port']}:127.0.0.1:8767", "-p", str(value["hub_port"]),
                   username(value["server_id"]) + "@" + value["hub_host"]]
            unit = ("# SOVAGRID_REMOTE_AGENT_HELPER_V1\n[Unit]\nDescription=SovaGrid Agent outbound Hub tunnel\n"
                    "Wants=network-online.target\nAfter=network-online.target\n[Service]\nType=simple\n"
                    "User=sovagrid-tunnel\nGroup=sovagrid-tunnel\n"
                    "LoadCredential=ssh-key:/etc/sovagrid-agent-tunnel/id_ed25519\n"
                    "ExecStart=" + " ".join(ssh) + "\nRestart=always\nRestartSec=5\nKillMode=control-group\n"
                    "UMask=0077\nNoNewPrivileges=true\nCapabilityBoundingSet=\nProtectSystem=strict\n"
                    "ProtectHome=true\nPrivateTmp=true\nPrivateDevices=true\nProtectKernelTunables=true\n"
                    "ProtectKernelModules=true\nProtectControlGroups=true\nRestrictSUIDSGID=true\nLockPersonality=true\n"
                    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nTasksMax=16\nMemoryMax=64M\n"
                    "[Install]\nWantedBy=multi-user.target\n").encode("ascii")
            self.owned_write("target", state, "/etc/systemd/system/sovagrid-agent-tunnel.service", unit, mode=0o644)
            template = self.files.read("/opt/sovagrid-agent/deploy/sovagrid-agent.service", limit=16384)
            self.owned_write("target", state, "/etc/systemd/system/sovagrid-agent.service", template, mode=0o644)
            self.owned_directory("target", state, "/etc/systemd/system/sovagrid-agent.service.d", 0o755)
            dropin = (b"# SOVAGRID_REMOTE_AGENT_HELPER_V1\n[Unit]\nWants=sovagrid-agent-tunnel.service\n"
                      b"After=sovagrid-agent-tunnel.service\n[Service]\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n")
            self.owned_write("target", state, "/etc/systemd/system/sovagrid-agent.service.d/10-tunnel.conf", dropin, mode=0o644)
            agent_gid = state["accounts"]["sovagrid"]["gid"]
            config = {"hub_url": f"https://localhost:{value['local_port']}", "server_id": value["server_id"],
                      "token_file": "/etc/sovagrid/agent.token", "ca_file": "/etc/sovagrid/hub-ca.pem",
                      "interval_seconds": 30, "allow_remote_commands": False, "allow_interactive_terminal": False,
                      "allow_file_manager": False, "allow_systemd_journal": False, "journal_units": [], "file_roots": {}}
            self.owned_write("target", state, "/etc/sovagrid/agent.json", encode(config) + b"\n", mode=0o640, gid=agent_gid)
            self.commands.run(["/usr/bin/systemd-analyze", "verify", "/etc/systemd/system/sovagrid-agent-tunnel.service",
                               "/etc/systemd/system/sovagrid-agent.service"])
            self.commands.run(["/usr/bin/systemctl", "daemon-reload"])
            self.check_loaded_unit("sovagrid-agent-tunnel.service", state)
            self.check_loaded_unit("sovagrid-agent.service", state)
            self.commands.run(["/usr/bin/systemctl", "enable", "--now", "sovagrid-agent-tunnel.service"])
            self.tls_ready(value["local_port"])
            require(self.services()["tunnel"], "SERVICE_FAILED")
            if state["phase"] == "prepared":
                state["phase"] = "transport_ready"
                self.save_state("target", state)
            return {"cas": self.cas("target"), "target": self.public_target(state), "services": self.services(), "tls_ready": True}

    def target_registered(self, value, *, activate=False):
        with self.locked("target"):
            self.check_cas("target", value["expected"])
            state = self.target_state(value["request_id"], required=True)
            self.same_identity(state, value)
            require(state["phase"] in ("transport_ready", "registered", "active"), "STATE_CONFLICT")
            self.verify_credentials(state)
            self.check_loaded_unit("sovagrid-agent.service", state)
            self.check_loaded_unit("sovagrid-agent-tunnel.service", state)
            self.tls_ready(state["local_port"], attempts=1)
            if activate:
                require(value["registration"]["state"] == "active" and all(self.services().values()), "SERVICE_FAILED")
                state["phase"] = "active"
                self.save_state("target", state)
            else:
                if state["phase"] != "active":
                    state["phase"] = "registered"
                    self.save_state("target", state)
                self.check_loaded_unit("sovagrid-agent.service", state)
                self.commands.run(["/usr/bin/systemctl", "enable", "--now", "sovagrid-agent.service"])
            return {"cas": self.cas("target"), "target": self.public_target(state), "services": self.services()}

    def hub_state(self):
        state = self.load_state("hub")
        if state is not None:
            require(state.get("kind") == "hub" and isinstance(state.get("enrollments"), dict)
                    and isinstance(state.get("accounts"), dict) and isinstance(state.get("owned_files"), dict), "STATE_CONFLICT")
        return state

    def hub_group(self, state):
        record = state.get("group")
        if record is None:
            try:
                grp.getgrnam(HUB_GROUP)
            except KeyError:
                pass
            else:
                raise Refuse("OWNERSHIP_CONFLICT")
            selected = None
            for candidate in range(64200, 65000):
                try:
                    grp.getgrgid(candidate)
                except KeyError:
                    selected = candidate
                    break
            require(selected is not None, "OWNERSHIP_CONFLICT")
            record = {"name": HUB_GROUP, "gid": selected}
            state["group"] = record
            self.save_state("hub", state)
        require(record.get("name") == HUB_GROUP and integer(record.get("gid"), 64200, 64999), "STATE_CONFLICT")
        try:
            group = grp.getgrnam(HUB_GROUP)
        except KeyError:
            self.commands.run(["/usr/sbin/groupadd", "--system", "--gid", str(record["gid"]), HUB_GROUP], capture=False)
            group = grp.getgrnam(HUB_GROUP)
        require(group.gr_gid == record["gid"] and not group.gr_mem, "OWNERSHIP_CONFLICT")
        return group

    def effective(self, name):
        require(isinstance(name, str) and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", name), "SSH_POLICY_CONFLICT")
        _, raw = self.commands.run(["/usr/sbin/sshd", "-T", "-C",
                                    "user=" + name + ",addr=127.0.0.1,host=localhost,laddr=127.0.0.1,lport=22"])
        result = {}
        for line in raw.decode("utf-8").splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                result[parts[0]] = parts[1]
        return result

    def enforce_tunnel_policy(self, name):
        actual = self.effective(name)
        expected = {"authenticationmethods": "publickey", "pubkeyauthentication": "yes",
                    "passwordauthentication": "no", "kbdinteractiveauthentication": "no",
                    "authorizedkeysfile": "/etc/ssh/sovagrid-tunnels/%u", "authorizedkeyscommand": "none",
                    "pubkeyacceptedalgorithms": "ssh-ed25519", "maxsessions": "0", "forcecommand": "/bin/false",
                    "allowtcpforwarding": "local", "permitopen": "127.0.0.1:8767", "permitlisten": "none",
                    "allowstreamlocalforwarding": "no", "allowagentforwarding": "no", "x11forwarding": "no",
                    "permittty": "no", "permittunnel": "no", "permituserrc": "no", "disableforwarding": "no"}
        require(all(actual.get(key) == value for key, value in expected.items()), "SSH_POLICY_CONFLICT")
        def matches(pattern, value):
            require(not any(char in pattern for char in "[],!"), "SSH_POLICY_CONFLICT")
            expression = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
            return re.fullmatch(expression, value) is not None
        allowed_users = actual.get("allowusers", "").split()
        denied_users = actual.get("denyusers", "").split()
        # Conditional user@host rules cannot be proven using the desktop's
        # address: the actual tunnel originates at the Agent. Never widen it.
        if allowed_users:
            require(any(matches(part.split("@", 1)[0], name)
                        and ("@" not in part or part.split("@", 1)[1] == "*") for part in allowed_users),
                    "SSH_POLICY_CONFLICT")
        require(not any(matches(part.split("@", 1)[0], name) for part in denied_users), "SSH_POLICY_CONFLICT")
        allowed_groups = actual.get("allowgroups", "").split()
        denied_groups = actual.get("denygroups", "").split()
        require(not allowed_groups or any(matches(part, HUB_GROUP) for part in allowed_groups), "SSH_POLICY_CONFLICT")
        require(not any(matches(part, HUB_GROUP) for part in denied_groups), "SSH_POLICY_CONFLICT")
        return actual

    def restore_policy(self, state, previous):
        raw = self.files.read(POLICY_PATH, missing=True)
        require(raw == POLICY and state["owned_files"].get(POLICY_PATH) == digest(POLICY), "CLEANUP_REQUIRED")
        if previous is None:
            self.files.path(POLICY_PATH).unlink()
            state["owned_files"].pop(POLICY_PATH, None)
        else:
            self.files.write(POLICY_PATH, previous, mode=0o644)
            state["owned_files"][POLICY_PATH] = digest(previous)
        self.save_state("hub", state)
        self.commands.run(["/usr/sbin/sshd", "-t"])
        self.commands.run(["/usr/bin/systemctl", "reload", "ssh.service"])

    def hub_authorize(self, value):
        with self.locked("hub"):
            self.check_cas("hub", value["expected"])
            state = self.hub_state()
            if state is None:
                require(not self.files.path(POLICY_PATH).exists()
                        and not self.files.path("/etc/ssh/sovagrid-tunnels").exists(), "OWNERSHIP_CONFLICT")
                state = {"protocol": 1, "kind": "hub", "created_at": int(time.time()), "group": None,
                         "enrollments": {}, "accounts": {}, "owned_files": {}, "owned_directories": {},
                         "pending_writes": {}}
                self.save_state("hub", state)
            eid, sid = value["enrollment_id"], value["server_id"]
            entry = state["enrollments"].get(eid)
            proposed = {"enrollment_id": eid, "server_id": sid, "username": username(sid),
                        "ssh_public_key": value["ssh_public_key"], "ssh_key_fingerprint": value["ssh_key_fingerprint"],
                        "revoked": False}
            if entry is not None:
                require(entry == proposed, "STATE_CONFLICT")
            else:
                enrollments = state["enrollments"]
                require(all(isinstance(item, dict) and type(item.get("revoked")) is bool
                            for item in enrollments.values()), "STATE_CONFLICT")
                require(len(enrollments) < MAX_HUB_ENROLLMENTS
                        and sum(not item["revoked"] for item in enrollments.values()) < MAX_HUB_ACTIVE_ENROLLMENTS,
                        "STATE_CONFLICT")
                require(not any(item["server_id"] == sid for item in state["enrollments"].values()), "STATE_CONFLICT")
                state["enrollments"][eid] = proposed
                self.save_state("hub", state)
            root_before = self.effective("root")
            # Do not silently inherit an unrelated global SSH key provider or
            # policies shadowing our Match: effective validation follows useradd.
            self.hub_group(state)
            self.account("hub", state, proposed["username"], role="hub-tunnel", group_name=HUB_GROUP, enrollment_id=eid)
            self.owned_directory("hub", state, "/var/empty/" + proposed["username"], 0o755)
            self.owned_directory("hub", state, "/etc/ssh/sovagrid-tunnels", 0o755)
            if self.files.inspect("/etc/ssh/sshd_config.d", directory=True, missing=True) is None:
                self.files.mkdir("/etc/ssh/sshd_config.d", 0o755)
            previous = self.files.read(POLICY_PATH, missing=True)
            self.owned_write("hub", state, POLICY_PATH, POLICY, mode=0o644)
            try:
                self.commands.run(["/usr/sbin/sshd", "-t"])
                self.enforce_tunnel_policy(proposed["username"])
                require(self.effective("root") == root_before, "SSH_POLICY_CONFLICT")
                self.commands.run(["/usr/bin/systemctl", "reload", "ssh.service"])
            except Refuse as exc:
                try:
                    self.restore_policy(state, previous)
                except (Refuse, OSError):
                    raise Refuse("CLEANUP_REQUIRED") from None
                raise Refuse("SSH_RELOAD_FAILED" if exc.code == "SERVICE_FAILED" else exc.code) from None
            key = ("restrict,port-forwarding,permitopen=\"127.0.0.1:8767\",command=\"/bin/false\" "
                   + value["ssh_public_key"] + " sovagrid:" + sid + ":" + eid + "\n").encode("ascii")
            self.owned_write("hub", state, "/etc/ssh/sovagrid-tunnels/" + proposed["username"], key, mode=0o644)
            self.enforce_tunnel_policy(proposed["username"])
            self.commands.run(["/usr/sbin/usermod", "--expiredate", "", proposed["username"]], capture=False)
            return {"cas": self.cas("hub"), "enrollment_id": eid, "server_id": sid,
                    "username": proposed["username"], "ssh_key_fingerprint": proposed["ssh_key_fingerprint"], "authorized": True}

    def hub_status(self, value):
        state = self.hub_state()
        entry = state["enrollments"].get(value["enrollment_id"]) if state else None
        if entry is None:
            return {"cas": self.cas("hub"), "enrollment_id": value["enrollment_id"], "server_id": value["server_id"],
                    "username": username(value["server_id"]), "ssh_key_fingerprint": None, "authorized": False}
        require(entry["server_id"] == value["server_id"], "STATE_CONFLICT")
        keypath = "/etc/ssh/sovagrid-tunnels/" + entry["username"]
        raw = self.files.read(keypath, missing=True)
        authorized = (not entry["revoked"] and raw is not None and digest(raw) == state["owned_files"].get(keypath))
        if authorized:
            self.enforce_tunnel_policy(entry["username"])
        return {"cas": self.cas("hub"), "enrollment_id": value["enrollment_id"], "server_id": value["server_id"],
                "username": entry["username"], "ssh_key_fingerprint": entry["ssh_key_fingerprint"], "authorized": authorized}

    def process_snapshot(self, uid):
        require(integer(uid, 1, 2**31 - 1), "OWNERSHIP_CONFLICT")
        require(sys.platform == "linux", "UNSUPPORTED_PLATFORM")
        result = {}
        entries = list(self.files.path("/proc").iterdir())
        require(len(entries) <= 32768, "CLEANUP_REQUIRED")
        for item in entries:
            if not item.name.isdecimal():
                continue
            try:
                # /proc is a kernel filesystem, not an enrollment-owned tree;
                # these fixed read-only files intentionally use separate logic.
                with (item / "status").open("rb") as stream:
                    status = stream.read(8193)
                if len(status) > 8192:
                    continue
                # A process comm may contain newlines. The genuine kernel
                # Uid line follows Name; take the last exact numeric field,
                # never a spoofed first line embedded in the process name.
                matches = re.findall(rb"(?m)^Uid:[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]*$", status)
                if not matches:
                    continue
                ids = matches[-1]
                if any(int(value) != uid for value in ids):
                    continue
                raw = (item / "stat").read_text()
                tail = raw.rsplit(")", 1)[1].split()
                result[int(item.name)] = (int(tail[19]), tail[0])
            except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError, StopIteration):
                continue
        return result

    def reconcile_account(self, side, state, name):
        record = state["accounts"][name]
        exact(record, {"uid", "gid", "home", "comment"} | ({"requested_uid"} if side == "hub" else set()))
        if side == "target":
            require(name in ("sovagrid", "sovagrid-tunnel"), "OWNERSHIP_CONFLICT")
            operation = state["identity"]["enrollment_id"]
            role = "agent" if name == "sovagrid" else "tunnel"
        else:
            matches = [item for item in state["enrollments"].values()
                       if item.get("username") == name and username(item["server_id"]) == name]
            require(len(matches) == 1, "OWNERSHIP_CONFLICT")
            operation = matches[0]["enrollment_id"]
            role = "hub-tunnel"
            require(integer(record["requested_uid"], HUB_UID_MIN, HUB_UID_MAX)
                    and record["uid"] in (None, record["requested_uid"]), "OWNERSHIP_CONFLICT")
        home = "/var/lib/sovagrid-agent" if role == "agent" else "/var/empty/" + name
        comment = "sovagrid-" + operation + "-" + role
        require(record["home"] == home and record["comment"] == comment
                and ((record["uid"] is None and record["gid"] is None)
                     or (integer(record["uid"], 1, 2**31 - 1) and integer(record["gid"], 1, 2**31 - 1))),
                "OWNERSHIP_CONFLICT")
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            # A missing name does not prove a numeric UID is unused: it may
            # have been reused or left orphan processes. Never signal it.
            if record["uid"] is not None:
                require(not self.process_snapshot(record["uid"]), "CLEANUP_REQUIRED")
            return None
        require(integer(entry.pw_uid, 1, 2**31 - 1) and integer(entry.pw_gid, 1, 2**31 - 1)
                and entry.pw_dir == home and entry.pw_gecos == comment and entry.pw_shell == "/usr/sbin/nologin"
                and set(os.getgrouplist(name, entry.pw_gid)) == {entry.pw_gid}, "OWNERSHIP_CONFLICT")
        if side == "hub":
            require(isinstance(state.get("group"), dict)
                    and entry.pw_gid == state["group"].get("gid")
                    and entry.pw_uid == record["requested_uid"], "OWNERSHIP_CONFLICT")
            group_name = HUB_GROUP
        else:
            group_name = name
        try:
            primary = grp.getgrnam(group_name)
        except KeyError:
            raise Refuse("OWNERSHIP_CONFLICT") from None
        require(primary.gr_gid == entry.pw_gid and not primary.gr_mem, "OWNERSHIP_CONFLICT")
        if record["uid"] is None:
            # The durable intent predates useradd. Exact full operation nonce,
            # home, shell and primary group reconcile a lost useradd response;
            # a matching name by itself never grants cleanup ownership.
            record.update(uid=entry.pw_uid, gid=entry.pw_gid)
            self.save_state(side, state)
        require(entry.pw_uid == record["uid"] and entry.pw_gid == record["gid"], "OWNERSHIP_CONFLICT")
        return entry

    def terminate_uid(self, name, record):
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            require(not self.process_snapshot(record["uid"]), "CLEANUP_REQUIRED")
            return
        require(integer(record.get("uid"), 1, 2**31 - 1) and integer(record.get("gid"), 1, 2**31 - 1)
                and entry.pw_uid == record["uid"] and entry.pw_gid == record["gid"]
                and entry.pw_gecos == record["comment"] and entry.pw_dir == record["home"]
                and entry.pw_shell == "/usr/sbin/nologin"
                and set(os.getgrouplist(name, entry.pw_gid)) == {entry.pw_gid}, "OWNERSHIP_CONFLICT")
        for sig, seconds in ((signal.SIGTERM, 2), (signal.SIGKILL, 2)):
            candidates = self.process_snapshot(entry.pw_uid)
            for pid, observed in candidates.items():
                if observed[1] == "Z":
                    continue
                current = self.process_snapshot(entry.pw_uid).get(pid)
                if current == observed:
                    fd = None
                    try:
                        if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
                            fd = os.pidfd_open(pid)
                            if self.process_snapshot(entry.pw_uid).get(pid) == observed:
                                signal.pidfd_send_signal(fd, sig)
                        else:
                            os.kill(pid, sig)
                    except ProcessLookupError:
                        pass
                    finally:
                        if fd is not None:
                            os.close(fd)
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                if not self.process_snapshot(entry.pw_uid):
                    return
                time.sleep(0.05)
        require(not self.process_snapshot(entry.pw_uid), "CLEANUP_REQUIRED")

    def remove_account(self, side, state, name):
        record = state["accounts"][name]
        entry = self.reconcile_account(side, state, name)
        if entry is not None:
            self.commands.run(["/usr/sbin/userdel", name], capture=False)
        # Target private groups can remain after userdel. An unrecorded group
        # without a user cannot be proven ours; preserve it and report cleanup.
        if side == "target":
            try:
                group = grp.getgrnam(name)
            except KeyError:
                group = None
            if group is not None:
                require(record["gid"] is not None and group.gr_gid == record["gid"]
                        and not group.gr_mem, "CLEANUP_REQUIRED")
                self.commands.run(["/usr/sbin/groupdel", name], capture=False)
        state["accounts"].pop(name, None)
        self.save_state(side, state)

    def check_owned_files(self, state):
        for path, expected in state.get("owned_files", {}).items():
            raw = self.files.read(path, limit=32 * 1024**2, missing=True)
            require(raw is None or digest(raw) == expected, "OWNERSHIP_CONFLICT")
            if raw is not None:
                info = self.files.inspect(path)
                require(state.get("file_metadata", {}).get(path) == {"mode": stat.S_IMODE(info.st_mode), "gid": info.st_gid},
                        "OWNERSHIP_CONFLICT")
        for path, intent in state.get("pending_writes", {}).items():
            raw = self.files.read(path, limit=32 * 1024**2, missing=True)
            require((digest(raw) if raw is not None else None) in (intent.get("old"), intent.get("new")),
                    "OWNERSHIP_CONFLICT")

    def unlink_owned(self, side, state, path):
        raw = self.files.read(path, limit=32 * 1024**2, missing=True)
        if raw is not None:
            expected = state.get("owned_files", {}).get(path)
            intent = state.get("pending_writes", {}).get(path)
            require(digest(raw) == expected or (intent and digest(raw) in (intent.get("old"), intent.get("new"))),
                    "OWNERSHIP_CONFLICT")
            self.files.path(path).unlink()
        state.get("owned_files", {}).pop(path, None)
        state.get("file_metadata", {}).pop(path, None)
        state.get("pending_writes", {}).pop(path, None)
        self.save_state(side, state)

    def hub_revoke(self, value):
        with self.locked("hub"):
            self.check_cas("hub", value["expected"])
            state = self.hub_state()
            require(state is not None, "STATE_CONFLICT")
            entry = state["enrollments"].get(value["enrollment_id"])
            require(entry is not None and entry["server_id"] == value["server_id"]
                    and entry["ssh_key_fingerprint"] == value["ssh_key_fingerprint"], "STATE_CONFLICT")
            name = entry["username"]
            # Stop new authentication before killing the already-open channels.
            self.unlink_owned("hub", state, "/etc/ssh/sovagrid-tunnels/" + name)
            if name in state["accounts"]:
                entry_account = self.reconcile_account("hub", state, name)
                if entry_account is not None:
                    self.terminate_uid(name, state["accounts"][name])
                self.remove_account("hub", state, name)
            home = "/var/empty/" + name
            if home in state["owned_directories"]:
                self.files.inspect(home, directory=True, missing=True)
                if self.files.path(home).exists():
                    try:
                        self.files.path(home).rmdir()
                    except OSError:
                        raise Refuse("CLEANUP_REQUIRED") from None
                state["owned_directories"].pop(home, None)
            entry["revoked"] = True
            self.save_state("hub", state)
            # Retain the exact harmless shared restriction/group. Other Agent
            # users and all unrelated/root SSH sessions remain untouched.
            return {"revoked": True, "cleanup_required": False}

    def target_remove(self, value):
        with self.locked("target"):
            self.check_cas("target", value["expected"])
            raw_state = self.load_state("target")
            if raw_state and raw_state.get("removed"):
                require(raw_state.get("identity") == {key: value[key] for key in ("request_id", "enrollment_id", "server_id")},
                        "STATE_CONFLICT")
                return {"removed": True, "cleanup_required": False}
            state = self.target_state(value["request_id"], required=True)
            self.same_identity(state, value)
            require(state["phase"] != "active", "ACTIVE_ENROLLMENT")
            require(state["phase"] != "registered" or value["registration"] is not None, "STATE_CONFLICT")
            self.check_owned_files(state)
            self.cleanup_keygen_scratch(state)
            state["cleanup_started"] = True
            self.save_state("target", state)
            for unit in ("sovagrid-agent.service", "sovagrid-agent-tunnel.service"):
                path = "/etc/systemd/system/" + unit
                if path in state["owned_files"]:
                    self.commands.run(["/usr/bin/systemctl", "disable", "--now", unit])
            for name in list(state["accounts"]):
                self.remove_account("target", state, name)
            for path in sorted(set(state["owned_files"]) | set(state["pending_writes"]), key=len, reverse=True):
                self.unlink_owned("target", state, path)
            for path in sorted(state["owned_directories"], key=len, reverse=True):
                if self.files.inspect(path, directory=True, missing=True) is not None:
                    try:
                        self.files.path(path).rmdir()
                    except OSError:
                        raise Refuse("CLEANUP_REQUIRED") from None
            self.commands.run(["/usr/bin/systemctl", "daemon-reload"])
            state.update(removed=True, source_files={}, owned_files={}, file_metadata={}, owned_directories={}, pending_writes={},
                         accounts={}, agent_token_sha256=None, ssh_public_key=None, ssh_key_fingerprint=None,
                         phase="prepared", local_port=None, transport=None)
            self.save_state("target", state)
            return {"removed": True, "cleanup_required": False}

    def target_features(self, action, value):
        # Feature changes require a newly selected, fully verified staged
        # bundle. The old installed helper/runtime and its source map stay put.
        require(self.executable != TARGET_HELPER, "SOURCE_UNTRUSTED")
        source_root = Path(self.executable).parents[2].as_posix()
        require(STAGE.fullmatch(source_root), "SOURCE_UNTRUSTED")
        source_sha, manifest = self.source("target")
        relative = "sovagrid-blueprint/deploy/agent_features.py"
        expected = manifest["sha256"].get(relative)
        require(isinstance(expected, str) and SHA.fullmatch(expected), "SOURCE_UNTRUSTED")
        path = source_root + "/" + relative
        raw = self.files.read(path, limit=256 * 1024)
        require(digest(raw) == expected, "SOURCE_CHANGED")
        namespace = {"__name__": "sovagrid_agent_feature_helper", "__file__": path}
        exec(compile(raw, path, "exec"), namespace)
        try:
            return namespace["FeatureManager"](self, source_sha, manifest, source_root).dispatch(action, value)
        except namespace["FeatureError"] as error:
            raise Refuse(error.code) from None

    def dispatch(self, action, value):
        value = validate_request(action, value)
        require(os.geteuid() == 0, "ROOT_REQUIRED")
        side = action.split("-", 1)[0]
        self.source(side)  # Fixed source/role verification before any writes.
        if action in FEATURE_ACTIONS:
            return self.target_features(action, value)
        if action.endswith("-preview"):
            return self.preview(side, value)
        if action == "target-prepare":
            return self.target_prepare(value)
        if action == "target-status":
            state = self.target_state(value["request_id"])
            return {"cas": self.cas("target"), "target": self.public_target(state),
                    "services": self.services() if state is not None else {"tunnel": False, "agent": False}}
        if action == "target-transport":
            return self.target_transport(value)
        if action in ("target-registered", "target-activate"):
            return self.target_registered(value, activate=action == "target-activate")
        if action == "target-remove":
            return self.target_remove(value)
        if action == "hub-authorize":
            return self.hub_authorize(value)
        if action == "hub-status":
            return self.hub_status(value)
        if action == "hub-revoke":
            return self.hub_revoke(value)
        raise Refuse("INVALID_REQUEST")


def tls_health(value):
    exact(value, {"protocol", "local_port"})
    require(value["protocol"] == 1 and type(value["protocol"]) is int and integer(value["local_port"], 1024, 65535))
    context = ssl.create_default_context(cafile="/etc/sovagrid/hub-ca.pem")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                         urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(f"https://localhost:{value['local_port']}/healthz", timeout=3) as response:
            raw = response.read(4097)
            require(response.status == 200 and len(raw) <= 4096, "TLS_UNAVAILABLE")
            result = json.loads(raw, object_pairs_hook=unique_object)
            require(isinstance(result, dict) and result.get("ok") is True, "TLS_UNAVAILABLE")
        return {"ok": True}
    except urllib.error.URLError as exc:
        raise Refuse("TLS_VERIFY_FAILED" if isinstance(exc.reason, ssl.SSLCertVerificationError) else "TLS_UNAVAILABLE") from None
    except ssl.SSLCertVerificationError:
        raise Refuse("TLS_VERIFY_FAILED") from None


def main(argv=None):
    os.umask(0o077)
    argv = sys.argv[1:] if argv is None else argv
    try:
        require(len(argv) == 1 and argv[0] in ACTIONS | {"_tls-health"})
        raw = sys.stdin.buffer.read(MAX_RPC + 1)
        require(len(raw) <= MAX_RPC)
        value = json.loads(raw, object_pairs_hook=unique_object)
        if argv[0] == "_tls-health":
            result = tls_health(value)
        else:
            result = {"protocol": 1, "ok": True, **Enrollment().dispatch(argv[0], value)}
        encoded = encode(result)
        require(len(encoded) <= MAX_RPC, "INTERNAL_ERROR")
        sys.stdout.buffer.write(encoded + b"\n")
        return 0
    except Refuse as exc:
        result = {"protocol": 1, "ok": False, "error": exc.code}
    except (ValueError, UnicodeError, TypeError, KeyError):
        result = {"protocol": 1, "ok": False, "error": "INVALID_REQUEST"}
    except Exception:
        result = {"protocol": 1, "ok": False, "error": "INTERNAL_ERROR"}
    sys.stdout.buffer.write(encode(result) + b"\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
