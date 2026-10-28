#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""SOVAGRID_REMOTE_AGENT_FEATURES_V1: staged, recoverable Agent opt-ins.

No credential, source projection, enrollment identity or tunnel is replaced.
Writable data and the PTY identity have a separate root-private ownership map.
"""
from __future__ import annotations

import hashlib
import ctypes
import errno
import json
import os
from pathlib import Path
import pwd
import grp
import re
import shlex
import stat
import sys
import tempfile
import uuid

STATE = "/var/lib/sovagrid-agent-enrollment/features.json"
CONFIG = "/etc/sovagrid/agent.json"
MANIFEST = "/opt/sovagrid-agent-installer/source-manifest.json"
SHELL_NAME = "sovagrid-shell"
SHELL_UID = 10003
SHELL_HOME = "/var/lib/sovagrid-shell"
SHELL_LOGIN_HOME = "/nonexistent"
SHELL_EXPIRY_DAY = 1
AGENT_HOME = "/var/lib/sovagrid-agent"
WORKSPACE = "/var/lib/sovagrid-agent/files"
SOCKET = "/run/sovagrid-terminal/control.sock"
UNITS = ("sovagrid-terminal-control.service", "sovagrid-terminal-control.socket")
SOURCE_PREFIX = "sovagrid-agent/"
SHA = re.compile(r"[0-9a-f]{64}\Z")
FLAGS = {"commands", "terminal", "files"}
TOKEN_DENIAL_PROBE = """import os
os.setgroups([])
os.setgid(10003)
os.setuid(10003)
try:
    fd = os.open('/etc/sovagrid/agent.token', os.O_RDONLY | os.O_NOFOLLOW)
except PermissionError:
    raise SystemExit(0)
else:
    os.close(fd)
    raise SystemExit(1)
"""


class FeatureError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(value, code="OWNERSHIP_CONFLICT"):
    if not value:
        raise FeatureError(code)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(value):
    return hashlib.sha256(value).hexdigest()


def canonical_id(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def current_flags(config):
    return {"commands": config["allow_remote_commands"], "terminal": config["allow_interactive_terminal"],
            "files": config["allow_file_manager"]}


def flags(value):
    need(isinstance(value, dict) and set(value) == FLAGS and all(type(item) is bool for item in value.values()), "STATE_CONFLICT")
    need(value["commands"] or not (value["terminal"] or value["files"]), "STATE_CONFLICT")
    return dict(value)


def publish_directory(source, destination):
    """Publish the recorded inode without ever replacing a competing path."""
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        rename = getattr(library, "renameat2", None)
        need(rename is not None, "STATE_CONFLICT")
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    elif sys.platform == "darwin":
        # Local filesystem fixtures use Darwin's equivalent RENAME_EXCL.
        rename = getattr(library, "renamex_np", None)
        need(rename is not None, "STATE_CONFLICT")
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(os.fsencode(source), os.fsencode(destination), 4)
    else:
        raise FeatureError("STATE_CONFLICT")
    if result != 0:
        code = ctypes.get_errno()
        raise FeatureError("OWNERSHIP_CONFLICT" if code in (errno.EEXIST, errno.ENOTEMPTY) else "STATE_CONFLICT")


class FeatureManager:
    def __init__(self, enrollment, source_sha, manifest, source_root):
        self.e = enrollment
        self.f = enrollment.files
        self.source_sha = source_sha
        self.manifest = manifest
        self.source_root = source_root
        self.core = self.state = self.agent = self.config = None

    def run(self, argv, **options):
        return self.e.commands.run(argv, timeout=options.pop("timeout", 20), limit=options.pop("limit", 8192), **options)

    def save(self):
        raw = encode(self.state) + b"\n"
        need(len(raw) <= 131072, "STATE_CONFLICT")
        self.f.write(STATE, raw)

    def load(self):
        self.core = self.e.load_state("target")
        need(isinstance(self.core, dict) and self.core.get("kind") == "target"
             and self.core.get("phase") == "active" and not self.core.get("removed"), "STATE_CONFLICT")
        identity = self.core.get("identity")
        need(isinstance(identity, dict) and set(identity) == {"request_id", "enrollment_id", "server_id"}
             and all(canonical_id(value) for value in identity.values()), "STATE_CONFLICT")
        need(isinstance(self.core.get("agent_token_sha256"), str) and SHA.fullmatch(self.core["agent_token_sha256"]), "STATE_CONFLICT")
        self.state = self.e.load_json(STATE, missing=True, limit=131072)
        if self.state is not None:
            need(self.state.get("protocol") == 1 and type(self.state["protocol"]) is int
                 and self.state.get("kind") == "target-features" and self.state.get("identity") == self.identity()
                 and self.state.get("phase") in ("applying", "ready")
                 and isinstance(self.state.get("owned_files"), dict) and isinstance(self.state.get("pending_writes"), dict)
                 and isinstance(self.state.get("data_directories"), dict), "STATE_CONFLICT")
            need(self.state.get("pending_features") is None if self.state["phase"] == "ready"
                 else isinstance(self.state.get("pending_features"), dict), "STATE_CONFLICT")
            if self.state.get("pending_features") is not None:
                flags(self.state["pending_features"])
                need(isinstance(self.state.get("config_base"), dict)
                     and isinstance(self.state.get("config_old_sha256"), str)
                     and SHA.fullmatch(self.state["config_old_sha256"]), "STATE_CONFLICT")
        self.verify_runtime()
        try:
            self.agent = pwd.getpwnam("sovagrid")
        except KeyError:
            raise FeatureError("OWNERSHIP_CONFLICT") from None
        account = self.core.get("accounts", {}).get("sovagrid", {})
        need(self.agent.pw_uid != 0 and self.agent.pw_gid != 0 and self.agent.pw_uid != SHELL_UID and self.agent.pw_gid != SHELL_UID
             and account.get("uid") == self.agent.pw_uid and account.get("gid") == self.agent.pw_gid
             and account.get("comment") == self.agent.pw_gecos and account.get("home") == self.agent.pw_dir
             and self.agent.pw_shell == "/usr/sbin/nologin"
             and set(os.getgrouplist("sovagrid", self.agent.pw_gid)) == {self.agent.pw_gid}, "OWNERSHIP_CONFLICT")
        self.e.verify_credentials(self.core)
        self.verify_core_owned()
        home = self.f.inspect(AGENT_HOME, directory=True)
        need(self.agent.pw_dir == AGENT_HOME and self.core.get("owned_directories", {}).get(AGENT_HOME) == 0o755
             and home.st_gid == os.getegid() and stat.S_IMODE(home.st_mode) == 0o755, "OWNERSHIP_CONFLICT")
        raw = self.f.read(CONFIG, limit=32768)
        config_info = self.f.inspect(CONFIG)
        need(stat.S_IMODE(config_info.st_mode) == 0o640 and config_info.st_gid == self.agent.pw_gid, "OWNERSHIP_CONFLICT")
        try:
            self.config = json.loads(raw)
        except (ValueError, UnicodeError):
            raise FeatureError("STATE_CONFLICT") from None
        self.validate_config(self.config)
        self.verify_artifacts()
        return self

    def identity(self):
        return {**self.core["identity"], "agent_token_sha256": self.core["agent_token_sha256"]}

    def verify_runtime(self):
        raw = self.f.read(MANIFEST, limit=524288)
        need(sha(raw) == self.core.get("source_manifest_sha256"), "SOURCE_CHANGED")
        try:
            old = json.loads(raw)
        except (ValueError, UnicodeError):
            raise FeatureError("SOURCE_CHANGED") from None
        projection = self.e.installed_projection(old)
        need(self.core.get("source_files") == projection, "SOURCE_CHANGED")
        self.e.verify_installed_files(self.core)
        wanted = {name: value for name, value in self.manifest["sha256"].items()
                  if name.startswith(SOURCE_PREFIX + "sovagrid_agent/") and name.endswith(".py")}
        installed = {name: value for name, value in old["sha256"].items()
                     if name.startswith(SOURCE_PREFIX + "sovagrid_agent/") and name.endswith(".py")}
        need(wanted and wanted == installed and old["sha256"].get(SOURCE_PREFIX + "deploy/sovagrid-agent.service")
             == self.manifest["sha256"].get(SOURCE_PREFIX + "deploy/sovagrid-agent.service"), "AGENT_UPDATE_REQUIRED")

    def validate_config(self, config):
        fields = {"hub_url", "server_id", "token_file", "ca_file", "interval_seconds", "allow_remote_commands",
                  "allow_interactive_terminal", "allow_file_manager", "allow_systemd_journal", "journal_units", "file_roots"}
        need(isinstance(config, dict) and set(config) == fields and config["server_id"] == self.core["identity"]["server_id"]
             and config["hub_url"] == "https://localhost:" + str(self.core.get("local_port"))
             and config["token_file"] == "/etc/sovagrid/agent.token" and config["ca_file"] == "/etc/sovagrid/hub-ca.pem"
             and not isinstance(config["interval_seconds"], bool) and isinstance(config["interval_seconds"], (int, float))
             and 5 <= config["interval_seconds"] <= 3600 and config["allow_systemd_journal"] is False
             and config["journal_units"] == [] and config["file_roots"] in ({}, {"workspace": WORKSPACE}), "STATE_CONFLICT")
        flags(current_flags(config))
        need(not config["allow_file_manager"] or config["file_roots"] == {"workspace": WORKSPACE}, "STATE_CONFLICT")

    def desired_config(self, desired):
        base = self.state["config_base"] if self.state and self.state["phase"] == "applying" else self.config
        result = dict(base)
        result.update(allow_remote_commands=desired["commands"], allow_interactive_terminal=desired["terminal"],
                      allow_file_manager=desired["files"])
        if desired["files"]:
            result["file_roots"] = {"workspace": WORKSPACE}
        return result

    def verify_core_owned(self):
        for path, expected in self.core.get("owned_files", {}).items():
            raw = self.f.read(path, limit=33554432)
            allowed = {expected}
            pending = self.core.get("pending_writes", {}).get(path)
            if pending is not None:
                need(path == CONFIG and self.state is not None and self.state["phase"] == "applying", "STATE_CONFLICT")
                desired = flags(self.state["pending_features"])
                need(pending.get("new") == sha(encode(self.desired_config(desired)) + b"\n")
                     and pending.get("old") == self.state["config_old_sha256"], "STATE_CONFLICT")
                allowed |= {pending["old"], pending["new"]}
            need(sha(raw) in allowed, "OWNERSHIP_CONFLICT")
            info = self.f.inspect(path)
            metadata = self.core.get("file_metadata", {}).get(path)
            need(metadata == {"mode": stat.S_IMODE(info.st_mode), "gid": info.st_gid}, "OWNERSHIP_CONFLICT")
        need(set(self.core.get("pending_writes", {})) <= {CONFIG}, "STATE_CONFLICT")

    def account_snapshot(self):
        record = self.state.get("shell_account") if self.state else None
        try:
            entry = pwd.getpwnam(SHELL_NAME)
        except KeyError:
            entry = None
        try:
            group = grp.getgrnam(SHELL_NAME)
        except KeyError:
            group = None
        if record is None:
            need(entry is None and group is None, "OWNERSHIP_CONFLICT")
            return None
        need(record.get("uid") == SHELL_UID and record.get("gid") == SHELL_UID
             and record.get("comment") == "sovagrid-features-" + self.core["identity"]["enrollment_id"], "STATE_CONFLICT")
        if group is not None:
            need(record.get("group_started") is True and group.gr_gid == SHELL_UID and not group.gr_mem, "OWNERSHIP_CONFLICT")
        if entry is not None:
            need(record.get("user_started") is True and group is not None and entry.pw_uid == SHELL_UID
                 and entry.pw_gid == SHELL_UID and entry.pw_dir == SHELL_LOGIN_HOME and entry.pw_gecos == record["comment"]
                 and entry.pw_shell == "/usr/sbin/nologin"
                 and set(os.getgrouplist(SHELL_NAME, entry.pw_gid)) == {entry.pw_gid}, "OWNERSHIP_CONFLICT")
            self.nonlogin_home()
            login_policy = self.shell_login_policy()
        need(self.state["phase"] == "applying" or entry is not None and group is not None, "OWNERSHIP_CONFLICT")
        return {"group": None if group is None else {"gid": group.gr_gid, "members": sorted(group.gr_mem)},
                "user": None if entry is None else {"uid": entry.pw_uid, "gid": entry.pw_gid, "home": entry.pw_dir,
                                                    "comment": entry.pw_gecos, "groups": sorted(os.getgrouplist(SHELL_NAME, entry.pw_gid)),
                                                    "login_policy": login_policy}}

    def nonlogin_home(self):
        # A runtime PTY HOME is writable; passwd HOME must never point there.
        # An existing /nonexistent must remain root-owned and nonwritable.
        self.f.inspect(SHELL_LOGIN_HOME, directory=True, missing=True)

    def shell_login_policy(self):
        code, raw = self.run(["/usr/bin/getent", "shadow", SHELL_NAME], check=False, limit=4096)
        try:
            lines = raw.decode("ascii").splitlines()
            fields = lines[0].split(":") if len(lines) == 1 else []
        except UnicodeError:
            fields = []
        # Never return, persist or hash a password field. Only this fixed
        # invalid-password marker and already-expired account are accepted.
        need(code == 0 and len(fields) == 9 and fields[0] == SHELL_NAME
             and fields[1] == "*NP*" and fields[7] == str(SHELL_EXPIRY_DAY), "OWNERSHIP_CONFLICT")
        return {"password_disabled": True, "expiry_day": SHELL_EXPIRY_DAY}

    def directory_snapshot(self, path, record):
        need(path in (WORKSPACE, SHELL_HOME) and isinstance(record, dict)
             and set(record) == {"uid", "gid", "mode", "ready", "publication"}
             and type(record.get("uid")) is int and type(record.get("gid")) is int and record.get("mode") == 0o700
             and type(record.get("ready")) is bool, "STATE_CONFLICT")
        expected_owner = (self.agent.pw_uid, self.agent.pw_gid) if path == WORKSPACE else (SHELL_UID, SHELL_UID)
        need((record["uid"], record["gid"]) == expected_owner, "STATE_CONFLICT")
        parent = str(Path(path).parent)
        self.f.inspect(parent, directory=True)
        publication = record["publication"]
        need(isinstance(publication, dict) and set(publication) == {"staging", "dev", "ino"}
             and type(publication["dev"]) is int and type(publication["ino"]) is int and publication["ino"] > 0
             and isinstance(publication["staging"], str) and str(Path(publication["staging"]).parent) == parent
             and re.fullmatch(r"\.sovagrid-feature-data\.[a-zA-Z0-9_-]{8}", Path(publication["staging"]).name), "STATE_CONFLICT")
        item = self.f.path(path)
        staging = self.f.path(publication["staging"])
        try:
            info = item.lstat()
        except FileNotFoundError:
            need(self.state["phase"] == "applying" and record.get("ready") is False, "OWNERSHIP_CONFLICT")
            try:
                info = staging.lstat()
            except FileNotFoundError:
                raise FeatureError("OWNERSHIP_CONFLICT") from None
            location = "staging"
        else:
            need(not staging.exists() and not staging.is_symlink(), "OWNERSHIP_CONFLICT")
            location = "published"
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700, "OWNERSHIP_CONFLICT")
        need((info.st_dev, info.st_ino) == (publication["dev"], publication["ino"]), "OWNERSHIP_CONFLICT")
        wanted = (record["uid"], record["gid"])
        actual = (info.st_uid, info.st_gid)
        need((location == "published" and actual == wanted) or self.state["phase"] == "applying" and record["ready"] is False
             and actual == (self.f.owner, os.getegid()), "OWNERSHIP_CONFLICT")
        return {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode), "dev": info.st_dev,
                "ino": info.st_ino, "location": location}

    def verify_artifacts(self):
        owned = self.state["owned_files"] if self.state else {}
        pending = self.state["pending_writes"] if self.state else {}
        need(set(owned) | set(pending) <= {"/etc/systemd/system/" + unit for unit in UNITS}, "STATE_CONFLICT")
        for unit in UNITS:
            path = "/etc/systemd/system/" + unit
            raw = self.f.read(path, limit=32768, missing=True)
            if path not in owned and path not in pending:
                need(raw is None, "OWNERSHIP_CONFLICT")
                continue
            allowed = {owned.get(path)}
            if path in pending:
                intent = pending[path]
                need(self.state["phase"] == "applying" and set(intent) == {"old", "new"}, "STATE_CONFLICT")
                allowed |= {intent["old"], intent["new"]}
            need((sha(raw) if raw is not None else None) in allowed, "OWNERSHIP_CONFLICT")
            if raw is not None:
                info = self.f.inspect(path)
                need(stat.S_IMODE(info.st_mode) == 0o644 and info.st_gid == os.getegid(), "OWNERSHIP_CONFLICT")
        self.account_snapshot()
        directories = self.state["data_directories"] if self.state else {}
        need(set(directories) <= {WORKSPACE, SHELL_HOME}, "STATE_CONFLICT")
        for path in (WORKSPACE, SHELL_HOME):
            if path not in directories:
                need(not self.f.path(path).exists() and not self.f.path(path).is_symlink(), "OWNERSHIP_CONFLICT")
            else:
                self.directory_snapshot(path, directories[path])

    def unit_policy(self, unit, *, optional=False):
        code, raw = self.run(["/usr/bin/systemctl", "show", unit,
                             "--property=FragmentPath,DropInPaths,User,Group,LoadState,UnitFileState"], check=False)
        values = dict(line.split("=", 1) for line in raw.decode("utf-8").splitlines() if "=" in line)
        if optional and values.get("LoadState") == "not-found":
            return values
        need(code == 0 and values.get("FragmentPath") == "/etc/systemd/system/" + unit
             and values.get("LoadState") == "loaded", "OWNERSHIP_CONFLICT")
        dropins = {"/etc/systemd/system/sovagrid-agent.service.d/10-tunnel.conf"} if unit == "sovagrid-agent.service" else set()
        need(set(shlex.split(values.get("DropInPaths", ""))) == dropins, "OWNERSHIP_CONFLICT")
        if unit.endswith(".service"):
            user = "sovagrid-tunnel" if unit == "sovagrid-agent-tunnel.service" else SHELL_NAME if unit in UNITS else "sovagrid"
            need(values.get("User") == user and values.get("Group") == user, "OWNERSHIP_CONFLICT")
        return values

    def services(self):
        base = self.e.services()
        states = []
        for unit in UNITS:
            code, _ = self.run(["/usr/bin/systemctl", "is-active", "--quiet", unit], check=False)
            states.append(code == 0)
        self._terminal_states = tuple(states)
        # A leftover broker OR socket still means terminal resources are live.
        # Successful enable separately requires both components to be active.
        return {**base, "terminal": any(states)}

    def terminal_ready(self, desired):
        return self._terminal_states == (desired, desired)

    def socket_snapshot(self):
        try:
            info = self.f.path(SOCKET).lstat()
        except FileNotFoundError:
            return None
        need(self.state is not None and ("/etc/systemd/system/sovagrid-terminal-control.socket" in self.state["owned_files"]
                                        or "/etc/systemd/system/sovagrid-terminal-control.socket" in self.state["pending_writes"]), "OWNERSHIP_CONFLICT")
        directory = self.f.inspect("/run/sovagrid-terminal", directory=True)
        need(directory.st_gid == os.getegid() and stat.S_IMODE(directory.st_mode) == 0o755, "OWNERSHIP_CONFLICT")
        need(stat.S_ISSOCK(info.st_mode) and info.st_uid == self.f.owner and info.st_gid == self.agent.pw_gid
             and stat.S_IMODE(info.st_mode) == 0o660, "OWNERSHIP_CONFLICT")
        return {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode), "dev": info.st_dev, "ino": info.st_ino,
                "directory": {"uid": directory.st_uid, "gid": directory.st_gid, "mode": stat.S_IMODE(directory.st_mode),
                              "dev": directory.st_dev, "ino": directory.st_ino}}

    def snapshot(self):
        self.e.platform()
        self.load()
        base = self.e.cas("target")
        policies = {unit: self.unit_policy(unit, optional=unit in UNITS)
                    for unit in ("sovagrid-agent.service", "sovagrid-agent-tunnel.service", *UNITS)}
        data = {path: self.directory_snapshot(path, record) for path, record in
                (self.state["data_directories"] if self.state else {}).items()}
        unit_files = {}
        for unit in UNITS:
            path = "/etc/systemd/system/" + unit
            raw = self.f.read(path, limit=32768, missing=True)
            unit_files[path] = sha(raw) if raw is not None else None
        expected = {"source_manifest_sha256": self.source_sha,
                    "features_sha256": sha(encode({"base": base["features_sha256"], "current": current_flags(self.config)})),
                    "policy_sha256": sha(encode({"base": base["policy_sha256"], "units": policies})),
                    "state_sha256": sha(encode({"base": base, "features": self.state, "units": unit_files,
                                                "data": data, "account": self.account_snapshot(), "socket": self.socket_snapshot()}))}
        return {"identity": self.identity(), "current": current_flags(self.config), "expected": expected,
                "source_manifest_sha256": self.source_sha, "recovery_required": self.state is not None and self.state["phase"] == "applying",
                "pending_features": self.state.get("pending_features") if self.state else None, "services": self.services()}

    def write_unit(self, unit):
        path = "/etc/systemd/system/" + unit
        relative = SOURCE_PREFIX + "deploy/" + unit
        raw = self.f.read(self.source_root + "/" + relative, limit=32768)
        need(sha(raw) == self.manifest["sha256"].get(relative), "SOURCE_CHANGED")
        old = self.f.read(path, limit=32768, missing=True)
        old_sha = sha(old) if old is not None else None
        wanted = sha(raw)
        pending = self.state["pending_writes"]
        if path in pending:
            need(pending[path]["new"] == wanted and old_sha in (pending[path]["old"], wanted), "OWNERSHIP_CONFLICT")
        else:
            need(old_sha == self.state["owned_files"].get(path), "OWNERSHIP_CONFLICT")
            pending[path] = {"old": old_sha, "new": wanted}
            self.save()
        if old_sha != wanted:
            self.f.write(path, raw, mode=0o644)
        self.state["owned_files"][path] = wanted
        del pending[path]
        self.save()

    def shell_available(self):
        self.nonlogin_home()
        for lookup, key in ((pwd.getpwnam, SHELL_NAME), (grp.getgrnam, SHELL_NAME),
                            (pwd.getpwuid, SHELL_UID), (grp.getgrgid, SHELL_UID)):
            try:
                lookup(key)
            except KeyError:
                pass
            else:
                raise FeatureError("OWNERSHIP_CONFLICT")

    def ensure_shell(self):
        if self.state.get("shell_account") is None:
            self.shell_available()
            self.state["shell_account"] = {"uid": SHELL_UID, "gid": SHELL_UID,
                "comment": "sovagrid-features-" + self.core["identity"]["enrollment_id"], "group_started": False, "user_started": False}
            self.save()
        record = self.state["shell_account"]
        try:
            grp.getgrnam(SHELL_NAME)
        except KeyError:
            record["group_started"] = True
            self.save()
            self.run(["/usr/sbin/groupadd", "--system", "--gid", str(SHELL_UID), SHELL_NAME], capture=False)
        try:
            pwd.getpwnam(SHELL_NAME)
        except KeyError:
            record["user_started"] = True
            self.save()
            # Ubuntu useradd --system ignores expiry. A normal explicit-UID
            # creation atomically denies forwarding-only SSH authentication.
            self.run(["/usr/sbin/useradd", "--uid", str(SHELL_UID), "--gid", str(SHELL_UID),
                      "--no-create-home", "--home-dir", SHELL_LOGIN_HOME, "--shell", "/usr/sbin/nologin", "--password", "*NP*",
                      "--expiredate", "1970-01-02",
                      "--comment", record["comment"], SHELL_NAME], capture=False)
        self.account_snapshot()
        self.ensure_data(SHELL_HOME, SHELL_UID, SHELL_UID)
        # PAM correctly refuses the expired account. Test kernel file access
        # by dropping UID/GID directly; the probe never reads token bytes.
        self.run(["/usr/bin/python3", "-I", "-B", "-c", TOKEN_DENIAL_PROBE], capture=False)

    def ensure_data(self, path, uid, gid):
        records = self.state["data_directories"]
        if path not in records:
            need(not self.f.path(path).exists() and not self.f.path(path).is_symlink(), "OWNERSHIP_CONFLICT")
            parent = str(Path(path).parent)
            self.f.inspect(parent, directory=True)
            staging = Path(tempfile.mkdtemp(prefix=".sovagrid-feature-data.", dir=self.f.path(parent)))
            fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                need(info.st_uid == self.f.owner and stat.S_IMODE(info.st_mode) == 0o700, "OWNERSHIP_CONFLICT")
                os.fchown(fd, self.f.owner, os.getegid())
                os.fsync(fd)
            finally:
                os.close(fd)
            self.sync_parent(path)
            # Losing a reply before this intent can leave an unused private
            # staging directory. It can never become the managed destination.
            records[path] = {"uid": uid, "gid": gid, "mode": 0o700, "ready": False,
                             "publication": {"staging": parent + "/" + staging.name, "dev": info.st_dev, "ino": info.st_ino}}
            self.save()
        record = records[path]
        need((record["uid"], record["gid"]) == (uid, gid), "STATE_CONFLICT")
        snapshot = self.directory_snapshot(path, record)
        item = self.f.path(path)
        if snapshot["location"] == "staging":
            publish_directory(self.f.path(record["publication"]["staging"]), item)
            self.sync_parent(path)
        fd = os.open(item, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            need((info.st_dev, info.st_ino) == (record["publication"]["dev"], record["publication"]["ino"]), "OWNERSHIP_CONFLICT")
            if (info.st_uid, info.st_gid) != (uid, gid):
                need(record["ready"] is False and (info.st_uid, info.st_gid) == (self.f.owner, os.getegid()), "OWNERSHIP_CONFLICT")
                os.fchown(fd, uid, gid)
            os.fchmod(fd, 0o700)
            os.fsync(fd)
        finally:
            os.close(fd)
        record["ready"] = True
        self.save()
        self.directory_snapshot(path, record)

    def sync_parent(self, path):
        fd = os.open(self.f.path(str(Path(path).parent)), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def socket_boundary(self):
        need(self.socket_snapshot() is not None, "SERVICE_FAILED")

    def apply(self, value):
        with self.e.locked("target"):
            before = self.snapshot()
            need(before["expected"] == value["expected"], "STALE_PREVIEW")
            need(value["server_id"] == before["identity"]["server_id"]
                 and value["enrollment_id"] == before["identity"]["enrollment_id"]
                 and value["agent_token_sha256"] == before["identity"]["agent_token_sha256"], "STATE_CONFLICT")
            desired = flags(value["features"])
            need(before["services"]["tunnel"], "SERVICE_FAILED")
            if self.state is not None and self.state["phase"] == "applying":
                need(self.state["pending_features"] == desired, "STATE_CONFLICT")
            elif before["current"] == desired and before["services"]["agent"] and self.terminal_ready(desired["terminal"]):
                return {**before, "desired": desired, "changed": False, "applied": True}
            else:
                if self.state is None:
                    self.state = {"protocol": 1, "kind": "target-features", "identity": self.identity(),
                                  "owned_files": {}, "pending_writes": {}, "data_directories": {}, "shell_account": None}
                self.state.update(phase="applying", pending_features=desired, config_base=dict(self.config),
                                  config_old_sha256=sha(self.f.read(CONFIG, limit=32768)))
                self.save()
            if desired["terminal"]:
                self.ensure_shell()
                for unit in UNITS:
                    self.write_unit(unit)
                self.run(["/usr/bin/systemd-analyze", "verify", *["/etc/systemd/system/" + unit for unit in UNITS]])
            if desired["files"]:
                self.ensure_data(WORKSPACE, self.agent.pw_uid, self.agent.pw_gid)
            config = self.desired_config(desired)
            self.validate_config(config)
            self.e.owned_write("target", self.core, CONFIG, encode(config) + b"\n", mode=0o640, gid=self.agent.pw_gid)
            self.run(["/usr/bin/systemctl", "daemon-reload"])
            if desired["terminal"]:
                for unit in UNITS:
                    self.unit_policy(unit)
                self.run(["/usr/bin/systemctl", "enable", "--now", "sovagrid-terminal-control.socket"])
                self.run(["/usr/bin/systemctl", "restart", "sovagrid-terminal-control.service"])
                self.socket_boundary()
            elif self.state["owned_files"]:
                self.run(["/usr/bin/systemctl", "disable", "--now", "sovagrid-terminal-control.socket"])
                self.run(["/usr/bin/systemctl", "stop", "sovagrid-terminal-control.service"])
            self.run(["/usr/bin/systemctl", "restart", "sovagrid-agent.service"], timeout=40)
            services = self.services()
            need(services["agent"] and services["tunnel"] and self.terminal_ready(desired["terminal"]), "SERVICE_FAILED")
            self.e.tls_ready(self.core["local_port"], attempts=1)
            self.state.update(phase="ready", pending_features=None, config_base=None, config_old_sha256=None)
            self.save()
            after = self.snapshot()
            return {**after, "desired": desired, "changed": True, "applied": True}

    def dispatch(self, action, value):
        if action == "target-features-apply":
            return self.apply(value)
        # The active enrollment already owns this lock. Shared, noncreating
        # reads cannot observe an exclusive writer between its durable intents.
        with self.e.locked("target", readonly=True):
            result = self.snapshot()
            need(result["identity"]["server_id"] == value["server_id"], "STATE_CONFLICT")
            if action == "target-features-preview":
                desired = flags(value["features"])
                if desired["terminal"] and (self.state is None or self.state.get("shell_account") is None):
                    self.shell_available()
                return {**result, "desired": desired, "changed": result["current"] != desired or result["recovery_required"]
                        or not result["services"]["agent"] or not self.terminal_ready(desired["terminal"])}
            return result
