# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Fixed-path, recoverable maintenance for an existing remote VPN broker.

This module never executes VPN commands, changes peer state, or restarts a VPN
container/interface. Source replacement pauses only management and inventory.
All filesystem access uses the source installer's owner/no-follow checks.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import subprocess

JOURNAL = "/var/lib/sovagrid/vpn-source/maintenance.json"
BLOCKER = "/var/lib/sovagrid/vpn-source/maintenance.blocked"
BLOCKER_BYTES = b"SOVAGRID_VPN_SOURCE_MAINTENANCE_V1\n"
GUARD_NAME = "90-sovagrid-vpn-source-maintenance.conf"
GUARD_BYTES = (b"# Managed by SovaGrid VPN source maintenance\n[Unit]\n"
               b"ConditionPathExists=!/var/lib/sovagrid/vpn-source/maintenance.blocked\n")
MAX_JOURNAL = 2 * 1024 * 1024
AMNEZIA = (
    ("sovagrid-amnezia-ctl", "/usr/local/bin/sovagrid-amnezia-ctl", 0o755),
    ("sovagrid-amnezia-broker", "/usr/local/libexec/sovagrid-amnezia-broker", 0o755),
    ("sovagrid-amnezia-control.service", "/etc/systemd/system/sovagrid-amnezia-control.service", 0o644),
    ("sovagrid-amnezia-control.socket", "/etc/systemd/system/sovagrid-amnezia-control.socket", 0o644),
)
WIREGUARD = (
    ("sovagrid-vpn-ctl", "/usr/local/bin/sovagrid-vpn-ctl", 0o755),
    ("sovagrid-vpn-broker", "/usr/local/libexec/sovagrid-vpn-broker", 0o755),
    ("sovagrid-vpn-control.service", "/etc/systemd/system/sovagrid-vpn-control.service", 0o644),
    ("sovagrid-vpn-control.socket", "/etc/systemd/system/sovagrid-vpn-control.socket", 0o644),
    ("sovagrid-vpn-status-agent.service", "/etc/systemd/system/sovagrid-vpn-status.service", 0o644),
    ("sovagrid-vpn-status.timer", "/etc/systemd/system/sovagrid-vpn-status.timer", 0o644),
)
FILES = AMNEZIA + WIREGUARD
WG_MARKER = "/etc/sovagrid-vpn/wireguard-control-install.json"
LOCKS = (
    "/etc/sovagrid-vpn/amnezia-install.lock",
    "/etc/sovagrid-vpn/wireguard-control-install.lock",
    "/var/lib/sovagrid-vpn/.lock",
    "/var/lib/sovagrid-vpn/amnezia-admin/.lock",
    "/var/lib/sovagrid-vpn/amnezia-provision/.lock",
    "/etc/sovagrid-vpn-routing/lock",
)
DATA_ROOTS = ("/etc/sovagrid-vpn", "/etc/wireguard", "/var/lib/sovagrid-vpn",
              "/etc/sovagrid-vpn-routing")
PENDING = (
    "/etc/sovagrid-vpn/wireguard-control-install.pending.json",
    "/var/lib/sovagrid-vpn/amnezia-provision/pending.json",
    "/var/lib/sovagrid-vpn/amnezia-admin/awg2.pending",
    "/var/lib/sovagrid-vpn/amnezia-admin/wireguard.pending",
    "/var/lib/sovagrid-vpn/amnezia-admin/awg2.settings-intent",
    "/var/lib/sovagrid-vpn/amnezia-admin/wireguard.settings-intent",
    "/etc/sovagrid-vpn-routing/pending.json",
)
UNIT_ORDER = ("sovagrid-amnezia-control.socket", "sovagrid-vpn-control.socket",
              "sovagrid-amnezia-control.service", "sovagrid-vpn-control.service",
              "sovagrid-vpn-status.service", "sovagrid-vpn-status.timer")
STOP_ORDER = ("sovagrid-vpn-status.timer", "sovagrid-amnezia-control.socket",
              "sovagrid-vpn-control.socket", "sovagrid-amnezia-control.service",
              "sovagrid-vpn-control.service", "sovagrid-vpn-status.service")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Maintenance:
    def __init__(self, installer, refuse):
        self.i, self.Refuse = installer, refuse

    def need(self, condition, code="STATE_CONFLICT"):
        if not condition:
            raise self.Refuse(code)

    def exists(self):
        return os.path.lexists(self.i.at(JOURNAL))

    def command(self, *args, timeout=30):
        try:
            result = self.i.run(list(args), check=False, capture_output=True, timeout=timeout,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
                     "PYTHONDONTWRITEBYTECODE": "1"})
        except (OSError, subprocess.TimeoutExpired):
            raise self.Refuse("OPERATION_FAILED") from None
        self.need(result.returncode == 0 and len(result.stdout) <= 65536 and
                  len(result.stderr) <= 65536, "OPERATION_FAILED")
        return result.stdout

    def unit(self, name):
        self.need(name in UNIT_ORDER)
        raw = self.command("/usr/bin/systemctl", "show", name, "--no-pager",
            "--property=ActiveState,UnitFileState,LoadState,FragmentPath,DropInPaths")
        try:
            fields = dict(line.split("=", 1) for line in raw.decode("utf-8").splitlines())
        except (ValueError, UnicodeError):
            raise self.Refuse("CONTROL_ACTIVE") from None
        own_guard = "/etc/systemd/system/" + name + ".d/" + GUARD_NAME
        during_maintenance = self.exists()
        self.need(set(fields) == {"ActiveState", "UnitFileState", "LoadState", "FragmentPath", "DropInPaths"}
            and fields["LoadState"] in (("loaded", "bad-setting", "error") if during_maintenance else ("loaded",))
            and fields["DropInPaths"] in (("", own_guard) if during_maintenance else ("",)) and
            fields["FragmentPath"] == "/etc/systemd/system/" + name and
            fields["ActiveState"] in (("active", "inactive", "failed") if during_maintenance else ("active", "inactive")) and
            fields["UnitFileState"] in ("enabled", "disabled", "static"), "CONTROL_ACTIVE")
        return {"active": fields["ActiveState"] == "active", "enablement": fields["UnitFileState"]}

    def protected(self):
        # Only hashes enter the journal. Private keys, profiles and peer tables
        # stay in their original files and are never copied into an RPC reply.
        result = {}
        ignored = set(LOCKS) | {WG_MARKER}
        for absolute in DATA_ROOTS:
            if self.i._inspect(absolute, directory=True, absent=True) is None:
                continue
            if absolute == "/etc/wireguard":
                # Active SovaGrid interfaces use root-owned configuration
                # symlinks. Hash link text without following it; their owned
                # targets are independently covered by /var/lib/sovagrid-vpn.
                for parent, directories, files in os.walk(self.i.at(absolute), followlinks=False):
                    relative_parent = "/" + Path(parent).relative_to(self.i.root).as_posix()
                    self.i._inspect(relative_parent, directory=True)
                    for name in list(directories) + files:
                        path = Path(parent) / name
                        full = "/" + path.relative_to(self.i.root).as_posix()
                        info = path.lstat()
                        self.need(info.st_uid == self.i.owner)
                        if stat.S_ISLNK(info.st_mode):
                            self.need(info.st_nlink == 1)
                        if stat.S_ISLNK(info.st_mode):
                            target = os.fsencode(os.readlink(path))
                            self.need(len(target) <= 4096)
                            after = path.lstat()
                            self.need((after.st_dev, after.st_ino, after.st_mtime_ns) ==
                                      (info.st_dev, info.st_ino, info.st_mtime_ns))
                            result[full] = {"symlink_sha256": sha(target), "uid": info.st_uid, "gid": info.st_gid}
                            if name in directories: directories.remove(name)
                        elif stat.S_ISDIR(info.st_mode):
                            self.i._inspect(full, directory=True)
                        else:
                            data = self.i._read(full)
                            result[full] = {"sha256": sha(data), "mode": stat.S_IMODE(info.st_mode),
                                            "uid": info.st_uid, "gid": info.st_gid}
                continue
            for name, digest in self.i._tree(absolute).items():
                full = absolute + "/" + name
                if full in ignored:
                    continue
                self.need(not name.endswith("/transaction.json") and full not in PENDING,
                          "RECOVERY_REQUIRED")
                info = self.i._inspect(full)
                result[full] = {"sha256": digest, "mode": stat.S_IMODE(info.st_mode),
                                "uid": info.st_uid, "gid": info.st_gid}
        return sha(canonical(result))

    def inspect(self, previous, source):
        self.need(not self.exists(), "RECOVERY_REQUIRED")
        self.need(previous is not None and previous["phase"] == "active")
        for absolute in PENDING:
            self.need(not os.path.lexists(self.i.at(absolute)), "RECOVERY_REQUIRED")
        families = []
        for family in (AMNEZIA, WIREGUARD):
            present = [os.path.lexists(self.i.at(absolute)) for _, absolute, _ in family]
            if any(present):
                self.need(all(present), "CONTROL_ACTIVE")
                families.extend(family)
        enable_markers = ("/etc/sovagrid-vpn/amnezia-control.enabled",
                          "/etc/sovagrid-vpn/amnezia-wireguard-control.enabled",
                          "/etc/sovagrid-vpn/amnezia-awg-settings.enabled")
        armed = False
        for path in enable_markers:
            if os.path.lexists(self.i.at(path)):
                self.need(self.i._read(path, private=True, limit=8) == b"enabled\n", "CONTROL_ACTIVE")
                armed = True
        provisioned = os.path.lexists(self.i.at("/var/lib/sovagrid-vpn/amnezia-provision/state.json"))
        self.need(not armed or all(item in families for item in AMNEZIA), "CONTROL_ACTIVE")
        if not families and not provisioned:
            return None
        old_files, new_files, units = {}, {}, {}
        for name, absolute, mode in families:
            raw = self.i._read(absolute, limit=262144)
            self.need(stat.S_IMODE(self.i._inspect(absolute).st_mode) == mode and
                sha(raw) == previous["source_files"].get("deploy/" + name), "CONTROL_ACTIVE")
            candidate = source.get("deploy/" + name)
            self.need(type(candidate) is bytes and len(candidate) <= 262144, "SOURCE_UNTRUSTED")
            old_files[absolute] = {"data": base64.b64encode(raw).decode(), "mode": mode}
            new_files[absolute] = {"data": base64.b64encode(candidate).decode(), "mode": mode}
            if absolute.startswith("/etc/systemd/system/"):
                units[Path(absolute).name] = self.unit(Path(absolute).name)
        # A running oneshot inventory cannot be captured as a persistent state.
        self.need(not units.get("sovagrid-vpn-status.service", {}).get("active"), "BUSY")
        if any(item in families for item in WIREGUARD):
            raw = self.i._read(WG_MARKER, limit=8192, private=True)
            try:
                marker = json.loads(raw)
            except (ValueError, UnicodeError):
                raise self.Refuse("CONTROL_ACTIVE") from None
            old_hashes = {absolute: sha(base64.b64decode(old_files[absolute]["data"]))
                          for _, absolute, _ in WIREGUARD}
            self.need(type(marker) is dict and set(marker) == {"schema_version", "files"} and
                      marker["schema_version"] == 2 and marker["files"] == old_hashes, "CONTROL_ACTIVE")
            new_marker = {"schema_version": 2, "files": {
                absolute: sha(source["deploy/" + name]) for name, absolute, _ in WIREGUARD}}
            old_files[WG_MARKER] = {"data": base64.b64encode(raw).decode(), "mode": 0o600}
            new_files[WG_MARKER] = {"data": base64.b64encode(canonical(new_marker) + b"\n").decode(), "mode": 0o600}
        policy_path = "/etc/sovagrid-vpn-routing/policy.json"
        if os.path.lexists(self.i.at(policy_path)):
            try:
                policy = json.loads(self.i._read(policy_path, limit=8192, private=True))
                self.need(type(policy) is dict and policy.get("pending_remove") == [], "RECOVERY_REQUIRED")
            except (ValueError, UnicodeError):
                raise self.Refuse("STATE_CONFLICT") from None
        dropin_dirs = {}
        for name in units:
            absolute = "/etc/systemd/system/" + name + ".d"
            exists = self.i._inspect(absolute, directory=True, absent=True) is not None
            self.need(not exists or not list(self.i.at(absolute).iterdir()), "CONTROL_ACTIVE")
            dropin_dirs[name] = exists
        snapshot = {"old_files": old_files, "new_files": new_files,
                    "units": units, "dropin_dirs": dropin_dirs, "protected_sha256": self.protected()}
        return snapshot

    @contextmanager
    def locks(self):
        descriptors = []
        try:
            for absolute in LOCKS:
                parent = str(Path(absolute).parent)
                # These exact private control directories are allowed only after
                # explicit maintenance confirmation, never during preview.
                self.i._mkdir(parent, 0o700)
                fd = os.open(self.i.at(absolute), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                descriptors.append(fd)
                info = os.fstat(fd)
                self.need(stat.S_ISREG(info.st_mode) and info.st_uid == self.i.owner and
                          info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                          "OWNERSHIP_CONFLICT")
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise self.Refuse("BUSY") from None
                observed = self.i.at(absolute).lstat()
                self.need((observed.st_dev, observed.st_ino) == (info.st_dev, info.st_ino), "OWNERSHIP_CONFLICT")
            yield
        finally:
            for fd in reversed(descriptors):
                os.close(fd)

    def save(self, value, phase=None):
        if phase is not None:
            value = {**value, "phase": phase}
        raw = canonical(value)
        self.need(len(raw) <= MAX_JOURNAL)
        self.i._write(JOURNAL, raw)
        self.i.checkpoint("maintenance:" + value["phase"])
        return value

    def read(self):
        raw = self.i._read(JOURNAL, limit=MAX_JOURNAL, private=True)
        try:
            value = json.loads(raw)
            self.need(type(value) is dict and set(value) == {"protocol", "phase", "snapshot", "pending"}
                and value["protocol"] == 1 and value["phase"] in
                ("prepared", "stopped", "files_switched", "runtime_started", "committed") and
                canonical(value) == raw)
            self.i._validate_state(value["pending"])
            self.need(value["pending"]["phase"] == "pending")
            snap = value["snapshot"]
            self.need(type(snap) is dict and set(snap) == {"old_files", "new_files", "units", "dropin_dirs", "protected_sha256"}
                and set(snap["old_files"]) == set(snap["new_files"]) and
                set(snap["old_files"]) <= {absolute for _, absolute, _ in FILES} | {WG_MARKER}
                and set(snap["units"]) <= set(UNIT_ORDER) and
                set(snap["dropin_dirs"]) == set(snap["units"]) and
                all(type(item) is bool for item in snap["dropin_dirs"].values()) and
                len(snap["protected_sha256"]) == 64)
            for group in ("old_files", "new_files"):
                for absolute, item in snap[group].items():
                    expected_mode = 0o600 if absolute == WG_MARKER else next(mode for _, name, mode in FILES if name == absolute)
                    self.need(type(item) is dict and set(item) == {"data", "mode"} and item["mode"] == expected_mode)
                    self.need(len(self.decode(item)) <= 262144)
            for unit, state in snap["units"].items():
                self.need(type(state) is dict and set(state) == {"active", "enablement"}
                          and type(state["active"]) is bool and state["enablement"] in ("enabled", "disabled", "static"))
        except (ValueError, TypeError, KeyError, StopIteration, UnicodeError):
            raise self.Refuse("STATE_CONFLICT") from None
        return value

    def decode(self, item):
        try:
            raw = base64.b64decode(item["data"], validate=True)
        except (ValueError, TypeError):
            raise self.Refuse("STATE_CONFLICT") from None
        self.need(base64.b64encode(raw).decode() == item["data"])
        return raw

    def check_files(self, snapshot):
        self.check_barriers(snapshot)
        for absolute, old in snapshot["old_files"].items():
            current = self.i._read(absolute, limit=262144)
            self.need(stat.S_IMODE(self.i._inspect(absolute).st_mode) == old["mode"] and
                current in (self.decode(old), self.decode(snapshot["new_files"][absolute])), "STATE_CONFLICT")
        self.need(self.protected() == snapshot["protected_sha256"], "STATE_CONFLICT")
        for name, old in snapshot["units"].items():
            self.need(self.unit(name)["enablement"] == old["enablement"], "STATE_CONFLICT")

    def check_barriers(self, snapshot):
        if os.path.lexists(self.i.at(BLOCKER)):
            self.need(self.i._read(BLOCKER, private=True) == BLOCKER_BYTES)
        for name, existed in snapshot["dropin_dirs"].items():
            directory = "/etc/systemd/system/" + name + ".d"
            info = self.i._inspect(directory, directory=True, absent=True)
            if info is None:
                self.need(not existed)
                continue
            self.need(stat.S_IMODE(info.st_mode) == 0o755)
            for part in self.i.at(directory).iterdir():
                if part.name != GUARD_NAME:
                    # An uncatchable exit inside atomic_write can leave only
                    # this helper's private temporary file. Its bytes must be
                    # an exact prefix of the fixed public guard template.
                    self.need(re.fullmatch(r"\.sg-vpn-[0-9a-f]{32}", part.name) is not None)
                    absolute_temp = directory + "/" + part.name
                    self.need(stat.S_IMODE(self.i._inspect(absolute_temp).st_mode) == 0o644 and
                              GUARD_BYTES.startswith(self.i._read(absolute_temp, limit=len(GUARD_BYTES))))
            absolute = directory + "/" + GUARD_NAME
            if os.path.lexists(self.i.at(absolute)):
                self.need(stat.S_IMODE(self.i._inspect(absolute).st_mode) == 0o644 and
                          self.i._read(absolute, limit=4096) == GUARD_BYTES)

    def barriers(self, snapshot):
        self.check_barriers(snapshot)
        self.i._write(BLOCKER, BLOCKER_BYTES)
        for name in snapshot["units"]:
            directory = "/etc/systemd/system/" + name + ".d"
            self.i._mkdir(directory, 0o755)
            self.i._write(directory + "/" + GUARD_NAME, GUARD_BYTES, mode=0o644)
            self.i.checkpoint("maintenance:guard:" + name)
        if snapshot["units"]:
            self.command("/usr/bin/systemctl", "daemon-reload")

    def unblock(self):
        if os.path.lexists(self.i.at(BLOCKER)):
            self.need(self.i._read(BLOCKER, private=True) == BLOCKER_BYTES)
            self.i.at(BLOCKER).unlink()
            self.i._fsync_dir(str(Path(BLOCKER).parent))

    def remove_barriers(self, snapshot):
        self.check_barriers(snapshot)
        self.unblock()
        for name, existed in snapshot["dropin_dirs"].items():
            directory = "/etc/systemd/system/" + name + ".d"
            absolute = directory + "/" + GUARD_NAME
            if os.path.lexists(self.i.at(absolute)):
                self.i.at(absolute).unlink()
                self.i._fsync_dir(directory)
            if os.path.lexists(self.i.at(directory)):
                for temporary in self.i.at(directory).iterdir():
                    # check_barriers above already bound name, owner and bytes.
                    temporary.unlink()
                self.i._fsync_dir(directory)
            if not existed and os.path.lexists(self.i.at(directory)):
                self.i.at(directory).rmdir()
                self.i._fsync_dir("/etc/systemd/system")
        if snapshot["units"]:
            self.command("/usr/bin/systemctl", "daemon-reload")

    def stop(self, snapshot):
        for name in STOP_ORDER:
            if name in snapshot["units"]:
                self.command("/usr/bin/systemctl", "stop", name)
        for name in snapshot["units"]:
            self.need(not self.unit(name)["active"], "OPERATION_FAILED")

    def install_files(self, value):
        snapshot = value["snapshot"]
        self.check_files(snapshot)
        for absolute, item in snapshot["new_files"].items():
            self.i._write(absolute, self.decode(item), mode=item["mode"])
            self.i.checkpoint("maintenance:file:" + Path(absolute).name)
        return self.save(value, "files_switched")

    def restart(self, snapshot):
        units = snapshot["units"]
        if units:
            self.command("/usr/bin/systemd-analyze", "verify", *(
                str(self.i.at("/etc/systemd/system/" + name)) for name in units))
            self.command("/usr/bin/systemctl", "daemon-reload")
        # Imports check candidate syntax and available dependencies without any
        # CLI, network change, automatic recovery, or peer mutation.
        self.command("/usr/bin/python3", "-B", "-I", "-c",
            "import sys;sys.path.insert(0,'/opt/sovagrid-vpn');"
            "import sovagrid_vpn.amnezia_control,sovagrid_vpn.managed,sovagrid_vpn.amnezia_provision")
        self.unblock()
        self.i.checkpoint("maintenance:unblocked")
        for name in UNIT_ORDER:
            if units.get(name, {}).get("active"):
                self.command("/usr/bin/systemctl", "start", name)
        for name, old in units.items():
            current = self.unit(name)
            self.need(current["enablement"] == old["enablement"] and
                      (not old["active"] or current["active"]), "OPERATION_FAILED")
        self.need(self.protected() == snapshot["protected_sha256"], "STATE_CONFLICT")

    def remove(self):
        self.i._inspect(JOURNAL, private=True)
        self.i.at(JOURNAL).unlink()
        self.i._fsync_dir(str(Path(JOURNAL).parent))

    def check_source_transaction(self, pending):
        previous = pending["previous"]
        self.need(previous is not None)
        for absolute, key in (("/opt/sovagrid-src/sovagrid-vpn", "source_files"),
                              ("/opt/sovagrid-vpn/sovagrid_vpn", "package_files")):
            if os.path.lexists(self.i.at(absolute)):
                self.need(self.i._tree(absolute) in (pending[key], previous[key]))
        stage = pending["stage"]
        if not os.path.lexists(self.i.at(stage)):
            return
        self.i._inspect(stage, directory=True, private=True)
        known = {"new_source": pending["source_files"], "new_package": pending["package_files"],
                 "old_source": previous["source_files"], "old_package": previous["package_files"],
                 "discard_source": pending["source_files"], "discard_package": pending["package_files"]}
        self.need({part.name for part in self.i.at(stage).iterdir()} <= set(known))
        for name, expected in known.items():
            if os.path.lexists(self.i.at(stage + "/" + name)):
                actual = self.i._tree(stage + "/" + name)
                for relative, digest in actual.items():
                    if relative in expected:
                        self.need(expected[relative] == digest)
                        continue
                    part = Path(relative)
                    self.need(name.startswith("new_") and
                        re.fullmatch(r"\.sg-vpn-[0-9a-f]{32}", part.name) is not None)
                    absolute = stage + "/" + name + "/" + relative
                    self.i._read(absolute)
                    candidates = pending["source_files"] if name == "new_source" else pending["package_files"]
                    # Completed staged files are checked by hash. A partial
                    # atomic temp is safe to discard only within this exact
                    # private new tree, never from the live or previous tree.
                    self.need(stat.S_IMODE(self.i._inspect(absolute).st_mode) == 0o644 and
                              any(Path(key).parent == part.parent for key in candidates))

    def rollback(self, value):
        snapshot = value["snapshot"]
        self.check_files(snapshot)  # Refuse every external edit before touching a unit.
        self.check_source_transaction(value["pending"])
        self.barriers(snapshot)
        self.stop(snapshot)
        for absolute, item in snapshot["old_files"].items():
            self.i._write(absolute, self.decode(item), mode=item["mode"])
        self.i._rollback(value["pending"])
        self.restart(snapshot)
        self.remove_barriers(snapshot)
        self.remove()

    def cleanup_committed(self, value):
        snap = value["snapshot"]
        self.check_files(snap)
        for absolute, item in snap["new_files"].items():
            self.need(self.i._read(absolute, limit=262144) == self.decode(item))
        state, _ = self.i._state()
        self.need(state is not None and state["phase"] == "active" and
                  state["source_files"] == value["pending"]["source_files"] and
                  state["package_files"] == value["pending"]["package_files"])
        self.i._active_files(state)
        stage = value["pending"]["stage"]
        if os.path.lexists(self.i.at(stage)):
            self.need({item.name for item in self.i.at(stage).iterdir()} <= {"old_source", "old_package"})
            for name, key in (("old_source", "source_files"), ("old_package", "package_files")):
                if os.path.lexists(self.i.at(stage + "/" + name)):
                    actual = self.i._tree(stage + "/" + name)
                    expected = value["pending"]["previous"][key]
                    self.need(set(actual) <= set(expected) and all(expected[part] == item for part, item in actual.items()))
            self.i._remove_stage(stage)
        self.i._save_state({**state, "garbage_stage": None})
        self.remove_barriers(snap)
        self.remove()

    def recover(self):
        value = self.read()
        with self.locks():
            if value["phase"] == "committed":
                self.cleanup_committed(value)
            else:
                self.rollback(value)
        return {"protocol": 1, "recovered": True}
