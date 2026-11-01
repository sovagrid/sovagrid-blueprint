#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Destructive portable-restore gate ONLY for a disposable GitHub Ubuntu VM.

Run after the combined signed-transition test. Three real portable snapshots
are created before removing the known CI installation. The private input pairs
and an independently verified /root source copy survive every case. The final
case intentionally retains recovery_required and its fence after a real Hub
database write; no later backend checks may run on that VM.

No production code bytes, release signatures, public addresses or accounts are
changed. Before public enablement the apply flag is enabled only in the child
process's memory. Once the pinned release enables it, the positive case uses
the public receiver and a detached systemd worker without changing the flag.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import grp
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from unittest.mock import patch
import uuid

sys.dont_write_bytecode = True


SOURCE = Path("/opt/sovagrid-src")
DOCKER = ("/usr/bin/docker", "--host", "unix:///var/run/docker.sock")
SHA = re.compile(r"[0-9a-f]{64}\Z")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
PREFIX = "sovagrid-portable-restore-ci-"
ROOTS = frozenset((
    "/etc/sovagrid", "/etc/sovagrid-hub", "/etc/sovagrid-vpn", "/etc/sovagrid-journal",
    "/etc/sovagrid-service", "/etc/sovagrid-vpn-routing",
    "/var/lib/sovagrid", "/var/lib/sovagrid-agent", "/var/lib/sovagrid-shell",
    "/var/lib/sovagrid-containers", "/var/lib/sovagrid-vpn",
    "/var/lib/sovagrid-hub-tunnels",
    "/var/lib/sovagrid-host-backup-operations", "/opt/sovagrid-src",
    "/var/cache/sovagrid-web-restores",
    "/opt/sovagrid-agent", "/opt/sovagrid-vpn", "/opt/sovagrid-candidates",
    "/usr/local/bin/sovagrid-vpn-ctl", "/usr/local/libexec/sovagrid-vpn-broker",
    "/etc/sysctl.d/70-sovagrid-vpn-routing.conf",
    "/etc/sovagrid-service-setup.lock",
))
PRESERVED = frozenset(("/var/lib/sovagrid-host-backups", "/var/lib/sovagrid-host-image-exports"))


def fixture_module():
    spec = importlib.util.spec_from_file_location("sovagrid_ci_restore_fixture",
        Path(__file__).with_name("portable_restore_fixture.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expected_manifest():
    value = os.environ.get("SOVAGRID_RESTORE_EXPECTED_MANIFEST", "")
    need(SHA.fullmatch(value) is not None, "requires the artifact-pinned source manifest")
    return value


def need(condition, reason):
    if not condition:
        raise RuntimeError("portable restore VM: " + reason)


def guard():
    need(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true" and
         os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
         os.environ.get("RUNNER_OS") == "Linux" and
         os.environ.get("SOVAGRID_PORTABLE_RESTORE_DISPOSABLE") == "1",
         "requires explicit disposable GitHub-hosted root Linux selection")
    values = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines()
                  if "=" in line and not line.startswith("#"))
    need(values.get("ID", "").strip('"') == "ubuntu" and
         Path("/proc/1/comm").read_text().strip() == "systemd", "requires Ubuntu with native systemd")
    need(shutil.rmtree.avoids_symlink_attacks, "safe descriptor-based tree removal is unavailable")


def command(*args, timeout=120, accepted=(0,)):
    environment = {key: value for key, value in os.environ.items()
                   if key not in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_TLS", "DOCKER_CERT_PATH")}
    environment.update(PATH="/usr/sbin:/usr/bin:/sbin:/bin", LC_ALL="C")
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False, env=environment)
    need(result.returncode in accepted, Path(args[0]).name + " failed with status " + str(result.returncode))
    need(len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 1024 * 1024, "oversized tool output")
    return result


def text(*args, **kwargs):
    return command(*args, **kwargs).stdout.decode("ascii").strip()


def load(bundle, filename, name):
    location = bundle / "sovagrid-blueprint/deploy" / filename
    spec = importlib.util.spec_from_file_location(name, location)
    need(spec is not None and spec.loader is not None, "missing verified helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def api(bundle):
    restore = load(bundle, "host_restore.py", "sovagrid_ci_portable_restore")
    core = load(bundle, "portable_restore_apply.py", "sovagrid_ci_portable_core")
    runtime = load(bundle, "portable_restore_runtime.py", "sovagrid_ci_portable_runtime")
    return restore, core, runtime


@contextlib.contextmanager
def enabled_vm_api(bundle):
    """One verified core binding, retaining the release's real public gate."""
    guard()
    verified_bundle(bundle)  # Hash original production bytes before importing.
    restore, core, runtime = api(bundle)
    need(type(core.APPLY_ENABLED) is bool, "invalid production apply capability")
    real_sibling = restore._sibling

    def sibling(filename, name):
        if filename == "portable_restore_apply.py":
            return core
        if filename == "portable_restore_runtime.py":
            return runtime
        return real_sibling(filename, name)

    with (patch.object(restore, "_sibling", side_effect=sibling),
          patch.object(core, "APPLY_ENABLED", True)):
        yield restore, core, runtime


def private_json(filename, maximum=512 * 1024):
    with os.fdopen(os.open(filename, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size <= maximum,
             "unsafe private fixture metadata")
        raw = stream.read(maximum + 1)
        need(len(raw) == info.st_size, "fixture metadata changed")
    return json.loads(raw)


def verified_bundle(bundle):
    expected = expected_manifest()
    need(bundle.is_absolute() and bundle.is_relative_to("/root") and
         bundle.parent.name.startswith(PREFIX) and not bundle.is_symlink(), "unexpected verifier location")
    cursor = Path("/")
    for part in bundle.parts[1:]:
        cursor /= part
        info = cursor.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
             "unsafe verifier parent")
    fixture_module().source_pin(bundle, expected)
    return expected


def initial_names(root, records, source):
    """The fresh installer fixture has closed children before its first seal."""
    exact = {
        "/var/lib/sovagrid-agent": {"", "files"}, "/var/lib/sovagrid-shell": {""},
        "/opt/sovagrid-candidates": {"", ".lock"},
        "/var/lib/sovagrid-host-backup-operations": {"", ".lock"},
        "/var/cache/sovagrid-web-restores": {"", "imports"},
        "/var/lib/sovagrid-containers": {"", "snapshot.json"},
        "/var/lib/sovagrid-vpn": {"", ".lock"},
        "/etc/sovagrid-hub": {"", "secret.key", "hub-secrets.key", "backup.key", "bot.token"},
        "/etc/sovagrid-journal": {"", "units.json"},
        "/etc/sovagrid-service": {"", "units.json", "policy.json"},
        "/etc/sovagrid-vpn": {"", "wireguard-control-install.json", "wireguard-control-install.lock"},
    }
    if root in exact:
        need(set(records) <= exact[root], "unknown initial fixture descendant")
        return
    if root == "/var/lib/sovagrid":
        leaves = {"", "hub", "hub/hub.sqlite", "hub/hub.sqlite-wal", "hub/hub.sqlite-shm", "vpn", "vpn/status.json",
                  "caddy", "backups", "backups/.lock", "backups/.broker-requests", "web-agent", "external-agent-operations",
                  "web-agent/.bundle.lock", "web-agent/jobs", "web-agent/jobs/.lock", "web-agent/jobs/.enrollment-web-mutation",
                  "web-agent/restores", "web-agent/restores/imports", "web-agent/restores/operations",
                  ".managed-by-run-sh", ".hub-backup-broker-managed-by-run-sh", ".release-feed-units-managed-by-run-sh",
                  ".ssh-gateway-managed-by-run-sh", ".web-agent-installer-managed-by-run-sh",
                  ".public-web.lock", ".local-web.lock"}
        caddy = {"caddy/caddy", "caddy/caddy/instance.uuid", "caddy/caddy/last_clean.json", "caddy/caddy/locks",
                 "caddy/caddy/pki", "caddy/caddy/pki/authorities", "caddy/caddy/pki/authorities/local",
                 "caddy/caddy/certificates", "caddy/caddy/certificates/local", "caddy/caddy/certificates/local/localhost"}
        caddy.update("caddy/caddy/pki/authorities/local/" + name
                     for name in ("root.crt", "root.key", "intermediate.crt", "intermediate.key"))
        caddy.update("caddy/caddy/certificates/local/localhost/localhost." + suffix for suffix in ("crt", "key", "json"))
        for name, record in records.items():
            match = re.fullmatch(r"web-agent/source-([0-9a-f]{64})\.tar\.gz", name)
            if match:
                need(record["sha256"] == match[1] and record["uid"] == record["gid"] == 0 and record["mode"] == 0o600,
                     "unknown initial Web producer bundle")
                fixture_module().archive_pin(Path(root) / name, expected_manifest())
                leaves.add(name)
        need(set(records) <= leaves | caddy, "unknown initial fixture data")
        return
    if root == "/etc/sovagrid":
        leaves = {"", "deploy.env", "admin-password", "agent.json", "agent.token", "hub-ca.pem",
                  ".agent-unit-managed-by-run-sh", ".terminal-unit-managed-by-run-sh", ".journal-managed-by-run-sh",
                  ".containers-managed-by-run-sh", ".vpn-unit-managed-by-run-sh", ".vpn-control-managed-by-run-sh",
                  ".external-agent-apply-managed-by-run-sh"}
        need(set(records) <= leaves, "unknown initial fixture configuration")
        return
    if root in ("/opt/sovagrid-agent", "/opt/sovagrid-vpn"):
        package = "sovagrid_agent" if root.endswith("agent") else "sovagrid_vpn"
        component = "sovagrid-agent" if root.endswith("agent") else "sovagrid-vpn"
        allowed = {"", package, package + "/__pycache__"}
        installed = [(file, package + "/" + file.name)
                     for file in (source / component / package).glob("*.py")]
        installed.extend((source / component / name, name)
                         for name in ("LICENSE", "ATTRIBUTION.md", "NOTICE"))
        for file, name in installed:
            allowed.add(name)
            if name in records:
                need(records[name]["sha256"] == hashlib.sha256(file.read_bytes()).hexdigest(), "installed code is foreign")
        for name in records:
            match = re.fullmatch(package + r"/__pycache__/([A-Za-z0-9_]+)\.cpython-[0-9]+\.pyc", name)
            need(name in allowed or match and package + "/" + match[1] + ".py" in allowed,
                 "unknown installed code descendant")
        return
    need(root == str(SOURCE) or records[""]["kind"] == "file", "unsupported initial fixture root")


def record_fixture():
    guard()
    expected = expected_manifest()
    fixture = fixture_module()
    fixture.guard()
    need(not os.path.lexists(fixture.MARKER), "fixture provenance already exists")
    fixture.source_pin(SOURCE, expected, allow_generated=True)
    trees = {}
    for root in sorted(ROOTS):
        if not os.path.lexists(root):
            continue
        records = fixture.inventory(Path(root))
        initial_names(root, records, SOURCE)
        trees[root] = records
    state = private_json(Path(os.environ["RUNNER_TEMP"]) / "sovagrid-remote-ci/state.json")
    guests = {state["container"]: guest_identity(state["container"], state)}
    value = {"protocol": fixture.PROTOCOL, "run_id": os.environ["GITHUB_RUN_ID"], "source": str(SOURCE),
             "manifest_sha256": expected, "initial_manifest_sha256": expected, "trees": trees,
             "units": fixture.unit_inventory(),
             "guests": guests, "guest_image": text(*DOCKER, "image", "inspect", "--format", "{{.Id}}", state["image"])}
    fixture.save(value, initial=True)
    print("PORTABLE_RESTORE_VM_INSTALL_FIXTURE_RECORDED", flush=True)


def process_identity(pid):
    need(type(pid) is int and pid > 1, "unknown guest process")
    root = Path("/proc") / str(pid)
    fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
    need(len(fields) > 19, "invalid guest process identity")
    return {"pid": pid, "start": fields[19], "exe": str((root / "exe").resolve()),
            "cmdline": (root / "cmdline").read_bytes().split(b"\0")[:-1]}


def guest_properties(name):
    # machinectl accepts one property per option, unlike systemctl's comma list.
    selected = ("Name", "Leader", "RootDirectory", "Service", "Class", "Unit")
    return dict(line.split("=", 1) for line in text("machinectl", "show", name,
        *("--property=" + key for key in selected)).splitlines() if "=" in line)


def guest_identity(name, state):
    suffix = re.fullmatch(r"sovagrid-ci-target-([0-9a-f]{12})", state.get("container", ""))
    need(suffix and name in (state["container"], "sovagrid-ci-web-target-" + suffix[1]) and
         state["image"] == "sovagrid-ci-target:" + suffix[1], "unknown guest fixture")
    root = Path("/var/lib/machines") / name
    info = root.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
         "unowned guest rootfs")
    need((root / "root/.ssh/authorized_keys").read_text() == state["auth_line"] + "\n", "guest fixture key changed")
    machine_id = (root / "etc/machine-id").read_text().strip()
    need(re.fullmatch(r"[0-9a-f]{32}", machine_id), "guest machine identity changed")
    properties = guest_properties(name)
    unit = "sg-ci-nspawn-" + name.removeprefix("sovagrid-ci-") + ".service"
    need(properties.get("Name") == name and properties.get("RootDirectory") == str(root) and
         properties.get("Service") == "systemd-nspawn" and properties.get("Class") == "container" and
         properties.get("Unit") == unit and properties.get("Leader", "").isdecimal(), "foreign registered guest")
    leader = int(properties["Leader"])
    leader_root = (Path("/proc") / str(leader) / "root").stat()
    need((leader_root.st_dev, leader_root.st_ino) == (info.st_dev, info.st_ino), "guest leader belongs to another rootfs")
    main = text("systemctl", "show", "--property=MainPID", "--value", unit)
    need(main.isdecimal(), "unknown nspawn supervisor")
    process = process_identity(int(main))
    expected = ["/usr/bin/systemd-nspawn", "--directory=" + str(root), "--machine=" + name, "--boot", "--register=yes",
                "--keep-unit", "--settings=no", "--console=read-only", "--drop-capability=CAP_NET_ADMIN,CAP_SYS_TIME",
                "--link-journal=no", "--resolv-conf=replace-host"]
    need(process["cmdline"] == [value.encode() for value in expected] and
         process["exe"] == str(Path("/usr/bin/systemd-nspawn").resolve()), "nspawn supervisor changed")
    process["cmdline"] = expected
    leader_process = process_identity(leader)
    leader_process["cmdline"] = [item.decode("ascii") for item in leader_process["cmdline"]]
    return {"root": [info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)],
            "machine_id": machine_id, "unit": unit, "supervisor": process, "leader": leader_process}


def record_guest(name, state):
    fixture = fixture_module()
    if not os.path.lexists(fixture.MARKER):
        return
    value = fixture.ledger()
    need(name not in value["guests"], "guest fixture already recorded")
    value["guests"][name] = guest_identity(name, state)
    fixture.save(value)


def hub_transport_snapshot(fixture, helper, expected):
    """Match exact producer identities before sealing any transport resource."""
    runner = helper.Enrollment(executable=str(SOURCE / "sovagrid-blueprint/deploy/remote_agent.py"))
    with runner.locked("hub", readonly=True):
        state = runner.hub_state()
        need(isinstance(state, dict) and set(state) == {"protocol", "kind", "created_at", "group", "enrollments",
             "accounts", "owned_files", "owned_directories", "pending_writes", "file_metadata"} and
             type(state["protocol"]) is int and state["protocol"] == 1 and state["kind"] == "hub" and
             type(state["created_at"]) is int and state["pending_writes"] == {} and
             state["enrollments"] == expected, "Hub transport enrollment set differs from the two producers")
        names = {entry["username"] for entry in expected.values()}
        need(len(expected) == len(names) == 2 and set(state["accounts"]) == names,
             "Hub transport account set differs from the two producers")
        group = grp.getgrnam(helper.HUB_GROUP)
        need(state["group"] == {"name": helper.HUB_GROUP, "gid": group.gr_gid} and
             64200 <= group.gr_gid <= 64999 and not group.gr_mem and
             {item.pw_name for item in pwd.getpwall() if item.pw_gid == group.gr_gid} == names,
             "Hub transport group has an unknown member")
        directories = {"/etc/ssh/sovagrid-tunnels": 0o755}
        files = {helper.POLICY_PATH: helper.POLICY}
        users = {}
        for entry in expected.values():
            name, eid, sid = entry["username"], entry["enrollment_id"], entry["server_id"]
            directories["/var/empty/" + name] = 0o755
            files["/etc/ssh/sovagrid-tunnels/" + name] = (
                'restrict,port-forwarding,permitopen="127.0.0.1:8767",command="/bin/false" '
                + entry["ssh_public_key"] + " sovagrid:" + sid + ":" + eid + "\n").encode("ascii")
            account = state["accounts"][name]
            user = pwd.getpwnam(name)
            need(set(account) == {"uid", "gid", "home", "comment", "requested_uid"} and
                 type(account["uid"]) is int and 100 <= account["uid"] <= 999 and
                 account["requested_uid"] == user.pw_uid == account["uid"] and
                 account["gid"] == user.pw_gid == group.gr_gid and
                 account["home"] == user.pw_dir == "/var/empty/" + name and
                 account["comment"] == user.pw_gecos == "sovagrid-" + eid + "-hub-tunnel" and
                 user.pw_shell == "/usr/sbin/nologin" and set(os.getgrouplist(name, user.pw_gid)) == {user.pw_gid} and
                 {item.pw_name for item in pwd.getpwall() if item.pw_uid == user.pw_uid} == {name},
                 "Hub transport account differs from its producer")
            users[name] = list(user) + [sorted(os.getgrouplist(name, user.pw_gid))]
        need(state["owned_directories"] == directories and
             state["owned_files"] == {path: hashlib.sha256(raw).hexdigest() for path, raw in files.items()} and
             state["file_metadata"] == {path: {"mode": 0o644, "gid": 0} for path in files},
             "Hub transport resource set differs from its producers")
        trees = {helper.HUB_STATE_DIR: fixture.transport_inventory()}
        for path, mode in directories.items():
            runner.files.inspect(path, directory=True)
            records = fixture.inventory(Path(path))
            allowed = {""} | (names if path == "/etc/ssh/sovagrid-tunnels" else set())
            need(set(records) == allowed and records[""]["uid"] == records[""]["gid"] == 0 and
                 records[""]["mode"] == mode, "unknown Hub transport directory descendant")
            trees[path] = records
        for path, raw in files.items():
            need(runner.files.read(path) == raw, "Hub transport policy or key differs from its producer")
            records = fixture.inventory(Path(path))
            need(set(records) == {""} and records[""]["uid"] == records[""]["gid"] == 0 and
                 records[""]["mode"] == 0o644, "unsafe Hub transport policy or key")
            if path == helper.POLICY_PATH:
                trees[path] = records
        return {"state": state, "trees": trees, "users": users, "group": list(group)}


def record_hub_transports(web_request):
    """Called by the Web enrollment producer, never by cleanup discovery."""
    guard()
    fixture = fixture_module()
    value = fixture.ledger()
    need("hub_transports" not in value and fixture.HUB_TRANSPORT not in value["trees"],
         "Hub transport fixture was already recorded")
    fixture.source_pin(SOURCE, value["manifest_sha256"], allow_generated=True)
    helper = load(SOURCE, "remote_agent.py", "sovagrid_ci_transport_producer")
    state = private_json(Path(os.environ["RUNNER_TEMP"]) / "sovagrid-remote-ci/state.json")
    suffix = re.fullmatch(r"sovagrid-ci-target-([0-9a-f]{12})", state.get("container", ""))
    need(suffix and state.get("web_container") == "sovagrid-ci-web-target-" + suffix[1] and
         set(value["guests"]) == {state["container"], state["web_container"]}, "unknown enrollment guest producers")
    expected = {}
    for name in (state["container"], state["web_container"]):
        need(guest_identity(name, state) == value["guests"][name], "enrollment guest producer changed")
        target = private_json(Path("/var/lib/machines") / name / "var/lib/sovagrid-agent-enrollment/state.json",
                              maximum=4 * 1024**2)
        identity = target.get("identity", {})
        need(target.get("protocol") == 1 and type(target.get("protocol")) is int and target.get("kind") == "target" and
             target.get("phase") == "active" and not target.get("removed") and target.get("pending_writes") == {} and
             target.get("source_manifest_sha256") == value["manifest_sha256"] and
             set(identity) == {"request_id", "enrollment_id", "server_id"}, "unknown active target producer")
        for item in identity.values():
            need(isinstance(item, str) and str(uuid.UUID(item)) == item, "invalid enrollment producer identity")
        public, fingerprint = helper.public_key(target.get("ssh_public_key"))
        need(target.get("ssh_key_fingerprint") == fingerprint, "enrollment producer key differs")
        journal_path = (Path("/var/lib/sovagrid/web-agent/jobs") if name == state["web_container"] else
                        Path("/run/sovagrid-ci-connect-" + suffix[1])) / (identity["request_id"] + ".json")
        journal = private_json(journal_path)
        registration = journal.get("registration") or {}
        need(journal.get("request_id") == identity["request_id"] and journal.get("phase") == "active" and
             journal.get("cleanup_required") is False and journal.get("hub_authorized") is True and
             journal.get("target") == helper.Enrollment.public_target(target) and registration.get("state") == "active" and
             registration.get("id") == identity["enrollment_id"] and registration.get("server_id") == identity["server_id"],
             "enrollment journal differs from its target producer")
        if name == state["web_container"]:
            need(identity["request_id"] == web_request and journal.get("name") == name,
                 "Web job differs from the exact creating request")
        else:
            need(journal.get("name") == "ci-remote-agent-" + suffix[1], "Connect journal belongs to another producer")
        eid, sid = identity["enrollment_id"], identity["server_id"]
        need(eid not in expected and sid not in {row["server_id"] for row in expected.values()},
             "enrollment producers reused an identity")
        expected[eid] = {"enrollment_id": eid, "server_id": sid, "username": helper.username(sid),
                         "ssh_public_key": public, "ssh_key_fingerprint": fingerprint, "revoked": False}
    proof = hub_transport_snapshot(fixture, helper, expected)
    value["hub_transports"] = proof
    value["trees"][fixture.HUB_TRANSPORT] = proof["trees"][fixture.HUB_TRANSPORT]
    fixture.save(value)


def check_transport_remainder(fixture, helper, proof, after):
    """A known revocation permits only its exact account/home/key removal."""
    names = set(after["accounts"])
    group = grp.getgrnam(helper.HUB_GROUP)
    need(list(group) == proof["group"] and
         {user.pw_name for user in pwd.getpwall() if user.pw_gid == group.gr_gid} == names,
         "Hub transport group changed during revocation")
    for name, expected in proof["users"].items():
        need({user.pw_name for user in pwd.getpwall() if user.pw_uid == expected[2]} ==
             ({name} if name in names else set()), "Hub transport UID was aliased or reused")
        try:
            user = pwd.getpwnam(name)
        except KeyError:
            need(name not in names, "known Hub transport account disappeared")
        else:
            need(name in names and list(user) + [sorted(os.getgrouplist(name, user.pw_gid))] == expected,
                 "Hub transport account changed during revocation")
    for path, sealed in proof["trees"].items():
        if path == helper.HUB_STATE_DIR:
            continue
        if path.startswith("/var/empty/") and Path(path).name not in names:
            need(not os.path.lexists(path), "revoked Hub transport home returned")
            continue
        if path == "/etc/ssh/sovagrid-tunnels":
            sealed = {name: record for name, record in sealed.items() if not name or name in names}
        fixture.compare(path, sealed, allow_mutable=False)
    records = fixture.transport_inventory()
    need(all(records[name] == proof["trees"][helper.HUB_STATE_DIR][name] for name in ("", "lock")) and
         records["state.json"]["sha256"] == hashlib.sha256(helper.encode(after) + b"\n").hexdigest(),
         "Hub transport state is not the exact public-helper transition")
    return records


def finish_hub_transport_cleanup(fixture, helper, runner, value, after):
    # Shared SSH/NSS cleanup never writes this tree. Retain the exact inventory
    # from the second known revoke, including its state-file inode.
    with runner.locked("hub", readonly=True):
        need(runner.hub_state() == after, "Hub transport state changed after shared cleanup")
        fixture.compare(fixture.HUB_TRANSPORT, value["trees"][fixture.HUB_TRANSPORT], allow_mutable=False)
        value["hub_transports"]["removed"] = True
        value["hub_transport_cleanup"]["phase"] = "removed"
        fixture.save(value)


def remove_hub_transports(bundle):
    """Revoke only the two sealed test enrollments after both guests stopped."""
    fixture = fixture_module()
    value = fixture.ledger()
    proof = value.get("hub_transports")
    need(isinstance(proof, dict) and not proof.get("removed") and "hub_transport_cleanup" not in value,
         "missing or interrupted Hub transport producer proof")
    verified_bundle(bundle)
    fixture.source_pin(SOURCE, value["manifest_sha256"], allow_generated=True)
    helper = load(bundle, "remote_agent.py", "sovagrid_ci_transport_cleanup")
    expected = proof["state"]["enrollments"]
    need(hub_transport_snapshot(fixture, helper, expected) == proof, "Hub transport producer proof changed")
    # The public helper verifies source, CAS, exact account identity and each
    # owned key before revocation. It does not write the Hub database or any
    # preserved snapshot input.
    runner = helper.Enrollment(executable=str(SOURCE / "sovagrid-blueprint/deploy/remote_agent.py"))
    after = copy.deepcopy(proof["state"])
    value["hub_transport_cleanup"] = {"phase": "revoking", "completed": []}
    fixture.save(value)  # A failure remains explicit; cleanup cannot recapture/adopt it on retry.
    for eid, entry in sorted(expected.items()):
        need(runner.hub_state() == after, "Hub transport changed before exact revocation")
        fixture.compare(fixture.HUB_TRANSPORT, value["trees"][fixture.HUB_TRANSPORT], allow_mutable=False)
        check_transport_remainder(fixture, helper, proof, after)
        result = runner.dispatch("hub-revoke", {"protocol": 1, "enrollment_id": eid, "server_id": entry["server_id"],
                                 "ssh_key_fingerprint": entry["ssh_key_fingerprint"], "expected": runner.cas("hub")})
        need(result == {"revoked": True, "cleanup_required": False}, "known Hub transport did not revoke")
        name = entry["username"]
        after["enrollments"][eid]["revoked"] = True
        del after["accounts"][name]
        del after["owned_directories"]["/var/empty/" + name]
        del after["owned_files"]["/etc/ssh/sovagrid-tunnels/" + name]
        del after["file_metadata"]["/etc/ssh/sovagrid-tunnels/" + name]
        need(runner.hub_state() == after and not os.path.lexists("/var/empty/" + name),
             "Hub transport revocation changed unrelated state")
        value["trees"][fixture.HUB_TRANSPORT] = check_transport_remainder(fixture, helper, proof, after)
        value["hub_transport_cleanup"]["completed"].append(eid)
        fixture.save(value)
    _restore, core, _runtime = api(bundle)
    for path in (helper.POLICY_PATH, "/etc/ssh/sovagrid-tunnels"):
        sealed = proof["trees"][path]
        if path == "/etc/ssh/sovagrid-tunnels":
            sealed = {"": sealed[""]}  # The two known public revocations removed only their key files.
        fixture.compare(path, sealed, allow_mutable=False)
        parent, leaf = core._safe_parent(Path("/"), path, uid=0)
        try:
            info = os.fstat(parent)
            held = {"parent": [info.st_dev, info.st_ino], "resource": core.tree_proof(parent, leaf)}
            identity = uuid.uuid4().hex
            shadow = ".sovagrid-restore-" + identity + "-0"
            step = {"kind": "publish", "resource": path,
                    "desired": {"shadow": shadow, "sha256": held["resource"]["sha256"]}}
            fixture.compare(path, sealed, allow_mutable=False)
            core.Publisher(Path("/"), identity, {path}).undo(step, held)
            remove_quarantined(fixture, core, parent, shadow, path, held, sealed)
        finally:
            os.close(parent)
    group = grp.getgrnam(helper.HUB_GROUP)
    need(list(group) == proof["group"] and not group.gr_mem and
         not any(user.pw_gid == group.gr_gid for user in pwd.getpwall()), "Hub transport group acquired another user")
    command("/usr/sbin/groupdel", helper.HUB_GROUP)
    command("/usr/sbin/sshd", "-t")
    command("systemctl", "reload", "ssh.service")
    finish_hub_transport_cleanup(fixture, helper, runner, value, after)
    print("PORTABLE_RESTORE_VM_TWO_OWNED_TRANSPORTS_REVOKED", flush=True)


def transition_fixture(action, old, target, candidate):
    fixture = fixture_module()
    if not os.path.lexists(fixture.MARKER):
        return
    value = fixture.ledger()
    need(all(SHA.fullmatch(item or "") for item in (old, target, candidate)) and target == expected_manifest(),
         "transition differs from artifact manifest pin")
    if action == "begin":
        need(value["manifest_sha256"] == old and "transition" not in value, "unexpected fixture transition")
        fixture.source_pin(SOURCE, old, allow_generated=True)
        fixture.check_all(value, ROOTS)
        fixture.check_units(value)
        value["transition"] = {"old": old, "target": target, "candidate": candidate}
        fixture.save(value)
        return
    need(action == "complete" and value.get("transition") == {"old": old, "target": target, "candidate": candidate},
         "transition producer identity changed")
    fixture.source_pin(SOURCE, target, allow_generated=True)
    candidates = Path("/opt/sovagrid-candidates")
    need({item.name for item in candidates.iterdir()} <= {".lock", "transactions", candidate},
         "unrecorded candidate appeared during transition")
    transactions = candidates / "transactions"
    need(not transactions.is_symlink() and transactions.is_dir() and not any(transactions.iterdir()),
         "updater did not remove its committed transaction")
    staged = candidates / candidate
    need({item.name for item in staged.iterdir()} == {".ready", "bundle.tar.gz", "source"} and
         (staged / ".ready").read_text() == candidate + "\n" and
         hashlib.sha256((staged / "bundle.tar.gz").read_bytes()).hexdigest() == candidate,
         "transition candidate ownership changed")
    staged_inventory = fixture.inventory(staged)
    need(all(staged_inventory[name]["uid"] == staged_inventory[name]["gid"] == 0 and
         staged_inventory[name]["mode"] == (0o700 if not name else 0o600)
         for name in ("", ".ready", "bundle.tar.gz")), "transition candidate permissions changed")
    fixture.source_pin(staged / "source", target)
    additions = {"/var/lib/sovagrid": {".auto-update.lock", "auto-update-status.json", "vpn-source", "vpn-source/.lock"},
                 "/etc/sovagrid": {"auto-update.json"}, "/var/lib/sovagrid-vpn": {".lock"}}
    retirements = None
    for root, expected in value["trees"].items():
        actual = fixture.inventory(Path(root))
        if root == str(SOURCE):
            pass  # Exact artifact-pinned source already checked above.
        elif root == str(candidates):
            need(set(actual) == {"", ".lock", "transactions", candidate} |
                 {candidate + "/" + name for name in fixture.inventory(staged) if name},
                 "unknown candidate descendant")
        else:
            permitted = set(expected) | additions.get(root, set())
            if root == "/var/lib/sovagrid":
                for name in set(actual) - permitted:
                    match = re.fullmatch(r"web-agent/source-([0-9a-f]{64})\.tar\.gz", name)
                    if match:
                        need(actual[name]["sha256"] == match[1], "updated Web bundle name changed")
                        fixture.archive_pin(Path(root) / name, target)
                        permitted.add(name)
            permitted |= {str(Path(name).relative_to(root)) for name in fixture.OPTIONAL if Path(name).is_relative_to(root)}
            need(set(actual) <= permitted, "unknown descendant created during transition")
            if root == "/var/lib/sovagrid":
                retirements = seal_web_bundle_retirements(fixture, expected, actual, old, target)
        value["trees"][root] = actual
    for root, names in (("/etc/sovagrid-vpn-routing", {"", "lock"}),
                        ("/etc/sovagrid-service-setup.lock", {""})):
        if root not in value["trees"] and os.path.lexists(root):
            actual = fixture.inventory(Path(root))
            need(set(actual) <= names and all(record["uid"] == record["gid"] == 0 and
                 record["mode"] == (0o700 if record["kind"] == "dir" else 0o600) and
                 (record["kind"] == "dir" or record["size"] == 0 and
                  record["sha256"] == hashlib.sha256(b"").hexdigest())
                 for record in actual.values()), "unowned transition lock")
            value["trees"][root] = actual
    value["manifest_sha256"] = target
    if retirements is not None:
        need("web_bundle_retirements" not in value, "Web archive retirement was already sealed")
        value["web_bundle_retirements"] = retirements
    units = fixture.unit_inventory()
    need(set(units) == set(value["units"]), "transition changed the declared unit set")
    value["units"] = units  # Only this known signed installer advances inodes.
    del value["transition"]
    fixture.save(value)


def web_bundle_jobs(fixture, records, *, root=Path("/var/lib/sovagrid")):
    """Read only byte/metadata-proven producer journals, never discovered jobs."""
    result = {}
    for name, record in records.items():
        match = re.fullmatch(r"web-agent/jobs/([0-9a-f-]{36})\.json", name)
        if match is None:
            continue
        need(str(uuid.UUID(match[1])) == match[1] and record["kind"] == "file" and
             record["uid"] == record["gid"] == 0 and record["mode"] == 0o600 and record["size"] <= 32 * 1024,
             "invalid producer Web journal")
        # inventory() proves no links and stable bytes; this second read must
        # match those exact bytes before they can authorize a missing archive.
        with os.fdopen(os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
            info = os.fstat(stream.fileno())
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                 (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_size) ==
                 tuple(record[key] for key in ("dev", "ino", "uid", "gid", "mode", "size")),
                 "producer Web journal identity changed")
            raw = stream.read(32 * 1024 + 1)
            after = os.fstat(stream.fileno())
            keys = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
            need(all(getattr(info, key) == getattr(after, key) for key in keys),
                 "producer Web journal changed during read")
        need(len(raw) == record["size"] and hashlib.sha256(raw).hexdigest() == record["sha256"],
             "producer Web journal changed")
        value = json.loads(raw)
        need(value.get("request_id") == match[1] and type(value.get("bundle")) is dict and
             set(value["bundle"]) == {"path", "sha256"}, "invalid producer Web bundle reference")
        result[name] = value
    return result


def seal_web_bundle_retirements(fixture, expected, actual, old, target, *, root=Path("/var/lib/sovagrid")):
    """The signed-transition producer seals only completed old runner archives.

    Startup pruning is suppressed while the updater owns the enrollment lock.
    A later restore starts without that lock and legitimately retires these
    archives. Pending enrollment/cleanup and restore-history pins stay required.
    """
    archives = {name for name in actual if re.fullmatch(r"web-agent/source-[0-9a-f]{64}\.tar\.gz", name)}
    current = archives - set(expected)
    need(len(current) == 1, "transition current Web archive is not unique")
    current, = current
    need(actual[current]["kind"] == "file" and actual[current]["uid"] == actual[current]["gid"] == 0 and
         actual[current]["mode"] == 0o600 and actual[current]["sha256"] == Path(current).name[7:-7],
         "invalid transition current Web archive")
    fixture.archive_pin(root / current, target)
    job_records = {name: record for name, record in actual.items()
                   if re.fullmatch(r"web-agent/jobs/[0-9a-f-]{36}\.json", name)}
    need(all(name in expected and record == expected[name] for name, record in job_records.items()),
         "producer Web journal changed during transition")
    jobs = web_bundle_jobs(fixture, job_records, root=root)
    retired = {}
    for name in sorted(archives & set(expected)):
        need(actual[name] == expected[name], "old producer Web archive changed")
        fixture.archive_pin(root / name, old)
        sha = Path(name).name.removeprefix("source-").removesuffix(".tar.gz")
        references = {path: job for path, job in jobs.items()
                      if job["bundle"] == {"path": str(Path("/var/lib/sovagrid") / name), "sha256": sha}}
        # 'active' means completed enrollment, not an in-progress operation.
        if references and all(job.get("phase") == "active" and job.get("cleanup_required") is False
                              for job in references.values()):
            retired[name] = sorted(references)
    need(not any(name.startswith("web-agent/restores/operations/") for name in actual),
         "Web restore history requires its pinned runner")
    return {"old_manifest_sha256": old, "target_manifest_sha256": target,
            "current": current, "archives": retired}


def retired_web_bundles(fixture, value, entries, actual, *, root=Path("/var/lib/sovagrid")):
    """An absent completed runner is optional only with its transition proof."""
    proof = value.get("web_bundle_retirements")
    if proof is None:
        return set()
    need(set(proof) == {"old_manifest_sha256", "target_manifest_sha256", "current", "archives"} and
         proof["old_manifest_sha256"] == value["initial_manifest_sha256"] and
         proof["target_manifest_sha256"] == expected_manifest() and
         proof["old_manifest_sha256"] != proof["target_manifest_sha256"], "invalid Web archive retirement proof")
    sealed = value["trees"]["/var/lib/sovagrid"]
    current = proof["current"]
    need(current in actual and current in entries and current in sealed and
         re.fullmatch(r"web-agent/source-[0-9a-f]{64}\.tar\.gz", current), "current Web archive disappeared")
    keys = ("kind", "uid", "gid", "mode", "size", "sha256")
    need(all(actual[current][key] == entries[current][key] == sealed[current][key] for key in keys),
         "current Web archive changed")
    fixture.archive_pin(root / current, expected_manifest())
    need(not any(name.startswith("web-agent/restores/operations/") for name in set(entries) | set(actual)),
         "Web restore history requires its pinned runner")
    jobs = web_bundle_jobs(fixture, {name: record for name, record in actual.items()
        if name in sealed and name in entries and record["kind"] == "file" and
        all(record[key] == sealed[name][key] == entries[name][key] for key in keys)}, root=root)
    retired = set()
    for name, references in proof["archives"].items():
        need(name != current and name in sealed and name in entries and
             re.fullmatch(r"web-agent/source-[0-9a-f]{64}\.tar\.gz", name) and
             all(sealed[name][key] == entries[name][key] for key in keys) and
             sealed[name]["sha256"] == Path(name).name[7:-7] and
             sealed[name]["kind"] == "file" and sealed[name]["uid"] == sealed[name]["gid"] == 0 and
             sealed[name]["mode"] == 0o600, "unproven retired Web archive")
        matches = sorted(path for path, job in jobs.items() if job["bundle"] == {
            "path": str(Path("/var/lib/sovagrid") / name), "sha256": sealed[name]["sha256"]})
        need(references and matches == references and all(jobs[path].get("phase") == "active" and
             jobs[path].get("cleanup_required") is False for path in references),
             "retired Web archive is still needed by enrollment")
        if name not in actual:
            retired.add(name)
    return retired


def record_restored(bundle, identity):
    """New inode provenance comes only from a committed exact restore plan."""
    fixture = fixture_module()
    value = fixture.ledger()
    restore, core, _runtime = api(bundle)
    need(core.host_status(restore, identity)["phase"] == "committed", "restore is not committed")
    fixture.source_pin(SOURCE, expected_manifest(), allow_generated=True)
    plan = private_json(restore.STAGING / (".apply-plan-" + identity + ".json"), maximum=8 * 1024**2)
    transaction = private_json(restore.STAGING / (".apply-" + identity + ".json"))
    need(transaction["phase"] == "committed" and transaction["id"] == identity, "restore journal is not committed")
    publications = {step["resource"]: step["proof"]["resource"] for step in transaction["steps"]
                    if step["kind"] == "publish" and step["state"] == "done"}
    resources = {item["target"]: item for item in plan["resources"]}
    trees = {}
    for root in ROOTS:
        if not os.path.lexists(root):
            continue
        actual = fixture.inventory(Path(root))
        permitted = set(value["trees"].get(root, {}))
        if root in resources:
            permitted |= set(resources[root]["entries"])
        permitted |= {str(Path(name).relative_to(root)) for name in fixture.OPTIONAL if Path(name).is_relative_to(root)}
        need(set(actual) <= permitted, "restored fixture has an undeclared descendant")
        required = {name for name in resources.get(root, {}).get("entries", {})
                    if str(Path(root) / name) not in fixture.OPTIONAL}
        if root == "/var/lib/sovagrid":
            required -= retired_web_bundles(fixture, value, resources[root]["entries"], actual)
        need(required <= set(actual), "restored fixture lost a declared descendant")
        need(root in publications and [actual[""][key] for key in ("dev", "ino")] ==
             [publications[root][key] for key in ("device", "inode")], "restored fixture root was replaced")
        for name, record in actual.items():
            reference = resources.get(root, {}).get("entries", {}).get(name) or value["trees"].get(root, {}).get(name)
            absolute = str(Path(root) / name)
            if reference is None and absolute in fixture.OPTIONAL:
                reference = resources[root]["entries"][str(Path(fixture.OPTIONAL[absolute]).relative_to(root))]
            need(reference is not None, "restored fixture has no producer metadata")
            keys = ("kind", "uid", "gid", "mode")
            if record["kind"] == "file" and absolute not in fixture.MUTABLE | set(fixture.OPTIONAL):
                keys += ("size", "sha256")
            need(all(record[key] == reference[key] for key in keys), "restored fixture changed before provenance seal")
        trees[root] = actual
    value["trees"] = trees
    units = fixture.unit_inventory()
    need(set(units) == {"/etc/systemd/system/" + unit for unit in plan["unit_states"]},
         "restored fixture contains undeclared units")
    for path, records in units.items():
        record, expected = records[""], resources[path]["entries"][""]
        need(path in publications and [record[key] for key in ("dev", "ino")] ==
             [publications[path][key] for key in ("device", "inode")] and
             all(record[key] == expected[key] for key in ("kind", "uid", "gid", "mode", "size", "sha256")),
             "restored fixture unit changed before provenance seal")
    value["units"] = units
    fixture.save(value)


def _snapshot_pause(deadline, seconds):
    remaining = deadline - time.monotonic()
    need(remaining > 0, "portable snapshot deadline expired")
    time.sleep(min(seconds, remaining))


def _snapshot_idle(orchestrator, request, deadline, ready):
    """Do not reuse a terminal record until its exact worker releases locks."""
    while True:
        remaining = deadline - time.monotonic()
        need(remaining > 0, "portable snapshot deadline expired")
        state = text("systemctl", "is-active", "sg-host-backup-" + request + ".service",
                     accepted=(0, 3, 4), timeout=min(10, remaining))
        need(state in ("active", "activating", "deactivating", "reloading", "refreshing",
                       "inactive", "failed", "unknown"), "unknown snapshot worker state")
        if state in ("inactive", "failed", "unknown"):
            try:
                # Match the worker's lock order. All three contexts are bounded;
                # a failed precheck must never adopt another active operation.
                with (orchestrator._global_lock(), orchestrator.update.web_agent_snapshot_lock(),
                      orchestrator.backup._locks()):
                    need(time.monotonic() < deadline, "portable snapshot deadline expired")
                    need(orchestrator._active() is None, "snapshot retry found an active operation")
                    ready()
                    return
            except (orchestrator.Refused, orchestrator.backup.Refused,
                    orchestrator.update.UpdateFailure) as exc:
                if str(exc) != "BUSY":
                    raise
        _snapshot_pause(deadline, 0.2)


def _snapshot_register(orchestrator, request, manifest, *, failed=False):
    """Seal only this fresh request's closed, pinned portable-v2 record."""
    value = orchestrator._record(request)
    keys = {"protocol", "request_id", "phase", "created_at", "updated_at",
            "expected_manifest_sha256", "layout", "active_units", "running_containers",
            "container_ids", "unit_hashes", "archive_id", "archive", "error",
            "portable_images", "image_receipt", "unit_states"}
    need(isinstance(value, dict) and set(value) == keys and
         value["protocol"] == orchestrator.PROTOCOL and value["request_id"] == request and
         value["expected_manifest_sha256"] == manifest, "snapshot record provenance differs")
    if failed:
        # In the pinned worker this exact terminal combination occurs only in
        # its compare before _stop. Later archive/restart failures are fatal.
        need(value["phase"] == "failed" and value["error"] == "STATE_CHANGED" and
             value["archive"] is None and value["image_receipt"] is None,
             "snapshot failure is not a pre-stop comparison")
    else:
        need(value["phase"] == "complete" and value["error"] is None and
             value["archive"] is not None and value["image_receipt"] is not None,
             "snapshot record is not complete")
    fixture = fixture_module()
    fixture.extend(fixture.ledger(), {str(orchestrator.STATE_DIR): {".lock", request + ".json"}})


def snapshot(bundle, manifest):
    orchestrator = load(bundle, "host_backup_orchestrator.py", "sovagrid_ci_portable_backup")
    deadline = time.monotonic() + 1500
    for attempt in range(6):
        need(time.monotonic() < deadline, "portable snapshot deadline expired")
        request = uuid.uuid4().hex
        record_path = orchestrator.STATE_DIR / (request + ".json")
        need(not os.path.lexists(record_path), "snapshot request already exists")
        try:
            started = orchestrator.start(request, manifest, portable=True)
        except orchestrator.Refused as exc:
            if str(exc) not in ("UNIT_STATE_UNAVAILABLE", "STATE_CHANGED", "BUSY"):
                raise
            # start must have refused before its first durable record/spawn.
            def absent(record_path=record_path):
                need(not os.path.lexists(record_path), "snapshot refusal created a record")
            absent()
            _snapshot_idle(orchestrator, request, deadline, absent)
            need(attempt < 5, "portable snapshot precheck retry limit: " + str(exc))
            _snapshot_pause(deadline, 1)
            continue
        need(started.get("protocol") == orchestrator.PROTOCOL and
             started.get("request_id") == request and started.get("phase") in
             ("accepted", "stopping", "archiving", "restarting", "complete"), "portable snapshot refused")
        changed = started["phase"] != "accepted"
        while True:
            need(time.monotonic() < deadline, "portable snapshot deadline expired")
            value = orchestrator.portable_status(request)
            need(value.get("protocol") == orchestrator.PROTOCOL and value.get("request_id") == request,
                 "snapshot status provenance differs")
            changed |= value["phase"] in ("stopping", "archiving", "restarting", "complete")
            if value["phase"] == "complete":
                break
            error = value.get("error")
            safe_error = error if isinstance(error, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", error) else "UNKNOWN"
            if value["phase"] == "failed" and safe_error == "STATE_CHANGED" and not changed:
                _snapshot_idle(orchestrator, request, deadline,
                               lambda request=request: _snapshot_register(orchestrator, request, manifest, failed=True))
                need(attempt < 5, "portable snapshot precheck retry limit: STATE_CHANGED")
                _snapshot_pause(deadline, 1)
                break
            need(value["phase"] not in ("failed", "recovery_required"),
                 "portable snapshot did not complete: " + value["phase"] + "/" + safe_error)
            _snapshot_pause(deadline, 0.5)
        if value["phase"] == "complete":
            break
    _snapshot_idle(orchestrator, request, deadline, lambda: None)
    identity = value["archive"]["id"]
    exporter = load(bundle, "host_image_export.py", "sovagrid_ci_portable_images")
    result = exporter.verify(identity, require_receipt=True)
    need(time.monotonic() < deadline, "portable snapshot deadline expired")
    receipt = result["receipt"]
    need(receipt["protocol"] == "sovagrid-portable-host-receipt-v2" and
         receipt["source_manifest_sha256"] == manifest and
         all(state["enablement"] in ("enabled", "disabled", "static")
             for state in receipt["unit_states"].values()), "snapshot lacks supported v2 unit states")
    print("PORTABLE_RESTORE_VM_SNAPSHOT_READY", flush=True)
    _snapshot_register(orchestrator, request, manifest)
    return identity, receipt


def stop_ci_guests_and_retag(bundle):
    fixture = fixture_module()
    provenance = fixture.ledger()
    parent = Path(os.environ["RUNNER_TEMP"]).resolve()
    state_dir = parent / "sovagrid-remote-ci"
    need(state_dir.parent == parent and state_dir.is_dir() and not state_dir.is_symlink(), "missing guarded guest fixture")
    state = private_json(state_dir / "state.json")
    suffix = re.fullmatch(r"sovagrid-ci-target-([0-9a-f]{12})", state.get("container", ""))
    need(suffix is not None and state.get("image") == "sovagrid-ci-target:" + suffix.group(1), "unknown guest fixture identity")
    selected = [name for name in (state.get("web_container"), state["container"]) if name]
    need(set(selected) == set(provenance["guests"]), "guest list differs from creator provenance")
    # Validate every guest before powering off any guest.
    for name in selected:
        need(guest_identity(name, state) == provenance["guests"][name], "guest identity changed before poweroff")
    for name in (state.get("web_container"), state["container"]):
        if name is None:
            continue
        need(re.fullmatch(r"sovagrid-ci-(?:web-)?target-[0-9a-f]{12}", name) is not None, "unknown guest machine")
        unit = "sg-ci-nspawn-" + name.removeprefix("sovagrid-ci-") + ".service"
        need(guest_identity(name, state) == provenance["guests"][name], "guest identity changed before poweroff")
        command("machinectl", "poweroff", name, accepted=(0, 1))
        command("systemctl", "stop", unit, accepted=(0, 5))
        command("machinectl", "terminate", name, accepted=(0, 1))
        deadline = time.monotonic() + 20
        while (text("systemctl", "is-active", unit, accepted=(0, 3, 4)) == "active" or
               command("machinectl", "show", name, accepted=(0, 1)).returncode == 0):
            need(time.monotonic() < deadline, "guest remained active or registered")
            time.sleep(0.2)
    remove_hub_transports(bundle)
    reference = state["image"]
    image = text(*DOCKER, "image", "inspect", "--format", "{{.Id}}", reference)
    need(IMAGE.fullmatch(image) is not None and image == provenance["guest_image"], "unverified guest image")
    alias = "sg-portable-remote-fixture:" + suffix.group(1)
    need(not text(*DOCKER, "image", "ls", "--format", "{{.Repository}}:{{.Tag}}", "--filter", "reference=" + alias), "guest alias already exists")
    command(*DOCKER, "image", "tag", image, alias)
    need(text(*DOCKER, "image", "inspect", "--format", "{{.Id}}", reference) == image, "guest image changed")
    command(*DOCKER, "image", "rm", "--no-prune", reference)
    return reference, alias, image


def restore_ci_image(pin):
    reference, alias, image = pin
    need(text(*DOCKER, "image", "inspect", "--format", "{{.Id}}", alias) == image, "guest alias changed")
    need(not text(*DOCKER, "image", "ls", "--format", "{{.Repository}}:{{.Tag}}", "--filter", "reference=" + reference), "guest original tag unexpectedly returned")
    command(*DOCKER, "image", "tag", image, reference)
    command(*DOCKER, "image", "rm", "--no-prune", alias)


def identity_snapshot(inspected, core, restore_id=None, provenance=None):
    groups = inspected["identities"]["groups"]
    names = set(inspected["identities"]["users"]) | {"sovagrid"}
    users = {}
    for name in names:
        entry = pwd.getpwnam(name)
        expected_uid = (provenance["trees"]["/var/lib/sovagrid-agent"][""]["uid"] if name == "sovagrid" and
                        provenance is not None else inspected["identities"]["users"].get(name))
        expected_groups = {entry.pw_gid}
        if name == "sovagrid-journal":
            expected_groups.add(grp.getgrnam("systemd-journal").gr_gid)
        need(expected_uid is not None and entry.pw_uid == expected_uid and entry.pw_uid > 0 and
             entry.pw_gid == groups[name] and entry.pw_shell == "/usr/sbin/nologin" and
             entry.pw_dir == ("/var/lib/sovagrid-agent" if name == "sovagrid" else "/nonexistent") and
             set(os.getgrouplist(name, entry.pw_gid)) == expected_groups and
             entry.pw_gecos == ("" if restore_id is None else "SovaGrid restore " + restore_id) and
             core.Identities._locked_password("/etc/shadow", name), "unknown CI service account")
        if restore_id is not None:
            need(entry.pw_gecos == "SovaGrid restore " + restore_id, "service account belongs to another restore")
        users[name] = list(entry) + [sorted(os.getgrouplist(name, entry.pw_gid))]
    records = {}
    for name, gid in groups.items():
        group = grp.getgrnam(name)
        need(group.gr_gid == gid and not group.gr_mem and
             core.Identities._locked_password("/etc/gshadow", name, group=True), "unknown CI group")
        records[name] = list(group)
    return users, records


def no_user_processes(uid):
    for proc in Path("/proc").iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            rows = (proc / "status").read_text().splitlines()
        except (OSError, ProcessLookupError):
            continue
        values = next((line.split()[1:] for line in rows if line.startswith("Uid:")), [])
        if str(uid) in values:
            return False
    return True


def remove_quarantined(fixture, core, parent, shadow, path, proof, expected):
    """Fresh hashing never grants ownership of a newly inserted descendant."""
    info = os.fstat(parent)
    need([info.st_dev, info.st_ino] == proof["parent"], "quarantine parent changed")
    need(core.tree_proof(parent, shadow) == proof["resource"], "quarantined tree changed")
    # Recheck the producer's CLOSED path/inode inventory through the retained
    # parent FD after rename. Keep original-path mutable exceptions for Hub's
    # known DB/status leaves; the random sibling path grants no new exception.
    fixture.compare(path, expected, parent_fd=parent, leaf=shadow)
    info = os.stat(shadow, dir_fd=parent, follow_symlinks=False)
    if stat.S_ISDIR(info.st_mode):
        shutil.rmtree(shadow, dir_fd=parent)
    else:
        os.unlink(shadow, dir_fd=parent)
    os.fsync(parent)


def restored_runtime_images(bundle, restore, core, identity, receipt):
    """Bind disposable cleanup IDs to the committed plan and actual images."""
    runtime = load(bundle, "portable_restore_runtime.py", "sovagrid_ci_cleanup_runtime")
    with core.transaction_locks(restore) as (fd, _exporter):
        journal = core.Journal(fd, identity, uid=restore.backup.ROOT_UID, gid=restore.backup.ROOT_GID)
        value = journal.read()
        need(value is not None and value["phase"] == "committed" and value["id"] == identity and
             receipt["host_archive_id"] == identity, "cleanup restore is not committed")
        need(all(value["bindings"][key] == receipt[key] for key in
                 ("source_manifest_sha256", "host_archive_sha256", "images_sha256")),
             "cleanup receipt differs from committed inputs")
        plan = runtime.load(restore, core, fd, identity, value["bindings"])
        need({name: image["config"] for name, image in plan["images"].items()} == receipt["exported_configs"] and
             {name: image["rootfs_sha256"] for name, image in plan["images"].items()} == receipt["rootfs_sha256"],
             "cleanup image content differs from receipt")
        steps = [step for step in value["steps"] if step["kind"] == "compose"]
        need(len(steps) == 1 and steps[0]["state"] == "done", "cleanup compose proof is incomplete")
        driver = runtime.Runtime(restore, core, plan, journal)
        driver.compose.verify(steps[0], steps[0]["proof"])
        resolved = driver.images.resolved(plan["images"])
        need(resolved == steps[0]["proof"].get("runtime_images"),
             "cleanup daemon image IDs differ from committed proof")
        return dict(resolved)


def uninstall(bundle, identity, receipt, *, restore_id=None):
    """Remove only a fully identified disposable installation, never glob-rm."""
    restore, core, _runtime = api(bundle)
    fixture = fixture_module()
    provenance = fixture.ledger()
    need(provenance["manifest_sha256"] == expected_manifest(), "cleanup provenance differs from artifact pin")
    fixture.source_pin(SOURCE, expected_manifest(), allow_generated=True)
    fixture.check_all(provenance, ROOTS)
    fixture.check_units(provenance)
    worker = load(bundle, "remote_update_worker.py", "sovagrid_ci_uninstall_manifest")
    expected = receipt["source_manifest_sha256"]
    need(worker.source_manifest(SOURCE, allow_generated=True)[0] == expected, "installed source changed before cleanup")
    inspected = restore.verify(identity)
    need(inspected["archive"]["layout"] == "full", "cleanup only supports this full fixture")
    users, groups = identity_snapshot(inspected, core, restore_id, provenance)
    units = {"/etc/systemd/system/" + name: state["sha256"] for name, state in receipt["unit_states"].items()}
    extra = Path("/etc/systemd/system/sovagrid-external-agent-apply@.service")
    if extra.exists():
        template = bundle / "sovagrid-blueprint/deploy" / extra.name
        need(extra.read_bytes() == template.read_bytes() and
             Path("/etc/sovagrid/.external-agent-apply-managed-by-run-sh").read_bytes() == b"SOVAGRID_EXTERNAL_AGENT_APPLY_UNIT_V1\n",
             "unmanaged external Agent template")
        need(not text("systemctl", "list-units", "--state=active,activating,deactivating", "--no-legend", "--plain",
                      "sovagrid-external-agent-apply@*.service"), "external Agent operation is active")
        units[str(extra)] = hashlib.sha256(extra.read_bytes()).hexdigest()
    need(set(units) == set(provenance["units"]), "archive unit set differs from fixture provenance")
    allowed = set(ROOTS) | set(units)
    for namespace in restore.SCAN_NAMESPACES:
        root = Path(namespace)
        if not root.exists():
            continue
        for entry in root.iterdir():
            if entry.name == "sovagrid" or entry.name.startswith("sovagrid-"):
                reason = "unknown SovaGrid namespace in disposable cleanup"
                if (os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
                        and os.environ.get("RUNNER_OS") == "Linux" and
                        os.environ.get("SOVAGRID_PORTABLE_RESTORE_DISPOSABLE") == "1"):
                    safe_name = entry.name if re.fullmatch(r"sovagrid(?:-[A-Za-z0-9_.@-]{1,160})?", entry.name) else "<invalid>"
                    reason += ": " + safe_name
                need(str(entry) in allowed | set(PRESERVED), reason)
    for name, digest in units.items():
        info = Path(name).lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o644 and hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest,
             "managed unit changed before cleanup")
    expected_images = (restored_runtime_images(bundle, restore, core, restore_id, receipt)
                       if restore_id else receipt["images"])
    records = {}
    projection = '{"id":{{json .Id}},"image":{{json .Image}},"labels":{{json .Config.Labels}}}'
    for service, image in expected_images.items():
        ids = text(*DOCKER, "ps", "-a", "--no-trunc", "--filter", "label=com.docker.compose.project=sovagrid",
                   "--filter", "label=com.docker.compose.service=" + service, "--format", "{{.ID}}").splitlines()
        need(len(ids) == 1 and SHA.fullmatch(ids[0]) is not None, "ambiguous CI container")
        record = json.loads(text(*DOCKER, "inspect", "--format", projection, ids[0]))
        need(record["id"] == ids[0] and record["image"] == image and
             record["labels"].get("com.docker.compose.project") == "sovagrid" and
             record["labels"].get("com.docker.compose.service") == service, "container ownership changed")
        if restore_id:
            need(record["labels"].get("org.sovagrid.restore") == restore_id, "foreign restored container")
        else:
            need(ids[0] == receipt["container_ids"][service], "original CI container was replaced")
        need(text(*DOCKER, "image", "inspect", "--format", "{{.Id}}", "sovagrid-" + service + ":local") == image,
             "local image tag changed")
        records[service] = record
    all_ids = text(*DOCKER, "ps", "-a", "--no-trunc", "--filter", "label=com.docker.compose.project=sovagrid", "--format", "{{.ID}}").splitlines()
    need(set(all_ids) == {record["id"] for record in records.values()}, "unknown project container")
    refs = text(*DOCKER, "image", "ls", "-a", "--format", "{{.Repository}}:{{.Tag}}").splitlines()
    need({value for value in refs if value.startswith("sovagrid-")} ==
         {"sovagrid-" + name + ":local" for name in expected_images}, "unknown managed image reference")
    network = json.loads(text(*DOCKER, "network", "inspect", "--format",
        '{"id":{{json .Id}},"labels":{{json .Labels}},"containers":{{json .Containers}},"name":{{json .Name}}}', "sovagrid_private"))
    need(SHA.fullmatch(network["id"]) is not None and network["name"] == "sovagrid_private" and
         network["labels"].get("com.docker.compose.project") == "sovagrid" and
         set(network["containers"]) == set(all_ids), "network has foreign endpoints")
    if restore_id:
        need(network["labels"].get("org.sovagrid.restore") == restore_id, "foreign restored network")
    with core.transaction_locks(restore):
        need(not core.FENCE.exists() and not core.FENCE.is_symlink(), "cleanup must not bypass an active restore fence")
        # Validate every descendant BEFORE stopping anything, then again once
        # owned services have stopped and before taking quarantine proofs.
        fixture.check_all(provenance, ROOTS)
        fixture.check_units(provenance)
        for suffix in (".timer", ".socket", ".service"):
            selected = [name for name in receipt["unit_states"] if name.endswith(suffix)]
            if selected:
                command("systemctl", "stop", *selected)
        enabled = [name for name, state in receipt["unit_states"].items() if state["enablement"] == "enabled"]
        if enabled:
            command("systemctl", "disable", *enabled)
        for record in records.values():
            current = json.loads(text(*DOCKER, "inspect", "--format", projection, record["id"]))
            need(current == record, "container changed before stop")
            command(*DOCKER, "stop", "--time", "30", record["id"])
            command(*DOCKER, "rm", record["id"])
        remaining = json.loads(text(*DOCKER, "network", "inspect", "--format", "{{json .Containers}}", network["id"]))
        need(not remaining, "network acquired another endpoint")
        command(*DOCKER, "network", "rm", network["id"])
        for service, image in expected_images.items():
            reference = "sovagrid-" + service + ":local"
            need(text(*DOCKER, "image", "inspect", "--format", "{{.Id}}", reference) == image, "image changed before untag")
            command(*DOCKER, "image", "rm", "--no-prune", reference)
        for name in receipt["unit_states"]:
            need(text("systemctl", "is-active", name, accepted=(0, 3, 4)) != "active", "managed unit remained active")
        runtime_expected = {}
        for path in set(core.SOCKET_PARENTS.values()) | {"/run/sovagrid-agent-control"}:
            root = Path(path)
            if not root.exists() and not root.is_symlink():
                continue
            info = root.lstat()
            need(stat.S_ISDIR(info.st_mode) and not any(root.iterdir()) and
                 ((info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o755) or
                  (path == "/run/sovagrid-agent-control" and info.st_uid == users["sovagrid"][2] and
                   info.st_gid == users["sovagrid"][3] and stat.S_IMODE(info.st_mode) == 0o700)),
                 "runtime directory has unknown state after stop")
            runtime_expected[path] = {"": {"kind": "dir", "uid": info.st_uid, "gid": info.st_gid,
                "mode": stat.S_IMODE(info.st_mode), "dev": info.st_dev, "ino": info.st_ino}}
            allowed.add(path)
        proofs = {}
        fixture.check_all(provenance, ROOTS)
        fixture.check_units(provenance)
        runtime_roots = set(core.SOCKET_PARENTS.values()) | {"/run/sovagrid-agent-control"}
        for path in sorted(allowed):
            if not Path(path).exists() and not Path(path).is_symlink():
                continue
            parent, leaf = core._safe_parent(Path("/"), path, uid=0)
            try:
                info = os.fstat(parent)
                proofs[path] = {"parent": [info.st_dev, info.st_ino], "resource": core.tree_proof(parent, leaf)}
                if path in runtime_roots:
                    need(proofs[path]["resource"]["entries"] == 1 and proofs[path]["resource"]["bytes"] == 0,
                         "runtime directory gained an unknown descendant")
            finally:
                os.close(parent)
        # A fresh quarantine digest cannot authorize a descendant added after
        # the earlier ownership check. Recheck the producer ledger after every
        # digest has been captured; Publisher still checks that exact digest
        # immediately before/after the no-replacement quarantine rename.
        fixture.check_all(provenance, ROOTS)
        fixture.check_units(provenance)
        for name, record in users.items():
            need(list(pwd.getpwnam(name)) + [sorted(os.getgrouplist(name, record[3]))] == record and no_user_processes(record[2]),
                 "service identity is changed or still in use")
        cleanup_id = uuid.uuid4().hex
        publisher = core.Publisher(Path("/"), cleanup_id, set(proofs))
        # Each live root is first moved without replacement, then checked again
        # under its unique private sibling name before descriptor-based removal.
        paths = sorted(proofs, key=lambda value: (value == str(SOURCE), -value.count("/"), value))
        for index, path in enumerate(paths):
            shadow = ".sovagrid-restore-" + cleanup_id + "-" + str(index)
            step = {"kind": "publish", "resource": path,
                    "desired": {"shadow": shadow, "sha256": proofs[path]["resource"]["sha256"]}}
            publisher.undo(step, proofs[path])
            parent, _leaf = core._safe_parent(Path("/"), path, uid=0)
            try:
                expected = (provenance["trees"].get(path) or provenance["units"].get(path) or
                            runtime_expected.get(path))
                need(expected is not None, "quarantine lacks producer provenance")
                remove_quarantined(fixture, core, parent, shadow, path, proofs[path], expected)
            finally:
                os.close(parent)
        # Ubuntu userdel may remove an empty, matching private primary group.
        # Seal every planned group immediately before our identity deletions.
        for name, record in groups.items():
            need(list(grp.getgrnam(name)) == record and not grp.getgrnam(name).gr_mem,
                 "group changed before user deletion")
        for name, record in users.items():
            need(list(pwd.getpwnam(name)) + [sorted(os.getgrouplist(name, record[3]))] == record and no_user_processes(record[2]),
                 "identity changed before user deletion")
            command("/usr/sbin/userdel", name)
        for name, record in groups.items():
            try:
                current = grp.getgrnam(name)
            except KeyError:
                need(name in users and users[name][3] == record[2] and
                     not any(group.gr_gid == record[2] for group in grp.getgrall()) and
                     not any(user.pw_gid == record[2] for user in pwd.getpwall()),
                     "unrelated planned group disappeared or its ID was reused")
                continue
            need(list(current) == record and not current.gr_mem and
                 not any(user.pw_gid == record[2] for user in pwd.getpwall()),
                 "group changed or gained another user")
            command("/usr/sbin/groupdel", name)
        command("systemctl", "daemon-reload")
    print("PORTABLE_RESTORE_VM_TARGET_CLEANED", flush=True)


@contextlib.contextmanager
def public_restore_inputs(restore, receiver, identity):
    """Retain only the five exact producer files while receiver republishes them.

    The real source and destination share this disposable VM. Production
    refuses to adopt an existing destination, so quarantine the immutable
    inputs on the same filesystem without deleting or repairing any entry.
    Every source FD remains held through transfer and every original byte
    remains in the private quarantine, including after a failed RPC.
    """
    need(re.fullmatch(r"[0-9a-f]{32}", identity), "invalid public restore archive")
    host = Path("/var/lib/sovagrid-host-backups")
    images = Path("/var/lib/sovagrid-host-image-exports") / identity
    paths = {"host_manifest": host / (identity + ".manifest.json"),
             "host": host / (identity + ".tar.gz"),
             "images_manifest": images / "manifest.json", "images": images / "images.tar",
             "receipt": images / "receipt.json"}
    with contextlib.ExitStack() as held:
        folders = {}
        for folder in (host, images.parent, images):
            fd = receiver._safe_open(folder, directory=True)
            held.callback(os.close, fd)
            receiver._private(os.fstat(fd), directory=True)
            folders[folder] = fd
        need(set(os.listdir(folders[images])) == {"manifest.json", "images.tar", "receipt.json"},
             "public snapshot image directory has foreign descendants")
        descriptors, metadata, before = {}, {}, {}
        for part, path in paths.items():
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=folders[path.parent])
            held.callback(os.close, fd)
            info = os.fstat(fd)
            receiver._private(info)
            need(0 < info.st_size <= receiver.MAX_PARTS[part], "invalid public snapshot part size")
            digest = receiver._hash_fd(fd, info.st_size)
            need(receiver._fingerprint(os.fstat(fd)) == receiver._fingerprint(info) and
                 receiver._fingerprint(os.stat(path.name, dir_fd=folders[path.parent], follow_symlinks=False)) ==
                 receiver._fingerprint(info), "public snapshot changed before quarantine")
            descriptors[part], before[part] = fd, info
            metadata[part] = {"bytes": info.st_size, "sha256": digest}
        exporter = restore._sibling("host_image_export.py", "sovagrid_ci_public_image_verifier")
        need(exporter.verify(identity, require_receipt=True)["receipt"]["protocol"] ==
             "sovagrid-portable-host-receipt-v2", "public snapshot receipt is not verified v2")
        sealed = fixture_module().inventory(images)
        private = Path(tempfile.mkdtemp(prefix=".sovagrid-public-restore-ci-", dir=host.parent))
        private.chmod(0o700)
        parent = os.open(private, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        held.callback(os.close, parent)
        private_info = os.fstat(parent)
        receiver._private(private_info, directory=True)
        need(all(os.fstat(fd).st_dev == private_info.st_dev for fd in folders.values()),
             "public snapshot quarantine must share its source filesystem")
        for part in ("host_manifest", "host"):
            path, info = paths[part], before[part]
            need(receiver._fingerprint(os.stat(path.name, dir_fd=folders[host], follow_symlinks=False)) ==
                 receiver._fingerprint(info), "public snapshot changed before rename")
            os.rename(path.name, part, src_dir_fd=folders[host], dst_dir_fd=parent)
            moved = os.stat(part, dir_fd=parent, follow_symlinks=False)
            need((moved.st_dev, moved.st_ino) == (info.st_dev, info.st_ino),
                 "public snapshot quarantine inode changed")
        image_info = os.fstat(folders[images])
        need(fixture_module().inventory(images) == sealed and
             (images.stat().st_dev, images.stat().st_ino) == (image_info.st_dev, image_info.st_ino),
             "public image snapshot changed before rename")
        os.rename(identity, "images", src_dir_fd=folders[images.parent], dst_dir_fd=parent)
        moved = os.stat("images", dir_fd=parent, follow_symlinks=False)
        need((moved.st_dev, moved.st_ino) == (image_info.st_dev, image_info.st_ino) and
             fixture_module().inventory(private / "images") == sealed,
             "public image snapshot quarantine changed")
        for fd in (folders[host], folders[images.parent], parent):
            os.fsync(fd)
        # rename may update ctime; content, owner, mode and the exact inode must
        # remain those just verified from the producer. Hold this new stable
        # fingerprint for every bounded transfer read.
        fingerprints = {}
        for part, fd in descriptors.items():
            info = os.fstat(fd)
            receiver._private(info)
            need((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) ==
                 (before[part].st_dev, before[part].st_ino, before[part].st_size, before[part].st_mtime_ns) and
                 receiver._hash_fd(fd, info.st_size) == metadata[part]["sha256"] and
                 receiver._fingerprint(os.fstat(fd)) == receiver._fingerprint(info),
                 "public snapshot quarantine bytes changed")
            fingerprints[part] = receiver._fingerprint(os.fstat(fd))
        yield descriptors, metadata, fingerprints


def run_public_restore(bundle, identity):
    """Real public bootstrap, framing, registration and detached apply once."""
    guard()
    expected = verified_bundle(bundle)
    restore, core, _runtime = api(bundle)
    need(core.APPLY_ENABLED is True, "public restore requires the pinned enabled release")
    archive = Path("/root/sovagrid-signed-next/source.tar.gz")
    with os.fdopen(os.open(archive, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0 and
             stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 64 * 1024**2,
             "public runner archive is not private and bounded")
        fixture_module().archive_pin(archive, expected)
        need(core._fingerprint(archive.lstat()) == core._fingerprint(info), "public runner archive was replaced")
        raw = stream.read(64 * 1024**2 + 1)
        need(len(raw) == info.st_size and core._fingerprint(os.fstat(stream.fileno())) == core._fingerprint(info),
             "public runner archive changed")
    spec = importlib.util.spec_from_file_location("sovagrid_ci_public_rpc",
        bundle / "sovagrid-blueprint/tests/portable_restore_bootstrap_vm.py")
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    operation, archive_sha = uuid.uuid4().hex, hashlib.sha256(raw).hexdigest()
    script = (bundle / "sovagrid-blueprint/deploy/portable_restore_bootstrap.sh").read_text()
    reply = smoke.command(["/bin/bash", "-c", script, "--", operation, str(len(raw)), archive_sha, expected],
                          raw, timeout=900)
    need(reply == [{"ok": True, "protocol": smoke.PROTOCOL, "operation_id": operation,
                   "runner_archive_sha256": archive_sha, "runner_manifest_sha256": expected,
                   "dependencies_ready": True}], "public bootstrap pins are not exact")
    work = Path("/root/.sovagrid-restore") / operation
    receiver = load(bundle, "portable_restore_receiver.py", "sovagrid_ci_public_receiver")
    args = ["/usr/bin/python3", "-B", "-I",
            str(work / "runner/sovagrid-blueprint/deploy/portable_restore_receiver.py"), "serve", operation]

    def rpc(frame, payload=b"", timeout=180):
        values = smoke.command(args, smoke.canonical(frame) + payload, timeout=timeout)
        need(len(values) == 1 and values[0].get("operation_id") == operation, "public RPC operation changed")
        return values[0]

    with public_restore_inputs(restore, receiver, identity) as (files, artifacts, fingerprints):
        request = {"protocol": smoke.PROTOCOL, "operation_id": operation, "archive_id": identity,
                   "runner_archive_sha256": archive_sha, "runner_manifest_sha256": expected, "artifacts": artifacts}
        rpc({"action": "init", "request": request})
        for part, fd in files.items():
            offset = 0
            while offset < artifacts[part]["bytes"]:
                need(receiver._fingerprint(os.fstat(fd)) == fingerprints[part], "public input changed during upload")
                data = os.pread(fd, min(receiver.MAX_CHUNK, artifacts[part]["bytes"] - offset), offset)
                need(bool(data), "public input ended before its declared size")
                rpc({"action": "receive", "part": part, "offset": offset, "length": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()}, data)
                offset += len(data)
            need(receiver._fingerprint(os.fstat(fd)) == fingerprints[part], "public input changed after upload")
        need(rpc({"action": "register"})["registered"] is True, "public receiver did not register the complete pair")
    preview = rpc({"action": "preview"})
    need(preview["backend_supported"] is True and preview["apply_available"] is True and
         preview["blockers"] == [] and SHA.fullmatch(preview.get("apply_review_sha256", "")),
         "public restore preview is not available")
    start = {"action": "start", "apply_review_sha256": preview["apply_review_sha256"]}
    need(rpc(start)["phase"] == "accepted", "public restore start was not accepted")
    original = private_json(work / "target-operation.json", maximum=16384)
    # Every rpc() starts and closes a different receiver process. Poll after
    # the first disconnect, then replay a potentially lost start ACK using the
    # exact original CAS. Neither reconnect may replace the durable worker.
    rpc({"action": "operation-status"})
    rpc(start)
    deadline = time.monotonic() + 1800
    while True:
        current = rpc({"action": "operation-status"})
        control = private_json(work / "target-operation.json", maximum=16384)
        need(all(control[key] == original[key] for key in ("worker_nonce", "unit", "apply_review_sha256")),
             "public reconnect launched another worker")
        need(current["error"] is None and current["phase"] not in ("failed", "rolled_back", "recovery_required"),
             "public restore worker failed")
        if current["phase"] == "committed" and current["worker_active"] is False:
            break
        need(time.monotonic() < deadline, "public detached restore did not finish")
        time.sleep(1)
    need(rpc(start)["phase"] == "committed" and
         private_json(work / "target-operation.json", maximum=16384)["worker_nonce"] == original["worker_nonce"],
         "public delayed acknowledgement replayed a completed apply")
    need(core.host_status(restore, identity)["phase"] == "committed" and not core.FENCE.exists(),
         "public restore did not commit without its fence")
    print("PORTABLE_RESTORE_VM_PUBLIC_DETACHED_APPLY_AND_RECONNECT_PASSED", flush=True)


def stage(bundle, identity):
    with enabled_vm_api(bundle) as (restore, _core, _runtime):
        plan = restore.portable_clean_plan(identity)
        need(plan["target_empty"] and plan["target_ready"] and plan["blockers"] == [], "target is not clean")
        restore.portable_stage(identity, plan["review_sha256"])
        preview = restore.portable_apply_preview(identity)
        need(preview["target_ready"] and preview["backend_supported"] and preview["apply_available"],
             "staged target is not ready")
        return preview["apply_review_sha256"]


def child(identity, review, mode):
    bundle = Path(__file__).resolve().parents[2]
    with enabled_vm_api(bundle) as (restore, core, runtime):
        return _enabled_child(restore, core, runtime, identity, review, mode)


def _enabled_child(restore, core, runtime, identity, review, mode):
    execute, health = runtime.Runtime.execute, runtime.Runtime.health

    def execute_with_exit(self, step, proof):
        if mode == "exit-before-service" and step["kind"] == "service":
            os._exit(91)  # Actual process death after persisted intent, no finally.
        return execute(self, step, proof)

    def failed_health(self, value):
        health(self, value)  # Real containers, HTTP, TLS, Gateway, Agent and sockets.
        if mode == "health-failure":
            script = '''import sqlite3
with sqlite3.connect('/data/hub.sqlite',timeout=15) as db:
 db.execute('CREATE TABLE sovagrid_restore_ci_writeproof (id INTEGER PRIMARY KEY, value TEXT NOT NULL)')
 db.execute("INSERT INTO sovagrid_restore_ci_writeproof VALUES (1, 'preserve-this-runtime-write')")
'''
            result = hub_sql_fixture(script, timeout=25)
            need(result.returncode == 0 and not result.stdout, "bounded Hub runtime witness write failed")
            raise core.Refused("CI_HEALTH_FAILURE")

    output = io.StringIO()
    with (patch.object(runtime.Runtime, "execute", execute_with_exit),
          patch.object(runtime.Runtime, "health", failed_health), contextlib.redirect_stdout(output)):
        status = restore.main(["portable-apply", identity, review])
    value = json.loads(output.getvalue())
    need(status == 0 and value.get("phase") == ("recovery_required" if mode == "health-failure" else "committed"),
         "real apply CLI returned " + str(value.get("phase", value.get("error", "NO_STATE"))))
    print("PORTABLE_RESTORE_VM_CHILD_" + value["phase"].upper(), flush=True)


def run_child(bundle, identity, review, mode):
    result = command("/usr/bin/python3", "-I", str(bundle / "sovagrid-blueprint/tests/portable_restore_apply_vm.py"),
                     "child", identity, review, mode, timeout=1800, accepted=(0, 1, 40, 91))
    expected = 91 if mode == "exit-before-service" else 0
    if result.returncode != expected:
        restore, core, _runtime = api(bundle)
        try:
            state = core.host_status(restore, identity)
        except Exception:
            state = {"phase": "NOT_CREATED"}
        print("PORTABLE_RESTORE_VM_UNEXPECTED_CHILD_STATE " + json.dumps(state, sort_keys=True), flush=True)
        # The child's top-level handler emits only its fixed refusal category.
        # Do not forward arbitrary subprocess stderr or credentials.
        codes = re.findall(rb"\b[A-Z][A-Z0-9_]{3,63}\b", result.stderr)
        print("PORTABLE_RESTORE_VM_CHILD_CODES " + ",".join(code.decode("ascii") for code in codes[-8:]), flush=True)
        need(False, "child process failed validation")
    if result.stdout:
        print(result.stdout.decode("ascii"), end="", flush=True)


def hub_request(method, path, token, *, body=None, idempotent=False):
    need(path.startswith("/api/v1/") and "\r" not in path and "\n" not in path, "invalid fixed Hub route")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    if idempotent:
        headers["Idempotency-Key"] = str(uuid.uuid4())
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request("http://127.0.0.1:8766" + path, data=data, method=method, headers=headers)
    with opener.open(request, timeout=20) as response:
        need(response.status in (200, 201, 202), "unexpected Hub operation status")
        raw = response.read(65537)
        need(len(raw) <= 65536, "oversized Hub operation result")
        return json.loads(raw)


def seed_queue_sentinel():
    """Retain a valid pre-backup command while the source admission gate is shut."""
    fixture = fixture_module()
    value = fixture.ledger()
    need("sentinel" not in value, "stale-command fixture already exists")
    server = json.loads(Path("/etc/sovagrid/agent.json").read_bytes())["server_id"]
    password = Path("/etc/sovagrid/admin-password").read_text().strip()
    token = hub_request("POST", "/api/v1/session", "", body={"username": "admin", "password": password})["token"]
    password = ""
    identity, nonce = str(uuid.uuid4()), uuid.uuid4().hex
    pending = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    effect = ".restore-ci-stale-command-" + nonce
    target = Path("/var/lib/sovagrid-agent/files") / effect
    need(not os.path.lexists(target), "stale-command effect already exists")
    data = {"server": server, "job": identity, "pending": pending,
            "session_hash": hashlib.sha256(token.encode()).hexdigest(), "now": int(time.time()),
            "command": "printf stale-command-must-not-run > " + str(target)}
    script = '''import hashlib,json,sqlite3,sys
data=json.load(sys.stdin)
with sqlite3.connect('/data/hub.sqlite',timeout=30) as db:
 db.execute('BEGIN IMMEDIATE')
 assert db.execute('SELECT remote_commands_enabled FROM servers WHERE id=?',(data['server'],)).fetchone()==(0,)
 assert db.execute('SELECT 1 FROM sessions WHERE token_hash=? AND expires_at>?',(data['session_hash'],data['now'])).fetchone()==(1,)
 db.execute("INSERT INTO jobs(id,server_id,actor_user_id,chat_id,source,session_token_hash,command_sha256,control_kind,command,state,created_at) VALUES(?,?,0,0,'web',?,?,'generic',?,'queued',?)",
  (data['job'],data['server'],data['session_hash'],hashlib.sha256(data['command'].encode()).hexdigest(),data['command'],data['now']))
 db.execute('INSERT INTO pending_commands(code_hash,server_id,actor_user_id,chat_id,command,created_at,expires_at) VALUES(?,?,1,1,?,?,?)',
  (data['pending'],data['server'],data['command'],data['now'],data['now']+86400))
'''
    result = hub_sql_fixture(script, input=json.dumps(data).encode(), timeout=45)
    need(result.returncode == 0 and not result.stdout, "could not seed the bounded stale-command fixture")
    value["sentinel"] = {"job": identity, "pending": pending, "server": server, "effect": effect}
    fixture.save(value)
    verify_queue_sentinel(restored=False)
    return token


def verify_queue_sentinel(*, restored):
    value = fixture_module().ledger()["sentinel"]
    need(re.fullmatch(r"\.restore-ci-stale-command-[0-9a-f]{32}", value["effect"]), "invalid stale-command effect")
    row = hub_sql_read("SELECT state,command='',server_id FROM jobs WHERE id=?", [value["job"]])[0]
    pending = hub_sql_read("SELECT COUNT(*) FROM pending_commands WHERE code_hash=?", [value["pending"]])[0][0]
    need(row == (["cancelled", 1, value["server"]] if restored else ["queued", 0, value["server"]]) and
         pending == (0 if restored else 1), "stale jobs/Telegram confirmation were not quarantined" if restored else
         "source fixture command lost its valid queued state")
    if restored:
        audit = hub_sql_read("SELECT details FROM audit_events WHERE action='portable_restore_queue_quarantined' ORDER BY id DESC LIMIT 1", [])
        counts = json.loads(audit[0][0]) if len(audit) == 1 else {}
        need(set(counts) == {"queued_jobs_cancelled", "pending_commands_removed"} and
             all(type(number) is int and number >= 1 for number in counts.values()),
             "quarantine did not record aggregate counts")
    need(not os.path.lexists(Path("/var/lib/sovagrid-agent/files") / value["effect"]), "pre-backup command was executed")


def hub_sql_fixture(script, *, input=None, timeout=25):
    # SQLite canonicalizes paths, so a host process running as Hub cannot cross
    # the root-only /var/lib/sovagrid parent even with a preselected cwd. Use
    # the verified live Hub's /data bind and UID for all WAL connections.
    projection = ('{"id":{{json .Id}},"name":{{json .Name}},"running":{{json .State.Running}},'
                  '"user":{{json .Config.User}},"labels":{{json .Config.Labels}},'
                  '"mounts":{{json .Mounts}}}')
    hub = json.loads(text(*DOCKER, "inspect", "--type", "container", "--format", projection, "sovagrid-hub-1"))
    need(SHA.fullmatch(hub["id"]) is not None and hub["name"] == "/sovagrid-hub-1" and
         hub["running"] is True and hub["user"] == "10001:10001" and
         hub["labels"].get("com.docker.compose.project") == "sovagrid" and
         hub["labels"].get("com.docker.compose.service") == "hub" and
         any(mount.get("Type") == "bind" and mount.get("Source") == "/var/lib/sovagrid/hub" and
             mount.get("Destination") == "/data" and mount.get("RW") is True for mount in hub["mounts"]),
         "Hub SQL fixture container identity changed")
    return subprocess.run([*DOCKER, "exec", "-i", "--user", "10001:10001", hub["id"],
        "python3", "-I", "-c", script], input=input, stdin=subprocess.DEVNULL if input is None else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})


def hub_sql_read(query, parameters):
    script = '''import json,sqlite3,sys
request=json.load(sys.stdin)
with sqlite3.connect('file:/data/hub.sqlite?mode=ro',uri=True,timeout=15) as db:
 print(json.dumps(db.execute(request['query'],request['parameters']).fetchall()))
'''
    result = hub_sql_fixture(script, input=json.dumps({"query": query, "parameters": parameters}).encode())
    need(result.returncode == 0 and len(result.stdout) <= 8192, "bounded Hub fixture read failed")
    return json.loads(result.stdout)


def hub_sql_read_offline(bundle, restore, core, identity, query, parameters):
    """Read only four fixed witnesses after rollback has removed the Hub."""
    guard()
    sentinel = fixture_module().ledger()["sentinel"]
    allowed = {"SELECT state,command='',server_id FROM jobs WHERE id=?": [sentinel["job"]],
               "SELECT COUNT(*) FROM pending_commands WHERE code_hash=?": [sentinel["pending"]],
               "SELECT details FROM audit_events WHERE action='portable_restore_queue_quarantined' ORDER BY id DESC LIMIT 1": [],
               "SELECT value FROM sovagrid_restore_ci_writeproof WHERE id=1": []}
    need(query in allowed and parameters == allowed[query], "invalid fixed offline SQLite witness")
    verified_bundle(bundle)
    with core.transaction_locks(restore) as (stage_fd, _exporter), contextlib.ExitStack() as held:
        value = core.Journal(stage_fd, identity).read()
        need(value is not None and value["id"] == identity and value["phase"] == "recovery_required" and
             value["bindings"]["source_manifest_sha256"] == expected_manifest(), "offline SQLite witness is not fenced")
        fence = core.Fence(restore.backup.ROOT)
        parent, leaf = core._safe_parent(restore.backup.ROOT, str(core.FENCE), uid=0)
        held.callback(os.close, parent)
        need(fence._read(parent, leaf) == fence._raw(identity, value["bindings"]), "offline SQLite fence changed")
        runtime = load(bundle, "portable_restore_runtime.py", "sovagrid_ci_offline_plan")
        plan = runtime.load(restore, core, stage_fd, identity, value["bindings"])
        roots = [resource for resource in plan["resources"] if resource["target"] == "/var/lib/sovagrid"]
        publications = [step for step in value["steps"] if step["kind"] == "publish" and step["resource"] == "/var/lib/sovagrid"]
        need(len(roots) == len(publications) == 1, "offline SQLite lacks a publication proof")
        entries = roots[0]["entries"]
        need(all((entries[name]["kind"], entries[name]["uid"], entries[name]["gid"], entries[name]["mode"]) == expected
                 for name, expected in (("hub", ("dir", 10001, 10001, 0o700)),
                                        ("hub/hub.sqlite", ("file", 10001, 10001, 0o600)))),
             "offline SQLite plan identity changed")
        parent, leaf = core._safe_parent(restore.backup.ROOT, "/var/lib/sovagrid/hub", uid=0)
        held.callback(os.close, parent)
        parent_info = os.fstat(parent)
        proof = publications[0]["proof"]["resource"]
        need((parent_info.st_dev, parent_info.st_ino) == (proof["device"], proof["inode"]),
             "offline SQLite publication was replaced")
        directory = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        held.callback(os.close, directory)
        directory_info = os.fstat(directory)
        core._private(directory_info, directory=True, uid=10001, gid=10001)
        database = os.open("hub.sqlite", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        held.callback(os.close, database)
        before = os.fstat(database)
        core._private(before, directory=False, uid=10001, gid=10001)
        for suffix in ("-wal", "-shm"):
            try:
                sidecar = os.stat("hub.sqlite" + suffix, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            core._private(sidecar, directory=False, uid=10001, gid=10001)
        script = '''import hashlib,json,os,sqlite3,sys
request=json.load(sys.stdin)
os.fchdir(int(sys.argv[1]));os.chroot('.');os.chdir('/');os.close(int(sys.argv[1]))
os.setgroups([]);os.setgid(10001);os.setuid(10001);os.umask(0o077)
assert (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(10001,10001,10001,10001)
with sqlite3.connect('file:/hub.sqlite?mode=ro',uri=True,timeout=15) as db:
 print(json.dumps(db.execute(request['query'],request['parameters']).fetchall()))
'''
        result = subprocess.run(["/usr/bin/python3", "-B", "-I", "-c", script, str(directory)],
            input=json.dumps({"query": query, "parameters": parameters}).encode(), pass_fds=(directory,),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25, check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        need(result.returncode == 0 and len(result.stdout) <= 8192 and len(result.stderr) <= 8192,
             "bounded offline SQLite witness read failed")
        named_directory = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        core._private(os.fstat(directory), directory=True, uid=10001, gid=10001)
        core._private(named_directory, directory=True, uid=10001, gid=10001)
        need(core._fingerprint(before) == core._fingerprint(os.fstat(database)) and
             core._fingerprint(before) == core._fingerprint(os.stat("hub.sqlite", dir_fd=directory, follow_symlinks=False)) and
             (directory_info.st_dev, directory_info.st_ino) == (named_directory.st_dev, named_directory.st_ino),
             "offline SQLite witness location changed")
        return json.loads(result.stdout)


def verify_command_files_terminal(config, row, token):
    host = config["server_id"]
    prefix = "/api/v1/servers/" + host
    previous_gate = row["remote_commands_enabled"]
    hub_request("POST", prefix + "/commands", token, body={"enabled": True})
    try:
        job = hub_request("POST", prefix + "/jobs", token,
                          body={"command": "printf SG_RESTORE_COMMAND_OK"}, idempotent=True)["job"]
        deadline = time.monotonic() + 35
        while True:
            result = hub_request("GET", "/api/v1/jobs/" + job["id"], token)["job"]
            if result["state"] in ("succeeded", "failed", "cancelled"):
                need(result["state"] == "succeeded" and result["exit_code"] == 0 and
                     "SG_RESTORE_COMMAND_OK" in result["output"], "restored command execution failed")
                break
            need(time.monotonic() < deadline, "restored command did not complete")
            time.sleep(0.2)

        def files(body):
            operation = hub_request("POST", prefix + "/files/operations", token,
                                    body=body, idempotent=True)["operation"]
            endpoint = prefix + "/files/operations/" + operation["id"]
            deadline = time.monotonic() + 35
            try:
                while True:
                    result = hub_request("GET", endpoint, token)["operation"]
                    if result["state"] in ("succeeded", "failed"):
                        need(result["state"] == "succeeded", "restored file operation failed")
                        return result["result"]
                    need(time.monotonic() < deadline, "restored file operation did not complete")
                    time.sleep(0.2)
            finally:
                hub_request("DELETE", endpoint, token)

        need("workspace" in files({"action": "roots"})["roots"], "restored file root is absent")
        name = "restore-ci-" + uuid.uuid4().hex + ".txt"
        target = Path("/var/lib/sovagrid-agent/files") / name
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            agent = pwd.getpwnam("sovagrid")
            os.fchown(descriptor, agent.pw_uid, agent.pw_gid)
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, b"before-ui-write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        before = files({"action": "read", "root": "workspace", "path": name})
        files({"action": "write", "root": "workspace", "path": name, "etag": before["etag"],
               "content": base64.urlsafe_b64encode(b"after-ui-write").decode().rstrip("=")})
        need(target.read_bytes() == b"after-ui-write" and target.stat().st_uid == agent.pw_uid,
             "file UI did not write as the restored unprivileged Agent")
        fixture = fixture_module()
        fixture.extend(fixture.ledger(), {"/var/lib/sovagrid-agent": {"files/" + name}})

        session = hub_request("POST", prefix + "/terminal/sessions", token,
                              body={"cols": 80, "rows": 24}, idempotent=True)["session"]
        endpoint = prefix + "/terminal/sessions/" + session["id"]
        deadline, after, sent = time.monotonic() + 40, 0, False
        output = bytearray()
        try:
            while True:
                events = hub_request("GET", endpoint + "/events?after=" + str(after), token)
                for event in events["events"]:
                    if event["type"] == "output":
                        output.extend(base64.urlsafe_b64decode(event["data"] + "=" * (-len(event["data"]) % 4)))
                after = events["next_after"]
                need(len(output) <= 32768, "oversized terminal verification output")
                if events["state"] == "active" and not sent:
                    raw = b"unset HISTFILE; printf 'SG_RESTORE_%s_OK\\n' TERMINAL; exit\n"
                    hub_request("POST", endpoint + "/input", token,
                                body={"seq": 1, "data": base64.urlsafe_b64encode(raw).decode().rstrip("=")})
                    sent = True
                if events["state"] == "closed":
                    need(sent and events["exit_code"] in (None, 0) and b"SG_RESTORE_TERMINAL_OK" in output,
                         "restored PTY did not execute the bounded command")
                    break
                need(time.monotonic() < deadline, "restored terminal did not finish")
        finally:
            hub_request("DELETE", endpoint, token)
    finally:
        hub_request("POST", prefix + "/commands", token, body={"enabled": previous_gate})
    print("PORTABLE_RESTORE_VM_REAL_COMMAND_FILE_AND_PTY_VERIFIED", flush=True)


def verify_live(bundle, since):
    location = bundle / "sovagrid-blueprint/tests/integrated_install_vm.py"
    spec = importlib.util.spec_from_file_location("sovagrid_ci_restored_live", location)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.verify_agent_quiescence()
    config = json.loads(Path("/etc/sovagrid/agent.json").read_bytes())
    host = config["server_id"]
    password = Path("/etc/sovagrid/admin-password").read_text().strip()
    token = module.request("POST", "/api/v1/session", body={"username": "admin", "password": password})[1]["token"]
    try:
        deadline = time.monotonic() + 40
        while True:
            rows = hub_request("GET", "/api/v1/servers", token)["servers"]
            row = next(item for item in rows if item["id"] == host)
            history = hub_request("GET", "/api/v1/servers/" + host + "/metrics?limit=1", token)["metrics"]
            if row["online"] is True and type(row["last_seen"]) is int and row["last_seen"] >= since and history:
                break
            need(time.monotonic() < deadline, "restored Agent did not publish metrics")
            time.sleep(1)
        need(config.get("allow_interactive_terminal") is True and config.get("allow_file_manager") is True,
             "terminal/files local opt-ins were lost")
        need(Path("/var/lib/sovagrid-agent/files").stat().st_uid == pwd.getpwnam("sovagrid").pw_uid and
             Path("/var/lib/sovagrid-shell").stat().st_uid == 10003, "runtime owners were not restored")
        verify_command_files_terminal(config, row, token)
    finally:
        module.request("DELETE", "/api/v1/session", token=token)
    print("PORTABLE_RESTORE_VM_REAL_HUB_AGENT_TLS_VERIFIED", flush=True)


def run():
    guard()
    expected = expected_manifest()
    fixture = fixture_module()
    provenance = fixture.ledger()
    need(provenance["manifest_sha256"] == expected, "fixture manifest differs from artifact pin")
    fixture.source_pin(SOURCE, expected, allow_generated=True)
    fixture.check_all(provenance, ROOTS)
    fixture.check_units(provenance)
    need(SOURCE.is_dir() and not SOURCE.is_symlink(), "installed CI source is missing")
    private = Path(tempfile.mkdtemp(prefix=PREFIX, dir="/root"))
    private.chmod(0o700)
    bundle = private / "bundle"
    shutil.copytree(SOURCE, bundle, symlinks=True, ignore=shutil.ignore_patterns("__pycache__"))
    manifest = verified_bundle(bundle)
    restore, core, _runtime = api(bundle)
    need(restore.backup.plan()["layout"] == "full" and not Path("/etc/sovagrid-vpn-routing/policy.json").exists() and
         not Path("/etc/sovagrid/public-web/state.json").exists(), "requires basic full CI layout without live routing/public overlay")
    need(not text("wg", "show", "interfaces"), "live WireGuard must not be present")
    snapshots = [snapshot(bundle, manifest)]
    source_session = seed_queue_sentinel()
    try:
        for _ in range(2):
            snapshots.append(snapshot(bundle, manifest))
            verify_queue_sentinel(restored=False)
    finally:
        hub_request("DELETE", "/api/v1/session", source_session)
        source_session = ""
    pin = stop_ci_guests_and_retag(bundle)
    try:
        uninstall(bundle, *snapshots[0])
        first, _receipt = snapshots[0]
        review = stage(bundle, first)
        run_child(bundle, first, review, "exit-before-service")
        need(core.FENCE.is_file(), "process death did not retain the persistent fence")
        recovered = core.recover_host(restore, first)
        need(recovered["phase"] == "rolled_back" and not core.FENCE.exists(), "pre-service interruption did not fully recover")
        need(restore.portable_clean_plan(snapshots[1][0])["target_empty"], "recovery left target resources")
        print("PORTABLE_RESTORE_VM_REAL_PROCESS_EXIT_RECOVERED", flush=True)
        second, receipt = snapshots[1]
        started = int(time.time())
        if core.APPLY_ENABLED:
            run_public_restore(bundle, second)
        else:
            review = stage(bundle, second)
            run_child(bundle, second, review, "success")
        record_restored(bundle, second)
        verify_queue_sentinel(restored=True)
        verify_live(bundle, started)
        verify_queue_sentinel(restored=True)
        need(core.host_status(restore, second)["phase"] == "committed" and not core.FENCE.exists(), "successful apply was not committed")
        uninstall(bundle, second, receipt, restore_id=second)
        third, _receipt = snapshots[2]
        run_child(bundle, third, stage(bundle, third), "health-failure")
        state = core.host_status(restore, third)
        need(state["phase"] == "recovery_required" and core.FENCE.is_file(), "changed runtime data was not fenced")
        with patch.object(sys.modules[__name__], "hub_sql_read",
                          side_effect=lambda query, parameters: hub_sql_read_offline(bundle, restore, core, third, query, parameters)):
            verify_queue_sentinel(restored=True)
            need(hub_sql_read("SELECT value FROM sovagrid_restore_ci_writeproof WHERE id=1", []) ==
                 [["preserve-this-runtime-write"]], "failed health discarded newly accepted database data")
        print("PORTABLE_RESTORE_VM_CHANGED_DATABASE_PRESERVED_AND_FENCED", flush=True)
    finally:
        restore_ci_image(pin)


if __name__ == "__main__":
    try:
        if len(sys.argv) == 1:
            run()
        elif sys.argv[1:] == ["record-fixture"]:
            record_fixture()
        else:
            need(len(sys.argv) == 5 and sys.argv[1] == "child" and
                 re.fullmatch(r"[0-9a-f]{32}", sys.argv[2]) is not None and SHA.fullmatch(sys.argv[3]) is not None and
                 sys.argv[4] in ("exit-before-service", "success", "health-failure"), "invalid child request")
            child(sys.argv[2], sys.argv[3], sys.argv[4])
    except Exception as error:
        # All assertions use fixed diagnostic categories; no credentials,
        # command bodies, database rows or fixture private state are logged.
        print(str(error), file=sys.stderr, flush=True)
        raise SystemExit(1)
