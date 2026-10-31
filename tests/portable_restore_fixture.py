# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Producer-owned provenance for the destructive disposable-VM restore gate.

This is a test fixture ledger, never an installation/adoption API. Creation is
explicit at initial install; later fixture producers register only the exact
objects they created. Cleanup cannot bless a fresh recursive directory walk.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile


MARKER = Path("/var/lib/.sovagrid-portable-restore-ci-fixture.json")
SOURCE = Path("/opt/sovagrid-src")
SHA = re.compile(r"[0-9a-f]{64}\Z")
PROTOCOL = "sovagrid-portable-restore-ci-fixture-v1"
COMPONENTS = {"sovagrid-blueprint", "sovagrid-hub", "sovagrid-web", "sovagrid-agent", "sovagrid-vpn"}
UNIT_ROOT = Path("/etc/systemd/system")
UNIT_NAME = re.compile(r"sovagrid-[a-z0-9-]+@?\.(?:service|socket|timer)\Z")
# These are product-owned mutable leaf names; directories and every other
# file retain the producer's inode/content proof. Optional SQLite sidecars
# have a closed basename and the database's exact owner/mode.
MUTABLE = {"/var/lib/sovagrid/hub/hub.sqlite", "/var/lib/sovagrid/vpn/status.json",
           "/var/lib/sovagrid-containers/snapshot.json"}
OPTIONAL = {"/var/lib/sovagrid/hub/hub.sqlite-wal": "/var/lib/sovagrid/hub/hub.sqlite",
            "/var/lib/sovagrid/hub/hub.sqlite-shm": "/var/lib/sovagrid/hub/hub.sqlite"}


def need(value, reason):
    if not value:
        raise RuntimeError("portable restore fixture: " + reason)


def guard():
    need(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true" and
         os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.environ.get("RUNNER_OS") == "Linux" and
         re.fullmatch(r"[1-9][0-9]{0,30}", os.environ.get("GITHUB_RUN_ID", "")) is not None,
         "requires the exact disposable GitHub run")


def read(path, limit=8 * 1024**2):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0 and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= limit, "unsafe private provenance")
        raw = os.read(descriptor, limit + 1)
        need(len(raw) == info.st_size, "provenance changed during read")
        return json.loads(raw)
    finally:
        os.close(descriptor)


def ledger():
    guard()
    value = read(MARKER)
    need(value.get("protocol") == PROTOCOL and value.get("run_id") == os.environ["GITHUB_RUN_ID"] and
         value.get("source") == str(SOURCE) and SHA.fullmatch(value.get("manifest_sha256", "")),
         "provenance belongs to another run")
    return value


def save(value, *, initial=False):
    guard()
    need(initial == (not os.path.lexists(MARKER)), "provenance creation/replacement mismatch")
    parent = MARKER.parent.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == parent.st_gid == 0 and not parent.st_mode & 0o022,
         "unsafe provenance parent")
    descriptor, temporary = tempfile.mkstemp(prefix=MARKER.name + ".", dir=MARKER.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        if initial:
            os.link(temporary, MARKER, follow_symlinks=False)
            os.unlink(temporary)
        else:
            os.replace(temporary, MARKER)
        directory = os.open(MARKER.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def source_pin(root, expected, *, allow_generated=False):
    """Verify all bytes with stdlib before importing any installed helper."""
    need(SHA.fullmatch(expected or "") is not None, "missing artifact manifest pin")
    raw = (root / "sovagrid-bundle.json").read_bytes()
    need(len(raw) <= 512 * 1024 and hashlib.sha256(raw).hexdigest() == expected, "artifact manifest pin mismatch")
    value = json.loads(raw)
    need(set(value) == {"format", "components", "sha256"} and value["format"] == 1 and
         set(value["components"]) == COMPONENTS and isinstance(value["sha256"], dict), "invalid source map")
    expected_names = set(value["sha256"]) | {"sovagrid-bundle.json"}
    allowed_dirs = {""} | COMPONENTS
    for name, digest in value["sha256"].items():
        need(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.@-]+(?:/[A-Za-z0-9_.@-]+)*", name) and
             all(part not in (".", "..") for part in name.split("/")) and name.split("/")[0] in COMPONENTS and
             SHA.fullmatch(digest or ""), "invalid source filename")
        allowed_dirs.update(str(parent) for parent in Path(name).parents if str(parent) != ".")
    actual = inventory(root)
    names = set()
    for name, record in actual.items():
        need(record["uid"] == record["gid"] == 0 and not record["mode"] & 0o022, "unsafe pinned source")
        if record["kind"] == "dir":
            # Installer-created bytecode may only accompany a known source.
            need(name in allowed_dirs or allow_generated and name.endswith("/__pycache__") and name[:-12] in allowed_dirs,
                 "unexpected pinned source directory")
            continue
        bytecode = re.fullmatch(r"(.+)/__pycache__/([A-Za-z0-9_]+)\.cpython-[0-9]+\.pyc", name)
        if allow_generated and bytecode and bytecode[1] + "/" + bytecode[2] + ".py" in expected_names:
            continue
        need(name in expected_names, "unexpected pinned source file")
        if name != "sovagrid-bundle.json":
            need(record["sha256"] == value["sha256"][name], "pinned source bytes changed")
        names.add(name)
    need(names == expected_names, "pinned source is incomplete")
    return actual


def inventory(root):
    """Closed no-link tree proof; callers must separately authorize path names."""
    parent = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return inventory_at(parent, root.name)
    finally:
        os.close(parent)


def inventory_at(parent_fd, leaf):
    """Read a renamed tree through its retained parent, without reopening paths."""
    records = {}

    def stable(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def visit(parent, leaf, name):
        need(len(records) < 20000, "fixture tree is oversized")
        info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
             "unsupported fixture descendant")
        record = {"kind": "dir" if stat.S_ISDIR(info.st_mode) else "file", "uid": info.st_uid,
                  "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode), "dev": info.st_dev, "ino": info.st_ino}
        records[name] = record
        descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW |
                             (os.O_DIRECTORY if record["kind"] == "dir" else 0), dir_fd=parent)
        try:
            need(stable(os.fstat(descriptor)) == stable(info), "fixture object changed")
            if record["kind"] == "dir":
                for child in sorted(os.listdir(descriptor)):
                    visit(descriptor, child, (name + "/" if name else "") + child)
            else:
                digest = hashlib.sha256()
                while True:
                    block = os.read(descriptor, 1024**2)
                    if not block:
                        break
                    digest.update(block)
                record.update(size=info.st_size, sha256=digest.hexdigest())
            need(stable(info) == stable(os.fstat(descriptor)) == stable(
                 os.stat(leaf, dir_fd=parent, follow_symlinks=False)), "fixture object changed")
        finally:
            os.close(descriptor)
    visit(parent_fd, leaf, "")
    return records


def unit_inventory(*, root=None, uid=0, gid=0):
    """Seal exact installed unit inodes, including the external-writer template."""
    root = UNIT_ROOT if root is None else root
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and info.st_gid == gid and
             not info.st_mode & 0o022, "unsafe fixture unit directory")
        result = {}
        for name in sorted(os.listdir(parent)):
            if not name.startswith("sovagrid-"):
                continue
            need(UNIT_NAME.fullmatch(name), "unrecorded fixture unit name")
            records = inventory_at(parent, name)
            record = records[""]
            need(set(records) == {""} and record["kind"] == "file" and record["uid"] == uid and
                 record["gid"] == gid and record["mode"] == 0o644, "unsafe fixture unit")
            result[str(root / name)] = records
        return result
    finally:
        os.close(parent)


def check_units(value, *, root=None, uid=0, gid=0):
    actual = unit_inventory(root=root, uid=uid, gid=gid)
    need(actual == value.get("units"), "producer-owned fixture unit changed")
    return actual


def archive_pin(path, expected):
    """Verify an exact producer bundle without extracting/executing a member."""
    need(SHA.fullmatch(expected or ""), "missing archive source pin")
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        need(len(members) <= 10000 and len({item.name.rstrip('/') for item in members}) == len(members) and
             all(item.isdir() or item.isfile() and item.size <= 32 * 1024**2 for item in members),
             "invalid producer source archive")
        manifests = [item for item in members if item.name == "sovagrid-bundle.json"]
        need(len(manifests) == 1 and manifests[0].size <= 512 * 1024, "missing producer archive source map")
        with archive.extractfile(manifests[0]) as stream:
            raw = stream.read()
        need(hashlib.sha256(raw).hexdigest() == expected, "producer archive source pin changed")
        hashes = json.loads(raw)["sha256"]
        actual = set()
        allowed_dirs = set(COMPONENTS)
        for name in hashes:
            allowed_dirs.update(str(parent) for parent in Path(name).parents if str(parent) != ".")
        for item in members:
            name = item.name.rstrip('/')
            if item.isdir():
                need(name in allowed_dirs, "unknown producer archive directory")
            elif name != "sovagrid-bundle.json":
                need(name in hashes, "unknown producer archive member")
                with archive.extractfile(item) as stream:
                    need(hashlib.sha256(stream.read()).hexdigest() == hashes[name], "producer archive bytes changed")
                actual.add(name)
        need(actual == set(hashes), "incomplete producer archive")


def compare(root, expected, *, allow_mutable=True, parent_fd=None, leaf=None):
    # root remains the ORIGINAL logical path for mutable-leaf exceptions even
    # after the actual tree has been quarantined under a private sibling name.
    actual = inventory(Path(root)) if parent_fd is None else inventory_at(parent_fd, leaf)
    extras = set(actual) - set(expected)
    for relative in list(extras):
        path = str(Path(root) / relative)
        base = OPTIONAL.get(path)
        if allow_mutable and base and str(Path(base).relative_to(root)) in expected:
            parent_record = expected[str(Path(base).relative_to(root))]
            need(actual[relative]["kind"] == "file" and all(actual[relative][key] == parent_record[key]
                 for key in ("uid", "gid", "mode")), "foreign SQLite sidecar")
            extras.remove(relative)
    need(not extras, "unknown descendant; cleanup refused")
    for name, record in expected.items():
        absolute = str(Path(root) / name)
        if name not in actual and allow_mutable and absolute in OPTIONAL:
            continue
        need(name in actual, "fixture descendant disappeared")
        if allow_mutable and absolute in MUTABLE | set(OPTIONAL):
            keys = ("kind", "uid", "gid", "mode")
            if absolute == "/var/lib/sovagrid/hub/hub.sqlite":
                keys += ("dev", "ino")
            need(all(actual[name][key] == record[key] for key in keys), "mutable fixture ownership changed")
        else:
            need(actual[name] == record, "producer-owned fixture changed")
    return actual


def check_all(value, roots):
    for root in roots:
        if os.path.lexists(root):
            need(root in value["trees"], "unrecorded cleanup root")
            compare(root, value["trees"][root])
        else:
            need(root not in value["trees"], "recorded cleanup root disappeared")


def extend(value, additions, *, changed=frozenset()):
    """A producer registers exact new names, never all newly observed names."""
    for root, expected in value["trees"].items():
        actual = inventory(Path(root))
        permitted = set(expected) | set(additions.get(root, ()))
        permitted |= {str(Path(name).relative_to(root)) for name in OPTIONAL if Path(name).is_relative_to(root)}
        need(set(actual) <= permitted, "producer observed an unknown descendant")
        # Preserve immutable existing proofs outside explicitly modified roots.
        if root not in changed:
            for name, record in expected.items():
                need(name in actual or str(Path(root) / name) in OPTIONAL, "producer observed missing data")
                if name in actual and str(Path(root) / name) not in MUTABLE | set(OPTIONAL):
                    need(actual[name] == record, "producer observed changed foreign data")
        value["trees"][root] = actual
    save(value)


def optional_hook(action, *args):
    """Called only by the exact creator, harmless in ordinary VM workflows."""
    if not os.path.lexists(MARKER):
        return
    guard()
    value = ledger()
    if action == "web-job":
        request_id, bundle_path = args
        need(str(__import__("uuid").UUID(request_id)) == request_id, "invalid known Web job")
        name = Path(bundle_path).name
        match = re.fullmatch(r"source-([0-9a-f]{64})\.tar\.gz", name)
        need(match and Path(bundle_path).parent == Path("/var/lib/sovagrid/web-agent") and
             hashlib.sha256(Path(bundle_path).read_bytes()).hexdigest() == match[1], "invalid known Web bundle")
        additions = {"/var/lib/sovagrid": {"web-agent/.bundle.lock", "web-agent/jobs", "web-agent/jobs/.lock",
                     "web-agent/jobs/.enrollment-web-mutation", "web-agent/completed-enrollments.jsonl",
                     "web-agent/jobs/" + request_id + ".json", "web-agent/" + name}}
        extend(value, additions)
    else:
        raise RuntimeError("unknown fixture producer")
