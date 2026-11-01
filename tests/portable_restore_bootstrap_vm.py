#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Pinned bootstrap/SSH framing smoke ONLY on a fresh hosted Ubuntu VM.

Run after restore-dependencies-only, before any SovaGrid installation. The
original source archive is streamed unchanged twice to one operation. A tiny
unregistered upload tests real binary framing and reconnect; no backup is
applied and no SovaGrid account, service or configuration is created.
"""
from __future__ import annotations

import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import uuid

sys.dont_write_bytecode = True
PROTOCOL = "sovagrid-portable-restore-target-v1"
BASE = Path("/root/.sovagrid-restore")
SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_ARCHIVE = 64 * 1024**2
MAX_OUTPUT = 64 * 1024
PARTS = ("host_manifest", "host", "images_manifest", "images", "receipt")


def need(value, reason):
    if not value:
        raise RuntimeError("portable restore bootstrap VM: " + reason)


def guard():
    need(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true" and
         os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.environ.get("RUNNER_OS") == "Linux" and
         os.environ.get("SOVAGRID_PORTABLE_RESTORE_DISPOSABLE") == "1",
         "requires explicit fresh GitHub-hosted root Linux selection")
    expected = os.environ.get("SOVAGRID_RESTORE_EXPECTED_MANIFEST", "")
    need(SHA.fullmatch(expected) is not None, "requires the artifact-pinned source manifest")
    values = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines()
                  if "=" in line and not line.startswith("#"))
    need(values.get("ID", "").strip('"') == "ubuntu" and
         Path("/proc/1/comm").read_text().strip() == "systemd", "requires Ubuntu with native systemd")
    return expected


def fresh_target():
    for parent in ("/etc", "/opt", "/var/lib", "/usr/local/bin", "/usr/local/libexec", "/etc/systemd/system"):
        need(not any(Path(parent).glob("sovagrid*")), "SovaGrid target state already exists")
    need(not any(item.pw_name.startswith(("sovagrid-", "sovagrid_")) or item.pw_name == "sovagrid"
                 for item in pwd.getpwall()) and
         not any(item.gr_name.startswith(("sovagrid-", "sovagrid_")) or item.gr_name == "sovagrid"
                 for item in grp.getgrall()), "SovaGrid identity exists")


def source_verifier(bundle, expected):
    """Pin the verifier itself before import, then verify the complete tree."""
    need(bundle.is_absolute() and bundle.is_relative_to("/root") and bundle != Path("/root"),
         "reviewed source must be under /root")
    cursor = Path("/")
    for part in bundle.parts[1:]:
        cursor /= part
        info = cursor.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
             "unsafe reviewed source parent")
    manifest = bundle / "sovagrid-bundle.json"
    info = manifest.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0 and
         not info.st_mode & 0o022 and info.st_size <= 512 * 1024, "unsafe source manifest")
    raw = manifest.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == expected, "source manifest pin mismatch")
    filename = bundle / "sovagrid-blueprint/tests/portable_restore_fixture.py"
    need(not filename.is_symlink() and hashlib.sha256(filename.read_bytes()).hexdigest() ==
         json.loads(raw)["sha256"]["sovagrid-blueprint/tests/portable_restore_fixture.py"], "verifier pin mismatch")
    spec = importlib.util.spec_from_file_location("sovagrid_bootstrap_vm_fixture", filename)
    need(spec is not None and spec.loader is not None, "missing pinned source verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.source_pin(bundle, expected)
    return module


def command(args, data, *, timeout):
    # Keep package/helper output private and bounded before decoding it.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        result = subprocess.run(args, input=data, stdout=output, stderr=error, timeout=timeout, check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"})
        need(result.returncode == 0 and output.tell() <= MAX_OUTPUT and error.tell() <= MAX_OUTPUT,
             "fixed bootstrap/receiver command failed or produced unbounded output")
        output.seek(0)
        raw = output.read(MAX_OUTPUT + 1)
    values = [json.loads(line) for line in raw.splitlines()]
    need(values and all(isinstance(value, dict) and value.get("ok") is True and
         value.get("protocol") == PROTOCOL for value in values), "invalid public JSON reply")
    return values


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def smoke(bundle, archive, expected):
    fixture = source_verifier(bundle, expected)
    fresh_target()
    need(not os.path.lexists(BASE), "restore runner namespace already exists")
    with os.fdopen(os.open(archive, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= MAX_ARCHIVE,
             "invalid original source archive")
        fixture.archive_pin(archive, expected)
        raw = stream.read(MAX_ARCHIVE + 1)
        after = os.fstat(stream.fileno())
        need(len(raw) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
             "original source archive changed")
    archive_sha = hashlib.sha256(raw).hexdigest()
    operation = uuid.uuid4().hex
    script = (bundle / "sovagrid-blueprint/deploy/portable_restore_bootstrap.sh").read_text()
    args = ["/bin/bash", "-c", script, "--", operation, str(len(raw)), archive_sha, expected]
    wanted = {"ok": True, "protocol": PROTOCOL, "operation_id": operation,
              "runner_archive_sha256": archive_sha, "runner_manifest_sha256": expected, "dependencies_ready": True}
    need(command(args, raw, timeout=900) == [wanted], "initial bootstrap did not report exact ready pins")
    work = BASE / operation
    info = work.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
         "unsafe bootstrap operation")
    fixture.source_pin(work / "runner", expected)
    runner_info = (work / "runner").lstat()
    receiver = str(work / "runner/sovagrid-blueprint/deploy/portable_restore_receiver.py")
    receive_args = ["/usr/bin/python3", "-B", "-I", receiver, "serve", operation]
    payload = b'\x00\xff\n{"action":"status"}\n'
    artifacts = {name: {"bytes": len(payload) if name == "host" else 1,
                         "sha256": hashlib.sha256(payload if name == "host" else b"x").hexdigest()}
                 for name in PARTS}
    request = {"protocol": PROTOCOL, "operation_id": operation, "archive_id": uuid.uuid4().hex,
               "runner_archive_sha256": archive_sha, "runner_manifest_sha256": expected, "artifacts": artifacts}
    frames = canonical({"action": "init", "request": request}) + canonical({"action": "receive", "part": "host",
             "offset": 0, "length": len(payload), "sha256": artifacts["host"]["sha256"]}) + payload + canonical({"action": "status"})
    values = command(receive_args, frames, timeout=60)
    need(len(values) == 3 and values[0]["artifacts"]["host"]["received"] == 0 and values[1] == values[2],
         "binary transfer did not preserve frame boundaries")
    status = values[2]
    need(status["operation_id"] == operation and status["archive_id"] == request["archive_id"] and
         status["request_sha256"] == hashlib.sha256(canonical(request)).hexdigest() and
         status["registered"] is False and status["max_chunk_bytes"] == 4 * 1024**2 and status["pending_chunk"] is None and
         status["artifacts"]["host"]["received"] == len(payload) and status["artifacts"]["host"]["complete"] is True,
         "receiver status binding or progress changed")
    # Repeat the complete original bundle after receiver state exists; resume
    # verifies the published runner and preserves its inode and upload bytes.
    need(command(args, raw, timeout=900) == [wanted], "verified bootstrap resume changed ready pins")
    current = (work / "runner").lstat()
    need((current.st_dev, current.st_ino) == (runner_info.st_dev, runner_info.st_ino), "resume replaced the runner")
    need(command(receive_args, canonical({"action": "status"}), timeout=60) == [status], "reconnect lost upload state")
    fixture.source_pin(work / "runner", expected)
    fresh_target()
    print("PORTABLE_RESTORE_VM_BOOTSTRAP_RESUME_AND_BINARY_RECONNECT_OK", flush=True)


def main(argv):
    expected = guard()  # Before any source/archive/system mutation.
    need(len(argv) == 1, "provide the original packaged source archive")
    smoke(Path(__file__).resolve().parents[2], Path(argv[0]), expected)


if __name__ == "__main__":
    main(sys.argv[1:])
