# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Fixed SSH target actions and detached, journaled restore workers.

Only a separately pinned receiver/runner is executable. Backup payloads never
select a helper path, shell command, unit property, or persisted credential.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
PROTOCOL = "sovagrid-portable-restore-target-v1"
CONTROL = "target-operation.json"
ID = re.compile(r"[0-9a-f]{32}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
ROOT_UID = ROOT_GID = 0


class Refused(RuntimeError):
    pass


def _need(value, code):
    if not value:
        raise Refused(code)


def _load(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    _need(spec is not None and spec.loader is not None, "RUNNER_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@contextmanager
def _context(identity):
    _need(os.geteuid() == 0 and isinstance(identity, str) and ID.fullmatch(identity), "INVALID_TARGET_OPERATION")
    receiver = _load("portable_restore_receiver.py", "_sovagrid_target_receiver")
    runner = receiver.verified_runner(identity)
    _need(Path(__file__).resolve() == runner / "sovagrid-blueprint/deploy/portable_restore_target.py", "RUNNER_IDENTITY_MISMATCH")
    request = receiver.load_request(identity)
    restored = _load("host_restore.py", "_sovagrid_target_host_restore")
    core = _load("portable_restore_apply.py", "_sovagrid_target_restore_core")
    descriptor = restored.backup._safe_open(runner.parent, directory=True)
    try:
        core._private(os.fstat(descriptor), directory=True, uid=ROOT_UID, gid=ROOT_GID)
        yield receiver, restored, core, request, descriptor
    finally:
        os.close(descriptor)


@contextmanager
def _lock(core, fd, name):
    descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        core._private(os.fstat(descriptor), directory=False, uid=ROOT_UID, gid=ROOT_GID)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused("RESTORE_WORKER_ACTIVE") from exc
        yield
    finally:
        os.close(descriptor)


def _control(core, fd, identity, request_sha):
    try:
        raw, _ = core._read_atomic_private_at(fd, CONTROL, maximum=16384, uid=ROOT_UID, gid=ROOT_GID)
    except FileNotFoundError:
        return None
    value = json.loads(raw, object_pairs_hook=core._unique)
    _need(isinstance(value, dict) and set(value) == {"protocol", "operation_id", "request_sha256", "action",
        "worker_nonce", "unit", "phase", "apply_review_sha256", "error"} and value["protocol"] == PROTOCOL and
        value["operation_id"] == identity and value["request_sha256"] == request_sha and
        value["action"] in ("apply", "recover") and isinstance(value["worker_nonce"], str) and ID.fullmatch(value["worker_nonce"]) and
        value["unit"] == "sg-host-restore-" + identity + "-" + value["worker_nonce"][:12] + ".service" and
        value["phase"] in ("accepted", "running", "finished", "failed") and
        (value["apply_review_sha256"] is None or isinstance(value["apply_review_sha256"], str) and SHA.fullmatch(value["apply_review_sha256"])) and
        (value["error"] is None or isinstance(value["error"], str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value["error"])), "INVALID_TARGET_JOURNAL")
    return value


def _save(core, fd, value):
    # Caller holds the operation control lock and has read/validated old state.
    temporary = ".target-operation-" + uuid.uuid4().hex + ".tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        os.fchmod(descriptor, 0o600)
        core._private(os.fstat(descriptor), directory=False, uid=ROOT_UID, gid=ROOT_GID)
        core._write(descriptor, core._canonical(value) + b"\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, CONTROL, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass


def _tool(args, *, timeout=30, accepted=(0,)):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused("RESTORE_WORKER_START_UNCERTAIN") from exc
    _need(result.returncode in accepted and len(result.stdout) <= 4096, "RESTORE_WORKER_START_UNCERTAIN")
    try:
        return result.stdout.decode("ascii").strip()
    except UnicodeError as exc:
        raise Refused("RESTORE_WORKER_START_UNCERTAIN") from exc


def _kernel(restore, core, archive):
    try:
        return core.host_status(restore, archive)
    except (core.Refused, FileNotFoundError) as exc:
        if isinstance(exc, FileNotFoundError) or str(exc) in ("RESTORE_NOT_FOUND", "STAGE_NOT_FOUND"):
            return None
        raise


def _status(receiver, restore, core, request, fd):
    transfer = receiver.request_status(request["operation_id"])
    state = _control(core, fd, request["operation_id"], transfer["request_sha256"])
    kernel = _kernel(restore, core, request["archive_id"])
    retry_state = core.host_retry_status(restore, request["archive_id"]) if kernel is None else None
    active = False
    if state is not None:
        active = _tool(["/usr/bin/systemctl", "show", "--property=ActiveState", "--value", state["unit"]],
                       accepted=(0, 1, 4)) in ("active", "activating", "deactivating", "reloading")
    phase = kernel["phase"] if kernel is not None else ("ready" if state is not None and
             state["action"] == "recover" and state["phase"] == "finished" else state["phase"] if state is not None else
             "ready" if transfer["registered"] else "receiving")
    retry_pending = retry_state is not None and retry_state["phase"] == "archiving"
    if not active and retry_pending:
        phase = "retry_required"
    elif (not active and retry_state is not None and retry_state["phase"] == "complete" and
          (state is None or state["phase"] in ("finished", "failed"))):
        phase = "ready"
    error = (kernel.get("error") if kernel is not None else None) or (state["error"] if state is not None else None)
    return {"ok": True, "protocol": PROTOCOL, "operation_id": request["operation_id"],
            "archive_id": request["archive_id"], "request_sha256": transfer["request_sha256"],
            "registered": transfer["registered"], "phase": phase, "worker_active": active,
            "action": None if state is None else state["action"], "kernel_status": kernel,
            "backend_supported": core.APPLY_ENABLED, "target_ready": False, "apply_available": False,
            "blockers": ([] if core.APPLY_ENABLED else ["APPLY_NOT_IMPLEMENTED"]) + ([] if error is None else [error]),
            "retry_available": not active and (retry_pending or kernel is not None and kernel["phase"] == "rolled_back"),
            "retry_in_progress": retry_pending,
            "terminal_sha256": (retry_state["terminal_sha256"] if retry_state is not None else
                                None if kernel is None else kernel.get("terminal_sha256")), "error": error}


def status(identity):
    with _context(identity) as context:
        return _status(*context)


def preview(identity):
    with _context(identity) as (receiver, restore, core, request, fd):
        status = _status(receiver, restore, core, request, fd)
        _need(status["registered"] and not status["worker_active"], "RESTORE_TARGET_NOT_READY")
        _need(status["kernel_status"] is None, "RESTORE_RECOVERY_REQUIRED")
        clean = restore.portable_clean_plan(request["archive_id"])
        if clean.get("target_ready") is not True:
            return {**status, "phase": "review", "preview": clean, "target_ready": False,
                    "blockers": clean["blockers"], "apply_review_sha256": None}
        restore.portable_stage(request["archive_id"], clean["review_sha256"])
        review = core.preview_host(restore, request["archive_id"])
        return {**status, "phase": "review", "preview": review,
                "backend_supported": review["backend_supported"], "target_ready": review["target_ready"],
                "apply_available": review["apply_available"], "blockers": review["blockers"],
                "apply_review_sha256": review["apply_review_sha256"]}


def launch(identity, action, review=None):
    _need(action in ("apply", "recover"), "INVALID_TARGET_ACTION")
    _need(review is None if action == "recover" else isinstance(review, str) and SHA.fullmatch(review), "INVALID_RESTORE_REVIEW")
    with _context(identity) as (receiver, restore, core, request, fd):
        with _lock(core, fd, ".control.lock"):
            current = _status(receiver, restore, core, request, fd)
            old = _control(core, fd, identity, current["request_sha256"])
            if action == "apply":
                _need(core.APPLY_ENABLED, "APPLY_NOT_IMPLEMENTED")
                if old is not None and old["action"] == "apply" and old["apply_review_sha256"] == review:
                    return current  # Uncertain acknowledgments never repeat apply.
                _need(current["kernel_status"] is None and current["registered"], "RESTORE_RECOVERY_REQUIRED")
                fresh = core.preview_host(restore, request["archive_id"])
                _need(fresh["apply_available"] and fresh["apply_review_sha256"] == review, "STALE_RESTORE_REVIEW")
            else:
                _need(not current["worker_active"], "RESTORE_WORKER_ACTIVE")
                if current["kernel_status"] is not None and current["kernel_status"]["phase"] in ("committed", "rolled_back"):
                    return current
            with _lock(core, fd, ".worker.lock"):
                nonce = uuid.uuid4().hex
                value = {"protocol": PROTOCOL, "operation_id": identity, "request_sha256": current["request_sha256"],
                         "action": action, "worker_nonce": nonce,
                         "unit": "sg-host-restore-" + identity + "-" + nonce[:12] + ".service",
                         "phase": "accepted", "apply_review_sha256": review, "error": None}
                _save(core, fd, value)  # Durable intent precedes systemd-run.
        # Type=exec may start the worker before systemd-run acknowledges it.
        # Release both process locks first; retain the verified operation FD
        # until detach completes. The durable nonce still rejects stale work.
        runner = receiver.verified_runner(identity)
        _tool(["/usr/bin/systemd-run", "--quiet", "--collect", "--unit=" + value["unit"],
               "--property=Type=exec", "--property=User=root", "--property=Group=root", "--property=UMask=0077",
               "--property=RuntimeMaxSec=10800", "/usr/bin/python3", "-B", "-I",
               str(runner / "sovagrid-blueprint/deploy/portable_restore_target.py"), "worker", identity, action, nonce])
        return {**current, "phase": "accepted", "action": action, "worker_active": True, "error": None}


def worker(identity, action, nonce):
    with _context(identity) as (receiver, restore, core, request, fd), _lock(core, fd, ".worker.lock"):
        transfer = receiver.request_status(identity)
        with _lock(core, fd, ".control.lock"):
            value = _control(core, fd, identity, transfer["request_sha256"])
            _need(value is not None and value["worker_nonce"] == nonce and value["action"] == action and
                  value["phase"] == "accepted" and transfer["registered"], "STALE_TARGET_WORKER")
            value["phase"] = "running"
            _save(core, fd, value)
        error = None
        try:
            if action == "apply":
                core.apply_host(restore, request["archive_id"], value["apply_review_sha256"])
            elif _kernel(restore, core, request["archive_id"]) is not None:
                core.recover_host(restore, request["archive_id"])
        except Exception as exc:
            code = str(exc)
            error = code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code) else "RESTORE_WORKER_FAILED"
        with _lock(core, fd, ".control.lock"):
            latest = _control(core, fd, identity, transfer["request_sha256"])
            _need(latest["worker_nonce"] == nonce, "STALE_TARGET_WORKER")
            value.update(phase="finished" if error is None else "failed", error=error)
            _save(core, fd, value)


def retry(identity, terminal):
    _need(isinstance(terminal, str) and SHA.fullmatch(terminal), "INVALID_RESTORE_REVIEW")
    with _context(identity) as (receiver, restore, core, request, fd), _lock(core, fd, ".control.lock"), _lock(core, fd, ".worker.lock"):
        result = core.retry_host(restore, request["archive_id"], terminal)
        # Retain the exact previous control intent as history; the core's
        # retry nonce is part of every subsequent apply CAS, so a delayed old
        # start acknowledgment cannot initiate another attempt.
        transfer = receiver.request_status(identity)
        old = _control(core, fd, identity, transfer["request_sha256"])
        if old is not None:
            core._rename_noreplace(fd, CONTROL, ".target-history-" + result["history_id"] + ".json")
            os.fsync(fd)
        current = _status(receiver, restore, core, request, fd)
        return {**current, "phase": "ready", "retry": result, "requires_fresh_preview": True}


def dispatch_frame(identity, frame):
    fields = {"preview": {"action"}, "start": {"action", "apply_review_sha256"},
              "operation-status": {"action"}, "recover": {"action"}, "retry": {"action", "terminal_sha256"}}
    _need(isinstance(frame, dict) and isinstance(frame.get("action"), str) and
          frame["action"] in fields and set(frame) == fields[frame["action"]], "INVALID_TARGET_ACTION")
    action = frame["action"]
    if action == "preview": return preview(identity)
    if action == "operation-status": return status(identity)
    if action == "start": return launch(identity, "apply", frame["apply_review_sha256"])
    if action == "recover": return launch(identity, "recover")
    return retry(identity, frame["terminal_sha256"])


def main(argv):
    try:
        if len(argv) == 4 and argv[0] == "worker":
            worker(argv[1], argv[2], argv[3])
            return 0
        _need(len(argv) in (2, 3), "USAGE")
        action = {"status": "operation-status"}.get(argv[0], argv[0])
        frame = {"action": action}
        if len(argv) == 3:
            frame["terminal_sha256" if action == "retry" else "apply_review_sha256"] = argv[2]
        print(json.dumps(dispatch_frame(argv[1], frame), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        code = str(exc)
        code = code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code) else "RESTORE_TARGET_FAILED"
        print(json.dumps({"ok": False, "protocol": PROTOCOL,
            "operation_id": argv[1] if len(argv) >= 2 and ID.fullmatch(argv[1]) else None,
            "error": code}, separators=(",", ":")))
        return 40


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
