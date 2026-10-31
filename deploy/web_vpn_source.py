#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Hub-side SSH bridge for the opt-in VPN source transaction.

No browser-supplied command or destination path crosses this boundary. A
short-lived, host-key-pinned transport stages the already verified managed
bundle, runs one fixed helper from it, and removes the stage. A private stage
record lets the next request clean an orphan after process interruption.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import uuid

from sovagrid_connect.agent_rpc import RPCError, Stage
from web_agent_target_ssh import PinnedTargetSSH, TargetSSHError


SHA = re.compile(r"[0-9a-f]{64}\Z")
STAGE_PATH = re.compile(r"/var/tmp/sovagrid-agent-enroll\.[A-Za-z0-9_-]{8,32}\Z")
ERRORS = frozenset({"ROOT_REQUIRED", "INVALID_REQUEST", "SOURCE_UNTRUSTED",
    "SOURCE_CHANGED", "STATE_CONFLICT", "OWNERSHIP_CONFLICT", "RECOVERY_REQUIRED",
    "STALE_PREVIEW", "CONTROL_ACTIVE", "BUSY", "OPERATION_FAILED",
    "INTERNAL_ERROR", "SSH_UNAVAILABLE", "STAGE_CLEANUP_REQUIRED",
    "APPLY_UNCERTAIN", "RECOVERY_UNCERTAIN"})


class VpnSourceError(RuntimeError):
    def __init__(self, code: str):
        self.code = code if code in ERRORS else "OPERATION_FAILED"
        super().__init__(self.code)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _uncertain(action: str) -> str:
    return "APPLY_UNCERTAIN" if action == "apply" else \
           "RECOVERY_UNCERTAIN" if action == "recover" else "OPERATION_FAILED"


class VpnSourceJobs:
    def __init__(self, enrollment_jobs, *, journal_path: Path | None = None,
                 transport_factory=PinnedTargetSSH):
        self.jobs = enrollment_jobs
        self.path = (Path(journal_path) if journal_path is not None else
                     enrollment_jobs._bundle_path.parent / "vpn-source-stage.json")
        self.transport_factory = transport_factory

    def _read_stage(self) -> dict | None:
        parent = self.path.parent
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or \
                stat.S_IMODE(info.st_mode) != 0o700:
            raise VpnSourceError("STATE_CONFLICT")
        if not os.path.lexists(self.path):
            return None
        before = self.path.lstat()
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            current = os.fstat(fd)
            if (not stat.S_ISREG(current.st_mode) or current.st_uid != os.geteuid() or
                    current.st_nlink != 1 or stat.S_IMODE(current.st_mode) != 0o600 or
                    (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino) or
                    current.st_size > 4096):
                raise VpnSourceError("STATE_CONFLICT")
            raw = os.read(fd, 4097)
        finally:
            os.close(fd)
        try:
            value = json.loads(raw, object_pairs_hook=_unique)
            if (type(value) is not dict or set(value) != {"protocol", "identity", "stage"} or
                    value["protocol"] != 1 or type(value["identity"]) is not dict or
                    set(value["identity"]) not in (
                        {"host", "port", "username", "fingerprint"},
                        {"host", "port", "username", "fingerprint", "jump"}) or
                    type(value["identity"]["host"]) is not str or
                    type(value["identity"]["username"]) is not str or
                    type(value["identity"]["fingerprint"]) is not str or
                    type(value["identity"]["port"]) is not int or
                    ("jump" in value["identity"] and
                     (type(value["identity"]["jump"]) is not dict or
                      set(value["identity"]["jump"]) !=
                      {"host", "port", "username", "fingerprint"} or
                      type(value["identity"]["jump"]["host"]) is not str or
                      type(value["identity"]["jump"]["port"]) is not int or
                      type(value["identity"]["jump"]["username"]) is not str or
                      type(value["identity"]["jump"]["fingerprint"]) is not str)) or
                    type(value["stage"]) is not dict or
                    set(value["stage"]) != {"remote_dir", "sha256", "source_manifest_sha256",
                                            "helper_sha256", "stage_id"} or
                    not STAGE_PATH.fullmatch(value["stage"]["remote_dir"]) or
                    not all(type(value["stage"][key]) is str and SHA.fullmatch(value["stage"][key])
                            for key in ("sha256", "source_manifest_sha256", "helper_sha256")) or
                    type(value["stage"]["stage_id"]) is not str or
                    not re.fullmatch(r"[0-9a-f]{32}", value["stage"]["stage_id"]) or
                    value["stage"]["remote_dir"] !=
                    "/var/tmp/sovagrid-agent-enroll." + value["stage"]["stage_id"] or
                    _canonical(value) != raw):
                raise ValueError
            return value
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise VpnSourceError("STATE_CONFLICT") from None

    def _save_stage(self, identity: dict, descriptor: dict) -> None:
        value = {"protocol": 1, "identity": identity, "stage": descriptor}
        raw = _canonical(value)
        if len(raw) > 4096 or self._read_stage() is not None:
            raise VpnSourceError("RECOVERY_REQUIRED")
        path = self.path.parent / (".vpn-stage-" + uuid.uuid4().hex)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(path, self.path)
            self._fsync_parent()
        finally:
            if os.path.lexists(path):
                path.unlink()

    def _fsync_parent(self):
        fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _clear_stage(self):
        self._read_stage()
        self.path.unlink()
        self._fsync_parent()

    def _cleanup_orphan(self, rpc, identity: dict) -> None:
        record = self._read_stage()
        if record is None:
            return
        if record["identity"] != identity:
            raise VpnSourceError("RECOVERY_REQUIRED")
        descriptor = record["stage"]
        stage = Stage(**descriptor, _owner=rpc._owner)
        rpc._stages[stage.stage_id] = stage
        try:
            rpc.cleanup_stage(stage)
        except Exception:
            raise VpnSourceError("STAGE_CLEANUP_REQUIRED") from None
        self._clear_stage()

    @staticmethod
    def _response(raw: bytes, status: int, action: str) -> dict:
        try:
            value = json.loads(raw, object_pairs_hook=_unique)
            if (type(value) is not dict or value.get("protocol") != 1 or
                    type(value.get("ok")) is not bool):
                raise ValueError
            if value["ok"] is False:
                if (set(value) != {"protocol", "ok", "error"} or
                        type(value["error"]) is not str or value["error"] not in ERRORS):
                    raise ValueError
                # The target helper uses exit 1 for structured refusals. A
                # transport failure after partial stdout is not a refusal.
                if status != 1:
                    raise VpnSourceError(_uncertain(action))
                raise VpnSourceError(value["error"])
            if (status != 0 or set(value) != {"protocol", "ok", "result"} or
                    type(value["result"]) is not dict):
                raise ValueError
            result = value["result"]
            if action == "preview":
                keys = {"protocol", "change", "source_manifest_sha256", "candidate_sha256",
                        "installed_sha256", "state_sha256", "cleanup_required", "expected"}
                if (set(result) != keys or result["change"] not in ("install", "update", "current") or
                        type(result["cleanup_required"]) is not bool or
                        type(result["expected"]) is not dict or
                        set(result["expected"]) != {"source_manifest_sha256", "candidate_sha256",
                                                   "installed_sha256", "state_sha256"}):
                    raise ValueError
                for key in ("source_manifest_sha256", "candidate_sha256",
                            "installed_sha256", "state_sha256"):
                    if (type(result[key]) is not str or not SHA.fullmatch(result[key]) or
                            result["expected"][key] != result[key]):
                        raise ValueError
            elif action == "apply":
                if (set(result) != {"protocol", "installed", "changed", "source_manifest_sha256",
                                    "candidate_sha256", "cleanup_required"} or
                        result["installed"] is not True or type(result["changed"]) is not bool or
                        type(result["cleanup_required"]) is not bool or
                        any(type(result[key]) is not str or not SHA.fullmatch(result[key])
                            for key in ("source_manifest_sha256", "candidate_sha256"))):
                    raise ValueError
            elif set(result) != {"protocol", "recovered"} or type(result["recovered"]) is not bool:
                raise ValueError
            if result["protocol"] != 1:
                raise ValueError
            return result
        except VpnSourceError:
            raise
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise VpnSourceError(_uncertain(action)) from None

    def execute(self, action: str, *, options, fingerprint: str, credential,
                expected: dict | None = None) -> dict:
        if action not in ("preview", "apply", "recover"):
            raise VpnSourceError("INVALID_REQUEST")
        if action == "apply" and (type(expected) is not dict or
                set(expected) != {"source_manifest_sha256", "candidate_sha256",
                                  "installed_sha256", "state_sha256"} or
                any(type(value) is not str or SHA.fullmatch(value) is None
                    for value in expected.values())):
            raise VpnSourceError("INVALID_REQUEST")
        if action != "apply" and expected is not None:
            raise VpnSourceError("INVALID_REQUEST")
        with self.jobs._exclusive():
            bundle = self.jobs._bundle()
            identity = {"host": options.host, "port": options.port,
                        "username": options.user, "fingerprint": fingerprint}
            route_kwargs = {}
            jump = getattr(credential, "jump", None)
            if jump is not None:
                if (options.jump_host != jump["host"] or
                        options.jump_port != jump["port"] or
                        options.jump_user != jump["username"]):
                    raise VpnSourceError("INVALID_REQUEST")
                identity["jump"] = {"host": options.jump_host,
                                    "port": options.jump_port,
                                    "username": options.jump_user,
                                    "fingerprint": jump["fingerprint"]}
                route_kwargs = {"jump": jump,
                                "target_host_key_blob": credential.target_host_key_blob}
            try:
                with self.transport_factory(host=options.host, port=options.port,
                        username=options.user, fingerprint=fingerprint,
                        method=credential.method, password=credential.password,
                        private_key=credential.private_key,
                        passphrase=credential.passphrase, **route_kwargs) as transport:
                    rpc = transport.target_rpc(transport.options)
                    self._cleanup_orphan(rpc, identity)
                    stage = None
                    try:
                        stage = rpc.stage_target(bundle, self.jobs._bundle_sha256,
                            checkpoint=lambda descriptor: self._save_stage(identity, descriptor))
                        path = stage.remote_dir + "/source/sovagrid-blueprint/deploy/vpn_source_install.py"
                        if not STAGE_PATH.fullmatch(stage.remote_dir):
                            raise VpnSourceError("SOURCE_UNTRUSTED")
                        bootstrap = ("import runpy,sys;sys.argv=[" + json.dumps(path) +
                                     "];runpy.run_path(" + json.dumps(path) +
                                     ",run_name='__main__')")
                        payload = {"protocol": 1, "action": action,
                                   "source_manifest_sha256": stage.source_manifest_sha256}
                        if action == "apply":
                            payload["expected"] = expected
                        try:
                            raw, status = rpc._exchange(bootstrap, (_canonical(payload),), 180)
                        except RPCError:
                            raise VpnSourceError(_uncertain(action)) from None
                        result = self._response(raw, status, action)
                        if action != "recover" and result["source_manifest_sha256"] != stage.source_manifest_sha256:
                            raise VpnSourceError("SOURCE_CHANGED")
                        if action == "apply" and result["candidate_sha256"] != expected["candidate_sha256"]:
                            raise VpnSourceError("SOURCE_CHANGED")
                        return {**result, "scope": "entered_target", "host": options.host,
                                "port": options.port, "host_key_fingerprint": fingerprint,
                                **({"jump_host": options.jump_host,
                                    "jump_port": options.jump_port,
                                    "jump_host_key_fingerprint": jump["fingerprint"]}
                                   if jump is not None else {}),
                                **({"temporary_writes": True, "activation_writes": False}
                                   if action == "preview" else {})}
                    finally:
                        if self._read_stage() is not None:
                            try:
                                self._cleanup_orphan(rpc, identity)
                            except VpnSourceError:
                                raise VpnSourceError("STAGE_CLEANUP_REQUIRED") from None
            except VpnSourceError:
                raise
            except RPCError as error:
                if error.code in ("ROOT_REQUIRED", "SOURCE_UNTRUSTED", "OWNERSHIP_CONFLICT", "BUSY"):
                    raise VpnSourceError(error.code) from None
                if error.code == "STAGE_BUSY":
                    raise VpnSourceError("BUSY") from None
                if error.code in ("CLEANUP_REQUIRED", "STAGE_INCOMPLETE"):
                    raise VpnSourceError("STAGE_CLEANUP_REQUIRED") from None
                raise VpnSourceError("SSH_UNAVAILABLE") from None
            except (TargetSSHError, OSError, ValueError, TypeError):
                raise VpnSourceError("SSH_UNAVAILABLE") from None
