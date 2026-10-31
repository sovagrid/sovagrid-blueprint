#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Pinned SSH bridge to the fixed, opt-in WireGuard broker installer.

The remote installer is already present in the verified VPN source tree. This
bridge never accepts a command, path, unit, interface, or profile from Web.
"""

from __future__ import annotations

import json
import re

from sovagrid_connect.agent_rpc import RPCError
from web_agent_target_ssh import PinnedTargetSSH, TargetSSHError


SHA = re.compile(r"[0-9a-f]{64}\Z")
CLI = "/opt/sovagrid-src/sovagrid-vpn/deploy/install-wireguard-control.py"
_MAX_OUTPUT = 8192
_DEPENDENCIES = frozenset({"wg", "wg-quick", "ip", "python3-cryptography", "apparmor_parser"})
_FULL_PREVIEW = frozenset({
    "schema_version", "action", "writes", "state_revision", "source_revision",
    "installed_current", "socket_active", "service_active", "socket_enabled",
    "pending_recovery", "inventory_timer_active", "inventory_timer_enabled",
    "inventory_snapshot_present", "missing_dependencies", "apparmor_profile_present",
    "can_apply", "requires_service_restart",
})
_SAFE_REASONS = frozenset({"RECOVERY_REQUIRED", "STOP_VPN_UNITS_BEFORE_UPGRADE"})
_EXACT_ERRORS = {
    "RECOVERY_REQUIRED": "RECOVERY_REQUIRED",
    "STOP_VPN_UNITS_BEFORE_UPGRADE": "CONTROL_ACTIVE",
    "VPN installation preview is stale": "STALE_PREVIEW",
    "Verified VPN source is busy": "BUSY",
    "Verified VPN source lock unavailable": "SOURCE_NOT_PREPARED",
    "VPN source and installed package differ": "SOURCE_CHANGED",
    "SovaGrid Agent group is missing": "AGENT_UNAVAILABLE",
    "Required WireGuard dependencies remain unavailable": "DEPENDENCIES_UNAVAILABLE",
}
_ERRORS = frozenset({
    "INVALID_REQUEST", "ROOT_REQUIRED", "SSH_UNAVAILABLE", "SOURCE_NOT_PREPARED",
    "SOURCE_CHANGED", "AGENT_UNAVAILABLE", "DEPENDENCIES_UNAVAILABLE",
    "STALE_PREVIEW", "RECOVERY_REQUIRED", "CONTROL_ACTIVE", "BUSY",
    "OPERATION_FAILED", "APPLY_UNCERTAIN", "RECOVERY_UNCERTAIN",
})


class WireguardControlError(RuntimeError):
    def __init__(self, code: str):
        self.code = code if code in _ERRORS else "OPERATION_FAILED"
        super().__init__(self.code)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _safe_reason(value: object) -> str:
    # Never forward an arbitrary exception string from the target host.
    return _EXACT_ERRORS.get(value, "OPERATION_FAILED") if type(value) is str else "OPERATION_FAILED"


def _script(action: str, state_revision: str | None = None) -> str:
    if action not in ("preview", "apply", "recover") or \
            (action == "apply") != (state_revision is not None) or \
            (state_revision is not None and
             (type(state_revision) is not str or SHA.fullmatch(state_revision) is None)):
        raise WireguardControlError("INVALID_REQUEST")
    argv = [CLI, action]
    if state_revision is not None:
        argv += ["--expected-state", state_revision]
    # Only a validated lowercase SHA can vary in this root command.
    return ("import runpy,sys;sys.argv=" + json.dumps(argv, separators=(",", ":")) +
            ";runpy.run_path(" + json.dumps(CLI) + ",run_name='__main__')")


def _response(raw: bytes, status: int, action: str) -> dict:
    if not raw or len(raw) > _MAX_OUTPUT or type(status) is not int:
        raise WireguardControlError("OPERATION_FAILED")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
        if type(value) is not dict or type(value.get("ok")) is not bool:
            raise ValueError
        if value["ok"] is False:
            if set(value) != {"ok", "error"} or type(value["error"]) is not str or status != 2:
                raise ValueError
            code = _safe_reason(value["error"])
            if code == "OPERATION_FAILED" and action == "apply":
                code = "APPLY_UNCERTAIN"
            elif code == "OPERATION_FAILED" and action == "recover":
                code = "RECOVERY_UNCERTAIN"
            raise WireguardControlError(code)
        if status != 0:
            raise ValueError
        if action == "preview":
            keys = set(value) - {"ok"}
            if keys == _FULL_PREVIEW or keys == _FULL_PREVIEW | {"reason"}:
                if (type(value["schema_version"]) is not int or value["schema_version"] != 1 or
                        value["action"] != "preview" or
                        value["writes"] is not False or
                        any(type(value[key]) is not bool for key in (
                            "installed_current", "socket_active", "service_active", "socket_enabled",
                            "pending_recovery", "inventory_timer_active", "inventory_timer_enabled",
                            "inventory_snapshot_present", "apparmor_profile_present", "can_apply",
                            "requires_service_restart")) or
                        any(type(value[key]) is not str or SHA.fullmatch(value[key]) is None
                            for key in ("state_revision", "source_revision")) or
                        type(value["missing_dependencies"]) is not list or
                        len(value["missing_dependencies"]) > len(_DEPENDENCIES) or
                        len(set(value["missing_dependencies"])) != len(value["missing_dependencies"]) or
                        any(type(name) is not str or name not in _DEPENDENCIES
                            for name in value["missing_dependencies"])):
                    raise ValueError
                if "reason" in value:
                    if value["reason"] not in _SAFE_REASONS or value["can_apply"] is not False:
                        raise ValueError
                    value["reason"] = _safe_reason(value["reason"])
                elif value["can_apply"] is not True:
                    raise ValueError
                return {key: item for key, item in value.items() if key != "ok"}
            degraded = {"schema_version", "action", "writes", "can_apply", "reason"}
            if keys not in (degraded, degraded | {"pending_recovery"}) or \
                    type(value["schema_version"]) is not int or value["schema_version"] != 1 or \
                    value["action"] != "preview" or \
                    value["writes"] is not False or value["can_apply"] is not False or \
                    type(value["reason"]) is not str or \
                    ("pending_recovery" in value and value["pending_recovery"] is not True):
                raise ValueError
            return {"schema_version": 1, "action": "preview", "writes": False,
                    "can_apply": False, "pending_recovery": value.get("pending_recovery", False),
                    "reason": _safe_reason(value["reason"])}
        if action == "apply":
            if (set(value) != {"ok", "action", "socket_active", "service_active",
                               "vpn_interface_changed", "inventory_timer_active",
                               "inventory_snapshot_present", "source_revision"} or
                    value["action"] != "installed" or
                    any(value[key] is not True for key in (
                        "socket_active", "service_active", "inventory_timer_active",
                        "inventory_snapshot_present")) or
                    value["vpn_interface_changed"] is not False or
                    type(value["source_revision"]) is not str or
                    SHA.fullmatch(value["source_revision"]) is None):
                raise ValueError
        elif (set(value) != {"ok", "action", "changed"} or
              value["action"] != "recovered" or type(value["changed"]) is not bool):
            raise ValueError
        return {key: item for key, item in value.items() if key != "ok"}
    except WireguardControlError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise WireguardControlError("OPERATION_FAILED") from None


class WireguardControlJobs:
    def __init__(self, enrollment_jobs, *, transport_factory=PinnedTargetSSH):
        self.jobs = enrollment_jobs
        self.transport_factory = transport_factory

    @staticmethod
    def _invoke(rpc, action: str, state_revision: str | None = None) -> dict:
        raw, status = rpc._exchange(_script(action, state_revision), (),
                                     540 if action == "apply" else 360 if action == "recover" else 60)
        return _response(raw, status, action)

    def execute(self, action: str, *, options, fingerprint: str, credential,
                expected: dict | None = None, confirm: bool | None = None) -> dict:
        if action not in ("preview", "apply", "recover"):
            raise WireguardControlError("INVALID_REQUEST")
        if action == "apply":
            if (type(expected) is not dict or set(expected) != {"state_revision", "source_revision"} or
                    any(type(value) is not str or SHA.fullmatch(value) is None
                        for value in expected.values()) or confirm is not True):
                raise WireguardControlError("INVALID_REQUEST")
        elif expected is not None or (confirm is not None and (action != "recover" or confirm is not True)) or \
                (action == "recover" and confirm is not True):
            raise WireguardControlError("INVALID_REQUEST")
        with self.jobs._exclusive():
            try:
                with self.transport_factory(host=options.host, port=options.port,
                        username=options.user, fingerprint=fingerprint,
                        method=credential.method, password=credential.password,
                        private_key=credential.private_key,
                        passphrase=credential.passphrase) as transport:
                    rpc = transport.target_rpc(transport.options)
                    rpc.preflight()  # establishes root or sudo -n, never an interactive sudo prompt
                    if action == "apply":
                        current = self._invoke(rpc, "preview")
                        if (current.get("state_revision") != expected["state_revision"] or
                                current.get("source_revision") != expected["source_revision"]):
                            raise WireguardControlError("STALE_PREVIEW")
                        if not current["can_apply"]:
                            raise WireguardControlError(current.get("reason", "OPERATION_FAILED"))
                    try:
                        result = self._invoke(rpc, action,
                            expected["state_revision"] if action == "apply" else None)
                    except RPCError:
                        raise WireguardControlError(
                            "APPLY_UNCERTAIN" if action == "apply" else
                            "RECOVERY_UNCERTAIN" if action == "recover" else "SSH_UNAVAILABLE") from None
                    except WireguardControlError as error:
                        if error.code == "OPERATION_FAILED" and action in ("apply", "recover"):
                            raise WireguardControlError(
                                "APPLY_UNCERTAIN" if action == "apply" else "RECOVERY_UNCERTAIN") from None
                        raise
                    if action == "apply" and result["source_revision"] != expected["source_revision"]:
                        raise WireguardControlError("APPLY_UNCERTAIN")
                    return {"protocol": 1, "scope": "entered_target", "host": options.host,
                            "port": options.port, "host_key_fingerprint": fingerprint, **result}
            except WireguardControlError:
                raise
            except RPCError as error:
                raise WireguardControlError(
                    "ROOT_REQUIRED" if error.code == "ROOT_REQUIRED" else
                    "BUSY" if error.code == "BUSY" else "SSH_UNAVAILABLE") from None
            except (TargetSSHError, OSError, ValueError, TypeError):
                raise WireguardControlError("SSH_UNAVAILABLE") from None
