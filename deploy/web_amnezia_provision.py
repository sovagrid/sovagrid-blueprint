#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Pinned SSH bridge to the fixed, opt-in AmneziaWG provisioner.

The browser selects only a private /24, UDP port and route mode. The target
command and source path are fixed; no server private key or profile crosses
this bridge.
"""

from __future__ import annotations

import ipaddress
import json
import re

from sovagrid_connect.agent_rpc import RPCError
from web_agent_target_ssh import PinnedTargetSSH, TargetSSHError


CLI = "/opt/sovagrid-src/sovagrid-vpn/deploy/sovagrid-amnezia-provision"
MODULE = "/opt/sovagrid-src/sovagrid-vpn/sovagrid_vpn/amnezia_provision.py"
SHA = re.compile(r"[0-9a-f]{64}\Z")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_OUTPUT = 8192
_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_PREVIEW_REASONS = frozenset({
    "UNSUPPORTED_PLATFORM", "RECOVERY_REQUIRED", "ALREADY_INSTALLED",
    "CONTAINER_EXISTS", "TUN_UNAVAILABLE", "ROOT_REQUIRED", "UNSAFE_STATE",
    "DOCKER_UNAVAILABLE", "DOCKER_OPERATION_FAILED", "IMAGE_IDENTITY_INVALID",
    "CONTAINER_IDENTITY_INVALID", "DOCKER_RESPONSE_TOO_LARGE", "INVALID_PORT", "INVALID_SUBNET",
    "INVALID_ROUTE", "SOURCE_NOT_PREPARED", "UDP_PORT_BUSY",
})
_CLI_ERRORS = _PREVIEW_REASONS | {
    "PREVIEW_STALE", "AWG_RUNTIME_UNVERIFIED", "MANUAL_RECOVERY_REQUIRED",
    "CONFIRMATION_REQUIRED", "INVALID_REVISION",
}
_ERRORS = _CLI_ERRORS | {
    "INVALID_REQUEST", "SSH_UNAVAILABLE", "BUSY", "APPLY_UNCERTAIN",
    "RECOVERY_UNCERTAIN", "OPERATION_FAILED", "STALE_PREVIEW",
}
_FULL_PREVIEW = frozenset({
    "schema_version", "action", "writes", "target", "container", "listen_port",
    "subnet", "route_mode", "image_digest", "image_cached", "state_revision",
    "can_apply",
})
_DEGRADED_PREVIEW = frozenset({
    "schema_version", "action", "writes", "target", "container", "can_apply", "reason",
})


class AmneziaProvisionError(RuntimeError):
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


def _uncertain(action: str) -> str:
    return "APPLY_UNCERTAIN" if action == "apply" else \
           "RECOVERY_UNCERTAIN" if action == "recover" else "OPERATION_FAILED"


def _target(listen_port: object, subnet: object, route_mode: object) -> tuple[int, str, str]:
    if type(listen_port) is not int or not 1 <= listen_port <= 65535 or \
            type(subnet) is not str or type(route_mode) is not str or \
            route_mode not in ("full", "split"):
        raise AmneziaProvisionError("INVALID_REQUEST")
    try:
        network = ipaddress.IPv4Network(subnet, strict=True)
    except (ValueError, TypeError):
        raise AmneziaProvisionError("INVALID_REQUEST") from None
    if (network.prefixlen != 24 or str(network) != subnet or
            not any(network.subnet_of(parent) for parent in _NETWORKS)):
        raise AmneziaProvisionError("INVALID_REQUEST")
    return listen_port, subnet, route_mode


def _script(action: str, *, listen_port: int | None = None, subnet: str | None = None,
            route_mode: str | None = None, expected_state: str | None = None) -> str:
    if action not in ("preview", "apply", "recover"):
        raise AmneziaProvisionError("INVALID_REQUEST")
    argv = ["/bin/sh", CLI, action]
    if action == "recover":
        if any(value is not None for value in (listen_port, subnet, route_mode, expected_state)):
            raise AmneziaProvisionError("INVALID_REQUEST")
    else:
        port, network, route = _target(listen_port, subnet, route_mode)
        argv += ["--port", str(port), "--subnet", network, "--route", route]
        if action == "apply":
            if type(expected_state) is not str or SHA.fullmatch(expected_state) is None:
                raise AmneziaProvisionError("INVALID_REQUEST")
            argv += ["--expected-state", expected_state, "--confirm"]
        elif expected_state is not None:
            raise AmneziaProvisionError("INVALID_REQUEST")
    timeout = {"preview": 30, "apply": 300, "recover": 60}[action]
    # This code runs as a fixed root command through pinned SSH. It validates
    # the root-owned source before invoking a shell wrapper that is 0644 on
    # Agent-only targets. Stderr is converted to a single allowlisted code.
    return (
        "import json,os,stat,subprocess,sys\n"
        "argv=" + json.dumps(argv, separators=(",", ":")) + "\n"
        "allowed=set(" + json.dumps(sorted(_CLI_ERRORS), separators=(",", ":")) + ")\n"
        "dirs=('/opt','/opt/sovagrid-src','/opt/sovagrid-src/sovagrid-vpn',"
        "'/opt/sovagrid-src/sovagrid-vpn/deploy',"
        "'/opt/sovagrid-src/sovagrid-vpn/sovagrid_vpn')\n"
        "files=(" + json.dumps(CLI) + "," + json.dumps(MODULE) + ")\n"
        "def emit(code,status):\n"
        " sys.stdout.write(json.dumps({'ok':False,'error':code},separators=(',',':'))+'\\n')\n"
        " raise SystemExit(status)\n"
        "try:\n"
        " for path in dirs:\n"
        "  item=os.lstat(path)\n"
        "  if not stat.S_ISDIR(item.st_mode) or item.st_uid!=0 or item.st_mode&0o022: emit('SOURCE_NOT_PREPARED',2)\n"
        " for path in files:\n"
        "  item=os.lstat(path)\n"
        "  if not stat.S_ISREG(item.st_mode) or item.st_uid!=0 or item.st_nlink!=1 or item.st_mode&0o022: emit('SOURCE_NOT_PREPARED',2)\n"
        "except OSError: emit('SOURCE_NOT_PREPARED',2)\n"
        "try:\n"
        " result=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,"
        "timeout=" + str(timeout) + ",check=False)\n"
        "except (OSError,subprocess.TimeoutExpired): emit('AMNEZIA_PROVISION_FAILED',3)\n"
        "if result.returncode==0 and not result.stderr and len(result.stdout)<=8192:\n"
        " sys.stdout.buffer.write(result.stdout)\n"
        " raise SystemExit(0)\n"
        "if result.returncode==2 and not result.stdout and len(result.stderr)<=128:\n"
        " try: code=result.stderr.decode('ascii').strip()\n"
        " except UnicodeError: code=''\n"
        " if code in allowed: emit(code,2)\n"
        "emit('AMNEZIA_PROVISION_FAILED',3)\n"
    )


def _response(raw: bytes, status: int, action: str) -> dict:
    if type(raw) is not bytes or not raw or len(raw) > _MAX_OUTPUT or type(status) is not int:
        raise AmneziaProvisionError(_uncertain(action))
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
        if type(value) is not dict:
            raise ValueError
        if status == 2 and set(value) == {"ok", "error"} and value["ok"] is False and \
                type(value["error"]) is str and value["error"] in _CLI_ERRORS:
            raise AmneziaProvisionError(value["error"])
        if status != 0:
            raise ValueError
        if action == "preview":
            fields = set(value)
            if fields == _DEGRADED_PREVIEW:
                if (type(value.get("schema_version")) is not int or value["schema_version"] != 1 or
                        value.get("action") != "preview" or
                        value.get("writes") is not False or value.get("target") != "awg2" or
                        value.get("container") != "amnezia-awg2" or value.get("can_apply") is not False or
                        type(value.get("reason")) is not str or value["reason"] not in _PREVIEW_REASONS):
                    raise ValueError
                return value
            if fields not in (_FULL_PREVIEW, _FULL_PREVIEW | {"reason"}):
                raise ValueError
            if (type(value.get("schema_version")) is not int or value["schema_version"] != 1 or
                    value.get("action") != "preview" or value.get("writes") is not False or
                    value.get("target") != "awg2" or value.get("container") != "amnezia-awg2" or
                    type(value.get("image_cached")) is not bool or type(value.get("can_apply")) is not bool or
                    type(value.get("state_revision")) is not str or SHA.fullmatch(value["state_revision"]) is None or
                    type(value.get("image_digest")) is not str or IMAGE.fullmatch(value["image_digest"]) is None):
                raise ValueError
            try:
                _target(value.get("listen_port"), value.get("subnet"), value.get("route_mode"))
            except AmneziaProvisionError:
                raise ValueError from None
            if ("reason" in value and (value["can_apply"] is not False or
                    type(value["reason"]) is not str or value["reason"] not in _PREVIEW_REASONS)) or \
                    ("reason" not in value and value["can_apply"] is not True):
                raise ValueError
            return value
        if action == "apply":
            if (set(value) != {"schema_version", "action", "target", "container", "container_id",
                               "image_id", "listen_port", "subnet", "route_mode", "recovery_required"} or
                    type(value.get("schema_version")) is not int or value["schema_version"] != 1 or
                    value.get("action") != "installed" or value.get("target") != "awg2" or
                    value.get("container") != "amnezia-awg2" or value.get("recovery_required") is not False or
                    type(value.get("container_id")) is not str or SHA.fullmatch(value["container_id"]) is None or
                    type(value.get("image_id")) is not str or IMAGE.fullmatch(value["image_id"]) is None):
                raise ValueError
            try:
                _target(value.get("listen_port"), value.get("subnet"), value.get("route_mode"))
            except AmneziaProvisionError:
                raise ValueError from None
            return value
        if (set(value) not in ({"schema_version", "action", "changed", "installed"},
                               {"schema_version", "action", "changed", "installed", "container_id"}) or
                type(value.get("schema_version")) is not int or value["schema_version"] != 1 or
                value.get("action") != "recovered" or type(value.get("changed")) is not bool or
                type(value.get("installed")) is not bool or
                ("container_id" in value and
                 (type(value["container_id"]) is not str or SHA.fullmatch(value["container_id"]) is None))):
            raise ValueError
        return value
    except AmneziaProvisionError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise AmneziaProvisionError(_uncertain(action)) from None


class AmneziaProvisionJobs:
    def __init__(self, enrollment_jobs, *, transport_factory=PinnedTargetSSH):
        self.jobs = enrollment_jobs
        self.transport_factory = transport_factory

    @staticmethod
    def _invoke(rpc, action: str, *, listen_port: int | None = None,
                subnet: str | None = None, route_mode: str | None = None,
                expected_state: str | None = None) -> dict:
        raw, status = rpc._exchange(_script(action, listen_port=listen_port, subnet=subnet,
                                            route_mode=route_mode, expected_state=expected_state), (),
                                     {"preview": 45, "apply": 330, "recover": 80}[action])
        return _response(raw, status, action)

    def execute(self, action: str, *, options, fingerprint: str, credential,
                listen_port: object = None, subnet: object = None, route_mode: object = None,
                expected_state: object = None, confirm: object = None) -> dict:
        if action not in ("preview", "apply", "recover"):
            raise AmneziaProvisionError("INVALID_REQUEST")
        if action == "recover":
            if confirm is not True or any(value is not None for value in
                                          (listen_port, subnet, route_mode, expected_state)):
                raise AmneziaProvisionError("INVALID_REQUEST")
        else:
            _target(listen_port, subnet, route_mode)
            if action == "apply":
                if (confirm is not True or type(expected_state) is not str or
                        SHA.fullmatch(expected_state) is None):
                    raise AmneziaProvisionError("INVALID_REQUEST")
            elif confirm is not None or expected_state is not None:
                raise AmneziaProvisionError("INVALID_REQUEST")
        with self.jobs._exclusive():
            try:
                with self.transport_factory(host=options.host, port=options.port,
                        username=options.user, fingerprint=fingerprint,
                        method=credential.method, password=credential.password,
                        private_key=credential.private_key,
                        passphrase=credential.passphrase) as transport:
                    rpc = transport.target_rpc(transport.options)
                    rpc.preflight()
                    if action == "apply":
                        current = self._invoke(rpc, "preview", listen_port=listen_port,
                                               subnet=subnet, route_mode=route_mode)
                        if not current["can_apply"]:
                            raise AmneziaProvisionError(current.get("reason", "OPERATION_FAILED"))
                        if current.get("state_revision") != expected_state:
                            raise AmneziaProvisionError("STALE_PREVIEW")
                    try:
                        result = self._invoke(rpc, action, listen_port=listen_port,
                                              subnet=subnet, route_mode=route_mode,
                                              expected_state=expected_state)
                    except RPCError:
                        raise AmneziaProvisionError(
                            "APPLY_UNCERTAIN" if action == "apply" else
                            "RECOVERY_UNCERTAIN" if action == "recover" else
                            "SSH_UNAVAILABLE") from None
                    if action == "apply" and (result["listen_port"] != listen_port or
                                              result["subnet"] != subnet or
                                              result["route_mode"] != route_mode):
                        raise AmneziaProvisionError("APPLY_UNCERTAIN")
                    if action == "preview" and ("state_revision" in result and
                                                (result["listen_port"] != listen_port or
                                                 result["subnet"] != subnet or
                                                 result["route_mode"] != route_mode)):
                        raise AmneziaProvisionError("OPERATION_FAILED")
                    return {"protocol": 1, "scope": "entered_target", "host": options.host,
                            "port": options.port, "host_key_fingerprint": fingerprint, **result}
            except AmneziaProvisionError:
                raise
            except RPCError as error:
                raise AmneziaProvisionError(
                    "ROOT_REQUIRED" if error.code == "ROOT_REQUIRED" else
                    "BUSY" if error.code == "BUSY" else "SSH_UNAVAILABLE") from None
            except (TargetSSHError, OSError, ValueError, TypeError):
                raise AmneziaProvisionError("SSH_UNAVAILABLE") from None
