#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Reviewed Web opt-ins for a separately enrolled Agent, over pinned SSH.

Each request stages the verified helper, binds the Agent identity to the live
Hub registration, and cleans its own stage. A lost apply leaves the Hub gate
closed or the target's existing durable feature journal for a fresh review.
SSH credentials and borrowed browser sessions are never persisted.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import time
import uuid

from sovagrid_connect.agent_rpc import RPCError
from sovagrid_connect.enrollment_api import EnrollmentAPIError
from sovagrid_connect.enrollment_protocol import ProtocolError, validate_features
from sovagrid_connect.remote_feature_api import RemoteFeatureAPI
from web_agent_local_rpc import LocalHubFacade
from web_agent_target_ssh import HostKeyChanged, PinnedTargetSSH, TargetSSHError
from web_vpn_source import VpnSourceJobs, VpnSourceError


SHA = re.compile(r"[0-9a-f]{64}\Z")
ERRORS = frozenset({"INVALID_REQUEST", "AUTH_REQUIRED", "ADMIN_FORBIDDEN", "HUB_UNAVAILABLE",
    "AGENT_NOT_ENROLLED", "ROOT_REQUIRED", "SOURCE_UNTRUSTED", "SOURCE_CHANGED",
    "OWNERSHIP_CONFLICT", "STATE_CONFLICT", "SERVICE_FAILED", "AGENT_UPDATE_REQUIRED",
    "STALE_PREVIEW", "RECOVERY_REQUIRED", "FEATURES_UNAVAILABLE", "HOST_KEY_CHANGED",
    "SSH_UNAVAILABLE", "APPLY_UNCERTAIN", "METRIC_UNCONFIRMED", "STAGE_CLEANUP_REQUIRED", "BUSY"})


class AgentFeatureError(RuntimeError):
    def __init__(self, code):
        self.code = code if code in ERRORS else "FEATURES_UNAVAILABLE"
        super().__init__(self.code)


def _flags(value):
    try:
        return validate_features(value)
    except ProtocolError:
        raise AgentFeatureError("INVALID_REQUEST") from None


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


class AgentFeatureJobs:
    def __init__(self, enrollment_jobs, *, transport_factory=PinnedTargetSSH,
                 api_factory=RemoteFeatureAPI, clock=time.monotonic, pause=time.sleep):
        self.jobs, self.transport_factory, self.api_factory = enrollment_jobs, transport_factory, api_factory
        self.clock, self.pause = clock, pause
        self.stages = VpnSourceJobs(enrollment_jobs,
            journal_path=Path(enrollment_jobs._bundle_path).parent / "agent-features-stage.json")

    @staticmethod
    def _bind(status, policy, registration, server_id):
        identity = status["identity"]
        if (identity["server_id"] != server_id or
                any(policy[key] != identity[key] for key in ("server_id", "enrollment_id", "agent_token_sha256")) or
                registration is None or registration["state"] != "active" or
                registration["id"] != identity["enrollment_id"] or registration["server_id"] != server_id):
            raise AgentFeatureError("AGENT_NOT_ENROLLED")

    @staticmethod
    def _review(identity, status, policy, registration, desired):
        # last_seen changes with every metric and cannot be a stable plan pin.
        registration = {key: registration[key] for key in ("id", "server_id", "name", "state")}
        return hashlib.sha256(_canonical({"route": identity, "target": status,
            "hub": policy, "registration": registration, "desired": desired})).hexdigest()

    def execute(self, action, *, server_id, features, options, fingerprint, credential,
                session_token, expected_review_sha256=None, confirm=None, authorize=lambda: None):
        try:
            if str(uuid.UUID(server_id)) != server_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise AgentFeatureError("INVALID_REQUEST") from None
        if action not in ("preview", "apply"):
            raise AgentFeatureError("INVALID_REQUEST")
        desired = None if features is None and action == "preview" else _flags(features)
        if (action == "apply" and (confirm is not True or not isinstance(expected_review_sha256, str) or
                SHA.fullmatch(expected_review_sha256) is None) or
                action == "preview" and (expected_review_sha256 is not None or confirm is not None)):
            raise AgentFeatureError("INVALID_REQUEST")
        identity = {"host": options.host, "port": options.port,
                    "username": options.user, "fingerprint": fingerprint}
        route = {"protocol": 1, "scope": "entered_target", "host": options.host,
            "port": options.port, "host_key_fingerprint": fingerprint,
            "server_id": server_id, "kind": "agent_only"}
        route_kwargs = {}
        jump = getattr(credential, "jump", None)
        if jump is not None:
            if (options.jump_host, options.jump_port, options.jump_user) != (
                    jump["host"], jump["port"], jump["username"]):
                raise AgentFeatureError("INVALID_REQUEST")
            identity["jump"] = {key: jump[key] for key in ("host", "port", "username", "fingerprint")}
            route_kwargs = {"jump": jump, "target_host_key_blob": credential.target_host_key_blob}
            route.update(jump_host=jump["host"], jump_port=jump["port"],
                         jump_host_key_fingerprint=jump["fingerprint"])
        elif options.jump_host is not None:
            raise AgentFeatureError("INVALID_REQUEST")
        api = self.api_factory(LocalHubFacade())
        mutation_started = False
        try:
            api.adopt_bearer(session_token)
            api.verify()
            policy = api.management(server_id)
            with self.jobs._exclusive():
                bundle = self.jobs._bundle()
                with self.transport_factory(host=options.host, port=options.port, username=options.user,
                        fingerprint=fingerprint, method=credential.method, password=credential.password,
                        private_key=credential.private_key, passphrase=credential.passphrase, **route_kwargs) as transport:
                    rpc = transport.target_rpc(transport.options)
                    self.stages._cleanup_orphan(rpc, identity)
                    stage_cleaned = False
                    try:
                        stage = rpc.stage_target(bundle, self.jobs._bundle_sha256,
                            checkpoint=lambda descriptor: self.stages._save_stage(identity, descriptor))

                        def target(operation, **payload):
                            result = rpc.call("target-features-" + operation,
                                {"protocol": 1, "server_id": server_id, **payload}, stage=stage)
                            if result["source_manifest_sha256"] != stage.source_manifest_sha256:
                                raise AgentFeatureError("SOURCE_CHANGED")
                            return result

                        status = target("status") if desired is None else target("preview", features=desired)
                        registration = api.get(status["identity"]["enrollment_id"])
                        self._bind(status, policy, registration, server_id)
                        selected = desired if desired is not None else status["pending_features"] or status["current"]
                        can_apply = desired is not None and status["pending_features"] in (None, desired)
                        review = None if desired is None else self._review(identity, status, policy, registration, desired)
                        public = {**route, "current": status["current"], "desired": selected,
                            "hub_enabled": policy["enabled"], "hub_revision": policy["revision"],
                            "source_manifest_sha256": stage.source_manifest_sha256}
                        changed = (status["current"] != selected or policy["enabled"] != selected["commands"] or
                                   status["recovery_required"])
                        if action == "preview":
                            return {**public, "action": "preview", "can_apply": can_apply,
                                "change_required": bool(changed), "recovery_required": status["recovery_required"],
                                "pending_features": status["pending_features"], "review_sha256": review,
                                "temporary_writes": True, "activation_writes": False}
                        if not can_apply:
                            raise AgentFeatureError("RECOVERY_REQUIRED")
                        if review != expected_review_sha256:
                            raise AgentFeatureError("STALE_PREVIEW")
                        authorize()
                        closed = api.set_management(policy, False)
                        mutation_started = True
                        authorize()
                        applied = target("apply", features=desired, expected=status["expected"],
                            enrollment_id=status["identity"]["enrollment_id"],
                            agent_token_sha256=status["identity"]["agent_token_sha256"])
                        baseline = api.get(applied["identity"]["enrollment_id"])
                        self._bind(applied, closed, baseline, server_id)
                        old_seen = baseline["last_seen"] or 0
                        deadline = self.clock() + 120
                        while True:
                            row = api.get(applied["identity"]["enrollment_id"])
                            self._bind(applied, closed, row, server_id)
                            if row["last_seen"] is not None and row["last_seen"] > old_seen:
                                break
                            if self.clock() >= deadline:
                                raise AgentFeatureError("METRIC_UNCONFIRMED")
                            self.pause(1)
                        final = target("status")
                        final_policy = api.management(server_id)
                        self._bind(final, final_policy, row, server_id)
                        if (final_policy != closed or final["current"] != desired or final["recovery_required"] or
                                any(final[key] != applied[key] for key in
                                    ("identity", "current", "expected", "source_manifest_sha256", "pending_features", "services"))):
                            raise AgentFeatureError("APPLY_UNCERTAIN")
                        # Nothing may reopen command delivery before the fresh
                        # metric, final target/policy checks and stage cleanup
                        # have all succeeded. The SSH context also closes
                        # before the last authorized Hub CAS below.
                        self.stages._cleanup_orphan(rpc, identity)
                        stage_cleaned = True
                    finally:
                        if not stage_cleaned and self.stages._read_stage() is not None:
                            self.stages._cleanup_orphan(rpc, identity)
                authorize()
                opened = api.set_management(closed, desired["commands"])
                return {**public, "action": "applied", "current": final["current"], "desired": desired,
                    "hub_enabled": opened["enabled"], "hub_revision": opened["revision"],
                    "applied": True, "changed": bool(changed), "fresh_metric_verified": True,
                    "cleanup_required": False}
        except AgentFeatureError:
            raise
        except EnrollmentAPIError as error:
            code = {401: "AUTH_REQUIRED", 403: "ADMIN_FORBIDDEN", 404: "AGENT_NOT_ENROLLED"}.get(error.status)
            if error.status == 409 and not mutation_started:
                code = "STALE_PREVIEW"
            raise AgentFeatureError(code or ("APPLY_UNCERTAIN" if mutation_started else "HUB_UNAVAILABLE")) from None
        except VpnSourceError:
            raise AgentFeatureError("STAGE_CLEANUP_REQUIRED") from None
        except HostKeyChanged:
            raise AgentFeatureError("HOST_KEY_CHANGED") from None
        except RPCError as error:
            raise AgentFeatureError(error.code if error.code in ERRORS else
                "APPLY_UNCERTAIN" if mutation_started else "FEATURES_UNAVAILABLE") from None
        except (TargetSSHError, OSError, ValueError, TypeError, KeyError):
            raise AgentFeatureError("APPLY_UNCERTAIN" if mutation_started else "SSH_UNAVAILABLE") from None
        finally:
            api.logout()  # Borrowed browser sessions are forgotten, never revoked.
