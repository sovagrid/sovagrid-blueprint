# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Restore cleanup must never stop foreign Docker project resources."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deploy import portable_restore_apply as core
from deploy import portable_restore_compose as compose


class ComposeTest(unittest.TestCase):
    def setUp(self):
        self.plan = {"id": "a" * 32, "bindings": {"apply_review_sha256": "b" * 64},
                     "compose_services": ["hub", "web"],
                     "images": {name: {"config": "sha256:" + digit * 64} for name, digit in (("hub", "c"), ("web", "d"))}}
        self.driver = compose.Compose(SimpleNamespace(), core, self.plan, Path("/ignored"))
        self.hashes = {"hub": "e" * 64, "web": "f" * 64}
        self.config = {"name": "sovagrid", "services": {}, "networks": {"private": {
            "name": "sovagrid_private", "driver": "bridge", "labels": self.driver.labels,
            "ipam": {"config": [{"subnet": "172.30.253.0/28", "gateway": "172.30.253.1"}]}}}}
        for name, uid in (("hub", "10001"), ("web", "10002")):
            self.config["services"][name] = {"image": "sovagrid-" + name + ":local", "user": uid + ":" + uid,
                "read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
                "networks": {"private": None}, "labels": self.driver.labels,
                "volumes": [{"type": "bind", "source": "/var/lib/sovagrid/" + ("hub" if name == "hub" else "caddy"), "target": "/data"}]}
            if name == "web":
                self.config["services"][name]["ports"] = [{"host_ip": "127.0.0.1", "published": str(published),
                    "target": target, "protocol": "tcp"} for published, target in ((8766, 8080), (8767, 8443))]
        self.records = {}
        self.network = None
        self.calls = []
        self.step = {"kind": "compose", "resource": "sovagrid", "desired": {
            "services": self.plan["compose_services"], "images": self.plan["images"]}}
        patchers = [patch.object(self.driver, "_args", return_value=["docker", "compose"]),
                    patch.object(self.driver, "_capture", side_effect=self.capture)]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def capture(self, args, **kwargs):
        self.calls.append(args)
        if args[:2] == ["docker", "compose"]:
            if "config" in args:
                if "--hash" in args:
                    return "\n".join(name + " " + value for name, value in self.hashes.items()).encode()
                return json.dumps(self.config).encode()
            if "up" in args:
                self.assertIn("--no-build", args)
                self.assertEqual(args[args.index("--pull") + 1], "never")
                self.start()
                return b""
        self.assertEqual(args[:3], list(compose.DOCKER))
        args = args[3:]
        if args[0] == "ps":
            return "\n".join(value["id"] for value in self.records.values()).encode()
        if args[0] == "inspect":
            return json.dumps(next(value for value in self.records.values() if value["id"] == args[-1])).encode()
        if args[:2] == ["network", "ls"]:
            return self.network["id"].encode() if self.network else b""
        if args[:2] == ["network", "inspect"]:
            return json.dumps(self.network).encode()
        if args[0] == "stop":
            for value in self.records.values():
                if value["id"] == args[-1]:
                    value["running"] = False
                    self.network["containers"].pop(value["id"], None)
            return b""
        if args[0] == "rm":
            self.records = {name: value for name, value in self.records.items() if value["id"] != args[-1]}
            return b""
        if args[:2] == ["network", "rm"]:
            self.assertFalse(self.network["containers"])
            self.network = None
            return b""
        raise AssertionError(args)

    def start(self):
        for name, digit in (("hub", "1"), ("web", "2")):
            self.records[name] = {"id": digit * 64, "image": self.plan["images"][name]["config"], "running": True,
                "health": "healthy" if name == "hub" else None,
                "labels": {**self.driver.labels, "com.docker.compose.project": "sovagrid", "com.docker.compose.service": name,
                    "com.docker.compose.container-number": "1", "com.docker.compose.config-hash": self.hashes[name]}}
        self.network = {"id": "3" * 64, "name": "sovagrid_private", "driver": "bridge", "labels": self.driver.labels,
                        "ipam": [{"Subnet": "172.30.253.0/28", "Gateway": "172.30.253.1"}],
                        "containers": {value["id"]: {} for value in self.records.values()}}

    def mutations(self):
        return [args for args in self.calls if any(value in args for value in ("up", "stop", "rm", "prune", "down"))]

    def test_verified_project_starts_without_build_pull_and_undo_is_idempotent(self):
        proof = self.driver.prepare(self.step)
        self.driver.execute(self.step, proof)
        self.driver.verify(self.step, proof)
        self.driver.undo(self.step, proof)
        self.driver.undo(self.step, proof)
        self.assertFalse(self.records)
        self.assertIsNone(self.network)
        self.assertFalse(any("prune" in args or "down" in args or "--force" in args for args in self.calls))

    def test_foreign_container_with_same_project_service_never_stops(self):
        proof = self.driver.prepare(self.step)
        self.start()
        self.records["web"]["labels"][compose.LABEL] = "4" * 32
        self.calls.clear()
        with self.assertRaisesRegex(core.Refused, "RESTORE_CONTAINER_CHANGED"):
            self.driver.undo(self.step, proof)
        self.assertFalse(self.mutations())

    def test_network_used_by_other_container_prevents_any_mutation(self):
        proof = self.driver.prepare(self.step)
        self.start()
        self.network["containers"]["9" * 64] = {}
        self.calls.clear()
        with self.assertRaisesRegex(core.Refused, "RESTORE_NETWORK_CHANGED"):
            self.driver.undo(self.step, proof)
        self.assertFalse(self.mutations())

    def test_changed_image_or_config_hash_is_not_treated_as_own_container(self):
        proof = self.driver.prepare(self.step)
        self.start()
        self.records["hub"]["image"] = "sha256:" + "0" * 64
        self.calls.clear()
        with self.assertRaisesRegex(core.Refused, "RESTORE_CONTAINER_CHANGED"):
            self.driver.undo(self.step, proof)
        self.assertFalse(self.mutations())

    def test_config_change_after_review_blocks_start(self):
        proof = self.driver.prepare(self.step)
        self.config["services"]["hub"]["command"] = ["changed"]
        self.calls.clear()
        with self.assertRaisesRegex(core.Refused, "RESTORE_COMPOSE_CHANGED"):
            self.driver.execute(self.step, proof)
        self.assertFalse(self.mutations())

    def test_foreign_mount_port_or_privileged_configuration_is_rejected_before_start(self):
        initial = copy.deepcopy(self.config)
        for mutate in (
                lambda config: config["services"]["hub"].update(privileged=True),
                lambda config: config["services"]["hub"]["volumes"][0].update(source="/etc"),
                lambda config: config["services"]["web"]["ports"][0].update(host_ip="0.0.0.0"),
                lambda config: config["services"]["hub"].update(network_mode="host")):
            self.config = copy.deepcopy(initial)
            mutate(self.config)
            with self.assertRaisesRegex(core.Refused, "RESTORE_COMPOSE_CONFIGURATION_INVALID"):
                self.driver.prepare(self.step)
        self.assertFalse(self.mutations())

    def test_partial_compose_start_is_recoverable_using_only_owned_labels(self):
        proof = self.driver.prepare(self.step)
        self.start()
        self.network["containers"].pop(self.records["web"]["id"])
        self.records.pop("web")
        self.driver.undo(self.step, proof)
        self.assertFalse(self.records)
        self.assertIsNone(self.network)

    def test_health_never_commits_after_wrong_container_state(self):
        proof = self.driver.prepare(self.step)
        self.start()
        self.records["hub"]["health"] = "unhealthy"
        with patch.object(self.driver, "_http_health") as http:
            with self.assertRaisesRegex(core.Refused, "RESTORE_UNHEALTHY"):
                self.driver.health(proof, timeout=0)
            http.assert_not_called()


if __name__ == "__main__":
    unittest.main()
