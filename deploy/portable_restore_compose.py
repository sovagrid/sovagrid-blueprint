#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Operation-labelled local Compose adapter for portable restoration.

It never runs compose down, pulls an image, builds source, or prunes Docker.
Recovery enumerates and checks every project resource before stopping any.
Database/runtime bytes are fenced separately by the publisher; a legitimate
runtime write may require manual recovery rather than destructive rollback.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import time
from types import SimpleNamespace
from typing import Any
import urllib.request


LABEL = "org.sovagrid.restore"
REVIEW_LABEL = "org.sovagrid.restore-review"
DOCKER = ("/usr/bin/docker", "--host", "unix:///var/run/docker.sock")
CONTAINER = re.compile(r"[0-9a-f]{64}\Z")


def override(plan: dict) -> bytes:
    labels = {LABEL: plan["id"], REVIEW_LABEL: plan["bindings"]["apply_review_sha256"]}
    return (json.dumps({"services": {service: {"labels": labels} for service in plan["compose_services"]},
                        "networks": {"private": {"labels": labels}}}, sort_keys=True,
                       separators=(",", ":")) + "\n").encode()


class Compose:
    def __init__(self, restore: Any, core: Any, plan: dict, overlay: Path, *, image_adapter=None):
        self.restore, self.core, self.plan, self.overlay = restore, core, plan, overlay
        self.labels = {LABEL: plan["id"], REVIEW_LABEL: plan["bindings"]["apply_review_sha256"]}
        self.services = plan["compose_services"]
        self.images = plan["images"]
        self.image_adapter = image_adapter or core.Images(SimpleNamespace(
            images={"exported_configs": {name: value["config"] for name, value in self.images.items()},
                    "rootfs_sha256": {name: value["rootfs_sha256"] for name, value in self.images.items()}},
            platforms={name: value["platform"] for name, value in self.images.items()},
            runtime_ids={name: value["runtime_ids"] for name, value in self.images.items()}))

    @staticmethod
    def _environment():
        return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                "SOVAGRID_BOT_TOKEN_FILE": "/etc/sovagrid-hub/bot.token"}

    def _capture(self, args, *, timeout=20, maximum=512 * 1024, data=None):
        try:
            input_options = {"stdin": subprocess.DEVNULL} if data is None else {"input": data}
            result = subprocess.run(args, **input_options, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=timeout, check=False,
                                    env=self._environment())
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise self.core.Refused("RESTORE_COMPOSE_FAILED") from exc
        if result.returncode or len(result.stdout) > maximum:
            raise self.core.Refused("RESTORE_COMPOSE_FAILED")
        return result.stdout

    def _args(self):
        expected = override(self.plan)
        descriptor = self.restore.backup._safe_open(self.overlay)
        try:
            raw, _fingerprint = self.core._read_private_fd(descriptor, maximum=8192,
                uid=self.restore.backup.ROOT_UID, gid=self.restore.backup.ROOT_GID)
            if raw != expected:
                raise self.core.Refused("RESTORE_COMPOSE_OVERRIDE_CHANGED")
        finally:
            os.close(descriptor)
        worker = self.restore._sibling("remote_update_worker.py", "_sovagrid_restore_compose_args")
        worker.ROOT = self.restore.backup.ROOT
        args, _environment = worker.compose_args(self.restore.backup._host("/opt/sovagrid-src"))
        if args[:2] != ["docker", "compose"]:
            raise self.core.Refused("RESTORE_COMPOSE_FAILED")
        return [*DOCKER, *args[1:], "--project-name", "sovagrid", "-f", str(self.restore.backup._host(self.overlay))]

    def _runtime_images(self, expected=None, *, loaded=True):
        self.image_adapter._desired({"kind": "images", "resource": "sovagrid-compose-images",
                                     "desired": {"services": self.images}})
        if expected is not None and (not isinstance(expected, dict) or set(expected) != set(self.services) or
                any(not isinstance(value, str) or self.core.Images.CONFIG.fullmatch(value) is None
                    for name, value in expected.items())):
            raise self.core.Refused("INVALID_RESTORE_PROOF")
        if not loaded:
            if expected is None:
                raise self.core.Refused("INVALID_RESTORE_PROOF")
            return expected
        actual = self.image_adapter.resolved(self.images)
        if expected is not None and actual != expected:
            raise self.core.Refused("RESTORE_IMAGE_CHANGED")
        return actual

    def _proof_images(self, proof):
        if proof.get("image_content_sha256") != hashlib.sha256(self.core._canonical(self.images)).hexdigest():
            raise self.core.Refused("INVALID_RESTORE_PROOF")
        return self._runtime_images(proof.get("runtime_images"), loaded=False)

    def _configuration(self, runtime_images):
        self._runtime_images(runtime_images, loaded=False)
        args = self._args()
        raw = self._capture([*args, "config", "--format", "json"])
        try:
            config = json.loads(raw, object_pairs_hook=self.core._unique)
        except (ValueError, UnicodeError) as exc:
            raise self.core.Refused("RESTORE_COMPOSE_CONFIGURATION_INVALID") from exc
        if (not isinstance(config, dict) or config.get("name") != "sovagrid" or
                not isinstance(config.get("services"), dict) or
                not set(self.services) <= set(config["services"]) <= {"hub", "web", "ssh-gateway"} or
                set(config.get("networks", {})) != {"private"} or config.get("volumes") or config.get("secrets") or
                config.get("configs")):
            raise self.core.Refused("RESTORE_COMPOSE_CONFIGURATION_INVALID")
        network = config["networks"]["private"]
        if (network.get("name") != "sovagrid_private" or network.get("driver") != "bridge" or
                network.get("external") or any(network.get("labels", {}).get(key) != value
                                               for key, value in self.labels.items())):
            raise self.core.Refused("RESTORE_COMPOSE_CONFIGURATION_INVALID")
        expected_ipam = [{"subnet": "172.30.253.0/28", "gateway": "172.30.253.1"}]
        if network.get("ipam", {}).get("config") != expected_ipam:
            raise self.core.Refused("RESTORE_COMPOSE_CONFIGURATION_INVALID")
        for service in self.services:
            value = config["services"][service]
            if (value.get("image") != "sovagrid-" + service + ":local" or
                    value.get("user") != {"hub": "10001:10001", "web": "10002:10002", "ssh-gateway": "10003:10003"}[service] or
                    value.get("read_only") is not True or value.get("privileged") or value.get("cap_add") or
                    set(value.get("cap_drop", [])) != {"ALL"} or value.get("devices") or value.get("device_cgroup_rules") or
                    value.get("network_mode") or value.get("pid") or value.get("ipc") not in (None, "private") or
                    value.get("userns_mode") or "no-new-privileges:true" not in value.get("security_opt", []) or
                    set(value.get("networks", {})) != {"private"} or
                    (set(value.get("group_add", [])) - ({"10005"} if service == "ssh-gateway" else set())) or
                    any(value.get("labels", {}).get(key) != label for key, label in self.labels.items())):
                raise self.core.Refused("RESTORE_COMPOSE_CONFIGURATION_INVALID")
            ports = [(port.get("host_ip"), str(port.get("published")), port.get("target"), port.get("protocol", "tcp"))
                     for port in value.get("ports", [])]
            required_ports = ({("127.0.0.1", "8766", 8080, "tcp"), ("127.0.0.1", "8767", 8443, "tcp")}
                              if service == "web" else set())
            if service == "web" and self.plan.get("public_config") is not None:
                required_ports |= {("0.0.0.0", "80", 9080, "tcp"), ("0.0.0.0", "443", 9443, "tcp")}
            if len(ports) != len(set(ports)) or set(ports) != required_ports:
                raise self.core.Refused("RESTORE_COMPOSE_CONFIGURATION_INVALID")
            allowed = {"hub": {"/var/lib/sovagrid/hub": ("/data", False),
                                "/var/lib/sovagrid/vpn": ("/vpn", True),
                                "/run/sovagrid-hub-backup": ("/run/sovagrid-hub-backup", True),
                                "/etc/sovagrid-hub/bot.token": ("/run/secrets/telegram-bot-token", True)},
                       "web": {"/var/lib/sovagrid/caddy": ("/data", False)},
                       "ssh-gateway": {"/run/sovagrid-web-agent": ("/run/sovagrid-web-agent", True)}}[service]
            for mount in value.get("volumes", []):
                source = mount.get("source")
                expected = allowed.get(source)
                if service == "web" and isinstance(source, str) and re.fullmatch(
                        r"/etc/sovagrid/(public|local)-web/generations/[0-9a-f]{32}/caddy", source):
                    expected = ("/etc/caddy/public" if "/public-web/" in source else "/etc/caddy/local", True)
                if (mount.get("type") != "bind" or expected is None or
                        (mount.get("target"), mount.get("read_only", False)) != expected):
                    raise self.core.Refused("RESTORE_COMPOSE_CONFIGURATION_INVALID")
        # Pin immutable daemon IDs selected only after the archive-bound images
        # were loaded. Stdin supplies the small override without another file or
        # silently changing the reviewed resource plan's engine-independent DAG.
        data = self.core._canonical({"services": {name: {"image": runtime_images[name]}
                                                   for name in self.services}}) + b"\n"
        args = [*args, "-f", "-"]
        pinned_raw = self._capture([*args, "config", "--format", "json"], data=data)
        try:
            pinned = json.loads(pinned_raw, object_pairs_hook=self.core._unique)
        except (ValueError, UnicodeError) as exc:
            raise self.core.Refused("RESTORE_COMPOSE_CONFIGURATION_INVALID") from exc
        for name in self.services:
            config["services"][name]["image"] = runtime_images[name]
        if pinned != config:
            raise self.core.Refused("RESTORE_COMPOSE_CONFIGURATION_INVALID")
        hashes = {}
        for row in self._capture([*args, "config", "--hash", "*"], data=data).decode("ascii").splitlines():
            fields = row.split()
            if len(fields) != 2 or fields[0] in hashes or self.core.SHA.fullmatch(fields[1]) is None:
                raise self.core.Refused("RESTORE_COMPOSE_CONFIGURATION_INVALID")
            hashes[fields[0]] = fields[1]
        if not set(self.services) <= set(hashes):
            raise self.core.Refused("RESTORE_COMPOSE_CONFIGURATION_INVALID")
        return (args, hashlib.sha256(self.core._canonical(pinned)).hexdigest(),
                {name: hashes[name] for name in self.services}, data)

    def _containers(self, proof):
        runtime_images = self._proof_images(proof)
        ids = self._capture([*DOCKER, "ps", "-a", "--no-trunc", "--filter",
                             "label=com.docker.compose.project=sovagrid", "--format", "{{.ID}}"], maximum=4096).decode("ascii").splitlines()
        if len(ids) > len(self.services) or len(ids) != len(set(ids)) or any(CONTAINER.fullmatch(value) is None for value in ids):
            raise self.core.Refused("RESTORE_CONTAINER_CHANGED")
        projection = ('{"id":{{json .Id}},"image":{{json .Image}},"labels":{{json .Config.Labels}},'
                      '"running":{{json .State.Running}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}}}')
        records = {}
        for identity in ids:
            try:
                value = json.loads(self._capture([*DOCKER, "inspect", "--format", projection, identity], maximum=16384),
                                   object_pairs_hook=self.core._unique)
                labels = value["labels"]
                service = labels["com.docker.compose.service"]
                if (value["id"] != identity or service not in self.services or service in records or
                        labels.get("com.docker.compose.project") != "sovagrid" or
                        labels.get("com.docker.compose.container-number") != "1" or
                        labels.get("com.docker.compose.config-hash") != proof["config_hashes"][service] or
                        any(labels.get(key) != label for key, label in self.labels.items()) or
                        value["image"] != runtime_images[service] or type(value["running"]) is not bool):
                    raise self.core.Refused("RESTORE_CONTAINER_CHANGED")
                records[service] = value
            except (ValueError, TypeError, KeyError, UnicodeError) as exc:
                raise self.core.Refused("RESTORE_CONTAINER_CHANGED") from exc
        return records

    def _networks(self, container_ids):
        ids = self._capture([*DOCKER, "network", "ls", "--no-trunc", "--filter",
                             "label=com.docker.compose.project=sovagrid", "--format", "{{.ID}}"], maximum=4096).decode("ascii").splitlines()
        if len(ids) > 1 or any(CONTAINER.fullmatch(value) is None for value in ids):
            raise self.core.Refused("RESTORE_NETWORK_CHANGED")
        for identity in ids:
            projection = '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Labels}},"driver":{{json .Driver}},"ipam":{{json .IPAM.Config}},"containers":{{json .Containers}}}'
            try:
                value = json.loads(self._capture([*DOCKER, "network", "inspect", "--format", projection, identity], maximum=32768),
                                   object_pairs_hook=self.core._unique)
                if (value["id"] != identity or value["name"] != "sovagrid_private" or value["driver"] != "bridge" or
                        value["ipam"] != [{"Subnet": "172.30.253.0/28", "Gateway": "172.30.253.1"}] or
                        any(value["labels"].get(key) != label for key, label in self.labels.items()) or
                        not isinstance(value["containers"], dict) or not set(value["containers"]) <= set(container_ids)):
                    raise self.core.Refused("RESTORE_NETWORK_CHANGED")
            except (ValueError, TypeError, KeyError, UnicodeError) as exc:
                raise self.core.Refused("RESTORE_NETWORK_CHANGED") from exc
        return ids

    def _desired(self, step):
        if (step["kind"] != "compose" or step["resource"] != "sovagrid" or
                step["desired"] != {"services": self.services, "images": self.images}):
            raise self.core.Refused("INVALID_RESTORE_COMPOSE")

    def prepare(self, step):
        self._desired(step)
        runtime_images = self._runtime_images()
        _args, digest, hashes, _data = self._configuration(runtime_images)
        proof = {"config_sha256": digest, "config_hashes": hashes,
                 "labels": self.labels, "absent": True, "runtime_images": runtime_images,
                 "image_content_sha256": hashlib.sha256(self.core._canonical(self.images)).hexdigest()}
        if self._containers(proof) or self._networks([]):
            raise self.core.Refused("RESTORE_PROJECT_EXISTS")
        return proof

    def execute(self, step, proof):
        self._desired(step)
        if proof != self.prepare(step):
            raise self.core.Refused("RESTORE_COMPOSE_CHANGED")
        args, _digest, _hashes, data = self._configuration(proof["runtime_images"])
        self._runtime_images(proof["runtime_images"])
        self._capture([*args, "up", "-d", "--no-build", "--pull", "never", *self.services], timeout=180, data=data)

    def verify(self, step, proof):
        self._desired(step)
        if proof.get("labels") != self.labels or proof.get("absent") is not True:
            raise self.core.Refused("INVALID_RESTORE_PROOF")
        self._proof_images(proof)
        self._runtime_images(proof.get("runtime_images"))
        _args, digest, hashes, _data = self._configuration(proof["runtime_images"])
        if digest != proof.get("config_sha256") or hashes != proof.get("config_hashes"):
            raise self.core.Refused("RESTORE_COMPOSE_CHANGED")
        records = self._containers(proof)
        if set(records) != set(self.services) or any(not value["running"] for value in records.values()):
            raise self.core.Refused("RESTORE_CONTAINER_UNHEALTHY")
        if not self._networks([value["id"] for value in records.values()]):
            raise self.core.Refused("RESTORE_NETWORK_CHANGED")

    def undo(self, step, proof):
        self._desired(step)
        if proof.get("labels") != self.labels or proof.get("absent") is not True or set(proof.get("config_hashes", {})) != set(self.services):
            raise self.core.Refused("INVALID_RESTORE_PROOF")
        self._proof_images(proof)
        records = self._containers(proof)
        identities = [value["id"] for value in records.values()]
        self._networks(identities)
        for identity in identities:
            self._capture([*DOCKER, "stop", "--time", "30", identity], timeout=45)
        stopped = self._containers(proof)
        if {name: value["id"] for name, value in stopped.items()} != {name: value["id"] for name, value in records.items()} or any(value["running"] for value in stopped.values()):
            raise self.core.Refused("RESTORE_CONTAINER_CHANGED")
        for identity in identities:
            # No --force/-v: foreign mounts/active containers cause a refusal.
            self._capture([*DOCKER, "rm", identity])
        if self._containers(proof):
            raise self.core.Refused("RESTORE_CONTAINER_CHANGED")
        for identity in self._networks([]):
            self._capture([*DOCKER, "network", "rm", identity])
        if self._networks([]):
            raise self.core.Refused("RESTORE_NETWORK_CHANGED")

    def _http_health(self):
        ca = self.restore.backup._host("/etc/sovagrid/hub-ca.pem")
        context = ssl.create_default_context(cafile=str(ca))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        for url in ("http://127.0.0.1:8766/healthz", "https://localhost:8767/healthz"):
            with opener.open(url, timeout=4) as response:
                if response.status != 200 or len(response.read(4097)) > 4096:
                    raise self.core.Refused("RESTORE_HTTP_UNHEALTHY")
        if "ssh-gateway" in self.services:
            request = urllib.request.Request("http://127.0.0.1:8766/api/v1/browser-ssh/host-key", data=b"{}",
                headers={"Content-Type": "application/json", "Origin": "http://127.0.0.1:8766"}, method="POST")
            with opener.open(request, timeout=5) as response:
                raw = response.read(16385)
                if response.status != 200 or len(raw) > 16384:
                    raise self.core.Refused("RESTORE_GATEWAY_UNHEALTHY")
            value = json.loads(raw, object_pairs_hook=self.core._unique)
            if (not isinstance(value, dict) or set(value) != {"protocol", "port", "key_type", "fingerprint", "host_key_blob"} or
                    type(value["protocol"]) is not int or value["protocol"] != 1 or type(value["port"]) is not int or
                    not 1 <= value["port"] <= 65535 or not isinstance(value["host_key_blob"], str)):
                raise self.core.Refused("RESTORE_GATEWAY_UNHEALTHY")
            key = base64.b64decode(value["host_key_blob"], validate=True)
            if not 8 <= len(key) <= 8192:
                raise self.core.Refused("RESTORE_GATEWAY_UNHEALTHY")
            length = int.from_bytes(key[:4], "big")
            fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key).digest()).decode("ascii").rstrip("=")
            if (not 4 <= length <= 96 or 4 + length > len(key) or key[4:4 + length].decode("ascii") != value["key_type"] or
                    base64.b64encode(key).decode("ascii") != value["host_key_blob"] or fingerprint != value["fingerprint"]):
                raise self.core.Refused("RESTORE_GATEWAY_UNHEALTHY")
        public = self.plan.get("public_config")
        if public is not None:
            # Connect to THIS host, verifying the configured certificate name.
            # DNS or an old source server can never satisfy this health check.
            with socket.create_connection(("127.0.0.1", 443), timeout=5) as connection:
                with ssl.create_default_context().wrap_socket(connection, server_hostname=public["address"]) as tls:
                    tls.sendall(("GET " + public["panel_path"] + " HTTP/1.1\r\nHost: " + public["address"] +
                                 "\r\nConnection: close\r\n\r\n").encode("ascii"))
                    response = http.client.HTTPResponse(tls)
                    response.begin()
                    if response.status != 200 or b"SovaGrid" not in response.read(65536):
                        raise self.core.Refused("RESTORE_PUBLIC_UNHEALTHY")

    def health(self, proof, *, timeout=90):
        deadline = time.monotonic() + timeout
        while True:
            try:
                records = self._containers(proof)
                if set(records) != set(self.services) or any(not value["running"] or
                        (name in ("hub", "ssh-gateway") and value["health"] != "healthy")
                        for name, value in records.items()):
                    raise self.core.Refused("RESTORE_CONTAINER_UNHEALTHY")
                self._http_health()
                return
            except (self.core.Refused, OSError, ValueError, TypeError, KeyError, UnicodeError):
                if time.monotonic() >= deadline:
                    raise self.core.Refused("RESTORE_UNHEALTHY") from None
                time.sleep(1)
