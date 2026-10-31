#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Exercise a signed discovery -> idle timer -> real updater transition.

Run only on a disposable GitHub-hosted Ubuntu with an installed full server or activated Hub-only promotion.
The next committed server archive must be root-private under /root. A fresh
throwaway signing key and an in-process HTTPS transport fixture replace only
release hosting: signature, archive verification, preflight, policy, SQLite
admission, Agent admission, installation and health run their real code.
No production signing material or public release is needed for this gate.
"""

from __future__ import annotations

import contextlib
import configparser
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from unittest.mock import patch


sys.dont_write_bytecode = True

SOURCE = Path("/opt/sovagrid-src/sovagrid-blueprint/deploy")
CONFIG = Path("/etc/sovagrid/release-feed.json")
KEY = "disposable-vm-key"


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise SystemExit("signed transition VM: " + reason)


def command(*args: str) -> None:
    subprocess.run(args, check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SOURCE / filename)
    need(spec is not None and spec.loader is not None, "missing installed module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def portable_fixture(action, old, target, candidate):
    if not os.path.lexists("/var/lib/.sovagrid-portable-restore-ci-fixture.json"):
        return
    spec = importlib.util.spec_from_file_location("sovagrid_ci_portable_transition_creator",
        Path(__file__).with_name("portable_restore_apply_vm.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.transition_fixture(action, old, target, candidate)


def private_archive(filename: str) -> bytes:
    source = Path(filename)
    need(source.is_absolute() and source.is_relative_to("/root") and source != Path("/root") and
         ".." not in source.parts,
         "candidate must be under private /root")
    cursor = Path("/")
    for part in source.parent.parts[1:]:
        cursor /= part
        info = cursor.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
             "unsafe candidate parent")
    with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 64 * 1024**2,
             "candidate must be a root-owned private regular file")
        raw = stream.read(64 * 1024**2 + 1)
        need(len(raw) == info.st_size, "candidate changed during read")
    return raw


def probe_broker_api():
    """Use the real Hub -> root broker status path without logging a password/token."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def request(method, path, payload=None, token=None):
        raw = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if token: headers["Authorization"] = "Bearer " + token
        with opener.open(urllib.request.Request("http://127.0.0.1:8766" + path,
                data=raw, headers=headers, method=method), timeout=45) as response:
            body = response.read(32769)
            need(response.status in (200, 204) and len(body) <= 32768, "broker API response unavailable")
            return json.loads(body) if body else None
    password = Path("/etc/sovagrid/admin-password").read_text().strip()
    login = request("POST", "/api/v1/session", {"username": "admin", "password": password})
    password = ""
    token = login.get("token") if isinstance(login, dict) else None
    need(isinstance(token, str) and len(token) >= 32, "fixture Hub login failed")
    try:
        report = request("GET", "/api/v1/release-feed", token=token)
        need(isinstance(report, dict) and report.get("format") == 1 and
             isinstance(report.get("state_revision"), str), "root broker status path failed")
    finally:
        request("DELETE", "/api/v1/session", token=token)
        token = ""


def sandbox_properties(text: str) -> dict[str, str]:
    """Preserve systemd's repeated/reset ReadWritePaths directives exactly.

    ConfigParser alone retains only the final assignment, whereas systemd
    merges list settings. The installed broker deliberately has two entries.
    """
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.read_string(text)
    service = parser["Service"]
    writable = []
    in_service = False
    for line in text.replace("\\\n", " ").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")): continue
        if line.startswith("["):
            in_service = line == "[Service]"
            continue
        if in_service and "=" in line:
            name, value = line.split("=", 1)
            if name.strip() == "ReadWritePaths":
                if value.strip(): writable.append(value.strip())
                else: writable.clear()
    service["ReadWritePaths"] = " ".join(writable)
    names = ("UMask", "NoNewPrivileges", "PrivateTmp", "PrivateDevices", "ProtectSystem",
             "ProtectHome", "ProtectKernelTunables", "ProtectControlGroups", "RestrictAddressFamilies",
             "CapabilityBoundingSet", "AmbientCapabilities", "ReadWritePaths", "TasksMax", "MemoryMax", "KillMode")
    need(service.get("ProtectSystem") == "strict", "broker sandbox is missing")
    paths = [path[1:] if path.startswith("-") else path
             for path in service.get("ReadWritePaths", "").split()]
    for path in ("/etc/sovagrid-hub", "/run/sovagrid-installation.lock", "/run/sovagrid-promotion.lock"):
        need(path in paths, "broker sandbox is missing an exact Hub-only write path")
    need("/run" not in paths and "/" not in paths, "broker sandbox has an overly broad write path")
    return {name: service[name] for name in names if name in service}


def sandbox_arm(feed, automatic, release, current, layout):
    """Run real arm under the installed backup broker's service sandbox.

    The transient unit copies the product unit's exact security/write-path
    directives. It neither changes the broker nor substitutes its checks.
    """
    properties = sandbox_properties(Path("/etc/systemd/system/sovagrid-hub-backup-control.service").read_text())
    unit = "sovagrid-signed-arm-fixture-" + os.urandom(6).hex()
    args = ["/usr/bin/systemd-run", "--quiet", "--wait", "--collect", "--pipe", "--unit=" + unit,
            "--property=Type=oneshot", "--property=User=root", "--property=Group=root",
            "--property=WorkingDirectory=/opt/sovagrid-src/sovagrid-hub"]
    args.extend("--property=" + name + "=" + value for name, value in properties.items())
    result = subprocess.run(args + ["/usr/bin/python3", "-I", str(automatic.WORKER.with_name(
        "hub_only_auto_update.py" if layout == "hub_only" else "auto_update.py")), "arm",
        release["archive_sha256"], current, "--layout", layout], capture_output=True, text=True,
        timeout=240, stdin=subprocess.DEVNULL)
    expected = "SG_HUB_ONLY_AUTO_UPDATE:ARMED" if layout == "hub_only" else "SG_AUTO_UPDATE:ARMED"
    need(result.returncode == 0 and expected in result.stdout.splitlines(), "arm failed inside broker sandbox")


def run(filename: str, layout: str = "full") -> None:
    need(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true" and
         os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
         os.environ.get("RUNNER_OS") == "Linux" and
         os.environ.get("SOVAGRID_SIGNED_TRANSITION_VM") == "1",
         "use only an explicitly selected disposable GitHub-hosted Ubuntu")
    need(Path("/proc/1/comm").read_text().strip() == "systemd", "systemd is required")
    need(layout in ("full", "hub_only"), "unsupported fixture layout")
    feed = load("sovagrid_vm_transition_feed", "release_feed.py")
    auto = load("sovagrid_vm_transition_auto", "hub_only_auto_update.py" if layout == "hub_only" else "auto_update.py")
    worker = load("sovagrid_vm_transition_worker", "hub_only_update.py" if layout == "hub_only" else "remote_update_worker.py")
    need(not CONFIG.exists() and not CONFIG.is_symlink() and not feed.existing_policy(),
         "the disposable install must have no existing subscription or approval")
    current = feed.current_manifest(layout)
    external = worker.promotion.capture_external() if layout == "hub_only" else None
    external_runtime = worker._external_runtime() if layout == "hub_only" else None
    if layout == "hub_only": probe_broker_api()
    archive = private_archive(filename)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as packed:
        manifests = [entry for entry in packed.getmembers() if entry.name == "sovagrid-bundle.json"]
        need(len(manifests) == 1 and manifests[0].isfile() and manifests[0].size <= 512 * 1024,
             "candidate has no single bounded source manifest")
        with packed.extractfile(manifests[0]) as manifest_file:
            target = hashlib.sha256(manifest_file.read()).hexdigest()
    need(target != current, "candidate must change the installed source")
    candidate_hash = hashlib.sha256(archive).hexdigest()
    candidate = feed.CANDIDATES / candidate_hash
    need(not candidate.exists() and not candidate.is_symlink(), "candidate was already staged")
    if layout == "full":
        portable_fixture("begin", current, target, candidate_hash)

    with tempfile.TemporaryDirectory(prefix=".sovagrid-signed-transition-", dir="/root") as directory:
        private = Path(directory)
        private.chmod(0o700)
        signing = private / "ephemeral.pem"
        public = private / "ephemeral.der"
        payload = private / "feed.json"
        signature_path = private / "feed.sig"
        command("/usr/bin/openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(signing))
        signing.chmod(0o600)
        command("/usr/bin/openssl", "pkey", "-in", str(signing), "-pubout", "-outform", "DER",
                "-out", str(public))
        der = public.read_bytes()
        need(der.startswith(feed.ED25519_SPKI_PREFIX) and len(der) == 44, "invalid ephemeral public key")
        now = int(time.time())
        document = {"format": 1, "channel": "stable", "key_id": KEY,
                    "issued_at": now, "expires_at": now + 3600,
                    "releases": [{"sequence": 1, "version": "1.0.0",
                                  "from_manifest_sha256": current, "to_manifest_sha256": target,
                                  "archive_sha256": candidate_hash, "archive_size": len(archive)}]}
        raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        payload.write_bytes(raw)
        command("/usr/bin/openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(signing),
                "-in", str(payload), "-out", str(signature_path))
        signature = signature_path.read_bytes()
        need(len(signature) == 64, "invalid ephemeral signature")
        wire = {feed.FEED_URL: raw, feed.FEED_URL + ".sig": signature,
                feed.archive_url("1.0.0"): archive}

        @contextlib.contextmanager
        def transport(url, hosts):
            feed._validate_url(url, hosts)
            need(url in wire, "unexpected discovery URL")
            with io.BytesIO(wire[url]) as response:
                yield response

        # A real timer must not race the explicit busy/success assertions.
        # This runtime-only override affects the disposable VM; direct tick()
        # below still executes the real selected updater and its idle guards.
        automatic_service = auto.TIMER.removesuffix(".timer") + ".service"
        override_dir = Path("/run/systemd/system") / (automatic_service + ".d")
        need(not override_dir.exists() and not override_dir.is_symlink(), "automatic fixture override already exists")
        override_dir.mkdir(mode=0o755)
        override = override_dir / "90-sovagrid-signed-transition.conf"
        override.write_text("[Service]\nExecStart=\nExecStart=/usr/bin/true\n")
        override.chmod(0o644)
        command("systemctl", "daemon-reload")
        try:
            with contextlib.ExitStack() as changes:
                for name, value in (("TRUST_ANCHORS", {KEY: der[-32:]}),
                                    ("CONFIG", private / "subscription.json"),
                                    ("STATE", private / "ledger.json"),
                                    ("LOCK", private / "discovery.lock"),
                                    ("_open", transport)):
                    changes.enter_context(patch.object(feed, name, value))
                feed.enable(KEY, expected_state=feed._snapshot()["state_revision"])
                command("systemctl", "disable", "--now", feed.TIMER)
                wire[feed.FEED_URL + ".sig"] = bytes([signature[0] ^ 1]) + signature[1:]
                try:
                    feed.poll()
                except feed.Refused as error:
                    need(str(error) == "INVALID_SIGNATURE", "wrong refusal for invalid signature")
                else:
                    need(False, "corrupt signature was accepted")
                need(not candidate.exists() and not auto.POLICY.exists(),
                     "invalid signature staged or approved an update")
                wire[feed.FEED_URL + ".sig"] = signature
                if layout == "hub_only":
                    with patch.object(feed, "arm_candidate", side_effect=lambda release, current, **kwargs:
                            sandbox_arm(feed, auto, release, current, kwargs.get("layout", "full"))):
                        feed.poll()
                else:
                    feed.poll()
                command("systemctl", "stop", auto.TIMER)
                policy = auto.load_policy()
                need(policy is not None and policy["archive_sha256"] == candidate_hash,
                     "signed discovery did not arm the exact verified candidate")
                with (worker.common if layout == "hub_only" else worker).automatic_idle_barrier():
                    auto.tick()
                need(auto.load_policy() is not None and feed.current_manifest() == current,
                     "active database writer did not defer the update")
                busy = json.loads(auto.STATUS.read_bytes())
                need(busy["state"] == "deferred_busy", "busy deferral was not recorded")
                auto.tick()
                need(feed.current_manifest() == target and auto.load_policy() is None,
                     "idle timer failed to install the exact candidate")
                final = json.loads(auto.STATUS.read_bytes())
                need(final["state"] == "applied", "successful transition was not recorded")
                need(feed._snapshot()["enabled"] is True, "subscription state was lost")
                feed.poll()  # Same signed release must now be CURRENT, never replayed.
                feed.disable(expected_state=feed._snapshot()["state_revision"])
        finally:
            command("systemctl", "stop", auto.TIMER)
            if auto.POLICY.exists():
                auto.disarm()
            override.unlink()
            override_dir.rmdir()
            command("systemctl", "daemon-reload")
    if layout == "hub_only":
        need(worker.promotion.capture_external() == external, "external Agent or SSH transport files changed")
        need(worker._external_runtime() == external_runtime, "external Agent or SSH transport processes changed")
        need(not Path("/etc/sovagrid/auto-update.json").exists(), "full-server approval appeared on Hub-only host")
    else:
        portable_fixture("complete", current, target, candidate_hash)
    print("Signed discovery, corrupt-signature refusal, busy deferral and real idle apply passed for " + layout)


if __name__ == "__main__":
    need(len(sys.argv) in (2, 3), "provide a reviewed next server archive and optional full|hub_only layout")
    run(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else "full")
