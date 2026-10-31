#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in, destructive external Agent apply trial on a disposable Ubuntu VM.

This fixture is never a product API. It runs only on a fresh GitHub-hosted
systemd VM with explicit opt-in. It replaces the published fixture Agent with
an enrolled historical Agent and applies the reviewed current candidate. A
private loopback TLS Hub supplies real HTTP lease and metrics traffic. Its
inert tunnel unit does not test real SSH forwarding.
"""

from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import importlib.util
import json
import os
from pathlib import Path
import pwd
import grp
import re
import secrets
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import uuid
from unittest import mock


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PORT = 19449
HUB_UNIT = "sovagrid-external-apply-test-hub.service"
HUB_ROOT = Path("/run/sovagrid-external-apply-test-hub")
HUB_STATE = HUB_ROOT / "state.json"
HUB_KEY = HUB_ROOT / "key.pem"
HUB_CERT = HUB_ROOT / "cert.pem"
SHA = re.compile(r"[0-9a-f]{64}\Z")
AGENT_UNIT = "sovagrid-agent.service"
BASELINE_AGENT_COMMIT = "1085a14a7c0c654a5a6ec16edd028dea1c543c8e"
EXPECTED_TRIAL_COMPONENTS = {
    "sovagrid-agent": "abb00bb36489814593304d8e2055779d08e67eb9",
    "sovagrid-hub": "cfaef4855e32245941e3a57a4393f93551e511d2",
    "sovagrid-web": "ce740bb11ff47ffb226826e31c1b5e9d6b85a0b9",
    "sovagrid-vpn": "5ccfd083c8a2fd26413beb0a0d46393890c62b20",
}


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise SystemExit("External Agent VM fixture: " + reason)


def command(*args: str, timeout: int = 60) -> str:
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout).stdout.strip()


def broker_request(payload: dict) -> dict:
    """Use the real backup broker socket as the Hub's fixed unprivileged UID."""
    script = ("import socket,sys\n"
              "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
              "s.settimeout(240)\n"
              "s.connect('/run/sovagrid-hub-backup/control.sock')\n"
              "s.sendall(sys.stdin.buffer.read())\n"
              "data=bytearray()\n"
              "while not data.endswith(b'\\n') and len(data)<65536:\n"
              " item=s.recv(4096)\n"
              " if not item: break\n"
              " data.extend(item)\n"
              "sys.stdout.buffer.write(data)\n")
    result = subprocess.run(["runuser", "-u", "sovagrid-hub", "--",
                             "/usr/bin/python3", "-I", "-c", script],
                            input=encode(payload), capture_output=True,
                            timeout=260, check=False)
    require(result.returncode == 0 and result.stdout.endswith(b"\n") and
            len(result.stdout) <= 65536, "backup broker socket unavailable")
    value = json.loads(result.stdout)
    require(isinstance(value, dict) and value.get("ok") is True,
            "backup broker refused external Agent request")
    return value


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def replace_root_file(path: Path, data: bytes, *, gid: int = 0,
                      mode: int = 0o644) -> None:
    require(path.is_file() and not path.is_symlink(), f"unexpected path: {path}")
    path.write_bytes(data)
    os.chown(path, 0, gid)
    path.chmod(mode)


def write_root_file(path: Path, data: bytes, *, gid: int = 0,
                    mode: int = 0o644) -> None:
    require(not path.exists() and not path.is_symlink(), f"path already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.chown(path, 0, gid)
    path.chmod(mode)


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"missing module: {path}")
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def installed_planner():
    return _module("sovagrid_vm_external_update",
                   Path("/opt/sovagrid-src/sovagrid-blueprint/deploy/external_agent_update.py"))


def _hub_counters() -> dict:
    return json.loads(HUB_STATE.read_text())


def _wait(predicate, label: str, *, seconds: float = 30) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.25)
    require(False, "timeout: " + label)


def _pid() -> int:
    require(command("systemctl", "is-active", AGENT_UNIT) == "active", "Agent inactive")
    value = command("systemctl", "show", "-P", "MainPID", AGENT_UNIT)
    require(value.isdecimal() and int(value) > 1, "Agent PID missing")
    return int(value)


class FixtureHub(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, token: str, server_id: str, manifest_sha256: str):
        super().__init__(("127.0.0.1", PORT), FixtureHandler)
        self.token = token
        self.base = f"/api/v1/servers/{server_id}"
        self.manifest_sha256 = manifest_sha256
        self.lock = threading.Lock()
        self.epoch = secrets.token_hex(16)
        self.lease_token: str | None = None
        self.lease_expires = 0
        self.max_until = 0
        self.counters = {"metrics": 0, "jobs": 0, "checks": 0,
                         "lease_acquire": 0, "lease_renew": 0,
                         "lease_release": 0, "lease_expires_at": 0}
        self.save()

    def save(self):
        temporary = HUB_STATE.with_suffix(".tmp")
        temporary.write_bytes(encode(self.counters))
        temporary.chmod(0o600)
        os.replace(temporary, HUB_STATE)


class FixtureHandler(BaseHTTPRequestHandler):
    server: FixtureHub

    def log_message(self, _format: str, *_args) -> None:
        # No bearer, request body or URL is emitted to runner logs.
        return

    def reply(self, code: int, value: dict) -> None:
        raw = encode(value)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def authorized(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        return hmac.compare_digest(supplied, "Bearer " + self.server.token)

    def body(self) -> dict | None:
        length = self.headers.get("Content-Length", "")
        if not length.isdecimal() or int(length) > 32768:
            return None
        try:
            value = json.loads(self.rfile.read(int(length)))
        except (ValueError, UnicodeError):
            return None
        return value if isinstance(value, dict) else None

    def do_GET(self) -> None:  # noqa: N802
        if not self.authorized():
            self.reply(403, {"error": "unauthorized"})
            return
        if self.path == self.server.base + "/agent-compatibility":
            self.reply(200, {"protocol": 1,
                             "bundle_manifest_sha256": self.server.manifest_sha256})
        elif self.path == self.server.base + "/jobs/next":
            with self.server.lock:
                self.server.counters["jobs"] += 1
                self.server.save()
            self.reply(200, {"job": None})
        else:
            self.reply(404, {"error": "unknown"})

    def do_POST(self) -> None:  # noqa: N802
        if not self.authorized():
            self.reply(403, {"error": "unauthorized"})
            return
        payload = self.body()
        if payload is None:
            self.reply(400, {"error": "invalid"})
            return
        if self.path == self.server.base + "/metrics":
            with self.server.lock:
                self.server.counters["metrics"] += 1
                self.server.save()
            self.reply(200, {"accepted": True})
        elif self.path == self.server.base + "/checks/claim":
            with self.server.lock:
                self.server.counters["checks"] += 1
                self.server.save()
            self.reply(200, {"lease": None})
        elif self.path.startswith(self.server.base + "/agent-maintenance/"):
            self.maintenance(payload)
        else:
            self.reply(404, {"error": "unknown"})

    def maintenance(self, payload: dict) -> None:
        action = self.path.removeprefix(self.server.base + "/agent-maintenance/")
        with self.server.lock:
            now = int(time.time())
            active = self.server.lease_token is not None and now < self.server.lease_expires
            if action == "lease" and payload == {
                    "bundle_manifest_sha256": self.server.manifest_sha256}:
                if active:
                    self.reply(409, {"error": "busy"})
                    return
                self.server.lease_token = secrets.token_urlsafe(32)
                self.server.max_until = now + 900
                self.server.lease_expires = now + 20
                self.server.counters["lease_acquire"] += 1
                result = {"protocol": 1, "scope": "jobs_and_new_relays",
                          "hub_epoch": self.server.epoch,
                          "expires_at": self.server.lease_expires,
                          "max_until": self.server.max_until,
                          "agent_idle_proven": False,
                          "lease_token": self.server.lease_token}
                code = 201
            elif action == "lease/renew" and active and payload == {
                    "lease_token": self.server.lease_token}:
                self.server.lease_expires = min(now + 20, self.server.max_until)
                self.server.counters["lease_renew"] += 1
                result = {"protocol": 1, "scope": "jobs_and_new_relays",
                          "hub_epoch": self.server.epoch,
                          "expires_at": self.server.lease_expires,
                          "max_until": self.server.max_until,
                          "agent_idle_proven": False}
                code = 200
            elif action == "lease/release" and active and payload == {
                    "lease_token": self.server.lease_token}:
                self.server.lease_token = None
                self.server.counters["lease_release"] += 1
                result, code = {"released": True}, 200
            else:
                self.reply(409, {"error": "lease_changed"})
                return
            self.server.counters["lease_expires_at"] = self.server.lease_expires
            self.server.save()
        self.reply(code, result)


def serve() -> None:
    state = json.loads(Path("/var/lib/sovagrid-agent-enrollment/state.json").read_text())
    token = Path("/etc/sovagrid/agent.token").read_text().strip()
    manifest = json.loads(Path("/run/sovagrid-external-apply-test-hub/manifest.json").read_text())
    server = FixtureHub(token, state["identity"]["server_id"], manifest["sha256"])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(HUB_CERT), str(HUB_KEY))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever(poll_interval=0.25)


def seed(candidate: Path, old_agent_source: Path) -> None:
    from promotion_vm import save_baseline, snapshot

    candidate = candidate.resolve(strict=True)
    old_agent_source = old_agent_source.resolve(strict=True)
    raw = (candidate / "sovagrid-bundle.json").read_bytes()
    candidate_manifest = json.loads(raw)
    manifest_sha256 = sha(raw)
    components = candidate_manifest.get("components") if isinstance(candidate_manifest, dict) else None
    require(isinstance(components, dict) and all(
            isinstance(components.get(name), dict) and
            components[name].get("commit") == commit
            for name, commit in EXPECTED_TRIAL_COMPONENTS.items()),
            "candidate does not use the reviewed server component set")
    require(SHA.fullmatch(manifest_sha256) is not None and
            (candidate / "sovagrid-agent/sovagrid_agent/trial_gate.py").is_file(),
            "candidate lacks trial-capable Agent")
    # Stage an actual older Agent source tree so the trial covers code migration.
    # The workflow extracts this tree from the pinned Git commit before seeding.
    helper = _module("sovagrid_vm_remote_agent", ROOT / "deploy/remote_agent.py")
    old_manifest = json.loads(raw)
    old_files = sorted(path for path in old_agent_source.rglob("*") if path.is_file())
    require(bool(old_files) and all(not path.is_symlink() for path in old_files) and
            (old_agent_source / "sovagrid_agent/trial_gate.py").is_file() and
            (old_agent_source / "sovagrid_agent/agent.py").read_bytes() !=
            (candidate / "sovagrid-agent/sovagrid_agent/agent.py").read_bytes(),
            "historical Agent source is missing or matches the candidate")
    old_hashes = {"sovagrid-agent/" + path.relative_to(old_agent_source).as_posix():
                  sha(path.read_bytes()) for path in old_files}
    hashes = old_manifest["sha256"]
    for relative in list(hashes):
        if relative.startswith("sovagrid-agent/"):
            del hashes[relative]
    hashes.update(old_hashes)
    old_manifest["components"]["sovagrid-agent"] = {
        "commit": BASELINE_AGENT_COMMIT, "file_count": len(old_hashes)}
    old_projection = helper.Enrollment.installed_projection(old_manifest)
    require(set(old_projection) <= set(helper.Enrollment.installed_projection(candidate_manifest)),
            "historical Agent has installed files absent from candidate")
    require(not HUB_ROOT.exists() and not Path("/etc/systemd/system", HUB_UNIT).exists(),
            "fixture already installed")
    command("systemctl", "stop", AGENT_UNIT)
    command("systemctl", "stop", "sovagrid-agent-tunnel.service")
    command("groupadd", "--system", "sovagrid-tunnel")
    command("useradd", "--system", "--gid", "sovagrid-tunnel", "--home-dir",
            "/var/empty/sovagrid-tunnel", "--shell", "/usr/sbin/nologin", "sovagrid-tunnel")
    tunnel_uid = pwd.getpwnam("sovagrid-tunnel").pw_uid
    agent = pwd.getpwnam("sovagrid")
    os.chown("/var/lib/sovagrid-agent", 0, agent.pw_gid)
    Path("/var/lib/sovagrid-agent").chmod(0o750)

    shutil.rmtree("/opt/sovagrid-agent")
    Path("/opt/sovagrid-agent").mkdir(mode=0o755)
    for destination in old_projection:
        relative = (helper.SELF_NAME if destination == helper.TARGET_HELPER else
                    "sovagrid-agent/" + destination.removeprefix("/opt/sovagrid-agent/"))
        data = ((candidate / relative).read_bytes() if destination == helper.TARGET_HELPER
                else (old_agent_source /
                      relative.removeprefix("sovagrid-agent/")).read_bytes())
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        os.chown(target, 0, 0)
        target.chmod(0o644)
    for directory in Path("/opt/sovagrid-agent").rglob("*"):
        if directory.is_dir():
            os.chown(directory, 0, 0)
            directory.chmod(0o755)
    old_raw = encode(old_manifest)
    manifest_path = Path("/opt/sovagrid-agent-installer/source-manifest.json")
    replace_root_file(manifest_path, old_raw)
    unit = Path("/etc/systemd/system/sovagrid-agent.service")
    replace_root_file(unit, (old_agent_source / "deploy/sovagrid-agent.service").read_bytes())
    tunnel = Path("/etc/systemd/system/sovagrid-agent-tunnel.service")
    replace_root_file(tunnel, ("[Unit]\nDescription=Disposable test transport\n"
                               "[Service]\nType=simple\nUser=sovagrid-tunnel\n"
                               "Group=sovagrid-tunnel\nExecStart=/usr/bin/sleep infinity\n"
                               "[Install]\nWantedBy=multi-user.target\n").encode())
    dropin = Path("/etc/systemd/system/sovagrid-agent.service.d/10-tunnel.conf")
    write_root_file(dropin, b"[Unit]\nWants=sovagrid-agent-tunnel.service\n"
                            b"After=sovagrid-agent-tunnel.service\n")
    dropin.parent.chmod(0o755)

    HUB_ROOT.mkdir(mode=0o700)
    command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-keyout", str(HUB_KEY), "-out", str(HUB_CERT))
    HUB_KEY.chmod(0o600)
    HUB_CERT.chmod(0o600)
    replace_root_file(Path("/etc/sovagrid/hub-ca.pem"), HUB_CERT.read_bytes())
    write_root_file(HUB_ROOT / "manifest.json", encode({"sha256": manifest_sha256}),
                    mode=0o600)
    config_path = Path("/etc/sovagrid/agent.json")
    server_id = str(uuid.uuid4())
    config = {"hub_url": f"https://localhost:{PORT}", "server_id": server_id,
              "token_file": "/etc/sovagrid/agent.token", "ca_file": "/etc/sovagrid/hub-ca.pem",
              "interval_seconds": 5, "allow_remote_commands": True,
              "allow_interactive_terminal": False, "allow_file_manager": False,
              "allow_systemd_journal": False, "journal_units": [], "file_roots": {}}
    replace_root_file(config_path, encode(config), gid=agent.pw_gid, mode=0o640)
    token = Path("/etc/sovagrid/agent.token").read_bytes()
    require(re.fullmatch(rb"[A-Za-z0-9_-]{43}\n", token) is not None,
            "seed token invalid")

    enrollment_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())
    key_dir = Path("/etc/sovagrid-agent-tunnel")
    key_dir.mkdir(mode=0o700, exist_ok=False)
    key_path = key_dir / "id_ed25519"
    command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
            "sovagrid:" + enrollment_id, "-f", str(key_path))
    key_path.chmod(0o600)
    public = key_path.with_suffix(".pub").read_text().strip().split()
    require(len(public) == 3 and public[2] == "sovagrid:" + enrollment_id,
            "fixture SSH key invalid")
    ssh_public_key, fingerprint = helper.public_key(" ".join(public[:2]))
    public_dir = Path("/etc/sovagrid-agent-tunnel-public")
    public_dir.mkdir(mode=0o755, exist_ok=False)
    write_root_file(public_dir / "known_hosts",
                    ("sovagrid-fixture " + ssh_public_key + "\n").encode())

    state_path = Path("/var/lib/sovagrid-agent-enrollment/state.json")
    tracked = [*map(Path, old_projection), manifest_path, unit, tunnel, dropin,
               config_path, Path("/etc/sovagrid/agent.token"),
               Path("/etc/sovagrid/hub-ca.pem"), key_path, key_path.with_suffix(".pub"),
               public_dir / "known_hosts"]
    owned = {str(path): sha(path.read_bytes()) for path in tracked}
    metadata = {str(path): {"mode": stat.S_IMODE(path.stat().st_mode),
                            "gid": path.stat().st_gid} for path in tracked}
    state = {"protocol": 1, "kind": "target", "identity": {
        "request_id": request_id, "enrollment_id": enrollment_id,
        "server_id": server_id}, "phase": "active", "created_at": int(time.time()),
        "source_manifest_sha256": sha(old_raw), "source_files": old_projection,
        "owned_files": owned, "file_metadata": metadata, "owned_directories": {},
        "pending_writes": {}, "accounts": {
            "sovagrid": {"uid": agent.pw_uid, "gid": agent.pw_gid},
            "sovagrid-tunnel": {"uid": tunnel_uid,
                                "gid": grp.getgrnam("sovagrid-tunnel").gr_gid}},
        "agent_token_sha256": sha(token.rstrip(b"\n")),
        "ssh_public_key": ssh_public_key, "ssh_key_fingerprint": fingerprint,
        "local_port": PORT, "transport": {"hub_host": "127.0.0.1",
            "hub_port": 22, "local_port": PORT,
            "hub_host_key": ssh_public_key,
            "hub_ca_pem": HUB_CERT.read_text()}}
    replace_root_file(state_path, encode(state), mode=0o600)
    # The promotion seed provides a placeholder enrollment state, but never
    # invokes the enrollment helper that normally creates this private lock.
    # Snapshot verification must use the same read-only lock as production.
    write_root_file(state_path.parent / "lock", b"", mode=0o600)
    service = ("[Unit]\nDescription=Disposable SovaGrid external apply test Hub\n"
               "[Service]\nType=simple\nUser=root\nGroup=root\n"
               f"ExecStart=/usr/bin/python3 -I {Path(__file__).resolve()} serve\n"
               "Restart=on-failure\nEnvironment=GITHUB_ACTIONS=true\n"
               "Environment=RUNNER_ENVIRONMENT=github-hosted\n"
               "Environment=SOVAGRID_EXTERNAL_APPLY_VM_FIXTURE=1\n"
               "[Install]\nWantedBy=multi-user.target\n")
    write_root_file(Path("/etc/systemd/system") / HUB_UNIT, service.encode())
    command("systemctl", "daemon-reload")
    command("systemctl", "enable", "--now", HUB_UNIT)
    command("systemctl", "start", "sovagrid-agent-tunnel.service")
    command("systemctl", "start", AGENT_UNIT)
    _wait(lambda: HUB_STATE.is_file() and _hub_counters()["metrics"] > 0,
          "Agent metrics to test Hub")
    planner = _module("sovagrid_vm_external_seed_update", ROOT / "deploy/external_agent_update.py")
    actual_sha, _manifest, _state = planner._external_snapshot()
    require(actual_sha == sha(old_raw), "full external enrollment validation failed")
    save_baseline({"external": snapshot()})
    print("Disposable external Agent, enrollment and test Hub are active")


def _review(planner, archive_sha256: str) -> tuple[str, str, str]:
    current = sha(Path("/opt/sovagrid-src/sovagrid-bundle.json").read_bytes())
    result = planner.preflight(archive_sha256, current)
    require(result["archive_sha256"] == archive_sha256 and
            result["current_hub_manifest_sha256"] == current,
            "review identity changed")
    return current, result["external_agent_manifest_sha256"], result["review_sha256"]


def _assert_restored(planner, old_sha: str, old_state: bytes, old_baseline: bytes) -> None:
    observed, _manifest, _state = planner._external_snapshot()
    require(observed == old_sha and
            Path("/var/lib/sovagrid-agent-enrollment/state.json").read_bytes() == old_state and
            Path("/var/lib/sovagrid-promotion/baseline.json").read_bytes() == old_baseline and
            planner.recovery.Recovery(planner.remote.Files())._load_journal() is None and
            not Path(planner.recovery.TRIAL_DROPIN).exists(),
            "precommit recovery did not restore exact source/state/baseline")
    _pid()


def _wait_lease_expiry() -> None:
    expiry = _hub_counters()["lease_expires_at"]
    require(type(expiry) is int and expiry > 0, "test Hub lease missing")
    _wait(lambda: time.time() > expiry + 1, "orphaned test lease expiry", seconds=30)


def killed_at_trial(archive_sha256: str) -> None:
    planner = installed_planner()
    current, old, review = _review(planner, archive_sha256)
    original = planner.recovery.Recovery.begin_trial

    def interrupt(transaction, **kwargs):
        original(transaction, **kwargs)
        os.kill(os.getpid(), signal.SIGKILL)

    with mock.patch.object(planner.recovery.Recovery, "begin_trial", interrupt):
        planner.apply(archive_sha256, current, old, review)
    raise SystemExit("trial SIGKILL did not happen")


def run(archive_sha256: str) -> None:
    require(SHA.fullmatch(archive_sha256) is not None, "archive SHA required")
    fixed_unit = Path("/etc/systemd/system/sovagrid-external-agent-apply@.service")
    fixed_marker = Path("/etc/sovagrid/.external-agent-apply-managed-by-run-sh")
    require(fixed_unit.is_file() and fixed_marker.is_file() and fixed_unit.read_bytes() ==
            (ROOT / "deploy/sovagrid-external-agent-apply@.service").read_bytes() and
            fixed_marker.read_bytes() == b"SOVAGRID_EXTERNAL_AGENT_APPLY_UNIT_V1\n",
            "repeat Hub-only install did not install the fixed Agent writer")
    planner = installed_planner()
    candidate_root, _commits = planner.common.candidate_source(archive_sha256)
    _candidate_sha, candidate_manifest = planner._manifest(candidate_root)
    require(planner._normal_activation_ready(candidate_manifest),
            "candidate lacks the production trial protocol")
    old_sha, _old_manifest, _old_state = planner._external_snapshot()
    old_state = Path("/var/lib/sovagrid-agent-enrollment/state.json").read_bytes()
    old_baseline = Path("/var/lib/sovagrid-promotion/baseline.json").read_bytes()
    initial_pid = _pid()
    current, old, review = _review(planner, archive_sha256)
    require(old == old_sha and old != current, "candidate is not an Agent update")

    original_switch = planner.recovery.Recovery._switch_under_quiescence

    def interrupted_switch(transaction, **kwargs):
        original_switch(transaction, **kwargs)
        raise planner.Refused("VM_PRECOMMIT_FAULT")

    with mock.patch.object(planner.recovery.Recovery,
                           "_switch_under_quiescence", interrupted_switch):
        try:
            planner.apply(archive_sha256, current, old, review)
        except planner.Refused as exc:
            causes = []
            item: BaseException | None = exc
            while item is not None and len(causes) < 4:
                value = str(item)
                causes.append(value if re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", value)
                              else type(item).__name__)
                item = item.__cause__
            require(str(exc) == "VM_PRECOMMIT_FAULT",
                    "wrong precommit failure: " + "/".join(causes))
        else:
            require(False, "precommit fault unexpectedly succeeded")
    _assert_restored(planner, old_sha, old_state, old_baseline)
    require(_pid() != initial_pid, "rollback did not restart old Agent")

    child = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()),
                            "kill-at-trial", archive_sha256], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=180, env={**os.environ,
                                             "SOVAGRID_EXTERNAL_APPLY_VM_FIXTURE": "1"})
    require(child.returncode == -signal.SIGKILL, "supervisor did not die at trial")
    require(Path(planner.recovery.JOURNAL).is_file() and
            Path(planner.recovery.TRIAL_DROPIN).is_file(),
            "trial journal was not durable before SIGKILL")
    command("systemctl", "start", AGENT_UNIT, timeout=90)
    _wait(lambda: command("systemctl", "is-active", AGENT_UNIT) == "active",
          "boot recovery Agent start")
    _assert_restored(planner, old_sha, old_state, old_baseline)
    for path in (planner.TRIAL_WATCH_SOCKET, planner.TRIAL_WATCH_EPOCH,
                 Path(planner.recovery.TRIAL_GATE_SOCKET)):
        require(not path.exists() and not path.is_symlink(),
                f"stale trial runtime remained after boot recovery: {path}")
    _wait_lease_expiry()

    old_pid = _pid()
    current, old, review = _review(planner, archive_sha256)
    checked = broker_request({"action": "external_preflight",
                              "archive_sha256": archive_sha256,
                              "current_hub_manifest_sha256": current})["result"]
    require(checked["review_sha256"] == review and
            checked["external_agent_manifest_sha256"] == old,
            "backup broker review differed from root CLI")
    operations = Path("/var/lib/sovagrid/external-agent-operations")
    template = Path("/etc/systemd/system/sovagrid-external-agent-apply@.service")
    require(operations.is_dir() and not operations.is_symlink() and
            stat.S_IMODE(operations.stat().st_mode) == 0o700 and
            template.is_file() and not template.is_symlink(),
            "fixed external Agent writer was not installed")
    operation_id = str(uuid.uuid4())
    accepted = broker_request({"action": "external_apply",
                               "request_id": operation_id,
                               "archive_sha256": archive_sha256,
                               "current_hub_manifest_sha256": current,
                               "external_agent_manifest_sha256": old,
                               "review_sha256": review})["operation"]
    require(accepted["request_id"] == operation_id and
            accepted["phase"] in ("accepted", "running", "complete"),
            "backup broker did not accept exact write")
    folder = operations / operation_id
    unit = "sovagrid-external-agent-apply@" + operation_id + ".service"
    trial_pid = None
    status = None
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        status = broker_request({"action": "external_operation_status",
                                 "request_id": operation_id})["operation"]
        require(status.get("request_id") == operation_id and
                status.get("phase") in ("accepted", "running", "complete",
                                         "failed", "uncertain"),
                "fixed writer status was invalid")
        if status["phase"] == "running":
            pid_text = subprocess.run(["systemctl", "show", "-P", "MainPID", AGENT_UNIT],
                                      capture_output=True, text=True,
                                      timeout=10, check=False).stdout.strip()
            if pid_text.isdecimal() and int(pid_text) > 1 and int(pid_text) != old_pid:
                trial_pid = int(pid_text)
        if status["phase"] in ("complete", "failed", "uncertain"):
            break
        time.sleep(0.5)
    require(status is not None and status["phase"] == "complete",
            "fixed writer did not complete: " + str(status.get("error") if status else "NO_STATUS"))
    require(json.loads((folder / "status.json").read_bytes()) == status and
            command("systemctl", "show", "-P", "Result", unit) == "success",
            "fixed writer durable status or systemd unit failed")
    final_pid = _pid()
    require(trial_pid == final_pid, "Agent PID changed between trial and normal dispatch")
    final_sha, _manifest, _state = planner._external_snapshot()
    require(final_sha == current and
            Path("/var/lib/sovagrid-agent-enrollment/state.json").read_bytes() != old_state and
            Path("/var/lib/sovagrid-promotion/baseline.json").read_bytes() != old_baseline and
            Path("/var/lib/sovagrid-agent/external-sentinel").is_file(),
            "committed source/state/baseline or Agent data invalid")
    after_commit = _hub_counters()
    _wait(lambda: _hub_counters()["jobs"] > after_commit["jobs"] and
          _hub_counters()["checks"] > after_commit["checks"],
          "normal job and check dispatch", seconds=15)
    require(not Path(planner.recovery.JOURNAL).exists() and
            not Path(planner.recovery.TRIAL_DROPIN).exists() and
            not planner.TRIAL_WATCH_SOCKET.exists() and
            not planner.TRIAL_WATCH_EPOCH.exists() and
            not Path(planner.recovery.TRIAL_GATE_SOCKET).exists() and
            subprocess.run(["systemctl", "is-enabled", "--quiet",
                            planner.RECOVERY_UNIT], check=False).returncode != 0,
            "temporary trial guard or recovery dependency remained")
    print("Real systemd Agent apply passed: precommit rollback, SIGKILL boot recovery, "
          "fixed-unit same-PID ACTIVE/DETACH, normal dispatch and exact cleanup")


def main(argv: list[str]) -> None:
    os.umask(0o077)
    require(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("SOVAGRID_EXTERNAL_APPLY_VM_FIXTURE") == "1" and
            Path("/proc/1/comm").read_text().strip() == "systemd",
            "requires explicit opt-in on a disposable GitHub-hosted systemd VM")
    if len(argv) == 3 and argv[0] == "seed":
        seed(Path(argv[1]), Path(argv[2]))
    elif len(argv) == 2 and argv[0] == "run":
        run(argv[1])
    elif len(argv) == 2 and argv[0] == "kill-at-trial":
        killed_at_trial(argv[1])
    elif argv == ["serve"]:
        serve()
    else:
        raise SystemExit("usage: integrated_external_agent_apply_vm.py "
                         "seed CANDIDATE_SOURCE OLD_AGENT_SOURCE | run ARCHIVE_SHA256")


if __name__ == "__main__":
    main(sys.argv[1:])
