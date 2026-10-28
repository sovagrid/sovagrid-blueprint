#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Actual OpenSSH enforcement in an explicitly disposable, offline container.

docker build -f tests/Dockerfile.sshd --build-arg UBUNTU_VERSION=22.04 -t sg-ssh-test .
docker run --rm --init --network none sg-ssh-test

No host mounts, published ports, privileged mode or production sshd. Only
systemctl reload is replaced by SIGHUP of this fixture's real sshd. This does
not prove systemd LoadCredential/cgroups, reboot or real-network recovery.
"""
from __future__ import annotations

import contextlib
import grp
import hashlib
import http.server
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import uuid

PORT = 22222
SOURCE = Path("/opt/sovagrid-src")


class Failure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Failure(code)  # Codes are fixed source literals, never remote text.


def run(argv, *, good=True, timeout=10):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, close_fds=True)
    require(not good or result.returncode == 0, "FIXTURE_COMMAND_FAILED")
    return result


def write(path, data, mode=0o644):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    path.chmod(mode)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def sshd_ready():
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=0.5) as connection:
            connection.settimeout(0.5)
            return connection.recv(64).startswith(b"SSH-2.0-")
    except OSError:
        return False


def eventually(check, code, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check(): return
        time.sleep(0.05)
    raise Failure(code)


def keypair(path):
    run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "fixture", "-f", str(path)])
    return " ".join(Path(str(path) + ".pub").read_text().split()[:2])


def installed_helper():
    """The Hub boundary sees an exact, root-owned five-component manifest."""
    require(not SOURCE.exists() and not Path("/var/lib/sovagrid-hub-tunnels").exists(), "NONEMPTY_FIXTURE")
    real = Path("/work/deploy/remote_agent.py").read_bytes()
    path = SOURCE / "sovagrid-blueprint/deploy/remote_agent.py"
    helper = types.ModuleType("fixture_remote_agent")
    helper.__file__ = str(path)
    exec(compile(real, str(path), "exec"), helper.__dict__)
    names = ("sovagrid-blueprint", "sovagrid-agent", "sovagrid-hub", "sovagrid-web", "sovagrid-vpn")
    hashes, components = {}, {}
    for name in names:
        relative = name + ("/deploy/remote_agent.py" if name == "sovagrid-blueprint" else "/LICENSE")
        data = real if name == "sovagrid-blueprint" else b"Disposable fixture, not a product installation.\n"
        write(SOURCE / relative, data)
        hashes[relative] = hashlib.sha256(data).hexdigest()
        components[name] = {"commit": "a" * 40, "file_count": 1}
    for relative in helper.REQUIRED_SOURCE - set(hashes):
        data = b"Disposable structural fixture; never executed.\n"
        write(SOURCE / relative, data)
        hashes[relative] = hashlib.sha256(data).hexdigest()
    for name in names:
        components[name]["file_count"] = sum(relative.startswith(name + "/") for relative in hashes)
    for parent, dirs, _ in os.walk(SOURCE):
        Path(parent).chmod(0o755)
    write(SOURCE / "sovagrid-bundle.json", json.dumps({"format": 1, "components": components, "sha256": hashes}))
    write("/var/lib/sovagrid/.managed-by-run-sh", b"disposable fixture\n", 0o600)
    return helper, path


class Health(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status":"ok"}'
        self.send_response(200 if self.path == "/healthz" else 404)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def log_message(self, *_args):
        pass


class Fixture:
    def __init__(self, directory):
        self.root = directory
        self.processes = []
        self.streams = []
        self.http = None
        self.unix_http = None
        self.proofs = []

    def spawn(self, argv, label):
        stream = (self.root / (label + ".log")).open("wb")
        self.streams.append(stream)
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=stream, start_new_session=True)
        self.processes.append(process)
        return process

    def ssh(self, user, key, options=(), command=()):
        return ["/usr/bin/ssh", "-F", "/dev/null", "-i", str(key), "-p", str(PORT),
                "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes",
                "-o", "UpdateHostKeys=no", "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "UserKnownHostsFile=" + str(self.root / "known_hosts"),
                "-o", "ConnectTimeout=2", "-o", "ServerAliveInterval=1", "-o", "ServerAliveCountMax=2",
                *options, user + "@127.0.0.1", *command]

    def check_master(self, identity):
        return run(self.ssh(identity["user"], identity["key"], ("-S", str(identity["control"]), "-O", "check")), good=False).returncode == 0

    def master(self, user, key, label, *, forward=False):
        result = {"user": user, "key": key, "control": self.root / (label + ".ctl"), "label": label}
        options = ["-M", "-N", "-S", str(result["control"]), "-o", "ExitOnForwardFailure=yes"]
        if forward:
            result["port"] = free_port()
            options += ["-L", "127.0.0.1:" + str(result["port"]) + ":127.0.0.1:8767"]
        result["process"] = self.spawn(self.ssh(user, key, options), label)
        eventually(lambda: self.check_master(result), "SSH_MASTER_NOT_READY")
        if forward: eventually(lambda: self.health(result["port"]), "ALLOWED_TLS_FORWARD_FAILED")
        return result

    def health(self, port, stream=None):
        connection = stream
        try:
            connection = connection or socket.create_connection(("127.0.0.1", port), timeout=2)
            connection.settimeout(2)
            with self.context.wrap_socket(connection, server_hostname="localhost") as tls:
                tls.sendall(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
                data = bytearray()
                while len(data) <= 4096:
                    part = tls.recv(1024)
                    if not part: break
                    data.extend(part)
                return bytes(data).startswith(b"HTTP/1.0 200") and bytes(data).endswith(b'{"status":"ok"}')
        except (OSError, ssl.SSLError):
            return False
        finally:
            if connection is not None: connection.close()

    def control(self, identity, operation, kind, mapping):
        return run(self.ssh(identity["user"], identity["key"],
            ("-S", str(identity["control"]), "-O", operation, kind, mapping)), good=False)

    def log(self, identity):
        return (self.root / (identity["label"] + ".log")).read_bytes()

    def forbidden_forward(self, identity, destination):
        port = free_port(); mapping = "127.0.0.1:" + str(port) + ":" + destination
        before = len(self.log(identity))
        require(self.control(identity, "forward", "-L", mapping).returncode == 0, "LOCAL_FORWARD_NOT_CREATED")
        try:
            require(not self.health(port), "FORBIDDEN_DESTINATION_REACHED")
            # OpenSSH's direct-streamlocal refusal retains the default
            # CONNECT_FAILED / fixed "open failed" reason. A real TLS Unix
            # backend and root SSH control prove it is not a missing socket.
            reason = (b"open failed: connect failed: open failed" if destination.startswith("/")
                      else b"administratively prohibited")
            eventually(lambda: reason in self.log(identity)[before:], "DESTINATION_NOT_POLICY_DENIED")
        finally:
            self.control(identity, "cancel", "-L", mapping)

    @staticmethod
    def read_exact(connection, length):
        data = bytearray()
        while len(data) < length:
            part = connection.recv(length - len(data))
            if not part: raise OSError("closed")
            data.extend(part)
        return bytes(data)

    def socks(self, port, address, destination_port):
        connection = socket.create_connection(("127.0.0.1", port), timeout=2)
        try:
            connection.sendall(b"\x05\x01\x00")
            require(self.read_exact(connection, 2) == b"\x05\x00", "SOCKS_GREETING_FAILED")
            connection.sendall(b"\x05\x01\x00" + address + struct.pack(">H", destination_port))
            header = self.read_exact(connection, 4)
            if header[:2] != b"\x05\x00": raise OSError("denied")
            size = 4 if header[3] == 1 else 16 if header[3] == 4 else self.read_exact(connection, 1)[0]
            self.read_exact(connection, size + 2)
            return connection
        except BaseException:
            connection.close(); raise

    def setup(self):
        self.helper, executable = installed_helper()
        for suffix in ("", ".pub"):
            Path("/etc/ssh/ssh_host_ed25519_key" + suffix).unlink(missing_ok=True)
        host_public = keypair(Path("/etc/ssh/ssh_host_ed25519_key"))
        root_public = keypair(self.root / "root-key")
        write("/etc/ssh/fixture-root-keys", root_public + "\n", 0o600)
        write(self.root / "known_hosts", "[127.0.0.1]:" + str(PORT) + " " + host_public + "\n", 0o600)
        Path("/run/sshd").mkdir(exist_ok=True); Path("/run/sshd").chmod(0o755)
        Path("/var/empty").mkdir(exist_ok=True); Path("/var/empty").chmod(0o755)
        Path("/run/nologin").unlink(missing_ok=True)
        run(["/usr/sbin/usermod", "--password", "*NP*", "--expiredate", "", "root"])
        write("/etc/ssh/fixture-nested.conf", "Match User never-fixture\n PermitOpen 127.0.0.1:8767\nMatch all\n")
        # Do not inherit the image's incidental distro fragments.
        for item in Path("/etc/ssh/sshd_config.d").glob("*.conf"): item.unlink()
        write("/etc/ssh/sshd_config", f"""Port {PORT}
ListenAddress 127.0.0.1
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile {self.root}/sshd.pid
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
AuthorizedKeysFile /etc/ssh/fixture-root-keys
PrintMotd no
PrintLastLog no
LogLevel VERBOSE
Subsystem sftp internal-sftp
Include /etc/ssh/sshd_config.d/*.conf
Include /etc/ssh/fixture-nested.conf
""")
        certificate, private = self.root / "ca.pem", self.root / "ca.key"
        run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:TRUE",
             "-keyout", str(private), "-out", str(certificate)])
        private.chmod(0o600); write("/etc/sovagrid/hub-ca.pem", certificate.read_bytes())
        self.context = ssl.create_default_context(cafile=str(certificate))
        self.http = http.server.ThreadingHTTPServer(("127.0.0.1", 8767), Health)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server_context.load_cert_chain(certificate, private)
        self.http.socket = server_context.wrap_socket(self.http.socket, server_side=True)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        unix_path = "/tmp/sovagrid-fixture-backend.sock"
        require(not Path(unix_path).exists(), "UNIX_FIXTURE_PATH_ALREADY_EXISTS")
        self.unix_http = socketserver.ThreadingUnixStreamServer(unix_path, Health)
        Path(unix_path).chmod(0o666)  # Only this offline disposable container.
        self.unix_http.socket = server_context.wrap_socket(self.unix_http.socket, server_side=True)
        threading.Thread(target=self.unix_http.serve_forever, daemon=True).start()
        run(["/usr/sbin/sshd", "-t"])
        self.sshd = self.spawn(["/usr/sbin/sshd", "-D", "-e"], "sshd")
        eventually(sshd_ready, "FIXTURE_SSHD_NOT_READY")
        fixture = self
        class Commands(self.helper.Commands):
            def run(self, argv, **options):
                if argv == ["/usr/bin/systemctl", "reload", "ssh.service"]:
                    require(fixture.sshd.poll() is None, "FIXTURE_SSHD_EXITED")
                    fixture.sshd.send_signal(signal.SIGHUP)
                    time.sleep(0.1); eventually(sshd_ready, "FIXTURE_SSHD_RELOAD_FAILED")
                    require(fixture.sshd.poll() is None, "FIXTURE_SSHD_RELOAD_FAILED")
                    return 0, b""
                result = super().run(argv, **options)
                if argv[0] == "/usr/sbin/useradd":
                    # The real distro useradd must accept the full operation
                    # nonce and keep a non-login, initially expired account.
                    account = pwd.getpwnam(argv[-1])
                    group = grp.getgrnam(fixture.helper.HUB_GROUP)
                    require(account.pw_uid > 0 and account.pw_gid == group.gr_gid
                            and set(os.getgrouplist(account.pw_name, account.pw_gid)) == {group.gr_gid}
                            and account.pw_dir == "/var/empty/" + account.pw_name
                            and account.pw_shell == "/usr/sbin/nologin"
                            and account.pw_gecos == argv[argv.index("--comment") + 1]
                            and ":" not in account.pw_gecos, "CREATED_ACCOUNT_POLICY_WRONG")
                    shadow = fixture.enrollment.files.read("/etc/shadow").decode("ascii")
                    fields = next(line.split(":") for line in shadow.splitlines()
                                  if line.startswith(account.pw_name + ":"))
                    require(len(fields) == 9 and fields[1] == "*NP*" and fields[7] == "1",
                            "CREATED_ACCOUNT_SHADOW_WRONG")
                return result
        self.enrollment = self.helper.Enrollment(executable=str(executable), commands=Commands())
        self.root_session = self.master("root", self.root / "root-key", "root")

    def call(self, action, **data):
        return self.enrollment.dispatch(action, {"protocol": 1, **data})

    def authorize(self, enrollment_id, server_id, public):
        return self.call("hub-authorize", enrollment_id=enrollment_id, server_id=server_id,
            expected=self.enrollment.cas("hub"), ssh_public_key=public,
            ssh_key_fingerprint=self.helper.public_key(public)[1])

    def revoke(self, record):
        return self.call("hub-revoke", **{key: record[key] for key in ("enrollment_id", "server_id", "ssh_key_fingerprint")},
                         expected=self.enrollment.cas("hub"))

    def exercise(self):
        root_policy = self.enrollment.effective("root")
        preview = self.call("hub-preview")
        require(preview["helper_v1"] and preview["hub_ca_pem"], "HUB_PREVIEW_FAILED")
        identities = [(str(uuid.uuid4()), str(uuid.uuid4()), self.root / name) for name in ("agent-a", "agent-b")]
        public_a, public_b = (keypair(item[2]) for item in identities)
        nested = Path("/etc/ssh/fixture-nested.conf"); original = nested.read_bytes()
        nested.write_bytes(original.replace(b":8767", b":8768"))
        require(self.enrollment.cas("hub") != preview["cas"], "NESTED_POLICY_NOT_IN_CAS")
        try:
            self.call("hub-authorize", enrollment_id=identities[0][0], server_id=identities[0][1],
                expected=preview["cas"], ssh_public_key=public_a, ssh_key_fingerprint=self.helper.public_key(public_a)[1])
        except self.helper.Refuse as error:
            require(error.code == "STALE_PREVIEW", "WRONG_STALE_POLICY_ERROR")
        else: raise Failure("STALE_POLICY_WAS_ACCEPTED")
        nested.write_bytes(original)
        for criterion in ("LocalPort " + str(PORT), "Address 192.0.2.0/24", "LocalAddress 127.0.0.1", "Host fixture.example"):
            # The helper's -T -C sample uses port22/loopback. A preceding
            # context-dependent Match must not grant a different policy at the
            # real endpoint or Agent address that this sample did not test.
            shadow = Path("/etc/ssh/sshd_config.d/00-fixture-shadow.conf")
            write(shadow, "Match Group sovagrid-tunnel " + criterion + "\n AllowTcpForwarding yes\n PermitListen any\nMatch all\n")
            try:
                try:
                    self.authorize(*identities[0][:2], public_a)
                except self.helper.Refuse as error:
                    require(error.code == "SSH_POLICY_CONFLICT", "WRONG_CONDITIONAL_POLICY_ERROR")
                else: raise Failure("CONDITIONAL_SHADOW_POLICY_ACCEPTED")
            finally: shadow.unlink()
        try:
            pwd.getpwnam(self.helper.username(identities[0][1]))
        except KeyError:
            pass
        else: raise Failure("REJECTED_PREFLIGHT_CREATED_ACCOUNT")
        a = self.authorize(*identities[0][:2], public_a)
        repeated = self.authorize(*identities[0][:2], public_a)
        require(a["username"] == repeated["username"], "REPEATED_AUTHORIZE_CHANGED_IDENTITY")
        b = self.authorize(*identities[1][:2], public_b)
        first = self.master(a["username"], identities[0][2], "agent-a", forward=True)
        second = self.master(b["username"], identities[1][2], "agent-b", forward=True)
        require(self.call("hub-status", enrollment_id=a["enrollment_id"], server_id=a["server_id"])["authorized"], "STATUS_NOT_AUTHORIZED")
        self.proofs += ["verified_tls_local_forward", "authorize_repeat_and_status", "nested_include_cas", "conditional_shadow_policy_refused",
                        "real_useradd_nonce_nonlogin_shadow_and_primary_group"]
        require(self.enrollment.effective(a["username"])["maxsessions"] == "0", "EFFECTIVE_MAXSESSIONS_NOT_ZERO")
        for options, command in (((), ("true",)), (("-tt",), ("true",)), (("-s",), ("sftp",))):
            denied = run(self.ssh(a["username"], identities[0][2], options, command), good=False)
            channel_denied = (b"open failed: administratively prohibited:" in denied.stderr
                              or b"open failed: connect failed: open failed" in denied.stderr)
            require(denied.returncode != 0 and channel_denied, "SESSION_NOT_POLICY_DENIED")
            require(self.check_master(first) and self.health(first["port"]), "SESSION_DENIAL_LOST_AUTHENTICATED_FORWARD")
        root_unix_port = free_port()
        root_unix_mapping = "127.0.0.1:" + str(root_unix_port) + ":/tmp/sovagrid-fixture-backend.sock"
        require(self.control(self.root_session, "forward", "-L", root_unix_mapping).returncode == 0,
                "ROOT_UNIX_CONTROL_NOT_CREATED")
        try:
            eventually(lambda: self.health(root_unix_port), "ROOT_UNIX_TLS_BACKEND_NOT_REACHABLE")
        finally:
            self.control(self.root_session, "cancel", "-L", root_unix_mapping)
        for destination in ("127.0.0.1:8768", "127.0.0.2:8767", "localhost:8767", "[::1]:8767", "/tmp/sovagrid-fixture-backend.sock"):
            self.forbidden_forward(first, destination)
        for mapping in ("127.0.0.1:" + str(free_port()) + ":127.0.0.1:8767",
                        "/tmp/sovagrid-fixture-" + uuid.uuid4().hex + ".sock:127.0.0.1:8767"):
            require(self.control(first, "forward", "-R", mapping).returncode != 0, "REMOTE_FORWARD_ALLOWED")
        self.proofs += ["exec_pty_sftp_denied", "remote_tcp_and_unix_forward_denied", "forbidden_tcp_and_unix_destinations_denied",
                        "root_reaches_real_unix_tls_backend"]
        socks_port = free_port(); mapping = "127.0.0.1:" + str(socks_port)
        require(self.control(first, "forward", "-D", mapping).returncode == 0, "SOCKS_LOCAL_BIND_FAILED")
        try:
            stream = self.socks(socks_port, b"\x01\x7f\x00\x00\x01", 8767)
            require(self.health(0, stream), "SOCKS_PERMITTED_TUPLE_FAILED")
            before = len(self.log(first))
            try:
                stream = self.socks(socks_port, b"\x01\x7f\x00\x00\x01", 8768)
                require(not self.health(0, stream), "SOCKS_FORBIDDEN_DESTINATION_REACHED")
            except OSError:
                pass
            eventually(lambda: b"administratively prohibited" in self.log(first)[before:], "SOCKS_NOT_POLICY_DENIED")
        finally: self.control(first, "cancel", "-D", mapping)
        self.proofs += ["socks_allowed_tuple_works", "socks_forbidden_destination_denied"]
        keypath = Path("/etc/ssh/sovagrid-tunnels") / a["username"]; public_line = keypath.read_bytes()
        keypath.unlink()
        require(self.health(first["port"]), "KEY_REMOVAL_UNEXPECTEDLY_CLOSED_LIVE_CHANNEL")
        write(keypath, public_line)
        require(self.revoke(a)["revoked"], "REVOKE_FAILED")
        eventually(lambda: first["process"].poll() is not None, "REVOKED_LIVE_SESSION_SURVIVED")
        require(not self.health(first["port"]), "REVOKED_FORWARD_SURVIVED")
        require(self.check_master(second) and self.health(second["port"]) and self.check_master(self.root_session), "UNRELATED_SESSION_LOST")
        require(run(self.ssh("root", self.root / "root-key", ("-S", str(self.root_session["control"])), ("true",))).returncode == 0, "ROOT_EXEC_LOST")
        require(self.revoke(a)["revoked"], "REPEAT_REVOKE_FAILED")
        require(not self.call("hub-status", enrollment_id=a["enrollment_id"], server_id=a["server_id"])["authorized"], "REVOKED_STATUS_WRONG")
        try:
            self.authorize(*identities[0][:2], public_a)
        except self.helper.Refuse as error:
            require(error.code == "STATE_CONFLICT", "WRONG_REVOKED_AUTHORIZE_ERROR")
        else: raise Failure("REVOKED_ENROLLMENT_RESURRECTED")
        require(self.enrollment.effective("root") == root_policy, "ROOT_POLICY_CHANGED")
        policy = self.enrollment.policy_snapshot("hub")
        require(policy[self.helper.POLICY_PATH] == self.helper.digest(self.helper.POLICY)
                and "/etc/ssh/fixture-nested.conf" in policy, "POLICY_HASHES_MISSING")
        self.proofs += ["key_removal_alone_does_not_revoke_live_channel", "revoke_reaps_only_own_uid", "revoke_repeat_and_status", "root_policy_unchanged"]
        require(self.revoke(b)["revoked"], "SECOND_FIXTURE_CLEANUP_FAILED")

    def close(self):
        if self.http is not None: self.http.shutdown(); self.http.server_close()
        if self.unix_http is not None: self.unix_http.shutdown(); self.unix_http.server_close()
        for process in reversed(self.processes):
            if process.poll() is None:
                with contextlib.suppress(ProcessLookupError): os.killpg(process.pid, signal.SIGTERM)
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError): os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)
        for stream in self.streams: stream.close()


def main():
    require(os.geteuid() == 0 and Path("/.dockerenv").is_file()
            and os.environ.get("SOVAGRID_DISPOSABLE_SSH_FIXTURE") == "1"
            and {p.name for p in Path("/sys/class/net").iterdir()} == {"lo"}, "DISPOSABLE_OFFLINE_CONTAINER_REQUIRED")
    os.umask(0o077)
    # Exercise the same boundary regression suite on the distribution's own
    # Python (3.10 on22.04), before the actual OpenSSH enforcement proof.
    regression = subprocess.run(["/usr/bin/python3", "-I", "-m", "unittest", "discover", "-s", "/work/tests",
                                 "-p", "test_remote_agent.py", "-v"], timeout=60)
    require(regression.returncode == 0, "DISTRIBUTION_REGRESSION_FAILED")
    feature_env = os.environ.copy()
    feature_env["SOVAGRID_DISPOSABLE_FEATURE_FIXTURE"] = "1"
    feature_regression = subprocess.run(["/usr/bin/python3", "-I", "-B", "-m", "unittest", "discover", "-s", "/work/tests",
                                         "-p", "test_agent_features.py", "-v"], timeout=90, env=feature_env)
    require(feature_regression.returncode == 0, "FEATURE_UID_REGRESSION_FAILED")
    with tempfile.TemporaryDirectory(prefix="sg-sshd-", dir="/run") as directory:
        fixture = Fixture(Path(directory))
        try:
            fixture.setup(); fixture.exercise()
            print(json.dumps({"ok": True, "proofs": fixture.proofs, "systemd_runtime_tested": False}))
        finally: fixture.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Keep source/helper exceptions and private fixture paths/material out
        # of CI logs. A fixed step code is enough to locate a failing assertion.
        code = str(error) if isinstance(error, Failure) else type(error).__name__
        helper_code = getattr(error, "code", None)
        if helper_code in {"INVALID_REQUEST", "SOURCE_UNTRUSTED", "SOURCE_CHANGED", "STALE_PREVIEW",
                           "OWNERSHIP_CONFLICT", "STATE_CONFLICT", "SSH_POLICY_CONFLICT",
                           "SSH_RELOAD_FAILED", "SERVICE_FAILED", "CLEANUP_REQUIRED", "KEY_CONFLICT"}:
            code = "HELPER_" + helper_code
        print(json.dumps({"ok": False, "error": code})); sys.exit(1)
