# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Headless SSH transport tests use only private local Unix sockets."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vendor/connect"))
sys.path.insert(0, str(ROOT / "deploy"))

from web_agent_target_ssh import (AskpassBroker, HostKeyChanged, PinnedTargetSSH, TargetSSHError,
                                  MAX_SCAN, _jump_proxy_client, _probe_jumped_target_host_key,
                                  _read_bounded_probe_diagnostic,
                                  host_key_alias, reviewed_key_blob,
                                  reviewed_public_key)


def fixture_key(seed=0):
    key = b"ssh-ed25519"
    raw = struct.pack(">I", len(key)) + key + struct.pack(">I", 32) + bytes(
        (value + seed) % 256 for value in range(32))
    blob = base64.b64encode(raw).decode("ascii")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return blob, fingerprint


def challenge(path: Path, nonce: str, prompt: str) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(str(path))
        client.sendall(json.dumps({"nonce": nonce, "prompt": prompt}).encode() + b"\n")
        result = bytearray()
        while True:
            part = client.recv(2048)
            if not part:
                return bytes(result)
            result.extend(part)


class ReviewedKeyTests(unittest.TestCase):
    def test_only_exact_reviewed_wire_key_is_accepted(self):
        blob, fingerprint = fixture_key()
        line = f"server.example ssh-ed25519 {blob}\n".encode()
        self.assertEqual(reviewed_public_key(b"# banner\n" + line, fingerprint), ("ssh-ed25519", blob))
        with self.assertRaises(TargetSSHError):
            reviewed_public_key(line, "SHA256:" + "A" * 43)
        with self.assertRaises(TargetSSHError):
            reviewed_public_key(line.replace(b"ssh-ed25519 ", b"ssh-rsa ", 1), fingerprint)
        self.assertEqual(reviewed_public_key(line + f"other ssh-rsa {blob}\n".encode(), fingerprint),
                         ("ssh-ed25519", blob))

    def test_oversized_and_malformed_scan_is_rejected(self):
        _, fingerprint = fixture_key()
        with self.assertRaises(TargetSSHError):
            reviewed_public_key(b"x" * 32769, fingerprint)
        with self.assertRaises(TargetSSHError):
            reviewed_public_key(b"not a key\n", fingerprint)

    def test_only_live_valid_mismatch_is_host_key_changed(self):
        reviewed_blob, reviewed_fp = fixture_key()
        changed_blob, _ = fixture_key(1)
        with self.assertRaises(HostKeyChanged):
            reviewed_public_key(f"server.example ssh-ed25519 {changed_blob}\n".encode(), reviewed_fp)
        for scan in (b"", b"not a key\n", b"server.example ssh-rsa " +
                     reviewed_blob.encode() + b"\n"):
            with self.subTest(scan=scan), self.assertRaises(TargetSSHError) as error:
                reviewed_public_key(scan, reviewed_fp)
            self.assertNotIsInstance(error.exception, HostKeyChanged)

    def test_host_key_alias_binds_the_reviewed_fingerprint(self):
        _, fingerprint = fixture_key()
        alias = host_key_alias(fingerprint)
        self.assertRegex(alias, r"^sg-[a-z2-7]{52}$")
        self.assertNotEqual(alias, host_key_alias("SHA256:" + "A" * 43))
        with self.assertRaises(TargetSSHError):
            host_key_alias("SHA256:" + "A" * 42)

    def test_reviewed_blob_requires_canonical_wire_key_and_exact_fingerprint(self):
        blob, fingerprint = fixture_key()
        self.assertEqual(reviewed_key_blob(blob, fingerprint), ("ssh-ed25519", blob))
        with self.assertRaises(TargetSSHError):
            reviewed_key_blob(blob, fixture_key(1)[1])
        with self.assertRaises(TargetSSHError):
            reviewed_key_blob(blob + "=", fingerprint)
        with self.assertRaises(TargetSSHError):
            reviewed_key_blob(base64.b64encode(b"wrong").decode(), fingerprint)


class AskpassTests(unittest.TestCase):
    def test_one_password_answer_per_ssh_child_and_no_otp_answer(self):
        with tempfile.TemporaryDirectory() as directory:
            broker = AskpassBroker(Path(directory) / "broker.sock", "password", "private-test-password",
                                   peer_uid=lambda _connection: os.geteuid())
            try:
                self.assertEqual(stat.S_IMODE(broker.path.stat().st_mode), 0o600)
                nonce = broker.arm()
                self.assertEqual(challenge(broker.path, nonce, "root@host's password:"),
                                 b"OK\nprivate-test-password\n")
                self.assertEqual(challenge(broker.path, nonce, "Password:"), b"DENY\n")
                nonce = broker.arm()
                self.assertEqual(challenge(broker.path, nonce, "Verification code / OTP:"), b"DENY\n")
                self.assertEqual(challenge(broker.path, nonce, "Password:"), b"DENY\n")
                nonce = broker.arm()
                self.assertEqual(challenge(broker.path, nonce, "Пароль:"), b"OK\nprivate-test-password\n")
            finally:
                broker.close()
            self.assertFalse(broker.path.exists())
            self.assertEqual(bytes(broker._secret), b"\0" * len("private-test-password"))

    def test_key_passphrase_and_wrong_local_peer(self):
        with tempfile.TemporaryDirectory() as directory:
            broker = AskpassBroker(Path(directory) / "broker.sock", "private_key", "phrase",
                                   peer_uid=lambda _connection: os.geteuid() + 1)
            try:
                nonce = broker.arm()
                self.assertEqual(challenge(broker.path, nonce, "Enter passphrase for key '/tmp/id':"), b"")
            finally:
                broker.close()
            broker = AskpassBroker(Path(directory) / "broker.sock", "private_key", "phrase",
                                   peer_uid=lambda _connection: os.geteuid())
            try:
                nonce = broker.arm()
                self.assertEqual(challenge(broker.path, nonce, "Enter passphrase for key '/tmp/id':"),
                                 b"OK\nphrase\n")
                nonce = broker.arm()
                self.assertEqual(challenge(broker.path, nonce, "Password:"), b"DENY\n")
            finally:
                broker.close()


class TransportTests(unittest.TestCase):
    def scanner(self, _host, _port):
        blob, _ = fixture_key()
        return f"example.invalid ssh-ed25519 {blob}\n".encode()

    @mock.patch("web_agent_target_ssh._probe_jumped_target_host_key",
                side_effect=AssertionError("direct SSH used the jump probe"))
    def test_private_key_and_strict_host_pin_live_only_in_private_runtime_directory(self, _probe):
        _blob, fingerprint = fixture_key()
        with tempfile.TemporaryDirectory() as directory:
            transport = PinnedTargetSSH(host="example.invalid", port=2222, username="root",
                fingerprint=fingerprint, method="private_key",
                private_key="-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----\n",
                passphrase="phrase", runtime_root=Path(directory), require_root=False,
                scanner=self.scanner, peer_uid=lambda _connection: os.geteuid(), python=sys.executable)
            with transport:
                folder = transport.config_path.parent
                self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)
                identity = Path(transport.options.identity)
                self.assertEqual(stat.S_IMODE(identity.stat().st_mode), 0o600)
                self.assertIn("StrictHostKeyChecking yes", transport.config_path.read_text())
                self.assertIn("GlobalKnownHostsFile /dev/null", transport.config_path.read_text())
                self.assertIn(f"HostKeyAlias {transport.alias}", transport.config_path.read_text())
                self.assertTrue((folder / "known_hosts").read_text().startswith(
                    f"{transport.alias} ssh-ed25519 "))
                self.assertNotIn("phrase", transport.config_path.read_text())
                self.assertNotIn("phrase", transport.launcher_path.read_text())
                effective = subprocess.run(["/usr/bin/ssh", "-F", str(transport.config_path),
                    "-G", "sovagrid-target"], capture_output=True, text=True, timeout=5, check=True).stdout
                self.assertIn(f"hostkeyalias {transport.alias}", effective)
                self.assertIn(f"userknownhostsfile {folder / 'known_hosts'}", effective)
                self.assertIn("stricthostkeychecking true", effective)
                self.assertIn("globalknownhostsfile /dev/null", effective)
                rpc = transport.target_rpc(transport.options)
                self.assertEqual(rpc.role, "target")
                self.assertEqual(rpc._installer.transport, transport)
                with self.assertRaises(TargetSSHError):
                    transport.target_rpc(rpc.options.__class__(host="elsewhere.invalid", user="root"))
            self.assertFalse(folder.exists())
            self.assertIsNone(transport.config_path)

    def test_password_is_not_in_argv_environment_or_files(self):
        _blob, fingerprint = fixture_key()
        with tempfile.TemporaryDirectory() as directory:
            with PinnedTargetSSH(host="example.invalid", port=22, username="ubuntu",
                    fingerprint=fingerprint, method="password", password="private-test-password",
                    runtime_root=Path(directory), require_root=False, scanner=self.scanner,
                    peer_uid=lambda _connection: os.geteuid(), python=sys.executable) as transport:
                args = []
                class Child:
                    def poll(self): return 0
                def spawn(argv, **kwargs):
                    args.append((argv, kwargs))
                    return Child()
                rpc = transport.target_rpc(transport.options)
                rpc._installer._popen = spawn
                with rpc._installer._session() as (config, helper):
                    rpc._installer._ssh(config, helper, "true")
                argv, kwargs = args[0]
                self.assertNotIn("private-test-password", repr(argv))
                self.assertNotIn("private-test-password", repr(kwargs["env"]))
                self.assertEqual(argv[0], "/usr/bin/ssh")
                self.assertIn("SOVAGRID_WEB_AGENT_ASKPASS_NONCE", kwargs["env"])
                for item in transport.config_path.parent.iterdir():
                    if item.is_file():
                        self.assertNotIn("private-test-password", item.read_text())

    def test_root_and_credential_shape_fail_closed(self):
        _blob, fingerprint = fixture_key()
        with mock.patch("web_agent_target_ssh.os.geteuid", return_value=1000):
            with self.assertRaises(TargetSSHError):
                PinnedTargetSSH(host="example.invalid", port=22, username="root",
                    fingerprint=fingerprint, method="password", password="pw")
        with self.assertRaises(TargetSSHError):
            PinnedTargetSSH(host="example.invalid", port=22, username="root",
                fingerprint=fingerprint, method="password", password="pw", private_key="KEY",
                require_root=False)

    @mock.patch("web_agent_target_ssh._probe_jumped_target_host_key")
    def test_jump_uses_two_pins_and_two_independent_secret_brokers(self, probe):
        target_blob, target_fp = fixture_key()
        jump_blob, jump_fp = fixture_key(7)
        jump = {"host": "jump.example", "port": 2201, "username": "relay",
                "fingerprint": jump_fp, "method": "password", "password": "jump-secret",
                "private_key": "", "passphrase": "", "host_key_blob": jump_blob}
        def scanner(host, _port):
            self.assertEqual(host, "jump.example")
            return f"jump.example ssh-ed25519 {jump_blob}\n".encode()
        with tempfile.TemporaryDirectory() as directory:
            with PinnedTargetSSH(host="target.example", port=2222, username="root",
                    fingerprint=target_fp, method="password", password="target-secret",
                    jump=jump, target_host_key_blob=target_blob,
                    runtime_root=Path(directory), require_root=False, scanner=scanner,
                    peer_uid=lambda _connection: os.geteuid(), python=sys.executable) as transport:
                self.assertEqual(transport.options.jump_host, "jump.example")
                probe.assert_called_once_with(transport.config_path, transport.jump_broker,
                                              target_fp)
                self.assertEqual(transport.options.jump_host_key_alias, host_key_alias(jump_fp))
                folder = transport.config_path.parent
                self.assertEqual((folder / "known_hosts").read_text(),
                    f"{host_key_alias(target_fp)} ssh-ed25519 {target_blob}\n")
                self.assertEqual((folder / "known_hosts_jump").read_text(),
                    f"{host_key_alias(jump_fp)} ssh-ed25519 {jump_blob}\n")
                target_config = subprocess.run(["/usr/bin/ssh", "-F", str(transport.config_path),
                    "-G", "sovagrid-target"], capture_output=True, text=True, timeout=5, check=True).stdout
                jump_config = subprocess.run(["/usr/bin/ssh", "-F", str(transport.jump_config_path),
                    "-G", "sovagrid-target"], capture_output=True, text=True, timeout=5, check=True).stdout
                self.assertIn("proxycommand " + str(transport.jump_proxy_path), target_config)
                self.assertIn(f"hostkeyalias {host_key_alias(target_fp)}", target_config)
                self.assertIn(f"hostkeyalias {host_key_alias(jump_fp)}", jump_config)
                self.assertIn("known_hosts_jump", jump_config)
                self.assertNotIn("target-secret", repr([p.read_text() for p in folder.iterdir()
                    if p.is_file()]))
                self.assertNotIn("jump-secret", repr([p.read_text() for p in folder.iterdir()
                    if p.is_file()]))
                rpc = transport.target_rpc(transport.options)
                calls = []
                class Child:
                    def poll(self): return 0
                def spawn(argv, **kwargs):
                    calls.append((argv, kwargs)); return Child()
                rpc._installer._popen = spawn
                with rpc._installer._session() as (config, helper):
                    rpc._installer._ssh(config, helper, "true")
                argv, kwargs = calls[0]
                self.assertNotIn("target-secret", repr(argv) + repr(kwargs["env"]))
                self.assertNotIn("jump-secret", repr(argv) + repr(kwargs["env"]))
                env = kwargs["env"]
                self.assertEqual(challenge(transport.broker.path,
                    env["SOVAGRID_WEB_AGENT_ASKPASS_NONCE"], "Password:"),
                    b"OK\ntarget-secret\n")
                self.assertEqual(challenge(transport.jump_broker.path,
                    env["SOVAGRID_WEB_AGENT_JUMP_ASKPASS_NONCE"], "Password:"),
                    b"OK\njump-secret\n")
                self.assertEqual(challenge(transport.broker.path,
                    env["SOVAGRID_WEB_AGENT_JUMP_ASKPASS_NONCE"], "Password:"), b"DENY\n")
                captured = []
                class Replaced(BaseException): pass
                def fake_exec(path, args, child_env):
                    captured.append((path, args, child_env)); raise Replaced()
                with mock.patch.dict(os.environ, env, clear=True), \
                     mock.patch("web_agent_target_ssh.os.execve", side_effect=fake_exec):
                    with self.assertRaises(Replaced):
                        _jump_proxy_client(str(folder))
                _, proxy_argv, proxy_env = captured[0]
                self.assertEqual(proxy_argv[-2:], ["target.example:2222", "sovagrid-target"])
                self.assertEqual(proxy_env["SOVAGRID_WEB_AGENT_ASKPASS_SOCKET"],
                                 str(transport.jump_broker.path))
                self.assertNotIn("SOVAGRID_WEB_AGENT_JUMP_ASKPASS_NONCE", proxy_env)

    def test_jump_changed_key_and_malformed_blob_fail_before_authentication(self):
        target_blob, target_fp = fixture_key()
        jump_blob, jump_fp = fixture_key(7)
        jump = {"host": "jump.example", "port": 22, "username": "relay",
                "fingerprint": jump_fp, "method": "password", "password": "jump-secret",
                "private_key": "", "passphrase": "", "host_key_blob": jump_blob}
        with self.assertRaises(TargetSSHError):
            PinnedTargetSSH(host="target.example", port=22, username="root",
                fingerprint=target_fp, method="password", password="target-secret",
                jump=jump, target_host_key_blob=jump_blob, require_root=False)
        with tempfile.TemporaryDirectory() as directory:
            wrong = f"jump.example ssh-ed25519 {target_blob}\n".encode()
            with self.assertRaises(HostKeyChanged):
                with PinnedTargetSSH(host="target.example", port=22, username="root",
                    fingerprint=target_fp, method="password", password="target-secret",
                    jump=jump, target_host_key_blob=target_blob,
                    runtime_root=Path(directory), require_root=False,
                    scanner=lambda _host, _port: wrong):
                    self.fail("changed jump key was accepted")

    def test_changed_live_target_key_closes_transport_before_rpc(self):
        target_blob, target_fp = fixture_key()
        jump_blob, jump_fp = fixture_key(7)
        jump = {"host": "jump.example", "port": 22, "username": "relay",
                "fingerprint": jump_fp, "method": "password", "password": "jump-secret",
                "private_key": "", "passphrase": "", "host_key_blob": jump_blob}
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch("web_agent_target_ssh._probe_jumped_target_host_key",
                            side_effect=HostKeyChanged("changed")) as probe:
                with self.assertRaises(HostKeyChanged):
                    with PinnedTargetSSH(host="target.example", port=22, username="root",
                            fingerprint=target_fp, method="password", password="target-secret",
                            jump=jump, target_host_key_blob=target_blob,
                            runtime_root=Path(directory), require_root=False,
                            scanner=lambda _host, _port: (
                                f"jump.example ssh-ed25519 {jump_blob}\n".encode()),
                            peer_uid=lambda _connection: os.geteuid(), python=sys.executable):
                        self.fail("changed target key reached an Agent action")
                probe.assert_called_once()
            self.assertEqual(list(Path(directory).iterdir()), [])

    @mock.patch("web_agent_target_ssh._probe_jumped_target_host_key")
    def test_jump_private_key_isolated_from_target_password(self, probe):
        target_blob, target_fp = fixture_key()
        jump_blob, jump_fp = fixture_key(9)
        jump = {"host": "relay.example", "port": 22, "username": "relay",
                "fingerprint": jump_fp, "method": "private_key", "password": "",
                "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----\n",
                "passphrase": "relay-phrase", "host_key_blob": jump_blob}
        with tempfile.TemporaryDirectory() as directory:
            with PinnedTargetSSH(host="target.example", port=22, username="root",
                    fingerprint=target_fp, method="password", password="target-secret",
                    jump=jump, target_host_key_blob=target_blob,
                    runtime_root=Path(directory), require_root=False,
                    scanner=lambda _host, _port: f"relay.example ssh-ed25519 {jump_blob}\n".encode(),
                    peer_uid=lambda _connection: os.geteuid(), python=sys.executable) as transport:
                identity = Path(transport.options.jump_identity)
                self.assertEqual(stat.S_IMODE(identity.stat().st_mode), 0o600)
                self.assertIn("fixture", identity.read_text())
                self.assertIsNone(transport.options.identity)
                target_config = subprocess.run(["/usr/bin/ssh", "-F", str(transport.config_path),
                    "-G", "sovagrid-target"], capture_output=True, text=True, timeout=5, check=True).stdout
                jump_config = subprocess.run(["/usr/bin/ssh", "-F", str(transport.jump_config_path),
                    "-G", "sovagrid-target"], capture_output=True, text=True, timeout=5, check=True).stdout
                self.assertIn("pubkeyauthentication false", target_config)
                self.assertIn("passwordauthentication no", jump_config)
                self.assertIn("kbdinteractiveauthentication no", jump_config)
                self.assertIn(f"identityfile {identity}", jump_config)
                nonce = transport.jump_broker.arm()
                self.assertEqual(challenge(transport.jump_broker.path, nonce,
                    "Enter passphrase for key '/run/id':"), b"OK\nrelay-phrase\n")
                probe.assert_called_once_with(transport.config_path, transport.jump_broker,
                                              target_fp)


class JumpedTargetProbeTests(unittest.TestCase):
    def setUp(self):
        self.fingerprint = fixture_key()[1]
        self.jump_broker = mock.Mock(path=Path("/run/private/jump.sock"))
        self.jump_broker.arm.return_value = "a" * 32

    def diagnostic(self, fingerprint, *, status):
        key_line = f"debug1: Server host key: ssh-ed25519 {fingerprint}\n".encode()
        return key_line + status

    def run_probe(self, diagnostic):
        child = mock.Mock()
        with mock.patch("web_agent_target_ssh.subprocess.Popen",
                        return_value=child) as runner, \
             mock.patch("web_agent_target_ssh._read_bounded_probe_diagnostic",
                        return_value=diagnostic):
            _probe_jumped_target_host_key(Path("/run/private/ssh_config"),
                                          self.jump_broker, self.fingerprint)
        return runner.call_args

    def test_unchanged_target_is_proven_without_target_auth_or_command(self):
        alias = host_key_alias(self.fingerprint)
        diagnostic = self.diagnostic(self.fingerprint, status=(
            f"debug1: Host '{alias}' is known and matches the ED25519 host key.\n".encode()
        )).replace(b"\n", b"\r\n")
        args, kwargs = self.run_probe(diagnostic)
        argv = args[0]
        self.assertIn("-N", argv)
        self.assertIn("-T", argv)
        self.assertNotIn("-W", argv)
        self.assertEqual(argv[-1], "sovagrid-target")
        self.assertIn("PreferredAuthentications=none", argv)
        self.assertIn("PubkeyAuthentication=no", argv)
        self.assertIn("PasswordAuthentication=no", argv)
        self.assertTrue(kwargs["start_new_session"])
        self.assertEqual(kwargs["env"]["SOVAGRID_WEB_AGENT_JUMP_ASKPASS_NONCE"], "a" * 32)
        self.assertEqual(kwargs["env"]["SOVAGRID_WEB_AGENT_TARGET_PROBE"], "1")
        self.assertNotIn("SOVAGRID_WEB_AGENT_ASKPASS_NONCE", kwargs["env"])
        self.jump_broker.disarm.assert_called_once()

    def test_changed_target_requires_live_openssh_mismatch_diagnostic(self):
        changed = fixture_key(1)[1]
        diagnostic = self.diagnostic(changed, status=(
            b"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            b"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n")).replace(b"\n", b"\r\n")
        child = mock.Mock()
        with mock.patch("web_agent_target_ssh.subprocess.Popen", return_value=child), \
             mock.patch("web_agent_target_ssh._read_bounded_probe_diagnostic",
                        return_value=diagnostic):
            with self.assertRaises(HostKeyChanged):
                _probe_jumped_target_host_key(Path("/run/private/ssh_config"),
                                              self.jump_broker, self.fingerprint)
        self.jump_broker.disarm.assert_called_once()

    def test_no_route_and_ambiguous_diagnostics_are_generic(self):
        changed = fixture_key(1)[1]
        alias = host_key_alias(self.fingerprint)
        cases = (
            b"ssh: connect to host target.example port 22: No route to host\n",
            self.diagnostic(changed, status=b"Host key verification failed.\n"),
            self.diagnostic(self.fingerprint, status=b"Permission denied.\n"),
            self.diagnostic(changed, status=b"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n")
            + self.diagnostic(self.fingerprint, status=(
                f"debug1: Host '{alias}' is known and matches the ED25519 host key.\n".encode())),
        )
        for diagnostic in cases:
            self.jump_broker.reset_mock()
            with self.subTest(diagnostic=diagnostic), self.assertRaises(TargetSSHError) as error:
                self.run_probe(diagnostic)
            self.assertNotIsInstance(error.exception, HostKeyChanged)
            self.jump_broker.disarm.assert_called_once()

    def test_diagnostic_capture_is_bounded_and_reaps_timed_out_process(self):
        finished = subprocess.Popen([sys.executable, "-c", "pass"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, start_new_session=True)
        with mock.patch("web_agent_target_ssh.os.killpg") as killpg:
            self.assertEqual(_read_bounded_probe_diagnostic(finished), b"")
        killpg.assert_called_once_with(finished.pid, signal.SIGKILL)
        writer = subprocess.Popen([sys.executable, "-c",
            "import os; os.write(2, b'x' * 50000)"], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True)
        self.assertEqual(len(_read_bounded_probe_diagnostic(writer)), MAX_SCAN + 1)
        self.assertIsNotNone(writer.returncode)
        sleeper = subprocess.Popen([sys.executable, "-c",
            "import time; time.sleep(5)"], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True)
        self.assertEqual(_read_bounded_probe_diagnostic(sleeper, timeout=0.1), b"")
        self.assertIsNotNone(sleeper.returncode)

    def test_unavailable_probe_disarms_jump_secret(self):
        with mock.patch("web_agent_target_ssh.subprocess.Popen", side_effect=OSError("offline")):
            with self.assertRaises(TargetSSHError) as error:
                _probe_jumped_target_host_key(Path("/run/private/ssh_config"),
                                              self.jump_broker, self.fingerprint)
        self.assertNotIsInstance(error.exception, HostKeyChanged)
        self.assertNotIn("offline", str(error.exception))
        self.jump_broker.disarm.assert_called_once()


if __name__ == "__main__":
    unittest.main()
