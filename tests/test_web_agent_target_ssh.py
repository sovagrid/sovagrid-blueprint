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

from web_agent_target_ssh import (AskpassBroker, PinnedTargetSSH, TargetSSHError,
                                  host_key_alias, reviewed_public_key)


def fixture_key():
    key = b"ssh-ed25519"
    raw = struct.pack(">I", len(key)) + key + struct.pack(">I", 32) + bytes(range(32))
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

    def test_host_key_alias_binds_the_reviewed_fingerprint(self):
        _, fingerprint = fixture_key()
        alias = host_key_alias(fingerprint)
        self.assertRegex(alias, r"^sg-[a-z2-7]{52}$")
        self.assertNotEqual(alias, host_key_alias("SHA256:" + "A" * 43))
        with self.assertRaises(TargetSSHError):
            host_key_alias("SHA256:" + "A" * 42)


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

    def test_private_key_and_strict_host_pin_live_only_in_private_runtime_directory(self):
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


if __name__ == "__main__":
    unittest.main()
