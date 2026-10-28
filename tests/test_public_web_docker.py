# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Disposable Docker proof: a validator cannot collide with live Web's IP/CA.

Explicit opt-in only; no host port publications and no production project.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import unittest
import uuid

from test_public_web import web, CONFIG, REPO, source_fixture
from test_build_contexts import build_contexts

LIVE_CADDY_CONFIG = ("{\nadmin off\nauto_https disable_redirects\nskip_install_trust\n"
                     "import /etc/caddy/public/global/*.options\n}\n"
                     ":8080 {\nrespond \"ready\"\n}\n"
                     "localhost:8443 {\ntls internal\nrespond \"agent\"\n}\n"
                     "import /etc/caddy/public/sites/*.caddy\n")


@unittest.skipUnless(os.environ.get("PUBLIC_WEB_DOCKER_TEST") == "1", "explicit disposable Docker fixture only")
class PublicWebDocker(unittest.TestCase):
    def command(self, *args):
        return subprocess.check_output(["docker", *args], stderr=subprocess.DEVNULL, timeout=90).decode().strip()

    def test_rebuild_refreshes_equal_size_epoch_inputs_at_the_same_context_path(self):
        image = "sg-context-test-" + uuid.uuid4().hex + ":fixture"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hub = root / "sovagrid-hub"
            context = root / "sovagrid-web"
            hub.mkdir()
            context.mkdir()
            (hub / "README").write_bytes(b"fixed second build context\n")
            dockerfile = context / "Dockerfile"
            dockerfile.write_text("FROM caddy:2.11.7-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f\n"
                                  "COPY payload /srv/build-payload\n")
            payload = context / "payload"
            payload.write_bytes(b"version=A\n")
            paths = [hub / "README", dockerfile, payload]
            for path in paths:
                os.utime(path, ns=(0, 0))

            def build():
                self.command("build", "-q", "--tag", image, str(context))

            def installed_bytes():
                container = self.command("create", "--network", "none", "--read-only", "--cap-drop", "ALL",
                                         "--security-opt", "no-new-privileges:true", "--entrypoint", "/bin/cat",
                                         image, "/srv/build-payload")
                try:
                    value = self.command("start", "--attach", container)
                    self.assertEqual(self.command("inspect", "--format", "{{.State.ExitCode}}", container), "0")
                    self.assertEqual(self.command("inspect", "--format", "{{.Image}}", container),
                                     self.command("image", "inspect", "--format", "{{.Id}}", image))
                    self.assertIn(self.command("inspect", "--format", "{{json .HostConfig.PortBindings}}", container), ("{}", "null"))
                    return value
                finally:
                    self.command("rm", container)

            try:
                build()
                self.assertEqual(installed_bytes(), "version=A")
                previous = payload.stat()
                # Match a replacement extracted from a deterministic archive:
                # same context path, file size, permissions and epoch mtime.
                replacement = context / "payload.next"
                replacement.write_bytes(b"version=B\n")
                replacement.chmod(previous.st_mode & 0o777)
                os.utime(replacement, ns=(0, 0))
                os.replace(replacement, payload)
                self.assertEqual((payload.stat().st_size, payload.stat().st_mtime_ns), (previous.st_size, 0))
                build()
                before_refresh = installed_bytes()
                self.assertIn(before_refresh, ("version=A", "version=B"))
                print("Equal-metadata BuildKit transfer stale before refresh:", before_refresh == "version=A")
                originals = {path: path.read_bytes() for path in paths}
                metadata = {path: path.stat() for path in paths}
                self.assertEqual(build_contexts.refresh(root), len(paths))
                for path, before in metadata.items():
                    after = path.stat()
                    self.assertNotEqual(after.st_mtime_ns, before.st_mtime_ns)
                    self.assertEqual(after.st_atime_ns, before.st_atime_ns)
                    self.assertEqual(after.st_mode, before.st_mode)
                    self.assertEqual(path.read_bytes(), originals[path])
                build()
                self.assertEqual(installed_bytes(), "version=B")
            finally:
                self.command("image", "rm", image)

    def test_installer_replaces_stopped_container_even_when_image_inputs_are_identical(self):
        name = "sg-recreate-test-" + uuid.uuid4().hex
        image = name + ":fixture"
        # Execute the actual installer command against an isolated project.
        # Identical build inputs exercise the case in which Compose could reuse
        # an existing stopped container. OCI attestation support is not required
        # by this fixture; image-ID verification remains exact on either store.
        commands = [line.strip() for line in (REPO / "run.sh").read_text().splitlines()
                    if line.strip() == '"${compose[@]}" up -d --build --force-recreate']
        self.assertEqual(len(commands), 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "Caddyfile"
            config.write_text("{\nadmin off\nauto_https off\n}\n:8080 {\nrespond \"ready\"\n}\n")
            compose_file = root / "compose.json"
            compose_file.write_text(json.dumps({"services": {"web": {
                "image": image,
                "build": {"context": str(REPO), "dockerfile": "tests/Dockerfile.public-web"},
                "network_mode": "none", "read_only": True, "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "environment": {"XDG_DATA_HOME": "/data", "XDG_CONFIG_HOME": "/tmp/config"},
                "tmpfs": ["/data:uid=10002,gid=10002,mode=0700", "/tmp:uid=10002,gid=10002,mode=0700"],
                "volumes": [{"type": "bind", "source": str(config),
                             "target": "/etc/caddy/Caddyfile", "read_only": True}],
            }}}))
            compose = ["compose", "--project-name", name, "--file", str(compose_file)]
            script = "compose=(" + shlex.join(["docker", *compose]) + ")\n" + commands[0]

            def up():
                result = subprocess.run(["bash", "-euc", script], capture_output=True, text=True, timeout=180)
                self.assertEqual(result.returncode, 0, (result.stdout + result.stderr)[-8192:])

            try:
                up()
                previous = self.command(*compose, "ps", "--quiet", "web")
                self.assertTrue(previous)
                self.command(*compose, "stop", "--timeout", "5", "web")
                self.assertEqual(self.command("inspect", "--format", "{{.State.Status}}", previous), "exited")
                up()
                current = self.command(*compose, "ps", "--quiet", "web")
                self.assertTrue(current)
                self.assertNotEqual(previous, current)
                self.assertEqual(self.command("inspect", "--format", "{{.Image}}", current),
                                 self.command("image", "inspect", "--format", "{{.Id}}", image))
                self.assertIn(self.command("inspect", "--format", "{{json .HostConfig.PortBindings}}", current), ("{}", "null"))
                for attempt in range(60):
                    try:
                        self.assertEqual(self.command("exec", current, "wget", "-q", "-O", "-", "http://127.0.0.1:8080"), "ready")
                        break
                    except subprocess.CalledProcessError:
                        if attempt == 59:
                            raise
                        time.sleep(0.1)
            finally:
                self.command(*compose, "down", "--remove-orphans", "--timeout", "5")
                self.command("image", "rm", image)

    def test_validator_alongside_live_static_ip_never_touches_live_ca(self):
        name = "sg-public-test-" + uuid.uuid4().hex
        image = name + ":fixture"
        self.command("build", "-q", "-f", str(REPO / "tests/Dockerfile.public-web"), "-t", image, str(REPO))
        self.addCleanup(lambda: self.command("image", "rm", image))
        network = name + "-net"
        self.command("network", "create", "--subnet", "172.30.253.0/28", network)
        self.addCleanup(lambda: self.command("network", "rm", network))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_fixture(root)
            actual_runner = web.Runner()
            def runner(args, timeout=45):
                # Redirect ONLY the product's fixed image lookup to this
                # disposable fixture tag. Validation then uses immutable ID.
                if args == ["docker", "image", "inspect", "--format", "{{.Id}}", "sovagrid-web:local"]:
                    args = [*args[:-1], image]
                return actual_runner(args, timeout=timeout)
            helper = web.PublicWeb(root, uid=os.getuid(), runner=runner)
            base = root / "opt/sovagrid-src/sovagrid-web/deploy/Caddyfile.container"
            base.write_text(LIVE_CADDY_CONFIG)
            compose = root / "opt/sovagrid-src/sovagrid-blueprint/deploy/compose.yaml"
            compose.write_text("services:\n  web:\n    image: " + image + "\n"
                               "    networks:\n      private:\n        ipv4_address: 172.30.253.10\n"
                               "networks:\n  private:\n    external: true\n    name: " + network + "\n")
            (root / "etc/sovagrid/deploy.env").write_text("SOVAGRID_HUB_DATA_DIR=/unused\nSOVAGRID_CADDY_DATA_DIR=/unused\n")
            candidate = helper.create_generation(CONFIG)
            container = self.command("run", "-d", "--name", name, "--network", network, "--ip", "172.30.253.10",
                                     "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                                     "--tmpfs", "/data:uid=10002,gid=10002,mode=0700", "--tmpfs", "/tmp:uid=10002,gid=10002,mode=0700",
                                     "-e", "XDG_DATA_HOME=/data", "-e", "XDG_CONFIG_HOME=/tmp/config",
                                     "--mount", "type=bind,src=" + str(base) + ",dst=/etc/caddy/Caddyfile,readonly",
                                     image)
            try:
                ca = "/data/caddy/pki/authorities/local/root.crt"
                for attempt in range(60):
                    try:
                        before = self.command("exec", container, "sha256sum", ca)
                        self.command("exec", container, "wget", "-q", "-O", "-", "http://127.0.0.1:8080")
                        break
                    except subprocess.CalledProcessError:
                        if attempt == 59:
                            raise
                        time.sleep(0.1)
                helper.validate_compose(candidate)
                self.assertEqual(before, self.command("exec", container, "sha256sum", ca))
                self.assertEqual(self.command("inspect", "--format", "{{.State.Running}}", container), "true")
                self.assertIn("172.30.253.10", self.command("inspect", "--format", "{{json .NetworkSettings.Networks}}", container))
                self.assertIn(self.command("inspect", "--format", "{{json .HostConfig.PortBindings}}", container), ("{}", "null"))
            except BaseException:
                # Disposable fixture configuration has no credentials. Keep
                # bounded startup diagnostics instead of masking its failure.
                logs = subprocess.run(["docker", "logs", "--tail", "80", container], capture_output=True,
                                      text=True, timeout=10)
                print((logs.stdout + logs.stderr)[-16384:])
                raise
            finally:
                self.command("rm", "-f", container)


if __name__ == "__main__":
    unittest.main()
