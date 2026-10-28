# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Owned filesystem transactions; no host service or network is modified."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import time
import unittest

SPEC = importlib.util.spec_from_file_location("public_web", Path(__file__).parents[1] / "deploy/public_web.py")
web = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(web)
REPO = Path(__file__).parents[1]
CONFIG = {"mode": "ip", "address": "8.8.8.8", "acme_environment": "production"}


class Fixture(web.PublicWeb):
    def __init__(self, root):
        super().__init__(root, uid=os.getuid(), runner=self.command)
        self.commands = []
        self.started = []
        self.public_failures = 0
        self.ssh_failures = 0
        self.ssh_checks = 0
        self.panel_failures = 0
        self.panel_checks = 0
        self.start_failure = False
        self.local_failures = 0
        self.runtime_present = True

    def command(self, args, timeout=45):
        self.commands.append(args)
        if args[:3] == ["docker", "image", "inspect"]:
            return b"sha256:" + b"a" * 64 + b"\n"
        return b""

    def local_health(self):
        if self.local_failures:
            self.local_failures -= 1
            raise web.PublicWebError("LOCAL_UNHEALTHY")

    def address_check(self, config):
        pass

    def ports(self, current):
        pass

    def start(self, state):
        self.started.append(state)
        if self.start_failure:
            raise web.PublicWebError("COMMAND_FAILED")
        self.runtime_present = True

    def public_health(self, config):
        if self.public_failures:
            self.public_failures -= 1
            raise web.PublicWebError("PUBLIC_UNHEALTHY")

    def public_ssh_health(self, config):
        self.ssh_checks += 1
        if self.ssh_failures:
            self.ssh_failures -= 1
            raise web.PublicWebError("PUBLIC_UNHEALTHY")

    def public_panel_health(self, config):
        self.panel_checks += 1
        if self.panel_failures:
            self.panel_failures -= 1
            raise web.PublicWebError("PUBLIC_UNHEALTHY")

    def runtime_matches(self, state):
        return self.runtime_present


def source_fixture(root):
    helper = Fixture(root)
    for name in ("etc", "etc/sovagrid", "var", "var/lib", "var/lib/sovagrid", "opt", "opt/sovagrid-src"):
        (root / name).mkdir(exist_ok=True, mode=0o755)
    marker = root / "var/lib/sovagrid/.managed-by-run-sh"
    marker.write_bytes(b"")
    marker.chmod(0o600)
    source = root / "opt/sovagrid-src"
    for component in web.COMPONENTS:
        (source / component).mkdir(mode=0o755)
    files = {}
    for name in web.REQUIRED:
        if name.startswith("sovagrid-blueprint/"):
            data = (REPO / name.removeprefix("sovagrid-blueprint/")).read_bytes()
        elif name.endswith("Dockerfile"):
            data = ("FROM " + web.PIN + "\n").encode()
        else:
            data = ("{\n" + web.IMPORTS[0] + "\n}\n" + web.IMPORTS[1] +
                    "\n:8080 {\n" + web.IMPORTS[2] + "\n}\n").encode()
        destination = source / name
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        destination.write_bytes(data)
        destination.chmod(0o644)
        files[name] = web.digest(data)
    manifest = {"format": 1, "components": {name: {} for name in web.COMPONENTS}, "sha256": files}
    (source / "sovagrid-bundle.json").write_bytes(web.encode(manifest))
    return helper


class PublicWebTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.helper = source_fixture(self.root)

    def enable(self, config=None):
        config = config or CONFIG
        preview = self.helper.preview(config)
        return self.helper.apply(config, preview["expected_state_sha256"], preview["source_manifest_sha256"])

    def change_site_template(self):
        source = self.root / "opt/sovagrid-src"
        name = "sovagrid-blueprint/deploy/public-web.site.template"
        target = source / name
        target.write_bytes(target.read_bytes() + b"\n# refreshed browser SSH route fixture\n")
        manifest = source / "sovagrid-bundle.json"
        value = web.decode(manifest.read_bytes(), 512 * 1024)
        value["sha256"][name] = web.digest(target.read_bytes())
        manifest.write_bytes(web.encode(value))

    def test_strict_public_address_validation_and_bounded_json(self):
        self.assertEqual(web.validate_config(CONFIG), {**CONFIG, "panel_path": "/sovagrid/monitoring/",
                                                       "root_behavior": "panel"})
        for bad_path in ("/", "sovagrid/monitoring/", "/SovaGrid/", "/a//b/", "/a/../",
                         "/-a/", "/a-/", "/a.b/", "/a/b/c/d/", "/a" + "a" * 100 + "/",
                         "/api/", "/api/v1/", "/api/v1/browser-ssh/", "/healthz/"):
            with self.subTest(panel_path=bad_path), self.assertRaises(web.PublicWebError):
                web.validate_config({**CONFIG, "panel_path": bad_path})
        for bad_mode in ("", "proxy", "panel\n", 1):
            with self.subTest(root_behavior=bad_mode), self.assertRaises(web.PublicWebError):
                web.validate_config({**CONFIG, "root_behavior": bad_mode})
        for address in ("127.0.0.1", "0.0.0.0", "10.0.0.1", "224.1.2.3", "::1", "::ffff:8.8.8.8", "08.8.8.8", "8.8.8.8:443", "8.8.8.8\n}"):
            with self.subTest(address=address), self.assertRaises(web.PublicWebError):
                web.validate_config({**CONFIG, "address": address})
        for address in ("Example.com", "example.com.", "localhost", "foo.local", "foo.test", "a..com", "-foo.com", "https://foo.com", "foo.com/path", "foo.com{evil}"):
            with self.subTest(address=address), self.assertRaises(web.PublicWebError):
                web.validate_config({**CONFIG, "mode": "dns", "address": address})
        self.assertEqual(web.validate_config({**CONFIG, "mode": "dns", "address": "panel.example.org"})["address"], "panel.example.org")
        for raw in (b'{"config":1,"config":2}', b'{"config":NaN}', b'[]', b'{' + b'"a":' + b'[' * 1800 + b'0' + b']' * 1800 + b'}', b' ' * 4097):
            with self.assertRaises(web.PublicWebError):
                web.decode(raw)

    def test_preview_is_read_only_and_changed_source_is_refused(self):
        before = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        result = self.helper.preview(CONFIG)
        self.assertTrue(result["changed"])
        self.assertFalse(result["certificate_verified"])
        self.assertIsNone(result["expected_state_sha256"])
        self.assertEqual(before, {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()})
        (self.root / "opt/sovagrid-src/sovagrid-web/Dockerfile").write_text("FROM unexpected\n")
        with self.assertRaises(web.PublicWebError) as error:
            self.helper.preview(CONFIG)
        self.assertEqual(error.exception.code, "SOURCE_UNTRUSTED")

    def test_apply_publishes_only_web_and_keeps_private_channels(self):
        result = self.enable()
        state, sha = self.helper.state()
        self.assertTrue(result["enabled"])
        self.assertTrue(result["certificate_verified"])
        self.assertEqual(sha, result["expected_state_sha256"])
        overlay = self.helper.path(self.helper.overlay(state)).read_text()
        self.assertIn('"0.0.0.0:80:9080/tcp"', overlay)
        self.assertIn('"0.0.0.0:443:9443/tcp"', overlay)
        self.assertNotIn("8767", overlay)
        self.assertNotIn("hub:", overlay)
        base = (REPO / "deploy/compose.yaml").read_text()
        self.assertIn('"127.0.0.1:8766:8080"', base)
        self.assertIn('"127.0.0.1:8767:8443"', base)
        self.assertIn("172.30.253.10", base)
        generation = self.helper.path(self.helper.overlay(state)).parent
        self.assertEqual(stat.S_IMODE((generation / "caddy/sites/public.caddy").stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((generation / "caddy/sites").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((generation / "caddy/local/panel.caddy").stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(self.helper.path(web.PUBLIC + "/state.json").stat().st_mode), 0o600)

    def test_idempotence_and_stale_compare_and_swap(self):
        initial = self.enable()
        state, _ = self.helper.state()
        repeat = self.enable()
        self.assertFalse(repeat["changed"])
        self.assertEqual(len(self.helper.started), 1)
        self.assertEqual(state, self.helper.state()[0])
        preview = self.helper.preview(CONFIG)
        with self.assertRaises(web.PublicWebError) as error:
            self.helper.apply({**CONFIG, "acme_environment": "staging"}, None, preview["source_manifest_sha256"])
        self.assertEqual(error.exception.code, "STATE_CHANGED")
        with self.assertRaises(web.PublicWebError) as error:
            self.helper.apply(CONFIG, initial["expected_state_sha256"], "0" * 64)
        self.assertEqual(error.exception.code, "STATE_CHANGED")
        self.assertEqual(len(self.helper.started), 1)

    def test_failed_first_apply_restores_disabled_web(self):
        self.helper.public_failures = 1
        with self.assertRaises(web.PublicWebError) as error:
            self.enable()
        self.assertEqual(error.exception.code, "PUBLIC_UNHEALTHY")
        self.assertIsNone(self.helper.state()[0])
        self.assertIsNone(self.helper.started[-1])

    def test_resume_replays_committed_generation_if_old_site_still_answers(self):
        self.enable()
        state = self.helper.state()
        self.helper.runtime_present = False  # killed after state commit, before compose up
        result = self.enable()
        self.assertTrue(result["enabled"])
        self.assertEqual(self.helper.state(), state)
        self.assertEqual(len(self.helper.started), 2)
        self.assertEqual(self.helper.started[-1], state[0])

    def test_failed_change_restores_exact_prior_generation(self):
        self.enable()
        old_state, old_sha = self.helper.state()
        self.helper.public_failures = 1
        with self.assertRaises(web.PublicWebError) as error:
            self.enable({**CONFIG, "acme_environment": "staging"})
        self.assertEqual(error.exception.code, "PUBLIC_UNHEALTHY")
        self.assertEqual(self.helper.state(), (old_state, old_sha))
        self.assertEqual(self.helper.started[-1], old_state)

    def test_rollback_failure_is_reported_and_prior_state_retained(self):
        self.enable()
        previous = self.helper.state()
        self.helper.start_failure = True
        with self.assertRaises(web.PublicWebError) as error:
            self.enable({**CONFIG, "acme_environment": "staging"})
        self.assertEqual(error.exception.code, "ROLLBACK_FAILED")
        self.assertEqual(self.helper.state(), previous)

    def test_disable_verified_and_state_corruption_refuses_update(self):
        result = self.enable()
        disabled = self.helper.disable(result["expected_state_sha256"])
        self.assertFalse(disabled["enabled"])
        self.assertIsNone(self.helper.state()[0])
        self.assertIsNone(self.helper.started[-1])
        self.assertFalse(self.helper.disable(None)["changed"])
        self.enable()
        state, _ = self.helper.state()
        self.helper.path(self.helper.overlay(state)).write_text("services: {evil: {}}")
        with self.assertRaises(web.PublicWebError) as error:
            self.helper.state()
        self.assertEqual(error.exception.code, "STATE_UNTRUSTED")

    def test_disable_does_not_report_off_before_public_bindings_are_closed(self):
        result = self.enable()
        before = self.helper.state()
        original = self.helper.start
        observed = []
        def stop(state):
            if state is None:
                observed.append(self.helper.state())
            return original(state)
        self.helper.start = stop
        self.helper.disable(result["expected_state_sha256"])
        self.assertEqual(observed, [before])
        self.assertIsNone(self.helper.state()[0])

    def test_unowned_directory_symlink_and_writable_config_fail_closed(self):
        directory = self.helper.path(web.PUBLIC)
        directory.mkdir(mode=0o700)
        with self.assertRaises(web.PublicWebError):
            self.helper.state()
        directory.rmdir()
        directory.symlink_to(self.root / "opt")
        with self.assertRaises(web.PublicWebError):
            self.helper.state()
        directory.unlink()
        self.enable()
        self.helper.path(web.PUBLIC + "/state.json").chmod(0o666)
        with self.assertRaises(web.PublicWebError):
            self.helper.state()

    def test_generation_remains_valid_after_verified_template_upgrade(self):
        self.enable()
        before = self.helper.state()
        # Reading a prior approved generation does not regenerate it using a
        # later package's templates, which would break ordinary updates.
        self.helper.templates = lambda: (_ for _ in ()).throw(AssertionError("should not regenerate"))
        self.assertEqual(self.helper.state(), before)

    def test_refresh_replaces_template_only_when_changed_and_preserves_address(self):
        self.enable()
        before, before_sha = self.helper.state()
        self.change_site_template()
        self.assertEqual(self.helper.state(), (before, before_sha))
        preview = self.helper.preview(CONFIG)
        self.assertTrue(preview["changed"])
        result = self.helper.refresh(lock_held=True)
        current, current_sha = self.helper.state()
        self.assertTrue(result["changed"])
        self.assertEqual(result["expected_state_sha256"], current_sha)
        self.assertEqual(current["config"], before["config"])
        self.assertNotEqual(current["generation"], before["generation"])
        self.assertEqual(self.helper.ssh_checks, 1)
        self.assertIn("refreshed browser SSH route fixture",
                      self.helper.path(web.PUBLIC + "/generations/" + current["generation"] +
                                       "/caddy/sites/public.caddy").read_text())
        self.assertFalse(self.helper.refresh(lock_held=True)["changed"])
        self.assertEqual(self.helper.ssh_checks, 2)
        self.assertEqual(self.helper.state(), (current, current_sha))

    def test_legacy_three_file_generation_refreshes_without_changing_root_behavior(self):
        self.enable()
        old, _ = self.helper.state()
        old["config"] = dict(CONFIG)
        old["sha256"].pop("caddy/local/panel.caddy")
        local = self.helper.path(web.PUBLIC + "/generations/" + old["generation"] + "/caddy/local")
        (local / "panel.caddy").unlink()
        local.rmdir()
        self.helper.atomic(web.PUBLIC + "/state.json", web.encode(old))
        legacy, legacy_sha = self.helper.state()
        self.assertEqual(legacy["config"]["root_behavior"], "panel")
        self.assertEqual(legacy["config"]["panel_path"], web.DEFAULT_PANEL_PATH)
        self.assertEqual(legacy_sha, web.digest(web.encode(old)))
        result = self.helper.refresh(lock_held=True)
        current, _ = self.helper.state()
        self.assertTrue(result["changed"])
        self.assertEqual(current["config"]["root_behavior"], "panel")
        self.assertIn("caddy/local/panel.caddy", current["sha256"])

    def test_custom_panel_path_and_root_modes_render_only_fixed_caddy_routes(self):
        site, compose = self.helper.templates()
        for behavior in ("untouched", "panel", "redirect", "not_found"):
            with self.subTest(behavior=behavior):
                config = {**CONFIG, "panel_path": "/my/server/panel/", "root_behavior": behavior}
                files = web.render(config, "/fixed-generation", site, compose)
                public = files["caddy/sites/public.caddy"].decode()
                local = files["caddy/local/panel.caddy"].decode()
                self.assertIn("redir /my/server/panel /my/server/panel/ 308", public)
                self.assertIn("handle_path /my/server/panel/*", public)
                self.assertIn("handle_path /sovagrid/monitoring/*", public)
                self.assertIn("handle_path /my/server/panel/*", local)
                self.assertIn("/api/v1/browser-ssh/*", public)
                if behavior == "panel":
                    self.assertIn("handle {\n    root * /srv", public)
                    self.assertNotIn("redir / /my/server/panel/", public)
                elif behavior == "redirect":
                    self.assertIn("redir / /my/server/panel/ 308", public)
                    self.assertIn("redir / /my/server/panel/ 308", local)
                elif behavior == "not_found":
                    self.assertIn("handle {\n        respond 404", public)
                    self.assertIn("handle / {\n    respond 404", local)
                else:
                    self.assertNotIn("redir / /my/server/panel/", public)
                    self.assertIn("handle {\n        respond 404", public)
                    self.assertNotIn("handle / {", local)

        for path, first in (("/sovagrid/", "/sovagrid/monitoring/*"),
                            ("/sovagrid/monitoring/ops/", "/sovagrid/monitoring/ops/*")):
            public = web.render({**CONFIG, "panel_path": path}, "/fixed-generation", site, compose)[
                "caddy/sites/public.caddy"].decode()
            other = "/sovagrid/*" if path == "/sovagrid/" else "/sovagrid/monitoring/*"
            self.assertLess(public.index("handle_path " + first), public.index("handle_path " + other))

    def test_public_panel_route_failure_restores_prior_generation(self):
        initial = self.enable()
        before = self.helper.state()
        self.helper.panel_failures = 1
        preview = self.helper.preview({**CONFIG, "panel_path": "/ops/monitoring/", "root_behavior": "not_found"})
        with self.assertRaises(web.PublicWebError) as error:
            self.helper.apply(preview["config"], initial["expected_state_sha256"], preview["source_manifest_sha256"])
        self.assertEqual(error.exception.code, "PUBLIC_UNHEALTHY")
        self.assertEqual(self.helper.state(), before)

    def test_active_local_panel_blocks_public_preview_before_host_checks(self):
        local = self.root / "etc/sovagrid/local-web"
        local.mkdir(mode=0o700)
        marker = local / ".managed"
        marker.write_bytes(b"SOVAGRID_LOCAL_WEB_V1\n")
        marker.chmod(0o600)
        state = local / "state.json"
        state.write_text("{}\n")
        state.chmod(0o600)
        before = list(self.helper.commands)
        with self.assertRaises(web.PublicWebError) as blocked:
            self.helper.preview(CONFIG)
        self.assertEqual(blocked.exception.code, "LOCAL_ACTIVE")
        self.assertEqual(self.helper.commands, before)
        state.unlink()
        self.assertTrue(self.helper.preview(CONFIG)["changed"])

    def test_public_apply_checks_ssh_when_gateway_is_managed(self):
        marker = self.helper.path(web.SSH_GATEWAY_MARKER)
        marker.write_bytes(b"SOVAGRID_SSH_GATEWAY_V1\n")
        marker.chmod(0o600)
        self.enable()
        self.assertEqual(self.helper.ssh_checks, 1)
        before = self.helper.state()
        self.helper.ssh_failures = 1
        preview = self.helper.preview({**CONFIG, "panel_path": "/ops/monitoring/"})
        with self.assertRaises(web.PublicWebError) as error:
            self.helper.apply(preview["config"], before[1], preview["source_manifest_sha256"])
        self.assertEqual(error.exception.code, "PUBLIC_UNHEALTHY")
        self.assertEqual(self.helper.state(), before)

    def test_failed_public_ssh_route_restores_old_generation(self):
        self.enable()
        before = self.helper.state()
        self.change_site_template()
        self.helper.ssh_failures = 1
        with self.assertRaises(web.PublicWebError) as error:
            self.helper.refresh(lock_held=True)
        self.assertEqual(error.exception.code, "PUBLIC_UNHEALTHY")
        self.assertEqual(self.helper.state(), before)
        self.assertEqual(self.helper.started[-1], before[0])

    def test_refresh_refuses_untrusted_template_and_missing_public_state(self):
        with self.assertRaises(web.PublicWebError) as error:
            self.helper.refresh(lock_held=True)
        self.assertEqual(error.exception.code, "STATE_CHANGED")
        self.enable()
        before = self.helper.state()
        target = self.root / "opt/sovagrid-src/sovagrid-blueprint/deploy/public-web.site.template"
        target.write_bytes(target.read_bytes() + b"tampered")
        with self.assertRaises(web.PublicWebError) as error:
            self.helper.refresh(lock_held=True)
        self.assertEqual(error.exception.code, "SOURCE_UNTRUSTED")
        self.assertEqual(self.helper.state(), before)

    def test_actual_common_lock_rejects_parallel_public_write(self):
        preview = self.helper.preview(CONFIG)
        with self.helper.lock():
            with self.assertRaises(web.PublicWebError) as error:
                self.helper.apply(CONFIG, None, preview["source_manifest_sha256"])
        self.assertEqual(error.exception.code, "BUSY")
        self.assertNotIn("/etc/sovagrid/", str(self.helper.path("/var/lib/sovagrid/.public-web.lock")))

    def test_validator_isolates_network_ca_and_live_static_address(self):
        self.enable()
        validations = [args for args in self.helper.commands if args[:2] == ["docker", "run"]]
        self.assertEqual(len(validations), 1)
        args = validations[0]
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertIn("--read-only", args)
        self.assertNotIn("172.30.253.10", " ".join(args))
        self.assertNotIn("/var/lib/sovagrid/caddy", " ".join(args))
        self.assertIn("/data:rw,nosuid,nodev,noexec,size=16m,uid=10002,gid=10002,mode=0700", args)

    def test_actual_child_output_and_wall_time_are_bounded(self):
        for script, timeout in (("import time; time.sleep(5)", 0.05),
                                ("import sys; sys.stdout.buffer.write(b'x'*3000000)", 5)):
            with self.subTest(script=script):
                started = time.monotonic()
                with self.assertRaises(web.PublicWebError) as error:
                    web.Runner()([sys.executable, "-I", "-c", script], timeout=timeout)
                self.assertEqual(error.exception.code, "COMMAND_FAILED")
                self.assertLess(time.monotonic() - started, 2)

    def test_existing_foreign_docker_publication_refuses_without_mutation(self):
        calls = []
        record = {"Config": {"Labels": {"com.docker.compose.project": "unrelated"}},
                  "NetworkSettings": {"Ports": {"443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}]}}}
        def command(args, timeout=45):
            calls.append(args)
            return b"a" * 12 + b"\n" if args[1] == "ps" else web.encode(record)
        self.helper.run = command
        with self.assertRaises(web.PublicWebError) as error:
            web.PublicWeb.ports(self.helper, None)
        self.assertEqual(error.exception.code, "PORT_BUSY")
        self.assertFalse(self.helper.path(web.PUBLIC).exists())
        self.assertIn("--format", calls[-1])
        self.assertNotIn(".Config.Env", calls[-1][calls[-1].index("--format") + 1])

    def test_escaped_descendant_holding_stdout_cannot_block_close_forever(self):
        pid_file = self.root / "escaped.pid"
        script = ("import pathlib,subprocess,sys; "
                  "p=subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(30)'],start_new_session=True); "
                  "pathlib.Path(sys.argv[1]).write_text(str(p.pid))")
        started = time.monotonic()
        try:
            with self.assertRaises(web.PublicWebError) as error:
                web.Runner()([sys.executable, "-I", "-c", script, str(pid_file)], timeout=2)
            self.assertEqual(error.exception.code, "COMMAND_FAILED")
            self.assertLess(time.monotonic() - started, 7)
            self.assertTrue(pid_file.is_file())
        finally:
            if pid_file.is_file():
                pid = int(pid_file.read_text())
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_renderer_ip_dns_and_agent_gate_order(self):
        for config in (CONFIG, {**CONFIG, "mode": "dns", "address": "panel.example.org"}):
            files = web.render(config, "/etc/sovagrid/public-web/generations/" + "a" * 32, *self.helper.templates())
            site = files["caddy/sites/public.caddy"].decode()
            self.assertIn("route {", site)
            self.assertLess(site.index("respond @agent_post"), site.index("handle @api"))
            self.assertLess(site.index("@browser_ssh path /api/v1/browser-ssh/*"),
                            site.index("@api path /api/*"))
            self.assertIn("header_up X-SovaGrid-Client-IP {remote_host}", site)
            self.assertIn("handle_path /sovagrid/monitoring/*", site)
            self.assertIn("profile shortlived", site) if config["mode"] == "ip" else self.assertNotIn("profile shortlived", site)
            self.assertIn("https://" + config["address"] + "{uri}", site)
            self.assertNotIn("https://{host}", site)

    def test_dns_resolution_uses_bounded_child_and_not_parent_getaddrinfo(self):
        calls = []
        def command(args, timeout=45):
            calls.append((args, timeout))
            if args[0] == "ip":
                return b'[{"addr_info":[{"local":"8.8.8.8","scope":"global"}]}]'
            return b'["8.8.8.8"]'
        self.helper.run = command
        web.PublicWeb.address_check(self.helper, {**CONFIG, "mode": "dns", "address": "panel.example.org"})
        self.assertEqual(calls[-1][1], 10)
        self.assertEqual(calls[-1][0][-1], "panel.example.org")
        self.assertIn("-I", calls[-1][0])

    def test_ipv6_fails_clearly_before_source_or_certificate_checks(self):
        with self.assertRaises(web.PublicWebError) as error:
            self.helper.preview({**CONFIG, "address": "2606:4700:4700::1111"})
        self.assertEqual(error.exception.code, "IPV6_UNAVAILABLE")
        def command(args, timeout=45):
            if args[0] == "ip":
                return b'[{"addr_info":[{"local":"8.8.8.8","scope":"global"}]}]'
            return b'["8.8.8.8","2606:4700:4700::1111"]'
        self.helper.run = command
        with self.assertRaises(web.PublicWebError) as error:
            web.PublicWeb.address_check(self.helper, {**CONFIG, "mode": "dns", "address": "panel.example.org"})
        self.assertEqual(error.exception.code, "IPV6_UNAVAILABLE")

    def test_runtime_identity_checks_all_public_and_loopback_bindings(self):
        self.enable()
        state, _ = self.helper.state()
        record = {"Mounts": [{"Destination": "/etc/caddy/public", "Source": str(self.helper.path(self.helper.overlay(state)).parent / "caddy"), "RW": False}],
                  "NetworkSettings": {"Ports": {
                      "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8766"}],
                      "8443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8767"}],
                      "9080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}],
                      "9443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}]},
                      "Networks": {"private": {"IPAddress": "172.30.253.10"}}}}
        self.helper.run = lambda args, timeout=45: b"a" * 12 + b"\n" if args[1] == "ps" else web.encode(record)
        self.assertTrue(web.PublicWeb.runtime_matches(self.helper, state))
        record["NetworkSettings"]["Ports"]["8443/tcp"][0]["HostIp"] = "0.0.0.0"
        self.assertFalse(web.PublicWeb.runtime_matches(self.helper, state))
        record["NetworkSettings"]["Ports"]["8443/tcp"][0]["HostIp"] = "127.0.0.1"
        record["NetworkSettings"]["Ports"]["9443/tcp"][0]["HostIp"] = "::"
        self.assertFalse(web.PublicWeb.runtime_matches(self.helper, state))


if __name__ == "__main__":
    unittest.main()
