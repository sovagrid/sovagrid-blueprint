#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Transactional loopback-only panel path for a managed Ubuntu Hub.

No public listener, account, credential, or arbitrary command is accepted.
The public-Web owner and this helper share one host lock. Existing public
sites keep ownership of their own local route; local-only apply is refused
while such a site is active. Installed source is checked against the pinned
bundle before any host mutation.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import string
import sys
import uuid


# This helper imports its peer from the pinned source tree. A generated .pyc
# there would make the installed manifest fail its next integrity check.
sys.dont_write_bytecode = True


PUBLIC_MODULE = Path(__file__).with_name("public_web.py")
SPEC = importlib.util.spec_from_file_location("_sovagrid_local_web_public", PUBLIC_MODULE)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("installed public Web helper is missing")
public = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(public)

LOCAL = "/etc/sovagrid/local-web"
MARKER = b"SOVAGRID_LOCAL_WEB_V1\n"
SOURCE = "/opt/sovagrid-src"
DEFAULT_PANEL_PATH = "/sovagrid/monitoring/"
HASH = re.compile(r"[0-9a-f]{64}\Z")
GENERATION = re.compile(r"[0-9a-f]{32}\Z")
PANEL_PATH = re.compile(r"/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/){1,3}\Z")
ROOT_BEHAVIORS = {"untouched", "panel", "redirect", "not_found"}
ERRORS = {
    "INVALID_REQUEST": "Неверный путь панели или настройки корня.",
    "UNMANAGED": "Нужна исправная установка SovaGrid под управлением установщика.",
    "SOURCE_UNTRUSTED": "Установленные исходники SovaGrid изменены.",
    "STATE_UNTRUSTED": "Локальные настройки изменены вне SovaGrid.",
    "STATE_CHANGED": "Настройки изменились. Повторите предварительный просмотр.",
    "PUBLIC_ACTIVE": "Публичной панелью управляют настройки HTTPS; измените путь там.",
    "COMMAND_FAILED": "Не удалось проверить или применить настройки Web.",
    "LOCAL_UNHEALTHY": "Локальная панель не отвечает по новому пути.",
    "ROLLBACK_FAILED": "Не удалось подтвердить восстановление Web.",
    "BUSY": "Другая операция Web ещё выполняется.",
    "ROOT_REQUIRED": "Операция требует прав администратора сервера.",
}

PANEL_HEALTH = r'''
import json, sys, time, urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
path, behavior = sys.argv[1:3]
for attempt in range(8):
    try:
        with opener.open('http://127.0.0.1:8766' + path, timeout=3) as response:
            page = response.read(262145)
            if response.status != 200 or len(page) > 262144 or not response.headers.get('Content-Type', '').startswith('text/html'):
                raise ValueError('panel unavailable')
        if b'id="sshLoginMode"' not in page or b'id="browserSshView"' not in page:
            raise ValueError('SSH panel unavailable')
        for asset in ('manifest.webmanifest', 'sw.js'):
            with opener.open('http://127.0.0.1:8766' + path + asset, timeout=3) as response:
                raw = response.read(65537)
                if response.status != 200 or len(raw) > 65536:
                    raise ValueError('PWA asset unavailable')
                if asset == 'manifest.webmanifest' and not isinstance(json.loads(raw).get('name'), str):
                    raise ValueError('invalid PWA manifest')
                if asset == 'sw.js' and b'addEventListener' not in raw:
                    raise ValueError('invalid service worker')
        if behavior in ('redirect', 'not_found'):
            try:
                with opener.open('http://127.0.0.1:8766/', timeout=3) as response:
                    status, location = response.status, response.headers.get('Location')
            except urllib.error.HTTPError as error:
                status, location = error.code, error.headers.get('Location')
            if behavior == 'redirect' and (status != 308 or location not in (path, 'http://127.0.0.1:8766' + path)):
                raise ValueError('wrong root redirect')
            if behavior == 'not_found' and status != 404:
                raise ValueError('wrong root response')
        sys.exit(0)
    except (OSError, ValueError, UnicodeError):
        time.sleep(0.5)
sys.exit(1)
'''


class LocalWebError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(ERRORS[code])


def require(condition, code="STATE_UNTRUSTED"):
    if not condition:
        raise LocalWebError(code)


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "INVALID_REQUEST")
        value[key] = item
    return value


def decode(raw, limit=4096):
    require(isinstance(raw, bytes) and len(raw) <= limit, "INVALID_REQUEST")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=lambda _item: require(False, "INVALID_REQUEST"))
        require(isinstance(value, dict), "INVALID_REQUEST")
        return value
    except (UnicodeError, ValueError, RecursionError) as error:
        raise LocalWebError("INVALID_REQUEST") from error


def validate_config(value):
    require(isinstance(value, dict) and set(value) == {"panel_path", "root_behavior"}, "INVALID_REQUEST")
    path, behavior = value["panel_path"], value["root_behavior"]
    require(isinstance(path, str) and len(path) <= 96 and PANEL_PATH.fullmatch(path) is not None and
            path.split("/")[1] not in {"api", "healthz"} and
            isinstance(behavior, str) and behavior in ROOT_BEHAVIORS, "INVALID_REQUEST")
    return {"panel_path": path, "root_behavior": behavior}


def validate_expected(value):
    require(value is None or isinstance(value, str) and HASH.fullmatch(value), "INVALID_REQUEST")
    return value


def render(config, generation, template):
    config = validate_config(config)
    path, behavior = config["panel_path"], config["root_behavior"]
    prefix = path[:-1]
    route = "# SovaGrid local-only panel generation\n"
    if path != DEFAULT_PANEL_PATH:
        route += (f"redir {prefix} {path} 308\n"
                  f"handle_path {prefix}/* {{\n"
                  "    root * /srv\n"
                  "    try_files {path} /index.html\n"
                  "    file_server\n"
                  "}\n")
    if behavior == "redirect":
        route += f"redir / {path} 308\n"
    elif behavior == "not_found":
        route += "handle / {\n    respond 404\n}\n"
    return {"caddy/panel.caddy": route.encode(),
            "compose.yaml": string.Template(template).substitute(caddy_dir=generation + "/caddy").encode()}


class LocalWeb:
    def __init__(self, root="/", *, uid=0, runner=None):
        self.shared = public.PublicWeb(root, uid=uid, runner=runner)

    def path(self, absolute):
        return self.shared.path(absolute)

    def source(self):
        try:
            source_sha = self.shared.source()
            self.shared.check(SOURCE + "/sovagrid-blueprint/deploy/local_web.py")
            self.shared.check(SOURCE + "/sovagrid-blueprint/deploy/compose.local-web.template")
            require(b"# SOVAGRID_LOCAL_WEB_V1" in self.shared.check(SOURCE + "/sovagrid-blueprint/run.sh"),
                    "SOURCE_UNTRUSTED")
            require(b"import /etc/caddy/local/*.caddy" in self.shared.check(
                SOURCE + "/sovagrid-web/deploy/Caddyfile.container"), "SOURCE_UNTRUSTED")
            return source_sha
        except (OSError, ValueError, public.PublicWebError) as error:
            raise LocalWebError("SOURCE_UNTRUSTED") from error

    def public_inactive(self):
        try:
            state, _sha = self.shared.state()
        except (OSError, ValueError, public.PublicWebError) as error:
            raise LocalWebError("STATE_UNTRUSTED") from error
        require(state is None, "PUBLIC_ACTIVE")

    def local_health(self):
        # A promoted Home Hub has its own CA. /etc/sovagrid/hub-ca.pem may
        # still belong to the independent external Agent and must not be used
        # to validate the local Hub's TLS listener.
        ca = ("/var/lib/sovagrid/local-hub-ca.pem" if
              os.path.lexists(self.path("/var/lib/sovagrid/local-hub-ca.pem")) else
              "/etc/sovagrid/hub-ca.pem")
        try:
            self.shared.check(ca, private=ca.startswith("/var/lib/"), limit=16384)
            self.shared.run([sys.executable, "-I", "-c", public.LOCAL_HEALTH_SCRIPT,
                             str(self.path(ca))], timeout=35)
        except (OSError, ValueError, public.PublicWebError) as error:
            raise LocalWebError("LOCAL_UNHEALTHY") from error

    def state(self):
        try:
            if not os.path.lexists(self.path(LOCAL)):
                return None, None
            self.shared.check(LOCAL, directory=True, private=True)
            require(self.shared.check(LOCAL + "/.managed", private=True) == MARKER)
            if not os.path.lexists(self.path(LOCAL + "/state.json")):
                return None, None
            raw = self.shared.check(LOCAL + "/state.json", private=True, limit=4096)
            value = decode(raw)
            require(set(value) == {"protocol", "generation", "config", "sha256"} and
                    type(value["protocol"]) is int and value["protocol"] == 1 and
                    isinstance(value["generation"], str) and GENERATION.fullmatch(value["generation"]) and
                    isinstance(value["sha256"], dict) and
                    set(value["sha256"]) == {"caddy/panel.caddy", "compose.yaml"})
            value["config"] = validate_config(value["config"])
            generation = LOCAL + "/generations/" + value["generation"]
            self.shared.check(generation, directory=True, private=True)
            for name, expected in value["sha256"].items():
                require(isinstance(expected, str) and HASH.fullmatch(expected) and
                        digest(self.shared.check(generation + "/" + name, limit=32768)) == expected)
            return value, digest(raw)
        except (OSError, ValueError, TypeError, KeyError, public.PublicWebError) as error:
            raise LocalWebError("STATE_UNTRUSTED") from error

    def overlay(self, state=None):
        if state is None:
            state, _sha = self.state()
        return LOCAL + "/generations/" + state["generation"] + "/compose.yaml" if state else None

    def compose(self, state):
        args = self.shared.compose(None)
        if state is not None:
            args += ["-f", str(self.path(self.overlay(state)))]
        return args

    def templates(self):
        return self.shared.check(SOURCE + "/sovagrid-blueprint/deploy/compose.local-web.template").decode()

    def generation_matches_templates(self, state):
        generation = LOCAL + "/generations/" + state["generation"]
        expected = render(state["config"], generation, self.templates())
        return {name: digest(raw) for name, raw in expected.items()} == state["sha256"]

    def preview(self, config):
        config = validate_config(config)
        source_sha = self.source()
        self.public_inactive()
        state, state_sha = self.state()
        try:
            self.local_health()
        except (OSError, ValueError, public.PublicWebError) as error:
            raise LocalWebError("LOCAL_UNHEALTHY") from error
        changed = state is None or state["config"] != config or not self.generation_matches_templates(state)
        return {"protocol": 1, "ok": True, "config": config,
                "expected_state_sha256": state_sha, "source_manifest_sha256": source_sha,
                "changed": changed, "url": "http://127.0.0.1:8766", "certificate_verified": False}

    def create_generation(self, config):
        if not os.path.lexists(self.path(LOCAL)):
            temporary = "/etc/sovagrid/.local-web-init-" + uuid.uuid4().hex
            self.shared.mkdir(temporary)
            self.shared.atomic(temporary + "/.managed", MARKER)
            require(not os.path.lexists(self.path(LOCAL)))
            os.rename(self.path(temporary), self.path(LOCAL))
            self.shared.sync_directory(self.path(LOCAL).parent)
        self.shared.mkdir(LOCAL + "/generations")
        generation = uuid.uuid4().hex
        base = LOCAL + "/generations/" + generation
        self.shared.mkdir(base)
        self.shared.mkdir(base + "/caddy", 0o755)
        files = render(config, base, self.templates())
        for name, raw in files.items():
            self.shared.atomic(base + "/" + name, raw, 0o644)
        return {"protocol": 1, "generation": generation, "config": config,
                "sha256": {name: digest(raw) for name, raw in files.items()}}

    def validate_compose(self, state):
        self.shared.run(self.compose(state) + ["config", "--quiet"])
        image = self.shared.run(["docker", "image", "inspect", "--format", "{{.Id}}",
                                 "sovagrid-web:local"], timeout=10).decode().strip()
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", image), "COMMAND_FAILED")
        self.shared.run(["docker", "run", "--rm", "--network", "none", "--read-only",
                         "--user", "10002:10002", "--cap-drop", "ALL",
                         "--security-opt", "no-new-privileges:true", "--pids-limit", "128",
                         "--memory", "128m",
                         "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m,uid=10002,gid=10002,mode=0700",
                         "--tmpfs", "/data:rw,nosuid,nodev,noexec,size=16m,uid=10002,gid=10002,mode=0700",
                         "-e", "XDG_DATA_HOME=/data", "-e", "XDG_CONFIG_HOME=/tmp/config",
                         "--mount", "type=bind,src=" + str(self.path(SOURCE + "/sovagrid-web/deploy/Caddyfile.container")) +
                         ",dst=/etc/caddy/Caddyfile,readonly",
                         "--mount", "type=bind,src=" + str(self.path(LOCAL + "/generations/" + state["generation"] +
                                                                "/caddy")) + ",dst=/etc/caddy/local,readonly",
                         image, "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"])

    def start(self, state):
        self.shared.run(self.compose(state) + ["up", "-d", "--no-deps", "web"], timeout=90)

    def runtime_matches(self, state):
        ids = self.shared.run(["docker", "ps", "--filter", "label=com.docker.compose.project=sovagrid",
                               "--filter", "label=com.docker.compose.service=web", "--format", "{{.ID}}"],
                              timeout=10).decode().splitlines()
        if len(ids) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", ids[0]):
            return False
        projection = '{"Mounts":{{json .Mounts}},"NetworkSettings":{{json .NetworkSettings}}}'
        value = json.loads(self.shared.run(["docker", "inspect", "--format", projection, ids[0]], timeout=10))
        require(isinstance(value, dict), "COMMAND_FAILED")
        mounts = [item for item in value.get("Mounts", []) if item.get("Destination") in
                  {"/etc/caddy/local", "/etc/caddy/public"}]
        if state is None:
            mounted = not mounts
        else:
            source = str(self.path(LOCAL + "/generations/" + state["generation"] + "/caddy"))
            mounted = (len(mounts) == 1 and mounts[0].get("Destination") == "/etc/caddy/local" and
                       mounts[0].get("Source") == source and mounts[0].get("RW") is False)
        bindings = value.get("NetworkSettings", {}).get("Ports", {}) or {}
        actual = {(port, binding.get("HostIp"), binding.get("HostPort"))
                  for port, rows in bindings.items() for binding in rows or []}
        expected = {("8080/tcp", "127.0.0.1", "8766"), ("8443/tcp", "127.0.0.1", "8767")}
        network = value.get("NetworkSettings", {}).get("Networks", {}) or {}
        private_ip = any(item.get("IPAddress") == "172.30.253.10" for item in network.values())
        return mounted and actual == expected and private_ip

    def panel_health(self, config):
        try:
            self.shared.run([sys.executable, "-I", "-c", PANEL_HEALTH,
                             config["panel_path"], config["root_behavior"]], timeout=45)
        except (OSError, ValueError, public.PublicWebError) as error:
            raise LocalWebError("LOCAL_UNHEALTHY") from error

    def restore(self, previous):
        if previous is not None:
            self.shared.atomic(LOCAL + "/state.json", encode(previous))
        self.start(previous)
        require(self.runtime_matches(previous), "ROLLBACK_FAILED")
        self.local_health()
        if previous is not None:
            self.panel_health(previous["config"])
        else:
            self.remove_state()

    def remove_state(self):
        with contextlib.suppress(FileNotFoundError):
            self.path(LOCAL + "/state.json").unlink()
        if self.path(LOCAL).is_dir():
            self.shared.sync_directory(self.path(LOCAL))

    def apply(self, config, expected, expected_source, *, lock_held=False):
        config, expected = validate_config(config), validate_expected(expected)
        require(isinstance(expected_source, str) and HASH.fullmatch(expected_source), "INVALID_REQUEST")
        with contextlib.nullcontext() if lock_held else self.shared.lock():
            return self._apply_locked(config, expected, expected_source)

    def _apply_locked(self, config, expected, expected_source):
        preview = self.preview(config)
        require(preview["source_manifest_sha256"] == expected_source, "STATE_CHANGED")
        previous, current_sha = self.state()
        require(expected == current_sha, "STATE_CHANGED")
        if not preview["changed"]:
            if not self.runtime_matches(previous):
                self.validate_compose(previous)
                self.start(previous)
                require(self.runtime_matches(previous), "COMMAND_FAILED")
            self.local_health()
            self.panel_health(config)
            return {**preview, "enabled": True, "changed": False}
        if previous is None:
            require(self.runtime_matches(None), "UNMANAGED")
        candidate = self.create_generation(config)
        self.validate_compose(candidate)
        self.shared.atomic(LOCAL + "/state.json", encode(candidate))
        try:
            self.start(candidate)
            require(self.runtime_matches(candidate), "COMMAND_FAILED")
            self.local_health()
            self.panel_health(config)
        except Exception as error:
            try:
                self.restore(previous)
            except Exception as rollback_error:
                raise LocalWebError("ROLLBACK_FAILED") from rollback_error
            if isinstance(error, LocalWebError):
                raise error
            raise LocalWebError("COMMAND_FAILED") from error
        _state, current_sha = self.state()
        return {**preview, "expected_state_sha256": current_sha,
                "enabled": True, "changed": True}

    def refresh(self, *, lock_held=False):
        with contextlib.nullcontext() if lock_held else self.shared.lock():
            source_sha = self.source()
            current, state_sha = self.state()
            require(current is not None, "STATE_CHANGED")
            return self._apply_locked(current["config"], state_sha, source_sha)

    def disable(self, expected):
        expected = validate_expected(expected)
        with self.shared.lock():
            self.source()
            self.public_inactive()
            previous, state_sha = self.state()
            require(state_sha == expected, "STATE_CHANGED")
            if previous is None:
                return {"protocol": 1, "ok": True, "enabled": False,
                        "changed": False, "expected_state_sha256": None}
            try:
                self.start(None)
                require(self.runtime_matches(None), "COMMAND_FAILED")
                self.local_health()
                self.remove_state()
            except Exception as error:
                try:
                    self.restore(previous)
                except Exception as rollback_error:
                    raise LocalWebError("ROLLBACK_FAILED") from rollback_error
                if isinstance(error, LocalWebError):
                    raise error
                raise LocalWebError("COMMAND_FAILED") from error
            return {"protocol": 1, "ok": True, "enabled": False,
                    "changed": True, "expected_state_sha256": None}


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        require(os.geteuid() == 0, "ROOT_REQUIRED")
        require(len(args) == 1 and args[0] in
                ("status", "preview", "apply", "disable", "compose-overlay", "refresh"), "INVALID_REQUEST")
        helper = LocalWeb()
        action = args[0]
        if action in ("preview", "apply", "disable"):
            request = decode(sys.stdin.buffer.read(4097))
            fields = ({"config"} if action == "preview" else
                      {"config", "expected_state_sha256", "source_manifest_sha256"} if action == "apply" else
                      {"expected_state_sha256"})
            require(set(request) == fields, "INVALID_REQUEST")
            result = (helper.preview(request["config"]) if action == "preview" else
                      helper.apply(request["config"], request["expected_state_sha256"],
                                   request["source_manifest_sha256"]) if action == "apply" else
                      helper.disable(request["expected_state_sha256"]))
        elif action == "refresh":
            result = helper.refresh(lock_held=os.environ.get("SOVAGRID_PUBLIC_WEB_LOCK_HELD") == "1")
        else:
            helper.source()
            state, state_sha = helper.state()
            if action == "compose-overlay":
                print(helper.overlay(state) or "")
                return 0
            result = {"protocol": 1, "ok": True, "enabled": state is not None,
                      "config": state["config"] if state else None,
                      "expected_state_sha256": state_sha}
        sys.stdout.buffer.write(encode(result))
        return 0
    except (LocalWebError, public.PublicWebError, OSError, ValueError, TypeError, KeyError) as error:
        code = (error.code if isinstance(error, LocalWebError) else
                error.code if isinstance(error, public.PublicWebError) and error.code in ERRORS else
                "COMMAND_FAILED")
        sys.stdout.buffer.write(encode({"protocol": 1, "ok": False,
                                        "error": {"code": code, "message": ERRORS[code]}}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
