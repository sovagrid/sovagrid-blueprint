#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Explicit public HTTPS for an existing managed Web container; no credentials.

JSON stdin: preview/apply accept config and expected_state_sha256 (apply only).
Disable accepts expected_state_sha256. Status, validate-state and refresh take no input.
compose-overlay prints only a validated owned overlay path for run.sh.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import string
import subprocess
import sys
import threading
import uuid


PUBLIC = "/etc/sovagrid/public-web"
LOCAL_WEB = "/etc/sovagrid/local-web"
SOURCE = "/opt/sovagrid-src"
DEFAULT_PANEL_PATH = "/sovagrid/monitoring/"
ROOT_BEHAVIORS = {"untouched", "panel", "redirect", "not_found"}
SSH_GATEWAY_MARKER = "/var/lib/sovagrid/.ssh-gateway-managed-by-run-sh"
COMPONENTS = {"sovagrid-blueprint", "sovagrid-hub", "sovagrid-web", "sovagrid-agent", "sovagrid-vpn"}
GENERATION = re.compile(r"[0-9a-f]{32}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
REQUIRED = {
    "sovagrid-blueprint/run.sh", "sovagrid-blueprint/deploy/compose.yaml",
    "sovagrid-blueprint/deploy/public_web.py",
    "sovagrid-blueprint/deploy/public-web.site.template",
    "sovagrid-blueprint/deploy/compose.public-web.template",
    "sovagrid-web/deploy/Caddyfile.container", "sovagrid-web/Dockerfile",
}
PIN = "caddy:2.11.7-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f"
IMPORTS = ("import /etc/caddy/public/global/*.options", "import /etc/caddy/public/sites/*.caddy",
           "import /etc/caddy/public/local/*.caddy")
ACTIVE_PROCESS = None
ERRORS = {
    "INVALID_REQUEST": "Неверные настройки публичного адреса.",
    "UNMANAGED": "Нужна исправная установка SovaGrid под управлением установщика.",
    "SOURCE_UNTRUSTED": "Установленные исходники изменились или не поддерживают HTTPS.",
    "STATE_UNTRUSTED": "Настройки публичного доступа изменены вне SovaGrid.",
    "STATE_CHANGED": "Настройки изменились. Обновите предварительный просмотр.",
    "LOCAL_ACTIVE": "Локальный путь панели уже настроен. Сначала отключите локальный режим.",
    "ADDRESS_NOT_LOCAL": "Адрес должен указывать на публичный IP этого сервера.",
    "IPV6_UNAVAILABLE": "Публичный доступ этой установки работает по IPv4. Используйте IPv4 или домен без AAAA.",
    "PORT_BUSY": "Порт 80 или 443 занят другой службой.",
    "COMMAND_FAILED": "Не удалось проверить или применить конфигурацию Web.",
    "LOCAL_UNHEALTHY": "Локальные каналы Web или Agent не отвечают.",
    "PUBLIC_UNHEALTHY": "Публичный сертификат или панель пока недоступны.",
    "ROLLBACK_FAILED": "Не удалось подтвердить восстановление Web. Требуется повторная проверка.",
    "BUSY": "Другая операция с публичным доступом ещё выполняется.",
    "ROOT_REQUIRED": "Операция требует прав администратора сервера.",
}

PUBLIC_HEALTH_SCRIPT = r'''
import ssl, sys, time, urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
context = ssl.create_default_context()
if sys.argv[2] == 'staging':
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect,
                                    urllib.request.HTTPSHandler(context=context))
for attempt in range(30):
    try:
        with opener.open(sys.argv[1] + '/healthz', timeout=3) as response:
            if response.status == 200 and len(response.read(8193)) <= 8192:
                sys.exit(0)
    except (OSError, ValueError):
        pass
    time.sleep(1)
sys.exit(1)
'''

PUBLIC_PANEL_HEALTH_SCRIPT = r'''
import ssl, sys, time, urllib.error, urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
origin, environment, panel_path, root_behavior = sys.argv[1:5]
context = ssl.create_default_context()
if environment == 'staging':
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect,
                                    urllib.request.HTTPSHandler(context=context))
for attempt in range(5):
    try:
        with opener.open(origin + panel_path, timeout=4) as response:
            if response.status != 200 or not response.headers.get('Content-Type', '').startswith('text/html'):
                raise ValueError('panel route unavailable')
            page = response.read(262145)
        if len(page) > 262144 or b'id="sshLoginMode"' not in page or b'id="browserSshView"' not in page:
            raise ValueError('SSH-first panel missing')
        for path in {panel_path, '/sovagrid/monitoring/'}:
            with opener.open(origin + path + 'sw.js', timeout=4) as response:
                if response.status != 200 or 'javascript' not in response.headers.get('Content-Type', ''):
                    raise ValueError('service worker unavailable')
                worker = response.read(65537)
            if len(worker) > 65536 or b'addEventListener' not in worker:
                raise ValueError('service worker route is not JavaScript')
        try:
            with opener.open(origin + '/', timeout=4) as response:
                root_status, root_location = response.status, response.headers.get('Location')
        except urllib.error.HTTPError as error:
            root_status, root_location = error.code, error.headers.get('Location')
        # With no SovaGrid root handler, this dedicated public site naturally
        # returns Caddy's 404. The loopback listener keeps its pre-existing /.
        expected = {'untouched': 404, 'panel': 200, 'redirect': 308, 'not_found': 404}[root_behavior]
        if root_status != expected:
            raise ValueError('unexpected root behavior')
        if root_behavior == 'redirect' and root_location not in (panel_path, origin + panel_path):
            raise ValueError('wrong root redirect')
        sys.exit(0)
    except (OSError, ValueError, UnicodeError):
        time.sleep(1)
sys.exit(1)
'''

PUBLIC_SSH_HEALTH_SCRIPT = r'''
import json, re, ssl, sys, time, urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
origin, panel_path = sys.argv[1], sys.argv[3]
context = ssl.create_default_context()
if sys.argv[2] == 'staging':
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect,
                                    urllib.request.HTTPSHandler(context=context))
for attempt in range(5):
    try:
        request = urllib.request.Request(origin + '/api/v1/browser-ssh/host-key',
            data=b'{}', method='POST',
            headers={'Content-Type': 'application/json', 'Origin': origin})
        with opener.open(request, timeout=4) as response:
            if response.status != 200:
                raise ValueError('unexpected status')
            raw = response.read(513)
        if len(raw) > 512:
            raise ValueError('oversized reply')
        value = json.loads(raw)
        if (not isinstance(value, dict) or set(value) != {'protocol', 'port', 'key_type', 'fingerprint'} or
                value['protocol'] != 1 or type(value['port']) is not int or
                not 1 <= value['port'] <= 65535 or not isinstance(value['key_type'], str) or
                not value['key_type'] or not isinstance(value['fingerprint'], str) or
                re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', value['fingerprint']) is None):
            raise ValueError('invalid host key')
        with opener.open(origin + panel_path, timeout=4) as response:
            if response.status != 200 or not response.headers.get('Content-Type', '').startswith('text/html'):
                raise ValueError('panel route unavailable')
            page = response.read(262145)
        if len(page) > 262144 or b'id="sshLoginMode"' not in page or b'id="browserSshView"' not in page:
            raise ValueError('SSH-first panel missing')
        sys.exit(0)
    except (OSError, ValueError, UnicodeError):
        time.sleep(1)
sys.exit(1)
'''

LOCAL_HEALTH_SCRIPT = r'''
import ssl, sys, time, urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
deadline = time.monotonic() + 30.0
context = ssl.create_default_context(cafile=sys.argv[1])
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect,
                                    urllib.request.HTTPSHandler(context=context))
urls = ('http://127.0.0.1:8766/healthz', 'https://localhost:8767/healthz')
while time.monotonic() < deadline:
    ready = True
    for url in urls:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            sys.exit(1)
        try:
            with opener.open(url, timeout=min(3.0, remaining)) as response:
                if response.status != 200 or len(response.read(8193)) > 8192:
                    ready = False
        except (OSError, ValueError):
            ready = False
    if ready and time.monotonic() <= deadline:
        sys.exit(0)
    remaining = deadline - time.monotonic()
    if remaining > 0:
        time.sleep(min(0.25, remaining))
sys.exit(1)
'''


class PublicWebError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(ERRORS[code])


def require(value, code="STATE_UNTRUSTED"):
    if not value:
        raise PublicWebError(code)


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "INVALID_REQUEST")
        result[key] = value
    return result


def constant(_value):
    raise PublicWebError("INVALID_REQUEST")


def decode(raw, limit=4096):
    require(isinstance(raw, bytes) and len(raw) <= limit, "INVALID_REQUEST")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=constant)
        require(isinstance(value, dict), "INVALID_REQUEST")
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            require(depth <= 32, "INVALID_REQUEST")
            if isinstance(item, dict):
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
        return value
    except (UnicodeError, ValueError, RecursionError) as error:
        raise PublicWebError("INVALID_REQUEST") from error


def validate_config(value):
    required = {"mode", "address", "acme_environment"}
    allowed = required | {"panel_path", "root_behavior"}
    require(isinstance(value, dict) and required <= set(value) <= allowed, "INVALID_REQUEST")
    mode, address, environment = value["mode"], value["address"], value["acme_environment"]
    panel_path = value.get("panel_path", DEFAULT_PANEL_PATH)
    root_behavior = value.get("root_behavior", "panel")
    require(mode in ("ip", "dns") and isinstance(address, str) and 1 <= len(address) <= 253
            and environment in ("production", "staging"), "INVALID_REQUEST")
    require(isinstance(panel_path, str) and len(panel_path) <= 96 and
            re.fullmatch(r"/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/){1,3}", panel_path) is not None and
            panel_path.split("/")[1] not in {"api", "healthz"} and
            isinstance(root_behavior, str) and root_behavior in ROOT_BEHAVIORS, "INVALID_REQUEST")
    if mode == "ip":
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as error:
            raise PublicWebError("INVALID_REQUEST") from error
        require(ip.is_global and not ip.is_multicast and not getattr(ip, "ipv4_mapped", None)
                and ip.compressed == address, "INVALID_REQUEST")
    else:
        labels = address.split(".")
        require(address.isascii() and address == address.lower() and 2 <= len(labels)
                and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
                and re.fullmatch(r"[a-z][a-z0-9-]*", labels[-1])
                and not address.endswith((".local", ".localhost", ".internal", ".test", ".invalid", ".example")),
                "INVALID_REQUEST")
    return {**value, "panel_path": panel_path, "root_behavior": root_behavior}


def validate_expected(value):
    require(value is None or isinstance(value, str) and HASH.fullmatch(value), "INVALID_REQUEST")
    return value


def render(config, generation_dir, site_template, compose_template):
    config = validate_config(config)
    address = config["address"]
    panel_path = config["panel_path"]
    panel_prefix = panel_path[:-1]
    root_behavior = config["root_behavior"]
    paths = {panel_path, DEFAULT_PANEL_PATH}
    panel_routes = "".join(
        f"    redir {path[:-1]} {path} 308\n"
        f"    handle_path {path[:-1]}/* {{\n"
        "        root * /srv\n"
        "        try_files {path} /index.html\n"
        "        file_server\n"
        "    }\n"
        for path in sorted(paths, key=lambda value: (-len(value), value)))
    panel_handler = ("    root * /srv\n"
                     "    try_files {path} /index.html\n"
                     "    file_server\n")
    if root_behavior == "panel":
        root_route = "    handle {\n" + panel_handler + "    }\n"
        local_root = ""
    elif root_behavior == "redirect":
        root_route = (f"    redir / {panel_path} 308\n"
                      "    handle {\n        respond 404\n    }\n")
        local_root = f"redir / {panel_path} 308\n"
    elif root_behavior == "not_found":
        root_route = "    handle {\n        respond 404\n    }\n"
        local_root = "handle / {\n    respond 404\n}\n"
    else:
        # Leave / to the host's other routing/default handling. The local
        # listener's existing root is likewise left alone. This public
        # virtual host has no other catchall, so an explicit 404 prevents
        # Caddy's empty implicit 200 for unknown paths.
        root_route = "    handle {\n        respond 404\n    }\n"
        local_root = ""
    local_route = "# SovaGrid generated local panel route\n"
    if panel_path != DEFAULT_PANEL_PATH:
        local_route += (f"redir {panel_prefix} {panel_path} 308\n"
                        f"handle_path {panel_prefix}/* {{\n"
                        "    root * /srv\n"
                        "    try_files {path} /index.html\n"
                        "    file_server\n"
                        "}\n")
    local_route += local_root
    site = f"[{address}]" if ":" in address else address
    issuer = ("https://acme-v02.api.letsencrypt.org/directory" if config["acme_environment"] == "production"
              else "https://acme-staging-v02.api.letsencrypt.org/directory")
    return {
        # HTTP/3 would advertise the internal high port and needs an additional
        # UDP publication. HTTP/1.1 and HTTP/2 provide the complete Web API.
        "caddy/global/public.options": (f"default_sni {address}\n" + "servers :9443 {\n    protocols h1 h2\n}\n").encode(),
        "caddy/sites/public.caddy": string.Template(site_template).substitute(
            site=site, issuer=issuer, profile="            profile shortlived\n" if config["mode"] == "ip" else "",
            panel_routes=panel_routes, root_route=root_route).encode(),
        "caddy/local/panel.caddy": local_route.encode(),
        "compose.yaml": string.Template(compose_template).substitute(caddy_dir=generation_dir + "/caddy").encode(),
    }


class Runner:
    """Fixed local tools, finite runtime/output, never return command output to UI."""
    def __call__(self, argv, timeout=45):
        global ACTIVE_PROCESS
        try:
            environment = dict(os.environ)
            # This is a fixed public pathname, never the Telegram credential.
            environment["SOVAGRID_BOT_TOKEN_FILE"] = "/etc/sovagrid-hub/bot.token"
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, start_new_session=True, env=environment, bufsize=0)
            ACTIVE_PROCESS = process
        except OSError as error:
            raise PublicWebError("COMMAND_FAILED") from error
        data = bytearray()
        overflow = threading.Event()

        def read():
            while True:
                try:
                    block = process.stdout.read(65536)
                except (OSError, ValueError):
                    return
                if not block:
                    return
                if len(data) + len(block) > 1024 * 1024:
                    overflow.set()
                    process.kill()
                    return
                data.extend(block)

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        try:
            status = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            os.killpg(process.pid, 9)
            process.wait()
            raise PublicWebError("COMMAND_FAILED") from error
        finally:
            reader.join(2)
            if reader.is_alive():
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, 9)
                reader.join(2)
            incomplete = reader.is_alive()
            # Raw FileIO has no BufferedReader lock: an escaped descendant may
            # retain the pipe, but close must never hold the operation lock.
            process.stdout.close()
            ACTIVE_PROCESS = None
        require(status == 0 and not overflow.is_set() and not incomplete, "COMMAND_FAILED")
        return bytes(data)


def interrupted(_number, _frame):
    # SSH disconnect/GUI cancellation must not release the shared update lock
    # while an orphaned Compose client is still changing containers. A write
    # may already have committed; the GUI always reconciles status afterwards.
    process = ACTIVE_PROCESS
    if process is not None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(2)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(2)
    raise InterruptedError("public Web operation interrupted")


class PublicWeb:
    def __init__(self, root="/", *, uid=0, runner=None):
        # A non-/ root and UID are dependency injection for disposable tests only.
        self.root, self.uid = Path(root), uid
        self.run = runner or Runner()

    def path(self, absolute):
        require(isinstance(absolute, str) and absolute.startswith("/") and ".." not in absolute.split("/"))
        return self.root / absolute.lstrip("/")

    def check(self, absolute, *, directory=False, private=False, limit=1024 * 1024):
        path = self.path(absolute)
        relative = path.relative_to(self.root)
        for ancestor in [self.root / Path(*relative.parts[:i]) for i in range(1, len(relative.parts))]:
            info = ancestor.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == self.uid and not info.st_mode & 0o022)
        info = path.lstat()
        require(info.st_uid == self.uid and not info.st_mode & 0o022
                and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1))
        if private:
            require(stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600))
        if not directory:
            require(info.st_size <= limit)
            return path.read_bytes()
        return None

    def source(self):
        try:
            require(self.check("/var/lib/sovagrid/.managed-by-run-sh", private=True) is not None, "UNMANAGED")
            root = self.path(SOURCE)
            self.check(SOURCE, directory=True)
            raw = self.check(SOURCE + "/sovagrid-bundle.json", limit=512 * 1024)
            manifest = decode(raw, 512 * 1024)
            require(set(manifest) == {"format", "components", "sha256"} and manifest["format"] == 1
                    and type(manifest["format"]) is int and isinstance(manifest["sha256"], dict)
                    and set(manifest["components"]) == COMPONENTS and REQUIRED <= set(manifest["sha256"]), "SOURCE_UNTRUSTED")
            require(set(p.name for p in root.iterdir()) == COMPONENTS | {"sovagrid-bundle.json"}, "SOURCE_UNTRUSTED")
            actual = set()
            for parent, dirs, files in os.walk(root, followlinks=False):
                for name in dirs:
                    self.check("/" + (Path(parent) / name).relative_to(self.root).as_posix(), directory=True)
                for name in files:
                    relative = (Path(parent) / name).relative_to(root).as_posix()
                    data = self.check(SOURCE + "/" + relative, limit=8 * 1024 * 1024)
                    if relative != "sovagrid-bundle.json":
                        require(HASH.fullmatch(str(manifest["sha256"].get(relative, "")))
                                and digest(data) == manifest["sha256"][relative], "SOURCE_UNTRUSTED")
                        actual.add(relative)
            require(actual == set(manifest["sha256"]), "SOURCE_UNTRUSTED")
            require(b"# SOVAGRID_PUBLIC_WEB_V1" in self.check(SOURCE + "/sovagrid-blueprint/run.sh")
                    and all(value.encode() in self.check(SOURCE + "/sovagrid-web/deploy/Caddyfile.container") for value in IMPORTS)
                    and PIN.encode() in self.check(SOURCE + "/sovagrid-web/Dockerfile"), "SOURCE_UNTRUSTED")
            return digest(raw)
        except (OSError, KeyError, TypeError, PublicWebError) as error:
            raise PublicWebError("SOURCE_UNTRUSTED") from error

    def templates(self):
        return (self.check(SOURCE + "/sovagrid-blueprint/deploy/public-web.site.template").decode(),
                self.check(SOURCE + "/sovagrid-blueprint/deploy/compose.public-web.template").decode())

    def ssh_gateway_managed(self):
        if not os.path.lexists(self.path(SSH_GATEWAY_MARKER)):
            return False
        require(self.check(SSH_GATEWAY_MARKER, private=True) == b"SOVAGRID_SSH_GATEWAY_V1\n")
        return True

    def local_web_inactive(self):
        # Separate local-only ownership must be released before this helper
        # installs a public overlay with its own loopback route. A broken or
        # foreign local directory must never be silently ignored.
        if not os.path.lexists(self.path(LOCAL_WEB)):
            return
        try:
            self.check(LOCAL_WEB, directory=True, private=True)
            require(self.check(LOCAL_WEB + "/.managed", private=True) == b"SOVAGRID_LOCAL_WEB_V1\n")
            require(not os.path.lexists(self.path(LOCAL_WEB + "/state.json")), "LOCAL_ACTIVE")
        except OSError as error:
            raise PublicWebError("STATE_UNTRUSTED") from error

    def state(self):
        try:
            if not os.path.lexists(self.path(PUBLIC)):
                return None, None
            self.check(PUBLIC, directory=True, private=True)
            require(self.check(PUBLIC + "/.managed", private=True) == b"SOVAGRID_PUBLIC_WEB_V1\n")
            if not os.path.lexists(self.path(PUBLIC + "/state.json")):
                return None, None
            raw = self.check(PUBLIC + "/state.json", private=True, limit=4096)
            value = decode(raw)
            require(set(value) == {"protocol", "generation", "config", "sha256"} and value["protocol"] == 1
                    and type(value["protocol"]) is int and isinstance(value["generation"], str)
                    and GENERATION.fullmatch(value["generation"]) and isinstance(value["sha256"], dict))
            # Older approved generations contain only the three original
            # address fields/files. Keep their root page behavior on refresh.
            value["config"] = validate_config(value["config"])
            generation = PUBLIC + "/generations/" + value["generation"]
            self.check(generation, directory=True, private=True)
            # A generation is immutable. A later package may improve templates;
            # updates must retain the already-approved public configuration.
            names = {"caddy/global/public.options", "caddy/sites/public.caddy", "compose.yaml"}
            new_names = names | {"caddy/local/panel.caddy"}
            require(set(value["sha256"]) in (names, new_names))
            for name in value["sha256"]:
                require(isinstance(value["sha256"][name], str) and HASH.fullmatch(value["sha256"][name])
                        and digest(self.check(generation + "/" + name)) == value["sha256"][name])
            return value, digest(raw)
        except (OSError, KeyError, TypeError, UnicodeError, PublicWebError) as error:
            raise PublicWebError("STATE_UNTRUSTED") from error

    def overlay(self, state=None):
        if state is None:
            state, _ = self.state()
        return PUBLIC + "/generations/" + state["generation"] + "/compose.yaml" if state else None

    def compose(self, state=None):
        # Preserve Telegram's existing opt-in overlay too. Fixed paths, no shell.
        args = ["docker", "compose", "--env-file", str(self.path("/etc/sovagrid/deploy.env")),
                "-f", str(self.path(SOURCE + "/sovagrid-blueprint/deploy/compose.yaml"))]
        token = self.path("/etc/sovagrid-hub/bot.token")
        if os.path.lexists(token):
            self.check("/etc/sovagrid-hub/bot.token", limit=4096)
            args += ["-f", str(self.path(SOURCE + "/sovagrid-blueprint/deploy/compose.telegram.yaml"))]
        if state:
            args += ["-f", str(self.path(self.overlay(state)))]
        return args

    def local_health(self):
        try:
            self.check("/etc/sovagrid/hub-ca.pem", limit=16384)
            # Compose returns before Caddy/its localhost certificate is ready.
            # Both channels must pass in the same polling round. A separate
            # process bounds NSS/DNS and slow streaming bodies, beyond socket
            # timeouts, while preserving strict private-CA/hostname validation.
            self.run([sys.executable, "-I", "-c", LOCAL_HEALTH_SCRIPT,
                      str(self.path("/etc/sovagrid/hub-ca.pem"))], timeout=35)
        except (OSError, ValueError) as error:
            raise PublicWebError("LOCAL_UNHEALTHY") from error

    def address_check(self, config):
        try:
            local = json.loads(self.run(["ip", "-j", "address", "show"], timeout=10))
            addresses = {ipaddress.ip_address(row["local"]).compressed for iface in local
                         for row in iface.get("addr_info", []) if row.get("scope") == "global"}
            if config["mode"] == "ip":
                require(config["address"] in addresses, "ADDRESS_NOT_LOCAL")
            else:
                # getaddrinfo runs in a bounded child, never an unbounded GUI DNS call.
                result = self.run([sys.executable, "-I", "-c",
                    "import json,socket,sys; print(json.dumps(sorted({r[4][0] for r in socket.getaddrinfo(sys.argv[1],443,type=socket.SOCK_STREAM)})))",
                    config["address"]], timeout=10)
                resolved = json.loads(result)
                require(isinstance(resolved, list), "ADDRESS_NOT_LOCAL")
                require(not any(isinstance(ip, str) and ipaddress.ip_address(ip).version == 6 for ip in resolved), "IPV6_UNAVAILABLE")
                require(isinstance(resolved, list) and resolved and all(
                    isinstance(ip, str) and ipaddress.ip_address(ip).is_global and ip in addresses for ip in resolved), "ADDRESS_NOT_LOCAL")
        except (OSError, ValueError, KeyError, TypeError) as error:
            if isinstance(error, PublicWebError):
                raise
            raise PublicWebError("ADDRESS_NOT_LOCAL") from error

    def ports(self, current):
        ids = self.run(["docker", "ps", "--format", "{{.ID}}"], timeout=10).decode("ascii").splitlines()
        require(len(ids) <= 1024, "PORT_BUSY")
        owned = set()
        for container in ids:
            require(re.fullmatch(r"[0-9a-f]{12,64}", container), "COMMAND_FAILED")
        # One bounded batch, rather than a separate 10s budget per container.
        # Avoid reading other applications' environment variables or secrets.
        projection = '{"Config":{"Labels":{{json .Config.Labels}}},"NetworkSettings":{"Ports":{{json .NetworkSettings.Ports}}}}'
        raw = self.run(["docker", "inspect", "--format", projection, *ids], timeout=10) if ids else b""
        records = [json.loads(line) for line in raw.splitlines()]
        require(isinstance(records, list) and len(records) == len(ids), "COMMAND_FAILED")
        for record in records:
            labels = record.get("Config", {}).get("Labels", {}) or {}
            web = labels.get("com.docker.compose.project") == "sovagrid" and labels.get("com.docker.compose.service") == "web"
            for internal, bindings in (record.get("NetworkSettings", {}).get("Ports", {}) or {}).items():
                for binding in bindings or []:
                    port = binding.get("HostPort")
                    if port in ("80", "443"):
                        require(current is not None and web and internal == {"80": "9080/tcp", "443": "9443/tcp"}[port]
                                and binding.get("HostIp") == "0.0.0.0", "PORT_BUSY")
                        owned.add(int(port))
        for port in (80, 443):
            if port in owned:
                continue
            for family, host in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
                try:
                    with socket.socket(family) as listener:
                        if family == socket.AF_INET6:
                            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        listener.bind((host, port))
                except OSError as error:
                    # IPv6 may be disabled. IPv4 conflicts must always fail closed.
                    if family == socket.AF_INET6 and error.errno in (97, 99):
                        continue
                    raise PublicWebError("PORT_BUSY") from error

    def preview(self, config):
        config = validate_config(config)
        require(not (config["mode"] == "ip" and ipaddress.ip_address(config["address"]).version == 6), "IPV6_UNAVAILABLE")
        self.local_web_inactive()
        source_sha = self.source()
        current, current_sha = self.state()
        self.local_health()
        self.address_check(config)
        self.ports(current)
        template_changed = current is not None and not self.generation_matches_templates(current)
        return {"protocol": 1, "ok": True, "config": config, "expected_state_sha256": current_sha,
                "source_manifest_sha256": source_sha, "changed": current is None or current["config"] != config or template_changed,
                "url": self.url(config), "certificate_verified": False}

    def generation_matches_templates(self, state):
        """Compare the approved generation with rendering at its own path."""
        generation = PUBLIC + "/generations/" + state["generation"]
        current = render(state["config"], generation, *self.templates())
        return {name: digest(raw) for name, raw in current.items()} == state["sha256"]

    @staticmethod
    def url(config):
        address = config["address"]
        return "https://" + (f"[{address}]" if ":" in address else address)

    def mkdir(self, absolute, mode=0o700):
        path = self.path(absolute)
        if os.path.lexists(path):
            self.check(absolute, directory=True)
            require(stat.S_IMODE(path.lstat().st_mode) == mode)
        else:
            path.mkdir(mode=mode)
            path.chmod(mode)
            self.check(absolute, directory=True)
            self.sync_directory(path.parent)

    @staticmethod
    def sync_directory(directory):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def atomic(self, absolute, raw, mode=0o600):
        parent = self.path(absolute).parent
        temporary = parent / (".write-" + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path(absolute))
            self.sync_directory(parent)
        finally:
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()

    @contextlib.contextmanager
    def lock(self):
        # /etc/sovagrid is already managed. Preview never creates this lock.
        self.check("/var/lib/sovagrid", directory=True)
        # Outside updater snapshots: restoring /etc/sovagrid must not replace
        # the inode of a held lock and admit a concurrent HTTPS operation.
        path = "/var/lib/sovagrid/.public-web.lock"
        descriptor = os.open(self.path(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            self.check(path, private=True)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise PublicWebError("BUSY") from error
            yield
        finally:
            os.close(descriptor)

    def create_generation(self, config):
        if not os.path.lexists(self.path(PUBLIC)):
            # Publish ownership atomically: interruption between mkdir and the
            # marker must not leave an unowned directory that GUI cannot retry.
            temporary = "/etc/sovagrid/.public-web-init-" + uuid.uuid4().hex
            self.mkdir(temporary)
            self.atomic(temporary + "/.managed", b"SOVAGRID_PUBLIC_WEB_V1\n")
            require(not os.path.lexists(self.path(PUBLIC)))
            os.rename(self.path(temporary), self.path(PUBLIC))
            self.sync_directory(self.path(PUBLIC).parent)
        self.mkdir(PUBLIC + "/generations")
        generation = uuid.uuid4().hex
        base = PUBLIC + "/generations/" + generation
        self.mkdir(base)
        for relative in ("caddy", "caddy/global", "caddy/sites", "caddy/local"):
            self.mkdir(base + "/" + relative, 0o755)
        files = render(config, base, *self.templates())
        for name, raw in files.items():
            self.atomic(base + "/" + name, raw, 0o644)
        return {"protocol": 1, "generation": generation, "config": config,
                "sha256": {name: digest(raw) for name, raw in files.items()}}

    def validate_compose(self, state):
        args = self.compose(state)
        self.run(args + ["config", "--quiet"])
        image = self.run(["docker", "image", "inspect", "--format", "{{.Id}}", "sovagrid-web:local"]).decode("ascii").strip()
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", image), "COMMAND_FAILED")
        # compose run inherits the live Web static IP. Use an isolated container
        # instead, with no network and a disposable CA, leaving live storage/IP
        # untouched. Only trusted source and the candidate fragments are mounted.
        self.run(["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "10002:10002",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pids-limit", "128", "--memory", "128m",
                  "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m,uid=10002,gid=10002,mode=0700",
                  "--tmpfs", "/data:rw,nosuid,nodev,noexec,size=16m,uid=10002,gid=10002,mode=0700",
                  "-e", "XDG_DATA_HOME=/data", "-e", "XDG_CONFIG_HOME=/tmp/config",
                  "--mount", "type=bind,src=" + str(self.path(SOURCE + "/sovagrid-web/deploy/Caddyfile.container")) + ",dst=/etc/caddy/Caddyfile,readonly",
                  "--mount", "type=bind,src=" + str(self.path(self.overlay(state)).parent / "caddy") + ",dst=/etc/caddy/public,readonly",
                  image, "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"])

    def start(self, state):
        self.run(self.compose(state) + ["up", "-d", "--no-deps", "web"], timeout=90)

    def runtime_matches(self, state):
        ids = self.run(["docker", "ps", "--filter", "label=com.docker.compose.project=sovagrid",
                        "--filter", "label=com.docker.compose.service=web", "--format", "{{.ID}}"], timeout=10).decode("ascii").splitlines()
        if len(ids) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", ids[0]):
            return False
        projection = '{"Mounts":{{json .Mounts}},"NetworkSettings":{{json .NetworkSettings}}}'
        record = json.loads(self.run(["docker", "inspect", "--format", projection, ids[0]], timeout=10))
        require(isinstance(record, dict), "COMMAND_FAILED")
        mounts = [item for item in record.get("Mounts", []) if item.get("Destination") == "/etc/caddy/public"]
        if state is None:
            mounted = not mounts
        else:
            expected_source = str(self.path(self.overlay(state)).parent / "caddy")
            mounted = len(mounts) == 1 and mounts[0].get("Source") == expected_source and mounts[0].get("RW") is False
        bindings = record.get("NetworkSettings", {}).get("Ports", {}) or {}
        actual_ports = {(port, binding.get("HostIp"), binding.get("HostPort"))
                        for port, rows in bindings.items() for binding in rows or []}
        expected_ports = {("8080/tcp", "127.0.0.1", "8766"), ("8443/tcp", "127.0.0.1", "8767")}
        if state is not None:
            expected_ports |= {("9080/tcp", "0.0.0.0", "80"), ("9443/tcp", "0.0.0.0", "443")}
        network = record.get("NetworkSettings", {}).get("Networks", {}) or {}
        private_ip = any(item.get("IPAddress") == "172.30.253.10" for item in network.values())
        return mounted and actual_ports == expected_ports and private_ip

    def public_health(self, config):
        # Staging is an explicit CA test, with no credentials transmitted. Never
        # call its certificate trusted. Production always uses system PKI.
        # A socket timeout does not bound libc/NSS DNS. The whole poll, including
        # TLS and resolution, runs in a child with an independent wall deadline.
        try:
            self.run([sys.executable, "-I", "-c", PUBLIC_HEALTH_SCRIPT, self.url(config), config["acme_environment"]], timeout=130)
        except PublicWebError as error:
            raise PublicWebError("PUBLIC_UNHEALTHY") from error

    def public_panel_health(self, config):
        try:
            self.run([sys.executable, "-I", "-c", PUBLIC_PANEL_HEALTH_SCRIPT,
                      self.url(config), config["acme_environment"], config["panel_path"],
                      config["root_behavior"]], timeout=45)
        except PublicWebError as error:
            raise PublicWebError("PUBLIC_UNHEALTHY") from error

    def public_ssh_health(self, config):
        try:
            self.run([sys.executable, "-I", "-c", PUBLIC_SSH_HEALTH_SCRIPT,
                      self.url(config), config["acme_environment"], config["panel_path"]], timeout=45)
        except PublicWebError as error:
            raise PublicWebError("PUBLIC_UNHEALTHY") from error

    def restore(self, previous):
        if previous is not None:
            self.atomic(PUBLIC + "/state.json", encode(previous))
        self.start(previous)
        require(self.runtime_matches(previous), "COMMAND_FAILED")
        self.local_health()
        if previous is not None:
            self.public_health(previous["config"])
        else:
            # Never report disabled while a previous public listener may still
            # be live. Commit removal only after closed bindings are verified.
            self.remove_state()

    def remove_state(self):
        with contextlib.suppress(FileNotFoundError):
            self.path(PUBLIC + "/state.json").unlink()
        if self.path(PUBLIC).is_dir():
            self.sync_directory(self.path(PUBLIC))

    def apply(self, config, expected, expected_source):
        config, expected = validate_config(config), validate_expected(expected)
        require(isinstance(expected_source, str) and HASH.fullmatch(expected_source), "INVALID_REQUEST")
        with self.lock():
            return self._apply_locked(config, expected, expected_source)

    def refresh(self, *, lock_held=False):
        """Re-render an already approved public address after a source update."""
        with contextlib.nullcontext() if lock_held else self.lock():
            source_sha = self.source()
            current, state_sha = self.state()
            require(current is not None, "STATE_CHANGED")
            return self._apply_locked(current["config"], state_sha, source_sha,
                                      require_ssh_route=True)

    def _apply_locked(self, config, expected, expected_source, *, require_ssh_route=False):
        preview = self.preview(config)
        require(preview["source_manifest_sha256"] == expected_source, "STATE_CHANGED")
        previous, current_sha = self.state()
        require(expected == current_sha, "STATE_CHANGED")
        if not preview["changed"]:
            # If the client vanished after state commit, the previous site
            # might still answer health on the same address. Check the live
            # immutable generation before accepting that response.
            if not self.runtime_matches(previous):
                self.validate_compose(previous)
                self.start(previous)
                require(self.runtime_matches(previous), "COMMAND_FAILED")
                self.local_health()
            self.public_health(config)
            self.public_panel_health(config)
            if require_ssh_route or self.ssh_gateway_managed():
                self.public_ssh_health(config)
            return {**preview, "enabled": True, "changed": False,
                    "certificate_verified": config["acme_environment"] == "production"}
        candidate = self.create_generation(config)
        self.validate_compose(candidate)
        self.atomic(PUBLIC + "/state.json", encode(candidate))
        try:
            self.start(candidate)
            require(self.runtime_matches(candidate), "COMMAND_FAILED")
            self.local_health()
            self.public_health(config)
            self.public_panel_health(config)
            if require_ssh_route or self.ssh_gateway_managed():
                self.public_ssh_health(config)
        except Exception as error:
            try:
                self.restore(previous)
            except Exception as rollback_error:
                raise PublicWebError("ROLLBACK_FAILED") from rollback_error
            if isinstance(error, PublicWebError):
                raise error
            raise PublicWebError("COMMAND_FAILED") from error
        _, current_sha = self.state()
        return {**preview, "expected_state_sha256": current_sha, "enabled": True, "changed": True,
                "certificate_verified": config["acme_environment"] == "production"}

    def disable(self, expected):
        expected = validate_expected(expected)
        with self.lock():
            self.source()
            previous, current_sha = self.state()
            require(expected == current_sha, "STATE_CHANGED")
            if previous is None:
                if not self.runtime_matches(None):
                    self.start(None)
                    require(self.runtime_matches(None), "COMMAND_FAILED")
                self.local_health()
                return {"protocol": 1, "ok": True, "enabled": False, "changed": False, "expected_state_sha256": None}
            # Keep the last committed state until closed bindings are verified.
            # Lost SSH can never produce a false disabled success/status while
            # the public listener remains live. A retry safely completes removal.
            try:
                self.start(None)
                require(self.runtime_matches(None), "COMMAND_FAILED")
                self.local_health()
                self.remove_state()
            except Exception as error:
                try:
                    self.restore(previous)
                except Exception as rollback_error:
                    raise PublicWebError("ROLLBACK_FAILED") from rollback_error
                if isinstance(error, PublicWebError):
                    raise error
                raise PublicWebError("COMMAND_FAILED") from error
            return {"protocol": 1, "ok": True, "enabled": False, "changed": True, "expected_state_sha256": None}


def main(argv=None):
    action = (sys.argv[1:] if argv is None else argv)
    try:
        require(os.geteuid() == 0, "ROOT_REQUIRED")
        for number in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
            signal.signal(number, interrupted)
        require(len(action) == 1 and action[0] in ("preview", "apply", "disable", "status", "validate-state", "compose-overlay", "refresh"), "INVALID_REQUEST")
        helper = PublicWeb()
        operation = action[0]
        if operation in ("preview", "apply", "disable"):
            value = decode(sys.stdin.buffer.read(4097))
            fields = {"config"} if operation == "preview" else ({"config", "expected_state_sha256", "source_manifest_sha256"} if operation == "apply" else {"expected_state_sha256"})
            require(set(value) == fields, "INVALID_REQUEST")
            result = (helper.preview(value["config"]) if operation == "preview" else
                      helper.apply(value["config"], value["expected_state_sha256"], value["source_manifest_sha256"]) if operation == "apply" else
                      helper.disable(value["expected_state_sha256"]))
        elif operation == "refresh":
            result = helper.refresh(lock_held=os.environ.get("SOVAGRID_PUBLIC_WEB_LOCK_HELD") == "1")
        else:
            helper.source()
            state, state_sha = helper.state()
            if operation == "compose-overlay":
                print(helper.overlay(state) or "")
                return 0
            result = {"protocol": 1, "ok": True, "enabled": state is not None,
                      "config": state["config"] if state else None, "expected_state_sha256": state_sha}
        sys.stdout.buffer.write(encode(result))
        return 0
    except (PublicWebError, OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        code = error.code if isinstance(error, PublicWebError) else "COMMAND_FAILED"
        sys.stdout.buffer.write(encode({"protocol": 1, "ok": False, "error": {"code": code, "message": ERRORS[code]}}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
