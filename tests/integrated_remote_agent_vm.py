#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Install remote Agents through Connect and Web on disposable CI.

Two Ubuntu root filesystems boot with systemd-nspawn and native systemd
credentials. Docker's systemd-in-container mode in this CI setup left LoadCredential empty,
so it cannot verify the production outbound tunnel. The nspawn machines share
only this disposable runner's network namespace and bind distinct SSH ports
on the private Compose bridge. Their files, processes and systemd managers
remain separate. Client identities and host keys exist only for this run.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import uuid


SOURCE = Path("/opt/sovagrid-src")
BLUEPRINT = Path(__file__).resolve().parents[1]
COMPOSE_NETWORK = "sovagrid_private"
COMPOSE_GATEWAY = "172.30.253.1"
MACHINES_ROOT = Path("/var/lib/machines")
CONNECT_PORT = 2222
WEB_PORT = 2223
SSH_CONFIG = Path("/etc/ssh/sshd_config.d/05-sovagrid-ci-listeners.conf")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA1 = re.compile(r"[0-9a-f]{40}\Z")


def require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def ci_guard(state_dir: Path) -> None:
    require(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "Linux",
            "Two-server integration runs only as root on a GitHub-hosted Linux runner")
    parent = Path(os.environ["RUNNER_TEMP"]).resolve()
    require(state_dir.parent.resolve() == parent and state_dir.name == "sovagrid-remote-ci"
            and not state_dir.is_symlink(), "Unexpected CI state path")


def ci_records_dir(state: dict) -> Path:
    """Keep Connect's private journal below a root-owned ancestor, not RUNNER_TEMP."""
    container = state.get("container")
    match = re.fullmatch(r"sovagrid-ci-target-([0-9a-f]{12})", container) if isinstance(container, str) else None
    require(match is not None, "Unexpected disposable target identity")
    return Path("/run/sovagrid-ci-connect-" + match.group(1))


def machine_root(name: str) -> Path:
    require(isinstance(name, str) and
            re.fullmatch(r"sovagrid-ci-(?:web-)?target-[0-9a-f]{12}", name) is not None,
            "Unexpected disposable machine name")
    return MACHINES_ROOT / name


def machine_unit(name: str) -> str:
    machine_root(name)
    return "sovagrid-ci-nspawn-" + name.removeprefix("sovagrid-ci-") + ".service"


def command(*argv: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=300, check=False)
    if check and result.returncode:
        # No command contains a credential. Bound diagnostic output in CI logs.
        detail = result.stderr or result.stdout
        raise RuntimeError(f"{argv[0]} failed ({result.returncode}): {detail[-1200:]}")
    return result


def machine_command(name: str, *argv: str, properties: tuple[str, ...] = (),
                    check: bool = True) -> subprocess.CompletedProcess[str]:
    machine_root(name)
    args = ["systemd-run", "--machine=" + name, "--quiet", "--wait", "--collect", "--pipe"]
    for prop in properties:
        args.extend(("--property", prop))
    return command(*args, *argv, check=check)


def save(state_dir: Path, state: dict) -> None:
    destination = state_dir / "state.json"
    temporary = state_dir / "state.json.tmp"
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(state, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)


def append_line(path: Path, line: str) -> None:
    require(not path.is_symlink(), "Refusing a symlink in the disposable SSH fixture")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_file() and path.stat().st_size and not path.read_bytes().endswith(b"\n"):
        with path.open("ab") as stream:
            stream.write(b"\n")
    with path.open("a", encoding="ascii") as stream:
        stream.write(line + "\n")
    path.chmod(0o600)


def remove_line(path: Path, line: str) -> None:
    if not path.exists():
        return
    require(not path.is_symlink(), "SSH fixture changed into a symlink")
    lines = path.read_text(encoding="ascii").splitlines()
    remaining = [item for item in lines if item != line]
    require(len(lines) - len(remaining) <= 1, "Disposable SSH key entry was duplicated")
    if len(lines) == len(remaining):
        return
    path.write_text("".join(item + "\n" for item in remaining), encoding="ascii")
    path.chmod(0o600)


def host_key_line(host: str, public: str) -> str:
    fields = public.strip().split()
    require(len(fields) >= 2 and fields[0] == "ssh-ed25519", "No ED25519 host key")
    return f"{host} {fields[0]} {fields[1]}"


def network_exists(name: str) -> bool:
    return command("docker", "network", "inspect", name, check=False).returncode == 0


def export_machine(state_dir: Path, state: dict, name: str, port: int) -> Path:
    """Extract only the pinned Ubuntu fixture image into a fresh rootfs."""
    root = machine_root(name)
    require(port in (CONNECT_PORT, WEB_PORT) and not root.exists() and not root.is_symlink(),
            "Disposable Ubuntu rootfs already exists")
    seed = name + "-export"
    state.setdefault("seed_containers", []).append(seed)
    save(state_dir, state)
    root.mkdir(mode=0o755)
    archive = state_dir / (name + ".tar")
    command("docker", "create", "--name", seed, state["image"])
    command("docker", "export", "--output", str(archive), seed)
    command("tar", "-xpf", str(archive), "-C", str(root))
    archive.unlink()
    command("docker", "rm", seed)

    machine_id = root / "etc/machine-id"
    require(not machine_id.is_symlink(), "Ubuntu machine ID is a symlink")
    machine_id.write_text(uuid.uuid4().hex + "\n", encoding="ascii")
    machine_id.chmod(0o644)
    ssh = root / "etc/ssh"
    for host_key in ssh.glob("ssh_host_*"):
        require(host_key.is_file() and not host_key.is_symlink(), "Unexpected Ubuntu SSH host key")
        host_key.unlink()
    # Docker export omits the runtime /dev mounts, so avoid chroot before nspawn
    # boots. OpenSSH's -f prefix writes distinct keys into this exact rootfs.
    command("ssh-keygen", "-A", "-f", str(root))
    policy = ssh / "sshd_config.d/05-sovagrid-ci.conf"
    require(policy.is_file() and not policy.is_symlink(), "Missing fixture SSH policy")
    policy.write_text(
        "# SovaGrid disposable nspawn SSH listener\n"
        f"Port {port}\nListenAddress {COMPOSE_GATEWAY}\n"
        "PermitRootLogin prohibit-password\nPasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\nPubkeyAuthentication yes\n",
        encoding="ascii")
    policy.chmod(0o644)
    authorized = root / "root/.ssh/authorized_keys"
    require(not authorized.exists() and not authorized.is_symlink(), "Unexpected fixture root key")
    authorized.write_text(state["auth_line"] + "\n", encoding="ascii")
    authorized.chmod(0o600)
    # Noble enables ssh.socket with a RequiredBy=ssh.service link. Masking the
    # socket before disabling it leaves ssh.service dependent on a masked unit.
    # Switch this disposable guest to the standalone service first.
    command("systemctl", "--root=" + str(root), "disable", "ssh.socket")
    socket_dependency = root / "etc/systemd/system/ssh.service.requires/ssh.socket"
    require(not socket_dependency.exists() and not socket_dependency.is_symlink(),
            "Ubuntu SSH service still requires the disabled socket")
    for relative in ("ssh.service.d/00-socket.conf", "ssh.socket.d/addresses.conf"):
        socket_dropin = root / "etc/systemd/system" / relative
        if socket_dropin.exists() or socket_dropin.is_symlink():
            require(socket_dropin.is_file() or socket_dropin.is_symlink(),
                    "Unexpected Ubuntu SSH socket drop-in")
            socket_dropin.unlink()
    # nspawn mounts a fresh /run, so the directory created while building the
    # Docker image is not guaranteed to exist when this service starts.
    ssh_runtime_dropin = root / "etc/systemd/system/ssh.service.d/05-sovagrid-ci-runtime.conf"
    require(not ssh_runtime_dropin.exists() and not ssh_runtime_dropin.is_symlink(),
            "Unexpected disposable SSH runtime drop-in")
    ssh_runtime_dropin.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    ssh_runtime_dropin.write_text("[Service]\nRuntimeDirectory=sshd\nRuntimeDirectoryMode=0755\n",
                                  encoding="ascii")
    ssh_runtime_dropin.chmod(0o644)
    # nspawn intentionally shares the runner network namespace so Docker's
    # private bridge reaches both SSH listeners. Guest boot services must not
    # manage its interfaces, DNS, kernel sysctls, modules or clock.
    for unit in ("ssh.socket", "systemd-networkd.service", "systemd-networkd.socket",
                 "systemd-networkd-wait-online.service", "NetworkManager-wait-online.service",
                 "systemd-resolved.service", "systemd-resolved.socket",
                 "systemd-timesyncd.service", "systemd-sysctl.service",
                 "systemd-modules-load.service", "NetworkManager.service",
                 "networking.service", "chrony.service", "ntp.service"):
        command("systemctl", "--root=" + str(root), "mask", "--force", unit)
    command("systemctl", "--root=" + str(root), "enable", "ssh.service")
    return root


def native_credential_probe(name: str) -> None:
    """Reject any nspawn setup that cannot deliver systemd credentials."""
    script = ("import os,pathlib,sys; d=os.environ.get('CREDENTIALS_DIRECTORY',''); "
              "p=pathlib.Path(d)/'ci-probe' if d else None; "
              "sys.exit(0 if p is not None and p.is_file() else 1)")
    result = machine_command(name, "/usr/bin/python3", "-c", script,
                             properties=("User=nobody", "Group=nogroup",
                                         "LoadCredential=ci-probe:/etc/machine-id",
                                         "NoNewPrivileges=true", "ProtectSystem=strict",
                                         "ProtectHome=true", "PrivateTmp=true",
                                         "PrivateDevices=true"), check=False)
    require(result.returncode == 0, "Native Ubuntu systemd did not deliver a private credential")


def start_machine(name: str, port: int) -> None:
    root = machine_root(name)
    require(port in (CONNECT_PORT, WEB_PORT), "Unexpected disposable SSH port")
    require(not command("ss", "-H", "-ltn", "sport = :" + str(port)).stdout.strip(),
            "Disposable Ubuntu SSH port is already occupied")
    command("systemd-run", "--quiet", "--collect", "--unit=" + machine_unit(name),
            "--property=Type=exec", "/usr/bin/systemd-nspawn", "--directory=" + str(root),
            "--machine=" + name, "--boot", "--register=yes", "--keep-unit", "--settings=no",
            "--console=read-only", "--drop-capability=CAP_NET_ADMIN,CAP_SYS_TIME",
            "--link-journal=no", "--resolv-conf=replace-host")
    deadline = time.monotonic() + 75
    unit = machine_unit(name)
    while time.monotonic() < deadline:
        if machine_command(name, "/usr/bin/systemctl", "is-active", "--quiet", "ssh.service",
                           check=False).returncode == 0:
            effective = machine_command(name, "/usr/sbin/sshd", "-T").stdout.splitlines()
            require([item for item in effective if item.startswith("port ")] == [f"port {port}"],
                    "Disposable Ubuntu SSH configuration also listens on the host port")
            native_credential_probe(name)
            listeners = {line.split()[3] for line in
                         command("ss", "-H", "-ltn", "sport = :" + str(port)).stdout.splitlines()}
            require(listeners == {f"{COMPOSE_GATEWAY}:{port}"},
                    "Disposable Ubuntu SSH escaped its private bridge listener")
            return
        state = command("systemctl", "show", unit, "--property=ActiveState", "--value",
                        check=False).stdout.strip()
        if state in ("failed", "inactive"):
            break
        time.sleep(1)
    journal = command("journalctl", "-u", unit, "-n", "24", "--no-pager",
                      "--output=cat", check=False).stdout
    registered = command("machinectl", "show", name, check=False).returncode == 0
    ssh_status = (machine_command(name, "/usr/bin/systemctl", "status", "ssh.service",
                                  "--no-pager", check=False) if registered else None)
    ssh_dependencies = (machine_command(name, "/usr/bin/systemctl", "list-dependencies",
                                        "ssh.service", "--no-pager", "--plain",
                                        check=False) if registered else None)
    details = {
        "unit": command("systemctl", "show", unit,
                        "--property=ActiveState,SubState,Result,ExecMainStatus",
                        check=False).stdout.splitlines()[:8],
        "registered": registered,
        "ssh_listener": command("ss", "-H", "-ltn", "sport = :" + str(port),
                                check=False).stdout.splitlines()[:4],
        "ssh_status": ((ssh_status.stdout + ssh_status.stderr)[-2200:].splitlines()[-16:]
                       if ssh_status else []),
        "ssh_dependencies": ((ssh_dependencies.stdout + ssh_dependencies.stderr)[-1200:].splitlines()[-12:]
                             if ssh_dependencies else []),
        "boot_log": [line[-500:] for line in journal.splitlines()[-16:]],
    }
    print("INTEGRATED_NSPAWN_BOOT_DIAGNOSTIC " + json.dumps(details, sort_keys=True), flush=True)
    raise RuntimeError("Disposable Ubuntu nspawn machine did not start SSH")


def setup(state_dir: Path) -> None:
    require(not state_dir.exists(), "Disposable CI fixture already exists")
    require(not network_exists(COMPOSE_NETWORK), "The Hub Docker network already exists")
    require(not SSH_CONFIG.exists() and not SSH_CONFIG.is_symlink(), "CI SSH policy already exists")
    suffix = uuid.uuid4().hex[:12]
    state = {"container": "sovagrid-ci-target-" + suffix,
             "image": "sovagrid-ci-target:" + suffix,
             "host_service_active": command("systemctl", "is-active", "--quiet", "ssh.service", check=False).returncode == 0,
             "host_socket_active": command("systemctl", "is-active", "--quiet", "ssh.socket", check=False).returncode == 0,
             "host_service_enabled": command("systemctl", "is-enabled", "--quiet", "ssh.service", check=False).returncode == 0,
             "host_socket_enabled": command("systemctl", "is-enabled", "--quiet", "ssh.socket", check=False).returncode == 0,
             "host_sshd_runtime_existed": Path("/run/sshd").exists(),
             "auth_file_existed": Path("/root/.ssh/authorized_keys").exists(),
             "known_hosts_existed": Path("/root/.ssh/known_hosts").exists(),
             "machines_root_existed": MACHINES_ROOT.exists()}
    records = ci_records_dir(state)
    require(not records.exists() and not records.is_symlink(),
            "Disposable Connect journal already exists")
    require(not MACHINES_ROOT.is_symlink(), "Machine root is a symlink")
    if not MACHINES_ROOT.exists():
        command("install", "-d", "-o", "root", "-g", "root", "-m", "0755", str(MACHINES_ROOT))
    parent = MACHINES_ROOT.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and
            not parent.st_mode & 0o022, "Machine root is not private to the runner")
    require(not machine_root(state["container"]).exists(), "Disposable target already exists")
    state_dir.mkdir(mode=0o700)
    save(state_dir, state)
    # Ubuntu 24.04 may use an inherited socket-activated SSH listener. Stop it
    # before the test opens any SSH service and restore its state at teardown.
    command("systemctl", "disable", "--now", "ssh.socket", check=False)
    command("systemctl", "stop", "ssh.service", check=False)

    # Compose adopts this labelled private bridge. The nspawn machines share
    # the runner network namespace but their SSH listeners use separate ports.
    command("docker", "network", "create", "--driver", "bridge",
            "--subnet", "172.30.253.0/28", "--gateway", COMPOSE_GATEWAY,
            "--label", "com.docker.compose.project=sovagrid",
            "--label", "com.docker.compose.network=private", COMPOSE_NETWORK)
    SSH_CONFIG.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    SSH_CONFIG.write_text(
        "# SovaGrid disposable GitHub CI bridge listeners\n"
        f"ListenAddress {COMPOSE_GATEWAY}\n"
        "PermitRootLogin prohibit-password\nPasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\nPubkeyAuthentication yes\n"
        "DisableForwarding no\nAllowTcpForwarding local\n"
        "PermitOpen 127.0.0.1:8766 127.0.0.1:8767\n",
        encoding="ascii")
    SSH_CONFIG.chmod(0o644)

    dockerfile = BLUEPRINT / "tests/fixtures/Dockerfile.remote-agent-ubuntu"
    command("docker", "build", "-f", str(dockerfile), "-t", state["image"], str(dockerfile.parent))
    key = state_dir / "ci_ed25519"
    command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "sovagrid-disposable-ci", "-f", str(key))
    public = key.with_suffix(".pub").read_text(encoding="ascii").strip()
    state["auth_line"] = public
    save(state_dir, state)
    append_line(Path("/root/.ssh/authorized_keys"), public)
    target_root = export_machine(state_dir, state, state["container"], CONNECT_PORT)
    start_machine(state["container"], CONNECT_PORT)

    if not Path("/usr/sbin/sshd").exists():
        command("apt-get", "update")
        command("apt-get", "install", "-y", "--no-install-recommends", "openssh-server")
    # Ubuntu's ssh.service normally creates this volatile directory before
    # ExecStart. We validate sshd ourselves before starting the unit, so make
    # the same runtime prerequisite explicit on a fresh GitHub runner.
    require(not Path("/run/sshd").is_symlink(), "SSH runtime directory is a symlink")
    command("install", "-d", "-o", "root", "-g", "root", "-m", "0755", "/run/sshd")
    command("ssh-keygen", "-A")
    command("/usr/sbin/sshd", "-t")
    require(all(host_forward_policy().values()),
            "CI host SSH policy does not allow the private panel forward")
    command("systemctl", "disable", "--now", "ssh.socket", check=False)
    command("systemctl", "enable", "--now", "ssh.service")
    command("systemctl", "restart", "ssh.service")
    listeners = {line.split()[3] for line in command("ss", "-H", "-ltn", "sport = :22").stdout.splitlines()}
    require(listeners == {f"{COMPOSE_GATEWAY}:22"},
            "CI host SSH must listen only on the private Docker bridge")

    host_public = Path("/etc/ssh/ssh_host_ed25519_key.pub").read_text(encoding="ascii")
    target_public = (target_root / "etc/ssh/ssh_host_ed25519_key.pub").read_text(encoding="ascii")
    state["known_lines"] = [host_key_line(COMPOSE_GATEWAY, host_public),
                            host_key_line(f"[{COMPOSE_GATEWAY}]:{CONNECT_PORT}", target_public)]
    save(state_dir, state)
    for line in state["known_lines"]:
        append_line(Path("/root/.ssh/known_hosts"), line)
    for port in (22, CONNECT_PORT):
        command("ssh", "-F", "/dev/null", "-p", str(port), "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5",
                "-i", str(key), f"root@{COMPOSE_GATEWAY}", "true")
    print("INTEGRATED_REMOTE_AGENT_FIXTURE_READY", flush=True)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def api_request(method: str, path: str, *, token: str | None = None, body: dict | None = None) -> dict:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    opener = build_opener(ProxyHandler({}), NoRedirect())
    request = Request("http://127.0.0.1:8766" + path, method=method, data=data, headers=headers)
    with opener.open(request, timeout=10) as response:
        require(response.status == 200, "Hub API returned an unexpected status")
        raw = response.read(65537)
    require(len(raw) <= 65536, "Hub API response is too large")
    value = json.loads(raw)
    require(isinstance(value, dict), "Hub API did not return an object")
    return value


def browser_ssh_request(path: str, body: dict, token: str, *, timeout: int = 30) -> dict:
    """Call the same-origin Web route, reporting only stable error codes."""
    require(path.startswith("/api/v1/browser-ssh/") and isinstance(body, dict),
            "Unexpected browser SSH request")
    headers = {"Accept": "application/json", "Content-Type": "application/json",
               "Origin": "http://127.0.0.1:8766", "Authorization": "Bearer " + token}
    request = Request("http://127.0.0.1:8766" + path, method="POST",
                      data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
                      headers=headers)
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            require(response.status == 200, "Browser SSH route returned an unexpected status")
            raw = response.read(65537)
    except HTTPError as error:
        try:
            payload = json.loads(error.read(513))
            code = payload.get("error") if isinstance(payload, dict) else None
        except (ValueError, UnicodeError, TypeError):
            code = None
        raise RuntimeError("Browser SSH route refused " + path.rsplit("/", 1)[-1] +
                           ": " + (code if isinstance(code, str) and
                                   re.fullmatch(r"[A-Z_]{3,48}", code) else "HTTP_ERROR")) from None
    require(len(raw) <= 65536, "Browser SSH route reply is too large")
    value = json.loads(raw)
    require(isinstance(value, dict), "Browser SSH route did not return an object")
    return value


def panel_probe(port: int) -> dict[str, str]:
    """Report only fixed route/status categories; never response or SSH data."""
    checks = (("health", "/healthz", 512),
              ("location", "/api/v1/panel-location", 512),
              ("page", "/sovagrid/monitoring/", 262144),
              ("manifest", "/sovagrid/monitoring/manifest.webmanifest", 8192))
    opener = build_opener(ProxyHandler({}), NoRedirect())
    result = {}
    for name, path, limit in checks:
        try:
            with opener.open(f"http://127.0.0.1:{port}{path}", timeout=1.2) as response:
                status = response.status
                kind = response.headers.get("Content-Type", "")
                raw = response.read(limit + 1)
            if status != 200:
                result[name] = f"http_{status}"
            elif len(raw) > limit:
                result[name] = "oversized"
            elif name == "health":
                result[name] = "ok" if json.loads(raw).get("ok") is True else "invalid"
            elif name == "location":
                value = json.loads(raw)
                result[name] = ("ok" if kind.startswith("application/json") and
                                value == {"panel_path": "/sovagrid/monitoring/"} else "invalid")
            elif name == "page":
                result[name] = "ok" if b"SovaGrid" in raw else "invalid"
            else:
                value = json.loads(raw)
                result[name] = ("ok" if isinstance(value, dict) and
                                "SovaGrid" in value.get("name", "") else "invalid")
        except HTTPError as error:
            result[name] = f"http_{error.code}"
            error.close()
        except (URLError, TimeoutError, OSError):
            result[name] = "unreachable"
        except (ValueError, TypeError, UnicodeError, AttributeError):
            result[name] = "invalid"
    return result


def wait_direct_panel() -> dict[str, str]:
    deadline = time.monotonic() + 10
    while True:
        observed = panel_probe(8766)
        if set(observed.values()) == {"ok"}:
            return observed
        if time.monotonic() >= deadline:
            raise RuntimeError("Installed panel route is not ready: " + json.dumps(observed, sort_keys=True))
        time.sleep(0.5)


def host_forward_policy() -> dict[str, bool]:
    """Summarize only the effective root SSH forwarding permissions."""
    effective = command("/usr/sbin/sshd", "-T", "-C",
                        f"user=root,addr={COMPOSE_GATEWAY},host=localhost,laddr={COMPOSE_GATEWAY},lport=22").stdout
    values = dict(line.split(maxsplit=1) for line in effective.splitlines() if " " in line)
    permit = values.get("permitopen", "").split()
    return {"tcp_forwarding": values.get("allowtcpforwarding") in ("yes", "local"),
            "forwarding_enabled": values.get("disableforwarding") == "no",
            "panel_destination": "any" in permit or "127.0.0.1:8766" in permit}


def start_web_target(state_dir: Path, state: dict) -> str:
    """Boot a distinct Ubuntu systemd machine for the Web gateway route."""
    name = "sovagrid-ci-web-target-" + state["container"].rsplit("-", 1)[-1]
    state["web_container"] = name
    save(state_dir, state)  # Cleanup can find it if a later step is interrupted.
    root = export_machine(state_dir, state, name, WEB_PORT)
    public = (root / "etc/ssh/ssh_host_ed25519_key.pub").read_text(encoding="ascii").split()
    require(len(public) >= 2 and public[1] != state["known_lines"][1].split()[2],
            "Web Agent target reused the Connect target's host key")
    start_machine(name, WEB_PORT)
    return COMPOSE_GATEWAY


def verify_web_agent(state_dir: Path, state: dict, host_id: str, connect_id: str) -> None:
    """Use real Web gateway routes to enroll a distinct Ubuntu target."""
    address = start_web_target(state_dir, state)
    password = Path("/etc/sovagrid/admin-password").read_text(encoding="ascii").strip()
    token = api_request("POST", "/api/v1/session",
                        body={"username": "admin", "password": password})["token"]
    web_id = None
    initial_seen = None
    try:
        host_key = browser_ssh_request("/api/v1/browser-ssh/target-host-key",
                                       {"host": address, "port": WEB_PORT}, token)
        require(host_key.get("protocol") == 1 and host_key.get("scope") == "entered_target"
                and host_key.get("host") == address and
                re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", host_key.get("fingerprint", "")),
                "Web gateway did not review the target SSH key")
        credential = {"host": address, "port": WEB_PORT, "username": "root",
                      "method": "private_key", "fingerprint": host_key["fingerprint"],
                      "password": "", "private_key": (state_dir / "ci_ed25519").read_text(),
                      "passphrase": ""}
        status = browser_ssh_request("/api/v1/browser-ssh/target-status", credential, token)
        require(status.get("protocol") == 1 and status.get("kind") == "missing" and
                status.get("host_key_fingerprint") == host_key["fingerprint"],
                "Web gateway did not confirm an empty target")
        fields = {**credential, "name": state["web_container"],
                  "hub_host": COMPOSE_GATEWAY, "hub_port": 22, "local_port": 18768}
        preview = browser_ssh_request("/api/v1/browser-ssh/target-install-preview",
                                      fields, token, timeout=45)
        require(preview.get("protocol") == 1 and preview.get("writes") is False and
                preview.get("target_kind") == "missing" and
                preview.get("hub_route") == "reachable" and
                preview.get("preflight_passed") is True,
                "Web gateway did not return a safe install preview")
        job = browser_ssh_request("/api/v1/browser-ssh/agent/prepare", fields, token,
                                  timeout=600)
        require(job.get("protocol") == 1 and job.get("phase") == "prepared" and
                job.get("writes") is True and job.get("activation_writes") is False and
                isinstance(job.get("request_id"), str) and
                isinstance(job.get("revision"), int) and
                job.get("platform", {}).get("ubuntu_version") == "24.04",
                "Web Agent prepare did not return a reviewed job")
        credential["private_key"] = fields["private_key"] = ""
        installed = browser_ssh_request("/api/v1/browser-ssh/agent/apply",
                {"request_id": job["request_id"], "expected_revision": job["revision"]},
                token, timeout=600)
        web_id = installed.get("server_id")
        require(installed.get("protocol") == 1 and installed.get("phase") == "active" and
                installed.get("registration_state") == "active" and
                isinstance(web_id, str) and web_id not in (host_id, connect_id),
                "Web Agent apply did not activate an independent server")
        for unit in ("sovagrid-agent.service", "sovagrid-agent-tunnel.service"):
            require(machine_command(state["web_container"], "/usr/bin/systemctl",
                                    "is-active", "--quiet", unit, check=False).returncode == 0,
                    "Web Agent target service is inactive")
        rows = api_request("GET", "/api/v1/servers", token=token).get("servers")
        require(isinstance(rows, list), "Hub returned no server inventory")
        web_row = next((item for item in rows if item.get("id") == web_id), None)
        require(web_row is not None, "Hub lacks the Web Agent server identity")
        initial_seen = web_row.get("last_seen")
    finally:
        api_request("DELETE", "/api/v1/session", token=token)

    # A new Web session observes later metrics, proving the Agent remains
    # connected after the browser administrator session has been revoked.
    token = api_request("POST", "/api/v1/session",
                        body={"username": "admin", "password": password})["token"]
    try:
        deadline = time.monotonic() + 85
        while True:
            rows = api_request("GET", "/api/v1/servers", token=token).get("servers")
            require(isinstance(rows, list), "Hub returned no server inventory")
            by_id = {row["id"]: row for row in rows}
            require(host_id in by_id and connect_id in by_id and web_id in by_id,
                    "Hub lacks a server identity after Web Agent apply")
            seen = by_id[web_id]["last_seen"]
            history = api_request("GET", f"/api/v1/servers/{web_id}/metrics?limit=5",
                                  token=token).get("metrics")
            if (by_id[web_id]["online"] is True and type(seen) is int and
                    (initial_seen is None or seen > initial_seen) and
                    isinstance(history, list) and len(history) >= 2):
                break
            require(time.monotonic() < deadline,
                    "Web Agent did not persist later metrics after browser logout")
            time.sleep(2)
    finally:
        api_request("DELETE", "/api/v1/session", token=token)
    print("INTEGRATED_WEB_AGENT_PERSISTS_AFTER_BROWSER", flush=True)


def verify(state_dir: Path) -> None:
    expected = os.environ.get("SOVAGRID_EXPECTED_MANIFEST", "")
    connect_ref = os.environ.get("CONNECT_REF", "")
    require(SHA256.fullmatch(expected) is not None and SHA1.fullmatch(connect_ref) is not None,
            "Exact server bundle and Connect commit pins are required")
    require(hashlib.sha256((SOURCE / "sovagrid-bundle.json").read_bytes()).hexdigest() == expected,
            "Installed Hub source differs from the bundled pin")
    connect = Path(os.environ["GITHUB_WORKSPACE"]) / "sovagrid-connect"
    require(command("git", "-C", str(connect), "rev-parse", "HEAD").stdout.strip() == connect_ref,
            "Checked-out Connect differs from the exact commit pin")
    state = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
    sys.path.insert(0, str(connect))
    from sovagrid_connect.agent_enrollment import AgentEnrollment
    from sovagrid_connect.core import ConnectionOptions, Tunnel
    from sovagrid_connect.enrollment_journal import EnrollmentJournal

    class ObservedTunnel(Tunnel):
        """Keep only boolean SSH evidence before Tunnel.start removes its log."""

        diagnostic: dict | None = None

        def close(self):
            try:
                if self.diagnostic is None and self.local_port is not None:
                    raw = b""
                    if self._ssh_log is not None:
                        try:
                            raw = Path(self._ssh_log).read_bytes()[:131072]
                        except OSError:
                            pass
                    marker = f"Local forwarding listening on 127.0.0.1 port {self.local_port}.".encode()
                    self.diagnostic = {
                        "ssh_alive": self.alive,
                        "authenticated_marker": b"Authenticated to " in raw,
                        "forward_marker": marker in raw,
                        "any_forward_marker": b"Local forwarding listening on " in raw,
                        "forward_denied_marker": b"administratively prohibited" in raw,
                        "local_bind_failed_marker": b"bind [127.0.0.1]" in raw,
                        "forward_ready": self._forward_ready(),
                        "panel_ready": self._panel_ready() if self.alive else False,
                        "forwarded_http": panel_probe(self.local_port) if self.alive else None,
                    }
            except Exception:
                # A diagnostic must never replace the original TunnelError.
                self.diagnostic = {"probe_failed": True}
            finally:
                super().close()

    key = str(state_dir / "ci_ed25519")
    hub = ConnectionOptions(host=COMPOSE_GATEWAY, user="root", identity=key)
    target = ConnectionOptions(host=COMPOSE_GATEWAY, port=CONNECT_PORT, user="root", identity=key)
    wait_direct_panel()
    tunnel = ObservedTunnel(hub, batch_mode=True)
    controller = None
    try:
        try:
            tunnel.start(timeout=40)
        except Exception:
            try:
                policy = host_forward_policy()
            except Exception:
                policy = {"unavailable": True}
            print("INTEGRATED_CONNECT_TUNNEL_PROBE " + json.dumps(
                {**(tunnel.diagnostic or {"unavailable": True}),
                 "host_policy": policy}, sort_keys=True), flush=True)
            raise
        controller = AgentEnrollment(tunnel, journal=EnrollmentJournal(ci_records_dir(state)))
        password = Path("/etc/sovagrid/admin-password").read_text(encoding="ascii").strip()
        preview = controller.prepare(target_options=target,
                                     name="ci-remote-agent-" + state["container"].rsplit("-", 1)[-1],
                                     bundle=Path(os.environ["RUNNER_TEMP"]) / "SovaGrid-server-source.tar.gz",
                                     hub_host=COMPOSE_GATEWAY, hub_port=22, local_port=18767,
                                     credentials={"username": "admin", "password": password})
        require(preview["platform"]["ubuntu_version"] == "24.04",
                "The second server is not Ubuntu 24.04")
        require(preview["record"]["phase"] == "prepared", "Connect did not complete review")
        try:
            installed = controller.apply()
        except Exception:
            journal = machine_command(state["container"], "/usr/bin/journalctl", "-u",
                                      "sovagrid-agent-tunnel.service", "-n", "16", "--no-pager",
                                      "--output=cat", check=False).stdout
            print("INTEGRATED_CONNECT_TARGET_TUNNEL_LOG " +
                  json.dumps(journal.splitlines()[-16:]), flush=True)
            raise
        require(installed["phase"] == "active" and installed["registration"]["state"] == "active",
                "Connect did not activate the second Agent")
        remote_id = installed["target"]["server_id"]
        first_seen = installed["registration"]["last_seen"]
        host_id = json.loads(Path("/etc/sovagrid/agent.json").read_text(encoding="utf-8"))["server_id"]
        require(remote_id != host_id and type(first_seen) is int,
                "Remote Agent did not get an independent server identity")
    finally:
        if controller is not None:
            controller.close()
        tunnel.close()
    require(not tunnel.alive, "Connect SSH session remained open")
    require(machine_command(state["container"], "/usr/bin/systemctl", "is-active", "--quiet",
                            "sovagrid-agent.service", check=False).returncode == 0,
            "Remote Agent service stopped after Connect closed")
    require(machine_command(state["container"], "/usr/bin/systemctl", "is-active", "--quiet",
                            "sovagrid-agent-tunnel.service", check=False).returncode == 0,
            "Remote tunnel service stopped after Connect closed")

    password = Path("/etc/sovagrid/admin-password").read_text(encoding="ascii").strip()
    token = api_request("POST", "/api/v1/session", body={"username": "admin", "password": password})["token"]
    deadline = time.monotonic() + 85
    while True:
        rows = api_request("GET", "/api/v1/servers", token=token).get("servers")
        require(isinstance(rows, list), "Hub returned no server inventory")
        by_id = {row["id"]: row for row in rows}
        require(host_id in by_id and remote_id in by_id, "Hub lacks one of the two server identities")
        history = api_request("GET", f"/api/v1/servers/{remote_id}/metrics?limit=5", token=token).get("metrics")
        if (by_id[remote_id]["last_seen"] is not None
                and by_id[remote_id]["last_seen"] > first_seen
                and by_id[remote_id]["online"] is True
                and isinstance(history, list) and len(history) >= 2):
            break
        require(time.monotonic() < deadline, "Remote Agent did not persist a later metric after Connect closed")
        time.sleep(2)
    api_request("DELETE", "/api/v1/session", token=token)
    print("INTEGRATED_REMOTE_AGENT_PERSISTS_AFTER_CONNECT", flush=True)
    verify_web_agent(state_dir, state, host_id, remote_id)


def cleanup(state_dir: Path) -> None:
    if not state_dir.exists():
        return
    state = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
    failures = []

    def attempt(label: str, action) -> None:
        try:
            action()
        except Exception as error:
            failures.append(f"{label}: {error}")

    records = ci_records_dir(state)
    if records.exists() or records.is_symlink():
        def remove_records() -> None:
            info = records.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
                    stat.S_IMODE(info.st_mode) == 0o700,
                    "Disposable Connect journal changed ownership or permissions")
            shutil.rmtree(records)
        attempt("Connect journal", remove_records)

    compose = SOURCE / "sovagrid-blueprint/deploy/compose.yaml"
    attempt("host Agent stop", lambda: command("systemctl", "stop", "sovagrid-agent.service", check=False))
    # Stop both guest systemd managers before touching their root filesystems.
    for name in (state.get("web_container"), state["container"]):
        if not name:
            continue
        machine_root(name)
        attempt("guest poweroff " + name,
                lambda name=name: command("machinectl", "poweroff", name, check=False))
        attempt("guest unit stop " + name,
                lambda name=name: command("systemctl", "stop", machine_unit(name), check=False))
        attempt("guest terminate " + name,
                lambda name=name: command("machinectl", "terminate", name, check=False))
        root = machine_root(name)
        if root.exists() or root.is_symlink():
            def remove_rootfs(root: Path = root, name: str = name) -> None:
                info = root.lstat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
                        not info.st_mode & 0o022, "Disposable Ubuntu rootfs changed ownership")
                for _ in range(20):
                    if command("machinectl", "show", name, check=False).returncode != 0:
                        break
                    time.sleep(0.5)
                require(command("machinectl", "show", name, check=False).returncode != 0,
                        "Disposable Ubuntu machine is still registered")
                require(command("systemctl", "is-active", "--quiet", machine_unit(name),
                                check=False).returncode != 0,
                        "Disposable Ubuntu service is still active")
                mounts = command("findmnt", "-rn", "-o", "TARGET").stdout.splitlines()
                require(not any(item == str(root) or item.startswith(str(root) + "/")
                                for item in mounts), "Disposable Ubuntu rootfs is still mounted")
                shutil.rmtree(root)
            attempt("guest rootfs " + name, remove_rootfs)
    if compose.is_file() and Path("/etc/sovagrid/deploy.env").is_file():
        attempt("compose down", lambda: command("docker", "compose", "--env-file", "/etc/sovagrid/deploy.env",
                  "-f", str(compose), "down", "--remove-orphans"))
    for seed in state.get("seed_containers", []):
        require(seed.endswith("-export"), "Unexpected Docker export fixture name")
        machine_root(seed.removesuffix("-export"))
        if command("docker", "inspect", seed, check=False).returncode == 0:
            attempt("rootfs seed " + seed, lambda seed=seed: command("docker", "rm", "-f", seed))
    if command("docker", "image", "inspect", state["image"], check=False).returncode == 0:
        attempt("target image removal", lambda: command("docker", "image", "rm", "-f", state["image"]))
    if network_exists(COMPOSE_NETWORK):
        attempt("Compose private network", lambda: command("docker", "network", "rm", COMPOSE_NETWORK))
    attempt("stop CI SSH", lambda: command("systemctl", "stop", "ssh.service", check=False))
    if state.get("host_sshd_runtime_existed") is False and Path("/run/sshd").is_dir():
        attempt("SSH runtime directory", lambda: Path("/run/sshd").rmdir())
    if SSH_CONFIG.exists() or SSH_CONFIG.is_symlink():
        def remove_policy():
            require(SSH_CONFIG.is_file() and not SSH_CONFIG.is_symlink() and
                    SSH_CONFIG.read_text(encoding="ascii").startswith(
                        "# SovaGrid disposable GitHub CI bridge listeners\n"),
                    "Disposable SSH policy was modified")
            SSH_CONFIG.unlink()
        attempt("SSH policy", remove_policy)
    for line in state.get("known_lines", []):
        attempt("known host", lambda line=line: remove_line(Path("/root/.ssh/known_hosts"), line))
    if state.get("auth_line"):
        attempt("client key", lambda: remove_line(Path("/root/.ssh/authorized_keys"), state["auth_line"]))
    for path, existed in ((Path("/root/.ssh/known_hosts"), state.get("known_hosts_existed")),
                          (Path("/root/.ssh/authorized_keys"), state.get("auth_file_existed"))):
        if existed is False and path.is_file() and not path.read_bytes():
            attempt("empty SSH fixture file", path.unlink)
    for unit, key in (("ssh.socket", "host_socket_enabled"), ("ssh.service", "host_service_enabled")):
        action = "enable" if state.get(key) else "disable"
        attempt("restore " + unit + " enablement", lambda unit=unit, action=action:
                command("systemctl", action, unit, check=False))
    if state.get("host_socket_active"):
        attempt("restore SSH socket", lambda: command("systemctl", "start", "ssh.socket"))
    if state.get("host_service_active"):
        attempt("restore SSH service", lambda: command("systemctl", "start", "ssh.service"))
    if state.get("machines_root_existed") is False and MACHINES_ROOT.is_dir():
        attempt("empty machine root", MACHINES_ROOT.rmdir)
    attempt("fixture directory", lambda: shutil.rmtree(state_dir))
    require(not failures, "; ".join(failures))


def main() -> None:
    require(len(sys.argv) == 3 and sys.argv[1] in ("prepare", "verify", "cleanup"),
            "usage: integrated_remote_agent_vm.py prepare|verify|cleanup STATE_DIR")
    state_dir = Path(sys.argv[2])
    ci_guard(state_dir)
    os.environ["HOME"] = "/root"
    if sys.argv[1] == "prepare":
        setup(state_dir)
    elif sys.argv[1] == "verify":
        verify(state_dir)
    else:
        cleanup(state_dir)


if __name__ == "__main__":
    main()
