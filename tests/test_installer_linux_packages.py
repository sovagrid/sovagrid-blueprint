# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Run installer policy with command fixtures; never install host packages."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "run.sh").read_text(encoding="utf-8")
ADAPTER = SOURCE[SOURCE.index("apt_refreshed=0\n"):
                 SOURCE.index("\nrestore_docker_with_binary() {")]
PACKAGES = SOURCE[SOURCE.index("compose_plugin_supported() {"):
                  SOURCE.index("\nrestore_target_empty() {")]
COMPOSE_BINARY = PACKAGES[PACKAGES.index("install_compose_binary() ("):
                          PACKAGES.index("\ninstall_core_dependencies() {")]
AMD64_SHA = "47737f4236e6d3ccea7291995203f8f018058783b4c3a9469119811a0b5db8c0"
ARM64_SHA = "42cfa75f51ad0ccf290bad37899e0038a8c10a0069e85233ecc1d53e3ff1347d"
SHA256SUM = shutil.which("gsha256sum") or shutil.which("sha256sum")


@unittest.skipUnless(shutil.which("bash"), "Bash is unavailable")
class InstallerLinuxPackagesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.log = self.root / "commands"
        self.state = self.root / "compose-version"

    def shell(self, script: str, **environment: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", TEST_LOG=str(self.log),
                   TEST_COMPOSE_STATE=str(self.state), **environment)
        return subprocess.run(["bash", "-c", "set -euo pipefail\numask 077\n"
                               "die() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
                               "say() { :; }\n" + script],
                              env=env, capture_output=True, text=True, check=False)

    def commands(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    def capability_fixture(self, name: str, **environment: str) -> subprocess.CompletedProcess[str]:
        source = (ROOT / name).read_text(encoding="utf-8")
        function = "require_host_capabilities" if name == "run.sh" else "require_bootstrap_capabilities"
        start = source.index("SOVAGRID_MIN_SYSTEMD=")
        end = source.index("\n" + function + "\n", start) + len(function) + 2
        gate = source[start:end]
        # Exercise simulated Linux capabilities on the macOS test runner.
        # Bash-version admission is separate from the command fixtures below.
        gate = gate.replace("(( BASH_VERSINFO[0] >= 4 ))", "true")
        for relative in ("run/systemd/system", "run/systemd/journal", "proc/self/fd"):
            (self.root / relative).mkdir(parents=True, exist_ok=True)
        for relative in ("proc/stat", "proc/meminfo", "proc/net/dev"):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        for executable in ("usr/bin/python3", "usr/sbin/nologin"):
            path = self.root / executable
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#!/bin/sh\n[ "${TEST_PYTHON_SUPPORTED:-1}" = 1 ]\n')
            path.chmod(0o755)
        for path in ("/run/systemd/system", "/run/systemd/journal", "/proc/self/fd", "/proc/stat",
                     "/proc/meminfo", "/proc/net/dev", "/usr/bin/python3", "/usr/sbin/nologin"):
            gate = gate.replace(path, str(self.root / path.lstrip("/")))
        if environment.get("TEST_SYSTEMD_RUNTIME", "1") == "0":
            gate = gate.replace(str(self.root / "run/systemd/system"), str(self.root / "missing-runtime"))
        fixtures = r'''
setup_mode=${TEST_SETUP_MODE:-install}
command() {
  if [[ $1 == -v ]]; then
    case $2 in
      python3) [[ ${TEST_PYTHON_PRESENT:-1} == 1 ]]; return ;;
      apt-get) [[ ${TEST_APT_PRESENT:-1} == 1 ]]; return ;;
    esac
    [[ " ${TEST_MISSING_TOOLS:-} " != *" $2 "* ]]; return
  fi
  builtin command "$@"
}
uname() { printf '%s\n' "${TEST_KERNEL:-Linux}"; }
stat() { printf '0:0\n'; }
getent() {
  if [[ $1 == passwd ]]; then printf 'root:x:0:0:root:/root:/bin/bash\n';
  else printf 'root:x:0:\n'; fi
}
systemctl() {
  printf 'systemctl %s\n' "$*" >> "$TEST_LOG"
  if [[ $1 == is-system-running ]]; then
    printf '%s\n' "${TEST_SYSTEMD_STATE:-running}"
    [[ ${TEST_SYSTEMD_STATE:-running} == running ]]; return
  fi
  printf '%s\n' "${TEST_SYSTEMD_VERSION:-252.39-1~deb12u1}"
}
python3() { [[ ${TEST_PYTHON_SUPPORTED:-1} == 1 ]]; }
'''
        return self.shell(fixtures + "\n" + gate, **environment)

    def test_both_gates_admit_capabilities_independently_of_os_metadata(self) -> None:
        for name in ("run.sh", "bootstrap/run.sh"):
            for identifier, version in (("fedora", "44"), ("unknown", "999"), ("", ""),
                                        ("ubuntu:26.04 debian", "12")):
                with self.subTest(installer=name, identifier=identifier):
                    result = self.capability_fixture(name, ID=identifier, VERSION_ID=version,
                                                     ID_LIKE="arbitrary", TEST_APT_PRESENT="0")
                    self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("SOVAGRID_PLATFORM_PAIRS=", SOURCE)
        self.assertNotIn("/etc/os-release", SOURCE.split("restore_dependencies_only() {", 1)[0])
        self.assertNotIn("/etc/os-release", (ROOT / "bootstrap/run.sh").read_text())

    def test_both_gates_require_linux_active_manager_and_minimum_versions(self) -> None:
        rejected = ({"TEST_KERNEL": "Darwin"}, {"TEST_SYSTEMD_RUNTIME": "0"},
                    {"TEST_SYSTEMD_STATE": "offline"}, {"TEST_SYSTEMD_STATE": "starting"},
                    {"TEST_SYSTEMD_VERSION": "246"}, {"TEST_SYSTEMD_VERSION": "bad-version"},
                    {"TEST_PYTHON_SUPPORTED": "0"}, {"TEST_MISSING_TOOLS": "stat flock"})
        for name in ("run.sh", "bootstrap/run.sh"):
            for environment in rejected:
                with self.subTest(installer=name, environment=environment):
                    result = self.capability_fixture(name, **environment)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
            result = self.capability_fixture(name, TEST_SYSTEMD_STATE="degraded", TEST_SYSTEMD_VERSION="247.1")
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_bootstrap_missing_python_needs_a_package_adapter(self) -> None:
        result = self.capability_fixture("bootstrap/run.sh", TEST_PYTHON_PRESENT="0", TEST_APT_PRESENT="0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Python 3.10", result.stderr)
        result = self.capability_fixture("bootstrap/run.sh", TEST_PYTHON_PRESENT="0", TEST_APT_PRESENT="1")
        self.assertEqual(result.returncode, 0, result.stderr)

    def docker_target_fixture(self, name: str, **environment: str) -> subprocess.CompletedProcess[str]:
        source = (ROOT / name).read_text(encoding="utf-8")
        start = source.index("require_local_docker_target() {")
        end = source.index("\n}\n", start) + 3
        fixtures = r'''
docker() {
  printf 'docker %s\n' "$*" >> "$TEST_LOG"
  if [[ $1 == context && $2 == inspect ]]; then printf '%s\n' "$TEST_CONTEXT_ENDPOINT"; return; fi
  return 99
}
'''
        verify = r'''
require_local_docker_target
[[ $DOCKER_HOST == unix:///var/run/docker.sock ]]
[[ ! ${DOCKER_CONTEXT+x} && ! ${DOCKER_TLS_VERIFY+x} && ! ${DOCKER_CERT_PATH+x} ]]
'''
        values = dict(DOCKER_HOST="", DOCKER_CONTEXT="", DOCKER_TLS_VERIFY="1", DOCKER_CERT_PATH="/tmp/unused",
                      TEST_CONTEXT_ENDPOINT="unix:///var/run/docker.sock")
        values.update(environment)
        return self.shell(source[start:end] + fixtures + verify, **values)

    def test_remote_docker_hosts_and_contexts_are_refused_without_daemon_calls(self) -> None:
        for name in ("run.sh", "bootstrap/run.sh"):
            for environment in ({"DOCKER_HOST": "tcp://foreign.invalid:2375"},
                                {"DOCKER_CONTEXT": "remote", "TEST_CONTEXT_ENDPOINT": "ssh://foreign.invalid"},
                                {"DOCKER_CONTEXT": "invalid", "TEST_CONTEXT_ENDPOINT": ""},
                                {"TEST_CONTEXT_ENDPOINT": ""},
                                {"TEST_SAVED_CONTEXT": "saved-remote", "TEST_CONTEXT_ENDPOINT": "tcp://foreign.invalid:2375"}):
                with self.subTest(installer=name, environment=environment):
                    self.log.unlink(missing_ok=True)
                    result = self.docker_target_fixture(name, **environment)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("docker info", self.commands())
                    self.assertNotIn("context use", self.commands())
                    self.assertNotIn("docker compose", self.commands())
                    self.assertNotIn("systemctl", self.commands())

    def test_custom_context_for_exact_local_socket_is_accepted_without_selecting_it(self) -> None:
        for name in ("run.sh", "bootstrap/run.sh"):
            with self.subTest(installer=name):
                self.log.unlink(missing_ok=True)
                result = self.docker_target_fixture(name, DOCKER_CONTEXT="custom-local")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("docker context inspect custom-local", self.commands())
                self.assertNotIn("context use", self.commands())

    def test_current_context_is_inspected_without_newer_context_show_command(self) -> None:
        for name in ("run.sh", "bootstrap/run.sh"):
            with self.subTest(installer=name):
                self.log.unlink(missing_ok=True)
                result = self.docker_target_fixture(name)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.commands(), "docker context inspect --format {{.Endpoints.docker.Host}}\n")

    def test_restore_dependency_setup_remains_ubuntu_only(self) -> None:
        start = SOURCE.index("restore_dependencies_only() {")
        end = SOURCE.index("\nif [[ ${1:-} == --restore-dependencies-only ]]; then", start)
        restore = SOURCE[start:end]
        release = self.root / "os-release"
        restore = restore.replace("/etc/os-release", str(release))
        for identifier, version in (("debian", "12"), ("debian", "13"), ("debian", "22.04")):
            with self.subTest(identifier=identifier, version=version):
                release.write_text(f"ID={identifier}\nVERSION_ID={version}\n")
                result = self.shell(restore + "\nID=$TEST_ID\nVERSION_ID=$TEST_VERSION\n"
                                    "restore_dependencies_only " + "0" * 64,
                                    TEST_ID=identifier, TEST_VERSION=version)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("requires Ubuntu 22.04", result.stderr)
                self.assertEqual(self.commands(), "")

    def dependency_fixture(self, **environment: str) -> subprocess.CompletedProcess[str]:
        binary = self.root / "docker-cli"
        if environment.get("TEST_DOCKER_PRESENT", "1") == "1" and environment.get("TEST_STANDARD_DOCKER_PATH", "1") == "1":
            binary.touch()
            binary.chmod(0o755)
        packages = PACKAGES.replace("/usr/bin/docker", str(binary))
        script = ADAPTER + packages + r'''
SOVAGRID_MIN_PYTHON='3.10'
apt_refresh() { printf 'apt-refresh\n' >> "$TEST_LOG"; }
python3() { printf 'python3 %s\n' "$*" >> "$TEST_LOG"; }
python_version_supported() { printf 'python-version-check %s\n' "$1" >> "$TEST_LOG"; }
ip() { :; }
ss() { :; }
restore_local_docker() { docker "$@"; }
require_new_docker_target() {
  [[ ${TEST_RETAINED_DOCKER:-0} == 0 ]] || die 'an existing Docker engine requires manual inspection before dependency installation'
}
command() {
  if [[ $* == '-v docker' ]]; then [[ ${TEST_DOCKER_PRESENT:-1} == 1 ]]; return; fi
  if [[ $* == '-v python3' ]]; then [[ ${TEST_PYTHON_PRESENT:-1} == 1 ]]; return; fi
  if [[ $* == '-v apt-get' ]]; then [[ ${TEST_APT_PRESENT:-1} == 1 ]]; return; fi
  if [[ $* == '-v ip' ]]; then [[ ${TEST_IP_PRESENT:-1} == 1 ]]; return; fi
  if [[ $* == '-v ss' ]]; then [[ ${TEST_SS_PRESENT:-1} == 1 ]]; return; fi
  builtin command "$@"
}
docker() {
  printf 'docker %s\n' "$*" >> "$TEST_LOG"
  if [[ $1 == info ]]; then
    [[ ${TEST_DOCKER_AVAILABLE:-1} == 1 ]] || return 1
    if [[ ${2:-} == --format ]]; then printf '%s\n' "${TEST_DOCKER_OSTYPE:-linux}"; fi
    return
  fi
  if [[ $* == 'compose --project-name sovagrid-installer-preflight --file - ps --all --quiet' ]]; then
    cat >/dev/null
    [[ ${TEST_COMPOSE_DAEMON_COMPATIBLE:-1} == 1 ]]; return
  fi
  [[ $1 == compose && $2 == version ]] || return 20
  if [[ -f $TEST_COMPOSE_STATE ]]; then cat "$TEST_COMPOSE_STATE"; return; fi
  [[ -n ${TEST_COMPOSE_VERSION:-} ]] || return 1
  printf '%s\n' "$TEST_COMPOSE_VERSION"
}
systemctl() { printf 'systemctl %s\n' "$*" >> "$TEST_LOG"; }
apt-cache() {
  printf 'apt-cache %s\n' "$*" >> "$TEST_LOG"
  case $2 in
    docker-cli) printf '  Candidate: %s\n' "${TEST_APT_DOCKER_CLI:-(none)}" ;;
    docker-compose-v2) printf '  Candidate: %s\n' "${TEST_APT_V2:-(none)}" ;;
    docker-compose-plugin) printf '  Candidate: %s\n' "${TEST_APT_PLUGIN:-(none)}" ;;
    docker-compose) printf '  Candidate: %s\n' "${TEST_APT_COMPOSE:-(none)}" ;;
    *) return 2 ;;
  esac
}
apt-get() {
  printf 'apt-get %s\n' "$*" >> "$TEST_LOG"
  if [[ $1 == --simulate ]]; then printf '%s\n' "${TEST_APT_PLAN:-}"; return; fi
  case ${*: -1} in
    docker.io|docker-cli)
      TEST_DOCKER_PRESENT=1
      if [[ ${TEST_INSTALLED_DOCKER_CLI:-1} == 1 ]]; then touch "$TEST_DOCKER_BINARY"; chmod 0755 "$TEST_DOCKER_BINARY"; fi ;;
    python3) TEST_PYTHON_PRESENT=1 ;;
    iproute2) TEST_IP_PRESENT=1; TEST_SS_PRESENT=1 ;;
    docker-compose-v2|docker-compose-plugin|docker-compose)
      printf '%s\n' "${TEST_INSTALLED_COMPOSE:-2.26.1}" > "$TEST_COMPOSE_STATE" ;;
    *) return 3 ;;
  esac
}
install_compose_binary() {
  printf 'verified-binary-fallback\n' >> "$TEST_LOG"
  printf '5.6.1\n' > "$TEST_COMPOSE_STATE"
}
install_core_dependencies
'''
        return self.shell(script, TEST_DOCKER_BINARY=str(binary), **environment)

    def test_existing_working_compose_does_not_change_packages_or_daemon(self) -> None:
        for version in ("2.24.6", "2.40.3+ds1-0ubuntu1~24.04.1"):
            with self.subTest(version=version):
                result = self.dependency_fixture(TEST_COMPOSE_VERSION=version, TEST_APT_PRESENT="0",
                                                 ID="unknown-distro", VERSION_ID="any-version")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("apt-", self.commands())
                self.assertNotIn("systemctl", self.commands())
                self.assertNotIn("verified-binary-fallback", self.commands())

    def test_no_package_adapter_reports_all_missing_dependencies_without_changes(self) -> None:
        result = self.dependency_fixture(TEST_APT_PRESENT="0", TEST_DOCKER_PRESENT="0",
                                         TEST_PYTHON_PRESENT="0", TEST_IP_PRESENT="0", TEST_SS_PRESENT="0")
        self.assertNotEqual(result.returncode, 0)
        for capability in ("Python 3.10", "Docker CLI", "ip", "ss", "install them manually"):
            self.assertIn(capability, result.stderr)
        self.assertEqual(self.commands(), "")

    def test_compose_fallback_does_not_require_apt_when_download_tools_exist(self) -> None:
        result = self.dependency_fixture(TEST_APT_PRESENT="0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified-binary-fallback", self.commands())
        self.assertNotIn("apt-", self.commands())
        self.assertNotIn("systemctl", self.commands())

    def test_unavailable_existing_docker_refuses_before_apt_or_restart(self) -> None:
        result = self.dependency_fixture(TEST_DOCKER_AVAILABLE="0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Docker daemon is unavailable", result.stderr)
        self.assertEqual(self.commands(), "docker info\n")

    def test_plugin_daemon_incompatibility_refuses_without_changing_engine(self) -> None:
        result = self.dependency_fixture(TEST_COMPOSE_VERSION="2.24.6", TEST_COMPOSE_DAEMON_COMPATIBLE="0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot communicate with the existing daemon", result.stderr)
        self.assertIn("ps --all --quiet", self.commands())
        self.assertNotIn("apt-", self.commands())
        self.assertNotIn("systemctl", self.commands())

    def test_non_linux_container_daemon_is_rejected(self) -> None:
        result = self.dependency_fixture(TEST_COMPOSE_VERSION="2.24.6", TEST_DOCKER_OSTYPE="windows")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Linux containers", result.stderr)
        self.assertNotIn("apt-", self.commands())
        self.assertNotIn("systemctl", self.commands())

    def test_existing_nonstandard_docker_cli_requires_manual_preparation(self) -> None:
        result = self.dependency_fixture(TEST_STANDARD_DOCKER_PATH="0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("prepare the existing Docker installation manually", result.stderr)
        self.assertEqual(self.commands(), "")

    def test_cli_less_existing_engine_is_not_adopted_or_restarted(self) -> None:
        result = self.dependency_fixture(TEST_DOCKER_PRESENT="0", TEST_RETAINED_DOCKER="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing Docker engine requires manual inspection", result.stderr)
        self.assertEqual(self.commands(), "")

    def test_absent_docker_installs_distribution_package_then_starts_it(self) -> None:
        result = self.dependency_fixture(TEST_DOCKER_PRESENT="0", TEST_APT_PLUGIN="5.6.1-1~debian.12~bookworm")
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = self.commands()
        self.assertIn("apt-get install -y --no-install-recommends --no-remove docker.io\n", commands)
        self.assertIn("systemctl enable --now docker\n", commands)
        self.assertLess(commands.index("docker.io\n"), commands.index("systemctl enable --now docker\n"))

    def test_fresh_docker_includes_split_cli_when_apt_candidate_exists(self) -> None:
        result = self.dependency_fixture(TEST_DOCKER_PRESENT="0", TEST_APT_DOCKER_CLI="26.1.5+dfsg1-9",
                                         TEST_APT_COMPOSE="2.26.1-4")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("apt-get install -y --no-install-recommends --no-remove docker.io docker-cli\n", self.commands())
        self.assertLess(self.commands().index("docker.io docker-cli\n"), self.commands().index("systemctl enable --now docker\n"))

    def test_fresh_docker_missing_cli_after_apt_refuses_before_enabling_daemon(self) -> None:
        result = self.dependency_fixture(TEST_DOCKER_PRESENT="0", TEST_INSTALLED_DOCKER_CLI="0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing dependency after package installation", result.stderr)
        self.assertNotIn("systemctl", self.commands())

    def test_configured_compose_packages_are_preferred_and_checked(self) -> None:
        for variable, candidate, package in (("TEST_APT_V2", "2.24.6+ds1-0ubuntu2", "docker-compose-v2"),
                                             ("TEST_APT_PLUGIN", "5.6.1-1~debian.12~bookworm", "docker-compose-plugin"),
                                             ("TEST_APT_COMPOSE", "2:2.26.1-4", "docker-compose")):
            with self.subTest(package=package):
                self.log.unlink(missing_ok=True)
                self.state.unlink(missing_ok=True)
                result = self.dependency_fixture(**{variable: candidate})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("apt-get install -y --no-install-recommends --no-remove " + package, self.commands())
                self.assertNotIn("verified-binary-fallback", self.commands())
                self.assertNotIn("systemctl", self.commands())

    def test_debian12_legacy_candidate_uses_verified_binary_fallback(self) -> None:
        result = self.dependency_fixture(TEST_APT_COMPOSE="1.29.2-3")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified-binary-fallback", self.commands())
        self.assertNotIn("--no-remove docker-compose\n", self.commands())
        self.assertNotIn("systemctl", self.commands())

    def test_successful_legacy_or_invalid_plugin_does_not_satisfy_requirement(self) -> None:
        for version in ("1.29.2", "unexpected output", "9999999999999999999999.1.0"):
            with self.subTest(version=version):
                self.log.unlink(missing_ok=True)
                self.state.unlink(missing_ok=True)
                result = self.dependency_fixture(TEST_APT_V2="2.24.6-1", TEST_INSTALLED_COMPOSE=version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("verified-binary-fallback", self.commands())

    def test_apt_plan_changing_docker_or_removing_packages_uses_binary(self) -> None:
        for plan in ("Inst docker.io (28.0 Debian:13 [amd64])", "Inst docker-ce-cli (29.0 Docker [amd64])", "Inst docker-cli (28.0 Debian:13 [amd64])",
                     "Conf containerd.io (2.0 Docker [amd64])", "Inst docker.io:amd64 (28.0 Debian:13 [amd64])",
                     "Remv unrelated-package [1.0]"):
            with self.subTest(plan=plan):
                self.log.unlink(missing_ok=True)
                self.state.unlink(missing_ok=True)
                result = self.dependency_fixture(TEST_APT_PLUGIN="5.6.1-1", TEST_APT_PLAN=plan)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("verified-binary-fallback", self.commands())
                self.assertNotIn("apt-get install -y", self.commands())

    def binary_fixture(self, *, valid_digest: bool = False, architecture: str = "amd64") -> subprocess.CompletedProcess[str]:
        payload = self.root / "fixture-compose"
        payload.write_text("#!/bin/sh\nprintf '5.6.1\\n'\n"
                           "printf executed >> " + shlex.quote(str(self.root / "executed")) + "\n")
        binary = COMPOSE_BINARY.replace("/usr", str(self.root / "usr"))
        if valid_digest:
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            binary = binary.replace(AMD64_SHA, digest).replace(ARM64_SHA, digest)
        fixtures = r'''
apt_refresh() { printf 'apt-refresh\n' >> "$TEST_LOG"; }
apt-get() { printf 'apt-get %s\n' "$*" >> "$TEST_LOG"; }
uname() { printf '%s\n' "$TEST_ARCHITECTURE"; }
sha256sum() { "$TEST_SHA256SUM" "$@"; }
install() { mkdir -p "${*: -1}"; chmod 0755 "${*: -1}"; }
stat() {
  case $2 in
    %u:%g) printf '0:0\n' ;;
    %a) printf '755\n' ;;
    %s) wc -c < "$3" ;;
    *) return 2 ;;
  esac
}
curl() {
  printf 'curl %s\n' "$*" >> "$TEST_LOG"
  local output=''
  while (( $# )); do
    if [[ $1 == --output ]]; then output=$2; shift; fi
    shift
  done
  cp "$TEST_PAYLOAD" "$output"
}
'''
        return self.shell(binary + "\n" + fixtures + "\ninstall_compose_binary\n",
                          TEST_ARCHITECTURE=architecture, TEST_PAYLOAD=str(payload),
                          TEST_SHA256SUM=SHA256SUM or "sha256sum")

    @unittest.skipUnless(SHA256SUM, "sha256sum is unavailable")
    def test_binary_checksum_failure_never_executes_or_publishes_download(self) -> None:
        result = self.binary_fixture()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 does not match", result.stderr)
        self.assertFalse((self.root / "executed").exists())
        directory = self.root / "usr/local/lib/docker/cli-plugins"
        self.assertEqual(list(directory.iterdir()), [])

    @unittest.skipUnless(SHA256SUM, "sha256sum is unavailable")
    def test_verified_binary_is_published_systemwide_for_each_supported_architecture(self) -> None:
        for architecture, asset in (("amd64", "x86_64"), ("arm64", "aarch64")):
            with self.subTest(architecture=architecture):
                shutil.rmtree(self.root / "usr", ignore_errors=True)
                self.log.unlink(missing_ok=True)
                result = self.binary_fixture(valid_digest=True, architecture=architecture)
                self.assertEqual(result.returncode, 0, result.stderr)
                plugin = self.root / "usr/local/lib/docker/cli-plugins/docker-compose"
                self.assertEqual(plugin.read_bytes(), (self.root / "fixture-compose").read_bytes())
                self.assertEqual(plugin.stat().st_mode & 0o777, 0o755)
                self.assertEqual(plugin.stat().st_nlink, 1)
                self.assertEqual(list(plugin.parent.iterdir()), [plugin])
                self.assertIn("--proto =https --proto-redir =https", self.commands())
                self.assertIn("--max-time 240 --max-filesize 67108864", self.commands())
                self.assertIn("/v5.6.1/docker-compose-linux-" + asset, self.commands())

    def test_existing_plugin_or_symlink_directory_is_preserved(self) -> None:
        directory = self.root / "usr/local/lib/docker/cli-plugins"
        directory.mkdir(parents=True)
        plugin = directory / "docker-compose"
        plugin.write_text("administrator-owned plugin\n")
        result = self.binary_fixture()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires manual inspection", result.stderr)
        self.assertEqual(plugin.read_text(), "administrator-owned plugin\n")
        self.assertEqual(self.commands(), "")
        plugin.unlink()
        directory.rmdir()
        directory.symlink_to(self.root)
        result = self.binary_fixture()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("directory is unsafe", result.stderr)
        self.assertTrue(directory.is_symlink())
        self.assertEqual(self.commands(), "")

    def test_unsupported_binary_architecture_refuses_before_mutation(self) -> None:
        result = self.binary_fixture(architecture="armhf")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("supports amd64 and arm64 only", result.stderr)
        self.assertFalse((self.root / "usr").exists())
        self.assertEqual(self.commands(), "")


if __name__ == "__main__":
    unittest.main()
