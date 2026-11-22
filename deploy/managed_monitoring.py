#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Install the dedicated Prometheus collector for a verified, running Hub."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable

SOURCE = Path("/opt/sovagrid-src")
STATE = Path("/var/lib/sovagrid-monitoring")
HUB_DATA = Path("/var/lib/sovagrid/hub")
HUB_MARKER = HUB_DATA.parent / ".managed-by-run-sh"
CANDIDATE_LOCK = Path("/opt/sovagrid-candidates/.lock")
DEPLOY = SOURCE / "sovagrid-blueprint/deploy"
PROJECT = "sovagrid-monitoring"
IMAGE_VERSION = "3.16.0"
IMAGE = ("docker.io/prom/prometheus:v3.16.0@"
         "sha256:e04987641b57704f408e31f6373ba4138ecf27cb4a165d24aabb6c38fddd0f06")
ORIGIN = "http://127.0.0.1:9090"
QUERY = 'up{job="sovagrid-hub",instance="127.0.0.1:8765"} == 1'
HEX = re.compile(r"[0-9a-f]{64}")
TOKEN = re.compile(rb"[A-Za-z0-9_-]{43}\n")
COMMAND_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/root", "LC_ALL": "C"}


class MonitoringError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Hub:
    container: str
    image: str
    manifest: str


@dataclass(frozen=True)
class Collector:
    container: str
    current: bool


@dataclass(frozen=True)
class Review:
    hub: Hub
    enabled: bool
    revision: int
    token_hash: str | None
    collector: Collector | None
    state: str

    @property
    def fingerprint(self) -> str:
        data = [
            1, IMAGE, self.hub.container, self.hub.image, self.hub.manifest,
            self.enabled, self.revision, self.token_hash,
            self.collector.container if self.collector else None, self.state,
        ]
        return hashlib.sha256(json.dumps(data, separators=(",", ":")).encode("ascii")).hexdigest()

    def result(self) -> dict:
        return {"protocol": 1, "action": "preview", "state": self.state,
                "image_version": IMAGE_VERSION, "review_sha256": self.fingerprint}


def _docker(*arguments: str, timeout: int = 6, extra_env: dict | None = None) -> str:
    try:
        result = subprocess.run(["docker", "--host=unix:///var/run/docker.sock", *arguments],
                                env=COMMAND_ENV | (extra_env or {}), timeout=timeout, check=True,
                                stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, text=True, encoding="utf-8")
        if len(result.stdout) > 512 * 1024:
            raise ValueError("Unexpected command output")
        return result.stdout
    except (OSError, ValueError, subprocess.SubprocessError):
        raise MonitoringError("MONITORING_UNAVAILABLE") from None


def _metadata(path: Path, *, uid: int, mode: int | None = None,
              directory: bool = False) -> os.stat_result:
    info = path.lstat()
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    if (not valid_type or (info.st_uid, info.st_gid) != (uid, uid) or info.st_mode & 0o022 or
            mode is not None and stat.S_IMODE(info.st_mode) != mode):
        raise ValueError("Unsafe managed file")
    return info


def _verifier():
    return runpy.run_path(str(DEPLOY / "remote_update_worker.py"))


def _container_ids(project: str, *, service: str | None = None, running: bool = False) -> list[str]:
    args = ["container", "ls", "--quiet", "--no-trunc", "--filter", "label=com.docker.compose.project=" + project]
    if service is not None:
        args.extend(("--filter", "label=com.docker.compose.service=" + service))
    if not running:
        args.append("--all")
    ids = _docker(*args).splitlines()
    if len(ids) > 1 or any(not HEX.fullmatch(container) for container in ids):
        raise MonitoringError("MONITORING_UNAVAILABLE")
    return ids


def _inspect(container: str) -> dict:
    details = json.loads(_docker("container", "inspect", container))
    if type(details) is not list or len(details) != 1 or details[0]["Id"] != container:
        raise ValueError("Unexpected container identity")
    return details[0]


def _running_hub(expected_manifest: str | None = None) -> Hub:
    try:
        if expected_manifest is None:
            expected_manifest, _ = _verifier()["source_manifest"](SOURCE, allow_generated=True)
        _metadata(HUB_MARKER, uid=0, mode=0o600)
        _metadata(HUB_DATA.parent, uid=0, directory=True)
        _metadata(HUB_DATA, uid=10001, directory=True)
        _metadata(HUB_DATA / "hub.sqlite", uid=10001)
        (container,) = _container_ids("sovagrid", service="hub", running=True)
        details = _inspect(container)
        image = details["Image"]
        config = details["Config"]
        stamps = [entry for entry in config["Env"]
                  if not isinstance(entry, str) or entry.startswith("SOVAGRID_BUNDLE_MANIFEST_SHA256=")]
        data_mounts = [mount for mount in details["Mounts"] if mount["Destination"] == "/data"]
        if (details["State"]["Running"] is not True or not re.fullmatch(r"sha256:[0-9a-f]{64}", image) or
                config["User"] != "10001:10001" or
                stamps != ["SOVAGRID_BUNDLE_MANIFEST_SHA256=" + expected_manifest] or
                len(data_mounts) != 1 or data_mounts[0]["Type"] != "bind" or
                data_mounts[0]["Source"] != str(HUB_DATA) or data_mounts[0]["RW"] is not True):
            raise ValueError("Unexpected Hub layout")
        return Hub(container, image, expected_manifest)
    except Exception:
        raise MonitoringError("HUB_UNAVAILABLE") from None


def _hub_status(hub: Hub, *operation: str) -> tuple[bool, int]:
    mutation = operation != ("status",)
    try:
        state = json.loads(_docker(
            "run", "--rm", "--pull=never", "--network=none", "--user=10001:10001",
            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=16",
            "--memory=128m", "--entrypoint=python3", "--mount",
            f"type=bind,source={HUB_DATA},target=/data",
            hub.image, "-B", "-m", "sovagrid_hub", "--db", "/data/hub.sqlite", "monitoring-managed",
            *operation, timeout=12,
        ))
        if (type(state) is not dict or set(state) != {"enabled", "revision"} or
                type(state["enabled"]) is not bool or type(state["revision"]) is not int or
                not 0 <= state["revision"] <= 2**63 - 1):
            raise ValueError("Unexpected Hub configuration")
        return state["enabled"], state["revision"]
    except (ValueError, MonitoringError):
        raise MonitoringError("MONITORING_UNCERTAIN" if mutation else "MONITORING_UNAVAILABLE") from None


def _token_hash() -> str | None:
    if not os.path.lexists(STATE):
        return None
    _metadata(STATE.parent, uid=0, directory=True)
    _metadata(STATE, uid=0, mode=0o700, directory=True)
    if {entry.name for entry in STATE.iterdir()} != {"tsdb", "hub-metrics", ".managed"}:
        raise ValueError("Unexpected managed directory")
    _metadata(STATE / "tsdb", uid=65534, mode=0o700, directory=True)
    token = STATE / "hub-metrics"
    info = _metadata(token, uid=65534, mode=0o400)
    marker = STATE / ".managed"
    marker_info = _metadata(marker, uid=0, mode=0o600)
    if info.st_size != 44 or marker_info.st_size != 3 or marker.read_bytes() != b"v1\n":
        raise ValueError("Unexpected managed files")
    raw = token.read_bytes()
    if not TOKEN.fullmatch(raw):
        raise ValueError("Unexpected bearer")
    return hashlib.sha256(raw.rstrip(b"\n")).hexdigest()


def _create_state() -> str:
    _metadata(STATE.parent, uid=0, directory=True)
    temporary = Path(tempfile.mkdtemp(prefix=".sovagrid-monitoring-", dir=STATE.parent))
    try:
        tsdb = temporary / "tsdb"
        tsdb.mkdir(mode=0o700)
        tsdb.chmod(0o700)
        os.chown(tsdb, 65534, 65534)
        for name, value, uid, mode in (
                (".managed", b"v1\n", 0, 0o600),
                ("hub-metrics", (secrets.token_urlsafe(32) + "\n").encode("ascii"), 65534, 0o400)):
            with (temporary / name).open("xb") as output:
                os.fchown(output.fileno(), uid, uid)
                os.fchmod(output.fileno(), mode)
                output.write(value)
                output.flush()
                os.fsync(output.fileno())
        _sync(temporary)
        temporary.rename(STATE)
        _sync(STATE.parent)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return _token_hash()


def _sync(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _collector_details(token_hash: str | None) -> dict | None:
    ids = _container_ids(PROJECT)
    if not ids:
        return None
    details = _inspect(ids[0])
    config = details["Config"]
    labels = config["Labels"]
    network = details["HostConfig"]["NetworkMode"]
    if (token_hash is None or labels.get("io.sovagrid.managed-monitoring") != "v1" or
            labels.get("com.docker.compose.service") != "prometheus" or
            not re.fullmatch(r"container:[0-9a-f]{64}", network)):
        raise MonitoringError("MONITORING_UNAVAILABLE")
    return details


def _collector(hub: Hub, token_hash: str | None) -> Collector | None:
    details = _collector_details(token_hash)
    if details is None:
        return None
    config = details["Config"]
    ready = (details["State"]["Running"] is True and
             details["HostConfig"]["NetworkMode"] == "container:" + hub.container and
             config["Image"] == IMAGE and config["Labels"].get("io.sovagrid.monitoring-manifest") == hub.manifest)
    return Collector(details["Id"], ready)


def _compose(hub: Hub, *arguments: str, timeout: int) -> str:
    return _docker("compose", "--env-file", "/dev/null", "--project-name", PROJECT,
                   "--project-directory", str(DEPLOY), "--file",
                   str(DEPLOY / "compose.monitoring.yaml"), *arguments, timeout=timeout,
                   extra_env={"SOVAGRID_MONITORING_HUB_ID": hub.container,
                              "SOVAGRID_MONITORING_MANIFEST": hub.manifest})


def _prepare_image() -> None:
    try:
        _docker("image", "inspect", "--format={{.Id}}", IMAGE)
    except MonitoringError:
        _docker("image", "pull", IMAGE, timeout=102)


def _promtool(collector: Collector, *arguments: str, timeout: int = 4) -> str:
    return _docker("container", "exec", collector.container, "/bin/promtool", *arguments, timeout=timeout)


def _scraping(collector: Collector, *, after: float) -> bool:
    try:
        query = f"timestamp({QUERY})"
        result = json.loads(_promtool(collector, "query", "instant", "--format=json", ORIGIN, query))
        if type(result) is not list or len(result) != 1:
            return False
        value = result[0]["value"]
        return (type(value) is list and len(value) == 2 and
                after <= float(value[1]) <= time.time() + 1)
    except (MonitoringError, TypeError, ValueError, KeyError):
        return False


def _wait(check: Callable[[], bool], *, seconds: int) -> None:
    deadline = time.monotonic() + seconds
    while True:
        try:
            if check():
                return
        except MonitoringError:
            pass
        if time.monotonic() >= deadline:
            raise MonitoringError("MONITORING_UNAVAILABLE")
        time.sleep(1)


def _review() -> Review:
    hub = _running_hub()
    try:
        enabled, revision = _hub_status(hub, "status")
        token_hash = _token_hash()
        collector = _collector(hub, token_hash)
        if enabled and collector and collector.current and _scraping(collector, after=time.time() - 30):
            state = "ready"
        elif enabled or token_hash or collector:
            state = "needs_reconcile"
        else:
            state = "absent"
        return Review(hub, enabled, revision, token_hash, collector, state)
    except (OSError, TypeError, ValueError, KeyError):
        raise MonitoringError("MONITORING_UNAVAILABLE") from None


def _install(review: Review, authorize: Callable[[], None]) -> dict:
    result = {"protocol": 1, "action": "applied", "state": "ready", "image_version": IMAGE_VERSION}
    if review.state == "ready":
        return result
    authorize()
    hub = review.hub
    applying = False
    try:
        # Pull only the static pin selected by this installer. A slow registry
        # times out before changing the running Hub or its collector config.
        _prepare_image()
        authorize()
        if _running_hub(hub.manifest) != hub or _hub_status(hub, "status") != (review.enabled, review.revision):
            raise MonitoringError("STALE_PREVIEW")
        applying = True
        bearer_hash = review.token_hash or _create_state()
        _compose(hub, "up", "-d", "--no-build", "--pull", "never", "prometheus", timeout=32)
        collector = _collector(hub, bearer_hash)
        if collector is None or not collector.current:
            raise MonitoringError("MONITORING_UNAVAILABLE")
        _wait(lambda: _promtool(collector, "check", "ready", "--url=" + ORIGIN) is not None,
              seconds=16)
        authorize()
        if _running_hub(hub.manifest) != hub:
            raise MonitoringError("STALE_PREVIEW")
        # If this was re-created from backup, the saved digest may no longer
        # have a corresponding local bearer. The same reviewed CAS replaces it.
        enabled, revision = _hub_status(hub, "configure", "--expected-revision",
                                        str(review.revision), "--exporter-token-sha256", bearer_hash)
        if not enabled or revision not in (review.revision, review.revision + 1):
            raise MonitoringError("MONITORING_UNCERTAIN")
        configured_at = time.time()
        _wait(lambda: _scraping(collector, after=configured_at), seconds=35)
        return result
    except MonitoringError as error:
        if applying:
            raise MonitoringError("MONITORING_UNCERTAIN") from None
        raise error
    except (OSError, TypeError, ValueError, KeyError):
        raise MonitoringError("MONITORING_UNCERTAIN") from None


def execute(action: str, payload: object, *, authorize: Callable[[], None]) -> dict:
    if type(payload) is not dict:
        raise MonitoringError("INVALID_INPUT")
    if action == "preview" and not payload:
        return _review().result()
    if (action != "apply" or set(payload) != {"confirm", "expected_review_sha256"} or
            payload["confirm"] is not True or type(payload["expected_review_sha256"]) is not str or
            not HEX.fullmatch(payload["expected_review_sha256"])):
        raise MonitoringError("INVALID_INPUT")
    review = _review()
    if not hmac.compare_digest(review.fingerprint, payload["expected_review_sha256"]):
        raise MonitoringError("STALE_PREVIEW")
    return _install(review, authorize)


@contextmanager
def operation_lock():
    """Follow the installer lock order before the broker's public Web lock."""
    verifier = _verifier()
    installation_error = verifier["UpdateFailure"]
    try:
        with verifier["installation_lock"]():
            try:
                _metadata(CANDIDATE_LOCK.parent, uid=0, mode=0o700, directory=True)
                observed = _metadata(CANDIDATE_LOCK, uid=0, mode=0o600)
                fd = os.open(CANDIDATE_LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            except (OSError, ValueError):
                raise MonitoringError("BUSY") from None
            try:
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) != (observed.st_dev, observed.st_ino):
                    raise MonitoringError("BUSY")
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    raise MonitoringError("BUSY") from None
                yield
            finally:
                os.close(fd)
    except (installation_error, OSError):
        raise MonitoringError("BUSY") from None


def stop_before_hub_recreation() -> None:
    """Release the existing Hub network namespace while retaining the TSDB."""
    if not os.path.lexists(STATE):
        return
    try:
        details = _collector_details(_token_hash())
        if details is not None and details["State"]["Running"] is True:
            _docker("container", "stop", "--time", "10", details["Id"], timeout=18)
    except (OSError, TypeError, ValueError, KeyError):
        raise MonitoringError("MONITORING_UNAVAILABLE") from None


def rebind() -> None:
    """Use only previously configured state after a managed Hub replacement."""
    if os.path.lexists(STATE):
        review = _review()
        if review.enabled:
            _install(review, lambda: None)


def _main() -> None:
    operations = {"install": lambda: _install(_review(), lambda: None),
                  "reconcile": rebind, "stop-before-recreate": stop_before_hub_recreation}
    if (os.geteuid() != 0 or Path(__file__).resolve().parent != DEPLOY or
            len(sys.argv) != 2 or sys.argv[1] not in operations):
        raise SystemExit("SovaGrid: fixed managed monitoring operation requires the installed root workflow")
    try:
        operations[sys.argv[1]]()
    except MonitoringError as error:
        raise SystemExit(f"SovaGrid: managed Prometheus: {error.code}") from None


if __name__ == "__main__":
    _main()
