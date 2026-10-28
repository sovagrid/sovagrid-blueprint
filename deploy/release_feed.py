#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Disabled-by-default, signed server release feed for the existing update timer.

No feed key is shipped yet. A reviewed public Ed25519 key must be pinned in
TRUST_ANCHORS by a later source release before this module can be enabled.
The release signing private key must never be present on a managed server.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


CONFIG = Path("/etc/sovagrid/release-feed.json")
STATE = Path("/var/lib/sovagrid/release-feed-state.json")
LOCK = Path("/var/lib/sovagrid/.release-feed.lock")
CANDIDATES = Path("/opt/sovagrid-candidates")
WORKER = Path(__file__).with_name("remote_update_worker.py")
AUTO_UPDATE = Path(__file__).with_name("auto_update.py")

# Deliberately empty until the release signing ceremony and independent key
# verification. Values are raw 32-byte Ed25519 public keys, never URLs/files.
TRUST_ANCHORS: dict[str, bytes] = {}
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
OPENSSL = "/usr/bin/openssl"
# Keep the feed in a separate repository. Tracking it in the packaged
# Blueprint would make the bundle hash recursively depend on its own feed.
FEED_URL = "https://raw.githubusercontent.com/sovagrid/sovagrid-update-feed/main/stable.json"
RELEASE_BASE = "https://github.com/sovagrid/sovagrid-blueprint/releases/download/"
ARCHIVE_NAME = "SovaGrid-server-source.tar.gz"
FEED_HOSTS = frozenset({"raw.githubusercontent.com"})
ARCHIVE_HOSTS = frozenset({"github.com", "release-assets.githubusercontent.com",
                           "objects.githubusercontent.com"})
CDN_HOSTS = frozenset({"release-assets.githubusercontent.com", "objects.githubusercontent.com"})
HASH = re.compile(r"[0-9a-f]{64}\Z")
KEY_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z")
SAFE_NAME = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z")
COMPONENTS = frozenset({"sovagrid-blueprint", "sovagrid-hub", "sovagrid-web",
                        "sovagrid-agent", "sovagrid-vpn"})
MAX_FEED = 32 * 1024
MAX_ARCHIVE = 64 * 1024**2
MAX_UNPACKED = 256 * 1024**2
MAX_FILES = 4096
MAX_RELEASES = 32
MAX_FEED_AGE = 30 * 86400
CLOCK_SKEW = 300
ROOT_UID = 0
TIMER = "sovagrid-release-feed.timer"
SERVICE = "sovagrid-release-feed.service"
SYSTEMD_UNITS = Path("/etc/systemd/system")
SYSTEMCTL = "/usr/bin/systemctl"
MANAGED_MARKER = Path("/var/lib/sovagrid/.release-feed-units-managed-by-run-sh")
MANAGED_MARKER_CONTENT = b"SOVAGRID_RELEASE_FEED_UNITS_V1\n"
INSTALLED_MANIFEST = Path("/opt/sovagrid-src/sovagrid-bundle.json")
MANUAL_POLICY = Path("/etc/sovagrid/auto-update.json")
HUB_ONLY_MANUAL_POLICY = Path("/etc/sovagrid-hub/hub-only-auto-update.json")
PROMOTION_STATE_DIR = Path("/var/lib/sovagrid-promotion")
HUB_ONLY_ARTIFACTS = (
    Path("/opt/sovagrid-agent-local"),
    Path("/etc/sovagrid-local"),
    Path("/var/lib/sovagrid-agent-local"),
    Path("/var/lib/sovagrid-containers-local"),
    Path("/etc/systemd/system/sovagrid-agent-local.service"),
    Path("/etc/systemd/system/sovagrid-hub-only-update.service"),
    Path("/etc/systemd/system/sovagrid-hub-only-update.timer"),
)


class Refused(Exception):
    pass


def require_root() -> None:
    if os.geteuid() != ROOT_UID:
        raise Refused("ROOT_REQUIRED")


def sha(value: object) -> str:
    if not isinstance(value, str) or HASH.fullmatch(value) is None:
        raise Refused("INVALID_DIGEST")
    return value


def _directory(path: Path, *, exact_mode: int | None = None) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise Refused("MISSING_DIRECTORY") from exc
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or
            info.st_mode & 0o022 or
            (exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode)):
        raise Refused("UNSAFE_DIRECTORY")


def _private_file(path: Path, *, optional: bool = False, limit: int = MAX_FEED) -> bytes | None:
    _directory(path.parent)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        if optional:
            return None
        raise Refused("MISSING_FILE")
    except OSError as exc:
        raise Refused("UNSAFE_FILE") from exc
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or
                info.st_size > limit):
            raise Refused("UNSAFE_FILE")
        return stream.read(limit + 1)


def _object(pairs: list[tuple[str, object]]) -> dict:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise Refused("DUPLICATE_JSON_KEY")
        value[key] = item
    return value


def _json(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    except (ValueError, UnicodeError) as exc:
        raise Refused("INVALID_JSON") from exc


def _atomic_private(path: Path, value: dict) -> None:
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(payload) > 4096:
        raise Refused("INVALID_STATE")
    _directory(path.parent)
    _private_file(path, optional=True, limit=4096)
    fd, name = tempfile.mkstemp(prefix=".release-feed-", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_dir(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextlib.contextmanager
def exclusive():
    require_root()
    _directory(LOCK.parent)
    try:
        fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as exc:
        raise Refused("UNSAFE_LOCK") from exc
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise Refused("UNSAFE_LOCK")
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield


def configuration(raw: bytes | None = None, *, require_trust: bool = True) -> dict:
    if raw is None:
        raw = _private_file(CONFIG, limit=4096)
    value = _json(raw or b"")
    if (not isinstance(value, dict) or set(value) != {"format", "channel", "enabled", "key_id"} or
            type(value["format"]) is not int or value["format"] != 1 or
            value["channel"] != "stable" or value["enabled"] is not True or
            not isinstance(value["key_id"], str) or KEY_ID.fullmatch(value["key_id"]) is None):
        raise Refused("INVALID_CONFIG")
    if require_trust:
        if value["key_id"] not in TRUST_ANCHORS:
            raise Refused("UNCONFIGURED_TRUST")
        key = TRUST_ANCHORS[value["key_id"]]
        if not isinstance(key, bytes) or len(key) != 32:
            raise Refused("UNCONFIGURED_TRUST")
    return value


def empty_state() -> dict:
    return {"format": 1, "highest_sequence": 0, "highest_version": "0.0.0",
            "highest_issued_at": 0, "last_seen_at": 0}


def _parse_state(raw: bytes | None) -> dict:
    if raw is None:
        return empty_state()
    value = _json(raw)
    # Older, never-activated previews wrote no feed issue timestamp. Import
    # their anti-replay sequence and upgrade the private ledger on next poll.
    if isinstance(value, dict) and "highest_issued_at" not in value:
        value = {**value, "highest_issued_at": 0}
    if (not isinstance(value, dict) or set(value) != set(empty_state()) or
            type(value["format"]) is not int or value["format"] != 1 or
            type(value["highest_sequence"]) is not int or value["highest_sequence"] < 0 or
            type(value["highest_issued_at"]) is not int or value["highest_issued_at"] < 0 or
            type(value["last_seen_at"]) is not int or value["last_seen_at"] < 0):
        raise Refused("INVALID_STATE")
    version(value["highest_version"])
    return value


def state() -> dict:
    return _parse_state(_private_file(STATE, optional=True, limit=4096))


def version(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise Refused("INVALID_VERSION")
    match = VERSION.fullmatch(value)
    if match is None:
        raise Refused("INVALID_VERSION")
    return tuple(int(part) for part in match.groups())


def verify_signature(raw: bytes, signature: bytes, key: bytes) -> None:
    if len(raw) > MAX_FEED or len(signature) != 64 or len(key) != 32:
        raise Refused("INVALID_SIGNATURE")
    with tempfile.TemporaryDirectory(prefix="sovagrid-feed-") as temporary:
        root = Path(temporary)
        for name, payload in (("feed.json", raw), ("feed.sig", signature),
                              ("release.der", ED25519_SPKI_PREFIX + key)):
            path = root / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
        try:
            result = subprocess.run(
                [OPENSSL, "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
                 "-inkey", str(root / "release.der"), "-sigfile", str(root / "feed.sig"),
                 "-in", str(root / "feed.json")],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=10, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise Refused("SIGNATURE_VERIFIER_UNAVAILABLE") from exc
        if result.returncode != 0:
            raise Refused("INVALID_SIGNATURE")


def validate_manifest(raw: bytes, signature: bytes, key_id: str, ledger: dict,
                      now: int | None = None) -> dict:
    if len(raw) > MAX_FEED or not raw:
        raise Refused("INVALID_MANIFEST")
    if key_id not in TRUST_ANCHORS:
        raise Refused("UNCONFIGURED_TRUST")
    verify_signature(raw, signature, TRUST_ANCHORS[key_id])
    value = _json(raw)
    if (not isinstance(value, dict) or set(value) != {"format", "channel", "key_id", "issued_at", "expires_at", "releases"} or
            type(value["format"]) is not int or value["format"] != 1 or
            value["channel"] != "stable" or value["key_id"] != key_id or
            type(value["issued_at"]) is not int or type(value["expires_at"]) is not int or
            not isinstance(value["releases"], list) or not 1 <= len(value["releases"]) <= MAX_RELEASES):
        raise Refused("INVALID_MANIFEST")
    now = int(time.time()) if now is None else now
    if (now + CLOCK_SKEW < ledger["last_seen_at"] or
            value["issued_at"] < ledger.get("highest_issued_at", 0) or
            value["issued_at"] > now + CLOCK_SKEW or
            value["expires_at"] <= now or value["issued_at"] <= 0 or
            value["expires_at"] <= value["issued_at"] or
            value["expires_at"] > value["issued_at"] + MAX_FEED_AGE):
        raise Refused("INVALID_MANIFEST_TIME")
    previous_sequence = 0
    previous_version = (0, 0, 0)
    previous_target = None
    seen_sources: set[str] = set()
    for item in value["releases"]:
        if (not isinstance(item, dict) or set(item) != {"sequence", "version", "from_manifest_sha256",
                                                      "to_manifest_sha256", "archive_sha256", "archive_size"} or
                type(item["sequence"]) is not int or not 0 < item["sequence"] < 2**63 or
                type(item["archive_size"]) is not int or not 0 < item["archive_size"] <= MAX_ARCHIVE):
            raise Refused("INVALID_RELEASE")
        current = sha(item["from_manifest_sha256"])
        target = sha(item["to_manifest_sha256"])
        sha(item["archive_sha256"])
        release_version = version(item["version"])
        if (item["sequence"] <= previous_sequence or release_version <= previous_version or
                current == target or current in seen_sources or target in seen_sources or
                (previous_target is not None and current != previous_target)):
            raise Refused("INVALID_RELEASE_ORDER")
        seen_sources.add(current)
        previous_sequence, previous_version = item["sequence"], release_version
        previous_target = target
    return value


def select_release(manifest: dict, current_manifest: str, ledger: dict) -> dict | None:
    sha(current_manifest)
    for item in manifest["releases"]:
        if item["from_manifest_sha256"] == current_manifest:
            if (item["sequence"] <= ledger["highest_sequence"] or
                    version(item["version"]) <= version(ledger["highest_version"])):
                raise Refused("REPLAY_OR_DOWNGRADE")
            return item
    for item in manifest["releases"]:
        if item["to_manifest_sha256"] == current_manifest:
            if (item["sequence"] < ledger["highest_sequence"] or
                    version(item["version"]) < version(ledger["highest_version"])):
                raise Refused("REPLAY_OR_DOWNGRADE")
            return None
    raise Refused("NO_COMPATIBLE_RELEASE")


def _validate_url(url: str, hosts: frozenset[str], *, allow_cdn_query: bool = False) -> None:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise Refused("UNSAFE_URL") from exc
    if (parsed.scheme != "https" or parsed.hostname not in hosts or parsed.username is not None or
            parsed.password is not None or port not in (None, 443) or
            (parsed.query and not (allow_cdn_query and parsed.hostname in CDN_HOSTS)) or
            parsed.fragment or not parsed.path.startswith("/")):
        raise Refused("UNSAFE_URL")


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3

    def __init__(self, hosts: frozenset[str]):
        self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_url(newurl, self.hosts, allow_cdn_query=self.hosts == ARCHIVE_HOSTS)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@contextlib.contextmanager
def _open(url: str, hosts: frozenset[str]):
    _validate_url(url, hosts)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _SafeRedirect(hosts),
    )
    request = urllib.request.Request(url, headers={
        "User-Agent": "SovaGrid-release-feed/1", "Accept-Encoding": "identity",
        "Cache-Control": "no-cache",
    })
    try:
        with opener.open(request, timeout=20) as response:
            _validate_url(response.geturl(), hosts, allow_cdn_query=hosts == ARCHIVE_HOSTS)
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise Refused("INVALID_RESPONSE")
            yield response
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise Refused("DOWNLOAD_FAILED") from exc


def fetch_small(url: str, hosts: frozenset[str], limit: int) -> bytes:
    with _open(url, hosts) as response:
        raw = response.read(limit + 1)
    if not raw or len(raw) > limit:
        raise Refused("INVALID_RESPONSE_SIZE")
    return raw


def archive_url(release_version: str) -> str:
    version(release_version)
    return RELEASE_BASE + "server-v" + release_version + "/" + ARCHIVE_NAME


def download_archive(release: dict, destination: Path) -> None:
    expected = release["archive_size"]
    digest = hashlib.sha256()
    total = 0
    deadline = time.monotonic() + 180
    with _open(archive_url(release["version"]), ARCHIVE_HOSTS) as response, destination.open("xb") as output:
        os.chmod(output.fileno(), 0o600)
        while True:
            if time.monotonic() > deadline:
                raise Refused("DOWNLOAD_TIMEOUT")
            block = response.read(min(1024 * 1024, expected - total + 1))
            if not block:
                break
            total += len(block)
            if total > expected:
                raise Refused("ARCHIVE_SIZE_MISMATCH")
            digest.update(block)
            output.write(block)
        output.flush()
        os.fsync(output.fileno())
    if total != expected or digest.hexdigest() != release["archive_sha256"]:
        raise Refused("ARCHIVE_HASH_MISMATCH")


def _member_name(member: tarfile.TarInfo) -> str:
    name = member.name.rstrip("/")
    if (not name.isascii() or SAFE_NAME.fullmatch(name) is None or
            any(part in (".", "..") for part in name.split("/")) or member.pax_headers):
        raise Refused("UNSAFE_ARCHIVE_MEMBER")
    if name != "sovagrid-bundle.json" and name.split("/", 1)[0] not in COMPONENTS:
        raise Refused("UNSAFE_ARCHIVE_MEMBER")
    return name


def unpack_archive(archive: Path, source: Path, target_manifest_sha256: str) -> None:
    sha(target_manifest_sha256)
    source.mkdir(mode=0o755)
    source.chmod(0o755)
    seen: set[str] = set()
    expanded = 0
    manifest_seen = False
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                name = _member_name(member)
                if name in seen or len(seen) >= MAX_FILES or member.uid != 0 or member.gid != 0:
                    raise Refused("UNSAFE_ARCHIVE_MEMBER")
                seen.add(name)
                output = source / name
                if member.type == tarfile.DIRTYPE:
                    if stat.S_IMODE(member.mode) != 0o755:
                        raise Refused("UNSAFE_ARCHIVE_MODE")
                    output.mkdir(mode=0o755)
                    output.chmod(0o755)
                    continue
                if (member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or
                        stat.S_IMODE(member.mode) not in (0o644, 0o755) or
                        member.size > 32 * 1024**2):
                    raise Refused("UNSAFE_ARCHIVE_MEMBER")
                expanded += member.size
                if expanded > MAX_UNPACKED or not output.parent.is_dir():
                    raise Refused("UNSAFE_ARCHIVE_MEMBER")
                if name == "sovagrid-bundle.json":
                    if member.size > 512 * 1024 or stat.S_IMODE(member.mode) != 0o644:
                        raise Refused("UNSAFE_ARCHIVE_MEMBER")
                    manifest_seen = True
                input_stream = tar.extractfile(member)
                if input_stream is None:
                    raise Refused("UNSAFE_ARCHIVE_MEMBER")
                fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             stat.S_IMODE(member.mode))
                os.fchmod(fd, stat.S_IMODE(member.mode))
                with os.fdopen(fd, "wb") as stream:
                    remaining = member.size
                    while remaining:
                        block = input_stream.read(min(1024 * 1024, remaining))
                        if not block:
                            raise Refused("TRUNCATED_ARCHIVE")
                        remaining -= len(block)
                        stream.write(block)
                    stream.flush()
                    os.fsync(stream.fileno())
        if (not manifest_seen or hashlib.sha256((source / "sovagrid-bundle.json").read_bytes()).hexdigest()
                != target_manifest_sha256):
            raise Refused("TARGET_MANIFEST_MISMATCH")
    except (OSError, tarfile.TarError) as exc:
        raise Refused("UNSAFE_ARCHIVE") from exc


def _worker(*args: str) -> subprocess.CompletedProcess[str]:
    try:
        info = WORKER.lstat()
    except OSError as exc:
        raise Refused("UNSAFE_WORKER") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
        raise Refused("UNSAFE_WORKER")
    try:
        return subprocess.run([sys.executable, "-I", str(WORKER), *args],
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              errors="replace", timeout=120, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refused("WORKER_UNAVAILABLE") from exc


def current_manifest() -> str:
    result = _worker("preview")
    matches = [line.removeprefix("SG_CURRENT_MANIFEST:") for line in result.stdout.splitlines()
               if line.startswith("SG_CURRENT_MANIFEST:")]
    if result.returncode != 0 or len(matches) != 1 or "SG_VERSION_PREFLIGHT:OK" not in result.stdout.splitlines():
        raise Refused("CURRENT_VERSION_UNAVAILABLE")
    return sha(matches[0])


def existing_policy() -> bool:
    # A manual one-candidate approval always takes priority over feed discovery.
    return any(policy.exists() or policy.is_symlink()
               for policy in (MANUAL_POLICY, HUB_ONLY_MANUAL_POLICY))


def stage_candidate(release: dict, current: str) -> None:
    _directory(CANDIDATES, exact_mode=0o700)
    target = CANDIDATES / release["archive_sha256"]
    if target.exists() or target.is_symlink():
        result = _worker("preflight", release["archive_sha256"], current)
        if result.returncode != 0 or "SG_UPDATE_PREFLIGHT:OK" not in result.stdout.splitlines():
            raise Refused("EXISTING_CANDIDATE_INVALID")
        _directory(target, exact_mode=0o700)
        if hashlib.sha256((target / "source/sovagrid-bundle.json").read_bytes()).hexdigest() != release["to_manifest_sha256"]:
            raise Refused("TARGET_MANIFEST_MISMATCH")
        return
    temporary = Path(tempfile.mkdtemp(prefix=".feed-stage-", dir=CANDIDATES))
    try:
        os.chmod(temporary, 0o700)
        archive = temporary / "bundle.tar.gz"
        download_archive(release, archive)
        unpack_archive(archive, temporary / "source", release["to_manifest_sha256"])
        ready = temporary / ".ready"
        with ready.open("x", encoding="ascii") as output:
            os.chmod(output.fileno(), 0o600)
            output.write(release["archive_sha256"] + "\n")
            output.flush()
            os.fsync(output.fileno())
        _fsync_dir(temporary)
        os.rename(temporary, target)
        _fsync_dir(CANDIDATES)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    result = _worker("preflight", release["archive_sha256"], current)
    if result.returncode != 0 or "SG_UPDATE_PREFLIGHT:OK" not in result.stdout.splitlines():
        raise Refused("PREFLIGHT_FAILED")


def arm_candidate(release: dict, current: str) -> None:
    try:
        info = AUTO_UPDATE.lstat()
    except OSError as exc:
        raise Refused("UNSAFE_AUTO_UPDATE") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
        raise Refused("UNSAFE_AUTO_UPDATE")
    try:
        result = subprocess.run([sys.executable, "-I", str(AUTO_UPDATE), "arm",
                                 release["archive_sha256"], current],
                                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                errors="replace", timeout=180, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refused("AUTO_UPDATE_UNAVAILABLE") from exc
    if result.returncode != 0 or "SG_AUTO_UPDATE:ARMED" not in result.stdout.splitlines():
        raise Refused("AUTO_UPDATE_REFUSED")


def _unit_installed(name: str) -> bool:
    path = SYSTEMD_UNITS / name
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise Refused("UNSAFE_UNIT") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
        raise Refused("UNSAFE_UNIT")
    return True


def _managed_units_installed() -> bool:
    marker = _private_file(MANAGED_MARKER, optional=True, limit=128)
    if marker is None:
        return False
    if marker != MANAGED_MARKER_CONTENT:
        raise Refused("UNSAFE_UNIT_MARKER")
    return _unit_installed(SERVICE) and _unit_installed(TIMER)


def _systemctl(*args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run([SYSTEMCTL, *args], stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, errors="replace",
                              timeout=30, check=False,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refused("TIMER_UNAVAILABLE") from exc


def _remove_config() -> None:
    if _private_file(CONFIG, optional=True, limit=4096) is not None:
        CONFIG.unlink()
        _fsync_dir(CONFIG.parent)


def _root_owned_file(path: Path, *, limit: int) -> bytes | None:
    """Read public managed bytes without following a swapped symlink."""
    if not path.parent.exists():
        return None
    _directory(path.parent)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise Refused("UNSAFE_FILE") from exc
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or
                info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > limit):
            raise Refused("UNSAFE_FILE")
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise Refused("UNSAFE_FILE")
        return raw


def _digest(raw: bytes | None) -> str | None:
    return hashlib.sha256(raw).hexdigest() if raw is not None else None


def _snapshot() -> dict:
    """Read-only optimistic preview; a mutation rechecks it under the root lock."""
    require_root()
    config_bytes = _private_file(CONFIG, optional=True, limit=4096)
    # A previously trusted key may be removed in a later server release.
    # Poll stays fail-closed, while status and reviewed disable must still work.
    config = configuration(config_bytes, require_trust=False) if config_bytes is not None else None
    ledger_bytes = _private_file(STATE, optional=True, limit=4096)
    ledger = _parse_state(ledger_bytes)
    marker_bytes = _private_file(MANAGED_MARKER, optional=True, limit=128)
    if marker_bytes is not None and marker_bytes != MANAGED_MARKER_CONTENT:
        raise Refused("UNSAFE_UNIT_MARKER")
    unit_bytes = {name: _root_owned_file(SYSTEMD_UNITS / name, limit=64 * 1024)
                  for name in (SERVICE, TIMER)}
    timer_installed = (marker_bytes is not None and
                       all(raw is not None for raw in unit_bytes.values()))
    timer_enabled = _systemctl("is-enabled", "--quiet", TIMER).returncode == 0
    timer_active = _systemctl("is-active", "--quiet", TIMER).returncode == 0
    manual_bytes = {str(path): _private_file(path, optional=True, limit=4096)
                    for path in (MANUAL_POLICY, HUB_ONLY_MANUAL_POLICY)}
    manifest_bytes = _root_owned_file(INSTALLED_MANIFEST, limit=512 * 1024)
    anchors = {key_id: hashlib.sha256(ED25519_SPKI_PREFIX + key).hexdigest()
               for key_id, key in sorted(TRUST_ANCHORS.items()) if isinstance(key, bytes) and len(key) == 32}
    report = {"format": 1, "channel": "stable", "enabled": config is not None,
              "key_id": config["key_id"] if config else None,
              "available_keys": anchors, "timer_installed": timer_installed,
              "timer_enabled": timer_enabled, "timer_active": timer_active,
              "manual_candidate_active": any(raw is not None for raw in manual_bytes.values()),
              "installed_manifest_sha256": _digest(manifest_bytes), "ledger": ledger}
    revision_input = {**report, "config_sha256": _digest(config_bytes),
                      "ledger_sha256": _digest(ledger_bytes),
                      "marker_sha256": _digest(marker_bytes),
                      "manual_policy_sha256": {name: _digest(raw) for name, raw in manual_bytes.items()},
                      "unit_sha256": {name: _digest(raw) for name, raw in unit_bytes.items()}}
    raw = json.dumps(revision_input, sort_keys=True, separators=(",", ":")).encode("utf-8")
    report["state_revision"] = hashlib.sha256(raw).hexdigest()
    return report


def status() -> None:
    """Machine-readable, local-only status without writing any files."""
    print(json.dumps(_snapshot(), sort_keys=True))


def _check_expected_state(expected_state: str | None) -> None:
    if expected_state is None:
        return
    if not isinstance(expected_state, str) or HASH.fullmatch(expected_state) is None:
        raise Refused("INVALID_EXPECTED_STATE")
    if _snapshot()["state_revision"] != expected_state:
        raise Refused("STATE_CHANGED")


def _require_full_server() -> None:
    """The signed feed currently arms only the full-server update worker.

    A Hub-only installation keeps an independent external Agent and reverse tunnel.
    Even a partial or unsafe promotion footprint must block full updates.
    """
    for path in (PROMOTION_STATE_DIR, *HUB_ONLY_ARTIFACTS, HUB_ONLY_MANUAL_POLICY):
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise Refused("HUB_ONLY_UNSUPPORTED") from exc
        raise Refused("HUB_ONLY_UNSUPPORTED")


def enable(key_id: str | None = None, *, expected_state: str | None = None) -> None:
    """Verify the live feed before creating an opt-in config or starting a timer."""
    with exclusive():
        _require_full_server()
        _check_expected_state(expected_state)
        available = {key for key, public in TRUST_ANCHORS.items()
                     if isinstance(public, bytes) and len(public) == 32}
        if key_id is None and len(available) == 1:
            key_id = next(iter(available))
        if key_id not in available or not isinstance(key_id, str) or KEY_ID.fullmatch(key_id) is None:
            raise Refused("UNCONFIGURED_TRUST")
        if not _managed_units_installed():
            raise Refused("TIMER_NOT_INSTALLED")
        existing = _private_file(CONFIG, optional=True, limit=4096)
        if existing is not None and configuration()["key_id"] != key_id:
            raise Refused("ALREADY_ENABLED_WITH_OTHER_KEY")
        ledger = state()
        raw = fetch_small(FEED_URL, FEED_HOSTS, MAX_FEED)
        signature = fetch_small(FEED_URL + ".sig", FEED_HOSTS, 64)
        manifest = validate_manifest(raw, signature, key_id, ledger)
        select_release(manifest, current_manifest(), ledger)
        _require_full_server()
        _atomic_private(STATE, {**ledger, "highest_issued_at": manifest["issued_at"],
                                "last_seen_at": int(time.time())})
        config = {"format": 1, "channel": "stable", "enabled": True, "key_id": key_id}
        _atomic_private(CONFIG, config)
        try:
            result = _systemctl("enable", "--now", TIMER)
            if result.returncode != 0 or _systemctl("is-active", "--quiet", TIMER).returncode != 0:
                raise Refused("TIMER_UNAVAILABLE")
        except Refused:
            if existing is None:
                _remove_config()
            raise
        print("SG_RELEASE_FEED:ENABLED:" + key_id)


def disable(*, expected_state: str | None = None) -> None:
    """Stop future discovery. The separate one-candidate approval is unchanged."""
    with exclusive():
        _check_expected_state(expected_state)
        timer_error = None
        try:
            if _unit_installed(TIMER) and _systemctl("disable", "--now", TIMER).returncode != 0:
                timer_error = Refused("TIMER_UNAVAILABLE")
        except Refused as exc:
            timer_error = exc
        # Even if systemctl fails, removing opt-in makes any running or future
        # poll refuse before network access or staging. Keep the failure visible.
        _remove_config()
        if timer_error is not None:
            raise timer_error
        print("SG_RELEASE_FEED:DISABLED")


def poll() -> None:
    with exclusive():
        _require_full_server()
        config = configuration()
        if existing_policy():
            print("SG_RELEASE_FEED:ONE_CANDIDATE_ACTIVE")
            return
        ledger = state()
        raw = fetch_small(FEED_URL, FEED_HOSTS, MAX_FEED)
        signature = fetch_small(FEED_URL + ".sig", FEED_HOSTS, 64)
        manifest = validate_manifest(raw, signature, config["key_id"], ledger)
        current = current_manifest()
        release = select_release(manifest, current, ledger)
        _require_full_server()
        if release is None:
            _atomic_private(STATE, {**ledger, "highest_issued_at": manifest["issued_at"],
                                    "last_seen_at": int(time.time())})
            print("SG_RELEASE_FEED:CURRENT")
            return
        stage_candidate(release, current)
        _require_full_server()
        # Consume the sequence durably before allowing the existing timer to
        # act. A crash or failed arm can require operator review, but cannot
        # leave an armed unattended update without its anti-replay record.
        _atomic_private(STATE, {"format": 1, "highest_sequence": release["sequence"],
                                "highest_version": release["version"],
                                "highest_issued_at": manifest["issued_at"],
                                "last_seen_at": int(time.time())})
        arm_candidate(release, current)
        print("SG_RELEASE_FEED:ARMED:" + release["version"])


def main(args: list[str]) -> int:
    try:
        if args == ["poll"]:
            poll()
        elif args == ["status"]:
            status()
        elif args == ["disarm"]:
            disable()
        elif args and args[0] in ("enable", "disable"):
            action = args[0]
            parts = args[1:]
            expected_state = None
            if "--expected-state" in parts:
                if len(parts) < 2 or parts[-2] != "--expected-state" or parts.count("--expected-state") != 1:
                    raise Refused("ARGS")
                expected_state = parts[-1]
                parts = parts[:-2]
            if action == "enable" and len(parts) <= 1:
                enable(parts[0] if parts else None, expected_state=expected_state)
            elif action == "disable" and not parts:
                disable(expected_state=expected_state)
            else:
                raise Refused("ARGS")
        else:
            raise Refused("ARGS")
    except Refused as exc:
        print("SG_RELEASE_FEED_REFUSE:" + str(exc), flush=True)
        return 40
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
