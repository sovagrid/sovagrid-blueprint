#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Local Hub half of the reviewed remote-Agent enrollment protocol.

This module is a substrate for a future root-owned Web enrollment worker. It
does not open a socket, accept browser input, or start an installation itself.
The unprivileged SSH gateway must never mount the host source or run this code.
"""

from __future__ import annotations

import os
from pathlib import Path
import hashlib
import json
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time

# The vendored package is part of the five-root source manifest. It is loaded
# from the Blueprint component, never from a dynamic site-package or PYTHONPATH.
_VENDOR = Path(__file__).resolve().parents[1] / "vendor" / "connect"


def _owned_regular(path: Path, *, mode: int | None = None, owner: int = 0) -> bytes:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1 or
            info.st_mode & 0o022 or mode is not None and stat.S_IMODE(info.st_mode) != mode or
            info.st_size > 32 * 1024 * 1024):
        raise ImportError("Managed source file is not root-owned and immutable to other users")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != info.st_dev or opened.st_ino != info.st_ino:
            raise ImportError("Managed source changed while being inspected")
        data = bytearray()
        while len(data) <= 32 * 1024 * 1024:
            chunk = os.read(descriptor, min(131072, 32 * 1024 * 1024 - len(data) + 1))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > 32 * 1024 * 1024:
            raise ImportError("Managed source file is too large")
        return bytes(data)
    finally:
        os.close(descriptor)


def _guard_vendor_import(source: Path, vendor: Path, marker: Path, *, owner: int = 0) -> None:
    """Verify exactly the vendored Python runtime before importing its code."""
    for directory in (source.parent, source, source / "sovagrid-blueprint",
                      source / "sovagrid-blueprint" / "vendor", vendor):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise ImportError("Managed source directory is not root-owned and immutable")
    _owned_regular(marker, mode=0o600, owner=owner)
    raw = _owned_regular(source / "sovagrid-bundle.json", owner=owner)
    if len(raw) > 524288:
        raise ImportError("Managed source manifest is too large")
    try:
        manifest = json.loads(raw)
        hashes = manifest["sha256"]
        if (type(manifest["format"]) is not int or manifest["format"] != 1 or not isinstance(hashes, dict) or
                not isinstance(manifest["components"], dict) or
                set(manifest["components"]) != {"sovagrid-blueprint", "sovagrid-hub", "sovagrid-web",
                                                 "sovagrid-agent", "sovagrid-vpn"}):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise ImportError("Managed source manifest is invalid") from None
    prefix = "sovagrid-blueprint/vendor/connect/"
    expected = {name: digest for name, digest in hashes.items()
                if isinstance(name, str) and name.startswith(prefix)}
    required = {prefix + "sovagrid_connect/" + name for name in
                ("__init__.py", "agent_rpc.py", "core.py", "enrollment_protocol.py", "installer.py")}
    if not required <= expected.keys() or not expected:
        raise ImportError("Managed source manifest lacks the Connect runtime")
    actual = set()
    stack = [vendor]
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                relative = path.relative_to(source).as_posix()
                info = entry.stat(follow_symlinks=False)
                if info.st_uid != owner or info.st_mode & 0o022:
                    raise ImportError("Managed Connect runtime has unsafe ownership")
                if stat.S_ISDIR(info.st_mode):
                    stack.append(path)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    actual.add(relative)
                    digest = expected.get(relative)
                    if (not isinstance(digest, str) or len(digest) != 64 or
                            hashlib.sha256(_owned_regular(path, owner=owner)).hexdigest() != digest):
                        raise ImportError("Managed Connect runtime differs from its manifest")
                else:
                    raise ImportError("Managed Connect runtime contains an unsafe file")
    if actual != set(expected):
        raise ImportError("Managed Connect runtime has missing or extra files")


# A root worker must run only from the installed managed package. This check
# precedes import of any vendored Python module; the RPC subsequently checks
# the *entire* five-component manifest before every Hub action.
if os.geteuid() == 0:
    if _VENDOR != Path("/opt/sovagrid-src/sovagrid-blueprint/vendor/connect"):
        raise ImportError("Local Hub RPC must run from the installed managed source")
    _guard_vendor_import(Path("/opt/sovagrid-src"), _VENDOR,
                         Path("/var/lib/sovagrid/.managed-by-run-sh"))
if not (_VENDOR / "sovagrid_connect" / "agent_rpc.py").is_file():
    raise ImportError("The pinned Connect runtime is absent from the managed source")
sys.dont_write_bytecode = True
sys.path.insert(0, str(_VENDOR))
from sovagrid_connect import agent_rpc as _agent_rpc  # noqa: E402
from sovagrid_connect.core import ConnectionOptions  # noqa: E402
from sovagrid_connect.enrollment_protocol import MAX_RPC  # noqa: E402

_VENDOR_PACKAGE = (_VENDOR / "sovagrid_connect").resolve()
for _name, _module in tuple(sys.modules.items()):
    if _name == "sovagrid_connect" or _name.startswith("sovagrid_connect."):
        _file = getattr(_module, "__file__", None)
        if _file is None or not Path(_file).resolve().is_relative_to(_VENDOR_PACKAGE):
            raise ImportError("The loaded Connect runtime is not the pinned vendor copy")

_PYTHON = "/usr/bin/python3"
_HUB_API_PORT = 8766
_MAX_SCRIPT = 65536
_MAX_TIMEOUT = 120


class LocalHubFacade:
    """The Hub is on this host; EnrollmentAPI still uses its loopback API."""

    def __init__(self):
        self.options = ConnectionOptions(host="127.0.0.1", user="root", port=22,
                                         local_port=_HUB_API_PORT).validated()
        self.url = f"http://127.0.0.1:{_HUB_API_PORT}/"
        self._alive = True

    @property
    def alive(self) -> bool:
        return self._alive

    def close(self) -> None:
        self._alive = False


def _kill_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        process.kill()


def _bounded_python(script: str, payload: bytes, timeout: float, cancelled: threading.Event,
                    *, popen=subprocess.Popen, on_spawn=None) -> tuple[bytes, int]:
    """Run one fixed Python snippet without a shell and with bounded pipe data.

    The child gets a clean environment and a private process group. Any timeout,
    cancellation or output overflow kills that group, including helper children.
    """
    if (not isinstance(script, str) or not 1 <= len(script) <= _MAX_SCRIPT or
            not isinstance(payload, bytes) or len(payload) > MAX_RPC or
            not isinstance(timeout, (int, float)) or not 0 < timeout <= _MAX_TIMEOUT):
        raise _agent_rpc.RPCError("INVALID_REQUEST")
    if cancelled.is_set():
        raise _agent_rpc.RPCError("CANCELLED")
    try:
        process = popen([_PYTHON, "-I", "-c", script], cwd="/",
                        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
                        bufsize=0)
    except OSError:
        raise _agent_rpc.RPCError("SSH_FAILED") from None
    if on_spawn is not None:
        on_spawn(process)
    output = bytearray()
    remaining = memoryview(payload)
    stdin_open = process.stdin is not None
    stdout_open = process.stdout is not None
    selector = selectors.DefaultSelector()
    failed_write = False
    completed = False
    deadline = time.monotonic() + timeout
    try:
        if not stdin_open or not stdout_open:
            raise _agent_rpc.RPCError("SSH_FAILED")
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        if remaining:
            selector.register(process.stdin, selectors.EVENT_WRITE)
        else:
            process.stdin.close()
            stdin_open = False
        while stdout_open or process.poll() is None:
            if cancelled.is_set():
                raise _agent_rpc.RPCError("CANCELLED")
            left = deadline - time.monotonic()
            if left <= 0:
                raise _agent_rpc.RPCError("TIMEOUT")
            if not selector.get_map():
                try:
                    process.wait(timeout=min(left, 0.1))
                except subprocess.TimeoutExpired:
                    pass
                continue
            for key, _mask in selector.select(min(left, 0.1)):
                if key.fileobj is process.stdin:
                    try:
                        count = os.write(process.stdin.fileno(), remaining[:8192])
                    except (BrokenPipeError, OSError):
                        failed_write = True
                        count = 0
                    remaining = remaining[count:]
                    if not remaining or failed_write:
                        selector.unregister(process.stdin)
                        process.stdin.close()
                        stdin_open = False
                else:
                    try:
                        chunk = os.read(process.stdout.fileno(), min(4096, MAX_RPC - len(output) + 1))
                    except OSError:
                        raise _agent_rpc.RPCError("SSH_FAILED") from None
                    if not chunk:
                        selector.unregister(process.stdout)
                        process.stdout.close()
                        stdout_open = False
                    else:
                        output.extend(chunk)
                        if len(output) > MAX_RPC:
                            raise _agent_rpc.RPCError("INVALID_REPLY")
        code = process.wait(timeout=5)
        if (failed_write or remaining) and code == 0:
            raise _agent_rpc.RPCError("INVALID_REPLY")
        completed = True
        return bytes(output), code
    except (OSError, subprocess.TimeoutExpired):
        raise _agent_rpc.RPCError("SSH_FAILED") from None
    finally:
        selector.close()
        if not completed or process.poll() is None:
            _kill_group(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _kill_group(process)
        for stream in (process.stdin, process.stdout):
            if stream is not None and not stream.closed:
                stream.close()
        output.clear()


class LocalHubRPC(_agent_rpc.AgentRPC):
    """AgentRPC's strict protocol over a local root process instead of SSH."""

    def __init__(self, options: ConnectionOptions, *, role: str, progress=None,
                 popen=subprocess.Popen, root_check=os.geteuid):
        if role != "hub" or options.validated() != LocalHubFacade().options:
            raise ValueError("Local Hub RPC accepts only this host's fixed Hub identity")
        self._root_check = root_check
        super().__init__(options, role="hub", progress=progress, popen=popen)

    def _exchange(self, script, chunks, timeout, *, prefix=None):
        if self._root_check() != 0:
            raise _agent_rpc.RPCError("ROOT_REQUIRED")
        if script not in (_agent_rpc._PREFLIGHT, _agent_rpc._CALL_SCRIPT) or prefix not in (None, ""):
            raise _agent_rpc.RPCError("INVALID_REQUEST")
        raw = bytearray()
        try:
            for chunk in chunks:
                if not isinstance(chunk, bytes) or len(raw) + len(chunk) > MAX_RPC:
                    raise _agent_rpc.RPCError("INVALID_REQUEST")
                raw.extend(chunk)
            def on_spawn(process):
                with self._lock:
                    self._process = process
            return _bounded_python(script, bytes(raw), timeout, self._cancelled,
                                   popen=self._popen, on_spawn=on_spawn)
        finally:
            raw.clear()
            with self._lock:
                self._process = None

    def preflight(self):
        if self._root_check() != 0:
            raise _agent_rpc.RPCError("ROOT_REQUIRED")
        platform = super().preflight()
        # A fresh hub-preview through _CALL_SCRIPT checks the root-owned
        # managed marker and every file in the installed source manifest.
        super().call("hub-preview", {"protocol": 1})
        return platform


__all__ = ("LocalHubFacade", "LocalHubRPC")
