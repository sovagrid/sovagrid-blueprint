#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Validate the Web assets required by the Agent setup and restore features."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys


AGENT_ASSETS = ("agent-features.js", "agent-features.css")
RESTORE_ASSETS = (*AGENT_ASSETS, "host-restore.js", "host-restore.css")
ENTRYPOINTS = "assets/entrypoints.json"
MAX_ENTRYPOINTS_BYTES = 64 * 1024
_ASSET_PATH = re.compile(r"assets/(js|css)/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+")


class WebAssetsError(ValueError):
    pass


def _directory(path: Path) -> None:
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise WebAssetsError(f"unsafe Web asset directory: {path.name}")


def _regular_file(root: Path, relative: str) -> Path:
    path = root
    parts = relative.split("/")
    try:
        for part in parts[:-1]:
            path = path / part
            _directory(path)
        path = path / parts[-1]
        info = path.lstat()
    except OSError as exc:
        raise WebAssetsError(f"missing Web asset: {relative}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
        raise WebAssetsError(f"unsafe or empty Web asset: {relative}")
    return path


def _entrypoints(root: Path) -> dict:
    path = _regular_file(root, ENTRYPOINTS)
    try:
        with path.open("rb") as stream:
            content = stream.read(MAX_ENTRYPOINTS_BYTES + 1)
        if len(content) > MAX_ENTRYPOINTS_BYTES:
            raise WebAssetsError("Web entrypoints manifest is too large")
        assets = json.loads(content)["assets"]
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise WebAssetsError("invalid Web entrypoints manifest") from exc
    if not isinstance(assets, dict):
        raise WebAssetsError("invalid Web entrypoints manifest")
    return assets


def asset_files(root: Path, names: tuple[str, ...] = RESTORE_ASSETS) -> dict[str, Path]:
    """Resolve the required files from one layout. An incomplete split tree fails."""
    _directory(root)
    if os.path.lexists(root / "assets"):
        entrypoints = _entrypoints(root)
    else:
        entrypoints = None
    files = {}
    for name in names:
        relative = name
        if entrypoints is not None:
            relative = entrypoints.get(name)
            match = _ASSET_PATH.fullmatch(relative) if isinstance(relative, str) else None
            if not match or match[1] != name.rsplit(".", 1)[1] or relative.split("/")[-1] != name:
                raise WebAssetsError(f"invalid Web entrypoint: {name}")
        files[name] = _regular_file(root, relative)
    return files


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: web_assets.py WEB_ROOT", file=sys.stderr)
        return 2
    try:
        asset_files(Path(argv[1]))
    except (OSError, WebAssetsError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
