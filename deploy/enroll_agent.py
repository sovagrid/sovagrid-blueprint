#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Enroll the Ubuntu host Agent through the local, certificate-verified Hub API."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import ssl
import stat
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


def request(path: str, context: ssl.SSLContext, payload: dict | None = None,
            token: str | None = None, method: str = "POST") -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        "https://localhost:8767" + path, data=data, headers=headers, method=method
    )
    with urllib.request.urlopen(req, context=context, timeout=10) as response:
        return json.load(response)


def write_private(path: Path, content: str, gid: int) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".agent-", dir=path.parent)
    try:
        os.fchown(fd, 0, gid)
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--token", type=Path, required=True)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--password-file", type=Path)
    parser.add_argument("--gid", type=int, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root")
    if args.config.exists() or args.token.exists():
        parser.error("Agent configuration or token already exists; refusing to replace it")
    if args.config.parent != args.token.parent:
        parser.error("Agent configuration and token must share a directory")
    if len(args.name) > 80:
        parser.error("server name is too long")

    context = ssl.create_default_context(cafile=str(args.ca))
    if args.password_file:
        password_stat = args.password_file.stat()
        if not stat.S_ISREG(password_stat.st_mode) or args.password_file.is_symlink():
            parser.error("admin password file must be a regular file, not a symlink")
        if password_stat.st_uid != 0 or stat.S_IMODE(password_stat.st_mode) != 0o600:
            parser.error("admin password file must be root-owned, mode 0600")
        username = "admin"
        password = args.password_file.read_text(encoding="utf-8").rstrip("\n")
    else:
        username = input("Hub admin username [admin]: ").strip() or "admin"
        password = getpass.getpass("Hub admin password: ")
    session = request("/api/v1/session", context, {"username": username, "password": password})
    password = ""
    session_token = session["token"]
    try:
        server = request("/api/v1/servers", context, {"name": args.name}, session_token)
        server_id = server["id"]
        agent_token = server["agent_token"]
        config = {
            "hub_url": "https://localhost:8767",
            "server_id": server_id,
            "token_file": str(args.token),
            "interval_seconds": 30,
            "allow_remote_commands": False,
            "ca_file": str(args.ca),
        }
        write_private(args.token, agent_token + "\n", args.gid)
        write_private(args.config, json.dumps(config, indent=2) + "\n", args.gid)
        print(f"Agent enrolled as server {server_id}; token saved outside Git.")
    finally:
        try:
            request("/api/v1/session", context, token=session_token, method="DELETE")
        except Exception:
            pass  # Session expires naturally; never print its bearer token.


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as exc:
        print(f"Hub API returned HTTP {exc.code}; enrollment stopped.", file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Enrollment failed: {exc}", file=sys.stderr)
        sys.exit(1)
