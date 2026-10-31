#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Verify the installed Web-to-Gateway-to-host SSH route before enabling it."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
import urllib.request


HOST_KEY_URL = "http://127.0.0.1:8766/api/v1/browser-ssh/host-key"
PANEL_URL = "http://127.0.0.1:8766/sovagrid/monitoring/"
MAX_KEY_RESPONSE = 16 * 1024
MAX_PANEL_RESPONSE = 256 * 1024
KEY_TYPE = re.compile(r"[A-Za-z0-9@._-]{4,96}\Z")
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")


def verify_host_key_response(raw: bytes) -> None:
    """Bind the Gateway's public host-key blob to its reported fingerprint."""
    if not isinstance(raw, bytes) or len(raw) > MAX_KEY_RESPONSE:
        raise ValueError("invalid host-key response size")
    value = json.loads(raw)
    if (not isinstance(value, dict) or set(value) !=
            {"protocol", "port", "key_type", "fingerprint", "host_key_blob"} or
            type(value["protocol"]) is not int or value["protocol"] != 1 or
            type(value["port"]) is not int or not 1 <= value["port"] <= 65535 or
            not isinstance(value["key_type"], str) or
            KEY_TYPE.fullmatch(value["key_type"]) is None or
            not isinstance(value["fingerprint"], str) or
            FINGERPRINT.fullmatch(value["fingerprint"]) is None or
            not isinstance(value["host_key_blob"], str) or
            not 12 <= len(value["host_key_blob"]) <= 10924):
        raise ValueError("invalid host-key response")
    try:
        key = base64.b64decode(value["host_key_blob"], validate=True)
    except binascii.Error as exc:
        raise ValueError("invalid host-key blob") from exc
    if (not 8 <= len(key) <= 8192 or
            base64.b64encode(key).decode("ascii") != value["host_key_blob"]):
        raise ValueError("noncanonical host-key blob")
    kind_length = int.from_bytes(key[:4], "big")
    if (not 4 <= kind_length <= 96 or 4 + kind_length > len(key) or
            key[4:4 + kind_length].decode("ascii", errors="replace") != value["key_type"]):
        raise ValueError("host-key type mismatch")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key).digest()).decode(
        "ascii").rstrip("=")
    if fingerprint != value["fingerprint"]:
        raise ValueError("host-key fingerprint mismatch")


def probe_once() -> None:
    request = urllib.request.Request(
        HOST_KEY_URL, data=b"{}", method="POST",
        headers={"Content-Type": "application/json", "Origin": "http://127.0.0.1:8766"})
    with urllib.request.urlopen(request, timeout=12) as response:
        if response.status != 200:
            raise ValueError("host-key route unavailable")
        raw = response.read(MAX_KEY_RESPONSE + 1)
    verify_host_key_response(raw)
    with urllib.request.urlopen(PANEL_URL, timeout=5) as response:
        if response.status != 200 or not response.headers.get(
                "Content-Type", "").startswith("text/html"):
            raise ValueError("panel route unavailable")
        page = response.read(MAX_PANEL_RESPONSE + 1)
    if (len(page) > MAX_PANEL_RESPONSE or b'id="sshLoginMode"' not in page or
            b'id="browserSshView"' not in page):
        raise ValueError("SSH-first panel missing")


def main() -> None:
    for attempt in range(5):
        try:
            probe_once()
            return
        except (OSError, ValueError, UnicodeError):
            if attempt == 4:
                raise SystemExit("browser SSH route cannot reach the host SSH service") from None
            time.sleep(1)


if __name__ == "__main__":
    main()
