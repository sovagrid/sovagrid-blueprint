#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Build a review candidate from this Blueprint and pinned current components.

The published server-v0.14.1 archive is the baseline under test. The candidate
uses exact reviewed component commits with a newer Blueprint checkout.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile


PUBLISHED_SHA256 = "c5786bb64467063196046144e665a98e347f40713facb37809b65a03eb70f347"
PUBLISHED_COMMITS = {
    "sovagrid-blueprint": "922c8e8bcc9752c090bacf3f5986765f8fa4865e",
    "sovagrid-agent": "abb00bb36489814593304d8e2055779d08e67eb9",
    "sovagrid-hub": "4fac7ee24201b451ecade607a2bf08e5ba7153dd",
    "sovagrid-vpn": "5ccfd083c8a2fd26413beb0a0d46393890c62b20",
    "sovagrid-web": "ca5db3ac6baf57318d5b02e944a1cac7f2e545bb",
}

def candidate_commits() -> dict[str, str]:
    commits = {"sovagrid-" + name.lower(): os.environ.get(name + "_REF", "")
               for name in ("HUB", "WEB", "AGENT", "VPN")}
    if any(re.fullmatch(r"[0-9a-f]{40}", value) is None for value in commits.values()):
        raise SystemExit("Set HUB_REF, WEB_REF, AGENT_REF and VPN_REF to exact reviewed commit SHAs")
    return commits


def check_published(archive: Path) -> None:
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != PUBLISHED_SHA256:
        raise SystemExit("Published server-v0.14.1 archive SHA-256 does not match the pin")
    with tarfile.open(archive, "r:gz") as package:
        entry = package.getmember("sovagrid-bundle.json")
        if entry.size > 1024 * 1024:
            raise SystemExit("Published bundle manifest is too large")
        stream = package.extractfile(entry)
        if stream is None:
            raise SystemExit("Published bundle manifest is unavailable")
        raw = stream.read(1024 * 1024)
        if hashlib.sha256(raw).hexdigest() != "ec6f567b0292916dd3f104f1441451708a955b79d02ef91f82237a8cf8603f1f":
            raise SystemExit("Published server-v0.14.1 inner manifest differs from its pin")
        manifest = json.loads(raw)
    commits = {name: item.get("commit") for name, item in manifest.get("components", {}).items()}
    if manifest.get("format") != 1 or commits != PUBLISHED_COMMITS:
        raise SystemExit("Published server-v0.14.1 component commits differ from the approved pin")


def git(*arguments: str, timeout: int = 180) -> str:
    return subprocess.check_output(("git", *arguments), text=True, timeout=timeout).strip()


def build(archive: Path, blueprint: Path, workspace: Path, output: Path) -> None:
    check_published(archive)
    selected = candidate_commits()
    if not (blueprint / ".git").exists() or not (blueprint / "package_server.py").is_file():
        raise SystemExit("Current Blueprint must be a Git checkout")
    if git("-C", str(blueprint), "status", "--porcelain", "--untracked-files=no"):
        raise SystemExit("Current Blueprint has uncommitted tracked files")
    head = git("-C", str(blueprint), "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise SystemExit("Current Blueprint commit is invalid")
    if workspace.exists() or workspace.is_symlink() or output.exists() or output.is_symlink():
        raise SystemExit("Candidate destination already exists")
    workspace.mkdir(parents=True)
    root = workspace / "sovagrid-blueprint"
    git("clone", "--quiet", "--no-hardlinks", "--", str(blueprint), str(root))
    git("-C", str(root), "checkout", "--quiet", "--detach", head)
    if git("-C", str(root), "rev-parse", "HEAD") != head:
        raise SystemExit("Candidate Blueprint checkout changed")
    for name, commit in selected.items():
        repo = workspace / name
        git("clone", "--quiet", "--", f"https://github.com/sovagrid/{name}.git", str(repo))
        git("-C", str(repo), "checkout", "--quiet", "--detach", commit)
        if git("-C", str(repo), "rev-parse", "HEAD") != commit:
            raise SystemExit(f"Candidate {name} checkout changed")
    subprocess.run((sys.executable, str(root / "package_server.py"), str(output)), check=True, timeout=180)
    with tarfile.open(output, "r:gz") as package:
        stream = package.extractfile("sovagrid-bundle.json")
        if stream is None:
            raise SystemExit("Candidate bundle manifest is unavailable")
        built = json.loads(stream.read(1024 * 1024))
    commits = {name: item.get("commit") for name, item in built["components"].items()}
    expected = selected | {"sovagrid-blueprint": head}
    if commits != expected:
        raise SystemExit("Candidate bundle component commits are incorrect")
    print(f"Candidate Blueprint {head}; published server-v0.14.1 baseline and current component pins verified; "
          f"candidate bundle SHA-256 {hashlib.sha256(output.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("usage: hub_only_candidate.py PUBLISHED_ARCHIVE BLUEPRINT_CHECKOUT WORKSPACE CANDIDATE_ARCHIVE")
    build(*(Path(value).resolve() for value in sys.argv[1:]))
