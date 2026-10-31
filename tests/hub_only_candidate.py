#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Build a review candidate from this Blueprint and pinned current components.

The published server-v0.11.0 archive is the baseline under test. The candidate
uses exact reviewed component commits with a newer Blueprint checkout.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile


PUBLISHED_SHA256 = "10abb18ca39d789d3a9cc8bd04d36126f6dd624a81e48219bd814fb6a15ab766"
PUBLISHED_COMMITS = {
    "sovagrid-blueprint": "aa778a8cbec811c0e7296d7a956683ee72e8bcc9",
    "sovagrid-agent": "7b4dab289ca239266b77584a927f6976f375042c",
    "sovagrid-hub": "f63511381c9c0fd8d8976891ed462aec9a88398e",
    "sovagrid-vpn": "e500d5a9a97ad329c33af6a06eb1d2f17a541897",
    "sovagrid-web": "cf126ca047f17df951ff40a5b75eb236b2939bd2",
}

CANDIDATE_COMMITS = {
    "sovagrid-agent": "7b4dab289ca239266b77584a927f6976f375042c",
    "sovagrid-hub": "ae8b2fc6075aa76b418ad202887515b78e9e63d1",
    "sovagrid-vpn": "e500d5a9a97ad329c33af6a06eb1d2f17a541897",
    "sovagrid-web": "eb53324c7f2ef6186ad445fb729b6687acf65595",
}


def check_published(archive: Path) -> None:
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != PUBLISHED_SHA256:
        raise SystemExit("Published server-v0.11.0 archive SHA-256 does not match the pin")
    with tarfile.open(archive, "r:gz") as package:
        entry = package.getmember("sovagrid-bundle.json")
        if entry.size > 1024 * 1024:
            raise SystemExit("Published bundle manifest is too large")
        stream = package.extractfile(entry)
        if stream is None:
            raise SystemExit("Published bundle manifest is unavailable")
        manifest = json.loads(stream.read(1024 * 1024))
    commits = {name: item.get("commit") for name, item in manifest.get("components", {}).items()}
    if manifest.get("format") != 1 or commits != PUBLISHED_COMMITS:
        raise SystemExit("Published server-v0.11.0 component commits differ from the approved pin")


def git(*arguments: str, timeout: int = 180) -> str:
    return subprocess.check_output(("git", *arguments), text=True, timeout=timeout).strip()


def build(archive: Path, blueprint: Path, workspace: Path, output: Path) -> None:
    check_published(archive)
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
    for name, commit in CANDIDATE_COMMITS.items():
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
    expected = CANDIDATE_COMMITS | {"sovagrid-blueprint": head}
    if commits != expected:
        raise SystemExit("Candidate bundle component commits are incorrect")
    print(f"Candidate Blueprint {head}; published server-v0.11.0 baseline and current component pins verified; "
          f"candidate bundle SHA-256 {hashlib.sha256(output.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("usage: hub_only_candidate.py PUBLISHED_ARCHIVE BLUEPRINT_CHECKOUT WORKSPACE CANDIDATE_ARCHIVE")
    build(*(Path(value).resolve() for value in sys.argv[1:]))
