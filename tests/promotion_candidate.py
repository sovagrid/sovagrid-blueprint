#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Build a review candidate from this Blueprint and exact current components.

The published archive is a dependency pin, not the installer under test.
Only the candidate assembled from the checked-out Blueprint is installed in
the disposable VM.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile


PUBLISHED_SHA256 = "9deb36ef29aff0b21eff7b2f367dd8642a747ccafc6d2d8f0bc75010d3e5d907"
PUBLISHED_COMMITS = {
    "sovagrid-blueprint": "3bf739960c87110efdec2c0a2a589df1b625e28d",
    "sovagrid-agent": "d6d80c5876a69c76ee9b3d7d1a39c348164bb2a8",
    "sovagrid-hub": "c5bdbd7410b8879d990ea201d804bc8c7892ed7b",
    "sovagrid-vpn": "0505dd6ed711deb12c35c88adc264240fb68b054",
    "sovagrid-web": "79e89d2486214aff91706e057eedeca745f5e320",
}
CANDIDATE_COMMITS = {
    "sovagrid-agent": "f43c00c13cecbf824aa062fec65c0efb85ba1c60",
    "sovagrid-hub": "99ff6fcfbf95f40e382efb1e21e6c442fc0754ba",
    "sovagrid-vpn": "8317390dbf2f41fad22ea6cdda65aa960cae2046",
    "sovagrid-web": "9378e3a2bd3ab90b410f3c85ddcd963dcbe51748",
}


def check_published(archive: Path) -> None:
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != PUBLISHED_SHA256:
        raise SystemExit("Published 0.3.8 archive SHA-256 does not match the pin")
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
        raise SystemExit("Published 0.3.8 component commits differ from the approved pin")


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
    print(f"Candidate Blueprint {head}; published 0.3.8 component pin verified; "
          f"candidate bundle SHA-256 {hashlib.sha256(output.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("usage: promotion_candidate.py PUBLISHED_ARCHIVE BLUEPRINT_CHECKOUT WORKSPACE CANDIDATE_ARCHIVE")
    build(*(Path(value).resolve() for value in sys.argv[1:]))
