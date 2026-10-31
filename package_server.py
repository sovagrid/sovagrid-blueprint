#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Create a portable server source archive from the five server repositories.

Only Git-tracked, committed regular files are included. Server credentials,
runtime data, Git metadata and local build caches are never copied.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile


COMPONENTS = (
    "sovagrid-blueprint",
    "sovagrid-hub",
    "sovagrid-web",
    "sovagrid-agent",
    "sovagrid-vpn",
)


def valid_manifest_source_name(name: str) -> bool:
    """Reject paths the installed enrollment helper cannot verify."""
    return (isinstance(name, str) and len(name) <= 240
            and re.fullmatch(r"[A-Za-z0-9_.@-]+(?:/[A-Za-z0-9_.@-]+)*", name) is not None
            and all(part not in (".", "..") for part in name.split("/")))


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(("git", "-C", str(repo), *args))


def add_directory(archive: tarfile.TarFile, name: str) -> None:
    entry = tarfile.TarInfo(name.rstrip("/") + "/")
    entry.type = tarfile.DIRTYPE
    entry.mode = 0o755
    entry.mtime = 0
    entry.uid = entry.gid = 0
    entry.uname = entry.gname = "root"
    archive.addfile(entry)


def add_file(archive: tarfile.TarFile, path: Path, name: str, git_mode: int) -> str:
    contents = path.read_bytes()
    entry = tarfile.TarInfo(name)
    entry.size = len(contents)
    entry.mode = git_mode & 0o755
    entry.mtime = 0
    entry.uid = entry.gid = 0
    entry.uname = entry.gname = "root"
    archive.addfile(entry, io.BytesIO(contents))
    return hashlib.sha256(contents).hexdigest()


def package(destination: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    manifest: dict[str, object] = {"format": 1, "components": {}}
    files: list[tuple[Path, str, int]] = []

    for name in COMPONENTS:
        repo = root / name
        if not repo.is_dir() or not (repo / ".git").exists():
            raise SystemExit(f"Missing checkout: {repo}")
        if git(repo, "status", "--porcelain", "--untracked-files=no").strip():
            raise SystemExit(f"Commit tracked changes before packaging: {name}")
        commit = git(repo, "rev-parse", "HEAD").decode("ascii").strip()
        indexed = git(repo, "ls-files", "--stage", "-z").split(b"\0")
        entries = []
        for raw in indexed:
            if not raw:
                continue
            metadata, separator, filename = raw.partition(b"\t")
            fields = metadata.split()
            if separator != b"\t" or len(fields) != 3 or fields[2] != b"0" or fields[0] not in (b"100644", b"100755"):
                raise SystemExit(f"Unsupported Git entry in {name}")
            entries.append((Path(os.fsdecode(filename)), int(fields[0], 8)))
        if not entries:
            raise SystemExit(f"Empty repository: {name}")
        for relative, git_mode in entries:
            path = repo / relative
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(repo.resolve()):
                raise SystemExit(f"Unsupported tracked file in {name}: {relative}")
            bundled_name = f"{name}/{relative.as_posix()}"
            if not valid_manifest_source_name(bundled_name):
                raise SystemExit(f"Unsupported bundled filename in {name}: {relative}")
            files.append((path, bundled_name, git_mode))
        manifest["components"][name] = {"commit": commit, "file_count": len(entries)}

    destination = destination.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.NamedTemporaryFile(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent, delete=False
    )
    temporary_path = Path(temporary.name)
    temporary.close()
    try:
        hashes = {}
        with temporary_path.open("wb") as output:
            with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as archive:
                    directories = set()
                    for path, name, git_mode in files:
                        parts = name.split("/")[:-1]
                        for length in range(1, len(parts) + 1):
                            directory = "/".join(parts[:length])
                            if directory not in directories:
                                add_directory(archive, directory)
                                directories.add(directory)
                        hashes[name] = add_file(archive, path, name, git_mode)
                    manifest["sha256"] = hashes
                    payload = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")
                    entry = tarfile.TarInfo("sovagrid-bundle.json")
                    entry.size = len(payload)
                    entry.mode = 0o644
                    entry.mtime = 0
                    entry.uid = entry.gid = 0
                    entry.uname = entry.gname = "root"
                    archive.addfile(entry, io.BytesIO(payload))
        os.replace(temporary_path, destination)
    finally:
        temporary_path.unlink(missing_ok=True)
    print(f"Created {destination}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", type=Path,
                        default=Path(__file__).resolve().parent.parent / "SovaGrid-server-source.tar.gz")
    package(parser.parse_args().output)
