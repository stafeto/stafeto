#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The tree of third-party/littlefs is the release v2.11.3 plus the change that
third-party/littlefs/STAFETO-CHANGES.md states, and nothing else.

It checks that (1) each of the seven files of the release has the SHA-256 of the release, except
lfs.c and lfs.h, which have the SHA-256 of the release with the change; (2) the patch of the change
(stafeto-changes.patch), applied backwards to lfs.c and lfs.h, gives exactly the files of the
release; (3) the directory holds no other C or header file; (4) the README and the file of the
change name the same checksums. A silent edit of lfs.c, lfs.h or any other file of the release
fails the first check; a change that is not in the patch fails the second.

Runs in `cargo xtask ci` ("littlefs sources"). To carry the change to a new release, follow
STAFETO-CHANGES.md and update the checksums below."""

import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIR = ROOT / "third-party" / "littlefs"

# The release v2.11.3 (tag commit 6cb4e86540eca0d9ba62500a298385c9d863c8be), file by file.
UPSTREAM = {
    "lfs.c": "a36d6a095785ddea9571d541d68d3e4ef01d5b255a99d17d3f07fb6ea60ea132",
    "lfs.h": "b1befd7288d08815accc8f9af744c55686c0b9e3ac0061c32ceee38a1b3eb96d",
    "lfs_util.c": "f2fbde533670560434bd9f5a547174cc7c5a4670a02c47b4bd85180dced8b2ec",
    "lfs_util.h": "548d46aa524dc7449e16739286c1a422a52f9de727ff0be0c2ffc5593f5ca981",
    "LICENSE.md": "0cb4ff1daf5fdc1359c6a6ee3116092f08fc100c9d58b1b77ab17bfd801f856d",
    "SPEC.md": "6dd74dfc58ac93589f8e002bb73c0830a59206912cfe8c951c07eb2bd5fccad0",
    "DESIGN.md": "2a8b3459d74b9fa8bdd947738522c46331739405b1fc3d70f057f636a1dea768",
}
# The two files the change touches, with the change.
CHANGED = {
    "lfs.c": "7fa02871d2147b6230183694e8b9efc1cfd797808cba687aa4e91e19debab557",
    "lfs.h": "9c13b195643ccfd5025961fa3fb6029bbb9be0f6ffce9488ec9be958d33163b6",
}
PATCH = "stafeto-changes.patch"
DOCS = ("README.md", "STAFETO-CHANGES.md")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_files():
    """The files of the directory, as paths relative to it: those git tracks (the check is about
    what is committed, so a `.DS_Store` or a build leftover of a local tree is not one), and every
    file of the directory when the tree is not a git checkout."""
    run = subprocess.run(["git", "ls-files", "-z", "--", str(DIR)], capture_output=True,
                         text=True, cwd=ROOT, stdin=subprocess.DEVNULL)
    if run.returncode == 0 and run.stdout:
        return sorted(Path(p).relative_to(DIR.relative_to(ROOT)).as_posix()
                      for p in run.stdout.split("\0") if p)
    return sorted(p.relative_to(DIR).as_posix() for p in DIR.rglob("*") if p.is_file())


def check():
    problems = []
    for name, upstream in UPSTREAM.items():
        want = CHANGED.get(name, upstream)
        got = sha256(DIR / name)
        if got != want:
            kind = "the release plus the change" if name in CHANGED else "the release"
            problems.append(f"{name}: SHA-256 {got}, wanted that of {kind} ({want})")

    # The patch, applied backwards, gives the release.
    patch = DIR / PATCH
    if not patch.is_file():
        problems.append(f"{PATCH} is missing")
    else:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "third-party" / "littlefs"
            base.mkdir(parents=True)
            for name in CHANGED:
                shutil.copy(DIR / name, base / name)
            run = subprocess.run(
                ["patch", "-R", "-f", "-p1", "-s", "-d", tmp, "-i", str(patch)],
                capture_output=True, text=True, stdin=subprocess.DEVNULL)
            if run.returncode != 0:
                problems.append(f"{PATCH} does not reverse on the tree: {run.stdout}{run.stderr}")
            else:
                for name, upstream in UPSTREAM.items():
                    if name in CHANGED and sha256(base / name) != upstream:
                        problems.append(
                            f"{name} with {PATCH} reversed is not the release: the change in the "
                            f"tree is not the change the patch states")

    # No other file in the directory or below it.
    known = set(UPSTREAM) | {PATCH, "build.rs", "Cargo.toml", "README.md", "STAFETO-CHANGES.md",
                             "src/lib.rs"}
    for name in tree_files():
        if name not in known:
            problems.append(f"{name}: a file that is neither the release nor the change")

    # The documents name the same checksums.
    for doc in DOCS:
        text = (DIR / doc).read_text()
        for digest in list(UPSTREAM.values()) + list(CHANGED.values()):
            if digest not in text and doc == "STAFETO-CHANGES.md":
                problems.append(f"{doc} does not name the checksum {digest}")
        for name, digest in CHANGED.items():
            if doc == "README.md" and digest not in text:
                problems.append(f"{doc} does not name the checksum of {name} with the change")
    return problems


def main():
    problems = check()
    if problems:
        print("third-party/littlefs is not the release v2.11.3 plus STAFETO-CHANGES.md:",
              file=sys.stderr)
        for line in problems:
            print("  " + line, file=sys.stderr)
        return 1
    print("littlefs sources: the release v2.11.3 plus the stated change, nothing else")
    return 0


if __name__ == "__main__":
    sys.exit(main())
