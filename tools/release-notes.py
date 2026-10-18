#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The notes of a release (.github/workflows/release.yml, docs/release.md):
a short introduction, the pull requests merged since the previous tag and
the Roadmap section of README.md.

    release-notes.py <version> <tag> [<previous tag>]
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def merged_pull_requests(tag: str, previous: str | None) -> list[tuple[int, str]]:
    """(number, title) of the merge commits of GitHub between the tags; the
    title is the first line of the merge commit's body."""
    span = f"{previous}..{tag}" if previous else tag
    log = subprocess.run(
        ["git", "log", "--first-parent", "--merges", "--reverse", "--format=%s%x1f%b%x1e", span],
        cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE).stdout
    found = []
    for entry in log.split("\x1e"):
        subject, _, body = entry.strip().partition("\x1f")
        match = re.match(r"Merge pull request #(\d+) ", subject)
        if match:
            title = next((line.strip() for line in body.splitlines() if line.strip()), subject)
            found.append((int(match.group(1)), title))
    return found


def roadmap() -> str:
    """The Roadmap section of README.md, without its heading."""
    text = (ROOT / "README.md").read_text()
    match = re.search(r"^## Roadmap\n(.*?)(?=^## )", text, re.M | re.S)
    if match is None:
        raise SystemExit("release-notes: README.md has no Roadmap section")
    return match.group(1).strip()


def notes(version: str, tag: str, previous: str | None) -> str:
    pulls = merged_pull_requests(tag, previous)
    since = f"since {previous}" if previous else "so far"
    lines = [
        f"stafeto {version}: a pre-release to boot in QEMU on aarch64.",
        "",
        f"Download `stafeto-{version}-aarch64-virt.tar.xz`, unpack it and run `./run.sh` "
        "(`--cpus N` for several CPUs, `--hvf` on a Mac with Apple silicon). "
        "The README in the archive lists what is inside and the limits.",
        "",
        "| File | Content |",
        "| --- | --- |",
        f"| `stafeto-{version}-aarch64-virt.tar.xz` | Image, boot image of the shell, `run.sh`, README, LICENSES |",
        f"| `stafeto-{version}-kernel.tar.xz` | the kernel Image and the ELF file with symbols |",
        f"| `stafeto-{version}-gpl-sources.tar.xz` | the sources of the GPL packages, our tree and relibc at its pin |",
        f"| `stafeto-{version}-sbom.spdx.json` | the packages with versions, licences, URLs and SHA-256 |",
        "| `SHA256SUMS` | SHA-256 of every file above |",
        "",
        f"## Merged pull requests {since}",
        "",
    ]
    lines += [f"- {title} (#{number})" for number, title in pulls] or ["- none"]
    lines += ["", "## Roadmap", "", roadmap(), ""]
    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) not in (3, 4):
        raise SystemExit(__doc__)
    previous = sys.argv[3] if len(sys.argv) == 4 and sys.argv[3] else None
    sys.stdout.write(notes(sys.argv[1], sys.argv[2], previous))


if __name__ == "__main__":
    main()
