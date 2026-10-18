#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The notes of a release (.github/workflows/release.yml, docs/release.md).
A summary written by hand in docs/releases/<version>.md comes first; a
release without one gets a short introduction. The table of release files
and a link to the pull requests merged since the previous tag follow.

    release-notes.py <version> <tag> [<previous tag>]
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def summary(version: str) -> str:
    """The summary written for this version, or a short introduction."""
    written = ROOT / "docs" / "releases" / f"{version}.md"
    if written.exists():
        return written.read_text().strip()
    return "\n".join([
        f"stafeto {version}: a POSIX system on its own capability microkernel for AArch64, to boot in QEMU.",
        "",
        f"Download `stafeto-{version}-aarch64-virt.tar.xz`, unpack it and run `./run.sh` "
        "(`--cpus N` for several CPUs, `--hvf` on a Mac with Apple silicon). "
        "The README in the archive lists what is inside and the limits.",
    ])


def notes(version: str, tag: str, previous: str | None) -> str:
    repository = "https://github.com/stafeto/stafeto"
    changes = (f"{repository}/compare/{previous}...{tag}" if previous
               else f"{repository}/pulls?q=is%3Apr+is%3Amerged")
    lines = [
        summary(version),
        "",
        "## Files",
        "",
        "| File | Content |",
        "| --- | --- |",
        f"| `stafeto-{version}-aarch64-virt.tar.xz` | Image, boot image of the shell, `run.sh`, README, LICENSES |",
        f"| `stafeto-{version}-kernel.tar.xz` | the kernel Image and the ELF file with symbols |",
        f"| `stafeto-{version}-gpl-sources.tar.xz` | the sources of the GPL packages, our tree and relibc at its pin |",
        f"| `stafeto-{version}-sbom.spdx.json` | the packages with versions, licences, URLs and SHA-256 |",
        "| `SHA256SUMS` | SHA-256 of every file above |",
        "",
        f"The plans are in the [README]({repository}#where-it-is-going); "
        f"every change of this release is in the [merged pull requests]({changes}).",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) not in (3, 4):
        raise SystemExit(__doc__)
    previous = sys.argv[3] if len(sys.argv) == 4 and sys.argv[3] else None
    sys.stdout.write(notes(sys.argv[1], sys.argv[2], previous))


if __name__ == "__main__":
    main()
