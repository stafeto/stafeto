#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The notes of a release (.github/workflows/release.yml, docs/release.md).
A summary written by hand in docs/releases/<version>.md comes first; a
release without one gets a short introduction. The table of release files
and a link to the pull requests merged since the previous tag follow.

    release-notes.py <version> <tag> [<previous tag>]

A packages-only update (docs/release.md) has its own form: the summary written
in docs/releases/<series>-pkgs.<k>.md, the table of the packages the update
changes (from the signed copy of its index against the copy of the previous
anchor of the series) and the table of its files.

    release-notes.py --packages <series>-pkgs.<k> <tag> <previous tag or ""> <new index> <previous index>
"""

import sys
import tomllib
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import dist  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def summary(version: str) -> str:
    """The summary written for this version, or a short introduction."""
    written = ROOT / "docs" / "releases" / f"{version}.md"
    if written.exists():
        return written.read_text().strip()
    return "\n".join([
        f"stafeto {version}: a POSIX system on its own capability microkernel for AArch64, to boot in QEMU.",
        "",
        f"Download `{dist.run_archive(version, 'base')}`, unpack it and run `./run.sh` "
        "(`--cpus N` for several CPUs, `--hvf` on a Mac with Apple silicon). "
        "The README in the archive lists what is inside and the limits.",
    ])


def files_table(version: str) -> list[str]:
    """The rows of the table of files: the names `tools/dist.py` packs."""
    return ["| " + ", ".join(f"`{name}`" for name in names) + f" | {content} |"
            for names, content in dist.release_files(version)]


def credits(root: Path = ROOT) -> list[str]:
    """The credit sentences the licences of the release's packages ask the
    notes to carry: for each package under the FreeType Licence (FTL) the line
    its record names as `CREDIT = tree:<path>` in `notices`, the wording the
    licence recommends."""
    found: list[str] = []
    for record in sorted((root / "packages").glob("*.toml")):
        description = tomllib.loads(record.read_text())
        if "FTL" not in description.get("license", "").replace("(", " ").replace(")", " ").split():
            continue
        for entry in description.get("notices", []):
            name, _, source = entry.partition(" = ")
            if name == "CREDIT" and source.startswith("tree:"):
                sentence = (root / source[len("tree:"):]).read_text().strip()
                if sentence not in found:
                    found.append(sentence)
    return found


def credit_lines() -> list[str]:
    """The section of the notes that carries the credits, or nothing when no
    package asks for one."""
    sentences = credits()
    if not sentences:
        return []
    return ["## Credits", "", *[f"{sentence}\n" for sentence in sentences]]


def index_records(path: Path) -> dict[str, dict[str, str]]:
    """The entries of an INDEX text by package name."""
    found = {}
    for block in path.read_text().split("\n\n")[1:]:
        fields = dict(line.partition(" ")[::2] for line in block.splitlines())
        if "name" in fields:
            found[fields["name"]] = fields
    return found


def storage_of(file: str) -> str:
    """The storage release an entry's `file` points into (`v0.5-pkgs.1-aarch64`),
    or the file itself when it is no address of the storage."""
    parts = file.split("/")
    return parts[-2] if file.startswith("https://") and len(parts) >= 2 else file


def changed_table(new: Path, old: Path) -> list[str]:
    """The rows of the table of the packages the update changes: those whose
    entry has another SHA-256 than in the previous copy, or is new, with
    `version-release` before and after and the storage release of the file."""
    now, before = index_records(new), index_records(old)
    rows = []
    for name in sorted(now):
        if name in before and before[name]["sha256"] == now[name]["sha256"]:
            continue
        was = before[name]["version"] if name in before else "-"
        rows.append(f"| `{name}` | {was} | {now[name]['version']} | `{storage_of(now[name]['file'])}` |")
    for name in sorted(set(before) - set(now)):
        rows.append(f"| `{name}` | {before[name]['version']} | - | - |")
    return rows


def packages_summary(name: str) -> str:
    """The summary written for this update, or a short introduction."""
    written = ROOT / "docs" / "releases" / f"{name}.md"
    if written.exists():
        return written.read_text().strip()
    series = name.split("-pkgs.")[0]
    return (f"An update of the packages of the series {series}, with no new version of the system. "
            "`pkg update` fetches the new index and `pkg upgrade` replaces the packages that changed.")


def packages_notes(name: str, tag: str, previous: str | None, new: Path, old: Path) -> str:
    repository = "https://github.com/stafeto/stafeto"
    changes = f"{repository}/compare/{previous}...{tag}" if previous else f"{repository}/pulls?q=is%3Apr+is%3Amerged"
    changed = changed_table(new, old)
    lines = [
        packages_summary(name),
        "",
        "## Changed packages",
        "",
        "| Package | Was | Now | Storage |",
        "| --- | --- | --- | --- |",
        *(changed or ["| - | - | - | - |"]),
        "",
        "## Files",
        "",
        "| File | Content |",
        "| --- | --- |",
        *["| " + ", ".join(f"`{n}`" for n in names) + f" | {content} |" for names, content in dist.packages_release_files(name)],
        "",
        f"Every change since the previous release is in the [merged pull requests]({changes}).",
        "",
    ]
    return "\n".join(lines)


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
        *files_table(version),
        "",
        *credit_lines(),
        f"The plans are in the [README]({repository}#where-it-is-going); "
        f"every change of this release is in the [merged pull requests]({changes}).",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) == 7 and sys.argv[1] == "--packages":
        _, _, name, tag, previous, new, old = sys.argv
        sys.stdout.write(packages_notes(name, tag, previous or None, Path(new), Path(old)))
        return
    if len(sys.argv) not in (3, 4):
        raise SystemExit(__doc__)
    previous = sys.argv[3] if len(sys.argv) == 4 and sys.argv[3] else None
    sys.stdout.write(notes(sys.argv[1], sys.argv[2], previous))


if __name__ == "__main__":
    main()
