#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The source archive of a package (docs/packages.md): `cargo xtask repo`
puts one next to every package whose licence, or the licence of a package
linked into it, is a GPL licence.

  pkg-source.py build --name N --out FILE --inputs LIST --commit C
      writes FILE (a tar.xz): the source archives of the package and of the
      packages it links in (packages/N.toml `build_depends`) as the SHA-256
      sums of their descriptions pin them, the files of the tree that the
      recipe of the package names (LIST holds its lines `file <path> <sha>`),
      and a README with the addresses and commits.
  pkg-source.py check --repo DIR
      checks that every entry of DIR/INDEX that needs a source archive has
      one, and that the archive holds the source of each package it names with
      the SHA-256 of its description.
  pkg-source.py scan ARCHIVE [--marker TEXT]... [--forbid-name TEXT]... [--allow-path TEXT]...
      prints the members of a tar.xz whose name holds a forbidden text and
      the markers found in the bytes of its members.

The archives come from the cache target/dist-cache, which tools/dist.py fills."""

import argparse
import lzma
import re
import shutil
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import dist  # noqa: E402
import pkgdesc  # noqa: E402

ROOT = pkgdesc.ROOT
CACHE = ROOT / "target" / "dist-cache"


def stem(description: dict) -> str:
    """`<name>-<short version>-<release>`, as xtask names the package file."""
    version = description["version"]
    short = version[:8] if re.fullmatch(r"[0-9a-f]{40}", version) else version
    return f"{description['name']}-{short}-{description['release']}"


def linked(name: str, describe) -> list[dict]:
    """The package and the packages linked into it, in that order."""
    description = describe(name)
    return [description] + [describe(d) for d in description.get("build_depends", [])]


def needs_source(name: str, describe) -> bool:
    return any("GPL" in d["license"] for d in linked(name, describe))


def build(name: str, out: Path, inputs: Path, commit: str, relibc: str,
          cache: Path = CACHE, describe=pkgdesc.load, fetch=dist.fetch, tree: Path = ROOT) -> None:
    descriptions = linked(name, describe)
    top = stem(descriptions[0]) + "-src"
    with tempfile.TemporaryDirectory() as work:
        stage = Path(work) / top
        (stage / "sources").mkdir(parents=True)
        lines = []
        for d in descriptions:
            archive = fetch(d, cache)
            shutil.copy(archive, stage / "sources" / dist.cache_name(d))
            lines.append(f"  sources/{dist.cache_name(d)}  {d['name']} {d['version']} {d['license']}"
                         f"  {d['url']}  sha256:{d['sha256']}")
        listed = []
        for line in inputs.read_text().splitlines():
            kind, _, rest = line.partition(" ")
            if kind != "file":
                continue
            path = rest.split(" ")[0]
            target = stage / "tree" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(tree / path, target)
            listed.append(path)
        (stage / "README").write_text(
            f"Corresponding source of the package {descriptions[0]['name']} "
            f"{descriptions[0]['version']}-{descriptions[0]['release']}.\n\n"
            "sources/  the original source archives of the package and of what is linked into it,\n"
            "          as the SHA-256 sums of packages/*.toml pin them:\n\n"
            + "\n".join(lines) + "\n\n"
            "tree/     the files of https://github.com/stafeto/stafeto at the commit "
            f"{commit} that the recipe of\n"
            "          the package names: the build scripts, their patches and ports, the descriptions\n\n"
            f"relibc:   https://github.com/stafeto/relibc at the commit {relibc}, which the programs\n"
            "          of the package are linked with\n\n"
            "Build: unpack the tree of that commit and run `cargo xtask pkg-build "
            f"{descriptions[0]['name']}`; the build scripts fetch the archives above by their URLs\n"
            "and check the same SHA-256 sums.\n")
        out.parent.mkdir(parents=True, exist_ok=True)
        dist.write_tar_xz(out, stage)


def same(path: Path, expected: str) -> bool:
    """`dist.matches`, with a damaged archive counted as a mismatch."""
    try:
        return dist.matches(path, expected)
    except (OSError, EOFError, lzma.LZMAError, zlib.error):
        return False


def index_entries(text: str) -> list[dict]:
    """The entries of an INDEX as dictionaries of their fields."""
    blocks = text.split("\n\n")[1:]
    entries = []
    for block in blocks:
        fields = {}
        for line in block.splitlines():
            key, _, value = line.partition(" ")
            fields[key] = value
        if fields:
            entries.append(fields)
    return entries


def check(repo: Path, describe=pkgdesc.load) -> int:
    """Raises SystemExit with the reason when the repository is short; the
    number of archives checked otherwise."""
    count = 0
    for entry in index_entries((repo / "INDEX").read_text()):
        name = entry["name"]
        if not needs_source(name, describe):
            if "source" in entry:
                raise SystemExit(f"pkg-source: {name} has a source archive but needs none")
            continue
        if "source" not in entry:
            raise SystemExit(f"pkg-source: {name} is GPL (or links GPL) and its entry has no source")
        archive = repo / entry["source"]
        if entry["source"].startswith("https://"):
            # An address in a storage release: the file is next to the index
            # in src/ when this build made it, else it was published before.
            archive = repo / "src" / entry["source"].rsplit("/", 1)[-1]
            if not archive.is_file():
                continue
        if not archive.is_file():
            raise SystemExit(f"pkg-source: {archive} is missing")
        with tempfile.TemporaryDirectory() as work:
            with tarfile.open(archive) as tar:
                tar.extractall(work, filter="data")
            for d in linked(name, describe):
                found = Path(work) / (stem(describe(name)) + "-src") / "sources" / dist.cache_name(d)
                if not found.is_file():
                    raise SystemExit(f"pkg-source: {archive.name} lacks the source of {d['name']}")
                if not same(found, d["sha256"]):
                    raise SystemExit(f"pkg-source: the source of {d['name']} in {archive.name} "
                                     f"is not the archive of SHA-256 {d['sha256']}")
        count += 1
    return count


def scan(archive: Path, markers: list[str], forbidden: list[str], allowed: list[str] = ()) -> list[str]:
    """What is wrong with a tar.xz: forbidden names and markers in bytes. A
    member whose name holds one of `allowed` is not looked at."""
    problems = []
    needles = [m.encode() for m in markers]
    with tarfile.open(archive) as tar:
        for member in tar:
            if any(text in member.name for text in allowed):
                continue
            for text in forbidden:
                if text in member.name:
                    problems.append(f"{archive.name}: member {member.name} has {text!r} in its name")
            if member.isfile() and needles:
                data = tar.extractfile(member).read()
                for needle in needles:
                    if needle in data:
                        problems.append(f"{archive.name}: member {member.name} holds {needle.decode()!r}")
    return problems


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--name", required=True)
    b.add_argument("--out", type=Path, required=True)
    b.add_argument("--inputs", type=Path, required=True)
    b.add_argument("--commit", required=True)
    b.add_argument("--relibc", default="")
    b.add_argument("--cache", type=Path, default=CACHE)
    c = sub.add_parser("check")
    c.add_argument("--repo", type=Path, required=True)
    s = sub.add_parser("scan")
    s.add_argument("archive", type=Path)
    s.add_argument("--marker", action="append", default=[])
    s.add_argument("--forbid-name", action="append", default=[])
    s.add_argument("--allow-path", action="append", default=[])
    args = parser.parse_args()
    if args.command == "build":
        build(args.name, args.out, args.inputs, args.commit, args.relibc, args.cache)
    elif args.command == "check":
        print(f"pkg-source: {check(args.repo)} source archives hold the sources their descriptions pin")
    else:
        problems = scan(args.archive, args.marker, args.forbid_name, args.allow_path)
        for problem in problems:
            print(problem)
        sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
