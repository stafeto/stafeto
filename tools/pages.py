#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The steps of `publish-packages.yml` that are more than a command line
(docs/release.md). Signing is left to `cargo xtask repo resign`, which refuses
an index whose signature the roots of the tree do not accept; this script
decides what to sign, in which order, and what goes to the branch `gh-pages`
of stafeto/packages.

  gate            whether an event has anything to do (never fails: no secret,
                  no published series and a pre-release are a clean end)
  previous        where a release carries its packages from: the published index
                  of its series, or nothing when the series is not published yet
  new-files       the package files and source archives of a release that its
                  storage release takes (the carried packages are in theirs)
  verify-storage  the attachments of the draft of the storage release are
                  the files of the signed index and no others
  check-addresses every address of the index answers with the size it says
  publish         the index of a release, signed again with a serial above the
                  one on the pages, into the branch
  weekly          every series of series.txt signed again, in one commit
"""

import argparse
import datetime
import hashlib
import re
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.dont_write_bytecode = True

PAGES = "https://stafeto.github.io/packages"
STORAGE = "https://github.com/stafeto/packages/releases/download"
ARCH = "aarch64"
EXPIRES_MIN_DAYS = 14
AUTHOR = ("Sergey Subbotin", "ssubbotin@gmail.com")
FINAL = re.compile(r"v\d+\.\d+\.\d+")


class Refusal(SystemExit):
    """A step that stops with a reason: nothing was written."""

    def __init__(self, message: str):
        super().__init__(f"pages: {message}")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def header(text: str) -> dict[str, str]:
    head = text.split("\n\n", 1)[0]
    return dict(line.partition(" ")[::2] for line in head.splitlines())


def entries(text: str) -> list[dict[str, str]]:
    found = []
    for block in text.split("\n\n")[1:]:
        fields = dict(line.partition(" ")[::2] for line in block.splitlines())
        if "name" in fields:
            found.append(fields)
    return found


# ---- gate ----

def gate(event: str, prerelease: str, tag: str, assets: list[str], fetch) -> tuple[bool, str]:
    """Whether the publication or the weekly job has work, and the line that
    says why not. `fetch(url)` gives the text at an address or None."""
    if event == "release":
        if prerelease == "true":
            return False, f"release {tag} is a pre-release: its packages are not published"
        if not FINAL.fullmatch(tag):
            return False, f"release {tag} has a suffix: its packages are not published"
        version = tag[1:]
        missing = [a for a in (f"stafeto-{version}-INDEX", f"stafeto-{version}-INDEX.sig") if a not in assets]
        if missing:
            return False, f"release {tag} has no {', '.join(missing)}: it holds no packages to publish"
        return True, f"release {tag} holds a signed index: publishing"
    series = fetch(f"{PAGES}/series.txt")
    if series is None or not series.split():
        return False, f"no series is published at {PAGES}/series.txt: there is nothing to sign again"
    return True, f"series published: {' '.join(series.split())}"


def previous(series: str, tree: Path, fetch) -> str:
    """The published index of `series` for `--previous`, or an empty string
    when the series was never published. A series that the pages list and the
    tree does not record as published is an error: building it as new would
    give new packages the names of published ones with other bytes."""
    recorded = (tree / "packages" / "published-serial.txt")
    known = recorded.is_file() and any(
        l.split(" ")[0] == series for l in recorded.read_text().splitlines() if l.strip())
    listed = (fetch(f"{PAGES}/series.txt") or "").split()
    if known:
        return f"{PAGES}/{series}/{ARCH}"
    if series in listed:
        raise Refusal(f"the pages list the series {series} and packages/published-serial.txt does not record it; add its line first")
    return ""


def new_files(directory: Path) -> list[Path]:
    """The package files of `directory` that were built for this release and
    the source archives of them: all `.stpkg` files except those that
    `carried.txt` lists, and `src/<stem>-src.tar.xz` for each."""
    carried = set()
    path = directory / "carried.txt"
    if path.is_file():
        carried = {line.split("\t")[0] for line in path.read_text().splitlines() if line}
    found = []
    for package in sorted(directory.glob("*.stpkg")):
        if package.name in carried:
            continue
        found.append(package)
        source = directory / "src" / f"{package.stem}-src.tar.xz"
        if source.is_file():
            found.append(source)
    return found


def fetch_text(url: str):
    try:
        with urllib.request.urlopen(url, timeout=60) as reply:
            return reply.read().decode()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


# ---- the storage release ----

def verify_storage(index: Path, storage: str, directory: Path) -> int:
    """The attachments in `directory` are, name for name, the files of the
    index that point into the storage release `storage`: same size and SHA-256
    for the package files; a source archive only has to be named by an entry.
    Returns the number of attachments."""
    prefix = f"{STORAGE}/{storage}/"
    wanted: dict[str, tuple[int | None, str | None]] = {}
    for e in entries(index.read_text()):
        if e.get("file", "").startswith(prefix):
            wanted[e["file"][len(prefix):]] = (int(e["size"]), e["sha256"])
        if e.get("source", "").startswith(prefix):
            wanted[e["source"][len(prefix):]] = (None, None)
    have = {p.name: p for p in directory.iterdir() if p.is_file()}
    extra, short = sorted(set(have) - set(wanted)), sorted(set(wanted) - set(have))
    if extra:
        raise Refusal(f"the storage release {storage} holds {', '.join(extra)}, which the signed index does not name")
    if short:
        raise Refusal(f"the storage release {storage} lacks {', '.join(short)}, which the signed index names")
    for name, (size, digest) in wanted.items():
        if size is not None and (have[name].stat().st_size != size or sha256_file(have[name]) != digest):
            raise Refusal(f"{name} in the storage release is not the file of the signed index (size or SHA-256)")
    return len(wanted)


def head(url: str) -> tuple[int, int | None]:
    request = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=60) as reply:
            length = reply.headers.get("Content-Length")
            return reply.status, int(length) if length else None
    except urllib.error.HTTPError as e:
        return e.code, None


def check_addresses(index: Path, probe=head, attempts: int = 5, pause: float = 10.0) -> int:
    """Every `file` and `source` that is an address answers 200; a `file`
    has the length `size`. The storage may need a moment after its release is
    published."""
    count = 0
    for e in entries(index.read_text()):
        for field in ("file", "source"):
            url = e.get(field, "")
            if not url.startswith("https://"):
                continue
            for attempt in range(attempts):
                status, length = probe(url)
                right = status == 200 and (field == "source" or length == int(e["size"]))
                if right:
                    break
                if attempt + 1 < attempts:
                    time.sleep(pause)
            else:
                raise Refusal(f"{url} answers {status} with length {length}, the index says {e['size']}")
            count += 1
    return count


# ---- the branch ----

def git(directory: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(directory), "-c", f"user.name={AUTHOR[0]}",
                           "-c", f"user.email={AUTHOR[1]}", *args],
                          capture_output=True, text=True)
    if done.returncode != 0:
        raise Refusal(f"git {' '.join(args)}: {done.stderr.strip()}")
    return done.stdout


def resign(command: str, index: Path, serial: int, out: Path) -> tuple[str, bytes]:
    """The index signed again by `command` (cargo xtask repo resign ...)."""
    done = subprocess.run(
        [*shlex.split(command), "--index", str(index), "--serial", str(serial), "--out", str(out)],
        capture_output=True, text=True)
    if done.returncode != 0:
        raise Refusal(f"signing {index.parent.parent.name} again failed: {(done.stdout + done.stderr).strip()}")
    return (out / "INDEX").read_text(), (out / "INDEX.sig").read_bytes()


def expires_of(text: str) -> datetime.datetime:
    return datetime.datetime.strptime(header(text)["expires"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc)


def place(pages: Path, series: str, text: str, signature: bytes, revoked: Path) -> list[str]:
    directory = pages / series / ARCH
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "INDEX").write_text(text)
    (directory / "INDEX.sig").write_bytes(signature)
    for name in ("revoked", "revoked.sig"):
        (directory / name).write_bytes((revoked / name).read_bytes())
    return [str(directory.relative_to(pages))]


def listed(pages: Path) -> list[str]:
    path = pages / "series.txt"
    if not path.is_file():
        return []
    return [l.strip() for l in path.read_text().splitlines() if l.strip() and not l.startswith("#")]


def commit(pages: Path, message: str, push: bool) -> None:
    (pages / ".nojekyll").touch()
    git(pages, "add", "-A")
    git(pages, "commit", "-m", message)
    if push:
        git(pages, "push", "origin", "HEAD:gh-pages")


def serial_of(path: Path) -> int | None:
    return int(header(path.read_text())["serial"]) if path.is_file() else None


def publish(pages: Path, version: str, index_dir: Path, revoked: Path, command: str, push: bool) -> int:
    text = (index_dir / "INDEX").read_text()
    series = header(text)["series"]
    on_pages = serial_of(pages / series / ARCH / "INDEX")
    serial = max((on_pages or 0) + 1, int(header(text)["serial"]))
    with tempfile.TemporaryDirectory() as work:
        new_text, signature = resign(command, index_dir / "INDEX", serial, Path(work))
    place(pages, series, new_text, signature, revoked)
    if series not in listed(pages):
        (pages / "series.txt").write_text("".join(f"{s}\n" for s in sorted(listed(pages) + [series])))
    commit(pages, f"publish {version}: serial {serial}", push)
    return serial


def weekly(pages: Path, revoked: Path, command: str, push: bool, now: datetime.datetime | None = None) -> dict[str, int]:
    series = listed(pages)
    if not series:
        raise Refusal("series.txt lists no series")
    now = now or datetime.datetime.now(datetime.timezone.utc)
    signed: dict[str, tuple[str, bytes, int]] = {}
    with tempfile.TemporaryDirectory() as work:
        for s in series:
            index = pages / s / ARCH / "INDEX"
            if not index.is_file():
                raise Refusal(f"the series {s} is in series.txt and has no {s}/{ARCH}/INDEX")
            serial = serial_of(index) + 1
            text, signature = resign(command, index, serial, Path(work) / s)
            if expires_of(text) < now + datetime.timedelta(days=EXPIRES_MIN_DAYS):
                raise Refusal(f"the index of {s} would expire in under {EXPIRES_MIN_DAYS} days")
            signed[s] = (text, signature, serial)
    for s, (text, signature, _) in signed.items():
        place(pages, s, text, signature, revoked)
    commit(pages, "resign " + ", ".join(f"{s}: serial {n}" for s, (_, _, n) in signed.items()), push)
    return {s: n for s, (_, _, n) in signed.items()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    steps = parser.add_subparsers(dest="step", required=True)
    g = steps.add_parser("gate")
    g.add_argument("--event", required=True)
    g.add_argument("--prerelease", default="false")
    g.add_argument("--tag", default="")
    g.add_argument("--assets", default="")
    r = steps.add_parser("previous")
    r.add_argument("--series", required=True)
    r.add_argument("--tree", type=Path, default=Path("."))
    n = steps.add_parser("new-files")
    n.add_argument("--dir", type=Path, required=True)
    v = steps.add_parser("verify-storage")
    v.add_argument("--index", type=Path, required=True)
    v.add_argument("--storage", required=True)
    v.add_argument("--dir", type=Path, required=True)
    c = steps.add_parser("check-addresses")
    c.add_argument("--index", type=Path, required=True)
    for name in ("publish", "weekly"):
        p = steps.add_parser(name)
        p.add_argument("--pages-dir", type=Path, required=True)
        p.add_argument("--revoked-dir", type=Path, required=True)
        p.add_argument("--resign-command", required=True)
        p.add_argument("--push", action="store_true")
        if name == "publish":
            p.add_argument("--version", required=True)
            p.add_argument("--index-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.step == "gate":
        go, reason = gate(args.event, args.prerelease, args.tag, args.assets.split(), fetch_text)
        print(f"pages: {reason}", file=sys.stderr)
        print(f"go={'true' if go else 'false'}")
    elif args.step == "previous":
        address = previous(args.series, args.tree, fetch_text)
        print(f"--previous {address}" if address else "")
        print(f"pages: {'carrying from ' + address if address else 'series ' + args.series + ' is not published: every package is new'}",
              file=sys.stderr)
    elif args.step == "new-files":
        print(" ".join(str(p) for p in new_files(args.dir)))
    elif args.step == "verify-storage":
        print(f"pages: {verify_storage(args.index, args.storage, args.dir)} attachments are the files of the signed index")
    elif args.step == "check-addresses":
        print(f"pages: {check_addresses(args.index)} addresses answer")
    elif args.step == "publish":
        serial = publish(args.pages_dir, args.version, args.index_dir, args.revoked_dir, args.resign_command, args.push)
        print(f"pages: published {args.version} with serial {serial}")
    else:
        done = weekly(args.pages_dir, args.revoked_dir, args.resign_command, args.push)
        print("pages: signed again " + ", ".join(f"{s} (serial {n})" for s, n in done.items()))


if __name__ == "__main__":
    main()
