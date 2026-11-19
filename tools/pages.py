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
                  of its series (the copy with the highest serial among the
                  releases `v<series>.<patch>` and `v<series>-pkgs.<k>`), or
                  nothing when the series is not published yet
  check-copy      a release is the newest of its kind in its series and its copy
                  follows the others
  check-drafts    no draft of the series is waiting and the name of a new
                  packages-only release is free
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
import json
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
RELEASES = "https://github.com/stafeto/stafeto/releases/download"
ARCH = "aarch64"
EXPIRES_MIN_DAYS = 14
AUTHOR = ("Sergey Subbotin", "ssubbotin@gmail.com")
FINAL = re.compile(r"v\d+\.\d+\.\d+")
# A packages-only update of a series: `v<series>-pkgs.<k>`, k counting from 1.
PKGS = re.compile(r"v(\d+)\.(\d+)-pkgs\.([1-9]\d*)")


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

def gate(event: str, prerelease: str, tag: str, assets: list[str], fetch, recorded: tuple[str, ...] = ()) -> tuple[bool, str]:
    """Whether the publication or the weekly job has work, and the line that
    says why not. `fetch(url)` gives the text at an address or None."""
    if event == "release":
        if prerelease == "true":
            return False, f"release {tag} is a pre-release: its packages are not published"
        if not (FINAL.fullmatch(tag) or PKGS.fullmatch(tag)):
            return False, f"release {tag} has a suffix: its packages are not published"
        version = tag[1:]
        missing = [a for a in (f"stafeto-{version}-INDEX", f"stafeto-{version}-INDEX.sig") if a not in assets]
        if missing:
            return False, f"release {tag} has no {', '.join(missing)}: it holds no packages to publish"
        return True, f"release {tag} holds a signed index: publishing"
    # Only a clean answer "there is no such file" means no series; a network error or
    # a server error stops the run with its reason (a published series that cannot be
    # reached is not an unpublished one), and so does an empty list once the tree
    # records a published series.
    try:
        series = fetch(f"{PAGES}/series.txt")
    except (OSError, ValueError) as e:
        raise Refusal(f"{PAGES}/series.txt cannot be read: {e}")
    if series is None or not series.split():
        if recorded:
            raise Refusal(f"packages/published-serial.txt records {', '.join(recorded)} and the pages list no series")
        return False, f"no series is published at {PAGES}/series.txt: there is nothing to sign again"
    return True, f"series published: {' '.join(series.split())}"


def recorded_series(tree: Path) -> tuple[str, ...]:
    """The series that `packages/published-serial.txt` records as published."""
    path = tree / "packages" / "published-serial.txt"
    if not path.is_file():
        return ()
    return tuple(l.split(" ")[0] for l in path.read_text().splitlines() if l.strip())


def copies_of(releases: list[dict]) -> list[dict]:
    """The published releases that carry a signed copy of the index
    (`stafeto-<version>-INDEX` and `.sig`): kind (`final` or `pkgs`), series,
    tag and addresses; a final release has its version numbers in `number`,
    a packages-only one its counter in `counter`. Drafts, pre-releases and
    releases with another suffix hold none that counts. The copy is where the
    records of a series come from; the pages only deliver them."""
    found = []
    for r in releases:
        tag = r.get("tag_name", "")
        if r.get("draft") or r.get("prerelease"):
            continue
        final, update = FINAL.fullmatch(tag), PKGS.fullmatch(tag)
        if not (final or update):
            continue
        urls = {a["name"]: a["browser_download_url"] for a in r.get("assets", [])}
        names = (f"stafeto-{tag[1:]}-INDEX", f"stafeto-{tag[1:]}-INDEX.sig")
        if all(n in urls for n in names):
            if final:
                number = tuple(int(x) for x in tag[1:].split("."))
                found.append({"kind": "final", "number": number, "counter": 0, "series": f"{number[0]}.{number[1]}",
                              "tag": tag, "index": urls[names[0]], "sig": urls[names[1]]})
            else:
                major, minor, counter = (int(x) for x in update.groups())
                found.append({"kind": "pkgs", "number": (major, minor), "counter": counter, "series": f"{major}.{minor}",
                              "tag": tag, "index": urls[names[0]], "sig": urls[names[1]]})
    return found


def newest_copies(releases: list[dict], get) -> dict[str, dict]:
    """The newest copy of each series: the one with the highest serial. The
    order of versions does not tell it, for `v0.5-pkgs.1` is newer than
    `v0.5.1` and `v0.5.2` is newer than `v0.5-pkgs.1`; the serials of the
    copies follow the order the releases were made in (`check_copy`)."""
    best: dict[str, tuple[int, dict]] = {}
    for c in copies_of(releases):
        serial = serial_in(get(c["index"]).decode())
        if c["series"] not in best or serial > best[c["series"]][0]:
            best[c["series"]] = (serial, c)
    return {series: copy for series, (_, copy) in best.items()}


def version_of(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in text.strip().split("."))


def recorded_version(pages: Path, series: str) -> tuple[int, ...] | None:
    """The version of the release last published for `series`, as the pages
    record it in `<series>/aarch64/release`. Only the token of stafeto/packages
    writes there, so a holder of the right to write to stafeto/stafeto, who can
    draft a release and publish an older one, cannot take it back."""
    path = pages / series / ARCH / "release"
    return version_of(path.read_text()) if path.is_file() else None


def check_floor(version: tuple[int, ...], floor: tuple[int, ...] | None, same_records: bool) -> None:
    if floor is None or version > floor:
        return
    word = ".".join(map(str, floor))
    if version == floor and same_records:
        return
    raise Refusal(f"{'.'.join(map(str, version))} is not above {word}, the release last published for the series"
                  + ("" if version < floor else " (a release published again must have the records of the pages)"))


def recorded_anchor(pages: Path, series: str) -> tuple[str, int] | None:
    """The anchor last published for `series`, as the pages record it in
    `<series>/aarch64/anchor`: the tag and the serial of its copy. Every
    publication writes it, a release and a packages-only update alike; the
    file does not exist on pages that were last written before it was added."""
    path = pages / series / ARCH / "anchor"
    if not path.is_file():
        return None
    tag, _, serial = path.read_text().strip().partition(" ")
    return tag, int(serial)


def check_anchor(tag: str, serial: int, floor: tuple[str, int] | None, same_records: bool) -> None:
    """An anchor is published, or followed in the week, only when the serial
    of its copy is not below the one recorded on the pages; an equal serial
    is the same anchor again with the records of the pages."""
    if floor is None or serial > floor[1]:
        return
    if serial == floor[1] and tag == floor[0] and same_records:
        return
    raise Refusal(f"the serial {serial} of the copy of {tag} is not above {floor[1]}, that of {floor[0]}, "
                  "the anchor last published for the series"
                  + (" (an anchor published again must have the records of the pages)" if serial == floor[1] and tag == floor[0] else ""))


def serial_in(text: str) -> int:
    return int(header(text)["serial"])


def parse_tag(tag: str) -> tuple[str, str, int]:
    """The kind (`final` or `pkgs`), the series and the number that orders
    the release among those of its kind: the version for a final release,
    the counter for a packages-only update."""
    final, update = FINAL.fullmatch(tag), PKGS.fullmatch(tag)
    if final:
        number = tuple(int(x) for x in tag[1:].split("."))
        return "final", f"{number[0]}.{number[1]}", number
    if update:
        return "pkgs", f"{update.group(1)}.{update.group(2)}", int(update.group(3))
    raise Refusal(f"{tag} is no release of packages")


def check_copy(tag: str, text: str, releases: list[dict], get) -> None:
    """The copy `text` of the release `tag` may be written to the pages (a
    release is published) or followed (the week): it names the series of the
    tag, the tag is the newest release of its kind in that series (by version
    for a final release, by counter for a packages-only update), and its
    serial is above the serial of the copy of every other published release
    of the series. The right to write to stafeto/stafeto is enough to publish
    an old release again, to swap an older copy into a draft or to put in a
    copy of another series; none of them gets past this."""
    kind, series, number = parse_tag(tag)
    if header(text).get("series") != series:
        raise Refusal(f"the copy of {tag} is of the series {header(text).get('series')}, the tag is of {series}")
    others = [c for c in copies_of(releases) if c["series"] == series and c["tag"] != tag]
    if kind == "final":
        newer = [c["tag"] for c in others if c["kind"] == "final" and c["number"] > number]
    else:
        newer = [c["tag"] for c in others if c["kind"] == "pkgs" and c["counter"] > number]
    if newer:
        raise Refusal(f"{tag} is not the newest release of the series {series} ({', '.join(newer)} is newer)")
    serial = serial_in(text)
    for c in others:
        if serial <= serial_in(get(c["index"]).decode()):
            raise Refusal(f"the serial {serial} of the copy of {tag} is not above that of the copy of {c['tag']}")


def check_drafts(series: str, tag: str, releases: list[dict]) -> None:
    """A packages-only update of `series` is drafted alone: no draft of the
    series is waiting (`v<series>.<patch>` or `v<series>-pkgs.<k>`), and no
    release, draft or published, has the name `tag` already."""
    if parse_tag(tag)[:2] != ("pkgs", series):
        raise Refusal(f"{tag} is no packages-only update of the series {series}")
    for r in releases:
        name = r.get("tag_name", "")
        if name == tag:
            raise Refusal(f"stafeto/stafeto has a release {tag} already; the owner deletes the draft before a tag is set again")
        if r.get("draft") and (FINAL.fullmatch(name) or PKGS.fullmatch(name)) and parse_tag(name)[1] == series:
            raise Refusal(f"stafeto/stafeto holds the draft {name} of the series {series}; it is published or deleted first")


def download(url: str) -> bytes:
    if not url.startswith(RELEASES + "/"):
        raise Refusal(f"{url} is no file of a release of stafeto/stafeto")
    with urllib.request.urlopen(url, timeout=120) as reply:
        return reply.read()


def fetch_copy(series: str, releases: list[dict], out: Path, get=download, floor: tuple[int, ...] | None = None,
               anchor: tuple[str, int] | None = None) -> Path:
    """The signed copy of the newest release of `series` in `out/<series>/`,
    after the checks of `check_copy` (a copy swapped into an old release stops
    the week as it stops a publication). `floor` is the version recorded in
    `release` and `anchor` the pair recorded in `anchor` on the pages."""
    copies = newest_copies(releases, get)
    if series not in copies:
        raise Refusal(f"no published release of stafeto/stafeto carries a signed index of the series {series}")
    chosen = copies[series]
    directory = out / series
    directory.mkdir(parents=True, exist_ok=True)
    text = get(chosen["index"])
    if chosen["kind"] == "final":
        check_floor(chosen["number"], floor, True)
    check_anchor(chosen["tag"], serial_in(text.decode()), anchor, True)
    check_copy(chosen["tag"], text.decode(), releases, get)
    (directory / "INDEX").write_bytes(text)
    (directory / "INDEX.sig").write_bytes(get(chosen["sig"]))
    return directory


def previous(series: str, tree: Path, fetch, releases: list[dict], out: Path, get=download) -> str:
    """The directory a build carries from, or an empty string when the series
    was never published. The records come from the signed copy in the release
    of the series, with the list of revocations of the tree beside them; a
    series that the pages list and the tree does not record as published is an
    error: building it as new would give new packages the names of published
    ones with other bytes."""
    known = series in recorded_series(tree)
    listed = (fetch(f"{PAGES}/series.txt") or "").split()
    if known:
        directory = fetch_copy(series, releases, out, get)
        for name in ("revoked", "revoked.sig"):
            (directory / name).write_bytes((tree / "keys" / name).read_bytes())
        return str(directory)
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


def resign(command: str, index: Path, serial: int, out: Path, anchor: Path, strict: bool = False) -> tuple[str, bytes]:
    """The index signed again by `command` (cargo xtask repo resign ...) with the
    records of the signed copy `anchor`."""
    done = subprocess.run(
        [*shlex.split(command), "--index", str(index), "--anchor", str(anchor), "--serial", str(serial),
         "--out", str(out), *(["--strict"] if strict else [])],
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
    found = [l.strip() for l in path.read_text().splitlines() if l.strip() and not l.startswith("#")]
    for name in found:
        if not re.fullmatch(r"\d+\.\d+", name):
            raise Refusal(f"series.txt names {name!r}, which is no series")
    return found


def commit(pages: Path, message: str, push: bool) -> None:
    (pages / ".nojekyll").touch()
    git(pages, "add", "-A")
    git(pages, "commit", "-m", message)
    if push:
        git(pages, "push", "origin", "HEAD:gh-pages")


def serial_of(path: Path) -> int | None:
    return int(header(path.read_text())["serial"]) if path.is_file() else None


def publish(pages: Path, version: str, index_dir: Path, revoked: Path, command: str, push: bool,
            releases: list[dict], get=download) -> int:
    """`version` is `0.5.1` for a release of the system and `0.5-pkgs.1` for a
    packages-only update; the tag is `v` and the version."""
    tag = f"v{version}"
    kind = parse_tag(tag)[0]
    text = (index_dir / "INDEX").read_text()
    check_copy(tag, text, releases, get)
    series = header(text)["series"]
    on_pages = serial_of(pages / series / ARCH / "INDEX")
    # The release last published for the series is on the pages: a draft and a publication of an
    # older release on stafeto/stafeto does not roll the series back. The same release again is
    # accepted when its records are those on the pages.
    on_pages_text = (pages / series / ARCH / "INDEX")
    same = on_pages_text.is_file() and text.split("\n\n", 1)[1:] == on_pages_text.read_text().split("\n\n", 1)[1:]
    if kind == "final":
        check_floor(version_of(version), recorded_version(pages, series), same)
    copy_serial = int(header(text)["serial"])
    check_anchor(tag, copy_serial, recorded_anchor(pages, series), same)
    serial = max((on_pages or 0) + 1, copy_serial)
    with tempfile.TemporaryDirectory() as work:
        new_text, signature = resign(command, index_dir / "INDEX", serial, Path(work), index_dir / "INDEX", True)
    place(pages, series, new_text, signature, revoked)
    if kind == "final":
        (pages / series / ARCH / "release").write_text(f"{version}\n")
    (pages / series / ARCH / "anchor").write_text(f"{tag} {copy_serial}\n")
    if series not in listed(pages):
        (pages / "series.txt").write_text("".join(f"{s}\n" for s in sorted(listed(pages) + [series])))
    commit(pages, f"publish {version}: serial {serial}", push)
    return serial


def weekly(pages: Path, revoked: Path, command: str, push: bool, releases: list[dict], anchors: Path,
           now: datetime.datetime | None = None, get=download) -> dict[str, int]:
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
            copy = fetch_copy(s, releases, anchors, get, recorded_version(pages, s), recorded_anchor(pages, s))
            text, signature = resign(command, index, serial, Path(work) / s, copy / "INDEX")
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
    g.add_argument("--tree", type=Path, default=Path("."))
    r = steps.add_parser("previous")
    r.add_argument("--series", required=True)
    r.add_argument("--tree", type=Path, default=Path("."))
    r.add_argument("--releases", type=Path, required=True)
    r.add_argument("--out", type=Path, required=True)
    k = steps.add_parser("check-copy")
    k.add_argument("--tag", required=True)
    k.add_argument("--index", type=Path, required=True)
    k.add_argument("--releases", type=Path, required=True)
    d = steps.add_parser("check-drafts")
    d.add_argument("--series", required=True)
    d.add_argument("--tag", required=True)
    d.add_argument("--releases", type=Path, required=True)
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
        if name == "weekly":
            p.add_argument("--anchors", type=Path, required=True)
        p.add_argument("--releases", type=Path, required=True)
        if name == "publish":
            p.add_argument("--version", required=True)
            p.add_argument("--index-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.step == "gate":
        go, reason = gate(args.event, args.prerelease, args.tag, args.assets.split(), fetch_text, recorded_series(args.tree))
        print(f"pages: {reason}", file=sys.stderr)
        print(f"go={'true' if go else 'false'}")
    elif args.step == "previous":
        address = previous(args.series, args.tree, fetch_text, json.loads(args.releases.read_text()), args.out)
        print(f"--previous {address}" if address else "")
        print(f"pages: {'carrying from ' + address if address else 'series ' + args.series + ' is not published: every package is new'}",
              file=sys.stderr)
    elif args.step == "check-copy":
        check_copy(args.tag, args.index.read_text(), json.loads(args.releases.read_text()), download)
        print(f"pages: the copy of {args.tag} is of its series, the newest release of its kind, with a serial above the others")
    elif args.step == "check-drafts":
        check_drafts(args.series, args.tag, json.loads(args.releases.read_text()))
        print(f"pages: no draft of the series {args.series} is waiting and {args.tag} is a new name")
    elif args.step == "new-files":
        print(" ".join(str(p) for p in new_files(args.dir)))
    elif args.step == "verify-storage":
        print(f"pages: {verify_storage(args.index, args.storage, args.dir)} attachments are the files of the signed index")
    elif args.step == "check-addresses":
        print(f"pages: {check_addresses(args.index)} addresses answer")
    elif args.step == "publish":
        serial = publish(args.pages_dir, args.version, args.index_dir, args.revoked_dir, args.resign_command, args.push,
                        json.loads(args.releases.read_text()))
        print(f"pages: published {args.version} with serial {serial}")
    else:
        done = weekly(args.pages_dir, args.revoked_dir, args.resign_command, args.push,
                      json.loads(args.releases.read_text()), args.anchors)
        print("pages: signed again " + ", ".join(f"{s} (serial {n})" for s, n in done.items()))


if __name__ == "__main__":
    main()
