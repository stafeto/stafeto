#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Fetch the root certificates of Mozilla as curl.se publishes them (one PEM
file made from Mozilla's certdata.txt) and put them unchanged in
target/ca-bundle/ca-certificates.crt, which the images with the network
service carry as /etc/ssl/certs/ca-certificates.crt.

The file is checked by its SHA-256, by the date in its header against the
version of the description, and by the number of certificates (at least
MIN_CERTIFICATES). Its header states its terms, MPL-2.0; the text of the
licence is tools/ca-bundle/MPL-2.0.txt."""

from hashlib import sha256
from pathlib import Path
import re
from urllib.request import urlopen

import pkgdesc


ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "ca-bundle"
OUTPUT = WORK / "ca-certificates.crt"
# Mozilla's store holds well over a hundred roots; a file with fewer is no
# bundle of it.
MIN_CERTIFICATES = 100
BEGIN = b"-----BEGIN CERTIFICATE-----"
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def certificates(data: bytes) -> int:
    """The number of certificate blocks of a PEM file."""
    return sum(1 for line in data.splitlines() if line.strip() == BEGIN)


def header_date(data: bytes) -> str | None:
    """The date of the header line `## Certificate data from Mozilla as of:
    Tue Oct 20 03:12:01 2026 GMT` (or `last updated on:` of older files) as
    YYYY-MM-DD."""
    text = data[:4096].decode("ascii", "replace")
    found = re.search(r"^## Certificate data from Mozilla (?:as of|last updated on): "
                      r"\w{3},? (\w{3}) +(\d{1,2}) [\d:]+ (\d{4})", text, re.M)
    if not found or found.group(1) not in MONTHS:
        return None
    month = MONTHS.index(found.group(1)) + 1
    return f"{found.group(3)}-{month:02}-{int(found.group(2)):02}"


def header(data: bytes) -> bytes:
    """The lines at the top of the file that begin with `##`: the source and
    the terms of the bundle."""
    lines = []
    for line in data.splitlines(keepends=True):
        if not line.startswith(b"##"):
            break
        lines.append(line)
    return b"".join(lines)


def check(data: bytes, expected_sha256: str, version: str) -> None:
    """Refuses a bundle that is not the one the description names."""
    if sha256(data).hexdigest() != expected_sha256:
        raise SystemExit("ca-bundle: the file has an unexpected SHA-256")
    count = certificates(data)
    if count < MIN_CERTIFICATES:
        raise SystemExit(f"ca-bundle: {count} certificates, fewer than {MIN_CERTIFICATES}")
    date = header_date(data)
    if date != version:
        raise SystemExit(f"ca-bundle: the header is of {date}, the description of {version}")


def main() -> None:
    package = pkgdesc.load("ca-bundle")
    stamp = WORK / "stamp"
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    text = f"{package['version']} {package['sha256']} {script}\n"
    if stamp.exists() and stamp.read_text() == text and OUTPUT.exists():
        print(f"ca-bundle ready: {OUTPUT}")
        return
    WORK.mkdir(parents=True, exist_ok=True)
    stamp.unlink(missing_ok=True)
    with urlopen(package["url"]) as response:
        data = response.read()
    check(data, package["sha256"], package["version"])
    OUTPUT.write_bytes(data)
    stamp.write_text(text)
    print(f"ca-bundle ready: {OUTPUT} ({certificates(data)} certificates)")


if __name__ == "__main__":
    main()
