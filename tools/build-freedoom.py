#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Fetch the Freedoom release archive (`/games/freedoom1.wad` of the games
image) with its SHA-256 checked and unpack the WAD and the licence text,
unchanged, under target/freedoom. The data are free (BSD-3-Clause); the image
carries the licence text (COPYING.txt of the archive) and the note of the
source."""

from hashlib import sha256
from pathlib import Path
import shutil
from urllib.request import urlopen
import zipfile

import pkgdesc


PACKAGE = pkgdesc.load("freedoom")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
URL = PACKAGE["url"]
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "freedoom"
WAD = WORK / f"freedoom-{VERSION}" / "freedoom1.wad"


def main() -> None:
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    stamp = WORK / "stamp"
    text = f"{VERSION} {SHA256} {script}\n"
    if stamp.exists() and stamp.read_text() == text and WAD.exists():
        print(f"freedoom ready: {WAD}")
        return
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    archive = WORK / f"freedoom-{VERSION}.zip"
    with urlopen(URL) as response:
        archive.write_bytes(response.read())
    if sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise SystemExit("Freedoom archive has an unexpected SHA-256")
    with zipfile.ZipFile(archive) as members:
        for name in ("freedoom1.wad", "COPYING.txt"):
            members.extract(f"freedoom-{VERSION}/{name}", WORK)
    stamp.write_text(text)
    print(f"freedoom ready: {WAD}")


if __name__ == "__main__":
    main()
