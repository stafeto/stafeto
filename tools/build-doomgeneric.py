#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build Doomgeneric for the games image (`/bin/doom`) from its pinned source
archive, unchanged, with the platform file of ports/doomgeneric, against
relibc's headers and the Linux AArch64 C ABI they describe.

Doomgeneric has no `configure`: its Makefile lists the source files of the
engine, and this script compiles the same list (without the file of X11,
which the platform file replaces) with the cross compiler of the project
(clang and lld). The result is one relocatable object,
target/doomgeneric/doom.o, that exports `main` alone: the names of the
engine's own helpers cannot meet relibc's or the program's.
tools/build-libc-so.py programs links it against libc.so.

Doomgeneric is GPL-2.0-or-later: the archive is fetched at build time with its
SHA-256 checked, as BusyBox is, and the image's licence notices name it."""

from hashlib import sha256
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
from urllib.request import urlopen

import pkgdesc


PACKAGE = pkgdesc.load("doomgeneric")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
URL = PACKAGE["url"]
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "doomgeneric"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
PORT_DIR = ROOT / "ports" / "doomgeneric"
# The platform's files: the functions the engine asks of its host, and the
# table of keys (which the host tests too).
PORT = [PORT_DIR / "doomgeneric_stafeto.c", PORT_DIR / "keys.c"]
PORT_HEADERS = [PORT_DIR / "keys.h"]
OUTPUT = WORK / "doom.o"
# Cortex-A53 erratum 835769 (the PinePhone's A64), as BusyBox's objects.
A53_ERRATA = "-mfix-cortex-a53-835769"
# Compiler-generated async unwind rows for C frames; no outlining
# (the native Rust policy owns it).
UNWIND_CFLAGS = ("-fasynchronous-unwind-tables", "-mllvm", "-enable-machine-outliner=never")
# The engine is C of the 1990s: the dialect it was written in.
ENGINE_CFLAGS = ("-std=gnu99", "-w", "-DNORMALUNIX", "-DLINUX", "-D_DEFAULT_SOURCE")


def tool(name: str, brew_formula: str | None = None) -> Path:
    if brew_formula:
        path = Path(f"/opt/homebrew/opt/{brew_formula}/bin/{name}")
        if path.exists():
            return path
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing {name}; install LLVM and lld")
    return Path(found).absolute()


def run(log: Path, *args, cwd: Path | None = None) -> None:
    with log.open("a") as out:
        out.write("$ " + " ".join(map(str, args)) + "\n")
        out.flush()
        result = subprocess.run([str(a) for a in args], cwd=cwd, stdout=out,
                                stderr=subprocess.STDOUT)
    if result.returncode:
        print("\n".join(log.read_text(errors="replace").splitlines()[-60:]))
        raise SystemExit(f"command failed: {' '.join(map(str, args))}")


def engine_files(source: Path) -> list[str]:
    """The engine's source list from the Makefile of the source, less the
    platform file of X11 (the port replaces it)."""
    makefile = (source / "Makefile").read_text()
    names = re.search(r"^SRC_DOOM\s*=\s*(.*)$", makefile, re.M)
    if names is None:
        raise SystemExit("the Makefile of Doomgeneric lists no SRC_DOOM")
    objects = [n for n in names.group(1).split() if n.endswith(".o")]
    return [n[:-2] + ".c" for n in objects if n != "doomgeneric_xlib.o"]


def main() -> None:
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    port = sha256(b"".join(p.read_bytes() for p in PORT + PORT_HEADERS)).hexdigest()
    libc = RELIBC / "lib" / "libc.a"
    if not (RELIBC / "include" / "stdio.h").exists() or not libc.exists():
        raise SystemExit("build relibc with cargo xtask relibc first")
    stamp = WORK / "stamp"
    text = (f"{VERSION} {SHA256} {script} {port} "
            f"{sha256(libc.read_bytes()).hexdigest()}\n")
    if stamp.exists() and stamp.read_text() == text and OUTPUT.exists():
        print(f"doomgeneric ready: {OUTPUT}")
        return
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    log = WORK / "build.log"
    log.write_text("")
    archive = WORK / f"doomgeneric-{VERSION}.tar.gz"
    with urlopen(URL) as response:
        archive.write_bytes(response.read())
    if sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise SystemExit("Doomgeneric source archive has an unexpected SHA-256")
    with tarfile.open(archive) as members:
        members.extractall(WORK, filter="data")
    source = WORK / f"doomgeneric-{VERSION}" / "doomgeneric"
    clang, lld = tool("clang", "llvm"), tool("ld.lld", "lld")
    objcopy = tool("llvm-objcopy", "llvm")
    cc = (str(clang), "--target=aarch64-linux-gnu", "-nostdinc",
          "-isystem", str(RELIBC / "include"), "-mno-outline-atomics",
          "-fstack-protector-strong", "-ffunction-sections", "-fdata-sections",
          A53_ERRATA, "-fPIC", "-O2", *UNWIND_CFLAGS, *ENGINE_CFLAGS,
          f"-I{source}", f"-I{PORT_DIR}")
    objects = []
    (WORK / "obj").mkdir()
    for path in [source / name for name in engine_files(source)] + PORT:
        obj = WORK / "obj" / (path.stem + ".o")
        run(log, *cc, "-c", path, "-o", obj)
        objects.append(obj)
    # A relocatable link: the Rust program links relibc and the crt.
    joined = WORK / "joined.o"
    run(log, lld, "-r", "-o", joined, *objects)
    OUTPUT.unlink(missing_ok=True)
    run(log, objcopy, "--keep-global-symbol=main", joined, OUTPUT)
    stamp.write_text(text)
    print(f"doomgeneric ready: {OUTPUT}")


if __name__ == "__main__":
    main()
