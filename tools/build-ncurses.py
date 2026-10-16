#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build ncurses for the shell image (libncursesw.a and its headers, the
terminfo entries of the image) from its release archive, unchanged, against
relibc's headers and the Linux AArch64 C ABI they describe.

ncurses' own `configure` runs with the cross compiler of the project (clang
and lld), static, wide characters on, no C++ binding, no programs and no
manual pages. The terminfo database is the one of the archive: its tools
(`tic`) are built for this machine from the same archive, and compile the
entries the image holds (xterm-256color, xterm, vt100, linux) into
target/ncurses/terminfo, which the image carries in /usr/share/terminfo.
The library reads /usr/share/terminfo, or the directory TERMINFO names.

ncurses (MIT) is fetched at build time with its SHA-256 checked, as BusyBox
is; nano and htop link the library, and the image's licence notices name
it."""

from hashlib import sha256
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from urllib.request import urlopen

import pkgdesc


PACKAGE = pkgdesc.load("ncurses")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
URL = PACKAGE["url"]
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "ncurses"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
INSTALL = WORK / "install"
TERMINFO = WORK / "terminfo"
# Where the image keeps the database, and the entries it holds.
TERMINFO_DIR = "/usr/share/terminfo"
ENTRIES = ("xterm-256color", "xterm", "vt100", "linux")
# Cortex-A53 erratum 835769 (the PinePhone's A64), as BusyBox's objects.
A53_ERRATA = "-mfix-cortex-a53-835769"
# Compiler-generated async unwind rows for C frames; no outlining
# (the native Rust policy owns it).
UNWIND_CFLAGS = ("-fasynchronous-unwind-tables", "-mllvm", "-enable-machine-outliner=never")
CONFIGURE = (
    "--host=aarch64-linux-gnu", "--build=aarch64-apple-darwin",
    "--prefix=/usr", f"--with-default-terminfo-dir={TERMINFO_DIR}",
    f"--with-terminfo-dirs={TERMINFO_DIR}", "--without-shared", "--with-normal",
    "--without-debug", "--without-cxx", "--without-cxx-binding", "--without-ada",
    "--without-manpages", "--without-tests", "--without-progs", "--enable-widec",
    "--without-fallbacks",
    "--disable-stripping", "--without-gpm", "--without-sysmouse", "--without-pcre2",
    "--disable-pc-files", "--disable-home-terminfo",
    "--disable-root-environ", "--disable-leaks", "--with-build-cc=cc",
    "--enable-sigwinch", "--enable-mixed-case",
    # The reader of terminfo files holds the entry in a buffer on the stack:
    # three nested frames of 32 KiB with the extended colours of the wide
    # build, three of 4 KiB without them (a program's stack is 64 KiB). 256
    # colours stay.
    "--disable-ext-colors", "--without-dlsym", "--disable-getcap",
)


def tool(name: str, brew_formula: str | None = None) -> Path:
    if brew_formula:
        path = Path(f"/opt/homebrew/opt/{brew_formula}/bin/{name}")
        if path.exists():
            return path
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing {name}; install LLVM, lld and GNU Make")
    return Path(found).resolve()


def run(log: Path, *args, cwd: Path | None = None, env: dict | None = None) -> None:
    with log.open("a") as out:
        out.write("$ " + " ".join(map(str, args)) + "\n")
        out.flush()
        result = subprocess.run([str(a) for a in args], cwd=cwd, stdout=out,
                                stderr=subprocess.STDOUT, env=env)
    if result.returncode:
        print("\n".join(log.read_text(errors="replace").splitlines()[-60:]))
        raise SystemExit(f"command failed: {' '.join(map(str, args))}")


def stubs(log: Path, clang: Path, nm: Path, libc: Path, out: Path) -> None:
    """An object that defines what libc.a asks of the program that links it
    (posix-crt's symbols, the compiler's complex multiplication), so that the
    link tests of `configure` find the functions they look for. Nothing of it
    reaches the image."""
    listing = subprocess.run([str(nm), "-g", str(libc)], capture_output=True,
                             text=True, check=True).stdout
    undefined, defined = set(), set()
    for line in listing.splitlines():
        words = line.split()
        if len(words) == 2 and words[0] == "U":
            undefined.add(words[1])
        elif len(words) == 3 and words[1] in "TDBRWVu":
            defined.add(words[2])
    lines = []
    for name in sorted(undefined - defined):
        if name.startswith(("stafeto_", "__mul")):
            lines.append(f"void {name}(void) {{}}")
        else:
            lines.append(f"char {name}[16];")
    source = out.with_suffix(".c")
    source.write_text("\n".join(lines) + "\n")
    run(log, clang, "--target=aarch64-linux-gnu", "-nostdinc", "-fno-builtin", "-c",
        source, "-o", out)


def host_tic(log: Path, source: Path, build: Path) -> Path:
    """`tic` of the same archive, built for this machine."""
    build.mkdir()
    run(log, source / "configure", "--without-shared", "--without-cxx",
        "--without-cxx-binding", "--without-ada", "--without-manpages",
        "--without-tests", "--without-debug", "--disable-stripping",
        "--without-gpm", "--enable-mixed-case", "--prefix=/nonexistent", cwd=build)
    run(log, "make", "-j4", "-C", "include", cwd=build)
    run(log, "make", "-j4", "-C", "ncurses", cwd=build)
    run(log, "make", "-j4", "-C", "progs", "tic", cwd=build)
    return build / "progs" / "tic"


def main() -> None:
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    libc = RELIBC / "lib" / "libc.a"
    if not (RELIBC / "include" / "stdio.h").exists() or not libc.exists():
        raise SystemExit("build relibc with cargo xtask relibc first")
    stamp = WORK / "stamp"
    text = f"{VERSION} {SHA256} {script} {sha256(libc.read_bytes()).hexdigest()}\n"
    library = INSTALL / "lib" / "libncursesw.a"
    if stamp.exists() and stamp.read_text() == text and library.exists():
        print(f"ncurses ready: {library}")
        return
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    log = WORK / "build.log"
    log.write_text("")
    archive = WORK / f"ncurses-{VERSION}.tar.gz"
    with urlopen(URL) as response:
        archive.write_bytes(response.read())
    if sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise SystemExit("ncurses source archive has an unexpected SHA-256")
    with tarfile.open(archive) as members:
        members.extractall(WORK, filter="data")
    source = WORK / f"ncurses-{VERSION}"
    clang, lld = tool("clang", "llvm"), tool("ld.lld", "lld")
    ar, ranlib = tool("llvm-ar", "llvm"), tool("llvm-ranlib", "llvm")
    nm = tool("llvm-nm", "llvm")
    # The entries of the image, compiled by the tic of this archive.
    tic = host_tic(log, source, WORK / "host")
    run(log, tic, "-x", "-o", TERMINFO, source / "misc" / "terminfo.src")
    keep = {TERMINFO / name[0] / name for name in ENTRIES}
    for path in sorted(TERMINFO.rglob("*")):
        if path.is_file() and path not in keep:
            path.unlink()
    for path in sorted(TERMINFO.rglob("*"), reverse=True):
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()
    missing = [str(p) for p in keep if not p.exists()]
    if missing:
        raise SystemExit(f"tic wrote no {missing}")
    build = WORK / "build"
    build.mkdir()
    stub = WORK / "stubs.o"
    stubs(log, clang, nm, libc, stub)
    cc = " ".join((str(clang), "--target=aarch64-linux-gnu", "-nostdinc",
                   f"-isystem {RELIBC / 'include'}", "-mno-outline-atomics",
                   "-fno-stack-protector", "-ffunction-sections", "-fdata-sections",
                   A53_ERRATA, "-fno-pic", *UNWIND_CFLAGS))
    env = dict(os.environ, CC=cc, CFLAGS="-Os -w",
               LDFLAGS=f"-static -nostdlib --ld-path={lld} -L{RELIBC / 'lib'} {stub}",
               LIBS="-lc", AR=str(ar), RANLIB=str(ranlib))
    run(log, source / "configure", *CONFIGURE, cwd=build, env=env)
    run(log, "make", "-j4", "libs", cwd=build)
    run(log, "make", "install.libs", "install.includes", f"DESTDIR={INSTALL}", cwd=build)
    # Installed under /usr; the build of a program takes the prefix.
    for name in ("lib", "include"):
        shutil.move(INSTALL / "usr" / name, INSTALL / name)
    stamp.write_text(text)
    print(f"ncurses ready: {library}")


if __name__ == "__main__":
    main()
