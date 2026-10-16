#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build htop for the shell image (`/bin/htop`) from its release archive,
unchanged, against relibc's headers and the Linux AArch64 C ABI they describe,
and against the ncurses of tools/build-ncurses.py.

htop's own `configure` runs with the cross compiler of the project (clang and
lld), with the Linux platform (the host triple names it), the wide-character
curses, and no optional library (hwloc, libsensors, libcap, libunwind). The
tests of `configure` that would run a program on the target take their
results from the cache variables below, each the answer of the layer. htop
reads the process list, the CPU times and the memory from /proc, which the
process service provides. The result is one relocatable object,
target/htop/htop.o, that exports `main` alone: the names of htop's own
helpers cannot meet relibc's or the program's. tests/htop links it with
relibc's libc.a and posix-crt.

htop is GPL-2.0-or-later: the archive is fetched at build time with its
SHA-256 checked, as BusyBox is, and the image's licence notices name it."""

from hashlib import sha256
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from urllib.request import urlopen

import pkgdesc

import importlib.util


PACKAGE = pkgdesc.load("htop")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
URL = PACKAGE["url"]
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "htop"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
NCURSES = ROOT / "target" / "ncurses" / "install"
# Headers htop includes on Linux that relibc lacks; searched after relibc's
# own (-idirafter).
COMPAT = ROOT / "tools" / "htop" / "compat"
OUTPUT = WORK / "htop.o"
# Cortex-A53 erratum 835769 (the PinePhone's A64), as BusyBox's objects.
A53_ERRATA = "-mfix-cortex-a53-835769"
# Compiler-generated async unwind rows for C frames; no outlining
# (the native Rust policy owns it).
UNWIND_CFLAGS = ("-fasynchronous-unwind-tables", "-mllvm", "-enable-machine-outliner=never")
# What `configure` cannot learn by running a program: filled in as the
# build needs them.
CACHE: dict[str, str] = {}
# htop's configure finds clock_gettime but never defines HAVE_CLOCK_GETTIME,
# so its clock functions (generic/gettime.c) fall back on gettimeofday, which
# the layer leaves out as POSIX.1-2024 does (ENOSYS). The macro says that
# clock_gettime is there.
DEFINES = "-DHAVE_CLOCK_GETTIME=1"
CONFIGURE = (
    "--host=aarch64-linux-gnu", "--build=aarch64-apple-darwin",
    "--enable-unicode", "--disable-affinity", "--disable-hwloc", "--disable-sensors",
    "--disable-capabilities", "--disable-delayacct", "--disable-dependency-tracking",
    "--with-proc=/proc",
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


def ncurses_module():
    spec = importlib.util.spec_from_file_location(
        "build_ncurses", ROOT / "tools" / "build-ncurses.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    libc = RELIBC / "lib" / "libc.a"
    curses = NCURSES / "lib" / "libncursesw.a"
    if not (RELIBC / "include" / "stdio.h").exists() or not libc.exists():
        raise SystemExit("build relibc with cargo xtask relibc first")
    if not curses.exists():
        raise SystemExit("build ncurses with tools/build-ncurses.py first")
    stamp = WORK / "stamp"
    text = (f"{VERSION} {SHA256} {script} {sha256(libc.read_bytes()).hexdigest()} "
            f"{sha256(curses.read_bytes()).hexdigest()}\n")
    if stamp.exists() and stamp.read_text() == text and OUTPUT.exists():
        print(f"htop ready: {OUTPUT}")
        return
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    log = WORK / "build.log"
    log.write_text("")
    archive = WORK / f"htop-{VERSION}.tar.xz"
    with urlopen(URL) as response:
        archive.write_bytes(response.read())
    if sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise SystemExit("htop source archive has an unexpected SHA-256")
    with tarfile.open(archive) as members:
        members.extractall(WORK, filter="data")
    source = WORK / f"htop-{VERSION}"
    build = WORK / "build"
    build.mkdir()
    clang, lld = tool("clang", "llvm"), tool("ld.lld", "lld")
    ar, ranlib = tool("llvm-ar", "llvm"), tool("llvm-ranlib", "llvm")
    objcopy, nm = tool("llvm-objcopy", "llvm"), tool("llvm-nm", "llvm")
    stub = WORK / "stubs.o"
    ncurses_module().stubs(log, clang, nm, libc, stub)
    cc = " ".join((str(clang), "--target=aarch64-linux-gnu", "-nostdinc",
                   f"-isystem {RELIBC / 'include'}", f"-idirafter {COMPAT}", "-mno-outline-atomics",
                   "-fno-stack-protector", "-ffunction-sections", "-fdata-sections",
                   A53_ERRATA, "-fno-pic", DEFINES, *UNWIND_CFLAGS))
    env = dict(os.environ, **CACHE, CC=cc, CFLAGS="-Os -w",
               CPPFLAGS=f"-I{NCURSES / 'include'}",
               CURSES_CFLAGS=f"-I{NCURSES / 'include'}",
               CURSES_LIBS=f"-L{NCURSES / 'lib'} -lncursesw",
               LDFLAGS=f"-static -nostdlib --ld-path={lld} -L{RELIBC / 'lib'} -L{NCURSES / 'lib'} {stub}",
               LIBS="-lc", AR=str(ar), RANLIB=str(ranlib))
    run(log, source / "configure", *CONFIGURE, cwd=build, env=env)
    # The link is a relocatable one: the Rust program links relibc and the
    # crt.
    run(log, "make", "-j4", "htop", "LIBS=-lncursesw",
        f"LDFLAGS=-nostdlib -r --ld-path={lld} -L{NCURSES / 'lib'}", cwd=build)
    joined = build / "htop"
    OUTPUT.unlink(missing_ok=True)
    run(log, objcopy, "--keep-global-symbol=main", joined, OUTPUT)
    stamp.write_text(text)
    print(f"htop ready: {OUTPUT}")


if __name__ == "__main__":
    main()
