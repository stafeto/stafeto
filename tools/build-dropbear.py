#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build the Dropbear SSH server for the images with the network service
(`/bin/dropbear`) from its release archive, unchanged, against relibc's
headers and the Linux AArch64 C ABI they describe.

Dropbear's own `configure` runs with the cross compiler of the project
(clang and lld) and the Linux platform (the host triple names it), with its
bundled LibTomCrypt and LibTomMath. Only the server is built. The login
records are left out: no utmp, utmpx, wtmp, wtmpx, lastlog or login(), and
no syslog (the server then logs to stderr and has no option `-E`). No zlib, no PAM, no
hardening flags of `configure` (the compiler options below carry the stack
protector). `localoptions.h` (tools/dropbear/localoptions.h) turns off what
the image does not hold: the re-execution of the server for each connection
(it needs /proc/self/exe), the SFTP server, the agent and X11 forwarding, the
password login and every kind of port forwarding; it also sets the limits of
connections that have not authenticated. The server and `dropbearkey` are one
program that runs as the name in argv[0] says. The boot script still starts
the server with `-s -j -k`, which this build ignores: a second layer. The result is one relocatable object,
target/dropbear/dropbear.o, that exports `main` alone; tools/build-libc-so.py
programs links it against libc.so.

Dropbear is under the MIT licence with parts under the 2-clause BSD licence
and others (its LICENSE file): the archive is fetched at build time with its
SHA-256 checked, and the package carries the whole LICENSE file."""

from hashlib import sha256
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time
from urllib.request import Request, urlopen

import pkgdesc


PACKAGE = pkgdesc.load("dropbear")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
URL = PACKAGE["url"]
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "dropbear"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
OPTIONS = ROOT / "tools" / "dropbear" / "localoptions.h"
OUTPUT = WORK / "dropbear.o"
# Cortex-A53 erratum 835769 (the PinePhone's A64), as BusyBox's objects.
A53_ERRATA = "-mfix-cortex-a53-835769"
# Two constants of the Linux headers that relibc's lack, given as the values
# of the Linux ABI: SOL_TCP (6, the protocol number of TCP), which Dropbear
# uses to ask for TCP Fast Open (the network service takes no such option and
# the server only traces the refusal), and IPPORT_RESERVED (1024), the first
# port that needs no privilege (the check of a forwarded port, which the
# server refuses by `-j -k` anyway).
LINUX_CONSTANTS = ("-DSOL_TCP=6", "-DIPPORT_RESERVED=1024")
# Compiler-generated async unwind rows for C frames; no outlining
# (the native Rust policy owns it).
UNWIND_CFLAGS = ("-fasynchronous-unwind-tables", "-mllvm", "-enable-machine-outliner=never")
# What `configure` cannot learn by running a program: filled in as the
# build needs them.
CACHE: dict[str, str] = {}
CONFIGURE = (
    "--host=aarch64-linux-gnu", "--build=aarch64-apple-darwin",
    "--enable-bundled-libtom", "--disable-zlib", "--disable-pam", "--disable-harden",
    "--disable-syslog", "--disable-lastlog", "--disable-utmp", "--disable-utmpx",
    "--disable-wtmp", "--disable-wtmpx", "--disable-loginfunc", "--disable-pututline",
    "--disable-pututxline",
)


def tool(name: str, brew_formula: str | None = None) -> Path:
    if brew_formula:
        path = Path(f"/opt/homebrew/opt/{brew_formula}/bin/{name}")
        if path.exists():
            return path
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing {name}; install LLVM, lld and GNU Make")
    return Path(found).absolute()


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
    options = sha256(OPTIONS.read_bytes()).hexdigest()
    libc = RELIBC / "lib" / "libc.a"
    if not (RELIBC / "include" / "stdio.h").exists() or not libc.exists():
        raise SystemExit("build relibc with cargo xtask relibc first")
    stamp = WORK / "stamp"
    text = (f"{VERSION} {SHA256} {script} {options} "
            f"{sha256(libc.read_bytes()).hexdigest()}\n")
    if stamp.exists() and stamp.read_text() == text and OUTPUT.exists():
        print(f"dropbear ready: {OUTPUT}")
        return
    began = time.monotonic()
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    log = WORK / "build.log"
    log.write_text("")
    archive = WORK / f"dropbear-{VERSION}.tar.bz2"
    # The server of the archive refuses the default agent of urllib.
    with urlopen(Request(URL, headers={"User-Agent": "stafeto-build"})) as response:
        archive.write_bytes(response.read())
    if sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise SystemExit("dropbear source archive has an unexpected SHA-256")
    with tarfile.open(archive) as members:
        members.extractall(WORK, filter="data")
    source = WORK / f"dropbear-{VERSION}"
    build = WORK / "build"
    build.mkdir()
    shutil.copy(OPTIONS, build / "localoptions.h")
    clang, lld = tool("clang", "llvm"), tool("ld.lld", "lld")
    ar, ranlib = tool("llvm-ar", "llvm"), tool("llvm-ranlib", "llvm")
    objcopy, nm = tool("llvm-objcopy", "llvm"), tool("llvm-nm", "llvm")
    stub = WORK / "stubs.o"
    ncurses_module().stubs(log, clang, nm, libc, stub)
    cc = " ".join((str(clang), "--target=aarch64-linux-gnu", "-nostdinc",
                   f"-isystem {RELIBC / 'include'}", "-mno-outline-atomics",
                   "-fstack-protector-strong", "-ffunction-sections", "-fdata-sections",
                   A53_ERRATA, *LINUX_CONSTANTS, "-fPIC", *UNWIND_CFLAGS))
    env = dict(os.environ, **CACHE, CC=cc, CFLAGS="-Os -w",
               LDFLAGS=f"-static -nostdlib --ld-path={lld} -L{RELIBC / 'lib'} {stub}",
               LIBS="-lc", AR=str(ar), RANLIB=str(ranlib),
               LTM_CFLAGS="-Os -fomit-frame-pointer")
    run(log, source / "configure", *CONFIGURE, cwd=build, env=env)
    # The link is a relocatable one: the Rust program links relibc and the
    # crt, and the C library of the program is libc.so. LibTomCrypt and
    # LibTomMath are archives of the build tree that the server's own link
    # takes in.
    # One program for the server and `dropbearkey` (the key of the host is made by the boot
    # script): `dropbearmulti` runs the one that argv[0] names.
    run(log, "make", "-j4", "PROGRAMS=dropbear dropbearkey", "MULTI=1", "dropbearmulti", "LIBS=",
        f"LDFLAGS=-nostdlib -r --ld-path={lld}", cwd=build)
    joined = build / "dropbearmulti"
    OUTPUT.unlink(missing_ok=True)
    run(log, objcopy, "--keep-global-symbol=main", joined, OUTPUT)
    listing = subprocess.run([str(nm), "-g", "--defined-only", str(OUTPUT)],
                             capture_output=True, text=True, check=True).stdout.split()
    if listing[-2:] != ["T", "main"] or len(listing) != 3:
        raise SystemExit(f"dropbear.o exports more than main: {listing[:12]}")
    stamp.write_text(text)
    print(f"dropbear ready: {OUTPUT} ({time.monotonic() - began:.0f} s)")


if __name__ == "__main__":
    main()
