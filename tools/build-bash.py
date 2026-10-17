#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build GNU bash for the shell image (`/bin/bash`) from its release archive,
unchanged, against relibc's headers and the Linux AArch64 C ABI they describe.

bash's own `configure` runs with the cross compiler of the project (clang and
lld), statically, with bash's malloc off (relibc's allocator serves it), the
readline and termcap library that come with bash, and no message catalogs. The
tests of `configure` that would run a program on the target take their results
from the cache variables below, each the answer of the layer. The result is
one relocatable object, target/bash/bash.o, that exports `main` alone: the
names of bash's own helpers cannot meet relibc's or the program's. tests/bash
links it with relibc's libc.a and posix-crt.

bash is GPL-3.0-or-later: the archive is fetched at build time with its
SHA-256 checked, as BusyBox is, and the image's licence notices name it."""

from hashlib import sha256
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from urllib.request import urlopen

import pkgdesc


PACKAGE = pkgdesc.load("bash")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
URL = PACKAGE["url"]
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "bash"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
OUTPUT = WORK / "bash.o"
# Cortex-A53 erratum 835769 (the PinePhone's A64), as BusyBox's objects.
A53_ERRATA = "-mfix-cortex-a53-835769"
# Compiler-generated async unwind rows for C frames; no outlining
# (the native Rust policy owns it).
UNWIND_CFLAGS = ("-fasynchronous-unwind-tables", "-mllvm", "-enable-machine-outliner=never")
# What `configure` cannot learn by running a program. Each is the layer's
# answer: sigsetjmp, named pipes, signal numbers and handlers as on Linux.
CACHE = {
    "bash_cv_func_sigsetjmp": "present",
    "bash_cv_sys_named_pipes": "present",
    "bash_cv_unusable_rtsigs": "no",
    "bash_cv_wcontinued_broken": "no",
    "bash_cv_must_reinstall_sighandlers": "no",
    "bash_cv_pgrp_pipe": "no",
}
CONFIGURE = (
    "--host=aarch64-linux-gnu", "--build=aarch64-apple-darwin",
    "--without-bash-malloc", "--enable-static-link", "--disable-nls",
    "--disable-rpath",
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


def main() -> None:
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    libc = RELIBC / "lib" / "libc.a"
    if not (RELIBC / "include" / "stdio.h").exists() or not libc.exists():
        raise SystemExit("build relibc with cargo xtask relibc first")
    stamp = WORK / "stamp"
    text = f"{VERSION} {SHA256} {script} {sha256(libc.read_bytes()).hexdigest()}\n"
    if stamp.exists() and stamp.read_text() == text and OUTPUT.exists():
        print(f"bash ready: {OUTPUT}")
        return
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    log = WORK / "build.log"
    log.write_text("")
    archive = WORK / f"bash-{VERSION}.tar.gz"
    with urlopen(URL) as response:
        archive.write_bytes(response.read())
    if sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise SystemExit("bash source archive has an unexpected SHA-256")
    with tarfile.open(archive) as members:
        members.extractall(WORK, filter="data")
    source = WORK / f"bash-{VERSION}"
    build = WORK / "build"
    build.mkdir()
    clang, lld = tool("clang", "llvm"), tool("ld.lld", "lld")
    ar, ranlib = tool("llvm-ar", "llvm"), tool("llvm-ranlib", "llvm")
    objcopy, nm = tool("llvm-objcopy", "llvm"), tool("llvm-nm", "llvm")
    stub = WORK / "stubs.o"
    stubs(log, clang, nm, libc, stub)
    cc = " ".join((str(clang), "--target=aarch64-linux-gnu", "-nostdinc",
                   f"-isystem {RELIBC / 'include'}", "-mno-outline-atomics",
                   "-fno-stack-protector", "-ffunction-sections", "-fdata-sections",
                   A53_ERRATA, "-fno-pic", *UNWIND_CFLAGS))
    env = dict(os.environ, **CACHE, CC=cc, CFLAGS="-Os -w",
               LDFLAGS=f"-static -nostdlib --ld-path={lld} -L{RELIBC / 'lib'} {stub}",
               LIBS="-lc", CC_FOR_BUILD="cc", AR=str(ar), RANLIB=str(ranlib))
    run(log, source / "configure", *CONFIGURE, cwd=build, env=env)
    # The link is a relocatable one: the Rust program links relibc and the
    # crt. LIBS keeps bash's own libraries and drops -lc.
    run(log, "make", "-j4", "bash", "LIBS=$(BUILTINS_LIB) $(LIBRARIES)",
        f"LDFLAGS=-nostdlib -r --ld-path={lld}", cwd=build)
    joined = build / "bash"
    OUTPUT.unlink(missing_ok=True)
    run(log, objcopy, "--keep-global-symbol=main", joined, OUTPUT)
    stamp.write_text(text)
    print(f"bash ready: {OUTPUT}")


if __name__ == "__main__":
    main()
