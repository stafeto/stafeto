#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build OpenDoas (`/bin/doas`, the set-user-ID program that runs a command as
another user by the rules of /etc/doas.conf) from its release archive,
unchanged, against relibc's headers and the Linux AArch64 C ABI they describe.

The build skips OpenDoas's `configure` and writes the header it would write:
no PAM, no shadow authentication and no timestamps for `persist`, so a rule
with a password (anything but `nopass`) is refused with "Authentication
required" and the program holds no code that reads a password. What relibc
lacks (execvpe, getprogname, setprogname and strtonum come from OpenDoas's own
libopenbsd; closefrom, setresuid and setresgid from tools/doas/compat.c) is added. The grammar
(parse.y) goes through the host's yacc. The result is one relocatable object,
target/doas/doas.o, that exports `main` alone; tools/build-libc-so.py programs
links it against libc.so.

OpenDoas is under the ISC licence, with files of libopenbsd under the BSD
licences: the archive is fetched at build time with its SHA-256 checked, and
the package carries the LICENSE file and the headers of the BSD files."""

from hashlib import sha256
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time
from urllib.request import urlopen

import pkgdesc


PACKAGE = pkgdesc.load("doas")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
URL = PACKAGE["url"]
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "doas"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
COMPAT = ROOT / "tools" / "doas" / "compat.c"
OUTPUT = WORK / "doas.o"
NOTICES = WORK / "libopenbsd-notices"
# Cortex-A53 erratum 835769 (the PinePhone's A64), as BusyBox's objects.
A53_ERRATA = "-mfix-cortex-a53-835769"
UNWIND_CFLAGS = ("-fasynchronous-unwind-tables", "-mllvm", "-enable-machine-outliner=never")
# What OpenDoas's configure would find in relibc. The functions it lacks are
# the ones openbsd.h declares without HAVE_: strtonum, execvpe and setprogname
# (libopenbsd's own), and closefrom, setresuid and setresgid (tools/doas/compat.c).
HAVE = ("REALLOCARRAY", "EXPLICIT_BZERO", "STRLCAT", "STRLCPY", "ERRC", "VERRC")
CONFIG_H = ("#ifndef CONFIG_H\n#define CONFIG_H\n\n"
            + "".join(f"#define HAVE_{name} 1\n" for name in HAVE)
            + "#define UID_MAX 65535\n#define GID_MAX 65535\n"
            '#define DOAS_CONF "/etc/doas.conf"\n\n#endif /* CONFIG_H */\n')
SOURCES = ("doas.c", "env.c", "parse.c", "libopenbsd/execvpe.c", "libopenbsd/progname.c",
           "libopenbsd/strtonum.c")
# The files of libopenbsd under a BSD licence: their headers are the notices.
BSD_FILES = ("libopenbsd/errc.c", "libopenbsd/execvpe.c", "libopenbsd/progname.c",
             "libopenbsd/verrc.c")


def tool(name: str, brew_formula: str | None = None) -> Path:
    if brew_formula:
        path = Path(f"/opt/homebrew/opt/{brew_formula}/bin/{name}")
        if path.exists():
            return path
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing {name}; install LLVM, lld and a yacc")
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


def main() -> None:
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    compat = sha256(COMPAT.read_bytes()).hexdigest()
    libc = RELIBC / "lib" / "libc.a"
    if not (RELIBC / "include" / "stdio.h").exists() or not libc.exists():
        raise SystemExit("build relibc with cargo xtask relibc first")
    stamp = WORK / "stamp"
    text = f"{VERSION} {SHA256} {script} {compat} {sha256(libc.read_bytes()).hexdigest()}\n"
    if stamp.exists() and stamp.read_text() == text and OUTPUT.exists() and NOTICES.exists():
        print(f"doas ready: {OUTPUT}")
        return
    began = time.monotonic()
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    log = WORK / "build.log"
    log.write_text("")
    archive = WORK / f"opendoas-{VERSION}.tar.xz"
    with urlopen(URL) as response:
        archive.write_bytes(response.read())
    if sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise SystemExit("doas source archive has an unexpected SHA-256")
    with tarfile.open(archive) as members:
        members.extractall(WORK, filter="data")
    source = WORK / f"opendoas-{VERSION}"
    (source / "config.h").write_text(CONFIG_H)
    # The grammar, as the makefile's implicit rule does it.
    run(log, tool("yacc"), "parse.y", cwd=source)
    (source / "y.tab.c").rename(source / "parse.c")
    shutil.copy(COMPAT, source / "compat.c")
    clang, lld = tool("clang", "llvm"), tool("ld.lld", "lld")
    objcopy, nm = tool("llvm-objcopy", "llvm"), tool("llvm-nm", "llvm")
    objects = []
    for name in (*SOURCES, "compat.c"):
        obj = source / (name.replace("/", "_") + ".o")
        run(log, clang, "--target=aarch64-linux-gnu", "-nostdinc", "-isystem", RELIBC / "include",
            "-I", source, "-I", source / "libopenbsd", "-D_DEFAULT_SOURCE", "-D_GNU_SOURCE", "-include", "alloca.h",
            "-Os", "-w", "-mno-outline-atomics", "-fstack-protector-strong",
            "-ffunction-sections", "-fdata-sections", A53_ERRATA, "-fPIC", *UNWIND_CFLAGS,
            "-c", source / name, "-o", obj)
        objects.append(obj)
    joined = WORK / "doas-joined.o"
    run(log, lld, "-r", "-o", joined, *objects)
    OUTPUT.unlink(missing_ok=True)
    run(log, objcopy, "--keep-global-symbol=main", joined, OUTPUT)
    listing = subprocess.run([str(nm), "-g", "--defined-only", str(OUTPUT)],
                             capture_output=True, text=True, check=True).stdout.split()
    if listing[-2:] != ["T", "main"] or len(listing) != 3:
        raise SystemExit(f"doas.o exports more than main: {listing[:12]}")
    notices = []
    for name in BSD_FILES:
        head = re.match(r"\s*/\*(.*?)\*/", (source / name).read_text(), re.S)
        if head is None:
            raise SystemExit(f"{name}: no licence header")
        notices.append(f"==== {name}\n{head.group(1).strip()}\n")
    NOTICES.write_text("\n".join(notices))
    stamp.write_text(text)
    print(f"doas ready: {OUTPUT} ({time.monotonic() - began:.0f} s)")


if __name__ == "__main__":
    main()
