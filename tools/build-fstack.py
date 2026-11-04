#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build F-Stack's libfstack.a (the TCP/IP stack of FreeBSD 15 in user
space) for stafeto, with the project's clang for AArch64.

The archive of the pinned commit is fetched with the SHA-256 of its tar
stream checked and unpacked under target/f-stack/source. ports/f-stack/
stafeto.patch is applied to it: a branch HOST_OS=stafeto of lib/Makefile
that takes no DPDK and builds the host layer of ports/f-stack in place of
F-Stack's DPDK files, and the few host files that named DPDK. The files of
the FreeBSD stack compile against F-Stack's own headers only (no libc); the
host files compile against relibc. The result is target/f-stack/libfstack.a
with the stack's own symbols made local, except the API (ff_api.symlist,
the ff_* names of the host files and the names ff_stafeto_*), the headers a
program needs under target/f-stack/include, and the probe of the stack
joined with the library (target/f-stack/fstack-probe.o, which
tools/build-libc-so.py programs links).

Each build counts the licences of the files it compiled (the sources and
every header they included, from the compiler's dependency files), by the
SPDX line of each file and by its text where it has none, writes the table
to target/f-stack/licences.txt (`tools/build-fstack.py licenses` prints
it), and fails when the files with the advertising clause of the
four-clause BSD licence are other than ADVERTISING_FILES. Then the unpacked
tree and the archive go (`--keep` keeps them, and `--again` rebuilds a kept
tree in place after a change of the port)."""

from hashlib import sha256
import gzip
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time
from urllib.request import urlopen

import importlib.util
import pkgdesc


PACKAGE = pkgdesc.load("f-stack")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
URL = PACKAGE["url"]
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "f-stack"
SOURCE = WORK / "source"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
PORT = ROOT / "ports" / "f-stack"
PATCH = PORT / "stafeto.patch"
# The files of ports/f-stack that go into lib/ of the tree.
OWN = ("ff_stafeto_if.c", "ff_stafeto_rte.h")
OUTPUT = WORK / "libfstack.a"
INCLUDE = WORK / "include"
# The headers of F-Stack a program includes.
HEADERS = ("ff_api.h", "ff_event.h", "ff_errno.h", "ff_flow_map.h")
# The probe of the stack on its loopback (tests/fstack-probe), one object
# with the library that exports `main` alone, for tools/build-libc-so.py
# programs.
PROBE_SOURCE = ROOT / "tests" / "fstack-probe" / "main.c"
PROBE = WORK / "fstack-probe.o"
# What the tree needs to build: the library, its make fragments and the
# FreeBSD sources, with the licence and the sample settings.
MEMBERS = ("lib/", "mk/", "freebsd/", "LICENSE")
# Cortex-A53 erratum 835769 (the PinePhone's A64), as BusyBox's objects.
A53_ERRATA = "-mfix-cortex-a53-835769"
# The options of F-Stack's Makefile that stay off: IPv6, netgraph, ipfw,
# the extra TCP stacks and their high-precision timer system, the kernel
# NIC interface, the page array and the coexistence with a host stack.
OPTIONS_OFF = ("FF_KNI", "FF_NETGRAPH", "FF_IPFW", "FF_INET6", "FF_TCPHPTS",
               "FF_EXTRA_TCP_STACKS", "FF_USE_PAGE_ARRAY", "FF_KERNEL_COEXIST",
               "FF_ZC_SEND", "FF_ZC_RECV", "FF_IPSEC")


def tool(name: str, brew_formula: str | None = None) -> Path:
    if brew_formula:
        path = Path(f"/opt/homebrew/opt/{brew_formula}/bin/{name}")
        if path.exists():
            return path
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing {name}; install LLVM, lld and GNU Make")
    return Path(found).absolute()


def make_tool() -> Path:
    """GNU Make 4 where the host has it as gmake (macOS keeps 3.81 as make)."""
    for name in ("gmake", "make"):
        found = shutil.which(name)
        if found:
            return Path(found)
    raise SystemExit("missing GNU Make")


def run(log: Path, *args, cwd: Path | None = None, env: dict | None = None) -> None:
    with log.open("a") as out:
        out.write("$ " + " ".join(map(str, args)) + "\n")
        out.flush()
        result = subprocess.run([str(a) for a in args], cwd=cwd, stdout=out,
                                stderr=subprocess.STDOUT, env=env)
    if result.returncode:
        print("\n".join(log.read_text(errors="replace").splitlines()[-80:]))
        raise SystemExit(f"command failed: {' '.join(map(str, args))}")


def relibc_commit() -> str:
    """The relibc commit tools/build-relibc.py pins, for the stamp."""
    spec = importlib.util.spec_from_file_location(
        "build_relibc", ROOT / "tools" / "build-relibc.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.COMMIT


def stamp_text() -> str:
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    own = sha256(b"".join((PORT / name).read_bytes()
                          for name in (*OWN, "stafeto.patch", "fstack.ini")))
    own.update(PROBE_SOURCE.read_bytes())
    return f"{VERSION} {SHA256} {script} {own.hexdigest()} relibc {relibc_commit()}\n"


def patched_files() -> list[str]:
    """The files of the tree stafeto.patch changes."""
    return [line.split()[1].split("/", 1)[1] for line in PATCH.read_text().splitlines()
            if line.startswith("+++ ")]


def unpack(log: Path, again: bool = False) -> None:
    """The pinned tree under SOURCE, patched, with the files of the port.
    `again` takes back only the files the patch changes, for a rebuild of
    the tree in place (the objects of make stay)."""
    archive = WORK / "f-stack.tar.gz"
    if not archive.exists():
        partial = archive.with_suffix(".part")
        with urlopen(URL) as response, partial.open("wb") as out:
            shutil.copyfileobj(response, out)
        partial.rename(archive)
    tar = gzip.decompress(archive.read_bytes())
    if sha256(tar).hexdigest() != SHA256:
        archive.unlink()
        raise SystemExit("the F-Stack archive has an unexpected SHA-256")
    if again:
        with tarfile.open(fileobj=io.BytesIO(tar)) as members:
            top = members.getnames()[0].split("/")[0]
            for name in patched_files():
                member = members.getmember(f"{top}/{name}")
                (SOURCE / name).write_bytes(members.extractfile(member).read())
        run(log, "patch", "-p1", "--no-backup-if-mismatch", "-i", PATCH, cwd=SOURCE)
        for name in OWN:
            shutil.copyfile(PORT / name, SOURCE / "lib" / name)
        return
    shutil.rmtree(SOURCE, ignore_errors=True)
    staging = WORK / "staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir()
    with tarfile.open(fileobj=io.BytesIO(tar)) as members:
        top = members.getnames()[0].split("/")[0]
        wanted = [m for m in members.getmembers()
                  if any(m.name == f"{top}/{p}" or m.name.startswith(f"{top}/{p}")
                         for p in MEMBERS)]
        members.extractall(staging, members=wanted, filter="data")
    (staging / top).rename(SOURCE)
    staging.rmdir()
    run(log, "patch", "-p1", "--no-backup-if-mismatch", "-i", PATCH, cwd=SOURCE)
    for name in OWN:
        shutil.copyfile(PORT / name, SOURCE / "lib" / name)


def build(log: Path, jobs: int) -> None:
    if not (RELIBC / "include" / "stdio.h").exists():
        raise SystemExit("build relibc with cargo xtask relibc first")
    clang, lld = tool("clang", "llvm"), tool("ld.lld", "lld")
    ar, nm = tool("llvm-ar", "llvm"), tool("llvm-nm", "llvm")
    objcopy = tool("llvm-objcopy", "llvm")
    # The compiler of both halves: the target and the code generation of the
    # programs of the system. The FreeBSD half adds -nostdinc and its own
    # headers (lib/Makefile); the host half adds relibc's.
    cc = " ".join((str(clang), "--target=aarch64-linux-gnu", "-mno-outline-atomics",
                   "-fno-stack-protector", "-ffunction-sections", "-fdata-sections",
                   A53_ERRATA, "-fPIC", "-MD"))
    host = " ".join(("-O2", "-nostdinc", f"-isystem {RELIBC / 'include'}", "-Wno-error"))
    variables = [f"{option}=" for option in OPTIONS_OFF]
    variables += [
        "HOST_OS=stafeto", "TGT_OS=stafeto", "MACHINE_CPUARCH=arm64", "COMPILER_TYPE=clang",
        f"CC={cc}", f"LD={lld}", f"AR={ar}", f"NM={nm}", f"OBJCOPY={objcopy}",
        f"STAFETO_HOST_CFLAGS={host}", "FF_LOOPBACK_SUPPORT=1", "WERROR=", "MK_SSP=no",
        # FreeBSD's generators of the kobj and vnode headers, run by GNU awk
        # where the host has it (the awk F-Stack is built with on Linux).
        f"AWK={shutil.which('gawk') or 'awk'}",
    ]
    run(log, make_tool(), f"-j{jobs}", "-C", SOURCE / "lib", *variables, "libfstack.a")


def install() -> None:
    shutil.copyfile(SOURCE / "lib" / "libfstack.a", OUTPUT)
    shutil.rmtree(INCLUDE, ignore_errors=True)
    INCLUDE.mkdir()
    for name in HEADERS:
        shutil.copyfile(SOURCE / "lib" / name, INCLUDE / name)
    # F-Stack's licence and the acknowledgements of the advertising clauses
    # the build carries, for the image's FSTACK-LICENSE.
    shutil.copyfile(SOURCE / "LICENSE", WORK / "LICENSE")
    (WORK / "ACKNOWLEDGEMENTS").write_text(
        "Files of the build under the four-clause BSD licence ask for these\n"
        "acknowledgements:\n" + "".join(
            f"  {path}: This product includes software developed by {who}.\n"
            for path, who in sorted(ADVERTISING_FILES.items())))


def probe(log: Path) -> None:
    """tests/fstack-probe joined with the library into one object that
    exports `main`: a name of the host layer the library keeps local is
    missing here, and the link of the program fails."""
    clang, lld = tool("clang", "llvm"), tool("ld.lld", "lld")
    objcopy = tool("llvm-objcopy", "llvm")
    main_o = WORK / "fstack-probe-main.o"
    joined = WORK / "fstack-probe.ro"
    run(log, clang, "--target=aarch64-linux-gnu", "-nostdinc", "-isystem", RELIBC / "include",
        "-I", INCLUDE, "-mno-outline-atomics", "-fno-stack-protector", "-ffunction-sections",
        "-fdata-sections", A53_ERRATA, "-fPIC", "-fno-builtin", "-O2", "-Wall", "-Werror",
        "-c", PROBE_SOURCE, "-o", main_o)
    run(log, lld, "-r", "-o", joined, main_o, OUTPUT)
    PROBE.unlink(missing_ok=True)
    run(log, objcopy, "--keep-global-symbol=main", joined, PROBE)
    joined.unlink()


def main() -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    jobs = os.cpu_count() or 4
    args = sys.argv[1:]
    if args == ["licenses"]:
        print((WORK / "licences.txt").read_text(), end="")
        return
    if args not in ([], ["--keep"], ["--again"]):
        raise SystemExit("usage: build-fstack.py [--keep | --again | licenses]")
    again = args == ["--again"]
    text = stamp_text()
    stamp = WORK / "stamp"
    if not again and stamp.exists() and stamp.read_text() == text and PROBE.exists():
        print(f"f-stack ready: {OUTPUT}")
        return
    stamp.unlink(missing_ok=True)
    log = WORK / "build.log"
    log.write_text("")
    started = time.monotonic()
    unpack(log, again and SOURCE.exists())
    build(log, jobs)
    install()
    probe(log)
    (WORK / "build-seconds").write_text(f"{time.monotonic() - started:.0f}\n")
    licenses()
    if not args:
        shutil.rmtree(SOURCE)
        (WORK / "f-stack.tar.gz").unlink()
    stamp.write_text(text)
    print(f"f-stack ready: {OUTPUT}")


# The words that name the licence of a file without an SPDX line.
ADVERTISING = re.compile(r"All advertising materials mentioning|This product includes software developed by", re.I)
NEITHER = re.compile(r"Neither the name|may not be used to endorse or promote|may be used to endorse or promote", re.I)
REDISTRIBUTION = re.compile(r"Redistribution and use in source and binary forms", re.I)
SPDX = re.compile(r"SPDX-License-Identifier:\s*([^*\n]+?)\s*(\*/)?$", re.M)


# The files of the build that carry the advertising clause of the
# four-clause BSD licence, each with the acknowledgement it asks for. The
# clauses of the University of California were rescinded in 1999; the
# others stand, and the image's note FSTACK-LICENSE carries them. A file
# that joins or leaves this list stops `licenses`.
ADVERTISING_FILES = {
    "freebsd/arm64/arm64/in_cksum.c": "the University of California, Berkeley and its contributors",
    "freebsd/netinet/tcp_sack.c": "the University of California, Berkeley and its contributors",
    "freebsd/sys/kernel.h": "the University of California, Berkeley and its contributors",
    "lib/ff_init_main.c": "the University of California, Berkeley and its contributors",
    "freebsd/net/bridgestp.h": "Wasabi Systems, Inc. for the NetBSD Project",
    "freebsd/net/if_bridge.c": "Wasabi Systems, Inc. for the NetBSD Project",
    "freebsd/net/if_bridgevar.h": "Wasabi Systems, Inc. for the NetBSD Project",
    "freebsd/net/if_media.c": "Jonathan Stone and Jason R. Thorpe for the NetBSD Project",
    "freebsd/net/if_media.h": "Jonathan Stone and Jason R. Thorpe for the NetBSD Project",
    "freebsd/sys/_pthreadtypes.h": "Chris Provenzano",
    "freebsd/sys/bus_dma.h": "Christopher G. Demetriou for the NetBSD Project",
    "lib/machine_include/machine/bus.h": "Christopher G. Demetriou for the NetBSD Project",
    "freebsd/sys/link_elf.h": "Paul Kranenburg",
    "freebsd/sys/priority.h": "Henrik Vestergaard Draboel",
    "freebsd/sys/rtprio.h": "Henrik Vestergaard Draboel",
    "freebsd/sys/sched.h": "HD Associates, Inc and Jukka Antero Ukkonen",
}


def compiled_files() -> list[Path]:
    """Every file the build compiled: the sources and the headers each
    included, from the dependency files of the compiler (-MD)."""
    files = set()
    for depend in (SOURCE / "lib").glob("*.d"):
        text = depend.read_text().replace("\\\n", " ")
        for name in text.split(":", 1)[1].split():
            path = (SOURCE / "lib" / name).resolve()
            if path.is_relative_to(SOURCE.resolve()):
                files.add(path)
    return sorted(files)


def licence_of(path: Path) -> str:
    """The SPDX line of the file or, where it has none, the licence its
    text names; the advertising clause marks the four-clause form."""
    head = "\n".join(path.read_text(errors="replace").splitlines()[:80])
    if ADVERTISING.search(head):
        return "advertising clause"
    found = SPDX.search(head)
    if found:
        return found.group(1).strip()
    if REDISTRIBUTION.search(head):
        return "BSD-3-Clause (no SPDX line)" if NEITHER.search(head) else "BSD-2-Clause (no SPDX line)"
    if "Copyright" in head or "copyright" in head:
        return "other notice"
    return "no notice"


def licenses() -> None:
    """The licences of the files the build compiled, into licences.txt."""
    files = compiled_files()
    if not files:
        raise SystemExit("no dependency files: the build compiled nothing")
    counts: dict[str, list[Path]] = {}
    for path in files:
        counts.setdefault(licence_of(path), []).append(path)
    root = SOURCE.resolve()
    sources = sum(1 for p in files if p.suffix in (".c", ".S"))
    lines = [f"f-stack: {len(files)} files compiled, {sources} of them sources"]
    for name, paths in sorted(counts.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        lines.append(f"  {len(paths):4} {name}")
    for name in ("advertising clause", "other notice"):
        for path in counts.get(name, []):
            lines.append(f"  {name}: {path.relative_to(root)}")
    (WORK / "licences.txt").write_text("\n".join(lines) + "\n")
    found = {str(p.relative_to(root)) for p in counts.get("advertising clause", [])}
    if found != set(ADVERTISING_FILES):
        raise SystemExit(f"the files with the advertising clause changed: new "
                         f"{sorted(found - set(ADVERTISING_FILES))}, gone "
                         f"{sorted(set(ADVERTISING_FILES) - found)}")


if __name__ == "__main__":
    main()
