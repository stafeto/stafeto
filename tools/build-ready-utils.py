#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build the ready-made utilities that BusyBox lacks (Ф10b) from their own
sources, unchanged, against relibc's headers: getconf, join and pathchk from
sbase (MIT), file and iconv from toybox (0BSD), compress from ncompress
(public domain).

Each program's `main` is renamed `ready_<applet>_main` (-Dmain=) and its objects are
linked into one relocatable object that exports that function alone, so the
names of the program's own helpers cannot meet BusyBox's. The objects go into
one archive that the BusyBox image links; BusyBox names the applets
(tools/busybox/stafeto/miscutils/stafeto_ready.c). What the programs ask of
the C library comes from relibc; the Linux headers it lacks are declared in
tools/ready-utils/compat (prototypes and constants, no code)."""

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import gzip
from pathlib import Path
import io
import os
import shutil
import subprocess
import tarfile
from urllib.request import urlopen

import pkgdesc


ROOT = Path(__file__).resolve().parents[1]
COMPAT = ROOT / "tools" / "ready-utils" / "compat"
# The headers of BusyBox's build that relibc lacks (byteswap.h among them),
# searched after relibc's own, as are those of COMPAT: a header relibc gets
# later takes their place.
BUSYBOX_COMPAT = ROOT / "tools" / "busybox" / "compat"

# name: (archive URL, SHA-256 of the archive after gunzip (the tar stream, which
# a server may compress differently), the licence file, its SPDX identifier),
# from the descriptions in packages/
SOURCES = {
    name: (d["url"], d["sha256"], d["license_file"], d["license"])
    for name, d in ((n, pkgdesc.load(n)) for n in ("sbase", "toybox", "ncompress"))
}
# The applets: the program they come from and the name of its main.
SBASE_APPLETS = ("getconf", "join", "pathchk")
TOYBOX_APPLETS = ("file", "iconv")
NCOMPRESS_APPLETS = ("compress",)
APPLETS = SBASE_APPLETS + TOYBOX_APPLETS + NCOMPRESS_APPLETS
# Files of sbase's libutil with a notice of their own (BSD-3-Clause, ISC) that
# comes with a binary copy: the programs link them (join: memmem; the others:
# strtonum, reallocarray).
SBASE_NOTICES = ("libutil/memmem.c", "libutil/strtonum.c", "libutil/reallocarray.c")
# What sbase's Makefile defines for its programs (CPPFLAGS).
SBASE_DEFINES = ("-D_DEFAULT_SOURCE", "-D_NETBSD_SOURCE", "-D_BSD_SOURCE",
                 "-D_XOPEN_SOURCE=700", "-D_FILE_OFFSET_BITS=64")
# What ncompress's notes ask for: utime.h and lstat. Its tables are static and
# every process of the shell image carries them in its quota: the Makefile's
# 800 kB of memory (USERMEM) asks for 1.3 MB of them, 16-bit codes for 700 kB,
# and BITS=14 (the codes POSIX requires an implementation to take, with the
# 12-bit ones of -b) for 180 kB.
NCOMPRESS_DEFINES = ("-DUTIME_H=1", "-DLSTAT=1", "-DBITS=14")
# What toybox's build adds to the compiler's flags: its char is unsigned, its
# pointers alias.
TOYBOX_FLAGS = ("-funsigned-char", "-fno-strict-aliasing")


def gnu_sed() -> bool:
    """Whether the `sed` on PATH is GNU sed (toybox's scripts use it by that name)."""
    found = subprocess.run(["sed", "--version"], text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, check=False)
    return found.returncode == 0 and "GNU sed" in found.stdout


def tool(name: str, brew_formula: str | None = None) -> Path:
    if brew_formula:
        path = Path(f"/opt/homebrew/opt/{brew_formula}/bin/{name}")
        if path.exists():
            return path
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing {name}; install LLVM, lld and GNU sed (brew install llvm lld gnu-sed)")
    return Path(found).absolute()


def licence_files(work: Path) -> dict[str, Path]:
    """The licence file of each program's source, by program."""
    return {name: next((work / "build" / name).glob("source*")) / SOURCES[name][2]
            for name in SOURCES}


def notices(source: Path) -> str:
    """The leading comment of each file of SBASE_NOTICES: its copyright, its
    terms."""
    out = []
    for name in SBASE_NOTICES:
        text = (source / name).read_text()
        start, end = text.index("/*", text.index("*/") if text.startswith("/*\t$") else 0), None
        end = text.index("*/", start) + 2
        block = text[start:end]
        if "Copyright" not in block or "ermission" not in block and "edistribution" not in block:
            raise SystemExit(f"sbase {name} has no notice at its start")
        out.append(f"==== sbase {name} ====\n\n{block}\n\n")
    return "".join(out)


def fetch(work: Path, name: str, suffix: str = "") -> Path:
    """The source of `name` (`suffix` for another copy of it) under `work`,
    from the pinned archive."""
    url, expected, _, _ = SOURCES[name]
    directory = work / "build" / name
    archive = work / "downloads" / f"{name}.tar.gz"
    source = directory / ("source" + suffix)
    if source.exists():
        return source
    directory.mkdir(parents=True, exist_ok=True)
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        with urlopen(url) as response:
            archive.write_bytes(response.read())
    tar = gzip.decompress(archive.read_bytes())
    if sha256(tar).hexdigest() != expected:
        archive.unlink()
        raise SystemExit(f"the archive of {name} has an unexpected SHA-256")
    staging = directory / ("staging" + suffix)
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir()
    with tarfile.open(fileobj=io.BytesIO(tar)) as members:
        members.extractall(staging, filter="data")
    (top,) = list(staging.iterdir())
    top.rename(source)
    staging.rmdir()
    return source


class Build:
    def __init__(self, work: Path, flags: list[str], clang: Path, lld: Path,
                 ar: Path, objcopy: Path, include: Path):
        self.work, self.flags = work, flags
        self.build = work / "build"
        self.clang, self.lld, self.ar, self.objcopy = clang, lld, ar, objcopy
        self.base = ["--target=aarch64-linux-gnu", "-nostdinc", f"-isystem{include}",
                     f"-idirafter{COMPAT}", f"-idirafter{BUSYBOX_COMPAT}", "-mno-outline-atomics", "-fno-stack-protector",
                     "-ffunction-sections", "-fdata-sections", "-Os", "-w", *flags]
        self.log = work / "build" / "build.log"

    def run(self, *args, cwd: Path | None = None, env: dict | None = None) -> None:
        with self.log.open("a") as log:
            log.write("$ " + " ".join(map(str, args)) + "\n")
            log.flush()
            result = subprocess.run([str(a) for a in args], cwd=cwd, stdout=log,
                                    stderr=subprocess.STDOUT, env=env)
        if result.returncode:
            print("\n".join(self.log.read_text(errors="replace").splitlines()[-40:]))
            raise SystemExit(f"command failed: {' '.join(map(str, args))}")

    def compile(self, source: Path, out: Path, *extra: str, cwd: Path | None = None) -> None:
        out.parent.mkdir(parents=True, exist_ok=True)
        self.run(self.clang, *self.base, *extra, "-c", source, "-o", out, cwd=cwd)

    def compile_all(self, jobs: list[tuple[Path, Path, tuple[str, ...], Path | None]]) -> None:
        with ThreadPoolExecutor(max_workers=4) as pool:
            for future in [pool.submit(self.compile, s, o, *e, cwd=c) for s, o, e, c in jobs]:
                future.result()

    def single(self, applet: str, objects: list[Path], libraries: list[Path], out: Path) -> None:
        """One relocatable object of `objects` and the members of `libraries`
        they need, with `ready_<applet>_main` the only global symbol it defines."""
        joined = out.with_suffix(".r.o")
        self.run(self.lld, "-r", *objects, *libraries, "-o", joined)
        self.run(self.objcopy, f"--keep-global-symbol=ready_{applet}_main", joined, out)
        joined.unlink()

    def sbase(self) -> list[Path]:
        source = fetch(self.work, "sbase")
        objects = self.build / "sbase" / "objects"
        generated = self.build / "sbase" / "generated"
        generated.mkdir(parents=True, exist_ok=True)
        # getconf.h is made from a script of the source, as its Makefile does.
        with (generated / "getconf.h").open("w") as header:
            subprocess.run(["sh", "scripts/getconf.sh"], cwd=source, stdout=header, check=True)
        extra = (f"-I{source}", f"-I{generated}", *SBASE_DEFINES)
        jobs = []
        archives = []
        for directory in ("libutil", "libutf"):
            members = []
            for c in sorted((source / directory).glob("*.c")):
                o = objects / directory / (c.stem + ".o")
                jobs.append((c, o, extra, None))
                members.append(o)
            archives.append((self.build / "sbase" / f"{directory}.a", members))
        for applet in SBASE_APPLETS:
            jobs.append((source / f"{applet}.c", objects / f"{applet}.o",
                         (*extra, f"-Dmain=ready_{applet}_main"), None))
        self.compile_all(jobs)
        libraries = []
        for archive, members in archives:
            archive.unlink(missing_ok=True)
            self.run(self.ar, "rcs", archive, *members)
            libraries.append(archive)
        out = []
        for applet in SBASE_APPLETS:
            o = self.build / "sbase" / f"{applet}.o"
            self.single(applet, [objects / f"{applet}.o"], libraries, o)
            out.append(o)
        return out

    def toybox(self) -> list[Path]:
        out = []
        for applet in TOYBOX_APPLETS:
            # Each program has its own copy of the tree: the headers toybox
            # generates are those of one command.
            source = fetch(self.work, "toybox", "-" + applet)
            env = dict(os.environ)
            if shutil.which("gsed") is None and not gnu_sed():
                raise SystemExit("missing GNU sed; install it (brew install gnu-sed) or put it first on PATH as sed")
            self.run("scripts/single.sh", applet, cwd=source, env={**env, "NOBUILD": "1"})
            objects = self.build / "toybox" / f"objects-{applet}"
            shutil.rmtree(objects, ignore_errors=True)
            names = [*sorted((source / "lib").glob("*.c")), source / "main.c",
                     *sorted((source / "toys").glob(f"*/{applet}.c"))]
            jobs = [(c, objects / (c.parent.name + "_" + c.stem + ".o"),
                     (*TOYBOX_FLAGS, f"-I{source}", "-include", "stafeto_toybox.h",
                      f"-Dmain=ready_{applet}_main"), source)
                    for c in names]
            self.compile_all(jobs)
            o = self.build / "toybox" / f"{applet}.o"
            self.single(applet, [j[1] for j in jobs], [], o)
            out.append(o)
        return out

    def ncompress(self) -> list[Path]:
        source = fetch(self.work, "ncompress")
        out = []
        for applet in NCOMPRESS_APPLETS:
            o = self.build / "ncompress" / f"{applet}.o"
            raw = self.build / "ncompress" / f"{applet}.raw.o"
            self.compile(source / "compress.c", raw, *NCOMPRESS_DEFINES, f"-Dmain=ready_{applet}_main")
            self.single(applet, [raw], [], o)
            out.append(o)
        return out


def build(work: Path, archive: Path, flags: list[str], include: Path, stamp_extra: str) -> None:
    """The archive of the ready-made utilities' objects at `archive`; `flags`
    are the compiler flags BusyBox's objects get (the processor's errata, the
    unwind tables), `include` relibc's headers."""
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    headers = sorted([*COMPAT.rglob("*.h"), *BUSYBOX_COMPAT.rglob("*.h")])
    compat = sha256(b"".join(path.read_bytes() for path in headers)).hexdigest()
    pins = " ".join(f"{name} {SOURCES[name][1]}" for name in SOURCES)
    stamp = work / "stamp"
    text = f"{pins} {script} {compat} {' '.join(flags)} {stamp_extra}\n"
    if stamp.exists() and stamp.read_text() == text and archive.exists():
        print(f"ready-made utilities ready: {archive}")
        return
    shutil.rmtree(work / "build", ignore_errors=True)
    (work / "build").mkdir(parents=True)
    clang = tool("clang", "llvm")
    builder = Build(work, flags, clang, tool("ld.lld", "lld"), tool("llvm-ar", "llvm"),
                    tool("llvm-objcopy", "llvm"), include)
    builder.log.write_text("")
    objects = builder.sbase() + builder.toybox() + builder.ncompress()
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.unlink(missing_ok=True)
    builder.run(builder.ar, "rcs", archive, *objects)
    # What the image says of the programs: where each comes from, its exact
    # archive, its licence and the file that holds it (cargo xtask reads it).
    lines = []
    for name, path in licence_files(work).items():
        if not path.exists():
            raise SystemExit(f"{name} has no {path.name}")
        url, digest, _, spdx = SOURCES[name]
        applets = {"sbase": SBASE_APPLETS, "toybox": TOYBOX_APPLETS,
                   "ncompress": NCOMPRESS_APPLETS}[name]
        lines.append("\t".join((name, url, digest, spdx, str(path.relative_to(work)),
                               " ".join(applets))))
    (work / "manifest").write_text("\n".join(lines) + "\n")
    (work / "notices").write_text(notices(work / "build" / "sbase" / "source"))
    stamp.write_text(text)
    print(f"ready-made utilities ready: {archive}")
