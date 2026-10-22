#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build the ready-made utilities that BusyBox lacks (Ф10b, Ф10c) from their own
sources, unchanged, against relibc's headers: getconf, join and pathchk from
sbase (MIT), file and iconv from toybox (0BSD), compress from ncompress
(public domain), csplit, gencat, m4 and write from chimerautils (BSD), pr
from nbase (BSD), pax from paxmirabilis (BSD, MirOS) with the fts of musl-fts
(BSD), newgrp from util-linux (GPL-2.0-or-later) and tput and tabs from
ncurses (MIT).

Each program's `main` is renamed `ready_<applet>_main` (-Dmain=) and its objects are
linked into one relocatable object that exports that function alone, so the
names of the program's own helpers cannot meet BusyBox's. The objects go into
one archive that the BusyBox image links; BusyBox names the applets
(tools/busybox/stafeto/miscutils/stafeto_ready.c). What the programs ask of
the C library comes from relibc; the Linux headers it lacks are declared in
tools/ready-utils/compat (prototypes and constants, no code); the
configuration headers `configure` would write for a source are in
tools/ready-utils/config/<source>."""

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import bz2
import importlib.util
import gzip
import lzma
from pathlib import Path
import io
import os
import re
import shutil
import subprocess
import tarfile
from urllib.request import urlopen

import pkgdesc


ROOT = Path(__file__).resolve().parents[1]
COMPAT = ROOT / "tools" / "ready-utils" / "compat"
# The headers `configure` writes for a source, kept by source.
CONFIG = ROOT / "tools" / "ready-utils" / "config"
# The headers of BusyBox's build that relibc lacks (byteswap.h among them),
# searched after relibc's own, as are those of COMPAT: a header relibc gets
# later takes their place.
BUSYBOX_COMPAT = ROOT / "tools" / "busybox" / "compat"

# name: (archive URL, SHA-256 of the archive after decompression (the tar
# stream, which a server may compress differently), the licence file (empty
# where the source has none: the notices of its files stand for it), its SPDX
# identifier), from the descriptions in packages/
SOURCES = {
    name: (d["url"], d["sha256"], d.get("license_file", ""), d["license"])
    for name, d in ((n, pkgdesc.load(n)) for n in (
        "sbase", "toybox", "ncompress", "chimerautils", "nbase", "paxmirabilis",
        "musl-fts", "util-linux"))
}
# ncurses is built by tools/build-ncurses.py; its description gives the
# licence and the pin of its archive (the archive itself, as that script
# checks it).
NCURSES = pkgdesc.load("ncurses")
# The applets: the program they come from and the name of its main.
SBASE_APPLETS = ("getconf", "join", "pathchk")
TOYBOX_APPLETS = ("file", "iconv")
NCOMPRESS_APPLETS = ("compress",)
# chimerautils (FreeBSD's programs on other C libraries): each applet and the
# files of src.freebsd it is made of; m4's parser and tokenizer are generated.
CHIMERA_PROGRAMS = {
    "csplit": ("coreutils/csplit/csplit.c",),
    "gencat": ("gencat/gencat.c",),
    "m4": ("m4/eval.c", "m4/expr.c", "m4/look.c", "m4/main.c", "m4/misc.c",
           "m4/gnum4.c", "m4/trace.c"),
    "write": ("miscutils/write/write.c",),
}
# What these programs call that relibc lacks (chimerautils' libcompat).
CHIMERA_COMPAT = ("src.freebsd/compat/ohash.c", "src.compat/strtonum.c",
                  "src.compat/reallocf.c")
NBASE_APPLETS = ("pr",)
PAX_APPLETS = ("pax",)
UTIL_LINUX_APPLETS = ("newgrp",)
NCURSES_APPLETS = ("tput", "tabs")
APPLETS = (SBASE_APPLETS + TOYBOX_APPLETS + NCOMPRESS_APPLETS + tuple(CHIMERA_PROGRAMS)
           + NBASE_APPLETS + PAX_APPLETS + UTIL_LINUX_APPLETS + NCURSES_APPLETS)
# The sources of paxmirabilis, and what its Build.sh would have found out
# about relibc. The program calls fts (musl-fts) and the utmp names of
# <utmpx.h>.
PAX_SOURCES = ("ar.c", "ar_io.c", "ar_subs.c", "buf_subs.c", "cache.c", "compat.c",
               "cpio.c", "file_subs.c", "ftree.c", "gen_subs.c", "getoldopt.c",
               "options.c", "pat_rep.c", "pax.c", "sel_subs.c", "tables.c", "tar.c",
               "tty_subs.c", "reallocarray.c", "strmode.c", "strtonum.c")
PAX_DEFINES = (
    "-DHAVE_STRINGS_H=1", "-DHAVE_SYS_MTIO_H=0", "-DHAVE_TIME_H=1", "-DHAVE_SYS_TIME_H=1",
    "-DHAVE_BOTH_TIME_H=1", "-DHAVE_GRP_H=1", "-DHAVE_ST_MTIMENSEC=0", "-DHAVE_FUTIMENS=1",
    "-DHAVE_UTIMENSAT=1", "-DHAVE_STRLCPY=0", "-DHAVE_STRLCAT=0", "-DHAVE_STRTONUM=0",
    "-DHAVE_STRMODE=0", "-DHAVE_REALLOCARRAY=0", "-DHAVE_PATHS_H=1", "-DHAVE_STDINT_H=1",
    "-DHAVE_SYS_SYSMACROS_H=1", "-DHAVE_SYS_RESOURCE_H=1", "-DHAVE_UTIME_H=1",
    "-DHAVE_LINKAT=1", "-DHAVE_FCHOWNAT=1", "-DHAVE_FCHMODAT=1", "-DHAVE_LCHOWN=1",
    "-DHAVE_DPRINTF=1", "-DHAVE_PLEDGE=0", "-DHAVE_SETPGENT=0", "-DHAVE_UG_FROM_UGID=0",
    "-DHAVE_UGID_FROM_UG=0", "-DHAVE_VIS_H=0", "-DHAVE_UTMPX_H=0", "-DHAVE_UTMP_H=0",
    "-DHAVE_UTIMES=1", "-DHAVE_FUTIMES=0", "-DHAVE_LUTIMES=0", "-DHAVE_LCHMOD=0",
    "-DHAVE_OFFT_LONG=1", "-DHAVE_TIMET_LONG=1", "-DHAVE_TIMET_LARGE=1",
    "-DHAVE_CAN_INTTYPES=1", "-DHAVE_CAN_ULONG=1", "-DHAVE_CAN_UCBINTS=1",
    "-DHAVE_ATTRIBUTE_USED=1", "-DHAVE_ATTRIBUTE_UNUSED=1", "-DHAVE_ATTRIBUTE_PURE=1",
    "-DHAVE_ATTRIBUTE_NORETURN=1", "-DHAVE_ATTRIBUTE_NONNULL=1",
    "-DHAVE_ATTRIBUTE_FORMAT=1", "-DHAVE_ATTRIBUTE_BOUNDED=0",
    "-DMKSH_DONT_EMIT_IDSTRING", "-DUT_NAMESIZE=32", "-D_PATH_TMP=\"/tmp/\"",
    "-DMBSDPORT_H=\"compat.h\"",
)
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


def host_tool(name: str) -> Path:
    """A program that runs on this machine (the generators of m4's parser)."""
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing {name}; install it (bison and flex come with macOS and apt)")
    return Path(found).absolute()


def licence_files(work: Path) -> dict[str, Path | None]:
    """The licence file of each program's source, by program (None where the
    source has none)."""
    return {name: (next((work / "build" / name).glob("source*")) / SOURCES[name][2]
                   if SOURCES[name][2] else None)
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


def file_notices(name: str, root: Path, paths: list[Path]) -> str:
    """The copyright and terms in the comments at the start of `paths` (files
    of the source `name` under `root`), each distinct text once, with the
    files that carry it. A file without a notice is an error."""
    blocks: dict[str, tuple[str, list[str]]] = {}
    for path in sorted(set(paths)):
        text = path.read_text(errors="replace")[:12000]
        found = [b for b in re.findall(r"/\*.*?\*/", text, re.S)
                 if re.search(r"copyright|\(c\)|©|public domain", b, re.I)
                 and re.search(r"permission|redistribution|provided that|licen[cs]e|public domain",
                               b, re.I)]
        if not found:
            raise SystemExit(f"{name} {path.relative_to(root)} has no notice at its start")
        for block in found:
            # The line of the version control system is no part of the terms.
            key = re.sub(r"\s+", " ", re.sub(r"\$[A-Za-z]+:[^$]*\$", "", block))
            blocks.setdefault(key, (block, []))[1].append(str(path.relative_to(root)))
    return "".join(f"==== {name} {', '.join(files)} ====\n\n{block}\n\n"
                   for block, files in blocks.values())


def unpack(archive: bytes, url: str) -> bytes:
    """The tar stream of an archive, by the extension of its URL."""
    if url.endswith((".gz", ".tgz")):
        return gzip.decompress(archive)
    if url.endswith(".xz"):
        return lzma.decompress(archive)
    if url.endswith(".bz2"):
        return bz2.decompress(archive)
    raise SystemExit(f"{url} is none of .gz, .tgz, .xz, .bz2")


def fetch(work: Path, name: str, suffix: str = "") -> Path:
    """The source of `name` (`suffix` for another copy of it) under `work`,
    from the pinned archive."""
    url, expected, _, _ = SOURCES[name]
    directory = work / "build" / name
    archive = work / "downloads" / f"{name}{Path(url).suffix}"
    source = directory / ("source" + suffix)
    if source.exists():
        return source
    directory.mkdir(parents=True, exist_ok=True)
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        with urlopen(url) as response:
            archive.write_bytes(response.read())
    tar = unpack(archive.read_bytes(), url)
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
        # The text of the notices in the files of the sources built here
        # (UTILITIES-LICENSE carries it).
        self.notice_text = ""

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

    def chimerautils(self) -> list[Path]:
        source = fetch(self.work, "chimerautils")
        freebsd = source / "src.freebsd"
        generated = self.build / "chimerautils" / "generated"
        objects = self.build / "chimerautils" / "objects"
        generated.mkdir(parents=True, exist_ok=True)
        # m4's parser and tokenizer, from its grammar and its scanner.
        self.run(host_tool("bison"), f"--defines={generated / 'parser.h'}", "-o",
                 generated / "parser.c", freebsd / "m4" / "parser.y")
        self.run(host_tool("flex"), "-o", generated / "tokenizer.c", freebsd / "m4" / "tokenizer.l")
        base = ("-D_GNU_SOURCE", "-D_FILE_OFFSET_BITS=64", "-Dlint",
                f"-I{CONFIG / 'chimerautils'}", f"-I{source / 'include'}",
                f"-I{freebsd / 'include'}", "-include", str(COMPAT / "stafeto_bsd.h"))
        jobs, units, noticed = [], {}, []
        for applet, files in CHIMERA_PROGRAMS.items():
            extra = (*base, f'-Dgetprogname()="{applet}"', f"-Dmain=ready_{applet}_main",
                     f"-I{(freebsd / files[0]).parent}")
            if applet == "m4":
                extra += ("-DEXTENDED", f"-I{generated}")
            if applet == "write":
                extra += ("-include", str(COMPAT / "stafeto_write.h"))
            members = []
            for name in files:
                c = freebsd / name
                o = objects / applet / (c.stem + ".o")
                jobs.append((c, o, extra, None))
                members.append(o)
                noticed.append(c)
            if applet == "m4":
                for c in (generated / "parser.c", generated / "tokenizer.c"):
                    o = objects / applet / (c.stem + ".o")
                    jobs.append((c, o, extra, None))
                    members.append(o)
                noticed += [freebsd / "m4" / "parser.y", freebsd / "m4" / "tokenizer.l"]
            units[applet] = members
        compat = []
        for name in CHIMERA_COMPAT:
            c = source / name
            o = objects / "compat" / (c.stem + ".o")
            jobs.append((c, o, base, None))
            compat.append(o)
        self.compile_all(jobs)
        library = self.build / "chimerautils" / "libcompat.a"
        library.unlink(missing_ok=True)
        self.run(self.ar, "rcs", library, *compat)
        out = []
        for applet, members in units.items():
            o = self.build / "chimerautils" / f"{applet}.o"
            self.single(applet, members, [library], o)
            out.append(o)
        # The compat files that carry a notice (the others are the project's
        # own and under its LICENSE).
        noticed.append(source / "src.freebsd/compat/ohash.c")
        self.notice_text += file_notices("chimerautils", source, noticed)
        return out

    def nbase(self) -> list[Path]:
        source = fetch(self.work, "nbase")
        extra = ("-D_GNU_SOURCE", "-D_FILE_OFFSET_BITS=64", f"-I{CONFIG / 'nbase'}",
                 f"-I{source / 'pr'}", "-include", str(COMPAT / "stafeto_bsd.h"),
                 "-Dmain=ready_pr_main")
        files = [source / "pr" / "pr.c", source / "pr" / "egetopt.c"]
        objects = [self.build / "nbase" / "objects" / (c.stem + ".o") for c in files]
        self.compile_all([(c, o, extra, None) for c, o in zip(files, objects)])
        o = self.build / "nbase" / "pr.o"
        self.single("pr", objects, [], o)
        self.notice_text += file_notices("nbase", source, files)
        return [o]

    def pax(self) -> list[Path]:
        source = fetch(self.work, "paxmirabilis")
        fts = fetch(self.work, "musl-fts")
        objects = self.build / "paxmirabilis" / "objects"
        extra = ("-D_GNU_SOURCE", "-D_FILE_OFFSET_BITS=64", f"-I{source}",
                 f"-I{fts}", *PAX_DEFINES, "-Dmain=ready_pax_main")
        files = [source / name for name in PAX_SOURCES]
        jobs = [(c, objects / (c.stem + ".o"), extra, None) for c in files]
        fts_object = objects / "fts.o"
        jobs.append((fts / "fts.c", fts_object, (f"-I{CONFIG / 'musl-fts'}", f"-I{fts}",
                                                  "-D_GNU_SOURCE"), None))
        self.compile_all(jobs)
        o = self.build / "paxmirabilis" / "pax.o"
        self.single("pax", [j[1] for j in jobs], [], o)
        # compat.h and the .linked files carry the terms of the files that
        # have no comment of their own.
        noticed = [*files, source / "compat.h", source / ".linked" / "strlfun.inc",
                   source / ".linked" / "mbsdcc.h"]
        self.notice_text += file_notices("paxmirabilis", source, noticed)
        self.notice_text += file_notices("musl-fts", fts, [fts / "fts.c"])
        return [o]

    def util_linux(self) -> list[Path]:
        source = fetch(self.work, "util-linux")
        raw = self.build / "util-linux" / "newgrp.raw.o"
        self.compile(source / "login-utils" / "newgrp.c", raw, "-D_GNU_SOURCE", "-include",
                     str(CONFIG / "util-linux" / "config.h"), f"-I{source / 'include'}",
                     "-D_PATH_BSHELL=\"/bin/sh\"", "-Dmain=ready_newgrp_main")
        o = self.build / "util-linux" / "newgrp.o"
        self.single("newgrp", [raw], [], o)
        return [o]

    def ncurses(self, ncurses) -> list[Path]:
        """tput and tabs of the ncurses `build-ncurses.py` built (`ncurses`
        is that script as a module): their sources of progs/, the library and
        its configured headers."""
        source = ncurses.WORK / f"ncurses-{ncurses.VERSION}"
        library = ncurses.INSTALL / "lib" / "libncursesw.a"
        generated = self.build / "ncurses" / "generated"
        objects = self.build / "ncurses" / "objects"
        generated.mkdir(parents=True, exist_ok=True)
        shutil.copy(CONFIG / "ncurses" / "transform.h", generated / "transform.h")
        extra = ("-D_GNU_SOURCE", "-DHAVE_CONFIG_H", f"-I{generated}",
                 f"-I{ncurses.WORK / 'build' / 'include'}", f"-I{source / 'progs'}",
                 f"-I{source / 'include'}", f"-I{source / 'ncurses'}",
                 f"-I{ncurses.WORK / 'build' / 'ncurses'}")
        progs = source / "progs"
        shared = ("tparm_type", "tty_settings")
        units = {"tput": ("tput", *shared, "transform", "reset_cmd", "clear_cmd"),
                 "tabs": ("tabs", *shared)}
        jobs, members = [], {}
        for applet, names in units.items():
            members[applet] = []
            for name in names:
                o = objects / applet / f"{name}.o"
                flags = (*extra, f"-Dmain=ready_{applet}_main") if name == applet else extra
                jobs.append((progs / f"{name}.c", o, flags, None))
                members[applet].append(o)
        self.compile_all(jobs)
        out = []
        for applet in units:
            o = self.build / "ncurses" / f"{applet}.o"
            self.single(applet, members[applet], [library], o)
            out.append(o)
        return out


def load_ncurses():
    """tools/build-ncurses.py as a module."""
    spec = importlib.util.spec_from_file_location(
        "build_ncurses", ROOT / "tools" / "build-ncurses.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build(work: Path, archive: Path, flags: list[str], include: Path, stamp_extra: str) -> None:
    """The archive of the ready-made utilities' objects at `archive`; `flags`
    are the compiler flags BusyBox's objects get (the processor's errata, the
    unwind tables), `include` relibc's headers."""
    # tput and tabs link the ncurses of the shell image.
    ncurses = load_ncurses()
    ncurses.main()
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    headers = sorted([*COMPAT.rglob("*"), *CONFIG.rglob("*"), *BUSYBOX_COMPAT.rglob("*")])
    compat = sha256(b"".join(path.read_bytes() for path in headers if path.is_file())).hexdigest()
    pins = " ".join(f"{name} {SOURCES[name][1]}" for name in SOURCES)
    ncurses_stamp = (ncurses.WORK / "stamp").read_text().strip()
    stamp = work / "stamp"
    text = f"{pins} {script} {compat} {' '.join(flags)} {stamp_extra} {ncurses_stamp}\n"
    if stamp.exists() and stamp.read_text() == text and archive.exists():
        print(f"ready-made utilities ready: {archive}")
        return
    shutil.rmtree(work / "build", ignore_errors=True)
    (work / "build").mkdir(parents=True)
    clang = tool("clang", "llvm")
    builder = Build(work, flags, clang, tool("ld.lld", "lld"), tool("llvm-ar", "llvm"),
                    tool("llvm-objcopy", "llvm"), include)
    builder.log.write_text("")
    objects = (builder.sbase() + builder.toybox() + builder.ncompress()
               + builder.chimerautils() + builder.nbase() + builder.pax()
               + builder.util_linux() + builder.ncurses(ncurses))
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.unlink(missing_ok=True)
    builder.run(builder.ar, "rcs", archive, *objects)
    # What the image says of the programs: where each comes from, its exact
    # archive, its licence and the file that holds it (cargo xtask reads it).
    # An empty licence file is `-`: the notices in the files stand for it.
    applets = {"sbase": SBASE_APPLETS, "toybox": TOYBOX_APPLETS,
               "ncompress": NCOMPRESS_APPLETS, "chimerautils": tuple(CHIMERA_PROGRAMS),
               "nbase": NBASE_APPLETS, "paxmirabilis": PAX_APPLETS,
               "musl-fts": ("fts of pax",), "util-linux": UTIL_LINUX_APPLETS}
    lines = []
    for name, path in licence_files(work).items():
        if path is not None and not path.exists():
            raise SystemExit(f"{name} has no {path.name}")
        url, digest, _, spdx = SOURCES[name]
        lines.append("\t".join((name, url, digest, spdx,
                               str(path.relative_to(work)) if path else "-",
                               " ".join(applets[name]), "the unpacked tar stream")))
    ncurses_licence = ncurses.WORK / f"ncurses-{ncurses.VERSION}" / NCURSES["license_file"]
    lines.append("\t".join(("ncurses", NCURSES["url"], NCURSES["sha256"], NCURSES["license"],
                           os.path.relpath(ncurses_licence, work),
                           " ".join(NCURSES_APPLETS), "the archive")))
    (work / "manifest").write_text("\n".join(lines) + "\n")
    (work / "notices").write_text(notices(work / "build" / "sbase" / "source")
                                  + builder.notice_text)
    stamp.write_text(text)
    print(f"ready-made utilities ready: {archive}")
