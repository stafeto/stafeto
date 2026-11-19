#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build FreeType for programs that draw text (the LVGL demo of stage G4)
from its pinned source archive, unchanged, as one static library.

The build is the one FreeType's documentation calls the single-object way:
FT2_BUILD_LIBRARY with a handful of the unity files of the source tree, the
configuration of ports/freetype (ftoption.h, ftmodule.h) as the only
configuration, against relibc's headers and the Linux AArch64 C ABI they
describe. The TrueType driver with its byte-code interpreter, the sfnt
container and the smooth rasterizer are the only modules; the files are
src/base/{ftbase,ftinit,ftsystem,ftdebug,ftglyph,ftbitmap,ftmm,ftsynth}.c,
src/sfnt/sfnt.c, src/truetype/truetype.c and src/smooth/smooth.c.

The result is target/freetype/libfreetype.a, the headers in
target/freetype/include (the source's own with the two configuration files
replaced, so a program that includes them sees the settings of the library)
and target/freetype/FTL.TXT, the licence text the notices of the package
carry. `--host` builds the same files with the compiler of the host into
target/freetype/host/ (the sample that compares the host's pixels with the
guest's links it).

FreeType is under the FreeType Licence (FTL): the archive is fetched at build
time with its SHA-256 checked, as the other C ports are.

Checks after the build, each stopping it with the names it found:
  - the archive's SHA-256 is the one of packages/freetype.toml;
  - the names the objects leave undefined are all in the list below (the
    functions of relibc the library calls) and relibc's libc.a defines each of
    them, and none is one of the names the
    library must never call (the environment, threads, the dynamic loader,
    the memory mapper, floating point from libm);
  - `getenv` appears in no object, no object calls `FT_Property_Set` from
    outside the file that defines it (ftobjs.c defines it in every build, as
    part of the public interface, so the name itself cannot be absent), and
    the text of the environment variable `FREETYPE_PROPERTIES` is in none:
    no property can change what a glyph looks like at run time."""

from hashlib import sha256
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tarfile
from urllib.request import urlopen

import pkgdesc


PACKAGE = pkgdesc.load("freetype")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
URL = PACKAGE["url"]
ROOT = Path(__file__).resolve().parents[1]
HOST = "--host" in sys.argv[1:]
WORK = ROOT / "target" / "freetype"
BUILD = WORK / "host" if HOST else WORK
# The directory of the configuration files; the test of the planted faults
# points it at a changed copy.
PORT_DIR = Path(os.environ.get("STAFETO_FREETYPE_PORT_DIR", ROOT / "ports" / "freetype"))
CACHE = ROOT / "target" / "freetype-src"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
OUTPUT = BUILD / "libfreetype.a"
SOURCES = [
    "src/base/ftbase.c", "src/base/ftinit.c", "src/base/ftsystem.c",
    "src/base/ftdebug.c", "src/base/ftglyph.c", "src/base/ftbitmap.c",
    "src/base/ftmm.c", "src/base/ftsynth.c", "src/sfnt/sfnt.c",
    "src/truetype/truetype.c", "src/smooth/smooth.c",
]
# Cortex-A53 erratum 835769 (the PinePhone's A64), as the other objects.
A53_ERRATA = "-mfix-cortex-a53-835769"
# Compiler-generated async unwind rows for C frames; no outlining.
UNWIND_CFLAGS = ("-fasynchronous-unwind-tables", "-mllvm", "-enable-machine-outliner=never")

# The names the library may leave undefined: the functions of the C library it
# calls with this configuration (the object files of one build leave exactly
# these) and the two helpers the stack protector asks of it. A name that is
# not here stops the build, so a path that would pull in strtol, strtod,
# calloc, snprintf or the like (the property strings, the debug memory)
# shows at once.
ALLOWED = {
    "fopen", "fread", "fseek", "ftell", "fclose", "malloc", "realloc", "free",
    "qsort", "setjmp", "longjmp", "memcpy", "memmove", "memset", "strcmp",
    "strlen", "strstr", "__stack_chk_fail", "__stack_chk_guard",
}
# The names the library must never reach.
FORBIDDEN = {"getenv", "secure_getenv", "mmap", "munmap", "dlopen", "dlsym", "dlclose"}
FORBIDDEN_PREFIXES = ("pthread_", "sem_", "thrd_", "mtx_")
# Floating-point functions of libm a glyph could pick up by accident.
FORBIDDEN_MATH = {
    "sin", "cos", "tan", "atan", "atan2", "sqrt", "pow", "exp", "log", "fabs",
    "floor", "ceil", "round", "trunc", "fmod", "hypot", "ldexp", "frexp", "modf",
    "sinf", "cosf", "tanf", "atanf", "atan2f", "sqrtf", "powf", "expf", "logf",
    "fabsf", "floorf", "ceilf", "roundf", "truncf", "fmodf", "hypotf",
}
# What no object may name, defined or not: the way to a run-time property.
ABSENT = ("getenv",)
# What no object may call. The library defines it (ftobjs.c) and keeps it as
# public interface; a call from another object is a way to a run-time property.
NOT_CALLED = ("FT_Property_Set",)
# The variable FT_CONFIG_OPTION_ENVIRONMENT_PROPERTIES makes ftinit.c read.
ENVIRONMENT_TEXT = b"FREETYPE_PROPERTIES"


def tool(name: str, brew_formula: str | None = None) -> Path:
    override = os.environ.get("STAFETO_C_TOOL_DIR")
    if override and (Path(override) / name).exists():
        return Path(override) / name
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


# The objects of the host build are Mach-O on macOS, where `nm` shows a C name
# with a leading underscore; ELF objects (the guest's, and the host's on
# Linux) show it as written.
MACHO = HOST and sys.platform == "darwin"


def symbol_names(listing: str) -> list[str]:
    """The names in the output of `llvm-nm --format=just-symbols` (one per
    line; the leading underscore of the C names of Mach-O is taken off)."""
    names = []
    for line in listing.splitlines():
        line = line.strip()
        if not line or line.endswith(":"):
            continue
        names.append(line[1:] if MACHO and line.startswith("_") else line)
    return names


def undefined_violations(names: list[str]) -> list[str]:
    """The names that may not stay undefined: the ones on the list of what
    the library never reaches, then those off the list of what it may."""
    bad = []
    for name in sorted(set(names)):
        if (name in FORBIDDEN or name in FORBIDDEN_MATH
                or name.startswith(FORBIDDEN_PREFIXES)):
            bad.append(f"{name} (a name the library never calls)")
        elif name in ALLOWED:
            continue
        else:
            bad.append(f"{name} (not in the list of the C library's functions it may call)")
    return bad


def absent_violations(names: list[str]) -> list[str]:
    """The names that no object may carry, defined or undefined."""
    return [f"{name} (the objects must not name it)"
            for name in ABSENT if name in set(names)]


def called_violations(undefined: list[str]) -> list[str]:
    """The names an object leaves undefined that no object may call."""
    return [f"{name} (called from outside its file)"
            for name in NOT_CALLED if name in set(undefined)]


def unresolved(undefined: list[str], provided: set[str]) -> list[str]:
    """The undefined names the C library does not define."""
    return [f"{name} (libc.a of relibc does not define it)"
            for name in sorted(set(undefined)) if name not in provided]


def nm(nm_tool: Path, *args) -> str:
    result = subprocess.run([str(nm_tool), "--format=just-symbols", *map(str, args)],
                            capture_output=True, text=True, check=True)
    return result.stdout


def check(log: Path, objects: list[Path], nm_tool: Path, lld: Path | None,
          libc: Path | None = None) -> list[str]:
    """The checks on the objects after the build; the list of what they found."""
    found = []
    every = []
    for obj in objects:
        every += symbol_names(nm(nm_tool, obj))
        found += called_violations(symbol_names(nm(nm_tool, "-u", obj)))
        if ENVIRONMENT_TEXT in obj.read_bytes():
            found.append(f"{ENVIRONMENT_TEXT.decode()} (the text is in {obj.name})")
    found += absent_violations(every)
    if lld is not None:
        # One relocatable link settles which names the objects answer for
        # each other; what stays undefined is what the C library must give.
        joined = BUILD / "joined.o"
        run(log, lld, "-r", "-o", joined, *objects)
        undefined = symbol_names(nm(nm_tool, "-u", joined))
        found += undefined_violations(undefined)
        if libc is not None:
            provided = set(symbol_names(nm(nm_tool, "-g", "--defined-only", libc)))
            found += unresolved(undefined, provided)
        print("freetype: undefined names: " + " ".join(sorted(set(undefined))))
        joined.unlink()
    else:
        found += [v for v in undefined_violations(
            [n for obj in objects for n in symbol_names(nm(nm_tool, "-u", obj))])
            if "never calls" in v]
    return found


def fetch() -> Path:
    """The source archive, from the cache or the network, with its SHA-256 checked."""
    CACHE.mkdir(parents=True, exist_ok=True)
    archive = CACHE / Path(URL).name
    if not archive.exists() or sha256(archive.read_bytes()).hexdigest() != SHA256:
        with urlopen(URL) as response:
            archive.write_bytes(response.read())
    if sha256(archive.read_bytes()).hexdigest() != SHA256:
        archive.unlink()
        raise SystemExit("the FreeType source archive has an unexpected SHA-256")
    return archive


def main() -> None:
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    port = sha256(b"".join(p.read_bytes() for p in sorted(PORT_DIR.rglob("*")) if p.is_file())).hexdigest()
    libc = RELIBC / "lib" / "libc.a"
    if not HOST and (not (RELIBC / "include" / "stdio.h").exists() or not libc.exists()):
        raise SystemExit("build relibc with cargo xtask relibc first")
    stamp = BUILD / "stamp"
    text = f"{VERSION} {SHA256} {script} {port}\n"
    if not HOST:
        text = text[:-1] + f" {sha256(libc.read_bytes()).hexdigest()}\n"
    if stamp.exists() and stamp.read_text() == text and OUTPUT.exists():
        print(f"freetype ready: {OUTPUT}")
        return
    archive = fetch()
    shutil.rmtree(BUILD, ignore_errors=True)
    BUILD.mkdir(parents=True)
    log = BUILD / "build.log"
    log.write_text("")
    with tarfile.open(archive) as members:
        members.extractall(BUILD, filter="data")
    source = BUILD / f"freetype-{VERSION}"
    clang, ar = tool("clang", "llvm"), tool("llvm-ar", "llvm")
    nm_tool, lld = tool("llvm-nm", "llvm"), tool("ld.lld", "lld")
    # -funsigned-char: the char of AArch64 Linux, on the host sample too;
    # -fwrapv: signed overflow wraps, as the 64-bit fixed-point code expects.
    flags = ["-O2", "-fwrapv", "-ffunction-sections", "-fdata-sections", "-DFT2_BUILD_LIBRARY",
             "-DFT_CONFIG_MODULES_H=<ftmodule.h>", "-DFT_CONFIG_OPTIONS_H=<ftoption.h>",
             f"-I{PORT_DIR}", f"-I{source / 'include'}"]
    if HOST:
        cc = (str(clang), "-fPIC", "-funsigned-char", *flags)
    else:
        cc = (str(clang), "--target=aarch64-linux-gnu", "-nostdinc",
              "-isystem", str(RELIBC / "include"), "-mno-outline-atomics",
              "-fstack-protector-strong", A53_ERRATA, "-fPIC", *UNWIND_CFLAGS, *flags)
    (BUILD / "obj").mkdir()
    objects = []
    for name in SOURCES:
        obj = BUILD / "obj" / (Path(name).stem + ".o")
        run(log, *cc, "-c", source / name, "-o", obj)
        objects.append(obj)
    found = check(log, objects, nm_tool, None if HOST else lld, None if HOST else libc)
    if found:
        raise SystemExit("freetype: " + "; ".join(found))
    OUTPUT.unlink(missing_ok=True)
    run(log, ar, "rcs", OUTPUT, *objects)
    # The headers: the source's own, with the settings of this build.
    include = BUILD / "include"
    shutil.copytree(source / "include", include)
    for name in ("ftoption.h", "ftmodule.h"):
        shutil.copy(PORT_DIR / name, include / "freetype" / "config" / name)
    shutil.copy(source / "docs" / PACKAGE["license_file"].split("/")[-1], BUILD / "FTL.TXT")
    stamp.write_text(text)
    print(f"freetype ready: {OUTPUT}")


if __name__ == "__main__":
    main()
