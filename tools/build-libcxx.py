#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build libc++, libc++abi and libunwind of the LLVM project for programs
written in C++ (`cargo xtask libcxx`): three static libraries for
aarch64-linux-gnu against the sysroot of relibc (target/relibc/sysroot,
`cargo xtask relibc`), from the pinned source archive of the release.

The archive is the release asset of packages/libcxx.toml (tag
llvmorg-23.1.6); it is fetched once into target/libcxx-src/, its SHA-256
checked, and only the directories the libraries need are unpacked: libcxx,
libcxxabi and libunwind without their tests and documents, and from libc the
header library `shared/` with what it includes (src/__support, hdr, include,
config), which libc++'s charconv takes its floating-point parser from. One
patch is applied to the unpacked tree (below); every other file is the
source's own.

The libraries are compiled one file at a time with the flags of LLVM's
CMake files for a static build with exceptions, run-time type information,
threads (pthread), localization and the file system library, and the time
zone database left out (it needs the tzdata files of a hosted system). CMake
is no part of the build: the list of the files is the one of
libcxx/src/CMakeLists.txt, libcxxabi/src/CMakeLists.txt and
libunwind/src/CMakeLists.txt for this configuration, the file
`__config_site` is filled from its template with the options below, and
`__assertion_handler` is the default one of libcxx/vendor/llvm. The
decisions that belong to stafeto:

  - the table of character classes: relibc does not define __GLIBC__, so the
    site file defines _LIBCPP_PROVIDES_DEFAULT_RUNE_TABLE and libc++ uses its
    own table (<ctype> then agrees with the C locale on every platform);
  - waits by address: libcxx/src/atomic.cpp calls syscall(SYS_futex, ...);
    ports/libcxx/include/linux/futex.h gives the two operations and the
    number, and relibc's syscall() answers them with the layer's futex;
  - exceptions: libunwind unwinds by .eh_frame_hdr through dl_iterate_phdr
    (relibc lists the program with AT_PHDR); `__stafeto__` is defined for the
    libraries, and the patch below turns the Linux signal-return check of
    libunwind off for it: that check reads memory through a raw
    rt_sigprocmask call and decodes the Linux return trampoline, neither of
    which exists here;
  - the destructors of thread-local objects go to relibc's
    __cxa_thread_atexit_impl (HAVE___CXA_THREAD_ATEXIT_IMPL).

The result is target/libcxx/: include/c++/v1 (the headers of libc++, the
site file, the assertion handler, cxxabi.h) and lib/libc++.a, libc++abi.a,
libunwind.a, and LICENSE.TXT (the three licence files, Apache-2.0 with the
LLVM exception). Checks after the build: the names the objects leave
undefined are defined by the libraries themselves or by relibc's libc.a and
libm.a, and no object holds the path of the build directory.

`--check` prints the stamp the build would write and exits."""

from hashlib import sha256
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys
import tarfile
from urllib.request import urlopen

import pkgdesc


PACKAGE = pkgdesc.load("libcxx")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
URL = PACKAGE["url"]
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "libcxx"
CACHE = ROOT / "target" / "libcxx-src"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
PORT = ROOT / "ports" / "libcxx"
TOP = f"llvm-project-{VERSION}.src"
# What of the archive is unpacked: a directory is taken whole except the
# subdirectories under SKIP; a path with a file name is that file.
TAKE = [
    "libcxx/include", "libcxx/src", "libcxx/vendor", "libcxx/LICENSE.TXT",
    "libcxxabi/include", "libcxxabi/src", "libcxxabi/LICENSE.TXT",
    "libunwind/include", "libunwind/src", "libunwind/LICENSE.TXT",
    "libc/shared", "libc/hdr", "libc/include", "libc/config", "libc/LICENSE.TXT",
    "libc/src/__support",
]
# Cortex-A53 erratum 835769 (the PinePhone's A64), as the other objects; no
# outlined atomics (libgcc's helpers are not in the sysroot); the compiler's
# unwind rows for C frames; no machine outlining, which drops unwind rows.
TARGET_FLAGS = ("--target=aarch64-linux-gnu", "-mfix-cortex-a53-835769",
                "-mno-outline-atomics", "-fno-pic", "-fasynchronous-unwind-tables",
                "-mllvm", "-enable-machine-outliner=never", "-O2", "-w")
# The options of the template of the site file (libcxx/include/__config_site.in).
SITE = {
    "_LIBCPP_ABI_VERSION": "1",
    "_LIBCPP_ABI_NAMESPACE": "__1",
    "_LIBCPP_ABI_FORCE_ITANIUM": 0,
    "_LIBCPP_ABI_FORCE_MICROSOFT": 0,
    "_LIBCPP_HAS_THREADS": 1,
    "_LIBCPP_HAS_MONOTONIC_CLOCK": 1,
    "_LIBCPP_HAS_MUSL_LIBC": 0,
    "_LIBCPP_HAS_THREAD_API_PTHREAD": 1,
    "_LIBCPP_HAS_THREAD_API_EXTERNAL": 0,
    "_LIBCPP_HAS_THREAD_API_WIN32": 0,
    "_LIBCPP_HAS_THREAD_API_C11": 0,
    "_LIBCPP_HAS_VENDOR_AVAILABILITY_ANNOTATIONS": 0,
    "_LIBCPP_HAS_FILESYSTEM": 1,
    "_LIBCPP_HAS_RANDOM_DEVICE": 1,
    "_LIBCPP_HAS_LOCALIZATION": 1,
    "_LIBCPP_HAS_UNICODE": 1,
    "_LIBCPP_HAS_WIDE_CHARACTERS": 1,
    "_LIBCPP_HAS_TIME_ZONE_DATABASE": 0,
    "_LIBCPP_INSTRUMENTED_WITH_ASAN": 0,
    "_LIBCPP_PSTL_BACKEND_SERIAL": "",
    "_LIBCPP_HARDENING_MODE_DEFAULT": "_LIBCPP_HARDENING_MODE_NONE",
    "_LIBCPP_ASSERTION_SEMANTIC_DEFAULT": "_LIBCPP_ASSERTION_SEMANTIC_IGNORE",
    "_LIBCPP_LIBC_PICOLIBC": 0,
    "_LIBCPP_LIBC_NEWLIB": 0,
    "_LIBCPP_LIBC_LLVM_LIBC": 0,
    "_LIBCPP_ABI_DEFINES": "",
    "_LIBCPP_EXTRA_SITE_DEFINES": "#define _LIBCPP_PROVIDES_DEFAULT_RUNE_TABLE",
}
# libc++'s own files for this configuration (libcxx/src/CMakeLists.txt; the
# experimental library, the time zone database, the platform files of
# other systems and the parallel algorithms' backends are not in it).
LIBCXX = [
    "algorithm", "any", "atomic", "barrier", "bind", "call_once", "charconv",
    "chrono", "condition_variable", "condition_variable_destructor",
    "error_category", "exception", "expected",
    "filesystem/directory_entry", "filesystem/directory_iterator",
    "filesystem/filesystem_clock", "filesystem/filesystem_error",
    "filesystem/int128_builtins", "filesystem/operations", "filesystem/path",
    "fstream", "functional", "future", "hash", "ios", "ios.instantiations",
    "iostream", "locale", "memory", "memory_resource", "mutex",
    "mutex_destructor", "new", "new_handler", "new_helpers", "optional",
    "ostream", "print", "random", "random_shuffle", "regex", "ryu/d2fixed",
    "ryu/d2s", "ryu/f2s", "shared_mutex", "stdexcept", "string", "strstream",
    "system_error", "text_encoding", "thread", "typeinfo", "valarray",
    "variant", "vector", "verbose_abort",
]
LIBCXXABI = [
    "abort_message", "cxa_aux_runtime", "cxa_default_handlers", "cxa_demangle",
    "cxa_exception", "cxa_exception_storage", "cxa_guard", "cxa_handlers",
    "cxa_noexception", "cxa_personality", "cxa_thread_atexit", "cxa_vector",
    "cxa_virtual", "fallback_malloc", "private_typeinfo", "stdlib_exception",
    "stdlib_new_delete", "stdlib_stdexcept", "stdlib_typeinfo",
]
LIBUNWIND_CXX = ["libunwind.cpp"]
LIBUNWIND_C = ["UnwindLevel1.c", "UnwindLevel1-gcc-ext.c"]
LIBUNWIND_ASM = ["UnwindRegistersRestore.S", "UnwindRegistersSave.S"]
# The patch of libunwind: its check of the Linux return trampoline is off for
# `__stafeto__` (libunwind/src/UnwindCursor.hpp).
UNWIND_FILE = "libunwind/src/UnwindCursor.hpp"
UNWIND_OLD = "#if defined(_LIBUNWIND_TARGET_LINUX) &&"
UNWIND_NEW = "#if !defined(__stafeto__) && defined(_LIBUNWIND_TARGET_LINUX) &&"
# Names the objects may leave undefined besides the C library's: none.
UNDEFINED_OK: set[str] = set()


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


def site_file(template: str, options: dict = SITE) -> str:
    """`__config_site` from its template: `#cmakedefine01 X` is `#define X 1`
    or 0, `#cmakedefine X @X@` a define when the option is set and a comment
    when not, and `@X@` the option's text."""
    def define01(match: re.Match) -> str:
        return f"#define {match[1]} {1 if options.get(match[1]) else 0}"

    def define(match: re.Match) -> str:
        name = match[1]
        if name not in options:
            return f"/* #undef {name} */"
        value = options[name]
        return f"#define {name} {value}".rstrip()

    text = re.sub(r"#cmakedefine01 (\w+)", define01, template)
    text = re.sub(r"#cmakedefine (\w+)[^\n]*", define, text)
    text = re.sub(r"@(\w+)@", lambda m: str(options.get(m[1], "")), text)
    left = re.findall(r"@\w+@|#cmakedefine", text)
    if left:
        raise SystemExit(f"the site file has unfilled options: {left}")
    return text


def patch_unwind(text: str) -> str:
    """UnwindCursor.hpp with the Linux return-trampoline check off for
    `__stafeto__`; the text must hold the line to change exactly once."""
    if text.count(UNWIND_OLD) != 1:
        raise SystemExit(f"{UNWIND_FILE}: the line to patch is not there exactly once")
    return text.replace(UNWIND_OLD, UNWIND_NEW)


def wanted(name: str) -> bool:
    """Whether the archive member `name` (below the top directory) is one of
    the directories or files of TAKE and not a test or a document."""
    return any(name == item or name.startswith(item + "/") for item in TAKE)


def stamp_text(script: bytes, port: bytes, relibc_stamp: str) -> str:
    return (f"{VERSION} {SHA256} {sha256(script).hexdigest()} {sha256(port).hexdigest()}"
            f" {relibc_stamp}\n")


def port_bytes() -> bytes:
    return b"".join(p.read_bytes() for p in sorted(PORT.rglob("*")) if p.is_file())


def relibc_stamp() -> str:
    path = ROOT / "target" / "relibc" / "stamp"
    if not (RELIBC / "lib" / "libc.a").exists() or not path.exists():
        raise SystemExit("build relibc first: cargo xtask relibc")
    return sha256(path.read_bytes()).hexdigest()


def fetch() -> Path:
    """The archive in the cache, with its SHA-256 checked."""
    CACHE.mkdir(parents=True, exist_ok=True)
    archive = CACHE / f"llvm-project-{VERSION}.src.tar.xz"
    if not archive.exists() or sha256(archive.read_bytes()).hexdigest() != SHA256:
        part = archive.with_suffix(".part")
        with urlopen(URL) as response, part.open("wb") as out:
            shutil.copyfileobj(response, out)
        if sha256(part.read_bytes()).hexdigest() != SHA256:
            part.unlink()
            raise SystemExit("the LLVM source archive has an unexpected SHA-256")
        part.replace(archive)
    return archive


def unpack(archive: Path, destination: Path) -> None:
    """The wanted directories of the archive under `destination`, read in
    one pass."""
    with tarfile.open(archive, "r|xz") as members:
        for member in members:
            name = member.name.split("/", 1)[1] if "/" in member.name else ""
            if member.name.split("/", 1)[0] != TOP or not wanted(name):
                continue
            member.name = name
            members.extract(member, destination, filter="data")


def objects_of(compiler_args: list[str], sources: list[tuple[Path, Path]], log: Path) -> list[Path]:
    """Compiles each (source, object) pair, several at a time."""
    def one(pair: tuple[Path, Path]) -> Path:
        source, obj = pair
        obj.parent.mkdir(parents=True, exist_ok=True)
        run(log, *compiler_args, "-c", source, "-o", obj)
        return obj
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        return list(pool.map(one, sources))


def parse_nm(listing: str) -> tuple[set[str], set[str]]:
    """The names defined and the names left undefined in the output of
    `llvm-nm --format=posix` (one line per symbol: name, type, ...)."""
    defined: set[str] = set()
    undefined: set[str] = set()
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) < 2 or line.endswith(":"):
            continue
        (undefined if fields[1] == "U" else defined).add(fields[0])
    return defined, undefined


def symbol_lists(nm: Path, objects: list[Path]) -> tuple[set[str], set[str]]:
    """The names the objects define and the names they leave undefined
    that no object of the list defines."""
    defined: set[str] = set()
    undefined: set[str] = set()
    for chunk in range(0, len(objects), 40):
        part = objects[chunk:chunk + 40]
        listing = subprocess.run(
            [str(nm), "--format=posix", *map(str, part)], capture_output=True,
            text=True, check=True).stdout
        found, missing = parse_nm(listing)
        defined |= found
        undefined |= missing
    return defined, undefined - defined


def archive_names(nm: Path, library: Path) -> set[str]:
    out = subprocess.run([str(nm), "--defined-only", "--format=just-symbols", str(library)],
                         capture_output=True, text=True, check=True).stdout
    return {line for line in out.splitlines() if line and not line.endswith(":")}


def strays(undefined: set[str], c_library: set[str]) -> list[str]:
    """The undefined names that neither the C library nor the exceptions of
    UNDEFINED_OK account for."""
    return sorted(undefined - c_library - UNDEFINED_OK)


def main() -> None:
    script = Path(__file__).read_bytes()
    text = stamp_text(script, port_bytes(), relibc_stamp())
    if "--check" in sys.argv[1:]:
        print(text, end="")
        return
    stamp = WORK / "stamp"
    libs = WORK / "lib"
    if stamp.exists() and stamp.read_text() == text and (libs / "libc++.a").exists():
        print(f"libcxx ready: {WORK}")
        return
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    log = WORK / "build.log"
    log.write_text("")
    source = WORK / "src"
    unpack(fetch(), source)
    clang, clangxx = tool("clang", "llvm"), tool("clang++", "llvm")
    ar, nm = tool("llvm-ar", "llvm"), tool("llvm-nm", "llvm")
    cursor = source / UNWIND_FILE
    cursor.write_text(patch_unwind(cursor.read_text()))
    # The installed headers: libc++'s, the site file and the assertion
    # handler, and cxxabi.h with its configuration.
    include = WORK / "include" / "c++" / "v1"
    shutil.copytree(source / "libcxx" / "include", include,
                    ignore=shutil.ignore_patterns("CMakeLists.txt", "*.in"))
    (include / "__config_site").write_text(
        site_file((source / "libcxx" / "include" / "__config_site.in").read_text()))
    shutil.copy(source / "libcxx" / "vendor" / "llvm" / "default_assertion_handler.in",
                include / "__assertion_handler")
    for header in ("cxxabi.h", "__cxxabi_config.h"):
        shutil.copy(source / "libcxxabi" / "include" / header, include / header)
    prefix = ("-ffile-prefix-map=" + f"{WORK}=/libcxx",)
    common = (*TARGET_FLAGS, *prefix, "-nostdinc", "-D__stafeto__=1")
    sysroot = ("-isystem", str(RELIBC / "include"))
    obj = WORK / "obj"
    cxx = (str(clangxx), *common, "-nostdinc++", "-fexceptions", "-frtti", "-DNDEBUG",
           "-fvisibility-inlines-hidden", "-D_LIBCPP_BUILDING_LIBRARY",
           "-DLIBCXX_BUILDING_LIBCXXABI", "-D_LIBCXXABI_BUILDING_LIBRARY",
           f"-I{source / 'libcxx' / 'src'}", f"-I{source / 'libc'}",
           f"-I{PORT / 'include'}", "-isystem", str(include), *sysroot)
    cxx_objects = objects_of(
        [*cxx, "-std=c++26"],
        [(source / "libcxx" / "src" / f"{n}.cpp", obj / "cxx" / f"{n.replace('/', '_')}.o")
         for n in LIBCXX], log)
    abi_objects = objects_of(
        [*cxx, "-std=c++20", "-DHAVE___CXA_THREAD_ATEXIT_IMPL",
         f"-I{source / 'libcxxabi' / 'src'}", f"-I{source / 'libunwind' / 'include'}"],
        [(source / "libcxxabi" / "src" / f"{n}.cpp", obj / "abi" / f"{n}.o")
         for n in LIBCXXABI], log)
    unwind_include = (f"-I{source / 'libunwind' / 'include'}", f"-I{source / 'libunwind' / 'src'}")
    unwind_flags = (*common, "-D_LIBUNWIND_IS_NATIVE_ONLY", "-funwind-tables",
                    "-fno-rtti", "-fvisibility=hidden", *unwind_include, *sysroot)
    unwind_pairs = lambda names, ext: [  # noqa: E731
        (source / "libunwind" / "src" / n, obj / "unwind" / (n + ".o")) for n in names]
    unwind_objects = (
        objects_of([str(clangxx), *unwind_flags, "-nostdinc++", "-std=c++17", "-fno-exceptions",
                    "-isystem", str(include)],
                   unwind_pairs(LIBUNWIND_CXX, "cpp"), log)
        + objects_of([str(clang), *unwind_flags, "-fexceptions", "-std=c11"], unwind_pairs(LIBUNWIND_C, "c"), log)
        + objects_of([str(clang), *unwind_flags], unwind_pairs(LIBUNWIND_ASM, "S"), log))
    libs.mkdir(parents=True)
    for name, members in (("libc++.a", cxx_objects), ("libc++abi.a", abi_objects),
                          ("libunwind.a", unwind_objects)):
        run(log, ar, "rcs", libs / name, *members)
    # The names the objects leave undefined must be the C library's.
    objects = cxx_objects + abi_objects + unwind_objects
    _, undefined = symbol_lists(nm, objects)
    c_library = archive_names(nm, RELIBC / "lib" / "libc.a") | archive_names(nm, RELIBC / "lib" / "libm.a")
    stray = strays(undefined, c_library)
    if stray:
        raise SystemExit("names the libraries need and the C library lacks: " + " ".join(stray))
    for member in objects:
        if str(WORK).encode() in member.read_bytes():
            raise SystemExit(f"{member.name} holds the path of the build directory")
    notice = WORK / "LICENSE.TXT"
    notice.write_text("\n\n".join(
        f"==== {part}/LICENSE.TXT ====\n\n" + (source / part / "LICENSE.TXT").read_text()
        for part in ("libcxx", "libcxxabi", "libunwind")))
    shutil.rmtree(obj)
    shutil.rmtree(source)
    stamp.write_text(text)
    print(f"libcxx ready: {WORK}")


if __name__ == "__main__":
    main()
