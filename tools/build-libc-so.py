#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build libc.so for stafeto (`cargo xtask libc-so`, spec 2, 3.12.3): the
shared C library that dynamically linked programs use. Nothing here runs a
guest.

Subcommands:
  build   (the default) relibc and openlibm in the position-independent
          model, the POSIX layer with the feature `shared`, the version
          script, ld.lld, every check of 3.12.3, crt1.o, and the sysroot
          target/libc-so/sysroot/{include,lib/libc.so,lib/crt1.o}.
  link -o OUT OBJECT_OR_ARCHIVE...
          link a dynamic program against that sysroot (the recipe of
          3.12.3; the programs of the images use it).
  programs [NAME...]
          link the dynamic programs of the images (busybox, busybox-utils,
          bash, nano, htop, ncdu, doom, nginx, nginx-fast; all by default) from the objects their build scripts left, into
          target/libc-so/programs, and check each one.
  probes  build the programs of tests/posix-so/dyn into
          target/libc-so/probes and check that each bad one has the
          property that makes it bad; fast-echo links libvirtio_net.a.
  vnet    the driver of the Virtio network device for a C program that
          owns the second device (lib/virtio-net with the feature `ffi`) as
          the static library target/libc-so/libvirtio_net.a, with its header
          lib/virtio-net/include/vnet.h.
  report  sizes, relocations by kind, exported names, the longest chain.

The relibc is the commit tools/build-relibc.py pins, built a second time
in target/libc-so/relibc with `-C relocation-model=pic -Z tls-model=
initial-exec` (-fPIC for the C). Options of build: --relibc-source DIR
uses a checkout of relibc (with local changes) in place of the pinned
fetch."""

import hashlib
import importlib.util
import os
import re
import shutil
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "target" / "libc-so"
SYSROOT = OUT / "sysroot"
PROBES = OUT / "probes"
STAMP = OUT / "stamp"
PROBES_STAMP = OUT / "probes-stamp"
PROGRAMS = OUT / "programs"
SOURCES = ROOT / "tests" / "posix-so" / "dyn"

LIBRARY_BASE = 0x0400_0000
LIBRARY_ROOM = range(0x0400_0000, 0x0800_0000)
PROGRAM_BASE = 0x20_0000
LOOKUPS_MAX = 8_192
RELOCS_MAX = 65_536
PAGE = 4096
CHAIN_LIMIT = 32
LAYER_TARGET = "aarch64-unknown-none"
TOOLCHAIN = "nightly-2026-05-24"
LAYER_FEATURES = "shared,procfs"
LAYER_RUSTFLAGS = ("-C relocation-model=pic -C target-feature=+fix-cortex-a53-835769"
                   " -C llvm-args=--enable-machine-outliner=never")

# Variables programs declare themselves and relibc's headers lack; each
# name carries its reason. They grow with the link errors of the programs.
EXTRA = {
    "environ": "programs declare it; relibc's headers lack it",
}
# libc.so's one entry and the probe hook of the layer (3.12.3).
ENTRY_NAMES = ["stafeto_start", "stafeto_probe_image", "stafeto_fast_probe_crash",
               "stafeto_probe_watch_builds"]
# Compiler helpers the objects of C programs refer to: the outlined atomics
# of AArch64, binary128 long double, 128-bit integers.
HELPER = re.compile(r"^(__aarch64_\w+|__[a-z]+(tf|ti)[0-9]|__(fix|float|extend|trunc)\w*(tf|ti)\w*)$")

# Helpers (the binary128 and 128-bit integer ones of compiler_builtins):
# programs call them, and libc.so's own objects mostly do not. The link keeps
# every one that relibc's archive defines (`-u`, 52 of them) and the export
# list names them (HELPER). Filled from relibc's archive by `build`.
HELPER_KEEP: dict = {}
CLANG_FLAGS = ["--target=aarch64-linux-gnu", "-mfix-cortex-a53-835769", "-nostdinc",
               "-fno-stack-protector", "-fno-builtin", "-std=c11", "-O2", "-Wall", "-Wextra",
               "-Werror"]
PROGRAM_LD = ["-z", "now", "-z", "norelro", "-z", "separate-loadable-segments",
              "-z", "max-page-size=4096", "--hash-style=gnu", "--fix-cortex-a53-843419"]

CRT1 = """\
// The entry of a dynamically linked program: the loader leaves the start
// area in x0 and enters here; main goes to libc.so's stafeto_start.
.text
.globl _start
.type _start, %function
_start:
    mov x29, xzr
    mov x30, xzr
    adrp x1, main
    add x1, x1, :lo12:main
    b stafeto_start
.size _start, . - _start
"""


class Failure(Exception):
    pass


def fail(message: str) -> None:
    raise Failure(message)


def llvm(name: str) -> str:
    brew = Path("/opt/homebrew/opt/llvm/bin") / name
    if brew.exists():
        return str(brew)
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"build-libc-so: missing {name}; install LLVM and lld")
    return found


def lld() -> str:
    for candidate in (Path("/opt/homebrew/opt/lld/bin/ld.lld"), Path("/opt/homebrew/opt/llvm/bin/ld.lld")):
        if candidate.exists():
            return str(candidate)
    found = shutil.which("ld.lld")
    if found is None:
        raise SystemExit("build-libc-so: missing ld.lld; install lld")
    return found


def run(*args, cwd=None, env=None, capture=False, check=True):
    result = subprocess.run([str(a) for a in args], cwd=cwd, env=env, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None)
    if check and result.returncode != 0:
        sys.exit(f"build-libc-so: {' '.join(str(a) for a in args)}\n"
                 f"{result.stderr if capture else ''}")
    return result


# ---------------------------------------------------------------- ELF reader

PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_PHDR, PT_TLS = 1, 2, 3, 6, 7
PF_X, PF_W, PF_R = 1, 2, 4
DT = {"NULL": 0, "NEEDED": 1, "PLTRELSZ": 2, "HASH": 4, "STRTAB": 5, "SYMTAB": 6, "RELA": 7,
      "RELASZ": 8, "INIT": 12, "FINI": 13, "SONAME": 14, "SYMBOLIC": 16, "REL": 17,
      "TEXTREL": 22, "JMPREL": 23, "BIND_NOW": 24, "INIT_ARRAY": 25, "FINI_ARRAY": 26,
      "FLAGS": 30, "PREINIT_ARRAY": 32, "RELRSZ": 35, "RELR": 36, "GNU_HASH": 0x6FFFFEF5,
      "FLAGS_1": 0x6FFFFFFB}
DF_SYMBOLIC, DF_TEXTREL, DF_BIND_NOW, DF_STATIC_TLS = 2, 4, 8, 16
RELOCATION = {257: "ABS64", 1024: "COPY", 1025: "GLOB_DAT", 1026: "JUMP_SLOT",
              1027: "RELATIVE", 1028: "TLS_DTPMOD64", 1029: "TLS_DTPREL64",
              1030: "TLS_TPREL64", 1031: "TLSDESC", 1032: "IRELATIVE"}
ELF_TYPE = {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN"}


class Elf:
    """The parts of an ELF64 little-endian file the checks read."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        d = self.data
        if d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 1:
            fail(f"{path}: not an ELF64 little-endian file")
        self.type, self.machine = struct.unpack_from("<HH", d, 16)
        self.phoff, self.shoff = struct.unpack_from("<QQ", d, 32)
        phentsize, self.phnum, shentsize, self.shnum, shstrndx = struct.unpack_from("<HHHHH", d, 54)
        self.segments = []
        for i in range(self.phnum):
            kind, flags, off, vaddr, paddr, filesz, memsz, align = struct.unpack_from(
                "<IIQQQQQQ", d, self.phoff + i * phentsize)
            self.segments.append(dict(type=kind, flags=flags, offset=off, vaddr=vaddr,
                                      filesz=filesz, memsz=memsz, align=align))
        self.sections = {}
        raw = []
        for i in range(self.shnum):
            raw.append(struct.unpack_from("<IIQQQQIIQQ", d, self.shoff + i * shentsize))
        if raw:
            names = raw[shstrndx]
            for name, kind, flags, addr, off, size, link, info, align, entsize in raw:
                text = self.string(names[4], name)
                self.sections[text] = dict(type=kind, flags=flags, addr=addr, offset=off,
                                           size=size, link=link, entsize=entsize)
        self.dynamic = self._dynamic()

    def string(self, table: int, index: int) -> str:
        end = self.data.index(b"\0", table + index)
        return self.data[table + index:end].decode()

    def file_offset(self, vaddr: int) -> int:
        for s in self.segments:
            if s["type"] == PT_LOAD and s["vaddr"] <= vaddr < s["vaddr"] + s["filesz"]:
                return s["offset"] + vaddr - s["vaddr"]
        fail(f"{self.path.name}: address {vaddr:#x} lies in no segment's file bytes")

    def _dynamic(self) -> list:
        found = []
        for s in self.segments:
            if s["type"] == PT_DYNAMIC:
                for at in range(s["offset"], s["offset"] + s["filesz"], 16):
                    tag, value = struct.unpack_from("<qQ", self.data, at)
                    found.append((tag, value))
                    if tag == 0:
                        break
        return found

    def tags(self, name: str) -> list:
        return [v for t, v in self.dynamic if t == DT[name]]

    def needed(self) -> list:
        strtab = self.tags("STRTAB")
        if not strtab:
            return []
        table = self.file_offset(strtab[0])
        return [self.string(table, v) for v in self.tags("NEEDED")]

    def flags(self) -> int:
        return sum(self.tags("FLAGS")) | (DF_BIND_NOW if self.tags("BIND_NOW") else 0) | \
            (DF_SYMBOLIC if self.tags("SYMBOLIC") else 0) | \
            (DF_TEXTREL if self.tags("TEXTREL") else 0)

    def interp(self) -> str | None:
        for s in self.segments:
            if s["type"] == PT_INTERP:
                return self.data[s["offset"]:s["offset"] + s["filesz"]].rstrip(b"\0").decode()
        return None

    def dynsym(self) -> list:
        """(name, defined, binding, visibility, kind) of every dynamic symbol."""
        section = self.sections.get(".dynsym")
        if not section:
            return []
        table = self.sections[".dynstr"]["offset"]
        symbols = []
        for at in range(section["offset"], section["offset"] + section["size"], 24):
            name, info, other, shndx, _, _ = struct.unpack_from("<IBBHQQ", self.data, at)
            symbols.append((self.string(table, name) if name else "", shndx != 0,
                            info >> 4, other & 3, info & 15))
        return symbols

    def relocations(self) -> list:
        """(offset, kind, symbol name) of every dynamic relocation, RELR
        included (each of its words counts as the RELATIVE it stands for)."""
        symbols = self.dynsym()
        found = []
        for name in (".rela.dyn", ".rela.plt", ".rela.iplt"):
            s = self.sections.get(name)
            if not s:
                continue
            for at in range(s["offset"], s["offset"] + s["size"], 24):
                offset, info, _ = struct.unpack_from("<QQq", self.data, at)
                kind, sym = info & 0xFFFFFFFF, info >> 32
                found.append((offset, RELOCATION.get(kind, f"TYPE{kind}"),
                              symbols[sym][0] if sym else ""))
        s = self.sections.get(".relr.dyn")
        if s:
            base = None
            for at in range(s["offset"], s["offset"] + s["size"], 8):
                (word,) = struct.unpack_from("<Q", self.data, at)
                if word & 1 == 0:
                    found.append((word, "RELATIVE", ""))
                    base = word + 8
                else:
                    if base is None:
                        fail(f"{self.path.name}: RELR bitmap before an address")
                    for bit in range(1, 64):
                        if word >> bit & 1:
                            found.append((base + (bit - 1) * 8, "RELATIVE", ""))
                    base += 63 * 8
        return found

    def chain_lengths(self) -> list:
        """The lengths of the chains of the GNU hash table."""
        section = self.sections.get(".gnu.hash")
        if not section:
            return []
        d, at = self.data, section["offset"]
        nbuckets, symoffset, bloom, _ = struct.unpack_from("<IIII", d, at)
        buckets = at + 16 + 8 * bloom
        chains = buckets + 4 * nbuckets
        lengths = []
        for b in range(nbuckets):
            (first,) = struct.unpack_from("<I", d, buckets + 4 * b)
            if first == 0:
                continue
            length, index = 0, first
            while True:
                (word,) = struct.unpack_from("<I", d, chains + 4 * (index - symoffset))
                length += 1
                if word & 1:
                    break
                index += 1
            lengths.append(length)
        return lengths


# ----------------------------------------------------------------- the build


def build_relibc(source: Path | None) -> Path:
    """relibc in the PIC model, through tools/build-relibc.py with its
    directories, flags and (optionally) source moved."""
    spec = importlib.util.spec_from_file_location("build_relibc", ROOT / "tools/build-relibc.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    work = OUT / "relibc"
    module.WORK, module.BUILD = work, work / "build"
    module.SYSROOT, module.STAMP = work / "sysroot", work / "stamp"
    module.SOURCE = source if source else work / "source"
    module.RUSTFLAGS = module.RUSTFLAGS.replace(
        "-C relocation-model=static -Z tls-model=local-exec",
        "-C relocation-model=pic -Z tls-model=initial-exec")
    module.CFLAGS += " -fPIC"
    assert "relocation-model=pic" in module.RUSTFLAGS
    if source:
        module.fetch = lambda env: None
    module.main()
    return module.SYSROOT


def build_layer() -> Path:
    env = dict(os.environ)
    for name in ("RUSTUP_TOOLCHAIN", "RUSTC", "CARGO_ENCODED_RUSTFLAGS"):
        env.pop(name, None)
    # No path of this machine in libc.so: the workspace, the toolchain's
    # library sources and CARGO_HOME get fixed names (as tools/build-relibc.py).
    sysroot = run("rustup", "run", TOOLCHAIN, "rustc", "--print", "sysroot", capture=True).stdout.strip()
    cargo_home = os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))
    remap = " ".join(f"--remap-path-prefix={path}={name}" for path, name in
                     ((ROOT, "/stafeto"), (sysroot, "/rust"), (cargo_home, "/cargo")))
    env["RUSTFLAGS"] = f"{LAYER_RUSTFLAGS} {remap}"
    env["CARGO_TARGET_DIR"] = str(OUT / "layer")
    # The precompiled core of the stable toolchain is static (ABS64 against
    # local symbols in .rodata), which ld.lld refuses in a shared object:
    # core, alloc and compiler_builtins are built again with the pinned
    # nightly relibc uses (-Z build-std).
    run("cargo", f"+{TOOLCHAIN}", "build", "--release", "--locked", "-p", "posix-crt",
        "--features", LAYER_FEATURES, "--target", LAYER_TARGET,
        "-Zbuild-std=core,alloc,compiler_builtins", cwd=ROOT, env=env)
    return OUT / "layer" / LAYER_TARGET / "release" / "libposix_crt.a"


VNET = OUT / "libvirtio_net.a"
VNET_INCLUDE = ROOT / "lib" / "virtio-net" / "include"


def build_vnet() -> Path:
    """lib/virtio-net with the feature `ffi` as a static library for C
    programs: no rt and no _start (crt1.o and libc.so have them), core and
    compiler_builtins built with the pinned nightly as for the layer, a
    panic that calls abort, and no allocator (the library allocates
    nothing). Cargo knows whether the sources changed."""
    env = dict(os.environ)
    for name in ("RUSTUP_TOOLCHAIN", "RUSTC", "CARGO_ENCODED_RUSTFLAGS"):
        env.pop(name, None)
    sysroot = run("rustup", "run", TOOLCHAIN, "rustc", "--print", "sysroot", capture=True).stdout.strip()
    cargo_home = os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))
    remap = " ".join(f"--remap-path-prefix={path}={name}" for path, name in
                     ((ROOT, "/stafeto"), (sysroot, "/rust"), (cargo_home, "/cargo")))
    env["RUSTFLAGS"] = f"-C target-feature=+fix-cortex-a53-835769 {remap}"
    env["CARGO_TARGET_DIR"] = str(OUT / "vnet")
    run("cargo", f"+{TOOLCHAIN}", "rustc", "--release", "--locked", "-p", "virtio-net",
        "--features", "ffi", "--target", LAYER_TARGET, "--crate-type", "staticlib",
        "-Zbuild-std=core,compiler_builtins", cwd=ROOT, env=env)
    built = OUT / "vnet" / LAYER_TARGET / "release" / "libvirtio_net.a"
    # One relocatable object with the functions of vnet.h alone global: the
    # archive of cargo also defines memcpy, memset, memcmp, strlen and the
    # functions of libm (compiler_builtins, weak) and the symbols of core,
    # which would take the program's own calls (nginx's, F-Stack's) away
    # from libc.so and clash with a second library of Rust. Inside the
    # object the library's code keeps its copies.
    work = OUT / "vnet-object"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    whole = work / "vnet.o"
    run(lld(), "-r", "--whole-archive", built, "-o", whole)
    keep = work / "keep.txt"
    keep.write_text("".join(f"{n}\n" for n in VNET_NAMES))
    run(llvm("llvm-objcopy"), f"--keep-global-symbols={keep}", "--strip-debug", whole)
    archive = work / "libvirtio_net.a"
    run(llvm("llvm-ar"), "rcs", archive, whole)
    if not VNET.exists() or digest(VNET) != digest(archive):
        shutil.copyfile(archive, VNET)
    defined = archive_names(VNET, "-g", "--defined-only")
    if defined != set(VNET_NAMES):
        extra = sorted(defined - set(VNET_NAMES))[:5]
        missing = sorted(set(VNET_NAMES) - defined)[:5]
        fail(f"libvirtio_net.a defines globally {extra} more and lacks {missing}")
    return VNET


# The functions of vnet.h.
VNET_NAMES = ["vnet_open", "vnet_rx_burst", "vnet_rx_return", "vnet_buf_take", "vnet_buf_ptr", "vnet_buf_free",
              "vnet_tx", "vnet_tx_kick", "vnet_tx_reclaim", "vnet_notify", "vnet_lost", "vnet_bells",
              "vnet_fill_sums", "vnet_copy", "vnet_bypass_push", "vnet_bypass_pop"]


def archive_names(archive: Path, *flags) -> set:
    out = run(llvm("llvm-nm"), *flags, archive, capture=True).stdout
    return {line.split()[-1] for line in out.splitlines()
            if line.strip() and not line.endswith(":") and len(line.split()) >= 2}


def raise_visibility(libc_a: Path, layer_a: Path) -> tuple[Path, int]:
    """The layer's archive with default visibility for the names relibc also
    defines. The compiler_builtins of the layer defines memcpy, memset,
    memcmp and the libm functions weakly and hidden; the linker merges the
    visibility of a definition and its duplicates to the narrowest, so
    relibc's strong memset would turn hidden and could not be exported."""
    shared = sorted(archive_names(libc_a, "--defined-only", "--extern-only")
                    & archive_names(layer_a, "--extern-only"))
    work = OUT / "layer-vis"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    listing = work / "names.txt"
    listing.write_text("".join(f"{n}\n" for n in shared))
    run(llvm("llvm-ar"), "x", layer_a, cwd=work)
    members = sorted(work.glob("*.o"))
    for member in members:
        run(llvm("llvm-objcopy"), f"--set-symbols-visibility={listing}=default", member)
    result = OUT / "libposix_crt_vis.a"
    result.unlink(missing_ok=True)
    run(llvm("llvm-ar"), "crs", result, *members)
    return result, len(shared)


def link_so(output: Path, libc_a: Path, layer_a: Path, extra: list) -> Path:
    run(lld(), "-shared", "-soname", "libc.so", f"--image-base={LIBRARY_BASE:#x}", "-Bsymbolic",
        "-z", "now", "-z", "defs", "-z", "norelro", "-z", "separate-loadable-segments",
        "-z", "max-page-size=4096", "--hash-style=gnu", "--gc-sections",
        "--fix-cortex-a53-843419", *extra, *(f"--undefined={n}" for n in HELPER_KEEP),
        "-o", output, "--whole-archive", libc_a, layer_a,
        "--no-whole-archive")
    return output


def export_names(sysroot: Path, plain: Elf) -> dict:
    """The names libc.so exports, each with its reason."""
    defined = {n for n, is_def, bind, vis, _ in plain.dynsym() if is_def and n and bind in (1, 2)}
    words = set()
    for header in (sysroot / "include").rglob("*.h"):
        words.update(re.findall(r"[A-Za-z_]\w*", header.read_text(errors="replace")))
    names = {n: "declared in a header" for n in defined & words}
    for n, why in EXTRA.items():
        names[n] = why
    for n in ENTRY_NAMES:
        names[n] = "entry or probe hook of libc.so"
    for n in defined:
        if HELPER.match(n):
            names.setdefault(n, "compiler helper")
    missing = sorted(n for n in names if n not in defined)
    if missing:
        fail(f"names to export are not defined in libc.so: {' '.join(missing)}")
    return names


# ----------------------------------------------------------------- the checks


def segment_pages(s: dict) -> range:
    return range(s["vaddr"] // PAGE, -(-(s["vaddr"] + s["memsz"]) // PAGE))


def check_library(path: Path, names: dict, layer_a: Path, libc_a: Path) -> list:
    """The checks of 3.12.3; any violation is a Failure. Returns the lines
    of what was checked, for the report."""
    elf = Elf(path)
    notes = []

    def need(condition: bool, message: str) -> None:
        if not condition:
            fail(f"libc.so: {message}")

    need(elf.type == 3, f"type {ELF_TYPE.get(elf.type, elf.type)}, expected ET_DYN")
    loads = [s for s in elf.segments if s["type"] == PT_LOAD]
    need([s["flags"] for s in loads] == [PF_R, PF_R | PF_X, PF_R | PF_W],
         f"loadable segments {[s['flags'] for s in loads]}, expected R, RX, RW once each")
    pages = [segment_pages(s) for s in loads]
    for i, run_ in enumerate(pages):
        need(run_.start * PAGE in LIBRARY_ROOM and run_.stop * PAGE - 1 in LIBRARY_ROOM,
             f"segment {i} lies outside LIBRARY_ROOM")
        for other in pages[:i]:
            need(run_.start >= other.stop, f"segment {i} shares a page with an earlier one")
    tls = [s for s in elf.segments if s["type"] == PT_TLS]
    need(len(tls) == 1, f"{len(tls)} PT_TLS segments, expected one")
    rw = loads[2]
    need(rw["vaddr"] <= tls[0]["vaddr"] and tls[0]["vaddr"] + tls[0]["filesz"] <= rw["vaddr"] + rw["filesz"],
         "PT_TLS lies outside the file bytes of the RW segment")
    need(tls[0]["align"] > 0 and tls[0]["vaddr"] % tls[0]["align"] == 0,
         "PT_TLS.p_vaddr is not a multiple of its alignment")
    for s in elf.segments:
        if s["type"] == PT_PHDR:
            need(loads[0]["vaddr"] <= s["vaddr"]
                 and s["vaddr"] + s["filesz"] <= loads[0]["vaddr"] + loads[0]["filesz"],
                 "PT_PHDR lies outside the R segment")
    # The loader hands out the address of the PT_TLS header: it lies in R.
    need(loads[0]["offset"] == 0 and elf.phoff + elf.phnum * 56 <= loads[0]["filesz"],
         "the program headers lie outside the R segment")
    dyn = [s for s in elf.segments if s["type"] == PT_DYNAMIC]
    need(len(dyn) == 1 and rw["vaddr"] <= dyn[0]["vaddr"]
         and dyn[0]["vaddr"] + dyn[0]["filesz"] <= rw["vaddr"] + rw["filesz"],
         "PT_DYNAMIC is missing or lies outside the file bytes of the RW segment")
    need(elf.interp() is None, "has a PT_INTERP")
    need(not elf.needed() and not elf.tags("NEEDED"), "has a DT_NEEDED")
    for tag in ("TEXTREL", "INIT", "FINI"):
        need(not elf.tags(tag), f"has a DT_{tag}")
    flags = elf.flags()
    need(flags & DF_SYMBOLIC and flags & DF_BIND_NOW, f"DT_FLAGS {flags:#x} lacks SYMBOLIC or BIND_NOW")
    need(flags & DF_TEXTREL == 0, "DT_FLAGS has TEXTREL")
    relocs = elf.relocations()
    kinds = Counter(k for _, k, _ in relocs)
    need(set(kinds) <= {"RELATIVE", "TLS_TPREL64"}, f"relocation kinds {dict(kinds)}")
    writable = range(rw["vaddr"], rw["vaddr"] + rw["filesz"])
    outside = [r for r in relocs if r[0] not in writable]
    need(not outside, f"{len(outside)} relocations outside the RW segment, the first at {outside[0][0]:#x}"
         if outside else "")
    symbols = elf.dynsym()
    undefined = sorted({n for n, is_def, _, _, _ in symbols if n and not is_def})
    need(not undefined, f"undefined symbols: {' '.join(undefined)}")
    # `main` and `__ehdr_start` are named by nothing in the library, in the
    # archive of the layer either.
    for archive in (layer_a, libc_a):
        refs = archive_names(archive, "--undefined-only") & {"main", "__ehdr_start"}
        need(not refs, f"{archive.name} refers to {' '.join(sorted(refs))}")
    exported = {n for n, is_def, bind, vis, _ in symbols if is_def and n and vis == 0}
    hidden = sorted(n for n in names if n not in exported)
    need(not hidden, f"{len(hidden)} names of the export list are not visible in .dynsym: "
         f"{' '.join(hidden[:20])}")
    extra = sorted(exported - set(names))
    need(not extra, f"{len(extra)} names are exported that the list lacks: {' '.join(extra[:20])}")
    for marker in (str(Path.home()), ".rustup", ".cargo"):
        need(marker.encode() not in elf.data, f"a path of this machine ({marker}) is in the file")
    chains = elf.chain_lengths()
    need(max(chains) <= CHAIN_LIMIT, f"the longest GNU hash chain has {max(chains)} entries "
         f"(at most {CHAIN_LIMIT})")
    notes.append(f"ET_DYN, R/RX/RW inside LIBRARY_ROOM, one PT_TLS and PT_DYNAMIC in RW, "
                 f"no INTERP/NEEDED/TEXTREL/INIT/FINI")
    notes.append(f"relocations {dict(kinds)} all in RW; no undefined symbol; {len(names)} names "
                 f"exported and visible; longest chain {max(chains)} (limit {CHAIN_LIMIT})")
    return notes


# ------------------------------------------------------------------- build


def digest(*parts) -> str:
    sha = hashlib.sha256()
    for part in parts:
        sha.update(part if isinstance(part, bytes) else Path(part).read_bytes())
    return sha.hexdigest()


def build_stamp(libc_a: Path, layer_a: Path) -> str:
    """The inputs of libc.so: both archives, this script, the programs' recipe
    (the same script), and the tools that link."""
    tools = run(lld(), "--version", capture=True).stdout
    return "\n".join((digest(libc_a), digest(layer_a), digest(Path(__file__)), tools.strip(),
                      TOOLCHAIN)) + "\n"


def raise_helpers(libc_a: Path) -> Path:
    """A copy of relibc's archive whose members that define a name of
    HELPER_KEEP have default visibility for it (compiler_builtins hides
    them, and a hidden definition cannot be exported)."""
    for name in archive_names(libc_a, "--defined-only", "--extern-only"):
        if HELPER.match(name) and not name.startswith("__aarch64_"):
            HELPER_KEEP[name] = "compiler helper of programs"
    work = OUT / "libc-vis"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    result = work / "libc.a"
    shutil.copyfile(libc_a, result)
    listing = work / "names.txt"
    listing.write_text("".join(f"{n}\n" for n in HELPER_KEEP))
    out = run(llvm("llvm-nm"), "-A", "--defined-only", "--extern-only", libc_a, capture=True).stdout
    members = sorted({line.split(":")[1] for line in out.splitlines()
                      if line.split()[-1] in HELPER_KEEP})
    for member in members:
        run(llvm("llvm-ar"), "x", libc_a, member, cwd=work)
        run(llvm("llvm-objcopy"), f"--set-symbols-visibility={listing}=default", work / member)
        run(llvm("llvm-ar"), "r", result, work / member)
    return result


def build(source: Path | None) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    sysroot = build_relibc(source)
    libc_a = sysroot / "lib" / "libc.a"
    layer_a = build_layer()
    # What libc.so is made of: a change of any of it builds it again.
    wanted = build_stamp(libc_a, layer_a)
    if (STAMP.exists() and STAMP.read_text() == wanted and (OUT / "libc.so").exists()
            and (SYSROOT / "lib" / "libc.so").exists() and (SYSROOT / "lib" / "crt1.o").exists()):
        print(f"libc.so is up to date: {SYSROOT / 'lib' / 'libc.so'}")
        return
    STAMP.unlink(missing_ok=True)
    layer_a, raised = raise_visibility(libc_a, layer_a)
    libc_a = raise_helpers(libc_a)
    print(f"layer archive: {raised} names shared with relibc raised to default visibility")

    plain = Elf(link_so(OUT / "libc-all.so", libc_a, layer_a, []))
    names = export_names(sysroot, plain)
    script = OUT / "libc.map"
    script.write_text("{ global:\n" + "".join(f"  {n};\n" for n in sorted(names))
                      + " local: *; };\n")
    final = OUT / "libc.so.new"
    link_so(final, libc_a, layer_a,
            ["-z", "pack-relative-relocs", f"--version-script={script}"])
    run(llvm("llvm-objcopy"), "--strip-debug", final)
    notes = check_library(final, names, layer_a, libc_a)
    for line in notes:
        print("check:", line)
    os.replace(final, OUT / "libc.so")
    final = OUT / "libc.so"

    # The sysroot: the headers of the static one, libc.so, crt1.o.
    shutil.rmtree(SYSROOT, ignore_errors=True)
    (SYSROOT / "lib").mkdir(parents=True)
    shutil.copytree(sysroot / "include", SYSROOT / "include")
    if (sysroot / "share").exists():
        shutil.copytree(sysroot / "share", SYSROOT / "share")
    shutil.copyfile(final, SYSROOT / "lib" / "libc.so")
    crt1 = OUT / "crt1.S"
    crt1.write_text(CRT1)
    run(llvm("clang"), "--target=aarch64-linux-gnu", "-c", crt1, "-o", SYSROOT / "lib" / "crt1.o")
    STAMP.write_text(wanted)
    print(f"libc.so ready: {SYSROOT / 'lib' / 'libc.so'}")


# -------------------------------------------------------------------- link


def link_program(output: Path, inputs: list, extra: list | None = None,
                 library: Path | None = None, capture=False):
    """The recipe of 3.12.3 for a program: ET_EXEC at 0x200000, one
    DT_NEEDED, no copy relocations, crt1.o first and libc.so last."""
    library = library or SYSROOT / "lib" / "libc.so"
    return run(lld(), "-z", "nocopyreloc", *PROGRAM_LD, "--dynamic-linker=/lib/ld.so",
               *(extra or []), "-o", output, SYSROOT / "lib" / "crt1.o", *inputs, library,
               capture=capture, check=not capture)


def compile_c(source: Path, output: Path, *flags, fpic=True) -> None:
    run(llvm("clang"), *CLANG_FLAGS, "-fPIC" if fpic else "-fno-pic", "-isystem",
        SYSROOT / "include", *flags, "-c", source, "-o", output)


# ------------------------------------------------------------------- probes

GOOD = ["so-hello", "so-image", "display-probe", "net-sock", "net-dns", "posix-net"]
# Good programs linked with libvirtio_net.a as well.
WITH_VNET = ["fast-echo"]
BAD = ["bad-interp", "bad-copy", "bad-tls", "bad-needed", "bad-symbol", "bad-ifunc", "bad-pie"]
PROBE_FILES = GOOD + WITH_VNET + BAD
# bad program: (source, what makes it bad, check)


def program_checks(name: str, elf: Elf) -> str | None:
    """None when the bad program has the property its name says; else why not."""
    kinds = Counter(k for _, k, _ in elf.relocations())
    if name == "bad-interp":
        return None if elf.interp() == "/lib/other.so" else f"interpreter {elf.interp()}"
    if name == "bad-copy":
        return None if kinds["COPY"] else "no COPY relocation"
    if name == "bad-tls":
        return None if any(s["type"] == PT_TLS for s in elf.segments) else "no PT_TLS"
    if name == "bad-needed":
        return None if len(elf.needed()) == 2 else f"needed {elf.needed()}"
    if name == "bad-symbol":
        missing = [n for n, is_def, bind, _, _ in elf.dynsym() if n == "so_missing" and not is_def]
        return None if missing else "no undefined so_missing"
    if name == "bad-ifunc":
        return None if kinds["IRELATIVE"] else "no IRELATIVE relocation"
    if name == "bad-pie":
        return None if elf.type == 3 else f"type {ELF_TYPE.get(elf.type)}"
    return f"unknown program {name}"


def good_checks(name: str, elf: Elf) -> str | None:
    if elf.type != 2:
        return "not ET_EXEC"
    if elf.interp() != "/lib/ld.so":
        return f"interpreter {elf.interp()}"
    if elf.needed() != ["libc.so"]:
        return f"needed {elf.needed()}"
    if any(s["type"] == PT_TLS for s in elf.segments):
        return "has a PT_TLS"
    # The address of a function of libc.so in the writable data of the
    # program (curl keeps malloc and free so) is an ABS64 against the name,
    # which the loader resolves in both modules.
    bad = {k for _, k, _ in elf.relocations()} - {"RELATIVE", "GLOB_DAT", "JUMP_SLOT", "ABS64"}
    if bad:
        return f"relocation kinds {sorted(bad)}"
    return None


def fast_checks(elf: Elf) -> None:
    """nginx-fast takes its string functions from libc.so (its own copies
    would take the program's calls away from the layer) and registers the
    stack's table through the layer."""
    symbols = elf.dynsym()
    imported = {name for name, defined, *_ in symbols if name and not defined}
    defined = {name for name, is_defined, *_ in symbols if name and is_defined}
    for name in ("memcpy", "stafeto_fast_register"):
        if name not in imported:
            fail(f"nginx-fast: {name} is not libc.so's")
    for name in ("memcpy", "strlen"):
        if name in defined:
            fail(f"nginx-fast defines {name}")


def probes_stamp() -> str:
    sources = sorted(SOURCES.glob("*.c"))
    return "\n".join((digest(SYSROOT / "lib" / "libc.so"), digest(SYSROOT / "lib" / "crt1.o"),
                      digest(Path(__file__)), digest(VNET), digest(VNET_INCLUDE / "vnet.h"),
                      *(digest(p) for p in sources))) + "\n"


def build_probes() -> list:
    if not (SYSROOT / "lib" / "libc.so").exists():
        fail("build libc.so first: tools/build-libc-so.py build")
    build_vnet()
    wanted = probes_stamp()
    if (PROBES_STAMP.exists() and PROBES_STAMP.read_text() == wanted
            and all((PROBES / n).exists() for n in PROBE_FILES)):
        print("probes are up to date")
        return sorted(PROBE_FILES)
    PROBES_STAMP.unlink(missing_ok=True)
    shutil.rmtree(PROBES, ignore_errors=True)
    PROBES.mkdir(parents=True)
    work = PROBES / "obj"
    work.mkdir()
    made = {}
    for name in GOOD:
        compile_c(SOURCES / f"{name}.c", work / f"{name}.o")
        # so-hello exports so_exported, which its dl mode looks up by name.
        link_program(PROBES / name, [work / f"{name}.o"],
                     ["--export-dynamic-symbol=so_exported"] if name == "so-hello" else None)
        made[name] = "good"
    # The owner of the second network device: the driver's static library
    # beside libc.so (its memcpy is libc.so's; the library has vnet_copy).
    for name in WITH_VNET:
        compile_c(SOURCES / f"{name}.c", work / f"{name}.o", "-I", VNET_INCLUDE)
        link_program(PROBES / name, [work / f"{name}.o", VNET], ["--gc-sections", "--strip-debug"])
        # The program's own calls of the C library go to libc.so.
        imported = {n for n, is_def, _, _, _ in Elf(PROBES / name).dynsym() if n and not is_def}
        if "memcpy" not in imported:
            fail(f"{name}: memcpy is not libc.so's")
        made[name] = "good"
    # bad-interp: another dynamic linker.
    compile_c(SOURCES / "bad-interp.c", work / "bad-interp.o")
    link_program(PROBES / "bad-interp", [work / "bad-interp.o"], ["--dynamic-linker=/lib/other.so"])
    # bad-copy: code without -fPIC refers to environ, copy relocations allowed.
    compile_c(SOURCES / "bad-copy.c", work / "bad-copy.o", fpic=False)
    run(lld(), *PROGRAM_LD, "--dynamic-linker=/lib/ld.so", "-o", PROBES / "bad-copy",
        SYSROOT / "lib" / "crt1.o", work / "bad-copy.o", SYSROOT / "lib" / "libc.so")
    # bad-tls: a thread-local variable gives the program a PT_TLS.
    compile_c(SOURCES / "bad-tls.c", work / "bad-tls.o")
    link_program(PROBES / "bad-tls", [work / "bad-tls.o"])
    # bad-needed: a second library in DT_NEEDED.
    (work / "libx.c").write_text("int libx_value(void) { return 1; }\n")
    compile_c(work / "libx.c", work / "libx.o")
    run(lld(), "-shared", "-soname", "libx.so", "-o", PROBES / "libx.so", work / "libx.o")
    compile_c(SOURCES / "bad-needed.c", work / "bad-needed.o")
    link_program(PROBES / "bad-needed", [work / "bad-needed.o", PROBES / "libx.so"])
    # bad-symbol: a strong reference to a name libc.so lacks, linked against
    # a stand-in libc.so that has it.
    (work / "stub.S").write_text(".text\n.globl so_missing\n.type so_missing, %function\n"
                                 "so_missing:\n ret\n.globl stafeto_start\n"
                                 ".type stafeto_start, %function\nstafeto_start:\n ret\n"
                                 ".globl printf\n.type printf, %function\nprintf:\n ret\n")
    run(llvm("clang"), "--target=aarch64-linux-gnu", "-c", work / "stub.S", "-o", work / "stub.o")
    run(lld(), "-shared", "-soname", "libc.so", "-o", work / "libc-stub.so", work / "stub.o")
    compile_c(SOURCES / "bad-symbol.c", work / "bad-symbol.o")
    link_program(PROBES / "bad-symbol", [work / "bad-symbol.o"], library=work / "libc-stub.so")
    # bad-ifunc: an ifunc gives an IRELATIVE relocation.
    compile_c(SOURCES / "bad-ifunc.c", work / "bad-ifunc.o")
    link_program(PROBES / "bad-ifunc", [work / "bad-ifunc.o"])
    # bad-pie: a position-independent executable.
    compile_c(SOURCES / "bad-pie.c", work / "bad-pie.o")
    link_program(PROBES / "bad-pie", [work / "bad-pie.o"], ["-pie"])
    for name in ("bad-interp", "bad-copy", "bad-tls", "bad-needed", "bad-symbol", "bad-ifunc",
                 "bad-pie"):
        made[name] = "bad"
    # Each program has the property its name and its test rest on.
    for name, kind in made.items():
        elf = Elf(PROBES / name)
        why = (good_checks if kind == "good" else program_checks)(name, elf)
        if why:
            fail(f"probe {name}: {why}")
    PROBES_STAMP.write_text(wanted)
    return sorted(made)


# ----------------------------------------------------------------- programs

# The directories of BusyBox's archives (tests/busybox/build.rs lists the same).
BUSYBOX_DIRECTORIES = ("libbb", "coreutils", "coreutils/libcoreutils", "shell", "procps",
                       "networking", "archival", "archival/libarchive", "editors", "findutils",
                       "miscutils", "util-linux", "sysklogd", "libpwdgrp", "console-tools")
BUSYBOX_MAIN = ROOT / "tools" / "busybox" / "dynamic-main.c"


def program_inputs() -> dict:
    """Name of the program: the files it is linked from."""
    def busybox(tree: str, ready: bool) -> list:
        inputs = [ROOT / "target" / tree / "source" / d / "lib.a" for d in BUSYBOX_DIRECTORIES]
        if ready:
            inputs.append(ROOT / "target" / "ready-utils" / "ready.a")
        return inputs
    return {
        "busybox": busybox("busybox", False),
        "busybox-utils": busybox("busybox-utils", True),
        "bash": [ROOT / "target" / "bash" / "bash.o"],
        "nano": [ROOT / "target" / "nano" / "nano.o"],
        "htop": [ROOT / "target" / "htop" / "htop.o"],
        "ncdu": [ROOT / "target" / "ncdu" / "ncdu.o"],
        "doom": [ROOT / "target" / "doomgeneric" / "doom.o"],
        "fstack-probe": [ROOT / "target" / "f-stack" / "fstack-probe.o", VNET],
        # The probe of the layer's sockets: a program that carries the stack
        # as nginx-fast will (the stack, the device's driver, the glue that
        # registers the table).
        "fast-layer": [ROOT / "target" / "f-stack" / "fast-layer.o",
                       ROOT / "target" / "f-stack" / "ff_stafeto_glue.o",
                       ROOT / "target" / "f-stack" / "libfstack.a", VNET],
        # nginx on the stack in its own process (packages/nginx-fast.toml):
        # nginx's object, the stack, the device's driver and the glue.
        "nginx-fast": [ROOT / "target" / "nginx" / "nginx.o",
                       ROOT / "target" / "f-stack" / "libfstack.a", VNET,
                       ROOT / "target" / "f-stack" / "ff_stafeto_glue.o"],
        "openssl": [ROOT / "target" / "openssl" / "openssl.o"],
        "curl": [ROOT / "target" / "curl" / "curl.o"],
        "nginx": [ROOT / "target" / "nginx" / "nginx.o"],
    }


# The extra options of the link of a program. The FreeBSD stack of F-Stack
# finds its SYSINIT, sysctl and module records in linker sets that only
# __start_ and __stop_ references name: they keep their sections.
PROGRAM_LINK = {"fstack-probe": ("-z", "nostart-stop-gc"),
                # Without nostart-stop-gc --gc-sections drops the SYSINIT
                # sets and the stack does not come up. A main stack of 1 MiB:
                # the stack and OpenSSL (TLS under HTTP/2) run on the one
                # thread of the worker.
                "nginx-fast": ("-z", "nostart-stop-gc", "-z", "stack-size=1048576"),
                # A main stack of 1 MiB (the default is 64 KiB): the stack
                # of FreeBSD runs on the thread's stack under the program's.
                "fast-layer": ("-z", "nostart-stop-gc", "-z", "stack-size=1048576")}


def build_programs(wanted_names: list) -> list:
    """Links the programs `wanted_names` (all when empty); each needs its
    objects, built by the script of its package. Returns the names built."""
    known = program_inputs()
    unknown = [n for n in wanted_names if n not in known]
    if unknown:
        fail(f"unknown program {unknown[0]}")
    if not (SYSROOT / "lib" / "libc.so").exists():
        fail("build libc.so first: tools/build-libc-so.py build")
    if (not wanted_names or "fstack-probe" in wanted_names or "fast-layer" in wanted_names
            or "nginx-fast" in wanted_names):
        build_vnet()
    PROGRAMS.mkdir(parents=True, exist_ok=True)
    work = PROGRAMS / "obj"
    work.mkdir(exist_ok=True)
    built, lines = [], []
    for name, inputs in known.items():
        if wanted_names and name not in wanted_names:
            continue
        missing = [p for p in inputs if not p.exists()]
        if missing:
            fail(f"{name}: missing {missing[0]}: build its package first")
        stamp = PROGRAMS / f"{name}.stamp"
        wanted = "\n".join((digest(SYSROOT / "lib" / "libc.so"), digest(SYSROOT / "lib" / "crt1.o"),
                            digest(Path(__file__)),
                            *((digest(BUSYBOX_MAIN),) if name.startswith("busybox") else ()),
                            *(digest(p) for p in inputs))) + "\n"
        output = PROGRAMS / name
        if stamp.exists() and stamp.read_text() == wanted and output.exists():
            built.append(name)
            continue
        stamp.unlink(missing_ok=True)
        objects = list(inputs)
        if name.startswith("busybox"):
            compile_c(BUSYBOX_MAIN, work / f"{name}-main.o")
            objects.insert(0, work / f"{name}-main.o")
        result = link_program(output, objects, ["--gc-sections", *PROGRAM_LINK.get(name, ())],
                              capture=True)
        if result.returncode != 0:
            names = sorted(set(re.findall(r"undefined symbol: (\S+)", result.stderr)))
            fail(f"{name}: link failed; undefined: {' '.join(names) or result.stderr[-2000:]}")
        elf = Elf(output)
        why = good_checks(name, elf)
        if why:
            fail(f"program {name}: {why}")
        if name == "nginx-fast":
            fast_checks(elf)
        stamp.write_text(wanted)
        built.append(name)
    for name in built:
        elf = Elf(PROGRAMS / name)
        kinds = Counter(k for _, k, _ in elf.relocations())
        lookups = kinds["GLOB_DAT"] + kinds["JUMP_SLOT"] + kinds["ABS64"]
        lines.append(f"{name}: {(PROGRAMS / name).stat().st_size} bytes, relocations "
                     f"{dict(kinds)}, symbol lookups {lookups} (limit {LOOKUPS_MAX})")
        if lookups >= LOOKUPS_MAX or sum(kinds.values()) >= RELOCS_MAX:
            fail(f"{name}: over the limits of the loader: {lines[-1]}")
    (PROGRAMS / "report.txt").write_text("\n".join(lines) + "\n")
    return built


# ------------------------------------------------------------------- report


def report() -> str:
    path = SYSROOT / "lib" / "libc.so"
    if not path.exists():
        fail("build libc.so first: tools/build-libc-so.py build")
    elf = Elf(path)
    lines = [f"libc.so: {path.stat().st_size} bytes"]
    for name, s in elf.sections.items():
        if s["size"] and s["flags"] & 2:
            lines.append(f"  {name:<14} {s['addr']:#010x} {s['size']:>9}")
    for s in elf.segments:
        kind = {PT_LOAD: "LOAD", PT_TLS: "TLS", PT_DYNAMIC: "DYNAMIC"}.get(s["type"])
        if kind:
            flags = "".join(c if s["flags"] & b else "-" for c, b in (("R", 4), ("W", 2), ("X", 1)))
            lines.append(f"  segment {kind:<8} {s['vaddr']:#010x} filesz {s['filesz']:>8} "
                         f"memsz {s['memsz']:>8} {flags}")
    kinds = Counter(k for _, k, _ in elf.relocations())
    lines.append(f"relocations: {sum(kinds.values())} " + ", ".join(f"{k} {v}" for k, v in kinds.most_common()))
    relr = elf.sections.get(".relr.dyn", {}).get("size", 0)
    lines.append(f"  .relr.dyn {relr} bytes, .rela.dyn {elf.sections.get('.rela.dyn', {}).get('size', 0)} bytes")
    symbols = elf.dynsym()
    lines.append(f"exported names: {sum(1 for n, d, b, v, _ in symbols if d and n)}; "
                 f"longest GNU hash chain {max(elf.chain_lengths())}")
    if PROBES.exists():
        for program in sorted(p for p in PROBES.iterdir() if p.is_file() and p.suffix == ""):
            e = Elf(program)
            k = Counter(r for _, r, _ in e.relocations())
            lines.append(f"{program.name}: {program.stat().st_size} bytes, relocations "
                         f"{sum(k.values())} {dict(k)}")
    return "\n".join(lines)


def main(argv: list) -> None:
    command = argv[0] if argv and not argv[0].startswith("-") else "build"
    rest = argv[1:] if argv and not argv[0].startswith("-") else argv
    try:
        if command == "build":
            source = None
            if "--relibc-source" in rest:
                source = Path(rest[rest.index("--relibc-source") + 1]).resolve()
            build(source)
        elif command == "link":
            if len(rest) < 3 or rest[0] != "-o":
                sys.exit("usage: build-libc-so.py link -o OUT OBJECT_OR_ARCHIVE...")
            link_program(Path(rest[1]), rest[2:])
        elif command == "programs":
            print("programs:", " ".join(build_programs(rest)))
            print((PROGRAMS / "report.txt").read_text(), end="")
        elif command == "probes":
            print("probes:", " ".join(build_probes()))
        elif command == "vnet":
            print(f"libvirtio_net.a ready: {build_vnet()}")
        elif command == "report":
            print(report())
        else:
            sys.exit(f"build-libc-so: unknown subcommand {command}")
    except Failure as error:
        sys.exit(f"build-libc-so: {error}")


if __name__ == "__main__":
    main(sys.argv[1:])
