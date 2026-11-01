#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build probe of a shared libc for stafeto. Nothing here runs a guest.

It builds, from the relibc commit tools/build-relibc.py pins, a second
relibc archive in the position-independent model (-C relocation-model=pic,
-Z tls-model=initial-exec, -fPIC for the C), builds the POSIX layer
(posix-crt and what it pulls in) with -C relocation-model=pic, links both
with ld.lld into libc.so (-shared -Bsymbolic -z now, image base 0x04000000),
links a C hello program against it (ET_EXEC at 0x200000, -z nocopyreloc),
and prints what part 3 of the shared-library step has to deal with:
relocation counts by type, section and segment sizes, dynamic symbols,
undefined symbols, and what blocks linking at a fixed address (text
relocations, copy relocations, symbols the layer must export).

The outputs go to target/libc-so/. Run `tools/probe-libc-so.py`; a second
run reuses the relibc stamp and relinks. Options:
  --relibc-source DIR  use a relibc checkout (a clone with local changes)
                       in place of the pinned fetch
"""

import importlib.util
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "target" / "libc-so"
LIBRARY_BASE = 0x0400_0000
PROGRAM_BASE = 0x20_0000
LAYER_TARGET = "aarch64-unknown-none"
TOOLCHAIN = "nightly-2026-05-24"
LAYER_RUSTFLAGS = ("-C relocation-model=pic -C target-feature=+fix-cortex-a53-835769"
                   " -C llvm-args=--enable-machine-outliner=never")
LINK_COMMON = ["-shared", "-Bsymbolic", "-z", "now", "-z", "norelro",
               "-z", "separate-loadable-segments", "-z", "max-page-size=4096",
               "--gc-sections", "--strip-debug", "--hash-style=gnu", f"--image-base={LIBRARY_BASE:#x}", "-soname", "libc.so"]
# The program's entry: rt's `_start` (libc.so exports it) takes the start
# area in x0, calls the layer's `__rt_main` and ends the process.
CRT1 = """\
.text
.globl crt1_entry
.type crt1_entry, %function
crt1_entry:
    b _start
"""
HELLO = """\
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern char **environ;
int main(int argc, char **argv) {
    char *p = malloc(32);
    strcpy(p, "hello");
    printf("%s %d %s\\n", p, argc, environ ? "env" : "noenv");
    fputs("done\\n", stdout);
    free(p);
    return 0;
}
"""


def llvm(name: str) -> str:
    brew = Path("/opt/homebrew/opt/llvm/bin") / name
    if brew.exists():
        return str(brew)
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing {name}; install LLVM and lld")
    return found


def run(*args, cwd=None, env=None, capture=False, check=True):
    result = subprocess.run([str(a) for a in args], cwd=cwd, env=env, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None)
    if check and result.returncode != 0:
        sys.exit(f"probe-libc-so: {' '.join(str(a) for a in args)}\n"
                 f"{result.stderr if capture else ''}")
    return result


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
    env["RUSTFLAGS"] = LAYER_RUSTFLAGS
    env["CARGO_TARGET_DIR"] = str(OUT / "layer")
    # The precompiled core of the stable toolchain is static (ABS64 against
    # local symbols in .rodata), which ld.lld refuses in a shared object:
    # core, alloc and compiler_builtins are built again, with the pinned
    # nightly relibc uses (-Z build-std).
    run("cargo", f"+{TOOLCHAIN}", "build", "--release", "--locked", "-p", "posix-crt", "--target",
        LAYER_TARGET, "-Zbuild-std=core,alloc,compiler_builtins", cwd=ROOT, env=env)
    return OUT / "layer" / LAYER_TARGET / "release" / "libposix_crt.a"


def raise_visibility(libc_a: Path, layer_a: Path) -> tuple[Path, int]:
    """The layer's archive with default visibility for the names relibc also
    defines. The compiler_builtins of the layer defines memcpy, memset,
    memcmp and the libm functions weakly and hidden; the linker merges the
    visibility of a definition and its duplicates to the narrowest, so
    relibc's strong memset would turn hidden and could not be exported."""
    def names(archive, *flags):
        out = run(llvm("llvm-nm"), *flags, archive, capture=True).stdout
        return {line.split()[-1] for line in out.splitlines()
                if line.strip() and not line.endswith(":") and len(line.split()) >= 2}
    mine = names(libc_a, "--defined-only", "--extern-only")
    theirs = names(layer_a, "--extern-only")
    shared = sorted(mine & theirs)
    work = OUT / "layer-vis"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    listing = work / "names.txt"
    listing.write_text("".join(f"{n}\n" for n in shared))
    run(llvm("llvm-ar"), "x", layer_a, cwd=work)
    members = sorted(m for m in work.glob("*.o"))
    for member in members:
        run(llvm("llvm-objcopy"), f"--set-symbols-visibility={listing}=default", member)
    result = OUT / "libposix_crt_vis.a"
    result.unlink(missing_ok=True)
    run(llvm("llvm-ar"), "crs", result, *members)
    return result, len(shared)


def link_so(name: str, libc_a: Path, layer_a: Path, extra: list) -> Path:
    path = OUT / name
    run("ld.lld", *LINK_COMMON, *extra, "-o", path, "--whole-archive", libc_a, layer_a,
        "--no-whole-archive")
    return path


def readelf(*args) -> str:
    return run(llvm("llvm-readelf"), "--wide", *args, capture=True).stdout


def nm(path: Path, *flags) -> list:
    return [line.split() for line in
            run(llvm("llvm-nm"), "-D", *flags, path, capture=True).stdout.splitlines()]


def sections(path: Path) -> dict:
    found = {}
    for line in readelf("-S", path).splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)"
                     r"\s+\S+\s+(\S*)", line)
        if m and m.group(1) != "NULL":
            found[m.group(1)] = (m.group(2), int(m.group(3), 16), int(m.group(4), 16),
                                 m.group(5))
    return found


def segments(path: Path) -> list:
    found = []
    for line in readelf("-l", path).splitlines():
        m = re.match(r"\s*(LOAD|TLS|DYNAMIC|GNU_RELRO)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+"
                     r"0x[0-9a-f]+\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+([RWE ]+?)\s+0x([0-9a-f]+)",
                     line)
        if m:
            found.append((m.group(1), int(m.group(3), 16), int(m.group(4), 16),
                          int(m.group(5), 16), m.group(6).strip(), int(m.group(2), 16)))
    return found


def relocations(path: Path) -> list:
    """(offset, type, symbol) of every dynamic relocation, RELR included."""
    found = []
    for line in readelf("-r", path).splitlines():
        m = re.match(r"\s*([0-9a-f]{8,16})\s+[0-9a-f]+\s+(R_AARCH64_\w+)\s*([0-9a-f]*)\s*(\S*)",
                     line)
        if m:
            found.append((int(m.group(1), 16), m.group(2), m.group(4)))
    return found


def dynamic_flags(path: Path) -> str:
    return readelf("-d", path)


def sizes_report(title: str, path: Path) -> list:
    lines = [f"== {title}: {path.name} ({path.stat().st_size} bytes on disk) =="]
    secs = sections(path)
    for name, (kind, addr, size, flags) in secs.items():
        if size and name not in (".comment", ".symtab", ".strtab", ".shstrtab"):
            lines.append(f"  {name:<18} {kind:<14} {addr:#010x} {size:>8} {flags}")
    lines.append("  segments (type, vaddr, filesz, memsz, flags):")
    for kind, vaddr, filesz, memsz, flags, _ in segments(path):
        lines.append(f"    {kind:<8} {vaddr:#010x} {filesz:>8} {memsz:>8} {flags}")
    return lines


def count_report(title: str, relocs: list) -> list:
    count = Counter(kind for _, kind, _ in relocs)
    lines = [f"== {title}: {len(relocs)} dynamic relocations =="]
    for kind, number in count.most_common():
        lines.append(f"  {kind:<28} {number:>7}")
    return lines


def text_relocations(path: Path, relocs: list) -> list:
    """Relocations whose target lies in a segment that is not writable."""
    writable = [(v, v + m) for kind, v, _, m, flags, _ in segments(path)
                if kind == "LOAD" and "W" in flags]
    return [r for r in relocs if not any(lo <= r[0] < hi for lo, hi in writable)
            and not r[1].startswith("R_AARCH64_JUMP_SLOT")]


def exported_names(sysroot: Path, defined: set) -> set:
    """Defined global names a header of relibc (or openlibm) declares."""
    words = set()
    for header in (sysroot / "include").rglob("*.h"):
        words.update(re.findall(r"[A-Za-z_]\w*", header.read_text(errors="replace")))
    return defined & words


def main() -> None:
    source = None
    if "--relibc-source" in sys.argv:
        source = Path(sys.argv[sys.argv.index("--relibc-source") + 1]).resolve()
    OUT.mkdir(parents=True, exist_ok=True)
    sysroot = build_relibc(source)
    libc_a = sysroot / "lib" / "libc.a"
    layer_a = build_layer()
    report = []
    layer_a, raised = raise_visibility(libc_a, layer_a)
    report.append(f"layer archive: {raised} names shared with relibc raised to default visibility")

    # 1. libc.so, everything exported, plain RELA relocations (the counts),
    # then packed (RELR, the sizes), then with the version script.
    plain = link_so("libc-all.so", libc_a, layer_a, [])
    packed = link_so("libc-packed.so", libc_a, layer_a, ["-z", "pack-relative-relocs"])
    defined = {row[-1] for row in nm(plain, "--defined-only") if len(row) >= 3}
    exported = exported_names(sysroot, defined)
    # The layer's start (rt's `_start`; stafeto_start joins it in part 3) and
    # the variables C programs declare for themselves.
    exported |= {"_start", "environ"} & defined
    script = OUT / "libc.map"
    script.write_text("{ global:\n" + "".join(f"  {n};\n" for n in sorted(exported))
                      + " local: *; };\n")
    final = link_so("libc.so", libc_a, layer_a,
                    ["-z", "pack-relative-relocs", f"--version-script={script}"])
    # The same with RELA, whose entries the counts below read, and which the
    # programs link against.
    final_rela = link_so("libc-rela.so", libc_a, layer_a, [f"--version-script={script}"])

    # 2. Programs against libc.so: the small hello above and the C program
    # of the guest probe tests/relibc-hello (hundreds of calls).
    crt1 = OUT / "crt1.S"
    crt1.write_text(CRT1)
    hello_c = OUT / "hello.c"
    hello_c.write_text(HELLO)
    clang = llvm("clang")
    run(clang, "--target=aarch64-linux-gnu", "-c", crt1, "-o", OUT / "crt1.o")
    programs = {}
    for name, source in (("hello", hello_c), ("hello-big", ROOT / "tests/relibc-hello/hello.c")):
        run(clang, "--target=aarch64-linux-gnu", "-mfix-cortex-a53-835769", "-nostdinc",
            "-fno-stack-protector", "-fPIC", "-fno-builtin", "-std=c11", "-O2",
            "-isystem", sysroot / "include", "-c", source, "-o", OUT / f"{name}.o")
        path = OUT / name
        link = run("ld.lld", "-z", "now", "-z", "nocopyreloc", "-z", "norelro",
                   "-z", "separate-loadable-segments", "-z", "max-page-size=4096",
                   "--gc-sections", "--strip-debug", "--hash-style=gnu", f"--image-base={PROGRAM_BASE:#x}",
                   "--dynamic-linker=/lib/ld.so", "-e", "crt1_entry", "-o", path,
                   OUT / "crt1.o", OUT / f"{name}.o", final_rela, capture=True, check=False)
        report.append(f"== {name} link ==")
        if link.returncode == 0:
            report.append("  ok")
            programs[name] = path
        else:
            report.append("  FAILED:\n" + "\n".join("    " + s for s in link.stderr.splitlines()[:30]))

    # 3. Numbers.
    all_relocs = relocations(plain)
    final_relocs = relocations(final_rela)
    report += count_report("libc.so (version script)", final_relocs)
    report.append(f"  RELR form: {sections(final)['.relr.dyn'][2]} bytes against "
                  f"{sections(final_rela)['.rela.dyn'][2]} bytes of RELA")
    report += sizes_report("RELA, all exported", plain)
    report += sizes_report("RELR, all exported", packed)
    report += sizes_report("RELR, version script", final)
    dyn_all = len([r for r in nm(plain, "--defined-only")])
    dyn_final = len(nm(final, "--defined-only"))
    report.append(f"== dynamic symbols ==\n  defined, all exported: {dyn_all}\n"
                  f"  defined, header names + _start + environ: {dyn_final}")
    undefined = sorted({row[-1] for row in nm(plain, "--undefined-only") if row})
    report.append(f"  undefined in libc.so: {len(undefined)}: {' '.join(undefined)}")
    unexported = sorted(n for n in defined if n.startswith(("stafeto_", "relibc_")))
    report.append(f"  stafeto_/relibc_ names defined (internal under the script): "
                  f"{len(unexported)}")

    # 4. Fixed-address blockers.
    report.append("== fixed address blockers ==")
    for name, path, relocs in (("libc.so", final, final_relocs),
                               ("libc.so (RELA)", plain, all_relocs)):
        text = text_relocations(path, relocs)
        flags = dynamic_flags(path)
        report.append(f"  {name}: relocations outside writable segments: {len(text)}"
                      f" {sorted({r[1] for r in text})}; DT_TEXTREL: "
                      f"{'TEXTREL' in flags}")
    bad = {k: v for k, v in Counter(k for _, k, _ in all_relocs).items()
           if k.split("R_AARCH64_")[1] in ("COPY", "IRELATIVE", "TLSDESC", "TLS_DTPMOD64",
                                           "TLS_DTPREL64")}
    report.append(f"  libc.so unsupported kinds (COPY IRELATIVE TLSDESC DTPMOD DTPREL): {bad}")
    tls = [s for s in segments(final) if s[0] == "TLS"]
    report.append(f"  libc.so PT_TLS: {[(hex(s[1]), s[2], s[3]) for s in tls]}")
    for name, path in programs.items():
        relocs = relocations(path)
        report += count_report(name, relocs)
        report += sizes_report(name, path)
        needed = re.findall(r"NEEDED.*\[(.*)\]", dynamic_flags(path))
        report.append(f"  {name} NEEDED: {needed}; COPY relocations: "
                      f"{sum(1 for r in relocs if r[1] == 'R_AARCH64_COPY')}; "
                      f"symbols imported: {len({r[2] for r in relocs if r[2]})}; "
                      f"undefined: "
                      f"{sorted({row[-1] for row in nm(path, '--undefined-only') if row})[:40]}")
        report.append(f"  {name} exports to libc.so: "
                      f"{sorted(row[-1] for row in nm(path, '--defined-only') if row)}")
    # What the layer needs from the program.
    report.append("  libc.so symbols the program must define: "
                  + (" ".join(n for n in undefined if n in ("main", "__ehdr_start")) or "none"))
    text = "\n".join(report) + "\n"
    (OUT / "report.txt").write_text(text)
    print(text)


if __name__ == "__main__":
    main()
