#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build the pinned AArch64 Picolibc used by `cargo xtask cprobe`."""

from pathlib import Path
import shutil
import subprocess


VERSION = "1.8.12"
COMMIT = "2ae376c6cdf4fef90ca2388ecf7a07457fa63cff"
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "picolibc"
SOURCE = WORK / "source"
BUILD = WORK / "build"
DEST = WORK / "root"
STAMP = WORK / "config"
CONFIG = f"{VERSION} {COMMIT} aarch64-none-elf no-tls posix-console heap=1048576 integer\n"


def run(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(args, cwd=cwd, check=True)


def tool(name: str, brew_formula: str | None = None) -> Path:
    if brew_formula:
        path = Path(f"/opt/homebrew/opt/{brew_formula}/bin/{name}")
        if path.exists():
            return path
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing {name}; install LLVM, lld, Meson and Ninja")
    return Path(found).resolve()


def main() -> None:
    output = DEST / "usr" / "lib" / "libc.a"
    if output.exists() and STAMP.exists() and STAMP.read_text() == CONFIG:
        print(f"Picolibc ready: {DEST / 'usr'}")
        return
    WORK.mkdir(parents=True, exist_ok=True)
    if not SOURCE.exists():
        run("git", "clone", "--depth", "1", "--branch", VERSION,
            "https://github.com/picolibc/picolibc.git", str(SOURCE))
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SOURCE, text=True).strip()
    if revision != COMMIT:
        raise SystemExit(f"Picolibc {VERSION} resolved to unexpected commit {revision}")
    clang = tool("clang", "llvm")
    llvm_dir = clang.parent
    linker = tool("ld.lld", "lld")
    cross = WORK / "aarch64-none-elf.txt"
    cross.write_text(
        "[binaries]\n"
        f"c = [{str(clang)!r}, '--target=aarch64-none-elf', '-nostdlib', '-fuse-ld={linker}']\n"
        f"cpp = [{str(clang)!r}, '--target=aarch64-none-elf', '-nostdlib', '-fuse-ld={linker}']\n"
        f"ar = {str(llvm_dir / 'llvm-ar')!r}\n"
        f"nm = {str(llvm_dir / 'llvm-nm')!r}\n"
        f"strip = {str(llvm_dir / 'llvm-strip')!r}\n"
        "[host_machine]\n"
        "system = 'none'\n"
        "cpu_family = 'aarch64'\n"
        "cpu = 'aarch64'\n"
        "endian = 'little'\n"
        "[properties]\n"
        "skip_sanity_check = true\n"
    )
    setup = ["meson", "setup"]
    if BUILD.exists():
        setup.append("--wipe")
    run(*setup, str(BUILD), "--cross-file", str(cross), "--prefix=/usr",
        "-Dmultilib=false", "-Dpicocrt=false", "-Dsemihost=false",
        "-Dthread-local-storage=false", "-Dposix-console=true",
        "-Dinternal-heap=1048576", "-Dformat-default=integer", "-Dtests=false", cwd=SOURCE)
    run("meson", "compile", "-C", str(BUILD), "-j", "8")
    run("meson", "install", "-C", str(BUILD), "--destdir", str(DEST))
    if not output.exists():
        raise SystemExit("Picolibc installation did not produce libc.a")
    STAMP.write_text(CONFIG)
    print(f"Picolibc ready: {DEST / 'usr'}")


if __name__ == "__main__":
    main()
