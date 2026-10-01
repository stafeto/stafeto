#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Stage ABI 1 headers and optionally build its Rust static library."""

import argparse
import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "lib/posix-abi"
TARGET = "aarch64-unknown-none"


def stage() -> Path:
    constants = (SOURCE / "src/constants.rs").read_text() + (
        ROOT / "lib/posix-types/src/constants.rs").read_text()
    version = re.search(r'pub const SYSROOT_VERSION: &str = "([0-9.]+)";', constants)[1]
    destination = ROOT / "target/posix-sysroot" / version / "aarch64-stafeto"
    include = destination / "include"
    # Remove old headers so a removed interface cannot survive a rebuild.
    if include.exists():
        shutil.rmtree(include)
    shutil.copytree(SOURCE / "include", include)
    shutil.copy2(ROOT / "LICENSE", destination / "LICENSE")
    shutil.copy2(ROOT / "LICENSE-MIT", destination / "LICENSE-MIT")
    shutil.copytree(ROOT / "docs/licenses/linked_list_allocator-0.10.6",
                    destination / "licenses/linked_list_allocator-0.10.6",
                    dirs_exist_ok=True)
    values = re.findall(r"pub const ([A-Z][A-Z0-9_]*): (?:i32|u32) = ([0-9]+);", constants)
    header = ["/* SPDX-License-Identifier: GPL-3.0-or-later */",
              "/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */",
              "#ifndef STAFETO_ABI_H", "#define STAFETO_ABI_H",
              f'#define STAFETO_SYSROOT_VERSION "{version}"']
    header.extend(f"#define {name} {value}" for name, value in values)
    header.extend(["int stafeto_posix_abi_version(void);", "#endif", ""])
    (include / "stafeto").mkdir()
    (include / "stafeto/abi.h").write_text("\n".join(header))
    return destination


def compile_probe(destination: Path) -> Path:
    configured = os.environ.get("STAFETO_C_TOOL_DIR")
    brew = Path("/opt/homebrew/opt/llvm/bin")
    tools = Path(configured) if configured else (brew if brew.exists() else Path())
    output = destination / "posix-abi-probe"
    subprocess.run([str(tools / "clang"), "--target=aarch64-none-elf", "-fuse-ld=lld",
                    "-ffreestanding", "-fno-builtin", "-nostdinc", "-nostdlib",
                    "-fno-stack-protector", "-fno-pic", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-O2", "-I", str(destination / "include"),
                    # Cortex-A53 errata 835769 and 843419 (the PinePhone's A64).
                    "-mfix-cortex-a53-835769", "-Wl,--fix-cortex-a53-843419",
                    "-Wl,--gc-sections", "-Wl,-z,max-page-size=4096",
                    "-Wl,-z,separate-loadable-segments", "-Wl,-z,norelro",
                    str(ROOT / "tests/posix-abi/probe.c"), str(destination / "lib/libc.a"),
                    "-o", str(output)], cwd=ROOT, check=True)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--headers-only", action="store_true")
    parser.add_argument("--probe", action="store_true", help="also link the standalone C probe")
    options = parser.parse_args()
    if options.probe and options.headers_only:
        parser.error("--probe requires the static library")
    destination = stage()
    if not options.headers_only:
        subprocess.run(["cargo", "build", "-p", "posix-crt", "--release", "--target", TARGET],
                       cwd=ROOT, check=True)
        (destination / "lib").mkdir(exist_ok=True)
        shutil.copy2(ROOT / "target" / TARGET / "release/libposix_crt.a",
                     destination / "lib/libc.a")
    if options.probe:
        print(f"Rust POSIX standalone probe: {compile_probe(destination)}")
    print(f"Rust POSIX sysroot: {destination}")


if __name__ == "__main__":
    main()
