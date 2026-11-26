#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The Linux reference of the cube (`apps/gles-cube --pbuffer`): the same Mesa
(packages/mesa.toml, the same archive and SHA-256 as tools/build-mesa.py),
built for the machine it runs on with the same options as the build for
stafeto (softpipe, no LLVM, no desktop OpenGL, the surfaceless platform) and
no patch of ports/mesa, then the same gles-cube.c built against it and run.
The frame lines it prints are the reference the lines of the guest
(`cargo xtask gles-pbuffer`) are compared with: the CRC of each of the ten
frames and the sum of its bytes (plan G8, 7.3).

It builds Mesa as shared libraries, which is the stock Linux build, with clang
(the compiler of the guest's build) when CC is not set, and runs on an arm64
Linux machine: `.github/workflows/mesa-reference.yml` runs it on a GitHub
runner. Output goes to target/mesa-reference/: the log of the build, the lines
of the program (gles-cube.txt) and a comparison with the CRCs the guest is
expected to print (comparison.txt); the comparison is also printed. The exit
status is 0 whatever the comparison says, unless `--require-equal` is given.

meson 1.5 or newer, ninja, flex, bison and Python with Mako, MarkupSafe,
PyYAML and packaging are needed (tools/build-mesa.py's venv gives the
Python packages and meson when the machine lacks them)."""

from pathlib import Path
import importlib.util
import os
import re
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("build_mesa", HERE / "build-mesa.py")
bm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bm)

ROOT = bm.ROOT
WORK = ROOT / "target" / "mesa-reference"
XTASK = ROOT / "xtask" / "src" / "gles_pbuffer.rs"
# The options of the stafeto build less the ones that make static targets
# for a cross build.
OMITTED = {"default_library", "b_staticpic", "c_std"}


def native_options() -> list[str]:
    options = {k: v for k, v in bm.OPTIONS.items() if k not in OMITTED}
    return bm.meson_options(options, bm.LIBDRM_OPTIONS) + [f"--prefix={WORK / 'prefix'}"]


def expected_crcs(text: str) -> list[int]:
    """The CRCs of EXPECTED_CRCS in xtask/src/gles_pbuffer.rs."""
    block = re.search(r"EXPECTED_CRCS: Option<\[u32; FRAMES\]> = Some\(\[(.*?)\]\);", text, re.S)
    if block is None:
        return []
    return [int(n.replace("_", ""), 16) for n in re.findall(r"0x[0-9a-fA-F_]+", block[1])]


def frames(output: str) -> list[tuple[int, int, int]]:
    """The (number, CRC, sum) of each frame line of the program."""
    return [(int(m[1]), int(m[2], 16), int(m[3]))
            for m in re.finditer(r"^gles-cube: frame (\d+) crc ([0-9a-f]{8}) sum (\d+)$", output, re.M)]


def comparison(expected: list[int], seen: list[tuple[int, int, int]]) -> tuple[str, bool]:
    """A table of the frames: the CRC the guest is expected to print, the one
    this machine printed, and whether they agree."""
    lines = ["frame  expected (guest)  reference (Linux)  same"]
    same = len(expected) == len(seen) == 10
    for (number, crc, total), want in zip(seen, expected):
        equal = crc == want
        same = same and equal
        lines.append(f"{number:5}  {want:08x}          {crc:08x}           {'yes' if equal else 'NO'}"
                     f"  (sum {total})")
    if len(seen) != len(expected):
        lines.append(f"{len(seen)} frames seen, {len(expected)} expected")
    return "\n".join(lines) + "\n", same


def run(log: Path, *args, cwd: Path | None = None, env: dict | None = None) -> None:
    bm.run(log, *args, cwd=cwd, env=env)


def main() -> None:
    require = "--require-equal" in sys.argv[1:]
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    log = WORK / "build.log"
    log.write_text("")
    bm.WORK = WORK
    bm.check_options()
    ninja = bm.tool("ninja", "ninja")
    bm.tool("flex", "flex")
    bison = bm.tool("bison", "bison")
    meson, front = bm.host_tools(log)
    env = {**os.environ, "SOURCE_DATE_EPOCH": "1",
           "PATH": os.pathsep.join([*map(str, front), str(bison.parent), str(ninja.parent),
                                    os.environ.get("PATH", "")])}
    env.setdefault("CC", "clang")
    env.setdefault("CXX", "clang++")
    source = bm.unpack(bm.fetch(bm.URL, bm.SHA256, f"mesa-{bm.VERSION}.tar.xz"), WORK / "src")
    libdrm = bm.fetch(bm.LIBDRM_URL, bm.LIBDRM_SHA256, f"libdrm-{bm.LIBDRM_VERSION}.tar.xz")
    cache = source / "subprojects" / "packagecache"
    cache.mkdir(exist_ok=True)
    shutil.copy(libdrm, cache / libdrm.name)
    build = WORK / "build"
    run(log, meson, "setup", build, source, *native_options(), cwd=WORK, env=env)
    run(log, ninja, "-C", build, cwd=WORK, env=env)
    run(log, meson, "install", "-C", build, cwd=WORK, env=env)
    prefix = WORK / "prefix"
    libdir = next(p for p in (prefix / "lib", *sorted((prefix / "lib").glob("*-linux-gnu"))) if (p / "libEGL.so").exists())
    program = WORK / "gles-cube"
    run(log, env["CC"], "-O2", "-Wall", "-std=gnu11", "-I", prefix / "include",
        ROOT / "apps" / "gles-cube" / "gles-cube.c", "-o", program, "-L", libdir, "-lEGL",
        "-lGLESv2", f"-Wl,-rpath,{libdir}", env=env)
    result = subprocess.run([str(program), "--pbuffer", "--ascii", "3"], capture_output=True,
                            text=True, env={**env, "LD_LIBRARY_PATH": str(libdir)})
    (WORK / "gles-cube.txt").write_text(result.stdout + result.stderr)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(f"gles-cube ended with status {result.returncode}: {result.stderr}")
    table, same = comparison(expected_crcs(XTASK.read_text()), frames(result.stdout))
    (WORK / "comparison.txt").write_text(table)
    print(table, end="")
    if require and not same:
        raise SystemExit("the frames of the reference differ from the ones the guest is expected to print")


if __name__ == "__main__":
    main()
