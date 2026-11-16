#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build pixman for the composition service (services/compositor) from its
pinned source archive, unchanged, as one static library.

The service is a program with no C library, so the build is freestanding:
the portable C paths of pixman (no SIMD, no threads, no timers) compiled
with the headers of ports/pixman/include standing for a C library's, and
ports/pixman/shim.c, which gives pixman the arena it allocates from and the
few functions of <math.h> and <string.h> it calls. The result is
target/pixman/libpixman.a, which lib/pixman's build script links, and
target/pixman/COPYING, the licence the notices of the package carry.

pixman is under the MIT licence: the archive is fetched at build time with
its SHA-256 checked, as the other C ports are, and the notice of the package
names it. The list of the files pixman compiles is the one of its
meson.build (pixman/meson.build, `pixman_files`) without two files that the
service never reaches, each replaced by its one function in shim.c:
pixman-combine-float.c (the combiners of the wide formats, 45 KB of code) and
pixman-access-accessors.c (the access of images with accessor functions,
33 KB): the windows are 8 bits to the channel, and no image has accessors."""

from hashlib import sha256
from pathlib import Path
import os
import shutil
import subprocess
import tarfile
from urllib.request import urlopen

import pkgdesc


PACKAGE = pkgdesc.load("pixman")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
URL = PACKAGE["url"]
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "pixman"
PORT = ROOT / "ports" / "pixman"
OUTPUT = WORK / "libpixman.a"
# The files of `pixman_files` in pixman/meson.build.
SOURCES = [
    "pixman", "pixman-access", "pixman-arm",
    "pixman-bits-image", "pixman-combine32",
    "pixman-conical-gradient", "pixman-edge", "pixman-edge-accessors",
    "pixman-fast-path", "pixman-filter", "pixman-glyph", "pixman-general",
    "pixman-gradient-walker", "pixman-image", "pixman-implementation",
    "pixman-linear-gradient", "pixman-matrix", "pixman-mips", "pixman-noop",
    "pixman-ppc", "pixman-radial-gradient", "pixman-region16",
    "pixman-region32", "pixman-region64f", "pixman-riscv",
    "pixman-solid-fill", "pixman-timer", "pixman-trap", "pixman-utils",
    "pixman-x86",
]
# Cortex-A53 erratum 835769 (the PinePhone's A64), as the other objects.
A53_ERRATA = "-mfix-cortex-a53-835769"


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
        raise SystemExit(f"missing {name}; install LLVM")
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


def main() -> None:
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    port = sha256(b"".join(p.read_bytes() for p in sorted(PORT.rglob("*")) if p.is_file())).hexdigest()
    stamp = WORK / "stamp"
    text = f"{VERSION} {SHA256} {script} {port}\n"
    if stamp.exists() and stamp.read_text() == text and OUTPUT.exists():
        print(f"pixman ready: {OUTPUT}")
        return
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    log = WORK / "build.log"
    log.write_text("")
    archive = WORK / f"pixman-{VERSION}.tar.gz"
    with urlopen(URL) as response:
        archive.write_bytes(response.read())
    if sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise SystemExit("the pixman source archive has an unexpected SHA-256")
    with tarfile.open(archive) as members:
        members.extractall(WORK, filter="data")
    source = WORK / f"pixman-{VERSION}"
    clang, ar = tool("clang", "llvm"), tool("llvm-ar", "llvm")
    include = WORK / "include"
    include.mkdir()
    # pixman-version.h from its template, the way meson writes it.
    major, minor, micro = VERSION.split(".")
    template = (source / "pixman" / "pixman-version.h.in").read_text()
    for key, value in (("MAJOR", major), ("MINOR", minor), ("MICRO", micro)):
        template = template.replace(f"@PIXMAN_VERSION_{key}@", value)
    (include / "pixman-version.h").write_text(template)
    shutil.copy(PORT / "pixman-config.h", include / "pixman-config.h")
    shutil.copy(source / "pixman" / "pixman.h", include / "pixman.h")
    shutil.copy(source / "COPYING", WORK / "COPYING")
    resource = subprocess.run([str(clang), "-print-resource-dir"], capture_output=True,
                              text=True, check=True).stdout.strip()
    cc = (str(clang), "--target=aarch64-none-elf", "-ffreestanding", "-nostdinc",
          "-isystem", str(PORT / "include"), "-isystem", f"{resource}/include",
          f"-I{include}", f"-I{source / 'pixman'}", "-DHAVE_CONFIG_H",
          "-DPIXMAN_NO_TLS", "-fno-pic", "-fno-stack-protector",
          "-ffunction-sections", "-fdata-sections", "-Os", A53_ERRATA,
          "-fasynchronous-unwind-tables", "-mllvm", "-enable-machine-outliner=never", "-w")
    (WORK / "obj").mkdir()
    objects = []
    for name in SOURCES:
        obj = WORK / "obj" / f"{name}.o"
        run(log, *cc, "-c", source / "pixman" / f"{name}.c", "-o", obj)
        objects.append(obj)
    shim = WORK / "obj" / "shim.o"
    run(log, *cc, "-fno-builtin", "-fno-math-errno", "-c", PORT / "shim.c", "-o", shim)
    objects.append(shim)
    OUTPUT.unlink(missing_ok=True)
    run(log, ar, "rcs", OUTPUT, *objects)
    stamp.write_text(text)
    print(f"pixman ready: {OUTPUT}")


if __name__ == "__main__":
    main()
