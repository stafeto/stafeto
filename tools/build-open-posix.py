#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Compile the Open POSIX Test Suite for stafeto (`cargo xtask open-posix`).

The suite is the one the LTP release 20260930 ships in
testcases/open_posix_testsuite (GPL-2.0-only, Intel and others). The
release archive is downloaded into target/open-posix, checked against the
pinned SHA-256 and unpacked there; its sources are used as they are and are
not part of this repository.

The tests are picked as the suite's own scripts/locate-test picks them:
conformance and stress `*[0-9].c` and `[0-9]*-[0-9]*.sh`, every .c of
functional, and the `*buildonly*.c` files, which are only compiled. Each
test is compiled with the flags of include/mk/config.mk.in and relibc's
headers into an object of its own; lib/common.c, which gives the tests their
`main`, is compiled once. The libraries of the suite's LDLIBS files
(-lpthread -lrt) are part of relibc's libc.a, so nothing is added to a link.

Writes target/open-posix/tests.tsv, a line a test with four tab-separated
fields: the name (`conformance/interfaces/fork/1-1`), the kind, the object
path (or `!failure` when the compilation failed) and the first diagnostic.
The kinds: RUN (compiled; boot and run), BUILDONLY (compiled; the compile
is the whole test), SCRIPT (a shell script of the suite, not run), ARGS
(the suite starts it with arguments from a .args file, not run)."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
from urllib.request import urlopen

RELEASE = "20260930"
URL = (f"https://github.com/linux-test-project/ltp/releases/download/{RELEASE}/"
       f"ltp-full-{RELEASE}.tar.xz")
SHA256 = "b9837481134fa6eabce91c2fba57d96695f81360468f83e11e6982584ad4d29d"
PREFIX = f"ltp-full-{RELEASE}/testcases/open_posix_testsuite/"
ROOT = Path(__file__).resolve().parents[1]
WORK = Path(os.environ.get("STAFETO_OPEN_POSIX_WORK", ROOT / "target" / "open-posix"))
ARCHIVE = WORK / f"ltp-full-{RELEASE}.tar.xz"
SOURCE = WORK / "source"
OBJECTS = WORK / "objects"
LIST = WORK / "tests.tsv"
STAMP = WORK / "stamp"
INCLUDE = Path(os.environ.get("STAFETO_RELIBC_SYSROOT", ROOT / "target" / "relibc" / "sysroot")) / "include"
SECTIONS = ("conformance/interfaces", "conformance/definitions", "conformance/behavior",
            "functional", "stress")
# include/mk/config.mk.in, with relibc's headers and the C ABI they describe.
FLAGS = ("--target=aarch64-linux-gnu", "-nostdinc", "-isystem", str(INCLUDE),
         "-mno-outline-atomics", "-mllvm", "-enable-machine-outliner=never",
         "-mfix-cortex-a53-835769", "-fno-stack-protector", "-fno-pic",
         "-g0", "-O2", "-w", f"-fmacro-prefix-map={SOURCE}/=", "-std=c99", "-D_POSIX_C_SOURCE=200809L", "-D_XOPEN_SOURCE=700")


def relibc_commit() -> str:
    spec = importlib.util.spec_from_file_location(
        "build_relibc", ROOT / "tools" / "build-relibc.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.COMMIT


def clang() -> str:
    brew = Path("/opt/homebrew/opt/llvm/bin/clang")
    if brew.exists():
        return str(brew)
    found = shutil.which("clang")
    if found is None:
        raise SystemExit("missing clang; install LLVM")
    return found


# Mistakes of the suite that stop a test from compiling anywhere: the member
# `cid` that `stress1.c` of pthread_cond_wait sets is missing from its
# `struct childdata` (the file of pthread_cond_timedwait has it).
SOURCE_FIXES = {
    "stress/threads/pthread_cond_wait/stress1.c": (
        "\tint fork;\n\tint *pBool;\n};",
        "\tint fork;\n\tint *pBool;\n\tclockid_t cid;\n};",
    ),
}


def fetch() -> None:
    """Download the release (once), check it, unpack the suite alone."""
    done = SOURCE / ".unpacked"
    if done.exists() and done.read_text() == SHA256:
        return
    WORK.mkdir(parents=True, exist_ok=True)
    if not ARCHIVE.exists() or hashlib.sha256(ARCHIVE.read_bytes()).hexdigest() != SHA256:
        with urlopen(URL) as response:
            ARCHIVE.write_bytes(response.read())
    digest = hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()
    if digest != SHA256:
        ARCHIVE.unlink()
        raise SystemExit(f"{URL}: SHA-256 {digest}, expected {SHA256}")
    if SOURCE.exists():
        shutil.rmtree(SOURCE)
    SOURCE.mkdir()
    with tarfile.open(ARCHIVE) as tar:
        for member in tar:
            if not member.name.startswith(PREFIX) or not member.isfile():
                continue
            relative = member.name[len(PREFIX):]
            if ".." in Path(relative).parts:
                raise SystemExit(f"unsafe name in the archive: {member.name}")
            target = SOURCE / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(tar.extractfile(member).read())
    for name, (old, new) in SOURCE_FIXES.items():
        path = SOURCE / name
        text = path.read_text()
        if old not in text:
            raise SystemExit(f"{name}: the text to fix is not there")
        path.write_text(text.replace(old, new, 1))
    done.write_text(SHA256)


def inventory() -> list[tuple[str, str, Path]]:
    """(name, kind, source path) of every test, sorted by name."""
    rows = []
    for section in SECTIONS:
        for path in sorted((SOURCE / section).rglob("*")):
            if not path.is_file() or path.suffix not in (".c", ".sh"):
                continue
            relative = path.relative_to(SOURCE)
            name = str(relative.with_suffix(""))
            base = path.name
            buildonly = "buildonly" in base
            if path.suffix == ".sh":
                if section == "functional" or not re.fullmatch(r"[0-9]+-[0-9]+\.sh", base):
                    continue
                rows.append((name, "SCRIPT", path))
            elif buildonly:
                rows.append((name, "BUILDONLY", path))
            elif section == "functional" or re.search(r"[0-9]\.c$", base):
                if "testfrmw" in relative.parts:
                    continue
                kind = "ARGS" if path.with_suffix(".args").exists() else "RUN"
                rows.append((name, kind, path))
    return sorted(rows)


def directory_flags(directory: Path) -> list[str]:
    """The suite's CFLAGS file of a directory (a shell word list; the one
    case of the release is a probe for -Wno-overflow, which clang takes)."""
    flags = []
    for parent in (directory, *directory.parents):
        if parent == SOURCE.parent:
            break
        file = parent / "CFLAGS"
        if file.exists():
            text = file.read_text().strip()
            flags += ["-Wno-overflow"] if text.startswith("`") else text.split()
    return flags


def first_error(errors: str) -> str:
    line = next((l for l in errors.splitlines() if "error:" in l), errors.strip()[:200])
    return line.replace(str(SOURCE) + "/", "").replace("\t", " ")[:300]


def compile_one(compiler: str, name: str, kind: str, source: Path) -> tuple[str, str, str, str]:
    if kind in ("SCRIPT", "ARGS"):
        return (name, kind, "-", "")
    target = OBJECTS / (hashlib.sha1(name.encode()).hexdigest()[:12] + ".o")
    command = [compiler, *FLAGS, "-I", str(SOURCE / "include"), "-I", str(source.parent),
               *directory_flags(source.parent), "-c", str(source), "-o", str(target)]
    result = subprocess.run(command, cwd=source.parent, capture_output=True, text=True)
    if result.returncode == 0:
        return (name, kind, str(target), "")
    return (name, kind, "!compile", first_error(result.stderr))


def main() -> None:
    if not (INCLUDE / "stdio.h").exists():
        raise SystemExit("build relibc with cargo xtask relibc first")
    fetch()
    tests = inventory()
    compiler = clang()
    script = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    config = f"{RELEASE} {SHA256} relibc {relibc_commit()} {' '.join(FLAGS)} script {script}\n"
    if STAMP.exists() and STAMP.read_text() == config and LIST.exists():
        print(f"open-posix objects ready: {LIST}")
        return
    if OBJECTS.exists():
        shutil.rmtree(OBJECTS)
    OBJECTS.mkdir(parents=True)
    common = OBJECTS / "common.o"
    subprocess.run([compiler, *FLAGS, "-I", str(SOURCE / "include"), "-c",
                    str(SOURCE / "lib" / "common.c"), "-o", str(common)], check=True)
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        rows = list(pool.map(lambda t: compile_one(compiler, *t), tests))
    LIST.write_text("".join("\t".join(row) + "\n" for row in rows))
    (WORK / "common.txt").write_text(str(common) + "\n")
    STAMP.write_text(config)
    print(f"open-posix objects ready: {LIST} ({len(rows)} tests)")


if __name__ == "__main__":
    main()
