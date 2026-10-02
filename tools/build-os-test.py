#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Compile os-test's suites for stafeto (`cargo xtask os-test`): Sortix's
os-test (ISC) at a pinned commit, its io and malloc suites, each test with
relibc's headers (target/relibc/sysroot, cargo xtask relibc) into an
object of its own under target/os-test/objects. A test that does not
compile gets os-test's outcome for it (compile.sh: missing_header,
undeclared, ...). Writes target/os-test/tests.txt, a line a test:
`suite/test object-path` or `suite/test !outcome`; the expectations stay in
target/os-test/source/<suite>.expect. A stamp of both commits makes a
second run do nothing."""

import importlib.util
from pathlib import Path
import re
import shutil
import subprocess


REPOSITORY = "https://gitlab.com/sortix/os-test.git"
COMMIT = "f8144f0215ea265fd46281e29271d8e857a6856e"
SUITES = ("io", "malloc")
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "os-test"
SOURCE = WORK / "source"
OBJECTS = WORK / "objects"
LIST = WORK / "tests.txt"
STAMP = WORK / "stamp"
INCLUDE = ROOT / "target" / "relibc" / "sysroot" / "include"
# os-test's compile.sh, with the C ABI relibc's headers describe.
FLAGS = ("--target=aarch64-linux-gnu", "-nostdinc", "-isystem", str(INCLUDE),
         "-mno-outline-atomics", "-mfix-cortex-a53-835769", "-fno-stack-protector",
         "-O2", "-Wall", "-Wextra", "-Werror=implicit-function-declaration",
         "-D_GNU_SOURCE", "-D_BSD_SOURCE", "-D_ALL_SOURCE", "-D_DEFAULT_SOURCE")


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


def outcome(errors: str, source: str) -> str:
    """os-test's misc/compile.sh: the outcome of a test that did not
    compile, by its first error."""
    if re.search(r"^/\*optional\*/$", source, re.M):
        return "missing_optional"
    first = next((line for line in errors.splitlines()
                  if "error:" in line and "type specifier missing," not in line), "")
    if "fatal error" in first:
        return "missing_header"
    if re.search(r"incompatible|pointer-sign", first):
        return "incompatible"
    if re.search(r"undeclared|no member named|is not defined", first):
        return "undeclared"
    if re.search(r"unknown type name|Wvisibility|expected declaration specifiers"
                 r"|function cannot return function type|storage size of"
                 r"|declared inside parameter list|tentative definition has type"
                 r"|expected identifier|a parameter list without types", first):
        return "unknown_type"
    return "compile_error"


def fetch() -> None:
    if SOURCE.exists() and subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=SOURCE, capture_output=True,
            text=True).stdout.strip() == COMMIT:
        return
    if SOURCE.exists():
        shutil.rmtree(SOURCE)
    WORK.mkdir(parents=True, exist_ok=True)
    # The suites, their expectations and misc/ alone: the other suites'
    # file names collide on a case-insensitive file system.
    subprocess.run(["git", "clone", "--quiet", "--no-checkout", REPOSITORY, str(SOURCE)],
                   check=True)
    subprocess.run(["git", "sparse-checkout", "set", "--no-cone", "/misc/", "/LICENSE",
                    *(f"/{suite}/" for suite in SUITES),
                    *(f"/{suite}.expect/" for suite in SUITES)], cwd=SOURCE, check=True)
    subprocess.run(["git", "checkout", "--quiet", COMMIT], cwd=SOURCE, check=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=SOURCE, capture_output=True,
                          text=True, check=True).stdout.strip()
    if head != COMMIT:
        raise SystemExit(f"os-test is at {head}, not {COMMIT}")


def main() -> None:
    if not (INCLUDE / "stdio.h").exists():
        raise SystemExit("build relibc with cargo xtask relibc first")
    config = f"{COMMIT} relibc {relibc_commit()} {' '.join(FLAGS)}\n"
    if STAMP.exists() and STAMP.read_text() == config and LIST.exists():
        print(f"os-test objects ready: {LIST}")
        return
    fetch()
    if OBJECTS.exists():
        shutil.rmtree(OBJECTS)
    compiler = clang()
    lines = []
    for suite in SUITES:
        (OBJECTS / suite).mkdir(parents=True)
        for test in sorted((SOURCE / suite).glob("*.c")):
            name = f"{suite}/{test.stem}"
            target = OBJECTS / suite / f"{test.stem}.o"
            result = subprocess.run([compiler, *FLAGS, "-c", str(test), "-o", str(target)],
                                    cwd=SOURCE / suite, capture_output=True, text=True)
            if result.returncode == 0:
                lines.append(f"{name} {target}")
            else:
                lines.append(f"{name} !{outcome(result.stderr, test.read_text())}")
    LIST.write_text("\n".join(lines) + "\n")
    STAMP.write_text(config)
    print(f"os-test objects ready: {LIST}")


if __name__ == "__main__":
    main()
