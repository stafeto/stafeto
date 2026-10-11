#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Compile os-test's suites for stafeto (`cargo xtask os-test`): Sortix's
os-test (ISC) at a pinned commit, its io, malloc, process, signal
and pty suites and the parts of its basic suite that start programs: basic/spawn,
the tests of basic/unistd named exec*, basic/unistd/getentropy (5e'), and
the tests of every part of basic/ that call fork; each test with relibc's headers
(target/relibc/sysroot, cargo xtask relibc) into an object of its own
under target/os-test/objects. A test that does not compile gets os-test's
outcome for it (compile.sh: missing_header, undeclared, ...). Writes
target/os-test/tests.txt, a line a test: `suite/test object-path` or
`suite/test !outcome` (basic tests are named basic/<part>/<test>); the
expectations stay in target/os-test/source/<suite>.expect, which the basic
suite has none of: its tests pass with the outcome `exit: 0`. A stamp of
both commits makes a second run do nothing.

--full-basic compiles all 1187 basic sources from the pinned Git objects
into a separate target/os-test-full. Numbered sources/objects, exact Git
inventory, source mapping and compilation diagnostics preserve every row
without changing the ordinary composition or its stamp."""

import importlib.util
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time


REPOSITORY = "https://gitlab.com/sortix/os-test.git"
COMMIT = "f8144f0215ea265fd46281e29271d8e857a6856e"
SUITES = ("io", "malloc", "process", "signal", "pty")
# The parts of the basic suite and which of their tests run: a glob, or
# None for the tests that call fork (5d) or pipe (5e). Readiness groups
# poll, sys_select and termios include every test explicitly (5f).
BASIC = (("spawn", "*.c"), ("unistd", "*exec*.c"), ("unistd", "getentropy.c"),
         ("unistd", None),
         ("nl_types", None), ("poll", "*.c"), ("pthread", None), ("signal", None),
         ("stdlib", None), ("sys_select", "*.c"), ("sys_wait", None), ("termios", "*.c"),
         ("fmtmsg", None), ("stdio", None), ("wchar", None))
FORK = re.compile(r"(^|[^_\w])(v?fork|pipe2?)\(")
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "os-test"
SOURCE = WORK / "source"
OBJECTS = WORK / "objects"
LIST = WORK / "tests.txt"
STAMP = WORK / "stamp"
INCLUDE = Path(os.environ.get("STAFETO_RELIBC_SYSROOT", ROOT / "target" / "relibc" / "sysroot")) / "include"
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
    at_commit = SOURCE.exists() and subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=SOURCE, capture_output=True,
        text=True).stdout.strip() == COMMIT
    if at_commit and all((SOURCE / suite).exists() for suite in SUITES) \
            and all((SOURCE / "basic" / part).exists() for part, _ in BASIC):
        return
    if not at_commit:
        if SOURCE.exists():
            shutil.rmtree(SOURCE)
        WORK.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--quiet", "--no-checkout", REPOSITORY, str(SOURCE)],
                       check=True)
    # The suites, their expectations and misc/ alone: the other suites'
    # file names collide on a case-insensitive file system. A clone at the
    # commit with fewer parts takes the new ones.
    subprocess.run(["git", "sparse-checkout", "set", "--no-cone", "/misc/", "/LICENSE",
                    "/basic/basic.h", *(f"/basic/{part}/" for part, _ in BASIC),
                    *(f"/{suite}/" for suite in SUITES),
                    *(f"/{suite}.expect/" for suite in SUITES)], cwd=SOURCE, check=True)
    subprocess.run(["git", "checkout", "--quiet", COMMIT], cwd=SOURCE, check=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=SOURCE, capture_output=True,
                          text=True, check=True).stdout.strip()
    if head != COMMIT:
        raise SystemExit(f"os-test is at {head}, expected {COMMIT}")


def git_inventory(repository: Path, prefix: str) -> list[str]:
    """Read exact case-sensitive names from Git, not the host checkout."""
    result = subprocess.run(["git", "ls-tree", "-r", "--name-only", COMMIT,
                             "--", prefix], cwd=repository, check=True,
                            capture_output=True, text=True)
    return sorted(result.stdout.splitlines())


def git_blobs(repository: Path, paths: list[str]) -> dict[str, bytes]:
    requests = "".join(f"{COMMIT}:{path}\n" for path in paths).encode()
    result = subprocess.run(["git", "cat-file", "--batch"], cwd=repository,
                            input=requests, capture_output=True, check=True)
    blobs = {}
    cursor = 0
    for path in paths:
        end = result.stdout.index(b"\n", cursor)
        header = result.stdout[cursor:end].split()
        if len(header) != 3 or header[1] != b"blob":
            raise RuntimeError(f"os-test Git blob missing: {path}")
        size = int(header[2])
        cursor = end + 1
        blobs[path] = result.stdout[cursor:cursor + size]
        cursor += size + 1
    if cursor != len(result.stdout):
        raise RuntimeError("unexpected trailing os-test Git blobs")
    return blobs


def compile_full_basic(repository: Path, work: Path, compiler: str,
                       expected: int = 1187) -> None:
    paths = git_inventory(repository, "basic")
    tests = [path for path in paths if path.endswith(".c")]
    if len(tests) != expected or len(set(tests)) != expected:
        raise RuntimeError(f"os-test basic inventory: {len(tests)}, expected {expected}")
    inventory = "".join(f"{number:06d}\t{path}\n" for number, path in enumerate(tests))
    flags = (*FLAGS, "-fno-builtin")
    config = (f"full-basic {COMMIT} relibc {relibc_commit()} {' '.join(flags)} "
              f"builder {hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}\n")
    stamp = work / "stamp"
    if stamp.exists() and stamp.read_text() == config \
            and (work / "inventory.tsv").exists() \
            and (work / "inventory.tsv").read_text() == inventory \
            and (work / "tests.txt").exists() and (work / "sources.txt").exists():
        rows = (work / "tests.txt").read_text().splitlines()
        names = [str(Path(path).with_suffix("")) for path in tests]
        if [row.split(" ", 1)[0] for row in rows] == names:
            print(f"os-test full basic objects ready: {work / 'tests.txt'}")
            return
    work.mkdir(parents=True, exist_ok=True)
    for directory in (work / "source", work / "objects"):
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir()
    # Preserve all genuine relative includes (including ../sys_select/select.c),
    # while each separately compiled test has its own numbered source path.
    dependencies = work / "source" / "dependencies"
    blobs = git_blobs(repository, paths + git_inventory(repository, "misc") + ["LICENSE"])
    for path, body in blobs.items():
        target = dependencies / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    (work / "source" / "LICENSE").write_bytes(blobs["LICENSE"])
    rows, sources, diagnostics = [], [], []
    environment = os.environ.copy()
    for variable in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH"):
        environment.pop(variable, None)
    for number, path in enumerate(tests):
        name = str(Path(path).with_suffix(""))
        source = work / "source" / f"{number:06d}" / Path(path).name
        source.parent.mkdir()
        source.write_bytes(blobs[path])
        target = work / "objects" / f"{number:06d}.o"
        began = time.monotonic()
        result = subprocess.run([compiler, *flags, "-iquote",
                                 str(dependencies / Path(path).parent),
                                 "-c", str(source), "-o", str(target)],
                                cwd=dependencies / Path(path).parent,
                                capture_output=True, text=True, env=environment)
        elapsed = time.monotonic() - began
        classification = "good" if result.returncode == 0 else outcome(
            result.stderr, blobs[path].decode())
        rows.append(f"{name} {target}" if result.returncode == 0 else
                    f"{name} !{classification}")
        sources.append(f"{name}\t{source.resolve()}")
        # Full diagnostics remain beside each object; the map carries a bounded
        # single-line tail, so one failure cannot consume the whole census.
        target.with_suffix(".err").write_text(result.stderr)
        tail = result.stderr[-2048:].replace("\t", " ").replace("\n", "\\n")
        diagnostics.append(f"{name}\t{classification}\t{elapsed:.6f}\t{tail}")
    (work / "inventory.tsv").write_text(inventory)
    (work / "tests.txt").write_text("\n".join(rows) + "\n")
    (work / "sources.txt").write_text("\n".join(sources) + "\n")
    (work / "compile.tsv").write_text("\n".join(diagnostics) + "\n")
    stamp.write_text(config)
    print(f"os-test full basic objects ready: {work / 'tests.txt'} ({len(rows)} rows)")


def main() -> None:
    if not (INCLUDE / "stdio.h").exists():
        raise SystemExit("build relibc with cargo xtask relibc first")
    args = sys.argv[1:]
    if args == ["--full-basic"]:
        fetch()
        compile_full_basic(SOURCE, ROOT / "target" / "os-test-full", clang())
        return
    if args and (len(args) != 2 or args[0] != "--suite"):
        raise SystemExit("usage: build-os-test.py [--suite NAME | --full-basic]")
    selected = args[1] if args else None
    parts = [(suite, suite, "*.c") for suite in SUITES]
    parts += [(f"basic/{part}", f"basic/{part}", pattern) for part, pattern in BASIC]
    if selected is not None:
        parts = [part for part in parts if part[0] == selected]
        if not parts:
            raise SystemExit(f"unknown os-test suite: {selected}")
    config = f"{COMMIT} {SUITES} {BASIC} suite {selected} relibc {relibc_commit()} {' '.join(FLAGS)}\n"
    if STAMP.exists() and STAMP.read_text() == config and LIST.exists():
        print(f"os-test objects ready: {LIST}")
        return
    fetch()
    if OBJECTS.exists():
        shutil.rmtree(OBJECTS)
    compiler = clang()
    lines = []
    seen = set()
    for suite, directory, pattern in parts:
        (OBJECTS / directory).mkdir(parents=True, exist_ok=True)
        for test in sorted((SOURCE / directory).glob(pattern or "*.c")):
            if pattern is None and not FORK.search(test.read_text()):
                continue
            name = f"{suite}/{test.stem}"
            if name in seen:
                continue
            seen.add(name)
            target = OBJECTS / directory / f"{test.stem}.o"
            result = subprocess.run([compiler, *FLAGS, "-c", str(test), "-o", str(target)],
                                    cwd=SOURCE / directory, capture_output=True, text=True)
            if result.returncode == 0:
                lines.append(f"{name} {target}")
            else:
                lines.append(f"{name} !{outcome(result.stderr, test.read_text())}")
    if not lines:
        raise SystemExit(f"empty os-test suite: {selected}")
    LIST.write_text("\n".join(lines) + "\n")
    STAMP.write_text(config)
    print(f"os-test objects ready: {LIST}")


if __name__ == "__main__":
    main()
