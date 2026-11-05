#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The answers to nginx's run-probes for a build on another machine
(tools/build-nginx.py, tools/nginx/cross-autotest.patch). `configure` runs
`autotest-answer.py PROBE` where it would run the compiled probe PROBE, with
the probe's name in NGX_AUTOTEST_NAME, and takes the exit status (and, for a
size, the output) as the probe's.

- `sizeof T` and `byte ordering`: the compiler of the project answers. The
  probe's own source (PROBE.c, with its includes) gets
  `_Static_assert(sizeof(T) == N)` for N of 1, 2, 4, 8, 16, or a check of
  `__BYTE_ORDER__`, and is compiled with NGX_AUTOTEST_CC; what compiles is
  the target's value.
- every other probe: the table ANSWERS, each answer with its reason.
- a name the table lacks: written to NGX_AUTOTEST_UNKNOWN and answered
  "not found"; the build script fails when that file is not empty, so no
  probe is decided silently.

Each answer goes to NGX_AUTOTEST_LOG, if set, with its reason."""

import os
import shlex
import subprocess
import sys
from pathlib import Path

# The probe's name: (exit status, why). 0 is "found and working".
ANSWERS = {
    "C compiler": (0, "the probe's program links, which is all that matters on the target"),
    "gcc builtin atomic operations": (0, "clang's __sync builtins compile to AArch64 atomics"),
    "C99 variadic macros": (0, "clang's preprocessor; sprintf of relibc"),
    "gcc variadic macros": (0, "clang's preprocessor; sprintf of relibc"),
    "epoll": (0, "the layer has epoll_create, epoll_ctl, epoll_wait and EPOLLET"),
    "mmap(MAP_ANON|MAP_SHARED)": (0, "an anonymous shared mapping stays shared across fork"),
    'mmap("/dev/zero", MAP_SHARED)': (1, "nginx takes MAP_ANON first; a shared /dev/zero is not claimed"),
    "System V shared memory": (1, "nginx takes MAP_ANON first; the segments of the pipe service are few (8 of 1 MiB)"),
    "POSIX semaphores": (1, "kept off: the accept mutex is off, and the lock of the one shared zone (the TLS session cache of tls.conf) is held briefly: nginx's shared mutex spins and yields with sched_yield"),
    "POSIX semaphores in libpthread": (1, "as POSIX semaphores"),
    "sendfile()": (1, "relibc has no sys/sendfile.h; nginx writes with writev"),
    "sendfile64()": (1, "relibc has no sys/sendfile.h; nginx writes with writev"),
    "prctl(PR_SET_DUMPABLE)": (1, "relibc has no sys/prctl.h"),
    "prctl(PR_SET_KEEPCAPS)": (1, "relibc has no sys/prctl.h"),
    "sys_nerr": (1, "relibc has no sys_nerr; nginx asks strerror for each number at start"),
    "_sys_nerr": (1, "relibc has no _sys_nerr"),
}

SIZES = (1, 2, 4, 8, 16)


def compiles(source: str, probe: Path) -> bool:
    """Whether `source`, written beside the probe (its quoted includes are
    found there), compiles with the compiler of the build."""
    command = shlex.split(os.environ["NGX_AUTOTEST_CC"])
    path = probe.with_name(probe.name + "-answer.c")
    path.write_text(source)
    try:
        result = subprocess.run([*command, "-fsyntax-only", str(path)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    finally:
        path.unlink(missing_ok=True)
    return result.returncode == 0


def size_of(kind: str, probe: Path) -> int | None:
    """sizeof(kind) on the target, with the includes of the probe's source."""
    text = probe.with_name(probe.name + ".c").read_text()
    for size in SIZES:
        if compiles(f'{text}\n_Static_assert(sizeof({kind}) == {size}, "size");\n', probe):
            return size
    return None


def answer(name: str, probe: Path) -> int:
    """The exit status of the probe `name`; a size goes to the output."""
    if name.startswith("sizeof "):
        size = size_of(name.removeprefix("sizeof "), probe)
        if size is None:
            return 1
        print(size, end="")
        return 0
    if name == "byte ordering":
        little = compiles('_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "order");\n',
                          probe)
        return 0 if little else 1
    if name in ANSWERS:
        return ANSWERS[name][0]
    unknown = os.environ.get("NGX_AUTOTEST_UNKNOWN")
    if unknown:
        with open(unknown, "a") as file:
            file.write(name + "\n")
    return 1


def main() -> int:
    if len(sys.argv) != 2 or "NGX_AUTOTEST_NAME" not in os.environ:
        print("usage: NGX_AUTOTEST_NAME=NAME autotest-answer.py PROBE", file=sys.stderr)
        return 2
    name = os.environ["NGX_AUTOTEST_NAME"]
    status = answer(name, Path(sys.argv[1]))
    log = os.environ.get("NGX_AUTOTEST_LOG")
    if log:
        why = ANSWERS[name][1] if name in ANSWERS else "the compiler of the build"
        if name.startswith("sizeof ") and status == 0:
            why = f"{size_of(name.removeprefix('sizeof '), Path(sys.argv[1]))} bytes, {why}"
        with open(log, "a") as file:
            file.write(f"{name}: {status} ({why})\n")
    return status


if __name__ == "__main__":
    sys.exit(main())
