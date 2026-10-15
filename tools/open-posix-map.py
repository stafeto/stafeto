#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build the failure map of the Open POSIX Test Suite run from
target/measure/open-posix.tsv (`cargo xtask open-posix --full`): the
outcomes by section, and every test that does not pass grouped by the part
of the plan that owns the fix and by cause. Prints Markdown; the committed
copy is docs/open-posix-map.md.

usage: open-posix-map.py [TSV]"""

from collections import Counter, defaultdict
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
OUTCOMES = ("PASS", "FAIL", "UNRESOLVED", "UNSUPPORTED", "UNTESTED",
            "BUILD", "LINK", "TIMEOUT", "SCRIPT", "ARGS")

# The parts: the first rule that matches the interface (or header) name wins.
PARTS = (
    ("F11b libc remainder", r"^(mq_|mqueue|aio_|lio_|nl_|getdate|makecontext|getcontext|setcontext|swapcontext|ucontext|sem_open|sem_close|sem_unlink|sem_timedwait|msg|shm_|sys_vfs)"),
    ("F13 real time", r"^(sched|pthread_(attr_)?(get|set)(sched|prio|inheritsched|scope|schedparam|schedpolicy|schedprio)|pthread_mutex(attr)?_(get|set)prioceiling|pthread_mutexattr_(get|set)protocol|clock_getcpuclockid|pthread_getcpuclockid|pthread_(attr_)?setinheritsched)"),
    ("Signals and process service", r"^(sig|kill|raise|pause|alarm|pthread_(sigmask|kill)|signal)"),
    ("Clocks and timers", r"^(timer_|clock|nanosleep|time$|difftime|strftime|gettimeofday|usleep|sleep|ctime|asctime|localtime|gmtime|mktime)"),
    ("Threads and synchronization", r"^(pthread_|sem_|thrd_)"),
    ("Memory", r"^(mmap|munmap|mlock|munlock|mprotect|madvise|posix_madvise|msync|shm_)"),
    ("Processes", r"^(fork|exec|wait|posix_spawn|_exit|exit|getpid|getppid|vfork)"),
)
# A compile error names a missing symbol: the part that owns the symbol takes
# the test whatever interface the test is of.
SYMBOL_PARTS = (
    ("F13 real time", r"^(no declaration of (sched_\w+|cpu_set_t|clock_getcpuclockid|\w*prioceiling\w*)|missing macro or member _POSIX_SPORADIC_SERVER)"),
    ("F11b libc remainder", r"^(missing header (mqueue|nl_types|ucontext|sys/vfs)\.h|no declaration of (mq_\w+|aio_\w+|lio_\w+|sem_open|sem_close|sem_unlink|SEM_VALUE_MAX|getdate))"),
    ("Signals and process service", r"^(no declaration of SIGPOLL|missing macro or member (POLL_\w+|si_band))"),
    ("Memory", r"^missing macro or member POSIX_MADV"),
    ("Threads and synchronization", r"^(no declaration of pthread_\w+|missing macro or member cid)"),
)
IMAGE = re.compile(r"/proc/|setrlimit|uid: ?[1-9]|Testing with user|/etc/passwd|getpwnam")


def part_of(name: str, detail: str, cause: str = "") -> str:
    for part, pattern in SYMBOL_PARTS:
        if re.search(pattern, cause):
            return part
    parts = name.split("/")
    section = parts[0] + "/" + parts[1] if parts[0] == "conformance" else parts[0]
    if IMAGE.search(detail):
        return "Image limits (no /proc, no second user, setrlimit)"
    interface = parts[2] if len(parts) > 2 else ""
    if section == "conformance/definitions":
        interface = parts[2].removesuffix("_h")
        if interface in ("mqueue", "aio"):
            return "F11b libc remainder"
        if interface == "sched":
            return "F13 real time"
        if interface == "signal":
            return "Signals and process service"
        if interface == "time":
            return "Clocks and timers"
        if interface == "pthread":
            return "Threads and synchronization"
        return "Other"
    for part, pattern in PARTS:
        if re.search(pattern, interface):
            return part
    if re.search(r"SPORADIC|CPUTIME|PRIORITY_SCHEDULING|_POSIX_PRIORITY", detail):
        return "F13 real time"
    return "Other"


def cause_of(result: str, detail: str) -> str:
    if result == "BUILD":
        m = re.search(r"'([\w/.]+\.h)' file not found", detail)
        if m:
            return f"missing header {m.group(1)}"
        m = re.search(r"undeclared function '(\w+)'", detail)
        if m:
            return f"no declaration of {m.group(1)}"
        m = re.search(r"undeclared identifier '(\w+)'", detail)
        if m:
            return f"no declaration of {m.group(1)}"
        m = re.search(r"(\w+) (is )?not defined|no member named '(\w+)'", detail)
        if m:
            return f"missing macro or member {m.group(1) or m.group(3)}"
        return "other compile error"
    if result == "LINK":
        return f"undefined symbols {detail}"
    if result == "TIMEOUT":
        return "hang or time limit"
    if result == "SCRIPT":
        return "shell script of the suite (not run)"
    if result == "ARGS":
        return "needs arguments (not run)"
    if "Function not implemented" in detail or "ENOSYS" in detail:
        return "ENOSYS"
    if detail.startswith("signal "):
        return "crash (" + detail.split()[0] + " " + detail.split()[1] + ")"
    if re.search(r"_POSIX_\w+ (is |was )?(not|un)\w*|unsupported|Unsupported|not supported|Does not support", detail):
        return "optional feature not claimed"
    if "RELIBC" in detail:
        return "libc panic or out of memory"
    if result == "UNSUPPORTED":
        return "optional feature not claimed"
    if result in ("UNRESOLVED", "UNTESTED"):
        return f"{result.lower()} by the test"
    return "wrong behavior"


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "target/measure/open-posix.tsv"
    rows = []
    for line in path.read_text().splitlines()[1:]:
        name, result, phase, detail = (line.split("\t") + ["", "", "", ""])[:4]
        rows.append((name, result, phase, detail))
    by_section = defaultdict(Counter)
    for name, result, _, _ in rows:
        p = name.split("/")
        section = p[0] + "/" + p[1] if p[0] == "conformance" else p[0]
        by_section[section][result] += 1
    total = Counter(r[1] for r in rows)
    out = ["# Open POSIX Test Suite map", "",
           "Generated by `tools/open-posix-map.py` from the table of "
           "`cargo xtask open-posix --full` (LTP 20260930). Every test that does "
           "not pass is listed once, by the part of the plan that owns the fix.", "",
           "## Outcomes", "",
           "| Section | " + " | ".join(OUTCOMES) + " | Total |",
           "|---|" + "---|" * (len(OUTCOMES) + 1)]
    for section in sorted(by_section):
        c = by_section[section]
        out.append(f"| {section} | " + " | ".join(str(c[o]) for o in OUTCOMES)
                   + f" | {sum(c.values())} |")
    out.append("| **all** | " + " | ".join(f"**{total[o]}**" for o in OUTCOMES)
               + f" | **{len(rows)}** |")
    grouped = defaultdict(lambda: defaultdict(list))
    for name, result, _, detail in rows:
        if result == "PASS":
            continue
        cause = cause_of(result, detail)
        grouped[part_of(name, detail, cause)][cause].append((name, result))
    out += ["", "## Parts", "", "| Part | Tests that do not pass | Of them SCRIPT or ARGS |", "|---|---|---|"]
    for part in sorted(grouped, key=lambda p: -sum(len(v) for v in grouped[p].values())):
        n = sum(len(v) for v in grouped[part].values())
        s = sum(len(v) for k, v in grouped[part].items() if "not run" in k)
        out.append(f"| {part} | {n} | {s} |")
    for part in sorted(grouped, key=lambda p: -sum(len(v) for v in grouped[p].values())):
        out += ["", f"## {part}", ""]
        for cause, tests in sorted(grouped[part].items(), key=lambda kv: -len(kv[1])):
            interfaces = Counter(t[0].split("/")[2] if t[0].split("/")[0] == "conformance" else t[0].rsplit("/", 1)[0] for t in tests)
            names = ", ".join(f"{k} ({v})" for k, v in sorted(interfaces.items()))
            out.append(f"- **{cause}**: {len(tests)} tests. {names}")
    print("\n".join(out))


if __name__ == "__main__":
    main()
