#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Cross-check the complete pinned os-test include and namespace suites.

Census rows keep original Git names. Numbered scratch files preserve names
which differ only in case on APFS. Only the upstream namespace parser is a
host executable; the tested declarations and links use the stafeto target.
"""

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import csv
from dataclasses import dataclass
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build_os_test", ROOT / "tools/build-os-test.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
COMMIT = builder.COMMIT
PROFILES = (("posix202405", ("-D_POSIX_C_SOURCE=202405L",)),
            ("posix200809", ("-D_POSIX_C_SOURCE=200809L",)),
            ("extension", ("-D_GNU_SOURCE", "-D_BSD_SOURCE", "-D_ALL_SOURCE",
                           "-D_DEFAULT_SOURCE")))


def run(args, **kwargs):
    command = [str(arg) for arg in args]
    try:
        return subprocess.run(command, capture_output=True,
                              text=True, timeout=60, **kwargs)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, 124, "", "command timed out after 60 seconds\n")


def cross_env():
    env = dict(os.environ)
    for name in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH",
                 "SDKROOT", "MACOSX_DEPLOYMENT_TARGET"):
        env.pop(name, None)
    return env


def target_flags(sysroot):
    return ["--target=aarch64-linux-gnu", "-nostdinc", "-isystem",
            str(sysroot / "include"), "-std=c17", "-mno-outline-atomics",
            "-mfix-cortex-a53-835769", "-fno-stack-protector", "-Wall", "-Wextra",
            "-Werror", "-Wno-error=deprecated", "-Wno-error=deprecated-declarations"]


def git_paths(source, commit, directories):
    result = subprocess.run(["git", "ls-tree", "-rz", "--name-only", commit,
                             "--", *directories], cwd=source, capture_output=True,
                            check=True)
    return sorted(name.decode() for name in result.stdout.split(b"\0") if name)


def blob(source, commit, name):
    return subprocess.run(["git", "show", f"{commit}:{name}"], cwd=source,
                          capture_output=True, check=True).stdout


def collisions(names):
    groups = defaultdict(list)
    for name in names:
        groups[name.casefold()].append(name)
    return sorted(group for group in groups.values() if len(group) > 1)


def inventory(source, commit=COMMIT, pinned=True):
    paths = git_paths(source, commit, ["include", "namespace"])
    include = [name for name in paths if name.startswith("include/") and name.endswith(".c")]
    namespace = [name for name in paths if name.startswith("namespace/") and name.endswith(".c")]
    api = [name for name in paths if name.startswith("include/") and name.endswith(".api")]
    pairs = collisions(include)
    if pinned and (len(include), len(namespace), len(pairs)) != (3758, 159, 17):
        raise ValueError(f"pinned inventory changed: {len(include)} include, "
                         f"{len(namespace)} namespace, {len(pairs)} case pairs")
    if collisions(api):
        raise ValueError("namespace API definitions collide on a case-insensitive filesystem")
    return include, namespace, api


def extract(source, commit, names, directory):
    directory.mkdir(parents=True, exist_ok=True)
    result = []
    for number, name in enumerate(names):
        path = directory / f"{number:05}.c"
        path.write_bytes(blob(source, commit, name))
        result.append((name, path))
    return result


@dataclass
class Row:
    name: str
    outcome: str
    profile: str
    stage: str
    diagnostic: str = ""


class LinkPlan:
    def __init__(self, directory):
        self.lld, self.ar, self.nm = [Path((directory / name).read_text().strip())
                                      for name in ("lld", "ar", "nm")]
        raw = (directory / "args.nul").read_bytes().split(b"\0")
        if raw[-1] == b"":
            raw.pop()
        self.args = [arg.decode() for arg in raw]
        for token, option in (("{OUTPUT}", "-o"), ("{ARCHIVE_DIR}", "-L")):
            if self.args.count(token) != 1:
                raise ValueError(f"link plan needs exactly one {token}")
            at = self.args.index(token)
            if at == 0 or self.args[at - 1] != option:
                raise ValueError(f"{token} must follow {option}")
        if self.args[:2] != ["-flavor", "gnu"]:
            raise ValueError("link plan needs explicit GNU flavor")

    def link(self, obj, directory):
        archive = directory / "libostest.a"
        made = run([self.ar, "crs", archive, obj])
        if made.returncode:
            raise RuntimeError(f"archive failed: {made.stderr}")
        symbols = run([self.nm, "--defined-only", "--extern-only", "--format=posix", obj])
        if symbols.returncode:
            raise RuntimeError(f"symbol enumeration failed: {symbols.stderr}")
        roots = [line.split()[0] for line in symbols.stdout.splitlines() if line.strip()]
        if "main" not in roots:
            raise RuntimeError("include test object defines no main")
        args = [str(directory / "test.elf") if arg == "{OUTPUT}" else
                str(directory) if arg == "{ARCHIVE_DIR}" else arg for arg in self.args]
        args += [f"--undefined={symbol}" for symbol in roots]
        return run([self.lld, *args])


def check_include(item, compiler, flags, plan):
    name, source = item
    with tempfile.TemporaryDirectory(prefix="include-", dir=source.parent) as scratch:
        directory = Path(scratch)
        obj = directory / "test.o"
        first_errors = ""
        for number, (profile, defines) in enumerate(PROFILES):
            compiled = run([compiler, *flags, *defines, "-c", source, "-o", obj], env=cross_env())
            if number == 0:
                first_errors = compiled.stderr
            if compiled.returncode == 124:
                return Row(name, "timeout", profile, "compile", compiled.stderr)
            if compiled.returncode:
                continue
            linked = plan.link(obj, directory)
            if linked.returncode:
                outcome = "timeout" if linked.returncode == 124 else (
                    "undefined" if "undefined symbol:" in linked.stderr else
                    "duplicate_symbol" if "duplicate symbol:" in linked.stderr else "link_error")
                return Row(name, outcome, profile, "link", linked.stderr)
            return Row(name, ("good", "previous_posix", "extension")[number], profile, "link")
        return Row(name, builder.outcome(first_errors, source.read_text()),
                   "posix202405", "compile", first_errors)


def namespace_parser(source, commit, directory, compiler):
    misc = directory / "misc"
    misc.mkdir()
    for name in ("namespace.c", "errors.h"):
        (misc / name).write_bytes(blob(source, commit, f"misc/{name}"))
    parser = misc / "namespace"
    built = run([compiler, "-std=c17", "-D_POSIX_C_SOURCE=200809L",
                 misc / "namespace.c", "-o", parser])
    if built.returncode:
        raise RuntimeError(f"native namespace parser failed: {built.stderr}")
    return parser


def check_namespace(item, compiler, flags, parser, api):
    name, source = item
    stem = Path(name).stem
    xsi = stem.endswith("-xsi")
    header = stem.removesuffix("-xsi")
    with tempfile.TemporaryDirectory(prefix="namespace-", dir=source.parent) as scratch:
        directory = Path(scratch)
        inputs, diagnostics = [], []
        for suffix, extra in (("i", []), ("dM", ["-dM"])):
            output = directory / f"test.{suffix}"
            processed = run([compiler, *flags, "-D_POSIX_C_SOURCE=202405L", "-E", *extra,
                             source, "-o", output], env=cross_env())
            if processed.returncode == 124:
                return Row(name, "timeout", "xopen800" if xsi else "posix202405",
                           "preprocess", processed.stderr)
            if processed.returncode:
                output.write_text("missing_header\n")
                diagnostics.append(processed.stderr)
            inputs.append(output)
        result, errors = directory / "result", directory / "errors"
        parsed = run([parser, "-o", result, "-e", errors, "-I", api, "-i", header,
                      *(["-x"] if xsi else []), *inputs])
        diagnostics.extend([parsed.stderr, errors.read_text() if errors.exists() else ""])
        if parsed.returncode:
            diagnostics.append(f"namespace parser exited with status {parsed.returncode}")
        outcome = result.read_text().strip() if parsed.returncode == 0 and result.exists() else (
            "timeout" if parsed.returncode == 124 else "parser_error")
        return Row(name, outcome, "xopen800" if xsi else "posix202405",
                   "namespace", "\n".join(text for text in diagnostics if text))


def write_rows(path, rows, expected):
    names = [row.name for row in rows]
    if Counter(names) != Counter(expected) or len(set(names)) != len(names):
        raise ValueError("census lost, duplicated or added test IDs")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as output:
        output.write(f"# os-test {COMMIT}; relibc {builder.relibc_commit()}\n")
        writer = csv.writer(output, delimiter="\t")
        writer.writerow(["test", "outcome", "profile", "stage", "diagnostic"])
        for row in sorted(rows, key=lambda row: row.name):
            writer.writerow([row.name, row.outcome, row.profile, row.stage,
                             row.diagnostic.replace("\n", "\\n").replace("\r", "")])


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=ROOT / "target/os-test/source")
    cli.add_argument("--sysroot", type=Path, default=Path(os.environ.get(
        "STAFETO_RELIBC_SYSROOT", ROOT / "target/relibc/sysroot")))
    cli.add_argument("--link-plan", type=Path)
    cli.add_argument("--output", type=Path, default=ROOT / "target/measure/os-test-headers.tsv")
    cli.add_argument("--suite", choices=["all", "include", "namespace"], default="all")
    cli.add_argument("--jobs", type=int, default=4)
    cli.add_argument("--bootstrap", type=Path)
    args = cli.parse_args()
    compiler = builder.clang()
    flags = target_flags(args.sysroot.resolve())
    if args.bootstrap:
        args.bootstrap.parent.mkdir(parents=True, exist_ok=True)
        source = args.bootstrap.with_suffix(".c")
        source.write_text("int main(void) { return 0; }\n")
        made = run([compiler, *flags, "-c", source, "-o", args.bootstrap], env=cross_env())
        if made.returncode:
            raise SystemExit(made.stderr)
        return
    if args.jobs < 1 or args.jobs > 32:
        cli.error("--jobs must be between 1 and 32")
    if not (args.sysroot / "include/stdio.h").is_file():
        cli.error("build relibc first")
    if args.suite != "namespace" and args.link_plan is None:
        cli.error("include checks require --link-plan")
    include, namespace, api_names = inventory(args.source)
    print(f"os-test header inventory: {len(include)} include, {len(namespace)} namespace, "
          f"{len(collisions(include))} case pairs", flush=True)
    rows, expected = [], []
    with tempfile.TemporaryDirectory(prefix="stafeto-headers-") as scratch:
        work = Path(scratch)
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            if args.suite != "namespace":
                plan = LinkPlan(args.link_plan)
                expected += include
                items = extract(args.source, COMMIT, include, work / "include")
                for number, row in enumerate(pool.map(
                        lambda item: check_include(item, compiler, flags, plan), items), 1):
                    rows.append(row)
                    if number % 250 == 0:
                        print(f"os-test include: {number}/{len(include)}", flush=True)
            if args.suite != "include":
                expected += namespace
                parser = namespace_parser(args.source, COMMIT, work, shutil.which("cc") or compiler)
                api = work / "api"
                api.mkdir()
                for name in api_names:
                    (api / Path(name).name).write_bytes(blob(args.source, COMMIT, name))
                items = extract(args.source, COMMIT, namespace, work / "namespace")
                rows += list(pool.map(lambda item: check_namespace(item, compiler, flags, parser, api), items))
    write_rows(args.output, rows, expected)
    for suite in ("include", "namespace"):
        counts = Counter(row.outcome for row in rows if row.name.startswith(suite + "/"))
        print(f"os-test {suite}: {dict(sorted(counts.items()))}")
    print(f"os-test header table: {args.output}")


if __name__ == "__main__":
    main()
