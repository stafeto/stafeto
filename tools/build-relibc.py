#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build relibc for stafeto (`cargo xtask relibc`): the fork
stafeto/relibc at a pinned commit, with its stafeto platform (--cfg
stafeto on aarch64-unknown-linux-gnu), into target/relibc/sysroot:
include/ (cbindgen's headers, relibc's include/ and openlibm's headers)
and lib/libc.a. The fork carries its dependencies in vendor/, so the build
itself runs with --frozen --offline; the first run fetches the commit, the
pinned nightly toolchain with rust-src and cbindgen. relibc builds with
its own release profile (level 3): a program's size has no bound, its
speed counts (rtbench). A stamp of the commit, the toolchain, the flags,
clang and the cbindgen version makes a second run do nothing."""

import os
from pathlib import Path
import shutil
import subprocess
import sys


REPOSITORY = "https://github.com/stafeto/relibc.git"
# A commit of the fork's branch stafeto, tagged pin-<short hash>.
COMMIT = "a5adc5f8e1c35b0ce05c099bdcde7191d91ec8bd"
TOOLCHAIN = "nightly-2026-05-24"
CBINDGEN = "0.29.4"
TARGET = "aarch64-unknown-linux-gnu"
# Cortex-A53 erratum 835769 (the PinePhone's A64): the Rust and the C of
# relibc both get the fix; xtask's disasm check fails a program without it.
RUSTFLAGS = ("--cfg stafeto -C relocation-model=static -Z tls-model=local-exec"
             " -C target-feature=+fix-cortex-a53-835769")
CFLAGS = "--target=aarch64-linux-gnu -mfix-cortex-a53-835769"
BUILD_STD = "core,alloc,compiler_builtins"
# The C math functions from the Rust libm crate (MIT), declared by
# openlibm's headers.
FEATURES = "math_libm"
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "relibc"
SOURCE = WORK / "source"
BUILD = WORK / "build"
SYSROOT = WORK / "sysroot"
STAMP = WORK / "stamp"
TOOLS = ROOT / "target" / "tools"
CARGO_HOME = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))


def run(*args, cwd=None, env=None, stdout=None) -> subprocess.CompletedProcess:
    return subprocess.run([str(a) for a in args], cwd=cwd, env=env, check=True,
                          stdout=stdout, text=True)


def output(*args, cwd=None, env=None) -> str:
    return run(*args, cwd=cwd, env=env, stdout=subprocess.PIPE).stdout.strip()


def clean_env() -> dict:
    """The environment without what the cargo that runs xtask set: the
    workspace's toolchain and flags must not reach relibc's build."""
    env = dict(os.environ)
    for name in list(env):
        if name in ("RUSTUP_TOOLCHAIN", "RUSTC", "RUSTC_WRAPPER", "RUSTDOC", "RUSTFLAGS",
                    "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR",
                    "CARGO_MAKEFLAGS", "CARGO_BUILD_TARGET") or name.startswith("CARGO_PKG_"):
            del env[name]
    return env


def llvm(name: str) -> Path:
    brew = Path("/opt/homebrew/opt/llvm/bin") / name
    if brew.exists():
        return brew
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing {name}; install LLVM")
    return Path(found).resolve()


def fetch(env: dict) -> None:
    """The fork at COMMIT in SOURCE, fetched alone (no history)."""
    if not (SOURCE / ".git").exists():
        SOURCE.mkdir(parents=True, exist_ok=True)
        run("git", "init", "-q", cwd=SOURCE, env=env)
        run("git", "remote", "add", "origin", REPOSITORY, cwd=SOURCE, env=env)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=SOURCE, env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.strip()
    if head != COMMIT:
        run("git", "fetch", "-q", "--depth", "1", "origin", COMMIT, cwd=SOURCE, env=env)
        run("git", "checkout", "-q", "--detach", "--force", COMMIT, cwd=SOURCE, env=env)
    head = output("git", "rev-parse", "HEAD", cwd=SOURCE, env=env)
    if head != COMMIT:
        raise SystemExit(f"relibc resolved to {head}, expected {COMMIT}")
    changed = output("git", "status", "--porcelain", "--untracked-files=no", cwd=SOURCE, env=env)
    if changed:
        raise SystemExit(f"{SOURCE} has local changes:\n{changed}")


def toolchain(env: dict) -> None:
    """The pinned nightly with rust-src, which -Z build-std compiles."""
    try:
        sysroot = output("rustup", "run", TOOLCHAIN, "rustc", "--print", "sysroot", env=env)
    except subprocess.CalledProcessError:
        sysroot = ""
    if not sysroot or not (Path(sysroot) / "lib/rustlib/src/rust/library/Cargo.lock").exists():
        run("rustup", "toolchain", "install", TOOLCHAIN, "--profile", "minimal",
            "--component", "rust-src", env=env)


def cbindgen(env: dict) -> Path:
    """cbindgen of the pinned version under target/tools."""
    binary = TOOLS / "bin" / "cbindgen"
    if binary.exists() and output(binary, "--version", env=env) == f"cbindgen {CBINDGEN}":
        return binary
    run("cargo", "install", "--locked", "--quiet", "--version", CBINDGEN, "--root", TOOLS,
        "--force", "cbindgen", cwd=ROOT, env=env)
    return binary


def remap(env: dict) -> tuple[str, str]:
    """RUSTFLAGS and CFLAGS with the build's directories (the source, the
    toolchain's library sources, CARGO_HOME, the build directory) mapped
    to fixed names: libc.a then holds no path of this machine."""
    sysroot = output("rustup", "run", TOOLCHAIN, "rustc", "--print", "sysroot", env=env)
    pairs = [(BUILD, "/build"), (SOURCE, "/relibc"), (Path(sysroot), "/rust"),
             (CARGO_HOME, "/cargo")]
    rust = " ".join(f"--remap-path-prefix={path}={name}" for path, name in pairs)
    c = " ".join(f"-ffile-prefix-map={path}={name}" for path, name in pairs)
    return f"{RUSTFLAGS} {rust}", f"{CFLAGS} {c}"


def config(env: dict) -> str:
    """What the stamp holds: a change of any of it builds relibc again."""
    rustflags, cflags = remap(env)
    clang = output(llvm("clang"), "--version", env=env).splitlines()[0]
    return (f"{COMMIT} {TOOLCHAIN} {TARGET} {rustflags} {cflags} build-std={BUILD_STD}"
            f" features={FEATURES} cbindgen {CBINDGEN} {clang}\n")


def build(env: dict) -> None:
    rustflags, cflags = remap(env)
    env = dict(env)
    env.update({
        "CARGO_TARGET_DIR": str(BUILD),
        "RUSTFLAGS": rustflags,
        "CC_aarch64_unknown_linux_gnu": str(llvm("clang")),
        "AR_aarch64_unknown_linux_gnu": str(llvm("llvm-ar")),
        "CFLAGS_aarch64_unknown_linux_gnu": cflags,
    })
    library = WORK / "librelibc.a"
    run("cargo", f"+{TOOLCHAIN}", "rustc", "--frozen", "--offline", "--release", "--target",
        TARGET, f"-Zbuild-std={BUILD_STD}", "--features", FEATURES, "--lib", "--", "--emit",
        f"link={library}",
        cwd=SOURCE, env=env)
    # relibc's Rust symbols get its prefix and its copies of core's math
    # go, so that it links with the Rust of a stafeto program (relibc's
    # Makefile does the same).
    env.update({"NM": str(llvm("llvm-nm")), "OBJCOPY": str(llvm("llvm-objcopy"))})
    run("bash", SOURCE / "renamesyms.sh", library, BUILD / TARGET / "release" / "deps",
        cwd=SOURCE, env=env)
    run("bash", SOURCE / "stripcore.sh", library, cwd=SOURCE, env=env)
    (SYSROOT / "lib").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(library, SYSROOT / "lib" / "libc.a")


def headers(env: dict, generator: Path) -> None:
    """The headers as relibc's Makefile writes them without USE_RUST_LIBM."""
    include = SYSROOT / "include"
    shutil.rmtree(include, ignore_errors=True)
    shutil.copytree(SOURCE / "include", include)
    for directory in (SOURCE / "openlibm" / "include", SOURCE / "openlibm" / "src"):
        for header in directory.glob("*.h"):
            shutil.copyfile(header, include / header.name)
    defaults = (SOURCE / "cbindgen.globdefs.toml").read_text()
    for directory in sorted((SOURCE / "src" / "header").iterdir()):
        config = directory / "cbindgen.toml"
        if directory.name.startswith("_") or directory.name == "math" or not config.exists():
            continue
        out = include / (directory.name.replace("_", "/") + ".h")
        out.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([str(generator), "--quiet", str(directory / "mod.rs"),
                        "--config=/dev/stdin", "--output", str(out)],
                       input=config.read_text() + defaults, cwd=SOURCE, env=env, check=True,
                       text=True)


def main() -> None:
    library = SYSROOT / "lib" / "libc.a"
    env = clean_env()
    toolchain(env)
    wanted = config(env)
    if library.exists() and STAMP.exists() and STAMP.read_text() == wanted:
        print(f"relibc ready: {SYSROOT}")
        return
    WORK.mkdir(parents=True, exist_ok=True)
    STAMP.unlink(missing_ok=True)
    fetch(env)
    generator = cbindgen(env)
    build(env)
    headers(env, generator)
    STAMP.write_text(wanted)
    print(f"relibc ready: {SYSROOT}")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(f"build-relibc: {error}")
