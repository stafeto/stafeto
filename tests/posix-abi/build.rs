// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("C compiler or archiver is missing");
    assert!(status.success(), "command failed: {cmd:?}");
}

fn main() {
    println!("cargo:rerun-if-changed=probe.c");
    println!("cargo:rerun-if-env-changed=STAFETO_C_TOOL_DIR");
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let tools = env::var_os("STAFETO_C_TOOL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let brew = PathBuf::from("/opt/homebrew/opt/llvm/bin");
            if brew.exists() { brew } else { PathBuf::new() }
        });
    let target = env::var("TARGET").expect("Cargo sets TARGET");
    assert_eq!(
        target, "aarch64-unknown-none",
        "POSIX ABI probe is a guest program"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    let generated = Command::new("python3")
        .arg(manifest.join("../../tools/build-posix-sysroot.py"))
        .arg("--headers-only")
        .output()
        .expect("Python sysroot generator");
    assert!(generated.status.success(), "sysroot generation failed");
    let output = String::from_utf8(generated.stdout).expect("sysroot path is UTF-8");
    let include = PathBuf::from(
        output
            .trim()
            .strip_prefix("Rust POSIX sysroot: ")
            .expect("sysroot path"),
    )
    .join("include");
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("../../lib/posix-abi/include").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest
            .join("../../lib/posix-abi/src/constants.rs")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest
            .join("../../tools/build-posix-sysroot.py")
            .display()
    );
    run(Command::new(tools.join("clang"))
        .args([
            "--target=aarch64-none-elf",
            "-ffreestanding",
            "-nostdinc",
            "-fno-builtin",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-stack-protector",
            "-fno-pic",
            "-O2",
            "-I",
        ])
        .arg(&include)
        .args(["-c", "probe.c", "-o"])
        .arg(out.join("probe.o")));
    run(Command::new(tools.join("llvm-ar"))
        .args(["crs"])
        .arg(out.join("libposixprobe.a"))
        .arg(out.join("probe.o")));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=posixprobe");
}
