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
    println!("cargo:rerun-if-changed=rtbench.c");
    println!("cargo:rerun-if-env-changed=STAFETO_C_TOOL_DIR");
    println!("cargo:rerun-if-env-changed=STAFETO_RELIBC_SYSROOT");
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    println!(
        "cargo:rerun-if-changed={}",
        manifest
            .join("../../lib/posix-types/src/constants.rs")
            .display()
    );
    let tools = env::var_os("STAFETO_C_TOOL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let brew = PathBuf::from("/opt/homebrew/opt/llvm/bin");
            if brew.exists() { brew } else { PathBuf::new() }
        });
    let target = env::var("TARGET").expect("Cargo sets TARGET");
    assert_eq!(
        target, "aarch64-unknown-none",
        "rtbench 2 is a guest program"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    relibc(&manifest, &tools, &out);
}

/// rtbench.c with relibc's headers, linked with relibc's libc.a
/// (target/relibc/sysroot, cargo xtask relibc).
fn relibc(manifest: &std::path::Path, tools: &std::path::Path, out: &std::path::Path) {
    let sysroot = env::var_os("STAFETO_RELIBC_SYSROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../target/relibc/sysroot"));
    let lib = sysroot.join("lib");
    assert!(
        lib.join("libc.a").exists(),
        "build relibc first: cargo xtask relibc"
    );
    println!("cargo:rerun-if-changed={}", lib.join("libc.a").display());
    run(Command::new(tools.join("clang"))
        .args([
            "--target=aarch64-linux-gnu",
            // Cortex-A53 erratum 835769 (the PinePhone's A64).
            "-mfix-cortex-a53-835769",
            "-nostdinc",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-pic",
            "-O2",
            "-isystem",
        ])
        .arg(sysroot.join("include"))
        .args(["-c", "rtbench.c", "-o"])
        .arg(out.join("rtbench.o")));
    run(Command::new(tools.join("llvm-ar"))
        .args(["crs"])
        .arg(out.join("librtbench.a"))
        .arg(out.join("rtbench.o")));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-search=native={}", lib.display());
    println!("cargo:rustc-link-lib=static=rtbench");
    println!("cargo:rustc-link-lib=static=c");
}
