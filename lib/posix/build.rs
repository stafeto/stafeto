// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("C compiler or archiver is missing");
    assert!(status.success(), "command failed: {cmd:?}");
}

fn main() {
    println!("cargo:rerun-if-changed=os.c");
    println!("cargo:rerun-if-env-changed=STAFETO_PICOLIBC_ROOT");
    println!("cargo:rerun-if-env-changed=STAFETO_C_TOOL_DIR");
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let root = env::var_os("STAFETO_PICOLIBC_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../target/picolibc/root/usr"));
    let tools = env::var_os("STAFETO_C_TOOL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let brew = PathBuf::from("/opt/homebrew/opt/llvm/bin");
            if brew.exists() { brew } else { PathBuf::new() }
        });
    let target = env::var("TARGET").expect("Cargo sets TARGET");
    assert_eq!(
        target, "aarch64-unknown-none",
        "POSIX bridge is a guest library"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    let include = root.join("include");
    let lib = root.join("lib");
    assert!(
        lib.join("libc.a").exists(),
        "build Picolibc with tools/build-picolibc.py first"
    );
    run(Command::new(tools.join("clang"))
        .args([
            "--target=aarch64-none-elf",
            "-ffreestanding",
            "-fno-stack-protector",
            "-fno-pic",
            "-O2",
            "-I",
        ])
        .arg(&include)
        .args(["-c", "os.c", "-o"])
        .arg(out.join("os.o")));
    run(Command::new(tools.join("llvm-ar"))
        .args(["crs"])
        .arg(out.join("libposixshim.a"))
        .arg(out.join("os.o")));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-search=native={}", lib.display());
    println!("cargo:rustc-link-lib=static=posixshim");
}
