// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Compiles data.c with relibc's headers and links relibc's libc.a, both
//! from the sysroot tools/build-relibc.py builds (cargo xtask relibc).

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("C compiler or archiver is missing");
    assert!(status.success(), "command failed: {cmd:?}");
}

fn main() {
    println!("cargo:rerun-if-changed=data.c");
    println!("cargo:rerun-if-env-changed=STAFETO_RELIBC_SYSROOT");
    println!("cargo:rerun-if-env-changed=STAFETO_C_TOOL_DIR");
    println!("cargo:rerun-if-env-changed=STAFETO_DATA_POSIX_MODE");
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let sysroot = env::var_os("STAFETO_RELIBC_SYSROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../target/relibc/sysroot"));
    let tools = env::var_os("STAFETO_C_TOOL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let brew = PathBuf::from("/opt/homebrew/opt/llvm/bin");
            if brew.exists() { brew } else { PathBuf::new() }
        });
    // The role the init-started launcher passes to the program: the image of each mode of
    // `cargo xtask data-posix` names its own (`run`, `write-run`, ...).
    let mode = env::var("STAFETO_DATA_POSIX_MODE").unwrap_or_else(|_| "run".to_owned());
    assert!(
        mode.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
        "STAFETO_DATA_POSIX_MODE {mode:?} is a role name"
    );
    let target = env::var("TARGET").expect("Cargo sets TARGET");
    assert_eq!(
        target, "aarch64-unknown-none",
        "posix-data is a guest program"
    );
    let lib = sysroot.join("lib");
    assert!(
        lib.join("libc.a").exists(),
        "build relibc first: cargo xtask relibc"
    );
    println!("cargo:rerun-if-changed={}", lib.join("libc.a").display());
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    run(Command::new(tools.join("clang"))
        .args([
            // The Linux C ABI relibc's headers describe.
            "--target=aarch64-linux-gnu",
            // Cortex-A53 erratum 835769 (the PinePhone's A64).
            "-mfix-cortex-a53-835769",
            "-nostdinc",
            "-fstack-protector-strong",
            "-fno-pic",
            "-std=c11",
            "-O2",
            // malloc and the others are calls: a probe's allocation is never
            // folded away.
            "-fno-builtin",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-isystem",
        ])
        .arg(sysroot.join("include"))
        .arg(format!("-DDATA_POSIX_MODE=\"{mode}\""))
        .args(["-c", "data.c", "-o"])
        .arg(out.join("data.o")));
    run(Command::new(tools.join("llvm-ar"))
        .arg("crs")
        .arg(out.join("libposixdata.a"))
        .arg(out.join("data.o")));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-search=native={}", lib.display());
    println!("cargo:rustc-link-lib=static=posixdata");
    println!("cargo:rustc-link-lib=static=c");
}
