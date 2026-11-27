// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Compiles layer.c with relibc's headers and links relibc's libc.a, both
//! from the sysroot tools/build-relibc.py builds (cargo xtask relibc).

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("C compiler or archiver is missing");
    assert!(status.success(), "command failed: {cmd:?}");
}

fn main() {
    println!("cargo:rerun-if-changed=layer.c");
    println!("cargo:rerun-if-env-changed=STAFETO_RELIBC_SYSROOT");
    println!("cargo:rerun-if-env-changed=STAFETO_C_TOOL_DIR");
    println!("cargo:rerun-if-env-changed=STAFETO_LAYER_POSIX_MODE");
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
    // The role the init-started launcher passes to the program: the image of this probe
    // names it (`run`).
    let mut mode = env::var("STAFETO_LAYER_POSIX_MODE").unwrap_or_else(|_| "run".to_owned());
    // The write probe has two boots on one disk: the phases are features (`cargo xtask layer-posix
    // write`).
    if env::var_os("CARGO_FEATURE_PHASE_WRITE").is_some() {
        mode = "write".to_owned();
    }
    if env::var_os("CARGO_FEATURE_PHASE_REREAD").is_some() {
        mode = "reread".to_owned();
    }
    // The copy probe has two boots on one disk as well (`cargo xtask layer-posix copy`).
    if env::var_os("CARGO_FEATURE_PHASE_COPY").is_some() {
        mode = "copy".to_owned();
    }
    if env::var_os("CARGO_FEATURE_PHASE_COPYREREAD").is_some() {
        mode = "copyreread".to_owned();
    }
    assert!(
        mode.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
        "STAFETO_LAYER_POSIX_MODE {mode:?} is a role name"
    );
    let target = env::var("TARGET").expect("Cargo sets TARGET");
    assert_eq!(
        target, "aarch64-unknown-none",
        "layer-posix is a guest program"
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
        .arg(format!("-DLAYER_POSIX_MODE=\"{mode}\""))
        .args(["-c", "layer.c", "-o"])
        .arg(out.join("data.o")));
    run(Command::new(tools.join("llvm-ar"))
        .arg("crs")
        .arg(out.join("liblayerposix.a"))
        .arg(out.join("data.o")));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-search=native={}", lib.display());
    println!("cargo:rustc-link-lib=static=layerposix");
    println!("cargo:rustc-link-lib=static=c");
}
