// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Links bash's object (tools/build-bash.py) and relibc's libc.a
//! (tools/build-relibc.py, cargo xtask relibc).

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=STAFETO_BASH_OBJECT");
    println!("cargo:rerun-if-env-changed=STAFETO_C_TOOL_DIR");
    println!("cargo:rerun-if-env-changed=STAFETO_RELIBC_SYSROOT");
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let object = env::var_os("STAFETO_BASH_OBJECT")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../target/bash/bash.o"));
    assert!(object.exists(), "build bash with tools/build-bash.py first");
    println!("cargo:rerun-if-changed={}", object.display());
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    // The object is one member of an archive: the linker takes it for
    // `main`, which relibc's start asks for.
    let archive = out.join("libbash_object.a");
    let _ = std::fs::remove_file(&archive);
    let tools = env::var_os("STAFETO_C_TOOL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let brew = PathBuf::from("/opt/homebrew/opt/llvm/bin");
            if brew.exists() { brew } else { PathBuf::new() }
        });
    let status = std::process::Command::new(tools.join("llvm-ar"))
        .arg("crs")
        .arg(&archive)
        .arg(&object)
        .status()
        .expect("llvm-ar is missing");
    assert!(status.success(), "llvm-ar failed");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static:+whole-archive=bash_object");
    // bash's program keeps neither debug sections nor symbols: the file has
    // to fit the RAM file service, and its pages are the image's.
    println!("cargo:rustc-link-arg-bins=--strip-all");
    let sysroot = env::var_os("STAFETO_RELIBC_SYSROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../target/relibc/sysroot"));
    let lib = sysroot.join("lib");
    assert!(
        lib.join("libc.a").exists(),
        "build relibc first: cargo xtask relibc"
    );
    println!("cargo:rerun-if-changed={}", lib.join("libc.a").display());
    println!("cargo:rustc-link-search=native={}", lib.display());
    println!("cargo:rustc-link-lib=static=c");
}
