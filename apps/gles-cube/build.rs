// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Compiles gles-cube.c with the headers of Khronos that tools/build-mesa.py
//! copies to target/mesa/include and relibc's headers, and links the archive
//! of Mesa (target/mesa/lib/libmesa.a, `cargo xtask mesa`), the libc++,
//! libc++abi and libunwind its GLSL compiler needs (target/libcxx, `cargo xtask
//! libcxx`) and relibc's libm.a and libc.a (the sysroot tools/build-relibc.py
//! builds, `cargo xtask relibc`).

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("C compiler or archiver is missing");
    assert!(status.success(), "command failed: {cmd:?}");
}

fn main() {
    println!("cargo:rerun-if-changed=gles-cube.c");
    println!("cargo:rerun-if-env-changed=STAFETO_RELIBC_SYSROOT");
    println!("cargo:rerun-if-env-changed=STAFETO_LIBCXX_DIR");
    println!("cargo:rerun-if-env-changed=STAFETO_MESA_DIR");
    println!("cargo:rerun-if-env-changed=STAFETO_C_TOOL_DIR");
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let sysroot = env::var_os("STAFETO_RELIBC_SYSROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../target/relibc/sysroot"));
    let libcxx = env::var_os("STAFETO_LIBCXX_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../target/libcxx"));
    let mesa = env::var_os("STAFETO_MESA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../target/mesa"));
    let tools = env::var_os("STAFETO_C_TOOL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let brew = PathBuf::from("/opt/homebrew/opt/llvm/bin");
            if brew.exists() { brew } else { PathBuf::new() }
        });
    let target = env::var("TARGET").expect("Cargo sets TARGET");
    assert_eq!(
        target, "aarch64-unknown-none",
        "gles-cube is a guest program"
    );
    let lib = sysroot.join("lib");
    let cxx_lib = libcxx.join("lib");
    let mesa_lib = mesa.join("lib");
    assert!(
        lib.join("libc.a").exists(),
        "build relibc first: cargo xtask relibc"
    );
    assert!(
        cxx_lib.join("libc++.a").exists(),
        "build libc++ first: cargo xtask libcxx"
    );
    assert!(
        mesa_lib.join("libmesa.a").exists(),
        "build Mesa first: cargo xtask mesa"
    );
    for library in ["libc.a", "libm.a"] {
        println!("cargo:rerun-if-changed={}", lib.join(library).display());
    }
    for library in ["libc++.a", "libc++abi.a", "libunwind.a"] {
        println!("cargo:rerun-if-changed={}", cxx_lib.join(library).display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        mesa_lib.join("libmesa.a").display()
    );
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
        // The headers of Khronos lie outside the sysroot.
        .arg("-isystem")
        .arg(mesa.join("include"))
        .args(["-c", "gles-cube.c", "-o"])
        .arg(out.join("gles-cube.o")));
    run(Command::new(tools.join("llvm-ar"))
        .arg("crs")
        .arg(out.join("libglescube.a"))
        .arg(out.join("gles-cube.o")));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-search=native={}", mesa_lib.display());
    println!("cargo:rustc-link-search=native={}", cxx_lib.display());
    println!("cargo:rustc-link-search=native={}", lib.display());
    println!("cargo:rustc-link-lib=static=glescube");
    println!("cargo:rustc-link-lib=static=mesa");
    println!("cargo:rustc-link-lib=static=c++");
    println!("cargo:rustc-link-lib=static=c++abi");
    println!("cargo:rustc-link-lib=static=unwind");
    println!("cargo:rustc-link-lib=static=m");
    println!("cargo:rustc-link-lib=static=c");
}
