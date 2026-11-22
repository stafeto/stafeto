// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Compiles cxx-probe.cpp with the headers of libc++ and relibc and links
//! libc++, libc++abi, libunwind and relibc's libc.a, from target/libcxx
//! (tools/build-libcxx.py, `cargo xtask libcxx`) and the sysroot
//! tools/build-relibc.py builds (`cargo xtask relibc`).

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("C++ compiler or archiver is missing");
    assert!(status.success(), "command failed: {cmd:?}");
}

fn main() {
    println!("cargo:rerun-if-changed=cxx-probe.cpp");
    println!("cargo:rerun-if-env-changed=STAFETO_RELIBC_SYSROOT");
    println!("cargo:rerun-if-env-changed=STAFETO_LIBCXX_DIR");
    println!("cargo:rerun-if-env-changed=STAFETO_C_TOOL_DIR");
    println!("cargo:rerun-if-env-changed=STAFETO_CXX_PROBE_NO_EH_FRAME_HDR");
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let sysroot = env::var_os("STAFETO_RELIBC_SYSROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../target/relibc/sysroot"));
    let libcxx = env::var_os("STAFETO_LIBCXX_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../target/libcxx"));
    let tools = env::var_os("STAFETO_C_TOOL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let brew = PathBuf::from("/opt/homebrew/opt/llvm/bin");
            if brew.exists() { brew } else { PathBuf::new() }
        });
    let target = env::var("TARGET").expect("Cargo sets TARGET");
    assert_eq!(
        target, "aarch64-unknown-none",
        "cxx-probe is a guest program"
    );
    let lib = sysroot.join("lib");
    let cxx_lib = libcxx.join("lib");
    assert!(
        lib.join("libc.a").exists(),
        "build relibc first: cargo xtask relibc"
    );
    assert!(
        cxx_lib.join("libc++.a").exists(),
        "build libc++ first: cargo xtask libcxx"
    );
    for library in ["libc.a", "libm.a"] {
        println!("cargo:rerun-if-changed={}", lib.join(library).display());
    }
    for library in ["libc++.a", "libc++abi.a", "libunwind.a"] {
        println!("cargo:rerun-if-changed={}", cxx_lib.join(library).display());
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    run(Command::new(tools.join("clang++"))
        .args([
            // The Linux C ABI relibc's headers describe.
            "--target=aarch64-linux-gnu",
            // Cortex-A53 erratum 835769 (the PinePhone's A64).
            "-mfix-cortex-a53-835769",
            "-mno-outline-atomics",
            "-nostdinc",
            "-nostdinc++",
            "-fstack-protector-strong",
            "-fno-pic",
            "-std=c++23",
            "-O2",
            // The compiler's unwind rows for every frame, and no outlining
            // (which drops them): exceptions need them.
            "-fexceptions",
            "-frtti",
            "-fasynchronous-unwind-tables",
            "-mllvm",
            "-enable-machine-outliner=never",
            // malloc and the others are calls: a probe's allocation is never
            // folded away.
            "-fno-builtin",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-isystem",
        ])
        .arg(libcxx.join("include/c++/v1"))
        .arg("-isystem")
        .arg(sysroot.join("include"))
        .args(["-c", "cxx-probe.cpp", "-o"])
        .arg(out.join("cxx-probe.o")));
    run(Command::new(tools.join("llvm-ar"))
        .arg("crs")
        .arg(out.join("libcxxprobe.a"))
        .arg(out.join("cxx-probe.o")));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-search=native={}", cxx_lib.display());
    println!("cargo:rustc-link-search=native={}", lib.display());
    // The planted fault of the probe's check: a program linked without the
    // header of its unwind tables (xtask cxx-probe refuses it).
    if env::var_os("STAFETO_CXX_PROBE_NO_EH_FRAME_HDR").is_some() {
        println!("cargo:rustc-link-arg=--no-eh-frame-hdr");
    }
    println!("cargo:rustc-link-lib=static=cxxprobe");
    println!("cargo:rustc-link-lib=static=c++");
    println!("cargo:rustc-link-lib=static=c++abi");
    println!("cargo:rustc-link-lib=static=unwind");
    println!("cargo:rustc-link-lib=static=c");
}
