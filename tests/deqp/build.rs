// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Links the dEQP-EGL module: the archives of target/deqp that
//! `deqp-egl.link` names (tools/build-deqp.py, `cargo xtask deqp`), the
//! archive of Mesa (target/mesa, `cargo xtask mesa`), the libc++, libc++abi
//! and libunwind of target/libcxx (`cargo xtask libcxx`) and relibc's libm.a
//! and libc.a (the sysroot `cargo xtask relibc` builds). The program's own C++
//! is in the archives, so the crate compiles nothing.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=STAFETO_RELIBC_SYSROOT");
    println!("cargo:rerun-if-env-changed=STAFETO_LIBCXX_DIR");
    println!("cargo:rerun-if-env-changed=STAFETO_MESA_DIR");
    println!("cargo:rerun-if-env-changed=STAFETO_DEQP_DIR");
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let dir = |variable: &str, default: &str| {
        env::var_os(variable)
            .map(PathBuf::from)
            .unwrap_or_else(|| manifest.join("../..").join(default))
    };
    let sysroot = dir("STAFETO_RELIBC_SYSROOT", "target/relibc/sysroot");
    let libcxx = dir("STAFETO_LIBCXX_DIR", "target/libcxx");
    let mesa = dir("STAFETO_MESA_DIR", "target/mesa");
    let deqp = dir("STAFETO_DEQP_DIR", "target/deqp");
    let target = env::var("TARGET").expect("Cargo sets TARGET");
    assert_eq!(
        target, "aarch64-unknown-none",
        "deqp-egl is a guest program"
    );
    let list = deqp.join("deqp-egl.link");
    assert!(
        list.exists(),
        "build dEQP first: cargo xtask deqp (no {})",
        list.display()
    );
    println!("cargo:rerun-if-changed={}", list.display());
    for (library, base) in [
        ("libc.a", sysroot.join("lib")),
        ("libm.a", sysroot.join("lib")),
        ("libc++.a", libcxx.join("lib")),
        ("libc++abi.a", libcxx.join("lib")),
        ("libunwind.a", libcxx.join("lib")),
        ("libmesa.a", mesa.join("lib")),
    ] {
        assert!(
            base.join(library).exists(),
            "{library} is missing in {}",
            base.display()
        );
        println!("cargo:rerun-if-changed={}", base.join(library).display());
    }
    println!(
        "cargo:rustc-link-search=native={}",
        deqp.join("lib").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        mesa.join("lib").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        libcxx.join("lib").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        sysroot.join("lib").display()
    );
    // The framework's recursion and the GLSL compiler of Mesa need more than
    // the 64 KiB a program starts with.
    println!("cargo:rustc-link-arg-bins=-zstack-size=1048576");
    // The log of the framework goes to the standard output
    // (tests/deqp/platform/tcuStafetoMain.cpp).
    println!("cargo:rustc-link-arg-bins=--wrap=fopen");
    let names = fs::read_to_string(&list).expect("read the link list");
    for line in names.lines().filter(|l| !l.is_empty()) {
        let name = line
            .strip_prefix("lib")
            .and_then(|n| n.strip_suffix(".a"))
            .unwrap_or_else(|| panic!("{line} is not the name of an archive"));
        // The object of the package entry registers the module by a static
        // object nothing refers to: the linker takes the whole archive.
        if name.ends_with("-main") {
            println!("cargo:rustc-link-lib=static:+whole-archive={name}");
        } else {
            println!("cargo:rustc-link-lib=static={name}");
        }
    }
    for name in ["mesa", "c++", "c++abi", "unwind", "m", "c"] {
        println!("cargo:rustc-link-lib=static={name}");
    }
}
