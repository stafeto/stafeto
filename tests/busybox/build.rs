// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Links BusyBox's objects (tools/build-busybox.py) and relibc's libc.a
//! (tools/build-relibc.py, cargo xtask relibc).

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=STAFETO_BUSYBOX_ROOT");
    println!("cargo:rerun-if-env-changed=STAFETO_RELIBC_SYSROOT");
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let root = env::var_os("STAFETO_BUSYBOX_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../target/busybox/source"));
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    for (archive, name) in [
        ("libbb/lib.a", "busybox_bb"),
        ("coreutils/lib.a", "busybox_coreutils"),
        ("shell/lib.a", "busybox_shell"),
        ("procps/lib.a", "busybox_procps"),
        ("coreutils/libcoreutils/lib.a", "busybox_libcoreutils"),
    ] {
        let path = root.join(archive);
        assert!(
            path.exists(),
            "build BusyBox with tools/build-busybox.py first"
        );
        println!("cargo:rerun-if-changed={}", path.display());
        std::fs::copy(&path, out.join(format!("lib{name}.a"))).expect("copy BusyBox objects");
        println!("cargo:rustc-link-lib=static={name}");
    }
    println!("cargo:rustc-link-search=native={}", out.display());
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
