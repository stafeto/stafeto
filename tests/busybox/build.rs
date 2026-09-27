// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=STAFETO_BUSYBOX_ROOT");
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let root = env::var_os("STAFETO_BUSYBOX_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../target/busybox/source"));
    for archive in ["libbb/lib.a", "coreutils/lib.a"] {
        assert!(
            root.join(archive).exists(),
            "build BusyBox with tools/build-busybox.py first"
        );
    }
    println!(
        "cargo:rerun-if-changed={}",
        root.join("libbb/lib.a").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        root.join("coreutils/lib.a").display()
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    std::fs::copy(root.join("libbb/lib.a"), out.join("libbusybox_bb.a")).expect("copy libbb");
    std::fs::copy(
        root.join("coreutils/lib.a"),
        out.join("libbusybox_coreutils.a"),
    )
    .expect("copy coreutils");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=busybox_bb");
    println!("cargo:rustc-link-lib=static=busybox_coreutils");
    println!(
        "cargo:rustc-link-search=native={}",
        manifest
            .join("../../target/picolibc/root/usr/lib")
            .display()
    );
    println!("cargo:rustc-link-lib=static=c");
}
