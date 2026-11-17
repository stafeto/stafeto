// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Builds pixman (tools/build-pixman.py, which fetches the pinned source and
//! checks its SHA-256) for programs and links it. On any other target the
//! crate is empty: the host tests of the service run on a plain copy loop.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../tools/build-pixman.py");
    println!("cargo:rerun-if-changed=../../packages/pixman.toml");
    println!("cargo:rerun-if-changed=../../ports/pixman");
    println!("cargo:rerun-if-env-changed=STAFETO_C_TOOL_DIR");
    if env::var("TARGET").as_deref() != Ok("aarch64-unknown-none") {
        return;
    }
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let root = manifest.join("../..");
    let status = Command::new("python3")
        .arg(root.join("tools/build-pixman.py"))
        .status()
        .expect("python3 is missing");
    assert!(status.success(), "tools/build-pixman.py failed");
    println!(
        "cargo:rustc-link-search=native={}",
        root.join("target/pixman").display()
    );
    println!("cargo:rustc-link-lib=static=pixman");
}
