// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The two constants of the build the tool trusts, made as the package
//! service makes them (services/pkgd/build.rs): the series of the system
//! (`major.minor` of this crate's version, which is the workspace's) and the
//! public keys of the roots. A development build names a file of `.pub`
//! lines in `STAFETO_PKG_ROOTS` (xtask gives the root of its development
//! keys to both programs); without it the roots are the official ones, which
//! `pkgfmt::OFFICIAL_ROOTS` holds.

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=STAFETO_PKG_ROOTS");
    let version = env::var("CARGO_PKG_VERSION").expect("Cargo sets the version");
    let series: Vec<&str> = version.split('.').take(2).collect();
    let mut out = format!("pub const SERIES: &str = {:?};\n", series.join("."));
    match env::var_os("STAFETO_PKG_ROOTS") {
        Some(path) => {
            println!("cargo:rerun-if-changed={}", PathBuf::from(&path).display());
            let text = fs::read_to_string(&path).expect("STAFETO_PKG_ROOTS names a readable file");
            let lines: Vec<String> = text
                .lines()
                .map(|l| format!("{:?}", format!("{l}\n")))
                .collect();
            assert!(!lines.is_empty(), "STAFETO_PKG_ROOTS holds no key");
            out.push_str(&format!(
                "pub const ROOTS: &[&str] = &[{}];\n",
                lines.join(", ")
            ));
        }
        None => out.push_str("pub const ROOTS: &[&str] = pkgfmt::OFFICIAL_ROOTS;\n"),
    }
    // The stack of a program started from its file is its PT_GNU_STACK (the loader, at least 64 KiB);
    // xtask holds the same number (`base_image::PKG_STACK_SIZE`) and tests it against the file.
    println!("cargo:rustc-link-arg-bins=-zstack-size=262144");
    let dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    fs::write(dir.join("config.rs"), out).expect("OUT_DIR is writable");
}
