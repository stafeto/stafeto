// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use std::{env, path::PathBuf, process::Command};
fn run(command: &mut Command) {
    assert!(command.status().expect("C tool is missing").success());
}
fn main() {
    println!("cargo:rerun-if-changed=probe.c");
    println!("cargo:rerun-if-env-changed=STAFETO_RELIBC_SYSROOT");
    println!("cargo:rerun-if-env-changed=STAFETO_C_TOOL_DIR");
    assert_eq!(env::var("TARGET").unwrap(), "aarch64-unknown-none");
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let sysroot = env::var_os("STAFETO_RELIBC_SYSROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("../../target/relibc/sysroot"));
    let tools = env::var_os("STAFETO_C_TOOL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/opt/homebrew/opt/llvm/bin"));
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    run(Command::new(tools.join("clang"))
        .args([
            "--target=aarch64-linux-gnu",
            "-mfix-cortex-a53-835769",
            "-nostdinc",
            "-fno-stack-protector",
            "-fno-pic",
            "-std=c11",
            "-O2",
            "-fno-builtin",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-isystem",
        ])
        .arg(sysroot.join("include"))
        .args(["-c", "probe.c", "-o"])
        .arg(out.join("probe.o")));
    run(Command::new(tools.join("llvm-ar"))
        .arg("crs")
        .arg(out.join("libramfsgc.a"))
        .arg(out.join("probe.o")));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!(
        "cargo:rustc-link-search=native={}",
        sysroot.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=ramfsgc");
    println!("cargo:rustc-link-lib=static=c");
}
