// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Compile hello.c against relibc's headers and link relibc's libc.a, both
//! built outside the workspace by tools/relibc-probe/build-relibc.sh.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("C compiler or archiver is missing");
    assert!(status.success(), "command failed: {cmd:?}");
}

fn main() {
    println!("cargo:rerun-if-changed=hello.c");
    println!("cargo:rerun-if-env-changed=STAFETO_RELIBC");
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let relibc = env::var_os("STAFETO_RELIBC")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../../third/relibc/target"));
    let library = relibc.join("stafeto-libc.a");
    println!("cargo:rerun-if-changed={}", library.display());
    let tools = PathBuf::from("/opt/homebrew/opt/llvm/bin");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("out dir"));
    run(Command::new(tools.join("clang"))
        .args([
            "--target=aarch64-linux-gnu",
            "-mfix-cortex-a53-835769",
            "-nostdinc",
            "-fno-stack-protector",
            "-fno-pic",
            "-O2",
            "-Wall",
            "-Werror",
            "-isystem",
        ])
        .arg(relibc.join("stafeto-include"))
        .args(["-c", "hello.c", "-o"])
        .arg(out.join("hello.o")));
    run(Command::new(tools.join("llvm-ar"))
        .arg("crs")
        .arg(out.join("libhello.a"))
        .arg(out.join("hello.o")));
    std::fs::copy(&library, out.join("librelibcstafeto.a")).expect("relibc libc.a");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=hello");
    println!("cargo:rustc-link-lib=static=relibcstafeto");
}
