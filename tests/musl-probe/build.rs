// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Compile the relibc probe's hello.c against musl's headers and link musl's
//! libc.a, built outside the workspace with a stafeto __syscall backend.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("C compiler or archiver is missing");
    assert!(status.success(), "command failed: {cmd:?}");
}

fn main() {
    println!("cargo:rerun-if-changed=../relibc-probe/hello.c");
    println!("cargo:rerun-if-env-changed=STAFETO_MUSL");
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let musl = env::var_os("STAFETO_MUSL")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../../third/musl/out"));
    let library = musl.join("lib/libc.a");
    println!("cargo:rerun-if-changed={}", library.display());
    let tools = PathBuf::from("/opt/homebrew/opt/llvm/bin");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("out dir"));
    run(Command::new(tools.join("clang"))
        .args([
            "--target=aarch64-linux-musl",
            "-mfix-cortex-a53-835769",
            "-nostdinc",
            "-fno-stack-protector",
            "-fno-pic",
            "-O2",
            "-Wall",
            "-Werror",
            "-DPROBE=\"musl-probe\"",
            "-isystem",
        ])
        .arg(musl.join("include"))
        .args(["-c", "../relibc-probe/hello.c", "-o"])
        .arg(out.join("hello.o")));
    run(Command::new(tools.join("llvm-ar"))
        .arg("crs")
        .arg(out.join("libhello.a"))
        .arg(out.join("hello.o")));
    std::fs::copy(&library, out.join("libmuslstafeto.a")).expect("musl libc.a");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=hello");
    println!("cargo:rustc-link-lib=static=muslstafeto");
}
