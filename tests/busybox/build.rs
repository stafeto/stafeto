// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("C compiler or archiver is missing");
    assert!(status.success(), "command failed: {cmd:?}");
}

fn main() {
    println!("cargo:rerun-if-env-changed=STAFETO_BUSYBOX_ROOT");
    println!("cargo:rerun-if-env-changed=STAFETO_C_TOOL_DIR");
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
    println!("cargo:rerun-if-changed=ash_os.c");
    let archive = root.join("shell/lib.a");
    assert!(
        archive.exists(),
        "build BusyBox ash with tools/build-busybox.py first"
    );
    println!("cargo:rerun-if-changed={}", archive.display());
    std::fs::copy(archive, out.join("libbusybox_shell.a")).expect("copy shell");
    println!("cargo:rustc-link-lib=static=busybox_shell");
    let tools = env::var_os("STAFETO_C_TOOL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let brew = PathBuf::from("/opt/homebrew/opt/llvm/bin");
            if brew.exists() { brew } else { PathBuf::new() }
        });
    let include = manifest.join("../../target/picolibc/root/usr/include");
    let compat = manifest.join("../../tools/busybox/compat");
    run(Command::new(tools.join("clang"))
        .args([
            "--target=aarch64-none-elf",
            "-ffreestanding",
            "-fno-stack-protector",
            "-O2",
        ])
        .arg("-I")
        .arg(&compat)
        .arg("-I")
        .arg(&include)
        .args(["-c", "ash_os.c", "-o"])
        .arg(out.join("ash_os.o")));
    run(Command::new(tools.join("llvm-ar"))
        .arg("crs")
        .arg(out.join("libash_os.a"))
        .arg(out.join("ash_os.o")));
    println!("cargo:rustc-link-lib=static=ash_os");
    println!(
        "cargo:rustc-link-search=native={}",
        manifest
            .join("../../target/picolibc/root/usr/lib")
            .display()
    );
    println!("cargo:rustc-link-lib=static=c");
}
