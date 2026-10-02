// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Links the object of one os-test test (STAFETO_OS_TEST_OBJECT, which
//! cargo xtask os-test sets) and relibc's libc.a. Without the variable the
//! program is an empty C main, so the workspace still builds.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("C compiler or archiver is missing");
    assert!(status.success(), "command failed: {cmd:?}");
}

fn main() {
    println!("cargo:rerun-if-env-changed=STAFETO_OS_TEST_OBJECT");
    println!("cargo:rerun-if-env-changed=STAFETO_RELIBC_SYSROOT");
    println!("cargo:rerun-if-env-changed=STAFETO_C_TOOL_DIR");
    if env::var("TARGET").as_deref() != Ok("aarch64-unknown-none") {
        return;
    }
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    let tools = env::var_os("STAFETO_C_TOOL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let brew = PathBuf::from("/opt/homebrew/opt/llvm/bin");
            if brew.exists() { brew } else { PathBuf::new() }
        });
    let object = match env::var_os("STAFETO_OS_TEST_OBJECT") {
        Some(object) => PathBuf::from(object),
        None => {
            let stub = out.join("empty.c");
            std::fs::write(&stub, "int main(void) { return 0; }\n").expect("write the stub");
            run(Command::new(tools.join("clang"))
                .args([
                    "--target=aarch64-linux-gnu",
                    "-mfix-cortex-a53-835769",
                    "-c",
                ])
                .arg(&stub)
                .arg("-o")
                .arg(out.join("empty.o")));
            out.join("empty.o")
        }
    };
    println!("cargo:rerun-if-changed={}", object.display());
    let archive = out.join("libostest.a");
    let _ = std::fs::remove_file(&archive);
    run(Command::new(tools.join("llvm-ar"))
        .arg("crs")
        .arg(&archive)
        .arg(&object));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=ostest");
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
