// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Compiles procs.c with relibc's headers and links relibc's libc.a, both
//! from the sysroot tools/build-relibc.py builds (cargo xtask relibc).

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("C compiler or archiver is missing");
    assert!(status.success(), "command failed: {cmd:?}");
}

fn main() {
    println!("cargo:rerun-if-changed=procs.c");
    println!("cargo:rerun-if-changed=lifetime.c");
    println!("cargo:rerun-if-changed=files.c");
    println!("cargo:rerun-if-changed=names.c");
    println!("cargo:rerun-if-changed=names-loss.c");
    println!("cargo:rerun-if-changed=names-volley.c");
    println!("cargo:rerun-if-changed=names-signal.c");
    println!("cargo:rerun-if-changed=open-policy.c");
    println!("cargo:rerun-if-changed=pending-open.c");
    println!("cargo:rerun-if-changed=pending-fork.c");
    println!("cargo:rerun-if-changed=cleanup.c");
    println!("cargo:rerun-if-changed=jobs.c");
    println!("cargo:rerun-if-changed=loader-abort.c");
    println!("cargo:rerun-if-changed=image-gates.c");
    println!("cargo:rerun-if-env-changed=STAFETO_RELIBC_SYSROOT");
    println!("cargo:rerun-if-env-changed=STAFETO_C_TOOL_DIR");
    // The branches of the steps mode (xtask process-steps N).
    println!("cargo:rerun-if-env-changed=STEPS_BRANCHES");
    let branches = env::var("STEPS_BRANCHES").unwrap_or_else(|_| "7".to_owned());
    // The identity sessions the steps mode clones and closes before the
    // exec steps, beside the one of the change stages (a measurement knob).
    println!("cargo:rerun-if-env-changed=STEPS_SESSIONS");
    let sessions = env::var("STEPS_SESSIONS").unwrap_or_else(|_| "0".to_owned());
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let sysroot = env::var_os("STAFETO_RELIBC_SYSROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../target/relibc/sysroot"));
    let tools = env::var_os("STAFETO_C_TOOL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let brew = PathBuf::from("/opt/homebrew/opt/llvm/bin");
            if brew.exists() { brew } else { PathBuf::new() }
        });
    let target = env::var("TARGET").expect("Cargo sets TARGET");
    assert_eq!(
        target, "aarch64-unknown-none",
        "posix-procs is a guest program"
    );
    let lib = sysroot.join("lib");
    assert!(
        lib.join("libc.a").exists(),
        "build relibc first: cargo xtask relibc"
    );
    println!("cargo:rerun-if-changed={}", lib.join("libc.a").display());
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    run(Command::new(tools.join("clang"))
        .arg(format!(
            "-DLOADER_ABORT_PROBE={}",
            u8::from(env::var_os("CARGO_FEATURE_LOADER_ABORT").is_some())
        ))
        .arg(format!("-DSTEPS_BRANCHES={branches}"))
        .arg(format!("-DSTEPS_SESSIONS={sessions}"))
        .arg(format!(
            "-DNATIVE_SCOPES_LAUNCHER={}",
            u8::from(env::var_os("CARGO_FEATURE_NATIVE_SCOPES_LAUNCHER").is_some())
        ))
        .arg(format!(
            "-DIMAGE_INFO_PROBE={}",
            u8::from(env::var_os("CARGO_FEATURE_IMAGE_INFO_PROBE").is_some())
        ))
        .arg(format!(
            "-DNAMES_PROBE={}",
            u8::from(env::var_os("CARGO_FEATURE_NAMES_PROBE").is_some())
        ))
        .arg(format!(
            "-DNAMES_LOSS={}",
            u8::from(env::var_os("CARGO_FEATURE_NAMES_LOSS").is_some())
        ))
        .arg(format!(
            "-DCHANGE_STEPS={}",
            u8::from(env::var_os("CARGO_FEATURE_CHANGE_STEPS").is_some())
        ))
        .arg(format!(
            "-DPENDING_OPEN_PROBE={}",
            u8::from(env::var_os("CARGO_FEATURE_PENDING_OPEN").is_some())
        ))
        .arg(format!(
            "-DIMAGE_GATES_NORMAL={}",
            u8::from(env::var_os("CARGO_FEATURE_IMAGE_GATES_NORMAL").is_some())
        ))
        .arg(format!(
            "-DIMAGE_GATES_PROBE={}",
            u8::from(env::var_os("CARGO_FEATURE_IMAGE_GATES").is_some())
        ))
        .arg(format!(
            "-DJOB_CONTROL_PROBE={}",
            u8::from(env::var_os("CARGO_FEATURE_JOBS").is_some())
        ))
        .args([
            // The Linux C ABI relibc's headers describe.
            "--target=aarch64-linux-gnu",
            // Cortex-A53 erratum 835769 (the PinePhone's A64).
            "-mfix-cortex-a53-835769",
            "-nostdinc",
            "-fno-stack-protector",
            "-fno-pic",
            "-std=c11",
            "-O2",
            // malloc and the others are calls: a probe's allocation is never
            // folded away.
            "-fno-builtin",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-isystem",
        ])
        .arg(sysroot.join("include"))
        .args([
            "-c",
            if env::var_os("CARGO_FEATURE_LIFETIME_PROBE").is_some() {
                "lifetime.c"
            } else if env::var_os("CARGO_FEATURE_IMAGE_GATES").is_some() {
                "image-gates.c"
            } else if env::var_os("CARGO_FEATURE_AUTH_PROBE").is_some() {
                "cleanup.c"
            } else if env::var_os("CARGO_FEATURE_FILES").is_some() {
                "files.c"
            } else {
                "procs.c"
            },
            "-o",
        ])
        .arg(out.join("procs.o")));
    run(Command::new(tools.join("llvm-ar"))
        .arg("crs")
        .arg(out.join("libposixprocs.a"))
        .arg(out.join("procs.o")));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-search=native={}", lib.display());
    println!("cargo:rustc-link-lib=static=posixprocs");
    println!("cargo:rustc-link-lib=static=c");
}
