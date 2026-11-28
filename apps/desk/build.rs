// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Builds the C side of the window manager `desk`: runs tools/build-lvgl.py
//! (which runs tools/build-freetype.py first), compiles the sources of
//! ports/desk against relibc's headers, the window and manager headers and the
//! headers of LVGL and FreeType (the configuration is that of ports/lvgl), and
//! links them with liblvgl.a, libfreetype.a and relibc's libc.a. Both
//! libraries and the sysroot come from the scripts and from `cargo xtask
//! relibc`.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The C files of the program: the loop, the policy, the drawing and the glue
/// between LVGL and the windows.
const SOURCES: [&str; 4] = ["main.c", "policy.c", "draw.c", "desk_io.c"];

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("a build tool is missing");
    assert!(status.success(), "command failed: {cmd:?}");
}

/// Fails when the file holds the build directory's path (a `__FILE__` that
/// -fmacro-prefix-map should have mapped).
fn no_build_path(file: &Path, root: &Path) {
    let bytes = std::fs::read(file).expect("the object is readable");
    let needle = root.to_string_lossy();
    let needle = needle.as_bytes();
    assert!(
        !bytes.windows(needle.len()).any(|w| w == needle),
        "{} holds the build directory's path {}",
        file.display(),
        root.display()
    );
}

fn main() {
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    // The canonical path: -fmacro-prefix-map must match the text of __FILE__.
    let root = manifest
        .join("../..")
        .canonicalize()
        .expect("the workspace root exists");
    let port = root.join("ports/desk");
    // The configuration of LVGL is the one the library was built with.
    let lvgl_port = root.join("ports/lvgl");
    for file in SOURCES {
        println!("cargo:rerun-if-changed={}", port.join(file).display());
    }
    for file in ["policy.h", "draw.h", "desk_io.h"] {
        println!("cargo:rerun-if-changed={}", port.join(file).display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        lvgl_port.join("lv_conf.h").display()
    );
    for file in [
        "tools/build-lvgl.py",
        "tools/build-freetype.py",
        "packages/lvgl.toml",
        "packages/freetype.toml",
        "lib/posix-crt/window/stafeto/window.h",
        "lib/posix-crt/window/stafeto/manager.h",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(file).display());
    }
    println!("cargo:rerun-if-env-changed=STAFETO_RELIBC_SYSROOT");
    println!("cargo:rerun-if-env-changed=STAFETO_C_TOOL_DIR");
    let sysroot = env::var_os("STAFETO_RELIBC_SYSROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target/relibc/sysroot"));
    let tools = env::var_os("STAFETO_C_TOOL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let brew = PathBuf::from("/opt/homebrew/opt/llvm/bin");
            if brew.exists() { brew } else { PathBuf::new() }
        });
    let target = env::var("TARGET").expect("Cargo sets TARGET");
    assert_eq!(target, "aarch64-unknown-none", "desk is a guest program");
    let lib = sysroot.join("lib");
    assert!(
        lib.join("libc.a").exists(),
        "build relibc first: cargo xtask relibc"
    );
    println!("cargo:rerun-if-changed={}", lib.join("libc.a").display());
    // The libraries: the scripts check their sources and skip what is built.
    run(Command::new("python3").arg(root.join("tools/build-lvgl.py")));
    let lvgl = root.join("target/lvgl");
    let freetype = root.join("target/freetype");
    for built in [lvgl.join("liblvgl.a"), freetype.join("libfreetype.a")] {
        println!("cargo:rerun-if-changed={}", built.display());
        no_build_path(&built, &root);
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    let mut objects: Vec<PathBuf> = Vec::new();
    for file in SOURCES {
        let object = out.join(Path::new(file).with_extension("o"));
        run(Command::new(tools.join("clang"))
            .args([
                // The Linux C ABI relibc's headers describe.
                "--target=aarch64-linux-gnu",
                // Cortex-A53 erratum 835769 (the PinePhone's A64).
                "-mfix-cortex-a53-835769",
                "-nostdinc",
                "-fstack-protector-strong",
                "-fno-pic",
                "-std=gnu11",
                "-O2",
                // The char of AArch64 Linux, wrapping overflow and no fused
                // multiply-add, as the libraries and the host reference.
                "-funsigned-char",
                "-fwrapv",
                "-ffp-contract=off",
                "-ffunction-sections",
                "-fdata-sections",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-isystem",
            ])
            .arg(sysroot.join("include"))
            // No object holds the build directory's path.
            .arg(format!("-fmacro-prefix-map={}/=", root.display()))
            .arg("-I")
            .arg(&port)
            .arg("-I")
            .arg(&lvgl_port)
            .arg("-I")
            .arg(lvgl.join("lvgl-9.6.0"))
            .arg("-I")
            .arg(freetype.join("include"))
            // The header of the window library lies outside the sysroot.
            .arg("-I")
            .arg(root.join("lib/posix-crt/window"))
            .arg("-c")
            .arg(port.join(file))
            .arg("-o")
            .arg(&object));
        no_build_path(&object, &root);
        objects.push(object);
    }
    let archive = out.join("libdesk.a");
    let mut ar = Command::new(tools.join("llvm-ar"));
    ar.arg("crs").arg(&archive).args(&objects);
    run(&mut ar);
    // The stack of a program started from its file is its PT_GNU_STACK (the
    // loader, at least 64 KiB): glyphs are drawn on it (FreeType's rasterizer
    // keeps a 16 KiB pool there, LVGL recurses over the widgets). The size is
    // the demo's.
    println!("cargo:rustc-link-arg-bins=-zstack-size=262144");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-search=native={}", lvgl.display());
    println!("cargo:rustc-link-search=native={}", freetype.display());
    println!("cargo:rustc-link-search=native={}", lib.display());
    println!("cargo:rustc-link-lib=static=desk");
    println!("cargo:rustc-link-lib=static=lvgl");
    println!("cargo:rustc-link-lib=static=freetype");
    println!("cargo:rustc-link-lib=static=c");
}
