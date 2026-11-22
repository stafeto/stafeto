// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Compiles littlefs (third-party/littlefs, with the change of STAFETO-CHANGES.md) and the flat interface of `csrc/glue.c` into
//! one archive. For the target (`aarch64-unknown-none`, no C library) the build is freestanding
//! with the string functions of `csrc/shim.c` and its own `string.h`; for the host it is the host's
//! compiler and library. littlefs never allocates (LFS_NO_MALLOC) and prints nothing.

use std::{env, path::PathBuf, process::Command};

/// An archiver that indexes ELF objects. The `ar` of macOS archives them with no symbol index, and
/// the linker then finds no `datafs_*`. The Rust toolchain's `llvm-ar` (the component
/// `llvm-tools`, which the repository's toolchain file names) does it on every host. None when the
/// environment names an archiver (`AR_aarch64_unknown_none` or `AR`, which `cc` reads) or the
/// toolchain has none.
fn elf_archiver() -> Option<PathBuf> {
    println!("cargo:rerun-if-env-changed=AR_aarch64_unknown_none");
    println!("cargo:rerun-if-env-changed=AR");
    if env::var_os("AR_aarch64_unknown_none").is_some() || env::var_os("AR").is_some() {
        return None;
    }
    let rustc = env::var_os("RUSTC")?;
    let out = Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .ok()?;
    let sysroot = PathBuf::from(String::from_utf8(out.stdout).ok()?.trim());
    let host = env::var("HOST").ok()?;
    let tool = sysroot
        .join("lib/rustlib")
        .join(host)
        .join("bin")
        .join(if cfg!(windows) {
            "llvm-ar.exe"
        } else {
            "llvm-ar"
        });
    tool.is_file().then_some(tool)
}

fn main() {
    let lfs =
        PathBuf::from(env::var("DEP_LITTLEFS_ROOT").expect("the littlefs crate says its root"));
    let own =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("Cargo sets the manifest directory"));
    let bare = env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "none");

    let mut build = cc::Build::new();
    if env::var_os("CARGO_FEATURE_BREAK_DATAFS_CONSISTENT").is_some() {
        build.define("DATAFS_BREAK_CONSISTENT", None);
    }
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_BREAK_DATAFS_CONSISTENT");
    if env::var_os("CARGO_FEATURE_BREAK_DATAFS_CTZ_HINTS").is_some() {
        build.define("LFS_CTZ_HINTS_NO_DROP", None);
    }
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_BREAK_DATAFS_CTZ_HINTS");
    if env::var_os("CARGO_FEATURE_BREAK_DATAFS_TRUST_PROG").is_some() {
        build.define("LFS_TRUST_PROG_NO_COPY", None);
    }
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_BREAK_DATAFS_TRUST_PROG");
    build
        .file(lfs.join("lfs.c"))
        .file(lfs.join("lfs_util.c"))
        .file(own.join("csrc/glue.c"))
        .include(&lfs)
        .define("LFS_NO_MALLOC", None)
        .define("LFS_NO_DEBUG", None)
        .define("LFS_NO_WARN", None)
        .define("LFS_NO_ERROR", None)
        .define("LFS_NO_ASSERT", None)
        .opt_level_str("s")
        .warnings(true)
        .extra_warnings(true)
        .flag_if_supported("-Wno-unused-function")
        .flag_if_supported("-Wno-unused-parameter");
    if bare {
        if let Some(ar) = elf_archiver() {
            build.archiver(&ar);
        }
        build
            .include(own.join("csrc/include"))
            .compiler(env::var("CC_aarch64_unknown_none").unwrap_or_else(|_| "clang".into()))
            .flag("--target=aarch64-none-elf")
            .flag("-ffreestanding")
            .flag("-fno-stack-protector")
            .flag("-fno-pic")
            .flag("-mfix-cortex-a53-835769")
            .flag("-mno-outline")
            .flag("-mno-outline-atomics")
            .pic(false);
        let mut shim = cc::Build::new();
        shim.file(own.join("csrc/shim.c"))
            .compiler(env::var("CC_aarch64_unknown_none").unwrap_or_else(|_| "clang".into()))
            .flag("--target=aarch64-none-elf")
            .flag("-ffreestanding")
            .flag("-fno-builtin")
            .flag("-fno-stack-protector")
            .flag("-mfix-cortex-a53-835769")
            .pic(false)
            .opt_level_str("s");
        if let Some(ar) = elf_archiver() {
            shim.archiver(&ar);
        }
        shim.compile("datafs_shim");
    }
    build.compile("datafs_c");
    println!("cargo:rerun-if-changed=csrc");
    // An edit of the sources of littlefs rebuilds the C side as well (rerun-if-changed above
    // would otherwise leave the old library after a change of lfs.c).
    for source in ["lfs.c", "lfs.h", "lfs_util.c", "lfs_util.h"] {
        println!("cargo:rerun-if-changed={}", lfs.join(source).display());
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CC_aarch64_unknown_none");
}
