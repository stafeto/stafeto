// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Compiles littlefs (third-party/littlefs, unchanged) and the flat interface of `csrc/glue.c` into
//! one archive. For the target (`aarch64-unknown-none`, no C library) the build is freestanding
//! with the string functions of `csrc/shim.c` and its own `string.h`; for the host it is the host's
//! compiler and library. littlefs never allocates (LFS_NO_MALLOC) and prints nothing.

use std::{env, path::PathBuf};

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
            .opt_level_str("s")
            .compile("datafs_shim");
    }
    build.compile("datafs_c");
    println!("cargo:rerun-if-changed=csrc");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CC_aarch64_unknown_none");
}
