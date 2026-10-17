// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{dir}/kernel.ld");
    // The checks of OBJ (obj.rs) run in the test images that do not measure
    // instructions: their cost would count in the limits of the others.
    println!("cargo:rustc-check-cfg=cfg(obj_checks)");
    if std::env::var_os("CARGO_FEATURE_KTEST").is_some()
        && std::env::var_os("CARGO_FEATURE_MEASURE").is_none()
    {
        println!("cargo:rustc-cfg=obj_checks");
    }
    println!("cargo:rerun-if-changed=kernel.ld");
    println!("cargo:rerun-if-changed=src/arch/aarch64/head.S");
    println!("cargo:rerun-if-changed=src/arch/aarch64/vectors.S");
    println!("cargo:rerun-if-changed=src/arch/aarch64/mmu.S");
    println!("cargo:rerun-if-changed=src/arch/aarch64/fpsimd.S");
    println!("cargo:rerun-if-changed=src/ktest/el0.S");
}
