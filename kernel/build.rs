// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{dir}/kernel.ld");
    println!("cargo:rerun-if-changed=kernel.ld");
    println!("cargo:rerun-if-changed=src/arch/aarch64/head.S");
    println!("cargo:rerun-if-changed=src/arch/aarch64/vectors.S");
    println!("cargo:rerun-if-changed=src/arch/aarch64/mmu.S");
    println!("cargo:rerun-if-changed=src/arch/aarch64/fpsimd.S");
    println!("cargo:rerun-if-changed=src/ktest/el0.S");
}
