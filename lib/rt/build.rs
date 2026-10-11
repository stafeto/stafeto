// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

fn main() {
    if std::env::var("TARGET").as_deref() == Ok("aarch64-unknown-none") {
        println!("cargo:rerun-if-changed=../../tools/linker/native-link");
        println!("cargo:rerun-if-changed=../../tools/linker/cfi.py");
    }
}
