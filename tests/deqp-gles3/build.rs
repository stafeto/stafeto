// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Links the dEQP-GLES3 module: the archives of `deqp-gles3.link` in target/deqp
//! (tools/build-deqp.py, `cargo xtask deqp`) with Mesa, libc++ and relibc, as
//! tests/deqp does for dEQP-EGL.

include!("../deqp/link.rs");

fn main() {
    println!("cargo:rerun-if-changed=../deqp/link.rs");
    link_module("deqp-gles3");
}
