// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Links the dEQP-EGL module: the archives of target/deqp that
//! `deqp-egl.link` names (tools/build-deqp.py, `cargo xtask deqp`), the
//! archive of Mesa (target/mesa, `cargo xtask mesa`), the libc++, libc++abi
//! and libunwind of target/libcxx (`cargo xtask libcxx`) and relibc's libm.a
//! and libc.a (the sysroot `cargo xtask relibc` builds). The program's own C++
//! is in the archives, so the crate compiles nothing. link.rs holds the steps
//! the programs of the other modules share.

include!("link.rs");

fn main() {
    println!("cargo:rerun-if-changed=link.rs");
    link_module("deqp-egl");
}
