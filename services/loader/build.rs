// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Links the loader at the start of its region (proto_loader::LOADER_BASE,
//! 16 MiB under the top of the lower half), where no program's segment
//! lies.

fn main() {
    println!("cargo:rustc-link-arg-bins=--image-base=0xffffff000000");
}
