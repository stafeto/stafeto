// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The cube (gles-cube.c) on relibc: posix-crt starts the layer and relibc
//! starts C. build.rs links the Mesa archive of target/mesa
//! (`cargo xtask mesa`) and the C++ runtime of target/libcxx.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;
