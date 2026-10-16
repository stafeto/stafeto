// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! GNU nano on relibc. posix-crt starts the process and hands the thread to
//! relibc, which calls nano's own `main` (tools/build-nano.py links it).

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

// The panic handler and the allocator-free runtime of the layer.
extern crate rt;
