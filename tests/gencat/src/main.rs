// SPDX-License-Identifier: BSD-2-Clause
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! gencat (gencat.c, FreeBSD) on relibc: posix-crt starts the layer, relibc
//! starts C.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;
