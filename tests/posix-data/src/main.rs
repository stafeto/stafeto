// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C probe of the reading paths of `/data` (data.c) on relibc: posix-crt starts the layer (with
//! the data file service, feature `data`), relibc starts C. The program has no Rust of its own.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;
