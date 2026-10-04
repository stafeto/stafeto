// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C PTY probe, entered through relibc.
#![no_std]
#![no_main]

mod description;
#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;
