// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C probe of the manager's calls (manager.c) on relibc: posix-crt, built
//! with its feature `window`, starts the layer and carries the functions of
//! `<stafeto/window.h>` and `<stafeto/manager.h>`; relibc starts C.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;
