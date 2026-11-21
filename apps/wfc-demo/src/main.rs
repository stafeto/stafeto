// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The scene demo (wfc-demo.c) on relibc: posix-crt, built with its features
//! `wfc` and `window`, starts the layer and carries the functions of
//! `<WF/wfc.h>` and `<stafeto/window.h>`; relibc starts C.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;
