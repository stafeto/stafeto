// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The display demo (wfd-demo.c) on relibc: posix-crt, built with its
//! feature `wfd`, starts the layer and carries the functions of
//! `<WF/wfd.h>`; relibc starts C.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;
