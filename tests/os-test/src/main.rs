// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! One test of os-test (tools/build-os-test.py) as a program on relibc:
//! posix-crt starts it and relibc calls the test's own `main`. Which test,
//! build.rs takes from STAFETO_OS_TEST_OBJECT.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;
