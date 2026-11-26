// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The dEQP-EGL module of VK-GL-CTS (tcuMain.cpp and the package of the
//! module, built by tools/build-deqp.py) on relibc: posix-crt starts the
//! layer and relibc starts C++. build.rs links the archives of target/deqp,
//! Mesa's target/mesa and the C++ runtime of target/libcxx.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;
