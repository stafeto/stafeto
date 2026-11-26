// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The dEQP-GLES2 module of VK-GL-CTS (tcuMain.cpp and the package of the
//! module, built by tools/build-deqp.py) on relibc, started as tests/deqp
//! starts dEQP-EGL.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;
