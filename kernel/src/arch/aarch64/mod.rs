// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

pub mod backtrace;
pub mod exceptions;
pub mod registers;
#[cfg(feature = "ktest")]
pub mod semihosting;

core::arch::global_asm!(include_str!("head.S"), options(raw));
core::arch::global_asm!(include_str!("vectors.S"), options(raw));
