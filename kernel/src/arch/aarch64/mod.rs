// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

pub mod backtrace;

core::arch::global_asm!(include_str!("head.S"), options(raw));
