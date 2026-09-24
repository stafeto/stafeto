// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Architecture layer. Only AArch64 exists; everything hardware specific lives below.

mod aarch64;

pub use aarch64::*;
