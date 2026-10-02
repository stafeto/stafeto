// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The layouts the layer's calls take: the AArch64 LP64 `stat` (from
//! file-service metadata) and `timespec`.

pub use posix_types::{Stat, Timespec};
