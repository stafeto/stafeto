// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The `assert!` of the kernel (kernel/src/failure.rs) for this crate: a
//! check with a message in a literal ends in one call that names the message,
//! with no `core::fmt::Arguments` on the stack and no `Location` constant at
//! the place of the check. The panic comes from `kcore::must`, whose file
//! the kernel's report leaves out.

macro_rules! assert {
    ($cond:expr $(,)?) => {
        if !$cond {
            ::kcore::must::fail_at(concat!("assertion failed: ", stringify!($cond)), line!())
        }
    };
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            ::kcore::must::fail_at($msg, line!())
        }
    };
    ($($arg:tt)+) => {
        ::core::assert!($($arg)+)
    };
}
