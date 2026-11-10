// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel's checks that stop it (spec 3.4, 16.1). Each `assert!`,
//! `panic!` and `unreachable!` of the kernel with a message in a literal
//! ends in one call that names the message: no `core::fmt::Arguments` on
//! the stack and no `Location` constant at the place of the check, which
//! the inlined copies of a check (a hundred of them in the exit loop and
//! the calls) would repeat. A check with arguments to format, and a check
//! in a `const` item, keep the macros of `core`.
//!
//! The panic names its message and the report ends with the backtrace, so
//! the place of a check comes from the return addresses.

/// The file of the panics below: `panicking` leaves their place out.
pub const FILE: &str = file!();

/// The panic of a check that failed: `msg` is what the check says.
#[cold]
#[inline(never)]
pub fn fail(msg: &'static str) -> ! {
    ::core::panic!("{msg}")
}

/// The panic of `unreachable!`.
#[cold]
#[inline(never)]
pub fn unreachable(msg: &'static str) -> ! {
    ::core::panic!("internal error: entered unreachable code: {msg}")
}

macro_rules! assert {
    ($cond:expr $(,)?) => {
        if !$cond {
            $crate::failure::fail(concat!("assertion failed: ", stringify!($cond)))
        }
    };
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            $crate::failure::fail($msg)
        }
    };
    ($($arg:tt)+) => {
        ::core::assert!($($arg)+)
    };
}

macro_rules! panic {
    ($msg:literal $(,)?) => {
        $crate::failure::fail($msg)
    };
    ($($arg:tt)*) => {
        ::core::panic!($($arg)*)
    };
}

macro_rules! unreachable {
    ($msg:literal $(,)?) => {
        $crate::failure::unreachable($msg)
    };
    ($($arg:tt)*) => {
        ::core::unreachable!($($arg)*)
    };
}
