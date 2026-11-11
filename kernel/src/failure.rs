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

/// The panic of a check that failed at line `line` of its file: the line is
/// the one place the report names, besides the backtrace.
#[cold]
#[inline(never)]
pub fn fail_at(msg: &'static str, line: u32) -> ! {
    ::core::panic!("{msg} (line {line})")
}

/// The panic of `unreachable!`.
#[cold]
#[inline(never)]
pub fn unreachable(msg: &'static str, line: u32) -> ! {
    ::core::panic!("internal error: entered unreachable code: {msg} (line {line})")
}

macro_rules! assert {
    ($cond:expr $(,)?) => {
        if !$cond {
            $crate::failure::fail_at(concat!("assertion failed: ", stringify!($cond)), line!())
        }
    };
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            $crate::failure::fail_at($msg, line!())
        }
    };
    ($($arg:tt)+) => {
        ::core::assert!($($arg)+)
    };
}

macro_rules! panic {
    ($msg:literal $(,)?) => {
        $crate::failure::fail_at($msg, line!())
    };
    ($($arg:tt)*) => {
        ::core::panic!($($arg)*)
    };
}

macro_rules! unreachable {
    ($msg:literal $(,)?) => {
        $crate::failure::unreachable($msg, line!())
    };
    ($($arg:tt)*) => {
        ::core::unreachable!($($arg)*)
    };
}
