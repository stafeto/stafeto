// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `Option::must`: `expect` for the kernel (spec 3.4). A failed `expect`
//! at each place of a call takes the message, its length and a `Location`
//! constant into the code and the constants; `must` takes the message and
//! its length into one call of a cold function that panics with it, and
//! has no `Location` of its own, so the many inlined copies of a check
//! stay small. The panic names its message; the backtrace names the place.

/// The file of `fail`: the panic report leaves its place out.
pub const FILE: &str = file!();

/// The panic of a check that failed.
#[cold]
#[inline(never)]
pub fn fail(msg: &'static str) -> ! {
    panic!("{msg}")
}

/// The panic of a check of the macros below, with the line of the check.
#[cold]
#[inline(never)]
pub fn fail_at(msg: &'static str, line: u32) -> ! {
    panic!("{msg} (line {line})")
}

/// The panic of a check that failed, through a cold function of its own
/// that takes no argument: for a check inside code that is inlined into many
/// places, where a call that names the message would stand in each of them.
#[macro_export]
macro_rules! fail_here {
    ($msg:literal) => {{
        #[cold]
        #[inline(never)]
        fn fail_here() -> ! {
            $crate::must::fail($msg)
        }
        fail_here()
    }};
}

// The kernel build of this crate checks with `fail`, as the kernel does
// (kernel/src/failure.rs); the host tests keep the macros of `core`, whose
// messages name the values of a comparison. A check with arguments to
// format, and a check in a const item, keep the macros of `core` either way.
#[cfg(not(test))]
macro_rules! assert {
    ($cond:expr $(,)?) => {
        if !$cond {
            $crate::must::fail_at(concat!("assertion failed: ", stringify!($cond)), line!())
        }
    };
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            $crate::must::fail_at($msg, line!())
        }
    };
    ($($arg:tt)+) => {
        ::core::assert!($($arg)+)
    };
}

#[cfg(not(test))]
macro_rules! panic {
    ($msg:literal $(,)?) => {
        $crate::must::fail_at($msg, line!())
    };
    ($($arg:tt)*) => {
        ::core::panic!($($arg)*)
    };
}

/// `expect` for an `Option` with a message that is a literal.
pub trait Must<T> {
    fn must(self, msg: &'static str) -> T;
}

impl<T> Must<T> for Option<T> {
    #[inline(always)]
    fn must(self, msg: &'static str) -> T {
        match self {
            Some(value) => value,
            None => fail(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn must_gives_the_value() {
        assert_eq!(Some(3).must("a value"), 3);
    }

    #[test]
    #[should_panic(expected = "a value")]
    fn must_panics_with_the_message() {
        None::<u8>.must("a value");
    }
}
