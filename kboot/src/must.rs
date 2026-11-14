// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The one check of this crate that stops the kernel: the panic of a check
//! that failed names its message alone, and the kernel's report leaves the
//! place out when the panic comes from `FILE` (as for `kcore::must`).

/// The file of `fail`: the panic report leaves its place out.
pub const FILE: &str = file!();

/// The panic of a check that failed.
#[cold]
#[inline(never)]
pub fn fail(msg: &'static str) -> ! {
    panic!("{msg}")
}

/// The panic of a check that failed, through a cold function of its own
/// that takes no argument: for a check inside code that is inlined into many
/// places, where a call that names the message would stand in each of them.
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
