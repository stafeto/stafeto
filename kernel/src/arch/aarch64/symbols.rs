// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Addresses of symbols defined by head.S and the linker script.

/// Link-time (virtual) address of a symbol, computed PC-relative.
macro_rules! symbol {
    ($name:literal) => {{
        let addr: usize;
        // SAFETY: computing an address has no side effects.
        unsafe {
            core::arch::asm!(
                concat!("adrp {0}, ", $name),
                concat!("add {0}, {0}, :lo12:", $name),
                out(reg) addr,
                options(nomem, nostack, preserves_flags),
            )
        };
        addr
    }};
}

/// The boot stack, the kernel stack of CPU 0.
pub fn boot_stack() -> core::ops::Range<usize> {
    symbol!("boot_stack")..symbol!("boot_stack_top")
}
