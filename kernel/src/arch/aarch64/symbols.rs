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

/// The whole kernel image in virtual memory: code, data, .bss, the boot
/// stack and the boot page tables.
pub fn image() -> core::ops::Range<usize> {
    symbol!("__image_start")..symbol!("__image_end")
}

/// Page-aligned boundaries of the kernel image (see kernel.ld).
pub struct ImageLayout {
    pub start: usize,
    pub text_end: usize,
    pub rodata_end: usize,
    pub stack_guard: usize,
    pub end: usize,
}

pub fn image_layout() -> ImageLayout {
    ImageLayout {
        start: symbol!("__image_start"),
        text_end: symbol!("__text_end"),
        rodata_end: symbol!("__rodata_end"),
        stack_guard: symbol!("__stack_guard"),
        end: symbol!("__image_end"),
    }
}

/// head.S's identity-map root table (TTBR0 while the MMU is switched on).
pub fn identity_table() -> usize {
    symbol!("l0_identity")
}

/// An all-zero root table: TTBR0 while the kernel runs, TTBR1 for an instant.
pub fn empty_table() -> usize {
    symbol!("boot_empty_l0")
}
