// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The copy of a frame. The target `aarch64-unknown-none` builds with
//! `+strict-align`, so the `memcpy` of compiler_builtins reads a source that
//! is not aligned like its destination one byte at a time (22 instructions
//! for 8 bytes), and the data of TCP in a frame of Ethernet lies 54 bytes into
//! the frame, so almost every copy of a frame goes that way. This one reads
//! and writes 64 bytes a turn with `ldp` and `stp` at any alignment.
//!
//! It is right under two conditions: the memory it copies is ordinary memory
//! (the buffers of the frames, mapped cached; the registers of a device are
//! touched only by the volatile accesses of `mmio`, never by a copy), and the
//! kernel leaves SCTLR_EL1.A clear for EL0, so that an unaligned access to
//! ordinary memory does not fault. The ranges do not overlap.
//!
//! The routine has two names. `copy_body!` is its text, which a program
//! assembles under the name `memcpy` when it wants every copy of the compiler
//! to take it (the network service does; a program over a C library has a
//! `memcpy` of its own, and a second strong symbol of that name is no
//! program). The library assembles it under the name `vnet_copy` (`copy`),
//! which the host's tests on Apple silicon compare with `copy_from_slice`.

/// The body of the routine, for `global_asm!`: x0 destination, x1 source, x2
/// length; returns the destination.
#[macro_export]
macro_rules! copy_body {
    () => {
        "
    mov x3, x0
    cmp x2, #64
    b.lo 20f
10:
    ldp x4, x5, [x1]
    ldp x6, x7, [x1, #16]
    ldp x8, x9, [x1, #32]
    ldp x10, x11, [x1, #48]
    stp x4, x5, [x3]
    stp x6, x7, [x3, #16]
    stp x8, x9, [x3, #32]
    stp x10, x11, [x3, #48]
    add x1, x1, #64
    add x3, x3, #64
    sub x2, x2, #64
    cmp x2, #64
    b.hs 10b
20:
    tbz x2, #5, 30f
    ldp x4, x5, [x1]
    ldp x6, x7, [x1, #16]
    stp x4, x5, [x3]
    stp x6, x7, [x3, #16]
    add x1, x1, #32
    add x3, x3, #32
30:
    tbz x2, #4, 40f
    ldp x4, x5, [x1], #16
    stp x4, x5, [x3], #16
40:
    tbz x2, #3, 50f
    ldr x4, [x1], #8
    str x4, [x3], #8
50:
    tbz x2, #2, 60f
    ldr w4, [x1], #4
    str w4, [x3], #4
60:
    tbz x2, #1, 70f
    ldrh w4, [x1], #2
    strh w4, [x3], #2
70:
    tbz x2, #0, 80f
    ldrb w4, [x1]
    strb w4, [x3]
80:
    ret
"
    };
}

#[cfg(all(target_arch = "aarch64", not(target_os = "macos")))]
core::arch::global_asm!(
    ".global vnet_copy",
    ".type vnet_copy, %function",
    "vnet_copy:",
    copy_body!(),
    ".size vnet_copy, . - vnet_copy"
);

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
core::arch::global_asm!(".global _vnet_copy", "_vnet_copy:", copy_body!());

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn vnet_copy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8;
}

/// Copies `n` bytes from `src` to `dst`.
///
/// # Safety
///
/// `src` is valid for `n` bytes of reads and `dst` for `n` bytes of writes,
/// both ordinary memory, and the ranges do not overlap.
#[inline]
pub unsafe fn copy(dst: *mut u8, src: *const u8, n: usize) {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: the caller's promise; the routine touches only the two ranges.
    unsafe {
        vnet_copy(dst, src, n);
    }
    #[cfg(not(target_arch = "aarch64"))]
    // SAFETY: the caller's promise.
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, n);
    }
}

/// Zeroes `pages` whole pages from `at` (the pages of a queue, which the
/// device's crate wants zeroed): 64 bytes a turn with `stp xzr`, a third of
/// the instructions of `write_bytes` on this target, which counts in the step
/// of a driver that makes its queues again (the second device back from its
/// owner).
///
/// # Safety
///
/// `at` is page-aligned and the pages are ordinary memory the caller may
/// write, with nothing referring into them.
#[inline]
pub unsafe fn zero_pages(at: usize, pages: usize) {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: the caller's promise; the loop writes the `pages` pages only.
    unsafe {
        let mut p = at;
        let end = at + pages * 4096;
        while p < end {
            core::arch::asm!(
                "stp xzr, xzr, [{p}]",
                "stp xzr, xzr, [{p}, #16]",
                "stp xzr, xzr, [{p}, #32]",
                "stp xzr, xzr, [{p}, #48]",
                p = in(reg) p,
                options(nostack, preserves_flags)
            );
            p += 64;
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    // SAFETY: the caller's promise.
    unsafe {
        core::ptr::write_bytes(at as *mut u8, 0, pages * 4096)
    };
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use super::vnet_copy;

    #[test]
    fn it_copies_every_length_at_every_shift() {
        let mut x: u32 = 0x9e37_79b9;
        let mut source = vec![0u8; 1700];
        for b in &mut source {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (x >> 24) as u8;
        }
        for src_shift in 0..16 {
            for dst_shift in 0..16 {
                for len in (0..=1600)
                    .step_by(1)
                    .filter(|l| l % 7 == 0 || *l < 130 || *l > 1590)
                {
                    let mut dst = vec![0xEEu8; 1700];
                    let returned = unsafe {
                        vnet_copy(
                            dst.as_mut_ptr().add(dst_shift),
                            source.as_ptr().add(src_shift),
                            len,
                        )
                    };
                    assert_eq!(returned, unsafe { dst.as_mut_ptr().add(dst_shift) });
                    assert_eq!(
                        dst[dst_shift..dst_shift + len],
                        source[src_shift..src_shift + len],
                        "shift {src_shift} {dst_shift} length {len}"
                    );
                    // Nothing outside the range is written.
                    assert!(dst[..dst_shift].iter().all(|&b| b == 0xEE));
                    assert!(dst[dst_shift + len..].iter().all(|&b| b == 0xEE));
                }
            }
        }
    }

    #[test]
    fn whole_pages_are_zeroed_and_nothing_past_them() {
        let mut memory = vec![0xAAu8; 4 * 4096];
        let at = (memory.as_mut_ptr() as usize).next_multiple_of(4096);
        unsafe { super::zero_pages(at, 2) };
        let start = at - memory.as_ptr() as usize;
        assert!(memory[start..start + 8192].iter().all(|&b| b == 0));
        assert!(memory[start + 8192..].iter().all(|&b| b == 0xAA));
        assert!(memory[..start].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn the_tail_of_less_than_eight_bytes_is_copied() {
        let source = [1u8, 2, 3, 4, 5, 6, 7];
        for len in 0..=7 {
            let mut dst = [0u8; 8];
            unsafe { vnet_copy(dst.as_mut_ptr(), source.as_ptr(), len) };
            assert_eq!(dst[..len], source[..len]);
            assert!(dst[len..].iter().all(|&b| b == 0));
        }
    }
}
