// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `memcpy` of the service. The target `aarch64-unknown-none` builds with
//! `+strict-align`, so the `memcpy` of compiler_builtins reads a source that
//! is not aligned like its destination one byte at a time (22 instructions
//! for 8 bytes), and the data of TCP in a frame of Ethernet lies 54 bytes into
//! the frame, so almost every copy of a frame goes that way. This one reads
//! and writes 64 bytes a turn with `ldp` and `stp` at any alignment.
//!
//! It is right under two conditions, both true in this service: the memory it
//! copies is ordinary memory (the sockets' buffers, the frames in the object
//! `net`, mapped cached; the window of the device's registers is touched only
//! by volatile accesses of one word, never by `memcpy`), and the kernel
//! leaves SCTLR_EL1.A clear for EL0 (kcore/src/sysreg.rs), so that an
//! unaligned access to ordinary memory does not fault. The ranges do not
//! overlap (`memcpy`); `memmove` stays compiler_builtins'.
//!
//! The same instructions are assembled under another name for the host's tests
//! (Apple silicon is aarch64), which compare them with `copy_from_slice`.

/// The body of the routine: x0 destination, x1 source, x2 length; returns the
/// destination.
#[allow(unused_macros)] // only the guest and the tests of aarch64 use it.
macro_rules! body {
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

#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".global memcpy",
    ".type memcpy, %function",
    "memcpy:",
    body!(),
    ".size memcpy, . - memcpy"
);

#[cfg(all(test, target_arch = "aarch64", target_os = "macos"))]
core::arch::global_asm!(".global _netd_copy_test", "_netd_copy_test:", body!());

#[cfg(all(test, target_arch = "aarch64", not(target_os = "macos")))]
core::arch::global_asm!(
    ".global netd_copy_test",
    ".type netd_copy_test, %function",
    "netd_copy_test:",
    body!()
);

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    unsafe extern "C" {
        fn netd_copy_test(dst: *mut u8, src: *const u8, n: usize) -> *mut u8;
    }

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
                        netd_copy_test(
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
    fn the_tail_of_less_than_eight_bytes_is_copied() {
        let source = [1u8, 2, 3, 4, 5, 6, 7];
        for len in 0..=7 {
            let mut dst = [0u8; 8];
            unsafe { netd_copy_test(dst.as_mut_ptr(), source.as_ptr(), len) };
            assert_eq!(dst[..len], source[..len]);
            assert!(dst[len..].iter().all(|&b| b == 0));
        }
    }
}
