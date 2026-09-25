// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calling thread's message buffer (spec 6.2, 13.2): the page the
//! kernel maps for each thread, whose address TPIDRRO_EL0 holds, in the
//! layout of abi::msgbuf. Bytes 64 and up of a message lie there: `sys`
//! puts them there before `send` and `reply`, and the kernel copies them
//! into the buffer of the receiver. After a `receive` or a `send` that
//! brought more than 64 bytes, `sys` puts bytes 0-63 there from x2-x9 as
//! well, so the whole message lies in the buffer.

use abi::msgbuf::SIZE;
use core::arch::asm;

/// The address of the calling thread's buffer, TPIDRRO_EL0, which only
/// the kernel writes (spec 6.2).
pub fn address() -> usize {
    let va: usize;
    // SAFETY: reading TPIDRRO_EL0 has no side effects.
    unsafe { asm!("mrs {}, tpidrro_el0", out(reg) va, options(nomem, nostack, preserves_flags)) };
    va
}

/// Writes `bytes` into the calling thread's buffer at `offset` (spec
/// 6.2); `bytes` may lie in the buffer itself, as a message that came does.
/// Panics past the end of the buffer.
pub fn write(offset: usize, bytes: &[u8]) {
    assert!(
        offset
            .checked_add(bytes.len())
            .is_some_and(|end| end <= SIZE),
        "past the message buffer"
    );
    // SAFETY: the buffer is the calling thread's page, mapped writable
    // while the thread lives (spec 6.2); only its own thread reaches it
    // here, and the range lies in it. `copy` allows the two to overlap.
    unsafe { core::ptr::copy(bytes.as_ptr(), (address() + offset) as *mut u8, bytes.len()) };
}

/// Reads the calling thread's buffer at `offset` into `bytes` (spec 6.2),
/// which may lie in the buffer itself. Panics past the end of the buffer.
pub fn read(offset: usize, bytes: &mut [u8]) {
    assert!(
        offset
            .checked_add(bytes.len())
            .is_some_and(|end| end <= SIZE),
        "past the message buffer"
    );
    // SAFETY: as in `write`.
    unsafe {
        core::ptr::copy(
            (address() + offset) as *const u8,
            bytes.as_mut_ptr(),
            bytes.len(),
        )
    };
}
