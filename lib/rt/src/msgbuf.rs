// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calling thread's message buffer (spec 6.2, 13.2): the page the
//! kernel maps for each thread, whose address TPIDRRO_EL0 holds, in the
//! layout of abi::msgbuf. Bytes 64 and up of a message lie there: `sys`
//! puts them there before `send` and `reply`, and the kernel copies them
//! into the buffer of the receiver. After a `receive` or a `send` that
//! brought more than 64 bytes, `sys` puts bytes 0-63 there from x2-x9 as
//! well, so the whole message lies in the buffer. The values of the handles
//! of a message lie there too: `sys` puts those the thread sends, and the
//! kernel writes those that came, with an info word each (`handle`).

use abi::msgbuf::{HANDLES, INFO, SIZE};
use abi::{MESSAGE_HANDLES, ObjectKind, Rights};
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

/// Puts the values of `handles`, at most abi::MESSAGE_HANDLES, where the
/// kernel reads those of the message the thread sends or answers with
/// (abi::msgbuf::HANDLES, spec 6.2).
pub fn put_handles(handles: &[abi::Handle]) {
    assert!(
        handles.len() <= MESSAGE_HANDLES,
        "a message carries four handles at most"
    );
    for (i, h) in handles.iter().enumerate() {
        write(HANDLES + 8 * i, &h.0.to_ne_bytes());
    }
}

/// Handle `i` of the message that came last, below its count of handles,
/// as the kernel wrote it (spec 6.2): its value (abi::msgbuf::HANDLES), and
/// the kind of its object with its rights (abi::msgbuf::INFO); a kind this
/// build does not know comes as ObjectKind::Unknown.
pub fn handle(i: usize) -> (abi::Handle, (ObjectKind, Rights)) {
    assert!(
        i < MESSAGE_HANDLES,
        "a message carries four handles at most"
    );
    let mut word = [0; 8];
    read(HANDLES + 8 * i, &mut word);
    let value = abi::Handle(u64::from_ne_bytes(word));
    read(INFO + 8 * i, &mut word);
    (value, abi::msgbuf::parse_info(u64::from_ne_bytes(word)))
}
