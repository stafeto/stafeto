// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C probe of the display service's place in a process (display.c) on
//! relibc: posix-crt starts the layer, relibc starts C. The functions
//! below give C the layer's `display` interface (the session, the display
//! piece) that no C function wraps yet.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};
use posix_abi::display;
use rt::handle::{Channel, Handle};

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

/// 1 when the process has a session with the display service.
#[unsafe(no_mangle)]
pub extern "C" fn dp_session() -> i32 {
    i32::from(display::session().is_some())
}

/// 0 when the process's session answers a CLONE with a session of its
/// own (which this closes), -1 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn dp_clone_ok() -> i32 {
    let Some(session) = display::session() else {
        return -1;
    };
    match rt::service::clone_session(
        &Handle::<Channel>::borrowed(session),
        &proto_gpu::Method::Clone.header().bytes(),
    ) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Maps a new object of `pages` pages as the display piece: its address,
/// or minus the errno.
#[unsafe(no_mangle)]
pub extern "C" fn dp_map(pages: u64) -> i64 {
    let Ok(object) = rt::sys::mem_create(pages * 4096) else {
        return -12;
    };
    match display::map_buffer(object, pages as usize) {
        Ok(address) => address as i64,
        Err(errno) => -i64::from(errno),
    }
}

/// The display piece leaves the process: 0, or the errno.
#[unsafe(no_mangle)]
pub extern "C" fn dp_unmap() -> i32 {
    display::unmap_buffer().err().unwrap_or(0)
}

/// The address of the display piece, 0 for none.
#[unsafe(no_mangle)]
pub extern "C" fn dp_buffer() -> u64 {
    display::buffer().map_or(0, |(address, _)| address as u64)
}

static HIDDEN: AtomicU64 = AtomicU64::new(0);

/// Hides the session (1) or shows it again (0), for the forks and spawns
/// between: the price of the CLONE the layer makes with it.
#[unsafe(no_mangle)]
pub extern "C" fn dp_hide(hide: i32) {
    if hide != 0 {
        let raw = display::probe_swap_session(0);
        if raw != 0 {
            HIDDEN.store(raw, Ordering::Release);
        }
    } else {
        let raw = HIDDEN.swap(0, Ordering::AcqRel);
        if raw != 0 {
            display::probe_swap_session(raw);
        }
    }
}

/// The clock in nanoseconds.
#[unsafe(no_mangle)]
pub extern "C" fn dp_ns() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}
