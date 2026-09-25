// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! init, the first program (spec 13.4). For now a stand-in that gives the
//! boot image its first file: it exits at once. The real init comes with
//! lib/rt.

#![no_std]
#![no_main]

use abi::Call;

fn exit(code: u64) -> ! {
    // SAFETY: process_exit ends the process and does not return.
    unsafe {
        core::arch::asm!(
            "svc #{call}",
            call = const Call::ProcessExit.number(),
            in("x0") code,
            options(noreturn, nostack),
        )
    }
}

#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    exit(0)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit(1)
}
