// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

/// Set by the first panic. Panics come only after `kernel_main` starts, when
/// the MMU and caches are on, so the atomic swap is safe to use.
static PANICKING: AtomicBool = AtomicBool::new(false);

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    if PANICKING.swap(true, Ordering::Relaxed) {
        // The handler itself failed, e.g. its stop call faulted. Anything more
        // than a line on the console could fail again and recurse.
        kprintln!("\nKERNEL PANIC while panicking; parking");
        park()
    }
    kprintln!("\nKERNEL PANIC: {info}");
    crate::arch::backtrace::print();
    stop()
}

fn park() -> ! {
    loop {
        // SAFETY: waiting for an event has no side effects.
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
    }
}

/// Powers the machine off through PSCI SYSTEM_OFF, in every build: a run
/// of the kernel tests ends the same way, and xtask fails a run that
/// printed a panic (spec 14).
pub(crate) fn stop() -> ! {
    crate::psci::system_off()
}
