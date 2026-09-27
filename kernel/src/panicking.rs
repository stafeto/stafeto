// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

/// Set by the first panic. Panics come only after `kernel_main` starts, when
/// the MMU and caches are on, so the atomic swap is safe to use.
static PANICKING: AtomicBool = AtomicBool::new(false);

/// The kernel's panic (spec 16.1): it takes the console's port back,
/// whoever has it, shows the records of the kernel log that nobody showed
/// or took, then its report and the backtrace, and powers the machine
/// off once the port's transmitter is idle (`stop`).
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    if PANICKING.swap(true, Ordering::Relaxed) {
        // The handler itself failed, e.g. its stop call faulted. Anything more
        // than a line on the console could fail again and recurse.
        kprintln!("\nKERNEL PANIC while panicking; parking");
        park()
    }
    take_console();
    kprintln!("\nKERNEL PANIC: {info}");
    crate::arch::backtrace::print();
    stop()
}

/// The start of every report that ends in a panic (spec 16.1): the
/// console's port comes back to the kernel, whoever has it, and the
/// records of the kernel log that nobody showed or took go out first,
/// once (crate::log::show_unshown).
pub(crate) fn take_console() {
    crate::console::take_back();
    crate::log::show_unshown();
}

fn park() -> ! {
    loop {
        // SAFETY: waiting for an event has no side effects.
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
    }
}

/// Powers the machine off through PSCI SYSTEM_OFF after reporting the panic.
pub(crate) fn stop() -> ! {
    crate::psci::system_off()
}
