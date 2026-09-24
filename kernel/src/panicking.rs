// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    kprintln!("\nKERNEL PANIC: {info}");
    crate::arch::backtrace::print();
    stop()
}

fn stop() -> ! {
    crate::psci::system_off()
}
