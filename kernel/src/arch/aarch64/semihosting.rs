// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Semihosting exit with a status code. Test builds only: QEMU must run with
//! `-semihosting`, otherwise HLT #0xF000 is an undefined instruction.

const SYS_EXIT: u64 = 0x18;
const ADP_STOPPED_APPLICATION_EXIT: u64 = 0x2_0026;

pub fn exit(code: u32) -> ! {
    let block = [ADP_STOPPED_APPLICATION_EXIT, u64::from(code)];
    // SAFETY: under -semihosting QEMU reads the parameter block and exits.
    unsafe {
        core::arch::asm!("hlt #0xf000", in("x0") SYS_EXIT, in("x1") block.as_ptr(), options(nostack))
    };
    loop {
        core::hint::spin_loop();
    }
}
