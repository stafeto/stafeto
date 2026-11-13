// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A refusal after `ExitBootServices` goes straight to the console port the
//! SPCR names, by polling: the firmware's console is gone, and a panic of
//! the kernel before it reads the tree is not visible on EC2 (spec 3.2).

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};
use firmware_tree::platform::{Uart, UartKind};

static BASE: AtomicU64 = AtomicU64::new(0);
/// 0 PL011; else the 16550's register shift + 1 (so that 1 is shift 0).
static KIND: AtomicU64 = AtomicU64::new(0);
static WIDTH: AtomicU64 = AtomicU64::new(1);

pub fn remember(u: &Uart) {
    BASE.store(u.base, Ordering::Relaxed);
    match u.kind {
        UartKind::Pl011 => KIND.store(0, Ordering::Relaxed),
        UartKind::Ns16550 => {
            KIND.store(if u.bit_width == 32 { 3 } else { 1 }, Ordering::Relaxed);
            WIDTH.store(
                if u.access_size == 3 || u.bit_width == 32 {
                    4
                } else {
                    1
                },
                Ordering::Relaxed,
            );
        }
    }
}

fn put(byte: u8) {
    let base = BASE.load(Ordering::Relaxed);
    if base == 0 {
        return;
    }
    let kind = KIND.load(Ordering::Relaxed);
    let wide = WIDTH.load(Ordering::Relaxed) == 4;
    // SAFETY: the port's registers at the address the SPCR gave, with the
    // access width it gave.
    unsafe {
        if kind == 0 {
            // PL011: FR (0x18) bit 5 TXFF, DR (0x00).
            let mut spins = 0u32;
            while read_volatile((base + 0x18) as *const u32) & (1 << 5) != 0 && spins < 1_000_000 {
                spins += 1;
            }
            write_volatile(base as *mut u32, u32::from(byte));
        } else {
            let shift = kind - 1;
            let reg = |n: u64| base + (n << shift);
            let rd = |n: u64| {
                if wide {
                    read_volatile(reg(n) as *const u32) as u8
                } else {
                    read_volatile(reg(n) as *const u8)
                }
            };
            let mut spins = 0u32;
            // LSR (5) bit 5 THRE.
            while rd(5) & (1 << 5) == 0 && spins < 1_000_000 {
                spins += 1;
            }
            if wide {
                write_volatile(reg(0) as *mut u32, u32::from(byte));
            } else {
                write_volatile(reg(0) as *mut u8, byte);
            }
        }
    }
}

pub fn puts(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            put(b'\r');
        }
        put(b);
    }
}
