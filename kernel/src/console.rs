// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel's console port (spec 3.2): the PL011 the device tree names
//! (BootInfo::uart_pl011), from `set_port` on, once the kernel tables
//! that map it are live; none before, and none on a machine without one,
//! such as Apple VZ. Until then, and with no port, what `kprintln!` says
//! goes into the kernel log (crate::log) as lines of the kernel, which
//! `set_port` shows on the port it found and the console's driver shows
//! otherwise; the kernel picks no platform in its build. Reached through
//! the linear map. A device window over a page of the port takes the port
//! from the kernel while the window lives (spec 9): the kernel log then
//! keeps what the kernel shows, for the port's driver. `kprintln!` writes
//! to the port whoever has it: the boot report, the kernel tests and the
//! reports that end in a panic, which take the port back first
//! (`panicking::take_console`). One CPU and interrupts masked in the
//! kernel: atomics with relaxed order stand for a lock.

use crate::arch::{mmio, timer};
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use kcore::bootinfo::{BootInfo, Region};
use kcore::console::{FR_TXFF, covers};
use kcore::layout::LINEAR_BASE;

/// Registers of the PL011 by their offsets [R12, G36].
const DR: usize = 0x000;
const FR: usize = 0x018;
const CR: usize = 0x030;
const IMSC: usize = 0x038;
/// UARTEN | TXE | RXE. QEMU transmits without it; real PL011s do not.
const CR_ENABLE: u32 = 0x301;

/// The port's physical address and size; a size of 0 when there is none,
/// as before `set_port`.
static PORT_BASE: AtomicU64 = AtomicU64::new(0);
static PORT_SIZE: AtomicU64 = AtomicU64::new(0);
/// The device windows alive now that cover a page of the port.
static WINDOWS: AtomicU32 = AtomicU32::new(0);
/// The last such window went: the next write sets the port up again.
static RETURNED: AtomicBool = AtomicBool::new(false);

fn port() -> Region {
    Region {
        base: PORT_BASE.load(Relaxed),
        size: PORT_SIZE.load(Relaxed),
    }
}

/// The address of register `offset` of the port in the linear map, while
/// there is a port.
fn reg(offset: usize) -> Option<usize> {
    let p = port();
    (p.size > 0).then(|| LINEAR_BASE + p.base as usize + offset)
}

/// Writes `value` to register `offset` of the port, if there is one.
fn write_reg(offset: usize, value: u32) {
    if let Some(addr) = reg(offset) {
        // SAFETY: the port is the PL011 of the device tree, device memory
        // in the linear map, which mm::kmap maps before `set_port`.
        unsafe { mmio::write32(addr, value) }
    }
}

/// Reads register `offset` of the port; 0 without one.
fn read_reg(offset: usize) -> u32 {
    // SAFETY: as in `write_reg`.
    reg(offset).map_or(0, |addr| unsafe { mmio::read32(addr) })
}

/// The port from now on is the PL011 of the device tree `info` describes,
/// or none (spec 3.2). A port is turned on, and what the kernel said
/// before goes out on it first, in its order (log::show_early). Called
/// once, when the kernel tables, which map that PL011, are live.
pub fn set_port(info: &BootInfo) {
    let p = info.uart_pl011.unwrap_or(Region { base: 0, size: 0 });
    PORT_BASE.store(p.base, Relaxed);
    PORT_SIZE.store(p.size, Relaxed);
    if p.size > 0 {
        write_reg(CR, CR_ENABLE);
        crate::log::show_early();
    }
}

/// Whether the kernel has the port: there is one, and no device window
/// covers it (spec 3.2).
pub fn is_kernels() -> bool {
    port().size > 0 && WINDOWS.load(Relaxed) == 0
}

/// A device window over the `pages` pages from `base` was made
/// (memory::create_window): one that covers a page of the port takes the
/// port from the kernel (spec 3.2, 9). O(1).
pub fn window_made(base: u64, pages: u64) {
    if covers(port(), base, pages) {
        WINDOWS.fetch_add(1, Relaxed);
    }
}

/// A device window over the `pages` pages from `base` went, with its last
/// portion of cleanup (memory::clean): the last one that covered a page of
/// the port gives the port back, and the next write of the kernel sets it
/// up again (spec 3.2). O(1).
pub fn window_gone(base: u64, pages: u64) {
    if covers(port(), base, pages) && WINDOWS.fetch_sub(1, Relaxed) == 1 {
        RETURNED.store(true, Relaxed);
    }
}

/// Sets the port up for the kernel (spec 3.2, 16.1): the transmitter and
/// the receiver on, as a driver that died may have left them off, and its
/// interrupts masked, as it may have left them open.
fn set_up() {
    write_reg(CR, CR_ENABLE);
    write_reg(IMSC, 0);
}

/// A report that ends in a panic takes the port, whoever has it (spec
/// 16.1, panicking::take_console).
pub fn take_back() {
    RETURNED.store(false, Relaxed);
    set_up();
}

fn putc(byte: u8) {
    let Some(dr) = reg(DR) else { return };
    while read_reg(FR) & FR_TXFF != 0 {}
    // SAFETY: as in `write_reg`.
    unsafe { mmio::write32(dr, u32::from(byte)) };
}

/// Writes `bytes` to the port as they are, but for a CR before each LF,
/// waiting for room in the transmit FIFO; the port is set up first when
/// the last window over it went since the last write (spec 3.2). Nothing
/// without a port.
pub fn write_bytes(bytes: &[u8]) {
    if RETURNED.swap(false, Relaxed) {
        set_up();
    }
    for &b in bytes {
        if b == b'\n' {
            putc(b'\r');
        }
        putc(b);
    }
}

/// Waits up to 10 ms of the counter for the port's transmitter to go idle
/// (spec 16.1): what the FIFO holds goes out before the machine powers
/// off. QEMU never shows the transmitter busy.
pub fn drain() {
    let deadline = timer::now().saturating_add(timer::frequency() / 100);
    kcore::console::drain(|| read_reg(FR), || timer::now() >= deadline);
}

struct Console;

impl Write for Console {
    /// To the port; with none, into the kernel log as text of the kernel
    /// (spec 3.2, 16.3).
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if port().size > 0 {
            write_bytes(s.as_bytes());
        } else {
            crate::log::kernel(|w| {
                let _ = w.write_str(s);
            });
        }
        Ok(())
    }
}

/// A writer to the port, for text that goes there as `kprintln!` sends it.
pub fn writer() -> impl Write {
    Console
}

/// `args` to the port; with none, into the kernel log as one text of the
/// kernel, in as few records as it fills (spec 3.2, 16.3).
pub fn print(args: fmt::Arguments<'_>) {
    if port().size > 0 {
        let _ = Console.write_fmt(args);
    } else {
        crate::log::kernel(|w| {
            let _ = w.write_fmt(args);
        });
    }
}

/// A line to the port, or into the kernel log without one: one write of
/// the text and its newline, so that a line takes as few records as it
/// can (spec 16.3).
macro_rules! kprintln {
    () => {
        $crate::console::print(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::console::print(format_args!("{}\n", format_args!($($arg)*)))
    };
}
