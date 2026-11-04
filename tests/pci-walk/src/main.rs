// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A walk of bus 0 on Apple VZ, from the window of its ECAM that init
//! gives the program (`ecam`, 32 devices of 8 functions, 4 KiB each). One
//! line for every function that answers:
//!
//! `pci: dev D fn F id VVVV:DDDD class CCCCCC header HH pin P`
//!
//! and for a network function (class 0x02) the size and kind of each BAR
//! and the Virtio structures of its capability list (Virtio 1.2, 4.1.4):
//! `pci: dev D fn F bar I size S mem32|mem64|io`, `pci: dev D fn F cap
//! type T bar B offset O length L` and `pci: dev D fn F common bar B
//! offset O` (or `common none`). The last line is `pci-walk: done`.
//!
//! A BAR is measured the standard way (PCI Local Bus 6.2.5.1): decoding
//! off, all ones written, the value read back, the old value restored,
//! decoding back. Only network functions are written to; the others are
//! read. Every access is 32 bits wide: VZ stops the machine at a byte
//! write into the configuration space.

#![no_std]
#![no_main]

use abi::Access;
use rt::handle::{Memory, Resource};
use rt::{mmio, sys};
use virtio_pci::COMMAND;

rt::entry!(main);

/// Where the program maps the ECAM window.
const ECAM_AT: usize = 0x10_2000_0000;
/// Bus 0 of ECAM: 32 devices of 8 functions of 4 KiB.
const ECAM_LEN: u64 = 0x10_0000;
const NETWORK_CLASS: u32 = 0x02;
const NO_FUNCTION: u32 = 0xFFFF_FFFF;
/// The command bits that decode memory and I/O.
const DECODING: u32 = 0b11;
/// A vendor capability, the cap list's start, and the BAR registers.
const VENDOR_CAPABILITY: u32 = 0x09;
const FIRST_CAPABILITY: usize = 0x40;
const MOST_CAPABILITIES: usize = 48;
const BAR_FIRST: usize = 0x10;
const BARS: usize = 6;

fn function_at(device: usize, function: usize) -> usize {
    ECAM_AT + (device << 15) + (function << 12)
}

fn read(base: usize, offset: usize) -> u32 {
    // SAFETY: the window maps all of bus 0's ECAM, read and write, as
    // device memory; `base` and `offset` stay within a function's page.
    unsafe { mmio::read32(base + offset) }
}

fn write(base: usize, offset: usize, value: u32) {
    // SAFETY: as for `read`.
    unsafe { mmio::write32(base + offset, value) }
}

/// The size of the BAR at `index` and its kind, measured as the module's
/// comment says; the second value is the number of BAR registers it
/// takes. Returns (size, kind, registers); a size of 0 means no BAR.
fn measure(base: usize, index: usize) -> (u64, &'static str, usize) {
    let at = BAR_FIRST + 4 * index;
    let old = read(base, at);
    write(base, at, 0xFFFF_FFFF);
    let probed = read(base, at);
    write(base, at, old);
    if probed == 0 {
        return (0, "none", 1);
    }
    if old & 1 == 1 {
        let size = u64::from(!(probed & !3)) + 1;
        return (size, "io", 1);
    }
    if (old >> 1) & 3 == 2 && index + 1 < BARS {
        let old_high = read(base, at + 4);
        write(base, at + 4, 0xFFFF_FFFF);
        let high = read(base, at + 4);
        write(base, at + 4, old_high);
        let mask = (u64::from(high) << 32) | u64::from(probed & !0xF);
        return (!mask + 1, "mem64", 2);
    }
    (u64::from(!(probed & !0xF)) + 1, "mem32", 1)
}

fn network(device: usize, function: usize, base: usize) {
    let command = read(base, COMMAND) & 0xFFFF;
    write(base, COMMAND, command & !DECODING);
    let mut index = 0;
    while index < BARS {
        let (size, kind, registers) = measure(base, index);
        if size != 0 {
            rt::println!("pci: dev {device} fn {function} bar {index} size {size:#x} {kind}");
        }
        index += registers;
    }
    write(base, COMMAND, command);
    let mut at = (read(base, virtio_pci::CAPABILITIES) & 0xFC) as usize;
    for _ in 0..MOST_CAPABILITIES {
        if at < FIRST_CAPABILITY || at & 3 != 0 {
            break;
        }
        let head = read(base, at);
        if head & 0xFF == VENDOR_CAPABILITY {
            let (bar, offset, length) = (
                read(base, at + 4) & 0xFF,
                read(base, at + 8),
                read(base, at + 12),
            );
            rt::println!(
                "pci: dev {device} fn {function} cap type {} bar {bar} offset {offset:#x} length {length:#x}",
                head >> 24
            );
        }
        at = ((head >> 8) & 0xFF) as usize;
    }
    match virtio_pci::common_config(|offset| read(base, offset)) {
        Some((bar, offset)) => {
            rt::println!("pci: dev {device} fn {function} common bar {bar} offset {offset:#x}");
        }
        None => rt::println!("pci: dev {device} fn {function} common none"),
    }
}

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let Ok(channel) = sys::channel_create(1) else {
        return 2;
    };
    let Ok(mut got) = rt::service::register(&start.parent, &channel) else {
        return 2;
    };
    let Ok(ecam) = got.take::<Memory>("ecam") else {
        return 2;
    };
    if sys::mem_map(&start.process, &ecam, 0, ECAM_LEN, ECAM_AT, Access::ReadWrite).is_err() {
        return 3;
    }
    for device in 0..32 {
        for function in 0..8 {
            let base = function_at(device, function);
            let id = read(base, 0);
            if id == NO_FUNCTION {
                continue;
            }
            let class = read(base, 0x08) >> 8;
            rt::println!(
                "pci: dev {device} fn {function} id {:04x}:{:04x} class {class:06x} header {:02x} pin {}",
                id & 0xFFFF,
                id >> 16,
                (read(base, 0x0C) >> 16) & 0x7F,
                (read(base, 0x3C) >> 8) & 0xFF
            );
            if class >> 16 == NETWORK_CLASS {
                network(device, function, base);
            }
        }
    }
    rt::println!("pci-walk: done");
    0
}
