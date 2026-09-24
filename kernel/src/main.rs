// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The stafeto kernel. Milestone 1: boot to Rust in the upper half, read the
//! device tree, report what it says and power off.

#![no_std]
#![no_main]

#[macro_use]
mod console;
mod arch;
#[cfg(feature = "ktest")]
mod ktest;
mod panicking;
mod psci;

use kcore::bootinfo::{self, BootInfo};
use kcore::fdt::Fdt;
use kcore::layout::{dtb_gib_is_mappable, fits_in_one_gib, KERNEL_VIRT, LINEAR_BASE};

#[unsafe(no_mangle)]
extern "C" fn kernel_main(dtb_pa: usize, kernel_pa: usize) -> ! {
    arch::exceptions::init();
    console::init();
    kprintln!("stafeto {} booting", env!("CARGO_PKG_VERSION"));
    if dtb_pa == 0 {
        panic!("no device tree in x0: boot the arm64 Image, not the ELF");
    }
    if !dtb_gib_is_mappable(dtb_pa as u64) {
        panic!("device tree pointer {dtb_pa:#x} is outside the RAM the boot page tables map");
    }
    // SAFETY: head.S mapped the GiB holding the device tree into the linear map,
    // and nothing writes to the device tree.
    let fdt = unsafe { Fdt::from_ptr((LINEAR_BASE + dtb_pa) as *const u8) }
        .unwrap_or_else(|e| panic!("device tree at {dtb_pa:#x}: {e:?}"));
    if !fits_in_one_gib(dtb_pa as u64, fdt.total_size() as u64) {
        panic!("device tree at {dtb_pa:#x} crosses a GiB boundary; only its first GiB is mapped");
    }
    let info = bootinfo::parse(&fdt).unwrap_or_else(|e| panic!("device tree: {e:?}"));
    psci::set_conduit(info.psci);
    report(&info, dtb_pa, kernel_pa);
    finish(&info)
}

#[cfg(not(feature = "ktest"))]
fn finish(_info: &BootInfo) -> ! {
    kprintln!("boot complete");
    psci::system_off()
}

#[cfg(feature = "ktest")]
fn finish(info: &BootInfo) -> ! {
    ktest::run(info)
}

fn report(info: &BootInfo, dtb_pa: usize, kernel_pa: usize) {
    for r in info.memory.as_slice() {
        kprintln!("memory     {:#x}..{:#x}", r.base, r.end());
    }
    for r in info.reserved.as_slice() {
        kprintln!("reserved   {:#x}..{:#x}", r.base, r.end());
    }
    if let Some(r) = info.initrd {
        kprintln!("boot image {:#x}..{:#x}", r.base, r.end());
    }
    kprintln!("kernel     PA {kernel_pa:#x} at VA {KERNEL_VIRT:#x}");
    kprintln!("dtb        PA {dtb_pa:#x}");
    if let Some(r) = info.uart_pl011 {
        kprintln!("pl011      {:#x}", r.base);
    }
    if let (Some(d), Some(c)) = (info.gic_distributor, info.gic_cpu_interface) {
        kprintln!("gic        distributor {:#x}, cpu interface {:#x}", d.base, c.base);
    }
    kprintln!("psci       {:?}", info.psci);
}
