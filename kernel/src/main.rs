// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The stafeto kernel. Milestone 1.2a: boot, read the device tree, set up
//! the kernel's memory, report and power off.

#![no_std]
#![no_main]

#[macro_use]
mod console;
mod arch;
mod boot;
#[cfg(feature = "ktest")]
mod ktest;
mod mm;
mod panicking;
mod psci;

use boot::Boot;
use kcore::layout::KERNEL_VIRT;

#[unsafe(no_mangle)]
extern "C" fn kernel_main(dtb_pa: usize, kernel_pa: usize) -> ! {
    arch::exceptions::init();
    console::init();
    kprintln!("stafeto {} booting", env!("CARGO_PKG_VERSION"));
    let boot = boot::collect(dtb_pa, kernel_pa);
    psci::set_conduit(boot.info.psci);
    let _rest = mm::phys::init(&boot); // RAM outside the GiBs mapped at boot
    report(&boot);
    #[cfg(feature = "fault-probe")]
    arch::probe::undefined_instruction();
    finish(&boot)
}

#[cfg(not(feature = "ktest"))]
fn finish(_boot: &Boot) -> ! {
    kprintln!("boot complete");
    psci::system_off()
}

#[cfg(feature = "ktest")]
fn finish(boot: &Boot) -> ! {
    ktest::run(boot)
}

fn report(boot: &Boot) {
    let info = &boot.info;
    for r in info.memory.as_slice() {
        kprintln!("memory     {:#x}..{:#x}", r.base, r.end());
    }
    for r in info.reserved.as_slice() {
        kprintln!("reserved   {:#x}..{:#x}", r.base, r.end());
    }
    if let Some(r) = info.initrd {
        kprintln!("boot image {:#x}..{:#x}", r.base, r.end());
    }
    kprintln!("kernel     PA {:#x} at VA {KERNEL_VIRT:#x}", boot.kernel_pa);
    kprintln!(
        "image      {:#x}..{:#x}",
        boot.kernel_image.base,
        boot.kernel_image.end()
    );
    kprintln!("dtb        PA {:#x}", boot.dtb.base);
    if let Some(r) = info.uart_pl011 {
        kprintln!("pl011      {:#x}", r.base);
    }
    if let (Some(d), Some(c)) = (info.gic_distributor, info.gic_cpu_interface) {
        kprintln!(
            "gic        distributor {:#x}, cpu interface {:#x}",
            d.base,
            c.base
        );
    }
    kprintln!("psci       {:?}", info.psci);
    for r in boot.usable.as_slice() {
        kprintln!("usable     {:#x}..{:#x}", r.base, r.end());
    }
    let total: u64 = boot.usable.as_slice().iter().map(|r| r.size).sum();
    kprintln!("usable     {} MiB in total", total >> 20);
    kprintln!(
        "frames     {} MiB free",
        (mm::phys::free_frames() * 4096) >> 20
    );
}
