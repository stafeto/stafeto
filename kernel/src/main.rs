// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The stafeto kernel. Milestone 1.2c: boot, read the device tree and the
//! boot image, set up the kernel's memory, the interrupt controller, the
//! timer and the scheduler, report, and start init from the boot image;
//! init's end ends the run. Test builds run the kernel tests instead of
//! init.

#![no_std]
#![no_main]

#[macro_use]
mod console;
mod arch;
mod boot;
#[cfg(not(feature = "ktest"))]
mod init;
mod interrupt;
#[cfg(feature = "ktest")]
mod ktest;
mod mm;
mod object;
mod panicking;
mod process;
mod psci;
mod sched;
mod syscall;
mod thread;

use boot::Boot;
use bootimg::Program;
use kcore::frames::PAGE_SIZE;
use kcore::layout::KERNEL_VIRT;
use kcore::time::Clock;

#[unsafe(no_mangle)]
extern "C" fn kernel_main(dtb_pa: usize, kernel_pa: usize) -> ! {
    arch::exceptions::init();
    console::init();
    kprintln!("stafeto {} booting", env!("CARGO_PKG_VERSION"));
    let boot = boot::collect(dtb_pa, kernel_pa);
    psci::set_conduit(boot.info.psci);
    // Until the kernel's own tables are built, the allocator sees only the
    // RAM in the GiBs the boot page tables map; the kernel tables are built
    // from that RAM, and the rest of RAM joins the allocator once they are live.
    let rest = mm::phys::init(boot);
    mm::kmap::switch_to_kernel_tables(boot);
    let init = boot::init_program(boot);
    arch::user::init();
    mm::phys::add(rest.as_slice());
    mm::aspace::init(boot);
    arch::gic::init(&boot.info);
    let clock = arch::timer::init();
    sched::init(clock);
    report(boot, clock, &init);
    #[cfg(feature = "fault-probe")]
    arch::probe::undefined_instruction();
    #[cfg(feature = "overflow-probe")]
    arch::probe::recurse(0);
    finish(boot, &init)
}

/// The kernel leaves for init (spec 13.3); init's exit turns the machine
/// off, and its fault or kill stops it (process::init_ended).
#[cfg(not(feature = "ktest"))]
fn finish(_boot: &Boot, program: &Program) -> ! {
    kprintln!("boot complete");
    init::start(program)
}

#[cfg(feature = "ktest")]
fn finish(boot: &Boot, _program: &Program) -> ! {
    ktest::run(boot)
}

fn report(boot: &Boot, clock: Clock, init: &Program) {
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
    let [code, rodata, data] = &init.segments;
    kprintln!(
        "init       entry {:#x}, stack {:#x}, code {:#x?}, rodata {:#x?}, data {:#x?}",
        init.entry,
        init.stack_size,
        code.pages(),
        rodata.pages(),
        data.pages()
    );
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
    kprintln!("timer      {} Hz", clock.hz());
    for r in boot.usable.as_slice() {
        kprintln!("usable     {:#x}..{:#x}", r.base, r.end());
    }
    let total: u64 = boot.usable.as_slice().iter().map(|r| r.size).sum();
    kprintln!("usable     {} MiB in total", total >> 20);
    kprintln!(
        "frames     {} MiB free",
        (mm::phys::free_frames() * PAGE_SIZE) >> 20
    );
}
