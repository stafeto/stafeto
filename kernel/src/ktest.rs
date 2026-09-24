// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! In-kernel tests for `cargo xtask test`. Each test prints one line in the
//! format xtask parses; the run ends with a semihosting exit code.

use crate::arch::symbols;
use crate::arch::{exceptions, registers, semihosting};
use crate::boot::Boot;
use crate::mm::phys;
use crate::mm::phys::LinearMem;
use core::sync::atomic::Ordering;
use kcore::bootinfo::{PsciConduit, Region};
use kcore::frames::PhysMem;
use kcore::layout::{KERNEL_VIRT, LINEAR_BASE};
use kcore::memmap;
use kcore::paging::{PXN, PageTable, TableMemory};

type TestFn = fn(&Boot) -> Result<(), &'static str>;

const TESTS: &[(&str, TestFn)] = &[
    (
        "device_tree_matches_qemu_virt",
        device_tree_matches_qemu_virt,
    ),
    (
        "boot_image_is_readable_through_linear_map",
        boot_image_is_readable_through_linear_map,
    ),
    (
        "kernel_runs_in_upper_half_with_mmu_on",
        kernel_runs_in_upper_half_with_mmu_on,
    ),
    ("identity_map_is_dropped", identity_map_is_dropped),
    (
        "brk_is_caught_and_execution_resumes",
        brk_is_caught_and_execution_resumes,
    ),
    (
        "usable_memory_leaves_the_boot_alone",
        usable_memory_leaves_the_boot_alone,
    ),
    (
        "frames_are_aligned_distinct_and_usable",
        frames_are_aligned_distinct_and_usable,
    ),
    (
        "kernel_text_is_read_only_and_data_writable",
        kernel_text_is_read_only_and_data_writable,
    ),
    (
        "only_kernel_text_is_executable",
        only_kernel_text_is_executable,
    ),
    ("stack_guard_page_is_unmapped", stack_guard_page_is_unmapped),
    (
        "physical_addresses_do_not_translate",
        physical_addresses_do_not_translate,
    ),
    ("linear_map_covers_all_ram", linear_map_covers_all_ram),
    ("console_is_device_memory", console_is_device_memory),
];

pub fn run(boot: &Boot) -> ! {
    let mut failed = 0u32;
    for (name, test) in TESTS {
        match test(boot) {
            Ok(()) => kprintln!("TEST {name} ok"),
            Err(why) => {
                failed += 1;
                kprintln!("TEST {name} FAIL {why}");
            }
        }
    }
    kprintln!("TESTS DONE failed={failed}");
    semihosting::exit(if failed == 0 { 0 } else { 1 })
}

fn check(ok: bool, why: &'static str) -> Result<(), &'static str> {
    if ok { Ok(()) } else { Err(why) }
}

fn device_tree_matches_qemu_virt(boot: &Boot) -> Result<(), &'static str> {
    let info = &boot.info;
    check(
        info.memory.as_slice()
            == [Region {
                base: 0x4000_0000,
                size: 512 << 20,
            }],
        "memory is not 512 MiB at 0x4000_0000",
    )?;
    check(
        info.uart_pl011.map(|r| r.base) == Some(0x0900_0000),
        "PL011 is not at 0x0900_0000",
    )?;
    check(
        info.gic_distributor.map(|r| r.base) == Some(0x0800_0000),
        "GIC distributor is not at 0x0800_0000",
    )?;
    check(
        info.gic_cpu_interface.map(|r| r.base) == Some(0x0801_0000),
        "GIC CPU interface is not at 0x0801_0000",
    )?;
    check(info.psci == PsciConduit::Hvc, "PSCI conduit is not HVC")?;
    check(info.initrd.is_some(), "no boot image in /chosen")
}

fn boot_image_is_readable_through_linear_map(boot: &Boot) -> Result<(), &'static str> {
    let initrd = boot.info.initrd.ok_or("no boot image in /chosen")?;
    // SAFETY: the boot image is RAM, and the kernel page tables map all RAM.
    let head = unsafe {
        core::slice::from_raw_parts((LINEAR_BASE + initrd.base as usize) as *const u8, 8)
    };
    check(
        head == b"STAFBOOT",
        "boot image does not start with STAFBOOT",
    )
}

fn kernel_runs_in_upper_half_with_mmu_on(_: &Boot) -> Result<(), &'static str> {
    check(
        kernel_runs_in_upper_half_with_mmu_on as *const () as usize >= KERNEL_VIRT,
        "code runs below the kernel window",
    )?;
    check(registers::sctlr_el1() & 1 == 1, "SCTLR_EL1.M is clear")?;
    check(registers::current_el() == 1, "kernel is not at EL1")
}

fn identity_map_is_dropped(_: &Boot) -> Result<(), &'static str> {
    let table = (registers::ttbr0_el1() & 0x0000_FFFF_FFFF_F000) as usize;
    // SAFETY: TTBR0 points at boot_empty_l0 inside the kernel image, whose GiB is in the linear map.
    let l0 = unsafe { core::slice::from_raw_parts((LINEAR_BASE + table) as *const u64, 512) };
    check(l0.iter().all(|&e| e == 0), "TTBR0 still maps something")
}

fn brk_is_caught_and_execution_resumes(_: &Boot) -> Result<(), &'static str> {
    exceptions::LAST_BRK.store(u64::MAX, Ordering::Relaxed);
    // SAFETY: the exception handler records BRK and returns past it.
    unsafe { core::arch::asm!("brk #0x51") };
    check(
        exceptions::LAST_BRK.load(Ordering::Relaxed) == 0x51,
        "BRK was not recorded",
    )
}

fn usable_memory_leaves_the_boot_alone(boot: &Boot) -> Result<(), &'static str> {
    let taken = [Some(boot.kernel_image), Some(boot.dtb), boot.info.initrd];
    let mut total = 0;
    for u in boot.usable.as_slice() {
        check(
            u.base.is_multiple_of(4096) && u.size.is_multiple_of(4096),
            "usable region is not page-aligned",
        )?;
        for t in taken.iter().flatten() {
            check(
                u.end() <= t.base || u.base >= t.end(),
                "usable memory overlaps the kernel, the device tree or the boot image",
            )?;
        }
        total += u.size;
    }
    check(
        total > 500 << 20 && total < 512 << 20,
        "usable memory is not just under 512 MiB",
    )
}

fn frames_are_aligned_distinct_and_usable(_: &Boot) -> Result<(), &'static str> {
    let mut guard = phys::FRAMES.lock();
    let frames = guard.as_mut().ok_or("no frame allocator")?;
    let before = frames.free_frames();
    let a = frames.alloc(0).ok_or("out of frames")?;
    let b = frames.alloc(0).ok_or("out of frames")?;
    let big = frames.alloc(9).ok_or("no 2 MiB block")?;
    check(a != b, "two allocations returned the same frame")?;
    check(big.is_multiple_of(2 << 20), "2 MiB block is misaligned")?;
    for (pa, pattern) in [(a, 0xA5A5_u64), (b, 0x5A5A)] {
        let p = (LINEAR_BASE + pa as usize) as *mut u64;
        // SAFETY: the frame was just allocated and lies in the linear map.
        let back = unsafe {
            p.write_volatile(pattern);
            p.read_volatile()
        };
        check(back == pattern, "a frame does not keep what was written")?;
    }
    frames.free(a, 0);
    frames.free(b, 0);
    frames.free(big, 9);
    check(
        frames.free_frames() == before,
        "free frame count did not come back",
    )
}

/// Walks the live kernel tables through the linear map; never allocates.
struct LiveTables;

impl TableMemory for LiveTables {
    fn alloc_table(&mut self) -> Option<u64> {
        None
    }
    fn read(&self, pa: u64) -> u64 {
        LinearMem.read(pa)
    }
    fn write(&mut self, _: u64, _: u64) {
        panic!("the live-table walk writes nothing");
    }
}

fn translates(par: u64) -> bool {
    par & 1 == 0
}

fn kernel_tables() -> PageTable {
    PageTable::from_root(registers::ttbr1_el1() & 0x0000_FFFF_FFFF_F000)
}

fn kernel_text_is_read_only_and_data_writable(_: &Boot) -> Result<(), &'static str> {
    let text = kernel_text_is_read_only_and_data_writable as *const () as usize;
    check(
        translates(registers::at_s1e1r(text)),
        "kernel text is not readable",
    )?;
    check(
        !translates(registers::at_s1e1w(text)),
        "kernel text is writable",
    )?;
    let data = &exceptions::LAST_BRK as *const _ as usize;
    check(
        translates(registers::at_s1e1w(data)),
        "kernel data is not writable",
    )
}

fn only_kernel_text_is_executable(_: &Boot) -> Result<(), &'static str> {
    let layout = symbols::image_layout();
    let pt = kernel_tables();
    let desc = |va: usize| pt.translate(&LiveTables, va as u64).map(|(_, d)| d);
    let text = desc(layout.start).ok_or("kernel text is unmapped")?;
    let rodata = desc(layout.text_end).ok_or("kernel rodata is unmapped")?;
    let data = desc(layout.rodata_end).ok_or("kernel data is unmapped")?;
    check(text & PXN == 0, "kernel text is not executable")?;
    check(rodata & PXN != 0, "kernel rodata is executable")?;
    check(data & PXN != 0, "kernel data is executable")
}

fn stack_guard_page_is_unmapped(_: &Boot) -> Result<(), &'static str> {
    let guard = symbols::image_layout().stack_guard;
    check(
        !translates(registers::at_s1e1r(guard)),
        "the stack guard page is mapped",
    )
}

fn physical_addresses_do_not_translate(boot: &Boot) -> Result<(), &'static str> {
    check(
        !translates(registers::at_s1e1r(boot.kernel_pa as usize)),
        "the kernel's physical address still translates through TTBR0",
    )
}

fn linear_map_covers_all_ram(boot: &Boot) -> Result<(), &'static str> {
    let ram = memmap::usable::<32>(boot.info.memory.as_slice(), boot.info.no_map.as_slice())
        .map_err(|_| "too many RAM regions")?;
    for r in ram.as_slice() {
        for pa in [r.base, r.end() - 4096] {
            check(
                translates(registers::at_s1e1r(LINEAR_BASE + pa as usize)),
                "RAM is missing from the linear map",
            )?;
        }
    }
    Ok(())
}

fn console_is_device_memory(boot: &Boot) -> Result<(), &'static str> {
    let uart = boot.info.uart_pl011.ok_or("no PL011 in the device tree")?;
    let (_, d) = kernel_tables()
        .translate(&LiveTables, (LINEAR_BASE + uart.base as usize) as u64)
        .ok_or("the PL011 is unmapped")?;
    check(
        (d >> 2) & 0b111 == 1,
        "the PL011 is not mapped as device memory",
    )
}
