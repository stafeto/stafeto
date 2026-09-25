// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! In-kernel tests for `cargo xtask test`. Each test prints one line in the
//! format xtask parses; the run ends with a semihosting exit code.

use crate::arch::{exceptions, registers, semihosting};
use core::sync::atomic::Ordering;
use kcore::bootinfo::{BootInfo, PsciConduit, Region};
use kcore::layout::{GIB, KERNEL_VIRT, LINEAR_BASE};

type TestFn = fn(&BootInfo) -> Result<(), &'static str>;

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
];

pub fn run(info: &BootInfo) -> ! {
    let mut failed = 0u32;
    for (name, test) in TESTS {
        match test(info) {
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

fn device_tree_matches_qemu_virt(info: &BootInfo) -> Result<(), &'static str> {
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

fn boot_image_is_readable_through_linear_map(info: &BootInfo) -> Result<(), &'static str> {
    let initrd = info.initrd.ok_or("no boot image in /chosen")?;
    check(
        initrd.base / GIB == 1,
        "boot image is outside the GiB mapped at boot",
    )?;
    // SAFETY: the boot image lies in the GiB at 0x4000_0000, mapped as RAM by head.S.
    let head = unsafe {
        core::slice::from_raw_parts((LINEAR_BASE + initrd.base as usize) as *const u8, 8)
    };
    check(
        head == b"STAFBOOT",
        "boot image does not start with STAFBOOT",
    )
}

fn kernel_runs_in_upper_half_with_mmu_on(_: &BootInfo) -> Result<(), &'static str> {
    check(
        kernel_runs_in_upper_half_with_mmu_on as *const () as usize >= KERNEL_VIRT,
        "code runs below the kernel window",
    )?;
    check(registers::sctlr_el1() & 1 == 1, "SCTLR_EL1.M is clear")?;
    check(registers::current_el() == 1, "kernel is not at EL1")
}

fn identity_map_is_dropped(_: &BootInfo) -> Result<(), &'static str> {
    let table = (registers::ttbr0_el1() & 0x0000_FFFF_FFFF_F000) as usize;
    // SAFETY: TTBR0 points at boot_empty_l0 inside the kernel image, whose GiB is in the linear map.
    let l0 = unsafe { core::slice::from_raw_parts((LINEAR_BASE + table) as *const u64, 512) };
    check(l0.iter().all(|&e| e == 0), "TTBR0 still maps something")
}

fn brk_is_caught_and_execution_resumes(_: &BootInfo) -> Result<(), &'static str> {
    exceptions::LAST_BRK.store(u64::MAX, Ordering::Relaxed);
    // SAFETY: the exception handler records BRK and returns past it.
    unsafe { core::arch::asm!("brk #0x51") };
    check(
        exceptions::LAST_BRK.load(Ordering::Relaxed) == 0x51,
        "BRK was not recorded",
    )
}
