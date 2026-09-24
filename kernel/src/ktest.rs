// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! In-kernel tests for `cargo xtask test`. Each test prints one line in the
//! format xtask parses; the run ends with a semihosting exit code.

use crate::arch::{exceptions, registers, semihosting};
use crate::boot::Boot;
use crate::mm::phys;
use core::sync::atomic::Ordering;
use kcore::bootinfo::{PsciConduit, Region};
use kcore::layout::{GIB, KERNEL_VIRT, LINEAR_BASE};

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
