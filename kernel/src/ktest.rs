// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! In-kernel tests for `cargo xtask test`. Each test prints one line in the
//! format xtask parses; the run ends with a semihosting exit code.

use crate::arch::symbols;
use crate::arch::{exceptions, registers, semihosting};
use crate::boot::Boot;
use crate::mm::pages::KernelPages;
use crate::mm::phys;
use crate::mm::phys::LinearMem;
use core::sync::atomic::Ordering;
use kcore::bootinfo::PsciConduit;
use kcore::esr::TEST_BRK;
use kcore::frames::{PAGE_SIZE, PhysMem};
use kcore::layout::{GIB, KERNEL_VIRT, LINEAR_BASE};
use kcore::memmap;
use kcore::paging::{MAIR_DEVICE, PXN, PageTable, TTBR_ROOT_MASK, TableMemory, attr_index};
use kcore::slab::Pool;

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
    (
        "boot_stack_linear_map_and_devices_are_not_executable",
        boot_stack_linear_map_and_devices_are_not_executable,
    ),
    ("console_is_device_memory", console_is_device_memory),
    (
        "pools_take_pages_from_the_frame_allocator",
        pools_take_pages_from_the_frame_allocator,
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

/// RAM of the machine as the device tree reports it.
fn ram_size(boot: &Boot) -> u64 {
    boot.info.memory.as_slice().iter().map(|r| r.size).sum()
}

fn device_tree_matches_qemu_virt(boot: &Boot) -> Result<(), &'static str> {
    let info = &boot.info;
    // xtask runs the tests on machines with 512 MiB and 2 GiB.
    let memory = info.memory.as_slice();
    check(
        memory.len() == 1
            && memory[0].base == 0x4000_0000
            && [512 << 20, 2 << 30].contains(&memory[0].size),
        "memory is not 512 MiB or 2 GiB at 0x4000_0000",
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
    let table = (registers::ttbr0_el1() & TTBR_ROOT_MASK) as usize;
    // SAFETY: TTBR0 points at boot_empty_l0 inside the kernel image, whose GiB is in the linear map.
    let l0 = unsafe { core::slice::from_raw_parts((LINEAR_BASE + table) as *const u64, 512) };
    check(l0.iter().all(|&e| e == 0), "TTBR0 still maps something")
}

fn brk_is_caught_and_execution_resumes(_: &Boot) -> Result<(), &'static str> {
    exceptions::LAST_BRK.store(u64::MAX, Ordering::Relaxed);
    // SAFETY: the exception handler records BRK and returns past it.
    unsafe { core::arch::asm!("brk #{imm}", imm = const TEST_BRK) };
    check(
        exceptions::LAST_BRK.load(Ordering::Relaxed) == u64::from(TEST_BRK),
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
    let ram = ram_size(boot);
    check(
        total > ram - (12 << 20) && total < ram,
        "usable memory is not just under the machine's RAM",
    )
}

fn frames_are_aligned_distinct_and_usable(boot: &Boot) -> Result<(), &'static str> {
    let meta = phys::metadata();
    let mut guard = phys::FRAMES.lock();
    let frames = guard.as_mut().ok_or("no frame allocator")?;
    let before = frames.free_frames();
    let a = frames.alloc(0).ok_or("out of frames")?;
    let b = frames.alloc(0).ok_or("out of frames")?;
    let big = frames.alloc(9).ok_or("no 2 MiB block")?;
    check(a != b, "two allocations returned the same frame")?;
    check(big.is_multiple_of(2 << 20), "2 MiB block is misaligned")?;
    for (pa, size) in [(a, PAGE_SIZE), (b, PAGE_SIZE), (big, 2 << 20)] {
        check(
            boot.usable
                .as_slice()
                .iter()
                .any(|u| pa >= u.base && pa + size <= u.end()),
            "a block lies outside usable RAM",
        )?;
        check(
            pa + size <= meta.base || pa >= meta.end(),
            "a block overlaps the allocator's metadata",
        )?;
    }
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

// SAFETY: it never allocates and never writes; reads reach the live
// kernel tables through the linear map.
unsafe impl TableMemory for LiveTables {
    fn alloc_table(&mut self) -> Option<u64> {
        None
    }
    fn read(&self, pa: u64) -> u64 {
        // SAFETY: the walk only reads the live kernel tables.
        unsafe { LinearMem::new() }.read(pa)
    }
    fn write(&mut self, _: u64, _: u64) {
        panic!("the live-table walk writes nothing");
    }
}

fn translates(par: u64) -> bool {
    par & 1 == 0
}

fn kernel_tables() -> PageTable {
    PageTable::from_root(registers::ttbr1_el1() & TTBR_ROOT_MASK)
}

/// Leaf descriptor of `va` in the live kernel tables.
fn kernel_descriptor(va: usize) -> Option<u64> {
    kernel_tables()
        .translate(&LiveTables, va as u64)
        .map(|(_, d)| d)
}

/// Calls `f` with the first and last page of every RAM region and the first
/// page of every GiB inside it, so a machine with more than 1 GiB also
/// probes RAM the boot page tables did not map.
fn for_each_ram_probe(
    boot: &Boot,
    mut f: impl FnMut(u64) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let ram = memmap::usable::<32>(boot.info.memory.as_slice(), boot.info.no_map.as_slice())
        .map_err(|_| "too many RAM regions")?;
    for r in ram.as_slice() {
        f(r.base)?;
        let mut gib = (r.base / GIB + 1) * GIB;
        while gib < r.end() {
            f(gib)?;
            gib += GIB;
        }
        f(r.end() - PAGE_SIZE)?;
    }
    Ok(())
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
    let text = kernel_descriptor(layout.start).ok_or("kernel text is unmapped")?;
    let rodata = kernel_descriptor(layout.text_end).ok_or("kernel rodata is unmapped")?;
    let data = kernel_descriptor(layout.rodata_end).ok_or("kernel data is unmapped")?;
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
    for_each_ram_probe(boot, |pa| {
        check(
            translates(registers::at_s1e1r(LINEAR_BASE + pa as usize)),
            "RAM is missing from the linear map",
        )
    })
}

fn boot_stack_linear_map_and_devices_are_not_executable(boot: &Boot) -> Result<(), &'static str> {
    let kernel_never_executes = |va: usize| kernel_descriptor(va).is_some_and(|d| d & PXN != 0);
    let stack = symbols::boot_stack();
    for va in [stack.start, stack.end - 1] {
        check(
            kernel_never_executes(va),
            "the boot stack is unmapped or executable",
        )?;
    }
    for_each_ram_probe(boot, |pa| {
        check(
            kernel_never_executes(LINEAR_BASE + pa as usize),
            "the linear map is unmapped or executable",
        )
    })?;
    let info = &boot.info;
    for dev in [
        info.uart_pl011,
        info.gic_distributor,
        info.gic_cpu_interface,
    ]
    .into_iter()
    .flatten()
    {
        check(
            kernel_never_executes(LINEAR_BASE + dev.base as usize),
            "a device is unmapped or executable",
        )?;
    }
    Ok(())
}

fn console_is_device_memory(boot: &Boot) -> Result<(), &'static str> {
    let uart = boot.info.uart_pl011.ok_or("no PL011 in the device tree")?;
    let d = kernel_descriptor(LINEAR_BASE + uart.base as usize).ok_or("the PL011 is unmapped")?;
    check(
        attr_index(d) == MAIR_DEVICE,
        "the PL011 is not mapped as device memory",
    )
}

fn pools_take_pages_from_the_frame_allocator(_: &Boot) -> Result<(), &'static str> {
    let before = phys::free_frames();
    let mut pool: Pool<[u64; 32]> = Pool::new();
    let mut src = KernelPages;
    let mut objects = [None; 40];
    for (i, slot) in objects.iter_mut().enumerate() {
        *slot = Some(
            pool.alloc(&mut src, [i as u64; 32])
                .map_err(|_| "out of pages")?,
        );
    }
    check(
        pool.pages() == 3,
        "40 objects of 256 bytes did not take 3 pages",
    )?;
    check(
        phys::free_frames() == before - 3,
        "pool pages did not come from the frame allocator",
    )?;
    for (i, object) in objects.iter().flatten().enumerate() {
        // SAFETY: the object is live.
        let last = unsafe { object.as_ref()[31] };
        check(last == i as u64, "an object lost its value")?;
    }
    for object in objects.iter().flatten() {
        // SAFETY: each object is live and not used afterwards.
        unsafe { pool.free(*object) };
    }
    check(
        pool.in_use() == 0,
        "objects are still in use after freeing all",
    )
}
