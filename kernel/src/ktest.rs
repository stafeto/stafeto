// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! In-kernel tests for `cargo xtask test`. Each test prints one line in the
//! format xtask parses; the run ends with a semihosting exit code. The tests
//! at EL0 (`el0`) come last, as a chain that never returns here.

pub mod calls;
pub mod el0;

use crate::arch::symbols;
use crate::arch::user::UserRegs;
use crate::arch::{self, exceptions, gic, registers, semihosting, timer};
use crate::boot::Boot;
use crate::mm::aspace::{self, AddressSpace};
use crate::mm::pages::KernelPages;
use crate::mm::phys;
use crate::mm::phys::LinearMem;
use crate::thread::Policy;
use crate::{process, thread};
use abi::Error;
use core::sync::atomic::{AtomicU32, Ordering};
use kcore::bootinfo::PsciConduit;
use kcore::esr::TEST_BRK;
use kcore::frames::{PAGE_SIZE, PhysMem};
use kcore::gic::{Ack, DEFAULT_PRIORITY};
use kcore::layout::{
    GIB, KERNEL_STACK_SIZE, KERNEL_VIRT, LINEAR_BASE, USER_END, frame_fits, image_pa,
};
use kcore::memmap;
use kcore::paging::{
    Attrs, MAIR_DEVICE, MapError, NG, PXN, PageTable, TTBR_ROOT_MASK, TableMemory, UXN, attr_index,
};
use kcore::sched::State;
use kcore::slab::Pool;
use kcore::sysreg::{self, CNTKCTL_EL1, CPACR_EL1, MDSCR_EL1, SCTLR_EL1, SPSR_EL0T};

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
        "kernel_stacks_suit_the_overflow_check",
        kernel_stacks_suit_the_overflow_check,
    ),
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
    (
        "virtual_counter_runs_at_the_reported_frequency",
        virtual_counter_runs_at_the_reported_frequency,
    ),
    (
        "timer_interrupt_arrives_through_the_gic",
        timer_interrupt_arrives_through_the_gic,
    ),
    ("past_deadline_fires_at_once", past_deadline_fires_at_once),
    ("far_deadline_does_not_fire", far_deadline_does_not_fire),
    (
        "spurious_interrupt_needs_no_eoi",
        spurious_interrupt_needs_no_eoi,
    ),
    (
        "timer_line_without_istatus_is_spurious",
        timer_line_without_istatus_is_spurious,
    ),
    (
        "pending_interrupt_shows_while_masked",
        pending_interrupt_shows_while_masked,
    ),
    (
        "asids_are_as_wide_as_tcr_allows",
        asids_are_as_wide_as_tcr_allows,
    ),
    (
        "user_pages_follow_their_rights",
        user_pages_follow_their_rights,
    ),
    (
        "switching_spaces_switches_translations",
        switching_spaces_switches_translations,
    ),
    (
        "unmapped_page_no_longer_translates",
        unmapped_page_no_longer_translates,
    ),
    (
        "asid_rollover_hides_old_mappings",
        asid_rollover_hides_old_mappings,
    ),
    (
        "released_asid_hides_old_mappings",
        released_asid_hides_old_mappings,
    ),
    (
        "destroying_a_space_returns_its_tables",
        destroying_a_space_returns_its_tables,
    ),
    (
        "ttbr0_is_empty_outside_processes",
        ttbr0_is_empty_outside_processes,
    ),
    ("system_registers_open_el0", system_registers_open_el0),
    (
        "kernel_memory_is_closed_to_el0",
        kernel_memory_is_closed_to_el0,
    ),
    (
        "processes_and_threads_return_their_memory",
        processes_and_threads_return_their_memory,
    ),
    (
        "unknown_system_calls_fail_with_invalid_args",
        calls::unknown_system_calls_fail_with_invalid_args,
    ),
    (
        "debug_write_checks_its_arguments",
        calls::debug_write_checks_its_arguments,
    ),
    (
        "object_info_reports_a_live_process",
        calls::object_info_reports_a_live_process,
    ),
    (
        "closing_a_handle_releases_its_object",
        calls::closing_a_handle_releases_its_object,
    ),
    (
        "init_handles_have_their_fixed_values",
        calls::init_handles_have_their_fixed_values,
    ),
    (
        "thread_set_priority_checks_its_arguments",
        calls::thread_set_priority_checks_its_arguments,
    ),
    (
        "process_create_checks_its_arguments",
        calls::process_create_checks_its_arguments,
    ),
    (
        "thread_create_checks_its_arguments",
        calls::thread_create_checks_its_arguments,
    ),
    (
        "process_kill_ends_threads_in_every_state",
        calls::process_kill_ends_threads_in_every_state,
    ),
];

/// Tests that failed so far, the EL0 tests' included.
static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn run(boot: &Boot) -> ! {
    #[cfg(feature = "icount")]
    report(
        "virtual_time_counts_instructions",
        virtual_time_counts_instructions(),
    );
    for (name, test) in TESTS {
        report(name, test(boot));
    }
    el0::run()
}

fn report(name: &str, result: Result<(), &'static str>) {
    match result {
        Ok(()) => kprintln!("TEST {name} ok"),
        Err(why) => {
            FAILED.fetch_add(1, Ordering::Relaxed);
            kprintln!("TEST {name} FAIL {why}");
        }
    }
}

/// Prints the verdict and leaves QEMU. The line counts the tests of the
/// build, so that xtask notices a TEST line lost in the output.
fn finish() -> ! {
    let failed = FAILED.load(Ordering::Relaxed);
    let total = usize::from(cfg!(feature = "icount")) + TESTS.len() + el0::count();
    kprintln!("TESTS DONE total={total} failed={failed}");
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
    fn free_table(&mut self, _: u64) {
        panic!("the live-table walk frees nothing");
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

/// The layout exception entry relies on (vectors.S): the boot stack aligned
/// to twice its size, the emergency stack right below the guard page and
/// inside the range where no trap frame fits, so an entry on it starts over
/// at its top; the emergency stack is writable and never executable.
fn kernel_stacks_suit_the_overflow_check(_: &Boot) -> Result<(), &'static str> {
    let stack = symbols::boot_stack();
    check(
        stack.start.is_multiple_of(2 * KERNEL_STACK_SIZE) && stack.len() == KERNEL_STACK_SIZE,
        "the boot stack is not 64 KiB aligned to 128 KiB",
    )?;
    let emergency = symbols::emergency_stack();
    check(
        emergency.end == symbols::image_layout().stack_guard,
        "the emergency stack does not end at the guard page",
    )?;
    check(
        !frame_fits(emergency.start) && !frame_fits(emergency.end - 16),
        "a trap frame fits on the emergency stack",
    )?;
    for va in [emergency.start, emergency.end - 8] {
        check(
            translates(registers::at_s1e1w(va)),
            "the emergency stack is not writable",
        )?;
        check(
            kernel_descriptor(va).is_some_and(|d| d & PXN != 0),
            "the emergency stack is executable",
        )?;
    }
    Ok(())
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

fn virtual_counter_runs_at_the_reported_frequency(_: &Boot) -> Result<(), &'static str> {
    check(
        timer::frequency() == 62_500_000,
        "CNTFRQ_EL0 is not the 62.5 MHz of QEMU's cortex-a72 and cortex-a53",
    )?;
    let start = timer::now();
    check(
        (0..1_000_000).any(|_| timer::now() > start),
        "the virtual counter does not move",
    )
}

/// Wake-ups `wait_for_timer` allows before giving up. `wfi` may end without
/// a pending interrupt; an interrupt that never comes hangs the test instead.
const WAKE_UPS: usize = 1000;

/// Sleeps with interrupts masked until the GIC hands out an interrupt, which
/// must be the timer's.
fn wait_for_timer() -> Result<Ack, &'static str> {
    for _ in 0..WAKE_UPS {
        if let Some(ack) = gic::wait() {
            if ack.intid() == timer::INTID {
                return Ok(ack);
            }
            gic::end(ack);
            return Err("an interrupt other than the timer's arrived");
        }
    }
    Err("the timer interrupt did not arrive")
}

fn timer_interrupt_arrives_through_the_gic(_: &Boot) -> Result<(), &'static str> {
    check(
        gic::is_enabled(timer::INTID) && gic::priority(timer::INTID) == DEFAULT_PRIORITY,
        "the timer line is masked or has another priority",
    )?;
    let deadline = timer::clock().deadline_after(timer::now(), 1_000_000);
    timer::arm(deadline);
    let ack = wait_for_timer()?;
    let fired = timer::now();
    let condition = timer::fired();
    let active = gic::is_active(timer::INTID);
    // The line is level-triggered: quiet the timer before the EOI.
    timer::disarm();
    gic::end(ack);
    check(fired >= deadline, "the timer fired before its deadline")?;
    check(
        condition,
        "the timer interrupt came without the timer's condition",
    )?;
    check(active, "the timer interrupt is not active before its EOI")?;
    check(
        !gic::is_active(timer::INTID),
        "the timer interrupt is still active after its EOI",
    )?;
    nothing_pending("an interrupt is pending after the EOI")
}

/// Err with `error` when the GIC hands out an interrupt. That interrupt
/// gets its EOI, so a failed test leaves no line active for the next.
fn nothing_pending(error: &'static str) -> Result<(), &'static str> {
    match gic::acknowledge() {
        Some(ack) => {
            gic::end(ack);
            Err(error)
        }
        None => Ok(()),
    }
}

fn past_deadline_fires_at_once(_: &Boot) -> Result<(), &'static str> {
    let clock = timer::clock();
    let start = timer::now();
    timer::arm(start.saturating_sub(clock.ns_to_ticks(1_000_000)));
    let ack = wait_for_timer()?;
    let waited = clock.ns_until(start, timer::now());
    timer::disarm();
    gic::end(ack);
    // An upper bound on time holds only where time counts instructions:
    // elsewhere a stall of the host could take longer (report 7.1).
    if cfg!(feature = "icount") {
        check(
            waited < 1_000_000,
            "a deadline in the past did not fire at once",
        )?;
    }
    Ok(())
}

/// A deadline centuries away must not wrap into the past: the timer stays
/// quiet while 1 ms of counter time passes.
fn far_deadline_does_not_fire(_: &Boot) -> Result<(), &'static str> {
    let clock = timer::clock();
    let start = timer::now();
    timer::arm(clock.deadline_after(start, u64::MAX));
    let later = clock.deadline_after(start, 1_000_000);
    while timer::now() < later {}
    let fired = gic::acknowledge();
    timer::disarm();
    match fired {
        Some(ack) => {
            gic::end(ack);
            Err("a deadline centuries away fired")
        }
        None => Ok(()),
    }
}

/// GICC_IAR with nothing to hand out reads a spurious INTID, which gets no
/// EOI; so does a line the distributor masks. Neither disturbs the next
/// real interrupt.
fn spurious_interrupt_needs_no_eoi(_: &Boot) -> Result<(), &'static str> {
    nothing_pending("IAR handed out an interrupt with nothing pending")?;
    gic::mask(timer::INTID);
    timer::arm(0);
    let masked = gic::acknowledge();
    gic::unmask(timer::INTID);
    if let Some(ack) = masked {
        timer::disarm();
        gic::end(ack);
        return Err("IAR handed out a masked line");
    }
    let ack = wait_for_timer()?;
    timer::disarm();
    gic::end(ack);
    check(
        !gic::is_active(timer::INTID),
        "the timer interrupt is still active after its EOI",
    )
}

/// On real hardware a level line may reach the GIC once more after the EOI
/// that followed a disarm. The handler then finds the timer off and treats
/// INTID 27 as spurious; the test makes the line pending by hand to get
/// that late interrupt.
fn timer_line_without_istatus_is_spurious(_: &Boot) -> Result<(), &'static str> {
    timer::disarm();
    gic::set_pending(timer::INTID);
    let ack = wait_for_timer()?;
    let fired = timer::fired();
    gic::end(ack);
    check(!fired, "a disarmed timer says its deadline has passed")?;
    check(
        !gic::is_active(timer::INTID),
        "the timer interrupt is still active after its EOI",
    )?;
    nothing_pending("an interrupt is pending after the EOI")
}

/// Long kernel operations poll for pending interrupts (spec 7.7): ISR_EL1
/// shows one while PSTATE masks it, and none once it is acknowledged.
fn pending_interrupt_shows_while_masked(_: &Boot) -> Result<(), &'static str> {
    check(
        !arch::irq_pending(),
        "ISR_EL1 shows an interrupt with nothing pending",
    )?;
    timer::arm(0);
    let seen = (0..1_000_000).any(|_| arch::irq_pending());
    let ack = wait_for_timer()?;
    let after_ack = arch::irq_pending();
    timer::disarm();
    gic::end(ack);
    check(seen, "ISR_EL1 does not show the pending timer interrupt")?;
    check(
        !after_ack,
        "ISR_EL1 still shows the interrupt after its acknowledgement",
    )?;
    check(
        !arch::irq_pending(),
        "ISR_EL1 shows an interrupt after the EOI",
    )
}

fn asids_are_as_wide_as_tcr_allows(_: &Boot) -> Result<(), &'static str> {
    check(
        registers::tcr_el1() & (1 << 36) != 0,
        "TCR_EL1.AS is clear on a CPU with 16-bit ASIDs",
    )?;
    check(
        aspace::asid_bits() == 16,
        "the ASID allocator is not 16 bits wide",
    )
}

/// A user address for the address space tests: 4 MiB, away from 0.
const USER_VA: usize = 0x40_0000;
const PAGE: usize = PAGE_SIZE as usize;

/// PAR_EL1.PA, bits [47:12], after a translation that succeeded.
const PAR_PA: u64 = 0x0000_FFFF_FFFF_F000;

/// A frame from the allocator, every word of it set to `pattern`.
fn frame_with(pattern: u64) -> Result<u64, &'static str> {
    let pa = phys::FRAMES
        .lock()
        .as_mut()
        .ok_or("no frame allocator")?
        .alloc(0)
        .ok_or("out of frames")?;
    // SAFETY: the frame was just taken from the allocator.
    let mut mem = unsafe { LinearMem::new() };
    for i in 0..PAGE_SIZE / 8 {
        mem.write(pa + i * 8, pattern);
    }
    Ok(pa)
}

fn free_frame(pa: u64) {
    phys::FRAMES
        .lock()
        .as_mut()
        .expect("frame allocator")
        .free(pa, 0);
}

/// The word at user address `va` in the active address space.
fn read_user(va: usize) -> u64 {
    // SAFETY: the caller has mapped `va` in the active space. The
    // cortex-a72 and cortex-a53 have no PAN, so EL1 reads pages that EL0
    // may read.
    unsafe { (va as *const u64).read_volatile() }
}

/// An address space that a test destroys when it is done with it, also on
/// an early return. Only `drop` takes the space out.
struct TestSpace(Option<AddressSpace>);

impl Drop for TestSpace {
    fn drop(&mut self) {
        if let Some(space) = self.0.take() {
            space.destroy();
        }
    }
}

impl core::ops::Deref for TestSpace {
    type Target = AddressSpace;
    fn deref(&self) -> &AddressSpace {
        self.0.as_ref().expect("a test space until it drops")
    }
}

impl core::ops::DerefMut for TestSpace {
    fn deref_mut(&mut self) -> &mut AddressSpace {
        self.0.as_mut().expect("a test space until it drops")
    }
}

fn new_space() -> Result<TestSpace, &'static str> {
    AddressSpace::new()
        .map(|space| TestSpace(Some(space)))
        .map_err(|_| "no frame for a root table")
}

fn map(space: &mut AddressSpace, va: usize, pa: u64, attrs: Attrs) -> Result<(), &'static str> {
    space
        .map(va, pa, PAGE_SIZE, attrs)
        .map_err(|_| "a user page did not map")
}

fn user_pages_follow_their_rights(_: &Boot) -> Result<(), &'static str> {
    let frame = frame_with(0x1111)?;
    let result = check_user_rights(frame);
    free_frame(frame);
    result
}

fn check_user_rights(frame: u64) -> Result<(), &'static str> {
    let mut space = new_space()?;
    let pages = [
        (USER_VA, Attrs::USER_RODATA),
        (USER_VA + PAGE, Attrs::USER_DATA),
        (USER_VA + 2 * PAGE, Attrs::USER_TEXT),
    ];
    for (va, attrs) in pages {
        map(&mut space, va, frame, attrs)?;
    }
    space.activate();
    for (va, attrs) in pages {
        let (_, d) = space
            .translate(va)
            .ok_or("a user page is not in the tables")?;
        check(d & NG != 0, "a user page is global")?;
        check(d & PXN != 0, "the kernel may execute a user page")?;
        check(
            (d & UXN == 0) == attrs.user_exec,
            "EL0 may execute a page it should not, or the other way round",
        )?;
        let read = registers::at_s1e0r(va);
        check(
            translates(read) && read & PAR_PA == frame,
            "EL0 cannot read its page",
        )?;
        check(
            translates(registers::at_s1e0w(va)) == attrs.write,
            "EL0 may write a page it should not, or the other way round",
        )?;
        check(
            translates(registers::at_s1e1r(va)),
            "the kernel cannot read a user page",
        )?;
    }
    check(
        !translates(registers::at_s1e0r(USER_VA + 3 * PAGE)),
        "a page nobody mapped translates",
    )
}

fn switching_spaces_switches_translations(_: &Boot) -> Result<(), &'static str> {
    let first = frame_with(0xA1)?;
    let second = frame_with(0xB2)?;
    let result = check_two_spaces(first, second);
    free_frame(first);
    free_frame(second);
    result
}

fn check_two_spaces(first: u64, second: u64) -> Result<(), &'static str> {
    let mut a = new_space()?;
    let mut b = new_space()?;
    map(&mut a, USER_VA, first, Attrs::USER_DATA)?;
    map(&mut b, USER_VA, second, Attrs::USER_DATA)?;
    a.activate();
    check(
        read_user(USER_VA) == 0xA1,
        "the first space misses its page",
    )?;
    b.activate();
    check(
        read_user(USER_VA) == 0xB2,
        "the second space sees the first one's page",
    )?;
    a.activate();
    check(
        read_user(USER_VA) == 0xA1,
        "the first space sees the second one's page",
    )?;
    let (x, y) = (a.asid(), b.asid());
    check(
        x.is_some() && y.is_some() && x != y && x != Some(0) && y != Some(0),
        "two live spaces share an ASID or run with the kernel's",
    )
}

fn unmapped_page_no_longer_translates(_: &Boot) -> Result<(), &'static str> {
    let frame = frame_with(0xC3)?;
    let other = frame_with(0xE5)?;
    let result = check_unmap(frame, other);
    free_frame(frame);
    free_frame(other);
    result
}

fn check_unmap(frame: u64, other: u64) -> Result<(), &'static str> {
    let mut space = new_space()?;
    map(&mut space, USER_VA, frame, Attrs::USER_DATA)?;
    space.activate();
    // The read brings the page into the TLB, which the unmap must drop.
    check(read_user(USER_VA) == 0xC3, "the page misses its contents")?;
    check(
        space.unmap(USER_VA) == Ok(frame),
        "unmap did not return the page's frame",
    )?;
    check(
        !translates(registers::at_s1e0r(USER_VA)) && !translates(registers::at_s1e1r(USER_VA)),
        "an unmapped page still translates",
    )?;
    check(
        space.translate(USER_VA).is_none(),
        "the tables still hold an unmapped page",
    )?;
    check(
        space.unmap(USER_VA) == Err(MapError::NotMapped),
        "a page was unmapped twice",
    )?;
    // Another frame at the same address shows through at once; a TLB entry
    // that the unmap left behind would still show the old one.
    map(&mut space, USER_VA, other, Attrs::USER_DATA)?;
    check(
        read_user(USER_VA) == 0xE5,
        "the TLB still holds the unmapped page",
    )
}

/// Two spaces map one address to different frames and run, one after the
/// other, with the same ASID of two generations: the TLB entry the first
/// one left must not show through in the second.
fn asid_rollover_hides_old_mappings(_: &Boot) -> Result<(), &'static str> {
    let first = frame_with(0xA1)?;
    let second = frame_with(0xB2)?;
    let result = check_rollover(first, second);
    free_frame(first);
    free_frame(second);
    result
}

fn check_rollover(first: u64, second: u64) -> Result<(), &'static str> {
    let mut a = new_space()?;
    let mut b = new_space()?;
    map(&mut a, USER_VA, first, Attrs::USER_DATA)?;
    map(&mut b, USER_VA, second, Attrs::USER_DATA)?;
    let start = aspace::asid_generation();
    aspace::use_up_asids();
    a.activate();
    check(
        aspace::asid_generation() == start + 1 && a.asid() == Some(1),
        "running out of ASIDs did not begin a new generation at ASID 1",
    )?;
    check(
        read_user(USER_VA) == 0xA1,
        "the first space misses its page",
    )?;
    aspace::use_up_asids();
    b.activate();
    check(
        aspace::asid_generation() == start + 2 && b.asid() == Some(1),
        "the second rollover did not hand out ASID 1 again",
    )?;
    check(
        read_user(USER_VA) == 0xB2,
        "a reused ASID shows the old space's page",
    )?;
    check(
        a.asid().is_none(),
        "an ASID of the old generation is still valid",
    )?;
    a.activate();
    check(
        a.asid().is_some_and(|asid| asid > 1),
        "the old space did not get a new ASID",
    )?;
    check(
        read_user(USER_VA) == 0xA1,
        "the old space lost its page in the new generation",
    )
}

/// A space goes while its ASID still tags a TLB entry; the next space gets
/// the same ASID and must not see the old page.
fn released_asid_hides_old_mappings(_: &Boot) -> Result<(), &'static str> {
    let first = frame_with(0xA1)?;
    let second = frame_with(0xB2)?;
    let result = check_released_asid(first, second);
    free_frame(first);
    free_frame(second);
    result
}

fn check_released_asid(first: u64, second: u64) -> Result<(), &'static str> {
    let mut a = new_space()?;
    let mut b = new_space()?;
    map(&mut a, USER_VA, first, Attrs::USER_DATA)?;
    map(&mut b, USER_VA, second, Attrs::USER_DATA)?;
    a.activate();
    check(
        read_user(USER_VA) == 0xA1,
        "the first space misses its page",
    )?;
    let asid = a.asid();
    // Only the ASID of `a` comes free when it goes.
    aspace::use_up_asids();
    let generation = aspace::asid_generation();
    // Destroys the space.
    drop(a);
    b.activate();
    check(
        aspace::asid_generation() == generation && b.asid() == asid,
        "the next space did not get the ASID of the one that went",
    )?;
    check(
        read_user(USER_VA) == 0xB2,
        "a released ASID shows the page of the space that went",
    )
}

fn destroying_a_space_returns_its_tables(_: &Boot) -> Result<(), &'static str> {
    let before = phys::free_frames();
    let frame = frame_with(0)?;
    let result = check_table_count(frame, before);
    free_frame(frame);
    result?;
    check(
        phys::free_frames() == before,
        "the tables did not go back to the frame allocator",
    )
}

/// Maps one frame at five addresses that need 13 tables between them, the
/// root included, and runs the space; it is destroyed when this returns.
fn check_table_count(frame: u64, before: u64) -> Result<(), &'static str> {
    let mut space = new_space()?;
    for va in [0x1000, USER_VA, 1 << 30, 1 << 39, USER_END - PAGE] {
        map(&mut space, va, frame, Attrs::USER_RODATA)?;
    }
    check(
        phys::free_frames() == before - 14,
        "13 tables and a page did not come from the frame allocator",
    )?;
    space.activate();
    Ok(())
}

fn ttbr0_is_empty_outside_processes(boot: &Boot) -> Result<(), &'static str> {
    let empty = image_pa(boot.kernel_pa, symbols::empty_table());
    check(
        registers::ttbr0_el1() == empty,
        "TTBR0 is not the empty table with ASID 0 after the tests before",
    )?;
    let frame = frame_with(0xD4)?;
    let result = check_deactivate(frame, empty);
    free_frame(frame);
    result
}

fn check_deactivate(frame: u64, empty: u64) -> Result<(), &'static str> {
    let mut space = new_space()?;
    map(&mut space, USER_VA, frame, Attrs::USER_DATA)?;
    space.activate();
    check(
        registers::ttbr0_el1() >> 48 != 0,
        "an address space runs with the kernel's ASID",
    )?;
    aspace::deactivate();
    check(
        registers::ttbr0_el1() == empty,
        "deactivate did not bring back the empty table",
    )?;
    check(
        !translates(registers::at_s1e0r(USER_VA)),
        "a user page translates outside processes",
    )?;
    space.activate();
    // Destroys the running space.
    drop(space);
    check(
        registers::ttbr0_el1() == empty,
        "destroying the running space left TTBR0 on its tables",
    )
}

fn system_registers_open_el0(_: &Boot) -> Result<(), &'static str> {
    check(
        registers::sctlr_el1() == SCTLR_EL1,
        "SCTLR_EL1 is not the value for programs at EL0",
    )?;
    check(
        registers::cpacr_el1() == CPACR_EL1,
        "FP and SIMD instructions trap",
    )?;
    check(
        registers::cntkctl_el1() == CNTKCTL_EL1,
        "EL0 cannot read the virtual counter, or can reach more timer registers",
    )?;
    check(
        registers::mdscr_el1() == MDSCR_EL1,
        "EL0 reaches the debug channel, or debug events are on",
    )?;
    check(
        !sysreg::has_pmu(registers::id_aa64dfr0_el1()) || registers::pmuserenr_el0() == 0,
        "EL0 reaches the performance monitors",
    )
}

/// EL0 reaches no kernel address: neither the image, nor the stacks, nor
/// the linear map, nor the devices.
fn kernel_memory_is_closed_to_el0(boot: &Boot) -> Result<(), &'static str> {
    // AT has no fetch variant, and AP alone does not keep EL0 from
    // fetching: every kernel page needs UXN. A probe the kernel cannot read
    // proves nothing.
    let closed = |va: usize| {
        translates(registers::at_s1e1r(va))
            && !translates(registers::at_s1e0r(va))
            && !translates(registers::at_s1e0w(va))
            && kernel_descriptor(va).is_some_and(|d| d & UXN != 0)
    };
    let layout = symbols::image_layout();
    for va in [
        layout.start,
        layout.text_end,
        layout.rodata_end,
        symbols::emergency_stack().start,
        symbols::boot_stack().start,
        symbols::boot_stack().end - 8,
    ] {
        check(closed(va), "EL0 reaches the kernel image or a kernel stack")?;
    }
    for_each_ram_probe(boot, |pa| {
        check(
            closed(LINEAR_BASE + pa as usize),
            "EL0 reaches the linear map",
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
            closed(LINEAR_BASE + dev.base as usize),
            "EL0 reaches a device",
        )?;
    }
    Ok(())
}

/// A process with a thread and mapped frames gives every frame back when
/// both go. The pools keep the page each takes for its first object, so
/// one round runs before the count.
fn processes_and_threads_return_their_memory(_: &Boot) -> Result<(), &'static str> {
    process_round()?;
    let before = phys::free_frames();
    process_round()?;
    check(
        phys::free_frames() == before,
        "a process or a thread kept frames after it went",
    )?;
    check(
        process::in_use() == 0 && thread::in_use() == 0,
        "a process or a thread is still in its pool",
    )
}

fn process_round() -> Result<(), &'static str> {
    let mut p = process::create(16, 63).map_err(|_| "no process")?;
    let before = phys::free_frames();
    // SAFETY: the process was just created, and only this test uses it.
    let mapped = unsafe { p.as_mut() }.map_frames(USER_VA, 3 * PAGE_SIZE, Attrs::USER_DATA);
    let result = match mapped {
        Ok(pa) => check_fresh_frames(pa, before).and_then(|()| check_thread_start(p)),
        Err(_) => Err("three pages did not map"),
    };
    // SAFETY: the process's threads went, the test's reference is the last,
    // and nothing uses it afterwards.
    unsafe { process::release(p) };
    result
}

/// Three pages take a zeroed block of four frames and three tables over it.
fn check_fresh_frames(pa: u64, before: u64) -> Result<(), &'static str> {
    check(
        phys::free_frames() == before - 7,
        "three pages did not take a block of four frames and three tables",
    )?;
    // SAFETY: the block belongs to the test's process, which nothing runs.
    let mem = unsafe { LinearMem::new() };
    check(
        (0..4 * PAGE_SIZE / 8).all(|i| mem.read(pa + i * 8) == 0),
        "the frames of a process are not zeroed",
    )
}

/// A new thread starts with the registers it was given and nothing else;
/// bad starts are refused.
fn check_thread_start(p: core::ptr::NonNull<process::Process>) -> Result<(), &'static str> {
    let stack = USER_VA + 3 * PAGE;
    let t = thread::create(p, USER_VA, stack, 7, 10, Policy::Fifo).map_err(|_| "no thread")?;
    // SAFETY: the thread was just created, and only this test uses it.
    let started = unsafe { t.as_ref() };
    let regs: &UserRegs = &started.regs;
    let result = check(
        regs.x[0] == 7
            && regs.x[1..].iter().all(|&x| x == 0)
            && regs.sp == stack as u64
            && regs.elr == USER_VA as u64
            && regs.spsr == SPSR_EL0T
            && regs.tpidr == 0
            && regs.tpidrro == 0
            && started.fp.v.iter().all(|&v| v == 0)
            && started.fp.fpcr == 0
            && started.fp.fpsr == 0
            && started.base_priority == 10
            && started.sched.priority() == 10
            && started.sched.policy() == Policy::Fifo
            && started.sched.state() == State::Stopped
            && started.process() == p,
        "a new thread does not start as it was told",
    );
    // SAFETY: the thread is not running, and nothing uses it afterwards.
    unsafe { thread::release(t) };
    result?;
    for (entry, stack, priority) in [
        (USER_END, stack, 10),
        (USER_VA + 2, stack, 10),
        (USER_VA, stack - 8, 10),
        (USER_VA, stack, 0),
    ] {
        match thread::create(p, entry, stack, 0, priority, Policy::RoundRobin) {
            Err(Error::InvalidArgs) => {}
            Ok(t) => {
                // SAFETY: the thread never ran, and nothing uses it afterwards.
                unsafe { thread::release(t) };
                return Err("a thread with a bad start was created");
            }
            Err(_) => return Err("a bad start failed with another error"),
        }
    }
    Ok(())
}

/// The icount build runs under `-icount shift=4` (xtask, qemu::ICOUNT):
/// one instruction per tick of the 62.5 MHz counter. 10 000 turns of a
/// two-instruction loop then take 20 000 ticks and a few more.
#[cfg(feature = "icount")]
fn virtual_time_counts_instructions() -> Result<(), &'static str> {
    let (start, end): (u64, u64);
    // SAFETY: a counted loop between two counter reads; no memory access.
    unsafe {
        core::arch::asm!(
            "isb",
            "mrs {start}, cntvct_el0",
            "mov {n}, #10000",
            "1: subs {n}, {n}, #1",
            "b.ne 1b",
            "isb",
            "mrs {end}, cntvct_el0",
            start = out(reg) start,
            end = out(reg) end,
            n = out(reg) _,
            options(nomem, nostack),
        )
    };
    check(
        (20_000..=20_100).contains(&(end - start)),
        "the run is not under -icount: the counter does not count instructions",
    )
}
