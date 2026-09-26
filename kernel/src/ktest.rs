// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! In-kernel tests for `cargo xtask test`. Each test prints one line in the
//! format xtask parses; the run ends with a semihosting exit code. The tests
//! at EL0 (`el0`) come last, as a chain that never returns here.

pub mod calls;
pub mod el0;
mod registers;

use crate::arch::symbols;
use crate::arch::user::UserRegs;
use crate::arch::{self, gic, semihosting, timer};
use crate::boot::Boot;
use crate::channel;
use crate::cleanup;
use crate::memory;
use crate::mm::aspace::{self, AddressSpace};
use crate::mm::pages::{self, KernelPages};
use crate::mm::phys;
use crate::mm::phys::LinearMem;
use crate::object::Object;
use crate::process::Stage;
use crate::{process, sched, session, thread, timer as timers};
use abi::{Access, Error, Policy, ProcessState, Rights};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use kcore::PAGE_SIZE;
use kcore::bootinfo::PsciConduit;
use kcore::frames::{MAX_ORDER, PhysMem};
use kcore::gic::{Ack, DEFAULT_PRIORITY};
use kcore::handles::{CHUNK, MAX_HANDLES};
use kcore::layout::{
    GIB, KERNEL_STACK_SIZE, KERNEL_VIRT, LINEAR_BASE, USER_END, frame_fits, image_pa,
};
use kcore::memmap;
use kcore::paging::{
    Attrs, MAIR_DEVICE, NG, PXN, PageTable, TTBR_ROOT_MASK, TableMemory, UXN, attr_index,
};
use kcore::quota::Account;
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
        "pool_churn_stays_under_the_quota",
        pool_churn_stays_under_the_quota,
    ),
    ("shell_goes_in_portions", shell_goes_in_portions),
    (
        "paid_charge_always_finds_a_frame",
        paid_charge_always_finds_a_frame,
    ),
    (
        "processes_and_threads_return_their_memory",
        processes_and_threads_return_their_memory,
    ),
    (
        "last_reference_only_queues_the_object",
        last_reference_only_queues_the_object,
    ),
    (
        "teardown_resumes_where_it_stopped",
        teardown_resumes_where_it_stopped,
    ),
    (
        "buffers_stage_counts_the_handles",
        buffers_stage_counts_the_handles,
    ),
    (
        "thread_portion_lets_its_handles_go",
        thread_portion_lets_its_handles_go,
    ),
    (
        "parent_quota_stage_sees_children_done",
        parent_quota_stage_sees_children_done,
    ),
    (
        "stop_wave_runs_at_the_ceiling",
        stop_wave_runs_at_the_ceiling,
    ),
    ("hasten_reaches_the_children", hasten_reaches_the_children),
    (
        "stop_cursor_skips_a_child_that_left",
        stop_cursor_skips_a_child_that_left,
    ),
    (
        "children_do_not_keep_their_parent_alive",
        children_do_not_keep_their_parent_alive,
    ),
    (
        "child_quota_comes_back_in_two_parts",
        child_quota_comes_back_in_two_parts,
    ),
    (
        "object_info_reports_what_the_kernel_counts",
        calls::object_info_reports_what_the_kernel_counts,
    ),
    (
        "closing_a_handle_releases_its_object",
        calls::closing_a_handle_releases_its_object,
    ),
    (
        "stopped_thread_takes_its_new_priority",
        calls::stopped_thread_takes_its_new_priority,
    ),
    (
        "process_create_checks_the_callers_limits",
        calls::process_create_checks_the_callers_limits,
    ),
    (
        "entry_0_of_a_child_stays_bad",
        calls::entry_0_of_a_child_stays_bad,
    ),
    (
        "table_chunks_are_paid_by_the_owner",
        calls::table_chunks_are_paid_by_the_owner,
    ),
    (
        "child_shell_is_paid_by_the_parent",
        calls::child_shell_is_paid_by_the_parent,
    ),
    (
        "thread_create_checks_the_callers_limits",
        calls::thread_create_checks_the_callers_limits,
    ),
    (
        "buffer_that_does_not_map_goes_back",
        calls::buffer_that_does_not_map_goes_back,
    ),
    (
        "process_kill_ends_threads_in_every_state",
        calls::process_kill_ends_threads_in_every_state,
    ),
    (
        "kill_hastens_a_dying_process",
        calls::kill_hastens_a_dying_process,
    ),
    (
        "channel_create_checks_the_callers_limits",
        calls::channel_create_checks_the_callers_limits,
    ),
    (
        "boost_is_capped_by_the_ceiling",
        calls::boost_is_capped_by_the_ceiling,
    ),
    (
        "handle_duplicate_checks_the_callers_limits",
        calls::handle_duplicate_checks_the_callers_limits,
    ),
    (
        "session_is_paid_by_the_caller",
        calls::session_is_paid_by_the_caller,
    ),
    (
        "sessions_of_a_closed_channel_go",
        calls::sessions_of_a_closed_channel_go,
    ),
    (
        "client_gone_when_the_holder_dies",
        calls::client_gone_when_the_holder_dies,
    ),
    (
        "teardown_level_is_at_least_the_notice",
        calls::teardown_level_is_at_least_the_notice,
    ),
    (
        "exit_notice_keeps_the_shell",
        calls::exit_notice_keeps_the_shell,
    ),
    (
        "notices_to_a_dying_parent_go_with_its_channel",
        calls::notices_to_a_dying_parent_go_with_its_channel,
    ),
    (
        "timer_create_checks_the_callers_limits",
        calls::timer_create_checks_the_callers_limits,
    ),
    (
        "timer_set_rounds_the_deadline_up",
        calls::timer_set_rounds_the_deadline_up,
    ),
    (
        "past_deadline_fires_within_timer_set",
        calls::past_deadline_fires_within_timer_set,
    ),
    (
        "dying_timer_does_not_fire",
        calls::dying_timer_does_not_fire,
    ),
    (
        "call_counter_runs_out_as_bad_state",
        calls::call_counter_runs_out_as_bad_state,
    ),
    (
        "thread_limit_of_the_system",
        calls::thread_limit_of_the_system,
    ),
    ("thread_numbers_come_back", calls::thread_numbers_come_back),
    (
        "object_pays_its_budget_back_to_the_payer",
        calls::object_pays_its_budget_back_to_the_payer,
    ),
    (
        "mem_create_over_the_quota_is_no_memory",
        calls::mem_create_over_the_quota_is_no_memory,
    ),
    ("new_object_is_zeroed", calls::new_object_is_zeroed),
    (
        "create_resumes_where_it_stopped",
        calls::create_resumes_where_it_stopped,
    ),
    (
        "killed_creator_lets_the_object_go",
        calls::killed_creator_lets_the_object_go,
    ),
    (
        "full_table_at_the_end_lets_the_object_go",
        calls::full_table_at_the_end_lets_the_object_go,
    ),
    (
        "another_call_gives_the_long_call_up",
        calls::another_call_gives_the_long_call_up,
    ),
    (
        "map_that_does_not_fit_maps_nothing",
        calls::map_that_does_not_fit_maps_nothing,
    ),
    ("prepaid_tables_come_back", calls::prepaid_tables_come_back),
    (
        "mapping_tables_are_paid_by_the_target",
        calls::mapping_tables_are_paid_by_the_target,
    ),
    (
        "abandoned_map_keeps_its_prefix",
        calls::abandoned_map_keeps_its_prefix,
    ),
    (
        "abandoned_unmap_keeps_the_rest",
        calls::abandoned_unmap_keeps_the_rest,
    ),
    (
        "abandoned_protect_goes_idle",
        calls::abandoned_protect_goes_idle,
    ),
    (
        "dying_target_ends_the_map",
        calls::dying_target_ends_the_map,
    ),
    (
        "exec_mapping_syncs_the_instruction_cache",
        calls::exec_mapping_syncs_the_instruction_cache,
    ),
    (
        "mappings_go_after_the_asid",
        calls::mappings_go_after_the_asid,
    ),
    (
        "unmapped_page_no_longer_translates",
        calls::unmapped_page_no_longer_translates,
    ),
    (
        "boot_image_frames_never_go",
        calls::boot_image_frames_never_go,
    ),
    (
        "init_load_maps_each_part_with_its_access",
        calls::init_load_maps_each_part_with_its_access,
    ),
];

/// Tests that failed so far, the EL0 tests' included.
static FAILED: AtomicU32 = AtomicU32::new(0);

/// The level of the cleanup the tests' own releases start: the tests run
/// the queue dry themselves (cleanup::drain), so any level will do.
pub const CAUSE: u8 = 1;

/// The quota of the tests' processes that have no parent: more than any
/// of them takes, a full table and a gigabyte of tables included.
pub const QUOTA: u64 = 16 << 20;
/// The quota of a child with a thread or two (spec 7.5).
pub const CHILD_QUOTA: u64 = 64 << 10;

/// Tests of the icount build besides TESTS and the EL0 tests: the first
/// checks that the run is under -icount, the second measures the portions
/// of the long calls of memory objects, whose counts mean instructions only
/// there (spec 15.3).
const ICOUNT_ONLY: usize = if cfg!(feature = "icount") { 2 } else { 0 };

pub fn run(boot: &Boot) -> ! {
    #[cfg(feature = "icount")]
    report(
        "virtual_time_counts_instructions",
        virtual_time_counts_instructions(),
    );
    for (name, test) in TESTS {
        report(name, test(boot));
    }
    #[cfg(feature = "icount")]
    report(
        "memory_portions_are_measured",
        calls::memory_portions_are_measured(boot),
    );
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
    let total = ICOUNT_ONLY + TESTS.len() + el0::count();
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

/// Immediate of the BRK marker that proves the exception return path.
const TEST_BRK: u16 = 0x51;

/// Immediate of the last BRK skipped in kernel code.
static LAST_BRK: AtomicU64 = AtomicU64::new(u64::MAX);

/// A BRK in kernel code (testpoint::skip_brk): the test marker is recorded
/// and stepped over; any other BRK stops the kernel, as in the build that
/// ships, since Rust lowers aborts and unreachable code to BRK.
pub fn brk(imm: u16) -> bool {
    if imm != TEST_BRK {
        return false;
    }
    LAST_BRK.store(u64::from(imm), Ordering::Relaxed);
    true
}

fn brk_is_caught_and_execution_resumes(_: &Boot) -> Result<(), &'static str> {
    LAST_BRK.store(u64::MAX, Ordering::Relaxed);
    // SAFETY: the exception handler records BRK and returns past it.
    unsafe { core::arch::asm!("brk #{imm}", imm = const TEST_BRK) };
    check(
        LAST_BRK.load(Ordering::Relaxed) == u64::from(TEST_BRK),
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
    let data = &LAST_BRK as *const _ as usize;
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
    // elsewhere a stall of the host could take longer.
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
/// an early return, and the quota its tables are charged to. Only `drop`
/// takes the space out.
struct TestSpace(Option<AddressSpace>, Account);

impl Drop for TestSpace {
    fn drop(&mut self) {
        if let Some(space) = self.0.take() {
            space.destroy(&mut self.1);
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
    let mut quota = Account::new(QUOTA);
    AddressSpace::new(&mut quota)
        .map(|space| TestSpace(Some(space), quota))
        .map_err(|_| "no frame for a root table")
}

fn map(space: &mut TestSpace, va: usize, pa: u64, attrs: Attrs) -> Result<(), &'static str> {
    let TestSpace(Some(tables), quota) = space else {
        return Err("a test space after its drop");
    };
    tables
        .map(va, pa, PAGE_SIZE, attrs, quota)
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
/// root included, each charged to the space's quota, and runs the space;
/// it is destroyed when this returns.
fn check_table_count(frame: u64, before: u64) -> Result<(), &'static str> {
    let mut space = new_space()?;
    for va in [0x1000, USER_VA, 1 << 30, 1 << 39, USER_END - PAGE] {
        map(&mut space, va, frame, Attrs::USER_RODATA)?;
    }
    check(
        phys::free_frames() == before - 14,
        "13 tables and a page did not come from the frame allocator",
    )?;
    check(
        space.1.used() == 13 * PAGE_SIZE,
        "the tables are not charged to the quota a page each",
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

/// A payer's pool pages stay its own (spec 7.8): a child with a quota of
/// eight pages fills its pool of threads until NO_MEMORY and lets every
/// thread go; the first block of its handle table then gets NO_MEMORY at
/// once, since the pages of the threads' pool keep its quota. Over the run
/// the pools take at most a page per page of the quota and one more, and
/// once the child goes the pages and the free frames are back. A first
/// child with nothing in it gives the root's pool of shells and its table
/// their pages.
fn pool_churn_stays_under_the_quota(_: &Boot) -> Result<(), &'static str> {
    const Q: u64 = 8 * PAGE_SIZE;
    cleanup::drain();
    let root = process::create_root(QUOTA, 16, 63).map_err(|_| "no process")?;
    let first = child_with(root, Q, 16, 63).and_then(|(_, h)| {
        process::close_handle(root, h, CAUSE).map_err(|_| "the child's handle did not close")
    });
    cleanup::drain();
    // A child whose quota does not add up would stop the kernel at its
    // stage Shell: on a failure the tree stays, and the failure is named.
    first.and_then(|()| churn(root, Q))?;
    // SAFETY: the test's reference goes, and nothing uses it afterwards.
    unsafe { process::release(root, CAUSE) };
    cleanup::drain();
    Ok(())
}

/// A child of `root` with quota `q` that only a handle in the root's table
/// holds fills its threads, lets them go and asks for a block of its
/// table; it is judged, then killed, and its handle closed. A child that
/// fails the judgement stays.
fn churn(root: NonNull<process::Process>, q: u64) -> Result<(), &'static str> {
    let (taken, frames) = (pages::taken(), phys::free_frames());
    let (child, held) = child_with(root, q, 16, 63)?;
    let mut threads = [None; abi::MAX_THREADS as usize];
    let mut last = Ok(());
    for slot in &mut threads {
        match thread::create(child, USER_VA, USER_VA, 0, 10, Policy::Fifo) {
            Ok(t) => *slot = Some(t),
            Err(e) => {
                last = Err(e);
                break;
            }
        }
    }
    for t in threads.into_iter().flatten() {
        // SAFETY: the test's reference goes; the thread never started.
        unsafe { thread::release(t, CAUSE) };
    }
    cleanup::drain();
    let grew = pages::taken() - taken;
    let block = process::insert_handle(child, Object::Resource, Rights::NONE);
    check(
        last == Err(Error::NoMemory),
        "the threads of the child did not end with NO_MEMORY",
    )?;
    check(
        block.is_err_and(|e| e == Error::NoMemory),
        "a block of the child's table found room in the quota its threads' pages hold",
    )?;
    check(
        grew as u64 <= q / PAGE_SIZE + 1,
        "the pools took more pages than the child's quota and one",
    )?;
    // SAFETY: the root's handle holds the child.
    unsafe { process::end(child, ProcessState::Killed, CAUSE) };
    process::close_handle(root, held, CAUSE).map_err(|_| "the child's handle did not close")?;
    cleanup::drain();
    check(
        pages::taken() == taken && phys::free_frames() == frames,
        "the pages of the child's pools or its frames did not come back",
    )
}

/// The pages of a process's pools go back with its shell, a portion at a
/// time (spec 7.7, 7.8): a root with 130 chunks of handles holds 66 pages
/// of blocks and a list page. Its handles go at the stage Handles and
/// leave the pages in the pool; the shell gives them back at most 32 a
/// portion, in three portions, and the last one gives the slot back.
fn shell_goes_in_portions(_: &Boot) -> Result<(), &'static str> {
    const CHUNKS: usize = 130;
    cleanup::drain();
    let processes = process::in_use();
    let p = process::create_root(QUOTA, (CHUNKS * CHUNK) as u32, 63).map_err(|_| "no process")?;
    let taken = pages::taken();
    let filled = (0..CHUNKS * CHUNK)
        .try_for_each(|_| process::insert_handle(p, Object::Resource, Rights::NONE).map(|_| ()));
    let held = pages::taken() - taken;
    // SAFETY: the test's reference, the last, goes; nothing uses it
    // afterwards.
    unsafe { process::release(p, CAUSE) };
    let mut portions = [0; 4];
    let mut n = 0;
    // Only the stage Shell gives pages of pools back.
    while cleanup::top().is_some() {
        let before = pages::taken();
        cleanup::portion();
        let back = before - pages::taken();
        if back > 0 && n < portions.len() {
            portions[n] = back;
            n += 1;
        }
    }
    filled.map_err(|_| "a handle did not go in")?;
    check(
        held == (CHUNKS + 1).div_ceil(2) + 1,
        "the blocks of the table did not take a page for two of them and a list page",
    )?;
    check(
        portions[..n] == [32, 32, held - 64],
        "the pages of a shell did not go back 32 a portion",
    )?;
    check(
        pages::taken() == taken && process::in_use() == processes,
        "the shell or pages of its pools stayed",
    )
}

/// A charge that passed always finds a frame (spec 7.8): with the free
/// frames cut down to what a root's quota leaves, the root and its three
/// children fill every kind they pay for by the page, one after another,
/// until their quotas run out: threads with their buffers and the tables
/// over them, handles, children with a page of quota, channels, and
/// sessions and timers of a channel. After every kind the free frames are
/// exactly the part of the quotas of the tree nobody used: no page was
/// taken without its charge, and none that passed its charge missed its
/// frame.
fn paid_charge_always_finds_a_frame(_: &Boot) -> Result<(), &'static str> {
    const PAGES: u64 = 160;
    cleanup::drain();
    let root =
        process::create_root(PAGES * PAGE_SIZE, MAX_HANDLES, 63).map_err(|_| "no process")?;
    let spare = PAGES - process::quota(root).used() / PAGE_SIZE;
    let held = hold_frames_but(spare);
    let result = fill_the_tree(root);
    give_frames_back(held);
    // SAFETY: the test's reference goes, and nothing uses it afterwards;
    // the root's threads would keep it alive, so it ends first.
    unsafe {
        process::end(root, ProcessState::Killed, CAUSE);
        process::release(root, CAUSE);
    }
    cleanup::drain();
    result
}

/// What a process pays for by the page, and fills in `fill_kind`.
#[derive(Clone, Copy)]
enum Kind {
    Threads,
    Handles,
    Children,
    Channels,
    Sessions,
    Timers,
}

const KINDS: [Kind; 6] = [
    Kind::Threads,
    Kind::Handles,
    Kind::Children,
    Kind::Channels,
    Kind::Sessions,
    Kind::Timers,
];

/// Three children of `root`, each filling the kinds in another order, and
/// then the root itself; the free frames are checked after each kind.
fn fill_the_tree(root: NonNull<process::Process>) -> Result<(), &'static str> {
    let mut tree = [Some(root), None, None, None];
    for i in 1..tree.len() {
        tree[i] = Some(child_with(root, 24 * PAGE_SIZE, MAX_HANDLES, 63)?.0);
        for k in 0..KINDS.len() {
            fill_kind(tree[i].expect("the child"), KINDS[(i + k) % KINDS.len()])?;
            frames_match_the_quotas(&tree)?;
        }
    }
    for kind in KINDS {
        fill_kind(root, kind)?;
        frames_match_the_quotas(&tree)?;
    }
    check(
        phys::free_frames() < 8 * tree.len() as u64,
        "the tree did not use up its quotas",
    )
}

/// Objects of `kind` for `p` until its quota runs out: the only error the
/// kind may end with is NO_MEMORY, but for threads past abi::MAX_THREADS,
/// sessions past the slots of their channel (abi::MAX_SLOTS) and timers
/// past abi::MAX_TIMERS. Handles in the table of `p` hold them; the
/// sessions and the timers are of one channel that `p` makes first.
fn fill_kind(p: NonNull<process::Process>, kind: Kind) -> Result<(), &'static str> {
    let buffers = USER_VA + 16 * PAGE;
    let mut target = None;
    for i in 0.. {
        let made = match kind {
            Kind::Handles => process::insert_handle(p, Object::Resource, Rights::NONE).map(|_| ()),
            Kind::Threads => {
                thread::create(p, USER_VA, USER_VA, 0, 10, Policy::Fifo).and_then(|t| {
                    let held = thread::give_buffer(t, buffers + i * PAGE)
                        .and_then(|()| process::insert_handle(p, Object::Thread(t), Rights::NONE));
                    // SAFETY: the test's reference goes; the handle, if it went
                    // in, holds the thread.
                    unsafe { thread::release(t, CAUSE) };
                    held.map(|_| ())
                })
            }
            Kind::Children => process::create_child(p, PAGE_SIZE, 16, 63).and_then(|c| {
                let held = process::insert_handle(p, Object::Process(c), Rights::NONE);
                // SAFETY: as above.
                unsafe { process::release(c, CAUSE) };
                held.map(|_| ())
            }),
            Kind::Channels => held_channel(p).map(drop),
            Kind::Sessions => match target {
                None => held_channel(p).map(|c| target = Some(c)),
                Some(c) => session::create(p, c, i as u64, 10).and_then(|s| {
                    let held = process::insert_handle(p, Object::Session(s), Rights::NONE);
                    // SAFETY: as above.
                    unsafe { session::unref(s, CAUSE) };
                    held.map(|_| ())
                }),
            },
            Kind::Timers => match target {
                None => held_channel(p).map(|c| target = Some(c)),
                Some(c) => timers::create(p, c, 0, 10).and_then(|t| {
                    let held = process::insert_handle(p, Object::Timer(t), Rights::NONE);
                    // SAFETY: as above.
                    unsafe { timers::release(t, CAUSE) };
                    held.map(|_| ())
                }),
            },
        };
        match made {
            Ok(()) => {}
            Err(Error::NoMemory) => break,
            Err(Error::LimitReached)
                if matches!(kind, Kind::Threads | Kind::Sessions | Kind::Timers) =>
            {
                break;
            }
            Err(_) => return Err("a kind ended with another error than NO_MEMORY"),
        }
    }
    cleanup::drain();
    Ok(())
}

/// A channel of `p`, which a handle of `p` with RECEIVE holds.
fn held_channel(p: NonNull<process::Process>) -> Result<NonNull<channel::Channel>, Error> {
    channel::create(p, 10).and_then(|c| {
        let held = process::insert_handle(p, Object::Channel(c), Rights::RECEIVE);
        // SAFETY: the test's reference goes; the handle, if it went in,
        // holds the channel.
        unsafe { channel::release(c, Rights::NONE, CAUSE) };
        held.map(|_| c)
    })
}

/// The free frames are the part of the quotas of `tree` that nobody used:
/// each process's grandchildren had a page of quota, which their root
/// tables took whole.
fn frames_match_the_quotas(tree: &[Option<NonNull<process::Process>>]) -> Result<(), &'static str> {
    let unused: u64 = tree
        .iter()
        .flatten()
        .map(|&p| process::quota(p))
        .map(|q| q.limit() - q.used())
        .sum();
    check(
        phys::free_frames() * PAGE_SIZE == unused,
        "the free frames are not the part of the quotas nobody used",
    )
}

/// Takes free frames, in the biggest blocks the allocator gives, until
/// only `left` are free; the blocks are linked through their first two
/// words (the next block and its order). Returns the first block.
fn hold_frames_but(left: u64) -> u64 {
    let mut guard = phys::FRAMES.lock();
    let frames = guard.as_mut().expect("frame allocator");
    // SAFETY: the blocks are the test's from their allocation to
    // `give_frames_back`.
    let mut mem = unsafe { LinearMem::new() };
    let mut first = u64::MAX;
    for order in (0..=MAX_ORDER).rev() {
        while frames.free_frames() >= left + (1 << order) {
            let Some(pa) = frames.alloc(order) else {
                break;
            };
            mem.write(pa, first);
            mem.write(pa + 8, u64::from(order));
            first = pa;
        }
    }
    first
}

/// Gives back the blocks `hold_frames_but` took.
fn give_frames_back(mut block: u64) {
    let mut guard = phys::FRAMES.lock();
    let frames = guard.as_mut().expect("frame allocator");
    // SAFETY: as in `hold_frames_but`.
    let mem = unsafe { LinearMem::new() };
    while block != u64::MAX {
        let (next, order) = (mem.read(block), mem.read(block + 8) as u8);
        frames.free(block, order);
        block = next;
    }
}

/// A process with a thread and a mapped memory object gives every frame
/// back when they go. The pools keep the page each takes for its first
/// object, so one round runs before the count.
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
    let p = process::create_root(QUOTA, 16, 63).map_err(|_| "no process")?;
    let before = (phys::free_frames(), process::quota(p).used());
    let result = match memory::create_whole(p, 3) {
        Ok(m) => {
            let mapped = process::map_whole(p, m, USER_VA, Access::ReadWrite);
            let checked = mapped
                .map_err(|_| "three pages did not map")
                .and_then(|()| check_fresh_frames(p, m, before));
            // SAFETY: the reference `create_whole` handed out goes; the
            // mapping, if it went in, holds the object.
            unsafe { memory::release(m, CAUSE) };
            checked.and_then(|()| check_thread_start(p))
        }
        Err(_) => Err("no memory object of three pages"),
    };
    // SAFETY: the process's threads went, the test's reference is the last,
    // and nothing uses it afterwards.
    unsafe { process::release(p, CAUSE) };
    cleanup::drain();
    result
}

/// A chain of processes, each holding the only handle to the next: the
/// last reference to the first only queues it, at the level of its cause.
/// Its portion of the stage Handles lets the next one's last reference go,
/// which queues the next at the same level and takes nothing apart inside
/// the portion (spec 7.7). Every later portion frees at most one process, and the
/// queue stays as short as it was: one teardown ends before the next
/// begins. A thread's portion lets the last reference to its process go
/// at the thread's level as well.
fn last_reference_only_queues_the_object(_: &Boot) -> Result<(), &'static str> {
    const CHAIN: usize = 16;
    const LEVEL: u8 = 7;
    cleanup::drain();
    let base = process::in_use();
    let first = process::create_root(QUOTA, 16, 63).map_err(|_| "no process")?;
    let mut last = first;
    for _ in 1..CHAIN {
        let Ok(next) = process::create_root(QUOTA, 16, 63) else {
            break;
        };
        let held = process::insert_handle(last, Object::Process(next), Rights::NONE);
        // SAFETY: the test's reference goes; the handle, if it went in,
        // holds the process.
        unsafe { process::release(next, CAUSE) };
        if held.is_err() {
            break;
        }
        last = next;
    }
    let whole = process::in_use() == base + CHAIN;
    // SAFETY: the test's reference is the last, and nothing uses it
    // afterwards.
    unsafe { process::release(first, LEVEL) };
    let result = check(whole, "the chain of processes was not built")
        .and_then(|()| portions_one_by_one(base, CHAIN, LEVEL))
        .and_then(|()| thread_portion_keeps_its_level(LEVEL));
    cleanup::drain();
    result
}

/// A thread holds the last reference to its process, and its own last
/// one goes at `level`: the thread's portion lets the process go at the
/// same level, which queues the process there.
fn thread_portion_keeps_its_level(level: u8) -> Result<(), &'static str> {
    let p = process::create_root(QUOTA, 16, 63).map_err(|_| "no process")?;
    let t = thread::create(p, USER_VA, USER_VA, 0, 10, Policy::Fifo);
    // SAFETY: the test's reference goes; the thread, if it was made,
    // holds the process.
    unsafe { process::release(p, CAUSE) };
    let t = t.map_err(|_| "no thread")?;
    let threads = thread::in_use();
    // SAFETY: the test's reference to the thread is its last, and nothing
    // uses it afterwards.
    unsafe { thread::release(t, level) };
    cleanup::portion();
    check(
        thread::in_use() + 1 == threads && (cleanup::len(), cleanup::top()) == (1, Some(level)),
        "a thread's portion did not queue its process at its own level",
    )
}

/// `chain` processes above `base` go in portions at `level`, the first
/// one only queueing the next.
fn portions_one_by_one(base: usize, chain: usize, level: u8) -> Result<(), &'static str> {
    check(
        process::in_use() == base + chain && (cleanup::len(), cleanup::top()) == (1, Some(level)),
        "the last reference did more than queue the process at the level of its cause",
    )?;
    // The stages Replies and Children, with no request and no child, then
    // the stage Handles.
    for _ in 0..3 {
        cleanup::portion();
    }
    check(
        process::in_use() == base + chain && (cleanup::len(), cleanup::top()) == (2, Some(level)),
        "a portion did not queue the next process at its own level",
    )?;
    // Each process takes a handful of portions: a guard against a loop.
    for _ in 0..16 * chain {
        let before = process::in_use();
        cleanup::portion();
        check(
            process::in_use() + 1 >= before,
            "a portion took more than one process apart",
        )?;
        check(
            cleanup::top().is_none_or(|l| l == level) && cleanup::len() <= 3,
            "a portion queued work at another level, or teardowns ran side by side",
        )?;
        if cleanup::top().is_none() {
            break;
        }
    }
    check(
        process::in_use() == base,
        "a process of the chain was not taken apart",
    )
}

/// A process ends and goes in stages, one step a portion, and each portion
/// goes on where the one before stopped (spec 7.7): with no request taken
/// and no children, the stages Replies and Children take a portion each;
/// the table a chunk a portion; the space first loses TTBR0 and its ASID,
/// and no call reaches its tables from then on, then a table a portion; the
/// buffers of the threads the end stopped in one portion, the process's
/// frames and the stage Quota in one more each. Then the shell stays for
/// the test's reference.
fn teardown_resumes_where_it_stopped(boot: &Boot) -> Result<(), &'static str> {
    const LEVEL: u8 = 9;
    cleanup::drain();
    let (processes, threads) = (process::in_use(), thread::in_use());
    let p = process::create_root(QUOTA, 3 * CHUNK as u32, 63).map_err(|_| "no process")?;
    let made = [0, 1].map(|_| thread::create(p, USER_VA, USER_VA, 0, 10, Policy::Fifo));
    let result = match made {
        [Ok(ready), Ok(stopped)] => fill_for_teardown(p, ready, stopped)
            .and_then(|()| check_stages(boot, p, [ready, stopped], LEVEL)),
        _ => Err("no thread"),
    };
    // SAFETY: the test's references go, and nothing uses them afterwards.
    unsafe {
        for t in made.into_iter().flatten() {
            sched::exit(t, CAUSE);
            thread::release(t, CAUSE);
        }
        process::release(p, CAUSE);
    }
    cleanup::drain();
    result?;
    check(
        process::in_use() == processes && thread::in_use() == threads,
        "the process or its threads stayed in their pools",
    )
}

/// Threads of `buffers_stage_counts_the_handles`.
const CARRIERS: usize = 16;

/// The stage Buffers counts the handles of the threads' requests as work
/// (spec 7.7): CARRIERS threads of a process that never ran, each with a
/// buffer and four handles on their way (Thread::transit), as a request
/// that waited in a queue leaves them. The first portion of the stage gives
/// 10 buffers back, whose units of six, a frame two and a handle one, fill
/// 60 of its 64, where the six of the next do not fit, and the second the
/// other 6; the handles go with them, and their channel then too.
fn buffers_stage_counts_the_handles(_: &Boot) -> Result<(), &'static str> {
    const LEVEL: u8 = 9;
    cleanup::drain();
    let (processes, threads, channels) = (process::in_use(), thread::in_use(), channel::in_use());
    let p = process::create_root(QUOTA, 16, 63).map_err(|_| "no process")?;
    let payer = process::create_root(QUOTA, 16, 63);
    let c = payer.map_err(|_| "no process").and_then(|payer| {
        let c = channel::create(payer, 10).map_err(|_| "no channel");
        // SAFETY: the test's reference goes; the channel holds the shell.
        unsafe { process::release(payer, CAUSE) };
        c
    });
    let mut carriers = [None; CARRIERS];
    let result = c
        .and_then(|c| give_carriers(p, c, &mut carriers))
        .and_then(|()| check_buffer_portions(p, LEVEL));
    // SAFETY: the test's references go, and nothing uses them afterwards.
    unsafe {
        if let Ok(c) = c {
            channel::release(c, Rights::NONE, CAUSE);
        }
        for t in carriers.into_iter().flatten() {
            sched::exit(t, CAUSE);
            thread::release(t, CAUSE);
        }
        process::release(p, CAUSE);
    }
    cleanup::drain();
    result?;
    check(
        (process::in_use(), thread::in_use(), channel::in_use()) == (processes, threads, channels),
        "the process, its threads or the channel of their handles stayed",
    )?;
    bare_buffers_take_two_units(LEVEL)
}

/// Threads with a buffer and no handle on their way, one more than a
/// portion of the stage Buffers takes: two units of work each.
const BARE: usize = BUFFERS_PER_PORTION + 1;
const BUFFERS_PER_PORTION: usize = 32;

/// The first portion of the stage Buffers of BARE threads with no handles
/// gives back BUFFERS_PER_PORTION buffers, a frame two units of its 64,
/// and the second the last one (spec 7.7).
fn bare_buffers_take_two_units(level: u8) -> Result<(), &'static str> {
    let (processes, threads) = (process::in_use(), thread::in_use());
    let p = process::create_root(QUOTA, 16, 63).map_err(|_| "no process")?;
    let mut bare = [None; BARE];
    let made = bare.iter_mut().enumerate().try_for_each(|(i, slot)| {
        let t =
            thread::create(p, USER_VA, USER_VA, 0, 10, Policy::Fifo).map_err(|_| "no thread")?;
        *slot = Some(t);
        thread::give_buffer(t, USER_VA + (i + 1) * PAGE).map_err(|_| "no buffer")
    });
    let result = made.and_then(|()| {
        // SAFETY: the test holds a reference to the process.
        unsafe { process::end(p, ProcessState::Killed, level) };
        for _ in 0..64 {
            if process::progress(p).0 == Stage::Buffers {
                break;
            }
            cleanup::portion();
        }
        let frames = phys::free_frames();
        cleanup::portion();
        let first = phys::free_frames() - frames;
        cleanup::portion();
        let second = phys::free_frames() - frames - first;
        check(
            first == BUFFERS_PER_PORTION as u64 && second == 1,
            "a portion of the stage Buffers did not give 32 buffers with no handles back",
        )
    });
    // SAFETY: the test's references go, and nothing uses them afterwards.
    unsafe {
        for t in bare.into_iter().flatten() {
            sched::exit(t, CAUSE);
            thread::release(t, CAUSE);
        }
        process::release(p, CAUSE);
    }
    cleanup::drain();
    result?;
    check(
        (process::in_use(), thread::in_use()) == (processes, threads),
        "the process or its threads stayed",
    )
}

/// A thread's own portion lets the handles on its way go (spec 6.1, 7.7):
/// CARRIERS threads of a live process that never ran, each with a buffer
/// and four handles to a channel on their way (Thread::transit), as a
/// request that waited in a queue leaves them. Once their last references
/// go, their portions give the buffers back and release the handles, and
/// the channel goes with them.
fn thread_portion_lets_its_handles_go(_: &Boot) -> Result<(), &'static str> {
    cleanup::drain();
    let (processes, threads, channels) = (process::in_use(), thread::in_use(), channel::in_use());
    let p = process::create_root(QUOTA, 16, 63).map_err(|_| "no process")?;
    let c = channel::create(p, 10).map_err(|_| "no channel");
    let mut carriers = [None; CARRIERS];
    let result = c.and_then(|c| give_carriers(p, c, &mut carriers));
    // SAFETY: the test's references go, and nothing uses them afterwards;
    // the threads never ran, so each goes with its own portion.
    unsafe {
        if let Ok(c) = c {
            channel::release(c, Rights::NONE, CAUSE);
        }
        for t in carriers.into_iter().flatten() {
            thread::release(t, CAUSE);
        }
    }
    cleanup::drain();
    let gone = (thread::in_use(), channel::in_use()) == (threads, channels);
    // SAFETY: as above.
    unsafe { process::release(p, CAUSE) };
    cleanup::drain();
    result?;
    check(
        gone && process::in_use() == processes,
        "the handles on their way stayed with the threads' portions",
    )
}

/// CARRIERS threads of `p` in `carriers`, each with a buffer and four
/// handles to `c` on their way.
fn give_carriers(
    p: NonNull<process::Process>,
    c: NonNull<channel::Channel>,
    carriers: &mut [Option<NonNull<thread::Thread>>; CARRIERS],
) -> Result<(), &'static str> {
    for (i, slot) in carriers.iter_mut().enumerate() {
        let t =
            thread::create(p, USER_VA, USER_VA, 0, 10, Policy::Fifo).map_err(|_| "no thread")?;
        *slot = Some(t);
        thread::give_buffer(t, USER_VA + (i + 1) * PAGE).map_err(|_| "no buffer")?;
        let mut values = [0; 4];
        for v in &mut values {
            *v = process::insert_handle(p, Object::Channel(c), Rights::NONE)
                .map_err(|_| "a handle did not go in")?
                .0;
        }
        // SAFETY: the thread never runs, and its handles on their way are
        // the test's to set.
        unsafe { thread::set_transit(t, process::take_handles(p, &values)) };
    }
    Ok(())
}

fn check_buffer_portions(p: NonNull<process::Process>, level: u8) -> Result<(), &'static str> {
    // SAFETY: the test holds a reference to the process.
    unsafe { process::end(p, ProcessState::Killed, level) };
    for _ in 0..64 {
        if process::progress(p).0 == Stage::Buffers {
            break;
        }
        cleanup::portion();
    }
    let frames = phys::free_frames();
    cleanup::portion();
    check(
        process::progress(p).0 == Stage::Buffers && phys::free_frames() == frames + 10,
        "the first portion of the stage Buffers did not stop at 10 buffers",
    )?;
    cleanup::portion();
    check(
        process::progress(p).0 == Stage::Mappings && phys::free_frames() == frames + 16,
        "the second portion of the stage Buffers did not give the other 6 back",
    )
}

/// Three full chunks of handles; a page of a memory object in each of two
/// gigabytes of the space, so that six tables map them; buffers for both
/// threads, one of which is ready; and the space in TTBR0 with an ASID.
fn fill_for_teardown(
    mut p: NonNull<process::Process>,
    ready: NonNull<thread::Thread>,
    stopped: NonNull<thread::Thread>,
) -> Result<(), &'static str> {
    for _ in 0..3 * CHUNK {
        process::insert_handle(p, Object::Resource, Rights::NONE)
            .map_err(|_| "a handle did not go in")?;
    }
    for va in [USER_VA, USER_VA + GIB as usize] {
        let m = memory::create_whole(p, 1).map_err(|_| "no memory object")?;
        let mapped = process::map_whole(p, m, va, Access::ReadWrite);
        // SAFETY: the reference `create_whole` handed out goes; the
        // mapping, if it went in, holds the object.
        unsafe { memory::release(m, CAUSE) };
        mapped.map_err(|_| "a page did not map")?;
    }
    for (t, page) in [(ready, 2), (stopped, 3)] {
        thread::give_buffer(t, USER_VA + page * PAGE).map_err(|_| "no buffer")?;
    }
    thread::start(ready).map_err(|_| "the thread did not start")?;
    // SAFETY: as above.
    unsafe { p.as_mut() }.activate();
    Ok(())
}

fn check_stages(
    boot: &Boot,
    p: NonNull<process::Process>,
    threads: [NonNull<thread::Thread>; 2],
    level: u8,
) -> Result<(), &'static str> {
    let frames = phys::free_frames();
    // SAFETY: the test holds a reference to the process.
    unsafe { process::end(p, ProcessState::Killed, level) };
    // SAFETY: the test holds references to the threads.
    let dead = threads.map(|t| unsafe { t.as_ref() }.sched.state() == State::Dead);
    check(
        dead == [true, true] && sched::first(10).is_none(),
        "the end did not stop the threads in the call",
    )?;
    check(
        (cleanup::len(), cleanup::top()) == (1, Some(level))
            && process::progress(p) == (Stage::Replies, 3 * CHUNK as u32, 0),
        "the end did more than queue the process",
    )?;
    cleanup::portion();
    check(
        process::progress(p) == (Stage::Children, 3 * CHUNK as u32, 0),
        "the stage Replies of a process that took no request took more than a portion",
    )?;
    cleanup::portion();
    check(
        process::progress(p) == (Stage::Handles, 3 * CHUNK as u32, 0),
        "the stage Children of a process with no child took more than a portion",
    )?;
    for left in [2, 1, 0] {
        cleanup::portion();
        let stage = if left > 0 {
            Stage::Handles
        } else {
            Stage::Space
        };
        check(
            process::progress(p) == (stage, left * CHUNK as u32, 0) && cleanup::len() == 1,
            "a portion of the stage Handles did not take one chunk",
        )?;
    }
    cleanup::portion();
    let empty = image_pa(boot.kernel_pa, symbols::empty_table());
    check(
        registers::ttbr0_el1() == empty && phys::free_frames() == frames,
        "the stage Space did not begin with TTBR0 and the ASID alone",
    )?;
    // The space is the stage's now: no call reaches its tables.
    check(
        process::translate(p, USER_VA).is_none()
            && process::map_page(p, USER_VA + 4 * PAGE, 0, Attrs::USER_DATA)
                == Err(Error::BadState),
        "the tables of the space are reachable at the stage Space",
    )?;
    check_space_steps(p, frames)?;
    cleanup::portion();
    check(
        process::progress(p).0 == Stage::Mappings && phys::free_frames() == frames + 6 + 2,
        "the stage Buffers did not give the buffers back in one portion",
    )?;
    cleanup::portion();
    check(
        process::progress(p).0 == Stage::Quota
            && cleanup::len() == 3
            && phys::free_frames() == frames + 6 + 2,
        "the stage Mappings did not let the two objects go in one portion",
    )?;
    cleanup::portion();
    check(
        process::progress(p).0 == Stage::Notify && cleanup::len() == 3,
        "the stage Quota took more than a portion",
    )?;
    cleanup::portion();
    check(
        process::progress(p).0 == Stage::Shell && cleanup::len() == 2,
        "the stage Notify took more than a portion, or the shell was queued",
    )?;
    cleanup::drain();
    check(
        phys::free_frames() == frames + 6 + 2 + 2,
        "the objects of the mappings did not give their frames back",
    )
}

/// The end of a process ends its descendants, which go depth first
/// (spec 4, 7.7): two children, one with a child of its own whose thread
/// is ready, each child and grandchild held only by a handle in its
/// parent's table. Each process passes its stage Quota only after its
/// children passed theirs, the ready thread leaves the scheduler, and the
/// tree goes; the levels of the stages are `stop_wave_runs_at_the_ceiling`'s.
fn parent_quota_stage_sees_children_done(_: &Boot) -> Result<(), &'static str> {
    const LEVEL: u8 = 12;
    cleanup::drain();
    process::take_early_quota();
    let (processes, threads) = (process::in_use(), thread::in_use());
    let root = process::create_root(QUOTA, 16, 63).map_err(|_| "no process")?;
    let built = child_of(root, 4 * CHILD_QUOTA).and_then(|a| {
        child_of(root, CHILD_QUOTA)?;
        let grandchild = child_of(a, CHILD_QUOTA)?;
        ready_thread(grandchild)
    });
    let result = built.and_then(|t| check_tree_end(root, t, LEVEL));
    if result == Err(STUCK) {
        // A drain would never end: the failure is named instead, and the
        // tree stays in the pools.
        return result;
    }
    // SAFETY: the test's reference goes, and nothing uses it afterwards.
    unsafe { process::release(root, CAUSE) };
    cleanup::drain();
    result?;
    check(
        process::in_use() == processes && thread::in_use() == threads,
        "a process or a thread of the tree stayed in its pool",
    )
}

/// The end of a process stops its descendants in a wave above the level of
/// the cause (spec 4, 7.7): a root with ceiling 40 ends at 12 with two
/// children, one with ceiling 30 and a child of its own, and a ready
/// thread in each process. The stage Stop takes a portion for each process
/// it ends, at the ceiling of the process that ends it: the root's at 40,
/// its child's at 30. Once it is over, no process of the tree lives and
/// every thread of it is dead; the rest of the teardown runs at 12. A
/// second such tree ends at 50, above every ceiling in it: its stage Stop
/// runs at 50, as the rest of its teardown does.
fn stop_wave_runs_at_the_ceiling(_: &Boot) -> Result<(), &'static str> {
    cleanup::drain();
    let (processes, threads) = (process::in_use(), thread::in_use());
    for (level, stops) in [(12, [40, 40, 30]), (50, [50, 50, 50])] {
        let root = process::create_root(QUOTA, 16, 40).map_err(|_| "no process")?;
        let tree = child_with(root, 4 * CHILD_QUOTA, 16, 30).and_then(|(a, _)| {
            let (b, _) = child_with(root, CHILD_QUOTA, 16, 40)?;
            let (g, _) = child_with(a, CHILD_QUOTA, 16, 30)?;
            let mut t = [None; 4];
            for (slot, p) in t.iter_mut().zip([root, a, b, g]) {
                *slot = Some((p, ready_thread(p)?));
            }
            Ok(t.map(|x| x.expect("a process and its thread")))
        });
        let tree = tree.inspect_err(|_| {
            // SAFETY: the test's reference goes, and nothing uses it
            // afterwards.
            unsafe { process::release(root, CAUSE) };
            cleanup::drain();
        })?;
        // A teardown at the wrong levels may never end: a failure is named,
        // and the tree stays in the pools, as in
        // `parent_quota_stage_sees_children_done`.
        check_waves(tree, level, stops)?;
        // SAFETY: the test's reference goes, and nothing uses it afterwards.
        unsafe { process::release(root, CAUSE) };
        cleanup::drain();
    }
    check(
        process::in_use() == processes && thread::in_use() == threads,
        "a process or a thread of the tree stayed in its pool",
    )
}

/// Ends the first process of `tree` at `level` and follows the portions:
/// three of the stage Stop at `stops`, then the teardown at `level`. When
/// the stops are above `level`, no process of the tree lives and every
/// thread of it is dead after them.
fn check_waves(
    tree: [(NonNull<process::Process>, NonNull<thread::Thread>); 4],
    level: u8,
    stops: [u8; 3],
) -> Result<(), &'static str> {
    // SAFETY: the test holds a reference to the root.
    unsafe { process::end(tree[0].0, ProcessState::Killed, level) };
    let mut levels = [0; 3];
    for l in &mut levels {
        *l = cleanup::top().unwrap_or(0);
        cleanup::portion();
    }
    check(
        levels == stops,
        "the stage Stop did not take a portion for each process it ended at the greater of the cause and the ceiling of the one that ended it",
    )?;
    // Above the cause, the wave is over before the rest of the teardown
    // runs; at the cause, the stages of the tree take turns.
    let stopped = tree.iter().all(|&(p, t)| {
        // SAFETY: handles in the tree hold the processes and the threads.
        process::progress(p).0 != Stage::Whole && unsafe { t.as_ref() }.sched.state() == State::Dead
    });
    check(
        stopped || stops.iter().any(|&s| s <= level),
        "a process of the tree lives, or a thread of it did not stop, after the stage Stop",
    )?;
    for _ in 0..256 {
        let Some(top) = cleanup::top() else {
            return Ok(());
        };
        check(
            top == level,
            "the teardown after the stage Stop ran at another level than its cause",
        )?;
        cleanup::portion();
    }
    Err(STUCK)
}

/// process_kill of a process that ended hastens its descendants too
/// (spec 7.7): a root with ceiling 10 ends at 2, its stage Stop ends its
/// child at 2, and the raise to 20 takes the whole tree above 20. A stage
/// Children that raised the child without its level would find it below
/// again at each portion, and the teardown would not end.
fn hasten_reaches_the_children(_: &Boot) -> Result<(), &'static str> {
    cleanup::drain();
    let processes = process::in_use();
    let root = process::create_root(QUOTA, 16, 10).map_err(|_| "no process")?;
    let result = child_with(root, CHILD_QUOTA, 16, 10).and_then(|_| {
        // SAFETY: the test holds a reference to the root.
        unsafe { process::end(root, ProcessState::Killed, 2) };
        while cleanup::top().is_some_and(|l| l > 2) {
            cleanup::portion();
        }
        // SAFETY: as above; no portion runs.
        unsafe { process::hasten(root, 20) };
        for _ in 0..256 {
            if !cleanup::top().is_some_and(|l| l >= 20) {
                return check(
                    process::progress(root).0 == Stage::Shell && cleanup::len() == 0,
                    "the tree's teardown did not end above the level of the kill",
                );
            }
            cleanup::portion();
        }
        Err(STUCK)
    });
    if result == Err(STUCK) {
        // As in `parent_quota_stage_sees_children_done`.
        return result;
    }
    // SAFETY: the test's reference goes, and nothing uses it afterwards.
    unsafe { process::release(root, CAUSE) };
    cleanup::drain();
    result?;
    check(
        process::in_use() == processes,
        "a process of the tree stayed in its pool",
    )
}

/// The cursor of the stage Stop moves past a child that leaves the list
/// (spec 7.7): a root at ceiling 40 with three children ends at 12, and
/// its first portion of the stage Stop ends its newest child. The middle
/// one, which only the test's reference holds, ends then at 50, above the
/// wave; its whole teardown, the stage Quota and its shell included, runs
/// before the root's next portion, and that portion ends the oldest child.
/// A cursor left on the middle child would reach its poisoned shell.
fn stop_cursor_skips_a_child_that_left(_: &Boot) -> Result<(), &'static str> {
    const LEVEL: u8 = 12;
    cleanup::drain();
    let (processes, threads) = (process::in_use(), thread::in_use());
    let root = process::create_root(QUOTA, 16, 40).map_err(|_| "no process")?;
    let made = [0, 1, 2].map(|_| process::create_child(root, CHILD_QUOTA, 16, 40));
    let result = match made {
        [Ok(oldest), Ok(middle), Ok(newest)] => {
            let result = check_cursor(root, [oldest, middle, newest], LEVEL);
            for p in [oldest, newest] {
                // SAFETY: the test's references go, and nothing uses them
                // afterwards; the middle one went inside the check.
                unsafe { process::release(p, CAUSE) };
            }
            result
        }
        _ => Err("no child"),
    };
    // SAFETY: as above.
    unsafe { process::release(root, CAUSE) };
    cleanup::drain();
    result?;
    check(
        process::in_use() == processes && thread::in_use() == threads,
        "a process of the test stayed in its pool",
    )
}

fn check_cursor(
    root: NonNull<process::Process>,
    [oldest, middle, newest]: [NonNull<process::Process>; 3],
    level: u8,
) -> Result<(), &'static str> {
    let live = |p: NonNull<process::Process>| {
        // SAFETY: the test holds a reference to the process.
        unsafe { p.as_ref() }.state() == ProcessState::Alive
    };
    // SAFETY: the test holds a reference to the root.
    unsafe { process::end(root, ProcessState::Killed, level) };
    cleanup::portion();
    check(
        !live(newest) && live(middle) && live(oldest),
        "the first portion of the stage Stop did not end the newest child alone",
    )?;
    let processes = process::in_use();
    // SAFETY: the test's reference, the middle child's last, goes: the
    // child ends, killed, at 50.
    unsafe { process::release(middle, 50) };
    while cleanup::top() == Some(50) {
        cleanup::portion();
    }
    check(
        process::in_use() + 1 == processes,
        "the middle child did not go before the next portion of its parent",
    )?;
    check(
        cleanup::top() == Some(40),
        "the stage Stop of the root is not next",
    )?;
    cleanup::portion();
    check(
        !live(oldest),
        "the stage Stop did not go on to the next child",
    )
}

/// A parent holds handles to its child, which holds its parent's shell,
/// and the child holds one to a grandchild: the last reference to the
/// parent ends it all the same (spec 4, 7.5), since a child's reference
/// keeps the shell and never the process, and the whole tree goes.
fn children_do_not_keep_their_parent_alive(_: &Boot) -> Result<(), &'static str> {
    cleanup::drain();
    let (processes, threads) = (process::in_use(), thread::in_use());
    let root = process::create_root(QUOTA, 16, 63).map_err(|_| "no process")?;
    let built = child_of(root, 4 * CHILD_QUOTA).and_then(|child| child_of(child, CHILD_QUOTA));
    // SAFETY: the test's reference, the root's last, goes, and nothing
    // uses it afterwards.
    unsafe { process::release(root, CAUSE) };
    cleanup::drain();
    built?;
    check(
        process::in_use() == processes && thread::in_use() == threads,
        "the children kept their parent alive, and the tree stayed",
    )
}

/// A child of `parent` with `quota` that only a handle in `parent`'s table
/// holds.
fn child_of(
    parent: NonNull<process::Process>,
    quota: u64,
) -> Result<NonNull<process::Process>, &'static str> {
    child_with(parent, quota, 16, 63).map(|(child, _)| child)
}

/// A child of `parent` with `quota`, room for `limit` handles and priority
/// ceiling `ceiling` that only the handle returned, in `parent`'s table,
/// holds.
fn child_with(
    parent: NonNull<process::Process>,
    quota: u64,
    limit: u32,
    ceiling: u8,
) -> Result<(NonNull<process::Process>, abi::Handle), &'static str> {
    let child = process::create_child(parent, quota, limit, ceiling).map_err(|_| "no child")?;
    let held = process::insert_handle(parent, Object::Process(child), Rights::NONE);
    // SAFETY: the test's reference goes; the handle, if it went in, holds
    // the child.
    unsafe { process::release(child, CAUSE) };
    held.map(|h| (child, h))
        .map_err(|_| "a handle did not go in")
}

/// A ready thread of `p` that only a handle in `p`'s table and the
/// scheduler hold.
fn ready_thread(p: NonNull<process::Process>) -> Result<NonNull<thread::Thread>, &'static str> {
    let t = thread::create(p, USER_VA, USER_VA, 0, 10, Policy::Fifo).map_err(|_| "no thread")?;
    let held = process::insert_handle(p, Object::Thread(t), Rights::NONE)
        .map_err(|_| "a handle did not go in")
        .and_then(|_| thread::start(t).map_err(|_| "the thread did not start"));
    // SAFETY: the test's reference goes; the handle, if it went in, holds
    // the thread.
    unsafe { thread::release(t, CAUSE) };
    held.map(|()| t)
}

/// A child's quota comes back to its parent in two parts that add up to
/// it (spec 7.5). The end of the child gives back at its stage Quota
/// everything but the page of its pool of threads, where the shell of its
/// thread, which a handle in the parent's table keeps, lies; its own shell
/// is in the parent's pool (spec 7.8). The thread's shell going back
/// refunds nothing; the rest comes back when the child's shell goes, with
/// the page.
fn child_quota_comes_back_in_two_parts(_: &Boot) -> Result<(), &'static str> {
    const LEVEL: u8 = 11;
    cleanup::drain();
    let (processes, threads) = (process::in_use(), thread::in_use());
    let root = process::create_root(QUOTA, 16, 63).map_err(|_| "no process")?;
    let result = child_of(root, CHILD_QUOTA).and_then(|child| {
        let t = thread::create(child, USER_VA, USER_VA, 0, 10, Policy::Fifo)
            .map_err(|_| "no thread")?;
        let held = process::insert_handle(root, Object::Thread(t), Rights::NONE);
        // SAFETY: the test's reference goes; the handle, if it went in,
        // holds the thread.
        unsafe { thread::release(t, CAUSE) };
        let held = held.map_err(|_| "a handle did not go in")?;
        check_two_parts(root, child, held, LEVEL)
    });
    // SAFETY: the test's reference goes, and nothing uses it afterwards.
    unsafe { process::release(root, CAUSE) };
    cleanup::drain();
    result?;
    check(
        process::in_use() == processes && thread::in_use() == threads,
        "the child or its thread stayed in its pool",
    )
}

/// Ends `child`, which only the root's handles hold, together with its
/// thread's shell, `held`, and follows the root's quota as the two parts
/// come back.
fn check_two_parts(
    root: NonNull<process::Process>,
    child: NonNull<process::Process>,
    held: abi::Handle,
    level: u8,
) -> Result<(), &'static str> {
    let before = process::quota(root).used();
    // SAFETY: the root's handle holds the child.
    unsafe { process::end(child, ProcessState::Killed, level) };
    cleanup::drain();
    let q = process::quota(child);
    let rest = PAGE_SIZE;
    check(
        q.limit() == CHILD_QUOTA && q.used() == rest && q.returned() == CHILD_QUOTA - rest,
        "the stage Quota did not give back all but the page of the child's threads",
    )?;
    check(
        process::quota(root).used() == before - q.returned(),
        "the parent did not get the free part at the child's stage Quota",
    )?;
    process::close_handle(root, held, CAUSE).map_err(|_| "the thread's handle did not close")?;
    cleanup::drain();
    check(
        process::quota(child).used() == rest
            && process::quota(root).used() == before - q.returned(),
        "the thread's shell refunded its slot, or went back to the parent",
    )?;
    // The root's handle to the child is the first handle of its table.
    let first = abi::Handle::new(0, 1);
    process::close_handle(root, first, CAUSE).map_err(|_| "the child's handle did not close")?;
    cleanup::drain();
    check(
        process::quota(root).used() == before - CHILD_QUOTA,
        "the rest of the child's quota did not come back with its shell",
    )
}

/// What `check_tree_end` says when the queue still holds work after its
/// portions: an object that goes back in front of the one it waits for.
const STUCK: &str = "the tree's teardown made no progress";

/// Ends `root` and runs the queue a portion at a time: the whole tree goes
/// in a bounded number of portions, the grandchild's thread leaves the
/// scheduler, and no process comes to its stage Quota before its
/// children.
fn check_tree_end(
    root: NonNull<process::Process>,
    t: NonNull<thread::Thread>,
    level: u8,
) -> Result<(), &'static str> {
    // SAFETY: the test holds a reference to the root.
    unsafe { process::end(root, ProcessState::Killed, level) };
    for _ in 0..256 {
        if cleanup::top().is_none() {
            break;
        }
        cleanup::portion();
    }
    let ready = sched::first(10) == Some(t);
    if ready {
        // A thread left ready would run in the tests at EL0.
        // SAFETY: a ready thread is alive; the scheduler's reference goes.
        unsafe { sched::exit(t, CAUSE) };
    }
    check(cleanup::top().is_none(), STUCK)?;
    check(!ready, "the grandchild's thread is still ready")?;
    check(
        process::take_early_quota() == 0,
        "a process came to its stage Quota before its children passed theirs",
    )
}

/// The stage Space frees a table a portion, at most, and keeps count; the
/// six tables go, the root last.
fn check_space_steps(p: NonNull<process::Process>, frames: u64) -> Result<(), &'static str> {
    for _ in 0..16 {
        let before = phys::free_frames();
        cleanup::portion();
        let (stage, _, tables) = process::progress(p);
        check(
            phys::free_frames() <= before + 1,
            "a portion of the stage Space freed more than one table",
        )?;
        if stage != Stage::Space {
            return check(
                stage == Stage::Buffers && phys::free_frames() == frames + 6,
                "the stage Space ended before its six tables went",
            );
        }
        check(
            tables as u64 == phys::free_frames() - frames,
            "the space does not count the tables it freed",
        )?;
    }
    Err("the stage Space did not end")
}

/// Three pages of a memory object mapped into the process translate to
/// the object's zeroed frames, and every frame the object and the mapping
/// took, three pages, the node of their list, three tables and the pages
/// of the pools, is charged to the process (spec 7.5).
fn check_fresh_frames(
    p: NonNull<process::Process>,
    m: NonNull<crate::memory::Memory>,
    (frames, used): (u64, u64),
) -> Result<(), &'static str> {
    let taken = frames - phys::free_frames();
    check(
        taken >= 3 + 1 + 3 && process::quota(p).used() == used + taken * PAGE_SIZE,
        "the object, its mapping and their tables were not charged to the process",
    )?;
    // SAFETY: the frames belong to the test's object, which nothing runs.
    let mem = unsafe { LinearMem::new() };
    for i in 0..3 {
        let pa = memory::frame(m, i);
        check(
            process::translate(p, USER_VA + i * PAGE).map(|(f, _)| f) == Some(pa),
            "a page does not show its frame of the object",
        )?;
        check(
            (0..PAGE_SIZE / 8).all(|w| mem.read(pa + w * 8) == 0),
            "the frames of a memory object are not zeroed",
        )?;
    }
    Ok(())
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
            && started.sched.base() == 10
            && started.sched.priority() == 10
            && started.sched.policy() == Policy::Fifo
            && started.sched.state() == State::Stopped
            && started.process() == p,
        "a new thread does not start as it was told",
    );
    // SAFETY: the thread is not running, and nothing uses it afterwards.
    unsafe { thread::release(t, CAUSE) };
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
                unsafe { thread::release(t, CAUSE) };
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
