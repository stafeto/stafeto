// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Kernel tests at EL0. They run after all the others, one after another,
//! as a chain: a test builds its processes and threads and returns to EL0,
//! and since every entry from EL0 starts over at the top of the kernel
//! stack, the kernel never comes back to the test's frame. A program ends
//! with `svc #SVC_DONE`: the test judges the thread, prints its line and
//! starts the next test; after the last one the run ends. The programs
//! are in el0.S.

use super::{check, finish, report};
use crate::arch::user::UserRegs;
use crate::arch::{cache, symbols, timer};
use crate::process::{self, Process};
use crate::syscall;
use crate::thread::{self, Policy, Thread};
use abi::Error;
use core::ptr::NonNull;
use kcore::esr;
use kcore::frames::PAGE_SIZE;
use kcore::layout::LINEAR_BASE;
use kcore::paging::Attrs;
use kcore::sync::Lock;
use kcore::sysreg::SPSR_NZCV;

core::arch::global_asm!(include_str!("el0.S"), options(raw));

unsafe extern "C" {
    static el0_programs: u8;
    static el0_programs_end: u8;
    static el0_read_counter: u8;
    static el0_pattern_nop: u8;
    static el0_pattern_unknown: u8;
    static el0_load: u8;
}

/// Test system calls: the numbers lie in abi::TEST_CALLS and exist in test
/// builds only (el0.S uses them too). NOP returns 0 in x0; DONE ends the
/// program.
pub const SVC_NOP: u16 = 0xFF00;
pub const SVC_DONE: u16 = 0xFF01;

const _: () = assert!(*abi::TEST_CALLS.start() <= SVC_NOP && SVC_DONE <= *abi::TEST_CALLS.end());

/// Where the test processes see their pages: the programs at TEXT_VA, and
/// one page of data at DATA_VA with the register pattern at its start and
/// the stack at its end.
const TEXT_VA: usize = 0x40_0000;
const DATA_VA: usize = 0x80_0000;
const PAGE: usize = PAGE_SIZE as usize;
const PRIORITY: u8 = 10;

struct El0Test {
    name: &'static str,
    /// Builds the test's threads; returns the one to run first.
    start: fn(&mut Fixture) -> Result<NonNull<Thread>, &'static str>,
    /// Judges a thread at its `svc #SVC_DONE`.
    done: fn(&Fixture, &Thread) -> Result<(), &'static str>,
}

const EL0_TESTS: &[El0Test] = &[
    El0Test {
        name: "el0_reads_the_virtual_counter",
        start: start_counter,
        done: done_counter,
    },
    El0Test {
        name: "registers_survive_a_system_call",
        start: start_nop,
        done: done_nop,
    },
    El0Test {
        name: "unknown_system_call_fails_with_invalid_args",
        start: start_unknown,
        done: done_unknown,
    },
    El0Test {
        name: "el0_load_from_kernel_memory_faults",
        start: start_kernel_load,
        done: done_kernel_load,
    },
];

/// What the running test built and expects: up to two processes with one
/// thread each.
struct Fixture {
    test: usize,
    processes: [Option<NonNull<Process>>; 2],
    threads: [Option<NonNull<Thread>>; 2],
    /// Threads that passed their `svc #SVC_DONE`.
    passed: [bool; 2],
    patterns: [Pattern; 2],
    /// The counter before the thread started.
    counter: u64,
    /// A kernel address the program loads from and must fault on.
    fault_at: Option<u64>,
    /// SP in the first test system call, and whether every later one had
    /// the same, near the top of the kernel stack.
    stack: Option<usize>,
    stack_ok: bool,
}

// SAFETY: the fixture's objects are reached only under the kernel's rules
// (spec 8.1): one CPU, interrupts masked inside the kernel.
unsafe impl Send for Fixture {}

impl Fixture {
    const fn new(test: usize) -> Fixture {
        Fixture {
            test,
            processes: [None; 2],
            threads: [None; 2],
            passed: [false; 2],
            patterns: [Pattern::ZERO; 2],
            counter: 0,
            fault_at: None,
            stack: None,
            stack_ok: true,
        }
    }

    /// Which of the test's threads `thread` is.
    fn slot(&self, thread: &Thread) -> usize {
        self.threads
            .iter()
            .position(|t| t.is_some_and(|t| core::ptr::eq(t.as_ptr(), thread)))
            .expect("a thread of the running test")
    }
}

static FIXTURE: Lock<Fixture> = Lock::new(Fixture::new(0));

/// Runs the EL0 tests and ends the run.
pub fn run() -> ! {
    start(0)
}

/// Starts the tests from `first` on; a test that cannot start fails, and
/// the next one starts.
fn start(first: usize) -> ! {
    for (i, test) in EL0_TESTS.iter().enumerate().skip(first) {
        let started = {
            let mut f = FIXTURE.lock();
            *f = Fixture::new(i);
            (test.start)(&mut f)
        };
        match started {
            Ok(thread) => thread::run(thread),
            Err(why) => {
                report(test.name, Err(why));
                teardown();
            }
        }
    }
    finish()
}

/// Ends the running test with `result` and starts the next one.
fn end(result: Result<(), &'static str>) -> ! {
    let test = FIXTURE.lock().test;
    report(EL0_TESTS[test].name, result);
    teardown();
    start(test + 1)
}

fn teardown() {
    let (threads, processes) = {
        let mut f = FIXTURE.lock();
        (
            core::mem::take(&mut f.threads),
            core::mem::take(&mut f.processes),
        )
    };
    for t in threads.into_iter().flatten() {
        // SAFETY: the test's threads go with it; the running one stops
        // being the running one.
        unsafe { thread::destroy(t) };
    }
    for p in processes.into_iter().flatten() {
        // SAFETY: the test's processes go with it, their threads gone.
        unsafe { process::destroy(p) };
    }
}

/// The test system calls; false for any other number.
pub fn syscall(thread: NonNull<Thread>, number: u16) -> bool {
    note_stack();
    match number {
        SVC_NOP => syscall::set_result(thread, Ok(())),
        SVC_DONE => done(thread),
        _ => return false,
    }
    true
}

/// Every entry from EL0 starts at the top of the kernel stack (spec 8.1),
/// so every test system call runs with the same SP.
fn note_stack() {
    let sp: usize;
    // SAFETY: reading SP has no side effects.
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags))
    };
    let top = symbols::boot_stack().end;
    let mut f = FIXTURE.lock();
    let first = *f.stack.get_or_insert(sp);
    f.stack_ok &= sp == first && top - sp < PAGE;
}

/// A thread's `svc #SVC_DONE`: the test judges it; once every thread of the
/// test has passed, the test ends, else the next of them runs.
fn done(thread: NonNull<Thread>) -> ! {
    let (result, next) = {
        let mut f = FIXTURE.lock();
        // SAFETY: the running thread is alive; nothing changes it meanwhile.
        let t = unsafe { thread.as_ref() };
        let result = check(
            f.stack_ok,
            "an entry from EL0 did not start at the top of the kernel stack",
        )
        .and_then(|()| (EL0_TESTS[f.test].done)(&f, t));
        let slot = f.slot(t);
        f.passed[slot] = result.is_ok();
        let next = (0..2).find(|&i| f.threads[i].is_some() && !f.passed[i]);
        (result, next.and_then(|i| f.threads[i]))
    };
    match (result, next) {
        (Ok(()), Some(next)) => thread::run(next),
        (result, _) => end(result),
    }
}

/// A fault at EL0: when the running test expects it, the test ends here;
/// otherwise this returns and the kernel reports the fault.
pub fn user_fault(thread: NonNull<Thread>, syndrome: u64, far: u64) {
    let Some(target) = FIXTURE.lock().fault_at else {
        return;
    };
    // SAFETY: the running thread is alive.
    let elr = unsafe { thread.as_ref() }.regs.elr;
    let result = check(
        esr::ec(syndrome) == esr::EC_DABT_LOWER,
        "the fault is not a data abort from EL0",
    )
    .and_then(|()| {
        check(
            esr::fault_status_name(syndrome) == "permission fault",
            "the fault is not a permission fault",
        )
    })
    .and_then(|()| check(far == target, "FAR is not the kernel address"))
    .and_then(|()| {
        check(
            elr == user_address(&raw const el0_load) as u64,
            "ELR is not the load",
        )
    });
    end(result)
}

/// The user address of a symbol in el0.S.
fn user_address(symbol: *const u8) -> usize {
    TEXT_VA + (symbol as usize - &raw const el0_programs as usize)
}

/// A process with the programs at TEXT_VA and a data page at DATA_VA
/// holding the pattern of slot `slot`, and in it a thread that starts at
/// `entry` (a symbol in el0.S) with `arg` in x0 and the pattern's
/// TPIDRRO_EL0. Both go into that slot of the fixture.
fn spawn(
    f: &mut Fixture,
    slot: usize,
    entry: *const u8,
    arg: u64,
) -> Result<NonNull<Thread>, &'static str> {
    let mut p = process::create().map_err(|_| "no process")?;
    f.processes[slot] = Some(p);
    // SAFETY: the process was just created, and only this test uses it.
    let process = unsafe { p.as_mut() };
    let text = process
        .map_frames(TEXT_VA, PAGE_SIZE, Attrs::USER_TEXT)
        .map_err(|_| "the programs did not map")?;
    let start = &raw const el0_programs as usize;
    let len = &raw const el0_programs_end as usize - start;
    assert!(len <= PAGE, "the EL0 programs outgrew their page");
    let text_va = LINEAR_BASE + text as usize;
    // SAFETY: the programs lie in the kernel image, and the frame is new,
    // one page, and reached through the linear map.
    unsafe { core::ptr::copy_nonoverlapping(start as *const u8, text_va as *mut u8, len) };
    cache::sync_icache(text_va, len);
    let data = process
        .map_frames(DATA_VA, PAGE_SIZE, Attrs::USER_DATA)
        .map_err(|_| "the data page did not map")?;
    // SAFETY: the frame is new, one page, aligned for the pattern, and
    // reached through the linear map.
    unsafe { ((LINEAR_BASE + data as usize) as *mut Pattern).write(f.patterns[slot].clone()) };
    let t = thread::create(
        p,
        user_address(entry),
        DATA_VA + PAGE,
        arg,
        PRIORITY,
        Policy::RoundRobin,
    )
    .map_err(|_| "no thread")?;
    f.threads[slot] = Some(t);
    // SAFETY: the thread was just created and does not run yet.
    unsafe { (*t.as_ptr()).regs.tpidrro = f.patterns[slot].tpidrro };
    Ok(t)
}

/// Values a program loads into all its registers (el0.S, LOAD_PATTERN), at
/// the offsets it reads them from, and the TPIDRRO_EL0 that the kernel
/// gives its thread.
#[repr(C)]
#[derive(Clone)]
struct Pattern {
    x: [u64; 31],
    sp: u64,
    nzcv: u64,
    tpidr: u64,
    fpcr: u64,
    fpsr: u64,
    v: [u128; 32],
    tpidrro: u64,
}

const _: () = {
    assert!(core::mem::offset_of!(Pattern, sp) == 248);
    assert!(core::mem::offset_of!(Pattern, nzcv) == 256);
    assert!(core::mem::offset_of!(Pattern, tpidr) == 264);
    assert!(core::mem::offset_of!(Pattern, fpcr) == 272);
    assert!(core::mem::offset_of!(Pattern, fpsr) == 280);
    assert!(core::mem::offset_of!(Pattern, v) == 288);
};

/// SplitMix64: a different, well-mixed value on every call.
fn mix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl Pattern {
    const ZERO: Pattern = Pattern {
        x: [0; 31],
        sp: 0,
        nzcv: 0,
        tpidr: 0,
        fpcr: 0,
        fpsr: 0,
        v: [0; 32],
        tpidrro: 0,
    };

    /// A pattern in which no two registers hold the same value, and no
    /// register holds what the pattern of another seed puts in it. Odd and
    /// even seeds set different flags and FP control bits.
    fn new(seed: u64) -> Pattern {
        let mut state = seed;
        let odd = seed % 2 == 1;
        let mut p = Pattern::ZERO;
        for x in &mut p.x {
            *x = mix(&mut state);
        }
        for v in &mut p.v {
            *v = u128::from(mix(&mut state)) << 64 | u128::from(mix(&mut state));
        }
        p.tpidr = mix(&mut state);
        p.tpidrro = mix(&mut state);
        p.sp = (DATA_VA + PAGE - 16 * seed as usize) as u64;
        // N and V, or Z and C.
        p.nzcv = if odd { 0x9 << 28 } else { 0x6 << 28 };
        // FPCR: AHP, DN and round towards plus infinity, or FZ and round
        // towards minus infinity.
        p.fpcr = if odd { 0x0640_0000 } else { 0x0180_0000 };
        // FPSR: every cumulative exception bit and QC, or IXC and IOC.
        p.fpsr = if odd { 0x0800_009F } else { 0x11 };
        p
    }
}

/// The thread's registers are the pattern's, except x0, which is `x0` (a
/// system call's result replaces the pattern's value there).
fn check_pattern(regs: &UserRegs, p: &Pattern, x0: u64) -> Result<(), &'static str> {
    let mut want = p.x;
    want[0] = x0;
    if let Some(i) = (0..31).find(|&i| regs.x[i] != want[i]) {
        kprintln!("x{i} is {:#x}, the pattern has {:#x}", regs.x[i], want[i]);
        return Err("a general register changed");
    }
    check(regs.sp == p.sp, "SP_EL0 changed")?;
    check(regs.spsr & SPSR_NZCV == p.nzcv, "the flags changed")?;
    check(
        regs.spsr & !SPSR_NZCV == 0,
        "the thread left EL0t or masked an exception",
    )?;
    check(regs.tpidr == p.tpidr, "TPIDR_EL0 changed")?;
    check(regs.tpidrro == p.tpidrro, "TPIDRRO_EL0 changed")
}

fn start_counter(f: &mut Fixture) -> Result<NonNull<Thread>, &'static str> {
    f.counter = timer::now();
    spawn(f, 0, &raw const el0_read_counter, 0)
}

fn done_counter(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    let (count, hz) = (t.regs.x[0], t.regs.x[1]);
    check(
        (f.counter..=timer::now()).contains(&count),
        "the counter EL0 read is not between two readings of the kernel",
    )?;
    check(
        hz == timer::frequency(),
        "EL0 reads another counter frequency",
    )
}

fn start_nop(f: &mut Fixture) -> Result<NonNull<Thread>, &'static str> {
    f.patterns[0] = Pattern::new(1);
    spawn(f, 0, &raw const el0_pattern_nop, DATA_VA as u64)
}

fn done_nop(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check_pattern(&t.regs, &f.patterns[0], 0)
}

fn start_unknown(f: &mut Fixture) -> Result<NonNull<Thread>, &'static str> {
    f.patterns[0] = Pattern::new(1);
    spawn(f, 0, &raw const el0_pattern_unknown, DATA_VA as u64)
}

fn done_unknown(f: &Fixture, t: &Thread) -> Result<(), &'static str> {
    check_pattern(&t.regs, &f.patterns[0], Error::InvalidArgs as u64)
}

/// The program loads from FIXTURE itself, a kernel variable.
fn start_kernel_load(f: &mut Fixture) -> Result<NonNull<Thread>, &'static str> {
    let target = &raw const FIXTURE as u64;
    f.fault_at = Some(target);
    spawn(f, 0, &raw const el0_load, target)
}

fn done_kernel_load(_: &Fixture, _: &Thread) -> Result<(), &'static str> {
    Err("a load from kernel memory at EL0 did not fault")
}
