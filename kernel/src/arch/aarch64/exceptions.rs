// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exception entry. A system call from EL0 goes to the dispatcher; every
//! other exception is reported with its registers and stops the kernel.
//! Test builds skip one BRK marker (kcore::esr::TEST_BRK) to prove the
//! vectors and the return path work. An entry from EL1 that finds no room
//! on the kernel stack runs on the emergency stack and never returns.

use super::user::UserRegs;
use super::{registers, symbols};
use crate::thread::{self, Thread};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use kcore::esr::{self, BrkAction};

/// Registers saved by vectors.S, in its layout, and the frame record that
/// links the interrupted code into backtraces.
#[repr(C)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub elr: u64,
    pub spsr: u64,
    /// SP_EL1 of the interrupted code.
    pub sp: u64,
    _padding: u64,
    pub frame_record: [u64; 2],
}

const _: () = assert!(core::mem::size_of::<TrapFrame>() == 304);

const VECTOR_NAMES: [&str; 16] = [
    "EL1t sync",
    "EL1t irq",
    "EL1t fiq",
    "EL1t serror",
    "EL1h sync",
    "EL1h irq",
    "EL1h fiq",
    "EL1h serror",
    "EL0 sync",
    "EL0 irq",
    "EL0 fiq",
    "EL0 serror",
    "EL0 AArch32 sync",
    "EL0 AArch32 irq",
    "EL0 AArch32 fiq",
    "EL0 AArch32 serror",
];
const VECTOR_EL1H_SYNC: u64 = 4;
const VECTOR_EL0_SYNC: u64 = 8;
/// Set in the vector index when the entry switched to the emergency stack.
const ON_EMERGENCY_STACK: u64 = 1 << 4;

/// Immediate of the last BRK skipped in kernel code.
pub static LAST_BRK: AtomicU64 = AtomicU64::new(u64::MAX);

/// Set by the first entry on the emergency stack. Another one starts over
/// at the top of that stack, on the frames of the first report, and may
/// fail the same way again: it stops the machine without a word.
static ON_EMERGENCY: AtomicBool = AtomicBool::new(false);

/// Points VBAR_EL1 at the vector table.
pub fn init() {
    // SAFETY: exception_vectors is a valid, 2 KiB aligned vector table in the
    // kernel image; the ISB makes the new VBAR take effect.
    unsafe {
        core::arch::asm!(
            "adrp {t}, exception_vectors",
            "add {t}, {t}, :lo12:exception_vectors",
            "msr vbar_el1, {t}",
            "isb",
            t = out(reg) _,
            options(nostack),
        )
    };
}

#[unsafe(no_mangle)]
extern "C" fn handle_exception(frame: &mut TrapFrame, index: u64) {
    let syndrome = registers::esr_el1();
    // Only an entry on the kernel stack may return: after a switch to the
    // emergency stack the vector has no way back to the interrupted SP.
    if index == VECTOR_EL1H_SYNC
        && let Some(imm) = esr::brk_immediate(syndrome)
        && esr::kernel_brk_action(imm, cfg!(feature = "ktest")) == BrkAction::Skip
    {
        LAST_BRK.store(u64::from(imm), Ordering::Relaxed);
        // A BRK exception returns to the BRK itself; step over it.
        frame.elr += 4;
        return;
    }
    let far = registers::far_el1();
    let class = esr::ec(syndrome);
    let guard = symbols::image_layout().stack_guard as u64;
    if index & ON_EMERGENCY_STACK != 0 {
        if ON_EMERGENCY.swap(true, Ordering::Relaxed) {
            crate::panicking::stop()
        }
        let stack = symbols::boot_stack();
        kprintln!(
            "kernel stack overflow: no room for the trap frame at SP {:#x} (kernel stack {:#x}..{:#x}); reporting on the emergency stack",
            frame.sp,
            stack.start,
            stack.end
        );
    } else if matches!(class, esr::EC_DABT_SAME | esr::EC_IABT_SAME)
        && (guard..guard + 4096).contains(&far)
    {
        kprintln!("kernel stack overflow: the guard page at {guard:#x} was hit");
    }
    print_x(&frame.x);
    kprintln!(
        "\nsp  {:#018x}  sp_el0 {:#018x}  elr {:#018x}  spsr {:#018x}",
        frame.sp,
        frame.sp_el0,
        frame.elr,
        frame.spsr
    );
    stop(index, syndrome, far, frame.elr)
}

/// Entry from EL0 (vectors.S): the program's registers are in the running
/// thread. A system call goes to the dispatcher and the thread goes on.
/// Any other synchronous exception is the program's fault and stops the
/// machine for now (milestone 1.2c ends just the process, spec 7.9); an
/// asynchronous one that no handler takes is an error of the system.
#[unsafe(no_mangle)]
extern "C" fn handle_user_exception(index: u64) -> ! {
    let thread = thread::current().expect("an entry from EL0 with no thread running");
    let syndrome = registers::esr_el1();
    match index {
        VECTOR_EL0_SYNC => match esr::svc_immediate(syndrome) {
            Some(number) => crate::syscall::dispatch(thread, number),
            None => user_fault(thread, index, syndrome),
        },
        // Not the program's fault: no interrupt reaches EL0 yet; PSTATE
        // masks SErrors inside the kernel, so one the kernel caused arrives
        // at EL0 as well; FIQs never reach EL1.
        _ => system_error(thread, index, syndrome),
    }
    thread::run(thread)
}

/// Reports a fault of the program at EL0 like a kernel fault, marked EL0,
/// and stops the machine. In test builds the running test may expect the
/// fault and go on instead.
fn user_fault(thread: NonNull<Thread>, index: u64, syndrome: u64) -> ! {
    let far = registers::far_el1();
    #[cfg(feature = "ktest")]
    crate::ktest::el0::user_fault(thread, syndrome, far);
    report_el0(thread, "program fault", index, syndrome, far)
}

/// An asynchronous exception at EL0 that no handler takes: an error of the
/// system, such as an SError from a write of the kernel, which the running
/// program did not cause. The report shows that program all the same, and
/// the machine stops.
fn system_error(thread: NonNull<Thread>, index: u64, syndrome: u64) -> ! {
    report_el0(
        thread,
        "system error",
        index,
        syndrome,
        registers::far_el1(),
    )
}

/// Reports an exception taken at EL0 with the program's registers and
/// stops the machine.
fn report_el0(thread: NonNull<Thread>, what: &str, index: u64, syndrome: u64, far: u64) -> ! {
    // SAFETY: the running thread is alive; nothing else refers to it now.
    let regs: &UserRegs = unsafe { &thread.as_ref().regs };
    kprintln!("{what} at EL0, thread {:#x}", thread.as_ptr() as usize);
    print_x(&regs.x);
    kprintln!(
        "\nsp_el0 {:#018x}  elr {:#018x}  spsr {:#018x}  tpidr_el0 {:#018x}",
        regs.sp,
        regs.elr,
        regs.spsr,
        regs.tpidr
    );
    stop(index, syndrome, far, regs.elr)
}

fn print_x(x: &[u64; 31]) {
    for (i, v) in x.iter().enumerate() {
        let sep = if i % 4 == 3 { "\n" } else { "  " };
        crate::console::print(format_args!("x{i:<2} {v:#018x}{sep}"));
    }
}

/// Names the fault of an abort and panics with the exception's syndrome.
fn stop(index: u64, syndrome: u64, far: u64, elr: u64) -> ! {
    let class = esr::ec(syndrome);
    if matches!(
        class,
        esr::EC_IABT_LOWER | esr::EC_IABT_SAME | esr::EC_DABT_LOWER | esr::EC_DABT_SAME
    ) {
        match esr::fault_level(syndrome) {
            Some(level) => kprintln!(
                "abort: {} at level {level}, FAR={far:#x}",
                esr::fault_status_name(syndrome)
            ),
            None => kprintln!("abort: {}, FAR={far:#x}", esr::fault_status_name(syndrome)),
        }
    }
    panic!(
        "unexpected exception {}: {} (EC {class:#x}) ESR={syndrome:#x} ELR={elr:#x} FAR={far:#x}",
        VECTOR_NAMES[(index & 15) as usize],
        esr::class_name(class),
    );
}
