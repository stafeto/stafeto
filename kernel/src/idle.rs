// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The bell and the poll in the idle loop (spec 8.1, decision
//! tasks/2026-11-06-f2-kernel-decision.md). A CPU with nothing to do spins
//! for a short window (`kcore::idlepoll`) before it sleeps in `wfi`. Each CPU
//! has a word of its own on a line of its own with two bits: POLLING while it
//! is in the window, BELL when another CPU put work for it. A sender rings
//! with one `fetch_or` of BELL and sends the SGI only when POLLING was clear
//! in the old value; the poller clears both with one `fetch_and` and sees
//! from the old value whether it was rung. Both change one word, whose
//! changes have one order for every CPU, so a bell is either seen by the
//! poller or comes with an SGI, and no barrier between two addresses is
//! needed (a bell that came with an SGI while POLLING was clear is caught by
//! `irq_pending`).

use crate::arch::cpu::{self, MAX_CPUS};
use crate::arch::{self, gic};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use kcore::gic::SGI_CMD;

/// The CPU is in the window of its poll.
const POLLING: u32 = 1;
/// Another CPU put work for this one.
const BELL: u32 = 2;

/// The word of a CPU, on a line of its own (128 bytes, the line of Apple's cores; more than the 64 bytes of the reservation granule of the Cortex-A53), so that a bell
/// for one CPU never writes the line of another.
#[repr(align(128))]
struct Word(AtomicU32);

static IDLE: [Word; MAX_CPUS] = [const { Word(AtomicU32::new(0)) }; MAX_CPUS];

/// Whether the machine polls: set once by CPU 0 before the others start.
static POLL_ON: AtomicBool = AtomicBool::new(false);

/// The deliberate breaks act once the test of the pairs asks for them
/// (`arm`), so that the earlier tests of the group run on a sound kernel and
/// the break shows as a call that hangs.
#[cfg(feature = "idle-probe")]
static ARMED: AtomicBool = AtomicBool::new(false);

/// The test of the pairs arms the breaks (debug_write "idle-probe arm").
#[cfg(feature = "idle-probe")]
pub fn arm() {
    ARMED.store(true, Ordering::Relaxed);
    WATCH.store(true, Ordering::Relaxed);
}

/// The probe kernels print their line about an interrupt pending at the end
/// of a window from the start of the test of the pairs (`arm`) to the end of
/// the test of the interrupt (`watch(false)`).
#[cfg(feature = "idle-probe")]
static WATCH: AtomicBool = AtomicBool::new(false);

/// The test of the interrupt stops the watch.
#[cfg(feature = "idle-probe")]
pub fn watch(on: bool) {
    WATCH.store(on, Ordering::Relaxed);
}

/// Whether a break is in force.
#[allow(dead_code)]
fn armed() -> bool {
    cfg!(feature = "idle-probe") && {
        #[cfg(feature = "idle-probe")]
        let on = ARMED.load(Ordering::Relaxed);
        #[cfg(not(feature = "idle-probe"))]
        let on = false;
        on
    }
}

/// The break `break-idle-drain`: the bell ends the poll with no drain.
pub fn skips_drain() -> bool {
    cfg!(feature = "break-idle-drain") && armed()
}

/// The window of the probe kernels, in ticks of the counter: 1 ms.
const PROBE_WINDOW_DIV: u64 = 1000;

/// Decides from the build and the machine whether the CPUs poll: the
/// features `idle-poll` and `no-idle-poll` for everywhere and nowhere, else
/// the table of `kcore::idlepoll::enabled` by MIDR_EL1.
pub fn init() {
    #[cfg(all(feature = "idle-poll", feature = "no-idle-poll"))]
    compile_error!("idle-poll and no-idle-poll exclude each other");
    let on = if cfg!(feature = "no-idle-poll") {
        false
    } else if cfg!(feature = "idle-poll") {
        true
    } else {
        kcore::idlepoll::enabled(arch::registers::midr_el1())
    };
    POLL_ON.store(on, Ordering::Relaxed);
}

/// Whether the CPUs poll.
pub fn on() -> bool {
    POLL_ON.load(Ordering::Relaxed)
}

/// The window of this CPU now, in ticks: `wanted` (the CPU's own, from
/// `kcore::idlepoll`), 0 when the machine does not poll, and 1 ms in the
/// probe kernels.
pub fn window(wanted: u64) -> u64 {
    if !on() {
        0
    } else if cfg!(feature = "idle-probe") {
        arch::timer::frequency() / PROBE_WINDOW_DIV
    } else {
        wanted
    }
}

/// Tells CPU `to` that commands wait in its queues: the bell, and the SGI
/// unless `to` is in the window of its poll. The place of every SGI_CMD to
/// another CPU (cmd::flush, cleanup, qsbr::kick).
pub fn ring(to: usize) {
    if !on() {
        crate::stamps::sgi_sent(to, true);
        return gic::send_sgi(to, SGI_CMD);
    }
    // Release: the queue (its tail was stored with Release) and the flags of
    // the threads are visible to the poller that sees the bell.
    #[cfg(not(feature = "break-idle-bell"))]
    let old = IDLE[to].0.fetch_or(BELL, Ordering::Release);
    // The deliberate break: the look at POLLING and the write of BELL are
    // two steps, and the poller may leave and sleep between them.
    #[cfg(feature = "break-idle-bell")]
    let old = {
        let old = IDLE[to].0.load(Ordering::Acquire);
        if old & POLLING != 0 && armed() {
            let until = arch::timer::now() + 2 * arch::timer::frequency() / 1000;
            while arch::timer::now() < until {}
        }
        IDLE[to].0.fetch_or(BELL, Ordering::Release);
        old
    };
    let sgi = old & POLLING == 0;
    crate::stamps::sgi_sent(to, sgi);
    #[cfg(feature = "smp-measure")]
    crate::smpm::rang(sgi);
    if sgi {
        gic::send_sgi(to, SGI_CMD);
    }
}

/// What ended the poll of a CPU: `bell` when another CPU rang, `quiet` when
/// the window ran out with nothing to see (the CPU sleeps in `wfi`). When
/// neither, an interrupt is pending.
pub struct Polled {
    pub bell: bool,
    pub quiet: bool,
}

/// The poll of this CPU for `window` ticks: each turn reads ISR_EL1, the
/// word and the counter, so that an interrupt or a bell ends it within one
/// turn. The caller has made the CPU quiescent (qsbr) and left the address
/// space of the thread before.
pub fn poll(window: u64) -> Polled {
    let word = &IDLE[cpu::this().index()].0;
    // A bell that came with an SGI is caught by the pending interrupt.
    word.swap(POLLING, Ordering::Relaxed);
    let end = arch::timer::now() + window;
    let mut quiet = false;
    loop {
        #[cfg(not(feature = "break-idle-irq"))]
        if arch::irq_pending() {
            break;
        }
        if word.load(Ordering::Acquire) & BELL != 0 {
            break;
        }
        if arch::timer::now() >= end {
            quiet = true;
            break;
        }
        core::hint::spin_loop();
    }
    let old = word.fetch_and(!(POLLING | BELL), Ordering::Acquire);
    #[cfg(feature = "idle-probe")]
    if quiet && old & BELL == 0 && WATCH.load(Ordering::Relaxed) && arch::irq_pending() {
        kprintln!("idle poll  an interrupt was pending at the end of the window");
    }
    let bell = old & BELL != 0;
    Polled {
        bell,
        quiet: quiet && !bell,
    }
}
