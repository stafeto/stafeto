// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Interrupts (spec 8.1, 9). PSTATE masks them inside the kernel: one
//! taken while a program runs at EL0 stays pending, and the way out of the
//! kernel (sched::resume) acknowledges and handles it, as it does between
//! two portions of cleanup and after the idle wait (gic::wait). The
//! scheduler decides afterwards who runs.

use crate::arch::{gic, timer};
use crate::{irq, sched};
use kcore::gic::Ack;

/// Handles an interrupt acknowledged at the GIC and ends it: the kernel's
/// timer; a line bound to a channel, which is masked and posts to it
/// (irq::deliver); any other line is masked and ended, since nothing
/// serves it (spec 9). O(1) but for the timer's part.
pub fn handle(ack: Ack) {
    let intid = ack.intid();
    if intid == timer::INTID {
        // A level line may reach the GIC once more after the EOI that
        // followed a disarm: without the timer's condition the interrupt is
        // spurious.
        if timer::fired() {
            // The line is level-triggered and has to be quiet before the
            // EOI: the scheduler turns the timer off, ends a quantum that is
            // over and queues the firing of each level whose timers of
            // programs expired (spec 10), and arms the timer for its next
            // deadline on the way out.
            sched::timer_fired();
            crate::testpoint::timer_fired();
        }
    } else if !irq::deliver(intid) {
        gic::mask(intid);
    }
    gic::end(ack);
}
