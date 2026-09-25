// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Interrupts (spec 8.1, 9). PSTATE masks them inside the kernel: they are
//! taken while a program runs at EL0, and the idle loop fetches them itself
//! through gic::wait. Either way the scheduler decides afterwards who runs
//! (sched::resume).

use crate::arch::{gic, timer};
use crate::sched;
use kcore::gic::Ack;

/// Handles an interrupt acknowledged at the GIC and ends it.
pub fn handle(ack: Ack) {
    let intid = ack.intid();
    if intid != timer::INTID {
        panic!("interrupt {intid} arrived, but only the timer's line is unmasked");
    }
    // A level line may reach the GIC once more after the EOI that followed
    // a disarm: without the timer's condition the interrupt is spurious.
    if timer::fired() {
        // The line is level-triggered and has to be quiet before the EOI:
        // the scheduler turns the timer off and ends a quantum that is
        // over, and arms the timer for its next deadline on the way out.
        sched::timer_fired();
        #[cfg(feature = "ktest")]
        crate::ktest::el0::timer_fired();
    }
    gic::end(ack);
}
