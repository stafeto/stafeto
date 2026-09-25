// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Interrupts (spec 8.1, 9). PSTATE masks them inside the kernel, so they
//! are taken only while a program runs at EL0; the idle loop of milestone
//! 1.2c will fetch them itself through gic::wait.

use crate::arch::{gic, timer};

/// An IRQ taken at EL0: acknowledges it at the GIC, handles it and ends it.
/// The interrupted thread goes on afterwards.
pub fn handle() {
    // A spurious read needs no EOI.
    let Some(ack) = gic::acknowledge() else {
        return;
    };
    let intid = ack.intid();
    if intid != timer::INTID {
        panic!("interrupt {intid} arrived, but only the timer's line is unmasked");
    }
    // A level line may reach the GIC once more after the EOI that followed
    // a disarm: without the timer's condition the interrupt is spurious.
    if timer::fired() {
        // The line is level-triggered and has to be quiet before the EOI.
        // The scheduler of milestone 1.2c arms its next deadline here.
        timer::disarm();
        #[cfg(feature = "ktest")]
        crate::ktest::el0::timer_fired();
    }
    gic::end(ack);
}
