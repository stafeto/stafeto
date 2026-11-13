// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The order of the writes init makes to a device of a record: the stop after an
//! instance ended (`Record::quiesce`, then `Record::release`) and the start before
//! the next one (`Record::start`). The worker supplies the register access
//! (`Regs`), the host tests a model of the device.

use crate::table::{Confirm, Gate, Record, Write};

/// The access to the registers of a device through the windows of its record.
pub trait Regs {
    /// Writes `q` and reads its register back until the bits of `q.settled`
    /// show the value (no read when `settled` is 0); false when the window does
    /// not come or the value does not settle.
    fn write(&mut self, record: &Record, q: &Write) -> bool;
    /// Whether the register of `c` shows its state within the time the worker
    /// allows; false when it does not or the window does not come.
    fn confirmed(&mut self, record: &Record, c: Confirm) -> bool;
    /// Whether the register of `g` shows one of its bits; a register that
    /// cannot be read counts as open.
    fn gate_open(&mut self, record: &Record, g: Gate) -> bool;
}

/// One write with its gate and its confirmation.
fn step(record: &Record, regs: &mut impl Regs, q: &Write) -> bool {
    if let Some(g) = q.only_if
        && !regs.gate_open(record, g)
    {
        return true;
    }
    regs.write(record, q) && q.confirm.is_none_or(|c| regs.confirmed(record, c))
}

/// Stops the device of `record` once an instance ended: the writes of
/// `quiesce` in their order up to the first that does not settle or confirm,
/// then the writes of `release`, each one whatever came before (a device that
/// did not stop still has bus mastering off). True when every step held.
pub fn stop(record: &Record, regs: &mut impl Regs) -> bool {
    let mut held = true;
    for q in record.quiesce {
        if !step(record, regs, q) {
            held = false;
            break;
        }
    }
    if cfg!(feature = "break-keep-master") && !held {
        return false;
    }
    for q in record.release {
        held &= step(record, regs, q);
    }
    held
}

/// Makes the device of `record` ready for an instance about to load: the writes
/// of `start` in their order. False at the first that does not hold.
pub fn start(record: &Record, regs: &mut impl Regs) -> bool {
    if cfg!(feature = "break-no-start") {
        return true;
    }
    record.start.iter().all(|q| step(record, regs, q))
}
