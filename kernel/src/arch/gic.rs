// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The GIC driver of `karch` with the parts that need the kernel: the ITS
//! comes up inside the bring-up of the GICv3's redistributors, the CPUs are
//! named by their numbers, and the time stamps see the idle wait.

use super::{cpu, its};
use crate::stamps;
use kboot::bootinfo::BootInfo;
use kcore::gic::Ack;

pub use karch::gic::*;

/// The boot CPU passes the device tree and sets the ITS up (its::init)
/// before its own LPIs and collection; every CPU then turns its LPIs on
/// (its::init_cpu). Called by the GICv3's bring-up of a CPU, once the
/// redistributor of the CPU is woken and its lines reset.
fn redistributor_ready(boot: Option<&BootInfo>, redistributor: usize) {
    if let Some(info) = boot {
        its::init(info, redistributor);
    }
    its::init_cpu(redistributor);
}

/// Resets the GIC and turns it on, as the device tree names it
/// (karch::gic::init). Runs once, at boot.
pub fn init(info: &BootInfo) {
    karch::gic::init(info, redistributor_ready);
}

/// What a CPU other than the first sets up for itself
/// (karch::gic::init_secondary).
pub fn init_secondary() {
    karch::gic::init_secondary(redistributor_ready);
}

/// Sends SGI `intid` to CPU `target` (its number, arch::cpu), which is up.
pub fn send_sgi(target: usize, intid: u32) {
    karch::gic::send_sgi(cpu::block(target), intid);
}

/// Whether the SGI `ack` came from CPU `sender` (karch::gic::sgi_from).
pub fn sgi_from(ack: &Ack, sender: usize) -> bool {
    karch::gic::sgi_from(ack, cpu::block(sender))
}

/// Sends the shared line `intid` to CPU `target`, which is up (spec 9).
pub fn set_route(intid: u32, target: usize) {
    karch::gic::set_route(intid, cpu::block(target));
}

/// Sleeps until an interrupt is pending at this CPU and acknowledges it.
/// PSTATE keeps interrupts masked, so none is taken; `wfi` ends all the
/// same. None when the wake-up brought nothing to acknowledge.
#[must_use = "an acknowledged interrupt stays active until gic::end"]
pub fn wait() -> Option<Ack> {
    stamps::wfi(false);
    karch::gic::sleep();
    stamps::wfi(true);
    acknowledge()
}
