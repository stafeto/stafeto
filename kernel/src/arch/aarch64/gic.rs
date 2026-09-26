// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! GICv2 driver (spec 9): the distributor and this CPU's interface, reached
//! through the linear map at the addresses from the device tree. Inside the
//! kernel PSTATE keeps interrupts masked (spec 8.1): the kernel sleeps in
//! `wfi`, which a pending interrupt ends all the same, and acknowledges the
//! interrupt itself through GICC_IAR.

use super::mmio;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use kcore::bootinfo::{BootInfo, GicVersion};
use kcore::gic::{
    self, Ack, CTLR_ENABLE, DEFAULT_PRIORITY, FIRST_SPI, GICC_CTLR, GICC_EOIR, GICC_IAR, GICC_PMR,
    GICD_CTLR, GICD_ICACTIVER, GICD_ICENABLER, GICD_ICPENDR, GICD_IPRIORITYR, GICD_ISENABLER,
    GICD_ITARGETSR, GICD_TYPER, PRIORITY_MASK,
};
use kcore::layout::LINEAR_BASE;

/// Virtual addresses of the distributor and the CPU interface; zero until `init`.
static DIST: AtomicUsize = AtomicUsize::new(0);
static CPU: AtomicUsize = AtomicUsize::new(0);
/// The lines of the distributor, from GICD_TYPER at `init`.
static LINE_COUNT: AtomicU32 = AtomicU32::new(0);

fn reg(base: &AtomicUsize, offset: usize) -> usize {
    let base = base.load(Ordering::Relaxed);
    assert!(base != 0, "the GIC is used before gic::init");
    base + offset
}

fn read(base: &AtomicUsize, offset: usize) -> u32 {
    // SAFETY: `init` stored the base of a GIC block the kernel tables map as
    // device memory; the offsets are registers of that block.
    unsafe { mmio::read32(reg(base, offset)) }
}

fn write(base: &AtomicUsize, offset: usize, value: u32) {
    // SAFETY: as in `read`.
    unsafe { mmio::write32(reg(base, offset), value) }
}

/// Resets the distributor and this CPU's interface and turns both on: every
/// line masked, not pending, not active, at DEFAULT_PRIORITY; shared lines
/// go to CPU 0; the priority mask lets DEFAULT_PRIORITY through.
pub fn init(info: &BootInfo) {
    let gic = info.gic.expect("no GIC in the device tree");
    assert!(gic.version == GicVersion::V2, "no driver for a GICv3");
    let [dist, cpu] = gic.mapped();
    DIST.store(LINEAR_BASE + dist.base as usize, Ordering::Relaxed);
    CPU.store(LINEAR_BASE + cpu.base as usize, Ordering::Relaxed);
    write(&DIST, GICD_CTLR, 0);
    let lines = gic::lines(read(&DIST, GICD_TYPER));
    LINE_COUNT.store(lines, Ordering::Relaxed);
    for intid in (0..lines).step_by(32) {
        for bank in [GICD_ICENABLER, GICD_ICPENDR, GICD_ICACTIVER] {
            write(&DIST, gic::bit(bank, intid).0, u32::MAX);
        }
    }
    let priority = u32::from_ne_bytes([DEFAULT_PRIORITY; 4]);
    for intid in (0..lines).step_by(4) {
        write(&DIST, gic::byte(GICD_IPRIORITYR, intid).0, priority);
    }
    for intid in (FIRST_SPI..lines).step_by(4) {
        write(&DIST, gic::byte(GICD_ITARGETSR, intid).0, 0x0101_0101);
    }
    write(&DIST, GICD_CTLR, CTLR_ENABLE);
    write(&CPU, GICC_PMR, u32::from(PRIORITY_MASK));
    write(&CPU, GICC_CTLR, CTLR_ENABLE);
}

/// Sets the priority of one line; lower values are more urgent.
pub fn set_priority(intid: u32, priority: u8) {
    let (offset, shift) = gic::byte(GICD_IPRIORITYR, intid);
    let old = read(&DIST, offset);
    write(
        &DIST,
        offset,
        (old & !(0xFF << shift)) | (u32::from(priority) << shift),
    );
}

/// Lets the line reach the CPU interface.
pub fn unmask(intid: u32) {
    let (offset, bit) = gic::bit(GICD_ISENABLER, intid);
    write(&DIST, offset, bit);
}

/// Stops the line at the distributor; a pending interrupt stays pending.
pub fn mask(intid: u32) {
    let (offset, bit) = gic::bit(GICD_ICENABLER, intid);
    write(&DIST, offset, bit);
}

/// Makes the line edge-triggered, or level-triggered, in GICD_ICFGR
/// [G25]; the line is masked meanwhile (spec 9).
pub fn set_trigger(intid: u32, edge: bool) {
    let (offset, bit) = gic::cfg(intid);
    let old = read(&DIST, offset);
    write(&DIST, offset, if edge { old | bit } else { old & !bit });
}

/// The lines of the distributor (kcore::gic::lines).
pub fn lines() -> u32 {
    LINE_COUNT.load(Ordering::Relaxed)
}

/// Reads GICC_IAR once. The interrupt becomes active until `end`; None for
/// a spurious read, which needs no EOI.
#[must_use = "an acknowledged interrupt stays active until gic::end"]
pub fn acknowledge() -> Option<Ack> {
    Ack::from_iar(read(&CPU, GICC_IAR))
}

/// EOI: ends an acknowledged interrupt. A level-triggered source must be
/// quiet by now, or the line fires again at once.
pub fn end(ack: Ack) {
    write(&CPU, GICC_EOIR, ack.eoi_value());
}

/// Sleeps until an interrupt is pending at this CPU and acknowledges it.
/// PSTATE keeps interrupts masked, so none is taken; `wfi` ends all the
/// same. None when the wake-up brought nothing to acknowledge.
#[must_use = "an acknowledged interrupt stays active until gic::end"]
pub fn wait() -> Option<Ack> {
    // SAFETY: waiting for an interrupt has no side effects; the DSB lets
    // earlier stores (to the GIC and the timer) complete first.
    unsafe { core::arch::asm!("dsb sy", "wfi", options(nostack, preserves_flags)) };
    acknowledge()
}

#[cfg(feature = "ktest")]
pub use test_access::{is_active, is_edge, is_enabled, priority, priority_mask, set_pending};

/// What the kernel tests read and steer here (crate::ktest).
#[cfg(feature = "ktest")]
mod test_access {
    use super::*;

    fn test_bit(bank: usize, intid: u32) -> bool {
        let (offset, bit) = gic::bit(bank, intid);
        read(&DIST, offset) & bit != 0
    }

    pub fn is_active(intid: u32) -> bool {
        test_bit(kcore::gic::GICD_ISACTIVER, intid)
    }

    pub fn is_enabled(intid: u32) -> bool {
        test_bit(GICD_ISENABLER, intid)
    }

    /// Whether GICD_ICFGR makes the line edge-triggered.
    pub fn is_edge(intid: u32) -> bool {
        let (offset, bit) = gic::cfg(intid);
        read(&DIST, offset) & bit != 0
    }

    /// Makes the line pending at the distributor, as if its source had fired.
    pub fn set_pending(intid: u32) {
        let (offset, bit) = gic::bit(kcore::gic::GICD_ISPENDR, intid);
        write(&DIST, offset, bit);
    }

    /// This CPU interface's priority mask, GICC_PMR.
    pub fn priority_mask() -> u8 {
        read(&CPU, GICC_PMR) as u8
    }

    pub fn priority(intid: u32) -> u8 {
        let (offset, shift) = gic::byte(GICD_IPRIORITYR, intid);
        (read(&DIST, offset) >> shift) as u8
    }
}
