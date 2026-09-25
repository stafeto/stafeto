// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! GICv2 driver (spec 9): the distributor and this CPU's interface, reached
//! through the linear map at the addresses from the device tree. Inside the
//! kernel PSTATE keeps interrupts masked (spec 8.1): the kernel sleeps in
//! `wfi`, which a pending interrupt ends all the same, and acknowledges the
//! interrupt itself through GICC_IAR.

use core::sync::atomic::{AtomicUsize, Ordering};
use kcore::bootinfo::BootInfo;
use kcore::gic::{
    self, Ack, CTLR_ENABLE, DEFAULT_PRIORITY, FIRST_SPI, GICC_CTLR, GICC_EOIR, GICC_IAR, GICC_PMR,
    GICD_CTLR, GICD_ICACTIVER, GICD_ICENABLER, GICD_ICPENDR, GICD_IPRIORITYR, GICD_ISENABLER,
    GICD_ITARGETSR, GICD_TYPER, PRIORITY_MASK,
};
use kcore::layout::LINEAR_BASE;

/// Virtual addresses of the distributor and the CPU interface; zero until `init`.
static DIST: AtomicUsize = AtomicUsize::new(0);
static CPU: AtomicUsize = AtomicUsize::new(0);

fn reg(base: &AtomicUsize, offset: usize) -> *mut u32 {
    let base = base.load(Ordering::Relaxed);
    assert!(base != 0, "the GIC is used before gic::init");
    (base + offset) as *mut u32
}

fn read(base: &AtomicUsize, offset: usize) -> u32 {
    // SAFETY: `init` stored the base of a GIC block the kernel tables map as
    // device memory; the offsets are registers of that block.
    unsafe { reg(base, offset).read_volatile() }
}

fn write(base: &AtomicUsize, offset: usize, value: u32) {
    // SAFETY: as in `read`.
    unsafe { reg(base, offset).write_volatile(value) }
}

/// Resets the distributor and this CPU's interface and turns both on: every
/// line masked, not pending, not active, at DEFAULT_PRIORITY; shared lines
/// go to CPU 0; the priority mask lets DEFAULT_PRIORITY through.
pub fn init(info: &BootInfo) {
    let dist = info
        .gic_distributor
        .expect("no GIC distributor in the device tree");
    let cpu = info
        .gic_cpu_interface
        .expect("no GIC CPU interface in the device tree");
    DIST.store(LINEAR_BASE + dist.base as usize, Ordering::Relaxed);
    CPU.store(LINEAR_BASE + cpu.base as usize, Ordering::Relaxed);
    write(&DIST, GICD_CTLR, 0);
    let lines = gic::lines(read(&DIST, GICD_TYPER));
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
#[cfg_attr(
    not(feature = "ktest"),
    expect(
        dead_code,
        reason = "lines bound to channels (milestone 1.3) are masked; so far only the kernel tests do"
    )
)]
pub fn mask(intid: u32) {
    let (offset, bit) = gic::bit(GICD_ICENABLER, intid);
    write(&DIST, offset, bit);
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
fn test_bit(bank: usize, intid: u32) -> bool {
    let (offset, bit) = gic::bit(bank, intid);
    read(&DIST, offset) & bit != 0
}

#[cfg(feature = "ktest")]
pub fn is_active(intid: u32) -> bool {
    test_bit(kcore::gic::GICD_ISACTIVER, intid)
}

#[cfg(feature = "ktest")]
pub fn is_enabled(intid: u32) -> bool {
    test_bit(GICD_ISENABLER, intid)
}

/// Makes the line pending at the distributor, as if its source had fired.
#[cfg(feature = "ktest")]
pub fn set_pending(intid: u32) {
    let (offset, bit) = gic::bit(kcore::gic::GICD_ISPENDR, intid);
    write(&DIST, offset, bit);
}

#[cfg(feature = "ktest")]
pub fn priority(intid: u32) -> u8 {
    let (offset, shift) = gic::byte(GICD_IPRIORITYR, intid);
    (read(&DIST, offset) >> shift) as u8
}
