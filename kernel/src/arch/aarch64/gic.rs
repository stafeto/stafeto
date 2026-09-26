// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! GIC driver (spec 9), GICv2 or GICv3 as the device tree names it: the
//! distributor, and this CPU's interface (GICv2) or redistributor and
//! system registers (GICv3), reached through the linear map at the
//! addresses from the device tree. Inside the kernel PSTATE keeps
//! interrupts masked (spec 8.1): the kernel sleeps in `wfi`, which a
//! pending interrupt ends all the same, and acknowledges the interrupt
//! itself.

use super::mmio;
use super::registers::{self, read_sysreg};
use core::arch::asm;
use core::ops::Range;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use kcore::bootinfo::{BootInfo, GicVersion, Region};
use kcore::gic::{
    self, Ack, CTLR_ENABLE, DEFAULT_PRIORITY, FIRST_SPI, Frame, GICC_CTLR, GICC_EOIR, GICC_IAR,
    GICC_PMR, GICD_CTLR, GICD_CTLR_RWP, GICD_CTLR_V3, GICD_ICACTIVER, GICD_ICENABLER, GICD_ICPENDR,
    GICD_IGROUPR, GICD_IPRIORITYR, GICD_IROUTER, GICD_ISENABLER, GICD_ITARGETSR, GICD_TYPER,
    GICR_CTLR, GICR_CTLR_RWP, GICR_TYPER, GICR_WAKER, ICC_SRE_SRE, PRIORITY_MASK, SGI_FRAME,
    WAKER_CHILDREN_ASLEEP, WAKER_PROCESSOR_SLEEP,
};
use kcore::layout::LINEAR_BASE;

/// Whether `init` found a GICv3 in the device tree.
static V3: AtomicBool = AtomicBool::new(false);
/// Virtual addresses of the distributor, and of the CPU interface (GICv2)
/// or this CPU's redistributor, its RD_base frame (GICv3); zero until
/// `init`.
static DIST: AtomicUsize = AtomicUsize::new(0);
static CPU: AtomicUsize = AtomicUsize::new(0);
/// The lines of the distributor, from GICD_TYPER at `init`.
static LINE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Polls of a Register Write Pending or a waking redistributor before the
/// kernel gives the GIC up: only a broken GIC takes that long.
const POLLS: u32 = 1_000_000;

fn kind() -> GicVersion {
    if V3.load(Ordering::Relaxed) {
        GicVersion::V3
    } else {
        GicVersion::V2
    }
}

fn base(block: &AtomicUsize) -> usize {
    let base = block.load(Ordering::Relaxed);
    assert!(base != 0, "the GIC is used before gic::init");
    base
}

fn read(at: usize) -> u32 {
    // SAFETY: `init` stored the base of a GIC block the kernel tables map as
    // device memory; `at` is a register of that block.
    unsafe { mmio::read32(at) }
}

fn write(at: usize, value: u32) {
    // SAFETY: as in `read`.
    unsafe { mmio::write32(at, value) }
}

/// Writes a system register of the GICv3 CPU interface; the ISB makes the
/// write take effect before the next instruction [G15].
macro_rules! write_icc {
    ($name:literal, $value:expr) => {
        // SAFETY: the GICv3 CPU interface affects only interrupts, which
        // PSTATE masks in the kernel.
        unsafe {
            asm!(concat!("msr ", $name, ", {}"), "isb", in(reg) u64::from($value), options(nostack, preserves_flags))
        }
    };
}

/// Polls the register at `at` until `bits` are clear; a GIC that keeps
/// them set stops the kernel, naming the register.
fn wait_clear(at: usize, bits: u32, what: &str) {
    for _ in 0..POLLS {
        if read(at) & bits == 0 {
            return;
        }
    }
    panic!("the GIC keeps {what} set");
}

/// The block of `intid`'s registers: the distributor, or on a GICv3 for
/// SGIs and PPIs the SGI frame of this CPU's redistributor
/// (kcore::gic::frame).
fn block(intid: u32) -> usize {
    match (kind(), gic::frame(intid)) {
        (GicVersion::V3, Frame::Sgi) => base(&CPU) + SGI_FRAME,
        _ => base(&DIST),
    }
}

/// Resets the GIC and turns it on, as the device tree names it (spec 9):
/// every line masked, not pending, not active, at DEFAULT_PRIORITY; shared
/// lines go to this CPU; the priority mask lets DEFAULT_PRIORITY through.
/// Runs once, at boot.
pub fn init(info: &BootInfo) {
    let gic = info.gic.expect("no GIC in the device tree");
    let [dist, cpu] = gic.mapped();
    assert!(DIST.load(Ordering::Relaxed) == 0, "gic::init runs once");
    V3.store(gic.version == GicVersion::V3, Ordering::Relaxed);
    DIST.store(LINEAR_BASE + dist.base as usize, Ordering::Relaxed);
    match gic.version {
        GicVersion::V2 => init_v2(cpu),
        GicVersion::V3 => init_v3(cpu),
    }
}

/// Masks the `intids` of the block at `at`, clears them pending and
/// active and gives them DEFAULT_PRIORITY.
fn reset_lines(at: usize, intids: Range<u32>) {
    for intid in intids.clone().step_by(32) {
        for bank in [GICD_ICENABLER, GICD_ICPENDR, GICD_ICACTIVER] {
            write(at + gic::bit(bank, intid).0, u32::MAX);
        }
    }
    let priority = u32::from_ne_bytes([DEFAULT_PRIORITY; 4]);
    for intid in intids.step_by(4) {
        write(at + gic::byte(GICD_IPRIORITYR, intid).0, priority);
    }
}

/// GICv2 [G25]: the distributor, then the CPU interface at `cpu`.
fn init_v2(cpu: Region) {
    let dist = base(&DIST);
    CPU.store(LINEAR_BASE + cpu.base as usize, Ordering::Relaxed);
    write(dist + GICD_CTLR, 0);
    let lines = gic::lines(read(dist + GICD_TYPER));
    LINE_COUNT.store(lines, Ordering::Relaxed);
    reset_lines(dist, 0..lines);
    for intid in (FIRST_SPI..lines).step_by(4) {
        write(dist + gic::byte(GICD_ITARGETSR, intid).0, 0x0101_0101);
    }
    write(dist + GICD_CTLR, CTLR_ENABLE);
    let cpu = base(&CPU);
    write(cpu + GICC_PMR, u32::from(PRIORITY_MASK));
    write(cpu + GICC_CTLR, CTLR_ENABLE);
}

/// GICv3 [G39]: the distributor, with every line in Group 1 and the shared
/// ones routed to this CPU; this CPU's redistributor, found by its
/// affinity in `redistributors`, the first REDISTRIBUTOR_WINDOW bytes of
/// the first redistributor region, and woken; then the CPU interface
/// through its system registers, which head.S opened at EL2.
fn init_v3(redistributors: Region) {
    let dist = base(&DIST);
    write(dist + GICD_CTLR, 0);
    wait_clear(dist + GICD_CTLR, GICD_CTLR_RWP, "GICD_CTLR.RWP");
    let lines = gic::lines(read(dist + GICD_TYPER));
    LINE_COUNT.store(lines, Ordering::Relaxed);
    let mpidr = registers::mpidr_el1();
    for intid in (FIRST_SPI..lines).step_by(32) {
        write(dist + gic::bit(GICD_IGROUPR, intid).0, u32::MAX);
    }
    reset_lines(dist, FIRST_SPI..lines);
    write(dist + GICD_CTLR, GICD_CTLR_V3);
    wait_clear(dist + GICD_CTLR, GICD_CTLR_RWP, "GICD_CTLR.RWP");
    // Routes only after ARE_NS is on: GICD_IROUTER is RES0 while affinity
    // routing is off, and UNKNOWN once it is turned on (IHI 0069D 8.9.13).
    for intid in FIRST_SPI..lines {
        let at = dist + GICD_IROUTER + 8 * intid as usize;
        // SAFETY: GICD_IROUTER is a 64-bit register of the distributor.
        unsafe { mmio::write64(at, gic::irouter(mpidr)) };
    }
    let window = LINEAR_BASE + redistributors.base as usize;
    let typer = |at: u64| {
        // SAFETY: the kernel tables map the window; GICR_TYPER is a 64-bit
        // register of each RD_base frame in it.
        unsafe { mmio::read64(window + at as usize + GICR_TYPER) }
    };
    let affinity = gic::redistributor_affinity(mpidr);
    let rd = gic::find_redistributor(typer, redistributors.size, affinity)
        .expect("no redistributor for this CPU in the first 256 KiB");
    let rd = window + rd as usize;
    CPU.store(rd, Ordering::Relaxed);
    write(
        rd + GICR_WAKER,
        read(rd + GICR_WAKER) & !WAKER_PROCESSOR_SLEEP,
    );
    wait_clear(
        rd + GICR_WAKER,
        WAKER_CHILDREN_ASLEEP,
        "GICR_WAKER.ChildrenAsleep",
    );
    write(rd + SGI_FRAME + GICD_IGROUPR, u32::MAX);
    reset_lines(rd + SGI_FRAME, 0..FIRST_SPI);
    wait_clear(rd + GICR_CTLR, GICR_CTLR_RWP, "GICR_CTLR.RWP");
    let sre = read_sysreg!("icc_sre_el1");
    write_icc!("icc_sre_el1", sre | ICC_SRE_SRE);
    assert!(
        read_sysreg!("icc_sre_el1") & ICC_SRE_SRE != 0,
        "GICv3 system registers are off"
    );
    write_icc!("icc_pmr_el1", PRIORITY_MASK);
    write_icc!("icc_bpr1_el1", 0u8);
    write_icc!("icc_ctlr_el1", 0u8);
    let priority_bits = ((read_sysreg!("icc_ctlr_el1") >> 8) & 7) + 1;
    write_icc!("icc_ap1r0_el1", 0u8);
    if priority_bits >= 6 {
        write_icc!("icc_ap1r1_el1", 0u8);
    }
    if priority_bits >= 7 {
        write_icc!("icc_ap1r2_el1", 0u8);
        write_icc!("icc_ap1r3_el1", 0u8);
    }
    write_icc!("icc_igrpen1_el1", 1u8);
}

/// Sets the priority of one line; lower values are more urgent.
pub fn set_priority(intid: u32, priority: u8) {
    let (offset, shift) = gic::byte(GICD_IPRIORITYR, intid);
    let at = block(intid) + offset;
    write(
        at,
        (read(at) & !(0xFF << shift)) | (u32::from(priority) << shift),
    );
}

/// Lets the line reach the CPU interface.
pub fn unmask(intid: u32) {
    let (offset, bit) = gic::bit(GICD_ISENABLER, intid);
    write(block(intid) + offset, bit);
}

/// Stops the line at the distributor or the redistributor; a pending
/// interrupt stays pending. On a GICv3 it returns once the GIC has seen
/// the write (RWP): an EOI through a system register is not ordered after
/// a write to device memory.
pub fn mask(intid: u32) {
    let (offset, bit) = gic::bit(GICD_ICENABLER, intid);
    let at = block(intid);
    write(at + offset, bit);
    if kind() == GicVersion::V3 {
        match gic::frame(intid) {
            Frame::Distributor => wait_clear(at + GICD_CTLR, GICD_CTLR_RWP, "GICD_CTLR.RWP"),
            Frame::Sgi => wait_clear(base(&CPU) + GICR_CTLR, GICR_CTLR_RWP, "GICR_CTLR.RWP"),
        }
    }
}

/// Makes the line edge-triggered, or level-triggered, in GICD_ICFGR
/// [G25]; the line is masked meanwhile (spec 9).
pub fn set_trigger(intid: u32, edge: bool) {
    let (offset, bit) = gic::cfg(intid);
    let at = block(intid) + offset;
    let old = read(at);
    write(at, if edge { old | bit } else { old & !bit });
}

/// The lines of the distributor (kcore::gic::lines).
pub fn lines() -> u32 {
    LINE_COUNT.load(Ordering::Relaxed)
}

/// Acknowledges once: GICC_IAR, or ICC_IAR1_EL1 on a GICv3. The interrupt
/// becomes active until `end`; None for a spurious read, which needs no
/// EOI.
#[must_use = "an acknowledged interrupt stays active until gic::end"]
pub fn acknowledge() -> Option<Ack> {
    let iar = match kind() {
        GicVersion::V2 => read(base(&CPU) + GICC_IAR),
        GicVersion::V3 => {
            let iar: u64;
            // SAFETY: reading ICC_IAR1_EL1 acknowledges the interrupt, as
            // the caller asks; the DSB completes the read before the
            // handler touches the device.
            unsafe {
                asm!("mrs {}, icc_iar1_el1", "dsb sy", out(reg) iar, options(nostack, preserves_flags))
            };
            iar as u32
        }
    };
    Ack::from_iar(iar)
}

/// EOI: ends an acknowledged interrupt, its priority drop and its
/// deactivation at once. A level-triggered source must be quiet by now, or
/// the line fires again at once.
pub fn end(ack: Ack) {
    match kind() {
        GicVersion::V2 => write(base(&CPU) + GICC_EOIR, ack.eoi_value()),
        GicVersion::V3 => write_icc!("icc_eoir1_el1", ack.eoi_value()),
    }
}

/// Sleeps until an interrupt is pending at this CPU and acknowledges it.
/// PSTATE keeps interrupts masked, so none is taken; `wfi` ends all the
/// same. None when the wake-up brought nothing to acknowledge.
#[must_use = "an acknowledged interrupt stays active until gic::end"]
pub fn wait() -> Option<Ack> {
    // SAFETY: waiting for an interrupt has no side effects; the DSB lets
    // earlier stores (to the GIC and the timer) complete first.
    unsafe { asm!("dsb sy", "wfi", options(nostack, preserves_flags)) };
    acknowledge()
}

#[cfg(feature = "ktest")]
pub use test_access::{
    control, cpu_interfaces, is_active, is_edge, is_enabled, is_group_1, priority, priority_mask,
    route, set_pending, version, waker,
};

/// What the kernel tests read and steer here (crate::ktest).
#[cfg(feature = "ktest")]
mod test_access {
    use super::*;

    fn test_bit(bank: usize, intid: u32) -> bool {
        let (offset, bit) = gic::bit(bank, intid);
        read(block(intid) + offset) & bit != 0
    }

    pub fn version() -> GicVersion {
        kind()
    }

    /// GICD_CTLR.
    pub fn control() -> u32 {
        read(base(&DIST) + GICD_CTLR)
    }

    pub fn is_active(intid: u32) -> bool {
        test_bit(kcore::gic::GICD_ISACTIVER, intid)
    }

    pub fn is_enabled(intid: u32) -> bool {
        test_bit(GICD_ISENABLER, intid)
    }

    /// Whether GICD_IGROUPR or GICR_IGROUPR0 puts the line in Group 1.
    pub fn is_group_1(intid: u32) -> bool {
        test_bit(GICD_IGROUPR, intid)
    }

    /// Whether GICD_ICFGR makes the line edge-triggered.
    pub fn is_edge(intid: u32) -> bool {
        let (offset, bit) = gic::cfg(intid);
        read(block(intid) + offset) & bit != 0
    }

    /// Makes the line pending, as if its source had fired.
    pub fn set_pending(intid: u32) {
        let (offset, bit) = gic::bit(kcore::gic::GICD_ISPENDR, intid);
        write(block(intid) + offset, bit);
    }

    /// This CPU interface's priority mask: GICC_PMR, or ICC_PMR_EL1.
    pub fn priority_mask() -> u8 {
        match kind() {
            GicVersion::V2 => read(base(&CPU) + GICC_PMR) as u8,
            GicVersion::V3 => read_sysreg!("icc_pmr_el1") as u8,
        }
    }

    pub fn priority(intid: u32) -> u8 {
        let (offset, shift) = gic::byte(GICD_IPRIORITYR, intid);
        (read(block(intid) + offset) >> shift) as u8
    }

    /// Where a shared line goes: its byte of GICD_ITARGETSR, or its
    /// GICD_IROUTER.
    pub fn route(intid: u32) -> u64 {
        let dist = base(&DIST);
        match kind() {
            GicVersion::V2 => {
                let (offset, shift) = gic::byte(GICD_ITARGETSR, intid);
                u64::from((read(dist + offset) >> shift) as u8)
            }
            // SAFETY: GICD_IROUTER is a 64-bit register of the distributor.
            GicVersion::V3 => unsafe { mmio::read64(dist + GICD_IROUTER + 8 * intid as usize) },
        }
    }

    /// The CPU interfaces of a GICv2: GICD_TYPER.CPUNumber + 1.
    pub fn cpu_interfaces() -> u32 {
        ((read(base(&DIST) + GICD_TYPER) >> 5) & 7) + 1
    }

    /// GICR_WAKER of this CPU's redistributor (GICv3).
    pub fn waker() -> u32 {
        read(base(&CPU) + GICR_WAKER)
    }
}
