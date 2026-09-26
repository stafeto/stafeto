// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The register layout of the GICv2 (IHI 0048B) and the GICv3 (IHI 0069D,
//! [G39]) and the arithmetic on it. The driver that touches the registers
//! lives in the kernel.

// Distributor registers, offsets from its base.
pub const GICD_CTLR: usize = 0x000;
pub const GICD_TYPER: usize = 0x004;
/// GICv3: one bit per line, set for Group 1.
pub const GICD_IGROUPR: usize = 0x080;
pub const GICD_ISENABLER: usize = 0x100;
pub const GICD_ICENABLER: usize = 0x180;
pub const GICD_ISPENDR: usize = 0x200;
pub const GICD_ICPENDR: usize = 0x280;
pub const GICD_ISACTIVER: usize = 0x300;
pub const GICD_ICACTIVER: usize = 0x380;
pub const GICD_IPRIORITYR: usize = 0x400;
pub const GICD_ITARGETSR: usize = 0x800;
pub const GICD_ICFGR: usize = 0xC00;
/// GICv3: the CPU of each shared line, 64 bits per line.
pub const GICD_IROUTER: usize = 0x6000;

// CPU interface registers, offsets from its base.
pub const GICC_CTLR: usize = 0x000;
pub const GICC_PMR: usize = 0x004;
pub const GICC_IAR: usize = 0x00C;
pub const GICC_EOIR: usize = 0x010;

// GICv3 redistributor registers, offsets from its RD_base frame.
pub const GICR_CTLR: usize = 0x0000;
pub const GICR_TYPER: usize = 0x0008;
pub const GICR_WAKER: usize = 0x0014;
/// The SGI_base frame of a redistributor, from its RD_base: the registers
/// of SGIs and PPIs, at the offsets of the distributor's bank 0.
pub const SGI_FRAME: usize = 0x1_0000;

/// GICv3 GICD_CTLR: Register Write Pending, while a write to GICD_CTLR or
/// GICD_ICENABLER has not reached every part of the GIC.
pub const GICD_CTLR_RWP: u32 = 1 << 31;
/// GICv3 GICD_CTLR: affinity routing (ARE_NS, bit 4), Group 1 on (bit 1,
/// EnableGrp1A) and bit 0, which enables Group 1 in the non-secure view
/// and Group 0 with one security state.
pub const GICD_CTLR_V3: u32 = (1 << 4) | (1 << 1) | 1;
/// GICR_CTLR: Register Write Pending of the SGI frame's GICR_ICENABLER0.
pub const GICR_CTLR_RWP: u32 = 1 << 3;
/// GICR_WAKER: ProcessorSleep; while set, the redistributor forwards
/// nothing to the CPU interface.
pub const WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
/// GICR_WAKER: ChildrenAsleep, set until the redistributor is awake.
pub const WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;
/// GICR_TYPER: VLPIS, two more frames of 64 KiB per redistributor.
const TYPER_VLPIS: u64 = 1 << 1;
/// GICR_TYPER: Last, the last redistributor of its region.
const TYPER_LAST: u64 = 1 << 4;
/// The frames of one redistributor: RD_base and SGI_base, and the two of
/// vLPIs with VLPIS.
const REDISTRIBUTOR: u64 = 0x2_0000;
const REDISTRIBUTOR_VLPI: u64 = 0x4_0000;

/// ICC_SRE_EL1 and ICC_SRE_EL2: SRE, the CPU interface is reached through
/// system registers.
pub const ICC_SRE_SRE: u64 = 1;

/// GICD_CTLR and GICC_CTLR: forward interrupts. With the security
/// extensions (the A64's GIC-400) the non-secure view of this bit enables
/// Group 1, where the firmware has put every interrupt.
pub const CTLR_ENABLE: u32 = 1;

/// Priority the kernel gives every line. The low nibble stays clear: the
/// GIC-400 implements fewer than 8 priority bits, the non-secure view fewer
/// still.
pub const DEFAULT_PRIORITY: u8 = 0xA0;

/// GICC_PMR: only priorities numerically below it reach the CPU. It resets
/// to 0, which masks everything.
pub const PRIORITY_MASK: u8 = 0xF0;

/// INTIDs below this are SGIs (0..16) and PPIs (16..32), banked per CPU.
pub const FIRST_SPI: u32 = 32;

/// The EL1 virtual timer: PPI 11.
pub const VIRTUAL_TIMER_INTID: u32 = 27;

/// The line of the kernel's console, the PL011 of QEMU `virt` (SPI 1):
/// no program binds it until milestone 1.4 (spec 9).
pub const CONSOLE_INTID: u32 = 33;

/// The bytes at the start of the first redistributor region of a GICv3
/// that the kernel maps and searches for the redistributor of its CPU
/// (spec 9): two frames of 128 KiB, or one of 256 KiB with vLPIs. The
/// kernel runs on one CPU (spec 1.1), the first on every machine it boots.
pub const REDISTRIBUTOR_WINDOW: u64 = 0x4_0000;

/// GICC_IAR reads 1020..=1023 when there is nothing to acknowledge.
pub const FIRST_SPURIOUS: u32 = 1020;

const INTID_MASK: u32 = 0x3FF;

/// Number of interrupt lines, from GICD_TYPER.ITLinesNumber.
pub fn lines(typer: u32) -> u32 {
    (32 * ((typer & 0x1F) + 1)).min(FIRST_SPURIOUS)
}

/// Where the registers of a line are on a GICv3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame {
    Distributor,
    /// The SGI frame of the redistributor of this CPU (SGI_FRAME).
    Sgi,
}

/// The frame of `intid`'s registers on a GICv3: SGIs and PPIs are in the
/// SGI frame of the CPU's redistributor, at the offsets their bits have in
/// the distributor's bank 0 (`bit`, `byte`); shared lines stay in the
/// distributor.
pub fn frame(intid: u32) -> Frame {
    if intid < FIRST_SPI {
        Frame::Sgi
    } else {
        Frame::Distributor
    }
}

/// GICD_IROUTER.Interrupt_Routing_Mode: the line goes to any CPU.
pub const IROUTER_ANY: u64 = 1 << 31;

/// The GICD_IROUTER value that routes a shared line to the CPU of `mpidr`:
/// Aff3 [39:32] and Aff2..Aff0 [23:0] of MPIDR_EL1. Bit 31, which MPIDR_EL1
/// always has set, stays clear: in GICD_IROUTER it is IROUTER_ANY.
pub fn irouter(mpidr: u64) -> u64 {
    mpidr & 0xFF_00FF_FFFF
}

/// The affinity of the CPU of `mpidr` as GICR_TYPER [63:32] holds it:
/// Aff3.Aff2.Aff1.Aff0.
pub fn redistributor_affinity(mpidr: u64) -> u32 {
    (((mpidr >> 8) & 0xFF00_0000) | (mpidr & 0xFF_FFFF)) as u32
}

/// The offset of the RD_base frame of the redistributor of `affinity` in
/// the first `window` bytes of a redistributor region, whose GICR_TYPER at
/// an offset `read_typer` reads. The frames go by 128 KiB, or 256 KiB
/// when GICR_TYPER has VLPIS; the search stops at a GICR_TYPER with Last,
/// and at the end of the window, since a GIC may leave Last clear. None
/// when no frame whole in the window has the affinity. O(window / 128 KiB).
pub fn find_redistributor(
    mut read_typer: impl FnMut(u64) -> u64,
    window: u64,
    affinity: u32,
) -> Option<u64> {
    let mut at = 0;
    while at + REDISTRIBUTOR <= window {
        let typer = read_typer(at);
        if (typer >> 32) as u32 == affinity {
            return Some(at);
        }
        if typer & TYPER_LAST != 0 {
            return None;
        }
        at += if typer & TYPER_VLPIS != 0 {
            REDISTRIBUTOR_VLPI
        } else {
            REDISTRIBUTOR
        };
    }
    None
}

/// Offset and mask of `intid`'s bit in a bank of one-bit-per-line
/// registers starting at `bank` (ISENABLER, ICENABLER, ISPENDR and so on).
pub fn bit(bank: usize, intid: u32) -> (usize, u32) {
    (bank + 4 * (intid / 32) as usize, 1 << (intid % 32))
}

/// Offset of the 32-bit register that holds `intid`'s byte in a bank of
/// one-byte-per-line registers (IPRIORITYR, ITARGETSR), and the byte's shift.
pub fn byte(bank: usize, intid: u32) -> (usize, u32) {
    (bank + (intid & !3) as usize, 8 * (intid % 4))
}

/// Offset and mask of the bit of GICD_ICFGR that makes `intid` edge-triggered
/// when set and level-triggered when clear: bit 2·(n % 16) + 1 of the
/// register at 0xC00 + 4·(n / 16) [G25].
pub fn cfg(intid: u32) -> (usize, u32) {
    (
        GICD_ICFGR + 4 * (intid / 16) as usize,
        1 << (2 * (intid % 16) + 1),
    )
}

/// An acknowledged interrupt: the GICC_IAR value, which goes back to
/// GICC_EOIR unchanged. Not `Copy`, so one acknowledgement gets one EOI.
#[derive(Debug, PartialEq, Eq)]
pub struct Ack(u32);

impl Ack {
    /// None for a spurious IAR (INTID 1020..=1023): it needs no EOI.
    pub fn from_iar(iar: u32) -> Option<Ack> {
        (iar & INTID_MASK < FIRST_SPURIOUS).then_some(Ack(iar))
    }

    pub fn intid(&self) -> u32 {
        self.0 & INTID_MASK
    }

    /// The value to write to GICC_EOIR.
    pub fn eoi_value(self) -> u32 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_come_from_typer() {
        assert_eq!(lines(0), 32);
        assert_eq!(lines(8), 288);
        assert_eq!(lines(0xFFFF_FF1F), 1020);
    }

    #[test]
    fn one_bit_per_line_registers() {
        assert_eq!(bit(GICD_ISENABLER, 27), (0x100, 1 << 27));
        assert_eq!(bit(GICD_ISENABLER, 33), (0x104, 1 << 1));
        assert_eq!(bit(GICD_ICENABLER, 1019), (0x180 + 4 * 31, 1 << 27));
        assert_eq!(bit(GICD_ISACTIVER, 31), (0x300, 1 << 31));
    }

    #[test]
    fn one_byte_per_line_registers() {
        assert_eq!(byte(GICD_IPRIORITYR, 27), (0x418, 24));
        assert_eq!(byte(GICD_IPRIORITYR, 32), (0x420, 0));
        assert_eq!(byte(GICD_ITARGETSR, 33), (0x820, 8));
    }

    #[test]
    fn trigger_bit_is_2n_plus_1() {
        assert_eq!(cfg(32), (0xC08, 1 << 1));
        assert_eq!(cfg(47), (0xC08, 1 << 31));
        assert_eq!(cfg(48), (0xC0C, 1 << 1));
        assert_eq!(cfg(1019), (0xC00 + 4 * 63, 1 << 23));
    }

    #[test]
    fn an_acknowledged_interrupt_keeps_the_whole_iar_for_its_eoi() {
        let timer = Ack::from_iar(27).unwrap();
        assert_eq!(timer.intid(), 27);
        assert_eq!(timer.eoi_value(), 27);
        // An SGI's IAR carries the sending CPU in bits [12:10].
        let sgi = Ack::from_iar((3 << 10) | 1).unwrap();
        assert_eq!(sgi.intid(), 1);
        assert_eq!(sgi.eoi_value(), (3 << 10) | 1);
    }

    #[test]
    fn spurious_iar_values_get_no_ack() {
        for iar in FIRST_SPURIOUS..=1023 {
            assert_eq!(Ack::from_iar(iar), None);
        }
        assert_eq!(Ack::from_iar((1 << 10) | 1023), None);
        assert_eq!(Ack::from_iar(1019).map(|a| a.intid()), Some(1019));
    }

    #[test]
    fn priorities_pass_the_priority_mask() {
        const { assert!(DEFAULT_PRIORITY < PRIORITY_MASK) };
        const { assert!(DEFAULT_PRIORITY & 0x0F == 0 && PRIORITY_MASK & 0x0F == 0) };
    }

    #[test]
    fn irouter_takes_affinity_without_bit_31() {
        assert_eq!(irouter(0x8000_0000) & IROUTER_ANY, 0);
        assert_eq!(irouter(0x8000_0000), 0);
        assert_eq!(irouter(0x81_8003_0201), 0x81_0003_0201);
        assert_eq!(irouter(u64::MAX), 0xFF_00FF_FFFF);
    }

    #[test]
    fn redistributor_affinity_packs_four_levels() {
        assert_eq!(redistributor_affinity(0x8000_0000), 0);
        assert_eq!(redistributor_affinity(0x04_8003_0201), 0x0403_0201);
        assert_eq!(redistributor_affinity(0x8000_0001), 1);
    }

    /// GICR_TYPER of frames by 128 KiB with the affinities 0, 1, 2, Last
    /// on the third.
    fn three(at: u64) -> u64 {
        let n = at / REDISTRIBUTOR;
        (n << 32) | if n == 2 { TYPER_LAST } else { 0 }
    }

    #[test]
    fn redistributor_is_found_by_affinity() {
        assert_eq!(find_redistributor(three, 0x4_0000, 0), Some(0));
        assert_eq!(find_redistributor(three, 0x4_0000, 1), Some(0x2_0000));
        assert_eq!(find_redistributor(three, 0x6_0000, 2), Some(0x4_0000));
        assert_eq!(find_redistributor(three, 1 << 30, 3), None);
    }

    /// HVF's GIC reads GICR_TYPER as 0: affinity 0, Last clear.
    #[test]
    fn redistributor_search_stops_at_the_window_end() {
        assert_eq!(find_redistributor(|_| 0, 0x4_0000, 0), Some(0));
        let mut read = Vec::new();
        let found = find_redistributor(
            |at| {
                assert!(at < 0x4_0000, "a read past the window at {at:#x}");
                read.push(at);
                0
            },
            0x4_0000,
            1,
        );
        assert_eq!(found, None);
        assert_eq!(read, [0, 0x2_0000]);
        assert_eq!(find_redistributor(|_| 0, 0x1_F000, 0), None);
    }

    #[test]
    fn redistributor_search_steps_256k_with_vlpis() {
        let vlpis = |at: u64| ((at / REDISTRIBUTOR_VLPI) << 32) | TYPER_VLPIS;
        assert_eq!(find_redistributor(vlpis, 0x8_0000, 1), Some(0x4_0000));
        let mut read = Vec::new();
        let _ = find_redistributor(
            |at| {
                read.push(at);
                vlpis(at)
            },
            0x8_0000,
            5,
        );
        assert_eq!(read, [0, 0x4_0000]);
    }

    /// On a GICv3 the registers of SGIs and PPIs sit in the SGI frame at
    /// the offsets of the distributor's bank 0: GICR_ISENABLER0 0x100,
    /// GICR_ICENABLER0 0x180, GICR_IPRIORITYR7 0x41C.
    #[test]
    fn private_lines_use_the_bank_0_offsets() {
        for intid in [0, 16, VIRTUAL_TIMER_INTID, FIRST_SPI - 1] {
            assert_eq!(frame(intid), Frame::Sgi, "{intid}");
        }
        for intid in [FIRST_SPI, CONSOLE_INTID, FIRST_SPURIOUS - 1] {
            assert_eq!(frame(intid), Frame::Distributor, "{intid}");
        }
        assert_eq!(bit(GICD_ISENABLER, VIRTUAL_TIMER_INTID).0, 0x100);
        assert_eq!(bit(GICD_ICENABLER, 31).0, 0x180);
        assert_eq!(bit(GICD_IGROUPR, 0).0, 0x080);
        assert_eq!(byte(GICD_IPRIORITYR, 31).0, 0x41C);
    }
}
