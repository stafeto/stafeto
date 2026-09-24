// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The GICv2 register layout (IHI 0048B) and the arithmetic on it. The
//! driver that touches the registers lives in the kernel.

// Distributor registers, offsets from its base.
pub const GICD_CTLR: usize = 0x000;
pub const GICD_TYPER: usize = 0x004;
pub const GICD_ISENABLER: usize = 0x100;
pub const GICD_ICENABLER: usize = 0x180;
pub const GICD_ISPENDR: usize = 0x200;
pub const GICD_ICPENDR: usize = 0x280;
pub const GICD_ISACTIVER: usize = 0x300;
pub const GICD_ICACTIVER: usize = 0x380;
pub const GICD_IPRIORITYR: usize = 0x400;
pub const GICD_ITARGETSR: usize = 0x800;

// CPU interface registers, offsets from its base.
pub const GICC_CTLR: usize = 0x000;
pub const GICC_PMR: usize = 0x004;
pub const GICC_IAR: usize = 0x00C;
pub const GICC_EOIR: usize = 0x010;

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

/// GICC_IAR reads 1020..=1023 when there is nothing to acknowledge.
pub const FIRST_SPURIOUS: u32 = 1020;

const INTID_MASK: u32 = 0x3FF;

/// Number of interrupt lines, from GICD_TYPER.ITLinesNumber.
pub fn lines(typer: u32) -> u32 {
    (32 * ((typer & 0x1F) + 1)).min(FIRST_SPURIOUS)
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
}
