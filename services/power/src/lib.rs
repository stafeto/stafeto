// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the service of the power button decides, apart from the device and the calls it makes.
//!
//! The button is pin 3 of the Arm PL061 GPIO block: on EC2 (Graviton) the block is `ARMH0061`
//! at 0x0903_0000 with the interrupt GSIV 39 (level), and its `_AEI` names pin 3 as a
//! rising-edge GpioInt that the DSDT turns into a notification of the power button (`_E03`);
//! QEMU `virt` has the same block, wired the same way, when no firmware with ACPI is loaded.
//! The register offsets are those of the PL061 TRM (the GPIO registers from 0x400) and of the
//! Linux driver drivers/gpio/gpio-pl061.c (GPIOIS 0x404, GPIOIBE 0x408, GPIOIEV 0x40C, GPIOIE
//! 0x410, GPIOMIS 0x418, GPIOIC 0x41C); the rising-edge setup is the driver's `pl061_irq_type`
//! (IS and IBE clear, IEV set) and the acknowledgement of an edge a write of the pin's bit to
//! GPIOIC. Everything here builds for the host, where `cargo test -p power` exercises it.

#![cfg_attr(not(test), no_std)]

/// The bytes of the register window: one page.
pub const PAGE: usize = 4096;
/// The base of the block on EC2 and on QEMU `virt`.
pub const BASE: u64 = 0x0903_0000;
/// The interrupt line of the block (GIC INTID 39 = SPI 7), level-triggered.
pub const LINE: u32 = 39;
/// The pin of the power button.
pub const PIN: u32 = 3;
/// The bit of the pin in every pin register.
pub const MASK: u32 = 1 << PIN;

/// GPIOIS: 0 detects an edge, 1 a level.
pub const GPIOIS: usize = 0x404;
/// GPIOIBE: 1 detects both edges (overrides GPIOIEV).
pub const GPIOIBE: usize = 0x408;
/// GPIOIEV: with an edge, 1 for the rising edge.
pub const GPIOIEV: usize = 0x40C;
/// GPIOIE: the interrupt mask, 1 enables the pin.
pub const GPIOIE: usize = 0x410;
/// GPIOMIS: the masked interrupt status.
pub const GPIOMIS: usize = 0x418;
/// GPIOIC: a write of 1 clears the edge interrupt of the pin.
pub const GPIOIC: usize = 0x41C;

/// The configuration registers of the block that the service writes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub is: u32,
    pub ibe: u32,
    pub iev: u32,
    pub ie: u32,
}

/// The registers with the button's pin set to the rising edge and masked: IS and IBE clear,
/// IEV set, IE clear. The other pins keep their bits, so the service leaves them alone.
pub const fn edge_masked(c: Config) -> Config {
    Config {
        is: c.is & !MASK,
        ibe: c.ibe & !MASK,
        iev: c.iev | MASK,
        ie: c.ie & !MASK,
    }
}

/// `ie` with the button's pin enabled and no other pin changed.
pub const fn enabled(ie: u32) -> u32 {
    ie | MASK
}

/// `ie` with the button's pin disabled and no other pin changed.
pub const fn disabled(ie: u32) -> u32 {
    ie & !MASK
}

/// Whether the masked status GPIOMIS shows the button.
pub const fn pressed(mis: u32) -> bool {
    mis & MASK != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A model of the block's registers that the service touches: an edge on a pin latches
    /// its raw status when the pin detects that edge, and GPIOMIS shows the latched status
    /// of the enabled pins.
    #[derive(Default)]
    struct Pl061 {
        config: Config,
        ris: u32,
        level: u32,
    }

    impl Pl061 {
        fn write(&mut self, offset: usize, value: u32) {
            let value = value & 0xFF;
            match offset {
                GPIOIS => self.config.is = value,
                GPIOIBE => self.config.ibe = value,
                GPIOIEV => self.config.iev = value,
                GPIOIE => self.config.ie = value,
                GPIOIC => self.ris &= !value,
                other => panic!("the service writes {other:#x}"),
            }
        }

        fn read(&self, offset: usize) -> u32 {
            match offset {
                GPIOIS => self.config.is,
                GPIOIBE => self.config.ibe,
                GPIOIEV => self.config.iev,
                GPIOIE => self.config.ie,
                GPIOMIS => self.ris & self.config.ie,
                other => panic!("the service reads {other:#x}"),
            }
        }

        /// The pin goes to `high`; an edge the pin detects latches.
        fn drive(&mut self, pin: u32, high: bool) {
            let bit = 1 << pin;
            let was = self.level & bit != 0;
            if high {
                self.level |= bit;
            } else {
                self.level &= !bit;
            }
            let rising = high && !was;
            let falling = !high && was;
            let edge_mode = self.config.is & bit == 0;
            let both = self.config.ibe & bit != 0;
            let wants_rising = self.config.iev & bit != 0;
            if edge_mode
                && ((rising && (both || wants_rising)) || (falling && (both || !wants_rising)))
            {
                self.ris |= bit;
            }
        }
    }

    /// The setup the service writes, in its order.
    fn setup(device: &mut Pl061) {
        let c = edge_masked(Config {
            is: device.read(GPIOIS),
            ibe: device.read(GPIOIBE),
            iev: device.read(GPIOIEV),
            ie: device.read(GPIOIE),
        });
        device.write(GPIOIE, c.ie);
        device.write(GPIOIS, c.is);
        device.write(GPIOIBE, c.ibe);
        device.write(GPIOIEV, c.iev);
        device.write(GPIOIC, MASK);
        let ie = device.read(GPIOIE);
        device.write(GPIOIE, enabled(ie));
    }

    #[test]
    fn the_pin_and_its_mask_are_the_buttons() {
        assert_eq!(PIN, 3);
        assert_eq!(MASK, 0x08);
        assert_eq!(LINE, 32 + 7);
    }

    #[test]
    fn the_offsets_are_those_of_the_pl061() {
        assert_eq!(
            [GPIOIS, GPIOIBE, GPIOIEV, GPIOIE, GPIOMIS, GPIOIC],
            [0x404, 0x408, 0x40C, 0x410, 0x418, 0x41C]
        );
        for offset in [GPIOIS, GPIOIBE, GPIOIEV, GPIOIE, GPIOMIS, GPIOIC] {
            assert!(offset % 4 == 0 && offset + 4 <= PAGE);
        }
    }

    #[test]
    fn the_edge_setup_changes_the_buttons_pin_only() {
        let before = Config {
            is: 0xF7,
            ibe: 0xFF,
            iev: 0x00,
            ie: 0xA8,
        };
        let after = edge_masked(before);
        assert_eq!(after.is, 0xF7 & !MASK);
        assert_eq!(after.ibe, 0xFF & !MASK);
        assert_eq!(after.iev, MASK);
        assert_eq!(after.ie, 0xA0);
        // Pin 4 (the sleep button of the DSDT) keeps whatever it had.
        let other = Config {
            is: 0x10,
            ibe: 0x10,
            iev: 0x10,
            ie: 0x10,
        };
        let changed = edge_masked(other);
        for (a, b) in [
            (changed.is, other.is),
            (changed.ibe, other.ibe),
            (changed.iev, other.iev),
            (changed.ie, other.ie),
        ] {
            assert_eq!(a & 0x10, b & 0x10);
        }
        assert_eq!(enabled(0x10), 0x18);
        assert_eq!(disabled(0x18), 0x10);
        assert!(pressed(0x08) && pressed(0xFF) && !pressed(0xF7) && !pressed(0));
    }

    #[test]
    fn a_press_raises_the_status_once_and_the_clear_drops_it() {
        let mut device = Pl061::default();
        setup(&mut device);
        assert_eq!(device.read(GPIOIE), MASK);
        assert!(!pressed(device.read(GPIOMIS)));
        // QEMU's gpio-key: the line goes high, and low 100 ms later.
        device.drive(PIN, true);
        assert!(pressed(device.read(GPIOMIS)));
        device.write(GPIOIC, MASK);
        assert!(!pressed(device.read(GPIOMIS)));
        // The falling edge is not the button.
        device.drive(PIN, false);
        assert!(!pressed(device.read(GPIOMIS)));
    }

    #[test]
    fn pin_4_is_not_enabled_and_does_not_show() {
        let mut device = Pl061::default();
        setup(&mut device);
        device.config.iev |= 1 << 4;
        device.drive(4, true);
        assert!(!pressed(device.read(GPIOMIS)));
        assert_eq!(device.read(GPIOMIS), 0);
        assert_eq!(device.read(GPIOIE), MASK);
    }

    #[test]
    fn an_edge_that_came_before_the_enable_is_cleared_by_the_setup() {
        let mut device = Pl061::default();
        device.config.iev = MASK;
        device.drive(PIN, true);
        device.drive(PIN, false);
        assert_eq!(device.ris & MASK, MASK);
        setup(&mut device);
        assert_eq!(device.ris & MASK, 0);
    }
}
