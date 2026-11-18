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

/// GPIODIR: 1 makes the pin an output, 0 an input.
pub const GPIODIR: usize = 0x400;
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

/// The detection registers of the block that the service writes for its pin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub is: u32,
    pub ibe: u32,
    pub iev: u32,
}

/// The registers with the button's pin set to the rising edge: IS and IBE clear, IEV set. The
/// other pins keep their bits.
pub const fn rising_edge(c: Config) -> Config {
    Config {
        is: c.is & !MASK,
        ibe: c.ibe & !MASK,
        iev: c.iev | MASK,
    }
}

/// GPIODIR with the button's pin an input; the other pins keep their direction.
pub const fn input(dir: u32) -> u32 {
    dir & !MASK
}

/// What the set-up writes to GPIOIE: the button's pin alone, whatever bits the firmware left
/// (a pin of the block with its interrupt enabled and an edge latched would hold the level line
/// high with no one to clear it).
pub const ENABLE: u32 = MASK;
/// What the set-up writes to GPIOIC before it enables the pin: every pending edge of the block.
pub const CLEAR_ALL: u32 = 0xFF;

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
        dir: u32,
        config: Config,
        ie: u32,
        ris: u32,
        level: u32,
    }

    impl Pl061 {
        fn write(&mut self, offset: usize, value: u32) {
            let value = value & 0xFF;
            match offset {
                GPIODIR => self.dir = value,
                GPIOIS => self.config.is = value,
                GPIOIBE => self.config.ibe = value,
                GPIOIEV => self.config.iev = value,
                GPIOIE => self.ie = value,
                GPIOIC => self.ris &= !value,
                other => panic!("the service writes {other:#x}"),
            }
        }

        fn read(&self, offset: usize) -> u32 {
            match offset {
                GPIODIR => self.dir,
                GPIOIS => self.config.is,
                GPIOIBE => self.config.ibe,
                GPIOIEV => self.config.iev,
                GPIOIE => self.ie,
                GPIOMIS => self.ris & self.ie,
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

    /// The set-up the service writes, in its order.
    fn setup(device: &mut Pl061) {
        device.write(GPIOIE, 0);
        device.write(GPIODIR, input(device.read(GPIODIR)));
        let c = rising_edge(Config {
            is: device.read(GPIOIS),
            ibe: device.read(GPIOIBE),
            iev: device.read(GPIOIEV),
        });
        device.write(GPIOIS, c.is);
        device.write(GPIOIBE, c.ibe);
        device.write(GPIOIEV, c.iev);
        device.write(GPIOIC, CLEAR_ALL);
        device.write(GPIOIE, ENABLE);
    }

    #[test]
    fn the_pin_and_its_mask_are_the_buttons() {
        assert_eq!(PIN, 3);
        assert_eq!(MASK, 0x08);
        assert_eq!(LINE, 32 + 7);
        assert_eq!(ENABLE, 0x08);
    }

    #[test]
    fn the_offsets_are_those_of_the_pl061() {
        let all = [GPIODIR, GPIOIS, GPIOIBE, GPIOIEV, GPIOIE, GPIOMIS, GPIOIC];
        assert_eq!(all, [0x400, 0x404, 0x408, 0x40C, 0x410, 0x418, 0x41C]);
        for offset in all {
            assert!(offset % 4 == 0 && offset + 4 <= PAGE);
        }
    }

    #[test]
    fn the_set_up_changes_the_buttons_pin_only_in_the_detection_registers() {
        let before = Config {
            is: 0xF7,
            ibe: 0xFF,
            iev: 0x00,
        };
        let after = rising_edge(before);
        assert_eq!(after.is, 0xF7 & !MASK);
        assert_eq!(after.ibe, 0xFF & !MASK);
        assert_eq!(after.iev, MASK);
        let other = Config {
            is: 0x10,
            ibe: 0x10,
            iev: 0x10,
        };
        let changed = rising_edge(other);
        assert_eq!(
            (changed.is & 0x10, changed.ibe & 0x10, changed.iev & 0x10),
            (0x10, 0x10, 0x10)
        );
        assert_eq!(input(0xFF), 0xF7);
        assert_eq!(input(0x10), 0x10);
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
    fn what_the_firmware_left_in_the_block_does_not_survive_the_set_up() {
        let mut device = Pl061 {
            dir: 0xFF,
            ie: 0x10,
            ris: 0x10,
            ..Pl061::default()
        };
        device.config.is = 0xFF;
        device.config.ibe = 0xFF;
        setup(&mut device);
        // Only the button's pin is enabled: the latched pin 4 raises no line.
        assert_eq!(device.read(GPIOIE), MASK);
        assert_eq!(device.read(GPIOMIS), 0);
        assert_eq!(device.ris, 0, "every pending edge is cleared");
        // The pin is an input detecting the rising edge only.
        assert_eq!(device.dir & MASK, 0);
        assert_eq!(device.config.is & MASK, 0);
        assert_eq!(device.config.ibe & MASK, 0);
        assert_eq!(device.config.iev & MASK, MASK);
        device.drive(PIN, true);
        assert!(pressed(device.read(GPIOMIS)));
    }

    #[test]
    fn pin_4_does_not_show() {
        let mut device = Pl061::default();
        setup(&mut device);
        device.config.iev |= 1 << 4;
        device.drive(4, true);
        assert_eq!(device.read(GPIOMIS), 0);
        assert_eq!(device.read(GPIOIE), MASK);
    }
}
