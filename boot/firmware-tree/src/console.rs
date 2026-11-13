// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The console port by polling, for what the loader says after
//! `ExitBootServices`: PL011 or 16550 at the address the SPCR gave, with the
//! register shift and access width `Uart::regs` decides. The register
//! arithmetic lives here, over a `Bus`, so that a host test can run it
//! against a model of each device: on EC2 the port is a PCI 16550 with byte
//! accesses, and a misaligned access to device memory there is a silent hang.

use crate::platform::{Uart, UartKind};

/// Volatile access to device registers of `width` bytes (1 or 4).
pub trait Bus {
    fn read(&mut self, address: u64, width: u8) -> u32;
    fn write(&mut self, address: u64, width: u8, value: u32);
}

/// How long to wait for the transmitter before the byte goes anyway.
const SPINS: u32 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Port {
    pub base: u64,
    pub pl011: bool,
    pub shift: u8,
    pub width: u8,
}

impl Port {
    /// The port of an SPCR console. A 16550 with contradictory access
    /// fields is the error `Uart::regs` gives.
    pub fn new(u: &Uart) -> Result<Port, crate::Error> {
        let (shift, width) = u.regs()?;
        Ok(Port {
            base: u.base,
            pl011: u.kind == UartKind::Pl011,
            shift,
            width,
        })
    }

    pub fn put<B: Bus>(&self, bus: &mut B, byte: u8) {
        let mut spins = 0;
        if self.pl011 {
            // FR (0x18) bit 5 TXFF, then DR (0x00), 32-bit accesses.
            while bus.read(self.base + 0x18, 4) & (1 << 5) != 0 && spins < SPINS {
                spins += 1;
            }
            bus.write(self.base, 4, u32::from(byte));
            return;
        }
        let reg = |n: u64| self.base + (n << self.shift);
        // LSR (5) bit 5 THRE, then THR (0), at the SPCR's access width.
        while bus.read(reg(5), self.width) & (1 << 5) == 0 && spins < SPINS {
            spins += 1;
        }
        bus.write(reg(0), self.width, u32::from(byte));
    }

    pub fn puts<B: Bus>(&self, bus: &mut B, text: &str) {
        for b in text.bytes() {
            if b == b'\n' {
                self.put(bus, b'\r');
            }
            self.put(bus, b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 16550 with registers `1 << shift` apart that faults, as Device
    /// memory does, on an access that is not of its width or not aligned
    /// to it, and a PL011.
    struct Model {
        base: u64,
        shift: u8,
        width: u8,
        pl011: bool,
        sent: Vec<u8>,
        busy: u32,
    }

    impl Bus for Model {
        fn read(&mut self, address: u64, width: u8) -> u32 {
            if self.pl011 {
                assert_eq!(
                    (address, width),
                    (self.base + 0x18, 4),
                    "PL011 FR is a dword at 0x18"
                );
                if self.busy > 0 {
                    self.busy -= 1;
                    return 1 << 5;
                }
                return 0;
            }
            assert_eq!(width, self.width, "16550 access width");
            assert_eq!(address % u64::from(width), 0, "aligned access");
            assert_eq!(address, self.base + (5 << self.shift), "only LSR is read");
            if self.busy > 0 {
                self.busy -= 1;
                0
            } else {
                1 << 5
            }
        }

        fn write(&mut self, address: u64, width: u8, value: u32) {
            if self.pl011 {
                assert_eq!((address, width), (self.base, 4), "PL011 DR is a dword at 0");
            } else {
                assert_eq!(width, self.width, "16550 access width");
                assert_eq!(address % u64::from(width), 0, "aligned access");
                assert_eq!(address, self.base, "only THR is written");
            }
            self.sent.push(value as u8);
        }
    }

    fn uart(kind: UartKind, bit_width: u8, access_size: u8) -> Uart {
        Uart {
            kind,
            interface_type: 0,
            base: 0x7000_0000,
            bit_width,
            access_size,
            gsiv: None,
            baud_code: 7,
            clock_hz: 0,
        }
    }

    fn says(u: &Uart, busy: u32) -> Vec<u8> {
        let port = Port::new(u).unwrap();
        let mut m = Model {
            base: u.base,
            shift: port.shift,
            width: port.width,
            pl011: port.pl011,
            sent: Vec::new(),
            busy,
        };
        port.puts(&mut m, "hi\n");
        m.sent
    }

    #[test]
    fn the_graviton_16550_with_byte_access_and_8_bit_registers_gets_byte_reads_at_shift_0() {
        let u = uart(UartKind::Ns16550, 8, 1);
        assert_eq!(u.regs(), Ok((0, 1)));
        assert_eq!(says(&u, 3), b"hi\r\n");
    }

    #[test]
    fn a_16550_with_dword_access_and_32_bit_registers_gets_dword_reads_at_shift_2() {
        let u = uart(UartKind::Ns16550, 32, 3);
        assert_eq!(u.regs(), Ok((2, 4)));
        assert_eq!(says(&u, 2), b"hi\r\n");
        // Access size 0 is a byte, as in Linux.
        assert_eq!(uart(UartKind::Ns16550, 0, 0).regs(), Ok((0, 1)));
    }

    #[test]
    fn contradictory_or_unsupported_access_is_refused_before_anything_is_read() {
        for (bits, access) in [(8, 3), (32, 1), (32, 0), (16, 2), (8, 2), (64, 4)] {
            let u = uart(UartKind::Ns16550, bits, access);
            assert!(u.regs().is_err(), "bits {bits}, access {access}");
            assert!(Port::new(&u).is_err());
        }
    }

    #[test]
    fn the_pl011_polls_its_flag_and_writes_a_dword_to_the_data_register() {
        let u = uart(UartKind::Pl011, 32, 3);
        assert_eq!(says(&u, 4), b"hi\r\n");
    }

    #[test]
    fn a_transmitter_that_never_frees_does_not_hang_the_loader() {
        assert_eq!(says(&uart(UartKind::Ns16550, 8, 1), u32::MAX), b"hi\r\n");
    }
}
