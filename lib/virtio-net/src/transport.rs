// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The transport of a network device: a virtio-mmio transport at a mapped
//! address (`mmio_transport`, QEMU), or a Virtio PCI function
//! (`pci_transport`, Apple VZ) over its configuration space, read either
//! through the page of the function in a window of ECAM (`Function`) or
//! from a copy of its 256 bytes (`Snapshot`), for a driver that has the
//! function's BAR 0 and no ECAM.
//!
//! Every access to the configuration space is 32 bits wide, as VZ stops the
//! machine at a byte write there. The function's BARs are written before
//! (the driver that owns ECAM does it): `pci_transport` reads the Virtio
//! structures from the capability list, resets the device and gives the
//! status it had before (Virtio 1.2, 2.4.1, 4.1.4).

use crate::host::{self, Host, Region};
use crate::mmio;
use core::ptr::NonNull;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use virtio_drivers::transport::pci::PciTransport;
use virtio_drivers::transport::pci::bus::{ConfigurationAccess, DeviceFunction, PciRoot};
use virtio_drivers::transport::{DeviceStatus, Transport};
use virtio_mmio::{Reject, check, device, regs};

/// Reads of the device's status after its reset, at most, before the
/// driver gives up: Virtio 1.2, 2.4.1, the reset is done once it reads 0.
pub const RESET_READS: u32 = 1_000_000;

/// Why a virtio-mmio transport could not be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    Rejected(Reject),
    /// The device's crate took the registers for no usable transport.
    Unusable,
}

/// The network device's virtio-mmio transport whose registers start at
/// `base`, after `virtio_mmio::check`: the status the device had before the
/// driver's reset (0 at the machine's start and after init stopped the
/// device of an instance that ended), for the driver's line.
///
/// # Safety
///
/// `base` is the start of a virtio-mmio transport of `regs::LEN` bytes in a
/// device window the process maps read and write, and nothing else reaches
/// the registers from here on.
pub unsafe fn mmio_transport(base: usize) -> Result<(MmioTransport<'static>, u32), OpenError> {
    // SAFETY: the registers read lie within the transport, aligned.
    let read = |offset: usize| unsafe { mmio::read32(base + offset) };
    check(read, device::NET).map_err(OpenError::Rejected)?;
    let status = read(regs::STATUS);
    let header = NonNull::new(base as *mut VirtIOHeader).ok_or(OpenError::Unusable)?;
    // SAFETY: the caller's promise.
    let transport = unsafe { MmioTransport::new(header, regs::LEN) };
    let transport = transport.map_err(|_| OpenError::Unusable)?;
    Ok((transport, status))
}

/// Why a Virtio PCI function could not be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Nothing of the expected kind is there.
    NoDevice,
    /// The device did not reset.
    NotReset,
    /// BAR 0 of the configuration space lies elsewhere than the BAR the
    /// caller maps: a wrong place, a snapshot of another function or the
    /// window of another device.
    BarElsewhere,
}

/// The configuration space of one function, as the device's crate reads
/// it: a page of a window of ECAM mapped at this address, each access a
/// 32-bit `ldr` or `str`.
pub struct Function(pub usize);

impl ConfigurationAccess for Function {
    fn read_word(&self, _: DeviceFunction, register_offset: u8) -> u32 {
        // SAFETY: the window maps the function's page of configuration as
        // device memory, read and write, and the offset lies within it.
        unsafe { mmio::read32(self.0 + usize::from(register_offset & !3)) }
    }

    fn write_word(&mut self, _: DeviceFunction, register_offset: u8, data: u32) {
        // SAFETY: as for `read_word`.
        unsafe { mmio::write32(self.0 + usize::from(register_offset & !3), data) }
    }

    unsafe fn unsafe_clone(&self) -> Self {
        Function(self.0)
    }
}

/// The words of a function's configuration space a snapshot holds: its 256
/// bytes, the header and the capability list.
pub const SNAPSHOT_WORDS: usize = 64;
/// The first BAR register, and the BARs of a header of type 0.
const BAR0_WORD: usize = 4;
const BARS: usize = 6;

/// The configuration space of a function from a copy of its 256 bytes, for a
/// driver that has the function's BAR 0 and no ECAM: the network service
/// reads the words through its own window and hands them over with the sizes
/// of the BARs. A read gives the copy's word; a write goes into the copy.
/// A write of all ones to a BAR register marks it as being measured, and the
/// next read gives the mask of its size (`!(size - 1)` with the BAR's type
/// bits), as the register of the device does (PCI Local Bus 3.0, 6.2.5.1);
/// any other write ends the measurement. The device itself is not touched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    words: [u32; SNAPSHOT_WORDS],
    bar_sizes: [u64; BARS],
    /// The BAR registers being measured, a bit each.
    measured: u8,
}

/// Where a BAR register stands: its own size, or the upper half of the
/// 64-bit BAR before it.
enum BarRegister {
    Low { size: u64, io: bool },
    High { size: u64 },
}

impl Snapshot {
    /// The copy `words`, and the bytes of each BAR (0 for one the function
    /// lacks; the size of a 64-bit BAR goes at its lower register).
    pub const fn new(words: [u32; SNAPSHOT_WORDS], bar_sizes: [u64; BARS]) -> Snapshot {
        Snapshot {
            words,
            bar_sizes,
            measured: 0,
        }
    }

    /// The words as they stand.
    pub const fn words(&self) -> &[u32; SNAPSHOT_WORDS] {
        &self.words
    }

    /// What BAR register `reg` (0 to 5) is, by the type bits of the BARs
    /// before it: a 64-bit memory BAR takes two registers.
    fn bar(&self, reg: usize) -> BarRegister {
        let mut k = 0;
        while k < BARS {
            let word = self.words[BAR0_WORD + k];
            let io = word & 1 != 0;
            let wide = !io && word & 0b110 == 0b100 && k + 1 < BARS;
            if k == reg {
                return BarRegister::Low {
                    size: self.bar_sizes[k],
                    io,
                };
            }
            if wide && k + 1 == reg {
                return BarRegister::High {
                    size: self.bar_sizes[k],
                };
            }
            k += if wide { 2 } else { 1 };
        }
        BarRegister::Low { size: 0, io: false }
    }

    /// The mask a BAR register reads while it is measured.
    fn mask(&self, reg: usize) -> u32 {
        match self.bar(reg) {
            BarRegister::Low { size: 0, .. } | BarRegister::High { size: 0 } => 0,
            BarRegister::Low { size, io } => {
                let flags = if io { 0b11 } else { 0b1111 };
                let word = self.words[BAR0_WORD + reg];
                (!(size - 1) as u32 & !flags) | (word & flags)
            }
            BarRegister::High { size } => (!(size - 1) >> 32) as u32,
        }
    }

    fn bar_index(register_offset: u8) -> Option<usize> {
        let word = usize::from(register_offset / 4);
        (BAR0_WORD..BAR0_WORD + BARS)
            .contains(&word)
            .then(|| word - BAR0_WORD)
    }
}

impl ConfigurationAccess for Snapshot {
    fn read_word(&self, _: DeviceFunction, register_offset: u8) -> u32 {
        if let Some(reg) = Self::bar_index(register_offset)
            && self.measured & (1 << reg) != 0
        {
            return self.mask(reg);
        }
        self.words[usize::from(register_offset / 4)]
    }

    fn write_word(&mut self, _: DeviceFunction, register_offset: u8, data: u32) {
        if let Some(reg) = Self::bar_index(register_offset) {
            if data == u32::MAX {
                self.measured |= 1 << reg;
                return;
            }
            self.measured &= !(1 << reg);
        }
        self.words[usize::from(register_offset / 4)] = data;
    }

    unsafe fn unsafe_clone(&self) -> Self {
        self.clone()
    }
}

/// The function a driver of one device sees: bus 0, device 0, function 0 of
/// its own configuration space.
const AT: DeviceFunction = DeviceFunction {
    bus: 0,
    device: 0,
    function: 0,
};

/// The address BAR 0 of the configuration space `access` holds: its low
/// word without the type bits, and the high word for a 64-bit memory BAR
/// (PCI Local Bus 3.0, 6.2.5.1).
pub fn bar0_address<C: ConfigurationAccess>(access: &C) -> u64 {
    let low = access.read_word(AT, BAR0_WORD as u8 * 4);
    if low & 1 != 0 {
        return u64::from(low & !0b11);
    }
    let high = if low & 0b110 == 0b100 {
        access.read_word(AT, (BAR0_WORD as u8 + 1) * 4)
    } else {
        0
    };
    u64::from(high) << 32 | u64::from(low & !0b1111)
}

/// The Virtio PCI transport of device `D` (slot `D` of `host`) over the
/// configuration space `access`, whose BAR 0 is `bar` (mapped at `bar.va`,
/// at `bar.pa` for the device): the structures found in the capability list,
/// the device reset; the status it had before the reset goes with it. BAR 0
/// of the configuration space must be `bar.pa` (`Failure::BarElsewhere`):
/// the structures the crate finds there are reached through `bar.va`. The
/// caller turns bus mastering on after this (Virtio 1.2, 2.4.1: the device
/// forgets every queue before it may master the bus again).
pub fn pci_transport<const D: usize, C: ConfigurationAccess>(
    access: C,
    bar: Region,
) -> Result<(PciTransport, u32), Failure> {
    if bar0_address(&access) != bar.pa {
        return Err(Failure::BarElsewhere);
    }
    if !host::attach_bar(D, bar) {
        return Err(Failure::NoDevice);
    }
    let mut root = PciRoot::new(access);
    let mut transport =
        PciTransport::new::<Host<D>, _>(&mut root, AT).map_err(|_| Failure::NoDevice)?;
    let status = transport.get_status().bits();
    transport.set_status(DeviceStatus::empty());
    if !(0..RESET_READS).any(|_| transport.get_status().is_empty()) {
        return Err(Failure::NotReset);
    }
    Ok((transport, status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use virtio_drivers::transport::DeviceType;
    use virtio_drivers::transport::pci::bus::{BarInfo, MemoryBarType};

    const BAR0: u64 = 0x1_0003_0000;
    const BAR_LEN: u64 = 0x1_0000;

    /// A vendor capability of Virtio at `at` (Virtio 1.2, 4.1.4): its type,
    /// its next, its length, and the structure in BAR 0 at `offset` of
    /// `len` bytes.
    fn capability(words: &mut [u32; 64], at: usize, kind: u32, next: u32, offset: u32, len: u32) {
        let cap_len = if kind == 2 { 20 } else { 16 };
        words[at / 4] = 0x09 | next << 8 | cap_len << 16 | kind << 24;
        words[at / 4 + 1] = 0;
        words[at / 4 + 2] = offset;
        words[at / 4 + 3] = len;
        if kind == 2 {
            // notify_off_multiplier
            words[at / 4 + 4] = 4;
        }
    }

    /// The second network device of VZ as `cargo xtask pci-walk-vz` saw it
    /// (reports/2026-11-04-net-p2): 1af4:1041, BAR 0 64-bit of 64 KiB, BAR 2
    /// 32-bit of 0x40, the common configuration at 0, the ISR at 0x1000, the
    /// notifications at 0x4000, the device's configuration at 0x8000.
    fn vz_function() -> Snapshot {
        let mut words = [0u32; 64];
        words[0] = 0x1041_1af4;
        // Status: a capability list; command: memory decoding, bus master.
        words[1] = 0x0010 << 16 | 0x0006;
        words[2] = 0x0200_0001;
        words[4] = BAR0 as u32 | 0b100;
        words[5] = (BAR0 >> 32) as u32;
        words[6] = 0x5003_0000;
        words[0x34 / 4] = 0x40;
        capability(&mut words, 0x40, 1, 0x50, 0, 0x38);
        capability(&mut words, 0x50, 2, 0x68, 0x4000, 8);
        capability(&mut words, 0x68, 3, 0x78, 0x1000, 1);
        capability(&mut words, 0x78, 4, 0, 0x8000, 0x11);
        Snapshot::new(words, [BAR_LEN, 0, 0x40, 0, 0, 0])
    }

    #[test]
    fn the_bars_of_a_snapshot_measure_as_the_device_s_do() {
        let snapshot = vz_function();
        let before = *snapshot.words();
        let mut root = PciRoot::new(snapshot.clone());
        let bar0 = Ok(Some(BarInfo::Memory {
            address_type: MemoryBarType::Width64,
            prefetchable: false,
            address: BAR0,
            size: BAR_LEN,
        }));
        assert_eq!(root.bar_info(AT, 0), bar0);
        assert_eq!(
            root.bar_info(AT, 2),
            Ok(Some(BarInfo::Memory {
                address_type: MemoryBarType::Width32,
                prefetchable: false,
                address: 0x5003_0000,
                size: 0x40,
            }))
        );
        assert_eq!(root.bar_info(AT, 3), Ok(None), "no BAR 3");
        // The measurement leaves the copy as it found it: a second one
        // finds the same, and the words and the command are unchanged.
        assert_eq!(root.bar_info(AT, 0), bar0);
        let mut copy = snapshot;
        for reg in 0..BARS as u8 {
            let at = 0x10 + 4 * reg;
            let word = copy.read_word(AT, at);
            copy.write_word(AT, at, u32::MAX);
            let _ = copy.read_word(AT, at);
            copy.write_word(AT, at, word);
        }
        assert_eq!(*copy.words(), before);
        assert_eq!(copy.measured, 0);
        assert_eq!(root.get_status_command(AT).1.bits(), 0x0006);
    }

    #[test]
    fn an_io_bar_keeps_its_two_type_bits() {
        let mut words = [0u32; 64];
        words[4] = 0xc001;
        let mut s = Snapshot::new(words, [0x20, 0, 0, 0, 0, 0]);
        s.write_word(AT, 0x10, u32::MAX);
        assert_eq!(s.read_word(AT, 0x10), 0xffff_ffe1);
        s.write_word(AT, 0x10, 0xc001);
        assert_eq!(s.read_word(AT, 0x10), 0xc001);
    }

    #[test]
    fn the_transport_finds_the_structures_in_bar_0() {
        let mut memory = vec![0u8; BAR_LEN as usize + 8];
        let bar = Region {
            va: memory.as_mut_ptr() as usize,
            pa: BAR0,
            len: BAR_LEN as usize,
        };
        // The device's configuration: the MAC first.
        memory[0x8000..0x8006].copy_from_slice(&[2, 0x73, 0x74, 0x66, 0, 2]);
        let (transport, status) = pci_transport::<0, _>(vz_function(), bar).expect("the transport");
        assert_eq!(status, 0);
        assert_eq!(transport.device_type(), DeviceType::Network);
        let mac: [u8; 6] =
            core::array::from_fn(|i| transport.read_config_space::<u8>(i).expect("a byte"));
        assert_eq!(mac, [2, 0x73, 0x74, 0x66, 0, 2]);
        drop(transport);
        drop(memory);
    }

    #[test]
    fn a_bar_mapped_elsewhere_than_bar_0_is_refused() {
        let snapshot = vz_function();
        assert_eq!(bar0_address(&snapshot), BAR0);
        let mut memory = vec![0u8; BAR_LEN as usize];
        // The BAR 0 of the first device of VZ, next to the second's.
        let other = Region {
            va: memory.as_mut_ptr() as usize,
            pa: BAR0 - BAR_LEN,
            len: BAR_LEN as usize,
        };
        assert_eq!(
            pci_transport::<1, _>(snapshot, other).err(),
            Some(Failure::BarElsewhere)
        );
        // A 32-bit BAR has no high word, and an I/O BAR two type bits.
        let mut words = [0u32; 64];
        words[4] = 0x5003_0008;
        words[5] = 0xffff_ffff;
        assert_eq!(bar0_address(&Snapshot::new(words, [0; 6])), 0x5003_0000);
        words[4] = 0xc001;
        assert_eq!(bar0_address(&Snapshot::new(words, [0; 6])), 0xc000);
    }
}
