// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The transport of a network device: the virtio-mmio transport of QEMU
//! (`virtio_mmio::transport`) or the Virtio PCI function of Apple VZ,
//! which the service sets up as the other drivers of VZ do (virtio_pci):
//! the ID of the function checked, the common configuration looked up in
//! its capability list (init stops the device through `device_status` at
//! the start of BAR 0), the BARs written with decoding off and then on,
//! the device reset, and bus mastering on only then (Virtio 1.2, 2.4.1,
//! 3.1.1). Every access to the configuration space is 32 bits wide, as VZ
//! stops the machine at a byte write there.

use crate::dma::{self, Host};
use netd::pci;
use rt::mmio;
use virtio_drivers::transport::pci::PciTransport;
use virtio_drivers::transport::pci::bus::{ConfigurationAccess, DeviceFunction, PciRoot};
use virtio_drivers::transport::{DeviceStatus, SomeTransport, Transport};

/// Reads of the device's status after its reset, at most, before the
/// service gives up: Virtio 1.2, 2.4.1, the reset is done once it reads 0.
const RESET_READS: u32 = 1_000_000;

/// Why a transport could not be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Nothing of the expected kind is there.
    NoDevice,
    /// The common configuration of the PCI function lies elsewhere than at
    /// the start of BAR 0, where init's stop writes.
    ConfigElsewhere,
    /// The device did not reset.
    NotReset,
}

/// The configuration space of one function, as the device's crate reads
/// it: a page of the window `ecam`, each access a 32-bit `ldr` or `str`.
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

/// The transport of the virtio-mmio device at `at`, whose page the window
/// maps at `mmio_at(device)`, and the status the device had before the
/// service's reset.
pub fn mmio_transport(
    device: usize,
    at: u64,
) -> Result<(SomeTransport<'static>, u32), virtio_mmio::OpenError> {
    let base = dma::mmio_at(device) + (at as usize & (virtio_mmio::PAGE - 1));
    // SAFETY: the window maps the transport's page at mmio_at as device
    // memory, read and write; `base` is the transport within it, and only
    // the transport and the reads of the configuration space reach the
    // registers from here on.
    let (transport, status) = unsafe { virtio_mmio::transport(base, virtio_mmio::device::NET) }?;
    Ok((transport.into(), status))
}

/// The Virtio PCI function of device `D` of the record, whose page the
/// window `ecam` maps at `ecam_at() + ecam_offset(D)`, set up with
/// decoding on and bus mastering off, reset, and then given bus mastering;
/// the status it had before the reset goes with it.
pub fn pci_transport<const D: usize>(
    place: &virtio_pci::Place,
) -> Result<(SomeTransport<'static>, u32), Failure> {
    let page = dma::ecam_at() + pci::ecam_offset(D) as usize;
    let read = |offset: usize| {
        // SAFETY: the page is mapped as device memory, read and write; the
        // offset is a register of virtio_pci.
        unsafe { mmio::read32(page + offset) }
    };
    let write = |offset: usize, value: u32| {
        // SAFETY: as for `read`.
        unsafe { mmio::write32(page + offset, value) }
    };
    // The record names the function of the network device; one that holds
    // something else ends the service before it writes there.
    if read(virtio_pci::ID) != place.id {
        return Err(Failure::NoDevice);
    }
    if virtio_pci::common_config(read) != Some((0, 0)) {
        return Err(Failure::ConfigElsewhere);
    }
    let found = read(virtio_pci::COMMAND) & 0xFFFF;
    for (offset, value) in place.set_up(found) {
        write(offset, value);
    }
    dma::attach_bar(D, place.bar, place.bar_len);
    let mut root = PciRoot::new(Function(page));
    let at = DeviceFunction {
        bus: 0,
        device: 0,
        function: 0,
    };
    let mut transport =
        PciTransport::new::<Host<D>, _>(&mut root, at).map_err(|_| Failure::NoDevice)?;
    let status = transport.get_status().bits();
    // The device forgets every queue before it may master the bus again
    // (Virtio 1.2, 2.4.1): a stop of an instance that ended may not have
    // run.
    transport.set_status(DeviceStatus::empty());
    if !(0..RESET_READS).any(|_| transport.get_status().is_empty()) {
        return Err(Failure::NotReset);
    }
    write(
        virtio_pci::COMMAND,
        virtio_pci::bus_master(read(virtio_pci::COMMAND)),
    );
    Ok((transport.into(), status))
}
