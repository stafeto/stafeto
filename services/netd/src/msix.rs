// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! MSI-X of the network function on QEMU's machine with an ITS
//! (`virtio_pci::qemu::NET`): one vector a queue, vector 0 for receiving
//! and vector 1 for sending, and none for the configuration (a change of
//! the link goes unsaid). init made the function's MSI device and bound
//! event 0 and event 1 (`irq`, `irqtx`); the kernel gives each binding the
//! address of GITS_TRANSLATER and its EventID [G43], which go into the
//! vector's entry of the table, unmasked. The driver then ties each queue
//! to its vector in the common configuration and turns MSI-X on in the
//! capability (PCI Local Bus 3.0, 6.8.2; Virtio 1.2, 4.1.4.3). An LPI has
//! no mask in the kernel [G40]: the device's notification flags of the
//! queues (`ring::settle_interrupts`) keep it quiet while a run of steps
//! lasts, as they do for the line.

use crate::dma;
use rt::handle::Interrupt;
use rt::{Handle, sys};
use virtio_pci::{MSIX_ENTRY, Msix, QUEUE_MSIX_VECTOR, QUEUE_SELECT, qemu};

/// The queue of each vector, in the order of the bindings.
const QUEUES: [u16; 2] = [crate::RECEIVEQ, crate::TRANSMITQ];

fn config_read(offset: usize) -> u32 {
    // SAFETY: the window `ecam` maps the function's page at ecam_at() as
    // device memory, read and write; `offset` is a register of it.
    unsafe { virtio_net::mmio::read32(dma::ecam_at() + offset) }
}

/// A 16-bit field of the common configuration at the start of BAR 4.
fn common_write(offset: usize, value: u16) {
    // SAFETY: the window `bar` maps BAR 4 at bar_at() as device memory,
    // read and write; `offset` is a field of the common configuration,
    // which the capability list put at offset 0 (`pci_transport`).
    unsafe { rt::mmio::write16(dma::bar_at() + offset, value) }
}

fn common_read(offset: usize) -> u16 {
    // SAFETY: as for `common_write`.
    unsafe { rt::mmio::read16(dma::bar_at() + offset) }
}

/// Fills the table with the vectors of `bindings` (receiving, sending),
/// ties the queues to them and turns MSI-X on; the device was reset and
/// its queues are made, and nothing has been told DRIVER_OK yet.
pub fn set_up(bindings: [&Handle<Interrupt>; 2]) -> Result<(), &'static str> {
    let msix = virtio_pci::msix(config_read).ok_or("no capability")?;
    let room = u64::from(msix.offset) + (QUEUES.len() * MSIX_ENTRY) as u64;
    if msix.bar != qemu::NET_MSIX_BAR
        || msix.vectors < QUEUES.len() as u16
        || room > qemu::NET_MSIX_LEN
    {
        return Err("the table is not where the window holds it");
    }
    let table = dma::bar_at() + qemu::NET.len as usize + msix.offset as usize;
    for (vector, binding) in bindings.into_iter().enumerate() {
        let info = sys::irq_info(binding).map_err(|_| "a binding without its info")?;
        if !info.lpi {
            return Err("a binding of a line");
        }
        // Vector Control, the last word, unmasks the vector once the
        // message is whole.
        let words = Msix::entry(info.msi_address, info.msi_data as u32);
        for (k, word) in words.into_iter().enumerate() {
            // SAFETY: the window `bar` maps the table's BAR after BAR 4,
            // and the entry lies within it (`room`).
            unsafe { virtio_net::mmio::write32(table + vector * MSIX_ENTRY + 4 * k, word) };
        }
    }
    // The device reads back NO_VECTOR for a vector it cannot take.
    for queue in QUEUES {
        let vector = msix.queue_vector(queue);
        common_write(QUEUE_SELECT, queue);
        common_write(QUEUE_MSIX_VECTOR, vector);
        if common_read(QUEUE_MSIX_VECTOR) != vector {
            return Err("the device refused a queue's vector");
        }
    }
    let on = Msix::enabled(config_read(msix.at));
    // SAFETY: as for `config_read`; the word is the capability's first.
    unsafe { virtio_net::mmio::write32(dma::ecam_at() + msix.at, on) };
    Ok(())
}
