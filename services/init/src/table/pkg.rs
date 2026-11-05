// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The tables of the package stages on QEMU's `virt` machine: the walk of
//! bus 0 (tests/pci-walk), which measures the host bridge, the disk's
//! function and its BAR before a driver relies on them.

use super::{Record, Window};

/// The walk of bus 0 (tests/pci-walk): one window over the ECAM of bus 0,
/// 32 devices of 32 KiB. The program ends by itself; it needs no binding
/// and no DMA.
pub const PCI_WALK_QEMU: Record = Record {
    windows: &[Window {
        name: "ecam",
        base: virtio_pci::qemu::ECAM,
        len: 0x10_0000,
        duplicate: false,
    }],
    ..super::vz::PCI_WALK
};

/// The image of the walk: the PL011's driver for the lines and the walk.
pub const PCI_WALK_QEMU_TABLE: &[Record] = &[super::normal::TABLE[0], PCI_WALK_QEMU];
