// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The start of a network device on its transport (Virtio 1.2, 3.1.1 and
//! 5.1): the reset, the features, the MAC address, the link status and the
//! MTU. The driver makes its queues next, fills the ring of receiving and
//! calls `finish_init`.

use virtio_drivers::transport::Transport;
use virtio_mmio::StartError;

/// The features of a network device a driver may ask for: the MTU, the MAC
/// address and the link status (Virtio 1.2, 5.1.3). Apple's device clears
/// `FEATURES_OK` for any set without MTU (it offers MTU and wants it
/// accepted), whatever else the set holds.
pub const MTU: u64 = 1 << 3;
pub const MAC: u64 = 1 << 5;
pub const STATUS: u64 = 1 << 16;
/// The offset of the link status in the configuration space (Virtio 1.2,
/// 5.1.4), after the six bytes of the MAC.
pub const STATUS_AT: usize = 6;
pub const LINK_UP: u32 = 1;
/// The offset of the MTU in the configuration space, after the MAC, the
/// status and `max_virtqueue_pairs`.
pub const MTU_AT: usize = 10;

/// What the start found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened {
    /// The features both sides have, `VIRTIO_F_VERSION_1` among them.
    pub features: u64,
    pub mac: [u8; 6],
    /// The link is up, or the device reports no status.
    pub link: bool,
    /// The device's MTU, when MTU was negotiated.
    pub mtu: Option<u16>,
}

/// Why the device did not start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenFailure {
    /// The device's status never read 0 after the reset.
    Reset,
    /// The device refused the features; these are the ones it offers.
    Features { offered: u64 },
    /// The device offers no MAC address.
    NoMac,
    /// The configuration space could not be read.
    Config,
}

/// The MAC address and the link status the configuration space of the
/// device holds, read at the width of each field (Virtio 1.2, 4.2.2.2: the
/// bytes of the MAC one at a time, the status as 16 bits) between two equal
/// generations (Virtio 1.2, 2.5.1).
pub fn read_config(transport: &impl Transport) -> Result<([u8; 6], bool), OpenFailure> {
    transport
        .read_consistent(|| {
            let mut mac = [0u8; 6];
            for (at, byte) in mac.iter_mut().enumerate() {
                *byte = transport.read_config_space::<u8>(at)?;
            }
            let status = transport.read_config_space::<u16>(STATUS_AT)?;
            Ok((mac, u32::from(status) & LINK_UP != 0))
        })
        .map_err(|_| OpenFailure::Config)
}

/// Resets the device and negotiates the `wanted` features
/// (`virtio_mmio::start_with`), then reads its MAC address, its link status
/// and, when MTU was negotiated, its MTU. The device must offer a MAC.
pub fn open<T: Transport>(transport: &mut T, wanted: u64) -> Result<Opened, OpenFailure> {
    let features = match virtio_mmio::start_with(transport, wanted) {
        Ok(bits) => bits,
        Err(StartError::Reset) => return Err(OpenFailure::Reset),
        Err(StartError::Features) => {
            return Err(OpenFailure::Features {
                offered: transport.read_device_features(),
            });
        }
    };
    if features & MAC == 0 {
        return Err(OpenFailure::NoMac);
    }
    let (mac, link) = read_config(transport)?;
    let mtu = if features & MTU != 0 {
        let mtu = transport.read_config_space::<u16>(MTU_AT);
        Some(mtu.map_err(|_| OpenFailure::Config)?)
    } else {
        None
    };
    Ok(Opened {
        features,
        mac,
        link: link || features & STATUS == 0,
        mtu,
    })
}
