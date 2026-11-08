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
/// The checksum offload (Virtio 1.2, 5.1.3): the device completes the sum of
/// a frame to send (`CSUM`) and checks the sum of a frame received
/// (`GUEST_CSUM`). Apple's device takes the two together or neither (a set of
/// one of them clears `FEATURES_OK`), and QEMU on user networking offers
/// neither and accepts any request, taking the bits it has.
pub const CSUM: u64 = 1 << 0;
pub const GUEST_CSUM: u64 = 1 << 1;
pub const OFFLOAD: u64 = CSUM | GUEST_CSUM;
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

/// The sets `open_offload` tries for `wanted`, in order: with the offload,
/// then as it is.
pub const fn attempts(wanted: u64) -> [u64; 2] {
    [wanted | OFFLOAD, wanted & !OFFLOAD]
}

/// Whether a negotiated set is one `open_offload` keeps: the offload whole or
/// none of it.
pub const fn offload_whole(features: u64) -> bool {
    features & OFFLOAD == OFFLOAD || features & OFFLOAD == 0
}

/// The attempts of `open_offload` on `open`: a set the device refuses (it
/// clears `FEATURES_OK` and says `Features`) or accepts with half the offload
/// is followed by the next, the last being `wanted` without the offload.
pub fn negotiate(
    wanted: u64,
    mut open: impl FnMut(u64) -> Result<Opened, OpenFailure>,
) -> Result<Opened, OpenFailure> {
    let [with, without] = attempts(wanted);
    match open(with) {
        Ok(opened) if offload_whole(opened.features) => Ok(opened),
        Ok(_) | Err(OpenFailure::Features { .. }) => open(without),
        Err(other) => Err(other),
    }
}

/// `open` with the checksum offload when the device takes it: both bits or
/// none (`negotiate`). The features of the result say what was accepted.
pub fn open_offload<T: Transport>(transport: &mut T, wanted: u64) -> Result<Opened, OpenFailure> {
    negotiate(wanted, |set| open(transport, set))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn opened(features: u64) -> Opened {
        Opened {
            features,
            mac: [2; 6],
            link: true,
            mtu: None,
        }
    }

    const BASE: u64 = MTU | MAC | STATUS;

    #[test]
    fn the_offload_is_asked_for_first_and_dropped_last() {
        assert_eq!(attempts(BASE), [BASE | OFFLOAD, BASE]);
        assert_eq!(attempts(BASE | CSUM), [BASE | OFFLOAD, BASE]);
    }

    #[test]
    fn a_device_that_takes_the_pair_keeps_it() {
        let mut asked = Vec::new();
        let got = negotiate(BASE, |set| {
            asked.push(set);
            Ok(opened(set))
        });
        assert_eq!(got.unwrap().features & OFFLOAD, OFFLOAD);
        assert_eq!(asked, [BASE | OFFLOAD]);
    }

    #[test]
    fn a_device_that_refuses_the_pair_gets_the_set_without_it() {
        // Apple's device for a set it does not take: FEATURES_OK cleared.
        let mut asked = Vec::new();
        let got = negotiate(BASE, |set| {
            asked.push(set);
            if set & OFFLOAD != 0 {
                Err(OpenFailure::Features { offered: !0 })
            } else {
                Ok(opened(set))
            }
        });
        assert_eq!(got.unwrap().features & OFFLOAD, 0);
        assert_eq!(asked, [BASE | OFFLOAD, BASE]);
    }

    #[test]
    fn a_device_that_accepts_but_does_not_offer_the_offload_gets_none() {
        // QEMU on user networking: the request is accepted, the bits it
        // does not have drop out of the word.
        let got = negotiate(BASE, |set| Ok(opened(set & !OFFLOAD)));
        assert_eq!(got.unwrap().features & OFFLOAD, 0);
        // Half of the pair is no offload: asked again without it.
        let mut asked = Vec::new();
        let got = negotiate(BASE, |set| {
            asked.push(set);
            Ok(opened(set & !GUEST_CSUM))
        });
        assert_eq!(got.unwrap().features & OFFLOAD, 0);
        assert_eq!(asked.len(), 2, "no half of the pair is kept");
    }

    #[test]
    fn a_failure_that_is_no_refusal_ends_the_start() {
        for failure in [OpenFailure::Reset, OpenFailure::Config, OpenFailure::NoMac] {
            let mut tries = 0;
            let got = negotiate(BASE, |_| {
                tries += 1;
                Err(failure)
            });
            assert_eq!(got, Err(failure));
            assert_eq!(tries, 1);
        }
        // A device that refuses both sets says so.
        let refused = OpenFailure::Features { offered: 7 };
        assert_eq!(negotiate(BASE, |_| Err(refused)), Err(refused));
    }
}
