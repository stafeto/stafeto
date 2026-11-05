// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The second network device in the hands of one trusted program (spec 6,
//! 3.9): the bodies of CLAIM, CLAIM_MORE and KICK, CONFIG with a device,
//! the bits the service notifies the owner with, and the layout of the
//! bypass ring.
//!
//! | Method | Request | Reply |
//! |---|---|---|
//! | CLAIM (26) | device (u32, 1), ring pages (u32, `RING_PAGES`); three handles: a copy of the identity session (NOTIFY, TRANSFER), a copy of the owner's channel with the label it wants (NOTIFY, TRANSFER), the owner's ring object (MAP_READ, MAP_WRITE, TRANSFER) | status, `Claimed`; four handles: the window, `dma1`, `net1a`, `net1b`. NOT_ALLOWED (not the superuser, no identity, no `handover 1`), BUSY (an owner, or the device on its way back), INVALID (the size of the ring, a device other than 1, no second device), NET_DOWN (no address yet) |
//! | CLAIM_MORE (36) | the header alone | status; two handles: `net1c`, `net1d`. BAD_STATE (no CLAIM of this session, or taken already) |
//! | KICK (37) | count (u32, 1..=`RING_SLOTS`: the frames the owner put in the ring to the service) | status, taken (u32: the frames this step took; the service's steps take the rest). BAD_STATE (the session owns nothing) |
//!
//! The owner makes the ring: `RING_PAGES` pages of its quota. Page 0 holds
//! the indices of the two rings (`Ends`): ring `TO_SERVICE` at 0, ring
//! `TO_OWNER` at `ENDS_LEN`. Each has `head` (u32, the count of frames its
//! writer put), `tail` (u32, the count its reader took) and `len`
//! (`RING_SLOTS` u16, the length of the frame in each slot). Pages 1 to 8
//! hold the 16 slots of 2 KiB to the service, pages 9 to 16 those to the
//! owner. A slot holds an Ethernet frame without the Virtio header, at most
//! `FRAME_MAX` bytes. Slot `i` of a ring is `i % RING_SLOTS`; `head - tail`
//! (wrapping) is never above `RING_SLOTS`.

use crate::{Config, Method};
use proto_wire::{Reader, Status, Writer};

/// The pages of the ring object.
pub const RING_PAGES: u32 = 17;
/// The slots of each ring and their size.
pub const RING_SLOTS: u32 = 16;
pub const SLOT_LEN: usize = 2048;
/// The longest frame a slot carries: Ethernet without the FCS.
pub const FRAME_MAX: usize = 1514;
/// The bytes of the indices of one ring on page 0: head, tail, the lengths.
pub const ENDS_LEN: usize = 64;
/// The rings: the owner writes the first and the service the second.
pub const TO_SERVICE: usize = 0;
pub const TO_OWNER: usize = 1;
const PAGE: usize = 4096;

/// Where slot `slot` of ring `ring` starts in the object.
pub const fn slot_offset(ring: usize, slot: u32) -> usize {
    PAGE + ring * (RING_SLOTS as usize * SLOT_LEN) + (slot % RING_SLOTS) as usize * SLOT_LEN
}

/// Where the head, the tail and the lengths of ring `ring` are.
pub const fn head_offset(ring: usize) -> usize {
    ring * ENDS_LEN
}
pub const fn tail_offset(ring: usize) -> usize {
    ring * ENDS_LEN + 4
}
pub const fn len_offset(ring: usize, slot: u32) -> usize {
    ring * ENDS_LEN + 8 + (slot % RING_SLOTS) as usize * 2
}

const _: () =
    assert!(slot_offset(TO_OWNER, RING_SLOTS - 1) + SLOT_LEN == RING_PAGES as usize * PAGE);
const _: () = assert!(len_offset(TO_OWNER, RING_SLOTS - 1) + 2 <= 2 * ENDS_LEN);

/// The bits the service notifies the owner with: the device's interrupt
/// came (the service read its status and opened the line), a frame waits
/// in the ring to the owner, the second address changed (CONFIG 1 tells
/// the new one), the device's configuration changed (the link).
pub const FAST_INTERRUPT: u64 = 1;
pub const FAST_RING: u64 = 2;
pub const FAST_ADDRESS: u64 = 4;
pub const FAST_CONFIG: u64 = 8;

/// The objects CLAIM tells of: `dma1`, `net1a` to `net1d`.
pub const OBJECTS: usize = 5;
/// The words of the configuration space of the PCI function in the reply.
pub const SNAPSHOT_WORDS: usize = 64;
/// The kinds of transport.
pub const MMIO: u32 = 1;
pub const PCI: u32 = 2;

/// An object of the claimed device: where it lies for the device, its
/// pages, and whether it is mapped uncached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Object {
    pub pa: u64,
    pub pages: u32,
    pub uncached: bool,
}

/// What CLAIM tells the owner besides the handles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claimed {
    /// MMIO (the transport at `transport` in the window's page) or PCI
    /// (BAR 0 at `transport` in the window).
    pub kind: u32,
    pub transport: u64,
    /// The second device's address, as CONFIG 1 tells it.
    pub config: Config,
    pub objects: [Object; OBJECTS],
    /// The sizes of the BARs, as the service measured them (PCI).
    pub bar_sizes: [u64; 6],
    /// The configuration space of the function (PCI; zeros on virtio-mmio).
    pub snapshot: [u32; SNAPSHOT_WORDS],
}

pub fn write_claim(ring_pages: u32, w: &mut Writer) -> Result<(), Status> {
    Method::Claim.header().write(w)?;
    w.u32(1)?;
    w.u32(ring_pages)
}

/// The device and the pages of the ring of a CLAIM.
pub fn read_claim(mut body: Reader<'_>) -> Result<(u32, u32), Status> {
    let device = body.u32()?;
    let pages = body.u32()?;
    body.finish()?;
    Ok((device, pages))
}

impl Claimed {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(Status::Ok.code())?;
        w.u32(self.kind)?;
        w.u64(self.transport)?;
        self.config.write_fields(w)?;
        w.u32(OBJECTS as u32)?;
        for o in &self.objects {
            w.u64(o.pa)?;
            w.u32(o.pages)?;
            w.u32(u32::from(o.uncached))?;
        }
        for size in self.bar_sizes {
            w.u64(size)?;
        }
        for word in self.snapshot {
            w.u32(word)?;
        }
        Ok(())
    }

    /// The reply of CLAIM; a refusal is its status alone and comes back as
    /// the error, any other shape as BAD_SIZE.
    pub fn read(reply: &[u8]) -> Result<Claimed, Status> {
        let mut r = Reader::new(reply);
        let status = Status::from_code(r.u32()?);
        if status != Status::Ok {
            return if reply.len() == proto_wire::HEADER_LEN {
                Err(status)
            } else {
                Err(Status::BadSize)
            };
        }
        let kind = r.u32()?;
        let transport = r.u64()?;
        let config = Config::read_fields(&mut r)?;
        if r.u32()? != OBJECTS as u32 || !(kind == MMIO || kind == PCI) {
            return Err(Status::BadSize);
        }
        let mut objects = [Object::default(); OBJECTS];
        for o in &mut objects {
            o.pa = r.u64()?;
            o.pages = r.u32()?;
            o.uncached = match r.u32()? {
                0 => false,
                1 => true,
                _ => return Err(Status::BadSize),
            };
        }
        let mut bar_sizes = [0; 6];
        for size in &mut bar_sizes {
            *size = r.u64()?;
        }
        let mut snapshot = [0; SNAPSHOT_WORDS];
        for word in &mut snapshot {
            *word = r.u32()?;
        }
        r.finish()?;
        Ok(Claimed {
            kind,
            transport,
            config,
            objects,
            bar_sizes,
            snapshot,
        })
    }
}

pub fn write_claim_more(w: &mut Writer) -> Result<(), Status> {
    Method::ClaimMore.header().write(w)
}

pub fn write_kick(count: u32, w: &mut Writer) -> Result<(), Status> {
    Method::Kick.header().write(w)?;
    w.u32(count)
}

/// The count of a KICK: 1..=RING_SLOTS.
pub fn read_kick(mut body: Reader<'_>) -> Result<u32, Status> {
    let count = body.u32()?;
    body.finish()?;
    if (1..=RING_SLOTS).contains(&count) {
        Ok(count)
    } else {
        Err(crate::code(crate::INVALID))
    }
}

pub fn write_kick_reply(taken: u32, w: &mut Writer) -> Result<(), Status> {
    w.u32(Status::Ok.code())?;
    w.u32(taken)
}

pub fn read_kick_reply(reply: &[u8]) -> Result<u32, Status> {
    let mut r = Reader::new(reply);
    let status = Status::from_code(r.u32()?);
    if status != Status::Ok {
        return Err(status);
    }
    let taken = r.u32()?;
    r.finish()?;
    Ok(taken)
}

/// CONFIG for device `device`: the header alone for device 0, as before
/// the second device had an owner.
pub fn write_config(device: u32, w: &mut Writer) -> Result<(), Status> {
    Method::Config.header().write(w)?;
    if device != 0 {
        w.u32(device)?;
    }
    Ok(())
}

/// The device of a CONFIG: 0 for the header alone, else 0 or 1.
pub fn read_config(mut body: Reader<'_>) -> Result<u32, Status> {
    if body.left() == 0 {
        return Ok(0);
    }
    let device = body.u32()?;
    body.finish()?;
    if device > 1 {
        return Err(crate::code(crate::INVALID));
    }
    Ok(device)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_wire::Header;

    fn sample() -> Claimed {
        let mut snapshot = [0; SNAPSHOT_WORDS];
        snapshot[0] = 0x1041_1af4;
        snapshot[63] = 7;
        Claimed {
            kind: PCI,
            transport: 0x1_0000,
            config: Config {
                address: [10, 0, 3, 15],
                prefix: 24,
                gateway: Some([10, 0, 3, 2]),
                dns: None,
                mac: [0x52, 0x54, 0, 0x12, 0x34, 0x57],
            },
            objects: [
                Object {
                    pa: 0x4100_0000,
                    pages: 8,
                    uncached: true,
                },
                Object {
                    pa: 0x4800_0000,
                    pages: 1024,
                    uncached: false,
                },
                Object {
                    pa: 0x4840_0000,
                    pages: 1024,
                    uncached: false,
                },
                Object {
                    pa: 0x5000_0000,
                    pages: 1024,
                    uncached: false,
                },
                Object {
                    pa: 0x4c00_0000,
                    pages: 1024,
                    uncached: false,
                },
            ],
            bar_sizes: [0x1_0000, 0, 0x40, 0, 0, 0],
            snapshot,
        }
    }

    #[test]
    fn claim_round_trips_and_fits_a_message() {
        let mut w = Writer::new();
        write_claim(RING_PAGES, &mut w).unwrap();
        let mut r = Reader::new(w.as_bytes());
        assert_eq!(Header::read(&mut r).unwrap(), Method::Claim.header());
        assert_eq!(read_claim(r), Ok((1, RING_PAGES)));
        let mut w = Writer::new();
        sample().write(&mut w).unwrap();
        let bytes = w.as_bytes();
        assert_eq!(bytes.len(), 4 + 4 + 8 + 84 + 4 + 5 * 16 + 48 + 256);
        assert!(bytes.len() <= abi::MESSAGE_MAX);
        assert_eq!(Claimed::read(bytes), Ok(sample()));
    }

    #[test]
    fn a_claim_of_the_wrong_shape_is_refused() {
        let mut w = Writer::new();
        sample().write(&mut w).unwrap();
        let whole = w.as_bytes().to_vec();
        assert_eq!(
            Claimed::read(&whole[..whole.len() - 1]),
            Err(Status::BadSize)
        );
        let mut long = whole.clone();
        long.push(0);
        assert_eq!(Claimed::read(&long), Err(Status::BadSize));
        let mut kind = whole.clone();
        kind[4] = 3;
        assert_eq!(Claimed::read(&kind), Err(Status::BadSize));
        let mut uncached = whole.clone();
        uncached[4 + 4 + 8 + 84 + 4 + 12] = 2;
        assert_eq!(Claimed::read(&uncached), Err(Status::BadSize));
        let busy = proto_wire::reply(crate::code(crate::BUSY));
        assert_eq!(Claimed::read(&busy), Err(crate::code(crate::BUSY)));
        assert_eq!(read_claim(Reader::new(&[1, 0, 0, 0])), Err(Status::BadSize));
    }

    #[test]
    fn kick_takes_one_to_sixteen_frames() {
        for count in [1, RING_SLOTS] {
            let mut w = Writer::new();
            write_kick(count, &mut w).unwrap();
            let mut r = Reader::new(w.as_bytes());
            assert_eq!(Header::read(&mut r).unwrap(), Method::Kick.header());
            assert_eq!(read_kick(r), Ok(count));
        }
        for count in [0, RING_SLOTS + 1] {
            assert_eq!(
                read_kick(Reader::new(&count.to_le_bytes())),
                Err(crate::code(crate::INVALID))
            );
        }
        let mut w = Writer::new();
        write_kick_reply(2, &mut w).unwrap();
        assert_eq!(read_kick_reply(w.as_bytes()), Ok(2));
        let mut w = Writer::new();
        write_claim_more(&mut w).unwrap();
        assert_eq!(w.as_bytes(), &Method::ClaimMore.header().bytes());
    }

    #[test]
    fn config_names_its_device_or_none() {
        let mut w = Writer::new();
        write_config(0, &mut w).unwrap();
        assert_eq!(w.as_bytes().len(), proto_wire::HEADER_LEN);
        let mut r = Reader::new(w.as_bytes());
        Header::read(&mut r).unwrap();
        assert_eq!(read_config(r), Ok(0));
        let mut w = Writer::new();
        write_config(1, &mut w).unwrap();
        let mut r = Reader::new(w.as_bytes());
        Header::read(&mut r).unwrap();
        assert_eq!(read_config(r), Ok(1));
        assert_eq!(
            read_config(Reader::new(&2u32.to_le_bytes())),
            Err(crate::code(crate::INVALID))
        );
        assert_eq!(read_config(Reader::new(&[1, 0])), Err(Status::BadSize));
    }

    #[test]
    fn the_ring_fills_its_seventeen_pages() {
        assert_eq!(slot_offset(TO_SERVICE, 0), 4096);
        assert_eq!(slot_offset(TO_SERVICE, 17), 4096 + 2048);
        assert_eq!(slot_offset(TO_OWNER, 0), 9 * 4096);
        assert_eq!(head_offset(TO_OWNER), 64);
        assert_eq!(tail_offset(TO_SERVICE), 4);
        assert_eq!(len_offset(TO_SERVICE, 16), 8);
        const { assert!(FRAME_MAX <= SLOT_LEN) };
    }
}
