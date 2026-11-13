// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The consumer of the service's switch: the layout of its ring object and
//! the bodies of ATTACH, PORT_HOLD and JOIN.
//!
//! | Method | Request | Reply |
//! |---|---|---|
//! | ATTACH (39) | version (u32, `VERSION`), `rx_slots`, `tx_slots`, cell size (u32 each); two handles: the ring object (MAP_READ, MAP_WRITE) and a copy of the caller thread's channel (NOTIFY) with the label it wants | status, `Attached` (the last word says whether the device offloads the TCP sums: only then may a TX entry say `TX_SUM`); one handle: a copy of the switch thread's channel (NOTIFY alone) with the consumer's label. LIMIT_REACHED (no place, or the session has a consumer), INVALID (sizes, rights, the object is smaller than the layout), NET_DOWN (no address) |
//! | PORT_HOLD (38) | protocol (u32, 6 or 17), first port, count (1..=`HOLD_MAX`), flags (u32, `REUSEPORT`); a handle: a copy of the identity session | status, place (u32, as SOCKET's description). NOT_ALLOWED (below 1024 without the superuser), IN_USE (the port is held), LIMIT_REACHED (no group) |
//! | JOIN (40) | place (u32) | status. INVALID (the session has no consumer, or no such place) |
//!
//! The ring object: page 0 holds lines of `LINE` bytes (the u32 of each at
//! its start), then the FILL ring (u32 cells), the DONE ring (8 bytes), the
//! TX ring (8 bytes), `rx_slots` cells to receive into and `tx_slots` to
//! send from, `CELL` bytes each (a cell of FILL is a cell number below `rx_slots`). Every index is a u32 that grows without
//! wrapping to the size; the entry of index `i` is `i % slots`.
//!
//! A frame of up to `TSO_FRAME_MAX` bytes (the segmentation offload, `TX_SUM | TX_TSO`) takes
//! `k = cells(len)` entries in a row, and so the `k` cells of those entries, which lie one after
//! the other in the object: the first entry has the length of the whole frame and the MSS in its
//! spare, the next `k - 1` are zero. A frame never runs over the end of the array of cells: the
//! consumer first writes a `TX_PAD` entry that skips the rest of the array (its spare is the
//! number of entries it skips, itself included). The switch takes the frame in pieces and frees
//! the entries (`TX_TAIL` moves by `k`) after the last.

use crate::{Config, Method};
use proto_wire::{Reader, Status, Writer};

pub const VERSION: u32 = 3;
pub const PAGE: usize = 4096;
pub const LINE: usize = 64;
/// The bytes of a cell and the longest frame in it.
pub const CELL: usize = 2048;
pub const FRAME_MAX: usize = 1514;
/// The bounds of the rings, in entries; each entry of the receiving ring and of the sending ring has
/// a cell of its own, so the object (and the mappings of the service that hold it) is as large as
/// the sizes the consumer asks for.
pub const RX_SLOTS: (u32, u32) = (256, 4096);
pub const TX_SLOTS: (u32, u32) = (64, 512);
/// The most ports one PORT_HOLD names.
pub const HOLD_MAX: u32 = 16;
pub const REUSEPORT: u32 = 1;

/// The lines of page 0 and who writes them.
pub const SIZES: usize = 0;
pub const FILL_HEAD: usize = LINE;
pub const FILL_TAIL: usize = 2 * LINE;
pub const DONE_HEAD: usize = 3 * LINE;
pub const DONE_TAIL: usize = 4 * LINE;
pub const TX_HEAD: usize = 5 * LINE;
pub const TX_TAIL: usize = 6 * LINE;
pub const CONSUMER_IDLE: usize = 7 * LINE;
pub const SWITCH_IDLE: usize = 8 * LINE;
/// Line 9: `rx_full` (u32) and `tx_refused` (u32), the switch's counters.
pub const COUNTERS: usize = 9 * LINE;

/// DONE flags: a copy of an ARP reply sent to every consumer; an ICMP
/// error steered by the header it carries; a packet of 127.0.0.0/8 from
/// another stack (Ethernet header, no sums): the consumer's stack takes it in
/// at its loopback interface.
pub const DONE_ARP_COPY: u16 = 1;
pub const DONE_ICMP_ERROR: u16 = 2;
pub const DONE_LOOP: u16 = 4;
/// The sum of the TCP segment is good: the device checked it, or the frame comes from a stack
/// that left it partial (the switch put the pseudo-header sum in it), or never left the
/// service's memory. The consumer's stack does not check the segment's sum then; without the
/// flag it does.
pub const DONE_SUM_OK: u16 = 0x100;
pub const DONE_FLAGS: u16 = DONE_ARP_COPY | DONE_ICMP_ERROR | DONE_LOOP | DONE_SUM_OK;
/// The TX flags of an ordinary frame.
pub const TX_FLAGS: u16 = 0;
/// A frame of TCP in IPv4 whose sum the stack did not compute: the switch writes the sum of
/// the pseudo-header from the frame it checked, and the device (or the switch, for a device
/// without the offload) completes the sum over the segment. The flag stands alone: with
/// `TX_LOOP` or on a frame that is no TCP the entry is refused.
pub const TX_SUM: u16 = 1;
/// A frame of TCP in IPv4 longer than one cell, which the device cuts into segments of the MSS in
/// the entry's spare (the offload of the segmentation): `TX_SUM | TX_TSO`, the frame in
/// `cells(len)` cells in a row. Allowed only when ATTACH said `tso`. Refused (and counted) for a
/// frame the checks of the header refuse (`netd::switchlogic::tso`).
pub const TX_TSO: u16 = 2;
/// The entry that skips the cells to the end of the array of cells (the next frame of the
/// segmentation offload starts at the first); its spare is the number of entries it skips.
pub const TX_PAD: u16 = 8;
/// The bytes of headers of a frame of the segmentation offload that the switch copies and
/// checks (Ethernet, IPv4 and TCP with options), and the most of data after them.
pub const TSO_HEAD_MAX: usize = 128;
pub const TSO_BODY_MAX: usize = 16384;
pub const TSO_FRAME_MAX: usize = TSO_BODY_MAX + TSO_HEAD_MAX;
/// The least MSS of an entry of the segmentation offload, and the most (1 500 less the shortest
/// IPv4 and TCP headers, the largest MTU of the wire). The least is FreeBSD's `tcp_minmss` (216):
/// the stack sends `t_maxseg` less the options, so a peer with an MSS of 536 and timestamps gets
/// segments of 524 (virtio has no floor of its own).
pub const TSO_MSS_MIN: u16 = 216;
pub const TSO_MSS_MAX: u32 = 1460;
/// The shortest frame of the segmentation offload: Ethernet, IPv4 and TCP headers without options.
pub const TSO_HEAD_MIN: usize = 54;
/// The most cells a frame of the segmentation offload takes.
pub const TSO_CELLS_MAX: u32 = TSO_FRAME_MAX.div_ceil(CELL) as u32;
const _: () = assert!(TSO_CELLS_MAX == 9);

/// The cells (and the entries of TX) a frame of `len` bytes takes.
pub const fn cells(len: usize) -> u32 {
    if len == 0 {
        1
    } else {
        len.div_ceil(CELL) as u32
    }
}

/// A packet of the loopback network of the consumer's stack for a port that is no port of
/// that stack (both addresses in 127.0.0.0/8, else the ring breaks); the switch routes it by
/// its port. `TX_FLAGS`, `TX_SUM`, `TX_LOOP`, `TX_SUM | TX_TSO` and `TX_PAD` are the values the
/// flags of a TX entry may have.
pub const TX_LOOP: u16 = 4;

/// The bits the switch notifies the consumer with.
pub const WAKE_RING: u64 = 1;
pub const WAKE_BROKEN: u64 = 2;
pub const WAKE_ADDRESS: u64 = 4;
pub const WAKE_GONE: u64 = 8;

/// The sizes of the rings, and from them every offset in the object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub rx_slots: u32,
    pub tx_slots: u32,
}

const fn pages(bytes: usize) -> usize {
    bytes.div_ceil(PAGE) * PAGE
}

impl Layout {
    /// 1 024 cells to receive into and 256 to send from: 645 pages, 11 chunks of 64 pages of
    /// the service's mappings (eight consumers fit the budget of `RING_MAPPINGS`).
    pub const DEFAULT: Layout = Layout {
        rx_slots: 1024,
        tx_slots: 256,
    };

    /// None unless the sizes are powers of two within their bounds.
    pub const fn new(rx_slots: u32, tx_slots: u32) -> Option<Layout> {
        let rx = rx_slots >= RX_SLOTS.0 && rx_slots <= RX_SLOTS.1 && rx_slots.is_power_of_two();
        let tx = tx_slots >= TX_SLOTS.0 && tx_slots <= TX_SLOTS.1 && tx_slots.is_power_of_two();
        if rx && tx {
            Some(Layout { rx_slots, tx_slots })
        } else {
            None
        }
    }

    pub const fn fill(&self) -> usize {
        PAGE
    }
    pub const fn fill_entry(&self, i: u32) -> usize {
        PAGE + (i % self.rx_slots) as usize * 4
    }
    pub const fn done(&self) -> usize {
        self.fill() + pages(self.rx_slots as usize * 4)
    }
    pub const fn done_entry(&self, i: u32) -> usize {
        self.done() + (i % self.rx_slots) as usize * 8
    }
    pub const fn tx(&self) -> usize {
        self.done() + pages(self.rx_slots as usize * 8)
    }
    pub const fn tx_entry(&self, i: u32) -> usize {
        self.tx() + (i % self.tx_slots) as usize * 8
    }
    pub const fn rx_cells(&self) -> usize {
        self.tx() + pages(self.tx_slots as usize * 8)
    }
    pub const fn rx_cell(&self, cell: u32) -> usize {
        self.rx_cells() + cell as usize * CELL
    }
    pub const fn tx_cells(&self) -> usize {
        self.rx_cells() + self.rx_slots as usize * CELL
    }
    /// The cell of TX entry `i`: `i % tx_slots` (a cell for each entry).
    pub const fn tx_cell(&self, i: u32) -> usize {
        self.tx_cells() + (i % self.tx_slots) as usize * CELL
    }
    pub const fn total(&self) -> usize {
        self.tx_cells() + self.tx_slots as usize * CELL
    }
    /// Whether `k` entries from index `i` lie in a row in the array (no run over its end).
    pub const fn tx_run_fits(&self, i: u32, k: u32) -> bool {
        (i % self.tx_slots) as u64 + k as u64 <= self.tx_slots as u64
    }
    /// The entries from index `i` to the end of the array of cells.
    pub const fn tx_to_end(&self, i: u32) -> u32 {
        self.tx_slots - i % self.tx_slots
    }
}

const _: () = assert!(Layout::DEFAULT.total() == 645 * PAGE);
const _: () = assert!(Layout::DEFAULT.rx_cells() == 5 * PAGE);
const _: () = assert!(Layout::DEFAULT.tx_cells() == 517 * PAGE);
const _: () = assert!(COUNTERS + 8 <= PAGE && FRAME_MAX <= CELL);

/// The ports a consumer's stack owns: the ports its process holds with the switch (one entry
/// for each description of a hold, the place's number) and the block of temporary ports of its
/// ring. Words and no lock: the glue of the stack asks inside the layer's lock for every packet
/// of its loopback interface. An entry goes with the last close of its description, so a port
/// whose group the process left is no longer counted as its own.
pub struct OwnPorts {
    /// Entry `i` is `port + 1` of a hold, 0 for none.
    ports: [core::sync::atomic::AtomicU32; OwnPorts::ENTRIES],
    /// The description of entry `i`, plus one.
    descriptions: [core::sync::atomic::AtomicU32; OwnPorts::ENTRIES],
    /// The first port and the count of the block, `first << 16 | count` (0: none).
    block: core::sync::atomic::AtomicU32,
}

impl OwnPorts {
    pub const ENTRIES: usize = 32;

    pub const fn new() -> OwnPorts {
        OwnPorts {
            ports: [const { core::sync::atomic::AtomicU32::new(0) }; OwnPorts::ENTRIES],
            descriptions: [const { core::sync::atomic::AtomicU32::new(0) }; OwnPorts::ENTRIES],
            block: core::sync::atomic::AtomicU32::new(0),
        }
    }

    pub fn set_block(&self, first: u16, count: u16) {
        use core::sync::atomic::Ordering::Release;
        self.block
            .store(u32::from(first) << 16 | u32::from(count), Release);
    }

    /// The description `description` holds `port`. False when the table is full (the packet for
    /// such a port goes to the switch, which hands it back to the stack when no one else holds
    /// it: the way is longer and no wrong answer follows).
    pub fn note(&self, port: u16, description: u32) -> bool {
        use core::sync::atomic::Ordering::{AcqRel, Acquire, Release};
        for (p, d) in self.ports.iter().zip(&self.descriptions) {
            if p.load(Acquire) == 0
                && d.compare_exchange(0, description.wrapping_add(1), AcqRel, Acquire)
                    .is_ok()
            {
                p.store(u32::from(port) + 1, Release);
                return true;
            }
        }
        false
    }

    /// The last close of description `description`: its entries go.
    pub fn forget(&self, description: u32) {
        use core::sync::atomic::Ordering::{Acquire, Release};
        for (p, d) in self.ports.iter().zip(&self.descriptions) {
            if d.load(Acquire) == description.wrapping_add(1) {
                p.store(0, Release);
                d.store(0, Release);
            }
        }
    }

    /// Whether `port` is one of the block or of a hold that is still open.
    pub fn owns(&self, port: u16) -> bool {
        use core::sync::atomic::Ordering::Acquire;
        let block = self.block.load(Acquire);
        let (first, count) = ((block >> 16) as u16, block & 0xffff);
        u32::from(port).wrapping_sub(u32::from(first)) < count
            || self
                .ports
                .iter()
                .any(|p| p.load(Acquire) == u32::from(port) + 1)
    }
}

impl Default for OwnPorts {
    fn default() -> OwnPorts {
        OwnPorts::new()
    }
}

/// An entry of DONE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Done {
    pub cell: u16,
    pub len: u16,
    pub flags: u16,
}

impl Done {
    pub fn to_bytes(self) -> [u8; 8] {
        let mut b = [0; 8];
        b[..2].copy_from_slice(&self.cell.to_le_bytes());
        b[2..4].copy_from_slice(&self.len.to_le_bytes());
        b[4..6].copy_from_slice(&self.flags.to_le_bytes());
        b
    }
    pub fn from_bytes(b: [u8; 8]) -> Done {
        Done {
            cell: u16::from_le_bytes([b[0], b[1]]),
            len: u16::from_le_bytes([b[2], b[3]]),
            flags: u16::from_le_bytes([b[4], b[5]]),
        }
    }
}

/// An entry of TX; the flags and the spare must be 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxEntry {
    pub len: u16,
    pub flags: u16,
    pub spare: u32,
}

impl TxEntry {
    pub fn to_bytes(self) -> [u8; 8] {
        let mut b = [0; 8];
        b[..2].copy_from_slice(&self.len.to_le_bytes());
        b[2..4].copy_from_slice(&self.flags.to_le_bytes());
        b[4..].copy_from_slice(&self.spare.to_le_bytes());
        b
    }
    pub fn from_bytes(b: [u8; 8]) -> TxEntry {
        TxEntry {
            len: u16::from_le_bytes([b[0], b[1]]),
            flags: u16::from_le_bytes([b[2], b[3]]),
            spare: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
}

fn invalid() -> Status {
    crate::code(crate::INVALID)
}

pub fn write_attach(layout: Layout, w: &mut Writer) -> Result<(), Status> {
    Method::Attach.header().write(w)?;
    w.u32(VERSION)?;
    w.u32(layout.rx_slots)?;
    w.u32(layout.tx_slots)?;
    w.u32(CELL as u32)
}

/// The layout of an ATTACH; INVALID for another version, sizes or cell.
pub fn read_attach(mut body: Reader<'_>) -> Result<Layout, Status> {
    let (version, rx, tx, cell) = (body.u32()?, body.u32()?, body.u32()?, body.u32()?);
    body.finish()?;
    if version != VERSION || cell as usize != CELL {
        return Err(invalid());
    }
    Layout::new(rx, tx).ok_or_else(invalid)
}

/// What ATTACH tells the consumer: its number and generation, the address
/// of device 0 and the block of ephemeral ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attached {
    pub consumer: u32,
    pub generation: u32,
    pub config: Config,
    pub block_first: u32,
    pub block_count: u32,
    /// The device completes the sums of TCP: only then may an entry say `TX_SUM` (else it is
    /// refused). The consumer sums its own segments otherwise.
    pub offload: bool,
    /// The device cuts frames of TCP into segments (`HOST_TSO4`): only then may an entry say
    /// `TX_SUM | TX_TSO` (else it is refused). Implies `offload`.
    pub tso: bool,
}

impl Attached {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(Status::Ok.code())?;
        w.u32(self.consumer)?;
        w.u32(self.generation)?;
        self.config.write_fields(w)?;
        w.u32(self.block_first)?;
        w.u32(self.block_count)?;
        w.u32(u32::from(self.offload))?;
        w.u32(u32::from(self.tso))
    }

    /// A refusal is its status alone and comes back as the error.
    pub fn read(reply: &[u8]) -> Result<Attached, Status> {
        let mut r = Reader::new(reply);
        let status = Status::from_code(r.u32()?);
        if status != Status::Ok {
            return Err(if reply.len() == proto_wire::HEADER_LEN {
                status
            } else {
                Status::BadSize
            });
        }
        let (consumer, generation) = (r.u32()?, r.u32()?);
        let config = Config::read_fields(&mut r)?;
        let (block_first, block_count) = (r.u32()?, r.u32()?);
        let offload = r.u32()? != 0;
        let tso = r.u32()? != 0;
        r.finish()?;
        Ok(Attached {
            consumer,
            generation,
            config,
            block_first,
            block_count,
            offload,
            tso,
        })
    }
}

/// The ports a PORT_HOLD asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hold {
    pub protocol: u32,
    pub first: u32,
    pub count: u32,
    pub flags: u32,
}

pub fn write_port_hold(h: &Hold, w: &mut Writer) -> Result<(), Status> {
    Method::PortHold.header().write(w)?;
    for v in [h.protocol, h.first, h.count, h.flags] {
        w.u32(v)?;
    }
    Ok(())
}

/// INVALID for a protocol other than TCP (6) and UDP (17), ports outside
/// 1..=65535, a count outside 1..=`HOLD_MAX` or flags other than REUSEPORT.
pub fn read_port_hold(mut body: Reader<'_>) -> Result<Hold, Status> {
    let h = Hold {
        protocol: body.u32()?,
        first: body.u32()?,
        count: body.u32()?,
        flags: body.u32()?,
    };
    body.finish()?;
    // `checked_add` keeps hostile values from wrapping in any build profile.
    let last = h.first.checked_add(h.count.wrapping_sub(1));
    let ports = h.first >= 1 && last.is_some_and(|l| l <= 65535);
    if !matches!(h.protocol, 6 | 17) || !ports || !(1..=HOLD_MAX).contains(&h.count) {
        return Err(invalid());
    }
    if h.flags & !REUSEPORT != 0 {
        return Err(invalid());
    }
    Ok(h)
}

/// The reply of PORT_HOLD: status and the place.
pub fn write_place_reply(place: u32, w: &mut Writer) -> Result<(), Status> {
    w.u32(Status::Ok.code())?;
    w.u32(place)
}

pub fn read_place_reply(reply: &[u8]) -> Result<u32, Status> {
    let mut r = Reader::new(reply);
    let status = Status::from_code(r.u32()?);
    if status != Status::Ok {
        return Err(status);
    }
    let place = r.u32()?;
    r.finish()?;
    Ok(place)
}

pub fn write_join(place: u32, w: &mut Writer) -> Result<(), Status> {
    Method::Join.header().write(w)?;
    w.u32(place)
}

pub fn read_join(mut body: Reader<'_>) -> Result<u32, Status> {
    let place = body.u32()?;
    body.finish()?;
    Ok(place)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_wire::Header;

    const CONFIG: Config = Config {
        address: [10, 0, 2, 15],
        prefix: 24,
        gateway: Some([10, 0, 2, 2]),
        dns: None,
        mac: [0x52, 0x54, 0, 1, 2, 3],
    };

    #[test]
    fn the_default_ring_is_645_pages_in_eleven_chunks() {
        let l = Layout::DEFAULT;
        assert_eq!((l.fill(), l.done(), l.tx()), (PAGE, 2 * PAGE, 4 * PAGE));
        assert_eq!(l.done_entry(1025), l.done() + 8);
        assert_eq!(l.fill_entry(u32::MAX), PAGE + 1023 * 4);
        assert_eq!(l.tx_cell(257), l.tx_cells() + CELL);
        assert_eq!(l.rx_cell(l.rx_slots - 1) + CELL, l.tx_cells());
        assert_eq!(l.total().div_ceil(PAGE).div_ceil(64), 11);
        let big = Layout::new(4096, 512).unwrap();
        assert_eq!(big.rx_cells() % PAGE, 0);
        assert!(big.tx_cell(u32::MAX) + CELL <= big.total());
    }

    #[test]
    fn sizes_are_powers_of_two_in_their_bounds() {
        assert!(Layout::new(256, 64).is_some() && Layout::new(4096, 512).is_some());
        for (rx, tx) in [
            (128, 64),
            (8192, 64),
            (300, 64),
            (256, 32),
            (256, 1024),
            (256, 100),
        ] {
            assert_eq!(Layout::new(rx, tx), None, "{rx} {tx}");
        }
    }

    #[test]
    fn a_port_is_own_while_a_description_of_its_hold_is_open() {
        let own = OwnPorts::new();
        own.set_block(49152, 512);
        assert!(own.owns(49152) && own.owns(49663) && !own.owns(49664) && !own.owns(49151));
        assert!(!own.owns(80));
        assert!(own.note(80, 7));
        // A second description of the same group (a fork's copy, a second socket).
        assert!(own.note(80, 9));
        assert!(own.owns(80));
        own.forget(7);
        assert!(own.owns(80), "one description of the group is still open");
        own.forget(9);
        assert!(!own.owns(80), "the last close takes the port out");
        // A close of a description that holds nothing takes nothing out.
        own.forget(1234);
        assert!(own.owns(49200));
        // The table of 32 entries fills and refuses the 33rd, and a close makes room.
        for i in 0..OwnPorts::ENTRIES as u32 {
            assert!(own.note(1000 + i as u16, i));
        }
        assert!(!own.note(2000, 99));
        own.forget(3);
        assert!(own.note(2000, 99));
        assert!(own.owns(2000) && !own.owns(1003));
    }

    #[test]
    fn entries_round_trip() {
        let d = Done {
            cell: 2047,
            len: 1514,
            flags: DONE_ARP_COPY,
        };
        assert_eq!(Done::from_bytes(d.to_bytes()), d);
        let t = TxEntry {
            len: 60,
            flags: 0,
            spare: 0,
        };
        assert_eq!(TxEntry::from_bytes(t.to_bytes()), t);
        assert_eq!(
            DONE_FLAGS,
            DONE_ARP_COPY | DONE_ICMP_ERROR | DONE_LOOP | DONE_SUM_OK
        );
        assert_eq!(DONE_SUM_OK, 1 << 8);
        assert_eq!(TX_SUM, 1);
        assert_eq!(
            DONE_SUM_OK & (DONE_ARP_COPY | DONE_ICMP_ERROR | DONE_LOOP),
            0
        );
        assert_eq!(DONE_LOOP, TX_LOOP);
    }

    #[test]
    fn a_frame_of_the_offload_takes_cells_and_runs_in_a_row_that_do_not_cross_the_end() {
        assert_eq!(cells(0), 1);
        assert_eq!(cells(1), 1);
        assert_eq!(cells(CELL), 1);
        assert_eq!(cells(CELL + 1), 2);
        assert_eq!(cells(10_300), 6);
        assert_eq!(cells(TSO_BODY_MAX + TSO_HEAD_MAX), 9);
        assert_eq!(cells(TSO_FRAME_MAX), TSO_CELLS_MAX);
        let l = Layout::new(256, 64).unwrap();
        assert!(l.tx_run_fits(0, 9) && l.tx_run_fits(55, 9) && !l.tx_run_fits(56, 9));
        assert!(l.tx_run_fits(63, 1) && !l.tx_run_fits(63, 2));
        assert!(l.tx_run_fits(64 + 55, 9), "the index wraps with the array");
        assert_eq!(l.tx_to_end(0), 64);
        assert_eq!(l.tx_to_end(61), 3);
        assert_eq!(l.tx_to_end(64), 64);
        assert_eq!(
            l.tx_to_end(u32::MAX),
            1,
            "indices wrap past u32 with the array"
        );
        // The cells of a run lie one after the other.
        assert_eq!(l.tx_cell(9) + 3 * CELL, l.tx_cell(12));
        // The flags of the offload and the pad are bits of their own.
        assert_eq!(TX_SUM | TX_TSO | TX_LOOP | TX_PAD, 15);
        assert_eq!(TX_TSO, 2);
        assert_eq!(TX_PAD, 8);
    }

    #[test]
    fn attach_round_trips_and_refuses_bad_sizes() {
        let mut w = Writer::new();
        write_attach(Layout::DEFAULT, &mut w).unwrap();
        let mut r = Reader::new(w.as_bytes());
        assert_eq!(Header::read(&mut r).unwrap(), Method::Attach.header());
        assert_eq!(read_attach(r), Ok(Layout::DEFAULT));
        let mut bad = w.as_bytes()[8..].to_vec();
        // A consumer of the version before TX_SUM and DONE_SUM_OK, and one of the next.
        for foreign in [VERSION - 1, VERSION + 1] {
            bad[0] = foreign as u8;
            assert_eq!(read_attach(Reader::new(&bad)), Err(invalid()));
        }
        bad[0] = VERSION as u8;
        bad[12] = 3;
        assert_eq!(read_attach(Reader::new(&bad)), Err(invalid()));
        assert_eq!(read_attach(Reader::new(&bad[..15])), Err(Status::BadSize));
    }

    #[test]
    fn attached_round_trips() {
        let a = Attached {
            consumer: 3,
            generation: 7,
            config: CONFIG,
            block_first: 49152,
            block_count: 512,
            offload: true,
            tso: true,
        };
        let mut w = Writer::new();
        a.write(&mut w).unwrap();
        assert!(w.as_bytes().len() <= abi::MESSAGE_MAX);
        assert_eq!(Attached::read(w.as_bytes()), Ok(a));
        let off = Attached {
            offload: false,
            tso: false,
            ..a
        };
        let mut w = Writer::new();
        off.write(&mut w).unwrap();
        assert_eq!(Attached::read(w.as_bytes()), Ok(off));
        assert_eq!(
            Attached::read(&w.as_bytes()[..w.as_bytes().len() - 1]),
            Err(Status::BadSize)
        );
        let down = proto_wire::reply(crate::code(crate::NET_DOWN));
        assert_eq!(Attached::read(&down), Err(crate::code(crate::NET_DOWN)));
    }

    #[test]
    fn port_hold_refuses_ranges_that_overflow() {
        for first in [u32::MAX, u32::MAX - 1, 65536] {
            for count in [1, 2, 16] {
                let h = Hold {
                    protocol: 17,
                    first,
                    count,
                    flags: 0,
                };
                let mut w = Writer::new();
                write_port_hold(&h, &mut w).unwrap();
                assert_eq!(
                    read_port_hold(Reader::new(&w.as_bytes()[8..])),
                    Err(invalid()),
                    "{h:?}"
                );
            }
        }
    }

    #[test]
    fn port_hold_and_join_round_trip() {
        let h = Hold {
            protocol: 6,
            first: 8080,
            count: 16,
            flags: REUSEPORT,
        };
        let mut w = Writer::new();
        write_port_hold(&h, &mut w).unwrap();
        let mut r = Reader::new(w.as_bytes());
        assert_eq!(Header::read(&mut r).unwrap(), Method::PortHold.header());
        assert_eq!(read_port_hold(r), Ok(h));
        for bad in [
            Hold { protocol: 1, ..h },
            Hold { first: 0, ..h },
            Hold { count: 0, ..h },
            Hold { count: 17, ..h },
            Hold { first: 65530, ..h },
            Hold { flags: 2, ..h },
        ] {
            let mut w = Writer::new();
            write_port_hold(&bad, &mut w).unwrap();
            assert_eq!(
                read_port_hold(Reader::new(&w.as_bytes()[8..])),
                Err(invalid()),
                "{bad:?}"
            );
        }
        let last = Hold {
            first: 65535,
            count: 1,
            ..h
        };
        let mut w = Writer::new();
        write_port_hold(&last, &mut w).unwrap();
        assert_eq!(read_port_hold(Reader::new(&w.as_bytes()[8..])), Ok(last));
        let mut w = Writer::new();
        write_place_reply(9, &mut w).unwrap();
        assert_eq!(read_place_reply(w.as_bytes()), Ok(9));
        let mut w = Writer::new();
        write_join(9, &mut w).unwrap();
        let mut r = Reader::new(w.as_bytes());
        assert_eq!(Header::read(&mut r).unwrap(), Method::Join.header());
        assert_eq!(read_join(r), Ok(9));
    }
}
