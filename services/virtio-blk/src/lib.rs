// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the driver of the Virtio block device decides (Virtio 1.2, 5.2),
//! apart from the device and the calls it makes: where its DMA object holds
//! the queue, the request headers and the cells (`dma`), the features it
//! asks for, the headers and the states of the device, the size of a BAR
//! and the cells of its clients (`Cells`) with the rule of the flush.
//! Everything here builds for the host too, where `cargo test -p
//! virtio-blk` exercises it.

#![cfg_attr(not(test), no_std)]

use proto_blk::{
    BUFFER_SIZE, CELL_BYTES, CELLS, FLAG_FLUSH, FLAG_READ_ONLY, SECTORS_MAX, in_range,
};
use proto_wire::Status;

/// The driver's DMA object (spec 7.3; spec 2, section 4): PAGES pages,
/// contiguous and uncached, one for all. The queue takes the first
/// QUEUE_PAGES (32 entries: the descriptors with the driver's ring, the
/// device's ring). Page 2 holds the headers and status bytes of the
/// requests, 32 bytes for each place, and the device's ID at ID_AT; page 3
/// is free; the cells of the staging area follow, CELL_PAGES each, four of
/// them. Uncached: no cache maintenance, only the barriers of the queue.
pub mod dma {
    use proto_blk::{CELL_BYTES, CELLS};

    pub const PAGES: usize = 32;
    pub const PAGE: usize = 4096;
    pub const QUEUE_PAGES: usize = 2;
    pub const QUEUE_SIZE: usize = 32;
    pub const HEADERS_PAGE: usize = 2;
    pub const CELL_PAGES: usize = CELL_BYTES as usize / PAGE;
    pub const FIRST_CELL_PAGE: usize = 4;
    /// The bytes of the answer to GET_ID (Virtio 1.2, 5.2.6).
    pub const ID_LEN: usize = 20;
    /// Where in the headers page the answer to GET_ID lies.
    pub const ID_AT: usize = 512;

    /// The places of the requests: one for each cell, one for FLUSH, one for GET_ID.
    pub const PLACES: usize = CELLS as usize + 2;
    pub const FLUSH_PLACE: usize = CELLS as usize;
    pub const ID_PLACE: usize = CELLS as usize + 1;

    /// The offset in the object of the header of `place`; its status byte
    /// follows 16 bytes after.
    pub const fn header(place: usize) -> usize {
        HEADERS_PAGE * PAGE + 32 * place
    }

    pub const fn status(place: usize) -> usize {
        header(place) + 16
    }

    pub const fn id() -> usize {
        HEADERS_PAGE * PAGE + ID_AT
    }

    /// The offset in the object of staging cell `cell`.
    pub const fn cell(cell: usize) -> usize {
        (FIRST_CELL_PAGE + CELL_PAGES * cell) * PAGE
    }

    // The cells fit the object, which is a power of two of pages.
    const _: () = assert!(FIRST_CELL_PAGE + CELL_PAGES * CELLS as usize <= PAGES);
    const _: () = assert!(PAGES.is_power_of_two());
    // A header, its status byte and the ID stay in their page.
    const _: () = assert!(status(PLACES - 1) < (HEADERS_PAGE + 1) * PAGE);
    const _: () = assert!(id() + ID_LEN < (HEADERS_PAGE + 1) * PAGE);
    const _: () = assert!(id() > status(PLACES - 1));
}

/// The most descriptors with the device at once: a read or a write has
/// three (header, data, status) for each of the cells, a flush two, GET_ID
/// three. The queue's 32 entries are enough.
pub const DESCRIPTORS_MAX: usize = CELLS as usize * 3 + 2 + 3;
const _: () = assert!(DESCRIPTORS_MAX <= dma::QUEUE_SIZE);

/// The feature bits of the block device (Virtio 1.2, 5.2.3) and the
/// transport's `VIRTIO_F_VERSION_1`.
pub mod feature {
    pub const RO: u64 = 1 << 5;
    pub const BLK_SIZE: u64 = 1 << 6;
    pub const FLUSH: u64 = 1 << 9;
    pub const VERSION_1: u64 = 1 << 32;
    /// What the driver asks for besides VERSION_1.
    pub const WANTED: u64 = RO | BLK_SIZE | FLUSH;
}

/// The features both the device and the driver have, or none at all for a
/// device without `VIRTIO_F_VERSION_1`.
pub fn negotiate(offered: u64) -> Option<u64> {
    virtio_mmio::negotiate(offered, feature::WANTED | feature::VERSION_1).ok()
}

/// The flags of INFO (proto_blk) for the features the driver ended up with.
pub const fn flags(features: u64) -> u32 {
    let mut flags = 0;
    if features & feature::FLUSH != 0 {
        flags |= FLAG_FLUSH;
    }
    if features & feature::RO != 0 {
        flags |= FLAG_READ_ONLY;
    }
    flags
}

/// The block size to report: the device's `blk_size` when it was
/// negotiated and sane, else a sector's.
pub const fn block_size(features: u64, config: u32) -> u32 {
    if features & feature::BLK_SIZE != 0 && config >= 512 && config.is_power_of_two() {
        config
    } else {
        512
    }
}

/// What the line of the driver says about the flags.
pub const fn describe(flags: u32) -> &'static str {
    if flags & FLAG_READ_ONLY != 0 {
        "read-only"
    } else if flags & FLAG_FLUSH != 0 {
        "flush"
    } else {
        "no flush"
    }
}

/// The types of request (Virtio 1.2, 5.2.6) and the header: type, a
/// reserved word of zero, the sector.
pub mod request {
    pub const IN: u32 = 0;
    pub const OUT: u32 = 1;
    pub const FLUSH: u32 = 4;
    pub const GET_ID: u32 = 8;
    pub const HEADER_LEN: usize = 16;

    pub fn header(kind: u32, sector: u64) -> [u8; HEADER_LEN] {
        let mut h = [0; HEADER_LEN];
        h[..4].copy_from_slice(&kind.to_le_bytes());
        h[8..].copy_from_slice(&sector.to_le_bytes());
        h
    }

    /// The status byte the driver writes before a request; the device
    /// overwrites it.
    pub const PENDING: u8 = 0xFF;
}

/// What the device answered (Virtio 1.2, 5.2.6): the status byte of a
/// request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Io,
    Unsupported,
}

impl Outcome {
    /// 0 is OK, 2 UNSUPP, and anything else, IOERR (1) and the byte the
    /// driver left, an error of input and output.
    pub const fn from_byte(byte: u8) -> Outcome {
        match byte {
            0 => Outcome::Ok,
            2 => Outcome::Unsupported,
            _ => Outcome::Io,
        }
    }

    /// The refusal TAKE gives; None for OK.
    pub const fn refusal(self) -> Option<Status> {
        match self {
            Outcome::Ok => None,
            Outcome::Io => Some(proto_blk::code(proto_blk::IO)),
            Outcome::Unsupported => Some(proto_blk::code(proto_blk::UNSUPPORTED)),
        }
    }
}

/// The size of a 64-bit memory BAR from the two words read back after
/// all ones were written to them (PCI 3.0, 6.2.5.1); 0 for a BAR that is
/// not implemented.
pub const fn bar_size(low: u32, high: u32) -> u64 {
    let mask = (high as u64) << 32 | (low & !0xF) as u64;
    (!mask).wrapping_add(1)
}

/// What a request is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Read,
    Write,
    Flush,
}

/// The state of a place (the rule of the flush): the request is with the device, has its
/// answer and waits for TAKE, or was let go (CANCEL, the client's end) and
/// the device still has it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Free,
    Device,
    Done(Outcome),
    Orphan,
}

/// Why a request is refused, before the device sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    BadSize,
    Invalid,
    NoBuffer,
    Busy,
    Range,
    ReadOnly,
    Unsupported,
}

impl Refusal {
    pub const fn status(self) -> Status {
        match self {
            Refusal::BadSize => Status::BadSize,
            Refusal::Invalid => proto_blk::code(proto_blk::INVALID),
            Refusal::NoBuffer => proto_blk::code(proto_blk::NO_BUFFER),
            Refusal::Busy => proto_blk::code(proto_blk::BUSY),
            Refusal::Range => proto_blk::code(proto_blk::RANGE),
            Refusal::ReadOnly => proto_blk::code(proto_blk::READ_ONLY),
            Refusal::Unsupported => proto_blk::code(proto_blk::UNSUPPORTED),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Place {
    state: State,
    kind: Kind,
    label: u64,
    key: u64,
    token: u16,
    count: u32,
}

const FREE: Place = Place {
    state: State::Free,
    kind: Kind::Read,
    label: 0,
    key: 0,
    token: 0,
    count: 0,
};

/// A request that went through TAKE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Finished {
    pub place: usize,
    pub kind: Kind,
    pub count: u32,
    pub outcome: Outcome,
}

/// What TAKE found for a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Taken {
    /// The device answered; the place is free again.
    Done(Finished),
    /// The device still has the request.
    Waits,
    Unknown,
}

/// What the answer of the device did to its place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    /// The client waits for the result: tell it.
    Tell { label: u64, key: u64 },
    /// The request was let go; the place is free.
    Dropped,
}

/// The places of the requests with the device: a cell for each of the
/// CELLS, one for FLUSH. Everything the rule of the flush needs is here.
#[derive(Debug)]
pub struct Cells {
    places: [Place; dma::FLUSH_PLACE + 1],
    sectors: u64,
    flags: u32,
}

impl Cells {
    pub const fn new(sectors: u64, flags: u32) -> Cells {
        Cells {
            places: [FREE; dma::FLUSH_PLACE + 1],
            sectors,
            flags,
        }
    }

    pub fn state(&self, place: usize) -> State {
        self.places[place].state
    }

    /// What the request in `place` is and how many sectors it names.
    pub fn request(&self, place: usize) -> (Kind, u32) {
        (self.places[place].kind, self.places[place].count)
    }

    /// Whether a write is with the device, one the client let go included.
    fn write_at_device(&self) -> bool {
        self.places[..CELLS as usize]
            .iter()
            .any(|p| p.kind == Kind::Write && matches!(p.state, State::Device | State::Orphan))
    }

    fn flush_at_device(&self) -> bool {
        matches!(
            self.places[dma::FLUSH_PLACE].state,
            State::Device | State::Orphan
        )
    }

    /// The place for a READ or a WRITE of `count` sectors from `sector` in
    /// `cell` (`buffered`: the session has its shared buffer), or why not.
    /// The checks go from the request to the state: the size, the cell, the
    /// disk's mode, the buffer, the range, then the state of the place and,
    /// for a write, of the flush.
    pub fn admit_io(
        &self,
        kind: Kind,
        cell: u32,
        count: u32,
        sector: u64,
        buffered: bool,
    ) -> Result<usize, Refusal> {
        debug_assert!(kind != Kind::Flush);
        if !(1..=SECTORS_MAX).contains(&count) {
            return Err(Refusal::BadSize);
        }
        if cell >= CELLS {
            return Err(Refusal::Invalid);
        }
        if kind == Kind::Write && self.flags & FLAG_READ_ONLY != 0 {
            return Err(Refusal::ReadOnly);
        }
        if !buffered {
            return Err(Refusal::NoBuffer);
        }
        if !in_range(self.sectors, sector, count) {
            return Err(Refusal::Range);
        }
        let place = cell as usize;
        if self.places[place].state != State::Free {
            return Err(Refusal::Busy);
        }
        if kind == Kind::Write && self.flush_at_device() {
            return Err(Refusal::Busy);
        }
        Ok(place)
    }

    /// The place of a FLUSH: the device must have the flush cache, no
    /// write may be with it (the FLUSH would not cover the answer it is
    /// about to give), and no other flush may be.
    pub fn admit_flush(&self) -> Result<usize, Refusal> {
        if self.flags & FLAG_FLUSH == 0 {
            return Err(Refusal::Unsupported);
        }
        if self.places[dma::FLUSH_PLACE].state != State::Free || self.write_at_device() {
            return Err(Refusal::Busy);
        }
        Ok(dma::FLUSH_PLACE)
    }

    /// The request in the free `place` is with the device under `token`.
    pub fn begin(
        &mut self,
        place: usize,
        kind: Kind,
        label: u64,
        key: u64,
        token: u16,
        count: u32,
    ) {
        debug_assert_eq!(self.places[place].state, State::Free);
        self.places[place] = Place {
            state: State::Device,
            kind,
            label,
            key,
            token,
            count,
        };
    }

    /// The place of a request that failed to reach the device.
    pub fn undo(&mut self, place: usize) {
        self.places[place] = FREE;
    }

    /// The place of the request the device holds under `token`.
    pub fn find(&self, token: u16) -> Option<usize> {
        self.places
            .iter()
            .position(|p| matches!(p.state, State::Device | State::Orphan) && p.token == token)
    }

    /// The device answered the request in `place`.
    pub fn complete(&mut self, place: usize, outcome: Outcome) -> Completion {
        let p = &mut self.places[place];
        match p.state {
            State::Device => {
                p.state = State::Done(outcome);
                Completion::Tell {
                    label: p.label,
                    key: p.key,
                }
            }
            _ => {
                *p = FREE;
                Completion::Dropped
            }
        }
    }

    fn lookup(&self, label: u64, key: u64) -> Option<usize> {
        self.places.iter().position(|p| {
            matches!(p.state, State::Device | State::Done(_)) && p.label == label && p.key == key
        })
    }

    /// TAKE: the result of the operation `key` of `label` once the device
    /// answered; the place goes free with it.
    pub fn take(&mut self, label: u64, key: u64) -> Taken {
        let Some(place) = self.lookup(label, key) else {
            return Taken::Unknown;
        };
        let p = &mut self.places[place];
        match p.state {
            State::Done(outcome) => {
                let finished = Finished {
                    place,
                    kind: p.kind,
                    count: p.count,
                    outcome,
                };
                *p = FREE;
                Taken::Done(finished)
            }
            _ => Taken::Waits,
        }
    }

    /// CANCEL: the operation ends at once. A request the device has keeps
    /// its place until the device answers. False for a key unknown.
    pub fn cancel(&mut self, label: u64, key: u64) -> bool {
        let Some(place) = self.lookup(label, key) else {
            return false;
        };
        let p = &mut self.places[place];
        *p = match p.state {
            State::Device => Place {
                state: State::Orphan,
                ..*p
            },
            _ => FREE,
        };
        true
    }

    /// The session of `label` went: what the device has becomes orphans,
    /// the answers nobody took go free.
    pub fn gone(&mut self, label: u64) {
        for p in &mut self.places {
            if p.label != label {
                continue;
            }
            match p.state {
                State::Device => p.state = State::Orphan,
                State::Done(_) => *p = FREE,
                State::Free | State::Orphan => {}
            }
        }
    }
}

const _: () = assert!(BUFFER_SIZE == CELLS * CELL_BYTES);

#[cfg(test)]
mod tests {
    use super::*;

    const SECTORS: u64 = 131_072;

    fn cells() -> Cells {
        Cells::new(SECTORS, FLAG_FLUSH)
    }

    fn start(c: &mut Cells, kind: Kind, cell: u32, token: u16) -> usize {
        let place = c.admit_io(kind, cell, 8, 100, true).unwrap();
        c.begin(place, kind, 7, 100 + u64::from(token), token, 8);
        place
    }

    fn flush(c: &mut Cells, token: u16) -> usize {
        let place = c.admit_flush().unwrap();
        c.begin(place, Kind::Flush, 7, 900, token, 0);
        place
    }

    #[test]
    fn the_object_holds_the_queue_the_headers_and_four_cells() {
        assert_eq!(dma::header(0), 0x2000);
        assert_eq!(dma::status(0), 0x2010);
        assert_eq!(dma::status(5), 0x2000 + 5 * 32 + 16);
        assert_eq!(dma::id(), 0x2200);
        assert_eq!(dma::cell(0), 4 * 4096);
        assert_eq!(dma::cell(3) + CELL_BYTES as usize, 20 * 4096);
        assert_eq!(dma::PLACES, 6);
        assert_eq!(DESCRIPTORS_MAX, 17);
    }

    #[test]
    fn a_most_loaded_queue_has_seventeen_descriptors() {
        let (read_write, flush, get_id) = (3, 2, 3);
        assert_eq!(
            CELLS as usize * read_write + flush + get_id,
            DESCRIPTORS_MAX
        );
    }

    #[test]
    fn the_headers_are_those_of_the_device() {
        assert_eq!(request::header(request::IN, 0), [0; 16]);
        assert_eq!(
            request::header(request::OUT, 0x0102_0304_0506_0708),
            [1, 0, 0, 0, 0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1]
        );
        assert_eq!(request::header(request::FLUSH, 0)[0], 4);
        assert_eq!(request::header(request::GET_ID, 0)[0], 8);
        assert_eq!(request::header(request::GET_ID, 0)[4..8], [0; 4]);
    }

    #[test]
    fn the_status_byte_is_read_as_the_device_gave_it() {
        assert_eq!(Outcome::from_byte(0), Outcome::Ok);
        assert_eq!(Outcome::from_byte(1), Outcome::Io);
        assert_eq!(Outcome::from_byte(2), Outcome::Unsupported);
        assert_eq!(Outcome::from_byte(3), Outcome::Io);
        assert_eq!(Outcome::from_byte(request::PENDING), Outcome::Io);
        assert_eq!(Outcome::Ok.refusal(), None);
        assert_eq!(Outcome::Io.refusal(), Some(Status::Unknown(1102)));
        assert_eq!(Outcome::Unsupported.refusal(), Some(Status::Unknown(1103)));
    }

    #[test]
    fn the_features_need_version_1_and_set_the_flags() {
        let all = feature::WANTED | feature::VERSION_1;
        assert_eq!(negotiate(all), Some(all));
        assert_eq!(negotiate(feature::WANTED), None);
        assert_eq!(negotiate(0), None);
        // A bit the driver did not ask for is dropped.
        assert_eq!(negotiate(all | 1 << 12), Some(all));
        let no_flush = negotiate(feature::VERSION_1 | feature::BLK_SIZE).unwrap();
        assert_eq!(flags(no_flush), 0);
        assert_eq!(describe(flags(no_flush)), "no flush");
        assert_eq!(flags(all), FLAG_FLUSH | FLAG_READ_ONLY);
        assert_eq!(describe(flags(all)), "read-only");
        assert_eq!(describe(flags(feature::FLUSH)), "flush");
    }

    #[test]
    fn the_block_size_is_the_devices_when_it_is_sane() {
        assert_eq!(block_size(feature::BLK_SIZE, 4096), 4096);
        assert_eq!(block_size(feature::BLK_SIZE, 512), 512);
        assert_eq!(block_size(feature::BLK_SIZE, 0), 512);
        assert_eq!(block_size(feature::BLK_SIZE, 1000), 512);
        assert_eq!(block_size(0, 4096), 512);
    }

    #[test]
    fn a_bar_of_16_kib_reads_back_its_mask() {
        assert_eq!(bar_size(0xFFFF_C00C, 0xFFFF_FFFF), 0x4000);
        assert_eq!(bar_size(0xFFFF_8000, 0xFFFF_FFFF), 0x8000);
        assert_eq!(bar_size(0, 0), 0);
        assert_eq!(bar_size(0x0000_0000, 0xFFFF_FFFF), 1 << 32);
    }

    #[test]
    fn a_request_is_checked_from_its_size_to_its_place() {
        let c = cells();
        let io =
            |count, cell, buffered, sector| c.admit_io(Kind::Read, cell, count, sector, buffered);
        assert_eq!(io(0, 0, true, 0), Err(Refusal::BadSize));
        assert_eq!(io(33, 0, true, 0), Err(Refusal::BadSize));
        assert_eq!(io(1, 4, true, 0), Err(Refusal::Invalid));
        assert_eq!(io(1, 0, false, 0), Err(Refusal::NoBuffer));
        assert_eq!(io(1, 3, true, 0), Ok(3));
        assert_eq!(io(32, 0, true, 0), Ok(0));
        assert_eq!(Refusal::BadSize.status(), Status::BadSize);
        assert_eq!(Refusal::NoBuffer.status(), Status::Unknown(1106));
    }

    #[test]
    fn the_range_is_checked_at_the_edge() {
        let c = cells();
        let io = |sector, count| c.admit_io(Kind::Read, 0, count, sector, true);
        assert_eq!(io(SECTORS - 32, 32), Ok(0));
        assert_eq!(io(SECTORS - 1, 1), Ok(0));
        assert_eq!(io(SECTORS - 1, 2), Err(Refusal::Range));
        assert_eq!(io(SECTORS, 1), Err(Refusal::Range));
        assert_eq!(io(u64::MAX, 2), Err(Refusal::Range));
        assert_eq!(io(u64::MAX - 1, 32), Err(Refusal::Range));
    }

    #[test]
    fn a_read_only_disk_refuses_writes_alone() {
        let c = Cells::new(SECTORS, FLAG_READ_ONLY);
        assert_eq!(
            c.admit_io(Kind::Write, 0, 1, 0, true),
            Err(Refusal::ReadOnly)
        );
        assert_eq!(c.admit_io(Kind::Read, 0, 1, 0, true), Ok(0));
        assert_eq!(c.admit_flush(), Err(Refusal::Unsupported));
    }

    #[test]
    fn a_disk_without_the_flush_cache_refuses_flush_and_serves_the_rest() {
        let mut c = Cells::new(SECTORS, 0);
        assert_eq!(c.admit_flush(), Err(Refusal::Unsupported));
        start(&mut c, Kind::Write, 0, 1);
        assert_eq!(c.admit_io(Kind::Read, 1, 1, 0, true), Ok(1));
    }

    #[test]
    fn a_cell_is_busy_from_its_start_to_its_take() {
        let mut c = cells();
        let place = start(&mut c, Kind::Read, 2, 5);
        assert_eq!(c.admit_io(Kind::Read, 2, 1, 0, true), Err(Refusal::Busy));
        assert_eq!(c.take(7, 999), Taken::Unknown);
        assert_eq!(c.take(7, 105), Taken::Waits);
        assert_eq!(c.find(5), Some(place));
        assert_eq!(
            c.complete(place, Outcome::Ok),
            Completion::Tell { label: 7, key: 105 }
        );
        // The answer is there, and the cell still busy until TAKE.
        assert_eq!(c.admit_io(Kind::Read, 2, 1, 0, true), Err(Refusal::Busy));
        assert_eq!(c.find(5), None);
        assert_eq!(
            c.take(7, 105),
            Taken::Done(Finished {
                place,
                kind: Kind::Read,
                count: 8,
                outcome: Outcome::Ok
            })
        );
        assert_eq!(c.state(place), State::Free);
        assert_eq!(c.take(7, 105), Taken::Unknown);
        assert_eq!(c.admit_io(Kind::Read, 2, 1, 0, true), Ok(2));
        // Another client's key is not this one's.
        let place = start(&mut c, Kind::Read, 2, 6);
        assert_eq!(c.take(8, 106), Taken::Unknown);
        assert!(!c.cancel(8, 106));
        assert_eq!(c.state(place), State::Device);
    }

    #[test]
    fn a_flush_is_refused_while_a_write_is_with_the_device() {
        let mut c = cells();
        let w = start(&mut c, Kind::Write, 1, 1);
        assert_eq!(c.admit_flush(), Err(Refusal::Busy));
        // A read does not stop it.
        let r = start(&mut c, Kind::Read, 0, 2);
        c.complete(w, Outcome::Ok);
        assert_eq!(c.admit_flush(), Ok(dma::FLUSH_PLACE));
        let _ = r;
        // A write that has its answer lies in the device's cache before the flush.
        let f = flush(&mut c, 3);
        assert_eq!(c.admit_flush(), Err(Refusal::Busy));
        c.complete(f, Outcome::Ok);
        assert_eq!(c.admit_flush(), Err(Refusal::Busy));
        assert!(matches!(c.take(7, 900), Taken::Done(_)));
        assert_eq!(c.admit_flush(), Ok(dma::FLUSH_PLACE));
    }

    #[test]
    fn a_write_is_refused_while_a_flush_is_with_the_device_and_a_read_goes() {
        let mut c = cells();
        let f = flush(&mut c, 1);
        assert_eq!(c.admit_io(Kind::Write, 0, 1, 0, true), Err(Refusal::Busy));
        assert_eq!(c.admit_io(Kind::Read, 0, 1, 0, true), Ok(0));
        c.complete(f, Outcome::Ok);
        assert_eq!(c.admit_io(Kind::Write, 0, 1, 0, true), Ok(0));
    }

    #[test]
    fn a_write_the_client_let_go_still_stops_a_flush() {
        let mut c = cells();
        let w = start(&mut c, Kind::Write, 0, 1);
        assert!(c.cancel(7, 101));
        assert_eq!(c.state(w), State::Orphan);
        assert_eq!(c.admit_flush(), Err(Refusal::Busy));
        assert_eq!(c.admit_io(Kind::Read, 0, 1, 0, true), Err(Refusal::Busy));
        assert_eq!(c.find(1), Some(w));
        assert_eq!(c.complete(w, Outcome::Ok), Completion::Dropped);
        assert_eq!(c.state(w), State::Free);
        assert_eq!(c.admit_flush(), Ok(dma::FLUSH_PLACE));
    }

    #[test]
    fn cancel_before_and_after_the_answer() {
        let mut c = cells();
        let p = start(&mut c, Kind::Read, 0, 1);
        assert!(c.cancel(7, 101));
        assert!(!c.cancel(7, 101));
        assert_eq!(c.take(7, 101), Taken::Unknown);
        assert_eq!(c.complete(p, Outcome::Io), Completion::Dropped);
        let p = start(&mut c, Kind::Read, 0, 2);
        c.complete(p, Outcome::Ok);
        assert!(c.cancel(7, 102));
        assert_eq!(c.state(p), State::Free);
    }

    #[test]
    fn a_session_that_goes_leaves_orphans_and_frees_the_answers() {
        let mut c = cells();
        let device = start(&mut c, Kind::Write, 0, 1);
        let done = start(&mut c, Kind::Read, 1, 2);
        c.complete(done, Outcome::Ok);
        let orphan = start(&mut c, Kind::Read, 2, 3);
        c.cancel(7, 103);
        let other = c.admit_io(Kind::Read, 3, 1, 0, true).unwrap();
        c.begin(other, Kind::Read, 9, 500, 4, 1);
        c.gone(7);
        assert_eq!(c.state(device), State::Orphan);
        assert_eq!(c.state(done), State::Free);
        assert_eq!(c.state(orphan), State::Orphan);
        assert_eq!(c.state(other), State::Device);
        assert_eq!(c.complete(device, Outcome::Ok), Completion::Dropped);
        assert_eq!(c.complete(orphan, Outcome::Io), Completion::Dropped);
        assert_eq!(c.state(device), State::Free);
        assert_eq!(c.state(orphan), State::Free);
    }

    #[test]
    fn a_request_that_never_reached_the_device_gives_its_place_back() {
        let mut c = cells();
        let p = start(&mut c, Kind::Write, 0, 1);
        c.undo(p);
        assert_eq!(c.state(p), State::Free);
        assert_eq!(c.admit_flush(), Ok(dma::FLUSH_PLACE));
    }
}
