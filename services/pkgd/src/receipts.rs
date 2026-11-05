// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The receipt of a package and the group of receipts (pk3-design R7, R9): what an
//! installation keeps between INSTALL_BEGIN and the end of its group. A receipt counts
//! the bytes fed (by FEED), hashed and written to the extent; it hashes in portions of
//! 16 KiB and takes the SHA-256 of the covered part (all but the trailer page) at the
//! page where the covered part ends, whatever the sizes of the pieces fed. A group holds
//! the store for one session from its first INSTALL_BEGIN to its end, keeps the packages
//! that were received and checked, and builds the table of the new state. Nothing here
//! touches the disk or memory: the service does, and tells what it did.

use crate::store::{
    BLOCK, DEPENDENCY, Extent, NO_REPO, PACKAGE, PACKAGES, RECORDS, Record, Table, WORLD,
    find_free, to_field,
};
use pkgfmt::Name;
use pkgfmt::sha::Stream;

/// The bytes the hash and the writes take at a time.
pub const PORTION: u64 = 16 * 1024;
/// The packages one group holds at most.
pub const GROUP_MAX: usize = 4;

/// FEED past the size of the package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLong;

/// Whether `len` more bytes fit a package of `size` of which `fed` came.
pub fn check_feed(size: u64, fed: u64, len: u32) -> Result<(), TooLong> {
    if fed
        .checked_add(u64::from(len))
        .is_some_and(|end| end <= size)
    {
        Ok(())
    } else {
        Err(TooLong)
    }
}

/// A package being received.
pub struct Receipt {
    number: u32,
    size: u64,
    fed: u64,
    hashed: u64,
    written: u64,
    stream: Stream,
    covered: Option<[u8; 32]>,
}

impl Receipt {
    /// A package of `size` bytes, whole pages, two at least.
    pub fn new(number: u32, size: u64) -> Receipt {
        Receipt {
            number,
            size,
            fed: 0,
            hashed: 0,
            written: 0,
            stream: Stream::new(),
            covered: None,
        }
    }

    pub fn number(&self) -> u32 {
        self.number
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// The bytes fed so far reached `fed` (the main thread's count).
    pub fn set_fed(&mut self, fed: u64) {
        self.fed = fed.min(self.size).max(self.fed);
    }

    /// The next bytes to hash, `from..to`: at most a portion, and not past the page
    /// where the covered part ends until the hash of the covered part is taken.
    pub fn portion(&self) -> Option<(u64, u64)> {
        let to = self.fed.min(self.hashed + PORTION);
        (to > self.hashed).then_some((self.hashed, to))
    }

    /// The bytes `hashed..hashed + bytes.len()` go into the hash.
    pub fn absorb(&mut self, bytes: &[u8]) {
        let end = self.hashed + bytes.len() as u64;
        let boundary = self.size - BLOCK as u64;
        if self.covered.is_none() && end >= boundary {
            let head = (boundary - self.hashed) as usize;
            self.stream.update(&bytes[..head]);
            self.covered = Some(self.stream.clone().finish());
            self.stream.update(&bytes[head..]);
        } else {
            self.stream.update(bytes);
        }
        self.hashed = end;
    }

    /// The whole blocks hashed and not yet written, as `(first block of the package,
    /// blocks)`, at most a portion.
    pub fn blocks_to_write(&self) -> Option<(u64, u64)> {
        let first = self.written / BLOCK as u64;
        let ready = self.hashed / BLOCK as u64;
        let blocks = (ready - first).min(PORTION / BLOCK as u64);
        (blocks > 0).then_some((first, blocks))
    }

    pub fn wrote(&mut self, blocks: u64) {
        self.written += blocks * BLOCK as u64;
    }

    /// Everything came, was hashed and written.
    pub fn complete(&self) -> bool {
        self.fed == self.size && self.hashed == self.size && self.written == self.size
    }

    /// The SHA-256 of the covered part and of the whole file; None unless complete.
    pub fn digests(self) -> Option<([u8; 32], [u8; 32])> {
        let covered = self.covered?;
        self.complete().then(|| (covered, self.stream.finish()))
    }
}

/// What INSTALL_BEGIN asks for.
#[derive(Clone, Copy, Debug)]
pub struct BeginArgs<'a> {
    pub name: &'a [u8],
    pub version: &'a [u8],
    pub size: u64,
    pub sha256: [u8; 32],
    /// The place of the repository in the table.
    pub repo: usize,
    pub world: bool,
}

/// A package received and checked, that waits for the end of its group.
#[derive(Clone, Copy, Debug)]
pub struct Staged {
    pub number: u32,
    /// The place in the table and the extent of its data.
    pub slot: usize,
    pub record: Record,
}

/// A package that was committed: what waits for the end of the group, and the
/// SHA-256 of its covered part and of the whole file.
#[derive(Clone, Copy, Debug)]
pub struct Committed {
    pub staged: Staged,
    pub covered: [u8; 32],
    pub whole: [u8; 32],
}

/// The one open group: the session that holds the store and what it received.
pub struct Group {
    owner: u64,
    staged: [Option<Staged>; GROUP_MAX],
    open: Option<(Receipt, Staged)>,
    numbers: u32,
}

impl Default for Group {
    fn default() -> Self {
        Self::new()
    }
}

impl Group {
    pub const fn new() -> Group {
        Group {
            owner: 0,
            staged: [None; GROUP_MAX],
            open: None,
            numbers: 0,
        }
    }

    /// The label of the session that holds the store, none when no group is open.
    pub fn owner(&self) -> Option<u64> {
        (self.owner != 0).then_some(self.owner)
    }

    /// The receipt being fed, when it is `number`.
    pub fn receipt(&mut self, number: u32) -> Option<&mut Receipt> {
        self.open
            .as_mut()
            .map(|(r, _)| r)
            .filter(|r| r.number == number)
    }

    /// The packages received and checked, in order.
    pub fn staged(&self) -> impl Iterator<Item = &Staged> {
        self.staged.iter().flatten()
    }

    /// The group is over: the store is free, what was taken is free (the table holds
    /// no extent of it).
    pub fn release(&mut self) {
        *self = Group {
            numbers: self.numbers,
            ..Group::new()
        };
    }

    /// INSTALL_BEGIN for `owner` against `table` of the state `opened`: the number of the
    /// receipt, the place and the extent taken, or the code of the refusal. The group
    /// opens with the first receipt; a receipt of the same session joins it once the
    /// one before is committed.
    pub fn begin(
        &mut self,
        owner: u64,
        table: &Table,
        table_extent: Extent,
        disk_blocks: u64,
        args: &BeginArgs<'_>,
        now: u64,
    ) -> Result<(u32, usize, Extent), u32> {
        if (self.owner != 0 && self.owner != owner) || self.open.is_some() {
            return Err(proto_pkg::BUSY);
        }
        if self.staged().count() >= GROUP_MAX {
            return Err(proto_pkg::INVALID);
        }
        let named = Name::new(core::str::from_utf8(args.name).map_err(|_| proto_pkg::INVALID)?);
        if named.is_err()
            || args.version.is_empty()
            || args.repo >= crate::store::REPOS
            || table.repo(args.repo).is_none()
            || self.staged().any(|s| s.record.name_bytes() == args.name)
        {
            return Err(proto_pkg::INVALID);
        }
        let (Some(name), Some(version)) = (to_field(args.name), to_field(args.version)) else {
            return Err(proto_pkg::INVALID);
        };
        // Whole pages, the covered part and the trailer page at least.
        if args.size < 2 * BLOCK as u64 || !args.size.is_multiple_of(BLOCK as u64) {
            return Err(proto_pkg::BAD_PACKAGE);
        }
        let blocks = args.size / BLOCK as u64;
        if blocks > u64::from(u32::MAX) {
            return Err(proto_pkg::NO_SPACE);
        }
        let Some(slot) = (0..PACKAGES)
            .find(|&i| table.record(i).kind != PACKAGE && !self.staged().any(|s| s.slot == i))
        else {
            return Err(proto_pkg::NO_SPACE);
        };
        let mut held = [Extent {
            first: 0,
            blocks: 0,
        }; RECORDS + 1];
        let n = table.occupied(table_extent, &mut held);
        let mut taken = [Extent {
            first: 0,
            blocks: 0,
        }; GROUP_MAX];
        let mut m = 0;
        for s in self.staged() {
            taken[m] = s.record.extent();
            m += 1;
        }
        let Some(first) = find_free(&held[..n], &taken[..m], disk_blocks, blocks) else {
            return Err(proto_pkg::NO_SPACE);
        };
        self.numbers = self.numbers.wrapping_add(1).max(1);
        let record = Record {
            kind: PACKAGE,
            flags: if args.world { WORLD } else { DEPENDENCY },
            repo: args.repo as u8,
            first,
            blocks: blocks as u32,
            length: args.size,
            number: 0,
            installed: now,
            sha256: args.sha256,
            name,
            version,
        };
        let staged = Staged {
            number: self.numbers,
            slot,
            record,
        };
        self.owner = owner;
        self.open = Some((Receipt::new(self.numbers, args.size), staged));
        Ok((self.numbers, slot, record.extent()))
    }

    /// INSTALL_COMMIT of receipt `number`, which must be complete: the package waits for
    /// the end of the group. `INVALID` for another number or a receipt that is not complete.
    pub fn commit(&mut self, number: u32) -> Result<Committed, u32> {
        let Some((receipt, staged)) = self.open.take_if(|(r, _)| r.number == number) else {
            return Err(proto_pkg::INVALID);
        };
        if !receipt.complete() {
            self.open = Some((receipt, staged));
            return Err(proto_pkg::INVALID);
        }
        // The digests are taken from the receipt that is whole.
        let (covered, whole) = receipt.digests().ok_or(proto_pkg::INVALID)?;
        let place = self
            .staged
            .iter_mut()
            .find(|s| s.is_none())
            .expect("a group below its limit has a place");
        *place = Some(staged);
        Ok(Committed {
            staged,
            covered,
            whole,
        })
    }

    /// The table of the state the group makes: `accepted` and one generation more, the
    /// staged packages in, and a package of the same name that was installed out. The
    /// places that went, in order of the staged packages (the layers to detach), and the
    /// places that came (the layers to attach).
    pub fn table(&self, accepted: &Table, out: &mut GroupTable) {
        out.next.0 = accepted.0;
        out.next.set_generation(accepted.generation() + 1);
        out.detach_len = 0;
        out.attach_len = 0;
        for s in self.staged() {
            let old = (0..PACKAGES).find(|&i| {
                let r = out.next.record(i);
                r.kind == PACKAGE && r.name_bytes() == s.record.name_bytes()
            });
            if let Some(old) = old {
                out.next.set_record(old, &Record::EMPTY);
                out.detach[out.detach_len] = old;
                out.detach_len += 1;
            }
            out.next.set_record(s.slot, &s.record);
            out.attach[out.attach_len] = s.slot;
            out.attach_len += 1;
        }
    }
}

/// The table of a group and its layers: the output of `Group::table`.
pub struct GroupTable {
    pub next: Table,
    pub detach: [usize; GROUP_MAX],
    pub detach_len: usize,
    pub attach: [usize; GROUP_MAX],
    pub attach_len: usize,
}

impl GroupTable {
    pub const fn new() -> GroupTable {
        GroupTable {
            next: Table::zeroed(),
            detach: [0; GROUP_MAX],
            detach_len: 0,
            attach: [0; GROUP_MAX],
            attach_len: 0,
        }
    }

    pub fn detach(&self) -> &[usize] {
        &self.detach[..self.detach_len]
    }

    pub fn attach(&self) -> &[usize] {
        &self.attach[..self.attach_len]
    }
}

impl Default for GroupTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Where a package of `NO_REPO` ends in a record: never for a package of the disk.
const _: () = assert!(NO_REPO as usize >= crate::store::REPOS);
