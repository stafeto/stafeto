// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The format of the store (pk3-design R6): the whole disk, in blocks of
//! 4 KiB. Two superblocks (blocks 0 and 1), one table of 5 blocks that a
//! superblock names, and the extents the table's records name: 64 places of
//! packages, one of the settings blob and one of the revocation list. The
//! table is written whole into a free extent and a superblock with a
//! generation one higher goes to the copy with the lower generation, so
//! the store at a start is the whole old state or the whole new one. Every
//! number is low byte first.

use pkgfmt::{Name, sha::sha256};

pub const BLOCK: usize = 4096;
/// The superblocks, and the first block the table of a new store takes.
pub const SUPERS: u64 = 2;
pub const TABLE_BLOCKS: u64 = 5;
pub const TABLE_BYTES: usize = TABLE_BLOCKS as usize * BLOCK;
pub const PACKAGES: usize = 64;
pub const SETTINGS_SLOT: usize = 64;
pub const REVOKED_SLOT: usize = 65;
pub const RECORDS: usize = 66;
pub const REPOS: usize = 16;
const HEADER: usize = 64;
const RECORD_SIZE: usize = 256;
const REPO_SIZE: usize = 64;
const REPOS_AT: usize = HEADER + RECORDS * RECORD_SIZE;

pub const SUPER_MAGIC: [u8; 8] = *b"STAFSTOR";
pub const TABLE_MAGIC: [u8; 8] = *b"STAFTBL1";
pub const VERSION: u32 = 1;

/// The kind of a record and its flags.
pub const EMPTY: u8 = 0;
pub const PACKAGE: u8 = 1;
pub const SETTINGS: u8 = 2;
pub const REVOKED_LIST: u8 = 3;
pub const WORLD: u8 = 1;
pub const DEPENDENCY: u8 = 2;
pub const REVOKED: u8 = 4;
pub const NO_REPO: u8 = 0xFF;

/// A run of blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    pub first: u64,
    pub blocks: u64,
}

impl Extent {
    pub const fn end(&self) -> u64 {
        self.first + self.blocks
    }
}

/// Why a superblock is not good.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuperError {
    Magic,
    Version,
    BlockSize,
    Blocks,
    Hash,
}

/// The superblock: where the table is, how long, and its SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Superblock {
    pub blocks: u64,
    pub generation: u64,
    pub table_first: u64,
    pub table_len: u32,
    pub table_sha: [u8; 32],
}

impl Superblock {
    pub fn encode(&self) -> [u8; BLOCK] {
        let mut b = [0; BLOCK];
        b[..8].copy_from_slice(&SUPER_MAGIC);
        b[8..12].copy_from_slice(&VERSION.to_le_bytes());
        b[12..16].copy_from_slice(&(BLOCK as u32).to_le_bytes());
        b[16..24].copy_from_slice(&self.blocks.to_le_bytes());
        b[24..32].copy_from_slice(&self.generation.to_le_bytes());
        b[32..40].copy_from_slice(&self.table_first.to_le_bytes());
        b[40..44].copy_from_slice(&self.table_len.to_le_bytes());
        b[48..80].copy_from_slice(&self.table_sha);
        let own = sha256(&b[..96]);
        b[96..128].copy_from_slice(&own);
        b
    }

    /// The superblock in `bytes` of a disk of `disk_blocks`.
    pub fn decode(bytes: &[u8], disk_blocks: u64) -> Result<Superblock, SuperError> {
        if bytes.len() < 128 || bytes[..8] != SUPER_MAGIC {
            return Err(SuperError::Magic);
        }
        if u32_at(bytes, 8) != VERSION {
            return Err(SuperError::Version);
        }
        if u32_at(bytes, 12) != BLOCK as u32 {
            return Err(SuperError::BlockSize);
        }
        if u64_at(bytes, 16) != disk_blocks {
            return Err(SuperError::Blocks);
        }
        if sha256(&bytes[..96])[..] != bytes[96..128] {
            return Err(SuperError::Hash);
        }
        let mut table_sha = [0; 32];
        table_sha.copy_from_slice(&bytes[48..80]);
        Ok(Superblock {
            blocks: disk_blocks,
            generation: u64_at(bytes, 24),
            table_first: u64_at(bytes, 32),
            table_len: u32_at(bytes, 40),
            table_sha,
        })
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("four bytes"))
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("eight bytes"))
}

/// One record of the table, as the 256 bytes hold it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub kind: u8,
    pub flags: u8,
    /// The index of the repository in the table's part of repositories.
    pub repo: u8,
    pub first: u64,
    pub blocks: u32,
    pub length: u64,
    /// The serial of the revocation list, 0 for the others.
    pub number: u64,
    /// The time of the installation, seconds of the PL031.
    pub installed: u64,
    pub sha256: [u8; 32],
    /// `Name::to_field` of the package, and of its version (the same
    /// field, whose rules are the version's of meta up to 63 bytes).
    pub name: [u8; 64],
    pub version: [u8; 64],
}

impl Record {
    pub const EMPTY: Record = Record {
        kind: EMPTY,
        flags: 0,
        repo: NO_REPO,
        first: 0,
        blocks: 0,
        length: 0,
        number: 0,
        installed: 0,
        sha256: [0; 32],
        name: [0; 64],
        version: [0; 64],
    };

    pub fn extent(&self) -> Extent {
        Extent {
            first: self.first,
            blocks: u64::from(self.blocks),
        }
    }

    fn encode(&self, out: &mut [u8]) {
        out.fill(0);
        out[0] = self.kind;
        out[1] = self.flags;
        out[2] = self.repo;
        out[4..12].copy_from_slice(&self.first.to_le_bytes());
        out[12..16].copy_from_slice(&self.blocks.to_le_bytes());
        out[16..24].copy_from_slice(&self.length.to_le_bytes());
        out[24..32].copy_from_slice(&self.number.to_le_bytes());
        out[32..40].copy_from_slice(&self.installed.to_le_bytes());
        out[40..72].copy_from_slice(&self.sha256);
        out[72..136].copy_from_slice(&self.name);
        out[136..200].copy_from_slice(&self.version);
    }

    fn decode(b: &[u8]) -> Record {
        let mut r = Record::EMPTY;
        r.kind = b[0];
        r.flags = b[1];
        r.repo = b[2];
        r.first = u64_at(b, 4);
        r.blocks = u32_at(b, 12);
        r.length = u64_at(b, 16);
        r.number = u64_at(b, 24);
        r.installed = u64_at(b, 32);
        r.sha256.copy_from_slice(&b[40..72]);
        r.name.copy_from_slice(&b[72..136]);
        r.version.copy_from_slice(&b[136..200]);
        r
    }

    /// The name as text: the bytes after the length of the field.
    pub fn name_bytes(&self) -> &[u8] {
        field_bytes(&self.name)
    }

    pub fn version_bytes(&self) -> &[u8] {
        field_bytes(&self.version)
    }
}

/// The bytes of a length-prefixed field of 64 bytes.
pub fn field_bytes(field: &[u8; 64]) -> &[u8] {
    &field[1..1 + usize::from(field[0]).min(63)]
}

/// The field of `text` (up to 63 bytes) the way `Name::to_field` writes one.
pub fn to_field(text: &[u8]) -> Option<[u8; 64]> {
    if text.len() > 63 {
        return None;
    }
    let mut f = [0; 64];
    f[0] = text.len() as u8;
    f[1..=text.len()].copy_from_slice(text);
    Some(f)
}

/// Why a table is not good.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError {
    Header,
    /// The generation is not the superblock's: another table's.
    Generation,
    /// A record or a repository breaks a rule; the place of the record.
    Record(usize),
    /// Two extents cross, or one leaves the disk.
    Extents,
}

/// The table in its 20,480 bytes.
pub struct Table(pub [u8; TABLE_BYTES]);

impl Table {
    pub const fn zeroed() -> Table {
        Table([0; TABLE_BYTES])
    }

    /// An empty table of `generation`.
    pub fn init(&mut self, generation: u64) {
        self.0.fill(0);
        self.0[..8].copy_from_slice(&TABLE_MAGIC);
        self.0[8..12].copy_from_slice(&VERSION.to_le_bytes());
        self.0[12..20].copy_from_slice(&generation.to_le_bytes());
        self.0[20..24].copy_from_slice(&(RECORDS as u32).to_le_bytes());
        self.0[24..28].copy_from_slice(&(REPOS as u32).to_le_bytes());
        for i in 0..RECORDS {
            self.set_record(i, &Record::EMPTY);
        }
    }

    pub fn generation(&self) -> u64 {
        u64_at(&self.0, 12)
    }

    pub fn set_generation(&mut self, generation: u64) {
        self.0[12..20].copy_from_slice(&generation.to_le_bytes());
    }

    pub fn sha(&self) -> [u8; 32] {
        sha256(&self.0)
    }

    pub fn record(&self, i: usize) -> Record {
        let at = HEADER + i * RECORD_SIZE;
        Record::decode(&self.0[at..at + RECORD_SIZE])
    }

    pub fn set_record(&mut self, i: usize, r: &Record) {
        let at = HEADER + i * RECORD_SIZE;
        r.encode(&mut self.0[at..at + RECORD_SIZE]);
    }

    /// The name and serial of repository `i`, None for a free place.
    pub fn repo(&self, i: usize) -> Option<(&[u8], u64)> {
        let at = REPOS_AT + i * REPO_SIZE;
        let field: &[u8; 64] = self.0[at..at + REPO_SIZE].try_into().ok()?;
        if field[0] == 0 {
            return None;
        }
        let serial = u64_at(&self.0, at + 32);
        Some((&field[1..1 + usize::from(field[0]).min(31)], serial))
    }

    /// Repository `i` as `name` with `serial`: the field of 32 bytes (a
    /// length and 31 bytes), then the serial and zeros.
    pub fn set_repo(&mut self, i: usize, name: &[u8], serial: u64) -> bool {
        if name.is_empty() || name.len() > 31 {
            return false;
        }
        let at = REPOS_AT + i * REPO_SIZE;
        self.0[at..at + REPO_SIZE].fill(0);
        self.0[at] = name.len() as u8;
        self.0[at + 1..at + 1 + name.len()].copy_from_slice(name);
        self.0[at + 32..at + 40].copy_from_slice(&serial.to_le_bytes());
        true
    }

    pub fn find_repo(&self, name: &[u8]) -> Option<usize> {
        (0..REPOS).find(|&i| self.repo(i).is_some_and(|(n, _)| n == name))
    }

    /// The table's header, generation, records, repositories, extents: all
    /// of them within the rules, for a disk of `blocks` and the table at
    /// `at`.
    pub fn check(&self, generation: u64, blocks: u64, at: u64) -> Result<(), TableError> {
        let h = &self.0;
        if h[..8] != TABLE_MAGIC
            || u32_at(h, 8) != VERSION
            || u32_at(h, 20) != RECORDS as u32
            || u32_at(h, 24) != REPOS as u32
            || h[28..HEADER].iter().any(|&b| b != 0)
        {
            return Err(TableError::Header);
        }
        if self.generation() != generation {
            return Err(TableError::Generation);
        }
        for i in 0..RECORDS {
            let r = self.record(i);
            let slot_kind = match i {
                SETTINGS_SLOT => SETTINGS,
                REVOKED_SLOT => REVOKED_LIST,
                _ => PACKAGE,
            };
            if r.kind == EMPTY {
                if r != Record::EMPTY {
                    return Err(TableError::Record(i));
                }
                continue;
            }
            let whole = r.length.div_ceil(BLOCK as u64);
            let named = i >= PACKAGES || Name::from_field(&r.name).is_ok();
            let repo_ok = r.repo == NO_REPO || usize::from(r.repo) < REPOS && i < PACKAGES;
            if r.kind != slot_kind
                || r.flags & !(WORLD | DEPENDENCY | REVOKED) != 0
                || r.length == 0
                || u64::from(r.blocks) != whole
                || !named
                || !repo_ok
                || (i < PACKAGES && r.repo == NO_REPO)
            {
                return Err(TableError::Record(i));
            }
        }
        let mut list = [Extent {
            first: 0,
            blocks: 0,
        }; RECORDS + 1];
        let n = self.occupied(
            Extent {
                first: at,
                blocks: TABLE_BLOCKS,
            },
            &mut list,
        );
        let mut end = SUPERS;
        for e in &list[..n] {
            if e.first < end || e.end() > blocks {
                return Err(TableError::Extents);
            }
            end = e.end();
        }
        Ok(())
    }

    /// The extents the table holds: its own at `at` and each record's,
    /// sorted by first block, in `out`; how many.
    pub fn occupied(&self, own: Extent, out: &mut [Extent; RECORDS + 1]) -> usize {
        let mut n = 0;
        let mut put = |e: Extent| {
            let mut i = n;
            while i > 0 && out[i - 1].first > e.first {
                out[i] = out[i - 1];
                i -= 1;
            }
            out[i] = e;
            n += 1;
        };
        put(own);
        for i in 0..RECORDS {
            let r = self.record(i);
            if r.kind != EMPTY {
                put(r.extent());
            }
        }
        n
    }
}

/// The first block of the first run of `need` blocks that no extent of
/// `occupied` (sorted) and none of `taken` holds, from block SUPERS to the
/// end of a disk of `blocks`.
pub fn find_free(occupied: &[Extent], taken: &[Extent], blocks: u64, need: u64) -> Option<u64> {
    let mut all = [Extent {
        first: 0,
        blocks: 0,
    }; RECORDS + 1 + 16];
    let mut n = 0;
    for e in occupied.iter().chain(taken) {
        let mut i = n;
        while i > 0 && all[i - 1].first > e.first {
            all[i] = all[i - 1];
            i -= 1;
        }
        all[i] = *e;
        n += 1;
    }
    let mut at = SUPERS;
    for e in &all[..n] {
        if e.first >= at + need {
            break;
        }
        at = at.max(e.end());
    }
    (at + need <= blocks).then_some(at)
}

/// The blocks no extent holds: the disk less the superblocks and the extents.
pub fn free_blocks(occupied: &[Extent], blocks: u64) -> u64 {
    blocks - SUPERS - occupied.iter().map(|e| e.blocks).sum::<u64>()
}
