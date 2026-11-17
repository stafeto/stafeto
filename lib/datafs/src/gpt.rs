// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The least of GPT (UEFI 2.10, section 5.3) the data volume needs: reading a table and finding the
//! partitions of this system by their type, writing a new table of up to eight partitions on a volume
//! that holds nothing, and setting the attribute bits of one entry.
//!
//! The root volume of a machine (the ESP and the boot image) is never written: `classify` calls a
//! volume `Blank` only when its first MiB is all zero, and a volume with any other contents and no
//! valid table `Foreign`. A cut of the power in `create` leaves a volume that is still `Blank` or
//! has a valid table: the copy at the end of the volume and its entries come first, the copy at the
//! start next and the protective MBR last, and the reader takes either copy.

use crate::{Device, DeviceError, SECTOR};

/// A GUID as it lies on the disk (the first three fields little endian).
pub type Guid = [u8; 16];

/// The type of the partition of files (littlefs), chosen for this system.
pub const TYPE_DATA: Guid = [
    59, 73, 174, 163, 129, 248, 89, 77, 163, 212, 188, 161, 104, 137, 29, 237,
];
/// The type of the partition of the package store.
pub const TYPE_STORE: Guid = [
    228, 241, 67, 52, 160, 203, 137, 79, 170, 131, 161, 134, 203, 214, 189, 144,
];

/// The attribute bit (the first of the type-specific bits, 48) that says the file system of a
/// partition was made and mounted once: a partition without it is formatted, one with it that does
/// not mount is left alone.
pub const FORMATTED: u64 = 1 << 48;

/// The entries of a table and the bytes of one.
pub const ENTRIES: u32 = 128;
pub const ENTRY_BYTES: usize = 128;
/// The sectors the entries take.
const ENTRY_SECTORS: u64 = ENTRIES as u64 * ENTRY_BYTES as u64 / SECTOR as u64;
/// The first sector the partitions can use, and the sectors of the zero check of `classify`.
const FIRST_USABLE: u64 = 2 + ENTRY_SECTORS;
pub const BLANK_SECTORS: u64 = 2048;
/// The partitions a table of this system keeps at most (`Table::parts`).
pub const KEPT: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// No valid header at either end: nothing to read.
    NoTable,
    /// The layout asked for does not fit the volume, or names too many partitions.
    Layout,
    /// The partition is not in the table.
    NoPartition,
    Device,
}

impl From<DeviceError> for Error {
    fn from(_: DeviceError) -> Self {
        Self::Device
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Partition {
    pub kind: Guid,
    pub unique: Guid,
    pub first: u64,
    /// The last sector, inclusive.
    pub last: u64,
    pub attributes: u64,
    pub name: [u16; 36],
    /// The place of the entry in the table.
    pub index: u32,
}

impl Partition {
    pub const fn sectors(&self) -> u64 {
        self.last - self.first + 1
    }

    /// The name, as far as it is ASCII; other characters show as `?`.
    pub fn name_ascii(&self, out: &mut [u8; 36]) -> usize {
        let mut n = 0;
        for &unit in &self.name {
            if unit == 0 {
                break;
            }
            out[n] = if (32..127).contains(&unit) {
                unit as u8
            } else {
                b'?'
            };
            n += 1;
        }
        n
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Table {
    pub disk: Guid,
    pub first_usable: u64,
    pub last_usable: u64,
    /// The last sector of the volume, where the backup header is.
    pub last: u64,
    /// The non-empty entries, the first `count` of `parts`; `total` counts all of them.
    pub parts: [Option<Partition>; KEPT],
    pub total: usize,
    /// The primary header was damaged and the backup one was read.
    pub from_backup: bool,
    entries_crc: u32,
    entries_lba: u64,
}

impl Table {
    /// The first partition of the type, if any.
    pub fn find(&self, kind: &Guid) -> Option<Partition> {
        self.parts
            .iter()
            .flatten()
            .find(|p| &p.kind == kind)
            .copied()
    }
}

/// What a volume is.
// The table is the large variant and the enum lives on the stack for the length of one call.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    Gpt(Table),
    /// The first MiB is zero and no table is there: free to partition.
    Blank,
    /// Something else is there (a boot disk, a foreign file system): not ours to write.
    Foreign(Found),
}

/// Where `classify` found the first byte that is not zero, for the console line of a refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Found {
    /// The sector and the offset in it of the first non-zero byte.
    pub sector: u64,
    pub offset: usize,
    /// The 32 bytes of the sector from `offset & !15`.
    pub bytes: [u8; 32],
    /// The first eight bytes of sector 1 and of the last sector.
    pub lba1: [u8; 8],
    pub last: [u8; 8],
}

/// A partition to create: the type, the sectors and the name.
#[derive(Clone, Copy, Debug)]
pub struct New {
    pub kind: Guid,
    pub first: u64,
    pub last: u64,
    pub name: &'static str,
}

pub fn crc32(mut crc: u32, data: &[u8]) -> u32 {
    crc = !crc;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

fn le64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

/// The CRC of the `ENTRY_SECTORS` sectors from `lba`, and the entries it passes to `see`
/// (the index, the 128 bytes).
fn walk_entries<D: Device>(
    dev: &mut D,
    lba: u64,
    mut see: impl FnMut(u32, &[u8]),
) -> Result<u32, Error> {
    let mut crc = 0;
    let mut sector = [0u8; SECTOR];
    for i in 0..ENTRY_SECTORS {
        dev.read(lba + i, &mut sector)?;
        crc = crc32(crc, &sector);
        for k in 0..SECTOR / ENTRY_BYTES {
            see(
                (i as usize * (SECTOR / ENTRY_BYTES) + k) as u32,
                &sector[k * ENTRY_BYTES..(k + 1) * ENTRY_BYTES],
            );
        }
    }
    Ok(crc)
}

/// Reads the header at `lba` and the entries it names; None when anything is wrong with them.
fn read_copy<D: Device>(dev: &mut D, lba: u64, last: u64) -> Result<Option<Table>, Error> {
    let mut sector = [0u8; SECTOR];
    dev.read(lba, &mut sector)?;
    if &sector[..8] != b"EFI PART" || le32(&sector, 8) != 0x0001_0000 || le32(&sector, 12) != 92 {
        return Ok(None);
    }
    let stored = le32(&sector, 16);
    sector[16..20].fill(0);
    if crc32(0, &sector[..92]) != stored {
        return Ok(None);
    }
    let alternate = if lba == 1 { last } else { 1 };
    let (entries_lba, count, size) = (le64(&sector, 72), le32(&sector, 80), le32(&sector, 84));
    if le64(&sector, 24) != lba
        || le64(&sector, 32) != alternate
        || count != ENTRIES
        || size as usize != ENTRY_BYTES
        || entries_lba == 0
        || entries_lba
            .checked_add(ENTRY_SECTORS)
            .is_none_or(|end| end > last + 1)
    {
        return Ok(None);
    }
    let (first_usable, last_usable) = (le64(&sector, 40), le64(&sector, 48));
    // The usable sectors lie past the start entries and before the end entries.
    if first_usable > last_usable
        || first_usable < entries_lba.min(2) + ENTRY_SECTORS
        || last_usable >= last - ENTRY_SECTORS
    {
        return Ok(None);
    }
    let mut disk = [0; 16];
    disk.copy_from_slice(&sector[56..72]);
    let mut parts = [None; KEPT];
    let (mut kept, mut total) = (0, 0);
    let crc = walk_entries(dev, entries_lba, |index, entry| {
        if entry[..16].iter().all(|&b| b == 0) {
            return;
        }
        total += 1;
        if kept < KEPT {
            let mut name = [0u16; 36];
            for (i, unit) in name.iter_mut().enumerate() {
                *unit = u16::from_le_bytes([entry[56 + 2 * i], entry[57 + 2 * i]]);
            }
            parts[kept] = Some(Partition {
                kind: entry[..16].try_into().expect("sixteen bytes"),
                unique: entry[16..32].try_into().expect("sixteen bytes"),
                first: le64(entry, 32),
                last: le64(entry, 40),
                attributes: le64(entry, 48),
                name,
                index,
            });
            kept += 1;
        }
    })?;
    if crc != le32(&sector, 88) {
        return Ok(None);
    }
    // A partition that does not lie inside the usable sectors makes the table unusable.
    for p in parts.iter().flatten() {
        if p.first > p.last || p.first < first_usable || p.last > last_usable {
            return Ok(None);
        }
    }
    Ok(Some(Table {
        disk,
        first_usable,
        last_usable,
        last,
        parts,
        total,
        from_backup: lba != 1,
        entries_crc: crc,
        entries_lba,
    }))
}

/// Reads the table: the primary copy, or the backup at the end of the volume if that is damaged.
pub fn read<D: Device>(dev: &mut D) -> Result<Table, Error> {
    let sectors = dev.sectors();
    if sectors < 2 * FIRST_USABLE {
        return Err(Error::NoTable);
    }
    let last = sectors - 1;
    if let Some(table) = read_copy(dev, 1, last)? {
        return Ok(table);
    }
    read_copy(dev, last, last)?.ok_or(Error::NoTable)
}

/// The first byte that is not zero in `count` sectors from `first` (the sector, the offset and the
/// bytes around it; the other fields are filled by the caller), or None when all are zero.
fn nonzero<D: Device>(dev: &mut D, first: u64, count: u64) -> Result<Option<Found>, Error> {
    let mut sector = [0u8; SECTOR];
    for i in 0..count.min(dev.sectors().saturating_sub(first)) {
        dev.read(first + i, &mut sector)?;
        if let Some(offset) = sector.iter().position(|&b| b != 0) {
            let from = offset & !15;
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&sector[from..from + 32]);
            return Ok(Some(Found {
                sector: first + i,
                offset,
                bytes,
                lba1: [0; 8],
                last: [0; 8],
            }));
        }
    }
    Ok(None)
}

/// The first eight bytes of a sector.
fn head<D: Device>(dev: &mut D, lba: u64) -> Result<[u8; 8], Error> {
    let mut sector = [0u8; SECTOR];
    dev.read(lba, &mut sector)?;
    Ok(sector[..8].try_into().expect("eight bytes"))
}

pub fn classify<D: Device>(dev: &mut D) -> Result<Class, Error> {
    match read(dev) {
        Ok(table) => Ok(Class::Gpt(table)),
        Err(Error::NoTable) => match nonzero(dev, 0, BLANK_SECTORS)? {
            None => Ok(Class::Blank),
            Some(mut found) => {
                found.lba1 = head(dev, 1)?;
                found.last = head(dev, dev.sectors() - 1)?;
                Ok(Class::Foreign(found))
            }
        },
        Err(other) => Err(other),
    }
}

/// The layout the design names for a blank volume: `store` of 1 GiB or half the volume, whichever is
/// less, then `data` with the rest, both on whole MiB from the first MiB. None when the volume is too
/// small for two partitions of 4 MiB.
pub fn default_layout(sectors: u64) -> Option<[New; 2]> {
    const MIB: u64 = 2048;
    let last_usable = sectors.checked_sub(FIRST_USABLE)?;
    // Whole MiB between sector 2048 and the last usable sector.
    let mibs = (last_usable + 1).checked_sub(MIB)? / MIB;
    if mibs < 8 {
        return None;
    }
    let store = (mibs / 2).min(1024);
    Some([
        New {
            kind: TYPE_STORE,
            first: MIB,
            last: MIB + store * MIB - 1,
            name: "store",
        },
        New {
            kind: TYPE_DATA,
            first: MIB + store * MIB,
            last: MIB + mibs * MIB - 1,
            name: "data",
        },
    ])
}

fn mix(seed: &mut u64) -> u64 {
    // SplitMix64.
    *seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_E9CB);
    z ^ (z >> 31)
}

fn guid(seed: &mut u64) -> Guid {
    let mut g = [0u8; 16];
    g[..8].copy_from_slice(&mix(seed).to_le_bytes());
    g[8..].copy_from_slice(&mix(seed).to_le_bytes());
    // Version 4, variant 1.
    g[7] = (g[7] & 0x0F) | 0x40;
    g[8] = (g[8] & 0x3F) | 0x80;
    g
}

struct Header {
    lba: u64,
    alternate: u64,
    first_usable: u64,
    last_usable: u64,
    disk: Guid,
    entries_lba: u64,
    entries_crc: u32,
}

fn write_header<D: Device>(dev: &mut D, h: &Header) -> Result<(), Error> {
    let mut sector = [0u8; SECTOR];
    sector[..8].copy_from_slice(b"EFI PART");
    sector[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    sector[12..16].copy_from_slice(&92u32.to_le_bytes());
    sector[24..32].copy_from_slice(&h.lba.to_le_bytes());
    sector[32..40].copy_from_slice(&h.alternate.to_le_bytes());
    sector[40..48].copy_from_slice(&h.first_usable.to_le_bytes());
    sector[48..56].copy_from_slice(&h.last_usable.to_le_bytes());
    sector[56..72].copy_from_slice(&h.disk);
    sector[72..80].copy_from_slice(&h.entries_lba.to_le_bytes());
    sector[80..84].copy_from_slice(&ENTRIES.to_le_bytes());
    sector[84..88].copy_from_slice(&(ENTRY_BYTES as u32).to_le_bytes());
    sector[88..92].copy_from_slice(&h.entries_crc.to_le_bytes());
    let crc = crc32(0, &sector[..92]);
    sector[16..20].copy_from_slice(&crc.to_le_bytes());
    dev.write(h.lba, &sector)?;
    Ok(())
}

fn entry_bytes(p: &Partition) -> [u8; ENTRY_BYTES] {
    let mut e = [0u8; ENTRY_BYTES];
    e[..16].copy_from_slice(&p.kind);
    e[16..32].copy_from_slice(&p.unique);
    e[32..40].copy_from_slice(&p.first.to_le_bytes());
    e[40..48].copy_from_slice(&p.last.to_le_bytes());
    e[48..56].copy_from_slice(&p.attributes.to_le_bytes());
    for (i, unit) in p.name.iter().enumerate() {
        e[56 + 2 * i..58 + 2 * i].copy_from_slice(&unit.to_le_bytes());
    }
    e
}

/// Writes the protective MBR: one partition of type 0xEE over the volume (to 0xFFFFFFFF sectors).
fn write_mbr<D: Device>(dev: &mut D) -> Result<(), Error> {
    let mut sector = [0u8; SECTOR];
    let size = u32::try_from(dev.sectors() - 1).unwrap_or(u32::MAX);
    sector[446 + 2] = 2;
    sector[446 + 4] = 0xEE;
    sector[446 + 5..446 + 8].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
    sector[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    sector[446 + 12..446 + 16].copy_from_slice(&size.to_le_bytes());
    sector[510] = 0x55;
    sector[511] = 0xAA;
    dev.write(0, &sector)?;
    Ok(())
}

/// Writes a new table with `spec` over a volume that was `Blank` (the caller checked), and reads it
/// back. `seed` makes the GUIDs.
pub fn create<D: Device>(dev: &mut D, spec: &[New], mut seed: u64) -> Result<Table, Error> {
    let sectors = dev.sectors();
    if sectors < 2 * FIRST_USABLE || spec.is_empty() || spec.len() > KEPT {
        return Err(Error::Layout);
    }
    let last = sectors - 1;
    let (first_usable, last_usable) = (FIRST_USABLE, last - ENTRY_SECTORS - 1);
    let mut sectors_of_entries = [[0u8; SECTOR]; 2];
    // Entries: only the first KEPT are non-empty, so they all lie in the first sector.
    let mut previous_end = first_usable - 1;
    for (i, new) in spec.iter().enumerate() {
        let name_ok = new.name.chars().count() <= 36 && new.name.is_ascii();
        if !name_ok || new.first > new.last || new.first <= previous_end || new.last > last_usable {
            return Err(Error::Layout);
        }
        previous_end = new.last;
        let mut name = [0u16; 36];
        for (unit, c) in name.iter_mut().zip(new.name.bytes()) {
            *unit = u16::from(c);
        }
        let p = Partition {
            kind: new.kind,
            unique: guid(&mut seed),
            first: new.first,
            last: new.last,
            attributes: 0,
            name,
            index: i as u32,
        };
        let at = i * ENTRY_BYTES;
        sectors_of_entries[0][at..at + ENTRY_BYTES].copy_from_slice(&entry_bytes(&p));
    }
    let _ = &mut sectors_of_entries[1];
    let mut crc = crc32(0, &sectors_of_entries[0]);
    let empty = [0u8; SECTOR];
    for _ in 1..ENTRY_SECTORS {
        crc = crc32(crc, &empty);
    }
    let disk = guid(&mut seed);
    let backup_entries = last - ENTRY_SECTORS;
    // The copy at the end first, then the copy at the start, then the MBR.
    let write_entries = |dev: &mut D, lba: u64| -> Result<(), Error> {
        dev.write(lba, &sectors_of_entries[0])?;
        for i in 1..ENTRY_SECTORS {
            dev.write(lba + i, &empty)?;
        }
        Ok(())
    };
    if cfg!(feature = "break-datafs-gpt-order") {
        // The start first, the MBR first, no flush between: a cut leaves a volume that is neither
        // blank nor a table.
        write_mbr(dev)?;
        write_entries(dev, 2)?;
    }
    write_entries(dev, backup_entries)?;
    write_header(
        dev,
        &Header {
            lba: last,
            alternate: 1,
            first_usable,
            last_usable,
            disk,
            entries_lba: backup_entries,
            entries_crc: crc,
        },
    )?;
    dev.flush()?;
    write_entries(dev, 2)?;
    write_header(
        dev,
        &Header {
            lba: 1,
            alternate: last,
            first_usable,
            last_usable,
            disk,
            entries_lba: 2,
            entries_crc: crc,
        },
    )?;
    write_mbr(dev)?;
    dev.flush()?;
    read(dev)
}

/// Sets the attribute word of the entry at `index` and writes both copies of the table.
///
/// The 32 sectors of entries come from the copy that `read` validated, so a copy whose entries never
/// reached the disk cannot give a valid header over empty entries. The copy that was not read comes
/// first (the end copy when the start one was read), then the one that was read, each entries,
/// flush, header, flush: at every cut one copy is whole.
pub fn set_attributes<D: Device>(dev: &mut D, index: u32, attributes: u64) -> Result<Table, Error> {
    let table = read(dev)?;
    table
        .parts
        .iter()
        .flatten()
        .find(|p| p.index == index)
        .ok_or(Error::NoPartition)?;
    let (sector_of, at) = (u64::from(index) / 4, (index as usize % 4) * ENTRY_BYTES);
    let last = table.last;
    let end_entries = last - ENTRY_SECTORS;
    let (read_entries, read_header) = if table.from_backup {
        (table.entries_lba, last)
    } else {
        (table.entries_lba, 1)
    };
    let (other_entries, other_header) = if table.from_backup {
        (2, 1)
    } else {
        (end_entries, last)
    };
    let header = |lba: u64, entries_lba: u64, crc: u32| Header {
        lba,
        alternate: if lba == 1 { last } else { 1 },
        first_usable: table.first_usable,
        last_usable: table.last_usable,
        disk: table.disk,
        entries_lba,
        entries_crc: crc,
    };
    // The other copy: every sector of the validated entries, the attribute word changed, and the
    // checksum of what is written.
    let mut crc = 0;
    let mut sector = [0u8; SECTOR];
    for i in 0..ENTRY_SECTORS {
        dev.read(read_entries + i, &mut sector)?;
        if i == sector_of {
            sector[at + 48..at + 56].copy_from_slice(&attributes.to_le_bytes());
        }
        crc = crc32(crc, &sector);
        dev.write(other_entries + i, &sector)?;
    }
    dev.flush()?;
    write_header(dev, &header(other_header, other_entries, crc))?;
    dev.flush()?;
    // The copy that was read: its one sector, then its header.
    dev.read(read_entries + sector_of, &mut sector)?;
    sector[at + 48..at + 56].copy_from_slice(&attributes.to_le_bytes());
    dev.write(read_entries + sector_of, &sector)?;
    dev.flush()?;
    write_header(dev, &header(read_header, read_entries, crc))?;
    dev.flush()?;
    read(dev)
}
