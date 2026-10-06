// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Immutable initial-program associations. Metadata validation precedes
//! bounded content comparison and authenticated image admission.

use crate::{BootImage, PROGRAM_MAGIC, Program, elf, rootfs};

pub const FILE: &str = "exec-bindings";
pub const MAGIC: [u8; 8] = *b"STAFEXEC";
pub const VERSION: u32 = 1;
pub const NONE: u32 = u32::MAX;
const HEADER: usize = 16;
const ENTRY: usize = 16;

/// Indices refer to the final immutable boot image and sorted rootfs table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialSource {
    pub artifact: u32,
    pub raw: u32,
    pub canonical: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    Size,
    Index,
    Order,
    Reserved,
    Coverage,
    Program,
    Layout,
    Canonical,
}

#[derive(Clone, Copy, Debug)]
pub struct Bindings<'a> {
    bytes: &'a [u8],
    count: u32,
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("checked word"))
}

impl<'a> Bindings<'a> {
    /// Validate exact size, ranges, reserved fields and increasing artifact IDs.
    pub fn parse(bytes: &'a [u8], files: u32) -> Result<Self, Error> {
        if bytes.len() < HEADER || bytes[..8] != MAGIC || word(bytes, 8) != VERSION {
            return Err(Error::Header);
        }
        let count = word(bytes, 12);
        if count == 0 || count > files || count as usize > rootfs::FILES_MAX {
            return Err(Error::Size);
        }
        if bytes.len() != HEADER + count as usize * ENTRY {
            return Err(Error::Size);
        }
        let table = Self { bytes, count };
        let mut previous = None;
        for index in 0..count {
            let at = HEADER + index as usize * ENTRY;
            let row = table.entry(index);
            if word(bytes, at + 12) != 0 {
                return Err(Error::Reserved);
            }
            if row.artifact >= files
                || row.raw >= files
                || row.artifact == row.raw
                || row
                    .canonical
                    .is_some_and(|n| n as usize >= rootfs::ENTRIES_MAX)
            {
                return Err(Error::Index);
            }
            if previous.is_some_and(|n| row.artifact <= n) {
                return Err(Error::Order);
            }
            previous = Some(row.artifact);
        }
        if table.entry(0).artifact != 0 {
            return Err(Error::Coverage);
        }
        Ok(table)
    }

    pub fn len(&self) -> u32 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The row at an index checked against len by the caller.
    pub fn entry(&self, index: u32) -> InitialSource {
        assert!(index < self.count);
        let at = HEADER + index as usize * ENTRY;
        let canonical = word(self.bytes, at + 8);
        InitialSource {
            artifact: word(self.bytes, at),
            raw: word(self.bytes, at + 4),
            canonical: (canonical != NONE).then_some(canonical),
        }
    }

    /// Check coverage and metadata against immutable bytes. Seed admission
    /// separately compares content in bounded chunks before trusting this source.
    pub fn validate_layout(&self, image: BootImage<'_>) -> Result<(), Error> {
        image.init().map_err(|_| Error::Program)?;
        let table = image
            .files()
            .find(|f| f.name == "rootfs")
            .map(|f| rootfs::Rootfs::parse(f.data, image.count()).map_err(|_| Error::Canonical))
            .transpose()?;
        let mut row = 0;
        for (artifact, file) in image.files().enumerate() {
            if !file.data.starts_with(&PROGRAM_MAGIC) {
                continue;
            }
            if row >= self.count || self.entry(row).artifact != artifact as u32 {
                return Err(Error::Coverage);
            }
            let source = self.entry(row);
            let packed = Program::parse(file.data).map_err(|_| Error::Program)?;
            let raw = image.file_at(source.raw).ok_or(Error::Index)?;
            let original = elf::program(raw.data, packed.stack_size).map_err(|_| Error::Program)?;
            if packed.entry != original.entry
                || packed.segments.iter().zip(original.segments).any(|(a, b)| {
                    a.vaddr != b.vaddr || a.mem_size != b.mem_size || a.bytes.len() != b.bytes.len()
                })
            {
                return Err(Error::Layout);
            }
            let canonical = table.as_ref().and_then(|t| {
                (0..t.len() as u32).find(|&n| {
                    let entry = t.entry(n);
                    !entry.is_directory() && entry.file == source.raw
                })
            });
            if canonical != source.canonical {
                return Err(Error::Canonical);
            }
            row += 1;
        }
        if row != self.count {
            return Err(Error::Coverage);
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "write"))]
pub fn write(rows: &[InitialSource], files: u32) -> Result<alloc::vec::Vec<u8>, Error> {
    use alloc::vec::Vec;
    let count = u32::try_from(rows.len()).map_err(|_| Error::Size)?;
    if rows.len() > rootfs::FILES_MAX {
        return Err(Error::Size);
    }
    let mut bytes = Vec::with_capacity(HEADER + rows.len() * ENTRY);
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&count.to_le_bytes());
    for row in rows {
        for word in [row.artifact, row.raw, row.canonical.unwrap_or(NONE), 0] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    }
    Bindings::parse(&bytes, files)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn rows() -> [InitialSource; 2] {
        [
            InitialSource {
                artifact: 0,
                raw: 2,
                canonical: None,
            },
            InitialSource {
                artifact: 1,
                raw: 3,
                canonical: Some(5),
            },
        ]
    }

    fn fixture(
        canonical: Option<u32>,
        include_rootfs: bool,
        changed_entry: bool,
    ) -> alloc::vec::Vec<u8> {
        let mut raw = vec![0u8; 4100];
        raw[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        raw[16..18].copy_from_slice(&2u16.to_le_bytes());
        raw[18..20].copy_from_slice(&183u16.to_le_bytes());
        raw[20..24].copy_from_slice(&1u32.to_le_bytes());
        raw[24..32].copy_from_slice(&4096u64.to_le_bytes());
        raw[32..40].copy_from_slice(&64u64.to_le_bytes());
        raw[52..54].copy_from_slice(&64u16.to_le_bytes());
        raw[54..56].copy_from_slice(&56u16.to_le_bytes());
        raw[56..58].copy_from_slice(&1u16.to_le_bytes());
        raw[64..68].copy_from_slice(&1u32.to_le_bytes());
        raw[68..72].copy_from_slice(&5u32.to_le_bytes());
        raw[72..80].copy_from_slice(&4096u64.to_le_bytes());
        raw[80..88].copy_from_slice(&4096u64.to_le_bytes());
        raw[96..104].copy_from_slice(&4u64.to_le_bytes());
        raw[104..112].copy_from_slice(&4096u64.to_le_bytes());
        raw[112..120].copy_from_slice(&4096u64.to_le_bytes());
        raw[4096..].copy_from_slice(&[1, 2, 3, 4]);
        let program = elf::program(&raw, 4096).unwrap();
        let packed = crate::write::program(&program).unwrap();
        let table = rootfs::write::rootfs(
            &[
                rootfs::Entry {
                    path: "/z",
                    mode: rootfs::REGULAR | 0o755,
                    uid: 0,
                    gid: 0,
                    file: 2,
                },
                rootfs::Entry {
                    path: "/a",
                    mode: rootfs::REGULAR | 0o755,
                    uid: 0,
                    gid: 0,
                    file: 2,
                },
            ],
            4,
        )
        .unwrap();
        if changed_entry {
            raw[24..32].copy_from_slice(&4100u64.to_le_bytes());
        }
        let rows = [InitialSource {
            artifact: 0,
            raw: 2,
            canonical,
        }];
        let metadata = write(&rows, 4).unwrap();
        crate::write::image(&[
            ("init", &packed),
            (if include_rootfs { "rootfs" } else { "spare" }, &table),
            ("init.elf", &raw),
            (FILE, &metadata),
        ])
        .unwrap()
    }

    fn validate(bytes: &[u8]) -> Result<(), Error> {
        let image = BootImage::parse(bytes).unwrap();
        let metadata = image.files().find(|f| f.name == FILE).unwrap();
        Bindings::parse(metadata.data, image.count())?.validate_layout(image)
    }

    #[test]
    fn canonical_hardlink_and_memory_only_sources_validate() {
        assert_eq!(validate(&fixture(Some(0), true, false)), Ok(()));
        assert_eq!(validate(&fixture(None, false, false)), Ok(()));
    }

    #[test]
    fn noncanonical_alias_and_false_memory_only_source_are_rejected() {
        assert_eq!(
            validate(&fixture(Some(1), true, false)),
            Err(Error::Canonical)
        );
        assert_eq!(validate(&fixture(None, true, false)), Err(Error::Canonical));
    }

    #[test]
    fn a_different_initial_entrypoint_is_rejected() {
        assert_eq!(validate(&fixture(Some(0), true, true)), Err(Error::Layout));
    }

    #[test]
    fn non_elf_raw_source_and_missing_program_coverage_are_rejected() {
        let bytes = fixture(None, false, false);
        let image = BootImage::parse(&bytes).unwrap();
        let row = InitialSource {
            artifact: 0,
            raw: 1,
            canonical: None,
        };
        let metadata = write(&[row], image.count()).unwrap();
        let files: alloc::vec::Vec<_> = image
            .files()
            .map(|f| {
                (
                    f.name,
                    if f.name == FILE {
                        metadata.as_slice()
                    } else {
                        f.data
                    },
                )
            })
            .collect();
        let wrong = crate::write::image(&files).unwrap();
        assert_eq!(validate(&wrong), Err(Error::Program));
        let packed = image.file_at(0).unwrap().data;
        let files: alloc::vec::Vec<_> = image
            .files()
            .map(|f| (f.name, if f.name == "spare" { packed } else { f.data }))
            .collect();
        let uncovered = crate::write::image(&files).unwrap();
        assert_eq!(validate(&uncovered), Err(Error::Coverage));
    }

    #[test]
    fn fixed_rows_round_trip_without_native_layout_padding() {
        let bytes = write(&rows(), 6).unwrap();
        assert_eq!(bytes.len(), 48);
        let table = Bindings::parse(&bytes, 6).unwrap();
        assert_eq!(table.entry(0), rows()[0]);
        assert_eq!(table.entry(1), rows()[1]);
    }

    #[test]
    fn truncated_trailing_version_count_and_reserved_are_rejected() {
        let good = write(&rows(), 6).unwrap();
        for cut in 0..good.len() {
            assert!(Bindings::parse(&good[..cut], 6).is_err());
        }
        let mut bad = good.clone();
        bad.push(0);
        assert_eq!(Bindings::parse(&bad, 6).unwrap_err(), Error::Size);
        for (at, value) in [(8, 2u32), (12, 0), (28, 1)] {
            let mut bad = good.clone();
            bad[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert!(Bindings::parse(&bad, 6).is_err());
        }
    }

    #[test]
    fn reused_out_of_range_or_uncovered_initial_indices_are_rejected() {
        let mut entries = rows();
        entries[1].artifact = 0;
        assert_eq!(write(&entries, 6).unwrap_err(), Error::Order);
        let mut entries = rows();
        entries[0].artifact = 1;
        assert_eq!(write(&entries, 6).unwrap_err(), Error::Order);
        let mut entries = rows();
        entries[1].raw = 6;
        assert_eq!(write(&entries, 6).unwrap_err(), Error::Index);
        assert_eq!(write(&[rows()[1]], 6).unwrap_err(), Error::Coverage);
    }
}
