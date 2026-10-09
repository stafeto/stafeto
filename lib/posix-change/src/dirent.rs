// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The records of a directory in the layout of Linux's dirent64, which is the
//! layout of relibc's `struct dirent` and `struct posix_dent`: the inode (8
//! bytes), the offset of the next entry (8), the length of the record (2),
//! the type (1) and the name with its NUL, each record rounded up to a
//! multiple of eight bytes (the next record is aligned for the inode).

/// The bytes before the name.
const HEADER: usize = 19;

/// The length of the record of a name: the header, the name and its NUL,
/// up to a multiple of eight.
pub const fn record_length(name_len: usize) -> usize {
    (HEADER + name_len + 1).next_multiple_of(8)
}

/// Writes one record at the start of `out`: its length, or None when it does
/// not fit.
pub fn record(out: &mut [u8], inode: u64, next: i64, kind: u8, name: &[u8]) -> Option<usize> {
    let length = record_length(name.len());
    let record = out.get_mut(..length)?;
    record.fill(0);
    record[..8].copy_from_slice(&inode.to_ne_bytes());
    record[8..16].copy_from_slice(&next.to_ne_bytes());
    record[16..18].copy_from_slice(&(length as u16).to_ne_bytes());
    record[18] = kind;
    record[HEADER..HEADER + name.len()].copy_from_slice(name);
    Some(length)
}

/// An entry the directory gave, with the offsets of the directory before it
/// was read and after.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Item {
    pub inode: u64,
    pub kind: u8,
    pub name_len: usize,
    pub before: i64,
    pub after: i64,
}

/// Fills `out` with the records of the entries `read` gives, as many as
/// fit: the number of bytes, 0 at the end of the directory. The first entry
/// that does not fit is put back (`seek` to the offset before it), so that
/// the next call takes it again; when not even one fits, the answer is EINVAL
/// and the offset has not moved. `read` writes the name into the buffer it
/// is given.
pub fn fill(
    out: &mut [u8],
    mut read: impl FnMut(&mut [u8; 256]) -> Result<Option<Item>, i32>,
    mut seek: impl FnMut(i64) -> Result<(), i32>,
) -> Result<usize, i32> {
    const EINVAL: i32 = 22;
    let mut used = 0;
    loop {
        let mut name = [0u8; 256];
        let Some(item) = read(&mut name)? else {
            break;
        };
        let name = &name[..item.name_len.min(name.len())];
        match record(&mut out[used..], item.inode, item.after, item.kind, name) {
            Some(length) => used += length,
            None => {
                seek(item.before)?;
                if used == 0 {
                    return Err(EINVAL);
                }
                break;
            }
        }
    }
    Ok(used)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// A directory of names, read from an offset.
    struct Directory {
        entries: Vec<(&'static [u8], u8)>,
        offset: i64,
    }

    impl Directory {
        fn read(&mut self, name: &mut [u8; 256]) -> Result<Option<Item>, i32> {
            let Some(&(text, kind)) = self.entries.get(self.offset as usize) else {
                return Ok(None);
            };
            name[..text.len()].copy_from_slice(text);
            let before = self.offset;
            self.offset += 1;
            Ok(Some(Item {
                inode: 100 + before as u64,
                kind,
                name_len: text.len(),
                before,
                after: self.offset,
            }))
        }
    }

    fn directory() -> Directory {
        Directory {
            entries: std::vec![
                (&b"."[..], 4),
                (&b".."[..], 4),
                (&b"a"[..], 8),
                (&b"a-name-of-some-length"[..], 8),
                (&b"link"[..], 10),
            ],
            offset: 0,
        }
    }

    fn fill_from(directory: &mut Directory, out: &mut [u8]) -> Result<usize, i32> {
        let cell = std::cell::RefCell::new(directory);
        fill(
            out,
            |name| cell.borrow_mut().read(name),
            |offset| {
                cell.borrow_mut().offset = offset;
                Ok(())
            },
        )
    }

    /// The records in `bytes` as (inode, next, type, name).
    fn parse(bytes: &[u8]) -> Vec<(u64, i64, u8, Vec<u8>)> {
        let mut records = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let inode = u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap());
            let next = i64::from_ne_bytes(bytes[at + 8..at + 16].try_into().unwrap());
            let length = u16::from_ne_bytes(bytes[at + 16..at + 18].try_into().unwrap()) as usize;
            let kind = bytes[at + 18];
            let name = &bytes[at + 19..at + length];
            let end = name.iter().position(|&byte| byte == 0).unwrap();
            records.push((inode, next, kind, name[..end].to_vec()));
            at += length;
        }
        assert_eq!(at, bytes.len(), "the records end where the last one ends");
        records
    }

    #[test]
    fn a_record_is_rounded_up_to_eight_bytes_with_its_name_and_a_nul() {
        for (name_len, length) in [
            (0, 24),
            (1, 24),
            (4, 24),
            (5, 32),
            (12, 32),
            (13, 40),
            (255, 280),
        ] {
            assert_eq!(record_length(name_len), length, "name of {name_len}");
        }
        let mut out = [0xaa; 40];
        let length = record(&mut out, 7, 3, 8, b"abc").unwrap();
        assert_eq!(length, 24);
        assert_eq!(&out[..8], &7u64.to_ne_bytes());
        assert_eq!(&out[8..16], &3i64.to_ne_bytes());
        assert_eq!(&out[16..18], &24u16.to_ne_bytes());
        assert_eq!(out[18], 8);
        assert_eq!(&out[19..23], b"abc\0");
        // The padding is zero, the bytes after the record untouched.
        assert!(out[23..24].iter().all(|&byte| byte == 0));
        assert!(out[24..].iter().all(|&byte| byte == 0xaa));
    }

    #[test]
    fn a_record_that_does_not_fit_is_not_written() {
        let mut out = [0xaa; 23];
        assert_eq!(record(&mut out, 7, 3, 8, b"abc"), None);
        assert!(out.iter().all(|&byte| byte == 0xaa));
    }

    #[test]
    fn all_entries_fit_in_a_large_buffer_with_their_types_and_next_offsets() {
        let mut directory = directory();
        let mut out = [0u8; 1024];
        let used = fill_from(&mut directory, &mut out).unwrap();
        let records = parse(&out[..used]);
        let names: Vec<&[u8]> = records.iter().map(|record| &record.3[..]).collect();
        assert_eq!(
            names,
            [&b"."[..], b"..", b"a", b"a-name-of-some-length", b"link"]
        );
        let kinds: Vec<u8> = records.iter().map(|record| record.2).collect();
        assert_eq!(kinds, [4, 4, 8, 8, 10]);
        let next: Vec<i64> = records.iter().map(|record| record.1).collect();
        assert_eq!(next, [1, 2, 3, 4, 5]);
        assert_eq!(used % 8, 0);
        // The end is 0, again and again.
        assert_eq!(fill_from(&mut directory, &mut out), Ok(0));
        assert_eq!(fill_from(&mut directory, &mut out), Ok(0));
    }

    #[test]
    fn the_entry_that_does_not_fit_is_taken_again_by_the_next_call() {
        let mut directory = directory();
        let mut out = [0u8; 56];
        // 24 + 24 fit, the 32-byte record of `a` does not.
        let used = fill_from(&mut directory, &mut out).unwrap();
        assert_eq!(used, 48);
        assert_eq!(directory.offset, 2);
        let mut rest = [0u8; 1024];
        let used = fill_from(&mut directory, &mut rest).unwrap();
        let names: Vec<Vec<u8>> = parse(&rest[..used])
            .into_iter()
            .map(|record| record.3)
            .collect();
        assert_eq!(
            names,
            [
                b"a".to_vec(),
                b"a-name-of-some-length".to_vec(),
                b"link".to_vec()
            ]
        );
    }

    #[test]
    fn a_buffer_with_no_room_for_one_record_is_einval_and_the_offset_stays() {
        let mut directory = directory();
        directory.offset = 2;
        for size in [0, 8, 23] {
            let mut out = std::vec![0u8; size];
            assert_eq!(fill_from(&mut directory, &mut out), Err(22), "size {size}");
            assert_eq!(directory.offset, 2, "size {size}");
        }
        // The same call with room takes the entry that was refused.
        let mut out = [0u8; 24];
        assert_eq!(fill_from(&mut directory, &mut out), Ok(32 - 8));
        assert_eq!(directory.offset, 3);
    }

    #[test]
    fn an_error_of_the_directory_is_the_error_of_the_call() {
        let mut out = [0u8; 64];
        let result = fill(&mut out, |_| Err(5), |_| Ok(()));
        assert_eq!(result, Err(5));
    }
}
