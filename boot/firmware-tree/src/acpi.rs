// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The ACPI tables as slices: the RSDP, the XSDT and every table it names,
//! each checked for length and checksum (ACPI 6.5, "Root System Description
//! Pointer" and "Extended System Description Table"). Nothing reads past the
//! length a table declares: every access is a bounds-checked slice.

use crate::error::Error;
use alloc::vec::Vec;

/// The size of the header every table starts with.
pub const HEADER_SIZE: usize = 36;

/// The largest table accepted: a DSDT of a big machine is a few hundred KiB.
const MAX_TABLE: usize = 16 << 20;

pub fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

pub fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

pub fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// True when the bytes add up to 0 modulo 256.
pub fn checksum_ok(b: &[u8]) -> bool {
    b.iter().fold(0u8, |sum, &x| sum.wrapping_add(x)) == 0
}

/// One table: its signature and all its bytes, header included.
#[derive(Debug, Clone, Copy)]
pub struct Table<'a> {
    pub signature: [u8; 4],
    pub revision: u8,
    pub data: &'a [u8],
}

impl Table<'_> {
    pub fn is(&self, signature: &[u8; 4]) -> bool {
        &self.signature == signature
    }
}

/// The address of the XSDT in a version 2 or later RSDP: signature
/// `RSD PTR `, the checksum of the first 20 bytes, the extended checksum of
/// `length` bytes.
pub fn xsdt_address(rsdp: &[u8]) -> Result<u64, Error> {
    if rsdp.get(..8) != Some(b"RSD PTR ") {
        return Err(Error::BadSignature("RSDP"));
    }
    if !checksum_ok(rsdp.get(..20).ok_or(Error::Truncated("RSDP"))?) {
        return Err(Error::BadChecksum("RSDP"));
    }
    if rsdp[15] < 2 {
        return Err(Error::Unsupported("RSDP older than version 2 (no XSDT)"));
    }
    let length = u32_at(rsdp, 20).ok_or(Error::Truncated("RSDP"))? as usize;
    let whole = rsdp.get(..length).ok_or(Error::Truncated("RSDP"))?;
    if length < 36 || !checksum_ok(whole) {
        return Err(Error::BadChecksum("RSDP extended"));
    }
    match u64_at(rsdp, 24) {
        Some(0) | None => Err(Error::Missing("XSDT address")),
        Some(a) => Ok(a),
    }
}

/// The tables the XSDT names. `resolve(address, length)` returns the `length`
/// bytes at a physical address, or None; it is asked first for a header, then
/// for the whole table. A table that is cut short, absurdly long or fails its
/// checksum is left out and its signature listed in `rejected`: a table the
/// kernel does not need never stops the boot.
pub struct Tables<'a> {
    pub tables: Vec<Table<'a>>,
    pub rejected: Vec<([u8; 4], Error)>,
}

impl<'a> Tables<'a> {
    pub fn read(
        xsdt: &[u8],
        mut resolve: impl FnMut(u64, usize) -> Option<&'a [u8]>,
    ) -> Result<Self, Error> {
        if xsdt.get(..4) != Some(b"XSDT") {
            return Err(Error::BadSignature("XSDT"));
        }
        let length = u32_at(xsdt, 4).ok_or(Error::Truncated("XSDT"))? as usize;
        let xsdt = xsdt.get(..length).ok_or(Error::Truncated("XSDT"))?;
        if length < HEADER_SIZE || !checksum_ok(xsdt) {
            return Err(Error::BadChecksum("XSDT"));
        }
        let mut out = Tables {
            tables: Vec::new(),
            rejected: Vec::new(),
        };
        for entry in xsdt[HEADER_SIZE..].as_chunks::<8>().0 {
            let address = u64::from_le_bytes(*entry);
            let Some(header) = resolve(address, HEADER_SIZE) else {
                out.rejected
                    .push((*b"????", Error::Truncated("table header")));
                continue;
            };
            let signature: [u8; 4] = header[..4].try_into().unwrap();
            let length = u32_at(header, 4).unwrap_or(0) as usize;
            let checked = (HEADER_SIZE..=MAX_TABLE)
                .contains(&length)
                .then(|| resolve(address, length))
                .flatten();
            let Some(data) = checked else {
                out.rejected.push((signature, Error::Truncated("table")));
                continue;
            };
            if !checksum_ok(data) {
                out.rejected.push((signature, Error::BadChecksum("table")));
                continue;
            }
            out.tables.push(Table {
                signature,
                revision: data[8],
                data,
            });
        }
        Ok(out)
    }

    pub fn find(&self, signature: &[u8; 4]) -> Option<&Table<'a>> {
        self.tables.iter().find(|t| t.is(signature))
    }
}

/// The sub-structures of a table that holds a list of (type, length)
/// records from `start` on (the MADT). A record shorter than its header or
/// longer than the table ends the list with an error.
pub fn records(data: &[u8], start: usize) -> impl Iterator<Item = Result<(u8, &[u8]), Error>> {
    let mut off = start;
    core::iter::from_fn(move || {
        if off >= data.len() {
            return None;
        }
        let len = *data.get(off + 1)? as usize;
        let rec = (len >= 2).then(|| data.get(off..off + len)).flatten();
        match rec {
            Some(r) => {
                off += len;
                Some(Ok((r[0], r)))
            }
            None => {
                off = data.len();
                Some(Err(Error::Truncated("table record")))
            }
        }
    })
}

#[cfg(test)]
pub(crate) mod testing {
    //! Tables for the tests: a header with the right length and checksum.

    use super::*;

    pub fn finish(mut t: Vec<u8>) -> Vec<u8> {
        let len = t.len() as u32;
        t[4..8].copy_from_slice(&len.to_le_bytes());
        t[9] = 0;
        let sum = t.iter().fold(0u8, |s, &x| s.wrapping_add(x));
        t[9] = 0u8.wrapping_sub(sum);
        t
    }

    pub fn table(signature: &[u8; 4], revision: u8, body: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend(signature);
        t.extend([0; 4]);
        t.extend([revision, 0]);
        t.extend(b"STAFET");
        t.extend(b"TESTTBL ");
        t.extend([0; 4 + 4 + 4]);
        t.extend(body);
        finish(t)
    }

    pub fn rsdp(xsdt: u64) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend(b"RSD PTR ");
        r.extend([0, b'S', b'T', b'F', b'T', b'O', b'!', 2]);
        r.extend([0; 4]);
        r.extend(36u32.to_le_bytes());
        r.extend(xsdt.to_le_bytes());
        r.extend([0; 4]);
        let sum = r[..20].iter().fold(0u8, |s, &x| s.wrapping_add(x));
        r[8] = 0u8.wrapping_sub(sum);
        let sum = r.iter().fold(0u8, |s, &x| s.wrapping_add(x));
        r[32] = 0u8.wrapping_sub(sum);
        r
    }

    /// An XSDT naming the tables at the addresses given, and the memory those
    /// tables sit in: (xsdt bytes, [(address, bytes)]).
    pub fn firmware(tables: Vec<Vec<u8>>) -> (Vec<u8>, Vec<(u64, Vec<u8>)>) {
        let mut body = Vec::new();
        let mut placed = Vec::new();
        for (i, t) in tables.into_iter().enumerate() {
            let addr = 0x1000_0000 + 0x1_0000 * i as u64;
            body.extend(addr.to_le_bytes());
            placed.push((addr, t));
        }
        (table(b"XSDT", 1, &body), placed)
    }

    pub fn resolver<'a>(
        placed: &'a [(u64, Vec<u8>)],
    ) -> impl FnMut(u64, usize) -> Option<&'a [u8]> {
        move |addr, len| {
            let (_, bytes) = placed.iter().find(|(a, _)| *a == addr)?;
            bytes.get(..len)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn the_rsdp_gives_the_xsdt_address_and_every_damage_is_refused() {
        let good = rsdp(0xdead_0000);
        assert_eq!(xsdt_address(&good), Ok(0xdead_0000));
        let mut bad = good.clone();
        bad[0] = b'X';
        assert_eq!(xsdt_address(&bad), Err(Error::BadSignature("RSDP")));
        let mut bad = good.clone();
        bad[24] ^= 1;
        assert_eq!(xsdt_address(&bad), Err(Error::BadChecksum("RSDP extended")));
        let mut bad = good.clone();
        bad[9] ^= 1;
        assert_eq!(xsdt_address(&bad), Err(Error::BadChecksum("RSDP")));
        assert_eq!(xsdt_address(&good[..30]), Err(Error::Truncated("RSDP")));
        let mut v1 = good.clone();
        v1[15] = 0;
        let sum = v1[..20].iter().fold(0u8, |s, &x| s.wrapping_add(x));
        v1[8] = v1[8].wrapping_sub(sum);
        assert!(matches!(xsdt_address(&v1), Err(Error::Unsupported(_))));
    }

    #[test]
    fn tables_come_checked_and_a_damaged_one_is_listed_not_fatal() {
        let mut bad_sum = table(b"BAD1", 1, &[1, 2, 3]);
        bad_sum[36] ^= 1;
        let mut lying = table(b"LIE1", 1, &[1, 2, 3]);
        lying[4..8].copy_from_slice(&0x9999u32.to_le_bytes());
        let (xsdt, placed) = firmware(vec![table(b"OKAY", 5, &[9; 10]), bad_sum, lying]);
        let got = Tables::read(&xsdt, resolver(&placed)).unwrap();
        assert_eq!(got.tables.len(), 1);
        assert!(got.find(b"OKAY").is_some_and(|t| t.revision == 5));
        assert_eq!(
            got.rejected,
            [
                (*b"BAD1", Error::BadChecksum("table")),
                (*b"LIE1", Error::Truncated("table"))
            ]
        );
    }

    #[test]
    fn an_xsdt_that_is_cut_short_or_wrong_is_an_error() {
        let (xsdt, placed) = firmware(vec![table(b"OKAY", 1, &[])]);
        assert!(Tables::read(&xsdt[..40], resolver(&placed)).is_err());
        let mut bad = xsdt.clone();
        bad[0] = b'R';
        assert!(Tables::read(&bad, resolver(&placed)).is_err());
    }

    #[test]
    fn records_stop_at_a_short_or_overlong_record() {
        let data = [1u8, 3, 0, 2, 2, 7, 0, 0];
        let got: Vec<_> = records(&data, 0).collect();
        assert_eq!(got.len(), 3);
        assert!(got[0].is_ok() && got[1].is_ok() && got[2].is_err());
        let overlong = [1u8, 9, 0];
        assert!(records(&overlong, 0).next().unwrap().is_err());
    }
}
