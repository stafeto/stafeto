// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Minimal flattened device tree (FDT) reader: header, memory reservation
//! block and a structure-block walker. It never allocates, and every read is
//! bounds checked, so a malformed blob yields an error instead of a fault.

const MAGIC: u32 = 0xd00d_feed;
const HEADER_SIZE: usize = 40;
const TOKEN_BEGIN_NODE: u32 = 1;
const TOKEN_END_NODE: u32 = 2;
const TOKEN_PROP: u32 = 3;
const TOKEN_NOP: u32 = 4;
const TOKEN_END: u32 = 9;

/// Deepest node nesting the walker accepts.
pub const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdtError {
    BadMagic,
    Truncated,
    UnsupportedVersion(u32),
    BadToken(u32),
    BadString,
    TooDeep,
}

/// One step of a depth-first walk over the structure block. The root node has
/// depth 1 and an empty name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    BeginNode { name: &'a str, depth: usize },
    Prop { name: &'a str, value: &'a [u8] },
    EndNode,
}

pub struct Fdt<'a> {
    data: &'a [u8],
    off_struct: usize,
    size_struct: usize,
    off_strings: usize,
    size_strings: usize,
    off_rsvmap: usize,
}

pub(crate) fn be32(data: &[u8], off: usize) -> Result<u32, FdtError> {
    let end = off.checked_add(4).ok_or(FdtError::Truncated)?;
    let b = data.get(off..end).ok_or(FdtError::Truncated)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

pub(crate) fn be64(data: &[u8], off: usize) -> Result<u64, FdtError> {
    let hi = u64::from(be32(data, off)?);
    let lo = u64::from(be32(data, off.checked_add(4).ok_or(FdtError::Truncated)?)?);
    Ok((hi << 32) | lo)
}

/// The NUL-terminated UTF-8 string at the start of `bytes`.
fn cstr(bytes: &[u8]) -> Result<&str, FdtError> {
    let len = bytes.iter().position(|&b| b == 0).ok_or(FdtError::Truncated)?;
    core::str::from_utf8(&bytes[..len]).map_err(|_| FdtError::BadString)
}

fn align4(x: usize) -> usize {
    (x + 3) & !3
}

impl<'a> Fdt<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, FdtError> {
        if be32(data, 0)? != MAGIC {
            return Err(FdtError::BadMagic);
        }
        let total = be32(data, 4)? as usize;
        if total < HEADER_SIZE || total > data.len() {
            return Err(FdtError::Truncated);
        }
        let data = &data[..total];
        let off_struct = be32(data, 8)? as usize;
        let off_strings = be32(data, 12)? as usize;
        let off_rsvmap = be32(data, 16)? as usize;
        let version = be32(data, 20)?;
        if version < 17 {
            return Err(FdtError::UnsupportedVersion(version));
        }
        let size_strings = be32(data, 32)? as usize;
        let size_struct = be32(data, 36)? as usize;
        let within = |off: usize, size: usize| off.checked_add(size).is_some_and(|end| end <= total);
        if !within(off_struct, size_struct) || !within(off_strings, size_strings) || off_rsvmap >= total {
            return Err(FdtError::Truncated);
        }
        Ok(Self { data, off_struct, size_struct, off_strings, size_strings, off_rsvmap })
    }

    /// Reads a device tree in place.
    ///
    /// # Safety
    /// `ptr` must point to a device tree whose `totalsize` bytes are readable
    /// for the rest of the program and never written.
    pub unsafe fn from_ptr(ptr: *const u8) -> Result<Fdt<'static>, FdtError> {
        // SAFETY: the caller guarantees the header is readable.
        let header = unsafe { core::slice::from_raw_parts(ptr, HEADER_SIZE) };
        if be32(header, 0)? != MAGIC {
            return Err(FdtError::BadMagic);
        }
        let total = be32(header, 4)? as usize;
        // SAFETY: the caller guarantees `totalsize` bytes are readable.
        Fdt::new(unsafe { core::slice::from_raw_parts(ptr, total) })
    }

    pub fn total_size(&self) -> usize {
        self.data.len()
    }

    /// Entries of the memory reservation block, up to the terminating zero pair.
    pub fn reservations(&self) -> Reservations<'a> {
        Reservations { data: self.data, off: self.off_rsvmap }
    }

    /// Walks the structure block depth first, calling `f` for every node start,
    /// property and node end.
    pub fn walk(&self, mut f: impl FnMut(Event<'a>)) -> Result<(), FdtError> {
        let data: &'a [u8] = self.data;
        let end = self.off_struct + self.size_struct;
        let strings = &data[self.off_strings..self.off_strings + self.size_strings];
        let mut off = self.off_struct;
        let mut depth = 0usize;
        loop {
            if off + 4 > end {
                return Err(FdtError::Truncated);
            }
            let token = be32(data, off)?;
            off += 4;
            match token {
                TOKEN_BEGIN_NODE => {
                    let name = cstr(&data[off..end])?;
                    off = align4(off + name.len() + 1);
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return Err(FdtError::TooDeep);
                    }
                    f(Event::BeginNode { name, depth });
                }
                TOKEN_END_NODE => {
                    if depth == 0 {
                        return Err(FdtError::BadToken(token));
                    }
                    depth -= 1;
                    f(Event::EndNode);
                }
                TOKEN_PROP => {
                    if off + 8 > end {
                        return Err(FdtError::Truncated);
                    }
                    let len = be32(data, off)? as usize;
                    let nameoff = be32(data, off + 4)? as usize;
                    off += 8;
                    let value_end = off.checked_add(len).ok_or(FdtError::Truncated)?;
                    if value_end > end {
                        return Err(FdtError::Truncated);
                    }
                    let name = strings.get(nameoff..).ok_or(FdtError::BadString).and_then(cstr)?;
                    f(Event::Prop { name, value: &data[off..value_end] });
                    off = align4(value_end);
                }
                TOKEN_NOP => {}
                TOKEN_END => {
                    return if depth == 0 { Ok(()) } else { Err(FdtError::Truncated) };
                }
                other => return Err(FdtError::BadToken(other)),
            }
        }
    }
}

pub struct Reservations<'a> {
    data: &'a [u8],
    off: usize,
}

impl Iterator for Reservations<'_> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<(u64, u64)> {
        let addr = be64(self.data, self.off).ok()?;
        let size = be64(self.data, self.off.checked_add(8)?).ok()?;
        if addr == 0 && size == 0 {
            return None;
        }
        self.off += 16;
        Some((addr, size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VIRT: &[u8] = include_bytes!("../tests/fixtures/virt.dtb");

    fn off_struct(blob: &[u8]) -> usize {
        be32(blob, 8).unwrap() as usize
    }

    #[test]
    fn parses_header_of_valid_blob() {
        let fdt = Fdt::new(VIRT).unwrap();
        assert_eq!(fdt.total_size(), VIRT.len());
    }

    #[test]
    fn walk_sees_top_level_nodes() {
        let fdt = Fdt::new(VIRT).unwrap();
        let mut names = Vec::new();
        fdt.walk(|e| {
            if let Event::BeginNode { name, depth: 2 } = e {
                names.push(name);
            }
        })
        .unwrap();
        assert_eq!(
            names,
            [
                "psci",
                "memory@40000000",
                "pl011@9000000",
                "pl011@9040000",
                "intc@8000000",
                "chosen"
            ]
        );
    }

    #[test]
    fn walk_balances_begin_and_end() {
        let fdt = Fdt::new(VIRT).unwrap();
        let (mut begins, mut ends) = (0, 0);
        fdt.walk(|e| match e {
            Event::BeginNode { .. } => begins += 1,
            Event::EndNode => ends += 1,
            Event::Prop { .. } => {}
        })
        .unwrap();
        assert_eq!(begins, 7);
        assert_eq!(begins, ends);
    }

    #[test]
    fn walk_reports_property_values() {
        let fdt = Fdt::new(VIRT).unwrap();
        let mut method = None;
        fdt.walk(|e| {
            if let Event::Prop { name: "method", value } = e {
                method = Some(value);
            }
        })
        .unwrap();
        assert_eq!(method, Some(&b"hvc\0"[..]));
    }

    #[test]
    fn reservations_list_memreserve_entries() {
        let fdt = Fdt::new(VIRT).unwrap();
        assert_eq!(fdt.reservations().collect::<Vec<_>>(), [(0x4800_0000, 0x1000)]);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut blob = VIRT.to_vec();
        blob[0] ^= 0xff;
        assert_eq!(Fdt::new(&blob).err(), Some(FdtError::BadMagic));
    }

    #[test]
    fn rejects_blob_shorter_than_totalsize() {
        assert_eq!(Fdt::new(&VIRT[..VIRT.len() - 1]).err(), Some(FdtError::Truncated));
    }

    #[test]
    fn rejects_empty_and_tiny_inputs() {
        assert_eq!(Fdt::new(&[]).err(), Some(FdtError::Truncated));
        assert_eq!(Fdt::new(&[0xd0, 0x0d, 0xfe, 0xed]).err(), Some(FdtError::Truncated));
    }

    #[test]
    fn rejects_old_versions() {
        let mut blob = VIRT.to_vec();
        blob[20..24].copy_from_slice(&16u32.to_be_bytes());
        assert_eq!(Fdt::new(&blob).err(), Some(FdtError::UnsupportedVersion(16)));
    }

    #[test]
    fn walk_reports_unknown_token() {
        // The root node is empty-named: token (4) + "\0" padded to 4 = the first
        // property token of the root sits 8 bytes into the structure block.
        let mut blob = VIRT.to_vec();
        let first_prop = off_struct(&blob) + 8;
        assert_eq!(be32(&blob, first_prop).unwrap(), 3);
        blob[first_prop..first_prop + 4].copy_from_slice(&0x77u32.to_be_bytes());
        let fdt = Fdt::new(&blob).unwrap();
        assert_eq!(fdt.walk(|_| {}), Err(FdtError::BadToken(0x77)));
    }

    #[test]
    fn walk_reports_string_offset_out_of_range() {
        let mut blob = VIRT.to_vec();
        let nameoff = off_struct(&blob) + 8 + 8;
        blob[nameoff..nameoff + 4].copy_from_slice(&0xFFFF_FF00u32.to_be_bytes());
        let fdt = Fdt::new(&blob).unwrap();
        assert_eq!(fdt.walk(|_| {}), Err(FdtError::BadString));
    }

    #[test]
    fn never_panics_on_any_single_corrupted_byte() {
        for i in 0..VIRT.len() {
            for delta in [0x01u8, 0x5a, 0xff] {
                let mut blob = VIRT.to_vec();
                blob[i] = blob[i].wrapping_add(delta);
                if let Ok(fdt) = Fdt::new(&blob) {
                    let _ = fdt.walk(|_| {});
                    let _ = fdt.reservations().count();
                }
            }
        }
    }
}
