// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The settings blob `STAFSET1`: the files of the settings layer
//! (`repositories` and `keys/<name>.pub`) as the owner of the device sets
//! them. The signature, the version u32 (1), the number of files u32, then
//! for each file the length of its name u16, the name, the length u32 and
//! the bytes. This reads the structure; what a name or a file may hold is
//! the service's rule (services/pkgd, settings.rs).

use proto_wire::{Reader, Status};

pub const MAGIC: [u8; 8] = *b"STAFSET1";
pub const VERSION: u32 = 1;
/// The most files and bytes a blob holds.
pub const FILES_MAX: u32 = 32;
pub const BYTES_MAX: usize = 64 * 1024;

/// One file of the blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct File<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
}

/// The files of a blob that passed `parse`.
#[derive(Clone, Copy, Debug)]
pub struct Blob<'a> {
    bytes: &'a [u8],
    pub count: u32,
}

impl<'a> Blob<'a> {
    /// BAD_SIZE for a blob over BYTES_MAX, cut, with a name of 0 bytes, a
    /// count over FILES_MAX or bytes after the last file; INVALID is the
    /// service's for the other signature or version.
    pub fn parse(bytes: &'a [u8]) -> Result<Blob<'a>, Status> {
        if bytes.len() > BYTES_MAX {
            return Err(Status::BadSize);
        }
        let mut r = Reader::new(bytes);
        if r.bytes(8)? != MAGIC || r.u32()? != VERSION {
            return Err(Status::BadSize);
        }
        let count = r.u32()?;
        if count > FILES_MAX {
            return Err(Status::BadSize);
        }
        for _ in 0..count {
            let name = usize::from(r.u16()?);
            if name == 0 {
                return Err(Status::BadSize);
            }
            r.bytes(name)?;
            let len = r.u32()? as usize;
            r.bytes(len)?;
        }
        r.finish()?;
        Ok(Blob { bytes, count })
    }

    pub fn files(&self) -> impl Iterator<Item = File<'a>> + use<'a> {
        let mut r = Reader::new(&self.bytes[16..]);
        (0..self.count).map(move |_| {
            let name = usize::from(r.u16().expect("parse checked"));
            let name = r.bytes(name).expect("parse checked");
            let len = r.u32().expect("parse checked") as usize;
            File {
                name,
                data: r.bytes(len).expect("parse checked"),
            }
        })
    }
}

/// The blob of `files`, for the host.
#[cfg(any(test, feature = "alloc"))]
pub fn write(files: &[(&str, &[u8])]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for (name, data) in files {
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}
