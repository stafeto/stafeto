// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Read-only ext4 access through an offset reader. A filesystem service can
//! implement [`ReadAt`] using a block-device channel without exposing writes.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use core::error::Error;
use core::fmt;
use ext4_view::{Ext4, Ext4Error, Ext4Read};

pub use ext4_view::{File, Metadata, ReadDir};

/// A device that fills a byte range or returns an error.
pub trait ReadAt {
    type Error: Error + Send + Sync + 'static;

    fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), Self::Error>;
}

/// A bounded, read-only device accepted by ext4-view.
pub struct Disk<D> {
    source: D,
    size: u64,
}

impl<D> Disk<D> {
    pub const fn new(source: D, size: u64) -> Self {
        Self { source, size }
    }
}

/// The filesystem requested bytes outside the device.
#[derive(Debug)]
pub struct OutOfRange;

impl fmt::Display for OutOfRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("read past the end of the block device")
    }
}

impl Error for OutOfRange {}

impl<D: ReadAt> Ext4Read for Disk<D> {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let len = u64::try_from(dst.len()).map_err(|_| Box::new(OutOfRange))?;
        let end = start_byte
            .checked_add(len)
            .ok_or_else(|| Box::new(OutOfRange))?;
        if end > self.size {
            return Err(Box::new(OutOfRange));
        }
        self.source
            .read_exact_at(start_byte, dst)
            .map_err(|e| Box::new(e) as _)
    }
}

/// Mount an ext2, ext3, or ext4 filesystem without write access.
pub fn mount<D: ReadAt + 'static>(source: D, size: u64) -> Result<Ext4, Ext4Error> {
    Ext4::load(Box::new(Disk::new(source, size)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    struct Image(&'static [u8]);

    impl ReadAt for Image {
        type Error = OutOfRange;

        fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), OutOfRange> {
            let start = usize::try_from(offset).map_err(|_| OutOfRange)?;
            let end = start.checked_add(out.len()).ok_or(OutOfRange)?;
            let bytes = self.0.get(start..end).ok_or(OutOfRange)?;
            out.copy_from_slice(bytes);
            Ok(())
        }
    }

    const IMAGE: &[u8] = include_bytes!("../tests/ext4.img");

    #[test]
    fn reads_image_from_e2fsprogs() {
        let fs = mount(Image(IMAGE), IMAGE.len() as u64).unwrap();
        assert_eq!(fs.read("/boot/hello.txt").unwrap(), b"hello from ext4\n");
        assert_eq!(fs.read("/boot/message").unwrap(), b"hello from ext4\n");
        let entries: Vec<_> = fs
            .read_dir("/boot")
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect();
        assert!(entries.iter().any(|entry| entry.file_name() == "hello.txt"));
        assert!(entries.iter().any(|entry| entry.file_name() == "message"));
    }

    #[test]
    fn rejects_short_device() {
        assert!(mount(Image(IMAGE), 1024).is_err());
    }
}
