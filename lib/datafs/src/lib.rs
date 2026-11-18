// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The data volume of the file service `datafs`: littlefs (third-party/littlefs, BSD-3-Clause) over a
//! `Device` of 512-byte sectors, and the GPT that names the partitions of a volume (`gpt`).
//!
//! littlefs keeps its metadata in pairs of blocks that it commits one after the other, each commit
//! closed by a checksum and a flush of the device, so a cut of the power leaves the last complete
//! commit and everything before it. A file that was never synced shows the contents of its last
//! sync, or does not exist if it was never synced. The wrapper adds nothing to that: `sync` is
//! `lfs_file_sync`, which writes the file's blocks, then the metadata that names them, then asks the
//! device to flush.
//!
//! The memory is the caller's: `Storage` is the one block of memory a volume uses (the caches, the
//! look-ahead of the allocator and one cache for each open file), and littlefs never allocates.

#![cfg_attr(not(test), no_std)]

pub mod fs;
pub mod gpt;
#[cfg(any(test, feature = "model"))]
pub mod mem;
pub mod server;
pub mod stop;
#[cfg(test)]
mod tests;
pub mod volume;

pub use fs::{Dir, Entry, Error, File, Fs, Info, Kind, Open, Storage, Whence};

use core::fmt;

/// The bytes of a sector and of a block of the volume (8 sectors).
pub const SECTOR: usize = 512;
pub const BLOCK: usize = 4096;
/// The sectors of a block.
pub const BLOCK_SECTORS: u64 = (BLOCK / SECTOR) as u64;
/// The files and directories open at once.
pub const FILES: usize = 8;
pub const DIRS: usize = 4;
/// The longest name of one component, in bytes.
pub const NAME_MAX: usize = 255;
/// The smallest volume that holds the file system: the superblock pair and room to write.
pub const BLOCKS_MIN: u64 = 16;

/// The device failed or lost power.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceError;

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the device failed")
    }
}

/// The sectors of a volume, as the disk service gives them: reads and writes of whole sectors,
/// and a flush that makes every write that returned reach the medium.
pub trait Device {
    /// The sectors of the volume.
    fn sectors(&self) -> u64;
    /// Reads `out.len() / 512` sectors from `sector`.
    fn read(&mut self, sector: u64, out: &mut [u8]) -> Result<(), DeviceError>;
    /// Writes `data.len() / 512` sectors from `sector`. A write that fails may have written a prefix.
    fn write(&mut self, sector: u64, data: &[u8]) -> Result<(), DeviceError>;
    /// Makes the writes that returned durable.
    fn flush(&mut self) -> Result<(), DeviceError>;
}

impl<D: Device + ?Sized> Device for &mut D {
    fn sectors(&self) -> u64 {
        (**self).sectors()
    }

    fn read(&mut self, sector: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        (**self).read(sector, out)
    }

    fn write(&mut self, sector: u64, data: &[u8]) -> Result<(), DeviceError> {
        (**self).write(sector, data)
    }

    fn flush(&mut self) -> Result<(), DeviceError> {
        (**self).flush()
    }
}

/// A device that is a window of another: the partition of a GPT.
pub struct Window<D: Device> {
    pub device: D,
    pub first: u64,
    pub sectors: u64,
}

impl<D: Device> Device for Window<D> {
    fn sectors(&self) -> u64 {
        self.sectors
    }

    fn read(&mut self, sector: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        let count = (out.len() / SECTOR) as u64;
        if sector
            .checked_add(count)
            .is_none_or(|end| end > self.sectors)
        {
            return Err(DeviceError);
        }
        self.device.read(self.first + sector, out)
    }

    fn write(&mut self, sector: u64, data: &[u8]) -> Result<(), DeviceError> {
        let count = (data.len() / SECTOR) as u64;
        if sector
            .checked_add(count)
            .is_none_or(|end| end > self.sectors)
        {
            return Err(DeviceError);
        }
        self.device.write(self.first + sector, data)
    }

    fn flush(&mut self) -> Result<(), DeviceError> {
        self.device.flush()
    }
}
