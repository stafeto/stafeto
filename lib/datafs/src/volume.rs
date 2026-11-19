// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Choosing the volume: which part of a disk is the data volume, and whether it is made, mounted or
//! left alone. The rules (the design note of the NVMe disks, section 3):
//!
//! - a disk with a valid GPT that has a partition of type `TYPE_DATA` uses that partition;
//! - a blank disk (the first MiB zero, no table) gets the table of `gpt::default_layout` (`store`
//!   and `data`) and then its `data` partition;
//! - a disk with a table and no such partition, or with anything else on it, is not written;
//! - a `data` partition without the attribute `FORMATTED` is formatted, mounted and given the
//!   attribute; one with it is only mounted, and when that fails nothing is written (a damaged
//!   volume is for its owner to look at).

use crate::fs::{BLOCKS_MAX, Fs, Storage};
use crate::gpt::{self, Class, FORMATTED, Found, Partition, TYPE_DATA};
use crate::{BLOCK_SECTORS, BLOCKS_MIN, Device, Window};

/// Why no volume was opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// Something else is on the disk.
    Foreign(Found),
    /// A table with no data partition.
    NoPartition,
    /// The partition is too small for the file system.
    TooSmall,
    /// The partition is over 4 GiB (`BLOCKS_MAX` blocks), the most this release uses: its window of
    /// the allocator covers one bit for each block, and a volume beyond it would walk the whole file
    /// system on every STATFS. The disk is left as it is.
    TooLarge,
    /// The file system of a formatted partition does not mount.
    Damaged,
    /// The disk is too small for a table, or failed.
    Device,
}

impl Refusal {
    pub const fn text(self) -> &'static str {
        match self {
            Self::Foreign(_) => {
                "the disk holds something else, left alone and unused in this release"
            }
            Self::NoPartition => "no data partition in the table",
            Self::TooSmall => "the data partition is too small",
            Self::TooLarge => {
                "the data partition is over 4 GiB, which this release does not use, left alone"
            }
            Self::Damaged => "the data volume does not mount, left alone",
            Self::Device => "the disk failed or is too small",
        }
    }
}

/// What `open` did, for a line on the console.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Did {
    /// A new table was written and the volume made.
    Partitioned,
    /// The partition was formatted.
    Formatted,
    /// The volume had grown: the backup copy of the table was moved to the new end, and the volume
    /// mounted.
    Relocated,
    Mounted,
}

/// Opens the data volume of `device` into `state`, `seed` making the GUIDs of a new table.
pub fn open<D: Device>(
    mut device: D,
    state: &mut Storage,
    seed: u64,
) -> Result<(Fs<'_, Window<D>>, Did, Partition), Refusal> {
    let mut did = Did::Mounted;
    let table = match gpt::classify(&mut device).map_err(|_| Refusal::Device)? {
        Class::Gpt(table) => table,
        Class::Foreign(found) => return Err(Refusal::Foreign(found)),
        Class::Blank => {
            let layout = gpt::default_layout(device.sectors()).ok_or(Refusal::Device)?;
            // Before the table is written: a disk that would get a data partition over the limit
            // is left blank.
            if (layout[1].last - layout[1].first + 1) / BLOCK_SECTORS > BLOCKS_MAX {
                return Err(Refusal::TooLarge);
            }
            did = Did::Partitioned;
            gpt::create(&mut device, &layout, seed).map_err(|_| Refusal::Device)?
        }
    };
    let part = table.find(&TYPE_DATA).ok_or(Refusal::NoPartition)?;
    if part.sectors() / BLOCK_SECTORS < BLOCKS_MIN {
        return Err(Refusal::TooSmall);
    }
    if part.sectors() / BLOCK_SECTORS > BLOCKS_MAX {
        return Err(Refusal::TooLarge);
    }
    let window = Window {
        first: part.first,
        sectors: part.sectors(),
        device,
    };
    let mut fs = Fs::new(window, state).map_err(|_| Refusal::TooSmall)?;
    if part.attributes & FORMATTED == 0 {
        fs.format().map_err(|_| Refusal::Device)?;
        fs.mount().map_err(|_| Refusal::Device)?;
        // The attribute goes in after the file system is there: a cut before it formats again.
        gpt::set_attributes(
            &mut fs.device().device,
            part.index,
            part.attributes | FORMATTED,
        )
        .map_err(|_| Refusal::Device)?;
        if did == Did::Mounted {
            did = Did::Formatted;
        }
    } else {
        fs.mount().map_err(|_| Refusal::Damaged)?;
    }
    // A table of ours (it has our data partition) on a volume that grew gets its backup copy moved,
    // once the volume is known to be one that is used: a volume that is refused is not written. A
    // table with no such partition is not ours and never gets here.
    if table.grown {
        gpt::relocate_backup(&mut fs.device().device).map_err(|_| Refusal::Device)?;
        did = Did::Relocated;
    }
    Ok((fs, did, part))
}
