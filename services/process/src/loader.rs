// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The loader's program (spec 2, 3.2; 5c), from the ELF file `loader.elf`
//! of the boot image, linked in the loader's region (proto_loader). At its
//! start the service copies its code and read-only data into one object
//! once, which each new process maps (code RX, data R): the boot image
//! itself has no MAP_EXEC to map in place. For each new process the
//! service makes an object of the loader's data and its stack, DATA_PAGES
//! at most, which it pays for until the loader unmaps it before it jumps
//! to the program.

use bootimg::BootImage;
use bootimg::elf::{self, Layout};
use bootimg::{PAGE_SIZE, Part};
use proto_loader::{LOADER_BASE, LOADER_END};
use rt::abi::{Access, Error};
use rt::handle::{Handle, Memory, Process};
use rt::sys;

/// The name of the loader's file in the boot image.
pub const FILE: &str = "loader.elf";
/// The stack of the loader, in pages, above its data.
const STACK_PAGES: u64 = 4;
/// The pages of the loader's data and stack at most: the service pays for
/// five pages a loader, LOADERS of them.
pub const DATA_PAGES: u64 = 5;
/// Where the loop maps the objects it fills, in its own space.
pub(super) const WINDOW: usize = 0x63_0000_0000;

pub struct Image {
    /// The code and the read-only data, one after the other.
    shared: Handle<Memory>,
    layout: Layout,
    code_len: u64,
    rodata_len: u64,
    /// The initial bytes of the loader's data, in the boot image.
    data: &'static [u8],
    data_at: u64,
    data_len: u64,
}

/// The bytes of the whole pages of `load`'s memory.
fn span(load: &elf::Load) -> u64 {
    let p = load.pages();
    p.end - p.start
}

/// `bytes` into `m` from its first byte, through the loop's window in
/// `own`.
fn fill(own: &Handle<Process>, m: &Handle<Memory>, at: u64, bytes: &[u8]) -> Result<(), Error> {
    if bytes.is_empty() {
        return Ok(());
    }
    let len = (at + bytes.len() as u64).next_multiple_of(PAGE_SIZE);
    sys::mem_map(own, m, 0, len, WINDOW, Access::ReadWrite)?;
    // SAFETY: the window maps `len` bytes of `m`, which only the loop uses
    // here, and `bytes` lies elsewhere.
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (WINDOW + at as usize) as *mut u8,
            bytes.len(),
        )
    };
    // SAFETY: the mapping made above, which nothing uses now.
    unsafe { sys::mem_unmap(own, WINDOW, len) }
}

impl Image {
    /// A shared segment's immutable mapping parameters, captured at startup.
    pub(super) fn shared_mapping(&self, part: Part) -> (u64, u64, usize, Access) {
        match part {
            Part::Code => (
                0,
                self.code_len,
                self.layout.segments[part as usize].vaddr as usize,
                Access::ReadExec,
            ),
            Part::Rodata => (
                self.code_len,
                self.rodata_len,
                self.layout.segments[part as usize].vaddr as usize,
                Access::Read,
            ),
            Part::Data => unreachable!("private data has its resident memory owner"),
        }
    }

    /// Only duplicates the shared owner; a later STEP maps and closes it.
    pub(super) fn narrow_shared(&self, part: Part) -> Result<Handle<Memory>, Error> {
        sys::handle_duplicate(&self.shared, self.shared_mapping(part).3.rights())
    }

    pub(super) fn data_len(&self) -> u64 {
        self.data_len
    }

    pub(super) fn data_bytes(&self) -> &'static [u8] {
        self.data
    }

    pub(super) fn data_at(&self) -> usize {
        self.data_at as usize
    }

    pub(super) fn entry(&self) -> u64 {
        self.layout.entry
    }

    /// The loader of the boot image `boot`, its code and read-only data
    /// copied into one object through `own`, the service's process; None
    /// for an image without one, or one whose segments leave the loader's
    /// region or whose data and stack pass DATA_PAGES.
    pub fn new(boot: BootImage<'static>, own: &Handle<Process>) -> Option<Image> {
        let file = boot.files().find(|f| f.name == FILE)?.data;
        let layout = elf::layout(file, file.len() as u64, LOADER_BASE..LOADER_END).ok()?;
        let [code, rodata, data] = layout.segments;
        let bytes = |l: &elf::Load| &file[l.offset as usize..(l.offset + l.file_size) as usize];
        let (code_len, rodata_len) = (span(&code), span(&rodata));
        let data_len = span(&data) + STACK_PAGES * PAGE_SIZE;
        if data_len > DATA_PAGES * PAGE_SIZE {
            return None;
        }
        // The data and the stack lie after the last page of the others
        // when the loader has no data of its own.
        let data_at = if data.is_empty() {
            layout
                .segments
                .iter()
                .map(|l| l.pages().end)
                .max()
                .unwrap_or(LOADER_BASE)
        } else {
            data.vaddr
        };
        let shared = sys::mem_create(code_len + rodata_len).ok()?;
        fill(own, &shared, 0, bytes(&code)).ok()?;
        fill(own, &shared, code_len, bytes(&rodata)).ok()?;
        Some(Image {
            shared,
            layout,
            code_len,
            rodata_len,
            data: bytes(&data),
            data_at,
            data_len,
        })
    }

    /// The address and length of the loader's data and stack, which it
    /// unmaps before it jumps to the program.
    pub fn data(&self) -> (u64, u64) {
        (self.data_at, self.data_len)
    }
}
