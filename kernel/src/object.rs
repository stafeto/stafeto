// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Kernel objects that handles name (spec 4, 5). A handle holds a counted
//! reference to its process, thread or channel, and the last reference
//! queues the object for cleanup (spec 7.7); a channel counts its handles
//! with RECEIVE too, since the last of them closes it (spec 6.8). The
//! system resource is one for the whole system and is not counted: what a
//! handle to it allows is in the handle's rights.

use crate::channel::{self, Channel};
use crate::mm::pages::KernelPages;
use crate::process::{self, Process};
use crate::thread::{self, Thread};
use abi::Rights;
use core::mem::{MaybeUninit, align_of, size_of};
use core::ptr::NonNull;
use kcore::handles::{Chunk, ChunkSource, Directory, HandleTable};
use kcore::slab::{PaidPages, Pool};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    Process(NonNull<Process>),
    Thread(NonNull<Thread>),
    Channel(NonNull<Channel>),
    /// Device windows, interrupts, the debug port and kernel statistics
    /// (spec 4): the rights DEVICE, DEBUG and KSTATS say which.
    Resource,
}

// SAFETY: objects are reached only under the kernel's rules (spec 8.1):
// one CPU, interrupts masked inside the kernel.
unsafe impl Send for Object {}

/// A process's handles.
pub type Handles = HandleTable<Object>;

impl Object {
    /// The process, for a lookup that needs one (HandleTable::get_as).
    pub fn process(&self) -> Option<NonNull<Process>> {
        match *self {
            Object::Process(p) => Some(p),
            _ => None,
        }
    }

    /// The thread, for a lookup that needs one.
    pub fn thread(&self) -> Option<NonNull<Thread>> {
        match *self {
            Object::Thread(t) => Some(t),
            _ => None,
        }
    }

    /// The channel, for a lookup that needs one.
    pub fn channel(&self) -> Option<NonNull<Channel>> {
        match *self {
            Object::Channel(c) => Some(c),
            _ => None,
        }
    }

    /// Some for the system resource, for a lookup that needs it.
    pub fn resource(&self) -> Option<()> {
        matches!(self, Object::Resource).then_some(())
    }
}

/// Adds the reference a new handle with `rights` holds.
pub fn retain(object: Object, rights: Rights) {
    match object {
        Object::Process(p) => process::retain(p),
        Object::Thread(t) => thread::retain(t),
        Object::Channel(c) => channel::retain(c, rights),
        Object::Resource => {}
    }
}

/// Drops the reference a handle with `rights` held; the last one queues
/// the object for cleanup at `cause` (1-63): the effective priority of the
/// thread whose call let the reference go, or the level of the object
/// whose portion did (spec 7.7). The last handle with RECEIVE to a channel
/// closes it. Nothing is taken apart here.
///
/// # Safety
/// The reference was the handle's, and the handle is gone.
pub unsafe fn release(object: Object, rights: Rights, cause: u8) {
    // SAFETY: the caller hands over the handle's reference.
    unsafe {
        match object {
            Object::Process(p) => process::release(p, cause),
            Object::Thread(t) => thread::release(t, cause),
            Object::Channel(c) => channel::release(c, rights, cause),
            Object::Resource => {}
        }
    }
}

/// A chunk or the directory of a handle table: both take 2048 bytes, so
/// one pool of the table's owner holds both, two to a page (spec 7.8).
pub type Block = MaybeUninit<Chunk<Object>>;

const _: () = assert!(
    size_of::<Directory<Object>>() <= size_of::<Block>()
        && align_of::<Directory<Object>>() <= align_of::<Block>()
        && size_of::<Block>() == 2048
);

/// Memory for the chunks and directories of a handle table: the pool of
/// blocks of the table's owner, whose pages are charged to the owner's
/// quota as the pool grows (spec 7.5, 7.8), whoever put the handle there.
/// A block that goes back stays in the pool and refunds nothing.
pub struct Chunks<'a> {
    pub blocks: &'a mut Pool<Block>,
    pub pages: PaidPages<'a, KernelPages>,
}

impl Chunks<'_> {
    /// A block of the owner's pool; None when its quota falls short.
    fn alloc(&mut self) -> Option<NonNull<Block>> {
        self.blocks
            .alloc(&mut self.pages, MaybeUninit::uninit())
            .ok()
    }

    /// Gives a block back to the pool.
    ///
    /// # Safety
    /// `block` came from `alloc` of this owner, and nothing uses it
    /// afterwards.
    unsafe fn free(&mut self, block: NonNull<Block>) {
        // SAFETY: the caller's promise; MaybeUninit drops nothing.
        unsafe { self.blocks.free(block) }
    }
}

// SAFETY: a chunk or a directory is a free slot of the owner's pool,
// sized and aligned for either; the pool hands it to no one else until it
// comes back.
unsafe impl ChunkSource<Object> for Chunks<'_> {
    fn alloc_chunk(&mut self) -> Option<NonNull<Chunk<Object>>> {
        self.alloc().map(NonNull::cast)
    }

    unsafe fn free_chunk(&mut self, chunk: NonNull<Chunk<Object>>) {
        // SAFETY: the chunk came from alloc_chunk.
        unsafe { self.free(chunk.cast()) }
    }

    fn alloc_directory(&mut self) -> Option<NonNull<Directory<Object>>> {
        self.alloc().map(NonNull::cast)
    }

    unsafe fn free_directory(&mut self, directory: NonNull<Directory<Object>>) {
        // SAFETY: the directory came from alloc_directory.
        unsafe { self.free(directory.cast()) }
    }
}
