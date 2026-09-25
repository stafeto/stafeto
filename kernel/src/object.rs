// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Kernel objects that handles name (spec 4, 5). A handle holds a counted
//! reference to its process or thread, and the last reference queues the
//! object for cleanup (spec 7.7). The system resource is one for the whole
//! system and is not counted: what a handle to it allows is in the
//! handle's rights.

use crate::mm::pages::KernelPages;
use crate::process::{self, Process};
use crate::thread::{self, Thread};
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use kcore::handles::{Chunk, ChunkSource, Directory, HandleTable};
use kcore::quota::Account;
use kcore::slab::Pool;
use kcore::sync::Lock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    Process(NonNull<Process>),
    Thread(NonNull<Thread>),
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

    /// Some for the system resource, for a lookup that needs it.
    pub fn resource(&self) -> Option<()> {
        matches!(self, Object::Resource).then_some(())
    }
}

/// Adds the reference a new handle holds.
pub fn retain(object: Object) {
    match object {
        Object::Process(p) => process::retain(p),
        Object::Thread(t) => thread::retain(t),
        Object::Resource => {}
    }
}

/// Drops the reference a handle held; the last one queues the object for
/// cleanup at `cause` (1-63): the effective priority of the thread whose
/// call let the reference go, or the level of the object whose portion
/// did (spec 7.7). Nothing is taken apart here.
///
/// # Safety
/// The reference was the handle's, and the handle is gone.
pub unsafe fn release(object: Object, cause: u8) {
    // SAFETY: the caller hands over the handle's reference.
    unsafe {
        match object {
            Object::Process(p) => process::release(p, cause),
            Object::Thread(t) => thread::release(t, cause),
            Object::Resource => {}
        }
    }
}

/// Memory for the chunks and directories of handle tables, each from a
/// pool of its own: two chunks or two directories to a pool page. A
/// pool's lock is taken for each chunk or directory alone, so a table
/// that releases its objects may release other tables meanwhile. Each
/// chunk and directory costs the quota of the table's owner its slot
/// (spec 7.5), whoever put the handle there: a table that does not fit
/// there has no memory.
pub struct Chunks<'a>(pub &'a mut Account);

type ChunkPool = Pool<MaybeUninit<Chunk<Object>>>;
type DirectoryPool = Pool<MaybeUninit<Directory<Object>>>;

static CHUNKS: Lock<ChunkPool> = Lock::new(Pool::new());
static DIRECTORIES: Lock<DirectoryPool> = Lock::new(Pool::new());

/// What a chunk of a handle table costs its owner's quota.
pub const CHUNK_COST: u64 = ChunkPool::SLOT as u64;
/// What the directory of a handle table costs its owner's quota.
pub const DIRECTORY_COST: u64 = DirectoryPool::SLOT as u64;

// SAFETY: a chunk or a directory is a free slot of its pool, sized and
// aligned for it; the pool hands it to no one else until it comes back.
unsafe impl ChunkSource<Object> for Chunks<'_> {
    fn alloc_chunk(&mut self) -> Option<NonNull<Chunk<Object>>> {
        self.0.charge(CHUNK_COST).ok()?;
        let Ok(slot) = CHUNKS.lock().alloc(&mut KernelPages, MaybeUninit::uninit()) else {
            self.0.refund(CHUNK_COST);
            return None;
        };
        Some(slot.cast())
    }

    unsafe fn free_chunk(&mut self, chunk: NonNull<Chunk<Object>>) {
        // SAFETY: the chunk came from alloc_chunk; MaybeUninit drops nothing.
        unsafe { CHUNKS.lock().free(chunk.cast()) };
        self.0.refund(CHUNK_COST);
    }

    fn alloc_directory(&mut self) -> Option<NonNull<Directory<Object>>> {
        self.0.charge(DIRECTORY_COST).ok()?;
        let Ok(slot) = DIRECTORIES
            .lock()
            .alloc(&mut KernelPages, MaybeUninit::uninit())
        else {
            self.0.refund(DIRECTORY_COST);
            return None;
        };
        Some(slot.cast())
    }

    unsafe fn free_directory(&mut self, directory: NonNull<Directory<Object>>) {
        // SAFETY: the directory came from alloc_directory; MaybeUninit
        // drops nothing.
        unsafe { DIRECTORIES.lock().free(directory.cast()) };
        self.0.refund(DIRECTORY_COST);
    }
}
