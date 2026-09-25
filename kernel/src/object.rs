// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Kernel objects that handles name (spec 4, 5). A handle holds a counted
//! reference to its process or thread, and the object goes with its last
//! reference. The system resource is one for the whole system and is not
//! counted: what a handle to it allows is in the handle's rights.

use crate::mm::pages::KernelPages;
use crate::process::{self, Process};
use crate::thread::{self, Thread};
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use kcore::handles::{Chunk, ChunkSource, HandleTable};
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
#[cfg_attr(
    not(feature = "ktest"),
    expect(
        dead_code,
        reason = "init's handles and thread_create (milestone 1.2c) make handles; so far only the kernel tests do"
    )
)]
pub fn retain(object: Object) {
    match object {
        Object::Process(p) => process::retain(p),
        Object::Thread(t) => thread::retain(t),
        Object::Resource => {}
    }
}

/// Drops the reference a handle held; the object goes with its last one.
///
/// # Safety
/// The reference was the handle's, and the handle is gone.
pub unsafe fn release(object: Object) {
    // SAFETY: the caller hands over the handle's reference.
    unsafe {
        match object {
            Object::Process(p) => process::release(p),
            Object::Thread(t) => thread::release(t),
            Object::Resource => {}
        }
    }
}

/// Memory for the chunks of handle tables: two chunks to a pool page. The
/// pool's lock is taken for each chunk alone, so a table that releases
/// its objects may release other tables meanwhile.
pub struct Chunks;

static CHUNKS: Lock<Pool<MaybeUninit<Chunk<Object>>>> = Lock::new(Pool::new());

// SAFETY: a chunk is a free slot of the pool, sized and aligned for
// Chunk<Object>; the pool hands it to no one else until it comes back.
unsafe impl ChunkSource<Object> for Chunks {
    fn alloc_chunk(&mut self) -> Option<NonNull<Chunk<Object>>> {
        let slot = CHUNKS
            .lock()
            .alloc(&mut KernelPages, MaybeUninit::uninit())
            .ok()?;
        Some(slot.cast())
    }

    unsafe fn free_chunk(&mut self, chunk: NonNull<Chunk<Object>>) {
        // SAFETY: the chunk came from alloc_chunk; MaybeUninit drops nothing.
        unsafe { CHUNKS.lock().free(chunk.cast()) };
    }
}
