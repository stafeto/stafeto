// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Kernel objects that handles name (spec 4, 5). A handle holds a counted
//! reference to its process, thread, channel, session, timer, memory
//! object or interrupt binding, and the last reference queues the object
//! for cleanup (spec 7.7); a channel counts its
//! handles with RECEIVE too, since the last of them closes it (spec 6.8).
//! A channel handle with a label names the label's session, which names
//! the channel (spec 5.3) and counts its handles as its copies. The system
//! resource is one for the whole system and is not counted: what a handle
//! to it allows is in the handle's rights. Every kind of object keeps its
//! count in a `Refs` and its number in a `Live`.

use crate::channel::{self, Channel};
use crate::irq::{self, Irq};
use crate::memory::{self, Memory};
use crate::mm::pages::KernelPages;
#[cfg(feature = "ktest")]
use crate::mm::pages::POISON;
use crate::process::{self, Process};
use crate::session::{self, Session};
use crate::thread::{self, Thread};
use crate::timer::{self, Timer};
use abi::{MESSAGE_HANDLES, ObjectKind, Rights};
use core::mem::{MaybeUninit, align_of, size_of};
use core::ptr::NonNull;
#[cfg(feature = "ktest")]
use core::sync::atomic::{AtomicUsize, Ordering};
use kcore::handles::{Chunk, ChunkSource, Directory, HandleTable};
use kcore::slab::{PaidPages, Pool};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    Process(NonNull<Process>),
    Thread(NonNull<Thread>),
    Channel(NonNull<Channel>),
    /// A channel handle with a label (spec 5.3).
    Session(NonNull<Session>),
    /// A timer of a program (spec 10).
    Timer(NonNull<Timer>),
    /// A memory object (spec 7.3).
    Memory(NonNull<Memory>),
    /// An interrupt binding (spec 9).
    Irq(NonNull<Irq>),
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

    /// The channel, for a lookup that needs one: a handle with a label
    /// names one through its session.
    pub fn channel(&self) -> Option<NonNull<Channel>> {
        match *self {
            Object::Channel(c) => Some(c),
            Object::Session(s) => Some(session::channel(s)),
            _ => None,
        }
    }

    /// The session of a channel handle with a label.
    pub fn session(&self) -> Option<NonNull<Session>> {
        match *self {
            Object::Session(s) => Some(s),
            _ => None,
        }
    }

    /// The timer, for a lookup that needs one.
    pub fn timer(&self) -> Option<NonNull<Timer>> {
        match *self {
            Object::Timer(t) => Some(t),
            _ => None,
        }
    }

    /// The memory object, for a lookup that needs one.
    pub fn memory(&self) -> Option<NonNull<Memory>> {
        match *self {
            Object::Memory(m) => Some(m),
            _ => None,
        }
    }

    /// The interrupt binding, for a lookup that needs one.
    pub fn irq(&self) -> Option<NonNull<Irq>> {
        match *self {
            Object::Irq(b) => Some(b),
            _ => None,
        }
    }

    /// Some for the system resource, for a lookup that needs it.
    pub fn resource(&self) -> Option<()> {
        matches!(self, Object::Resource).then_some(())
    }

    /// The kind a message reports for a handle to the object (spec 6.2):
    /// a handle with a label names a channel.
    pub fn kind(&self) -> ObjectKind {
        match self {
            Object::Process(_) => ObjectKind::Process,
            Object::Thread(_) => ObjectKind::Thread,
            Object::Channel(_) | Object::Session(_) => ObjectKind::Channel,
            Object::Timer(_) => ObjectKind::Timer,
            Object::Memory(_) => ObjectKind::Memory,
            Object::Irq(_) => ObjectKind::Interrupt,
            Object::Resource => ObjectKind::Resource,
        }
    }
}

/// The count of references that keep a kernel object (spec 4, 7.7): which
/// ones each kind names. The last one to go queues the object for cleanup.
/// Test builds poison an object whose place went back to its pool
/// (`Live::gone`), and every use of the count stops on the poison.
pub struct Refs(u32);

impl Refs {
    /// The first reference, which the object's `create` hands out.
    pub const fn one() -> Refs {
        Refs(1)
    }

    /// Stops test builds on an object that went: the poison of its place
    /// reached the count. Nothing in the build that ships.
    #[track_caller]
    pub fn check(&self) {
        #[cfg(feature = "ktest")]
        assert!(
            self.0 != u32::from_ne_bytes([POISON; 4]),
            "an object is used after it went"
        );
    }

    /// Adds a reference to an object someone refers to. An object nobody
    /// refers to waits for its portion of cleanup, and taking it back from
    /// the queue would free it twice.
    #[track_caller]
    pub fn retain(&mut self) {
        self.check();
        assert!(self.0 > 0, "an object nobody refers to is retained");
        self.0 = self.0.checked_add(1).expect("references overflow");
    }

    /// Adds a reference with no check of the count: the cleanup queue's
    /// own, which it takes when the last reference just went, or one that
    /// a reference of the caller keeps.
    #[track_caller]
    pub fn take(&mut self) {
        self.check();
        self.0 = self.0.checked_add(1).expect("references overflow");
    }

    /// Drops a reference; true when it was the last.
    #[track_caller]
    pub fn release(&mut self) -> bool {
        self.check();
        self.0 = self
            .0
            .checked_sub(1)
            .expect("an object is released once too often");
        self.0 == 0
    }

    /// Drops `n` references, none of them the last.
    #[track_caller]
    pub fn release_many(&mut self, n: u32) {
        self.check();
        self.0 = self
            .0
            .checked_sub(n)
            .filter(|&left| left > 0)
            .expect("the last reference went with others");
    }

    /// The count.
    #[track_caller]
    pub fn get(&self) -> u32 {
        self.check();
        self.0
    }
}

/// The objects of one kind whose places have not gone back to their pool,
/// counted in test builds (crate::ktest); nothing in the build that ships.
pub struct Live(#[cfg(feature = "ktest")] AtomicUsize);

impl Live {
    pub const fn new() -> Live {
        Live(
            #[cfg(feature = "ktest")]
            AtomicUsize::new(0),
        )
    }

    /// One more object of the kind.
    pub fn made(&self) {
        #[cfg(feature = "ktest")]
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// The place of `object` just went back to its pool: one object fewer,
    /// and test builds poison the place past the pool's link, so that its
    /// `Refs` stops a use after free.
    ///
    /// # Safety
    /// The place is the pool's again, its first 8 bytes the pool's link, and
    /// nothing uses the object afterwards.
    pub unsafe fn gone<T>(&self, _object: NonNull<T>) {
        #[cfg(feature = "ktest")]
        {
            self.0.fetch_sub(1, Ordering::Relaxed);
            // SAFETY: the caller's promise; the link stays.
            unsafe {
                core::ptr::write_bytes(
                    _object.cast::<u8>().as_ptr().add(8),
                    POISON,
                    size_of::<T>() - 8,
                )
            };
        }
    }

    /// The objects of the kind now.
    #[cfg(feature = "ktest")]
    pub fn count(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

/// The handles of a message on their way (spec 6.1): out of the sender's
/// table, with their rights and the references they held, in the order the
/// message lists them.
pub type Moving = [Option<(Object, Rights)>; MESSAGE_HANDLES];

/// Adds the reference a new handle with `rights` holds.
pub fn retain(object: Object, rights: Rights) {
    match object {
        Object::Process(p) => process::retain(p),
        Object::Thread(t) => thread::retain(t),
        Object::Channel(c) => channel::retain(c, rights),
        Object::Session(s) => session::retain(s, rights),
        Object::Timer(t) => timer::retain(t),
        Object::Memory(m) => memory::retain(m),
        Object::Irq(b) => irq::retain_handle(b),
        Object::Resource => {}
    }
}

/// Drops the reference a handle with `rights` held; the last one queues
/// the object for cleanup at `cause` (1-63): the effective priority of the
/// thread whose call let the reference go, or the level of the object
/// whose portion did (spec 7.7). The last handle with RECEIVE to a channel
/// closes it, and the last copy of a session posts CLIENT_GONE (spec 5.3).
/// Nothing is taken apart here.
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
            Object::Session(s) => session::release(s, rights, cause),
            Object::Timer(t) => timer::release(t, cause),
            Object::Memory(m) => memory::release(m, cause),
            Object::Irq(b) => irq::release_handle(b, cause),
            Object::Resource => {}
        }
    }
}

/// The handles of a message go, where no table takes them (spec 6.1, 7.7):
/// each releases its reference at `cause`, as a closed handle does.
///
/// # Safety
/// The references are the caller's, and nothing uses them afterwards.
pub unsafe fn release_moving(moving: Moving, cause: u8) {
    for (object, rights) in moving.into_iter().flatten() {
        // SAFETY: the caller's promise.
        unsafe { release(object, rights, cause) };
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
