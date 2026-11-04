// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process-local descriptors sharing backend open descriptions. The owner
//! serializes table access and releases backends after unlocking. Ordinary
//! operation holds have a separate budget from resident job records.
//! Open, Scalar and Control use sixteen independent resident job slots.
//! A live Open record preserves its completion through fd replacement.
//! The caller pins this table's address while records or waiters exist.

#![no_std]

#[cfg(test)]
extern crate self as posix_fd;
#[cfg(test)]
extern crate std;

mod io;
pub use io::*;
mod closing;
mod control;
pub mod owners;
pub use closing::*;
mod scalar;
pub use control::*;
pub use scalar::*;

use core::{
    num::NonZeroU64,
    ptr::NonNull,
    sync::atomic::{AtomicU32, Ordering},
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Flags {
    pub close_on_exec: bool,
    pub close_on_fork: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    BadFileDescriptor,
    TooManyOpenFiles,
    InvalidArgument,
    Io,
    /// The number lies in the page `k` of entries, which the table does not
    /// have yet: the caller maps a page, gives it to `add_page`, and asks again.
    NeedPage(usize),
}

/// A caller-issued, nonreused lifetime. Detach precedes thread-place reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerToken(NonZeroU64);

impl OwnerToken {
    pub fn new(value: u64) -> Result<Self, Error> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(Error::InvalidArgument)
    }

    pub fn value(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenToken {
    slot: usize,
    generation: u64,
}

impl OpenToken {
    pub fn slot(self) -> usize {
        32 + self.slot
    }

    pub fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimToken {
    open: OpenToken,
    serial: u64,
}

impl ClaimToken {
    pub fn open(self) -> OpenToken {
        self.open
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryToken {
    pub fd: u32,
    generation: NonZeroU64,
}

impl EntryToken {
    pub fn generation(self) -> u64 {
        self.generation.get()
    }

    fn new(fd: u32, generation: u64) -> Self {
        Self {
            fd,
            generation: NonZeroU64::new(generation).expect("live entry generation"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    Opened(u32),
    Failed(i32),
}

impl Completion {
    pub fn into_result(self) -> Result<u32, i32> {
        match self {
            Self::Opened(fd) => Ok(fd),
            Self::Failed(errno) => Err(errno),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenPhase {
    Preparing,
    Reserved,
    Committed,
    Published,
    Failed,
    Canceling,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenSnapshot<R> {
    pub owner: Option<OwnerToken>,
    pub claimant: Option<OwnerToken>,
    pub phase: OpenPhase,
    pub recovery: Option<R>,
    pub entry: Option<EntryToken>,
    pub flags: Option<Flags>,
    pub completion: Option<Completion>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Claim<R> {
    Acquired {
        token: ClaimToken,
        snapshot: OpenSnapshot<R>,
    },
    Busy(OwnerToken),
    Complete(Completion),
    Canceling(OpenSnapshot<R>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Replacement<T> {
    Complete { fd: u32, release: Option<T> },
    Pending(OpenToken),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Abandoned<T, R> {
    /// The exact unreturned entry has been closed, or its lifetime ended.
    Discarded {
        token: OpenToken,
        release: Option<T>,
    },
    /// Canonical remote cleanup remains payable by this resident record.
    Recover {
        token: OpenToken,
        snapshot: OpenSnapshot<R>,
    },
    /// A helper lifetime ended. The original caller retains its completion.
    ClaimReleased(OpenToken),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitValue {
    Sequence(u32),
    /// Help or use a bounded timer before rechecking. Futex wait is forbidden.
    NeverSleep,
}

#[derive(Clone, Copy)]
struct Entry<T> {
    backend: T,
    flags: Flags,
}

#[derive(Clone, Copy)]
enum EntryState<T> {
    Empty,
    Pending(usize),
    Closing(CloseToken),
    Open(Entry<T>),
}

#[derive(Clone, Copy)]
struct EntrySlot<T> {
    generation: u64,
    state: EntryState<T>,
}

/// A page of `N` entries for the numbers `N` and above, in memory the caller
/// maps (`Table::add_page`). Its size is `N` entries; the owner of the table
/// checks that it fits the page it maps.
pub struct EntryPage<T, const N: usize> {
    slots: [EntrySlot<T>; N],
}

/// The words of the bitmap of the numbers in use: 1 024 numbers at most.
const OCCUPIED_WORDS: usize = 16;

#[derive(Clone, Copy)]
struct Hold<T> {
    backend: T,
    count: u16,
    closed: bool,
    released: bool,
}

#[derive(Clone, Copy)]
enum Phase<T, R> {
    Preparing(R),
    Reserved {
        recovery: R,
        entry: EntryToken,
        flags: Flags,
    },
    Committed {
        recovery: R,
        entry: EntryToken,
        flags: Flags,
        backend: T,
    },
    Published(EntryToken),
    Failed(i32),
    Canceling {
        recovery: R,
        entry: Option<EntryToken>,
        backend: Option<T>,
    },
}

#[derive(Clone, Copy)]
struct OpenRecord<T, R> {
    owner: Option<OwnerToken>,
    claimant: Option<OwnerToken>,
    serial: u64,
    phase: Phase<T, R>,
}

impl<T: Copy, R: Copy> OpenRecord<T, R> {
    fn snapshot(self) -> OpenSnapshot<R> {
        let (phase, recovery, entry, flags, completion) = match self.phase {
            Phase::Preparing(r) => (OpenPhase::Preparing, Some(r), None, None, None),
            Phase::Reserved {
                recovery,
                entry,
                flags,
            } => (
                OpenPhase::Reserved,
                Some(recovery),
                Some(entry),
                Some(flags),
                None,
            ),
            Phase::Committed {
                recovery,
                entry,
                flags,
                ..
            } => (
                OpenPhase::Committed,
                Some(recovery),
                Some(entry),
                Some(flags),
                None,
            ),
            Phase::Published(e) => (
                OpenPhase::Published,
                None,
                Some(e),
                None,
                Some(Completion::Opened(e.fd)),
            ),
            Phase::Failed(errno) => (
                OpenPhase::Failed,
                None,
                None,
                None,
                Some(Completion::Failed(errno)),
            ),
            Phase::Canceling {
                recovery, entry, ..
            } => (OpenPhase::Canceling, Some(recovery), entry, None, None),
        };
        OpenSnapshot {
            owner: self.owner,
            claimant: self.claimant,
            phase,
            recovery,
            entry,
            flags,
            completion,
        }
    }

    fn cancel(&mut self) {
        self.phase = match self.phase {
            Phase::Preparing(recovery) => Phase::Canceling {
                recovery,
                entry: None,
                backend: None,
            },
            Phase::Reserved {
                recovery, entry, ..
            } => Phase::Canceling {
                recovery,
                entry: Some(entry),
                backend: None,
            },
            Phase::Committed {
                recovery,
                entry,
                backend,
                ..
            } => Phase::Canceling {
                recovery,
                entry: Some(entry),
                backend: Some(backend),
            },
            phase => phase,
        };
        self.claimant = None;
    }
}

#[derive(Clone, Copy)]
enum Held<T, R, S, C> {
    Empty,
    Io(Hold<T>),
    Open(OpenRecord<T, R>),
    Scalar(ScalarRecord<T, S>),
    Control(ControlRecord<C>),
    RecoverableIo(IoRecord<T, R>),
    Disposal(DisposalSnapshot<T, R>),
}

struct HoldSlot<T, R, S, C> {
    generation: u64,
    changed: AtomicU32,
    held: Held<T, R, S, C>,
}

impl<T, R, S, C> HoldSlot<T, R, S, C> {
    fn change(&self) {
        let value = self.changed.load(Ordering::Relaxed);
        self.changed
            .store(value.saturating_add(1), Ordering::Release);
    }
}

/// The most jobs of one session of a file service a process keeps in flight:
/// the service holds 16 for a session, whatever their kind.
pub const JOBS_MAX: usize = 16;

/// The most descriptions a process pins for its shared mappings of files,
/// apart from its numbers (`Table::pin`).
pub const MAP_PINS: usize = 16;

/// What a place of the pins keeps.
#[derive(Clone, Copy)]
struct PinSlot<T> {
    backend: T,
    /// The identity of the file the mappings through it show.
    key: u64,
    /// The description was open for writing: mappings that write back go
    /// through a pin of this kind only.
    writes: bool,
    /// The shared mappings that hold the pin.
    refs: u32,
}

/// A reference to a pin: its place and the generation of the place, so
/// that a reference to a pin that went never names the pin that took its
/// place.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinRef {
    place: usize,
    generation: u64,
}

impl PinRef {
    pub fn new(place: usize, generation: u64) -> Self {
        PinRef { place, generation }
    }

    pub fn place(self) -> usize {
        self.place
    }

    pub fn generation(self) -> u64 {
        self.generation
    }
}

impl Default for PinRef {
    /// A reference that names no pin.
    fn default() -> Self {
        PinRef {
            place: usize::MAX,
            generation: 0,
        }
    }
}

/// Whether the table has a place for one more job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobPlace {
    Free,
    /// All places are taken. `sequence` is the value of the wait word the
    /// caller waits on; `own` says that the caller's own live operations
    /// hold every place, so no other thread can free one.
    Full {
        sequence: u32,
        own: bool,
    },
}

/// The table of descriptors. The numbers `0..N` lie in the table itself, the
/// numbers `N..N * (1 + PAGES)` in `PAGES` pages of `N` entries each that the
/// owner maps when a number asks for one (`Error::NeedPage`); the holds stay
/// `N`. A bitmap names the numbers that are not empty, so that the walks
/// visit those alone.
pub struct Table<
    T: Copy + Eq,
    const N: usize,
    R: Copy = (),
    S: Copy = (),
    C: Copy = (),
    const PAGES: usize = 0,
> {
    entries: [EntrySlot<T>; N],
    pages: [Option<NonNull<EntryPage<T, N>>>; PAGES],
    occupied: [u64; OCCUPIED_WORDS],
    holds: [HoldSlot<T, R, S, C>; N],
    /// All job kinds retain custody while every ordinary I/O hold is occupied.
    residents: [HoldSlot<T, R, S, C>; JOBS_MAX],
    closings: [closing::CloseSlot<T, C>; JOBS_MAX],
    release_early: fn(T) -> bool,
    /// Descriptions kept alive for the shared mappings of files without a
    /// number: no descriptor shows them, `fcntl`, `closefrom` and the
    /// numbers a program picks never meet them.
    pins: [Option<PinSlot<T>>; MAP_PINS],
    /// The generation of each place: it grows when the place takes a new
    /// pin, so a stale `PinRef` names nothing.
    pin_generations: [u64; MAP_PINS],
    /// Counts the records of jobs that went; a thread that waits for a place
    /// waits on it. The caller wakes it after unlocking.
    jobs: AtomicU32,
    allocation_limit: u32,
}

impl<T: Copy + Eq, const N: usize, R: Copy, S: Copy, C: Copy, const PAGES: usize> Default
    for Table<T, N, R, S, C, PAGES>
{
    fn default() -> Self {
        const { assert!(N * (1 + PAGES) <= OCCUPIED_WORDS * 64) };
        Self {
            entries: [EntrySlot {
                generation: 0,
                state: EntryState::Empty,
            }; N],
            pages: [None; PAGES],
            occupied: [0; OCCUPIED_WORDS],
            holds: [const {
                HoldSlot {
                    generation: 0,
                    changed: AtomicU32::new(0),
                    held: Held::Empty,
                }
            }; N],
            residents: [const {
                HoldSlot {
                    generation: 0,
                    changed: AtomicU32::new(0),
                    held: Held::Empty,
                }
            }; JOBS_MAX],
            closings: [const {
                closing::CloseSlot {
                    generation: 0,
                    changed: AtomicU32::new(0),
                    record: None,
                }
            }; JOBS_MAX],
            release_early: |_| false,
            pins: [None; MAP_PINS],
            pin_generations: [0; MAP_PINS],
            jobs: AtomicU32::new(0),
            allocation_limit: Self::FDS as u32,
        }
    }
}

impl<T: Copy + Eq, const N: usize, R: Copy, S: Copy, C: Copy, const PAGES: usize>
    Table<T, N, R, S, C, PAGES>
{
    /// The numbers the table can name: the table's own and those of its pages.
    pub const FDS: usize = N * (1 + PAGES);

    /// Armed early-release operations retain their generations in the service.
    pub fn with_early_release(release_early: fn(T) -> bool) -> Self {
        Self {
            release_early,
            ..Self::default()
        }
    }

    /// Initialize a table directly in its permanent startup allocation.
    /// Every slot receives a valid enum and atomic value independently.
    ///
    /// # Safety
    /// `destination` is aligned, writable, and valid for a complete uninitialized
    /// `Self`. The caller has exclusive access until startup publishes Ready.
    /// No initialized resources may occupy this allocation. Its address remains
    /// pinned while live records or waiters refer to the hold headers.
    pub unsafe fn initialize_at(destination: *mut Self, release_early: fn(T) -> bool) {
        // SAFETY: the caller provides exclusive writable storage for all fields.
        let entries =
            unsafe { core::ptr::addr_of_mut!((*destination).entries) }.cast::<EntrySlot<T>>();
        // SAFETY: this field lies within the caller's complete Self allocation.
        let holds =
            unsafe { core::ptr::addr_of_mut!((*destination).holds) }.cast::<HoldSlot<T, R, S, C>>();
        for index in 0..N {
            // SAFETY: index is bounded by the entries array; write initializes
            // this element without reading or dropping uninitialized bytes.
            unsafe {
                entries.add(index).write(EntrySlot {
                    generation: 0,
                    state: EntryState::Empty,
                });
            }
            // SAFETY: index is bounded by the holds array. The enum and atomic
            // receive their valid initial values before any reader exists.
            unsafe {
                holds.add(index).write(HoldSlot {
                    generation: 0,
                    changed: AtomicU32::new(0),
                    held: Held::Empty,
                });
            }
        }
        // SAFETY: forming a field address does not read uninitialized storage.
        let residents = unsafe { core::ptr::addr_of_mut!((*destination).residents) }
            .cast::<HoldSlot<T, R, S, C>>();
        for index in 0..JOBS_MAX {
            // SAFETY: exclusive startup access initializes each additional slot.
            unsafe {
                residents.add(index).write(HoldSlot {
                    generation: 0,
                    changed: AtomicU32::new(0),
                    held: Held::Empty,
                });
            }
        }
        // SAFETY: this field is within the complete exclusive startup allocation.
        let closings = unsafe { core::ptr::addr_of_mut!((*destination).closings) }
            .cast::<closing::CloseSlot<T, C>>();
        for index in 0..JOBS_MAX {
            // SAFETY: each bounded close slot receives valid enum and atomic values.
            unsafe {
                closings.add(index).write(closing::CloseSlot {
                    generation: 0,
                    changed: AtomicU32::new(0),
                    record: None,
                });
            }
        }
        const { assert!(N * (1 + PAGES) <= OCCUPIED_WORDS * 64) };
        // SAFETY: exclusive startup ownership permits initializing these fields.
        unsafe {
            core::ptr::addr_of_mut!((*destination).pages).write([None; PAGES]);
            core::ptr::addr_of_mut!((*destination).occupied).write([0; OCCUPIED_WORDS]);
            core::ptr::addr_of_mut!((*destination).release_early).write(release_early);
            core::ptr::addr_of_mut!((*destination).pins).write([None; MAP_PINS]);
            core::ptr::addr_of_mut!((*destination).pin_generations).write([0; MAP_PINS]);
            core::ptr::addr_of_mut!((*destination).jobs).write(AtomicU32::new(0));
            core::ptr::addr_of_mut!((*destination).allocation_limit).write(Self::FDS as u32);
        }
    }

    fn job_gone(&self) {
        let value = self.jobs.load(Ordering::Relaxed);
        self.jobs.store(value.wrapping_add(1), Ordering::Release);
    }

    /// The places of jobs in use: Open, Scalar and Control records. Each
    /// stands for one job of the session in the service from before its
    /// first request until the operation has let it go.
    pub fn jobs_in_use(&self) -> usize {
        self.residents
            .iter()
            .filter(|slot| {
                matches!(
                    slot.held,
                    Held::Open(_) | Held::Scalar(_) | Held::Control(_)
                )
            })
            .count()
    }

    /// The places that records owned by `owner` take: the operations of one
    /// thread that are still in flight, those it left by a jump included.
    pub fn jobs_owned_by(&self, owner: OwnerToken) -> usize {
        self.residents
            .iter()
            .filter(|slot| match slot.held {
                Held::Open(record) => record.owner == Some(owner),
                Held::Scalar(record) => record.owner() == Some(owner),
                Held::Control(record) => record.owner() == Some(owner),
                _ => false,
            })
            .count()
    }

    /// Whether `owner` may take a place for a new job now. The check and the
    /// `begin_*` that follows it run under the same lock of the caller.
    /// The resident job count is independent of ordinary I/O holds.
    pub fn job_place(&self, owner: OwnerToken) -> JobPlace {
        let used = self.jobs_in_use();
        if used < JOBS_MAX {
            return JobPlace::Free;
        }
        JobPlace::Full {
            sequence: self.jobs.load(Ordering::Acquire),
            own: used >= JOBS_MAX && self.jobs_owned_by(owner) >= used,
        }
    }

    /// The word of the places of jobs. The address stays through the life of
    /// the table, which the caller pins while a thread waits on it.
    pub fn jobs_wait_word(&self) -> &AtomicU32 {
        &self.jobs
    }

    /// The record of number `fd`, in the table or in its page; None when the
    /// number is out of range or its page is not there.
    #[inline(always)]
    fn slot(&self, fd: u32) -> Option<&EntrySlot<T>> {
        let fd = fd as usize;
        if fd < N {
            return self.entries.get(fd);
        }
        let page = (*self.pages.get(fd / N - 1)?)?;
        // SAFETY: a page given to `add_page` stays mapped and is the table's
        // alone until the table is gone.
        Some(unsafe { &page.as_ref().slots[fd % N] })
    }

    #[inline(always)]
    fn slot_mut(&mut self, fd: u32) -> Option<&mut EntrySlot<T>> {
        let fd = fd as usize;
        if fd < N {
            return self.entries.get_mut(fd);
        }
        let mut page = (*self.pages.get(fd / N - 1)?)?;
        // SAFETY: as in `slot`; `&mut self` makes the access exclusive.
        Some(unsafe { &mut page.as_mut().slots[fd % N] })
    }

    /// `Error::NeedPage` when `fd` is a number of the table whose page is not
    /// there yet.
    #[inline(always)]
    fn need_page(&self, fd: u32) -> Result<(), Error> {
        if (fd as usize) < Self::FDS && self.slot(fd).is_none() {
            return Err(Error::NeedPage(fd as usize / N - 1));
        }
        Ok(())
    }

    /// Writes the state of `fd` and keeps the bitmap of the numbers in use:
    /// the number is in use unless it is empty.
    #[inline(always)]
    fn set_state(&mut self, fd: u32, state: EntryState<T>) {
        let empty = matches!(state, EntryState::Empty);
        self.slot_mut(fd)
            .expect("the page of the number is there")
            .state = state;
        let (word, bit) = (fd as usize / 64, fd % 64);
        if empty {
            self.occupied[word] &= !(1 << bit);
        } else {
            self.occupied[word] |= 1 << bit;
        }
    }

    /// The page of entries that the number `fd` lies in when the table does
    /// not have it yet; None when the number is in place, its page is there,
    /// or no page could hold it.
    pub fn missing_page(&self, fd: u32) -> Option<usize> {
        match self.need_page(fd) {
            Err(Error::NeedPage(k)) => Some(k),
            _ => None,
        }
    }

    /// The lowest number at or above `from` that is in use (open, being
    /// opened or being closed), a word of the bitmap at a time.
    pub fn next_used(&self, from: u32) -> Option<u32> {
        let mut word = from as usize / 64;
        let mut bits = self
            .occupied
            .get(word)
            .map(|w| w & (!0u64 << (from % 64)))?;
        loop {
            if bits != 0 {
                return Some(word as u32 * 64 + bits.trailing_zeros());
            }
            word += 1;
            bits = *self.occupied.get(word)?;
        }
    }

    /// The numbers in use (not empty), from the lowest.
    fn used(&self) -> impl Iterator<Item = u32> + '_ {
        self.occupied.iter().enumerate().flat_map(|(w, &word)| {
            let mut left = word;
            core::iter::from_fn(move || {
                if left == 0 {
                    return None;
                }
                let bit = left.trailing_zeros();
                left &= left - 1;
                Some(w as u32 * 64 + bit)
            })
        })
    }

    /// Whether a number holds `backend` in an open entry.
    #[inline(always)]
    fn references_by_number(&self, backend: T) -> bool {
        for (word, &bits) in self.occupied.iter().enumerate() {
            let mut left = bits;
            while left != 0 {
                let fd = word as u32 * 64 + left.trailing_zeros();
                left &= left - 1;
                if matches!(self.slot(fd).map(|s| s.state), Some(EntryState::Open(e)) if e.backend == backend)
                {
                    return true;
                }
            }
        }
        false
    }

    /// Gives the table the page `k` (the number `N * (k + 1)` and the `N - 1`
    /// after it): `memory` is written with `N` empty records of generation 0.
    /// Returns false, with `memory` untouched, when the table has the page
    /// already; the caller then frees its own. A page stays until the table is
    /// gone, so that no number's generation starts again.
    ///
    /// # Safety
    /// `memory` is aligned for `EntryPage<T, N>`, writable for its size, and
    /// stays mapped, used by nothing else, for the life of the table.
    pub unsafe fn add_page(&mut self, k: usize, memory: NonNull<EntryPage<T, N>>) -> bool {
        let Some(place) = self.pages.get_mut(k) else {
            return false;
        };
        if place.is_some() {
            return false;
        }
        // SAFETY: the caller's guarantee covers the write of N records.
        unsafe {
            memory.as_ptr().write(EntryPage {
                slots: [EntrySlot {
                    generation: 0,
                    state: EntryState::Empty,
                }; N],
            });
        }
        *place = Some(memory);
        true
    }

    /// Whether the page `k` is there.
    pub fn has_page(&self, k: usize) -> bool {
        self.pages.get(k).is_some_and(|p| p.is_some())
    }

    #[inline(always)]
    fn entry(&self, fd: u32) -> Result<Entry<T>, Error> {
        match self.slot(fd).map(|slot| slot.state) {
            Some(EntryState::Open(entry)) => Ok(entry),
            _ => Err(Error::BadFileDescriptor),
        }
    }

    #[inline(always)]
    pub fn get(&self, fd: u32) -> Result<T, Error> {
        Ok(self.entry(fd)?.backend)
    }

    pub fn flags(&self, fd: u32) -> Result<Flags, Error> {
        Ok(self.entry(fd)?.flags)
    }

    pub fn set_flags(&mut self, fd: u32, flags: Flags) -> Result<(), Error> {
        let backend = self.get(fd)?;
        self.set_state(fd, EntryState::Open(Entry { backend, flags }));
        Ok(())
    }

    pub fn entry_token(&self, fd: u32) -> Result<EntryToken, Error> {
        self.entry(fd)?;
        let generation = self.slot(fd).ok_or(Error::BadFileDescriptor)?.generation;
        Ok(EntryToken::new(fd, generation))
    }

    /// Published descriptors form the fork and exec snapshot.
    pub fn open(&self) -> impl Iterator<Item = (u32, T, Flags)> + '_ {
        self.used().filter_map(|fd| match self.slot(fd)?.state {
            EntryState::Open(e) => Some((fd, e.backend, e.flags)),
            _ => None,
        })
    }

    /// Existing descriptors and already reserved Opens retain their custody.
    pub fn set_allocation_limit(&mut self, limit: u64) {
        self.allocation_limit = limit.min(Self::FDS as u64) as u32;
    }

    #[inline(always)]
    pub fn vacant(&self, minimum: u32) -> Result<u32, Error> {
        if minimum as usize >= Self::FDS || minimum >= self.allocation_limit {
            return Err(Error::InvalidArgument);
        }
        // The first zero of the bitmap at or above `minimum` and below the
        // limit, a word at a time.
        let limit = self.allocation_limit;
        let mut fd = minimum;
        while fd < limit {
            let (word, bit) = (fd as usize / 64, fd % 64);
            let free = !self.occupied[word] >> bit << bit;
            if free != 0 {
                let found = word as u32 * 64 + free.trailing_zeros();
                if found >= limit {
                    break;
                }
                self.need_page(found)?;
                return Ok(found);
            }
            fd = (word as u32 + 1) * 64;
        }
        Err(Error::TooManyOpenFiles)
    }

    #[inline(always)]
    fn install(&mut self, fd: u32, backend: T, flags: Flags) -> Result<(), Error> {
        let Some(slot) = self.slot_mut(fd) else {
            self.need_page(fd)?;
            return Err(Error::BadFileDescriptor);
        };
        let generation = slot.generation.checked_add(1).ok_or(Error::Io)?;
        slot.generation = generation;
        slot.state = EntryState::Open(Entry { backend, flags });
        self.occupied[fd as usize / 64] |= 1 << (fd % 64);
        Ok(())
    }

    pub fn insert(&mut self, backend: T, flags: Flags) -> Result<u32, Error> {
        self.insert_at_free(backend, 0, flags)
    }

    pub fn duplicate(&mut self, fd: u32, minimum: u32, flags: Flags) -> Result<u32, Error> {
        let backend = self.get(fd)?;
        if minimum >= self.allocation_limit {
            return Err(Error::InvalidArgument);
        }
        self.insert_at_free(backend, minimum, flags)
    }

    fn insert_at_free(&mut self, backend: T, minimum: u32, flags: Flags) -> Result<u32, Error> {
        if minimum == 0 && self.allocation_limit == 0 {
            return Err(Error::TooManyOpenFiles);
        }
        let fd = self.vacant(minimum)?;
        self.install(fd, backend, flags)?;
        Ok(fd)
    }

    /// Whether another open descriptor names what `fd` names.
    #[inline(always)]
    pub fn has_open_alias(&self, fd: u32) -> bool {
        let Ok(backend) = self.get(fd) else {
            return false;
        };
        for (word, &bits) in self.occupied.iter().enumerate() {
            let mut left = bits;
            while left != 0 {
                let number = word as u32 * 64 + left.trailing_zeros();
                left &= left - 1;
                if number != fd
                    && matches!(self.slot(number).map(|s| s.state), Some(EntryState::Open(e)) if e.backend == backend)
                {
                    return true;
                }
            }
        }
        false
    }

    fn referenced(&self, backend: T) -> bool {
        self.references_by_number(backend)
            || self.pinned_backend(backend)
            || self.closing_references(backend, true)
    }

    /// Whether a pin keeps `backend`.
    pub(crate) fn pinned_backend(&self, backend: T) -> bool {
        self.pins
            .iter()
            .flatten()
            .any(|slot| slot.backend == backend)
    }

    /// A reference to a pin of the shared mapping of the file `key`, kept
    /// without a number: the live pin of the file when it serves (it
    /// writes if `writes` asks for that), else a new pin of the description
    /// `fd` names, which stays alive after every number of it closed. Each
    /// call counts one reference; `release_pin` gives it back. The flag
    /// says that the pin is new. TooManyOpenFiles when all `MAP_PINS`
    /// places are taken.
    pub fn pin_or_retain(
        &mut self,
        fd: u32,
        key: u64,
        writes: bool,
    ) -> Result<(PinRef, bool), Error> {
        let found = self.pins.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|slot| slot.key == key && (slot.writes || !writes))
        });
        if let Some(place) = found {
            let slot = self.pins[place].as_mut().expect("a live pin");
            slot.refs = slot.refs.checked_add(1).ok_or(Error::TooManyOpenFiles)?;
            return Ok((self.pin_ref(place), false));
        }
        let backend = self.get(fd)?;
        let place = self
            .pins
            .iter()
            .position(Option::is_none)
            .ok_or(Error::TooManyOpenFiles)?;
        self.pin_generations[place] = self.pin_generations[place]
            .checked_add(1)
            .ok_or(Error::Io)?;
        self.pins[place] = Some(PinSlot {
            backend,
            key,
            writes,
            refs: 1,
        });
        Ok((self.pin_ref(place), true))
    }

    fn pin_ref(&self, place: usize) -> PinRef {
        PinRef {
            place,
            generation: self.pin_generations[place],
        }
    }

    fn pin_slot(&self, pin: PinRef) -> Option<&PinSlot<T>> {
        let slot = self.pins.get(pin.place)?.as_ref()?;
        (self.pin_generations[pin.place] == pin.generation).then_some(slot)
    }

    /// What the pin keeps; BadFileDescriptor for a pin that went.
    pub fn pinned(&self, pin: PinRef) -> Result<T, Error> {
        self.pin_slot(pin)
            .map(|slot| slot.backend)
            .ok_or(Error::BadFileDescriptor)
    }

    /// The descriptions the pins keep, for a child of `fork`.
    pub fn pinned_all(&self) -> impl Iterator<Item = T> + '_ {
        self.pins.iter().flatten().map(|slot| slot.backend)
    }

    /// Gives back one reference of the pin: the description to release,
    /// when it was the last and nothing else keeps the description. A
    /// reference to a pin that went does nothing.
    pub fn release_pin(&mut self, pin: PinRef) -> Option<T> {
        self.pin_slot(pin)?;
        let slot = self.pins[pin.place].as_mut()?;
        slot.refs -= 1;
        if slot.refs > 0 {
            return None;
        }
        let backend = slot.backend;
        self.pins[pin.place] = None;
        self.left(backend)
    }

    fn left(&mut self, backend: T) -> Option<T> {
        if self.referenced(backend) || self.scalar_pinned(backend) || self.io_pinned(backend) {
            return None;
        }
        let hold = self.holds.iter_mut().find_map(|slot| match &mut slot.held {
            Held::Io(h) if h.backend == backend => Some(h),
            _ => None,
        });
        match hold {
            Some(hold) => {
                hold.closed = true;
                if (self.release_early)(backend) {
                    hold.released = true;
                    Some(backend)
                } else {
                    None
                }
            }
            None => Some(backend),
        }
    }

    pub fn hold(&mut self, fd: u32) -> Result<T, Error> {
        let backend = self.get(fd)?;
        self.hold_backend(backend)
    }

    /// As `hold` for the description a pin keeps.
    pub fn hold_pin(&mut self, pin: PinRef) -> Result<T, Error> {
        let backend = self.pinned(pin)?;
        self.hold_backend(backend)
    }

    fn hold_backend(&mut self, backend: T) -> Result<T, Error> {
        if let Some(hold) = self.holds.iter_mut().find_map(|slot| match &mut slot.held {
            Held::Io(h) if h.backend == backend => Some(h),
            _ => None,
        }) {
            hold.count = hold.count.checked_add(1).ok_or(Error::TooManyOpenFiles)?;
            return Ok(backend);
        }
        let free = self
            .holds
            .iter_mut()
            .find(|slot| matches!(slot.held, Held::Empty))
            .ok_or(Error::TooManyOpenFiles)?;
        free.held = Held::Io(Hold {
            backend,
            count: 1,
            closed: false,
            released: false,
        });
        Ok(backend)
    }

    /// Read the exact ordinary I/O loan without changing its custody.
    /// At most the existing bounded I/O hold array is inspected.
    pub fn io_loan_state(&self, backend: T) -> Option<(u16, bool, bool)> {
        self.holds.iter().find_map(|slot| match &slot.held {
            Held::Io(hold) if hold.backend == backend => {
                Some((hold.count, hold.closed, hold.released))
            }
            _ => None,
        })
    }

    pub fn unhold(&mut self, backend: T) -> Option<T> {
        let slot = self
            .holds
            .iter_mut()
            .find(|slot| matches!(slot.held, Held::Io(h) if h.backend == backend))?;
        let Held::Io(hold) = &mut slot.held else {
            unreachable!()
        };
        hold.count -= 1;
        if hold.count > 0 {
            return None;
        }
        let closed = hold.closed && !hold.released;
        slot.held = Held::Empty;
        self.job_gone();
        (closed
            && !self.referenced(backend)
            && !self.scalar_pinned(backend)
            && !self.io_pinned(backend))
        .then_some(backend)
    }

    /// Discard abandoned ordinary I/O holds one release at a time.
    pub fn abandon_hold(&mut self) -> Option<T> {
        while let Some(slot) = self
            .holds
            .iter_mut()
            .find(|slot| matches!(slot.held, Held::Io(_)))
        {
            let Held::Io(hold) = slot.held else {
                unreachable!()
            };
            slot.held = Held::Empty;
            self.job_gone();
            if hold.closed
                && !hold.released
                && !self.referenced(hold.backend)
                && !self.scalar_pinned(hold.backend)
                && !self.io_pinned(hold.backend)
            {
                return Some(hold.backend);
            }
        }
        None
    }

    pub fn close(&mut self, fd: u32) -> Result<Option<T>, Error> {
        let backend = self.get(fd)?;
        self.set_state(fd, EntryState::Empty);
        Ok(self.left(backend))
    }

    /// Close an unreturned result only while its original entry lifetime lives.
    pub fn close_exact(&mut self, entry: EntryToken) -> Option<T> {
        if self.entry_token(entry.fd) != Ok(entry) {
            return None;
        }
        self.close(entry.fd).ok().flatten()
    }

    pub fn pending(&self, fd: u32) -> Option<OpenToken> {
        let EntryState::Pending(slot) = self.slot(fd)?.state else {
            return None;
        };
        let held = self.residents.get(slot)?;
        matches!(held.held, Held::Open(_)).then_some(OpenToken {
            slot,
            generation: held.generation,
        })
    }

    pub fn try_dup2(&mut self, source: u32, target: u32) -> Result<Replacement<T>, Error> {
        self.replace(source, target, Flags::default(), true)
    }

    pub fn try_dup3(
        &mut self,
        source: u32,
        target: u32,
        flags: Flags,
    ) -> Result<Replacement<T>, Error> {
        self.replace(source, target, flags, false)
    }

    /// Tuple interface for callers whose tables contain ordinary descriptors.
    /// Reservation-aware callers use `try_dup2` and `try_dup3`.
    pub fn dup2(&mut self, source: u32, target: u32) -> Result<(u32, Option<T>), Error> {
        Self::ordinary_replacement(self.try_dup2(source, target)?)
    }

    pub fn dup3(
        &mut self,
        source: u32,
        target: u32,
        flags: Flags,
    ) -> Result<(u32, Option<T>), Error> {
        Self::ordinary_replacement(self.try_dup3(source, target, flags)?)
    }

    fn ordinary_replacement(result: Replacement<T>) -> Result<(u32, Option<T>), Error> {
        match result {
            Replacement::Complete { fd, release } => Ok((fd, release)),
            Replacement::Pending(_) => Err(Error::Io),
        }
    }

    fn replace(
        &mut self,
        source: u32,
        target: u32,
        flags: Flags,
        allow_same: bool,
    ) -> Result<Replacement<T>, Error> {
        let backend = self.get(source)?;
        if target as usize >= Self::FDS {
            return Err(Error::BadFileDescriptor);
        }
        if source == target {
            return if allow_same {
                Ok(Replacement::Complete {
                    fd: target,
                    release: None,
                })
            } else {
                Err(Error::InvalidArgument)
            };
        }
        if target >= self.allocation_limit {
            return Err(Error::BadFileDescriptor);
        }
        if let Some(token) = self.pending(target) {
            return Ok(Replacement::Pending(token));
        }
        if self.closing(target).is_some() {
            return Err(Error::Io);
        }
        let old = self.entry(target).ok();
        // A page that is not there yet is asked for before any change.
        self.need_page(target)?;
        self.install(target, backend, flags)?;
        let release = old
            .filter(|old| old.backend != backend)
            .and_then(|old| self.left(old.backend));
        Ok(Replacement::Complete {
            fd: target,
            release,
        })
    }

    pub fn place(&mut self, fd: u32, backend: T, flags: Flags) -> Result<(), Error> {
        if fd as usize >= Self::FDS {
            return Err(Error::BadFileDescriptor);
        }
        self.need_page(fd)?;
        let slot = self.slot(fd).ok_or(Error::BadFileDescriptor)?;
        if !matches!(slot.state, EntryState::Empty) {
            return Err(Error::BadFileDescriptor);
        }
        self.install(fd, backend, flags)
    }

    fn record(&self, token: OpenToken) -> Result<OpenRecord<T, R>, Error> {
        let slot = self
            .residents
            .get(token.slot)
            .ok_or(Error::BadFileDescriptor)?;
        if slot.generation != token.generation {
            return Err(Error::BadFileDescriptor);
        }
        match slot.held {
            Held::Open(record) => Ok(record),
            _ => Err(Error::BadFileDescriptor),
        }
    }

    fn claimed(&self, token: ClaimToken) -> Result<OpenRecord<T, R>, Error> {
        let record = self.record(token.open)?;
        if record.claimant.is_none() || record.serial != token.serial {
            return Err(Error::BadFileDescriptor);
        }
        Ok(record)
    }

    fn save(&mut self, token: OpenToken, record: OpenRecord<T, R>) {
        let slot = &mut self.residents[token.slot];
        slot.held = Held::Open(record);
        slot.change();
    }

    fn free_open(&mut self, token: OpenToken) {
        let slot = &mut self.residents[token.slot];
        slot.held = Held::Empty;
        slot.change();
        self.job_gone();
    }

    /// Pay a resident record before Prepare or any irreversible effect.
    pub fn begin_open(
        &mut self,
        owner: OwnerToken,
        recovery: R,
    ) -> Result<(OpenToken, ClaimToken), Error> {
        let (index, slot) = self
            .residents
            .iter_mut()
            .take(N.min(JOBS_MAX))
            .enumerate()
            .find(|(_, slot)| {
                matches!(slot.held, Held::Empty)
                    && slot.generation < u64::MAX
                    && slot.changed.load(Ordering::Relaxed) < u32::MAX
            })
            .ok_or(Error::TooManyOpenFiles)?;
        slot.generation += 1;
        let open = OpenToken {
            slot: index,
            generation: slot.generation,
        };
        let claim = ClaimToken { open, serial: 1 };
        slot.held = Held::Open(OpenRecord {
            owner: Some(owner),
            claimant: Some(owner),
            serial: 1,
            phase: Phase::Preparing(recovery),
        });
        slot.change();
        Ok((open, claim))
    }

    pub fn open_snapshot(&self, token: OpenToken) -> Result<OpenSnapshot<R>, Error> {
        Ok(self.record(token)?.snapshot())
    }

    pub fn open_tokens(&self) -> impl Iterator<Item = OpenToken> + '_ {
        self.residents.iter().enumerate().filter_map(|(slot, h)| {
            matches!(h.held, Held::Open(_)).then_some(OpenToken {
                slot,
                generation: h.generation,
            })
        })
    }

    pub fn claim_open(&mut self, token: OpenToken, helper: OwnerToken) -> Result<Claim<R>, Error> {
        let mut record = self.record(token)?;
        if let Some(completion) = record.snapshot().completion {
            return Ok(Claim::Complete(completion));
        }
        if matches!(record.phase, Phase::Canceling { .. }) {
            return Ok(Claim::Canceling(record.snapshot()));
        }
        if let Some(owner) = record.claimant {
            return Ok(Claim::Busy(owner));
        }
        let Some(serial) = record
            .serial
            .checked_add(1)
            .filter(|serial| *serial < u64::MAX)
        else {
            record.serial = u64::MAX;
            record.cancel();
            self.save(token, record);
            return Ok(Claim::Canceling(record.snapshot()));
        };
        record.serial = serial;
        record.claimant = Some(helper);
        self.save(token, record);
        Ok(Claim::Acquired {
            token: ClaimToken {
                open: token,
                serial,
            },
            snapshot: record.snapshot(),
        })
    }

    pub fn release_claim(&mut self, claim: ClaimToken) -> Result<(), Error> {
        let mut record = self.claimed(claim)?;
        record.claimant = None;
        if record.serial == u64::MAX {
            record.cancel();
        }
        self.save(claim.open, record);
        Ok(())
    }

    /// Inspect one current claim without advancing the resident wait sequence.
    pub fn claim_snapshot(&self, claim: ClaimToken) -> Result<OpenSnapshot<R>, Error> {
        Ok(self.claimed(claim)?.snapshot())
    }

    pub fn update_open(&mut self, claim: ClaimToken, recovery: R) -> Result<(), Error> {
        let mut record = self.claimed(claim)?;
        record.phase = match record.phase {
            Phase::Preparing(_) => Phase::Preparing(recovery),
            Phase::Reserved { entry, flags, .. } => Phase::Reserved {
                recovery,
                entry,
                flags,
            },
            Phase::Committed {
                entry,
                flags,
                backend,
                ..
            } => Phase::Committed {
                recovery,
                entry,
                flags,
                backend,
            },
            _ => return Err(Error::BadFileDescriptor),
        };
        self.save(claim.open, record);
        Ok(())
    }

    /// Extract a local capability only from an exact cancellation record.
    /// The caller releases its table guard before closing the extracted handle.
    pub fn update_open_cleanup<V>(
        &mut self,
        token: OpenToken,
        update: impl FnOnce(&mut R) -> V,
    ) -> Result<V, Error> {
        let mut record = self.record(token)?;
        let Phase::Canceling {
            ref mut recovery, ..
        } = record.phase
        else {
            return Err(Error::InvalidArgument);
        };
        let value = update(recovery);
        self.save(token, record);
        Ok(value)
    }

    /// Reserve after fallible preparation. Installation reuses this generation.
    pub fn reserve_open(
        &mut self,
        claim: ClaimToken,
        minimum: u32,
        flags: Flags,
    ) -> Result<EntryToken, Error> {
        let mut record = self.claimed(claim)?;
        let Phase::Preparing(recovery) = record.phase else {
            return Err(Error::InvalidArgument);
        };
        if minimum == 0 && self.allocation_limit == 0 {
            return Err(Error::TooManyOpenFiles);
        }
        let fd = self.vacant(minimum)?;
        let slot = self.slot_mut(fd).ok_or(Error::BadFileDescriptor)?;
        let generation = slot.generation.checked_add(1).ok_or(Error::Io)?;
        let entry = EntryToken::new(fd, generation);
        slot.generation = generation;
        self.set_state(fd, EntryState::Pending(claim.open.slot));
        record.phase = Phase::Reserved {
            recovery,
            entry,
            flags,
        };
        self.save(claim.open, record);
        Ok(entry)
    }

    /// Return an exact reservation to preparation after a proven remote no-effect result.
    /// The caller validates that result and supplies its next recovery state under the same lock.
    /// This revokes the final-phase claim and preserves the numeric entry generation.
    pub fn unreserve_open(
        &mut self,
        claim: ClaimToken,
        expected: EntryToken,
        recovery: R,
    ) -> Result<EntryToken, Error> {
        let mut record = self.claimed(claim)?;
        if record.owner.is_none() {
            return Err(Error::InvalidArgument);
        }
        let Phase::Reserved { entry, .. } = record.phase else {
            return Err(Error::InvalidArgument);
        };
        if entry != expected || !self.reserved(claim.open, entry) {
            return Err(Error::Io);
        }
        self.set_state(entry.fd, EntryState::Empty);
        record.phase = Phase::Preparing(recovery);
        record.claimant = None;
        self.save(claim.open, record);
        Ok(entry)
    }

    pub fn stage_committed(&mut self, claim: ClaimToken, backend: T) -> Result<(), Error> {
        let mut record = self.claimed(claim)?;
        let Phase::Reserved {
            recovery,
            entry,
            flags,
        } = record.phase
        else {
            return Err(Error::InvalidArgument);
        };
        record.phase = Phase::Committed {
            recovery,
            entry,
            flags,
            backend,
        };
        self.save(claim.open, record);
        Ok(())
    }

    fn reserved(&self, token: OpenToken, entry: EntryToken) -> bool {
        self.slot(entry.fd).is_some_and(|slot| {
            slot.generation == entry.generation()
                && matches!(slot.state, EntryState::Pending(h) if h == token.slot)
        })
    }

    /// Install a prepaid backend once. Completion survives fd close and reuse.
    pub fn publish_open(&mut self, claim: ClaimToken) -> Result<EntryToken, Error> {
        let mut record = self.claimed(claim)?;
        if record.owner.is_none() {
            return Err(Error::InvalidArgument);
        }
        let Phase::Committed {
            entry,
            flags,
            backend,
            ..
        } = record.phase
        else {
            return Err(Error::InvalidArgument);
        };
        if !self.reserved(claim.open, entry) {
            return Err(Error::Io);
        }
        self.set_state(entry.fd, EntryState::Open(Entry { backend, flags }));
        record.phase = Phase::Published(entry);
        record.claimant = None;
        self.save(claim.open, record);
        Ok(entry)
    }

    /// The original caller copies this saved result before leaving its defer.
    pub fn ack_open(&mut self, token: OpenToken, owner: OwnerToken) -> Result<Completion, Error> {
        let record = self.record(token)?;
        if record.owner != Some(owner) {
            return Err(Error::BadFileDescriptor);
        }
        let completion = record.snapshot().completion.ok_or(Error::InvalidArgument)?;
        self.free_open(token);
        Ok(completion)
    }

    /// Canonical cancellation uses the exact backend operation in recovery.
    /// The transition revokes all late stage and publication authority.
    pub fn begin_cancel(&mut self, claim: ClaimToken) -> Result<OpenSnapshot<R>, Error> {
        let mut record = self.claimed(claim)?;
        record.cancel();
        self.save(claim.open, record);
        Ok(record.snapshot())
    }

    /// Complete an idempotent exact cancellation after its remote confirmation.
    /// The returned value is a staged snapshot. The canonical remote outcome
    /// establishes whether a backend reference remains owned. The caller
    /// releases only a separately proven, still-owned reference.
    pub fn finish_cancel(&mut self, token: OpenToken, errno: i32) -> Result<Option<T>, Error> {
        if errno <= 0 {
            return Err(Error::InvalidArgument);
        }
        let mut record = self.record(token)?;
        let Phase::Canceling { entry, backend, .. } = record.phase else {
            return Err(Error::BadFileDescriptor);
        };
        if let Some(entry) = entry {
            if !self.reserved(token, entry) {
                return Err(Error::Io);
            }
            self.set_state(entry.fd, EntryState::Empty);
        }
        if record.owner.is_none() {
            self.free_open(token);
        } else {
            record.phase = Phase::Failed(errno);
            self.save(token, record);
        }
        Ok(backend)
    }

    /// Discard a completion or detach an unresolved operation for recovery.
    /// The caller proves that the owner's execution has ended or been revoked.
    pub fn abandon_open(&mut self, token: OpenToken) -> Result<Abandoned<T, R>, Error> {
        let mut record = self.record(token)?;
        match record.phase {
            Phase::Published(entry) => {
                let release = self.close_exact(entry);
                self.free_open(token);
                Ok(Abandoned::Discarded { token, release })
            }
            Phase::Failed(_) => {
                self.free_open(token);
                Ok(Abandoned::Discarded {
                    token,
                    release: None,
                })
            }
            _ => {
                record.owner = None;
                record.claimant = None;
                if record.serial == u64::MAX {
                    record.cancel();
                }
                self.save(token, record);
                Ok(Abandoned::Recover {
                    token,
                    snapshot: record.snapshot(),
                })
            }
        }
    }

    /// Preserve last-reference cleanup of a Published, unreturned Open in
    /// its prepaid record. The caller preflights exact remote authority in R.
    /// Other phases retain their existing recovery payload. Ordinary alias
    /// and I/O hold release semantics remain those of abandon_open.
    pub fn abandon_open_with_recovery(
        &mut self,
        token: OpenToken,
        recovery: R,
    ) -> Result<Abandoned<T, R>, Error> {
        let mut record = self.record(token)?;
        let Phase::Published(entry) = record.phase else {
            return self.abandon_open(token);
        };
        let io_held = self.get(entry.fd).ok().is_some_and(|backend| {
            self.holds
                .iter()
                .any(|slot| matches!(slot.held, Held::Io(h) if h.backend == backend))
        });
        let release = self.close_exact(entry);
        if let Some(backend) = release.filter(|_| !io_held) {
            record.owner = None;
            record.claimant = None;
            record.phase = Phase::Canceling {
                recovery,
                entry: None,
                backend: Some(backend),
            };
            self.save(token, record);
            return Ok(Abandoned::Recover {
                token,
                snapshot: record.snapshot(),
            });
        }
        self.free_open(token);
        Ok(Abandoned::Discarded { token, release })
    }

    /// Detach one original owner or helper claim per call, before slot reuse.
    pub fn abandon_owner(&mut self, owner: OwnerToken) -> Option<Abandoned<T, R>> {
        let (slot, record) =
            self.residents
                .iter()
                .enumerate()
                .find_map(|(slot, h)| match h.held {
                    Held::Open(record)
                        if record.owner == Some(owner) || record.claimant == Some(owner) =>
                    {
                        Some((slot, record))
                    }
                    _ => None,
                })?;
        let token = OpenToken {
            slot,
            generation: self.residents[slot].generation,
        };
        if record.owner == Some(owner) {
            return self.abandon_open(token).ok();
        }
        let mut record = record;
        record.claimant = None;
        if record.serial == u64::MAX {
            record.cancel();
        }
        self.save(token, record);
        Some(Abandoned::ClaimReleased(token))
    }

    /// The fork child drops inherited Open/Scalar/Control/Io/Disposal recovery locally.
    /// Published fd references survive. The parent owns every unresolved job.
    /// The caller establishes child-exclusive access before this operation.
    pub fn discard_open_after_fork(&mut self) {
        for word in 0..OCCUPIED_WORDS {
            let mut left = self.occupied[word];
            while left != 0 {
                let fd = word as u32 * 64 + left.trailing_zeros();
                left &= left - 1;
                if matches!(
                    self.slot(fd).map(|s| s.state),
                    Some(EntryState::Pending(_) | EntryState::Closing(_))
                ) {
                    self.set_state(fd, EntryState::Empty);
                }
            }
        }
        for slot in self.holds.iter_mut().chain(self.residents.iter_mut()) {
            if matches!(
                slot.held,
                Held::Open(_)
                    | Held::Scalar(_)
                    | Held::Control(_)
                    | Held::RecoverableIo(_)
                    | Held::Disposal(_)
            ) {
                slot.held = Held::Empty;
                slot.change();
            }
        }
        for slot in &mut self.closings {
            slot.record = None;
            let value = slot.changed.load(Ordering::Relaxed);
            slot.changed
                .store(value.saturating_add(1), Ordering::Release);
        }
        self.job_gone();
    }

    /// This address remains stable through slot reuse. The caller pins Table.
    /// Wake occurs after unlocking; every waiter then revalidates its token.
    pub fn wait_word(&self, token: OpenToken) -> Result<&AtomicU32, Error> {
        self.residents
            .get(token.slot)
            .map(|slot| &slot.changed)
            .ok_or(Error::BadFileDescriptor)
    }

    pub fn wait_snapshot(&self, token: OpenToken) -> Result<WaitValue, Error> {
        self.record(token)?;
        let sequence = self.residents[token.slot].changed.load(Ordering::Acquire);
        Ok(if sequence == u32::MAX {
            WaitValue::NeverSleep
        } else {
            WaitValue::Sequence(sequence)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thirty_two_waiting_reads_leave_all_open_and_scalar_places_available() {
        type Big = Table<u32, 32, u64, u64, u64>;
        for scalar in [false, true] {
            let mut table = Big::default();
            for index in 0..32 {
                let fd = table.insert(100 + index, Flags::default()).unwrap();
                assert_eq!(table.hold(fd), Ok(100 + index));
            }
            for index in 0..JOBS_MAX {
                assert_eq!(table.job_place(owner(1)), JobPlace::Free);
                let key = if scalar {
                    table
                        .begin_scalar(owner(1), 0, index as u64)
                        .unwrap()
                        .0
                        .slot()
                } else {
                    table.begin_open(owner(1), index as u64).unwrap().0.slot()
                };
                assert_eq!(key, 32 + index);
                assert_eq!(table.jobs_in_use(), index + 1);
            }
            assert!(matches!(
                table.job_place(owner(2)),
                JobPlace::Full { own: false, .. }
            ));
            assert_eq!(table.begin_open(owner(2), 99), Err(Error::TooManyOpenFiles));
            assert_eq!(
                table.begin_scalar(owner(2), 0, 99),
                Err(Error::TooManyOpenFiles)
            );
            for fd in 0..32 {
                assert_eq!(table.get(fd), Ok(100 + fd));
            }
        }
    }

    #[test]
    fn last_fd_releases_early_once_while_generation_hold_survives() {
        let mut table = Table::<u32, 4>::with_early_release(|backend| backend >= 100);
        let fd = table.insert(100, Flags::default()).unwrap();
        let copy = table.duplicate(fd, 0, Flags::default()).unwrap();
        assert_eq!(table.hold(fd), Ok(100));
        assert_eq!(table.close(fd), Ok(None));
        assert_eq!(table.close(copy), Ok(Some(100)));
        let fresh = table.insert(101, Flags::default()).unwrap();
        assert_eq!(fresh, fd);
        assert_eq!(table.unhold(100), None);
        assert_eq!(table.get(fresh), Ok(101));
        assert_eq!(table.close(fresh), Ok(Some(101)));
        let ram = table.insert(7, Flags::default()).unwrap();
        table.hold(ram).unwrap();
        assert_eq!(table.close(ram), Ok(None));
        assert_eq!(table.unhold(7), Some(7));
    }

    #[test]
    fn a_pin_keeps_a_description_without_a_number() {
        let mut table = Table::<u32, 4>::default();
        let fd = table.insert(7, Flags::default()).unwrap();
        let (pin, new) = table.pin_or_retain(fd, 500, false).unwrap();
        assert!(new);
        // The number goes, the pin keeps the description alive.
        assert_eq!(table.close(fd), Ok(None));
        assert_eq!(table.pinned(pin), Ok(7));
        assert_eq!(table.insert(8, Flags::default()), Ok(fd));
        assert_eq!(table.pinned_all().next(), Some(7));
        // A request holds it while the pin goes: the release waits for it.
        assert_eq!(table.hold_pin(pin), Ok(7));
        assert_eq!(table.release_pin(pin), None);
        assert_eq!(table.pinned(pin), Err(Error::BadFileDescriptor));
        assert_eq!(table.unhold(7), Some(7));
        // Without a hold, the last reference returns the description.
        let again = table.insert(9, Flags::default()).unwrap();
        let (pin, _) = table.pin_or_retain(again, 501, false).unwrap();
        assert_eq!(table.release_pin(pin), None);
        let (pin, _) = table.pin_or_retain(again, 501, false).unwrap();
        assert_eq!(table.close(again), Ok(None));
        assert_eq!(table.release_pin(pin), Some(9));
    }

    #[test]
    fn a_pin_counts_the_mappings_that_hold_it() {
        let mut table = Table::<u32, 4>::default();
        let fd = table.insert(7, Flags::default()).unwrap();
        let (first, new) = table.pin_or_retain(fd, 500, true).unwrap();
        assert!(new);
        // Another description of the file finds the live pin.
        let other = table.insert(8, Flags::default()).unwrap();
        let (second, new) = table.pin_or_retain(other, 500, true).unwrap();
        assert!(!new);
        assert_eq!(second, first);
        assert_eq!(table.pinned(first), Ok(7));
        assert_eq!(table.close(fd), Ok(None));
        assert_eq!(table.release_pin(first), None);
        assert_eq!(table.pinned(first), Ok(7));
        assert_eq!(table.release_pin(second), Some(7));
        assert_eq!(table.pinned(first), Err(Error::BadFileDescriptor));
    }

    #[test]
    fn a_stale_reference_does_nothing() {
        let mut table = Table::<u32, 4>::default();
        let a = table.insert(7, Flags::default()).unwrap();
        let (old, _) = table.pin_or_retain(a, 500, false).unwrap();
        assert_eq!(table.release_pin(old), None);
        // Another file takes the place of the pin that went.
        let b = table.insert(8, Flags::default()).unwrap();
        let (new, fresh) = table.pin_or_retain(b, 600, false).unwrap();
        assert!(fresh);
        assert_eq!(new.place(), old.place());
        assert_ne!(new.generation(), old.generation());
        // The second release of the old reference leaves the new pin alone.
        assert_eq!(table.release_pin(old), None);
        assert_eq!(table.pinned(old), Err(Error::BadFileDescriptor));
        assert_eq!(table.pinned(new), Ok(8));
        assert_eq!(table.close(b), Ok(None));
        assert_eq!(table.release_pin(new), Some(8));
    }

    #[test]
    fn a_read_only_pin_does_not_serve_a_writing_mapping() {
        let mut table = Table::<u32, 4>::default();
        let read = table.insert(7, Flags::default()).unwrap();
        let write = table.insert(8, Flags::default()).unwrap();
        let (a, _) = table.pin_or_retain(read, 500, false).unwrap();
        // A mapping that reads takes the pin that is there.
        let (again, new) = table.pin_or_retain(write, 500, false).unwrap();
        assert!(!new && again == a);
        // One that writes gets a pin of its own description.
        let (b, new) = table.pin_or_retain(write, 500, true).unwrap();
        assert!(new);
        assert_ne!(a.place(), b.place());
        assert_eq!(table.pinned(b), Ok(8));
        // And a later reader takes the first pin of the file that serves.
        let (c, new) = table.pin_or_retain(read, 500, false).unwrap();
        assert!(!new);
        assert_eq!(c, a);
    }

    #[test]
    fn the_pins_are_sixteen() {
        let mut table = Table::<u32, 32>::default();
        let mut pins = [PinRef::default(); MAP_PINS];
        for (index, pin) in pins.iter_mut().enumerate() {
            let fd = table.insert(100 + index as u32, Flags::default()).unwrap();
            *pin = table
                .pin_or_retain(fd, 1000 + index as u64, false)
                .unwrap()
                .0;
        }
        let fd = table.insert(200, Flags::default()).unwrap();
        assert_eq!(
            table.pin_or_retain(fd, 2000, false),
            Err(Error::TooManyOpenFiles)
        );
        assert_eq!(table.release_pin(pins[3]), None);
        assert_eq!(table.pin_or_retain(fd, 2000, false).unwrap().0.place(), 3);
    }

    #[test]
    fn allocation_reuses_lowest_slot_and_enforces_limit() {
        let mut table = Table::<u32, 3>::default();
        assert_eq!(table.insert(10, Flags::default()), Ok(0));
        assert_eq!(table.insert(11, Flags::default()), Ok(1));
        assert_eq!(table.duplicate(0, 0, Flags::default()), Ok(2));
        assert_eq!(
            table.duplicate(0, 0, Flags::default()),
            Err(Error::TooManyOpenFiles)
        );
        assert_eq!(
            table.duplicate(0, 3, Flags::default()),
            Err(Error::InvalidArgument)
        );
        assert_eq!(table.close(1), Ok(Some(11)));
        assert_eq!(table.duplicate(0, 1, Flags::default()), Ok(1));
        assert_eq!(table.get(1), Ok(10));
    }

    #[test]
    fn duplication_preserves_shared_ownership_until_last_close() {
        let mut table = Table::<u32, 3>::default();
        let source = table.insert(40, Flags::default()).unwrap();
        let copy = table.duplicate(source, 0, Flags::default()).unwrap();
        assert_eq!(table.close(source), Ok(None), "the copy names it");
        assert_eq!(table.get(source), Err(Error::BadFileDescriptor));
        assert_eq!(table.get(copy), Ok(40));
        assert_eq!(table.close(copy), Ok(Some(40)));
        assert_eq!(table.close(copy), Err(Error::BadFileDescriptor));
    }

    /// A backend held outside the owner's lock goes at its last unhold
    /// once its descriptors went, and never while a hold remains; a backend
    /// held with a descriptor left stays.
    #[test]
    fn a_held_backend_goes_after_the_last_hold() {
        let mut table = Table::<u32, 4>::default();
        let fd = table.insert(40, Flags::default()).unwrap();
        assert_eq!(table.hold(fd), Ok(40));
        assert_eq!(table.hold(fd), Ok(40));
        assert_eq!(table.close(fd), Ok(None), "held: not yet");
        assert_eq!(table.get(fd), Err(Error::BadFileDescriptor));
        assert_eq!(table.unhold(40), None, "a second hold remains");
        assert_eq!(table.unhold(40), Some(40));
        assert_eq!(table.unhold(40), None, "no hold left");
        let fd = table.insert(50, Flags::default()).unwrap();
        assert_eq!(table.hold(fd), Ok(50));
        assert_eq!(table.unhold(50), None, "the descriptor stays");
        assert_eq!(table.close(fd), Ok(Some(50)));
        let a = table.insert(60, Flags::default()).unwrap();
        let b = table.insert(61, Flags::default()).unwrap();
        assert_eq!(table.hold(b), Ok(61));
        assert_eq!(table.dup2(a, b), Ok((b, None)), "the replaced one is held");
        assert_eq!(table.unhold(61), Some(61));
    }

    /// Holds nobody will end go: a held backend whose descriptors went is
    /// handed back to release, once; one with a descriptor left stays.
    #[test]
    fn io_loan_observation_preserves_exact_backend_and_closed_custody() {
        let mut table = Table::<(u32, u64), 8>::default();
        let backend = (3, 1_u64 << 32);
        let fd = table.insert(backend, Flags::default()).unwrap();
        assert_eq!(table.io_loan_state(backend), None);
        table.hold(fd).unwrap();
        table.hold(fd).unwrap();
        assert_eq!(table.io_loan_state(backend), Some((2, false, false)));
        assert_eq!(table.io_loan_state((3, 0)), None);
        assert_eq!(table.close(fd).unwrap(), None);
        assert_eq!(table.io_loan_state(backend), Some((2, true, false)));
        assert_eq!(table.unhold(backend), None);
        assert_eq!(table.io_loan_state(backend), Some((1, true, false)));
        assert_eq!(table.unhold(backend), Some(backend));
        assert_eq!(table.io_loan_state(backend), None);
    }

    #[test]
    fn abandoned_holds_hand_back_what_was_closed() {
        let mut table = Table::<u32, 4>::default();
        let a = table.insert(70, Flags::default()).unwrap();
        let b = table.insert(71, Flags::default()).unwrap();
        assert_eq!(table.hold(a), Ok(70));
        assert_eq!(table.hold(a), Ok(70));
        assert_eq!(table.hold(b), Ok(71));
        assert_eq!(table.close(a), Ok(None), "held");
        assert_eq!(table.abandon_hold(), Some(70));
        assert_eq!(table.abandon_hold(), None, "71 has its descriptor");
        assert_eq!(table.unhold(70), None, "no hold left");
        assert_eq!(table.close(b), Ok(Some(71)), "no hold keeps it now");
    }

    #[test]
    fn replacement_hands_back_the_old_backend() {
        let mut table = Table::<u32, 3>::default();
        let flags = Flags {
            close_on_exec: true,
            close_on_fork: true,
        };
        table.insert(10, flags).unwrap();
        table.insert(11, flags).unwrap();
        assert_eq!(table.dup2(9, 1), Err(Error::BadFileDescriptor));
        assert_eq!(table.dup2(0, 3), Err(Error::BadFileDescriptor));
        assert_eq!(table.get(1), Ok(11));
        assert_eq!(table.flags(1), Ok(flags));
        assert_eq!(table.dup2(0, 0), Ok((0, None)));
        assert_eq!(table.flags(0), Ok(flags));
        assert_eq!(
            table.dup3(0, 0, Flags::default()),
            Err(Error::InvalidArgument)
        );
        assert_eq!(table.dup2(0, 1), Ok((1, Some(11))));
        assert_eq!(table.get(1), Ok(10));
        assert_eq!(table.flags(1), Ok(Flags::default()));
        assert_eq!(table.dup2(0, 1), Ok((1, None)), "the same backend");
        assert_eq!(table.place(1, 12, flags), Err(Error::BadFileDescriptor));
        assert_eq!(table.place(2, 12, flags), Ok(()));
        assert_eq!(table.open().count(), 3);
    }

    #[test]
    fn flags_belong_to_each_descriptor_and_dup3_sets_them() {
        let mut table = Table::<u32, 4>::default();
        let flags = Flags {
            close_on_exec: true,
            close_on_fork: true,
        };
        table.insert(10, flags).unwrap();
        let copy = table.duplicate(0, 0, Flags::default()).unwrap();
        assert_eq!(table.flags(copy), Ok(Flags::default()));
        assert_eq!(table.flags(0), Ok(flags));
        table
            .set_flags(
                copy,
                Flags {
                    close_on_exec: true,
                    close_on_fork: false,
                },
            )
            .unwrap();
        assert_eq!(table.dup3(0, 3, flags), Ok((3, None)));
        assert_eq!(table.flags(3), Ok(flags));
        assert_eq!(table.flags(0), Ok(flags));
        assert_eq!(table.set_flags(9, flags), Err(Error::BadFileDescriptor));
        assert_eq!(table.flags(9), Err(Error::BadFileDescriptor));
    }

    #[test]
    fn lowered_allocation_ceiling_preserves_high_descriptors_and_imports() {
        let mut table = Table::<u32, 8>::default();
        table.place(6, 60, Flags::default()).unwrap();
        table.set_allocation_limit(2);
        assert_eq!(table.get(6), Ok(60));
        assert_eq!(table.dup2(6, 6), Ok((6, None)));
        assert_eq!(table.dup2(6, 3), Err(Error::BadFileDescriptor));
        assert_eq!(
            table.duplicate(6, 2, Flags::default()),
            Err(Error::InvalidArgument)
        );
        assert_eq!(table.insert(10, Flags::default()), Ok(0));
        assert_eq!(table.duplicate(6, 0, Flags::default()), Ok(1));
        assert_eq!(
            table.insert(20, Flags::default()),
            Err(Error::TooManyOpenFiles)
        );
        table.place(7, 70, Flags::default()).unwrap();
        table.set_allocation_limit(u64::MAX);
        assert_eq!(table.insert(20, Flags::default()), Ok(2));
    }

    #[test]
    fn reserved_open_linearizes_before_ceiling_change_and_zero_refuses_new_opens() {
        let mut table = Table::<u32, 8, u64>::default();
        let (_open, claim) = table.begin_open(owner(1), 17).unwrap();
        let entry = table.reserve_open(claim, 4, Flags::default()).unwrap();
        table.set_allocation_limit(0);
        // The exact paid reservation remains intact; only fresh allocation stops.
        assert_eq!(table.pending(entry.fd), Some(_open));
        assert_eq!(
            table.insert(10, Flags::default()),
            Err(Error::TooManyOpenFiles)
        );
        let (_, second) = table.begin_open(owner(2), 18).unwrap();
        assert_eq!(
            table.reserve_open(second, 0, Flags::default()),
            Err(Error::TooManyOpenFiles)
        );
    }

    fn owner(value: u64) -> OwnerToken {
        OwnerToken::new(value).unwrap()
    }

    fn acquired<R: Copy>(claim: Claim<R>) -> ClaimToken {
        let Claim::Acquired { token, .. } = claim else {
            panic!("an acquired claim")
        };
        token
    }

    #[test]
    fn reserved_fd_is_hidden_and_replacement_waits_then_revalidates() {
        let mut table = Table::<u32, 4, u64>::default();
        let source = table.insert(10, Flags::default()).unwrap();
        let (open, claim) = table.begin_open(owner(1), 70).unwrap();
        let flags = Flags {
            close_on_exec: true,
            close_on_fork: false,
        };
        let entry = table.reserve_open(claim, 0, flags).unwrap();
        assert_eq!(entry.fd, 1);
        assert_eq!(table.get(entry.fd), Err(Error::BadFileDescriptor));
        assert_eq!(table.flags(entry.fd), Err(Error::BadFileDescriptor));
        assert_eq!(
            table.set_flags(entry.fd, flags),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(table.close(entry.fd), Err(Error::BadFileDescriptor));
        assert_eq!(table.vacant(0), Ok(2));
        assert_eq!(table.open().count(), 1);
        assert_eq!(
            table.try_dup2(source, entry.fd),
            Ok(Replacement::Pending(open))
        );
        assert_eq!(
            table.try_dup3(source, entry.fd, flags),
            Ok(Replacement::Pending(open))
        );
        assert_eq!(table.try_dup2(9, entry.fd), Err(Error::BadFileDescriptor));
        let before = table.wait_snapshot(open).unwrap();
        table.begin_cancel(claim).unwrap();
        table.finish_cancel(open, 5).unwrap();
        assert_ne!(table.wait_snapshot(open).unwrap(), before);
        table.close(source).unwrap();
        assert_eq!(
            table.try_dup2(source, entry.fd),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(table.vacant(0), Ok(0));
        assert_eq!(table.ack_open(open, owner(1)), Ok(Completion::Failed(5)));
    }

    #[test]
    fn helper_completion_survives_handler_close_reuse_and_exact_ack() {
        let mut table = Table::<u32, 2, u64>::default();
        let (open, original) = table.begin_open(owner(1), 70).unwrap();
        let entry = table.reserve_open(original, 0, Flags::default()).unwrap();
        table.release_claim(original).unwrap();
        let helper = acquired(table.claim_open(open, owner(2)).unwrap());
        assert_eq!(
            table.stage_committed(original, 10),
            Err(Error::BadFileDescriptor)
        );
        table.update_open(helper, 71).unwrap();
        table.stage_committed(helper, 10).unwrap();
        assert_eq!(table.publish_open(helper), Ok(entry));
        assert_eq!(table.publish_open(helper), Err(Error::BadFileDescriptor));
        assert_eq!(
            table.claim_open(open, owner(3)),
            Ok(Claim::Complete(Completion::Opened(entry.fd)))
        );
        assert_eq!(table.close(entry.fd), Ok(Some(10)));
        assert_eq!(table.insert(20, Flags::default()), Ok(entry.fd));
        assert_eq!(
            table.ack_open(open, owner(2)),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(
            table.ack_open(open, owner(1)),
            Ok(Completion::Opened(entry.fd))
        );
        assert_eq!(table.get(entry.fd), Ok(20));
        assert_eq!(
            table.ack_open(open, owner(1)),
            Err(Error::BadFileDescriptor)
        );
        let (fresh, _) = table.begin_open(owner(1), 72).unwrap();
        assert_eq!(fresh.slot(), open.slot());
        assert!(fresh.generation() > open.generation());
        assert_eq!(table.finish_cancel(open, 5), Err(Error::BadFileDescriptor));
        assert_eq!(table.open_snapshot(fresh).unwrap().recovery, Some(72));
    }

    #[test]
    fn published_pre_ack_cleanup_checks_entry_lifetime_even_for_same_backend() {
        let mut table = Table::<u32, 3>::default();
        let source = table.insert(10, Flags::default()).unwrap();
        let (open, claim) = table.begin_open(owner(1), ()).unwrap();
        let entry = table.reserve_open(claim, 0, Flags::default()).unwrap();
        table.stage_committed(claim, 10).unwrap();
        table.publish_open(claim).unwrap();
        assert_eq!(table.dup2(source, entry.fd), Ok((entry.fd, None)));
        let replacement = table.entry_token(entry.fd).unwrap();
        assert!(replacement.generation() > entry.generation());
        assert_eq!(
            table.abandon_owner(owner(1)),
            Some(Abandoned::Discarded {
                token: open,
                release: None
            })
        );
        assert_eq!(table.entry_token(entry.fd), Ok(replacement));
        assert_eq!(table.get(entry.fd), Ok(10));
        assert_eq!(table.close(source), Ok(None));
        assert_eq!(table.close(entry.fd), Ok(Some(10)));
    }

    #[test]
    fn deferred_open_allows_handler_replacement_and_keeps_exact_attempt() {
        let mut table = Table::<u32, 3, u64>::default();
        let source = table.insert(90, Flags::default()).unwrap();
        let (open, claim) = table.begin_open(owner(1), 700).unwrap();
        let flags = Flags {
            close_on_exec: true,
            close_on_fork: true,
        };
        let first = table.reserve_open(claim, 0, flags).unwrap();
        assert_eq!(
            table.try_dup2(source, first.fd),
            Ok(Replacement::Pending(open))
        );
        let before = table.wait_snapshot(open).unwrap();
        assert_eq!(table.unreserve_open(claim, first, 701), Ok(first));
        assert_ne!(table.wait_snapshot(open).unwrap(), before);
        assert_eq!(table.pending(first.fd), None);
        let snapshot = table.open_snapshot(open).unwrap();
        assert_eq!(snapshot.owner, Some(owner(1)));
        assert_eq!(snapshot.claimant, None);
        assert_eq!(snapshot.phase, OpenPhase::Preparing);
        assert_eq!(snapshot.recovery, Some(701));
        assert_eq!(table.open_tokens().count(), 1);
        assert_eq!(table.open_tokens().next(), Some(open));
        assert_eq!(
            table.stage_committed(claim, 20),
            Err(Error::BadFileDescriptor)
        );
        // A handler can replace the released number before the same attempt continues.
        assert_eq!(table.dup2(source, first.fd), Ok((first.fd, None)));
        assert_eq!(table.get(first.fd), Ok(90));
        let next = acquired(table.claim_open(open, owner(1)).unwrap());
        assert!(next.serial > claim.serial);
        let second = table.reserve_open(next, 0, flags).unwrap();
        assert_ne!(second.fd, first.fd);
        table.stage_committed(next, 20).unwrap();
        table.publish_open(next).unwrap();
        assert_eq!(
            table.ack_open(open, owner(1)),
            Ok(Completion::Opened(second.fd))
        );
        assert_eq!(table.get(first.fd), Ok(90));
        assert_eq!(table.get(second.fd), Ok(20));
        assert_eq!(table.flags(second.fd), Ok(flags));
    }

    #[test]
    fn unreserve_checks_exact_entry_claim_and_phase_before_any_change() {
        let mut table = Table::<u32, 2, u64>::default();
        let (open, first_claim) = table.begin_open(owner(1), 70).unwrap();
        let first = table
            .reserve_open(first_claim, 0, Flags::default())
            .unwrap();
        let before = table.open_snapshot(open).unwrap();
        let sequence = table.wait_snapshot(open).unwrap();
        for wrong in [
            EntryToken::new(1, first.generation()),
            EntryToken::new(first.fd, first.generation() + 1),
        ] {
            assert_eq!(table.unreserve_open(first_claim, wrong, 99), Err(Error::Io));
            assert_eq!(table.open_snapshot(open).unwrap(), before);
            assert_eq!(table.wait_snapshot(open).unwrap(), sequence);
            assert_eq!(table.pending(first.fd), Some(open));
        }
        table.release_claim(first_claim).unwrap();
        let next = acquired(table.claim_open(open, owner(2)).unwrap());
        let before = table.open_snapshot(open).unwrap();
        assert_eq!(
            table.unreserve_open(first_claim, first, 99),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(table.open_snapshot(open).unwrap(), before);
        table.unreserve_open(next, first, 71).unwrap();
        let next = acquired(table.claim_open(open, owner(2)).unwrap());
        let before = table.open_snapshot(open).unwrap();
        assert_eq!(
            table.unreserve_open(next, first, 99),
            Err(Error::InvalidArgument)
        );
        assert_eq!(table.open_snapshot(open).unwrap(), before);
        let second = table.reserve_open(next, 0, Flags::default()).unwrap();
        assert_eq!(second.fd, first.fd);
        assert!(second.generation() > first.generation());
        let before = table.open_snapshot(open).unwrap();
        assert_eq!(table.unreserve_open(next, first, 99), Err(Error::Io));
        assert_eq!(table.open_snapshot(open).unwrap(), before);
        assert_eq!(table.pending(second.fd), Some(open));
        table.stage_committed(next, 10).unwrap();
        let before = table.open_snapshot(open).unwrap();
        assert_eq!(
            table.unreserve_open(next, second, 99),
            Err(Error::InvalidArgument)
        );
        assert_eq!(table.open_snapshot(open).unwrap(), before);
        table.publish_open(next).unwrap();
        assert_eq!(
            table.unreserve_open(next, second, 99),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(table.get(second.fd), Ok(10));
    }

    #[test]
    fn deferred_open_keeps_paid_hold_and_ended_owner_cleanup() {
        let mut table = Table::<u32, 32, u64>::default();
        let mut last = None;
        for i in 0..JOBS_MAX as u64 {
            let (open, claim) = table.begin_open(owner(1), i).unwrap();
            let entry = table.reserve_open(claim, 0, Flags::default()).unwrap();
            table.unreserve_open(claim, entry, i).unwrap();
            last = Some((open, claim, entry));
        }
        assert_eq!(table.begin_open(owner(2), 99), Err(Error::TooManyOpenFiles));
        assert_eq!(table.vacant(0), Ok(0));
        let (open, old_claim, entry) = last.unwrap();
        let new_claim = acquired(table.claim_open(open, owner(2)).unwrap());
        table.abandon_open(open).unwrap();
        assert_eq!(
            table.unreserve_open(old_claim, entry, 99),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(
            table.unreserve_open(new_claim, entry, 99),
            Err(Error::BadFileDescriptor)
        );
        // Drain all ended-owner attempts through the canonical cancellation path.
        while let Some(abandoned) = table.abandon_owner(owner(1)) {
            assert!(matches!(abandoned, Abandoned::Recover { .. }));
        }
        let mut tokens = [None; 32];
        for (slot, token) in table.open_tokens().enumerate() {
            tokens[slot] = Some(token);
        }
        for token in tokens.into_iter().flatten() {
            let claim = acquired(table.claim_open(token, owner(3)).unwrap());
            table.begin_cancel(claim).unwrap();
            assert_eq!(table.finish_cancel(token, 5), Ok(None));
        }
        assert_eq!(table.open_tokens().count(), 0);
        assert!(table.begin_open(owner(2), 99).is_ok());
    }

    #[test]
    fn unreserve_preserves_reused_mapping_and_ended_owner_reservation() {
        let mut table = Table::<u32, 2, u64>::default();
        let (open, claim) = table.begin_open(owner(1), 70).unwrap();
        let entry = table.reserve_open(claim, 0, Flags::default()).unwrap();
        // An inconsistent late entry must preserve the replacement's ownership.
        table.entries[entry.fd as usize].state = EntryState::Open(Entry {
            backend: 90,
            flags: Flags::default(),
        });
        let before = table.open_snapshot(open).unwrap();
        let sequence = table.wait_snapshot(open).unwrap();
        assert_eq!(table.unreserve_open(claim, entry, 99), Err(Error::Io));
        assert_eq!(table.get(entry.fd), Ok(90));
        assert_eq!(table.open_snapshot(open).unwrap(), before);
        assert_eq!(table.wait_snapshot(open).unwrap(), sequence);
        let mut table = Table::<u32, 2, u64>::default();
        let (open, claim) = table.begin_open(owner(1), 70).unwrap();
        let entry = table.reserve_open(claim, 0, Flags::default()).unwrap();
        table.abandon_open(open).unwrap();
        let helper = acquired(table.claim_open(open, owner(2)).unwrap());
        let before = table.open_snapshot(open).unwrap();
        let sequence = table.wait_snapshot(open).unwrap();
        assert_eq!(
            table.unreserve_open(helper, entry, 99),
            Err(Error::InvalidArgument)
        );
        assert_eq!(table.pending(entry.fd), Some(open));
        assert_eq!(table.open_snapshot(open).unwrap(), before);
        assert_eq!(table.wait_snapshot(open).unwrap(), sequence);
        table.begin_cancel(helper).unwrap();
        assert_eq!(table.finish_cancel(open, 5), Ok(None));
        assert_eq!(table.vacant(0), Ok(entry.fd));
    }

    #[test]
    fn unreserve_preserves_terminal_generation_and_claim_limits() {
        let mut table = Table::<u32, 1, u64>::default();
        table.entries[0].generation = u64::MAX - 1;
        let (open, claim) = table.begin_open(owner(1), 70).unwrap();
        let entry = table.reserve_open(claim, 0, Flags::default()).unwrap();
        assert_eq!(entry.generation(), u64::MAX);
        table.unreserve_open(claim, entry, 71).unwrap();
        let next = acquired(table.claim_open(open, owner(1)).unwrap());
        assert_eq!(
            table.reserve_open(next, 0, Flags::default()),
            Err(Error::Io)
        );
        assert_eq!(table.open_snapshot(open).unwrap().recovery, Some(71));
        table.begin_cancel(next).unwrap();
        table.finish_cancel(open, 5).unwrap();
        table.ack_open(open, owner(1)).unwrap();
        let mut table = Table::<u32, 1, u64>::default();
        let (open, claim) = table.begin_open(owner(1), 80).unwrap();
        let entry = table.reserve_open(claim, 0, Flags::default()).unwrap();
        let Held::Open(record) = &mut table.residents[0].held else {
            panic!("open")
        };
        record.serial = u64::MAX - 1;
        let final_claim = ClaimToken {
            open,
            serial: u64::MAX - 1,
        };
        table.unreserve_open(final_claim, entry, 81).unwrap();
        assert!(matches!(
            table.claim_open(open, owner(2)),
            Ok(Claim::Canceling(_))
        ));
        assert_eq!(table.pending(entry.fd), None);
        assert_eq!(
            table.unreserve_open(claim, entry, 82),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(table.open_snapshot(open).unwrap().recovery, Some(81));
        table.finish_cancel(open, 5).unwrap();
        assert_eq!(table.ack_open(open, owner(1)), Ok(Completion::Failed(5)));
    }

    #[test]
    fn unreturned_entry_closes_once_and_acked_fd_survives_owner_death() {
        let mut table = Table::<u32, 2>::with_early_release(|_| true);
        let (open, claim) = table.begin_open(owner(1), ()).unwrap();
        let entry = table.reserve_open(claim, 0, Flags::default()).unwrap();
        table.stage_committed(claim, 10).unwrap();
        table.publish_open(claim).unwrap();
        table.hold(entry.fd).unwrap();
        assert_eq!(
            table.abandon_owner(owner(1)),
            Some(Abandoned::Discarded {
                token: open,
                release: Some(10)
            })
        );
        assert_eq!(table.get(entry.fd), Err(Error::BadFileDescriptor));
        assert_eq!(table.unhold(10), None);
        assert_eq!(table.abandon_owner(owner(1)), None);
        let (open, claim) = table.begin_open(owner(1), ()).unwrap();
        let entry = table.reserve_open(claim, 0, Flags::default()).unwrap();
        table.stage_committed(claim, 20).unwrap();
        table.publish_open(claim).unwrap();
        assert_eq!(
            table.ack_open(open, owner(1)),
            Ok(Completion::Opened(entry.fd))
        );
        assert_eq!(table.abandon_owner(owner(1)), None);
        assert_eq!(table.get(entry.fd), Ok(20));
    }

    #[test]
    fn owner_and_helper_death_revoke_claims_and_allow_canonical_cleanup() {
        let mut table = Table::<u32, 2, u64>::default();
        let (open, first) = table.begin_open(owner(1), 70).unwrap();
        let entry = table.reserve_open(first, 0, Flags::default()).unwrap();
        table.release_claim(first).unwrap();
        let second = acquired(table.claim_open(open, owner(2)).unwrap());
        assert_eq!(table.claim_open(open, owner(3)), Ok(Claim::Busy(owner(2))));
        assert_eq!(
            table.abandon_owner(owner(2)),
            Some(Abandoned::ClaimReleased(open))
        );
        let third = acquired(table.claim_open(open, owner(3)).unwrap());
        assert_eq!(table.release_claim(second), Err(Error::BadFileDescriptor));
        table.stage_committed(third, 10).unwrap();
        let abandoned = table.abandon_owner(owner(1)).unwrap();
        assert!(
            matches!(abandoned, Abandoned::Recover { token, snapshot } if token == open && snapshot.owner.is_none())
        );
        assert_eq!(table.publish_open(third), Err(Error::BadFileDescriptor));
        let cleanup = acquired(table.claim_open(open, owner(4)).unwrap());
        assert_eq!(table.publish_open(cleanup), Err(Error::InvalidArgument));
        let snapshot = table.begin_cancel(cleanup).unwrap();
        assert_eq!(snapshot.recovery, Some(70));
        assert_eq!(table.pending(entry.fd), Some(open));
        assert_eq!(table.finish_cancel(open, 5), Ok(Some(10)));
        assert_eq!(table.vacant(0), Ok(entry.fd));
        assert_eq!(table.open_tokens().count(), 0);
        assert_eq!(table.finish_cancel(open, 5), Err(Error::BadFileDescriptor));
        assert!(table.begin_open(owner(5), 80).is_ok());
    }

    #[test]
    fn cancel_rejects_stale_publication_and_preserves_failed_completion() {
        let mut table = Table::<u32, 1, u64>::default();
        let (open, claim) = table.begin_open(owner(1), 70).unwrap();
        let entry = table.reserve_open(claim, 0, Flags::default()).unwrap();
        table.stage_committed(claim, 10).unwrap();
        table.begin_cancel(claim).unwrap();
        assert_eq!(table.publish_open(claim), Err(Error::BadFileDescriptor));
        assert_eq!(
            table.stage_committed(claim, 20),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(table.finish_cancel(open, 0), Err(Error::InvalidArgument));
        assert_eq!(table.pending(entry.fd), Some(open));
        assert_eq!(table.finish_cancel(open, 5), Ok(Some(10)));
        assert_eq!(table.finish_cancel(open, 5), Err(Error::BadFileDescriptor));
        assert_eq!(table.ack_open(open, owner(1)), Ok(Completion::Failed(5)));
        let (new, claim) = table.begin_open(owner(1), 80).unwrap();
        table.reserve_open(claim, 0, Flags::default()).unwrap();
        table.stage_committed(claim, 20).unwrap();
        table.publish_open(claim).unwrap();
        assert_eq!(table.finish_cancel(open, 5), Err(Error::BadFileDescriptor));
        assert_eq!(table.finish_cancel(new, 5), Err(Error::BadFileDescriptor));
        assert_eq!(table.get(0), Ok(20));
        assert_eq!(table.ack_open(new, owner(1)), Ok(Completion::Opened(0)));
    }

    #[test]
    fn io_credits_remain_available_with_all_unacked_job_completions() {
        let mut table = Table::<u32, 32>::default();
        for backend in 0..16 {
            let fd = table.insert(backend, Flags::default()).unwrap();
            table.hold(fd).unwrap();
        }
        let mut opens = [None; 16];
        for (i, token) in opens.iter_mut().enumerate() {
            let (open, claim) = table.begin_open(owner(1), ()).unwrap();
            table.reserve_open(claim, 0, Flags::default()).unwrap();
            table.stage_committed(claim, (i + 16) as u32).unwrap();
            table.publish_open(claim).unwrap();
            *token = Some(open);
        }
        assert_eq!(table.begin_open(owner(1), ()), Err(Error::TooManyOpenFiles));
        assert_eq!(table.hold(31), Ok(31));
        assert_eq!(table.hold(0), Ok(0));
        assert_eq!(table.close(31), Ok(None));
        assert_eq!(table.unhold(31), Some(31));
        assert_eq!(table.begin_open(owner(1), ()), Err(Error::TooManyOpenFiles));
        table.ack_open(opens[15].unwrap(), owner(1)).unwrap();
        assert!(table.begin_open(owner(1), ()).is_ok());
        assert_eq!(table.abandon_hold(), None);
        assert_eq!(table.open_tokens().count(), 16);
    }

    #[test]
    fn exhausted_generations_reject_admission_and_existing_cleanup_finishes() {
        let mut table = Table::<u32, 1>::default();
        table.residents[0].generation = u64::MAX - 1;
        table.entries[0].generation = u64::MAX - 1;
        let (open, claim) = table.begin_open(owner(1), ()).unwrap();
        let entry = table.reserve_open(claim, 0, Flags::default()).unwrap();
        assert_eq!(open.generation(), u64::MAX);
        assert_eq!(entry.generation(), u64::MAX);
        table.stage_committed(claim, 10).unwrap();
        table.publish_open(claim).unwrap();
        assert_eq!(table.ack_open(open, owner(1)), Ok(Completion::Opened(0)));
        assert_eq!(table.close(0), Ok(Some(10)));
        assert_eq!(table.insert(20, Flags::default()), Err(Error::Io));
        assert_eq!(table.begin_open(owner(1), ()), Err(Error::TooManyOpenFiles));
        let mut table = Table::<u32, 2>::default();
        table.entries[0].generation = u64::MAX;
        let (open, claim) = table.begin_open(owner(1), ()).unwrap();
        assert_eq!(
            table.reserve_open(claim, 0, Flags::default()),
            Err(Error::Io)
        );
        assert_eq!(
            table.open_snapshot(open).unwrap().phase,
            OpenPhase::Preparing
        );
        table.begin_cancel(claim).unwrap();
        table.finish_cancel(open, 5).unwrap();
        table.abandon_owner(owner(1)).unwrap();
        assert_eq!(table.open_tokens().count(), 0);
    }

    #[test]
    fn terminal_claim_serial_revokes_late_reply_and_cancels_without_new_serial() {
        let mut table = Table::<u32, 1, u64>::default();
        let (open, claim) = table.begin_open(owner(1), 70).unwrap();
        let entry = table.reserve_open(claim, 0, Flags::default()).unwrap();
        table.stage_committed(claim, 10).unwrap();
        let Held::Open(record) = &mut table.residents[0].held else {
            panic!("open")
        };
        record.serial = u64::MAX;
        let last = ClaimToken {
            open,
            serial: u64::MAX,
        };
        table.release_claim(last).unwrap();
        assert!(matches!(
            table.claim_open(open, owner(2)),
            Ok(Claim::Canceling(_))
        ));
        assert_eq!(table.publish_open(last), Err(Error::BadFileDescriptor));
        assert_eq!(table.pending(entry.fd), Some(open));
        table.abandon_owner(owner(1)).unwrap();
        assert_eq!(table.finish_cancel(open, 5), Ok(Some(10)));
        assert_eq!(table.open_tokens().count(), 0);
        assert_eq!(table.vacant(0), Ok(0));
        assert!(table.begin_open(owner(2), 80).is_ok());
    }

    #[test]
    fn saturated_wait_word_never_wraps_and_cleanup_keeps_stable_address() {
        let mut table = Table::<u32, 1>::default();
        let (open, claim) = table.begin_open(owner(1), ()).unwrap();
        let address = table.wait_word(open).unwrap() as *const AtomicU32;
        table.residents[0]
            .changed
            .store(u32::MAX - 1, Ordering::Relaxed);
        let before = table.wait_snapshot(open).unwrap();
        let entry = table.reserve_open(claim, 0, Flags::default()).unwrap();
        assert_eq!(before, WaitValue::Sequence(u32::MAX - 1));
        assert_eq!(table.wait_snapshot(open), Ok(WaitValue::NeverSleep));
        table.begin_cancel(claim).unwrap();
        table.abandon_owner(owner(1)).unwrap();
        table.finish_cancel(open, 5).unwrap();
        assert_eq!(table.wait_word(open).unwrap() as *const AtomicU32, address);
        assert_eq!(
            table.wait_word(open).unwrap().load(Ordering::Acquire),
            u32::MAX
        );
        assert_eq!(table.begin_open(owner(1), ()), Err(Error::TooManyOpenFiles));
        assert_eq!(table.insert(10, Flags::default()), Ok(entry.fd));
        assert_eq!(table.hold(entry.fd), Ok(10));
        assert_eq!(table.close(entry.fd), Ok(None));
        assert_eq!(table.unhold(10), Some(10));
        assert_eq!(
            table.wait_word(open).unwrap().load(Ordering::Acquire),
            u32::MAX
        );
    }

    #[test]
    fn fork_discard_preserves_published_refs_and_drops_recovery_authority() {
        let mut child = Table::<u32, 3, u64>::default();
        let (published, claim) = child.begin_open(owner(1), 70).unwrap();
        let live = child.reserve_open(claim, 0, Flags::default()).unwrap();
        child.stage_committed(claim, 10).unwrap();
        child.publish_open(claim).unwrap();
        child.hold(live.fd).unwrap();
        let (pending, claim) = child.begin_open(owner(2), 80).unwrap();
        let transient = child.reserve_open(claim, 0, Flags::default()).unwrap();
        child.stage_committed(claim, 20).unwrap();
        child.discard_open_after_fork();
        assert_eq!(child.open_tokens().count(), 0);
        assert_eq!(
            child.open_snapshot(published),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(child.open_snapshot(pending), Err(Error::BadFileDescriptor));
        assert_eq!(child.get(live.fd), Ok(10));
        assert_eq!(child.pending(transient.fd), None);
        assert_eq!(child.vacant(0), Ok(transient.fd));
        assert_eq!(child.abandon_hold(), None);
        assert_eq!(child.close(live.fd), Ok(Some(10)));
    }

    #[test]
    fn flags_and_same_fd_dup_preserve_entry_lifetime() {
        let mut table = Table::<u32, 1>::default();
        table.insert(10, Flags::default()).unwrap();
        let entry = table.entry_token(0).unwrap();
        table
            .set_flags(
                0,
                Flags {
                    close_on_exec: true,
                    close_on_fork: false,
                },
            )
            .unwrap();
        assert_eq!(table.dup2(0, 0), Ok((0, None)));
        assert_eq!(table.entry_token(0), Ok(entry));
        table.entries[0].generation = u64::MAX;
        let at_max = table.entry_token(0).unwrap();
        assert_eq!(table.dup2(0, 0), Ok((0, None)));
        assert_eq!(table.entry_token(0), Ok(at_max));
    }

    #[test]
    fn exhausted_replacement_preserves_target_and_owner_death_skips_reused_fd() {
        let mut table = Table::<u32, 3>::default();
        let flags = Flags {
            close_on_exec: true,
            close_on_fork: true,
        };
        table.insert(10, Flags::default()).unwrap();
        table.insert(20, flags).unwrap();
        table.entries[1].generation = u64::MAX;
        let target = table.entry_token(1).unwrap();
        assert_eq!(table.try_dup2(0, 1), Err(Error::Io));
        assert_eq!(table.try_dup3(0, 1, Flags::default()), Err(Error::Io));
        assert_eq!(table.get(1), Ok(20));
        assert_eq!(table.flags(1), Ok(flags));
        assert_eq!(table.entry_token(1), Ok(target));
        let (open, claim) = table.begin_open(owner(1), ()).unwrap();
        let entry = table.reserve_open(claim, 0, Flags::default()).unwrap();
        table.stage_committed(claim, 30).unwrap();
        table.publish_open(claim).unwrap();
        assert_eq!(table.close(entry.fd), Ok(Some(30)));
        assert_eq!(table.insert(40, Flags::default()), Ok(entry.fd));
        let fresh = table.entry_token(entry.fd).unwrap();
        assert_eq!(
            table.abandon_owner(owner(1)),
            Some(Abandoned::Discarded {
                token: open,
                release: None
            })
        );
        assert_eq!(table.entry_token(entry.fd), Ok(fresh));
        assert_eq!(table.get(entry.fd), Ok(40));
    }

    #[test]
    fn claim_reaching_max_enters_canceling_without_publication_authority() {
        let mut table = Table::<u32, 1, u64>::default();
        let (open, original) = table.begin_open(owner(1), 70).unwrap();
        let entry = table.reserve_open(original, 0, Flags::default()).unwrap();
        table.stage_committed(original, 10).unwrap();
        table.release_claim(original).unwrap();
        let Held::Open(record) = &mut table.residents[0].held else {
            panic!("open")
        };
        record.serial = u64::MAX - 2;
        let last = acquired(table.claim_open(open, owner(2)).unwrap());
        assert_eq!(last.serial, u64::MAX - 1);
        table.release_claim(last).unwrap();
        assert!(
            matches!(table.claim_open(open, owner(3)), Ok(Claim::Canceling(snapshot))
            if snapshot.phase == OpenPhase::Canceling && snapshot.claimant.is_none())
        );
        let Held::Open(record) = table.residents[0].held else {
            panic!("open")
        };
        assert_eq!(record.serial, u64::MAX);
        assert_eq!(table.publish_open(last), Err(Error::BadFileDescriptor));
        assert_eq!(
            table.stage_committed(last, 20),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(
            table.publish_open(ClaimToken {
                open,
                serial: u64::MAX
            }),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(table.pending(entry.fd), Some(open));
        table.abandon_owner(owner(1)).unwrap();
        assert_eq!(table.finish_cancel(open, 5), Ok(Some(10)));
        assert_eq!(table.open_tokens().count(), 0);
        assert_eq!(table.vacant(0), Ok(entry.fd));
        assert!(table.begin_open(owner(4), 80).is_ok());
    }

    fn publish<const N: usize>(
        table: &mut Table<u32, N, u64>,
        backend: u32,
    ) -> (OpenToken, ClaimToken, EntryToken) {
        let (open, claim) = table.begin_open(owner(1), 70).unwrap();
        let entry = table.reserve_open(claim, 0, Flags::default()).unwrap();
        table.stage_committed(claim, backend).unwrap();
        table.publish_open(claim).unwrap();
        (open, claim, entry)
    }

    #[test]
    fn claim_snapshot_preserves_wait_state_and_rejects_released_serials() {
        let mut table = Table::<u32, 32, u64>::default();
        let (open, first) = table.begin_open(owner(1), 70).unwrap();
        let before = table.wait_snapshot(open).unwrap();
        assert_eq!(table.claim_snapshot(first), table.open_snapshot(open));
        assert_eq!(table.wait_snapshot(open), Ok(before));
        table.release_claim(first).unwrap();
        let second = acquired(table.claim_open(open, owner(2)).unwrap());
        let before = table.wait_snapshot(open).unwrap();
        assert_eq!(table.claim_snapshot(first), Err(Error::BadFileDescriptor));
        assert_eq!(table.claim_snapshot(second), table.open_snapshot(open));
        assert_eq!(table.wait_snapshot(open), Ok(before));
        table.abandon_open_with_recovery(open, 80).unwrap();
        assert_eq!(table.claim_snapshot(second), Err(Error::BadFileDescriptor));
    }

    #[test]
    fn published_cleanup_stays_paid_with_full_io_and_job_budgets() {
        let mut table = Table::<u32, 32, u64>::default();
        for backend in 0..31 {
            let fd = table.insert(backend, Flags::default()).unwrap();
            table.hold(fd).unwrap();
        }
        for _ in 1..JOBS_MAX {
            table.begin_open(owner(2), 80).unwrap();
        }
        let (open, late, entry) = publish(&mut table, 50);
        assert_eq!(table.begin_open(owner(2), 80), Err(Error::TooManyOpenFiles));
        let Abandoned::Recover { snapshot, .. } =
            table.abandon_open_with_recovery(open, 500).unwrap()
        else {
            panic!("last target remains resident")
        };
        assert_eq!(snapshot.phase, OpenPhase::Canceling);
        assert_eq!(snapshot.recovery, Some(500));
        assert_eq!(snapshot.entry, None);
        assert_eq!(snapshot.owner, None);
        assert_eq!(snapshot.claimant, None);
        assert!(table.get(entry.fd).is_err());
        assert_eq!(table.begin_open(owner(2), 80), Err(Error::TooManyOpenFiles));
        assert_eq!(
            table.ack_open(open, owner(1)),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(table.publish_open(late), Err(Error::BadFileDescriptor));
        assert!(matches!(
            table.claim_open(open, owner(2)),
            Ok(Claim::Canceling(_))
        ));
        assert_eq!(table.finish_cancel(open, 5), Ok(Some(50)));
        assert!(table.begin_open(owner(2), 80).is_ok());
    }

    #[test]
    fn published_cleanup_survives_helper_death_before_and_after_remote_cancel() {
        let mut table = Table::<u32, 2, u64>::default();
        let (open, _, entry) = publish(&mut table, 0x10003);
        table.abandon_open_with_recovery(open, 0x10003).unwrap();
        // The first helper dies before it sends exact Cancel.
        assert_eq!(table.abandon_owner(owner(2)), None);
        assert_eq!(table.open_snapshot(open).unwrap().recovery, Some(0x10003));
        // The backend confirms cancellation, then a second helper dies.
        assert_eq!(table.abandon_owner(owner(3)), None);
        table.abandon_open_with_recovery(open, 0x20003).unwrap();
        assert_eq!(table.open_snapshot(open).unwrap().recovery, Some(0x10003));
        // A new backend lifetime reuses the native numeric fd 3 and local fd.
        let replacement = table.insert(0x20003, Flags::default()).unwrap();
        assert_eq!(replacement, entry.fd);
        let snapshot = table.finish_cancel(open, 5).unwrap();
        assert_eq!(snapshot, Some(0x10003));
        // Exact remote cancellation consumed this snapshot; replacement lives.
        assert_eq!(table.get(replacement), Ok(0x20003));
        assert_eq!(table.finish_cancel(open, 5), Err(Error::BadFileDescriptor));
    }

    #[test]
    fn published_cleanup_discard_preserves_alias_and_io_release_semantics() {
        let mut alias = Table::<u32, 2, u64>::default();
        let (open, _, entry) = publish(&mut alias, 10);
        let copied = alias.duplicate(entry.fd, 0, Flags::default()).unwrap();
        assert_eq!(
            alias.abandon_open_with_recovery(open, 500),
            Ok(Abandoned::Discarded {
                token: open,
                release: None
            })
        );
        assert_eq!(alias.get(copied), Ok(10));
        assert_eq!(alias.close(copied), Ok(Some(10)));
        for early in [false, true] {
            let mut table =
                Table::<u32, 2, u64>::with_early_release(if early { |_| true } else { |_| false });
            let (open, _, entry) = publish(&mut table, 20);
            table.hold(entry.fd).unwrap();
            assert_eq!(
                table.abandon_open_with_recovery(open, 500),
                Ok(Abandoned::Discarded {
                    token: open,
                    release: early.then_some(20)
                })
            );
            assert!(table.open_snapshot(open).is_err());
            assert_eq!(table.unhold(20), (!early).then_some(20));
        }
    }

    #[test]
    fn published_cleanup_does_not_close_replaced_same_backend_entry() {
        let mut table = Table::<u32, 3, u64>::default();
        let source = table.insert(10, Flags::default()).unwrap();
        let (open, _, old) = publish(&mut table, 10);
        table.dup2(source, old.fd).unwrap();
        let replacement = table.entry_token(old.fd).unwrap();
        assert!(replacement.generation() > old.generation());
        assert_eq!(
            table.abandon_open_with_recovery(open, 500),
            Ok(Abandoned::Discarded {
                token: open,
                release: None
            })
        );
        assert_eq!(table.entry_token(old.fd), Ok(replacement));
        assert_eq!(table.get(old.fd), Ok(10));
        assert!(table.open_snapshot(open).is_err());
    }

    #[test]
    fn abandonment_payload_is_unchanged_before_publication_and_on_repeat() {
        let mut table = Table::<u32, 2, u64>::default();
        let (open, claim) = table.begin_open(owner(1), 70).unwrap();
        table.reserve_open(claim, 0, Flags::default()).unwrap();
        let first = table.abandon_open_with_recovery(open, 500).unwrap();
        assert_eq!(table.open_snapshot(open).unwrap().recovery, Some(70));
        assert_eq!(table.abandon_open_with_recovery(open, 900), Ok(first));
        let claim = acquired(table.claim_open(open, owner(2)).unwrap());
        let canceled = table.begin_cancel(claim).unwrap();
        assert_eq!(
            table.abandon_open_with_recovery(open, 900).unwrap(),
            Abandoned::Recover {
                token: open,
                snapshot: canceled
            }
        );
    }

    #[test]
    fn preparing_and_committed_abandonment_keep_existing_recovery() {
        for committed in [false, true] {
            let mut table = Table::<u32, 1, u64>::default();
            let (open, claim) = table.begin_open(owner(1), 70).unwrap();
            if committed {
                table.reserve_open(claim, 0, Flags::default()).unwrap();
                table.stage_committed(claim, 10).unwrap();
            }
            let phase = table.open_snapshot(open).unwrap().phase;
            table.abandon_open_with_recovery(open, 500).unwrap();
            let snapshot = table.open_snapshot(open).unwrap();
            assert_eq!(snapshot.recovery, Some(70));
            assert_eq!(snapshot.phase, phase);
            assert_eq!(snapshot.owner, None);
            assert_eq!(snapshot.claimant, None);
        }
    }

    #[test]
    fn published_cleanup_terminal_counters_need_no_new_authority() {
        let mut table = Table::<u32, 1, u64>::default();
        table.residents[0].generation = u64::MAX - 1;
        let (open, _, _) = publish(&mut table, 10);
        let Held::Open(record) = &mut table.residents[0].held else {
            panic!("open")
        };
        record.serial = u64::MAX;
        table.residents[0]
            .changed
            .store(u32::MAX, Ordering::Relaxed);
        table.abandon_open_with_recovery(open, 500).unwrap();
        assert_eq!(table.wait_snapshot(open), Ok(WaitValue::NeverSleep));
        assert!(matches!(
            table.claim_open(open, owner(2)),
            Ok(Claim::Canceling(_))
        ));
        assert_eq!(table.finish_cancel(open, 5), Ok(Some(10)));
        assert_eq!(table.open_tokens().count(), 0);
        assert_eq!(table.begin_open(owner(2), 80), Err(Error::TooManyOpenFiles));
        assert_eq!(table.insert(20, Flags::default()), Ok(0));
    }

    #[test]
    fn cancelled_published_cleanup_stale_tokens_cannot_touch_new_record() {
        let mut table = Table::<u32, 1, u64>::default();
        let (old, late, _) = publish(&mut table, 10);
        table.abandon_open_with_recovery(old, 500).unwrap();
        table.finish_cancel(old, 5).unwrap();
        let (new, _, entry) = publish(&mut table, 20);
        let before = table.open_snapshot(new).unwrap();
        assert_eq!(table.finish_cancel(old, 5), Err(Error::BadFileDescriptor));
        assert_eq!(
            table.abandon_open_with_recovery(old, 900),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(table.ack_open(old, owner(1)), Err(Error::BadFileDescriptor));
        assert_eq!(table.publish_open(late), Err(Error::BadFileDescriptor));
        assert_eq!(
            table.claim_open(old, owner(2)),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(table.open_snapshot(new), Ok(before));
        assert_eq!(table.get(entry.fd), Ok(20));
    }

    #[test]
    fn fork_child_discards_cleanup_without_releasing_parent_target() {
        let mut table = Table::<u32, 1, u64>::default();
        let (open, _, _) = publish(&mut table, 10);
        table.abandon_open_with_recovery(open, 500).unwrap();
        table.discard_open_after_fork();
        assert_eq!(table.open_tokens().count(), 0);
        assert!(table.open_snapshot(open).is_err());
        assert_eq!(table.finish_cancel(open, 5), Err(Error::BadFileDescriptor));
        assert!(table.begin_open(owner(2), 80).is_ok());
    }

    /// A table of 4 numbers in place and 3 pages of 4 more, and the pages
    /// the test gives it (leaked: the table keeps them for its life).
    use std::{boxed::Box, vec, vec::Vec};

    type Paged = Table<u32, 4, u64, (), (), 3>;

    fn page(table: &mut Paged, k: usize) {
        let memory = Box::leak(Box::new(
            core::mem::MaybeUninit::<EntryPage<u32, 4>>::uninit(),
        ));
        // Memory that is not zero, as a heap page that was used before.
        // SAFETY: the leaked box is writable for its size.
        unsafe { core::ptr::write_bytes(memory.as_mut_ptr(), 0xA5, 1) };
        // SAFETY: the memory is aligned, writable, and leaked for good.
        assert!(unsafe { table.add_page(k, NonNull::new(memory.as_mut_ptr()).unwrap()) });
    }

    #[test]
    fn a_number_in_a_page_that_is_not_there_asks_for_it() {
        let mut table = Paged::default();
        for fd in 0..4 {
            assert_eq!(table.insert(10 + fd, Flags::default()), Ok(fd));
        }
        assert_eq!(table.insert(14, Flags::default()), Err(Error::NeedPage(0)));
        assert_eq!(table.place(9, 1, Flags::default()), Err(Error::NeedPage(1)));
        assert_eq!(table.dup2(0, 9), Err(Error::NeedPage(1)));
        assert_eq!(table.get(9), Err(Error::BadFileDescriptor));
        // Out of the numbers of the table: no page helps.
        assert_eq!(
            table.place(16, 1, Flags::default()),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(table.dup2(0, 16), Err(Error::BadFileDescriptor));
    }

    #[test]
    fn a_page_starts_empty() {
        let mut table = Paged::default();
        page(&mut table, 0);
        assert!(table.has_page(0));
        for fd in 4..8 {
            assert_eq!(table.get(fd), Err(Error::BadFileDescriptor));
            assert_eq!(table.entry_token(fd), Err(Error::BadFileDescriptor));
            assert_eq!(table.slot(fd).unwrap().generation, 0);
        }
        assert_eq!(table.open().count(), 0);
        assert_eq!(table.vacant(4), Ok(4));
        // A second page for the same place is refused and leaves the first.
        table.place(5, 55, Flags::default()).unwrap();
        let memory = Box::leak(Box::new(
            core::mem::MaybeUninit::<EntryPage<u32, 4>>::uninit(),
        ));
        // SAFETY: as above.
        assert!(!unsafe { table.add_page(0, NonNull::new(memory.as_mut_ptr()).unwrap()) });
        assert_eq!(table.get(5), Ok(55));
    }

    #[test]
    fn vacant_goes_through_the_border_of_a_page() {
        let mut table = Paged::default();
        page(&mut table, 0);
        for fd in 0..8 {
            assert_eq!(table.insert(fd, Flags::default()), Ok(fd));
        }
        // The ninth number is in the second page.
        assert_eq!(table.insert(8, Flags::default()), Err(Error::NeedPage(1)));
        page(&mut table, 1);
        assert_eq!(table.insert(8, Flags::default()), Ok(8));
        // The least free number is found again after a close in a page.
        table.close(6).unwrap();
        assert_eq!(table.insert(66, Flags::default()), Ok(6));
        assert_eq!(table.vacant(7), Ok(9));
        assert_eq!(table.vacant(0), Ok(9));
    }

    #[test]
    fn the_allocation_limit_stops_below_a_page() {
        let mut table = Paged::default();
        table.set_allocation_limit(6);
        for fd in 0..4 {
            table.insert(fd, Flags::default()).unwrap();
        }
        // Number 4 is below the limit but its page is not there.
        assert_eq!(table.insert(4, Flags::default()), Err(Error::NeedPage(0)));
        page(&mut table, 0);
        assert_eq!(table.insert(4, Flags::default()), Ok(4));
        assert_eq!(table.insert(5, Flags::default()), Ok(5));
        // The limit ends the numbers: no page is asked for past it.
        assert_eq!(
            table.insert(6, Flags::default()),
            Err(Error::TooManyOpenFiles)
        );
        assert_eq!(table.dup2(0, 6), Err(Error::BadFileDescriptor));
        table.set_allocation_limit(1_000_000);
        assert_eq!(table.insert(6, Flags::default()), Ok(6));
    }

    #[test]
    fn the_generation_of_a_number_in_a_page_grows() {
        let mut table = Paged::default();
        page(&mut table, 0);
        table.place(5, 50, Flags::default()).unwrap();
        let first = table.entry_token(5).unwrap();
        table.close(5).unwrap();
        table.place(5, 51, Flags::default()).unwrap();
        let second = table.entry_token(5).unwrap();
        assert!(second.generation() > first.generation());
        assert_ne!(first, second);
    }

    #[test]
    fn the_walks_see_the_numbers_in_use_only() {
        let mut table = Paged::default();
        page(&mut table, 0);
        page(&mut table, 1);
        table.place(2, 20, Flags::default()).unwrap();
        table.place(7, 70, Flags::default()).unwrap();
        table.place(11, 70, Flags::default()).unwrap();
        let open: Vec<_> = table.open().map(|(fd, b, _)| (fd, b)).collect();
        assert_eq!(open, vec![(2, 20), (7, 70), (11, 70)]);
        assert!(table.has_open_alias(7));
        assert!(table.has_open_alias(11));
        assert!(!table.has_open_alias(2));
        assert_eq!(table.close(7), Ok(None));
        assert!(!table.has_open_alias(11));
        assert_eq!(table.close(11), Ok(Some(70)));
        let open: Vec<_> = table.open().map(|(fd, _, _)| fd).collect();
        assert_eq!(open, vec![2]);
    }

    #[test]
    fn a_reservation_in_a_page_counts_in_the_bitmap_and_goes_after_a_fork() {
        let mut table = Paged::default();
        page(&mut table, 0);
        for fd in 0..4 {
            table.place(fd, fd, Flags::default()).unwrap();
        }
        let (open, claim) = table.begin_open(owner(1), 5).unwrap();
        let entry = table
            .reserve_open(claim, 4, Flags::default())
            .expect("the number 4 is free and its page is there");
        assert_eq!(entry.fd, 4);
        assert_eq!(table.vacant(0), Ok(5));
        table.discard_open_after_fork();
        assert_eq!(table.vacant(0), Ok(4));
        let _ = open;
    }
}
