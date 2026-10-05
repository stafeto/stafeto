// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process-local descriptors sharing backend open descriptions. The owner
//! serializes table access and releases backends after unlocking. Ordinary
//! operation holds and resident Open/Scalar records share the fixed hold budget.
//! A live Open record preserves its completion through fd replacement.
//! The caller pins this table's address while records or waiters exist.

#![no_std]

mod io;
pub use io::*;
mod control;
mod scalar;
pub use control::*;
pub use scalar::*;

use core::{
    num::NonZeroU64,
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
        self.slot
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
    Open(Entry<T>),
}

#[derive(Clone, Copy)]
struct EntrySlot<T> {
    generation: u64,
    state: EntryState<T>,
}

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

pub struct Table<T: Copy + Eq, const N: usize, R: Copy = (), S: Copy = (), C: Copy = ()> {
    entries: [EntrySlot<T>; N],
    holds: [HoldSlot<T, R, S, C>; N],
    release_early: fn(T) -> bool,
}

impl<T: Copy + Eq, const N: usize, R: Copy, S: Copy, C: Copy> Default for Table<T, N, R, S, C> {
    fn default() -> Self {
        Self {
            entries: [EntrySlot {
                generation: 0,
                state: EntryState::Empty,
            }; N],
            holds: [const {
                HoldSlot {
                    generation: 0,
                    changed: AtomicU32::new(0),
                    held: Held::Empty,
                }
            }; N],
            release_early: |_| false,
        }
    }
}

impl<T: Copy + Eq, const N: usize, R: Copy, S: Copy, C: Copy> Table<T, N, R, S, C> {
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
        // SAFETY: exclusive startup ownership permits initializing this field.
        unsafe {
            core::ptr::addr_of_mut!((*destination).release_early).write(release_early);
        }
    }

    fn entry(&self, fd: u32) -> Result<Entry<T>, Error> {
        match self.entries.get(fd as usize).map(|slot| slot.state) {
            Some(EntryState::Open(entry)) => Ok(entry),
            _ => Err(Error::BadFileDescriptor),
        }
    }

    pub fn get(&self, fd: u32) -> Result<T, Error> {
        Ok(self.entry(fd)?.backend)
    }

    pub fn flags(&self, fd: u32) -> Result<Flags, Error> {
        Ok(self.entry(fd)?.flags)
    }

    pub fn set_flags(&mut self, fd: u32, flags: Flags) -> Result<(), Error> {
        let backend = self.get(fd)?;
        self.entries[fd as usize].state = EntryState::Open(Entry { backend, flags });
        Ok(())
    }

    pub fn entry_token(&self, fd: u32) -> Result<EntryToken, Error> {
        self.entry(fd)?;
        Ok(EntryToken::new(fd, self.entries[fd as usize].generation))
    }

    /// Published descriptors form the fork and exec snapshot.
    pub fn open(&self) -> impl Iterator<Item = (u32, T, Flags)> + '_ {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(fd, slot)| match slot.state {
                EntryState::Open(e) => Some((fd as u32, e.backend, e.flags)),
                _ => None,
            })
    }

    pub fn vacant(&self, minimum: u32) -> Result<u32, Error> {
        if minimum as usize >= N {
            return Err(Error::InvalidArgument);
        }
        self.entries
            .iter()
            .enumerate()
            .skip(minimum as usize)
            .find(|(_, slot)| matches!(slot.state, EntryState::Empty))
            .map(|(fd, _)| fd as u32)
            .ok_or(Error::TooManyOpenFiles)
    }

    fn install(&mut self, fd: u32, backend: T, flags: Flags) -> Result<(), Error> {
        let slot = &mut self.entries[fd as usize];
        let generation = slot.generation.checked_add(1).ok_or(Error::Io)?;
        slot.generation = generation;
        slot.state = EntryState::Open(Entry { backend, flags });
        Ok(())
    }

    pub fn insert(&mut self, backend: T, flags: Flags) -> Result<u32, Error> {
        self.insert_at_free(backend, 0, flags)
    }

    pub fn duplicate(&mut self, fd: u32, minimum: u32, flags: Flags) -> Result<u32, Error> {
        let backend = self.get(fd)?;
        self.insert_at_free(backend, minimum, flags)
    }

    fn insert_at_free(&mut self, backend: T, minimum: u32, flags: Flags) -> Result<u32, Error> {
        let fd = self.vacant(minimum)?;
        self.install(fd, backend, flags)?;
        Ok(fd)
    }

    fn referenced(&self, backend: T) -> bool {
        self.entries
            .iter()
            .any(|slot| matches!(slot.state, EntryState::Open(e) if e.backend == backend))
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
        self.entries[fd as usize].state = EntryState::Empty;
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
        let EntryState::Pending(slot) = self.entries.get(fd as usize)?.state else {
            return None;
        };
        let held = self.holds.get(slot)?;
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
        if target as usize >= N {
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
        if let Some(token) = self.pending(target) {
            return Ok(Replacement::Pending(token));
        }
        let old = self.entry(target).ok();
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
        let slot = self
            .entries
            .get(fd as usize)
            .ok_or(Error::BadFileDescriptor)?;
        if !matches!(slot.state, EntryState::Empty) {
            return Err(Error::BadFileDescriptor);
        }
        self.install(fd, backend, flags)
    }

    fn record(&self, token: OpenToken) -> Result<OpenRecord<T, R>, Error> {
        let slot = self.holds.get(token.slot).ok_or(Error::BadFileDescriptor)?;
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
        let slot = &mut self.holds[token.slot];
        slot.held = Held::Open(record);
        slot.change();
    }

    fn free_open(&mut self, token: OpenToken) {
        let slot = &mut self.holds[token.slot];
        slot.held = Held::Empty;
        slot.change();
    }

    /// Pay a resident record before Prepare or any irreversible effect.
    pub fn begin_open(
        &mut self,
        owner: OwnerToken,
        recovery: R,
    ) -> Result<(OpenToken, ClaimToken), Error> {
        let (index, slot) = self
            .holds
            .iter_mut()
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
        self.holds.iter().enumerate().filter_map(|(slot, h)| {
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
        let fd = self.vacant(minimum)?;
        let slot = &mut self.entries[fd as usize];
        let generation = slot.generation.checked_add(1).ok_or(Error::Io)?;
        let entry = EntryToken::new(fd, generation);
        slot.generation = generation;
        slot.state = EntryState::Pending(claim.open.slot);
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
        self.entries[entry.fd as usize].state = EntryState::Empty;
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
        self.entries.get(entry.fd as usize).is_some_and(|slot| {
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
        self.entries[entry.fd as usize].state = EntryState::Open(Entry { backend, flags });
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
            self.entries[entry.fd as usize].state = EntryState::Empty;
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
        let (slot, record) = self
            .holds
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
            generation: self.holds[slot].generation,
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
        for entry in &mut self.entries {
            if matches!(entry.state, EntryState::Pending(_)) {
                entry.state = EntryState::Empty;
            }
        }
        for slot in &mut self.holds {
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
    }

    /// This address remains stable through slot reuse. The caller pins Table.
    /// Wake occurs after unlocking; every waiter then revalidates its token.
    pub fn wait_word(&self, token: OpenToken) -> Result<&AtomicU32, Error> {
        self.holds
            .get(token.slot)
            .map(|slot| &slot.changed)
            .ok_or(Error::BadFileDescriptor)
    }

    pub fn wait_snapshot(&self, token: OpenToken) -> Result<WaitValue, Error> {
        self.record(token)?;
        let sequence = self.holds[token.slot].changed.load(Ordering::Acquire);
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
        for i in 0..32 {
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
        let Held::Open(record) = &mut table.holds[0].held else {
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
    fn all_32_credits_are_shared_by_io_and_unacked_completions() {
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
        assert_eq!(table.hold(31), Err(Error::TooManyOpenFiles));
        assert_eq!(table.hold(0), Ok(0));
        assert_eq!(table.close(31), Ok(Some(31)));
        assert_eq!(table.begin_open(owner(1), ()), Err(Error::TooManyOpenFiles));
        table.ack_open(opens[15].unwrap(), owner(1)).unwrap();
        assert!(table.begin_open(owner(1), ()).is_ok());
        assert_eq!(table.abandon_hold(), None);
        assert_eq!(table.open_tokens().count(), 16);
    }

    #[test]
    fn exhausted_generations_reject_admission_and_existing_cleanup_finishes() {
        let mut table = Table::<u32, 1>::default();
        table.holds[0].generation = u64::MAX - 1;
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
        let Held::Open(record) = &mut table.holds[0].held else {
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
        table.holds[0]
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
        let Held::Open(record) = &mut table.holds[0].held else {
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
        let Held::Open(record) = table.holds[0].held else {
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
    fn published_cleanup_stays_paid_in_full_mixed_32_budget() {
        let mut table = Table::<u32, 32, u64>::default();
        for backend in 0..31 {
            let fd = table.insert(backend, Flags::default()).unwrap();
            table.hold(fd).unwrap();
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
        table.holds[0].generation = u64::MAX - 1;
        let (open, _, _) = publish(&mut table, 10);
        let Held::Open(record) = &mut table.holds[0].held else {
            panic!("open")
        };
        record.serial = u64::MAX;
        table.holds[0].changed.store(u32::MAX, Ordering::Relaxed);
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
}
