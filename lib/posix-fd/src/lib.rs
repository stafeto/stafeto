// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process-local descriptors sharing backend open descriptions. The owner
//! serializes mutations; the table deliberately cannot be cloned. Backend
//! ownership ends after the last local reference: a close or a replacement
//! hands the backend back to the caller to release, which it does after it
//! let go of the owner (spec 2, 3.4; 5c). A backend an operation holds
//! (`hold`) outside the owner's lock ordinarily goes at its last `unhold`.
//! Early release backends keep operation references at their service; the
//! local hold records their released generation until the request ends.

#![no_std]

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

#[derive(Clone, Copy)]
struct Entry<T> {
    backend: T,
    flags: Flags,
}

/// A backend held by operations outside the owner's lock: how many hold
/// it, and whether its last descriptor went meanwhile.
#[derive(Clone, Copy)]
struct Hold<T> {
    backend: T,
    count: u16,
    closed: bool,
    released: bool,
}

pub struct Table<T: Copy + Eq, const N: usize> {
    entries: [Option<Entry<T>>; N],
    holds: [Option<Hold<T>>; N],
    release_early: fn(T) -> bool,
}

impl<T: Copy + Eq, const N: usize> Default for Table<T, N> {
    fn default() -> Self {
        Self {
            entries: [None; N],
            holds: [None; N],
            release_early: |_| false,
        }
    }
}

impl<T: Copy + Eq, const N: usize> Table<T, N> {
    /// Release the real backend when its last fd closes. Operations retain
    /// their own generation references at the service.
    pub fn with_early_release(release_early: fn(T) -> bool) -> Self {
        Self {
            release_early,
            ..Self::default()
        }
    }

    fn entry(&self, fd: u32) -> Result<Entry<T>, Error> {
        self.entries
            .get(fd as usize)
            .copied()
            .flatten()
            .ok_or(Error::BadFileDescriptor)
    }

    pub fn get(&self, fd: u32) -> Result<T, Error> {
        Ok(self.entry(fd)?.backend)
    }

    pub fn flags(&self, fd: u32) -> Result<Flags, Error> {
        Ok(self.entry(fd)?.flags)
    }

    pub fn set_flags(&mut self, fd: u32, flags: Flags) -> Result<(), Error> {
        self.entry(fd)?;
        self.entries[fd as usize].as_mut().unwrap().flags = flags;
        Ok(())
    }

    /// The descriptors that are open, with their backends and flags.
    pub fn open(&self) -> impl Iterator<Item = (u32, T, Flags)> + '_ {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(fd, e)| e.map(|e| (fd as u32, e.backend, e.flags)))
    }

    /// Return the lowest free descriptor at least `minimum` without allocating it.
    pub fn vacant(&self, minimum: u32) -> Result<u32, Error> {
        if minimum as usize >= N {
            return Err(Error::InvalidArgument);
        }
        self.entries
            .iter()
            .enumerate()
            .skip(minimum as usize)
            .find(|(_, entry)| entry.is_none())
            .map(|(slot, _)| slot as u32)
            .ok_or(Error::TooManyOpenFiles)
    }

    pub fn insert(&mut self, backend: T, flags: Flags) -> Result<u32, Error> {
        self.insert_at_free(backend, 0, flags)
    }

    /// F_DUPFD-style allocation. Flags belong to the descriptor.
    pub fn duplicate(&mut self, fd: u32, minimum: u32, flags: Flags) -> Result<u32, Error> {
        let backend = self.get(fd)?;
        self.insert_at_free(backend, minimum, flags)
    }

    fn insert_at_free(&mut self, backend: T, minimum: u32, flags: Flags) -> Result<u32, Error> {
        let fd = self.vacant(minimum)?;
        self.entries[fd as usize] = Some(Entry { backend, flags });
        Ok(fd)
    }

    fn referenced(&self, backend: T) -> bool {
        self.entries.iter().flatten().any(|e| e.backend == backend)
    }

    /// `backend` lost a descriptor: the caller releases it when no other
    /// descriptor names it and no operation holds it; a held one goes at
    /// its last `unhold`. An early release backend goes at this close,
    /// and the hold remembers that the release already happened.
    fn left(&mut self, backend: T) -> Option<T> {
        if self.referenced(backend) {
            return None;
        }
        match self
            .holds
            .iter_mut()
            .flatten()
            .find(|h| h.backend == backend)
        {
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

    /// The backend of `fd`, held for an operation the caller makes outside
    /// the owner's lock. Ordinary backends remain open until `unhold`;
    /// early release backends keep their armed operations in the service.
    /// TooManyOpenFiles with N backends held.
    pub fn hold(&mut self, fd: u32) -> Result<T, Error> {
        let backend = self.get(fd)?;
        if let Some(hold) = self
            .holds
            .iter_mut()
            .flatten()
            .find(|h| h.backend == backend)
        {
            hold.count += 1;
            return Ok(backend);
        }
        let free = self
            .holds
            .iter_mut()
            .find(|h| h.is_none())
            .ok_or(Error::TooManyOpenFiles)?;
        *free = Some(Hold {
            backend,
            count: 1,
            closed: false,
            released: false,
        });
        Ok(backend)
    }

    /// An operation's hold of `backend` ends: the backend to release when
    /// it was the last and the backend's last descriptor went meanwhile.
    pub fn unhold(&mut self, backend: T) -> Option<T> {
        let slot = self
            .holds
            .iter_mut()
            .find(|h| h.is_some_and(|h| h.backend == backend))?;
        let hold = slot.as_mut().expect("a hold");
        hold.count -= 1;
        if hold.count > 0 {
            return None;
        }
        let closed = hold.closed && !hold.released;
        *slot = None;
        (closed && !self.referenced(backend)).then_some(backend)
    }

    /// The holds of operations that never end go (the other threads of a
    /// process that execs, stopped for good), one call at a time: the next
    /// backend whose last descriptor went meanwhile, to release; None once
    /// no hold is left.
    pub fn abandon_hold(&mut self) -> Option<T> {
        while let Some(slot) = self.holds.iter_mut().find(|h| h.is_some()) {
            let hold = slot.take().expect("a hold");
            if hold.closed && !hold.released && !self.referenced(hold.backend) {
                return Some(hold.backend);
            }
        }
        None
    }

    /// Close: the descriptor goes at once; the backend to release, when it
    /// was the last that named it and either nothing holds it or its
    /// service retains armed operation references independently.
    pub fn close(&mut self, fd: u32) -> Result<Option<T>, Error> {
        let backend = self.get(fd)?;
        self.entries[fd as usize] = None;
        Ok(self.left(backend))
    }

    pub fn dup2(&mut self, source: u32, target: u32) -> Result<(u32, Option<T>), Error> {
        self.replace(source, target, Flags::default(), true)
    }

    pub fn dup3(
        &mut self,
        source: u32,
        target: u32,
        flags: Flags,
    ) -> Result<(u32, Option<T>), Error> {
        self.replace(source, target, flags, false)
    }

    /// `target` names `source`'s backend with `flags`: the target and the
    /// backend it named before to release (as `close`).
    fn replace(
        &mut self,
        source: u32,
        target: u32,
        flags: Flags,
        allow_same: bool,
    ) -> Result<(u32, Option<T>), Error> {
        let backend = self.get(source)?;
        if target as usize >= N {
            return Err(Error::BadFileDescriptor);
        }
        if source == target {
            return if allow_same {
                Ok((target, None))
            } else {
                Err(Error::InvalidArgument)
            };
        }
        let old = self.entries[target as usize].replace(Entry { backend, flags });
        let release = old
            .filter(|old| old.backend != backend)
            .and_then(|old| self.left(old.backend));
        Ok((target, release))
    }

    /// A descriptor at `fd` of `backend` with `flags`, for a table a
    /// process starts with (its parent's, spec 2, 3.2): BadFileDescriptor
    /// past N or for a number already open.
    pub fn place(&mut self, fd: u32, backend: T, flags: Flags) -> Result<(), Error> {
        let slot = self
            .entries
            .get_mut(fd as usize)
            .ok_or(Error::BadFileDescriptor)?;
        if slot.is_some() {
            return Err(Error::BadFileDescriptor);
        }
        *slot = Some(Entry { backend, flags });
        Ok(())
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
}
