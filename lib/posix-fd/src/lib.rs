// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process-local descriptors sharing backend open descriptions. The owner
//! serializes mutations; the table deliberately cannot be cloned. Backend
//! ownership ends after the last local reference, through a release callback.

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

pub struct Table<T: Copy + Eq, const N: usize> {
    entries: [Option<Entry<T>>; N],
}

impl<T: Copy + Eq, const N: usize> Default for Table<T, N> {
    fn default() -> Self {
        Self { entries: [None; N] }
    }
}

impl<T: Copy + Eq, const N: usize> Table<T, N> {
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

    fn last_reference(&self, backend: T) -> bool {
        self.entries
            .iter()
            .flatten()
            .filter(|entry| entry.backend == backend)
            .count()
            == 1
    }

    pub fn close(
        &mut self,
        fd: u32,
        release: impl FnOnce(T) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let backend = self.get(fd)?;
        if self.last_reference(backend) {
            release(backend)?;
        }
        self.entries[fd as usize] = None;
        Ok(())
    }

    pub fn dup2(
        &mut self,
        source: u32,
        target: u32,
        release: impl FnOnce(T) -> Result<(), Error>,
    ) -> Result<u32, Error> {
        self.replace(source, target, Flags::default(), true, release)
    }

    pub fn dup3(
        &mut self,
        source: u32,
        target: u32,
        flags: Flags,
        release: impl FnOnce(T) -> Result<(), Error>,
    ) -> Result<u32, Error> {
        self.replace(source, target, flags, false, release)
    }

    fn replace(
        &mut self,
        source: u32,
        target: u32,
        flags: Flags,
        allow_same: bool,
        release: impl FnOnce(T) -> Result<(), Error>,
    ) -> Result<u32, Error> {
        let backend = self.get(source)?;
        if target as usize >= N {
            return Err(Error::BadFileDescriptor);
        }
        if source == target {
            return if allow_same {
                Ok(target)
            } else {
                Err(Error::InvalidArgument)
            };
        }
        if let Some(old) = self.entries[target as usize]
            && old.backend != backend
            && self.last_reference(old.backend)
        {
            // Keep both descriptors and flags intact if releasing fails.
            release(old.backend)?;
        }
        self.entries[target as usize] = Some(Entry { backend, flags });
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        table
            .close(1, |backend| {
                assert_eq!(backend, 11);
                Ok(())
            })
            .unwrap();
        assert_eq!(table.duplicate(0, 1, Flags::default()), Ok(1));
        assert_eq!(table.get(1), Ok(10));
    }

    #[test]
    fn duplication_preserves_shared_ownership_until_last_close() {
        let mut table = Table::<u32, 3>::default();
        let source = table.insert(40, Flags::default()).unwrap();
        let copy = table.duplicate(source, 0, Flags::default()).unwrap();
        table
            .close(source, |_| panic!("shared backend released early"))
            .unwrap();
        assert_eq!(table.get(source), Err(Error::BadFileDescriptor));
        assert_eq!(table.get(copy), Ok(40));
        let mut releases = 0;
        table
            .close(copy, |backend| {
                assert_eq!(backend, 40);
                releases += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(releases, 1);
        assert_eq!(
            table.close(copy, |_| panic!("closed twice")),
            Err(Error::BadFileDescriptor)
        );
    }

    #[test]
    fn replacement_errors_preserve_target_and_flags() {
        let mut table = Table::<u32, 3>::default();
        let flags = Flags {
            close_on_exec: true,
            close_on_fork: true,
        };
        table.insert(10, flags).unwrap();
        table.insert(11, flags).unwrap();
        assert_eq!(
            table.dup2(9, 1, |_| panic!("invalid source released target")),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(
            table.dup2(0, 3, |_| panic!("invalid target")),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(table.dup2(0, 1, |_| Err(Error::Io)), Err(Error::Io));
        assert_eq!(table.get(1), Ok(11));
        assert_eq!(table.flags(1), Ok(flags));
        assert_eq!(
            table.dup2(0, 0, |_| panic!("self dup closed source")),
            Ok(0)
        );
        assert_eq!(table.flags(0), Ok(flags));
        assert_eq!(
            table.dup3(0, 0, Flags::default(), |_| panic!("self dup3")),
            Err(Error::InvalidArgument)
        );
        table
            .dup2(0, 1, |backend| {
                assert_eq!(backend, 11);
                Ok(())
            })
            .unwrap();
        assert_eq!(table.get(1), Ok(10));
        assert_eq!(table.flags(1), Ok(Flags::default()));
        table
            .dup2(0, 1, |_| panic!("same backend released"))
            .unwrap();
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
        table
            .dup3(0, 3, flags, |_| panic!("free target released"))
            .unwrap();
        assert_eq!(table.flags(3), Ok(flags));
        assert_eq!(table.flags(0), Ok(flags));
        assert_eq!(table.set_flags(9, flags), Err(Error::BadFileDescriptor));
        assert_eq!(table.flags(9), Err(Error::BadFileDescriptor));
    }
}
