// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The owners of the signals of sockets (`fcntl` F_SETOWN and F_GETOWN) and
//! their asynchronous flags (`ioctl` FIOASYNC), one record for a descriptor
//! (its number and the generation of its entry). A record whose descriptor
//! is gone is free again. The layer keeps one table under the lock of the
//! descriptors (posix_abi::owners).

/// EINVAL of Linux: the table holds as many live records as it can.
const EINVAL: i32 = 22;

/// The records at most: nginx sets one owner on each channel of a worker.
pub const OWNERS: usize = 16;

/// One record: the descriptor, the generation of its entry, the owner (a
/// PID, or a process group negated) and the asynchronous flag.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Record {
    fd: u32,
    generation: u64,
    owner: i32,
    asynchronous: bool,
}

/// The records of the process.
#[derive(Debug)]
pub struct Owners {
    records: [Option<Record>; OWNERS],
}

impl Default for Owners {
    fn default() -> Self {
        Owners::new()
    }
}

impl Owners {
    pub const fn new() -> Owners {
        Owners {
            records: [None; OWNERS],
        }
    }

    fn find(&self, fd: u32, generation: u64) -> Option<usize> {
        self.records
            .iter()
            .position(|r| r.is_some_and(|r| r.fd == fd && r.generation == generation))
    }

    /// The record of the descriptor, made when it has none: a record whose
    /// descriptor is gone (`live` false) is taken. None when all are live.
    fn record(
        &mut self,
        fd: u32,
        generation: u64,
        live: impl Fn(u32, u64) -> bool,
    ) -> Option<&mut Record> {
        let at = match self.find(fd, generation) {
            Some(at) => at,
            None => {
                let at = self
                    .records
                    .iter()
                    .position(|r| r.is_none_or(|r| !live(r.fd, r.generation)))?;
                self.records[at] = Some(Record {
                    fd,
                    generation,
                    ..Record::default()
                });
                at
            }
        };
        self.records[at].as_mut()
    }

    /// F_SETOWN: EINVAL when the table holds as many live records as it can.
    pub fn set_owner(
        &mut self,
        fd: u32,
        generation: u64,
        owner: i32,
        live: impl Fn(u32, u64) -> bool,
    ) -> Result<(), i32> {
        self.record(fd, generation, live).ok_or(EINVAL)?.owner = owner;
        Ok(())
    }

    /// F_GETOWN: 0 when none was set.
    pub fn owner(&self, fd: u32, generation: u64) -> i32 {
        self.find(fd, generation)
            .and_then(|at| self.records[at])
            .map_or(0, |r| r.owner)
    }

    /// FIOASYNC.
    pub fn set_asynchronous(
        &mut self,
        fd: u32,
        generation: u64,
        on: bool,
        live: impl Fn(u32, u64) -> bool,
    ) -> Result<(), i32> {
        self.record(fd, generation, live)
            .ok_or(EINVAL)?
            .asynchronous = on;
        Ok(())
    }

    pub fn asynchronous(&self, fd: u32, generation: u64) -> bool {
        self.find(fd, generation)
            .and_then(|at| self.records[at])
            .is_some_and(|r| r.asynchronous)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_owner_is_kept_for_its_descriptor_and_read_back() {
        let mut t = Owners::new();
        let all = |_: u32, _: u64| true;
        assert_eq!(t.owner(3, 1), 0);
        t.set_owner(3, 1, 42, all).unwrap();
        assert_eq!(t.owner(3, 1), 42);
        // Another generation of the same number is another descriptor.
        assert_eq!(t.owner(3, 2), 0);
        t.set_owner(3, 1, -7, all).unwrap();
        assert_eq!(t.owner(3, 1), -7);
        t.set_asynchronous(3, 1, true, all).unwrap();
        assert!(t.asynchronous(3, 1));
        assert_eq!(t.owner(3, 1), -7);
    }

    #[test]
    fn the_seventeenth_live_record_is_refused_and_a_dead_one_is_taken() {
        let mut t = Owners::new();
        let all = |_: u32, _: u64| true;
        for fd in 0..OWNERS as u32 {
            t.set_owner(fd, 1, fd as i32 + 100, all).unwrap();
        }
        assert_eq!(t.set_owner(99, 1, 5, all), Err(EINVAL));
        // Descriptor 4 closed: its record is free.
        let live = |fd: u32, _: u64| fd != 4;
        t.set_owner(99, 1, 5, live).unwrap();
        assert_eq!(t.owner(99, 1), 5);
        assert_eq!(t.owner(4, 1), 0);
        assert_eq!(t.owner(5, 1), 105);
    }
}
