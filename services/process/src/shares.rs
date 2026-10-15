// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The rendezvous of shared memory (POSIX `mmap` with MAP_SHARED, `shm_open`;
//! Ф8): the objects that processes map as the same pages, by the key of the
//! file they show. The first process to ask makes the object and says so
//! (Reserve); the others who ask meanwhile wait (Busy) and then get a
//! handle of it. An entry lives as long as a process uses it: a process
//! that unmaps its last piece detaches, and the end of a process (or the
//! exec of a new image in it) detaches it from every entry; the last to go
//! frees the entry and the service's handle, so the object goes with the
//! last mapping. O(SHARES) a call, with SHARES = 16 entries.

use proto_process::RECORDS;

/// The entries of the table.
pub const SHARES: usize = 16;

const WORDS: usize = RECORDS.div_ceil(64);

/// What the table answers to Get.
#[derive(Debug, PartialEq, Eq)]
pub enum Got<'a, T> {
    /// The object: its pages and the service's handle, to copy.
    Found(u32, &'a T),
    /// There is none, and the caller makes it (an entry waits for its Put).
    Reserved,
    /// There is none and the table has no place: the caller makes an object
    /// that is not registered.
    Full,
    /// Another process makes it now.
    Busy,
}

enum State<T> {
    /// A process makes the object: the record of that process.
    Making(usize),
    Ready {
        pages: u32,
        memory: T,
    },
}

struct Entry<T> {
    key: u64,
    state: State<T>,
    users: [u64; WORDS],
}

/// The grants at most; a grant that finds the table full takes the place of
/// the oldest.
pub const GRANTS: usize = 64;

/// What a file service said of a process: it may map the shared memory of
/// the file of `key`, for writing when `write`.
#[derive(Clone, Copy)]
struct Grant {
    record: u16,
    key: u64,
    write: bool,
}

pub struct Shares<T> {
    entries: [Option<Entry<T>>; SHARES],
    grants: [Option<Grant>; GRANTS],
    next_grant: usize,
}

impl<T> Shares<T> {
    pub const fn new() -> Self {
        Shares {
            entries: [const { None }; SHARES],
            grants: [const { None }; GRANTS],
            next_grant: 0,
        }
    }

    /// The file service vouches that the process in `record` has the file
    /// of `key` open: for reading, and for writing when `write`.
    pub fn grant(&mut self, record: usize, key: u64, write: bool) {
        let record = record as u16;
        let place = self
            .grants
            .iter()
            .position(|g| g.is_some_and(|g| g.record == record && g.key == key))
            .or_else(|| self.grants.iter().position(Option::is_none))
            .unwrap_or_else(|| {
                let place = self.next_grant;
                self.next_grant = (place + 1) % GRANTS;
                place
            });
        self.grants[place] = Some(Grant { record, key, write });
    }

    /// Whether the process in `record` may map the file of `key`: Some(write).
    pub fn granted(&self, record: usize, key: u64) -> Option<bool> {
        self.grants
            .iter()
            .flatten()
            .find(|g| usize::from(g.record) == record && g.key == key)
            .map(|g| g.write)
    }

    fn find(&self, key: u64) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.as_ref().is_some_and(|e| e.key == key))
    }

    fn add_user(entry: &mut Entry<T>, record: usize) {
        entry.users[record / 64] |= 1 << (record % 64);
    }

    /// The caller in `record` asks for the object of `key`; it is a user of
    /// the entry from here on.
    pub fn get(&mut self, key: u64, record: usize, may_make: bool) -> Got<'_, T> {
        match self.find(key) {
            Some(i) => {
                let entry = self.entries[i].as_mut().expect("an entry");
                match &entry.state {
                    State::Making(owner) if *owner != record => Got::Busy,
                    State::Making(_) => Got::Reserved,
                    State::Ready { .. } => {
                        Self::add_user(entry, record);
                        let State::Ready { pages, memory } = &entry.state else {
                            unreachable!()
                        };
                        Got::Found(*pages, memory)
                    }
                }
            }
            None => {
                let Some(place) = self.entries.iter().position(Option::is_none) else {
                    return Got::Full;
                };
                if !may_make {
                    return Got::Full;
                }
                let mut entry = Entry {
                    key,
                    state: State::Making(record),
                    users: [0; WORDS],
                };
                Self::add_user(&mut entry, record);
                self.entries[place] = Some(entry);
                Got::Reserved
            }
        }
    }

    /// The caller made the object of the entry it reserved: false when it
    /// reserved none (the object is not kept then).
    pub fn put(&mut self, key: u64, record: usize, pages: u32, memory: T) -> Result<(), T> {
        let Some(i) = self.find(key) else {
            return Err(memory);
        };
        let entry = self.entries[i].as_mut().expect("an entry");
        if !matches!(entry.state, State::Making(owner) if owner == record) {
            return Err(memory);
        }
        entry.state = State::Ready { pages, memory };
        Ok(())
    }

    /// A process that maps an object it has already (a forked child) joins
    /// the entry of its key, which it makes when the entry went meanwhile.
    pub fn attach(&mut self, key: u64, record: usize, pages: u32, memory: T) {
        match self.find(key) {
            Some(i) => {
                let entry = self.entries[i].as_mut().expect("an entry");
                if matches!(entry.state, State::Ready { .. }) {
                    Self::add_user(entry, record);
                }
            }
            None => {
                if let Some(place) = self.entries.iter().position(Option::is_none) {
                    let mut entry = Entry {
                        key,
                        state: State::Ready { pages, memory },
                        users: [0; WORDS],
                    };
                    Self::add_user(&mut entry, record);
                    self.entries[place] = Some(entry);
                }
            }
        }
    }

    fn settle(&mut self, i: usize) {
        let empty = self.entries[i]
            .as_ref()
            .is_some_and(|e| e.users.iter().all(|w| *w == 0));
        if empty {
            self.entries[i] = None;
        }
    }

    /// The caller gives up what it reserved (it could not make the object) or
    /// unmapped the last piece of it.
    pub fn detach(&mut self, key: u64, record: usize) {
        if let Some(i) = self.find(key) {
            let entry = self.entries[i].as_mut().expect("an entry");
            entry.users[record / 64] &= !(1 << (record % 64));
            self.settle(i);
        }
    }

    /// The process in `record` is gone (or its image is): it uses nothing.
    pub fn drop_user(&mut self, record: usize) {
        for grant in &mut self.grants {
            if grant.is_some_and(|g| usize::from(g.record) == record) {
                *grant = None;
            }
        }
        for i in 0..SHARES {
            if let Some(entry) = self.entries[i].as_mut() {
                entry.users[record / 64] &= !(1 << (record % 64));
                self.settle(i);
            }
        }
    }

    /// The entries in use.
    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Default for Shares<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first asker makes the object, a second asker meanwhile waits and
    /// then gets it; the entry goes with its last user.
    #[test]
    fn the_first_makes_the_object_and_the_rest_wait_then_share() {
        let mut t = Shares::<u32>::new();
        assert_eq!(t.get(7, 1, true), Got::Reserved);
        assert_eq!(t.get(7, 2, true), Got::Busy);
        assert_eq!(t.put(7, 2, 4, 99), Err(99), "not the maker");
        assert_eq!(t.put(7, 1, 4, 55), Ok(()));
        assert_eq!(t.get(7, 2, true), Got::Found(4, &55));
        t.detach(7, 1);
        assert_eq!(t.len(), 1);
        t.detach(7, 2);
        assert!(t.is_empty());
        assert_eq!(
            t.get(7, 3, true),
            Got::Reserved,
            "a new object after the last went"
        );
    }

    /// A maker that ended before its Put leaves nothing, and a process that
    /// ended stops using every entry.
    #[test]
    fn the_end_of_a_process_frees_what_only_it_used() {
        let mut t = Shares::<u32>::new();
        assert_eq!(t.get(1, 5, true), Got::Reserved);
        assert_eq!(t.get(2, 5, true), Got::Reserved);
        assert_eq!(t.put(2, 5, 1, 20), Ok(()));
        assert_eq!(t.get(2, 6, true), Got::Found(1, &20));
        t.drop_user(5);
        assert_eq!(t.len(), 1, "the entry a second process uses stays");
        assert_eq!(t.get(1, 6, true), Got::Reserved);
        t.drop_user(6);
        assert!(t.is_empty());
    }

    /// A grant is for one process and one file, and goes with the process;
    /// a reader makes no entry.
    #[test]
    fn grants_belong_to_a_process_and_a_file() {
        let mut t = Shares::<u32>::new();
        assert_eq!(t.granted(1, 9), None);
        t.grant(1, 9, false);
        t.grant(2, 9, true);
        assert_eq!(t.granted(1, 9), Some(false));
        assert_eq!(t.granted(2, 9), Some(true));
        assert_eq!(t.granted(1, 8), None);
        t.grant(1, 9, true);
        assert_eq!(t.granted(1, 9), Some(true));
        assert_eq!(t.get(9, 1, false), Got::Full, "a reader makes no entry");
        assert!(t.is_empty());
        t.drop_user(1);
        assert_eq!(t.granted(1, 9), None);
        assert_eq!(t.granted(2, 9), Some(true));
        for key in 0..GRANTS as u64 + 3 {
            t.grant(5, 1000 + key, false);
        }
        assert_eq!(t.granted(5, 1000), None, "the oldest made room");
        assert_eq!(t.granted(5, 1000 + GRANTS as u64 + 2), Some(false));
    }

    /// A full table makes the caller go without registering; an attach of a
    /// forked child makes the entry that went.
    #[test]
    fn a_full_table_and_an_attach() {
        let mut t = Shares::<u32>::new();
        for key in 0..SHARES as u64 {
            assert_eq!(t.get(key + 100, 1, true), Got::Reserved);
        }
        assert_eq!(t.get(1, 1, true), Got::Full);
        t.detach(100, 1);
        t.attach(100, 2, 3, 33);
        assert_eq!(t.get(100, 3, true), Got::Found(3, &33));
        t.attach(100, 4, 9, 77);
        assert_eq!(
            t.get(100, 5, true),
            Got::Found(3, &33),
            "an existing entry stays"
        );
        t.drop_user(2);
        t.drop_user(3);
        t.drop_user(4);
        t.drop_user(5);
        assert_eq!(t.len(), SHARES - 1);
    }
}
