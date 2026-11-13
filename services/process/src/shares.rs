// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The rendezvous of shared memory (POSIX `mmap` with MAP_SHARED, `shm_open`): the objects that processes map as the same pages, by the key of the
//! file they show. The first process to ask makes the object and says so
//! (Reserve); the others who ask meanwhile, a thread of the same process
//! among them, wait (Busy: the service holds their requests, `wait`, and
//! answers each when the object is there or the maker is gone, `ready`) and
//! then get a handle of it. An entry lives as long as a process uses it: a process
//! that unmaps its last piece detaches, and the end of a process (or the
//! exec of a new image in it) detaches it from every entry; the last to go
//! frees the entry and the service's handle, so the object goes with the
//! last mapping. O(SHARES) a call, with SHARES = 48 entries.
//!
//! An entry has a kind. The entries of files carry the object. The entries
//! of anonymous shared objects (`MAP_SHARED` with no file) carry none: the
//! object lives in the processes that map it, the key is made here
//! (`anon`) and the entry lives while a process uses it. Besides the users
//! an entry keeps its writers (a file's grant said write, or the object is
//! the process's own), and `held` tells what right a record has to a
//! key: that is the right the services that wait on an address ask for
//! (`Method::ShareHeld`).

use proto_process::RECORDS;

/// The entries of the table.
pub const SHARES: usize = 48;

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
    /// A process makes it now: the caller waits (`Shares::wait`), whichever
    /// process that is, its own included.
    Busy,
}

enum State<T> {
    /// A process makes the object: the record of that process.
    Making(usize),
    Ready {
        pages: u32,
        memory: T,
    },
    /// An anonymous shared object: the processes that map it keep it, the
    /// entry only says who they are.
    Anon,
}

struct Entry<T> {
    key: u64,
    state: State<T>,
    users: [u64; WORDS],
    /// The users that may write the object.
    writers: [u64; WORDS],
}

/// What right a record has to an object, as `held` tells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Held {
    None,
    Read,
    Write,
}

/// What kind of object a key names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Anon,
}

/// The grants at most, and the most one process holds: a grant is for one
/// Get or Attach that follows at once, so two serve the threads of a
/// process, and a process never takes the places of the others.
pub const GRANTS: usize = 64;
pub const GRANTS_PER_PROCESS: usize = 2;

/// What a file service said of a process: it may map the shared memory of
/// the file of `key`, for writing when `write`. Used once for each vouching.
#[derive(Clone, Copy)]
struct Grant {
    record: u16,
    key: u64,
    write: bool,
    /// The vouchings not used yet: the threads of a process that map one
    /// file together vouch once each, and each answered Get uses one up.
    count: u8,
    /// When it came, to find a process's oldest.
    age: u32,
}

/// A request of Get that waits for the object of a key, with what the
/// service answers it by (`W`: the deferred reply).
struct Waiting<W> {
    record: u16,
    key: u64,
    data: W,
    /// When it came, to answer the oldest first.
    age: u32,
}

/// The places for the requests that wait, one for each place of a grant: a
/// request waits after the grant of its process and key, and the grant
/// stays until the request is answered, so these are the requests that the
/// grants hold, but for the threads of a process that ask for one key
/// together (they share a grant), which take places of their own. No more
/// than `WAITING` wait; the rest are answered Busy at once.
pub const WAITING: usize = GRANTS;
/// The places one process may hold: the threads that map one file together
/// need a few, and one process cannot take the places of all the others.
pub const WAITING_PER_PROCESS: usize = 4;
/// The requests `ready_batch` gives at once.
pub const BATCH: usize = 2;

pub struct Shares<T, W> {
    entries: [Option<Entry<T>>; SHARES],
    grants: [Option<Grant>; GRANTS],
    waiting: [Option<Waiting<W>>; WAITING],
    ages: u32,
    /// The last key `anon` made: keys count up from 1 and never repeat
    /// while the service runs; bit 63, which the keys of files have, stays
    /// clear.
    anon_keys: u64,
}

impl<T, W> Shares<T, W> {
    /// What `new` makes, in place in zeroed memory (the service's `.bss`).
    ///
    /// # Safety
    /// `at` is valid for writes, exclusive and zeroed.
    #[cfg(target_os = "none")]
    pub unsafe fn initialize_at(at: *mut Self) {
        use core::ptr::addr_of_mut;
        // SAFETY: each field is in bounds and written once; `ages` is zero
        // in `new`.
        unsafe {
            rt::bss::fill_none(addr_of_mut!((*at).entries));
            rt::bss::fill_none(addr_of_mut!((*at).grants));
            rt::bss::fill_none(addr_of_mut!((*at).waiting));
        }
    }

    pub const fn new() -> Self {
        Shares {
            entries: [const { None }; SHARES],
            grants: [const { None }; GRANTS],
            waiting: [const { None }; WAITING],
            ages: 0,
            anon_keys: 0,
        }
    }

    /// The file service vouches that the process in `record` has the file
    /// of `key` open: for reading, and for writing when `write`. A process
    /// that holds its two grants loses its oldest to the new one; the table
    /// full of other processes' grants refuses (false), and none of theirs
    /// is touched.
    pub fn grant(&mut self, record: usize, key: u64, write: bool) -> bool {
        let record = record as u16;
        self.ages = self.ages.wrapping_add(1);
        // A second vouching of the same pair (another thread of the process
        // maps the file at once) counts up: the first answer must not take
        // the other thread's grant with it.
        if let Some(g) = self
            .grants
            .iter_mut()
            .flatten()
            .find(|g| g.record == record && g.key == key)
        {
            g.count = g.count.saturating_add(1);
            g.write |= write;
            g.age = self.ages;
            return true;
        }
        let own = |g: &Option<Grant>| g.is_some_and(|g| g.record == record);
        let full = self.grants.iter().filter(|g| own(g)).count() >= GRANTS_PER_PROCESS;
        let place = if full {
            // The oldest of its own that no request waits for.
            self.grants
                .iter()
                .enumerate()
                .filter(|(_, g)| own(g))
                .filter(|(_, g)| {
                    let g = g.expect("own");
                    !self
                        .waiting
                        .iter()
                        .flatten()
                        .any(|w| w.record == g.record && w.key == g.key)
                })
                .max_by_key(|(_, g)| self.ages.wrapping_sub(g.expect("own").age))
                .map(|(i, _)| i)
        } else {
            self.grants.iter().position(Option::is_none)
        };
        let Some(place) = place else {
            return false;
        };
        self.grants[place] = Some(Grant {
            record,
            key,
            write,
            count: 1,
            age: self.ages,
        });
        true
    }

    /// One vouching is used; the grant is gone with the last.
    pub fn revoke(&mut self, record: usize, key: u64) {
        for grant in &mut self.grants {
            if let Some(g) = grant
                && usize::from(g.record) == record
                && g.key == key
            {
                g.count = g.count.saturating_sub(1);
                if g.count == 0 {
                    *grant = None;
                }
            }
        }
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

    fn add_user(entry: &mut Entry<T>, record: usize, write: bool) {
        entry.users[record / 64] |= 1 << (record % 64);
        if write {
            entry.writers[record / 64] |= 1 << (record % 64);
        }
    }

    fn has(mask: &[u64; WORDS], record: usize) -> bool {
        mask[record / 64] & (1 << (record % 64)) != 0
    }

    /// The caller in `record` maps a new anonymous shared object: its key
    /// (made here), with the caller as its user and writer. None when the
    /// table has no place; the object then has no key.
    pub fn anon(&mut self, record: usize) -> Option<u64> {
        let place = self.entries.iter().position(Option::is_none)?;
        self.anon_keys += 1;
        let mut entry = Entry {
            key: self.anon_keys,
            state: State::Anon,
            users: [0; WORDS],
            writers: [0; WORDS],
        };
        Self::add_user(&mut entry, record, true);
        self.entries[place] = Some(entry);
        Some(self.anon_keys)
    }

    /// What right the process in `record` has to the object of `key`.
    pub fn held(&self, record: usize, kind: Kind, key: u64) -> Held {
        let Some(entry) = self
            .entries
            .iter()
            .flatten()
            .find(|e| e.key == key && matches!(e.state, State::Anon) == (kind == Kind::Anon))
        else {
            return Held::None;
        };
        if Self::has(&entry.writers, record) {
            Held::Write
        } else if Self::has(&entry.users, record) {
            Held::Read
        } else {
            Held::None
        }
    }

    /// A forked child takes the membership its parent has in the anonymous
    /// objects, as writer when the parent is. The entries of files stay as
    /// they are: the child joins them with an Attach the file service
    /// vouched for.
    pub fn fork_anon(&mut self, parent: usize, child: usize) {
        for entry in self.entries.iter_mut().flatten() {
            if matches!(entry.state, State::Anon) && Self::has(&entry.users, parent) {
                let write = Self::has(&entry.writers, parent);
                Self::add_user(entry, child, write);
            }
        }
    }

    /// The caller in `record` asks for the object of `key`; it is a user of
    /// the entry from here on.
    pub fn get(&mut self, key: u64, record: usize, may_make: bool) -> Got<'_, T> {
        match self.find(key) {
            Some(i) => {
                let entry = self.entries[i].as_mut().expect("an entry");
                match &entry.state {
                    // The maker's own process waits too, for another of its
                    // threads: two threads that map one file together make
                    // one object.
                    State::Making(_) => Got::Busy,
                    // The key of an anonymous object is no file's.
                    State::Anon => Got::Full,
                    State::Ready { .. } => {
                        Self::add_user(entry, record, may_make);
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
                    writers: [0; WORDS],
                };
                Self::add_user(&mut entry, record, true);
                self.entries[place] = Some(entry);
                Got::Reserved
            }
        }
    }

    /// The request `data` of the process in `record` for the object of
    /// `key` waits for it (after a Get that said Busy). With no place left
    /// it comes back, and the caller answers Busy.
    pub fn wait(&mut self, key: u64, record: usize, data: W) -> Result<(), W> {
        let held = self
            .waiting
            .iter()
            .flatten()
            .filter(|w| usize::from(w.record) == record)
            .count();
        if held >= WAITING_PER_PROCESS {
            return Err(data);
        }
        self.ages = self.ages.wrapping_add(1);
        let age = self.ages;
        match self.waiting.iter_mut().find(|w| w.is_none()) {
            Some(place) => {
                *place = Some(Waiting {
                    record: record as u16,
                    key,
                    data,
                    age,
                });
                Ok(())
            }
            None => Err(data),
        }
    }

    /// Up to N of the oldest waiting requests that nobody makes the object for
    /// any more: their entry is Ready, or gone with its maker. They leave the
    /// table into `out` with their record, key and `data`, and the caller
    /// asks `get` for each again. Of the requests of a key whose maker went
    /// only the oldest comes (it becomes the maker, `get` gives it Reserved),
    /// the others wait on. Gives the count taken and whether more are ready.
    /// One pass over the places and the entries, O(WAITING + SHARES) with
    /// the few entries in use, and N picks over the places.
    pub fn ready_batch<const N: usize>(
        &mut self,
        out: &mut [Option<(usize, u64, W)>; N],
    ) -> (usize, bool) {
        // The entries in use: key and whether it is made now.
        let mut known = [(0u64, false); SHARES];
        let mut count = 0;
        for e in self.entries.iter().flatten() {
            known[count] = (e.key, matches!(e.state, State::Making(_)));
            count += 1;
        }
        // 0 closed, 1 the object is there, 2 its maker went.
        let mut status = [0u8; WAITING];
        for (state, w) in status.iter_mut().zip(&self.waiting) {
            if let Some(w) = w {
                *state = match known[..count].iter().find(|(k, _)| *k == w.key) {
                    None => 2,
                    Some((_, false)) => 1,
                    Some((_, true)) => 0,
                };
            }
        }
        let ages = self.ages;
        let mut claimed = [0u64; N];
        let mut taken = 0;
        while taken < N {
            let mut best: Option<(usize, u32)> = None;
            for (i, state) in status.iter().enumerate() {
                let Some(w) = self.waiting[i].as_ref() else {
                    continue;
                };
                let open = *state == 1 || (*state == 2 && !claimed[..taken].contains(&w.key));
                let older = best.is_none_or(|(_, b)| ages.wrapping_sub(w.age) > b);
                if open && older {
                    best = Some((i, ages.wrapping_sub(w.age)));
                }
            }
            let Some((i, _)) = best else {
                break;
            };
            let w = self.waiting[i].take().expect("a waiting request");
            if status[i] == 2 {
                claimed[taken] = w.key;
            }
            out[taken] = Some((usize::from(w.record), w.key, w.data));
            status[i] = 0;
            taken += 1;
        }
        let more = status.iter().enumerate().any(|(i, state)| {
            self.waiting[i]
                .as_ref()
                .is_some_and(|w| *state == 1 || (*state == 2 && !claimed[..taken].contains(&w.key)))
        });
        (taken, more)
    }

    /// The oldest ready request, as `ready_batch` gives it.
    pub fn ready(&mut self) -> Option<(usize, u64, W)> {
        let mut out = [None];
        self.ready_batch::<1>(&mut out);
        out[0].take()
    }

    /// The requests waiting.
    pub fn waiters(&self) -> usize {
        self.waiting.iter().flatten().count()
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
    /// the entry of its key. It makes the entry when that went meanwhile, but
    /// only if it may write the file: a reader's object, whatever rights its
    /// handle has, is not what writers are to get.
    pub fn attach(&mut self, key: u64, record: usize, pages: u32, memory: T, write: bool) {
        match self.find(key) {
            Some(i) => {
                let entry = self.entries[i].as_mut().expect("an entry");
                if matches!(entry.state, State::Ready { .. }) {
                    Self::add_user(entry, record, write);
                }
            }
            None => {
                if !write {
                    return;
                }
                if let Some(place) = self.entries.iter().position(Option::is_none) {
                    let mut entry = Entry {
                        key,
                        state: State::Ready { pages, memory },
                        users: [0; WORDS],
                        writers: [0; WORDS],
                    };
                    Self::add_user(&mut entry, record, true);
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
    /// unmapped the last piece of it. True when it was a user: its right
    /// is lost, and the services that remember it must ask again.
    pub fn detach(&mut self, key: u64, record: usize) -> bool {
        let Some(i) = self.find(key) else {
            return false;
        };
        let entry = self.entries[i].as_mut().expect("an entry");
        let was = Self::has(&entry.users, record);
        entry.users[record / 64] &= !(1 << (record % 64));
        entry.writers[record / 64] &= !(1 << (record % 64));
        self.settle(i);
        was
    }

    /// The process in `record` is gone (or its image is): it uses nothing,
    /// and its requests that wait go (their replies with them). True when
    /// it was a user of an entry (its right is lost, as in `detach`).
    pub fn drop_user(&mut self, record: usize) -> bool {
        let mut lost = false;
        for request in &mut self.waiting {
            if request
                .as_ref()
                .is_some_and(|w| usize::from(w.record) == record)
            {
                *request = None;
            }
        }
        for grant in &mut self.grants {
            if grant.is_some_and(|g| usize::from(g.record) == record) {
                *grant = None;
            }
        }
        for i in 0..SHARES {
            if let Some(entry) = self.entries[i].as_mut() {
                lost |= Self::has(&entry.users, record);
                entry.users[record / 64] &= !(1 << (record % 64));
                entry.writers[record / 64] &= !(1 << (record % 64));
                self.settle(i);
            }
        }
        lost
    }

    /// The entries in use.
    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T, W> Default for Shares<T, W> {
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
        let mut t = Shares::<u32, u32>::new();
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
        let mut t = Shares::<u32, u32>::new();
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
        let mut t = Shares::<u32, u32>::new();
        assert_eq!(t.granted(1, 9), None);
        assert!(t.grant(1, 9, false));
        assert!(t.grant(2, 9, true));
        assert_eq!(t.granted(1, 9), Some(false));
        assert_eq!(t.granted(2, 9), Some(true));
        assert_eq!(t.granted(1, 8), None);
        assert!(t.grant(1, 9, true));
        assert_eq!(t.granted(1, 9), Some(true));
        assert_eq!(t.get(9, 1, false), Got::Full, "a reader makes no entry");
        assert!(t.is_empty());
        t.drop_user(1);
        assert_eq!(t.granted(1, 9), None);
        assert_eq!(t.granted(2, 9), Some(true));
        // A process holds two; its third takes the place of its oldest.
        assert!(t.grant(5, 1000, false));
        assert!(t.grant(5, 1001, false));
        assert!(t.grant(5, 1002, false));
        assert_eq!(t.granted(5, 1000), None);
        assert_eq!(t.granted(5, 1001), Some(false));
        assert_eq!(t.granted(5, 1002), Some(false));
        // A grant is used once.
        t.revoke(5, 1001);
        assert_eq!(t.granted(5, 1001), None);
        // The table full of other processes' grants refuses a new process
        // and takes nothing of theirs.
        let mut t = Shares::<u32, u32>::new();
        for record in 0..GRANTS / GRANTS_PER_PROCESS {
            for k in 0..GRANTS_PER_PROCESS as u64 {
                assert!(t.grant(record, 500 + k, true));
            }
        }
        assert!(!t.grant(200, 1, false), "no place");
        for record in 0..GRANTS / GRANTS_PER_PROCESS {
            assert_eq!(t.granted(record, 500), Some(true));
            assert_eq!(t.granted(record, 501), Some(true));
        }
        // A reader's attach makes no entry; a writer's does.
        let mut t = Shares::<u32, u32>::new();
        t.attach(7, 1, 1, 70, false);
        assert!(t.is_empty());
        t.attach(7, 1, 1, 70, true);
        assert_eq!(t.len(), 1);
    }

    /// A request that gets Busy waits, and the Put of the maker lets it go
    /// to Get again, the oldest first; the maker's own process waits too,
    /// for another thread.
    #[test]
    fn requests_wait_for_the_maker_and_go_oldest_first() {
        let mut t = Shares::<u32, u32>::new();
        assert_eq!(t.get(7, 1, true), Got::Reserved);
        assert_eq!(t.get(7, 1, true), Got::Busy, "a second thread of the maker");
        assert_eq!(t.wait(7, 1, 100), Ok(()));
        assert_eq!(t.get(7, 2, true), Got::Busy);
        assert_eq!(t.wait(7, 2, 200), Ok(()));
        assert_eq!(t.get(8, 3, true), Got::Reserved);
        assert_eq!(t.get(8, 4, true), Got::Busy);
        assert_eq!(t.wait(8, 4, 400), Ok(()));
        assert_eq!(t.waiters(), 3);
        assert_eq!(t.ready(), None, "both keys have a maker");
        assert_eq!(t.put(7, 1, 4, 55), Ok(()));
        assert_eq!(t.ready(), Some((1, 7, 100)), "the oldest first");
        assert_eq!(t.get(7, 1, true), Got::Found(4, &55));
        assert_eq!(t.ready(), Some((2, 7, 200)));
        assert_eq!(t.get(7, 2, true), Got::Found(4, &55));
        assert_eq!(t.ready(), None, "the key 8 is still made");
        assert_eq!(t.waiters(), 1);
    }

    /// A maker that goes (it detaches, or its process ends) hands the right
    /// to make to the first request that waits; the others wait on.
    #[test]
    fn the_right_to_make_passes_to_the_first_waiter() {
        let mut t = Shares::<u32, u32>::new();
        assert_eq!(t.get(7, 1, true), Got::Reserved);
        for (record, data) in [(2, 20), (3, 30), (4, 40)] {
            assert_eq!(t.get(7, record, true), Got::Busy);
            assert_eq!(t.wait(7, record, data), Ok(()));
        }
        t.detach(7, 1);
        assert_eq!(t.ready(), Some((2, 7, 20)));
        assert_eq!(
            t.get(7, 2, true),
            Got::Reserved,
            "the first becomes the maker"
        );
        assert_eq!(t.ready(), None, "the others wait for it");
        // It ends before its Put: the next one makes.
        t.drop_user(2);
        assert_eq!(t.ready(), Some((3, 7, 30)));
        assert_eq!(t.get(7, 3, true), Got::Reserved);
        assert_eq!(t.put(7, 3, 2, 9), Ok(()));
        assert_eq!(t.ready(), Some((4, 7, 40)));
        assert_eq!(t.get(7, 4, true), Got::Found(2, &9));
    }

    /// The end of a process takes its waiting requests away; a process holds
    /// WAITING_PER_PROCESS places and the table WAITING.
    #[test]
    fn a_waiter_that_ends_leaves_and_the_places_are_few() {
        let mut t = Shares::<u32, u32>::new();
        assert_eq!(t.get(7, 1, true), Got::Reserved);
        for i in 0..WAITING {
            assert_eq!(t.wait(7, 2 + i / WAITING_PER_PROCESS, i as u32), Ok(()));
        }
        assert_eq!(t.wait(7, 2, 999), Err(999), "a process holds four");
        assert_eq!(t.wait(7, 99, 999), Err(999), "no place left");
        t.drop_user(2);
        assert_eq!(t.waiters(), WAITING - WAITING_PER_PROCESS);
        assert_eq!(t.wait(7, 99, 999), Ok(()));
        assert_eq!(t.wait(7, 99, 998), Ok(()));
        for record in 3..2 + WAITING / WAITING_PER_PROCESS {
            t.drop_user(record);
        }
        t.drop_user(99);
        assert_eq!(t.waiters(), 0);
        // A reader waits too, and gets the answer Full when the maker went.
        assert_eq!(t.wait(7, 5, 5), Ok(()));
        t.detach(7, 1);
        assert_eq!(t.ready(), Some((5, 7, 5)));
        assert_eq!(t.get(7, 5, false), Got::Full);
    }

    /// The threads of a process that map one file vouch once each, and the
    /// answer to the first does not take the grant of the second; the grant
    /// of a request that waits is not pushed out by newer ones.
    #[test]
    fn a_grant_counts_the_vouchings_of_a_pair() {
        let mut t = Shares::<u32, u32>::new();
        assert!(t.grant(1, 9, true));
        assert!(t.grant(1, 9, false));
        assert_eq!(t.granted(1, 9), Some(true));
        assert_eq!(t.get(9, 1, true), Got::Reserved);
        t.revoke(1, 9);
        assert_eq!(t.granted(1, 9), Some(true), "the second thread's grant");
        assert_eq!(t.get(9, 1, true), Got::Busy);
        assert_eq!(t.wait(9, 1, 1), Ok(()));
        // Two more keys: the table of the process is full, the pair with a
        // waiting request is not the one that goes.
        assert!(t.grant(1, 10, true));
        assert!(t.grant(1, 11, true));
        assert_eq!(t.granted(1, 9), Some(true));
        assert_eq!(t.granted(1, 10), None, "the oldest without a waiter");
        assert_eq!(t.granted(1, 11), Some(true));
        // Every pair of the process with a waiter: no place.
        assert_eq!(t.get(11, 1, true), Got::Reserved);
        assert_eq!(t.get(11, 2, true), Got::Busy);
        assert_eq!(t.wait(11, 1, 2), Ok(()));
        assert!(!t.grant(1, 12, true));
        t.revoke(1, 9);
        assert_eq!(t.granted(1, 9), None);
    }

    /// A batch gives the oldest ready requests, at most N, one request of a
    /// key whose maker went, and says whether more are ready.
    #[test]
    fn a_batch_gives_the_oldest_and_one_maker_a_key() {
        let mut t = Shares::<u32, u32>::new();
        assert_eq!(t.get(7, 1, true), Got::Reserved);
        for (record, data) in [(2, 20), (3, 30), (4, 40), (5, 50)] {
            assert_eq!(t.get(7, record, true), Got::Busy);
            assert_eq!(t.wait(7, record, data), Ok(()));
        }
        let mut out = [None, None];
        assert_eq!(t.ready_batch(&mut out), (0, false));
        assert_eq!(t.put(7, 1, 3, 77), Ok(()));
        assert_eq!(t.ready_batch(&mut out), (2, true));
        assert_eq!(out, [Some((2, 7, 20)), Some((3, 7, 30))]);
        let mut out = [None, None];
        assert_eq!(t.ready_batch(&mut out), (2, false));
        assert_eq!(out, [Some((4, 7, 40)), Some((5, 7, 50))]);
        // The maker goes: of three waiters of one key only the oldest comes.
        let mut t = Shares::<u32, u32>::new();
        assert_eq!(t.get(8, 1, true), Got::Reserved);
        for (record, data) in [(2, 20), (3, 30), (4, 40)] {
            assert_eq!(t.get(8, record, true), Got::Busy);
            assert_eq!(t.wait(8, record, data), Ok(()));
        }
        t.detach(8, 1);
        let mut out = [None, None];
        assert_eq!(t.ready_batch(&mut out), (1, false));
        assert_eq!(out[0], Some((2, 8, 20)));
    }

    /// A full table makes the caller go without registering; an attach of a
    /// forked child makes the entry that went.
    #[test]
    fn a_full_table_and_an_attach() {
        let mut t = Shares::<u32, u32>::new();
        for key in 0..SHARES as u64 {
            assert_eq!(t.get(key + 100, 1, true), Got::Reserved);
        }
        assert_eq!(t.get(1, 1, true), Got::Full);
        t.detach(100, 1);
        t.attach(100, 2, 3, 33, true);
        assert_eq!(t.get(100, 3, true), Got::Found(3, &33));
        t.attach(100, 4, 9, 77, true);
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

    /// The right of a record to a key: the writer of a file, the reader of
    /// it, the maker of an anonymous object, and nobody else.
    #[test]
    fn held_tells_the_right_of_a_record() {
        let mut t = Shares::<u32, u32>::new();
        let file = proto_process::share_key(3, 9);
        assert_eq!(t.get(file, 1, true), Got::Reserved);
        assert_eq!(t.put(file, 1, 1, 10), Ok(()));
        assert_eq!(t.get(file, 2, false), Got::Found(1, &10));
        assert_eq!(t.held(1, Kind::File, file), Held::Write);
        assert_eq!(
            t.held(2, Kind::File, file),
            Held::Read,
            "a reader is no writer"
        );
        assert_eq!(t.held(3, Kind::File, file), Held::None, "a stranger");
        assert_eq!(t.held(1, Kind::File, file + 1), Held::None, "another key");
        let key = t.anon(4).expect("a place");
        assert_eq!(t.held(4, Kind::Anon, key), Held::Write);
        assert_eq!(t.held(1, Kind::Anon, key), Held::None, "a stranger");
        assert_eq!(
            t.held(4, Kind::File, key),
            Held::None,
            "the kind is part of the key"
        );
        assert_eq!(t.held(1, Kind::Anon, file), Held::None);
        // A reader's right is lost with its detach, once.
        assert!(t.detach(file, 2));
        assert!(!t.detach(file, 2), "nothing more to lose");
        assert_eq!(t.held(2, Kind::File, file), Held::None);
        assert!(t.detach(key, 4));
        assert_eq!(t.held(4, Kind::Anon, key), Held::None, "after the unmap");
        assert!(
            t.is_empty() || t.len() == 1,
            "the anonymous entry went with its user"
        );
        assert_eq!(t.len(), 1);
        // The end of a process loses what it held, and says so.
        assert!(t.drop_user(1));
        assert!(!t.drop_user(1));
        assert!(t.is_empty());
        // An attach of a reader is a reader, of a writer a writer.
        t.attach(file, 6, 1, 10, true);
        t.attach(file, 7, 1, 10, false);
        assert_eq!(t.held(6, Kind::File, file), Held::Write);
        assert_eq!(t.held(7, Kind::File, file), Held::Read);
    }

    /// A fork gives the child the parent's membership in the anonymous
    /// objects only, and only the parent's.
    #[test]
    fn a_fork_carries_the_anonymous_objects_of_the_parent() {
        let mut t = Shares::<u32, u32>::new();
        let file = proto_process::share_key(1, 1);
        assert_eq!(t.get(file, 1, true), Got::Reserved);
        assert_eq!(t.put(file, 1, 1, 10), Ok(()));
        let mine = t.anon(1).expect("a place");
        let other = t.anon(2).expect("a place");
        t.fork_anon(1, 5);
        assert_eq!(t.held(5, Kind::Anon, mine), Held::Write);
        assert_eq!(
            t.held(5, Kind::Anon, other),
            Held::None,
            "another process's"
        );
        assert_eq!(
            t.held(5, Kind::File, file),
            Held::None,
            "files wait for an Attach"
        );
        assert_eq!(t.held(1, Kind::Anon, mine), Held::Write);
        // The child's own end takes its membership, and the parent keeps its.
        assert!(t.drop_user(5));
        assert_eq!(t.held(1, Kind::Anon, mine), Held::Write);
        // A parent that lost the object has nothing to give.
        assert!(t.detach(mine, 1));
        t.fork_anon(1, 6);
        assert_eq!(t.held(6, Kind::Anon, mine), Held::None);
    }

    /// The keys of anonymous objects are not those of files and do not
    /// repeat; a full table gives none.
    #[test]
    fn anonymous_keys_are_the_services_and_the_table_is_finite() {
        let mut t = Shares::<u32, u32>::new();
        let mut seen = [0u64; SHARES];
        for slot in &mut seen {
            let key = t.anon(1).expect("a place");
            assert_eq!(key & 1 << 63, 0, "no file's bit");
            assert_ne!(key, 0);
            *slot = key;
        }
        assert_eq!(t.anon(1), None, "the table is full");
        let mut sorted = seen;
        sorted.sort_unstable();
        assert!(sorted.windows(2).all(|w| w[0] != w[1]), "no repeats");
        // A key that went is not made again.
        assert!(t.detach(seen[0], 1));
        let again = t.anon(1).expect("a place");
        assert!(!seen.contains(&again));
        // A file's Get of an anonymous key finds no file.
        assert_eq!(t.get(seen[1], 2, true), Got::Full);
        assert_eq!(t.held(2, Kind::Anon, seen[1]), Held::None);
    }
}
