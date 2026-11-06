// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of images (spec 2, 3.12.2): the objects of the code and of the
//! read-only data of programs, which the processes that exec or spawn one
//! file map as the same pages. The loader of the first process to ask for a
//! part makes the object and says so (Reserved); the loaders that ask
//! meanwhile wait (Busy: the service holds their requests, `wait`, and
//! answers each when the object is there or the maker is gone) and then get
//! a handle of it. The key is the part with the whole identity of the file
//! (`ImageKey`), compared in full. An entry lives as long as a process that
//! committed its load uses it: the end of a process, or the exec of a new
//! image in it, lets go of it, and the last to go frees the entry and the
//! service's handle, so the object goes with the last mapping. A load that
//! has not committed joins an entry provisionally (`joining`); commit
//! settles it, abort lets it go. O(IMAGES) a call.

use crate::loaders::LOADERS;
use proto_process::{IMAGES, ImageKey, RECORDS};

const WORDS: usize = RECORDS.div_ceil(64);

/// The requests that wait: one for each loader at most.
pub const WAITING: usize = LOADERS;
/// The requests `ready_batch` gives at once.
pub const BATCH: usize = 2;

/// Whether a handle with `rights` may be the object of a part: it reads,
/// duplicates and transfers, the code also runs, and none writes (spec 2,
/// 3.12.2). The table hands out what it keeps with the same rights.
pub fn fits(part: u32, rights: abi::Rights) -> bool {
    use abi::Rights;
    let wanted = Rights::MAP_READ | Rights::DUPLICATE | Rights::TRANSFER;
    rights.contains(wanted)
        && !rights.contains(Rights::MAP_WRITE)
        && (part != proto_process::IMAGE_CODE || rights.contains(Rights::MAP_EXEC))
}

/// What the table answers to Get.
#[derive(Debug, PartialEq, Eq)]
pub enum Got<'a, T> {
    /// The object: its pages and the service's handle, to copy.
    Found(u32, &'a T),
    /// There is none, and the caller makes it (the entry waits for its Put).
    Reserved,
    /// There is none and the table has no place: the caller makes an object
    /// that is not registered.
    Full,
    /// A loader makes it now: the caller waits (`Images::wait`).
    Busy,
}

enum State<T> {
    /// The loader of the record makes the object.
    Making(usize),
    Ready {
        pages: u32,
        memory: T,
    },
}

struct Entry<T> {
    key: ImageKey,
    state: State<T>,
    /// The records whose load committed with this entry.
    users: [u64; WORDS],
    /// The records whose load has not committed yet.
    joining: [u64; WORDS],
}

impl<T> Entry<T> {
    fn unused(&self) -> bool {
        self.users.iter().chain(&self.joining).all(|w| *w == 0)
    }
}

/// A Get that waits for the object of a key, with what the service answers
/// it by (`W`: the deferred reply).
struct Waiting<W> {
    record: u16,
    key: ImageKey,
    data: W,
    age: u32,
    /// The place of the entry of `key`, GONE when its maker went and none
    /// has made it again (kept at each change of the entries, so that a
    /// pass over the waiting requests reads their state in O(1) each).
    entry: u8,
}

const GONE: u8 = u8::MAX;

pub struct Images<T, W> {
    entries: [Option<Entry<T>>; IMAGES],
    waiting: [Option<Waiting<W>>; WAITING],
    ages: u32,
}

impl<T, W> Images<T, W> {
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
            rt::bss::fill_none(addr_of_mut!((*at).waiting));
        }
    }

    pub const fn new() -> Self {
        Images {
            entries: [const { None }; IMAGES],
            waiting: [const { None }; WAITING],
            ages: 0,
        }
    }

    fn find(&self, key: &ImageKey) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.as_ref().is_some_and(|e| e.key == *key))
    }

    /// The entry in `i` goes; the requests that wait for it lose their entry.
    fn free(&mut self, i: usize) {
        self.entries[i] = None;
        for w in self.waiting.iter_mut().flatten() {
            if usize::from(w.entry) == i {
                w.entry = GONE;
            }
        }
    }

    fn join(entry: &mut Entry<T>, record: usize) {
        // Always: a record that uses the entry already (the exec of the
        // file it runs) joins again, so that commit, which lets go of what
        // the replaced image used, finds it joined and keeps it.
        entry.joining[record / 64] |= 1 << (record % 64);
    }

    /// The loader of the record in `record` asks for the object of `key`;
    /// its load joins the entry from here on.
    pub fn get(&mut self, key: &ImageKey, record: usize) -> Got<'_, T> {
        match self.find(key) {
            Some(i) => {
                let entry = self.entries[i].as_mut().expect("an entry");
                // The maker's own record waits too (an exec of a record
                // whose other loader makes it): one object is made.
                if matches!(entry.state, State::Making(_)) {
                    return Got::Busy;
                }
                Self::join(entry, record);
                let State::Ready { pages, memory } = &entry.state else {
                    unreachable!()
                };
                Got::Found(*pages, memory)
            }
            None => {
                let Some(place) = self.entries.iter().position(Option::is_none) else {
                    return Got::Full;
                };
                let mut entry = Entry {
                    key: *key,
                    state: State::Making(record),
                    users: [0; WORDS],
                    joining: [0; WORDS],
                };
                Self::join(&mut entry, record);
                self.entries[place] = Some(entry);
                // The waiters of a key whose maker went wait for this one.
                for w in self.waiting.iter_mut().flatten() {
                    if w.key == *key {
                        w.entry = place as u8;
                    }
                }
                Got::Reserved
            }
        }
    }

    /// The request `data` of the loader of `record` for the object of `key`
    /// waits for it (after a Get that said Busy). With no place left it
    /// comes back, and the caller answers Full.
    pub fn wait(&mut self, key: ImageKey, record: usize, data: W) -> Result<(), W> {
        if self
            .waiting
            .iter()
            .flatten()
            .any(|w| usize::from(w.record) == record)
        {
            return Err(data);
        }
        self.ages = self.ages.wrapping_add(1);
        let age = self.ages;
        let entry = self.find(&key).map_or(GONE, |i| i as u8);
        match self.waiting.iter_mut().find(|w| w.is_none()) {
            Some(place) => {
                *place = Some(Waiting {
                    record: record as u16,
                    key,
                    data,
                    age,
                    entry,
                });
                Ok(())
            }
            None => Err(data),
        }
    }

    /// Up to N of the oldest waiting requests that nobody makes the object
    /// for any more: their entry is Ready, or gone with its maker. They leave
    /// the table into `out` with their record, key and `data`, and the
    /// caller asks `get` for each again. Of the requests of a key whose
    /// maker went only the oldest comes (`get` gives it Reserved); the
    /// others wait on. Gives the count taken and whether more are ready.
    /// One pass over the places, O(WAITING) (each request keeps the place of
    /// its entry), and N picks over the places.
    pub fn ready_batch<const N: usize>(
        &mut self,
        out: &mut [Option<(usize, ImageKey, W)>; N],
    ) -> (usize, bool) {
        // 0 closed, 1 the object is there, 2 its maker went.
        let mut status = [0u8; WAITING];
        for (state, w) in status.iter_mut().zip(&self.waiting) {
            if let Some(w) = w {
                *state = match self
                    .entries
                    .get(usize::from(w.entry))
                    .and_then(Option::as_ref)
                {
                    None => 2,
                    Some(e) => u8::from(!matches!(e.state, State::Making(_))),
                };
            }
        }
        let ages = self.ages;
        let mut claimed = [None::<ImageKey>; N];
        let mut taken = 0;
        let open = |state: u8, key: &ImageKey, claimed: &[Option<ImageKey>]| {
            state == 1 || (state == 2 && !claimed.contains(&Some(*key)))
        };
        while taken < N {
            let mut best: Option<(usize, u32)> = None;
            for (i, state) in status.iter().enumerate() {
                let Some(w) = self.waiting[i].as_ref() else {
                    continue;
                };
                let older = best.is_none_or(|(_, b)| ages.wrapping_sub(w.age) > b);
                if open(*state, &w.key, &claimed[..taken]) && older {
                    best = Some((i, ages.wrapping_sub(w.age)));
                }
            }
            let Some((i, _)) = best else {
                break;
            };
            let w = self.waiting[i].take().expect("a waiting request");
            if status[i] == 2 {
                claimed[taken] = Some(w.key);
            }
            out[taken] = Some((usize::from(w.record), w.key, w.data));
            status[i] = 0;
            taken += 1;
        }
        let more = status.iter().enumerate().any(|(i, state)| {
            self.waiting[i]
                .as_ref()
                .is_some_and(|w| open(*state, &w.key, &claimed[..taken]))
        });
        (taken, more)
    }

    /// The requests waiting.
    pub fn waiters(&self) -> usize {
        self.waiting.iter().flatten().count()
    }

    /// The loader of `record` made the object of the entry it reserved: Err
    /// when it reserved none (the object is not kept then).
    pub fn put(&mut self, key: &ImageKey, record: usize, pages: u32, memory: T) -> Result<(), T> {
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

    fn settle(&mut self, i: usize) {
        if self.entries[i]
            .as_ref()
            .is_some_and(|e| e.unused() && matches!(e.state, State::Ready { .. }))
        {
            self.free(i);
        }
    }

    /// The loader of `record` could not make the object it reserved, or
    /// asks no more for one it found: the entry it makes goes, or its
    /// join does.
    pub fn detach(&mut self, key: &ImageKey, record: usize) {
        let Some(i) = self.find(key) else {
            return;
        };
        let entry = self.entries[i].as_mut().expect("an entry");
        if matches!(entry.state, State::Making(owner) if owner == record) {
            self.free(i);
            return;
        }
        entry.joining[record / 64] &= !(1 << (record % 64));
        self.settle(i);
    }

    /// The load of `record` committed (SpawnCommit, ExecCommit): what it
    /// joined it uses now, and the entries of an image it replaced it uses
    /// no more.
    pub fn commit(&mut self, record: usize) {
        let (word, bit) = (record / 64, 1u64 << (record % 64));
        for i in 0..IMAGES {
            let Some(entry) = self.entries[i].as_mut() else {
                continue;
            };
            if matches!(entry.state, State::Making(owner) if owner == record) {
                // An object nobody Put: the load went on without it.
                self.free(i);
                continue;
            }
            entry.users[word] &= !bit;
            if entry.joining[word] & bit != 0 {
                entry.joining[word] &= !bit;
                entry.users[word] |= bit;
            }
            self.settle(i);
        }
    }

    /// The load of `record` stopped: its joins, its waiting request and the
    /// entries it makes go, what it used before (the image an exec
    /// replaces) stays.
    pub fn abort(&mut self, record: usize) {
        self.forget(record, false);
    }

    /// The process in `record` is gone: it uses nothing, and its requests
    /// that wait go (their replies with them).
    pub fn drop_user(&mut self, record: usize) {
        self.forget(record, true);
    }

    fn forget(&mut self, record: usize, users: bool) {
        // A load that stops asks for nothing more: the loader that waited
        // for an object is gone with its request.
        for request in &mut self.waiting {
            if request
                .as_ref()
                .is_some_and(|w| usize::from(w.record) == record)
            {
                *request = None;
            }
        }
        let (word, bit) = (record / 64, 1u64 << (record % 64));
        for i in 0..IMAGES {
            let Some(entry) = self.entries[i].as_mut() else {
                continue;
            };
            if matches!(entry.state, State::Making(owner) if owner == record) {
                self.free(i);
                continue;
            }
            entry.joining[word] &= !bit;
            if users {
                entry.users[word] &= !bit;
            }
            self.settle(i);
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

impl<T, W> Default for Images<T, W> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_process::{IMAGE_CODE, IMAGE_RODATA};

    fn key(inode: u64) -> ImageKey {
        ImageKey {
            part: IMAGE_CODE,
            device: 1,
            inode,
            size: 4096,
            modify: (10, 5),
            change: (11, 6),
        }
    }

    #[test]
    fn the_rights_of_a_part_never_include_writing() {
        use abi::Rights;
        let base = Rights::MAP_READ | Rights::DUPLICATE | Rights::TRANSFER;
        assert!(fits(IMAGE_RODATA, base));
        assert!(!fits(IMAGE_CODE, base), "the code runs");
        assert!(fits(IMAGE_CODE, base | Rights::MAP_EXEC));
        assert!(!fits(IMAGE_RODATA, base | Rights::MAP_WRITE));
        assert!(!fits(
            IMAGE_CODE,
            base | Rights::MAP_EXEC | Rights::MAP_WRITE
        ));
        assert!(!fits(IMAGE_RODATA, Rights::MAP_READ | Rights::TRANSFER));
    }

    #[test]
    fn the_first_makes_the_object_and_the_rest_wait_then_share() {
        let mut t = Images::<u32, u32>::new();
        assert_eq!(t.get(&key(7), 1), Got::Reserved);
        assert_eq!(t.get(&key(7), 2), Got::Busy);
        assert_eq!(t.put(&key(7), 2, 4, 99), Err(99), "not the maker");
        assert_eq!(t.put(&key(7), 1, 4, 55), Ok(()));
        assert_eq!(t.get(&key(7), 2), Got::Found(4, &55));
        t.commit(1);
        t.commit(2);
        t.drop_user(1);
        assert_eq!(t.len(), 1, "the second keeps the entry");
        t.drop_user(2);
        assert!(t.is_empty());
    }

    #[test]
    fn a_key_differs_in_every_field() {
        let mut t = Images::<u32, u32>::new();
        let base = key(7);
        assert_eq!(t.get(&base, 1), Got::Reserved);
        t.put(&base, 1, 1, 1).unwrap();
        for other in [
            ImageKey {
                part: IMAGE_RODATA,
                ..base
            },
            ImageKey { device: 2, ..base },
            ImageKey { inode: 8, ..base },
            ImageKey { size: 4097, ..base },
            ImageKey {
                modify: (10, 6),
                ..base
            },
            ImageKey {
                modify: (11, 5),
                ..base
            },
            ImageKey {
                change: (11, 7),
                ..base
            },
            ImageKey {
                change: (12, 6),
                ..base
            },
        ] {
            assert_eq!(t.get(&other, 2), Got::Reserved, "{other:?}");
            t.detach(&other, 2);
        }
        assert_eq!(t.get(&base, 2), Got::Found(1, &1));
    }

    #[test]
    fn a_full_table_says_so() {
        let mut t = Images::<u32, u32>::new();
        for i in 0..IMAGES as u64 {
            assert_eq!(t.get(&key(i), 1), Got::Reserved);
        }
        assert_eq!(t.get(&key(1000), 2), Got::Full);
        t.detach(&key(3), 1);
        assert_eq!(t.get(&key(1000), 2), Got::Reserved);
    }

    #[test]
    fn a_waiter_is_answered_when_the_object_is_there_or_the_maker_went() {
        let mut t = Images::<u32, u32>::new();
        assert_eq!(t.get(&key(1), 1), Got::Reserved);
        assert_eq!(t.get(&key(1), 2), Got::Busy);
        assert_eq!(t.get(&key(1), 3), Got::Busy);
        t.wait(key(1), 2, 20).unwrap();
        t.wait(key(1), 3, 30).unwrap();
        assert_eq!(t.wait(key(1), 3, 31), Err(31), "one a record");
        let mut out = [None, None];
        assert_eq!(t.ready_batch(&mut out).0, 0, "made now");
        // The maker goes: the oldest of the waiters makes it, the other waits.
        t.drop_user(1);
        let (n, more) = t.ready_batch(&mut out);
        assert_eq!((n, more), (1, false));
        assert_eq!(out[0].take().map(|(r, _, d)| (r, d)), Some((2, 20)));
        assert_eq!(t.get(&key(1), 2), Got::Reserved);
        assert_eq!(t.waiters(), 1);
        t.put(&key(1), 2, 2, 5).unwrap();
        let (n, _) = t.ready_batch(&mut out);
        assert_eq!(n, 1);
        assert_eq!(t.get(&key(1), 3), Got::Found(2, &5));
    }

    #[test]
    fn a_batch_is_bounded() {
        let mut t = Images::<u32, u32>::new();
        assert_eq!(t.get(&key(1), 0), Got::Reserved);
        for r in 1..=6 {
            assert_eq!(t.get(&key(1), r), Got::Busy);
            t.wait(key(1), r, r as u32).unwrap();
        }
        t.put(&key(1), 0, 1, 1).unwrap();
        let mut out = [None, None];
        let (n, more) = t.ready_batch(&mut out);
        assert_eq!((n, more), (2, true));
        assert_eq!(out[0].as_ref().map(|o| o.0), Some(1), "the oldest first");
    }

    #[test]
    fn an_abort_lets_go_of_the_join_and_keeps_the_old_image() {
        let mut t = Images::<u32, u32>::new();
        // Record 4 runs the image of key 1.
        assert_eq!(t.get(&key(1), 4), Got::Reserved);
        t.put(&key(1), 4, 1, 1).unwrap();
        t.commit(4);
        // Its exec loads key 2 and fails.
        assert_eq!(t.get(&key(2), 4), Got::Reserved);
        t.abort(4);
        assert_eq!(t.len(), 1, "the entry it made is gone, the old one stays");
        // The exec that goes through lets go of the old image.
        assert_eq!(t.get(&key(2), 4), Got::Reserved);
        t.put(&key(2), 4, 1, 2).unwrap();
        t.commit(4);
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(&key(1), 5), Got::Reserved, "key 1 went with the exec");
    }

    #[test]
    fn a_join_that_aborts_does_not_hold_the_entry() {
        let mut t = Images::<u32, u32>::new();
        t.get(&key(1), 1);
        t.put(&key(1), 1, 1, 1).unwrap();
        t.commit(1);
        assert_eq!(t.get(&key(1), 2), Got::Found(1, &1));
        t.abort(2);
        t.drop_user(1);
        assert!(t.is_empty());
    }

    #[test]
    fn an_exec_of_the_file_a_record_runs_keeps_the_entry() {
        let mut t = Images::<u32, u32>::new();
        assert_eq!(t.get(&key(1), 4), Got::Reserved);
        t.put(&key(1), 4, 1, 1).unwrap();
        t.commit(4);
        // The record runs key 1 and execs the same file.
        assert_eq!(t.get(&key(1), 4), Got::Found(1, &1));
        t.commit(4);
        assert_eq!(t.len(), 1, "the entry lives while its user does");
        assert_eq!(
            t.get(&key(1), 5),
            Got::Found(1, &1),
            "the next exec shares it"
        );
        // An exec of the same file that aborts keeps the old registration.
        assert_eq!(t.get(&key(1), 4), Got::Found(1, &1));
        t.abort(4);
        t.abort(5);
        assert_eq!(t.len(), 1);
        t.drop_user(4);
        assert!(t.is_empty());
    }

    #[test]
    fn the_waiters_of_a_gone_maker_leave_one_at_a_time_when_taken_between() {
        let mut t = Images::<u32, u32>::new();
        assert_eq!(t.get(&key(1), 0), Got::Reserved);
        for r in 1..=2 {
            assert_eq!(t.get(&key(1), r), Got::Busy);
            t.wait(key(1), r, r as u32).unwrap();
        }
        t.abort(0);
        let mut one = [None];
        assert_eq!(t.ready_batch(&mut one).0, 1);
        let (record, k, _) = one[0].take().unwrap();
        assert_eq!(record, 1);
        assert_eq!(
            t.get(&k, record),
            Got::Reserved,
            "the oldest becomes the maker"
        );
        let mut one = [None];
        assert_eq!(t.ready_batch(&mut one).0, 0, "the other waits for it");
    }

    #[test]
    fn a_commit_drops_an_entry_nobody_put() {
        let mut t = Images::<u32, u32>::new();
        assert_eq!(t.get(&key(1), 1), Got::Reserved);
        t.commit(1);
        assert!(t.is_empty());
    }
}
