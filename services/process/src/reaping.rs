// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The places the loop and the reaper thread pass image objects through
//! (reaper.rs makes the calls): one place for each entry of the table of
//! images. The loop gives a place a raw handle, the level to close it at and
//! the record it is for, and tells the thread (a bit of the place); the thread
//! takes the handle, closes it and sets `done`; the loop takes the place back
//! (`take`). The logic is here with no kernel call in it, so that the host
//! tests it.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64, Ordering};

pub struct Place {
    /// The place is given and not taken yet.
    used: AtomicBool,
    /// The raw handle of the object, 0 once the thread took it.
    handle: AtomicU64,
    /// The handle of the process whose end freed the object (0 for none): its
    /// memory account is what the thread watches after the close.
    child: AtomicU64,
    level: AtomicU8,
    record: AtomicU16,
    /// The object is for the exit of the record: the loop reports its end
    /// when the last of its objects is back.
    exit: AtomicBool,
    done: AtomicBool,
}

impl Place {
    const fn new() -> Place {
        Place {
            used: AtomicBool::new(false),
            handle: AtomicU64::new(0),
            child: AtomicU64::new(0),
            level: AtomicU8::new(1),
            record: AtomicU16::new(0),
            exit: AtomicBool::new(false),
            done: AtomicBool::new(false),
        }
    }
}

/// What a place holds for the thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Work {
    pub handle: u64,
    pub child: u64,
    pub level: u8,
}

pub struct Places<const N: usize> {
    places: [Place; N],
}

impl<const N: usize> Places<N> {
    pub const fn new() -> Places<N> {
        Places {
            places: [const { Place::new() }; N],
        }
    }

    /// Gives a free place the object `handle` for `record`, to close at `level`
    /// (at least 1); the number of the place, which the thread is to be told.
    /// None when no place is free.
    pub fn give(
        &self,
        handle: u64,
        child: u64,
        level: u8,
        record: usize,
        exit: bool,
    ) -> Option<usize> {
        let at = self.places.iter().position(|p| {
            p.used
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        })?;
        let p = &self.places[at];
        p.done.store(false, Ordering::Release);
        p.child.store(child, Ordering::Release);
        p.level.store(level.max(1), Ordering::Release);
        p.record.store(record as u16, Ordering::Release);
        p.exit.store(exit, Ordering::Release);
        p.handle.store(handle, Ordering::Release);
        Some(at)
    }

    /// The thread could not be told: the place is free again and the handle
    /// comes back.
    pub fn undo(&self, place: usize) -> u64 {
        let p = &self.places[place];
        let handle = p.handle.swap(0, Ordering::AcqRel);
        p.used.store(false, Ordering::Release);
        handle
    }

    /// The thread takes the object of `place`; None when it holds none (a
    /// notice of a place that was done or never given).
    pub fn start(&self, place: usize) -> Option<Work> {
        let p = self.places.get(place)?;
        let handle = p.handle.swap(0, Ordering::AcqRel);
        if handle == 0 {
            return None;
        }
        Some(Work {
            handle,
            child: p.child.load(Ordering::Acquire),
            level: p.level.load(Ordering::Acquire),
        })
    }

    /// The thread closed the object of `place`.
    pub fn finish(&self, place: usize) {
        self.places[place].done.store(true, Ordering::Release);
    }

    /// A place the thread is done with: the record it was given for and whether
    /// its end waits for it; the place is free again. None when no place is done.
    pub fn take(&self) -> Option<(usize, bool)> {
        for p in &self.places {
            if p.used.load(Ordering::Acquire) && p.done.load(Ordering::Acquire) {
                let taken = (
                    usize::from(p.record.load(Ordering::Acquire)),
                    p.exit.load(Ordering::Acquire),
                );
                p.done.store(false, Ordering::Relaxed);
                p.used.store(false, Ordering::Release);
                return Some(taken);
            }
        }
        None
    }

    /// Whether a place is done and not taken.
    pub fn waiting(&self) -> bool {
        self.places
            .iter()
            .any(|p| p.used.load(Ordering::Acquire) && p.done.load(Ordering::Acquire))
    }

    /// The highest level among the places given and not closed yet (0 for
    /// none): the level the thread works at, so that a close of a process of a
    /// higher level never waits behind one of a lower level.
    pub fn highest_open(&self) -> u8 {
        self.places
            .iter()
            .filter(|p| p.used.load(Ordering::Acquire) && p.handle.load(Ordering::Acquire) != 0)
            .map(|p| p.level.load(Ordering::Acquire))
            .max()
            .unwrap_or(0)
    }

    /// The level of `place`.
    pub fn level(&self, place: usize) -> u8 {
        self.places[place].level.load(Ordering::Acquire)
    }

    /// Whether another place, given for the same process (`child`) and not
    /// closed yet, is open besides `place`: only the last object of a process
    /// waits for its pages.
    pub fn another_open(&self, place: usize, child: u64) -> bool {
        self.places.iter().enumerate().any(|(i, p)| {
            i != place
                && p.used.load(Ordering::Acquire)
                && p.handle.load(Ordering::Acquire) != 0
                && p.child.load(Ordering::Acquire) == child
        })
    }

    /// Takes the object of every place given and not closed (the thread is gone):
    /// each is `(place, handle)`, and the caller closes it and calls `finish`.
    pub fn open(&self) -> impl Iterator<Item = (usize, u64)> + '_ {
        self.places.iter().enumerate().filter_map(|(i, p)| {
            if !p.used.load(Ordering::Acquire) {
                return None;
            }
            let handle = p.handle.swap(0, Ordering::AcqRel);
            (handle != 0).then_some((i, handle))
        })
    }
}

impl<const N: usize> Default for Places<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_place_goes_from_the_loop_to_the_thread_and_back() {
        let places = Places::<4>::new();
        let at = places.give(7, 99, 28, 3, true).unwrap();
        assert_eq!(places.highest_open(), 28);
        assert!(places.take().is_none(), "not done yet");
        assert_eq!(
            places.start(at),
            Some(Work {
                handle: 7,
                child: 99,
                level: 28
            })
        );
        assert_eq!(places.start(at), None, "a second notice finds nothing");
        assert_eq!(places.highest_open(), 0, "closing is not open any more");
        places.finish(at);
        assert!(places.waiting());
        assert_eq!(places.take(), Some((3, true)));
        assert!(!places.waiting());
        assert!(places.take().is_none());
        // The place is free again.
        assert!(places.give(8, 0, 1, 0, false).is_some());
    }

    #[test]
    fn the_places_run_out_and_a_failed_tell_gives_the_handle_back() {
        let places = Places::<2>::new();
        let a = places.give(1, 5, 10, 0, true).unwrap();
        let b = places.give(2, 5, 20, 1, true).unwrap();
        assert!(places.give(3, 5, 30, 2, true).is_none());
        assert_eq!(places.undo(b), 2);
        assert!(places.give(3, 5, 30, 2, true).is_some());
        assert_eq!(places.undo(a), 1);
    }

    #[test]
    fn the_highest_open_level_and_the_last_object_of_a_process() {
        let places = Places::<4>::new();
        let a = places.give(1, 5, 10, 0, true).unwrap();
        let b = places.give(2, 5, 28, 0, true).unwrap();
        let c = places.give(3, 6, 20, 1, true).unwrap();
        assert_eq!(places.highest_open(), 28);
        assert!(places.another_open(a, 5), "b is open for the same process");
        assert!(!places.another_open(c, 6));
        places.start(b).unwrap();
        assert!(!places.another_open(a, 5), "b is being closed");
        assert_eq!(places.highest_open(), 20);
        assert_eq!(places.level(a), 10);
    }

    #[test]
    fn the_objects_of_a_thread_that_is_gone_are_taken_for_the_loop_to_close() {
        let places = Places::<4>::new();
        places.give(1, 5, 10, 0, true).unwrap();
        let b = places.give(2, 5, 28, 0, true).unwrap();
        places.start(b).unwrap();
        let open: Vec<(usize, u64)> = places.open().collect();
        assert_eq!(open, vec![(0, 1)]);
        assert_eq!(places.open().count(), 0, "taken once");
    }
}
