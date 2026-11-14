// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The accounting of EntropyRejoin (proto_process): a process with no channel
//! to init, whose session with the entropy service died with the service's
//! instance, asks the process service for a new one.
//!
//! The loop of the service only checks and queues the request, in O(1)
//! (`Rejoin::admit`, `Rejoin::queue`); a thread of the service at the entropy
//! service's level takes the session from the service's root and the loop
//! answers (`Rejoin::finish`). A process gets one session in each generation
//! of the root (each Register of the entropy service starts the next), and
//! only when it was born under an earlier one: the session it held died
//! with that instance, and a process born later got its own from the loader.
//! All together the processes of one generation get `MAX` sessions, so the
//! root's 255 clones (services/entropy) keep 63 for the loaders: the start of
//! a child that heals its closed session, and a set-ID program's check.

use proto_process::RECORDS;

/// The sessions one generation of the root gives at most. The entropy
/// service's root has 255 clones in all; the loaders keep the rest.
pub const MAX: u32 = if cfg!(feature = "rejoin-max-2") {
    2
} else {
    192
};
/// The clones of the root that the loaders keep: the heal of a child's closed
/// session at each start, and the check of a set-ID program's sessions.
pub const LOADER_RESERVE: usize = 63;
const _: () = assert!(MAX as usize + LOADER_RESERVE <= proto_entropy::ROOT_CLONES);
/// The requests that are taken and not yet answered at most.
pub const QUEUE: usize = 4;

/// Why a request is refused at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The process was born under the current instance, or has had its
    /// session in this generation: it has nothing to replace, or no right
    /// to a second.
    Permission,
    /// The root is not registered or not open (the service is between two
    /// instances), or the queue is full: the client asks again.
    Again,
    /// `MAX` sessions went out in this generation.
    LimitReached,
}

/// What the thread made of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A new session.
    Given,
    /// No session, for a reason of the moment (the root closed, a failed
    /// call): the client asks again.
    Failed,
    /// The root has no clones left: the client is refused for good.
    Refused,
}

/// A place of the queue.
enum Place<P> {
    Free,
    /// A request that waits for the thread's session. `index` is the record
    /// that asked (None once its process ended), `generation` the one it was
    /// counted in.
    Queued {
        index: Option<usize>,
        generation: u32,
        pending: P,
    },
}

/// The records' standing in the rejoin and the queue of requests.
pub struct Rejoin<P> {
    /// The generation of the root: each Register of the entropy service
    /// starts the next. 0 before the first.
    generation: u32,
    /// The records that took a session in this generation.
    rejoined: u32,
    /// The generation each record was born in, and the one it took its
    /// session in (0 for none).
    born: [u32; RECORDS],
    taken: [u32; RECORDS],
    queue: [Place<P>; QUEUE],
}

impl<P> Rejoin<P> {
    pub const fn new() -> Self {
        Self {
            generation: 0,
            rejoined: 0,
            born: [0; RECORDS],
            taken: [0; RECORDS],
            queue: [const { Place::Free }; QUEUE],
        }
    }

    /// The entropy service registered a root: its instance is the next
    /// generation, and it has its own sessions to give. `previous_open` says
    /// whether the root it replaces is registered and open: a Register from
    /// the instance that is alive already (a repeated one) starts nothing, or
    /// every process of the current instance would look old.
    pub fn registered(&mut self, previous_open: bool) {
        if previous_open && !cfg!(feature = "break-rejoin-always-bump") {
            return;
        }
        self.generation = self.generation.saturating_add(1);
        if !cfg!(feature = "break-rejoin-keep-count") {
            self.rejoined = 0;
        }
    }

    /// The record `index` was made: it belongs to the current generation.
    pub fn born(&mut self, index: usize) {
        self.born[index] = self.generation;
        self.taken[index] = 0;
    }

    /// The record `index` ended, and a request of it that waits has no taker.
    /// The session it took stays counted: a session has TRANSFER, so a
    /// process can hand its clone to another and end, and the clone lives on.
    /// The processes that may ask are those of the old instance, fixed when
    /// the next one registers, so the count is the most clones the generation
    /// can hold.
    pub fn ended(&mut self, index: usize) {
        if self.generation != 0
            && self.taken[index] == self.generation
            && cfg!(feature = "break-rejoin-leak")
        {
            self.rejoined = self.rejoined.saturating_sub(1);
        }
        self.taken[index] = 0;
        self.born[index] = 0;
        for place in &mut self.queue {
            if let Place::Queued { index: held, .. } = place
                && *held == Some(index)
            {
                *held = None;
            }
        }
    }

    /// Whether the record `index` may ask now, and the place for its request.
    /// `root_open` says whether the entropy service's root is registered and
    /// open, and comes first: between the end of an instance and the
    /// registration of the next the generation is still the old one, so a
    /// process of that instance would look like one of the current, and a
    /// refusal then (PERMISSION) would end its attempts for good; AGAIN makes it
    /// ask again after the new instance registered.
    pub fn admit(&self, index: usize, root_open: impl FnOnce() -> bool) -> Result<usize, Refusal> {
        if !root_open() {
            return Err(Refusal::Again);
        }
        let old = self.born[index] < self.generation || cfg!(feature = "break-rejoin-born");
        let once = self.taken[index] != self.generation || cfg!(feature = "break-rejoin-twice");
        if !old || !once {
            return Err(Refusal::Permission);
        }
        if self.rejoined >= MAX && !cfg!(feature = "break-rejoin-unlimited") {
            return Err(Refusal::LimitReached);
        }
        self.queue
            .iter()
            .position(|p| matches!(p, Place::Free))
            .ok_or(Refusal::Again)
    }

    /// Takes the request of `index` into `place` (from `admit`): the record
    /// has its session in this generation, whatever comes of the request.
    pub fn queue(&mut self, place: usize, index: usize, pending: P) {
        self.taken[index] = self.generation;
        self.rejoined = self.rejoined.saturating_add(1);
        self.queue[place] = Place::Queued {
            index: Some(index),
            generation: self.generation,
            pending,
        };
    }

    /// Whether `place` holds a request.
    pub fn queued(&self, place: usize) -> bool {
        matches!(self.queue.get(place), Some(Place::Queued { .. }))
    }

    /// The thread is done with the request in `place`: the place is free and
    /// the request comes back, with whether its process is alive to be
    /// answered. A request that failed leaves its record without a session
    /// and returns its count, for a try after the pause. A request the root
    /// refused keeps its count: the root has no clones left, and a retry
    /// would only cost the root another request.
    pub fn finish(&mut self, place: usize, outcome: Outcome) -> Option<(P, bool)> {
        let Place::Queued {
            index,
            generation,
            pending,
        } = core::mem::replace(self.queue.get_mut(place)?, Place::Free)
        else {
            return None;
        };
        if let Some(index) = index
            && (outcome == Outcome::Failed
                || (outcome == Outcome::Refused && cfg!(feature = "break-rejoin-refund-refused")))
            && generation == self.generation
            && self.taken[index] == generation
        {
            self.taken[index] = 0;
            self.rejoined = self.rejoined.saturating_sub(1);
        }
        Some((pending, index.is_some()))
    }

    /// The generation of the root and the sessions this generation gave.
    pub fn standing(&self) -> (u32, u32) {
        (self.generation, self.rejoined)
    }
}

impl<P> Default for Rejoin<P> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPEN: fn() -> bool = || true;

    /// A table in generation 1 with the records `old` born before it.
    fn after_restart(old: &[usize]) -> Rejoin<u32> {
        let mut r = Rejoin::new();
        r.registered(false);
        for &i in old {
            r.born(i);
        }
        // The next instance registers: the old records were born before it.
        r.registered(false);
        r
    }

    fn ask(r: &mut Rejoin<u32>, index: usize) -> Result<usize, Refusal> {
        let place = r.admit(index, OPEN)?;
        r.queue(place, index, index as u32);
        Ok(place)
    }

    #[test]
    fn a_process_of_the_old_instance_gets_one_session() {
        let mut r = after_restart(&[3]);
        let place = ask(&mut r, 3).unwrap();
        assert!(r.queued(place));
        assert_eq!(r.finish(place, Outcome::Given), Some((3, true)));
        assert!(!r.queued(place));
        assert_eq!(r.standing(), (2, 1));
    }

    #[test]
    fn a_second_request_in_the_same_generation_is_refused() {
        let mut r = after_restart(&[3]);
        let place = ask(&mut r, 3).unwrap();
        r.finish(place, Outcome::Given);
        assert_eq!(ask(&mut r, 3), Err(Refusal::Permission));
        // Also while the first still waits.
        let mut r = after_restart(&[3]);
        ask(&mut r, 3).unwrap();
        assert_eq!(ask(&mut r, 3), Err(Refusal::Permission));
    }

    #[test]
    fn a_process_born_under_the_current_instance_is_refused() {
        let mut r = after_restart(&[3]);
        r.born(4);
        assert_eq!(ask(&mut r, 4), Err(Refusal::Permission));
        // A record made before any root was registered is of the instance
        // before the first.
        let mut r = Rejoin::<u32>::new();
        r.born(5);
        r.registered(false);
        assert!(ask(&mut r, 5).is_ok());
    }

    #[test]
    fn a_closed_root_asks_the_client_to_wait() {
        let mut r = after_restart(&[3]);
        assert_eq!(r.admit(3, || false), Err(Refusal::Again));
        // Nothing was counted: the retry is the first request.
        assert_eq!(r.standing().1, 0);
        assert!(ask(&mut r, 3).is_ok());
        // The root is asked first: a process that looks like one of the
        // current instance while the next has not registered is asked to
        // wait.
        r.born(4);
        assert_eq!(r.admit(4, || false), Err(Refusal::Again));
        assert_eq!(r.admit(4, OPEN), Err(Refusal::Permission));
    }

    #[test]
    fn a_generation_gives_max_sessions_and_refuses_the_next() {
        let all: Vec<usize> = (0..MAX as usize + 3).collect();
        let mut r = after_restart(&all);
        for &i in &all[..MAX as usize] {
            let place = ask(&mut r, i).unwrap();
            r.finish(place, Outcome::Given);
        }
        assert_eq!(r.standing().1, MAX);
        assert_eq!(ask(&mut r, MAX as usize), Err(Refusal::LimitReached));
        assert_eq!(ask(&mut r, MAX as usize + 1), Err(Refusal::LimitReached));
        // The refused record has not used its turn.
        assert_eq!(r.standing().1, MAX);
    }

    #[test]
    fn the_end_of_a_record_keeps_its_session_counted() {
        let all: Vec<usize> = (0..MAX as usize + 1).collect();
        let mut r = after_restart(&all);
        for &i in &all[..MAX as usize] {
            let place = ask(&mut r, i).unwrap();
            r.finish(place, Outcome::Given);
        }
        assert_eq!(ask(&mut r, MAX as usize), Err(Refusal::LimitReached));
        // The clone may be in another process's hands: the end does not free
        // a place, whoever ends.
        r.ended(0);
        r.ended(MAX as usize - 1);
        assert_eq!(r.standing().1, MAX);
        assert_eq!(ask(&mut r, MAX as usize), Err(Refusal::LimitReached));
        // A record that never took one leaves the count as it is.
        r.born(250);
        r.ended(250);
        assert_eq!(r.standing().1, MAX);
    }

    #[test]
    fn a_register_starts_a_generation_with_no_sessions_taken() {
        let mut r = after_restart(&[3, 4]);
        let place = ask(&mut r, 3).unwrap();
        r.finish(place, Outcome::Given);
        assert_eq!(r.standing(), (2, 1));
        r.registered(false);
        assert_eq!(r.standing(), (3, 0));
        // Both are of an older instance again, and may ask once more.
        assert!(ask(&mut r, 3).is_ok());
        assert!(ask(&mut r, 4).is_ok());
        // The end of a record that took its session in the generation before
        // the register leaves the new count alone.
        let mut r = after_restart(&[3, 4]);
        let place = ask(&mut r, 3).unwrap();
        r.finish(place, Outcome::Given);
        r.registered(false);
        ask(&mut r, 4).unwrap();
        r.ended(3);
        assert_eq!(r.standing(), (3, 1));
    }

    #[test]
    fn a_repeated_register_of_a_live_instance_starts_nothing() {
        let mut r = after_restart(&[3]);
        r.born(4);
        let place = ask(&mut r, 3).unwrap();
        r.finish(place, Outcome::Given);
        // The previous root is open: the same instance registers again.
        r.registered(true);
        r.registered(true);
        assert_eq!(r.standing(), (2, 1));
        // The process born in this instance does not look old.
        assert_eq!(ask(&mut r, 4), Err(Refusal::Permission));
        // A register with no open root before it is a new instance.
        r.registered(false);
        assert_eq!(r.standing(), (3, 0));
        assert!(ask(&mut r, 4).is_ok());
    }

    #[test]
    fn a_request_the_root_refused_keeps_its_count_and_its_turn() {
        let mut r = after_restart(&[3]);
        let place = ask(&mut r, 3).unwrap();
        assert_eq!(r.finish(place, Outcome::Refused), Some((3, true)));
        // No refund: the root has no clones left, and the process does not
        // ask again (PERMISSION), so the root is asked once for it.
        assert_eq!(r.standing().1, 1);
        assert_eq!(ask(&mut r, 3), Err(Refusal::Permission));
    }

    #[test]
    fn a_failed_request_gives_its_turn_back() {
        let mut r = after_restart(&[3]);
        let place = ask(&mut r, 3).unwrap();
        assert_eq!(r.finish(place, Outcome::Failed), Some((3, true)));
        assert_eq!(r.standing().1, 0);
        // The client asks again after its pause.
        assert!(ask(&mut r, 3).is_ok());
        // A failure that finishes after a register has no count to return.
        let mut r = after_restart(&[3, 4]);
        let place = ask(&mut r, 3).unwrap();
        r.registered(false);
        ask(&mut r, 4).unwrap();
        assert_eq!(r.finish(place, Outcome::Failed), Some((3, true)));
        assert_eq!(r.standing(), (3, 1));
    }

    #[test]
    fn a_request_of_an_ended_process_has_no_taker_and_no_second_return() {
        let mut r = after_restart(&[3]);
        let place = ask(&mut r, 3).unwrap();
        r.ended(3);
        assert_eq!(r.standing().1, 1);
        // The record's index may belong to a new process already.
        r.born(3);
        assert_eq!(r.finish(place, Outcome::Failed), Some((3, false)));
        assert_eq!(r.standing().1, 1);
    }

    #[test]
    #[cfg(not(feature = "rejoin-max-2"))]
    fn the_queue_holds_four_and_asks_the_fifth_to_wait() {
        let all: Vec<usize> = (0..QUEUE + 1).collect();
        let mut r = after_restart(&all);
        let mut places = Vec::new();
        for &i in &all[..QUEUE] {
            places.push(ask(&mut r, i).unwrap());
        }
        places.sort();
        places.dedup();
        assert_eq!(places.len(), QUEUE);
        assert_eq!(ask(&mut r, QUEUE), Err(Refusal::Again));
        assert_eq!(r.standing().1, QUEUE as u32);
        r.finish(places[0], Outcome::Given);
        assert!(ask(&mut r, QUEUE).is_ok());
    }

    #[test]
    fn a_place_that_is_free_finishes_nothing() {
        let mut r = Rejoin::<u32>::new();
        assert_eq!(r.finish(0, Outcome::Given), None);
        assert_eq!(r.finish(QUEUE, Outcome::Given), None);
        assert!(!r.queued(QUEUE));
    }
}
