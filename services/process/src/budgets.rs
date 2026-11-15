// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The time budgets of POSIX threads the service keeps (`Method::Budget`,
//! proto_process::sporadic; plan 4b). One entry for each thread of a record
//! that runs under a sporadic server: the number init gave its budget and the
//! handle of it (`cur`), and the budget a request for a new one got and that
//! waits for the thread's bind (`probation`). The jobs for init (ASK for a
//! budget, RELEASE for a share) go to the service's budget thread, one at a
//! time, which asks init: the loop never sends to init, which lies below it.
//!
//! Generic over the handle `H` and the owed reply `P`, so that the rules are
//! tested on the host. Nothing here calls the kernel.

use proto_process::sporadic::{Ask, JOB_ASK, JOB_RELEASE};

/// The threads with a budget at once, in all the records together. Init
/// holds twice as many numbers: each entry has a current and a probation.
pub const ENTRIES: usize = 32;
/// The requests for a budget that wait for init.
pub const ASKS: usize = 8;
/// The numbers of budgets that wait to be given back: at most the numbers
/// that live, two for each entry.
const OWED: usize = 2 * ENTRIES;

/// Why a request for a budget was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The thread's request is on, or the queue of requests is full.
    Again,
    /// No room for another thread's entry.
    Room,
}

struct Entry<H> {
    record: u16,
    /// The record's label when the entry was made: an entry of a record
    /// whose index another record took is not the new one's.
    label: u64,
    thread: u32,
    cur: Option<(u64, H)>,
    probation: Option<(u64, H)>,
    /// A request for this entry waits for init or for its DONE.
    busy: bool,
    /// What the probation was asked for, for the child that takes it (TAKE).
    ask: Option<Ask>,
    /// The thread of the old image whose budget this one replaces (exec):
    /// its entry goes when this one is bound.
    from: u32,
}

struct AskJob<P> {
    seq: u32,
    slot: u8,
    ask: Ask,
    replace: u64,
    pending: Option<P>,
    /// The reply carries no handles: the budget is for a thread that is not
    /// there yet (a child, a new image), which takes it with TAKE.
    plain: bool,
    /// Given to the budget thread.
    running: bool,
}

/// What the budget thread is told to do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Next {
    pub kind: u32,
    pub seq: u32,
    pub id: u64,
    pub ask: Ask,
}

/// The reply a finished ASK owes its client.
pub struct Completed<P> {
    pub plain: bool,
    pub pending: P,
    /// 0, or init's status for the refusal (`Err` of the kernel's code).
    pub status: u32,
    pub slot: usize,
}

pub struct Budgets<H, P> {
    entries: [Option<Entry<H>>; ENTRIES],
    asks: [Option<AskJob<P>>; ASKS],
    owed: [u64; OWED],
    owed_count: usize,
    /// The release the budget thread does now.
    releasing: Option<(u32, u64)>,
    seq: u32,
}

impl<H, P> Default for Budgets<H, P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H, P> Budgets<H, P> {
    pub fn new() -> Self {
        Budgets {
            entries: [const { None }; ENTRIES],
            asks: [const { None }; ASKS],
            owed: [0; OWED],
            owed_count: 0,
            releasing: None,
            seq: 0,
        }
    }

    fn find(&self, record: usize, label: u64, thread: u32) -> Option<usize> {
        self.entries.iter().position(|e| {
            e.as_ref().is_some_and(|e| {
                usize::from(e.record) == record && e.label == label && e.thread == thread
            })
        })
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1).max(1);
        self.seq
    }

    /// A request for a budget for `thread` of the record `record` (whose
    /// label is `label`): queued for init, with the client's owed reply.
    /// The entry's current budget, if any, is what the new one replaces.
    /// The reply comes back with the refusal.
    pub fn ask(
        &mut self,
        record: usize,
        label: u64,
        ask: Ask,
        pending: P,
    ) -> Result<(), (Refusal, P)> {
        self.ask_for(record, label, ask, 0, false, pending)
    }

    /// `ask` for a thread of another record or image (`plain`): a child of
    /// `fork` or `posix_spawn`, or the new image of an exec, whose main
    /// thread (`ask.thread`) replaces the budget of the thread `from` of the
    /// old image (0 for none) and takes the new one with `take`.
    pub fn ask_for(
        &mut self,
        record: usize,
        label: u64,
        ask: Ask,
        from: u32,
        plain: bool,
        pending: P,
    ) -> Result<(), (Refusal, P)> {
        let Some(job) = self.asks.iter().position(Option::is_none) else {
            return Err((Refusal::Again, pending));
        };
        let slot = match self.find(record, label, ask.thread) {
            Some(slot) => slot,
            None => {
                let Some(slot) = self.entries.iter().position(Option::is_none) else {
                    return Err((Refusal::Room, pending));
                };
                self.entries[slot] = Some(Entry {
                    record: record as u16,
                    label,
                    thread: ask.thread,
                    cur: None,
                    probation: None,
                    busy: false,
                    ask: None,
                    from: 0,
                });
                slot
            }
        };
        let entry = self.entries[slot].as_mut().expect("the entry just found");
        if entry.busy || entry.probation.is_some() {
            return Err((Refusal::Again, pending));
        }
        entry.busy = true;
        entry.from = from;
        let mut replace = entry.cur.as_ref().map_or(0, |(id, _)| *id);
        if from != 0
            && let Some(old) = self.find(record, label, from)
        {
            replace = self.entries[old]
                .as_ref()
                .and_then(|e| e.cur.as_ref())
                .map_or(0, |(id, _)| *id);
        }
        let seq = self.next_seq();
        self.asks[job] = Some(AskJob {
            seq,
            slot: slot as u8,
            ask,
            replace,
            pending: Some(pending),
            plain,
            running: false,
        });
        Ok(())
    }

    /// The next job for the budget thread, if there is one that it has not
    /// got: the shares to give back first, then the requests in their order.
    pub fn take_job(&mut self) -> Option<Next> {
        if self.releasing.is_some() || self.asks.iter().flatten().any(|j| j.running) {
            return None;
        }
        if self.owed_count > 0 {
            self.owed_count -= 1;
            let id = self.owed[self.owed_count];
            let seq = self.next_seq();
            self.releasing = Some((seq, id));
            return Some(Next {
                kind: JOB_RELEASE,
                seq,
                id,
                ask: Ask {
                    thread: 0,
                    cpu: 0,
                    low: 0,
                    max_repl: 0,
                    c_ns: 0,
                    t_ns: 0,
                },
            });
        }
        let job = self
            .asks
            .iter_mut()
            .flatten()
            .filter(|j| !j.running)
            .min_by_key(|j| j.seq)?;
        job.running = true;
        Some(Next {
            kind: JOB_ASK,
            seq: job.seq,
            id: job.replace,
            ask: job.ask,
        })
    }

    /// The budget thread finished job `seq`: init's `status` (0 for a budget
    /// made, with its number `id` and `handle`). A finished ASK gives the
    /// reply its client is owed; a release gives nothing.
    pub fn done(
        &mut self,
        seq: u32,
        status: u32,
        id: u64,
        handle: Option<H>,
    ) -> Option<Completed<P>> {
        if self.releasing.is_some_and(|(s, _)| s == seq) {
            self.releasing = None;
            return None;
        }
        let job = self
            .asks
            .iter()
            .position(|j| j.as_ref().is_some_and(|j| j.running && j.seq == seq))?;
        let mut job = self.asks[job].take()?;
        let slot = usize::from(job.slot);
        let Some(entry) = self.entries.get_mut(slot).and_then(Option::as_mut) else {
            // The entry went with its record or thread while init worked.
            if status == 0 {
                self.give_back(id);
            }
            return None;
        };
        match (status, handle) {
            (0, Some(handle)) => {
                entry.probation = Some((id, handle));
                entry.ask = Some(job.ask);
            }
            (0, None) => {
                // A share without its budget goes back at once.
                entry.busy = false;
                self.give_back(id);
                return job.pending.take().map(|pending| Completed {
                    plain: job.plain,
                    pending,
                    status: proto_process::FULL,
                    slot,
                });
            }
            _ => {
                entry.busy = false;
                if entry.cur.is_none() {
                    self.entries[slot] = None;
                }
            }
        }
        job.pending.take().map(|pending| Completed {
            plain: job.plain,
            pending,
            status,
            slot,
        })
    }

    /// The handles of the entry in `slot` for the reply of an ASK: the new
    /// budget and, when the thread has one, the current.
    pub fn handles(&self, slot: usize) -> Option<(&H, Option<&H>)> {
        let entry = self.entries.get(slot)?.as_ref()?;
        let new = &entry.probation.as_ref()?.1;
        Some((new, entry.cur.as_ref().map(|(_, h)| h)))
    }

    /// The reply of an ASK could not be made: the probation of the entry in
    /// `slot` goes back.
    pub fn fail(&mut self, slot: usize) {
        let Some(entry) = self.entries.get_mut(slot).and_then(Option::as_mut) else {
            return;
        };
        entry.busy = false;
        let back = entry.probation.take().map(|(id, _)| id);
        if entry.cur.is_none() {
            self.entries[slot] = None;
        }
        if let Some(id) = back {
            self.give_back(id);
        }
    }

    /// TAKE: the budget the entry of `thread` got for it while it was not
    /// there, with what it was asked for.
    pub fn taken(&self, record: usize, label: u64, thread: u32) -> Option<(&H, Ask)> {
        let slot = self.find(record, label, thread)?;
        let entry = self.entries[slot].as_ref()?;
        Some((&entry.probation.as_ref()?.1, entry.ask?))
    }

    /// The thread's current budget, for the thread that leaves the policy.
    pub fn current(&self, record: usize, label: u64, thread: u32) -> Option<&H> {
        let slot = self.find(record, label, thread)?;
        let entry = self.entries[slot].as_ref()?;
        if entry.busy || entry.probation.is_some() {
            return None;
        }
        entry.cur.as_ref().map(|(_, h)| h)
    }

    /// DONE: the layer bound the thread (`bound`): the probation becomes the
    /// current budget and the old one's share goes back; with no probation
    /// the thread left its budget, whose share goes back. Not bound: the
    /// probation goes back and the old stays. False for a thread with no
    /// entry.
    pub fn commit(&mut self, record: usize, label: u64, thread: u32, bound: bool) -> bool {
        let Some(slot) = self.find(record, label, thread) else {
            return false;
        };
        let entry = self.entries[slot].as_mut().expect("the entry just found");
        entry.busy = false;
        let from = core::mem::take(&mut entry.from);
        let mut back = [0u64; 2];
        match (entry.probation.take(), bound) {
            (Some((id, handle)), true) => {
                if let Some((old, _)) = entry.cur.replace((id, handle)) {
                    back[0] = old;
                }
            }
            (Some((id, _)), false) => back[0] = id,
            (None, true) => {
                if let Some((old, _)) = entry.cur.take() {
                    back[0] = old;
                }
            }
            (None, false) => {}
        }
        if entry.cur.is_none() {
            self.entries[slot] = None;
        }
        for id in back.into_iter().filter(|&id| id != 0) {
            self.give_back(id);
        }
        // The new image is bound: the thread of the old one that its
        // budget replaced is gone with the image.
        if bound
            && from != 0
            && from != thread
            && let Some(old) = self.find(record, label, from)
        {
            self.free(old);
        }
        true
    }

    /// The thread ended: its budgets go back and its entry goes.
    pub fn drop_thread(&mut self, record: usize, label: u64, thread: u32) -> bool {
        let Some(slot) = self.find(record, label, thread) else {
            return false;
        };
        self.free(slot);
        true
    }

    /// The record ended: every entry of it goes.
    pub fn drop_record(&mut self, record: usize, label: u64) {
        for slot in 0..ENTRIES {
            if self.entries[slot]
                .as_ref()
                .is_some_and(|e| usize::from(e.record) == record && e.label == label)
            {
                self.free(slot);
            }
        }
        // The requests of the record that wait lose their client (its
        // pending reply answers by itself); their budgets, when they
        // come, find no entry and go back.
    }

    fn free(&mut self, slot: usize) {
        if let Some(entry) = self.entries[slot].take() {
            for (id, _) in entry.cur.into_iter().chain(entry.probation) {
                self.give_back(id);
            }
            // A request of the entry that waits for init finds no entry
            // when it comes: `done` returns its budget.
            for job in self.asks.iter_mut().flatten() {
                if usize::from(job.slot) == slot {
                    job.slot = ENTRIES as u8;
                }
            }
        }
    }

    fn give_back(&mut self, id: u64) {
        if self.owed_count < OWED {
            self.owed[self.owed_count] = id;
            self.owed_count += 1;
        }
    }

    /// Budgets that wait to be given back (the tests read it).
    pub fn owed(&self) -> &[u64] {
        &self.owed[..self.owed_count]
    }

    /// Whether a thread of the record has a budget.
    pub fn holds(&self, record: usize, label: u64) -> bool {
        self.entries
            .iter()
            .flatten()
            .any(|e| usize::from(e.record) == record && e.label == label && e.cur.is_some())
    }

    /// The entries in use.
    pub fn threads(&self) -> usize {
        self.entries.iter().flatten().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type B = Budgets<u32, &'static str>;

    fn ask(thread: u32) -> Ask {
        Ask {
            thread,
            cpu: 1,
            low: 3,
            max_repl: 4,
            c_ns: 1_000_000,
            t_ns: 10_000_000,
        }
    }

    #[test]
    fn a_request_goes_to_init_and_comes_back_with_the_budget() {
        let mut b = B::new();
        b.ask(5, 77, ask(2), "client").ok().unwrap();
        let job = b.take_job().unwrap();
        assert_eq!((job.kind, job.id, job.ask.thread), (JOB_ASK, 0, 2));
        assert_eq!(b.take_job(), None, "one job at a time");
        let done = b.done(job.seq, 0, 41, Some(1001)).unwrap();
        assert_eq!((done.pending, done.status), ("client", 0));
        assert_eq!(b.handles(done.slot), Some((&1001, None)));
        assert!(b.commit(5, 77, 2, true));
        assert_eq!(b.current(5, 77, 2), Some(&1001));
        assert!(b.owed().is_empty());
    }

    #[test]
    fn a_refused_request_leaves_no_entry() {
        let mut b = B::new();
        b.ask(5, 77, ask(2), "client").ok().unwrap();
        let job = b.take_job().unwrap();
        let done = b.done(job.seq, 501, 0, None).unwrap();
        assert_eq!(done.status, 501);
        assert_eq!(b.threads(), 0);
    }

    #[test]
    fn a_change_names_the_old_budget_and_gives_it_back_once_bound() {
        let mut b = B::new();
        b.ask(5, 77, ask(2), "first").ok().unwrap();
        let job = b.take_job().unwrap();
        let done = b.done(job.seq, 0, 41, Some(1001)).unwrap();
        assert_eq!(done.pending, "first");
        b.commit(5, 77, 2, true);
        b.ask(5, 77, ask(2), "second").ok().unwrap();
        let job = b.take_job().unwrap();
        assert_eq!(job.id, 41, "the new budget replaces number 41");
        let done = b.done(job.seq, 0, 42, Some(1002)).unwrap();
        assert_eq!(b.handles(done.slot), Some((&1002, Some(&1001))));
        b.commit(5, 77, 2, true);
        assert_eq!(b.owed(), &[41]);
        assert_eq!(b.current(5, 77, 2), Some(&1002));
    }

    #[test]
    fn a_bind_that_failed_gives_back_the_new_share_and_keeps_the_old() {
        let mut b = B::new();
        b.ask(5, 77, ask(2), "a").ok().unwrap();
        let job = b.take_job().unwrap();
        b.done(job.seq, 0, 41, Some(1001));
        b.commit(5, 77, 2, true);
        b.ask(5, 77, ask(2), "b").ok().unwrap();
        let job = b.take_job().unwrap();
        b.done(job.seq, 0, 42, Some(1002));
        b.commit(5, 77, 2, false);
        assert_eq!(b.owed(), &[42]);
        assert_eq!(b.current(5, 77, 2), Some(&1001));
    }

    #[test]
    fn leaving_the_policy_gives_the_share_back_and_ends_the_entry() {
        let mut b = B::new();
        b.ask(5, 77, ask(2), "a").ok().unwrap();
        let job = b.take_job().unwrap();
        b.done(job.seq, 0, 41, Some(1001));
        b.commit(5, 77, 2, true);
        assert_eq!(b.current(5, 77, 2), Some(&1001));
        assert!(b.commit(5, 77, 2, true));
        assert_eq!(b.owed(), &[41]);
        assert_eq!(b.threads(), 0);
        assert!(!b.commit(5, 77, 2, true));
    }

    #[test]
    fn the_end_of_a_thread_or_a_record_gives_every_share_back() {
        let mut b = B::new();
        for thread in [2, 3] {
            b.ask(5, 77, ask(thread), "a").ok().unwrap();
            let job = b.take_job().unwrap();
            b.done(job.seq, 0, 40 + u64::from(thread), Some(thread));
            b.commit(5, 77, thread, true);
        }
        b.ask(6, 78, ask(2), "other").ok().unwrap();
        let job = b.take_job().unwrap();
        b.done(job.seq, 0, 50, Some(9));
        b.commit(6, 78, 2, true);
        assert!(b.drop_thread(5, 77, 2));
        assert_eq!(b.owed(), &[42]);
        b.drop_record(5, 77);
        assert_eq!(b.owed(), &[42, 43]);
        assert_eq!(b.threads(), 1, "the other record's entry stays");
        // The index reused by a record of another label is no owner.
        assert_eq!(b.current(5, 99, 2), None);
    }

    #[test]
    fn a_budget_that_arrives_for_a_record_that_ended_goes_back() {
        let mut b = B::new();
        b.ask(5, 77, ask(2), "a").ok().unwrap();
        let job = b.take_job().unwrap();
        b.drop_record(5, 77);
        assert!(b.done(job.seq, 0, 41, Some(1001)).is_none());
        assert_eq!(b.owed(), &[41]);
        assert_eq!(b.threads(), 0);
    }

    #[test]
    fn a_thread_has_one_request_at_a_time_and_the_queues_are_bounded() {
        let mut b = B::new();
        b.ask(5, 77, ask(2), "a").ok().unwrap();
        assert_eq!(b.ask(5, 77, ask(2), "b").err(), Some((Refusal::Again, "b")));
        for thread in 3..=ASKS as u32 + 1 {
            b.ask(5, 77, ask(thread), "x").ok().unwrap();
        }
        assert_eq!(
            b.ask(5, 77, ask(40), "y").err(),
            Some((Refusal::Again, "y"))
        );
    }

    #[test]
    fn the_shares_to_give_back_go_to_init_before_new_requests() {
        let mut b = B::new();
        b.ask(5, 77, ask(2), "a").ok().unwrap();
        let job = b.take_job().unwrap();
        b.done(job.seq, 0, 41, Some(1));
        b.commit(5, 77, 2, true);
        b.drop_thread(5, 77, 2);
        b.ask(5, 77, ask(3), "b").ok().unwrap();
        let job = b.take_job().unwrap();
        assert_eq!((job.kind, job.id), (JOB_RELEASE, 41));
        assert!(b.done(job.seq, 0, 0, None).is_none());
        assert_eq!(b.take_job().unwrap().kind, JOB_ASK);
    }

    #[test]
    fn the_new_image_of_an_exec_replaces_the_budget_of_the_old_one() {
        let mut b = B::new();
        // The old image's thread 7 has number 41.
        b.ask(5, 77, ask(7), "a").ok().unwrap();
        let job = b.take_job().unwrap();
        b.done(job.seq, 0, 41, Some(1001));
        b.commit(5, 77, 7, true);
        // The exec asks for the new main thread (1), replacing thread 7's.
        b.ask_for(5, 77, ask(1), 7, true, "exec").ok().unwrap();
        let job = b.take_job().unwrap();
        assert_eq!(job.id, 41, "admission counts the old share out");
        let done = b.done(job.seq, 0, 42, Some(1002)).unwrap();
        assert!(done.plain);
        let (handle, got) = b.taken(5, 77, 1).unwrap();
        assert_eq!((*handle, got.thread), (1002, 1));
        assert!(b.commit(5, 77, 1, true));
        assert_eq!(b.owed(), &[41]);
        assert_eq!(b.threads(), 1);
        assert_eq!(b.current(5, 77, 1), Some(&1002));
        assert_eq!(b.current(5, 77, 7), None);
    }

    #[test]
    fn an_exec_by_the_main_thread_keeps_its_own_entry() {
        let mut b = B::new();
        b.ask(5, 77, ask(1), "a").ok().unwrap();
        let job = b.take_job().unwrap();
        b.done(job.seq, 0, 41, Some(1001));
        b.commit(5, 77, 1, true);
        b.ask_for(5, 77, ask(1), 1, true, "exec").ok().unwrap();
        let job = b.take_job().unwrap();
        assert_eq!(job.id, 41);
        b.done(job.seq, 0, 42, Some(1002));
        assert!(b.commit(5, 77, 1, true));
        assert_eq!(b.current(5, 77, 1), Some(&1002));
        assert_eq!(b.owed(), &[41]);
    }

    #[test]
    fn the_table_of_entries_has_room_for_its_size() {
        let mut b: Budgets<u32, u32> = Budgets::new();
        for i in 0..ENTRIES as u32 {
            let thread = i + 1;
            b.ask(1, 1, ask(thread), 0).ok().unwrap();
            let job = b.take_job().unwrap();
            b.done(job.seq, 0, u64::from(thread), Some(thread));
            b.commit(1, 1, thread, true);
        }
        assert_eq!(b.ask(1, 1, ask(99), 0).err(), Some((Refusal::Room, 0)));
    }
}
