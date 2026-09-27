// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The jobs of init's worker thread (spec 8, 13.4): it loads instances,
//! tears down those that ended and kills those that went silent, one job
//! at a time, while init's main thread at 63 serves its channel. The main
//! thread keeps the jobs (`Jobs`) and sets the worker's level: one above
//! the highest ceiling among the service of the job it does and those of
//! the jobs that wait, at most 62. Work that grows with the size of a
//! service so runs above the service and below the more important ones,
//! and a job that comes while a less important one runs lifts the worker
//! at once: it waits for no more than the rest of one job.

use crate::table::{MAX_RECORDS, Record};
use proto_init::Work;

/// The highest level of the worker, under init's 63.
pub const WORKER_MAX: u8 = 62;
/// The level of the worker with no job.
pub const WORKER_IDLE: u8 = 1;

/// A job of the worker: its work, the place of its record in init's table,
/// and the ceiling of that record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Job {
    pub work: Work,
    pub record: usize,
    pub ceiling: u8,
}

impl Job {
    /// The job of `work` for `record`, at place `place` of the table.
    pub const fn new(work: Work, place: usize, record: &Record) -> Job {
        Job {
            work,
            record: place,
            ceiling: record.ceiling,
        }
    }
}

/// The jobs that wait for the worker: at most one for each record, taken
/// by the ceiling of their record, highest first, and within a level in
/// the order they came.
#[derive(Debug)]
pub struct Queue {
    /// By the place of the record: the job and when it came.
    jobs: [Option<(Job, u64)>; MAX_RECORDS],
    came: u64,
}

impl Queue {
    pub const fn new() -> Queue {
        Queue {
            jobs: [None; MAX_RECORDS],
            came: 0,
        }
    }

    /// Puts `job` in the queue; it comes back when a job of its record
    /// waits already, or its record is past MAX_RECORDS.
    pub fn push(&mut self, job: Job) -> Result<(), Job> {
        match self.jobs.get_mut(job.record) {
            Some(slot @ None) => {
                *slot = Some((job, self.came));
                self.came += 1;
                Ok(())
            }
            _ => Err(job),
        }
    }

    /// Takes the next job out of the queue.
    pub fn pop(&mut self) -> Option<Job> {
        let (place, _) = self
            .jobs
            .iter()
            .enumerate()
            .filter_map(|(p, j)| j.map(|(job, came)| (p, (job.ceiling, u64::MAX - came))))
            .max_by_key(|&(_, key)| key)?;
        self.jobs[place].take().map(|(job, _)| job)
    }

    /// Whether a job of the record at `place` waits.
    pub fn holds(&self, place: usize) -> bool {
        self.jobs.get(place).is_some_and(Option::is_some)
    }

    pub fn len(&self) -> usize {
        self.jobs.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The highest ceiling among the jobs that wait.
    pub fn top(&self) -> Option<u8> {
        self.jobs.iter().flatten().map(|(job, _)| job.ceiling).max()
    }
}

impl Default for Queue {
    fn default() -> Queue {
        Queue::new()
    }
}

/// The worker's jobs (spec 13.4): the one it does and those that wait.
#[derive(Debug, Default)]
pub struct Jobs {
    queue: Queue,
    current: Option<Job>,
}

impl Jobs {
    pub const fn new() -> Jobs {
        Jobs {
            queue: Queue::new(),
            current: None,
        }
    }

    /// The job the worker does.
    pub fn current(&self) -> Option<Job> {
        self.current
    }

    /// The jobs that wait.
    pub fn queue(&self) -> &Queue {
        &self.queue
    }

    /// Puts `job` in the queue (Queue::push, whose refusal gives it back):
    /// the level the worker goes to at once while it does a job, above the
    /// job that came when its record is the higher; None for an idle
    /// worker, which gets its next job through `pop` and `start`.
    pub fn push(&mut self, job: Job) -> Result<Option<u8>, Job> {
        self.queue.push(job)?;
        let level = worker_level(self.current, &self.queue);
        Ok(self.current.is_some().then_some(level))
    }

    /// Takes the next job out of the queue (Queue::pop) for an idle
    /// worker, for `start` or to be dropped; None while the worker does a
    /// job.
    pub fn pop(&mut self) -> Option<Job> {
        match self.current {
            Some(_) => None,
            None => self.queue.pop(),
        }
    }

    /// `job`, taken out of the queue, is the worker's from now on: its
    /// level with the jobs that wait (`worker_level`).
    pub fn start(&mut self, job: Job) -> u8 {
        self.current = Some(job);
        worker_level(self.current, &self.queue)
    }

    /// The worker did its job: that job, None for an idle worker.
    pub fn done(&mut self) -> Option<Job> {
        self.current.take()
    }
}

/// The level of the worker while it does `current` and `queue` waits: one
/// above the highest ceiling among them, at most WORKER_MAX; WORKER_IDLE
/// with no job at all.
pub fn worker_level(current: Option<Job>, queue: &Queue) -> u8 {
    match current.map(|j| j.ceiling).max(queue.top()) {
        Some(ceiling) => ceiling.saturating_add(1).min(WORKER_MAX),
        None => WORKER_IDLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::{Kind, Restart};
    use crate::watch::Watch;

    /// A service at `priority` under `ceiling`.
    const fn record(priority: u8, ceiling: u8) -> Record {
        Record {
            name: "svc",
            program: "svc",
            kind: Kind::Service(Watch {
                period_ns: 20_000_000,
                deadline_ns: 100_000_000,
            }),
            priority,
            ceiling,
            quota: 16 * crate::PAGE,
            handle_limit: 16,
            restart: Restart::Always,
            console: false,
            log: false,
            trace: false,
            windows: &[],
            bindings: &[],
            connects: &[],
            args: &[],
        }
    }

    fn drain(q: &mut Queue) -> Vec<usize> {
        core::iter::from_fn(|| q.pop()).map(|j| j.record).collect()
    }

    #[test]
    fn jobs_go_by_the_ceiling_of_their_service() {
        // Base priorities in the other order than the ceilings.
        let table = [record(20, 20), record(30, 40), record(35, 35)];
        let mut q = Queue::new();
        for (place, r) in table.iter().enumerate() {
            q.push(Job::new(Work::Load, place, r)).unwrap();
        }
        assert_eq!(q.len(), 3);
        assert_eq!(q.top(), Some(40));
        assert_eq!(drain(&mut q), [1, 2, 0]);
        assert!(q.is_empty());
    }

    #[test]
    fn equal_levels_keep_their_order() {
        let table = [record(40, 40); 6];
        let mut q = Queue::new();
        for place in [3, 1, 5] {
            q.push(Job::new(Work::Teardown, place, &table[place]))
                .unwrap();
        }
        assert_eq!(q.pop().map(|j| j.record), Some(3));
        for place in [0, 4] {
            q.push(Job::new(Work::Load, place, &table[place])).unwrap();
        }
        assert_eq!(drain(&mut q), [1, 5, 0, 4]);
    }

    #[test]
    fn the_worker_takes_the_highest_pending_level() {
        let table = [record(20, 20), record(40, 40), record(30, 30)];
        let mut q = Queue::new();
        assert_eq!(worker_level(None, &q), WORKER_IDLE);
        let current = Job::new(Work::Load, 0, &table[0]);
        assert_eq!(worker_level(Some(current), &q), 21);
        // A job of a service above comes while the load of the one below
        // runs: the worker goes above the waiting one at once.
        q.push(Job::new(Work::Teardown, 1, &table[1])).unwrap();
        assert_eq!(worker_level(Some(current), &q), 41);
        // One below changes nothing.
        q.push(Job::new(Work::Kill, 2, &table[2])).unwrap();
        assert_eq!(worker_level(Some(current), &q), 41);
        // The next job: the level is worked out again.
        let next = q.pop().unwrap();
        assert_eq!((next.record, next.work), (1, Work::Teardown));
        assert_eq!(worker_level(Some(next), &q), 41);
        let last = q.pop().unwrap();
        assert_eq!(worker_level(Some(last), &q), 31);
        assert_eq!(worker_level(None, &q), WORKER_IDLE);
    }

    #[test]
    fn a_job_that_comes_lifts_the_busy_worker() {
        let table = [record(20, 20), record(40, 40), record(30, 30)];
        let mut jobs = Jobs::new();
        // An idle worker: the job waits for `start`, and the worker's level
        // comes with it.
        let load = Job::new(Work::Load, 0, &table[0]);
        assert_eq!(jobs.push(load), Ok(None));
        assert_eq!(jobs.current(), None);
        assert_eq!(jobs.pop(), Some(load));
        assert_eq!(jobs.start(load), 21);
        assert_eq!(jobs.current(), Some(load));
        // The teardown of a service above comes during the load: the worker
        // goes above it at once, and one below leaves it there.
        let teardown = Job::new(Work::Teardown, 1, &table[1]);
        assert_eq!(jobs.push(teardown), Ok(Some(41)));
        let kill = Job::new(Work::Kill, 2, &table[2]);
        assert_eq!(jobs.push(kill), Ok(Some(41)));
        // A second job of a record whose job waits comes back.
        let again = Job::new(Work::Load, 1, &table[1]);
        assert_eq!(jobs.push(again), Err(again));
        // Nothing comes out of the queue while the worker does a job.
        assert_eq!(jobs.pop(), None);
        assert_eq!(jobs.queue().len(), 2);
        // The load is done; the next job goes by its ceiling.
        assert_eq!(jobs.done(), Some(load));
        assert_eq!(jobs.done(), None);
        assert_eq!(jobs.pop(), Some(teardown));
        assert_eq!(jobs.start(teardown), 41);
        // A load below comes during the teardown: the level stays.
        assert_eq!(jobs.push(load), Ok(Some(41)));
        assert_eq!(jobs.done(), Some(teardown));
        assert_eq!(jobs.pop(), Some(kill));
        assert_eq!(jobs.start(kill), 31);
        assert_eq!(jobs.done(), Some(kill));
        assert_eq!(jobs.pop(), Some(load));
        assert!(jobs.queue().is_empty());
    }

    #[test]
    fn the_worker_stays_below_63() {
        let top = record(61, 61);
        let q = Queue::new();
        assert_eq!(worker_level(Some(Job::new(Work::Kill, 0, &top)), &q), 62);
        let mut q = Queue::new();
        q.push(Job::new(Work::Load, 1, &record(40, 40))).unwrap();
        assert_eq!(worker_level(Some(Job::new(Work::Load, 0, &top)), &q), 62);
        // A ceiling past the table's keeps the worker at 62 too.
        for ceiling in [62, 63, u8::MAX] {
            let job = Job::new(Work::Kill, 0, &record(ceiling, ceiling));
            assert_eq!(worker_level(Some(job), &Queue::new()), WORKER_MAX);
            let mut q = Queue::new();
            q.push(job).unwrap();
            assert_eq!(worker_level(None, &q), WORKER_MAX);
        }
    }

    #[test]
    fn one_job_per_service() {
        let r = record(40, 40);
        let mut q = Queue::new();
        let load = Job::new(Work::Load, 2, &r);
        q.push(load).unwrap();
        let kill = Job::new(Work::Kill, 2, &r);
        assert_eq!(q.push(kill), Err(kill));
        assert!(q.holds(2));
        assert!(!q.holds(1));
        assert_eq!(q.len(), 1);
        assert_eq!(q.pop(), Some(load));
        // Once taken, the record may have a job again.
        assert_eq!(q.push(kill), Ok(()));
        let far = Job::new(Work::Load, MAX_RECORDS, &r);
        assert_eq!(q.push(far), Err(far));
        // Every record of a full table has its place.
        let mut q = Queue::new();
        for place in 0..MAX_RECORDS {
            q.push(Job::new(Work::Load, place, &r)).unwrap();
        }
        assert_eq!(q.len(), MAX_RECORDS);
    }
}
