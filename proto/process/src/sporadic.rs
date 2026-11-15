// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The time budgets of POSIX threads (`Method::Budget`, SCHED_SPORADIC; spec
//! 8). The service keeps one entry for each thread of a process that runs
//! under a sporadic server: the thread's number in the layer's table, the
//! number init gave its budget and the handle of the budget. The handle
//! stays with the service, so that a program cannot shed the budget of its
//! thread: it gets a copy with the rights BUDGET and TRANSFER (no DUPLICATE) for the
//! time of one bind, and the service gives the current budget back only for a thread
//! that leaves the policy through the service.
//!
//! The body of a request is the operation u32 (`ask`, `done`, ...) and its
//! fields. Through a record's session:
//!
//! - ASK (`Ask`): a budget for the thread. The reply waits until init
//!   admitted or refused the share (the service's budget thread asks init):
//!   status u32 (`FULL` for a refused share, `INVALID` for numbers the kernel
//!   refuses, `AGAIN` while another request of the record waits or the
//!   service has no room for the entry), zero u32 and, with status 0, one
//!   handle, the new budget (BUDGET), and a second one, the budget the thread
//!   has now, when it has one. The entry is on probation until DONE.
//! - DONE: thread u32, bound u32. 1: the thread was bound (to the new budget,
//!   or taken off the old one); the service keeps the new entry and gives
//!   the old share back. 0: the bind failed; the new share goes back and the
//!   old entry stays. A probation entry that nobody finishes stays until the
//!   record ends.
//! - UNBIND: thread u32; reply status u32, zero u32 and one handle, the
//!   thread's current budget (BUDGET), for the thread that leaves the
//!   policy; NO_PROCESS when the thread has no entry. DONE with 1 follows.
//! - DROP: thread u32: the entry goes and the share with it (the thread
//!   ended, or a bind of a new thread failed); the reply is its status.
//!
//! Through the channel with no label, from the service's own budget thread
//! (WORK): the result of its last job (`Done`) and, with the reply, its next
//! job (`Job`), which waits until the loop has one.

use proto_wire::{Reader, Status, Writer};

/// The status of a refused share in the budget thread's reply (`FULL`).
pub const SHARE_REFUSED: u32 = crate::FULL;

pub const ASK: u32 = 1;
pub const DONE: u32 = 2;
pub const UNBIND: u32 = 3;
pub const DROP: u32 = 4;
/// The budget thread's request (label 0 only).
pub const WORK: u32 = 5;

/// The threads of one process that may run under a budget at once.
pub const THREADS_MAX: usize = 8;

/// The body of ASK after the operation: 40 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ask {
    /// The thread's number in the layer's table.
    pub thread: u32,
    pub cpu: u32,
    /// The level the thread falls to when its budget is gone.
    pub low: u32,
    pub max_repl: u32,
    pub c_ns: u64,
    pub t_ns: u64,
}

impl Ask {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.thread)?;
        w.u32(self.cpu)?;
        w.u32(self.low)?;
        w.u32(self.max_repl)?;
        w.u64(self.c_ns)?;
        w.u64(self.t_ns)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Ask, Status> {
        Ok(Ask {
            thread: r.u32()?,
            cpu: r.u32()?,
            low: r.u32()?,
            max_repl: r.u32()?,
            c_ns: r.u64()?,
            t_ns: r.u64()?,
        })
    }
}

/// The kinds of job the budget thread gets.
pub const JOB_ASK: u32 = 1;
pub const JOB_RELEASE: u32 = 2;

/// The reply to WORK: the next job of the budget thread, 44 bytes after
/// the status: the kind u32, the job's number u32 (which the thread's next
/// WORK names), the number u64 of the budget to replace (ASK) or to give
/// back (RELEASE), and the `Ask` fields of an ASK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Job {
    pub kind: u32,
    pub seq: u32,
    pub id: u64,
    pub ask: Ask,
}

impl Job {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.kind)?;
        w.u32(self.seq)?;
        w.u64(self.id)?;
        self.ask.write(w)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Job, Status> {
        Ok(Job {
            kind: r.u32()?,
            seq: r.u32()?,
            id: r.u64()?,
            ask: Ask::read(r)?,
        })
    }
}

/// The body of WORK after the operation: the number u32 of the job that
/// finished (0 for none yet), init's status for it as a u32 (0, or the
/// kernel's code of its refusal) and the budget's number u64 that init
/// gave; one handle, the budget, when the status is 0 for an ASK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Done {
    pub seq: u32,
    pub status: u32,
    pub id: u64,
}

impl Done {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.seq)?;
        w.u32(self.status)?;
        w.u64(self.id)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Done, Status> {
        Ok(Done {
            seq: r.u32()?,
            status: r.u32()?,
            id: r.u64()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fields_keep_their_sizes() {
        let ask = Ask {
            thread: 3,
            cpu: 2,
            low: 4,
            max_repl: 4,
            c_ns: 1_000_000,
            t_ns: 10_000_000,
        };
        let mut w = Writer::new();
        ask.write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 32);
        assert_eq!(Ask::read(&mut Reader::new(w.as_bytes())), Ok(ask));
        let job = Job {
            kind: JOB_ASK,
            seq: 9,
            id: 5,
            ask,
        };
        let mut w = Writer::new();
        job.write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 48);
        assert_eq!(Job::read(&mut Reader::new(w.as_bytes())), Ok(job));
        let done = Done {
            seq: 9,
            status: 0,
            id: 77,
        };
        let mut w = Writer::new();
        done.write(&mut w).unwrap();
        assert_eq!(Done::read(&mut Reader::new(w.as_bytes())), Ok(done));
    }
}
