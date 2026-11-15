// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The time budgets of POSIX threads under SCHED_SPORADIC (`Method::Budget`;
//! spec 8). The wire format is final for the series 0.5; in 0.5.0 the
//! service gives every operation a refusal and no program binds a budget.
//!
//! The design the format serves: init makes each budget and gives its only
//! handle to the service; no program holds a handle of a budget. A program
//! that asks names its own thread with a handle (MANAGE); the service checks
//! the right (the caller's effective user ID is 0 in 0.5), the limit of
//! `THREADS_MAX` for a process and the share of the user, and its binder
//! thread of the thread's CPU binds, rebinds or unbinds the thread. The
//! service tells init to release a share only after it unbound the budget
//! itself. `exec` keeps the budget of the calling thread for the new image;
//! `fork`, `posix_spawn` and `pthread_create` bind before the new thread
//! starts.
//!
//! Every body is the operation u32 and its fields, in numbers low byte
//! first. Each message has a `flags` word and a reserved word; a bit that
//! is not defined below, and any reserved word that is not zero, is
//! `INVALID` (the readers return it). Through a record's session:
//!
//! - `SET` (`Set`, one handle: the thread, with MANAGE): the thread runs
//!   under a budget of the parameters from now on, a new one or the
//!   replacement of the one it has (a rebind with no moment between).
//! - `CLEAR` (`Clear`): the thread leaves its budget (the policy);
//!   `thread` is its number in the layer's table.
//! - `DROP` (`Clear` again): the thread ended; its budget and share go.
//! - `RESERVE` (`Reserve`): the budget for the main thread of a child of
//!   `fork` or `posix_spawn` (`child` the PID the service gave) or of the new
//!   image of an exec (`child` 0, the budget of `thread` kept). With
//!   `RESERVE_FROM_RECORD` the parameters are those of the caller's thread
//!   in the service's record, and the `Set` fields are zero.
//! - `QUERY` (no body after the operation): the reply is the status u32, the
//!   mask u32 of the CPUs on which POSIX threads have a share, and `flags`
//!   u32 (zero). The mask is what `sysconf(_SC_SPORADIC_SERVER)` reads.
//!
//! Through the channel with no label, from the service's own threads:
//! `WORK` (`Work`, `Job`): the thread that asks init reports the job it did
//! and waits for the next; `BIND_WORK` (`BindWork`, `BindJob`): the binder
//! thread of a CPU reports the bind it did and waits for the next.
//!
//! In 0.5.0 the service answers `QUERY` with mask 0 and every other
//! operation with `FULL`; `INVALID` for a body off the rules, `PERMISSION`
//! for an operation of the channel with no label through a session.

use proto_wire::{Reader, Status, Writer};

pub const SET: u32 = 1;
pub const CLEAR: u32 = 2;
pub const DROP: u32 = 3;
pub const RESERVE: u32 = 4;
pub const QUERY: u32 = 5;
pub const WORK: u32 = 6;
pub const BIND_WORK: u32 = 7;

/// The threads of one process that may run under a budget at once.
pub const THREADS_MAX: u32 = 8;
/// The pending replenishments a budget may ask for, 1 to this.
pub const REPL_MAX: u32 = 4;

/// `Reserve` flag: the parameters are those of the caller's thread.
pub const RESERVE_FROM_RECORD: u32 = 1;

/// The status of a body off the rules.
fn invalid() -> Status {
    Status::from_code(crate::INVALID)
}

/// Flags and reserved word as the readers check them: `allowed` are the
/// bits the message defines.
fn checked(flags: u32, reserved: u32, allowed: u32) -> Result<(), Status> {
    if flags & !allowed != 0 || reserved != 0 {
        return Err(invalid());
    }
    Ok(())
}

/// The body of `SET` after the operation, 40 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Set {
    /// The thread's number in the layer's table.
    pub thread: u32,
    pub cpu: u32,
    /// The level the thread falls to when its budget is gone.
    pub low: u32,
    /// Pending replenishments, 1 to `REPL_MAX`.
    pub max_repl: u32,
    pub flags: u32,
    pub reserved: u32,
    /// The budget C and the period T in nanoseconds.
    pub c_ns: u64,
    pub t_ns: u64,
}

impl Set {
    pub const LEN: usize = 40;

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.thread)?;
        w.u32(self.cpu)?;
        w.u32(self.low)?;
        w.u32(self.max_repl)?;
        w.u32(self.flags)?;
        w.u32(self.reserved)?;
        w.u64(self.c_ns)?;
        w.u64(self.t_ns)
    }

    /// INVALID for a flag that is not defined or a reserved word that is not
    /// zero; the numbers are the service's to check.
    pub fn read(r: &mut Reader<'_>) -> Result<Set, Status> {
        let set = Set {
            thread: r.u32()?,
            cpu: r.u32()?,
            low: r.u32()?,
            max_repl: r.u32()?,
            flags: r.u32()?,
            reserved: r.u32()?,
            c_ns: r.u64()?,
            t_ns: r.u64()?,
        };
        checked(set.flags, set.reserved, 0)?;
        Ok(set)
    }
}

/// The body of `CLEAR` and `DROP` after the operation, 8 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clear {
    pub thread: u32,
    pub flags: u32,
}

impl Clear {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.thread)?;
        w.u32(self.flags)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Clear, Status> {
        let clear = Clear {
            thread: r.u32()?,
            flags: r.u32()?,
        };
        checked(clear.flags, 0, 0)?;
        Ok(clear)
    }
}

/// The body of `RESERVE` after the operation, 56 bytes: the child, the
/// calling thread, `flags` and a reserved word, then a `Set` body (with its
/// own `flags` and reserved word, zero).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reserve {
    pub child: u32,
    pub thread: u32,
    pub flags: u32,
    pub reserved: u32,
    pub set: Set,
}

impl Reserve {
    pub const LEN: usize = 16 + Set::LEN;

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.child)?;
        w.u32(self.thread)?;
        w.u32(self.flags)?;
        w.u32(self.reserved)?;
        self.set.write(w)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Reserve, Status> {
        let reserve = Reserve {
            child: r.u32()?,
            thread: r.u32()?,
            flags: r.u32()?,
            reserved: r.u32()?,
            set: Set::read(r)?,
        };
        checked(reserve.flags, reserve.reserved, RESERVE_FROM_RECORD)?;
        Ok(reserve)
    }
}

/// The reply of `QUERY` after the status, 8 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shares {
    /// The CPUs on which POSIX threads have a share.
    pub mask: u32,
    pub flags: u32,
}

impl Shares {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.mask)?;
        w.u32(self.flags)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Shares, Status> {
        let shares = Shares {
            mask: r.u32()?,
            flags: r.u32()?,
        };
        checked(shares.flags, 0, 0)?;
        Ok(shares)
    }
}

/// The body of `WORK` after the operation, 24 bytes: the number of the job
/// that finished (0 for none), init's status for it, the number init gave
/// the budget, `flags` and a reserved word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Work {
    pub seq: u32,
    pub status: u32,
    pub id: u32,
    pub flags: u32,
    pub reserved: u32,
}

impl Work {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.seq)?;
        w.u32(self.status)?;
        w.u32(self.id)?;
        w.u32(self.flags)?;
        w.u32(self.reserved)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Work, Status> {
        let work = Work {
            seq: r.u32()?,
            status: r.u32()?,
            id: r.u32()?,
            flags: r.u32()?,
            reserved: r.u32()?,
        };
        checked(work.flags, work.reserved, 0)?;
        Ok(work)
    }
}

/// The kinds of job for init and for a binder.
pub const JOB_ASK: u32 = 1;
pub const JOB_RELEASE: u32 = 2;
pub const JOB_BIND: u32 = 3;
pub const JOB_REBIND: u32 = 4;
pub const JOB_UNBIND: u32 = 5;

/// The reply to `WORK` after the status: the next job of the thread that
/// asks init, 56 bytes: the kind, the number of the job, the number of the
/// budget to replace or give back, `flags`, then a `Set` body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Job {
    pub kind: u32,
    pub seq: u32,
    pub id: u32,
    pub flags: u32,
    pub set: Set,
}

impl Job {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.kind)?;
        w.u32(self.seq)?;
        w.u32(self.id)?;
        w.u32(self.flags)?;
        self.set.write(w)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Job, Status> {
        let job = Job {
            kind: r.u32()?,
            seq: r.u32()?,
            id: r.u32()?,
            flags: r.u32()?,
            set: Set::read(r)?,
        };
        checked(job.flags, 0, 0)?;
        Ok(job)
    }
}

/// The body of `BIND_WORK` after the operation, 16 bytes: the job that
/// finished (0 for none), the kernel's status for it (0 or its code),
/// `flags` and a reserved word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindWork {
    pub seq: u32,
    pub status: u32,
    pub flags: u32,
    pub reserved: u32,
}

impl BindWork {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.seq)?;
        w.u32(self.status)?;
        w.u32(self.flags)?;
        w.u32(self.reserved)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<BindWork, Status> {
        let work = BindWork {
            seq: r.u32()?,
            status: r.u32()?,
            flags: r.u32()?,
            reserved: r.u32()?,
        };
        checked(work.flags, work.reserved, 0)?;
        Ok(work)
    }
}

/// The reply to `BIND_WORK` after the status: the next bind of the binder's
/// CPU, 16 bytes: the kind (`JOB_BIND`, `JOB_REBIND`, `JOB_UNBIND`), the
/// number of the job, the entry of the service's table and `flags`; the
/// thread comes as a handle with MANAGE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindJob {
    pub kind: u32,
    pub seq: u32,
    pub entry: u32,
    pub flags: u32,
}

impl BindJob {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.kind)?;
        w.u32(self.seq)?;
        w.u32(self.entry)?;
        w.u32(self.flags)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<BindJob, Status> {
        let job = BindJob {
            kind: r.u32()?,
            seq: r.u32()?,
            entry: r.u32()?,
            flags: r.u32()?,
        };
        checked(job.flags, 0, 0)?;
        Ok(job)
    }
}

/// The refusal of 0.5.0 for an operation of a session: `QUERY` has a reply of
/// its own (`Shares`), every other operation is `FULL`, and a number that is
/// no operation is `INVALID`.
pub const fn refusal(op: u32) -> Option<u32> {
    match op {
        SET | CLEAR | DROP | RESERVE => Some(crate::FULL),
        QUERY | WORK | BIND_WORK => None,
        _ => Some(crate::INVALID),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> Set {
        Set {
            thread: 3,
            cpu: 2,
            low: 4,
            max_repl: 4,
            flags: 0,
            reserved: 0,
            c_ns: 1_000_000,
            t_ns: 10_000_000,
        }
    }

    fn bytes(f: impl FnOnce(&mut Writer) -> Result<(), Status>) -> Vec<u8> {
        let mut w = Writer::new();
        f(&mut w).unwrap();
        w.as_bytes().to_vec()
    }

    #[test]
    fn every_body_keeps_its_fields_and_its_size() {
        let b = bytes(|w| set().write(w));
        assert_eq!(b.len(), Set::LEN);
        assert_eq!(Set::read(&mut Reader::new(&b)), Ok(set()));
        let clear = Clear {
            thread: 5,
            flags: 0,
        };
        let b = bytes(|w| clear.write(w));
        assert_eq!(b.len(), 8);
        assert_eq!(Clear::read(&mut Reader::new(&b)), Ok(clear));
        let reserve = Reserve {
            child: 70,
            thread: 2,
            flags: RESERVE_FROM_RECORD,
            reserved: 0,
            set: Set {
                cpu: 0,
                low: 0,
                max_repl: 0,
                c_ns: 0,
                t_ns: 0,
                ..set()
            },
        };
        let b = bytes(|w| reserve.write(w));
        assert_eq!(b.len(), Reserve::LEN);
        assert_eq!(Reserve::read(&mut Reader::new(&b)), Ok(reserve));
        let shares = Shares {
            mask: 0b1110,
            flags: 0,
        };
        let b = bytes(|w| shares.write(w));
        assert_eq!(b.len(), 8);
        assert_eq!(Shares::read(&mut Reader::new(&b)), Ok(shares));
        let work = Work {
            seq: 9,
            status: 0,
            id: 4,
            flags: 0,
            reserved: 0,
        };
        let b = bytes(|w| work.write(w));
        assert_eq!(b.len(), 20);
        assert_eq!(Work::read(&mut Reader::new(&b)), Ok(work));
        let job = Job {
            kind: JOB_ASK,
            seq: 9,
            id: 4,
            flags: 0,
            set: set(),
        };
        let b = bytes(|w| job.write(w));
        assert_eq!(b.len(), 16 + Set::LEN);
        assert_eq!(Job::read(&mut Reader::new(&b)), Ok(job));
        let bw = BindWork {
            seq: 1,
            status: 0,
            flags: 0,
            reserved: 0,
        };
        let b = bytes(|w| bw.write(w));
        assert_eq!(b.len(), 16);
        assert_eq!(BindWork::read(&mut Reader::new(&b)), Ok(bw));
        let bj = BindJob {
            kind: JOB_BIND,
            seq: 1,
            entry: 2,
            flags: 0,
        };
        let b = bytes(|w| bj.write(w));
        assert_eq!(b.len(), 16);
        assert_eq!(BindJob::read(&mut Reader::new(&b)), Ok(bj));
    }

    #[test]
    fn a_flag_or_a_reserved_word_that_is_not_zero_is_invalid() {
        let bad = Status::from_code(crate::INVALID);
        for (flags, reserved) in [(1, 0), (0, 1), (0x8000_0000, 0)] {
            let b = bytes(|w| {
                Set {
                    flags,
                    reserved,
                    ..set()
                }
                .write(w)
            });
            assert_eq!(Set::read(&mut Reader::new(&b)), Err(bad));
        }
        let b = bytes(|w| {
            Clear {
                thread: 1,
                flags: 2,
            }
            .write(w)
        });
        assert_eq!(Clear::read(&mut Reader::new(&b)), Err(bad));
        let b = bytes(|w| Shares { mask: 0, flags: 1 }.write(w));
        assert_eq!(Shares::read(&mut Reader::new(&b)), Err(bad));
        let b = bytes(|w| {
            Work {
                seq: 0,
                status: 0,
                id: 0,
                flags: 0,
                reserved: 7,
            }
            .write(w)
        });
        assert_eq!(Work::read(&mut Reader::new(&b)), Err(bad));
        let b = bytes(|w| {
            BindWork {
                seq: 0,
                status: 0,
                flags: 4,
                reserved: 0,
            }
            .write(w)
        });
        assert_eq!(BindWork::read(&mut Reader::new(&b)), Err(bad));
        let b = bytes(|w| {
            BindJob {
                kind: 1,
                seq: 0,
                entry: 0,
                flags: 1,
            }
            .write(w)
        });
        assert_eq!(BindJob::read(&mut Reader::new(&b)), Err(bad));
        // RESERVE defines one flag; the next bit and the reserved word are refused.
        for (flags, reserved) in [(2, 0), (RESERVE_FROM_RECORD, 1)] {
            let r = Reserve {
                child: 1,
                thread: 1,
                flags,
                reserved,
                set: set(),
            };
            let b = bytes(|w| r.write(w));
            assert_eq!(Reserve::read(&mut Reader::new(&b)), Err(bad));
        }
        // The Set inside a Reserve is checked too.
        let r = Reserve {
            child: 1,
            thread: 1,
            flags: 0,
            reserved: 0,
            set: Set { flags: 1, ..set() },
        };
        let b = bytes(|w| r.write(w));
        assert_eq!(Reserve::read(&mut Reader::new(&b)), Err(bad));
    }

    #[test]
    fn a_short_body_is_a_size_error() {
        let b = bytes(|w| set().write(w));
        assert!(Set::read(&mut Reader::new(&b[..Set::LEN - 1])).is_err());
    }

    #[test]
    fn in_0_5_0_every_operation_of_a_session_is_refused_but_the_query() {
        for op in [SET, CLEAR, DROP, RESERVE] {
            assert_eq!(refusal(op), Some(crate::FULL));
        }
        assert_eq!(refusal(QUERY), None);
        assert_eq!(refusal(0), Some(crate::INVALID));
        assert_eq!(refusal(8), Some(crate::INVALID));
    }
}
