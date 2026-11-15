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
//! - `GET` (`Get`): the policy and the parameters of the thread, for
//!   `sched_getparam` and `pthread_getschedparam` of a thread under a budget,
//!   also in a new image after an exec that kept the budget. The reply is
//!   the status u32, a zero u32 and `Params`.
//! - `QUERY` (`Query`): the shares of the CPUs from `first`, at most `count`
//!   (and `SHARES_MAX`) of them. The reply is the status u32, a zero u32,
//!   `SharesHead` and `head.count` entries of `Share` (the total of POSIX
//!   threads and what is used of it, in parts per million). The form has no
//!   width: the kernel starts 8 CPUs at most (`kboot::bootinfo::MAX_CPUS`),
//!   and a CPU past `head.cpus` has no entry. A CPU has a share when its
//!   total is not 0; `sysconf(_SC_SPORADIC_SERVER)` reads that.
//!
//! Through the channel with no label, from the service's own threads:
//! `WORK` (`Work`, `Job`): the thread that asks init reports the job it did
//! and waits for the next; `BIND_WORK` (`BindWork`, `BindJob`): the binder
//! thread of a CPU reports the bind it did and waits for the next.
//!
//! In 0.5.0 the service answers `QUERY` with no CPU (`head.cpus` 0) and every
//! other operation with `FULL`; `INVALID` for a body off the rules,
//! `PERMISSION` for an operation of the channel with no label through a
//! session, and `UnknownMethod` (proto_wire) for a number that is no operation,
//! so that a later layer can probe for an operation.
//!
//! The fingerprint of the series hashes the version of this crate alone, so
//! the tests of this file are the guard of the wire format: every message
//! has its size and a round trip tested, and a change of a body with no
//! change of its test fails them.

use proto_wire::{Reader, Status, Writer};

pub const SET: u32 = 1;
pub const CLEAR: u32 = 2;
pub const DROP: u32 = 3;
pub const RESERVE: u32 = 4;
pub const QUERY: u32 = 5;
pub const WORK: u32 = 6;
pub const BIND_WORK: u32 = 7;
pub const GET: u32 = 8;

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

/// The body of `CLEAR`, `DROP` and `GET` after the operation, 12 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clear {
    pub thread: u32,
    pub flags: u32,
    pub reserved: u32,
}

/// `GET` takes the same body.
pub type Get = Clear;

impl Clear {
    pub const LEN: usize = 12;

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.thread)?;
        w.u32(self.flags)?;
        w.u32(self.reserved)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Clear, Status> {
        let clear = Clear {
            thread: r.u32()?,
            flags: r.u32()?,
            reserved: r.u32()?,
        };
        checked(clear.flags, clear.reserved, 0)?;
        Ok(clear)
    }
}

/// The reply of `GET` after the status and a zero u32, 40 bytes: the POSIX
/// policy of the thread, `flags`, and the parameters as `Set` has them
/// (the CPU, `low`, `max_repl`, C, T; the policy is 4 for a thread under a
/// budget).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub policy: u32,
    pub flags: u32,
    pub cpu: u32,
    pub low: u32,
    pub max_repl: u32,
    pub reserved: u32,
    pub c_ns: u64,
    pub t_ns: u64,
}

impl Params {
    pub const LEN: usize = 40;

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.policy)?;
        w.u32(self.flags)?;
        w.u32(self.cpu)?;
        w.u32(self.low)?;
        w.u32(self.max_repl)?;
        w.u32(self.reserved)?;
        w.u64(self.c_ns)?;
        w.u64(self.t_ns)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Params, Status> {
        let params = Params {
            policy: r.u32()?,
            flags: r.u32()?,
            cpu: r.u32()?,
            low: r.u32()?,
            max_repl: r.u32()?,
            reserved: r.u32()?,
            c_ns: r.u64()?,
            t_ns: r.u64()?,
        };
        checked(params.flags, params.reserved, 0)?;
        Ok(params)
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

/// The most entries one reply of `QUERY` carries.
pub const SHARES_MAX: u32 = 64;

/// The body of `QUERY` after the operation, 16 bytes: the first CPU asked
/// about, `flags`, a reserved word and how many CPUs at most.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Query {
    pub first: u32,
    pub flags: u32,
    pub reserved: u32,
    pub count: u32,
}

impl Query {
    pub const LEN: usize = 16;

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.first)?;
        w.u32(self.flags)?;
        w.u32(self.reserved)?;
        w.u32(self.count)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Query, Status> {
        let query = Query {
            first: r.u32()?,
            flags: r.u32()?,
            reserved: r.u32()?,
            count: r.u32()?,
        };
        checked(query.flags, query.reserved, 0)?;
        Ok(query)
    }
}

/// The head of the reply of `QUERY` after the status and a zero u32, 16
/// bytes: `flags`, a reserved word, the CPUs the table covers (0 when no CPU
/// has a share) and the number of `Share` entries that follow, which start at
/// CPU `first` of the query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharesHead {
    pub flags: u32,
    pub reserved: u32,
    pub cpus: u32,
    pub count: u32,
}

impl SharesHead {
    pub const LEN: usize = 16;

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.flags)?;
        w.u32(self.reserved)?;
        w.u32(self.cpus)?;
        w.u32(self.count)
    }

    /// INVALID for a flag or a reserved word that is not zero, or a count
    /// above `SHARES_MAX`.
    pub fn read(r: &mut Reader<'_>) -> Result<SharesHead, Status> {
        let head = SharesHead {
            flags: r.u32()?,
            reserved: r.u32()?,
            cpus: r.u32()?,
            count: r.u32()?,
        };
        checked(head.flags, head.reserved, 0)?;
        if head.count > SHARES_MAX {
            return Err(invalid());
        }
        Ok(head)
    }
}

/// One entry of the reply of `QUERY`, 8 bytes: the share of the CPU that POSIX
/// threads may take together, and what they take of it now, in parts per
/// million.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Share {
    pub total_ppm: u32,
    pub used_ppm: u32,
}

impl Share {
    pub const LEN: usize = 8;

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.total_ppm)?;
        w.u32(self.used_ppm)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Share, Status> {
        Ok(Share {
            total_ppm: r.u32()?,
            used_ppm: r.u32()?,
        })
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

    fn round<T: PartialEq + core::fmt::Debug + Copy>(
        value: T,
        len: usize,
        write: impl Fn(&T, &mut Writer) -> Result<(), Status>,
        read: impl Fn(&mut Reader<'_>) -> Result<T, Status>,
    ) {
        let b = bytes(|w| write(&value, w));
        assert_eq!(b.len(), len);
        let mut r = Reader::new(&b);
        assert_eq!(read(&mut r), Ok(value));
        assert_eq!(r.finish(), Ok(()));
        assert!(
            read(&mut Reader::new(&b[..len - 1])).is_err(),
            "a short body"
        );
    }

    #[test]
    fn every_message_keeps_its_fields_and_its_size() {
        round(set(), Set::LEN, Set::write, Set::read);
        round(
            Clear {
                thread: 5,
                flags: 0,
                reserved: 0,
            },
            Clear::LEN,
            Clear::write,
            Clear::read,
        );
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
        round(reserve, Reserve::LEN, Reserve::write, Reserve::read);
        let params = Params {
            policy: 4,
            flags: 0,
            cpu: 2,
            low: 4,
            max_repl: 4,
            reserved: 0,
            c_ns: 1,
            t_ns: 2,
        };
        round(params, Params::LEN, Params::write, Params::read);
        round(
            Query {
                first: 0,
                flags: 0,
                reserved: 0,
                count: 8,
            },
            Query::LEN,
            Query::write,
            Query::read,
        );
        round(
            SharesHead {
                flags: 0,
                reserved: 0,
                cpus: 4,
                count: 4,
            },
            SharesHead::LEN,
            SharesHead::write,
            SharesHead::read,
        );
        round(
            Share {
                total_ppm: 500_000,
                used_ppm: 100_000,
            },
            Share::LEN,
            Share::write,
            Share::read,
        );
        let work = Work {
            seq: 9,
            status: 0,
            id: 4,
            flags: 0,
            reserved: 0,
        };
        round(work, 20, Work::write, Work::read);
        let job = Job {
            kind: JOB_ASK,
            seq: 9,
            id: 4,
            flags: 0,
            set: set(),
        };
        round(job, 16 + Set::LEN, Job::write, Job::read);
        round(
            BindWork {
                seq: 1,
                status: 0,
                flags: 0,
                reserved: 0,
            },
            16,
            BindWork::write,
            BindWork::read,
        );
        round(
            BindJob {
                kind: JOB_BIND,
                seq: 1,
                entry: 2,
                flags: 0,
            },
            16,
            BindJob::write,
            BindJob::read,
        );
    }

    #[test]
    fn the_operation_numbers_are_fixed() {
        assert_eq!(
            [SET, CLEAR, DROP, RESERVE, QUERY, WORK, BIND_WORK, GET],
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
        assert_eq!((THREADS_MAX, REPL_MAX, SHARES_MAX), (8, 4, 64));
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
            let b = bytes(|w| {
                Clear {
                    thread: 1,
                    flags,
                    reserved,
                }
                .write(w)
            });
            assert_eq!(Clear::read(&mut Reader::new(&b)), Err(bad));
            let b = bytes(|w| {
                Query {
                    first: 0,
                    flags,
                    reserved,
                    count: 1,
                }
                .write(w)
            });
            assert_eq!(Query::read(&mut Reader::new(&b)), Err(bad));
            let b = bytes(|w| {
                SharesHead {
                    flags,
                    reserved,
                    cpus: 0,
                    count: 0,
                }
                .write(w)
            });
            assert_eq!(SharesHead::read(&mut Reader::new(&b)), Err(bad));
            let b = bytes(|w| {
                Work {
                    seq: 0,
                    status: 0,
                    id: 0,
                    flags,
                    reserved,
                }
                .write(w)
            });
            assert_eq!(Work::read(&mut Reader::new(&b)), Err(bad));
            let b = bytes(|w| {
                BindWork {
                    seq: 0,
                    status: 0,
                    flags,
                    reserved,
                }
                .write(w)
            });
            assert_eq!(BindWork::read(&mut Reader::new(&b)), Err(bad));
            let p = Params {
                policy: 0,
                flags,
                cpu: 0,
                low: 0,
                max_repl: 0,
                reserved,
                c_ns: 0,
                t_ns: 0,
            };
            let b = bytes(|w| p.write(w));
            assert_eq!(Params::read(&mut Reader::new(&b)), Err(bad));
        }
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
        let r = Reserve {
            child: 1,
            thread: 1,
            flags: 0,
            reserved: 0,
            set: Set { flags: 1, ..set() },
        };
        let b = bytes(|w| r.write(w));
        assert_eq!(Reserve::read(&mut Reader::new(&b)), Err(bad));
        // A reply that claims more entries than a reply holds.
        let b = bytes(|w| {
            SharesHead {
                flags: 0,
                reserved: 0,
                cpus: 8,
                count: SHARES_MAX + 1,
            }
            .write(w)
        });
        assert_eq!(SharesHead::read(&mut Reader::new(&b)), Err(bad));
    }
}
