// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The jobs of the files of shared memory segments (BROKER_JOBS). The pages
//! of an XSI segment are the file `/dev/shm/.sysvN` of the file service; the
//! pipe service keeps the rights of the segment and, when they change or the
//! segment goes, a job for its file. It never calls the file service: the file
//! service calls it, on the broker session it has for named pipes, and takes
//! the jobs, at most [JOBS_MAX] (one: a removal of a file is a step of the file
//! service of several thousand ticks) in a call.
//!
//! - BROKER_JOBS: body flags u32 (bit 0: the request brings a handle, a
//!   copy of the file service's channel with NOTIFY only, which the pipe
//!   service keeps to tell it of a job nobody asked for). Reply: status,
//!   more u32 (1 when jobs are left), count u32 (at most JOBS_MAX), and each
//!   job: kind u32, serial u64, uid u32, gid u32, mode u32.
//!
//! Only the file service's broker session (label RAM_BROKER) may call it.
//!
//! The pipe service makes no call that waits to the file service, now or
//! later: the two would wait for each other (the file service calls the pipe
//! service for named pipes and for these jobs). It tells the file service of
//! a job with a notification, which never waits.

use crate::Method;
use proto_wire::{Reader, Status, Writer};

/// The jobs one call gives at most.
pub const JOBS_MAX: usize = 1;
/// The bit of the flags that says the request brings the notify handle.
pub const BRINGS_NOTIFY: u32 = 1;
/// The bit the pipe service notifies the file service with.
pub const NOTIFY_BIT: u64 = 2;

/// What is to be done to the file of the segment `serial`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Job {
    /// Owner, group and the permission bits of the file become these.
    Own {
        serial: u64,
        uid: u32,
        gid: u32,
        mode: u32,
    },
    /// The file is removed.
    Remove { serial: u64 },
}

impl Job {
    pub const fn serial(&self) -> u64 {
        match *self {
            Job::Own { serial, .. } | Job::Remove { serial } => serial,
        }
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        match *self {
            Job::Own {
                serial,
                uid,
                gid,
                mode,
            } => {
                w.u32(1)?;
                w.u64(serial)?;
                w.u32(uid)?;
                w.u32(gid)?;
                w.u32(mode)
            }
            Job::Remove { serial } => {
                w.u32(2)?;
                w.u64(serial)?;
                w.u32(0)?;
                w.u32(0)?;
                w.u32(0)
            }
        }
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Job, Status> {
        let kind = r.u32()?;
        let (serial, uid, gid, mode) = (r.u64()?, r.u32()?, r.u32()?, r.u32()?);
        match kind {
            1 => Ok(Job::Own {
                serial,
                uid,
                gid,
                mode,
            }),
            2 => Ok(Job::Remove { serial }),
            _ => Err(Status::BadSize),
        }
    }
}

/// The request: the flags.
pub fn write_request(flags: u32, w: &mut Writer) -> Result<(), Status> {
    Method::BrokerJobs.header().write(w)?;
    w.u32(flags)
}

pub fn parse_request(mut r: Reader<'_>) -> Result<u32, Status> {
    let flags = r.u32()?;
    r.finish()?;
    if flags & !BRINGS_NOTIFY != 0 {
        return Err(Status::BadSize);
    }
    Ok(flags)
}

/// The reply after the status: whether jobs are left, and the jobs.
pub fn write_reply(
    more: bool,
    jobs: &[Option<Job>; JOBS_MAX],
    w: &mut Writer,
) -> Result<(), Status> {
    w.u32(u32::from(more))?;
    w.u32(jobs.iter().flatten().count() as u32)?;
    for job in jobs.iter().flatten() {
        job.write(w)?;
    }
    Ok(())
}

pub fn read_reply(mut r: Reader<'_>) -> Result<(bool, [Option<Job>; JOBS_MAX]), Status> {
    let more = r.u32()? != 0;
    let count = r.u32()? as usize;
    if count > JOBS_MAX {
        return Err(Status::BadSize);
    }
    let mut jobs = [None; JOBS_MAX];
    for slot in jobs.iter_mut().take(count) {
        *slot = Some(Job::read(&mut r)?);
    }
    r.finish()?;
    Ok((more, jobs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_carries_its_jobs() {
        let jobs = [Some(Job::Own {
            serial: 0x1234_5678_9abc,
            uid: 1000,
            gid: 100,
            mode: 0o640,
        })];
        let mut w = Writer::new();
        write_reply(true, &jobs, &mut w).unwrap();
        let (more, got) = read_reply(Reader::new(w.as_bytes())).unwrap();
        assert!(more);
        assert_eq!(got, jobs);
        let mut w = Writer::new();
        write_request(BRINGS_NOTIFY, &mut w).unwrap();
        assert_eq!(w.as_bytes().len(), proto_wire::HEADER_LEN + 4);
    }

    #[test]
    fn a_reply_of_too_many_jobs_is_refused() {
        let mut w = Writer::new();
        w.u32(0).unwrap();
        w.u32(JOBS_MAX as u32 + 1).unwrap();
        assert!(read_reply(Reader::new(w.as_bytes())).is_err());
    }
}
