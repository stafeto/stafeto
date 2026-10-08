// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! One admitted data operation retains arguments, bytes and its cleanup obligation.

use crate::{
    Fds, Ram,
    io::{DataLease, TruncatePreparation, WritePreparation},
    storage::Token,
};
use proto_fs::{DataKind, DataOutcome, DataPhase, DataResult, DataStart, Timestamp};

// The fixed paid job owns this union without another allocator.
#[allow(clippy::large_enum_variant)]
enum Preparation {
    Captured(DataLease),
    Write(WritePreparation),
    Truncate(TruncatePreparation),
    Empty,
}

/// Admission and authenticated session ownership belong to the outer service job.
pub struct Journal {
    pub args: DataStart,
    pub phase: DataPhase,
    result: DataResult,
    prepared: Preparation,
    bytes: [u8; proto_fs::MAX_READ],
    fed: usize,
    rebuilding: bool,
    cleanup_done: bool,
    originating_root: crate::storage::Root,
}

impl Journal {
    pub fn capture(ram: &mut Ram<'_>, fds: &Fds, args: DataStart) -> Result<Self, u32> {
        args.validate().map_err(|error| error.code())?;
        let lease = ram.capture_data_lease(
            fds,
            args.description.fd(),
            Token {
                slot: args.description.slot() as u16,
                generation: args.description.generation,
            },
        )?;
        if let Err(code) = lease.validate_kind(args.kind) {
            lease.cancel(ram);
            return Err(code);
        }
        Ok(Self {
            args,
            phase: DataPhase::Captured,
            result: DataResult::None,
            prepared: Preparation::Captured(lease),
            bytes: [0; proto_fs::MAX_READ],
            fed: 0,
            rebuilding: false,
            cleanup_done: false,
            originating_root: fds.root,
        })
    }

    /// Host fault injection retains prepared pages through a cached terminal result.
    #[cfg(feature = "host-replay")]
    pub fn fail_cleanup_replay(&mut self, code: u32) {
        assert!(proto_fs::terminal_failure(code));
        assert_eq!(self.result, DataResult::None);
        let _ = self.fail(code);
    }

    pub fn originating_root(&self) -> crate::storage::Root {
        self.originating_root
    }

    pub fn outcome(&self, job: u64) -> DataOutcome {
        DataOutcome {
            phase: self.phase,
            job,
            result: self.result,
        }
    }

    pub fn feed(&mut self, offset: usize, bytes: &[u8]) -> Result<(), u32> {
        let end = offset
            .checked_add(bytes.len())
            .ok_or(proto_fs::INVALID_ARGUMENT)?;
        if !self.args.kind.writes()
            || bytes.len() > proto_fs::FEED_MAX
            || end > self.args.count as usize
        {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        if end <= self.fed {
            return if self.bytes[offset..end] == *bytes {
                Ok(())
            } else {
                Err(proto_fs::PERMISSION)
            };
        }
        if offset != self.fed || !matches!(self.phase, DataPhase::Captured | DataPhase::Feeding) {
            return Err(proto_fs::PERMISSION);
        }
        self.bytes[offset..end].copy_from_slice(bytes);
        self.fed = end;
        self.phase = DataPhase::Feeding;
        Ok(())
    }

    fn fail(&mut self, code: u32) -> Result<bool, u32> {
        if code == proto_fs::STALE_PROOF {
            self.rebuilding = true;
            self.phase = DataPhase::Preparing;
            return Err(proto_fs::RESOLVING);
        }
        if proto_fs::terminal_failure(code) {
            self.phase = DataPhase::Completed;
            self.result = DataResult::FailedNoEffect(code);
        }
        Err(code)
    }

    /// One capture, one preparation or one private page initialization per call.
    pub fn step(&mut self, ram: &mut Ram<'_>) -> Result<bool, u32> {
        if self.phase == DataPhase::Completed {
            return Ok(true);
        }
        if self.phase == DataPhase::Canceling {
            return Err(proto_fs::OPEN_RETIRED);
        }
        if matches!(self.phase, DataPhase::Ready | DataPhase::TimeDeferred) {
            return Ok(true);
        }
        if self.rebuilding {
            let lease = match &mut self.prepared {
                Preparation::Write(prepared) => prepared.restart_step(ram)?,
                Preparation::Truncate(prepared) => prepared.restart_step(ram)?,
                Preparation::Captured(lease) => {
                    lease.refresh(ram)?;
                    self.rebuilding = false;
                    return Ok(false);
                }
                Preparation::Empty => return Err(proto_fs::BAD_FD),
            };
            if let Some(lease) = lease {
                self.prepared = Preparation::Captured(lease);
            }
            return Ok(false);
        }
        if self.args.kind.writes() && self.fed != self.args.count as usize {
            return Ok(false);
        }
        if matches!(self.prepared, Preparation::Captured(_)) {
            if self.args.kind.reads() {
                self.phase = DataPhase::Ready;
                return Ok(true);
            }
            let Preparation::Captured(lease) =
                core::mem::replace(&mut self.prepared, Preparation::Empty)
            else {
                unreachable!()
            };
            if self.args.kind == DataKind::Truncate {
                match ram.prepare_truncate_held(lease, self.args.position) {
                    Ok(prepared) => self.prepared = Preparation::Truncate(prepared),
                    Err((code, lease)) => {
                        self.prepared = Preparation::Captured(lease);
                        return self.fail(code);
                    }
                }
            } else {
                let position = (self.args.kind == DataKind::PWrite).then_some(self.args.position);
                match ram.prepare_write_held(lease, &self.bytes[..self.fed], position) {
                    Ok(prepared) => self.prepared = Preparation::Write(prepared),
                    Err((code, lease)) => {
                        self.prepared = Preparation::Captured(lease);
                        return self.fail(code);
                    }
                }
            }
            self.phase = DataPhase::Preparing;
            return Ok(false);
        }
        let ready = match &mut self.prepared {
            Preparation::Write(prepared) => prepared.step(ram),
            Preparation::Truncate(prepared) => prepared.step(ram),
            _ => return Err(proto_fs::BAD_FD),
        };
        match ready {
            Ok(ready) => {
                if ready {
                    self.phase = DataPhase::Ready;
                }
                Ok(ready)
            }
            Err(code) => self.fail(code),
        }
    }

    pub fn needs_time(&self) -> bool {
        self.result == DataResult::None
            && (self.args.count != 0 || self.args.kind == DataKind::Truncate)
    }

    /// Cached results precede validation and Clock. The only effect stores its result once.
    pub fn commit(&mut self, ram: &mut Ram<'_>, now: Option<Timestamp>) -> Result<DataResult, u32> {
        if self.result != DataResult::None {
            return Ok(self.result);
        }
        if !matches!(self.phase, DataPhase::Ready | DataPhase::TimeDeferred) {
            return Err(proto_fs::RESOLVING);
        }
        let now = if self.needs_time() {
            match now {
                Some(now) => now,
                None => {
                    self.phase = DataPhase::TimeDeferred;
                    return Err(proto_fs::TIME_DEFERRED);
                }
            }
        } else {
            Timestamp::ZERO
        };
        let result = match &mut self.prepared {
            Preparation::Write(prepared) => prepared.commit(ram, now).map(|count| count as u64),
            Preparation::Truncate(prepared) => prepared.commit(ram, now).map(|_| 0),
            Preparation::Captured(lease) if self.args.kind.reads() => {
                let position = (self.args.kind == DataKind::PRead).then_some(self.args.position);
                ram.read_held(
                    lease,
                    position,
                    &mut self.bytes[..self.args.count as usize],
                    now,
                )
                .map(|count| count as u64)
            }
            _ => return Err(proto_fs::BAD_FD),
        };
        match result {
            Ok(count) => {
                self.result = DataResult::Bytes(count);
                self.phase = DataPhase::Completed;
                Ok(self.result)
            }
            Err(code) => match self.fail(code) {
                Err(error) => Err(error),
                Ok(_) => unreachable!(),
            },
        }
    }

    pub fn read_result(&self) -> Result<&[u8], u32> {
        if !self.args.kind.reads() {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        match self.result {
            DataResult::Bytes(count) => Ok(&self.bytes[..count as usize]),
            DataResult::FailedNoEffect(code) => Err(code),
            DataResult::None => Err(proto_fs::RESOLVING),
        }
    }

    /// Client disappearance revokes new effects while preserving cleanup and cached results.
    pub fn abandon(&mut self) {
        self.phase = DataPhase::Canceling;
    }

    pub fn ack_allowed(&self) -> bool {
        self.result != DataResult::None
    }

    pub fn cleanup_done(&self) -> bool {
        self.cleanup_done
    }

    /// One private page or retained lease per cleanup step. File effects remain committed.
    pub fn cancel_step(&mut self, ram: &mut Ram<'_>) -> Result<bool, u32> {
        if self.cleanup_done {
            return Ok(true);
        }
        self.phase = DataPhase::Canceling;
        let done = match &mut self.prepared {
            Preparation::Write(prepared) => prepared.cancel(ram),
            Preparation::Truncate(prepared) => prepared.cancel(ram),
            Preparation::Captured(_) => {
                let Preparation::Captured(lease) =
                    core::mem::replace(&mut self.prepared, Preparation::Empty)
                else {
                    unreachable!()
                };
                lease.cancel(ram);
                Ok(true)
            }
            Preparation::Empty => Ok(true),
        }?;
        self.cleanup_done = done;
        Ok(done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        File, Open, REG,
        storage::{ROOT, Root},
    };
    use proto_fs::{DataDescription, OpenKey, READ_WRITE};
    const ROOT_ACCOUNT: Root = Root {
        id: 27,
        generation: 4,
    };
    fn file(ram: &mut Ram<'_>, name: &[u8]) -> (Fds, u32, Token) {
        let reservation = ram
            .storage
            .reserve(ROOT_ACCOUNT, ROOT, name, (REG, 0o6755, 1, 2))
            .unwrap();
        let inode = ram.storage.commit(reservation).unwrap();
        let mut fds = Fds {
            root: ROOT_ACCOUNT,
            ..Fds::default()
        };
        let fd = ram
            .insert(
                &mut fds,
                Open {
                    file: File::Node(inode),
                    flags: READ_WRITE,
                    offset: 0,
                },
            )
            .unwrap();
        (fds, fd, inode)
    }
    fn args(
        ram: &Ram<'_>,
        fds: &Fds,
        fd: u32,
        kind: DataKind,
        count: u32,
        position: u64,
    ) -> DataStart {
        let token = ram.description_token(fds, fd).unwrap();
        DataStart {
            key: OpenKey {
                slot: 0,
                generation: 1,
            },
            kind,
            count,
            position,
            description: DataDescription {
                packed: fd | ((token.slot as u32) << 8),
                generation: token.generation,
            },
        }
    }
    fn ready(journal: &mut Journal, ram: &mut Ram<'_>) {
        for _ in 0..4096 {
            if journal.step(ram).unwrap() {
                return;
            }
        }
        panic!("bounded preparation");
    }
    fn cleanup(journal: &mut Journal, ram: &mut Ram<'_>) {
        for _ in 0..4096 {
            if journal.cancel_step(ram).unwrap() {
                return;
            }
        }
        panic!("bounded cleanup");
    }
    #[test]
    fn feed_replay_and_clock_defer_preserve_exact_bytes_and_no_effect() {
        let mut ram = Ram::new(Timestamp::ZERO);
        let (fds, fd, inode) = file(&mut ram, b"feed");
        let request = args(&ram, &fds, fd, DataKind::Write, 1012, 0);
        let mut j = Journal::capture(&mut ram, &fds, request).unwrap();
        assert!(!j.ack_allowed());
        assert!(!j.step(&mut ram).unwrap());
        assert_eq!(j.feed(0, &[7; 1004]), Ok(()));
        assert_eq!(j.feed(1004, &[8; 8]), Ok(()));
        assert_eq!(j.feed(1004, &[8; 8]), Ok(()));
        assert_eq!(j.feed(1004, &[9; 8]), Err(proto_fs::PERMISSION));
        ready(&mut j, &mut ram);
        let usage = ram.storage.usage(ROOT_ACCOUNT);
        let times = ram.storage.node(inode).unwrap().times;
        assert_eq!(j.commit(&mut ram, None), Err(proto_fs::TIME_DEFERRED));
        assert_eq!(j.phase, DataPhase::TimeDeferred);
        assert!(!j.ack_allowed());
        assert_eq!(ram.storage.usage(ROOT_ACCOUNT), usage);
        assert_eq!(ram.storage.node(inode).unwrap().length, 0);
        assert_eq!(ram.storage.node(inode).unwrap().times, times);
        let now = Timestamp::new(-1, 12).unwrap();
        assert_eq!(j.commit(&mut ram, Some(now)), Ok(DataResult::Bytes(1012)));
        assert_eq!(ram.storage.node(inode).unwrap().mode & 0o6000, 0);
        assert_eq!(j.commit(&mut ram, None), Ok(DataResult::Bytes(1012)));
        assert_eq!(ram.storage.node(inode).unwrap().times[1], now);
        assert_eq!(j.outcome(256).validate(request), Ok(()));
        cleanup(&mut j, &mut ram);
        assert_eq!(j.outcome(256).validate(request), Ok(()));
        assert_eq!(j.commit(&mut ram, None), Ok(DataResult::Bytes(1012)));
    }
    #[test]
    fn read_result_is_cached_once_after_offset_and_atime_change() {
        let mut ram = Ram::new(Timestamp::ZERO);
        let (mut fds, fd, inode) = file(&mut ram, b"read");
        ram.write_at(&mut fds, fd, b"abc", Timestamp::ZERO).unwrap();
        ram.seek(&mut fds, fd, 0).unwrap();
        let request = args(&ram, &fds, fd, DataKind::Read, 3, 0);
        let mut j = Journal::capture(&mut ram, &fds, request).unwrap();
        ready(&mut j, &mut ram);
        assert_eq!(j.commit(&mut ram, None), Err(proto_fs::TIME_DEFERRED));
        let now = Timestamp::new(3, 0).unwrap();
        assert_eq!(j.commit(&mut ram, Some(now)), Ok(DataResult::Bytes(3)));
        ram.pwrite(&mut fds, fd, 0, b"xyz", Timestamp::new(4, 0).unwrap())
            .unwrap();
        assert_eq!(j.commit(&mut ram, None), Ok(DataResult::Bytes(3)));
        assert_eq!(j.read_result(), Ok(&b"abc"[..]));
        assert_eq!(ram.get(&fds, fd).unwrap().offset, 3);
        assert_eq!(ram.storage.node(inode).unwrap().times[0], now);
        cleanup(&mut j, &mut ram);
    }
    #[test]
    fn competing_append_writers_rebuild_same_lease_before_the_effect() {
        let mut ram = Ram::new(Timestamp::ZERO);
        let (fds, fd, inode) = file(&mut ram, b"append-journal");
        let mut second_fds = Fds {
            root: ROOT_ACCOUNT,
            ..Fds::default()
        };
        let second_fd = ram
            .insert(
                &mut second_fds,
                Open {
                    file: File::Node(inode),
                    offset: 0,
                    flags: READ_WRITE | proto_fs::APPEND,
                },
            )
            .unwrap();
        let first_fds = fds;
        let mut open = ram.get(&first_fds, fd).unwrap();
        open.flags |= proto_fs::APPEND;
        ram.put(&first_fds, fd, open).unwrap();
        let first_args = args(&ram, &first_fds, fd, DataKind::Write, 1, 0);
        let second_args = args(&ram, &second_fds, second_fd, DataKind::Write, 1, 0);
        let mut first = Journal::capture(&mut ram, &first_fds, first_args).unwrap();
        let mut second = Journal::capture(&mut ram, &second_fds, second_args).unwrap();
        first.feed(0, b"A").unwrap();
        second.feed(0, b"B").unwrap();
        ready(&mut first, &mut ram);
        ready(&mut second, &mut ram);
        assert_eq!(
            first.commit(&mut ram, Some(Timestamp::ZERO)),
            Ok(DataResult::Bytes(1))
        );
        assert_eq!(
            second.commit(&mut ram, Some(Timestamp::ZERO)),
            Err(proto_fs::RESOLVING)
        );
        ready(&mut second, &mut ram);
        assert_eq!(
            second.commit(&mut ram, Some(Timestamp::ZERO)),
            Ok(DataResult::Bytes(1))
        );
        let mut out = [0; 2];
        ram.storage.read(inode, 0, &mut out).unwrap();
        assert_eq!(out, *b"AB");
        cleanup(&mut first, &mut ram);
        cleanup(&mut second, &mut ram);
    }
    #[test]
    fn zero_read_skips_clock_and_eof_request_records_time() {
        let mut ram = Ram::new(Timestamp::ZERO);
        let (fds, fd, inode) = file(&mut ram, b"eof");
        let request = args(&ram, &fds, fd, DataKind::Read, 0, 0);
        let mut zero = Journal::capture(&mut ram, &fds, request).unwrap();
        ready(&mut zero, &mut ram);
        assert!(!zero.needs_time());
        assert_eq!(zero.commit(&mut ram, None), Ok(DataResult::Bytes(0)));
        cleanup(&mut zero, &mut ram);
        let request = DataStart {
            count: 1,
            ..request
        };
        let mut eof = Journal::capture(&mut ram, &fds, request).unwrap();
        ready(&mut eof, &mut ram);
        assert_eq!(eof.commit(&mut ram, None), Err(proto_fs::TIME_DEFERRED));
        let now = Timestamp::new(-7, 8).unwrap();
        assert_eq!(eof.commit(&mut ram, Some(now)), Ok(DataResult::Bytes(0)));
        assert_eq!(ram.storage.node(inode).unwrap().times[0], now);
        cleanup(&mut eof, &mut ram);
    }

    #[test]
    fn abandonment_marks_only_and_releases_at_most_one_private_page_per_step() {
        let mut ram = Ram::new(Timestamp::ZERO);
        let (fds, fd, inode) = file(&mut ram, b"abandoned");
        let before = ram.storage.usage(ROOT_ACCOUNT);
        let request = args(&ram, &fds, fd, DataKind::PWrite, 1012, 4095);
        let mut journal = Journal::capture(&mut ram, &fds, request).unwrap();
        journal.feed(0, &[3; 1004]).unwrap();
        journal.feed(1004, &[3; 8]).unwrap();
        ready(&mut journal, &mut ram);
        let prepared = ram.storage.usage(ROOT_ACCOUNT);
        assert_eq!(prepared.pages, before.pages + 2);
        journal.abandon();
        journal.abandon();
        assert_eq!(journal.originating_root(), ROOT_ACCOUNT);
        assert_eq!(ram.storage.usage(ROOT_ACCOUNT), prepared);
        assert_eq!(
            journal.commit(&mut ram, Some(Timestamp::ZERO)),
            Err(proto_fs::RESOLVING)
        );
        assert_eq!(ram.storage.node(inode).unwrap().length, 0);
        let mut done = false;
        for _ in 0..8 {
            let old = ram.storage.usage(ROOT_ACCOUNT).pages;
            done = journal.cancel_step(&mut ram).unwrap();
            let new = ram.storage.usage(ROOT_ACCOUNT).pages;
            assert!(new <= old && old - new <= 1);
            if done {
                break;
            }
        }
        assert!(done);
        assert_eq!(ram.storage.usage(ROOT_ACCOUNT), before);
        assert!(journal.cancel_step(&mut ram).unwrap());
        assert_eq!(ram.storage.usage(ROOT_ACCOUNT), before);
        assert!(ram.get(&fds, fd).is_ok());
    }
}
