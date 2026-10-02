// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of init (spec 13.3, 13.4, 13.8, proto_wire): the numbers
//! of its methods, which never change once given, and their bodies.
//! Every number goes low byte first.
//!
//! START: a program asks its parent for its start data through its start
//! channel (spec 13.3); the request is the header alone, and each START
//! gets the next reply until one with LAST. A reply that is not a refusal
//! (`StartReply`):
//!
//! | Bytes | Field |
//! |---|---|
//! | 0..4 | status 0 |
//! | 4..6 | flags: bit 0 LAST, the others 0 |
//! | 6..8 | length of the piece of arguments, at most START_PIECE_MAX |
//! | 8..72 | four names of 16 bytes: name i names handle i of the reply |
//! | 72.. | the piece of arguments |
//!
//! The reply is 72 bytes and its piece long. Names past the count of
//! handles that came are 16 zeros. A refusal is its status alone
//! (proto_wire::reply).
//!
//! The arguments of a service (`ServiceArgs`), which init puts into the
//! start data of each record of its table: bytes 0..8 the period of its
//! heartbeat in nanoseconds, 8..16 the deadline of its watchdog, then its
//! own arguments, at most OWN_ARGS_MAX bytes. A client has 0 in both.
//!
//! REGISTER: a service gives init its channel (spec 13.4); the request is
//! the header with one handle. The reply that is no refusal
//! (`RegisterReply`) has the layout of `StartReply` with LAST and no
//! arguments: the names of the windows and bindings of the record, the
//! windows first, each naming the handle in its place.
//!
//! CONNECT: a program asks init for a session with a service (spec 13.4);
//! the request (`Connect`) is the header and the name of the service, 16
//! bytes, 24 in all. The reply is its status alone, with one handle when
//! the status is 0.
//!
//! LIST: the records of init's table in pages, init itself first (spec
//! 13.4). The request (`ListRequest`):
//!
//! | Bytes | Field |
//! |---|---|
//! | 0..8 | header |
//! | 8..10 | the first record of the page |
//! | 10..16 | zero |
//!
//! The reply that is no refusal (`ListReply`): bytes 0..4 status 0, 4..6
//! the records in the reply, at most LIST_PAGE, 6..8 the records in all,
//! then the records, RECORD_LEN bytes each (`Record`):
//!
//! | Bytes | Field |
//! |---|---|
//! | 0..16 | name |
//! | 16 | state (`State`) |
//! | 17 | priority |
//! | 18 | ceiling |
//! | 19 | kind: 0 service, 1 client |
//! | 20 | failures in the last 60 s |
//! | 21..24 | zero |
//! | 24..28 | restarts in all |
//! | 28..32 | live handles |
//! | 32..36 | retired handles |
//! | 36..40 | room for handles |
//! | 40..44 | quota in pages |
//! | 44..48 | pages used |
//!
//! A record with no instance that lives has 0 in its handles and pages.
//!
//! STATS: what init and the kernel do (spec 13.4); the request is the
//! header alone. The reply that is no refusal (`Stats`), 104 bytes:
//!
//! | Bytes | Field |
//! |---|---|
//! | 0..4 | status 0 |
//! | 4..8 | zero |
//! | 8..80 | the nine words of KERNEL_STATS, x1 to x9 |
//! | 80 | the work of init's worker thread: 0 none, 1 load, 2 teardown, 3 kill, 4 show the kernel log (`Work`) |
//! | 81 | the record it works for, its number in LIST (its place in init's table plus 1); 0 with no work |
//! | 82 | the worker's base priority |
//! | 83 | the worker's effective priority |
//! | 84 | the worker's state (THREAD_STATE x1) |
//! | 85 | the jobs that wait for the worker |
//! | 86 | 1 once the worker took its work from init, 0 before and with no work |
//! | 87 | zero |
//! | 88..96 | free pages of init's quota |
//! | 96..104 | labels init gave |
//!
//! HEARTBEAT: a service tells init that it lives (spec 13.4); PING: a round
//! trip to init, for bench (spec 13.6). The request of each is the header
//! alone, the reply its status alone.
//!
//! ADOPT and ADOPTED come only from the POSIX process service (spec 2,
//! section 3.1), which creates and loads every POSIX process itself: the
//! service asks init for the next POSIX record of init's table to start,
//! and init holds the request until there is one; init never asks the
//! service anything. ADOPT: the header alone; the reply (`Adoption`) its
//! status (8 bytes, proto_wire::reply), the ticket of the instance, the
//! record's quota, room for handles, ceiling, priority, root and program,
//! and two handles: the instance's start channel (a copy of init's channel
//! with SEND, TRANSFER and the ticket as its label), which the process
//! gets as its entry 0, and its witness (a copy with TRANSFER alone and a
//! label of its own), which the service closes once the process ended, so
//! that its CLIENT_GONE tells init of the end. ADOPTED: the header, the ticket u64 and the
//! service's status u32 (0, or why it made no process), and with status 0
//! three handles: the session of the record, the process (MANAGE,
//! DUPLICATE, TRANSFER) and its first thread (MANAGE, TRANSFER), which
//! init gives the process in its start data under `posix`, `process` and
//! `thread`; the reply is its status alone. Init keeps a copy of the
//! process with no rights and reads its end once the last copy of the
//! witness closed. Once init answered 0, the service starts the thread; on
//! any other answer it kills the process.
//!
//! SPAWN, also from the process service alone, for posix_spawn of a
//! POSIX process (5b, until the loader of 5c): the header and the name of
//! a record of init's table that starts on demand, 16 bytes; the reply
//! that is no refusal is that of ADOPT for that record (`Adoption`), whose
//! process the service makes as for ADOPT and gives with ADOPTED.
//! ACCESS_DENIED for a name of no record that starts on demand,
//! LIMIT_REACHED while an instance of it lives or ends.

#![cfg_attr(not(test), no_std)]

use abi::{KernelStats, MESSAGE_HANDLES, MESSAGE_MAX};
use proto_wire::{HEADER_LEN, Header, NAME_LEN, Name, Reader, Status, Writer};

/// The version of the protocol, in the header of each request.
pub const VERSION: u16 = 1;

/// The methods of init with their numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Start = 1,
    Register = 2,
    Connect = 3,
    Heartbeat = 4,
    List = 5,
    Stats = 6,
    Ping = 7,
    Adopt = 8,
    Adopted = 9,
    Spawn = 10,
}

impl Method {
    pub const ALL: [Method; 10] = [
        Method::Start,
        Method::Register,
        Method::Connect,
        Method::Heartbeat,
        Method::List,
        Method::Stats,
        Method::Ping,
        Method::Adopt,
        Method::Adopted,
        Method::Spawn,
    ];

    pub const fn number(self) -> u16 {
        self as u16
    }

    pub fn from_number(number: u16) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.number() == number)
    }

    /// The header of a request of this method.
    pub const fn header(self) -> Header {
        Header::new(self.number(), VERSION)
    }
}

/// The reply to ADOPT that is no refusal (the text above):
///
/// | Bytes | Field |
/// |---|---|
/// | 0..8 | status 0 (proto_wire::reply) |
/// | 8..16 | ticket |
/// | 16..24 | quota in bytes |
/// | 24..28 | room for handles |
/// | 28 | ceiling |
/// | 29 | priority of the first thread |
/// | 30 | root: 0 or 1 |
/// | 31 | zero |
/// | 32..48 | the program's name in the boot image |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Adoption {
    pub ticket: u64,
    pub quota: u64,
    pub handle_limit: u32,
    pub ceiling: u8,
    pub priority: u8,
    pub root: bool,
    pub program: Name,
}

impl Adoption {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.bytes(&proto_wire::reply(Status::Ok))?;
        w.u64(self.ticket)?;
        w.u64(self.quota)?;
        w.u32(self.handle_limit)?;
        w.bytes(&[self.ceiling, self.priority, u8::from(self.root), 0])?;
        w.name(Some(self.program))
    }

    /// BAD_SIZE unless `bytes` hold status 0 and the fields in their
    /// layout, with a root byte of 0 or 1 and a name.
    pub fn read(bytes: &[u8]) -> Result<Adoption, Status> {
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 || r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let (ticket, quota, handle_limit) = (r.u64()?, r.u64()?, r.u32()?);
        let b = r.bytes(4)?;
        if b[2] > 1 || b[3] != 0 {
            return Err(Status::BadSize);
        }
        let program = r.name()?.ok_or(Status::BadSize)?;
        r.finish()?;
        Ok(Adoption {
            ticket,
            quota,
            handle_limit,
            ceiling: b[0],
            priority: b[1],
            root: b[2] == 1,
            program,
        })
    }
}

/// Names in a reply to START: one per handle a message carries.
pub const START_NAMES: usize = MESSAGE_HANDLES;
/// The bytes of a reply to START before its piece of arguments.
pub const START_FIXED: usize = HEADER_LEN + START_NAMES * NAME_LEN;
/// The longest piece of arguments one reply carries.
pub const START_PIECE_MAX: usize = MESSAGE_MAX - START_FIXED;
/// The flag of the last reply to START.
pub const LAST: u16 = 1;

/// A reply to START that is no refusal (the table above).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartReply<'a> {
    pub last: bool,
    /// Name i names handle i of the reply; None past their count.
    pub names: [Option<Name>; START_NAMES],
    pub args: &'a [u8],
}

impl<'a> StartReply<'a> {
    /// BAD_SIZE for a piece longer than START_PIECE_MAX.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        let len = u16::try_from(self.args.len()).map_err(|_| Status::BadSize)?;
        if usize::from(len) > START_PIECE_MAX {
            return Err(Status::BadSize);
        }
        w.u32(Status::Ok.code())?;
        w.u16(if self.last { LAST } else { 0 })?;
        w.u16(len)?;
        for name in self.names {
            w.name(name)?;
        }
        w.bytes(self.args)
    }

    /// The reply in `bytes`, which came with `handles` handles: BAD_SIZE
    /// unless its status is 0, its flags are LAST or 0, its piece is at
    /// most START_PIECE_MAX and the bytes after the names, and exactly the
    /// first `handles` names are there.
    pub fn read(bytes: &'a [u8], handles: usize) -> Result<StartReply<'a>, Status> {
        let mut r = Reader::new(bytes);
        let (status, flags, len) = (r.u32()?, r.u16()?, usize::from(r.u16()?));
        if status != 0 || flags & !LAST != 0 || len > START_PIECE_MAX || handles > START_NAMES {
            return Err(Status::BadSize);
        }
        let mut names = [None; START_NAMES];
        for (i, name) in names.iter_mut().enumerate() {
            *name = r.name()?;
            if name.is_some() != (i < handles) {
                return Err(Status::BadSize);
            }
        }
        let args = r.bytes(len)?;
        r.finish()?;
        Ok(StartReply {
            last: flags == LAST,
            names,
            args,
        })
    }
}

/// A reply to REGISTER that is no refusal (spec 13.4): the layout of
/// `StartReply` with LAST and no arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterReply {
    /// Name i names handle i of the reply, the windows first; None past
    /// their count.
    pub names: [Option<Name>; START_NAMES],
}

impl RegisterReply {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        StartReply {
            last: true,
            names: self.names,
            args: &[],
        }
        .write(w)
    }

    /// The reply in `bytes`, which came with `handles` handles: BAD_SIZE
    /// unless it is a StartReply (StartReply::read) with LAST and no
    /// arguments.
    pub fn read(bytes: &[u8], handles: usize) -> Result<RegisterReply, Status> {
        let reply = StartReply::read(bytes, handles)?;
        if !reply.last || !reply.args.is_empty() {
            return Err(Status::BadSize);
        }
        Ok(RegisterReply { names: reply.names })
    }
}

/// A request of CONNECT: the name of the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connect {
    pub name: Name,
}

impl Connect {
    /// The header of CONNECT, then the name.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        Method::Connect.header().write(w)?;
        w.name(Some(self.name))
    }

    /// The request from `body`, its bytes after the header: BAD_SIZE
    /// unless they are one name of 16 bytes (Name::from_field), not 16
    /// zeros.
    pub fn read(mut body: Reader<'_>) -> Result<Connect, Status> {
        let name = body.name()?.ok_or(Status::BadSize)?;
        body.finish()?;
        Ok(Connect { name })
    }
}

/// The records of a reply to LIST at most.
pub const LIST_PAGE: usize = 8;
/// The bytes of a record in a reply to LIST.
pub const RECORD_LEN: usize = 48;
/// The bytes of a reply to LIST before its records.
pub const LIST_FIXED: usize = 8;

/// A request of LIST: the first record of the page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListRequest {
    pub first: u16,
}

impl ListRequest {
    /// The header of LIST, the first record and six zeros.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        Method::List.header().write(w)?;
        w.u16(self.first)?;
        w.bytes(&[0; 6])
    }

    /// The request from `body`, its bytes after the header: BAD_SIZE
    /// unless they are the first record and six zeros.
    pub fn read(mut body: Reader<'_>) -> Result<ListRequest, Status> {
        let first = body.u16()?;
        if body.bytes(6)? != [0; 6] {
            return Err(Status::BadSize);
        }
        body.finish()?;
        Ok(ListRequest { first })
    }
}

/// The state of a record in a reply to LIST.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Loaded; a service waits for its REGISTER.
    Starting = 0,
    Running = 1,
    /// Its load waits for init's worker thread or runs.
    Loading = 2,
    /// It waits out its pause before a restart.
    Paused = 3,
    /// Its start waits for init's quota.
    Quota = 4,
    /// The teardown or the kill of its instance waits or runs.
    Stopping = 5,
    /// Failed too often; it is not started again.
    Broken = 6,
    /// Ended, and its policy does not start it again.
    Ended = 7,
}

impl State {
    pub const ALL: [State; 8] = [
        State::Starting,
        State::Running,
        State::Loading,
        State::Paused,
        State::Quota,
        State::Stopping,
        State::Broken,
        State::Ended,
    ];

    pub const fn byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(byte: u8) -> Option<State> {
        State::ALL.into_iter().find(|s| s.byte() == byte)
    }
}

/// A record in a reply to LIST (the table above).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub state: State,
    pub priority: u8,
    pub ceiling: u8,
    pub client: bool,
    /// Failures in the last 60 s.
    pub failures: u8,
    pub restarts: u32,
    pub live: u32,
    pub retired: u32,
    pub limit: u32,
    pub quota_pages: u32,
    pub used_pages: u32,
}

impl Record {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.name(Some(self.name))?;
        w.bytes(&[
            self.state.byte(),
            self.priority,
            self.ceiling,
            u8::from(self.client),
            self.failures,
            0,
            0,
            0,
        ])?;
        for n in [
            self.restarts,
            self.live,
            self.retired,
            self.limit,
            self.quota_pages,
            self.used_pages,
        ] {
            w.u32(n)?;
        }
        Ok(())
    }

    /// BAD_SIZE for a record without a name, of a state or kind not in
    /// the table, or with bytes that must be zero and are not.
    pub fn read(r: &mut Reader<'_>) -> Result<Record, Status> {
        let name = r.name()?.ok_or(Status::BadSize)?;
        let b = r.bytes(8)?;
        let state = State::from_byte(b[0]).ok_or(Status::BadSize)?;
        if b[3] > 1 || b[5..] != [0; 3] {
            return Err(Status::BadSize);
        }
        Ok(Record {
            name,
            state,
            priority: b[1],
            ceiling: b[2],
            client: b[3] == 1,
            failures: b[4],
            restarts: r.u32()?,
            live: r.u32()?,
            retired: r.u32()?,
            limit: r.u32()?,
            quota_pages: r.u32()?,
            used_pages: r.u32()?,
        })
    }
}

/// A reply to LIST that is no refusal: up to LIST_PAGE records and the
/// count of records in all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListReply {
    pub total: u16,
    records: [Option<Record>; LIST_PAGE],
    count: usize,
}

impl ListReply {
    /// A page with no records yet, of `total` records in all.
    pub const fn new(total: u16) -> ListReply {
        ListReply {
            total,
            records: [None; LIST_PAGE],
            count: 0,
        }
    }

    /// Adds `record` to the page; it comes back when the page holds
    /// LIST_PAGE.
    pub fn push(&mut self, record: Record) -> Result<(), Record> {
        let slot = self.records.get_mut(self.count).ok_or(record)?;
        *slot = Some(record);
        self.count += 1;
        Ok(())
    }

    /// The records of the page, in order.
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records[..self.count].iter().flatten()
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(Status::Ok.code())?;
        w.u16(self.count as u16)?;
        w.u16(self.total)?;
        for record in self.records() {
            record.write(w)?;
        }
        Ok(())
    }

    /// The reply in `bytes`: BAD_SIZE unless its status is 0, it has at
    /// most LIST_PAGE records and exactly their bytes, and each record
    /// reads (Record::read).
    pub fn read(bytes: &[u8]) -> Result<ListReply, Status> {
        let mut r = Reader::new(bytes);
        let (status, count, total) = (r.u32()?, usize::from(r.u16()?), r.u16()?);
        if status != 0 || count > LIST_PAGE || r.left() != count * RECORD_LEN {
            return Err(Status::BadSize);
        }
        let mut reply = ListReply::new(total);
        for _ in 0..count {
            let _ = reply.push(Record::read(&mut r)?);
        }
        r.finish()?;
        Ok(reply)
    }
}

/// The work of init's worker thread (spec 13.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Work {
    /// Loads an instance of a record (rt::loader::spawn).
    Load = 1,
    /// Closes init's handles of an instance that ended.
    Teardown = 2,
    /// Kills an instance that went silent, then tears it down.
    Kill = 3,
    /// Shows what is left of the kernel log once its reader, the
    /// console's driver, ended for good.
    ShowLog = 4,
}

impl Work {
    pub const fn byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(byte: u8) -> Option<Work> {
        [Work::Load, Work::Teardown, Work::Kill, Work::ShowLog]
            .into_iter()
            .find(|w| w.byte() == byte)
    }
}

/// The bytes of a reply to STATS.
pub const STATS_LEN: usize = 104;

/// A reply to STATS that is no refusal (the table above).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    pub kernel: KernelStats,
    /// The work of init's worker thread and the place in init's table of
    /// the record it works for; None with no work.
    pub job: Option<(Work, u8)>,
    pub worker_priority: u8,
    pub worker_effective: u8,
    /// abi::ThreadInfo's state as THREAD_STATE gives it in x1.
    pub worker_state: u8,
    pub pending: u8,
    /// The worker took its work from init and does it; false before and
    /// with no work.
    pub begun: bool,
    pub free_pages: u64,
    pub labels: u64,
}

impl Stats {
    /// BAD_SIZE for a record at place 255, which has no byte.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(Status::Ok.code())?;
        w.u32(0)?;
        for word in self.kernel.to_words() {
            w.u64(word)?;
        }
        let (work, record) = match self.job {
            Some((work, record)) => (work.byte(), record.checked_add(1).ok_or(Status::BadSize)?),
            None => (0, 0),
        };
        w.bytes(&[
            work,
            record,
            self.worker_priority,
            self.worker_effective,
            self.worker_state,
            self.pending,
            u8::from(self.begun && self.job.is_some()),
            0,
        ])?;
        w.u64(self.free_pages)?;
        w.u64(self.labels)
    }

    /// The reply in `bytes`: BAD_SIZE unless it is STATS_LEN bytes with
    /// status 0, the bytes that must be zero are, the work and its record
    /// are both there or both 0, and byte 86 is 0, or 1 with a work.
    pub fn read(bytes: &[u8]) -> Result<Stats, Status> {
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 || r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let mut words = [0; 9];
        for word in &mut words {
            *word = r.u64()?;
        }
        let b = r.bytes(8)?;
        let job = match (b[0], b[1]) {
            (0, 0) => None,
            (work, record @ 1..) => {
                Some((Work::from_byte(work).ok_or(Status::BadSize)?, record - 1))
            }
            _ => return Err(Status::BadSize),
        };
        if b[6] > u8::from(job.is_some()) || b[7] != 0 {
            return Err(Status::BadSize);
        }
        let stats = Stats {
            kernel: KernelStats::from_words(words),
            job,
            worker_priority: b[2],
            worker_effective: b[3],
            worker_state: b[4],
            pending: b[5],
            begun: b[6] == 1,
            free_pages: r.u64()?,
            labels: r.u64()?,
        };
        r.finish()?;
        Ok(stats)
    }
}

/// The own arguments of a record at most.
pub const OWN_ARGS_MAX: usize = 240;
/// The bytes of the arguments of a service before its own.
pub const SERVICE_ARGS_FIXED: usize = 16;

/// The arguments init gives a record of its table (the text above).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceArgs<'a> {
    pub period_ns: u64,
    pub deadline_ns: u64,
    pub own: &'a [u8],
}

impl<'a> ServiceArgs<'a> {
    /// BAD_SIZE for more than OWN_ARGS_MAX bytes of its own.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if self.own.len() > OWN_ARGS_MAX {
            return Err(Status::BadSize);
        }
        w.u64(self.period_ns)?;
        w.u64(self.deadline_ns)?;
        w.bytes(self.own)
    }

    /// The arguments in `bytes`: BAD_SIZE when they end before 16 bytes or
    /// have more than OWN_ARGS_MAX of their own.
    pub fn read(bytes: &'a [u8]) -> Result<ServiceArgs<'a>, Status> {
        let mut r = Reader::new(bytes);
        let (period_ns, deadline_ns) = (r.u64()?, r.u64()?);
        let own = r.bytes(r.left())?;
        if own.len() > OWN_ARGS_MAX {
            return Err(Status::BadSize);
        }
        Ok(ServiceArgs {
            period_ns,
            deadline_ns,
            own,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Option<Name> {
        Some(Name::new(s.as_bytes()).unwrap())
    }

    fn written(reply: &StartReply<'_>) -> Vec<u8> {
        let mut w = Writer::new();
        reply.write(&mut w).unwrap();
        w.as_bytes().to_vec()
    }

    #[test]
    fn adoption_round_trips_and_refuses_its_layout() {
        let adoption = Adoption {
            ticket: 0x1234_5678_9abc,
            quota: 512 * 4096,
            handle_limit: 32,
            ceiling: 31,
            priority: 30,
            root: true,
            program: name("posix-abi-probe").unwrap(),
        };
        let mut w = Writer::new();
        adoption.write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 48);
        assert_eq!(Adoption::read(w.as_bytes()), Ok(adoption));
        let mut bad = w.as_bytes().to_vec();
        bad[30] = 2;
        assert_eq!(Adoption::read(&bad), Err(Status::BadSize));
        let mut refusal = w.as_bytes().to_vec();
        refusal[0] = 1;
        assert_eq!(Adoption::read(&refusal), Err(Status::BadSize));
        assert_eq!(Adoption::read(&w.as_bytes()[..47]), Err(Status::BadSize));
    }

    #[test]
    fn start_reply_round_trips() {
        let args = [0xA5; 40];
        let reply = StartReply {
            last: true,
            names: [name("process"), name("thread"), None, None],
            args: &args,
        };
        let bytes = written(&reply);
        assert_eq!(bytes.len(), START_FIXED + 40);
        assert_eq!(bytes[..8], [0, 0, 0, 0, 1, 0, 40, 0]);
        assert_eq!(&bytes[8..15], b"process");
        assert_eq!(&bytes[24..30], b"thread");
        assert_eq!(bytes[40..72], [0; 32]);
        assert_eq!(bytes[72..], args);
        assert_eq!(StartReply::read(&bytes, 2), Ok(reply));
        let piece = StartReply {
            last: false,
            names: [name("0"), name("1"), name("2"), name("3")],
            args: &[],
        };
        let bytes = written(&piece);
        assert_eq!(bytes.len(), START_FIXED);
        assert_eq!(StartReply::read(&bytes, 4), Ok(piece));
        // A refusal is no reply of this layout.
        let refused = proto_wire::reply(Status::BadVersion);
        assert_eq!(StartReply::read(&refused, 0), Err(Status::BadSize));
        // Nor are flags other than LAST.
        let mut flagged = written(&piece);
        flagged[4] = 2;
        assert_eq!(StartReply::read(&flagged, 4), Err(Status::BadSize));
    }

    #[test]
    fn start_reply_refuses_names_past_the_handles() {
        let reply = StartReply {
            last: true,
            names: [name("process"), name("thread"), name("extra"), None],
            args: &[],
        };
        let bytes = written(&reply);
        assert_eq!(StartReply::read(&bytes, 3), Ok(reply));
        // A name without its handle, and a handle without its name.
        assert_eq!(StartReply::read(&bytes, 2), Err(Status::BadSize));
        assert_eq!(StartReply::read(&bytes, 4), Err(Status::BadSize));
        assert_eq!(StartReply::read(&bytes, 5), Err(Status::BadSize));
    }

    #[test]
    fn start_reply_refuses_a_long_args_length() {
        let long = [7; START_PIECE_MAX + 1];
        let mut w = Writer::new();
        let too_long = StartReply {
            last: true,
            names: [None; START_NAMES],
            args: &long,
        };
        assert_eq!(too_long.write(&mut w), Err(Status::BadSize));
        let most = StartReply {
            args: &long[..START_PIECE_MAX],
            ..too_long
        };
        let mut bytes = written(&most);
        assert_eq!(bytes.len(), MESSAGE_MAX);
        assert_eq!(StartReply::read(&bytes, 0), Ok(most));
        // A length past the most, or other than the bytes after the names.
        bytes[6..8].copy_from_slice(&(START_PIECE_MAX as u16 + 1).to_le_bytes());
        assert_eq!(StartReply::read(&bytes, 0), Err(Status::BadSize));
        bytes[6..8].copy_from_slice(&(START_PIECE_MAX as u16 - 1).to_le_bytes());
        assert_eq!(StartReply::read(&bytes, 0), Err(Status::BadSize));
        assert_eq!(
            StartReply::read(&bytes[..MESSAGE_MAX - 2], 0),
            Err(Status::BadSize)
        );
    }

    #[test]
    fn register_reply_is_the_start_layout() {
        let names = [name("rtc"), name("rtc-irq"), None, None];
        let reply = RegisterReply { names };
        let mut w = Writer::new();
        reply.write(&mut w).unwrap();
        let start = StartReply {
            last: true,
            names,
            args: &[],
        };
        assert_eq!(w.as_bytes(), written(&start));
        assert_eq!(w.as_bytes().len(), START_FIXED);
        assert_eq!(RegisterReply::read(w.as_bytes(), 2), Ok(reply));
        assert_eq!(
            StartReply::read(w.as_bytes(), 2),
            Ok(start),
            "rt reads it as a reply to START"
        );
        // A reply without LAST, or with arguments, is no reply to REGISTER.
        let piece = written(&StartReply {
            last: false,
            ..start
        });
        assert_eq!(RegisterReply::read(&piece, 2), Err(Status::BadSize));
        let with_args = written(&StartReply {
            args: &[1],
            ..start
        });
        assert_eq!(RegisterReply::read(&with_args, 2), Err(Status::BadSize));
        assert_eq!(RegisterReply::read(w.as_bytes(), 1), Err(Status::BadSize));
    }

    #[test]
    fn connect_request_round_trips() {
        let c = Connect {
            name: Name::new(b"echo").unwrap(),
        };
        let mut w = Writer::new();
        c.write(&mut w).unwrap();
        let bytes = w.as_bytes();
        assert_eq!(bytes.len(), HEADER_LEN + NAME_LEN);
        assert_eq!(bytes[..8], Method::Connect.header().bytes());
        assert_eq!(&bytes[8..12], b"echo");
        assert_eq!(bytes[12..], [0; 12]);
        assert_eq!(Connect::read(Reader::new(&bytes[HEADER_LEN..])), Ok(c));
    }

    #[test]
    fn connect_refuses_a_bad_name() {
        let body = |field: &[u8]| Connect::read(Reader::new(field));
        let mut inside = [0; NAME_LEN];
        inside[..2].copy_from_slice(b"ec");
        inside[3] = b'o';
        assert_eq!(body(&inside), Err(Status::BadSize), "a zero inside");
        assert_eq!(body(&[0; NAME_LEN]), Err(Status::BadSize), "empty");
        assert_eq!(
            body(&[b'a'; NAME_LEN + 1]),
            Err(Status::BadSize),
            "17 bytes"
        );
        assert_eq!(body(&[b'a'; NAME_LEN - 1]), Err(Status::BadSize), "cut");
        assert_eq!(Name::new(&[b'a'; NAME_LEN + 1]), Err(Status::BadSize));
    }

    fn record(n: &str, state: State) -> Record {
        Record {
            name: Name::new(n.as_bytes()).unwrap(),
            state,
            priority: 40,
            ceiling: 41,
            client: false,
            failures: 3,
            restarts: 0x0102_0304,
            live: 5,
            retired: 6,
            limit: 16,
            quota_pages: 20,
            used_pages: 19,
        }
    }

    #[test]
    fn list_request_and_reply_round_trip() {
        let request = ListRequest { first: 0x0908 };
        let mut w = Writer::new();
        request.write(&mut w).unwrap();
        assert_eq!(w.as_bytes()[..8], Method::List.header().bytes());
        assert_eq!(w.as_bytes()[8..], [8, 9, 0, 0, 0, 0, 0, 0]);
        let body = Reader::new(&w.as_bytes()[HEADER_LEN..]);
        assert_eq!(ListRequest::read(body), Ok(request));
        let mut dirty = w.as_bytes()[HEADER_LEN..].to_vec();
        dirty[7] = 1;
        assert_eq!(ListRequest::read(Reader::new(&dirty)), Err(Status::BadSize));
        let mut reply = ListReply::new(10);
        for state in State::ALL {
            reply.push(record("sink", state)).unwrap();
        }
        assert!(reply.push(record("extra", State::Running)).is_err());
        let mut w = Writer::new();
        reply.write(&mut w).unwrap();
        let bytes = w.as_bytes();
        assert_eq!(bytes.len(), LIST_FIXED + LIST_PAGE * RECORD_LEN);
        assert_eq!(bytes[..8], [0, 0, 0, 0, 8, 0, 10, 0]);
        let first = &bytes[LIST_FIXED..LIST_FIXED + RECORD_LEN];
        assert_eq!(&first[..4], b"sink");
        assert_eq!(first[16..24], [0, 40, 41, 0, 3, 0, 0, 0]);
        assert_eq!(first[24..28], [4, 3, 2, 1]);
        assert_eq!(first[44..48], [19, 0, 0, 0]);
        assert_eq!(ListReply::read(bytes), Ok(reply));
        let read = ListReply::read(bytes).unwrap();
        let states: Vec<State> = read.records().map(|r| r.state).collect();
        assert_eq!(states, State::ALL);
        // An empty page, past the last record.
        let mut w = Writer::new();
        ListReply::new(10).write(&mut w).unwrap();
        assert_eq!(ListReply::read(w.as_bytes()).map(|r| r.len()), Ok(0));
        // A kind other than 0 and 1, and a state past the table.
        let mut client = bytes.to_vec();
        client[LIST_FIXED + 19] = 1;
        let read = ListReply::read(&client).unwrap();
        assert!(read.records().next().unwrap().client);
        client[LIST_FIXED + 19] = 2;
        assert_eq!(ListReply::read(&client), Err(Status::BadSize));
        let mut state = bytes.to_vec();
        state[LIST_FIXED + 16] = 8;
        assert_eq!(ListReply::read(&state), Err(Status::BadSize));
        // Bytes 21..24 of a record are zero.
        let mut dirty = bytes.to_vec();
        dirty[LIST_FIXED + 23] = 1;
        assert_eq!(ListReply::read(&dirty), Err(Status::BadSize));
    }

    #[test]
    fn list_reply_refuses_a_count_past_its_bytes() {
        let mut reply = ListReply::new(3);
        reply.push(record("echo", State::Running)).unwrap();
        reply.push(record("slow", State::Starting)).unwrap();
        let mut w = Writer::new();
        reply.write(&mut w).unwrap();
        let mut bytes = w.as_bytes().to_vec();
        assert_eq!(ListReply::read(&bytes), Ok(reply));
        // Three records said, two came.
        bytes[4] = 3;
        assert_eq!(ListReply::read(&bytes), Err(Status::BadSize));
        // One said, two came.
        bytes[4] = 1;
        assert_eq!(ListReply::read(&bytes), Err(Status::BadSize));
        // Nine records, past a page, with the bytes of nine.
        bytes[4] = 9;
        bytes.resize(LIST_FIXED + 9 * RECORD_LEN, 0);
        for i in 2..9 {
            let at = LIST_FIXED + i * RECORD_LEN;
            bytes.copy_within(LIST_FIXED..LIST_FIXED + RECORD_LEN, at);
        }
        assert_eq!(ListReply::read(&bytes), Err(Status::BadSize));
        // A refusal is no page.
        let refused = proto_wire::reply(Status::Kernel(abi::Error::AccessDenied));
        assert_eq!(ListReply::read(&refused), Err(Status::BadSize));
    }

    #[test]
    fn stats_reply_round_trips() {
        let stats = Stats {
            kernel: KernelStats::from_words([1, 2, 3, 4, 5, 6, 7, 8, 9]),
            job: Some((Work::Kill, 5)),
            worker_priority: 33,
            worker_effective: 34,
            worker_state: 1,
            pending: 2,
            begun: true,
            free_pages: 0x1_0000_0001,
            labels: 77,
        };
        let mut w = Writer::new();
        stats.write(&mut w).unwrap();
        let bytes = w.as_bytes();
        assert_eq!(bytes.len(), STATS_LEN);
        assert_eq!(bytes[..8], [0; 8]);
        assert_eq!(bytes[8..16], 1u64.to_le_bytes());
        assert_eq!(bytes[64..72], 8u64.to_le_bytes());
        assert_eq!(bytes[72..80], 9u64.to_le_bytes());
        assert_eq!(bytes[80..88], [3, 6, 33, 34, 1, 2, 1, 0]);
        assert_eq!(bytes[88..96], 0x1_0000_0001u64.to_le_bytes());
        assert_eq!(bytes[96..104], 77u64.to_le_bytes());
        assert_eq!(Stats::read(bytes), Ok(stats));
        let idle = Stats {
            job: None,
            begun: false,
            ..stats
        };
        let mut w = Writer::new();
        idle.write(&mut w).unwrap();
        assert_eq!(w.as_bytes()[80..82], [0, 0]);
        assert_eq!(Stats::read(w.as_bytes()), Ok(idle));
        // A work without its record, a record without its work, a work
        // past the four, and a byte that must be zero.
        for (at, byte) in [(81, 0), (80, 0), (80, 5), (86, 2), (87, 1), (4, 1)] {
            let mut bad = bytes.to_vec();
            bad[at] = byte;
            assert_eq!(Stats::read(&bad), Err(Status::BadSize), "byte {at}");
        }
        assert_eq!(Stats::read(&bytes[..STATS_LEN - 1]), Err(Status::BadSize));
        let far = Stats {
            job: Some((Work::Load, 255)),
            ..stats
        };
        assert_eq!(far.write(&mut Writer::new()), Err(Status::BadSize));
    }

    #[test]
    fn service_args_round_trip() {
        let own = [0xE7; OWN_ARGS_MAX];
        let args = ServiceArgs {
            period_ns: 20_000_000,
            deadline_ns: 100_000_000,
            own: &own,
        };
        let mut w = Writer::new();
        args.write(&mut w).unwrap();
        let bytes = w.as_bytes();
        assert_eq!(bytes.len(), SERVICE_ARGS_FIXED + OWN_ARGS_MAX);
        assert_eq!(bytes[..8], 20_000_000u64.to_le_bytes());
        assert_eq!(bytes[8..16], 100_000_000u64.to_le_bytes());
        assert_eq!(ServiceArgs::read(bytes), Ok(args));
        // A client: both numbers 0, and no arguments of its own.
        let client = ServiceArgs {
            period_ns: 0,
            deadline_ns: 0,
            own: &[],
        };
        let mut w = Writer::new();
        client.write(&mut w).unwrap();
        assert_eq!(w.as_bytes(), [0; SERVICE_ARGS_FIXED]);
        assert_eq!(ServiceArgs::read(w.as_bytes()), Ok(client));
        assert_eq!(ServiceArgs::read(&[0; 15]), Err(Status::BadSize));
        // They fit the start data of a program (rt::startup::ARGS_MAX).
        assert_eq!(SERVICE_ARGS_FIXED + OWN_ARGS_MAX, 256);
    }

    #[test]
    fn service_args_refuse_long_own_args() {
        let own = [1; OWN_ARGS_MAX + 1];
        let args = ServiceArgs {
            period_ns: 1,
            deadline_ns: 3,
            own: &own,
        };
        assert_eq!(args.write(&mut Writer::new()), Err(Status::BadSize));
        let mut bytes = vec![0; SERVICE_ARGS_FIXED];
        bytes.extend_from_slice(&own);
        assert_eq!(ServiceArgs::read(&bytes), Err(Status::BadSize));
        assert!(ServiceArgs::read(&bytes[..bytes.len() - 1]).is_ok());
    }

    #[test]
    fn method_numbers_are_fixed() {
        let numbers = Method::ALL.map(Method::number);
        assert_eq!(numbers, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        for m in Method::ALL {
            assert_eq!(Method::from_number(m.number()), Some(m));
            assert_eq!(m.header(), Header::new(m.number(), VERSION));
        }
        assert_eq!(Method::from_number(0), None);
        assert_eq!(Method::from_number(11), None);
        assert_eq!(VERSION, 1);
        assert_eq!(Method::Start.header().bytes(), [1, 0, 1, 0, 0, 0, 0, 0]);
        assert_eq!(START_PIECE_MAX, 952);
    }
}
