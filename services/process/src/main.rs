// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The POSIX process service (spec 2, section 3.1): the records of the
//! processes, their PIDs and credentials. The service gives every session
//! it serves through `handle_label` on its own channel, the label naming
//! the record (proto_process::Label), so the label of a request finds its
//! record in O(1) and no kernel call names a process. Create comes only
//! through the channel with no label, from the service's own adopter
//! (adopt.rs), which takes the processes init loaded with ADOPT; Child
//! through the session of a record, which the new record inherits its
//! credentials from, CHILDREN_MAX at a time. Either takes a process handle
//! with MANAGE alone, which the service calls with later. A record goes with the
//! CLIENT_GONE of its session, once the last copy of it closed: when its
//! process ended, or when nobody took the session.
#![no_std]
#![no_main]
use proto_process::{Change, Credentials, INIT_PID, Label, Method, RECORDS};
use proto_wire::Status;
use rt::{
    abi::{ProcessState, Rights},
    handle::{Channel, Handle, Outgoing, Process, Resource},
    service::{Answer, Config, Heartbeat, Request, Service, Session},
    sys,
};
mod adopt;
mod replies;
use core::mem::ManuallyDrop;
use replies::{Journal, Reply};
rt::entry!(main);
struct Record {
    /// Its process, which the service keeps for its later calls (5b).
    _process: Handle<Process>,
    label: Label,
    parent: u32,
    credentials: Credentials,
    /// The live records Child made through its session.
    children: u32,
    /// The record whose Child made it, by its label.
    maker: Option<Label>,
}
/// The live records one record makes through Child at most, so that no
/// process fills the table (RLIMIT_NPROC of 5b replaces it).
const CHILDREN_MAX: u32 = 32;
/// The sessions of the loop: init's through the channel with no label at
/// place 0, a record's at its index plus 1 (`Service::place`), and a few
/// for labels no record has.
const SESSIONS: usize = RECORDS + 1 + 4;
struct Processes {
    /// The service's channel, which the sessions are copies of.
    channel: ManuallyDrop<Handle<Channel>>,
    /// The priority of the slot of a session: the loop's level.
    level: u8,
    records: [Option<Record>; RECORDS],
    /// The last generation each index gave, 0 for none.
    generations: [u32; RECORDS],
    /// The free indices, the last freed on top.
    free: [u16; RECORDS],
    free_len: usize,
    replies: Journal,
    #[cfg(feature = "transport-probe")]
    pressure: [Option<Handle<rt::handle::Channel>>; 128],
    /// The sessions of the records of the probe of the bound.
    #[cfg(feature = "transport-probe")]
    held: [Option<Handle<Channel>>; RECORDS],
}
#[derive(Default)]
struct Data {
    #[cfg(feature = "transport-probe")]
    interrupt: Option<(u16, Handle<rt::handle::Thread>)>,
}
fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    if cfg!(feature = "exit-early") {
        return 9;
    }
    let Ok(channel) = sys::channel_create(1) else {
        return 3;
    };
    if rt::service::register(&start.parent, &channel).is_err() {
        return 4;
    }
    let level = sys::thread_info(&start.thread).map_or(1, |i| i.base);
    if adopt::start(&start.process, &start.parent, &channel, level).is_err() {
        return 6;
    }
    let args = proto_init::ServiceArgs::read(start.args()).ok();
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &start.parent,
            period_ns: args.map_or(0, |a| a.period_ns),
            priority: level,
        }),
    };
    let mut free = [0; RECORDS];
    for (i, slot) in free.iter_mut().enumerate() {
        *slot = (RECORDS - 1 - i) as u16;
    }
    let mut owner = Processes {
        channel: Handle::borrowed(channel.raw()),
        level,
        records: core::array::from_fn(|_| None),
        generations: [0; RECORDS],
        free,
        free_len: RECORDS,
        replies: Journal::new(start.process),
        #[cfg(feature = "transport-probe")]
        pressure: core::array::from_fn(|_| None),
        #[cfg(feature = "transport-probe")]
        held: core::array::from_fn(|_| None),
    };
    rt::println!("posix-process: ready (sessions by label, root by init's table)");
    let _ = rt::service::run::<Processes, SESSIONS, 0>(&channel, &mut owner, config);
    5
}
fn status(result: Result<(), posix_credentials::Error>) -> Status {
    Status::from_code(match result {
        Ok(()) => 0,
        Err(posix_credentials::Error::Invalid) => proto_process::INVALID,
        Err(posix_credentials::Error::Permission) => proto_process::PERMISSION,
    })
}
fn snapshot(r: &mut Request<'_>, record: &Record) {
    let w = r.reply();
    w.u32(0)
        .and_then(|()| w.u32(record.label.pid()))
        .and_then(|()| w.u32(record.parent))
        .expect("process snapshot identity");
    for id in record.credentials.words() {
        w.u32(id).expect("process credentials");
    }
}
fn refuse(code: u32) -> Answer {
    Answer::Status(Status::from_code(code))
}
impl Processes {
    /// The index of the record whose session has `label`, if it lives.
    fn find(&self, label: u64) -> Option<usize> {
        let label = Label::from_raw(label)?;
        let index = usize::from(label.index);
        self.records[index]
            .as_ref()
            .is_some_and(|r| r.label == label)
            .then_some(index)
    }
    /// A new record of the process the request brought, with `parent` and
    /// `credentials`: the reply is its snapshot and its session (`add`).
    fn insert(
        &mut self,
        r: &mut Request<'_>,
        parent: u32,
        credentials: Credentials,
        maker: Option<Label>,
    ) -> Answer {
        // The service calls with the handle later (process_kill, mem_map).
        let manages = r
            .handles
            .info(0)
            .is_some_and(|(_, rights)| rights.contains(Rights::MANAGE));
        if !manages {
            return refuse(proto_process::PERMISSION);
        }
        let Ok(process) = r.handles.take::<Process>(0) else {
            return Answer::Status(Status::BadSize);
        };
        if sys::process_state(&process) != Ok(ProcessState::Alive) {
            return refuse(proto_process::UNREGISTERED);
        }
        match self.add(process, parent, credentials, maker) {
            Ok((index, session)) => {
                snapshot(r, self.records[index].as_ref().expect("new record"));
                Answer::Reply([session.erase()].into())
            }
            Err(status) => Answer::Status(status),
        }
    }
    /// A record of `process` in the free index on top, one generation on,
    /// and its session: O(1). FULL with every record taken; the error of
    /// handle_label as the status, and the index stays free.
    fn add(
        &mut self,
        process: Handle<Process>,
        parent: u32,
        credentials: Credentials,
        maker: Option<Label>,
    ) -> Result<(usize, Handle<Channel>), Status> {
        if self.free_len == 0 {
            return Err(Status::from_code(proto_process::FULL));
        }
        let index = self.free[self.free_len - 1];
        let i = usize::from(index);
        let label = Label {
            index,
            generation: Label::next_generation(self.generations[i]),
        };
        let rights = Rights::SEND | Rights::TRANSFER;
        let session = sys::handle_label(&self.channel, rights, label.raw(), self.level)
            .map_err(Status::Kernel)?;
        self.free_len -= 1;
        self.generations[i] = label.generation;
        self.records[i] = Some(Record {
            _process: process,
            label,
            parent,
            credentials,
            children: 0,
            maker,
        });
        if let Some(m) = maker {
            self.records[usize::from(m.index)]
                .as_mut()
                .expect("a live maker")
                .children += 1;
        }
        Ok((i, session))
    }
}
impl Service<0> for Processes {
    const VERSION: u16 = proto_process::VERSION;
    #[cfg(not(feature = "transport-probe"))]
    const METHODS: &'static [u16] = proto_process::METHODS;
    #[cfg(feature = "transport-probe")]
    const METHODS: &'static [u16] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    const PLACED: usize = RECORDS + 1;
    type Data = Data;
    fn place(&self, label: u64) -> Option<usize> {
        if label == 0 {
            return Some(0);
        }
        self.find(label).map(|i| i + 1)
    }
    fn request(&mut self, s: &mut Session<Data, 0>, r: &mut Request<'_>) -> Answer {
        if r.method() == Method::Create as u16 {
            // Only init holds the channel with no label.
            if r.label() != 0 {
                return refuse(proto_process::PERMISSION);
            }
            let mut body = r.body();
            let root = match body.u32() {
                Ok(0) => false,
                Ok(1) => true,
                _ => return Answer::Status(Status::BadSize),
            };
            if body.finish().is_err() || r.handles.len() != 1 {
                return Answer::Status(Status::BadSize);
            }
            let credentials = if root {
                Credentials::ROOT
            } else {
                Credentials::NOBODY
            };
            return self.insert(r, INIT_PID, credentials, None);
        }
        #[cfg(feature = "transport-probe")]
        if r.method() == 6 {
            let mut body = r.body();
            let Ok(method) = body.u32() else {
                return Answer::Status(Status::BadSize);
            };
            if ![Method::Change as u32, Method::Ack as u32].contains(&method)
                || body.finish().is_err()
                || r.handles.len() != 1
                || s.data.interrupt.is_some()
            {
                return Answer::Status(Status::BadSize);
            }
            let Ok(thread) = r.handles.take::<rt::handle::Thread>(0) else {
                return Answer::Status(Status::BadSize);
            };
            s.data.interrupt = Some((method as u16, thread));
            return Answer::Status(Status::Ok);
        }
        #[cfg(feature = "transport-probe")]
        if r.method() == 7 {
            if !r.handles.is_empty() || r.body().finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            let (used, committed, handles, memory) = self.replies.stats();
            let count = self.records.iter().flatten().count() as u64;
            let w = r.reply();
            w.u32(0).expect("process stats");
            for v in [used, committed, handles, memory, count] {
                w.u64(v).expect("process stats word");
            }
            return Answer::Reply(Outgoing::new());
        }
        #[cfg(feature = "transport-probe")]
        if r.method() == 8 || r.method() == 9 {
            let mut body = r.body();
            let Ok(hold) = body.u32() else {
                return Answer::Status(Status::BadSize);
            };
            if hold > 1 || body.finish().is_err() || !r.handles.is_empty() {
                return Answer::Status(Status::BadSize);
            }
            if r.method() == 8 {
                self.replies.reject = if hold != 0 { Some(r.label()) } else { None };
            } else {
                for slot in &mut self.pressure {
                    if hold == 0 {
                        *slot = None;
                    } else if slot.is_none() {
                        match sys::channel_create(1) {
                            Ok(channel) => *slot = Some(channel),
                            Err(_) => break,
                        }
                    }
                }
            }
            return Answer::Status(Status::Ok);
        }
        // A session of a label the caller names, which the service gave
        // no record: the probe of a session the service did not give.
        #[cfg(feature = "transport-probe")]
        if r.method() == 10 {
            let mut body = r.body();
            let Ok(label) = body.u64() else {
                return Answer::Status(Status::BadSize);
            };
            if label == 0 || self.find(label).is_some() || body.finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            let rights = Rights::SEND | Rights::TRANSFER;
            return match sys::handle_label(&self.channel, rights, label, self.level) {
                Ok(session) => {
                    r.reply().u32(0).expect("probe session");
                    Answer::Reply([session.erase()].into())
                }
                Err(e) => Answer::Status(Status::Kernel(e)),
            };
        }
        let Some(index) = self.find(r.label()) else {
            return refuse(proto_process::UNREGISTERED);
        };
        // The probe of the bound: with a process, records of copies of it
        // in every free index, whose sessions the service keeps; without,
        // the service lets them go. The records made.
        #[cfg(feature = "transport-probe")]
        if r.method() == 11 {
            let mut body = r.body();
            let fill = match body.u32() {
                Ok(1) if r.handles.len() == 1 => true,
                Ok(0) if r.handles.is_empty() => false,
                _ => return Answer::Status(Status::BadSize),
            };
            if body.finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            let mut made = 0;
            if fill {
                let Ok(process) = r.handles.take::<Process>(0) else {
                    return Answer::Status(Status::BadSize);
                };
                let pid = self.records[index].as_ref().expect("filler").label.pid();
                for slot in 0..RECORDS {
                    if self.held[slot].is_some() {
                        continue;
                    }
                    let Ok(copy) = sys::handle_duplicate(&process, Rights::MANAGE) else {
                        break;
                    };
                    match self.add(copy, pid, Credentials::NOBODY, None) {
                        Ok((_, session)) => {
                            self.held[slot] = Some(session);
                            made += 1;
                        }
                        Err(_) => break,
                    }
                }
            } else {
                self.held = core::array::from_fn(|_| None);
            }
            r.reply()
                .u32(0)
                .and_then(|()| r.reply().u32(made))
                .expect("fill reply");
            return Answer::Reply(Outgoing::new());
        }
        if r.method() == Method::Child as u16 {
            if r.body().finish().is_err() || r.handles.len() != 1 {
                return Answer::Status(Status::BadSize);
            }
            let parent = self.records[index].as_ref().expect("registered parent");
            if parent.children >= CHILDREN_MAX {
                return refuse(proto_process::FULL);
            }
            let (label, credentials) = (parent.label, parent.credentials);
            return self.insert(r, label.pid(), credentials, Some(label));
        }
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let label = r.label();
        let mut body = r.body();
        let answer = match r.method() {
            n if n == Method::Query as u16 => {
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                snapshot(r, self.records[index].as_ref().expect("query process"));
                Answer::Reply(Outgoing::new())
            }
            n if n == Method::Ack as u16 => {
                let Ok(nonce) = body.u64() else {
                    return Answer::Status(Status::BadSize);
                };
                if nonce == 0 || body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                self.replies.ack(label, nonce);
                Answer::Status(Status::Ok)
            }
            n if n == Method::Change as u16 => {
                let (Ok(nonce), Ok(operation), Ok(id)) = (body.u64(), body.u32(), body.u32())
                else {
                    return Answer::Status(Status::BadSize);
                };
                if nonce == 0 || body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let Some(operation) = Change::from_number(operation) else {
                    return refuse(proto_process::INVALID);
                };
                let result = if let Some(Reply::Change {
                    operation: old,
                    id: old_id,
                    result,
                }) = self.replies.ready(label, nonce)
                {
                    if operation != old || id != old_id {
                        return refuse(proto_process::INVALID);
                    }
                    result
                } else {
                    if self.replies.reserve(label, nonce).is_err() {
                        return refuse(proto_process::FULL);
                    }
                    let record = self.records[index].as_mut().expect("change process");
                    let result = match posix_credentials::change(record.credentials, operation, id)
                    {
                        Ok(next) => {
                            record.credentials = next;
                            Ok(())
                        }
                        Err(error) => Err(error),
                    };
                    self.replies.complete(
                        label,
                        nonce,
                        Reply::Change {
                            operation,
                            id,
                            result,
                        },
                    );
                    result
                };
                Answer::Status(status(result))
            }
            _ => Answer::Status(Status::UnknownMethod),
        };
        #[cfg(feature = "transport-probe")]
        if s.data
            .interrupt
            .as_ref()
            .is_some_and(|(m, _)| *m == r.method())
        {
            let (_, thread) = s.data.interrupt.take().expect("process interrupt");
            sys::thread_interrupt(&thread).expect("process caller awaits reply");
        }
        #[cfg(not(feature = "transport-probe"))]
        let _ = s;
        answer
    }
    /// The last copy of a session closed: its retained replies go, and its
    /// record with them; the index waits on top of the free ones, its next
    /// PID one generation on.
    fn gone(&mut self, s: &mut Session<Data, 0>) {
        let label = s.label();
        self.replies.forget(label);
        #[cfg(feature = "transport-probe")]
        if self.replies.reject == Some(label) {
            self.replies.reject = None;
        }
        if let Some(index) = self.find(label) {
            let maker = self.records[index].as_ref().and_then(|r| r.maker);
            if let Some(m) = maker
                && let Some(i) = self.find(m.raw())
                && let Some(made) = self.records[i].as_mut()
            {
                made.children -= 1;
            }
            self.records[index] = None;
            self.free[self.free_len] = index as u16;
            self.free_len += 1;
        }
    }
}
