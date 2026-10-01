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
use posix_process_service::records::{Record, Records};
use proto_process::{Change, Credentials, INIT_PID, Label, Method, RECORDS};
use proto_wire::Status;
use rt::{
    abi::{ProcessState, Rights},
    handle::{Channel, Handle, Outgoing, Process, Resource},
    service::{Answer, Config, Heartbeat, Request, Service, Session},
    sys,
};
mod adopt;
use core::mem::ManuallyDrop;
rt::entry!(main);
/// The sessions of the loop: init's through the channel with no label at
/// place 0, a record's at its index plus 1 (`Service::place`), and a few
/// for labels no record has.
const SESSIONS: usize = RECORDS + 1 + 4;
struct Processes {
    /// The service's channel, which the sessions are copies of.
    channel: ManuallyDrop<Handle<Channel>>,
    /// The priority of the slot of a session: the loop's level.
    level: u8,
    records: Records<Handle<Process>>,
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
    let mut owner = Processes {
        channel: Handle::borrowed(channel.raw()),
        level,
        records: Records::new(),
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
fn snapshot(r: &mut Request<'_>, record: &Record<Handle<Process>>) {
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
                snapshot(r, self.records.get(index).expect("new record"));
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
        let label = self
            .records
            .next_label()
            .ok_or(Status::from_code(proto_process::FULL))?;
        let rights = Rights::SEND | Rights::TRANSFER;
        let session = sys::handle_label(&self.channel, rights, label.raw(), self.level)
            .map_err(Status::Kernel)?;
        let index = self
            .records
            .insert(label, process, parent, credentials, maker);
        Ok((index, session))
    }
}
impl Service<0> for Processes {
    const VERSION: u16 = proto_process::VERSION;
    const METHODS: &'static [u16] = proto_process::METHODS;
    const PLACED: usize = RECORDS + 1;
    type Data = ();
    fn place(&self, label: u64) -> Option<usize> {
        if label == 0 {
            return Some(0);
        }
        self.records.find(label).map(|i| i + 1)
    }
    fn request(&mut self, _: &mut Session<(), 0>, r: &mut Request<'_>) -> Answer {
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
        let Some(index) = self.records.find(r.label()) else {
            return refuse(proto_process::UNREGISTERED);
        };
        if r.method() == Method::Child as u16 {
            if r.body().finish().is_err() || r.handles.len() != 1 {
                return Answer::Status(Status::BadSize);
            }
            if !self.records.may_make(index) {
                return refuse(proto_process::FULL);
            }
            let parent = self.records.get(index).expect("registered parent");
            let (label, credentials) = (parent.label, parent.credentials);
            return self.insert(r, label.pid(), credentials, Some(label));
        }
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let mut body = r.body();
        match r.method() {
            n if n == Method::Query as u16 => {
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                snapshot(r, self.records.get(index).expect("query process"));
                Answer::Reply(Outgoing::new())
            }
            n if n == Method::Change as u16 => {
                let (Ok(operation), Ok(id)) = (body.u32(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let Some(operation) = Change::from_number(operation) else {
                    return refuse(proto_process::INVALID);
                };
                let record = self.records.get_mut(index).expect("change process");
                let result = posix_credentials::change(record.credentials, operation, id)
                    .map(|next| record.credentials = next);
                Answer::Status(status(result))
            }
            _ => Answer::Status(Status::UnknownMethod),
        }
    }
    /// The last copy of a session closed: its record goes; the index waits
    /// on top of the free ones, its next PID one generation on.
    fn gone(&mut self, s: &mut Session<(), 0>) {
        self.records.remove(s.label());
    }
}
