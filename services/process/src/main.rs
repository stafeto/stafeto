// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Shared authenticated process registry and POSIX credentials.
#![no_std]
#![no_main]
use proto_process::{Change, Credentials, Method};
use proto_wire::Status;
use rt::{
    abi::{ProcessIdentity, ProcessState},
    handle::{Handle, Outgoing, Process, Resource},
    service::{Answer, Config, Heartbeat, Request, Service, Session},
    sys,
};
mod replies;
use replies::{Journal, Reply};
rt::entry!(main);
struct Record {
    process: Handle<Process>,
    identity: ProcessIdentity,
    credentials: Credentials,
}
struct Processes {
    records: [Option<Record>; 64],
    replies: Journal,
    #[cfg(feature = "transport-probe")]
    pressure: [Option<Handle<rt::handle::Channel>>; 128],
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
    if !sys::process_identity(&start.process).is_ok_and(|id| id.parent == 1) {
        return 2;
    }
    let Ok(channel) = sys::channel_create(1) else {
        return 3;
    };
    if rt::service::register(&start.parent, &channel).is_err() {
        return 4;
    }
    let args = proto_init::ServiceArgs::read(start.args()).ok();
    let level = sys::thread_info(&start.thread).map_or(1, |i| i.base);
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &start.parent,
            period_ns: args.map_or(0, |a| a.period_ns),
            priority: level,
        }),
    };
    let mut owner = Processes {
        records: core::array::from_fn(|_| None),
        replies: Journal::new(start.process),
        #[cfg(feature = "transport-probe")]
        pressure: core::array::from_fn(|_| None),
    };
    rt::println!("posix-process: ready (init children start with root credentials)");
    let _ = rt::service::run::<Processes, 32, 0>(&channel, &mut owner, config);
    5
}
fn status(result: Result<(), posix_credentials::Error>) -> Status {
    Status::from_code(match result {
        Ok(()) => 0,
        Err(posix_credentials::Error::Invalid) => proto_process::INVALID,
        Err(posix_credentials::Error::Permission) => proto_process::PERMISSION,
    })
}
fn snapshot(r: &mut Request<'_>, record: &Record) -> Answer {
    let w = r.reply();
    w.u32(0)
        .and_then(|()| w.u32(record.identity.id))
        .and_then(|()| w.u32(record.identity.parent))
        .expect("process snapshot identity");
    for id in record.credentials.words() {
        w.u32(id).expect("process credentials");
    }
    Answer::Reply(Outgoing::new())
}
impl Processes {
    fn find(&self, pid: u32) -> Option<usize> {
        self.records
            .iter()
            .position(|r| r.as_ref().is_some_and(|r| r.identity.id == pid))
    }
    fn reap(&mut self) {
        for record in &mut self.records {
            if record
                .as_ref()
                .is_some_and(|r| sys::process_state(&r.process) != Ok(ProcessState::Alive))
                && let Some(record) = record.take()
            {
                self.replies.forget_process(record.identity.id);
            }
        }
    }
    fn register(&mut self, r: &mut Request<'_>, caller: ProcessIdentity, child: bool) -> Answer {
        if r.body().finish().is_err() || r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let Ok(process) = r.handles.take::<Process>(0) else {
            return Answer::Status(Status::BadSize);
        };
        let Ok(identity) = sys::process_identity(&process) else {
            return Answer::Status(Status::BadSize);
        };
        if sys::process_state(&process) != Ok(ProcessState::Alive) {
            return Answer::Status(Status::from_code(proto_process::UNREGISTERED));
        }
        let credentials = if child {
            if identity.parent != caller.id {
                return Answer::Status(Status::from_code(proto_process::PERMISSION));
            }
            let Some(parent) = self.find(caller.id) else {
                return Answer::Status(Status::from_code(proto_process::UNREGISTERED));
            };
            self.records[parent]
                .as_ref()
                .expect("registered parent")
                .credentials
        } else {
            if identity != caller {
                return Answer::Status(Status::from_code(proto_process::PERMISSION));
            }
            if let Some(index) = self.find(caller.id) {
                return snapshot(r, self.records[index].as_ref().expect("registered self"));
            }
            if caller.parent != 1 {
                return Answer::Status(Status::from_code(proto_process::PERMISSION));
            }
            Credentials::ROOT
        };
        if let Some(index) = self.find(identity.id) {
            // A retry preserves the original snapshot, even if the parent changed later.
            return snapshot(r, self.records[index].as_ref().expect("registered child"));
        }
        let Some(index) = self.records.iter().position(Option::is_none) else {
            return Answer::Status(Status::from_code(proto_process::FULL));
        };
        self.records[index] = Some(Record {
            process,
            identity,
            credentials,
        });
        snapshot(r, self.records[index].as_ref().expect("new process"))
    }
}
impl Service<0> for Processes {
    const VERSION: u16 = proto_process::VERSION;
    #[cfg(not(feature = "transport-probe"))]
    const METHODS: &'static [u16] = proto_process::METHODS;
    #[cfg(feature = "transport-probe")]
    const METHODS: &'static [u16] = &[1, 2, 3, 4, 5, 6, 7, 8, 9];
    type Data = Data;
    fn request(&mut self, s: &mut Session<Data, 0>, r: &mut Request<'_>) -> Answer {
        let caller = match r.sender_identity() {
            Ok(id) => id,
            Err(e) => return Answer::Status(Status::Kernel(e)),
        };
        self.reap();
        if r.method() == Method::Enroll as u16 || r.method() == Method::Child as u16 {
            let child = r.method() == Method::Child as u16;
            return self.register(r, caller, child);
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
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let Some(index) = self.find(caller.id) else {
            return Answer::Status(Status::from_code(proto_process::UNREGISTERED));
        };
        let mut body = r.body();
        let answer = match r.method() {
            n if n == Method::Query as u16 => {
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                snapshot(r, self.records[index].as_ref().expect("query process"))
            }
            n if n == Method::Ack as u16 => {
                let Ok(nonce) = body.u64() else {
                    return Answer::Status(Status::BadSize);
                };
                if nonce == 0 || body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                self.replies.ack(caller.id, r.label(), nonce);
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
                    return Answer::Status(Status::from_code(proto_process::INVALID));
                };
                let result = if let Some(Reply::Change {
                    operation: old,
                    id: old_id,
                    result,
                }) = self.replies.ready(caller.id, r.label(), nonce)
                {
                    if operation != old || id != old_id {
                        return Answer::Status(Status::from_code(proto_process::INVALID));
                    }
                    result
                } else {
                    if self.replies.reserve(caller.id, r.label(), nonce).is_err() {
                        return Answer::Status(Status::from_code(proto_process::FULL));
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
                        caller.id,
                        r.label(),
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
    fn gone(&mut self, s: &mut Session<Data, 0>) {
        self.replies.forget(s.label());
        #[cfg(feature = "transport-probe")]
        if self.replies.reject == Some(s.label()) {
            self.replies.reject = None;
        }
    }
}
