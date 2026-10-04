// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Holds the exact transferred RAM session after its authenticated owner exits.
#![no_std]
#![no_main]
use proto_wire::{Reader, Status};
use rt::handle::{Channel, Handle, Resource};
use rt::service::{Answer, Config, Heartbeat, Request, Service, Session};
use rt::sys;
rt::entry!(main);

fn snapshot(channel: &Handle<Channel>) -> Result<[u32; 9], Status> {
    let request = proto_wire::Header::new(0xfffe, proto_fs::VERSION).bytes();
    let reply = sys::send(channel, &request)?;
    if !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut reader = Reader::new(reply.bytes(&mut buffer));
    let mut result = [0; 9];
    for item in &mut result {
        *item = reader.u32()?;
    }
    reader.finish()?;
    if result[0] != 0 {
        return Err(Status::from_code(result[0]));
    }
    Ok(result)
}
struct Holder {
    kept: [Option<Handle<Channel>>; 3],
    before: [[u32; 9]; 3],
}
impl Service<0> for Holder {
    const VERSION: u16 = 1;
    const METHODS: &'static [u16] = &[1, 2];
    type Data = ();
    fn request(&mut self, _: &mut Session<(), 0>, request: &mut Request<'_>) -> Answer {
        if request.method() == 1 {
            let mut body = request.body();
            let Ok(phase) = body.u32() else {
                return Answer::Status(Status::BadSize);
            };
            if body.finish().is_err() || request.handles.len() != 1 {
                return Answer::Status(Status::BadSize);
            }
            let Ok(kept) = request.handles.take::<Channel>(0) else {
                return Answer::Status(Status::BadSize);
            };
            let before = match snapshot(&kept) {
                Ok(value) => value,
                Err(status) => return Answer::Status(status),
            };
            if before[1..6] != [1, 0, 1, 1, 0] || before[8] != phase {
                rt::println!(
                    "ramfs-holder: unexpected admission {:?} expected {phase}",
                    before
                );
                return Answer::Status(Status::Kernel(rt::abi::Error::BadState));
            }
            if !(1..=3).contains(&phase) || self.kept[(phase - 1) as usize].is_some() {
                return Answer::Status(Status::BadSize);
            }
            self.before[(phase - 1) as usize] = before;
            self.kept[(phase - 1) as usize] = Some(kept);
            return Answer::Status(Status::Ok);
        }
        let mut body = request.body();
        let Ok(phase) = body.u32() else {
            return Answer::Status(Status::BadSize);
        };
        if body.finish().is_err() || !request.handles.is_empty() || !(1..=3).contains(&phase) {
            return Answer::Status(Status::BadSize);
        }
        let index = (phase - 1) as usize;
        let Some(kept) = self.kept[index].as_ref() else {
            return Answer::Status(Status::Kernel(rt::abi::Error::BadState));
        };
        let current = match snapshot(kept) {
            Ok(value) => value,
            Err(status) => return Answer::Status(status),
        };
        for value in current.into_iter().chain([
            self.before[index][6],
            self.before[index][7],
            self.before[index][8],
        ]) {
            if request.reply().u32(value).is_err() {
                return Answer::Status(Status::BadSize);
            }
        }
        Answer::Reply(Default::default())
    }
}
fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let Ok(channel) = sys::channel_create(1) else {
        return 2;
    };
    if rt::service::register(&start.parent, &channel).is_err() {
        return 3;
    }
    let _ = rt::service::run::<Holder, 4, 0>(
        &channel,
        &mut Holder {
            kept: [const { None }; 3],
            before: [[0; 9]; 3],
        },
        Config {
            issued: 0,
            heartbeat: Some(Heartbeat {
                to: &start.parent,
                period_ns: proto_init::ServiceArgs::read(start.args())
                    .map_or(0, |args| args.period_ns),
                priority: sys::thread_info(&start.thread).map_or(1, |info| info.base),
            }),
        },
    );
    4
}
