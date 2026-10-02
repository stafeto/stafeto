// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Clock transport shared by native threads. A request the service accepted
//! is answered once: an interruption ends only a request still in the queue,
//! which the service never saw, so a call that comes back INTERRUPTED is
//! sent again.
#![no_std]

use posix_time::{Anchor, Observation, Snapshot, Time};
use proto_clock::Method;
use proto_wire::{Reader, Status, Writer};
use rt::abi::{Error, MESSAGE_MAX};
use rt::handle::{Channel, Handle};
use rt::{service, sys};

pub struct Client {
    channel: Handle<Channel>,
    /// Whether the service has the caller's identity for the session.
    vouched: core::sync::atomic::AtomicBool,
}
impl Client {
    pub fn connect(parent: &Handle<Channel>) -> Result<Self, Status> {
        Self::connect_named(parent, "clock")
    }
    pub fn connect_named(parent: &Handle<Channel>, name: &str) -> Result<Self, Status> {
        Ok(Self {
            channel: service::connect(parent, name)?,
            vouched: core::sync::atomic::AtomicBool::new(false),
        })
    }
    /// A client through `channel`, a session the program was given.
    pub fn from_session(channel: Handle<Channel>) -> Self {
        Self {
            channel,
            vouched: core::sync::atomic::AtomicBool::new(false),
        }
    }
    /// The session, which a child gets a clone of.
    pub fn session(&self) -> &Handle<Channel> {
        &self.channel
    }
    fn call<'a>(
        &self,
        request: &[u8],
        buffer: &'a mut [u8; MESSAGE_MAX],
    ) -> Result<&'a [u8], Status> {
        loop {
            let reply = match sys::send(&self.channel, request) {
                Err(Error::Interrupted) => continue,
                result => result.map_err(Status::Kernel)?,
            };
            if !reply.handles.is_empty() {
                return Err(Status::BadSize);
            }
            let bytes = reply.bytes(buffer);
            match Status::from_code(Reader::new(bytes).u32()?) {
                Status::Ok => return Ok(bytes),
                status => return Err(status),
            }
        }
    }
    pub fn get(&self, id: u32) -> Result<Snapshot, Status> {
        let mut request = Writer::new();
        Method::Get.header().write(&mut request)?;
        request.u32(id)?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut reader = Reader::new(self.call(request.as_bytes(), &mut buffer)?);
        reader.u32()?;
        let time = Time {
            seconds: reader.u64()? as i64,
            nanos: reader.u64()? as i64,
        };
        let resolution = reader.u64()?;
        let generation = reader.u64()?;
        reader.finish()?;
        if time.value().is_err() || !(1..=1_000_000_000).contains(&resolution) {
            return Err(Status::BadSize);
        }
        Ok(Snapshot {
            time,
            resolution,
            generation,
        })
    }
    /// Install one notification endpoint per clock session; retry by replacing
    /// a previous copy after Interrupted consumed the transfer or its reply.
    pub fn watch(&self, channel: &Handle<Channel>) -> Result<(), Status> {
        let request = Method::Watch.header().bytes();
        loop {
            let copy = sys::handle_duplicate(
                channel,
                rt::abi::Rights::NOTIFY | rt::abi::Rights::TRANSFER,
            )?;
            let reply = match sys::send_handles(&self.channel, &request, [copy.erase()]) {
                Err(e) if e.error == Error::Interrupted => continue,
                result => result.map_err(|e| Status::Kernel(e.error))?,
            };
            let mut buffer = [0; MESSAGE_MAX];
            let bytes = reply.bytes(&mut buffer);
            if !reply.handles.is_empty() || bytes.len() != proto_wire::HEADER_LEN {
                return Err(Status::BadSize);
            }
            let status = Status::from_code(Reader::new(bytes).u32()?);
            if bytes != proto_wire::reply(status) {
                return Err(Status::BadSize);
            }
            return match status {
                Status::Ok => Ok(()),
                status => Err(status),
            };
        }
    }
    /// PAGE: the service's page of the CLOCK_REALTIME anchor, to map for
    /// reading (proto_clock::page).
    pub fn page(&self) -> Result<Handle<rt::handle::Memory>, Status> {
        let request = Method::Page.header().bytes();
        loop {
            let mut reply = match sys::send(&self.channel, &request) {
                Err(Error::Interrupted) => continue,
                result => result.map_err(Status::Kernel)?,
            };
            let mut buffer = [0; MESSAGE_MAX];
            let bytes = reply.bytes(&mut buffer);
            match Status::from_code(Reader::new(bytes).u32()?) {
                Status::Ok => {}
                status => return Err(status),
            }
            if reply.handles.len() != 1 {
                return Err(Status::BadSize);
            }
            return reply.handles.take(0).map_err(Status::Kernel);
        }
    }
    pub fn anchor(&self) -> Result<Anchor, Status> {
        let request = Method::Anchor.header().bytes();
        let mut buffer = [0; MESSAGE_MAX];
        let mut reader = Reader::new(self.call(&request, &mut buffer)?);
        reader.u32()?;
        let time = Time {
            seconds: reader.u64()? as i64,
            nanos: reader.u64()? as i64,
        };
        let mono = reader.u64()?;
        let resolution = reader.u64()?;
        let generation = reader.u64()?;
        reader.finish()?;
        if time.value().is_err() || !(1..=1_000_000_000).contains(&resolution) {
            return Err(Status::BadSize);
        }
        Ok(Anchor {
            time,
            mono,
            resolution,
            generation,
        })
    }
    /// Exclusive observation consumer for this subscribed session. Consuming
    /// the interval peak starts a new interval at the sampled current date.
    pub fn observe(&self) -> Result<Observation, Status> {
        let request = Method::Observe.header().bytes();
        let mut buffer = [0; MESSAGE_MAX];
        let mut reader = Reader::new(self.call(&request, &mut buffer)?);
        reader.u32()?;
        let time = Time {
            seconds: reader.u64()? as i64,
            nanos: reader.u64()? as i64,
        };
        let mono = reader.u64()?;
        let resolution = reader.u64()?;
        let generation = reader.u64()?;
        let high = reader.u64()?;
        let low = reader.u64()?;
        reader.finish()?;
        let peak = i128::try_from((u128::from(high) << 64) | u128::from(low))
            .map_err(|_| Status::BadSize)?;
        if time.value().is_err() || !(1..=1_000_000_000).contains(&resolution) {
            return Err(Status::BadSize);
        }
        let value = Observation {
            anchor: Anchor {
                time,
                mono,
                resolution,
                generation,
            },
            peak,
        };
        Ok(value)
    }
    /// SET: the service sets the date once, whatever signals come while
    /// the caller waits for the reply. `identity` is the caller's identity
    /// session of the process service (a copy of it goes with the request:
    /// the service keeps the last one offered for the session); without one the
    /// service answers PERMISSION.
    pub fn set(&self, time: Time, identity: Option<&Handle<Channel>>) -> Result<(), Status> {
        time.value()
            .map_err(|_| Status::from_code(proto_clock::INVALID))?;
        let mut request = Writer::new();
        Method::Set.header().write(&mut request)?;
        request.u64(time.seconds as u64)?;
        request.u64(time.nanos as u64)?;
        let Some(identity) = identity else {
            return self.unit(request.as_bytes());
        };
        // The copy of the identity goes with the first SET of the session,
        // and again when the service answers PERMISSION to a SET without
        // one (it gave its place for the session to another).
        let first = !self.vouched.load(core::sync::atomic::Ordering::Relaxed);
        let result = self.set_with(request.as_bytes(), first.then_some(identity));
        let result = match result {
            Err(s) if !first && s == Status::from_code(proto_clock::PERMISSION) => {
                self.set_with(request.as_bytes(), Some(identity))
            }
            other => other,
        };
        if result.is_ok() {
            self.vouched
                .store(true, core::sync::atomic::Ordering::Relaxed);
        }
        result
    }
    /// SET of `request`, with a copy of `identity` (NOTIFY, TRANSFER and
    /// DUPLICATE: the service has the process service vouch for it) when
    /// given.
    fn set_with(&self, request: &[u8], identity: Option<&Handle<Channel>>) -> Result<(), Status> {
        loop {
            let rights =
                rt::abi::Rights::NOTIFY | rt::abi::Rights::TRANSFER | rt::abi::Rights::DUPLICATE;
            let sent = match identity {
                Some(identity) => {
                    let copy = sys::handle_duplicate(identity, rights)?;
                    sys::send_handles(&self.channel, request, [copy.erase()]).map_err(|e| e.error)
                }
                None => sys::send(&self.channel, request),
            };
            let reply = match sent {
                Err(Error::Interrupted) => continue,
                result => result.map_err(Status::Kernel)?,
            };
            let mut buffer = [0; MESSAGE_MAX];
            let bytes = reply.bytes(&mut buffer);
            if !reply.handles.is_empty() {
                return Err(Status::BadSize);
            }
            return match Status::from_code(Reader::new(bytes).u32()?) {
                Status::Ok if bytes == proto_wire::reply(Status::Ok) => Ok(()),
                Status::Ok => Err(Status::BadSize),
                status => Err(status),
            };
        }
    }
    /// A request as the caller wrote it, for the probes of malformed
    /// bodies.
    pub fn raw(&self, request: &[u8]) -> Result<(), Status> {
        self.unit(request)
    }
    fn unit(&self, request: &[u8]) -> Result<(), Status> {
        let mut buffer = [0; MESSAGE_MAX];
        if self.call(request, &mut buffer)? != proto_wire::reply(Status::Ok) {
            return Err(Status::BadSize);
        }
        Ok(())
    }
}
