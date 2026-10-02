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
}
impl Client {
    pub fn connect(parent: &Handle<Channel>) -> Result<Self, Status> {
        Self::connect_named(parent, "clock")
    }
    pub fn connect_named(parent: &Handle<Channel>, name: &str) -> Result<Self, Status> {
        Ok(Self {
            channel: service::connect(parent, name)?,
        })
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
    /// the caller waits for the reply.
    pub fn set(&self, time: Time) -> Result<(), Status> {
        time.value()
            .map_err(|_| Status::from_code(proto_clock::INVALID))?;
        let mut request = Writer::new();
        Method::Set.header().write(&mut request)?;
        request.u64(time.seconds as u64)?;
        request.u64(time.nanos as u64)?;
        self.unit(request.as_bytes())
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
