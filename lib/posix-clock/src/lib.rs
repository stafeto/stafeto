// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Clock transport shared by native threads. Interrupted writes retain their nonce.
#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};
use posix_time::{Snapshot, Time};
use proto_clock::Method;
use proto_wire::{Reader, Status, Writer};
use rt::abi::{Error, MESSAGE_MAX};
use rt::handle::{Channel, Handle};
use rt::{service, sys};

static NEXT: AtomicU64 = AtomicU64::new(1);

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
    pub fn set(&self, time: Time) -> Result<(), Status> {
        time.value()
            .map_err(|_| Status::from_code(proto_clock::INVALID))?;
        let nonce = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Status::from_code(proto_clock::OVERFLOW))?;
        let mut request = Writer::new();
        Method::Set.header().write(&mut request)?;
        request.u64(nonce)?;
        request.u64(time.seconds as u64)?;
        request.u64(time.nanos as u64)?;
        self.unit(request.as_bytes())?;
        let mut ack = Writer::new();
        Method::Ack.header().write(&mut ack)?;
        ack.u64(nonce)?;
        self.unit(ack.as_bytes())
    }
    /// Test-only interruption after a committed SET or ACK, while this native
    /// caller is in AwaitingReply. The normal service does not expose method 4.
    #[cfg(feature = "transport-probe")]
    pub fn probe_interrupt(
        &self,
        thread: &Handle<rt::handle::Thread>,
        method: Method,
    ) -> Result<(), Status> {
        let mut request = Writer::new();
        proto_wire::Header {
            version: proto_clock::VERSION,
            method: 4,
        }
        .write(&mut request)?;
        request.u32(method as u32)?;
        let copy =
            sys::handle_duplicate(thread, rt::abi::Rights::MANAGE | rt::abi::Rights::TRANSFER)?;
        let reply = sys::send_handles(&self.channel, request.as_bytes(), [copy.erase()])
            .map_err(|e| Status::Kernel(e.error))?;
        let mut buffer = [0; MESSAGE_MAX];
        let bytes = reply.bytes(&mut buffer);
        if bytes != proto_wire::reply(Status::Ok) {
            return Err(Status::BadSize);
        }
        Ok(())
    }
    /// Exercise retained operations and malformed bodies without acknowledging.
    #[cfg(feature = "transport-probe")]
    pub fn probe_call(&self, request: &[u8]) -> Result<(), Status> {
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
