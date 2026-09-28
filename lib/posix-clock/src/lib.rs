// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Clock transport shared by native threads. Interrupted writes retain their nonce.
#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};
use posix_time::{Anchor, Observation, Snapshot, Time};
use proto_clock::Method;
use proto_wire::{Reader, Status, Writer};
use rt::abi::{Error, MESSAGE_MAX};
use rt::handle::{Channel, Handle};
use rt::{service, sys};

static NEXT: AtomicU64 = AtomicU64::new(1);

fn nonce() -> Result<u64, Status> {
    NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .map_err(|_| Status::from_code(proto_clock::OVERFLOW))
}
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
        let nonce = nonce()?;
        let value = self.observe_retained(nonce)?;
        self.ack(nonce)?;
        Ok(value)
    }
    fn observe_retained(&self, nonce: u64) -> Result<Observation, Status> {
        let mut request = Writer::new();
        Method::Observe.header().write(&mut request)?;
        request.u64(nonce)?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut reader = Reader::new(self.call(request.as_bytes(), &mut buffer)?);
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
    pub fn set(&self, time: Time) -> Result<(), Status> {
        time.value()
            .map_err(|_| Status::from_code(proto_clock::INVALID))?;
        let nonce = nonce()?;
        let mut request = Writer::new();
        Method::Set.header().write(&mut request)?;
        request.u64(nonce)?;
        request.u64(time.seconds as u64)?;
        request.u64(time.nanos as u64)?;
        let result = self.unit(request.as_bytes());
        self.ack(nonce)?;
        result
    }
    fn ack(&self, nonce: u64) -> Result<(), Status> {
        let mut ack = Writer::new();
        Method::Ack.header().write(&mut ack)?;
        ack.u64(nonce)?;
        self.unit(ack.as_bytes())
    }
    /// Test-only interruption after a committed SET, ACK or OBSERVE, while this native
    /// caller is in AwaitingReply. The normal service does not expose method 4.
    #[cfg(feature = "transport-probe")]
    pub fn probe_interrupt(
        &self,
        thread: &Handle<rt::handle::Thread>,
        method: Method,
    ) -> Result<(), Status> {
        self.probe_arm(thread, method, false)
    }
    #[cfg(feature = "transport-probe")]
    pub fn probe_upcall(
        &self,
        thread: &Handle<rt::handle::Thread>,
        method: Method,
    ) -> Result<(), Status> {
        self.probe_arm(thread, method, true)
    }
    #[cfg(feature = "transport-probe")]
    fn probe_arm(
        &self,
        thread: &Handle<rt::handle::Thread>,
        method: Method,
        upcall: bool,
    ) -> Result<(), Status> {
        let mut request = Writer::new();
        proto_wire::Header {
            version: proto_clock::VERSION,
            method: if upcall { 8 } else { 4 },
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
    #[cfg(feature = "transport-probe")]
    pub fn probe_observe(&self, nonce: u64) -> Result<Observation, Status> {
        self.observe_retained(nonce)
    }
    #[cfg(feature = "transport-probe")]
    pub fn probe_ack(&self, nonce: u64) -> Result<(), Status> {
        self.ack(nonce)
    }
    #[cfg(feature = "transport-probe")]
    pub fn probe_reject(&self, reject: bool) -> Result<(), Status> {
        let mut request = Writer::new();
        proto_wire::Header {
            version: proto_clock::VERSION,
            method: 9,
        }
        .write(&mut request)?;
        request.u32(u32::from(reject))?;
        self.unit(request.as_bytes())
    }
    #[cfg(feature = "transport-probe")]
    pub fn probe_pressure(&self, hold: bool) -> Result<(), Status> {
        let mut request = Writer::new();
        proto_wire::Header {
            version: proto_clock::VERSION,
            method: 11,
        }
        .write(&mut request)?;
        request.u32(u32::from(hold))?;
        self.unit(request.as_bytes())
    }
    #[cfg(feature = "transport-probe")]
    pub fn probe_stats(&self) -> Result<(u64, u64, u64, u64), Status> {
        let request = proto_wire::Header {
            version: proto_clock::VERSION,
            method: 10,
        }
        .bytes();
        let mut buffer = [0; MESSAGE_MAX];
        let mut reader = Reader::new(self.call(&request, &mut buffer)?);
        reader.u32()?;
        let value = (reader.u64()?, reader.u64()?, reader.u64()?, reader.u64()?);
        reader.finish()?;
        Ok(value)
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
