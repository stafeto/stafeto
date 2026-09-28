// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Value-only IPC client; POSIX credential policy resides in the GPL service.
#![no_std]
use core::sync::atomic::{AtomicU64, Ordering};
use proto_process::{Change, Credentials, Method};
use proto_wire::{Reader, Status, Writer};
use rt::{
    abi::{Error, ProcessIdentity, Rights},
    handle::{Channel, Handle, Process},
    service, sys,
};
static NEXT: AtomicU64 = AtomicU64::new(1);
pub struct Client {
    channel: Handle<Channel>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub identity: ProcessIdentity,
    pub credentials: Credentials,
}
impl Client {
    pub fn connect(parent: &Handle<Channel>) -> Result<Self, Status> {
        Ok(Self {
            channel: service::connect(parent, "posix")?,
        })
    }
    fn call<'a>(&self, request: &[u8], buffer: &'a mut [u8; 64]) -> Result<&'a [u8], Status> {
        loop {
            let reply = match sys::send(&self.channel, request) {
                Err(Error::Interrupted) => continue,
                other => other.map_err(Status::Kernel)?,
            };
            if !reply.handles.is_empty() {
                return Err(Status::BadSize);
            }
            if reply.len > 64 {
                return Err(Status::BadSize);
            }
            buffer.copy_from_slice(&rt::abi::inline_bytes(&reply.words));
            let bytes = &buffer[..reply.len];
            match Status::from_code(Reader::new(bytes).u32()?) {
                Status::Ok => return Ok(bytes),
                error => {
                    if bytes != proto_wire::reply(error) {
                        return Err(Status::BadSize);
                    }
                    return Err(error);
                }
            }
        }
    }
    fn snapshot(bytes: &[u8]) -> Result<Snapshot, Status> {
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let identity = ProcessIdentity {
            id: r.u32()?,
            parent: r.u32()?,
        };
        let mut words = [0; 6];
        for w in &mut words {
            *w = r.u32()?;
        }
        r.finish()?;
        if identity.id == 0
            || identity.id > rt::abi::PROCESS_ID_MAX
            || identity.parent > rt::abi::PROCESS_ID_MAX
            || words.contains(&u32::MAX)
        {
            return Err(Status::BadSize);
        }
        Ok(Snapshot {
            identity,
            credentials: Credentials::from_words(words),
        })
    }
    fn register(&self, method: Method, process: &Handle<Process>) -> Result<Snapshot, Status> {
        let request = method.header().bytes();
        loop {
            let handle = sys::handle_duplicate(process, Rights::TRANSFER)?;
            let reply = match sys::send_handles(&self.channel, &request, [handle.erase()]) {
                Err(error) if error.error == Error::Interrupted => continue,
                other => other.map_err(|e| Status::Kernel(e.error))?,
            };
            if !reply.handles.is_empty() {
                return Err(Status::BadSize);
            }
            let mut buffer = [0; 64];
            if reply.len > 64 {
                return Err(Status::BadSize);
            }
            buffer.copy_from_slice(&rt::abi::inline_bytes(&reply.words));
            let bytes = &buffer[..reply.len];
            let status = Status::from_code(Reader::new(bytes).u32()?);
            if status != Status::Ok {
                if bytes != proto_wire::reply(status) {
                    return Err(Status::BadSize);
                }
                return Err(status);
            }
            return Self::snapshot(bytes);
        }
    }
    pub fn enroll(&self, own: &Handle<Process>) -> Result<Snapshot, Status> {
        self.register(Method::Enroll, own)
    }
    /// Parent registers its native child with a credential snapshot before start.
    pub fn child(&self, child: &Handle<Process>) -> Result<Snapshot, Status> {
        self.register(Method::Child, child)
    }
    pub fn query(&self) -> Result<Snapshot, Status> {
        let mut buffer = [0; 64];
        Self::snapshot(self.call(&Method::Query.header().bytes(), &mut buffer)?)
    }
    pub fn change(&self, operation: Change, id: u32) -> Result<(), Status> {
        let nonce = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Status::from_code(proto_process::FULL))?;
        let result = self.change_retained(nonce, operation, id);
        // Error outcomes are also retained; acknowledge before returning the status.
        if !matches!(
            result,
            Err(Status::Kernel(_) | Status::BadSize | Status::BadVersion | Status::UnknownMethod)
        ) {
            self.ack(nonce)?;
        }
        result
    }
    pub fn change_retained(&self, nonce: u64, operation: Change, id: u32) -> Result<(), Status> {
        let mut w = Writer::new();
        Method::Change.header().write(&mut w)?;
        w.u64(nonce)?;
        w.u32(operation as u32)?;
        w.u32(id)?;
        let mut buffer = [0; 64];
        let bytes = self.call(w.as_bytes(), &mut buffer)?;
        if bytes != proto_wire::reply(Status::Ok) {
            return Err(Status::BadSize);
        }
        Ok(())
    }
    pub fn ack(&self, nonce: u64) -> Result<(), Status> {
        let mut w = Writer::new();
        Method::Ack.header().write(&mut w)?;
        w.u64(nonce)?;
        let mut buffer = [0; 64];
        let bytes = self.call(w.as_bytes(), &mut buffer)?;
        if bytes != proto_wire::reply(Status::Ok) {
            return Err(Status::BadSize);
        }
        Ok(())
    }
    #[cfg(feature = "transport-probe")]
    pub fn interrupt(
        &self,
        thread: &Handle<rt::handle::Thread>,
        method: Method,
    ) -> Result<(), Status> {
        let mut w = Writer::new();
        proto_wire::Header {
            version: proto_process::VERSION,
            method: 6,
        }
        .write(&mut w)?;
        w.u32(method as u32)?;
        let copy = sys::handle_duplicate(thread, Rights::MANAGE | Rights::TRANSFER)?;
        let reply = sys::send_handles(&self.channel, w.as_bytes(), [copy.erase()])
            .map_err(|e| Status::Kernel(e.error))?;
        let mut buffer = [0; 64];
        if reply.len > 64 {
            return Err(Status::BadSize);
        }
        buffer.copy_from_slice(&rt::abi::inline_bytes(&reply.words));
        let bytes = &buffer[..reply.len];
        if !reply.handles.is_empty() || bytes != proto_wire::reply(Status::Ok) {
            return Err(Status::BadSize);
        }
        Ok(())
    }
    #[cfg(feature = "transport-probe")]
    pub fn stats(&self) -> Result<[u64; 5], Status> {
        let w = proto_wire::Header {
            version: proto_process::VERSION,
            method: 7,
        }
        .bytes();
        let mut buffer = [0; 64];
        let mut r = Reader::new(self.call(&w, &mut buffer)?);
        r.u32()?;
        let mut values = [0; 5];
        for value in &mut values {
            *value = r.u64()?;
        }
        r.finish()?;
        Ok(values)
    }
    #[cfg(feature = "transport-probe")]
    pub fn control(&self, method: u16, on: bool) -> Result<(), Status> {
        let mut w = Writer::new();
        proto_wire::Header {
            version: proto_process::VERSION,
            method,
        }
        .write(&mut w)?;
        w.u32(u32::from(on))?;
        let mut buffer = [0; 64];
        let bytes = self.call(w.as_bytes(), &mut buffer)?;
        if bytes != proto_wire::reply(Status::Ok) {
            return Err(Status::BadSize);
        }
        Ok(())
    }
}
