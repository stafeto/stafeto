// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Value-only IPC client; POSIX credential policy resides in the GPL service.
//! A client speaks through the session of its record, which the service
//! gave (proto_process): init puts it in the start data of a process under
//! the name `posix`, and Child gives one for a native child.
#![no_std]
use core::sync::atomic::{AtomicU64, Ordering};
use proto_process::{Change, Credentials, Method};
use proto_wire::{Reader, Status, Writer};
use rt::{
    abi::{Error, Rights},
    handle::{Channel, Handle, Process},
    sys,
};
static NEXT: AtomicU64 = AtomicU64::new(1);
/// The name of the session in the start data of a process: the name of
/// the service, since `process` names the process's own handle.
pub const START_NAME: &str = "posix";
pub struct Client {
    channel: Handle<Channel>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub pid: u32,
    pub parent: u32,
    pub credentials: Credentials,
}
impl Client {
    /// A client through `session`, the session of a record.
    pub const fn new(session: Handle<Channel>) -> Self {
        Self { channel: session }
    }
    /// The session the client speaks through.
    pub fn session(&self) -> &Handle<Channel> {
        &self.channel
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
        let (pid, parent) = (r.u32()?, r.u32()?);
        let mut words = [0; 6];
        for w in &mut words {
            *w = r.u32()?;
        }
        r.finish()?;
        if pid == 0
            || pid > i32::MAX as u32
            || parent > i32::MAX as u32
            || words.contains(&u32::MAX)
        {
            return Err(Status::BadSize);
        }
        Ok(Snapshot {
            pid,
            parent,
            credentials: Credentials::from_words(words),
        })
    }
    /// A record of `process` through `method` with `body`: its snapshot
    /// and its session. An interrupted request goes again: the session of
    /// the lost reply closed, and its record went with it.
    fn register(
        &self,
        method: Method,
        body: &[u8],
        process: &Handle<Process>,
    ) -> Result<(Snapshot, Handle<Channel>), Status> {
        let mut w = Writer::new();
        method.header().write(&mut w)?;
        w.bytes(body)?;
        loop {
            let rights = Rights::MANAGE | Rights::TRANSFER;
            let handle = sys::handle_duplicate(process, rights)?;
            let mut reply = match sys::send_handles(&self.channel, w.as_bytes(), [handle.erase()]) {
                Err(error) if error.error == Error::Interrupted => continue,
                other => other.map_err(|e| Status::Kernel(e.error))?,
            };
            let mut buffer = [0; 64];
            if reply.len > 64 {
                return Err(Status::BadSize);
            }
            buffer.copy_from_slice(&rt::abi::inline_bytes(&reply.words));
            let bytes = &buffer[..reply.len];
            let status = Status::from_code(Reader::new(bytes).u32()?);
            if status != Status::Ok {
                if bytes != proto_wire::reply(status) || !reply.handles.is_empty() {
                    return Err(Status::BadSize);
                }
                return Err(status);
            }
            let snapshot = Self::snapshot(bytes)?;
            if reply.handles.len() != 1 {
                return Err(Status::BadSize);
            }
            let session = reply.handles.take(0).map_err(|_| Status::BadSize)?;
            return Ok((snapshot, session));
        }
    }
    /// Create through the service's channel with no label, which only init
    /// holds: a record of `process` with root credentials when `root`,
    /// with no privilege otherwise, its parent PID 1. PERMISSION through a
    /// session.
    pub fn create(
        &self,
        process: &Handle<Process>,
        root: bool,
    ) -> Result<(Snapshot, Handle<Channel>), Status> {
        self.register(Method::Create, &u32::from(root).to_le_bytes(), process)
    }
    /// A record of the native child `child` with the caller's credentials,
    /// before the child starts: its snapshot and the session the parent
    /// gives it.
    pub fn child(&self, child: &Handle<Process>) -> Result<(Snapshot, Handle<Channel>), Status> {
        self.register(Method::Child, &[], child)
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
    /// A session of the service with `label`, which names no record (the
    /// probe of a session the service did not give).
    #[cfg(feature = "transport-probe")]
    pub fn forge(&self, label: u64) -> Result<Handle<Channel>, Status> {
        let mut w = Writer::new();
        proto_wire::Header {
            version: proto_process::VERSION,
            method: 10,
        }
        .write(&mut w)?;
        w.u64(label)?;
        let mut reply = sys::send(&self.channel, w.as_bytes())?;
        let mut buffer = [0; 64];
        if reply.len > 64 {
            return Err(Status::BadSize);
        }
        buffer.copy_from_slice(&rt::abi::inline_bytes(&reply.words));
        let bytes = &buffer[..reply.len];
        let status = Status::from_code(Reader::new(bytes).u32()?);
        if status != Status::Ok {
            return Err(status);
        }
        reply.handles.take(0).map_err(|_| Status::BadSize)
    }
    /// With `process`, the service fills its free records with copies of
    /// it and keeps their sessions; without, it lets them go. The records
    /// it made, 0 for a release.
    #[cfg(feature = "transport-probe")]
    pub fn fill(&self, process: Option<&Handle<Process>>) -> Result<u32, Status> {
        let mut w = Writer::new();
        proto_wire::Header {
            version: proto_process::VERSION,
            method: 11,
        }
        .write(&mut w)?;
        w.u32(u32::from(process.is_some()))?;
        let reply = match process {
            Some(p) => {
                let rights = Rights::DUPLICATE | Rights::MANAGE | Rights::TRANSFER;
                let copy = sys::handle_duplicate(p, rights)?;
                sys::send_handles(&self.channel, w.as_bytes(), [copy.erase()])
                    .map_err(|e| Status::Kernel(e.error))?
            }
            None => sys::send(&self.channel, w.as_bytes())?,
        };
        let mut buffer = [0; 64];
        if reply.len > 64 || !reply.handles.is_empty() {
            return Err(Status::BadSize);
        }
        buffer.copy_from_slice(&rt::abi::inline_bytes(&reply.words));
        let mut r = Reader::new(&buffer[..reply.len]);
        match Status::from_code(r.u32()?) {
            Status::Ok => {}
            status => return Err(status),
        }
        let made = r.u32()?;
        r.finish()?;
        Ok(made)
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
