// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Value-only IPC client; POSIX credential policy resides in the GPL service.
//! A client speaks through the session of its record, which the service
//! gave (proto_process): init puts it in the start data of a process under
//! the name `posix`.
#![no_std]
use proto_process::{Change, Credentials, Method};
use proto_wire::{Reader, Status, Writer};
use rt::{
    abi::Error,
    handle::{Channel, Handle},
    sys,
};
/// The name of the session in the start data of a process: the name of
/// the service, since `process` names the process's own handle.
pub const START_NAME: &str = "posix";
/// The name of the identity session in the start data of a process: what
/// the process gives a copy of to a service that asks the process service
/// who it is.
pub const IDENTITY_NAME: &str = "posix-id";
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
    pub fn query(&self) -> Result<Snapshot, Status> {
        let mut buffer = [0; 64];
        Self::snapshot(self.call(&Method::Query.header().bytes(), &mut buffer)?)
    }
    /// Change: the service changes the record's credentials once, whatever
    /// signals come while the caller waits for the reply.
    pub fn change(&self, operation: Change, id: u32) -> Result<(), Status> {
        let mut w = Writer::new();
        Method::Change.header().write(&mut w)?;
        w.u32(operation as u32)?;
        w.u32(id)?;
        let mut buffer = [0; 64];
        let bytes = self.call(w.as_bytes(), &mut buffer)?;
        if bytes != proto_wire::reply(Status::Ok) {
            return Err(Status::BadSize);
        }
        Ok(())
    }
}
