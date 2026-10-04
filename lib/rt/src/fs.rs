// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Per-process file descriptors for the first RAM file service. The three
//! standard descriptors use the console; file descriptors 3 and above
//! belong to one session with `ramfs`.

use crate::handle::{Channel, Handle};
use crate::{console, service, sys};
use abi::{Error, MESSAGE_MAX};
use proto_fs::{MAX_READ, MAX_WRITE, Metadata, Method, valid_path};
use proto_uart::{ReadReply, ReadRequest, WriteReply, WriteRequest};
use proto_wire::{Reader, Status, Writer};

/// A console transport snapshot, without a borrow of the file owner.
/// It carries no application buffer or file-state pointer. The owning Files
/// must remain alive while this snapshot is used; it does not retain a UART
/// session. A closed or failed transport is reported by the kernel.
#[derive(Clone, Copy)]
pub struct Input {
    uart: Option<abi::Handle>,
}

impl Input {
    /// A process-local transport identifier for value-message routing.
    pub fn uart(&self) -> Option<abi::Handle> {
        self.uart
    }

    /// Borrow a transport retained elsewhere in this process; no ownership is taken.
    pub const fn from_uart(uart: Option<abi::Handle>) -> Self {
        Self { uart }
    }

    /// A write of standard output or error to the console through this
    /// snapshot, as `Files::write` makes it: out of any lock of its owner,
    /// since the driver answers a write into a full ring later.
    pub fn write(&self, bytes: &[u8]) -> Result<usize, Status> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let uart = self.uart.map(Handle::<Channel>::borrowed);
        console_write(uart.as_deref(), bytes)
    }

    /// A plain READ (proto_uart): the reply waits for input. A program
    /// with signals reads in two steps instead (posix-abi), so that a
    /// signal never waits behind it.
    pub fn read(&self, out: &mut [u8]) -> Result<usize, Status> {
        if out.is_empty() {
            return Ok(0);
        }
        let Some(raw) = self.uart else {
            // No console's driver to read from: input has no transport.
            return Err(Status::Kernel(Error::BadHandle));
        };
        let uart = Handle::<Channel>::borrowed(raw);
        let max = out.len().min(proto_uart::READ_MAX) as u32;
        let mut request = Writer::new();
        ReadRequest { max }.write(&mut request)?;
        let mut reply = [0; MESSAGE_MAX];
        let bytes = Files::call_on(&uart, request.as_bytes(), &mut reply)?;
        let input = ReadReply::read(bytes, max)?.bytes;
        Ok(self.deliver(input, out))
    }

    /// Bytes `input` the console gave: into `out` with CR as LF, and their
    /// echo back to the console (CR as CR LF); the count.
    pub fn deliver(&self, input: &[u8], out: &mut [u8]) -> usize {
        let uart = self.uart.map(Handle::<Channel>::borrowed);
        let mut echo = [0; proto_uart::READ_MAX];
        let mut echoed = 0;
        for (dst, &src) in out.iter_mut().zip(input) {
            *dst = if src == b'\r' { b'\n' } else { src };
        }
        // Data has already been delivered. Echo failure cannot turn this
        // successful read into an error and lose its bytes.
        for &src in input {
            let visible = if src == b'\r' {
                &b"\r\n"[..]
            } else {
                core::slice::from_ref(&src)
            };
            if echoed + visible.len() > echo.len() {
                if console_write(uart.as_deref(), &echo[..echoed]).is_err() {
                    return input.len().min(out.len());
                }
                echoed = 0;
            }
            echo[echoed..echoed + visible.len()].copy_from_slice(visible);
            echoed += visible.len();
        }
        if echoed > 0 {
            let _ = console_write(uart.as_deref(), &echo[..echoed]);
        }
        input.len().min(out.len())
    }
}

/// An exact hidden descriptor returned by a committed paid Open operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedOpen {
    pub fd: u32,
    pub slot: u32,
    pub generation: u64,
    pub random: bool,
}

impl PreparedOpen {
    pub fn marked_fd(self) -> u32 {
        self.fd
            | (self.slot << proto_fs::OPEN_DESCRIPTION_SHIFT)
            | if self.random {
                proto_fs::OPEN_RANDOM
            } else {
                0
            }
    }
}

/// Recovery separates a live paid preparation from its completed descriptor handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenOutcome {
    Active { job: u64, phase: u32 },
    Finished(PreparedOpen),
}

pub struct Files {
    channel: Handle<Channel>,
    uart: Option<Handle<Channel>>,
}

/// The transports of a Files, borrowed: what a request needs outside the
/// lock of the Files' owner (spec 2, 3.4). The owner keeps the Files open
/// while any view is used; a view closes nothing.
#[derive(Clone, Copy)]
pub struct View {
    channel: abi::Handle,
    uart: Option<abi::Handle>,
}

impl View {
    /// The Files of the view, which closes nothing when it goes.
    pub fn files(&self) -> core::mem::ManuallyDrop<Files> {
        core::mem::ManuallyDrop::new(Files {
            channel: Handle::from_raw(self.channel),
            uart: self.uart.map(Handle::from_raw),
        })
    }
}

/// A retained service preparation; cancellation also releases the captured base.
struct Proof<'a> {
    files: &'a Files,
    id: u64,
}
impl Proof<'_> {
    fn send(&self, request: &[u8]) -> Result<crate::sys::Reply, Status> {
        Files::send_on(&self.files.channel, request)
    }
    fn ready(&self) -> Result<(), Status> {
        let mut w = Writer::new();
        Method::ResolveStep.header().write(&mut w)?;
        w.u64(self.id)?;
        loop {
            let reply = self.send(w.as_bytes())?;
            let mut buffer = [0; MESSAGE_MAX];
            match Status::from_code(Reader::new(reply.bytes(&mut buffer)).u32()?) {
                Status::Ok => return Ok(()),
                Status::Unknown(proto_fs::RESOLVING) => {}
                status => return Err(status),
            }
        }
    }
}
impl Drop for Proof<'_> {
    fn drop(&mut self) {
        let mut w = Writer::new();
        if Method::ResolveCancel
            .header()
            .write(&mut w)
            .and_then(|()| w.u64(self.id))
            .is_ok()
        {
            while let Err(Status::Kernel(Error::Interrupted)) = self.send(w.as_bytes()) {}
        }
    }
}

impl Files {
    /// Capture a mutable-open path and its policy before prepaying descriptor resources.
    pub fn open_start(
        &self,
        key: proto_fs::OpenKey,
        path: &[u8],
        flags: u32,
        mode: u32,
        umask: u32,
    ) -> Result<u64, Status> {
        let mut w = Writer::new();
        Method::OpenStart.header().write(&mut w)?;
        w.u32(key.slot)?;
        w.u64(key.generation)?;
        w.u32(0)?;
        w.u64(1)?;
        w.u32(flags)?;
        w.u32(mode)?;
        w.u32(umask)?;
        w.bytes(path)?;
        let reply = Self::send_on(&self.channel, w.as_bytes())?;
        Self::open_start_reply(&reply)
    }
    /// Decode a Start transport reply before acknowledging the resident operation.
    pub fn open_start_reply(reply: &crate::sys::Reply) -> Result<u64, Status> {
        Self::open_reply(reply, 12)?;
        let id = (reply.words[0] >> 32) | ((reply.words[1] as u32 as u64) << 32);
        Self::open_job_id(id)?;
        Ok(id)
    }
    fn open_job_id(id: u64) -> Result<(), Status> {
        if id >> 8 == 0 || id & 255 >= 128 {
            return Err(Status::BadSize);
        }
        Ok(())
    }
    /// Recover the paid job after the original Start reply was unavailable.
    pub fn open_query(&self, key: proto_fs::OpenKey) -> Result<OpenOutcome, Status> {
        let mut w = Writer::new();
        Method::OpenQuery.header().write(&mut w)?;
        w.u32(key.slot)?;
        w.u64(key.generation)?;
        let reply = Self::send_on(&self.channel, w.as_bytes())?;
        Self::open_query_reply(&reply)
    }
    pub fn open_query_reply(reply: &crate::sys::Reply) -> Result<OpenOutcome, Status> {
        let phase = (reply.words[0] >> 32) as u32;
        if phase == 5 {
            Self::open_reply(reply, 32)?;
            if reply.words[1] != 0 || reply.words[2] >> 32 != 0 {
                return Err(Status::BadSize);
            }
            let result = Self::open_description(reply.words[2] as u32, reply.words[3])?;
            return Ok(OpenOutcome::Finished(result));
        }
        Self::open_reply(reply, 16)?;
        if phase > 4 {
            return Err(Status::BadSize);
        }
        Self::open_job_id(reply.words[1])?;
        Ok(OpenOutcome::Active {
            job: reply.words[1],
            phase,
        })
    }
    /// The resident caller captures expected fd/generation before sending this handoff.
    pub fn open_finish(&self, key: proto_fs::OpenKey) -> Result<PreparedOpen, Status> {
        let mut w = Writer::new();
        Method::OpenFinish.header().write(&mut w)?;
        w.u32(key.slot)?;
        w.u64(key.generation)?;
        let reply = Self::send_on(&self.channel, w.as_bytes())?;
        Self::open_commit_reply(&reply)
    }
    /// The numeric-reservation phase performs one request before releasing its defer.
    /// AUTHENTICATING leaves staged refresh to the caller's recovery decision.
    pub fn open_finish_once(&self, key: proto_fs::OpenKey) -> Result<PreparedOpen, Status> {
        let reply = self.open_key_once(Method::OpenFinish, key)?;
        Self::open_commit_reply(&reply)
    }

    pub fn open_query_once(&self, key: proto_fs::OpenKey) -> Result<OpenOutcome, Status> {
        let reply = self.open_key_once(Method::OpenQuery, key)?;
        Self::open_query_reply(&reply)
    }

    pub fn open_cancel_key_once(&self, key: proto_fs::OpenKey) -> Result<(), Status> {
        let reply = self.open_key_once(Method::OpenCancel, key)?;
        Self::open_reply(&reply, 8)
    }

    fn open_key_once(&self, method: Method, key: proto_fs::OpenKey) -> Result<sys::Reply, Status> {
        key.validate().map_err(Status::from_code)?;
        let mut w = Writer::new();
        method.header().write(&mut w)?;
        w.u32(key.slot)?;
        w.u64(key.generation)?;
        sys::send(&self.channel, w.as_bytes()).map_err(Status::Kernel)
    }
    /// Cleanup uses the client key even before its server job ID was decoded.
    pub fn open_cancel_key(&self, key: proto_fs::OpenKey) -> Result<(), Status> {
        let mut w = Writer::new();
        Method::OpenCancel.header().write(&mut w)?;
        w.u32(key.slot)?;
        w.u64(key.generation)?;
        let reply = Self::send_on(&self.channel, w.as_bytes())?;
        Self::open_reply(&reply, 8)
    }
    fn open_reply(reply: &crate::sys::Reply, len: usize) -> Result<(), Status> {
        let code = Self::reply_code(reply)?;
        if !reply.handles.is_empty() {
            return Err(Status::BadSize);
        }
        if code != 0 {
            if reply.len != 8 || reply.words[0] >> 32 != 0 {
                return Err(Status::BadSize);
            }
            return Err(Status::from_code(code));
        }
        if reply.len != len || (len == 8 && reply.words[0] >> 32 != 0) {
            return Err(Status::BadSize);
        }
        Ok(())
    }
    /// Advance one bounded traversal or descriptor-prepayment phase.
    pub fn open_advance(&self, id: u64, prepare: bool) -> Result<bool, Status> {
        let mut w = Writer::new();
        (if prepare {
            Method::OpenPrepare
        } else {
            Method::ResolveStep
        })
        .header()
        .write(&mut w)?;
        w.u64(id)?;
        let reply = Self::send_on(&self.channel, w.as_bytes())?;
        if Self::reply_code(&reply)? == proto_fs::RESOLVING {
            if reply.len != 8 || reply.words[0] >> 32 != 0 || !reply.handles.is_empty() {
                return Err(Status::BadSize);
            }
            return Ok(false);
        }
        Self::open_reply(&reply, 8)?;
        Ok(true)
    }
    /// Retry this same operation ID to recover its exact committed result.
    pub fn open_commit(&self, id: u64) -> Result<PreparedOpen, Status> {
        let mut w = Writer::new();
        Method::OpenCommit.header().write(&mut w)?;
        w.u64(id)?;
        let reply = Self::send_on(&self.channel, w.as_bytes())?;
        Self::open_commit_reply(&reply)
    }
    pub fn open_commit_once(&self, id: u64) -> Result<PreparedOpen, Status> {
        Self::open_job_id(id)?;
        let mut w = Writer::new();
        Method::OpenCommit.header().write(&mut w)?;
        w.u64(id)?;
        let reply = sys::send(&self.channel, w.as_bytes()).map_err(Status::Kernel)?;
        Self::open_commit_reply(&reply)
    }
    /// Successful wire shape must describe a real server descriptor lifetime.
    pub fn open_commit_reply(reply: &crate::sys::Reply) -> Result<PreparedOpen, Status> {
        Self::open_reply(reply, 16)?;
        Self::open_description((reply.words[0] >> 32) as u32, reply.words[1])
    }
    fn open_description(marked_fd: u32, generation: u64) -> Result<PreparedOpen, Status> {
        let fd = marked_fd & proto_fs::OPEN_FD_MASK;
        if marked_fd & !proto_fs::OPEN_RESULT_MASK != 0 || !(3..35).contains(&fd) || generation == 0
        {
            return Err(Status::BadSize);
        }
        Ok(PreparedOpen {
            fd,
            slot: (marked_fd & proto_fs::OPEN_DESCRIPTION_MASK) >> proto_fs::OPEN_DESCRIPTION_SHIFT,
            generation,
            random: marked_fd & proto_fs::OPEN_RANDOM != 0,
        })
    }
    /// Release the exact job and hidden descriptor after a completed or abandoned Open.
    pub fn open_cancel(&self, id: u64) -> Result<(), Status> {
        let mut w = Writer::new();
        Method::ResolveCancel.header().write(&mut w)?;
        w.u64(id)?;
        let reply = Self::send_on(&self.channel, w.as_bytes())?;
        Self::open_reply(&reply, 8)
    }
    /// Even a long reply retains its first 64 bytes in the returned registers.
    /// Reading status needs no message-buffer copy or kilobyte stack frame.
    fn reply_code(reply: &crate::sys::Reply) -> Result<u32, Status> {
        if reply.len < 4 {
            return Err(Status::BadSize);
        }
        Ok(reply.words[0] as u32)
    }
    /// Bind this ordinary session to the actual Process identity capability.
    pub fn bind(&self, identity: &Handle<Channel>) -> Result<(), Status> {
        loop {
            // A refusal consumes outgoing handles. Each no-effect retry owns
            // a fresh duplicate of the actual retained identity capability.
            let copy = sys::handle_duplicate(
                identity,
                abi::Rights::NOTIFY | abi::Rights::DUPLICATE | abi::Rights::TRANSFER,
            )
            .map_err(Status::Kernel)?;
            let reply = sys::send_handles(
                &self.channel,
                &Method::Bind.header().bytes(),
                [copy.erase()],
            )
            .map_err(|e| Status::Kernel(e.error))?;
            if reply.len != proto_wire::HEADER_LEN
                || reply.words[0] >> 32 != 0
                || !reply.handles.is_empty()
            {
                return Err(Status::BadSize);
            }
            match Status::from_code(Self::reply_code(&reply)?) {
                Status::Unknown(proto_fs::AUTHENTICATING) => Self::finish_on(&self.channel)?,
                Status::Unknown(proto_fs::RESOLVING) => return self.finish_binding(),
                status => return Err(status),
            }
        }
    }
    pub fn finish_binding(&self) -> Result<(), Status> {
        Self::finish_on(&self.channel)
    }
    pub fn finish_on(channel: &Handle<Channel>) -> Result<(), Status> {
        let request = Method::FinishBinding.header().bytes();
        loop {
            let reply = match sys::send(channel, &request) {
                Err(Error::Interrupted) => continue,
                result => result.map_err(Status::Kernel)?,
            };
            if reply.len != proto_wire::HEADER_LEN
                || reply.words[0] >> 32 != 0
                || !reply.handles.is_empty()
            {
                return Err(Status::BadSize);
            }
            match Status::from_code(Self::reply_code(&reply)?) {
                Status::Ok => return Ok(()),
                Status::Unknown(proto_fs::RESOLVING) => {}
                status => return Err(status),
            }
        }
    }
    /// AUTHENTICATING guarantees no file effect. Complete the retained
    /// refresh before retrying the exact original handle-free request.
    pub fn send_on(channel: &Handle<Channel>, request: &[u8]) -> Result<crate::sys::Reply, Status> {
        loop {
            let reply = sys::send(channel, request).map_err(Status::Kernel)?;
            if Self::reply_code(&reply)? != proto_fs::AUTHENTICATING {
                return Ok(reply);
            }
            if reply.len != proto_wire::HEADER_LEN
                || reply.words[0] >> 32 != 0
                || !reply.handles.is_empty()
            {
                return Err(Status::BadSize);
            }
            Self::finish_on(channel)?;
        }
    }
    pub fn clone_on(channel: &Handle<Channel>, request: &[u8]) -> Result<Handle<Channel>, Status> {
        let mut reply = Self::send_on(channel, request)?;
        match Status::from_code(Self::reply_code(&reply)?) {
            Status::Ok if reply.handles.len() == 1 => reply.handles.take(0).map_err(Status::Kernel),
            Status::Ok => Err(Status::BadSize),
            status => Err(status),
        }
    }
    /// Returned handles retain the exact offered object and its original rights.
    pub fn verify_on(
        channel: &Handle<Channel>,
        request: &[u8],
        mut offered: Handle<Channel>,
    ) -> Result<Handle<Channel>, Status> {
        loop {
            let mut reply = sys::send_handles(channel, request, [offered.erase()])
                .map_err(|refused| Status::Kernel(refused.error))?;
            let status = Self::reply_code(&reply)?;
            if status != 0 && status != proto_fs::AUTHENTICATING {
                return Err(Status::from_code(status));
            }
            if reply.len != 4
                || reply.handles.len() != 1
                || !reply.handles.info(0).is_some_and(|(kind, rights)| {
                    kind == abi::ObjectKind::Channel
                        && rights.contains(abi::Rights::SEND | abi::Rights::TRANSFER)
                })
            {
                return Err(Status::BadSize);
            }
            let returned = reply.handles.take::<Channel>(0).map_err(Status::Kernel)?;
            if status == 0 {
                return Ok(returned);
            }
            offered = returned;
            Self::finish_on(channel)?;
        }
    }

    fn prepare<'a>(&'a self, path: &[u8]) -> Result<Proof<'a>, Status> {
        if path.is_empty() {
            return Err(Status::Unknown(proto_fs::NO_ENTRY));
        }
        if path.len() > proto_fs::MAX_PATH {
            return Err(Status::Unknown(proto_fs::NAME_TOO_LONG));
        }
        if path.contains(&0) {
            return Err(Status::BadSize);
        }
        let mut w = Writer::new();
        Method::ResolveStart.header().write(&mut w)?;
        w.u32(0)?;
        w.u64(1)?;
        w.u32(0)?;
        w.u32(1)?;
        w.bytes(path)?;
        let reply = Self::send_on(&self.channel, w.as_bytes())?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut r = Reader::new(reply.bytes(&mut buffer));
        let status = Status::from_code(r.u32()?);
        if status != Status::Ok {
            return Err(status);
        }
        let proof = Proof {
            files: self,
            id: r.u64()?,
        };
        r.finish()?;
        proof.ready()?;
        Ok(proof)
    }
    fn path_call<'a>(
        &self,
        method: Method,
        path: &[u8],
        prefix: Option<u32>,
        buffer: &'a mut [u8; MESSAGE_MAX],
    ) -> Result<&'a [u8], Status> {
        let proof = self.prepare(path)?;
        let mut w = Writer::new();
        method.header().write(&mut w)?;
        if let Some(prefix) = prefix {
            w.u32(prefix)?;
        }
        w.u64(proof.id)?;
        loop {
            let reply = Self::send_on(&self.channel, w.as_bytes())?;
            let status = Status::from_code(Reader::new(reply.bytes(buffer)).u32()?);
            if status == Status::Unknown(proto_fs::STALE_PROOF) {
                proof.ready()?;
                continue;
            }
            return if status == Status::Ok {
                Ok(reply.bytes(buffer))
            } else {
                Err(status)
            };
        }
    }
    /// A cold loader root returns exact incoming channels before paid preparation.
    /// Every retry transfers the newly returned objects in their original order.
    pub fn bind_pending_on(
        root: &Handle<Channel>,
        require_fds: bool,
        mut offered: Option<Handle<Channel>>,
        mut identity: Handle<Channel>,
    ) -> Result<Handle<Channel>, Status> {
        if require_fds && offered.is_none() {
            return Err(Status::BadSize);
        }
        let count = 1 + usize::from(offered.is_some());
        let mut request = Writer::new();
        Method::BindPending.header().write(&mut request)?;
        request.u32(u32::from(require_fds))?;
        loop {
            let mut outgoing = crate::handle::Outgoing::new();
            if let Some(channel) = offered.take() {
                outgoing
                    .push(channel.erase())
                    .map_err(|_| Status::BadSize)?;
            }
            outgoing
                .push(identity.erase())
                .map_err(|_| Status::BadSize)?;
            let mut reply = sys::send_handles(root, request.as_bytes(), outgoing)
                .map_err(|refused| Status::Kernel(refused.error))?;
            let code = Self::reply_code(&reply)?;
            if code == proto_fs::AUTHENTICATING {
                if reply.len != proto_wire::HEADER_LEN
                    || reply.words[0] >> 32 != 0
                    || reply.handles.len() != count
                    || !reply.handles.info(count - 1).is_some_and(|(kind, rights)| {
                        kind == abi::ObjectKind::Channel
                            && rights.contains(
                                abi::Rights::NOTIFY
                                    | abi::Rights::DUPLICATE
                                    | abi::Rights::TRANSFER,
                            )
                    })
                    || (count == 2
                        && !reply.handles.info(0).is_some_and(|(kind, rights)| {
                            kind == abi::ObjectKind::Channel
                                && rights.contains(abi::Rights::SEND | abi::Rights::TRANSFER)
                        }))
                {
                    return Err(Status::BadSize);
                }
                offered = if count == 2 {
                    Some(reply.handles.take::<Channel>(0).map_err(Status::Kernel)?)
                } else {
                    None
                };
                identity = reply
                    .handles
                    .take::<Channel>(count - 1)
                    .map_err(Status::Kernel)?;
                continue;
            }
            if code != 0 {
                if reply.len != proto_wire::HEADER_LEN
                    || reply.words[0] >> 32 != 0
                    || !reply.handles.is_empty()
                {
                    return Err(Status::BadSize);
                }
                return Err(Status::from_code(code));
            }
            if reply.len != 4
                || reply.handles.len() != 1
                || !reply.handles.info(0).is_some_and(|(kind, rights)| {
                    kind == abi::ObjectKind::Channel
                        && rights.contains(abi::Rights::SEND | abi::Rights::TRANSFER)
                })
            {
                return Err(Status::BadSize);
            }
            return reply.handles.take::<Channel>(0).map_err(Status::Kernel);
        }
    }
    /// A loader's image, after its authentic pending identity resolves each component.
    pub fn open_exec(
        &self,
        path: &[u8],
        identity: &Handle<Channel>,
    ) -> Result<Handle<Channel>, Status> {
        let identity = sys::handle_duplicate(
            identity,
            abi::Rights::NOTIFY | abi::Rights::DUPLICATE | abi::Rights::TRANSFER,
        )
        .map_err(Status::Kernel)?;
        let session = Self::bind_pending_on(&self.channel, false, None, identity)?;
        let prepared = Self::from_sessions(session, None);
        prepared.finish_binding()?;
        prepared.open_exec_bound(path)
    }
    fn open_exec_bound(&self, path: &[u8]) -> Result<Handle<Channel>, Status> {
        let proof = self.prepare(path)?;
        let mut w = Writer::new();
        Method::OpenExec.header().write(&mut w)?;
        w.u64(proof.id)?;
        loop {
            let mut reply = proof.send(w.as_bytes())?;
            let code = Self::reply_code(&reply)?;
            if code == 0 {
                if reply.len != 4
                    || reply.handles.len() != 1
                    || !reply.handles.info(0).is_some_and(|(kind, rights)| {
                        kind == abi::ObjectKind::Channel
                            && rights.contains(abi::Rights::SEND | abi::Rights::TRANSFER)
                    })
                {
                    return Err(Status::BadSize);
                }
                return reply.handles.take::<Channel>(0).map_err(Status::Kernel);
            }
            if reply.len != proto_wire::HEADER_LEN
                || reply.words[0] >> 32 != 0
                || !reply.handles.is_empty()
            {
                return Err(Status::BadSize);
            }
            if code == proto_fs::RESOLVING {
                continue;
            }
            if code == proto_fs::STALE_PROOF {
                proof.ready()?;
                continue;
            }
            return Err(Status::from_code(code));
        }
    }

    pub fn connect(parent: &Handle<Channel>) -> Result<Self, Status> {
        Ok(Self {
            channel: service::connect(parent, "ramfs")?,
            uart: None,
        })
    }

    pub fn connect_with_uart(parent: &Handle<Channel>) -> Result<Self, Status> {
        Ok(Self {
            channel: service::connect(parent, "ramfs")?,
            uart: Some(service::connect(parent, "uart")?),
        })
    }

    /// Files through sessions the program was given: its own session with
    /// the RAM file service and, for input, with the console's driver (a
    /// POSIX program its loader started, spec 2, 3.2).
    pub fn from_sessions(channel: Handle<Channel>, uart: Option<Handle<Channel>>) -> Self {
        Self { channel, uart }
    }

    /// A borrowed view of the transports (`View`).
    pub fn view(&self) -> View {
        View {
            channel: self.channel.raw(),
            uart: self.uart.as_ref().map(Handle::raw),
        }
    }

    /// The session with the RAM file service and the console's driver's.
    pub fn sessions(&self) -> (&Handle<Channel>, Option<&Handle<Channel>>) {
        (&self.channel, self.uart.as_ref())
    }

    /// Snapshot the input endpoint; this Files retains its UART session.
    pub fn input(&self) -> Input {
        Input {
            uart: self.uart.as_ref().map(Handle::raw),
        }
    }

    pub fn has_uart(&self) -> bool {
        self.uart.is_some()
    }

    fn call<'a>(
        &self,
        request: &[u8],
        buffer: &'a mut [u8; MESSAGE_MAX],
    ) -> Result<&'a [u8], Status> {
        let reply = Self::send_on(&self.channel, request)?;
        let bytes = reply.bytes(buffer);
        match Status::from_code(Reader::new(bytes).u32()?) {
            Status::Ok => Ok(bytes),
            status => Err(status),
        }
    }

    fn call_on<'a>(
        channel: &Handle<Channel>,
        request: &[u8],
        buffer: &'a mut [u8; MESSAGE_MAX],
    ) -> Result<&'a [u8], Status> {
        let reply = sys::send(channel, request).map_err(Status::Kernel)?;
        let bytes = reply.bytes(buffer);
        match Status::from_code(Reader::new(bytes).u32()?) {
            Status::Ok => Ok(bytes),
            status => Err(status),
        }
    }

    fn number(&self, method: Method, fd: u32, second: Option<u32>) -> Result<u32, Status> {
        let mut w = Writer::new();
        method.header().write(&mut w)?;
        w.u32(fd)?;
        if let Some(second) = second {
            w.u32(second)?;
        }
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(w.as_bytes(), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let value = r.u32()?;
        r.finish()?;
        Ok(value)
    }

    pub fn open(&self, path: &str, flags: u32) -> Result<u32, Status> {
        self.open_marked(path, flags).map(|(fd, _)| fd)
    }

    /// OPEN with the mark of the reply: the descriptor, and whether the
    /// file is a random device, whose reads the caller serves itself.
    pub fn open_marked(&self, path: &str, flags: u32) -> Result<(u32, bool), Status> {
        valid_path(path.as_bytes())?;
        self.open_marked_bytes(path.as_bytes(), flags)
    }
    pub fn open_marked_bytes(&self, path: &[u8], flags: u32) -> Result<(u32, bool), Status> {
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.path_call(Method::Open, path, Some(flags), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let fd = r.u32()?;
        let random = match r.u32() {
            Ok(proto_fs::RANDOM_DEVICE) => true,
            Ok(_) => return Err(Status::BadSize),
            Err(_) => false,
        };
        r.finish()?;
        Ok((fd, random))
    }

    pub fn read(&self, fd: u32, out: &mut [u8]) -> Result<usize, Status> {
        if fd == 0 {
            return self.input().read(out);
        }
        let mut w = Writer::new();
        Method::Read.header().write(&mut w)?;
        w.u32(fd)?;
        w.u32(out.len().min(MAX_READ) as u32)?;
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(w.as_bytes(), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let n = r.u32()? as usize;
        if n > out.len() || n > MAX_READ {
            return Err(Status::BadSize);
        }
        out[..n].copy_from_slice(r.bytes(n)?);
        r.finish()?;
        Ok(n)
    }

    /// Reads from `offset` of the file; the position of the description
    /// stays (READ_AT). Only a file of the RAM service reads so.
    pub fn read_at(&self, fd: u32, offset: u64, out: &mut [u8]) -> Result<usize, Status> {
        let mut w = Writer::new();
        Method::ReadAt.header().write(&mut w)?;
        w.u32(fd)?;
        w.u64(offset)?;
        w.u32(out.len().min(MAX_READ) as u32)?;
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(w.as_bytes(), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let n = r.u32()? as usize;
        if n > out.len() || n > MAX_READ {
            return Err(Status::BadSize);
        }
        out[..n].copy_from_slice(r.bytes(n)?);
        r.finish()?;
        Ok(n)
    }

    /// WRITE_AT: `bytes` at `offset` of the file of `fd`, the open
    /// description's position as it was; the count written.
    pub fn write_at(&self, fd: u32, offset: u64, bytes: &[u8]) -> Result<usize, Status> {
        let bytes = &bytes[..bytes.len().min(MAX_WRITE - 8)];
        let mut w = Writer::new();
        Method::WriteAt.header().write(&mut w)?;
        w.u32(fd)?;
        w.u64(offset)?;
        w.bytes(bytes)?;
        let mut reply = [0; MESSAGE_MAX];
        let got = self.call(w.as_bytes(), &mut reply)?;
        let mut r = Reader::new(got);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let n = r.u32()? as usize;
        r.finish()?;
        if n > bytes.len() {
            return Err(Status::BadSize);
        }
        Ok(n)
    }

    pub fn write(&self, fd: u32, bytes: &[u8]) -> Result<usize, Status> {
        if bytes.is_empty() && (fd == 1 || fd == 2) {
            return Ok(0);
        }
        if fd == 1 || fd == 2 {
            return console_write(self.uart.as_ref(), bytes);
        }
        let bytes = &bytes[..bytes.len().min(MAX_WRITE)];
        let mut w = Writer::new();
        Method::Write.header().write(&mut w)?;
        w.u32(fd)?;
        w.bytes(bytes)?;
        Ok(self.number_from_written(w.as_bytes())? as usize)
    }

    fn number_from_written(&self, request: &[u8]) -> Result<u32, Status> {
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(request, &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let n = r.u32()?;
        r.finish()?;
        Ok(n)
    }

    pub fn lseek(&self, fd: u32, offset: u32) -> Result<u32, Status> {
        self.number(Method::Seek, fd, Some(offset))
    }

    /// Signed, 64-bit seek with an origin. The service owns the offset.
    pub fn seek_from(
        &self,
        fd: u32,
        offset: i64,
        origin: proto_fs::SeekFrom,
    ) -> Result<i64, Status> {
        let mut w = Writer::new();
        Method::SeekFrom.header().write(&mut w)?;
        w.u32(fd)?;
        w.u64(offset as u64)?;
        w.u32(origin as u32)?;
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(w.as_bytes(), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let offset = i64::try_from(r.u64()?).map_err(|_| Status::BadSize)?;
        r.finish()?;
        Ok(offset)
    }

    pub fn fstat_size(&self, fd: u32) -> Result<u32, Status> {
        self.number(Method::Stat, fd, None)
    }

    /// Read one directory entry by index. Kind 1 is a directory, 2 a file.
    pub fn read_dir(
        &self,
        path: &str,
        index: u32,
        out: &mut [u8],
    ) -> Result<Option<(usize, u32)>, Status> {
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.path_call(Method::ReadDir, path.as_bytes(), Some(index), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let kind = r.u32()?;
        let name = r.bytes(r.left())?;
        if kind == 0 {
            return if name.is_empty() {
                Ok(None)
            } else {
                Err(Status::BadSize)
            };
        }
        if !(1..=2).contains(&kind) || name.is_empty() || name.len() > out.len() {
            return Err(Status::BadSize);
        }
        out[..name.len()].copy_from_slice(name);
        Ok(Some((name.len(), kind)))
    }

    /// Read one entry and advance the shared service-owned directory offset.
    pub fn read_dir_fd(
        &self,
        fd: u32,
        out: &mut [u8],
    ) -> Result<Option<(usize, u32, u64)>, Status> {
        let mut w = Writer::new();
        Method::ReadDirFd.header().write(&mut w)?;
        w.u32(fd)?;
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(w.as_bytes(), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let Some(entry) = proto_fs::DirectoryEntry::read(&mut r)? else {
            return Ok(None);
        };
        if entry.name.len() > out.len() {
            return Err(Status::BadSize);
        }
        out[..entry.name.len()].copy_from_slice(entry.name);
        Ok(Some((entry.name.len(), entry.kind, entry.inode)))
    }

    pub fn lookup(&self, path: &str) -> Result<Metadata, Status> {
        valid_path(path.as_bytes())?;
        self.lookup_bytes(path.as_bytes())
    }
    pub fn lookup_bytes(&self, path: &[u8]) -> Result<Metadata, Status> {
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.path_call(Method::Lookup, path, None, &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let metadata = Metadata {
            kind: r.u32()?,
            size: r.u32()?,
        };
        if !(1..=2).contains(&metadata.kind) {
            return Err(Status::BadSize);
        }
        r.finish()?;
        Ok(metadata)
    }

    pub fn node_information(&self, path: &str) -> Result<proto_fs::NodeInfo, Status> {
        self.node_information_bytes(path.as_bytes())
    }
    pub fn node_information_bytes(&self, path: &[u8]) -> Result<proto_fs::NodeInfo, Status> {
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.path_call(Method::InfoPath, path, None, &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let info = proto_fs::NodeInfo::read(&mut r)?;
        r.finish()?;
        Ok(info)
    }

    pub fn descriptor_information(&self, fd: u32) -> Result<proto_fs::NodeInfo, Status> {
        let mut w = Writer::new();
        Method::InfoFd.header().write(&mut w)?;
        w.u32(fd)?;
        self.information(w.as_bytes())
    }

    fn information(&self, request: &[u8]) -> Result<proto_fs::NodeInfo, Status> {
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(request, &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let info = proto_fs::NodeInfo::read(&mut r)?;
        r.finish()?;
        Ok(info)
    }

    pub fn close(&self, fd: u32) -> Result<(), Status> {
        let mut w = Writer::new();
        Method::Close.header().write(&mut w)?;
        w.u32(fd)?;
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(w.as_bytes(), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        r.finish()
    }
}

fn console_write(uart: Option<&Handle<Channel>>, bytes: &[u8]) -> Result<usize, Status> {
    if let Some(uart) = uart {
        let chunk = &bytes[..bytes.len().min(proto_uart::WRITE_MAX)];
        let mut request = Writer::new();
        WriteRequest { bytes: chunk }.write(&mut request)?;
        let mut reply = [0; MESSAGE_MAX];
        let response = Files::call_on(uart, request.as_bytes(), &mut reply)?;
        return Ok(WriteReply::read(response)?.written as usize);
    }
    console::write(bytes).map_err(Status::Kernel)?;
    Ok(bytes.len())
}
