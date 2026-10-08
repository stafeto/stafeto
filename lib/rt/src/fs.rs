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

/// Startup imports capture the exact existing descriptor and its access policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapturedDescription {
    pub held: PreparedOpen,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseOutcome {
    Closed,
    AlreadyGone,
}

/// Recovery separates a live paid preparation from its completed descriptor handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenOutcome {
    Active { job: u64, phase: u32 },
    Finished(PreparedOpen),
}

/// A canonical first final request retained its preparation without a file effect.
pub struct OpenNoEffect {
    key: proto_fs::OpenKey,
    session: abi::Handle,
    code: u32,
}

impl OpenNoEffect {
    pub fn matches_request(&self, key: proto_fs::OpenKey, session: abi::Handle) -> bool {
        self.key == key && self.session == session
    }

    pub fn status(&self) -> Status {
        Status::from_code(self.code)
    }
}

/// One native Finish request has no automatic binding or preparation retry.
pub enum OpenFinalizeAttempt {
    Finished(PreparedOpen),
    Deferred(OpenNoEffect),
    Rejected(Status),
    Ambiguous(Status),
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

/// Header and existing descriptor requirement for the pending binding.
fn pending_binding_request(require_fds: bool) -> [u8; 12] {
    let mut request = [0; 12];
    request[..8].copy_from_slice(&Method::BindPending.header().bytes());
    request[8..].copy_from_slice(&u32::from(require_fds).to_le_bytes());
    request
}

/// Header and exact paid job for the resolver and image handoff requests.
fn job_request(method: Method, job: u64) -> [u8; 16] {
    let mut request = [0; 16];
    request[..8].copy_from_slice(&method.header().bytes());
    request[8..].copy_from_slice(&job.to_le_bytes());
    request
}

/// ResolveStep returns only the canonical status envelope, with no capabilities.
fn proof_ready_status(len: usize, first: u64, handles: usize) -> Result<Status, Status> {
    if len != proto_wire::HEADER_LEN || first >> 32 != 0 || handles != 0 {
        return Err(Status::BadSize);
    }
    Ok(Status::from_code(first as u32))
}

/// Fill the existing resolver prefix and path in the caller's bounded request.
fn resolve_start_request(
    request: &mut [u8; 28 + proto_fs::MAX_PATH],
    path: &[u8],
) -> Result<usize, Status> {
    if path.is_empty() {
        return Err(Status::Unknown(proto_fs::NO_ENTRY));
    }
    if path.len() > proto_fs::MAX_PATH {
        return Err(Status::Unknown(proto_fs::NAME_TOO_LONG));
    }
    if path.contains(&0) {
        return Err(Status::BadSize);
    }
    request[..28].fill(0);
    request[..8].copy_from_slice(&Method::ResolveStart.header().bytes());
    request[12..20].copy_from_slice(&1_u64.to_le_bytes());
    request[24..28].copy_from_slice(&1_u32.to_le_bytes());
    request[28..28 + path.len()].copy_from_slice(path);
    Ok(28 + path.len())
}

/// ResolveStart has a twelve-byte job reply or a canonical status-only refusal.
fn resolve_start_job(len: usize, words: &[u64; 8], handles: usize) -> Result<u64, Status> {
    if len < 4 || handles != 0 {
        return Err(Status::BadSize);
    }
    let status = Status::from_code(words[0] as u32);
    if status != Status::Ok {
        return if len == proto_wire::HEADER_LEN && words[0] >> 32 == 0 {
            Err(status)
        } else {
            Err(Status::BadSize)
        };
    }
    if len != 12 {
        return Err(Status::BadSize);
    }
    let mut bytes = [0; 12];
    bytes[..8].copy_from_slice(&words[0].to_le_bytes());
    bytes[8..].copy_from_slice(&(words[1] as u32).to_le_bytes());
    let mut reader = Reader::new(&bytes);
    reader.u32()?;
    let job = reader.u64()?;
    reader.finish()?;
    if job == 0 {
        return Err(Status::BadSize);
    }
    Ok(job)
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
        let request = job_request(Method::ResolveStep, self.id);
        loop {
            let reply = self.send(&request)?;
            match proof_ready_status(reply.len, reply.words[0], reply.handles.len())? {
                Status::Ok => return Ok(()),
                Status::Unknown(proto_fs::RESOLVING) => {}
                status => return Err(status),
            }
        }
    }
}
impl Drop for Proof<'_> {
    fn drop(&mut self) {
        let request = job_request(Method::ResolveCancel, self.id);
        while let Err(Status::Kernel(Error::Interrupted)) = self.send(&request) {}
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
    /// Bind precedes this read-only normalization; imports publish after exact capture.
    pub fn capture_description(&self, fd: u32) -> Result<CapturedDescription, Status> {
        let mut w = Writer::new();
        Method::CaptureDescription.header().write(&mut w)?;
        w.u32(fd)?;
        let reply = Self::send_on(&self.channel, w.as_bytes())?;
        Self::capture_description_reply(&reply)
    }

    pub fn capture_description_reply(reply: &sys::Reply) -> Result<CapturedDescription, Status> {
        Self::open_reply(reply, 20)?;
        let held = Self::open_description((reply.words[0] >> 32) as u32, reply.words[1])?;
        let flags = reply.words[2] as u32;
        if flags & !(3 | proto_fs::APPEND) != 0 || flags & 3 == 3 {
            return Err(Status::BadSize);
        }
        Ok(CapturedDescription { held, flags })
    }

    /// Canonical exact cleanup preserves a replacement at the same numeric fd.
    pub fn close_exact(&self, held: PreparedOpen) -> Result<CloseOutcome, Status> {
        let mut w = Writer::new();
        Method::CloseExact.header().write(&mut w)?;
        w.u32(Self::exact_description_word(held)?)?;
        w.u64(held.generation)?;
        let reply = Self::send_on(&self.channel, w.as_bytes())?;
        Self::close_exact_reply(&reply)
    }

    pub fn close_exact_reply(reply: &sys::Reply) -> Result<CloseOutcome, Status> {
        if Self::reply_code(reply)? != 0 {
            Self::open_reply(reply, 8)?;
        }
        if reply.len != 8 || !reply.handles.is_empty() {
            return Err(Status::BadSize);
        }
        match reply.words[0] >> 32 {
            0 => Ok(CloseOutcome::Closed),
            1 => Ok(CloseOutcome::AlreadyGone),
            _ => Err(Status::BadSize),
        }
    }

    fn exact_description_word(held: PreparedOpen) -> Result<u32, Status> {
        if !(3..35).contains(&held.fd) || held.slot >= 128 || held.generation == 0 {
            return Err(Status::BadSize);
        }
        Ok(held.fd | (held.slot << proto_fs::OPEN_DESCRIPTION_SHIFT))
    }

    /// Whole-list token validation precedes every shared reference and CWD effect.
    pub fn clone_exact_on(
        channel: &Handle<Channel>,
        descriptions: &[PreparedOpen],
    ) -> Result<Handle<Channel>, Status> {
        if descriptions.len() > 32 {
            return Err(Status::BadSize);
        }
        let mut w = Writer::new();
        Method::CloneExact.header().write(&mut w)?;
        w.u32(descriptions.len() as u32)?;
        for held in descriptions {
            w.u32(Self::exact_description_word(*held)?)?;
            w.u64(held.generation)?;
        }
        let mut reply = Self::send_on(channel, w.as_bytes())?;
        let code = Self::reply_code(&reply)?;
        if code != 0 {
            return match Self::open_reply(&reply, 4) {
                Err(error) => Err(error),
                Ok(()) => Err(Status::BadSize),
            };
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
        reply.handles.take(0).map_err(Status::Kernel)
    }

    /// The numeric-reservation phase performs one request before releasing its defer.
    /// AUTHENTICATING leaves staged refresh to the caller's recovery decision.
    pub fn open_finish_once(&self, key: proto_fs::OpenKey) -> Result<PreparedOpen, Status> {
        let reply = self.open_key_once(Method::OpenFinish, key)?;
        Self::open_commit_reply(&reply)
    }

    /// Finalize a preparation atomically; an uncertain reply requires exact Query recovery.
    pub fn open_finalize_once(&self, key: proto_fs::OpenKey) -> OpenFinalizeAttempt {
        match self.open_key_once(Method::OpenFinish, key) {
            Ok(reply) => Self::open_finalize_reply(&reply, key, self.channel.raw()),
            Err(error) => OpenFinalizeAttempt::Ambiguous(error),
        }
    }

    fn open_finalize_reply(
        reply: &sys::Reply,
        key: proto_fs::OpenKey,
        session: abi::Handle,
    ) -> OpenFinalizeAttempt {
        let code = match Self::reply_code(reply) {
            Ok(code) => code,
            Err(error) => return OpenFinalizeAttempt::Ambiguous(error),
        };
        if code == 0 {
            return match Self::open_commit_reply(reply) {
                Ok(held) => OpenFinalizeAttempt::Finished(held),
                Err(error) => OpenFinalizeAttempt::Ambiguous(error),
            };
        }
        if reply.len != 8 || reply.words[0] >> 32 != 0 || !reply.handles.is_empty() {
            return OpenFinalizeAttempt::Ambiguous(Status::BadSize);
        }
        if matches!(code, proto_fs::AUTHENTICATING | proto_fs::TIME_DEFERRED) {
            OpenFinalizeAttempt::Deferred(OpenNoEffect { key, session, code })
        } else {
            OpenFinalizeAttempt::Rejected(Status::from_code(code))
        }
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
        let mut request = [0; 28 + proto_fs::MAX_PATH];
        let len = resolve_start_request(&mut request, path)?;
        let reply = Self::send_on(&self.channel, &request[..len])?;
        let proof = Proof {
            files: self,
            id: resolve_start_job(reply.len, &reply.words, reply.handles.len())?,
        };
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
        let request = pending_binding_request(require_fds);
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
            let mut reply = sys::send_handles(root, &request, outgoing)
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
    /// Resolve an executable using this authenticated bound session.
    /// The service requires a genuine Pending loader binding for the image handoff.
    pub fn open_exec_bound(&self, path: &[u8]) -> Result<Handle<Channel>, Status> {
        let proof = self.prepare(path)?;
        let request = job_request(Method::OpenExec, proof.id);
        loop {
            let mut reply = proof.send(&request)?;
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

impl Files {
    /// One native request. Refresh and recovery remain outside the final signal defer.
    pub fn data_start_once(
        &self,
        args: proto_fs::DataStart,
    ) -> Result<(proto_fs::DataPhase, u64), Status> {
        let mut request = Writer::new();
        Method::DataStart.header().write(&mut request)?;
        args.write(&mut request)?;
        let reply = sys::send(&self.channel, request.as_bytes()).map_err(Status::Kernel)?;
        let mut buffer = [0; MESSAGE_MAX];
        proto_fs::data_start_reply(reply.bytes(&mut buffer), reply.handles.len())
    }

    pub fn data_feed_once(&self, job: u64, offset: u32, bytes: &[u8]) -> Result<(), Status> {
        Self::open_job_id(job)?;
        if bytes.len() > proto_fs::FEED_MAX {
            return Err(Status::BadSize);
        }
        let mut request = Writer::new();
        Method::DataFeed.header().write(&mut request)?;
        request.u64(job)?;
        request.u32(offset)?;
        request.bytes(bytes)?;
        let reply = sys::send(&self.channel, request.as_bytes()).map_err(Status::Kernel)?;
        let mut buffer = [0; MESSAGE_MAX];
        proto_fs::data_progress_reply(reply.bytes(&mut buffer), reply.handles.len())
    }

    pub fn data_step_once(&self, job: u64) -> Result<(), Status> {
        let reply = self.data_job_once(Method::DataStep, job)?;
        let mut buffer = [0; MESSAGE_MAX];
        proto_fs::data_progress_reply(reply.bytes(&mut buffer), reply.handles.len())
    }

    pub fn data_commit_once(
        &self,
        job: u64,
        args: proto_fs::DataStart,
    ) -> Result<proto_fs::DataOutcome, Status> {
        let reply = self.data_job_once(Method::DataCommit, job)?;
        let mut buffer = [0; MESSAGE_MAX];
        let outcome =
            proto_fs::DataOutcome::read(reply.bytes(&mut buffer), reply.handles.len(), args)?;
        if outcome.job != job {
            return Err(Status::BadSize);
        }
        Ok(outcome)
    }

    pub fn data_query_once(
        &self,
        args: proto_fs::DataStart,
    ) -> Result<proto_fs::DataOutcome, Status> {
        let reply = self.open_key_once(Method::DataQuery, args.key)?;
        let mut buffer = [0; MESSAGE_MAX];
        proto_fs::DataOutcome::read(reply.bytes(&mut buffer), reply.handles.len(), args)
    }

    pub fn data_cancel_once(&self, key: proto_fs::OpenKey) -> Result<(), Status> {
        self.data_cleanup_once(Method::DataCancel, key)
    }

    pub fn data_ack_once(&self, key: proto_fs::OpenKey) -> Result<(), Status> {
        self.data_cleanup_once(Method::DataAck, key)
    }

    pub fn data_read_result_once(
        &self,
        key: proto_fs::OpenKey,
        count: usize,
        out: &mut [u8],
    ) -> Result<usize, Status> {
        if count > out.len() || count > MAX_READ {
            return Err(Status::BadSize);
        }
        let reply = self.open_key_once(Method::DataReadResult, key)?;
        let mut buffer = [0; MESSAGE_MAX];
        let bytes =
            proto_fs::data_read_reply(reply.bytes(&mut buffer), reply.handles.len(), count)?;
        out[..count].copy_from_slice(bytes);
        Ok(count)
    }

    fn data_job_once(&self, method: Method, job: u64) -> Result<sys::Reply, Status> {
        Self::open_job_id(job)?;
        let mut request = Writer::new();
        method.header().write(&mut request)?;
        request.u64(job)?;
        sys::send(&self.channel, request.as_bytes()).map_err(Status::Kernel)
    }

    fn data_cleanup_once(&self, method: Method, key: proto_fs::OpenKey) -> Result<(), Status> {
        let reply = self.open_key_once(method, key)?;
        let mut buffer = [0; MESSAGE_MAX];
        proto_fs::data_progress_reply(reply.bytes(&mut buffer), reply.handles.len())
    }
}

#[cfg(test)]
mod finalize_reply_tests {
    use super::*;
    fn key() -> proto_fs::OpenKey {
        proto_fs::OpenKey {
            slot: 2,
            generation: 9,
        }
    }
    fn session() -> abi::Handle {
        abi::Handle::new(7, 9)
    }
    fn reply(len: usize, first: u64, second: u64) -> sys::Reply {
        let mut words = [0; 8];
        words[0] = first;
        words[1] = second;
        sys::Reply {
            len,
            words,
            handles: crate::handle::Incoming::none(),
        }
    }
    #[test]
    fn canonical_no_effect_receipt_binds_request_and_transport_generations() {
        for code in [proto_fs::AUTHENTICATING, proto_fs::TIME_DEFERRED] {
            let r = reply(8, code as u64, 0);
            let OpenFinalizeAttempt::Deferred(receipt) =
                Files::open_finalize_reply(&r, key(), session())
            else {
                panic!("canonical receipt");
            };
            assert_eq!(receipt.status(), Status::Unknown(code));
            assert!(receipt.matches_request(key(), session()));
            assert!(!receipt.matches_request(
                proto_fs::OpenKey {
                    slot: 2,
                    generation: 10
                },
                session()
            ));
            assert!(!receipt.matches_request(key(), abi::Handle::new(7, 10)));
        }
    }
    #[test]
    fn malformed_no_effect_envelopes_remain_ambiguous() {
        for code in [proto_fs::AUTHENTICATING, proto_fs::TIME_DEFERRED] {
            for len in [0, 4, 7, 9, 12, 16, 32] {
                assert!(matches!(
                    Files::open_finalize_reply(&reply(len, code as u64, 0), key(), session()),
                    OpenFinalizeAttempt::Ambiguous(_)
                ));
            }
            assert!(matches!(
                Files::open_finalize_reply(&reply(8, code as u64 | 1 << 32, 0), key(), session()),
                OpenFinalizeAttempt::Ambiguous(_)
            ));
        }
    }
    #[test]
    fn completed_finalization_requires_the_exact_descriptor_envelope() {
        let held = PreparedOpen {
            fd: 3,
            slot: 127,
            generation: 11,
            random: true,
        };
        let first = (held.marked_fd() as u64) << 32;
        assert!(
            matches!(Files::open_finalize_reply(&reply(16, first, held.generation), key(), session()), OpenFinalizeAttempt::Finished(found) if found == held)
        );
        for len in [8, 15, 17, 32] {
            assert!(matches!(
                Files::open_finalize_reply(&reply(len, first, held.generation), key(), session()),
                OpenFinalizeAttempt::Ambiguous(_)
            ));
        }
        for (packed, generation) in [(first, 0), (35u64 << 32, 1), (first | 1 << 60, 1)] {
            assert!(matches!(
                Files::open_finalize_reply(&reply(16, packed, generation), key(), session()),
                OpenFinalizeAttempt::Ambiguous(_)
            ));
        }
    }
    #[test]
    fn canonical_terminal_refusal_creates_no_prepared_receipt() {
        assert!(matches!(
            Files::open_finalize_reply(
                &reply(8, proto_fs::ACCESS_DENIED as u64, 0),
                key(),
                session()
            ),
            OpenFinalizeAttempt::Rejected(Status::Unknown(proto_fs::ACCESS_DENIED))
        ));
    }
}

#[cfg(test)]
mod resolver_small_wire_tests {
    use super::*;

    #[test]
    fn paid_job_requests_match_the_existing_full_writer() {
        for method in [Method::ResolveStep, Method::OpenExec, Method::ResolveCancel] {
            for job in [1, 256, u64::MAX] {
                let mut writer = Writer::new();
                method.header().write(&mut writer).unwrap();
                writer.u64(job).unwrap();
                assert_eq!(job_request(method, job).as_slice(), writer.as_bytes());
            }
        }
    }

    #[test]
    fn pending_binding_request_matches_the_existing_full_writer() {
        for require_fds in [false, true] {
            let mut writer = Writer::new();
            Method::BindPending.header().write(&mut writer).unwrap();
            writer.u32(u32::from(require_fds)).unwrap();
            assert_eq!(
                pending_binding_request(require_fds).as_slice(),
                writer.as_bytes()
            );
        }
    }

    #[test]
    fn resolver_start_matches_the_existing_full_writer_and_path_guards() {
        let max = [b'x'; proto_fs::MAX_PATH];
        for path in [b"/".as_slice(), b"../bin/probe", max.as_slice()] {
            let mut request = [0xa5; 28 + proto_fs::MAX_PATH];
            let len = resolve_start_request(&mut request, path).unwrap();
            let mut writer = Writer::new();
            Method::ResolveStart.header().write(&mut writer).unwrap();
            writer.u32(0).unwrap();
            writer.u64(1).unwrap();
            writer.u32(0).unwrap();
            writer.u32(1).unwrap();
            writer.bytes(path).unwrap();
            assert_eq!(&request[..len], writer.as_bytes());
            assert_eq!(len, 28 + path.len());
        }
        let mut request = [0xa5; 28 + proto_fs::MAX_PATH];
        for (path, status) in [
            (b"".as_slice(), Status::Unknown(proto_fs::NO_ENTRY)),
            (
                &[0; proto_fs::MAX_PATH + 1],
                Status::Unknown(proto_fs::NAME_TOO_LONG),
            ),
            (b"/a\0b".as_slice(), Status::BadSize),
        ] {
            assert_eq!(resolve_start_request(&mut request, path), Err(status));
            assert_eq!(request, [0xa5; 28 + proto_fs::MAX_PATH]);
        }
    }

    fn start_words(status: Status, job: u64) -> [u64; 8] {
        let mut words = [0; 8];
        words[0] = status.code() as u64 | (job & 0xffff_ffff) << 32;
        words[1] = job >> 32;
        words
    }

    #[test]
    fn resolver_start_requires_exact_job_and_status_envelopes() {
        for job in [1, 256, 1 << 32, u64::MAX] {
            let words = start_words(Status::Ok, job);
            assert_eq!(resolve_start_job(12, &words, 0), Ok(job));
            for len in [0, 4, 8, 11, 13, 16, 64, MESSAGE_MAX, MESSAGE_MAX + 1] {
                assert_eq!(resolve_start_job(len, &words, 0), Err(Status::BadSize));
            }
            for caps in [1, 2, 8] {
                assert_eq!(resolve_start_job(12, &words, caps), Err(Status::BadSize));
            }
        }
        assert_eq!(
            resolve_start_job(12, &start_words(Status::Ok, 0), 0),
            Err(Status::BadSize)
        );
        for status in [
            Status::Unknown(proto_fs::ACCESS_DENIED),
            Status::Kernel(Error::Interrupted),
            Status::BadSize,
        ] {
            let words = start_words(status, 0);
            assert_eq!(resolve_start_job(8, &words, 0), Err(status));
            for len in [0, 4, 7, 9, 12, 16, MESSAGE_MAX] {
                assert_eq!(resolve_start_job(len, &words, 0), Err(Status::BadSize));
            }
            for bit in 32..64 {
                let mut reserved = words;
                reserved[0] |= 1 << bit;
                assert_eq!(resolve_start_job(8, &reserved, 0), Err(Status::BadSize));
            }
            assert_eq!(resolve_start_job(8, &words, 1), Err(Status::BadSize));
        }
    }

    #[test]
    fn ready_status_preserves_canonical_outcomes() {
        for status in [
            Status::Ok,
            Status::Unknown(proto_fs::RESOLVING),
            Status::Unknown(proto_fs::STALE_PROOF),
            Status::Unknown(proto_fs::ACCESS_DENIED),
            Status::Kernel(Error::Interrupted),
            Status::BadSize,
        ] {
            let bytes = proto_wire::reply(status);
            assert_eq!(bytes.len(), 8);
            let first = u64::from_le_bytes(bytes);
            assert_eq!(proof_ready_status(8, first, 0), Ok(status));
        }
    }

    #[test]
    fn ready_status_rejects_prefixes_reserved_bits_and_capabilities() {
        for code in [0, proto_fs::RESOLVING, proto_fs::ACCESS_DENIED] {
            for len in [0, 1, 4, 7, 9, 16, 32, MESSAGE_MAX, MESSAGE_MAX + 1] {
                assert_eq!(
                    proof_ready_status(len, code as u64, 0),
                    Err(Status::BadSize)
                );
            }
            for bit in 32..64 {
                assert_eq!(
                    proof_ready_status(8, code as u64 | 1 << bit, 0),
                    Err(Status::BadSize)
                );
            }
            for caps in [1, 2, 8] {
                assert_eq!(
                    proof_ready_status(8, code as u64, caps),
                    Err(Status::BadSize)
                );
            }
        }
    }
}
