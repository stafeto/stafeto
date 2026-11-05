// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The session with the package service (pk4-design R2): the one the start
//! gave (`posix_abi::packages::session`), a buffer of four cells that the
//! service and `pkg` share, and the requests. A request that changes the
//! store carries a copy of the process's identity session; the long ones
//! answer WAIT with a key and are taken until READY. A read that meets the
//! moment of a change gets BUSY and is asked again. The session ends with the
//! process, and the service drops the group of an installation whose session
//! went, so an installation cut short leaves no half behind.

use crate::sys;
use alloc::string::String;
use alloc::vec::Vec;
use pkg::output::Installed;
use posix_abi::allocation;
use proto_pkg::{self as p, Method, Stat};
use proto_wire::{Reader, Status, Writer, long};
use rt::abi::{Access, Error, MESSAGE_MAX, Rights};
use rt::handle::{Channel, Handle};
use rt::sys as rts;

/// Where the buffer is mapped in this process.
pub const BUFFER_AT: usize = 0x10_4000_0000;

/// The cell `n` of the buffer.
pub fn cell(n: u32) -> *mut u8 {
    (BUFFER_AT + n as usize * p::CELL_BYTES as usize) as *mut u8
}

pub struct Client {
    session: core::mem::ManuallyDrop<Handle<Channel>>,
}

/// A reply: the bytes and how many are meant.
pub type Bytes = ([u8; MESSAGE_MAX], usize);

impl Client {
    /// The session of the process, with a buffer given to the service. None when the
    /// image has no package service.
    pub fn open() -> Result<Result<Client, Status>, ()> {
        let Some(raw) = posix_abi::packages::session() else {
            return Err(());
        };
        let client = Client {
            session: Handle::<Channel>::borrowed(raw),
        };
        Ok(client.buffer().map(|()| client))
    }

    /// One request and its reply; with `identity`, the copy of the process's
    /// identity session goes with it.
    fn exchange(&self, request: &[u8], identity: bool) -> Result<Bytes, Status> {
        loop {
            let copy = identity
                .then(posix_abi::process::identity)
                .flatten()
                .and_then(|i| rts::handle_duplicate(i, Rights::NOTIFY | Rights::TRANSFER).ok());
            let sent = match copy {
                None => rts::send(&self.session, request),
                Some(h) => {
                    rts::send_handles(&self.session, request, [h.erase()]).map_err(|r| r.error)
                }
            };
            let reply = match sent {
                Err(Error::Interrupted) => continue,
                other => other?,
            };
            let mut out = [0; MESSAGE_MAX];
            let len = reply.bytes(&mut out).len();
            return Ok((out, len));
        }
    }

    /// A request whose reply is a status and what the method says after it; the
    /// service's refusal is the error.
    fn ask(&self, request: &[u8], identity: bool) -> Result<Bytes, Status> {
        let (out, len) = self.exchange(request, identity)?;
        match Status::from_code(Reader::new(&out[..len]).u32()?) {
            Status::Ok => Ok((out, len)),
            status => Err(status),
        }
    }

    /// `ask` again while the service says BUSY: it is changing its state.
    fn patient(&self, request: &[u8]) -> Result<Bytes, Status> {
        for _ in 0..50 {
            match self.ask(request, false) {
                Err(Status::Unknown(p::BUSY)) => sys::pause_ms(20),
                done => return done,
            }
        }
        Err(Status::Unknown(p::BUSY))
    }

    fn word(&self, method: Method, value: u32) -> Result<Bytes, Status> {
        let mut w = Writer::new();
        p::write_word(method, value, &mut w)?;
        self.patient(w.as_bytes())
    }

    /// BUFFER: a new object of four cells, mapped here and given to the service
    /// with the identity session, so that the superuser has one of the places
    /// the others cannot take.
    fn buffer(&self) -> Result<(), Status> {
        let object = rts::mem_create(u64::from(p::BUFFER_SIZE))?;
        rts::mem_map(
            allocation::process(),
            &object,
            0,
            u64::from(p::BUFFER_SIZE),
            BUFFER_AT,
            Access::ReadWrite,
        )?;
        let copy = rts::handle_duplicate(
            &object,
            Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER,
        )?;
        let mut w = Writer::new();
        p::write_word(Method::Buffer, p::BUFFER_SIZE, &mut w)?;
        let who = posix_abi::process::identity()
            .and_then(|i| rts::handle_duplicate(i, Rights::NOTIFY | Rights::TRANSFER).ok());
        let reply = match who {
            None => rts::send_handles(&self.session, w.as_bytes(), [copy.erase()]),
            Some(who) => {
                rts::send_handles(&self.session, w.as_bytes(), [copy.erase(), who.erase()])
            }
        }
        .map_err(|r| r.error)?;
        let mut out = [0; MESSAGE_MAX];
        match Status::from_code(Reader::new(reply.bytes(&mut out)).u32()?) {
            Status::Ok => Ok(()),
            status => Err(status),
        }
    }

    /// STATUS, once the service has read its disk (30 s at most).
    pub fn status(&self) -> Result<Stat, Status> {
        for _ in 0..1500 {
            let (out, len) = self.patient(&Method::Status.header().bytes())?;
            let stat = Stat::read(&out[..len])?;
            if stat.flags & p::STATUS_STARTING == 0 {
                return Ok(stat);
            }
            sys::pause_ms(20);
        }
        Err(Status::Unknown(0))
    }

    /// The packages of the store: the disk's and the image's.
    pub fn list(&self) -> Result<Vec<Installed>, Status> {
        let mut found = Vec::new();
        let mut first = 0;
        loop {
            let (out, len) = self.word(Method::List, first)?;
            let mut entries = [None; 4];
            let (count, next) = p::read_list(&out[..len], &mut entries)?;
            for e in entries.iter().take(count as usize).flatten() {
                let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
                found.push(Installed {
                    name: text(e.name),
                    version: text(e.version),
                    sha256: e.sha256,
                    flags: e.flags,
                    repository: text(e.repository),
                    provides: Vec::new(),
                    depends: Vec::new(),
                });
            }
            if next == 0 {
                return Ok(found);
            }
            first = next;
        }
    }

    /// The `meta` of the installed package `name`, whole.
    pub fn meta(&self, name: &str) -> Result<String, Status> {
        let mut meta = Vec::new();
        loop {
            let mut w = Writer::new();
            p::write_info(name.as_bytes(), meta.len() as u32, &mut w)?;
            let (out, len) = self.patient(w.as_bytes())?;
            let mut r = Reader::new(&out[4..len]);
            let total = r.u32()? as usize;
            let part = r.bytes(r.left())?;
            meta.extend_from_slice(part);
            if meta.len() >= total || part.is_empty() {
                return String::from_utf8(meta).map_err(|_| Status::BadSize);
            }
        }
    }

    /// The serial of `repository` the service holds, 0 for one it does not know.
    pub fn serial(&self, repository: &str) -> Result<u64, Status> {
        let mut w = Writer::new();
        p::write_serial(repository.as_bytes(), None, &mut w)?;
        let (out, len) = self.patient(w.as_bytes())?;
        Reader::new(&out[4..len]).u64()
    }

    pub fn serial_set(&self, repository: &str, serial: u64) -> Result<(), Status> {
        let mut w = Writer::new();
        p::write_serial(repository.as_bytes(), Some(serial), &mut w)?;
        self.change(w.as_bytes(), true).map(drop)
    }

    /// REMOVE of `names` (at most `REMOVE_MAX`), one change of the store.
    pub fn remove(&self, names: &[&str]) -> Result<(), Status> {
        let bytes: Vec<&[u8]> = names.iter().map(|n| n.as_bytes()).collect();
        let mut w = Writer::new();
        p::write_remove(&bytes, &mut w)?;
        self.change(w.as_bytes(), true).map(drop)
    }

    /// WORLD_SET: the package `name` is of the world (`true`) or only a dependency, the table alone.
    pub fn world_set(&self, name: &str, world: bool) -> Result<(), Status> {
        let mut w = Writer::new();
        p::write_world(name.as_bytes(), world, &mut w)?;
        self.change(w.as_bytes(), true).map(drop)
    }

    /// SETTINGS_SET: the blob, which goes into the cells of the buffer.
    pub fn settings_set(&self, blob: &[u8]) -> Result<(), Status> {
        if blob.len() > p::BUFFER_SIZE as usize {
            return Err(Status::BadSize);
        }
        // SAFETY: the buffer is mapped and holds BUFFER_SIZE bytes from cell 0 on.
        unsafe { core::ptr::copy_nonoverlapping(blob.as_ptr(), cell(0), blob.len()) };
        let mut w = Writer::new();
        p::write_word(Method::SettingsSet, blob.len() as u32, &mut w)?;
        self.change(w.as_bytes(), true).map(drop)
    }

    /// REVOKED_SET of the list and its block, one after the other in cell 0.
    pub fn revoked_set(&self, list: &[u8], block: &[u8]) -> Result<(), Status> {
        let len = list.len() + block.len();
        if len > 2 * p::CELL_BYTES as usize {
            return Err(Status::BadSize);
        }
        // SAFETY: the buffer is mapped, two cells are `len` bytes at least.
        unsafe {
            core::ptr::copy_nonoverlapping(list.as_ptr(), cell(0), list.len());
            core::ptr::copy_nonoverlapping(block.as_ptr(), cell(0).add(list.len()), block.len());
        }
        let mut w = Writer::new();
        p::write_word(Method::RevokedSet, len as u32, &mut w)?;
        self.change(w.as_bytes(), true).map(drop)
    }

    /// The settings blob, whole; a part with another generation than the first
    /// starts the reading again.
    pub fn settings(&self) -> Result<Vec<u8>, Status> {
        'again: for _ in 0..20 {
            let mut blob: Vec<u8> = Vec::new();
            let mut generation = None;
            loop {
                let (out, len) = self.word(Method::SettingsGet, blob.len() as u32)?;
                let part = p::Settings::read(&out[..len])?;
                if *generation.get_or_insert(part.generation) != part.generation {
                    continue 'again;
                }
                // SAFETY: cell 0 of the mapped buffer holds `copied` bytes the service wrote.
                let bytes = unsafe { core::slice::from_raw_parts(cell(0), part.copied as usize) };
                blob.extend_from_slice(bytes);
                if blob.len() >= part.total as usize || part.copied == 0 {
                    return Ok(blob);
                }
            }
        }
        Err(Status::BadSize)
    }

    /// INSTALL_BEGIN: the receipt. BUSY (a group of another session is open) is
    /// asked again once a second for 30 s.
    pub fn begin(&self, record: &p::Begin<'_>) -> Result<u32, Status> {
        let mut w = Writer::new();
        record.write(&mut w)?;
        self.change_for(w.as_bytes(), true, 30, 1000)
    }

    /// FEED: `len` bytes in cell `cell` of the buffer.
    pub fn feed(&self, receipt: u32, cell: u32, len: u32) -> Result<(), Status> {
        let mut w = Writer::new();
        p::Feed { receipt, cell, len }.write(&mut w)?;
        self.ask(w.as_bytes(), false).map(drop)
    }

    pub fn commit(&self, receipt: u32, end: bool) -> Result<(), Status> {
        let mut w = Writer::new();
        p::write_commit(receipt, if end { p::COMMIT_END } else { 0 }, &mut w)?;
        self.change(w.as_bytes(), false).map(drop)
    }

    /// INSTALL_CANCEL: the group is dropped. Errors are not told: a group that
    /// is gone is as good as one that was cancelled.
    pub fn cancel(&self, receipt: u32) {
        let mut w = Writer::new();
        if p::write_word(Method::InstallCancel, receipt, &mut w).is_ok() {
            let _ = self.ask(w.as_bytes(), false);
        }
    }

    /// A request that changes the store: WAIT with a key, TAKE until READY, the
    /// first word of the result. BUSY is asked again: the service may not have
    /// dropped a group that was cancelled.
    fn change(&self, request: &[u8], identity: bool) -> Result<u32, Status> {
        self.change_for(request, identity, 2_000, 5)
    }

    /// `change` that asks again `tries` times, `wait` ms apart, while the service says BUSY.
    fn change_for(
        &self,
        request: &[u8],
        identity: bool,
        tries: u32,
        wait: i64,
    ) -> Result<u32, Status> {
        for _ in 0..tries {
            let (out, len) = self.exchange(request, identity)?;
            let key = match long::Reply::read(&out[..len]) {
                Ok(long::Reply::Wait(key)) => key,
                Err(Status::Unknown(p::BUSY)) => {
                    sys::pause_ms(wait);
                    continue;
                }
                Ok(_) => return Err(Status::BadSize),
                Err(status) => return Err(status),
            };
            match self.take(key) {
                Err(Status::Unknown(p::BUSY)) => sys::pause_ms(wait),
                done => return done,
            }
        }
        Err(Status::Unknown(p::BUSY))
    }

    /// TAKE until the operation is READY (a quarter of an hour at most). The pause between the
    /// asks grows from 2 ms to 64 ms (`output::backoff_ms`): a long operation, a replacement of
    /// Doom or a removal, is not asked 500 times a second.
    fn take(&self, key: u64) -> Result<u32, Status> {
        let mut w = Writer::new();
        p::write_take(key, &mut w)?;
        for n in 0..15_000u32 {
            let (out, len) = self.exchange(w.as_bytes(), false)?;
            match long::Reply::read(&out[..len])? {
                long::Reply::Ready(result) => {
                    let mut word = [0u8; 4];
                    let n = result.len().min(4);
                    word[..n].copy_from_slice(&result[..n]);
                    return Ok(u32::from_le_bytes(word));
                }
                long::Reply::Armed => sys::pause_ms(pkg::output::backoff_ms(n)),
                _ => return Err(Status::BadSize),
            }
        }
        Err(Status::Kernel(Error::WouldBlock))
    }
}
