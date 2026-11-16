// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The disk service over a memory object (proto_blk): the same protocol
//! as the Virtio driver (services/virtio-blk), with the sectors in an object
//! the service makes for itself, so the package service (services/pkgd)
//! keeps its store in memory on an image that has no disk (EC2). The size is the first
//! eight bytes of the record's own arguments, little-endian, in bytes. The object
//! is zero when the service starts, so the package service formats it, and it is gone
//! with the service: a restart would show a running client an empty disk, so the table
//! never restarts this service.
//!
//! A request is done in the step that takes it: the data pass between the client's cell
//! of the shared buffer and the object, and the answer is WAIT k that the next TAKE turns
//! into READY, as the driver's answer after the device's interrupt. The places of the
//! requests (`virtio_blk::Cells`) keep the rule of the flush and the cell's state, so a
//! client sees the same refusals. FLUSH is always done: the medium is the memory.

#![no_std]
#![no_main]

use abi::{Access, Error, Rights};
use core::alloc::{GlobalAlloc, Layout};
use proto_blk::{
    BUFFER_SIZE, CELL_BYTES, FLAG_FLUSH, Info, Io, Key, Method, SECTOR, VERSION, read_buffer,
};
use proto_init::ServiceArgs;
use proto_wire::{Status, long};
use rt::handle::{Memory, Outgoing, Process};
use rt::service::{Answer, Config, Heartbeat, LongOps, LongSession, Request, Service, Session};
use rt::{Handle, sys};
use virtio_blk::{Cells, Kind, Outcome, Refusal, Taken};

rt::entry!(main);

/// The library of the driver's decisions links the Virtio crate, which may ask for a heap
/// this service never uses: every allocation fails.
struct NoHeap;

#[global_allocator]
static ALLOCATOR: NoHeap = NoHeap;

// SAFETY: every allocation fails with a null pointer, which the contract allows; nothing is
// ever handed out to come back.
unsafe impl GlobalAlloc for NoHeap {
    unsafe fn alloc(&self, _: Layout) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

/// Where the service maps the object of the sectors and the client's shared buffer.
const STORE_AT: usize = 0x10_0000_0000;
const BUFFER_AT: usize = 0x10_8000_0000;
/// The sessions of the channel and the operations that wait at once.
const SESSIONS: usize = 2;
const OPERATIONS: usize = 8;
const PAGE: u64 = 4096;

/// The codes of a start that failed: no start data or no size; the object; the mapping; the
/// registration; the loop ended.
const NO_START_DATA: u64 = 1;
const NO_OBJECT: u64 = 2;
const NOT_REGISTERED: u64 = 3;
const NOT_MAPPED: u64 = 4;
const STOPPED: u64 = 5;

fn word(own: &[u8], at: usize) -> u64 {
    own.get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<rt::handle::Resource>("console") {
        rt::console::set(console);
    }
    let args = ServiceArgs::read(s.args()).ok();
    let own = args.map_or(&[][..], |a| a.own);
    let bytes = word(own, 0);
    if bytes == 0 || !bytes.is_multiple_of(PAGE) || bytes > abi::MAX_MEMORY {
        return NO_START_DATA;
    }
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    // The object is made before the service registers: it takes and zeroes its pages
    // before the first request can come.
    let Ok(store) = sys::mem_create(bytes) else {
        return NO_OBJECT;
    };
    if sys::mem_map(&s.process, &store, 0, bytes, STORE_AT, Access::ReadWrite).is_err() {
        return NOT_MAPPED;
    }
    let Ok(channel) = sys::channel_create(1) else {
        return NOT_REGISTERED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return NOT_REGISTERED;
    }
    rt::println!(
        "mem-blk: {} sectors in memory; installed packages are gone after a reboot",
        bytes / SECTOR as u64
    );
    let mut disk = Disk {
        cells: Cells::new(bytes / SECTOR as u64, FLAG_FLUSH),
        ops: LongOps::new(),
        info: Info {
            sectors: bytes / SECTOR as u64,
            block: SECTOR as u32,
            flags: FLAG_FLUSH,
        },
        buffer: None,
        process: Handle::borrowed(s.process.raw()),
        _store: store,
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &s.parent,
            period_ns: args.map_or(0, |a| a.period_ns),
            priority: level,
        }),
    };
    let _ = rt::service::run::<Disk, SESSIONS, 0>(&channel, &mut disk, config);
    STOPPED
}

/// The service: the places of the requests, the operations that wait, the session that holds
/// the shared buffer and the object of the sectors, mapped for its life.
struct Disk {
    cells: Cells,
    ops: LongOps<OPERATIONS>,
    info: Info,
    /// The label of the session whose buffer is mapped at BUFFER_AT.
    buffer: Option<u64>,
    process: core::mem::ManuallyDrop<Handle<Process>>,
    _store: Handle<Memory>,
}

impl Disk {
    /// READ and WRITE: the data pass at once, WAIT k.
    fn io(&mut self, s: &mut Session<LongSession, 0>, r: &mut Request<'_>, kind: Kind) -> Answer {
        let io = match Io::read(r.body()) {
            Ok(io) => io,
            Err(status) => return Answer::Status(status),
        };
        let label = r.label();
        let buffered = self.buffer == Some(label);
        let place = match self
            .cells
            .admit_io(kind, io.cell, io.count, io.sector, buffered)
        {
            Ok(place) => place,
            Err(refusal) => return refuse(refusal),
        };
        let len = io.count as usize * SECTOR;
        let cell = (BUFFER_AT + place * CELL_BYTES as usize) as *mut u8;
        let sectors = (STORE_AT + io.sector as usize * SECTOR) as *mut u8;
        let (from, to) = if kind == Kind::Write {
            (cell as *const u8, sectors)
        } else {
            (sectors as *const u8, cell)
        };
        // SAFETY: the request was admitted, so the sectors lie in the object and the cell
        // within the client's buffer, both mapped; a raw copy, since the client may write its
        // cell meanwhile and spoils only its own bytes.
        unsafe { core::ptr::copy_nonoverlapping(from, to, len) };
        self.start(s, r, place, kind, io.count)
    }

    fn flush(&mut self, s: &mut Session<LongSession, 0>, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        match self.cells.admit_flush() {
            Ok(place) => self.start(s, r, place, Kind::Flush, 0),
            Err(refusal) => refuse(refusal),
        }
    }

    /// The request in `place` is done: the answer waits in its place for TAKE.
    fn start(
        &mut self,
        s: &mut Session<LongSession, 0>,
        r: &mut Request<'_>,
        place: usize,
        kind: Kind,
        count: u32,
    ) -> Answer {
        let label = r.label();
        let key = match self.ops.start(&mut s.data, label) {
            Ok(key) => key,
            Err(error) => return Answer::Status(Status::Kernel(error)),
        };
        self.cells.begin(place, kind, label, key, 0, count);
        let _ = self.cells.complete(place, Outcome::Ok);
        long_answer(r, long::Reply::Wait(key))
    }

    /// BUFFER: the object the request carries becomes the session's shared buffer.
    fn give_buffer(&mut self, r: &mut Request<'_>) -> Answer {
        let size = match read_buffer(r.body()) {
            Ok(size) => size,
            Err(status) => return Answer::Status(status),
        };
        if size != BUFFER_SIZE || r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let needed = Rights::MAP_READ | Rights::MAP_WRITE;
        let rights = r.handles.info(0).map_or(Rights::NONE, |(_, rights)| rights);
        let Ok(object) = r.handles.take::<Memory>(0) else {
            return Answer::Status(proto_blk::code(proto_blk::INVALID));
        };
        if rights.0 & needed.0 != needed.0 {
            return Answer::Status(proto_blk::code(proto_blk::INVALID));
        }
        match sys::memory_info(&object) {
            Ok(info)
                if info.size >= u64::from(BUFFER_SIZE)
                    && info.pages * PAGE >= u64::from(BUFFER_SIZE) => {}
            _ => return Answer::Status(proto_blk::code(proto_blk::INVALID)),
        }
        match self.buffer {
            Some(label) if label == r.label() => {
                return Answer::Status(proto_blk::code(proto_blk::EXISTS));
            }
            Some(_) => return Answer::Status(proto_blk::code(proto_blk::BUSY)),
            None => {}
        }
        let mapped = sys::mem_map(
            &self.process,
            &object,
            0,
            u64::from(BUFFER_SIZE),
            BUFFER_AT,
            Access::ReadWrite,
        );
        match mapped {
            Ok(()) => {
                self.buffer = Some(r.label());
                Answer::Status(Status::Ok)
            }
            Err(Error::NoMemory | Error::LimitReached) => {
                Answer::Status(Status::Kernel(Error::LimitReached))
            }
            Err(error) => Answer::Status(Status::Kernel(error)),
        }
    }

    /// TAKE: READY for an operation that was done.
    fn take(&mut self, s: &mut Session<LongSession, 0>, r: &mut Request<'_>) -> Answer {
        let key = match Key::read(r.body()) {
            Ok(key) => key.key,
            Err(status) => return Answer::Status(status),
        };
        let label = r.label();
        match self.cells.take(label, key) {
            Taken::Done(_) => {
                self.ops.finish(&mut s.data, label, key);
                long_answer(r, long::Reply::Ready(&[]))
            }
            Taken::Waits | Taken::Unknown => Answer::Status(Status::Kernel(Error::BadState)),
        }
    }

    fn cancel(&mut self, s: &mut Session<LongSession, 0>, r: &mut Request<'_>) -> Answer {
        let key = match Key::read(r.body()) {
            Ok(key) => key.key,
            Err(status) => return Answer::Status(status),
        };
        let label = r.label();
        if !self.cells.cancel(label, key) {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        self.ops.finish(&mut s.data, label, key);
        long_answer(r, long::Reply::Cancelled)
    }

    fn info(&self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let w = r.reply();
        if w.u32(Status::Ok.code())
            .and_then(|()| self.info.write(w))
            .is_err()
        {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }
}

fn refuse(refusal: Refusal) -> Answer {
    Answer::Status(refusal.status())
}

const METHODS: &[u16] = &[
    Method::Info.number(),
    Method::Read.number(),
    Method::Write.number(),
    Method::Flush.number(),
    Method::Buffer.number(),
    Method::Take.number(),
    Method::Cancel.number(),
];

impl Service<0> for Disk {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = LongSession;

    fn request(&mut self, s: &mut Session<LongSession, 0>, r: &mut Request<'_>) -> Answer {
        match Method::from_number(r.method()) {
            Some(Method::Info) => self.info(r),
            Some(Method::Read) => self.io(s, r, Kind::Read),
            Some(Method::Write) => self.io(s, r, Kind::Write),
            Some(Method::Flush) => self.flush(s, r),
            Some(Method::Buffer) => self.give_buffer(r),
            Some(Method::Take) => self.take(s, r),
            Some(Method::Cancel) => self.cancel(s, r),
            _ => Answer::Status(Status::UnknownMethod),
        }
    }

    fn gone(&mut self, s: &mut Session<LongSession, 0>) {
        let label = s.label();
        self.cells.gone(label);
        self.ops.gone(&mut s.data);
        if self.buffer == Some(label) {
            // SAFETY: nothing of the service's own lies in the buffer's range; the bytes
            // there are the client's.
            let gone = unsafe { sys::mem_unmap(&self.process, BUFFER_AT, u64::from(BUFFER_SIZE)) };
            if gone.is_ok() {
                self.buffer = None;
            }
        }
    }
}

/// The reply of a long operation, through the request's reply buffer.
fn long_answer(r: &mut Request<'_>, reply: long::Reply<'_>) -> Answer {
    match reply.write(r.reply()) {
        Ok(()) => Answer::Reply(Outgoing::new()),
        Err(status) => Answer::Status(status),
    }
}
