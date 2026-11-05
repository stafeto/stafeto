// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The worker thread (pk3-design R1, R4, R12): everything that takes long.
//! It reads the store from the disk through the disk service, creates and
//! maps the object of each package, hashes it as the bytes arrive, checks
//! its signature, and attaches it to the file service as a layer, all in
//! straight lines that wait in calls; the main thread of the service never
//! waits for any of it and keeps answering. At the start the thread fills the
//! table of the store and the packages of the disk, and the main thread reads
//! what the thread published, entry by entry, meanwhile (`shared`). Then the
//! thread serves the jobs of the main thread (`jobs.rs`): the receipt of a
//! package, the transactions of the store.

use crate::shared::*;
use abi::{Access, MESSAGE_MAX, Rights, Source};
use core::sync::atomic::Ordering::{Acquire, Release};
use pkgd::commit::{self, Device, Failed, Point, Start};
use pkgd::packages::Entry;
use pkgd::settings::{self, Settings};
use pkgd::store::{self, BLOCK, Record, Table};
use pkgd::verify::{self, Fault, Phase};
use pkgfmt::revoked::Revoked;
use pkgfmt::sha::{Stream, sha256};
use pkgfmt::{Key, Trust, keyfile};
use proto_blk::{CELL_BYTES, CELLS, Info, Key as BlkKey, Method as Blk, SECTOR};
use proto_fs::{LayerOp, LayerReply, LayerStart, LayerStep};
use proto_wire::{Status, Writer, long};
use rt::Handle;
use rt::handle::{Any, Channel, Memory, Process};
use rt::sys::{self, Received};

/// The measured use is some 54 KiB; the margin is the rest. The stack is an object of its own,
/// mapped at `STACK_AT` with no mapping on the page below it: an overflow faults on the guard
/// page and ends the process, where a stack in `.bss` (`rt::Stack`) would overwrite the
/// statics next to it.
const STACK_SIZE: usize = 128 * 1024;
const STACK_AT: usize = 0x58_2000_0000;
/// The thread's message buffer: the page after the main thread's.
const MSGBUF: usize = abi::INIT_MSGBUF as usize + 4096;
/// The blocks of a cell and the sectors of a block.
const CELL_BLOCKS: u64 = CELL_BYTES as u64 / BLOCK as u64;
const BLOCK_SECTORS: u32 = (BLOCK / SECTOR) as u32;

/// The raw handles of the main thread's, kept for this thread.
pub const HANDLES: usize = 6;
pub static RAW: [core::sync::atomic::AtomicU64; HANDLES] =
    [const { core::sync::atomic::AtomicU64::new(0) }; HANDLES];
pub const PROCESS: usize = 0;
pub const BLK_SESSION: usize = 1;
pub const LAYERS_SESSION: usize = 2;
pub const MAIN_CHANNEL: usize = 3;
pub const WAKE: usize = 4;
/// The channel the main thread kicks: the thread waits on it for a job.
pub const JOBS: usize = 5;

pub fn view<K>(i: usize) -> core::mem::ManuallyDrop<Handle<K>> {
    Handle::borrowed(abi::Handle(RAW[i].load(Acquire)))
}

/// Starts the thread; it begins with the work of the start.
pub fn start(process: &Handle<Process>) -> Result<Handle<rt::handle::Thread>, abi::Error> {
    // The mapping keeps the object; the page below `STACK_AT` is never mapped.
    let stack = sys::mem_create(STACK_SIZE as u64)?;
    sys::mem_map(
        process,
        &stack,
        0,
        STACK_SIZE as u64,
        STACK_AT,
        Access::ReadWrite,
    )?;
    // SAFETY: the stack is the thread's alone.
    let thread = unsafe {
        sys::thread_create(
            process,
            work,
            STACK_AT + STACK_SIZE,
            0,
            LEVEL,
            abi::Policy::RoundRobin,
            MSGBUF,
        )
    }?;
    sys::thread_start(&thread)?;
    Ok(thread)
}

/// The level of the thread: the clients' of the service, the ones that
/// the layer calls it makes name (`LayerStart::level`).
pub const LEVEL: u8 = 30;

extern "C" fn work(_: u64) -> ! {
    let worker = match boot() {
        Ok(worker) => Some(worker),
        Err(why) => {
            rt::println!("pkgd: the start failed: {why}");
            None
        }
    };
    STARTING.store(false, Release);
    let tell = view::<Channel>(WAKE);
    let _ = sys::notify(&tell, 1);
    match worker {
        Some(mut worker) => worker.serve(),
        // No store to serve: the thread waits for the end of the process.
        None => {
            let jobs = view::<Channel>(JOBS);
            loop {
                let _ = sys::receive(&jobs);
            }
        }
    }
}

type Fail = &'static str;

/// The disk service as a `Device`: one block at a time, with its own channel
/// for the notifications of the operations.
pub struct Disk {
    session: core::mem::ManuallyDrop<Handle<Channel>>,
    own: Handle<Channel>,
    /// The timer on `own` that ends the wait for an answer of the disk service (`finish`).
    timer: Handle<rt::handle::Timer>,
    /// The disk service did not answer in time: a request may still be with it and its cell
    /// will be written whenever it answers, so no request goes to it any more (this start of
    /// the service; the disk service that restarts is not followed, a restart of the machine
    /// is).
    dead: core::sync::atomic::AtomicBool,
    /// A copy of `own` with NOTIFY for each cell, labelled by the cell plus one.
    notify: [Handle<Channel>; CELLS as usize],
    sectors: u64,
    pub flush: bool,
}

/// Where the thread maps the disk service's buffer.
const BUFFER_AT: usize = 0x58_1000_0000;

enum Got {
    Ready,
    Wait(u64),
    Armed,
}

impl Disk {
    fn call(&self, request: &[u8], handle: Option<Handle<Any>>) -> Result<Got, Status> {
        if self.dead.load(Acquire) {
            return Err(Status::Kernel(abi::Error::PeerClosed));
        }
        let reply = match handle {
            None => sys::send(&self.session, request)?,
            Some(h) => sys::send_handles(&self.session, request, [h]).map_err(|r| r.error)?,
        };
        let mut buffer = [0; MESSAGE_MAX];
        match long::Reply::read(reply.bytes(&mut buffer))? {
            long::Reply::Ready(_) => Ok(Got::Ready),
            long::Reply::Wait(key) => Ok(Got::Wait(key)),
            long::Reply::Armed => Ok(Got::Armed),
            long::Reply::Cancelled => Err(Status::BadSize),
        }
    }

    fn io(&self, method: Blk, cell: u32, count: u32, sector: u64) -> Result<u64, Status> {
        let mut w = Writer::new();
        method.header().write(&mut w)?;
        w.u32(cell)?;
        w.u32(count)?;
        w.u64(sector)?;
        match self.call(w.as_bytes(), None)? {
            Got::Wait(key) => Ok(key),
            _ => Err(Status::BadSize),
        }
    }

    /// TAKE of `key` until it is READY: the first time with a handle that
    /// notifies this thread's channel. The wait for the notification has a deadline
    /// (`DISK_WAIT_NS`): a disk service that died or stopped answering with the request
    /// leaves the thread no other end, and the install with its group would wait for ever.
    /// Past it the disk is dead (`dead`) and the wait is an error, which the job that waits
    /// turns into IO and drops its group.
    fn finish(&self, key: u64, cell: usize) -> Result<(), Status> {
        let mut w = Writer::new();
        BlkKey { key }.write(Blk::Take, &mut w)?;
        let mut notify = Some(
            sys::handle_duplicate(&self.notify[cell], Rights::NOTIFY | Rights::TRANSFER)?.erase(),
        );
        let until = rt::time::ticks_to_ns(rt::time::now()) + DISK_WAIT_NS;
        let mut armed = false;
        let done = (|| loop {
            match self.call(w.as_bytes(), notify.take())? {
                Got::Ready => return Ok(()),
                Got::Armed => {}
                Got::Wait(_) => return Err(Status::BadSize),
            }
            if !armed {
                sys::timer_set(&self.timer, until)?;
                armed = true;
            }
            loop {
                match sys::receive(&self.own)? {
                    Received::Notification {
                        source: Source::Session,
                        label,
                        bits,
                        ..
                    } if label == cell as u64 + 1 && bits & 1 != 0 => break,
                    // An expiry before the deadline is a stale one of an earlier wait.
                    Received::Notification {
                        source: Source::Timer,
                        ..
                    } if rt::time::reached(until) => {
                        self.dead.store(true, Release);
                        rt::println!("pkgd: the disk service did not answer in time");
                        return Err(Status::Kernel(abi::Error::WouldBlock));
                    }
                    _ => {}
                }
            }
        })();
        if armed {
            let _ = sys::timer_cancel(&self.timer);
        }
        done
    }

    fn cell(cell: usize) -> *mut u8 {
        (BUFFER_AT + cell * CELL_BYTES as usize) as *mut u8
    }

    /// `bytes` (whole blocks, at most a cell) to the blocks from `first`.
    pub fn write_blocks(&mut self, first: u64, bytes: &[u8]) -> Result<(), Failed> {
        debug_assert!(bytes.len().is_multiple_of(BLOCK) && bytes.len() <= CELL_BYTES as usize);
        // SAFETY: cell 0 of the mapped buffer; no request of it is in flight.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), Self::cell(0), bytes.len()) };
        let key = self
            .io(
                Blk::Write,
                0,
                (bytes.len() / SECTOR) as u32,
                first * u64::from(BLOCK_SECTORS),
            )
            .map_err(|_| Failed)?;
        self.finish(key, 0).map_err(|_| Failed)
    }

    /// Reads `blocks` blocks from `first` into `to(chunk_start_block, bytes)`,
    /// four cells in flight; `done` sees each chunk as it lands.
    fn read_run(
        &self,
        first: u64,
        blocks: u64,
        mut sink: impl FnMut(u64, &[u8]),
    ) -> Result<(), Failed> {
        let mut issued = 0;
        let mut taken = 0;
        let mut keys = [0u64; CELLS as usize];
        let total = blocks.div_ceil(CELL_BLOCKS);
        while taken < total {
            while issued < total && issued - taken < u64::from(CELLS) {
                let at = issued * CELL_BLOCKS;
                let count = (blocks - at).min(CELL_BLOCKS) as u32 * BLOCK_SECTORS;
                let cell = (issued % u64::from(CELLS)) as u32;
                keys[cell as usize] = self
                    .io(
                        Blk::Read,
                        cell,
                        count,
                        (first + at) * u64::from(BLOCK_SECTORS),
                    )
                    .map_err(|_| Failed)?;
                issued += 1;
            }
            let cell = (taken % u64::from(CELLS)) as usize;
            self.finish(keys[cell], cell).map_err(|_| Failed)?;
            let at = taken * CELL_BLOCKS;
            let len = (blocks - at).min(CELL_BLOCKS) as usize * BLOCK;
            // SAFETY: the cell lies in the mapped buffer, READY: the service wrote it and
            // no request of this cell is in flight.
            sink(at, unsafe {
                core::slice::from_raw_parts(Self::cell(cell), len)
            });
            taken += 1;
        }
        Ok(())
    }
}

impl Device for Disk {
    fn blocks(&self) -> u64 {
        self.sectors / u64::from(BLOCK_SECTORS)
    }

    fn read(&mut self, block: u64, out: &mut [u8; BLOCK]) -> Result<(), Failed> {
        self.read_run(block, 1, |_, bytes| out.copy_from_slice(bytes))
    }

    fn write(&mut self, block: u64, data: &[u8; BLOCK]) -> Result<(), Failed> {
        // SAFETY: cell 0 of the mapped buffer; no request of it is in flight.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), Self::cell(0), BLOCK) };
        let key = self
            .io(
                Blk::Write,
                0,
                BLOCK_SECTORS,
                block * u64::from(BLOCK_SECTORS),
            )
            .map_err(|_| Failed)?;
        self.finish(key, 0).map_err(|_| Failed)
    }

    fn flush(&mut self) -> Result<(), Failed> {
        match self.call(&Blk::Flush.header().bytes(), None) {
            Ok(Got::Wait(key)) => self.finish(key, 0).map_err(|_| Failed),
            _ => Err(Failed),
        }
    }

    fn attach(&mut self, slot: usize) -> Result<(), u32> {
        // SAFETY: the worker's: the objects change under its hand alone.
        let objects = unsafe { &*OBJECTS.get() };
        let Some(memory) = objects[slot].as_ref() else {
            return Err(proto_pkg::INVALID);
        };
        let layer = next_layer();
        attach_layer(memory, layer)?;
        // SAFETY: as above.
        unsafe { (*LAYER_OF.get())[slot] = layer };
        Ok(())
    }

    fn detach(&mut self, slot: usize) {
        // SAFETY: the worker's.
        let layer = unsafe { core::mem::take(&mut (*LAYER_OF.get())[slot]) };
        if layer != 0 {
            detach_layer(layer);
        }
    }

    fn point(&mut self, point: Point) {
        crash_at(point);
    }

    #[cfg(feature = "crash")]
    fn tear(&mut self, block: u64, data: &[u8; BLOCK]) {
        if CRASH_AT != Point::SuperTorn.number() {
            return;
        }
        // The write is torn inside its first sector: the first 64 bytes of the superblock reach
        // the disk, the rest of the sector is zeros. The superblock is 128 bytes with its own
        // SHA-256 at the end, so the copy is refused and the other copy is the state.
        // SAFETY: cell 0 of the mapped buffer; no request of it is in flight.
        unsafe {
            core::ptr::write_bytes(Self::cell(0), 0, SECTOR);
            core::ptr::copy_nonoverlapping(data.as_ptr(), Self::cell(0), 64);
        }
        if let Ok(key) = self.io(Blk::Write, 0, 1, block * u64::from(BLOCK_SECTORS)) {
            let _ = self.finish(key, 0);
        }
        crash_at(Point::SuperTorn);
    }
}

/// The point the build for the crash tests stops at (`STAFETO_PKGD_CRASH_AT`), 0 for none.
#[cfg(feature = "crash")]
const CRASH_AT: u8 = match option_env!("STAFETO_PKGD_CRASH_AT") {
    Some(text) => {
        let (bytes, mut n, mut i) = (text.as_bytes(), 0u8, 0);
        while i < bytes.len() {
            n = n * 10 + (bytes[i] - b'0');
            i += 1;
        }
        n
    }
    None => 0,
};

/// The build for the crash tests prints the line of its point and stops there for good:
/// the host kills the machine on the line and starts it again on the same disk.
#[cfg(feature = "crash")]
pub fn crash_at(point: Point) {
    if point.number() != CRASH_AT {
        return;
    }
    rt::println!("pkgd: crash point {} {}", point.number(), point.name());
    let held = sys::channel_create(LEVEL);
    loop {
        if let Ok(channel) = &held {
            let _ = sys::receive(channel);
        }
    }
}

#[cfg(not(feature = "crash"))]
pub fn crash_at(_: Point) {}

/// How long the thread waits for the disk service to answer one request it took: a read or a
/// write of 16 KiB or a flush takes milliseconds, and ten seconds is a service that is gone.
#[cfg(not(feature = "short-deadline"))]
const DISK_WAIT_NS: u64 = 10_000_000_000;
#[cfg(feature = "short-deadline")]
const DISK_WAIT_NS: u64 = 1_000_000_000;

/// The disk service: the buffer of four cells and its INFO.
fn connect_disk(process: &Handle<Process>) -> Result<Disk, Fail> {
    let session = view::<Channel>(BLK_SESSION);
    let object = sys::mem_create(u64::from(proto_blk::BUFFER_SIZE)).map_err(|_| "no memory")?;
    sys::mem_map(
        process,
        &object,
        0,
        u64::from(proto_blk::BUFFER_SIZE),
        BUFFER_AT,
        Access::ReadWrite,
    )
    .map_err(|_| "the buffer is not mapped")?;
    let copy = sys::handle_duplicate(
        &object,
        Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER,
    )
    .map_err(|_| "no copy")?;
    let mut w = Writer::new();
    proto_blk::write_buffer(proto_blk::BUFFER_SIZE, &mut w).map_err(|_| "request")?;
    let reply = sys::send_handles(&session, w.as_bytes(), [copy.erase()]).map_err(|_| "BUFFER")?;
    let mut buffer = [0; MESSAGE_MAX];
    if proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
        return Err("the disk service refused the buffer");
    }
    let reply = sys::send(&session, &Blk::Info.header().bytes()).map_err(|_| "INFO")?;
    let info = Info::read(reply.bytes(&mut buffer)).map_err(|_| "INFO reply")?;
    let own = sys::channel_create(LEVEL).map_err(|_| "no channel")?;
    let label = |cell: u64| {
        sys::handle_label(
            &own,
            Rights::NOTIFY | Rights::TRANSFER | Rights::DUPLICATE,
            cell + 1,
            LEVEL,
        )
        .map_err(|_| "no notification")
    };
    let notify = [label(0)?, label(1)?, label(2)?, label(3)?];
    let timer = sys::timer_create(&own, LEVEL).map_err(|_| "no timer")?;
    Ok(Disk {
        session,
        notify,
        own,
        timer,
        dead: core::sync::atomic::AtomicBool::new(false),
        sectors: info.sectors,
        flush: info.flush(),
    })
}

/// A number for the next layer: from 1 to the greatest the file service takes and round
/// again, never one a layer of the table holds.
fn next_layer() -> u32 {
    loop {
        let n = LAYER.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
            % proto_fs::LAYER_NUMBER_MAX
            + 1;
        // SAFETY: the worker's.
        if !unsafe { &*LAYER_OF.get() }.contains(&n) {
            return n;
        }
    }
}

/// How long the file service may stay busy with the layer before it, in nanoseconds.
const BUSY_NS: u64 = 30_000_000_000;

/// Attaches `memory` as a layer: LayerStart with the object and the
/// notification, then LayerStep until the answer. The code of the refusal.
fn attach_layer(memory: &Handle<Memory>, layer: u32) -> Result<(), u32> {
    let session = view::<Channel>(LAYERS_SESSION);
    let main = view::<Channel>(MAIN_CHANNEL);
    let until = rt::time::now() + rt::time::ns_to_ticks(BUSY_NS);
    loop {
        let copy = sys::handle_duplicate(memory, Rights::MAP_READ | Rights::TRANSFER)
            .map_err(|_| proto_pkg::NO_MEMORY)?;
        let tell = sys::handle_label(
            &main,
            Rights::NOTIFY | Rights::TRANSFER,
            LABEL_LAYER + u64::from(layer),
            MAIN_LEVEL,
        )
        .map_err(|_| proto_pkg::NO_MEMORY)?;
        let mut w = Writer::new();
        let start = LayerStart {
            op: LayerOp::Attach,
            layer,
            level: u32::from(LEVEL),
        };
        start.write(&mut w).map_err(|_| proto_pkg::INVALID)?;
        let reply = sys::send_handles(&session, w.as_bytes(), [copy.erase(), tell.erase()])
            .map_err(|_| proto_pkg::IO)?;
        match layer_steps(&session, layer, reply)? {
            Steps::Done => return Ok(()),
            Steps::Busy => {}
        }
        // The mapping thread of the file service is busy with the last layer.
        if rt::time::now() > until {
            return Err(proto_pkg::BUSY);
        }
        let _ = sys::yield_now();
    }
}

/// Detaches layer `layer`: LayerStart, then LayerStep until the answer. A layer the file
/// service does not know is gone already.
fn detach_layer(layer: u32) {
    let session = view::<Channel>(LAYERS_SESSION);
    let until = rt::time::now() + rt::time::ns_to_ticks(BUSY_NS);
    loop {
        let mut w = Writer::new();
        let start = LayerStart {
            op: LayerOp::Detach,
            layer,
            level: 0,
        };
        if start.write(&mut w).is_err() {
            return;
        }
        let Ok(reply) = sys::send(&session, w.as_bytes()) else {
            return;
        };
        match layer_steps(&session, layer, reply) {
            Ok(Steps::Busy) if rt::time::now() <= until => {
                let _ = sys::yield_now();
            }
            Ok(Steps::Done) => return,
            _ => {
                rt::println!("pkgd: layer {layer}: not detached");
                return;
            }
        }
    }
}

enum Steps {
    Done,
    Busy,
}

/// The answers of the file service to a LayerStart until the end: Done, or BUSY when its
/// mapping thread has the last layer still; the code of any other refusal.
fn layer_steps(session: &Handle<Channel>, layer: u32, mut reply: sys::Reply) -> Result<Steps, u32> {
    let mut buffer = [0; MESSAGE_MAX];
    loop {
        let answer = LayerReply::read(proto_wire::Reader::new(reply.bytes(&mut buffer)))
            .map_err(|_| proto_pkg::IO)?;
        match answer {
            LayerReply::Resolving => {
                let mut w = Writer::new();
                LayerStep { layer }
                    .write(&mut w)
                    .map_err(|_| proto_pkg::INVALID)?;
                reply = sys::send(session, w.as_bytes()).map_err(|_| proto_pkg::IO)?;
            }
            LayerReply::Done { .. } => return Ok(Steps::Done),
            LayerReply::Entry { status, entry } => {
                rt::println!("pkgd: layer {layer}: status {status} at entry {entry}");
                return Err(match status {
                    proto_fs::CONFLICT => proto_pkg::CONFLICT,
                    _ => proto_pkg::BAD_PACKAGE,
                });
            }
            LayerReply::Refused { status } if status == proto_fs::BUSY => return Ok(Steps::Busy),
            LayerReply::Refused { status } if status == proto_fs::NO_SPACE => {
                return Err(proto_pkg::NO_SPACE);
            }
            LayerReply::Refused { .. } => return Err(proto_pkg::IO),
        }
    }
}

/// What the worker keeps between its jobs.
pub struct Worker {
    pub disk: Disk,
    pub process: core::mem::ManuallyDrop<Handle<Process>>,
    pub roots: ([Key; 4], usize),
    /// The list of revocations of the state, parsed from `REVOKED_FILE`.
    pub revoked: Option<Revoked<'static>>,
    /// The receipt being fed: its number, the place of the table, the size and the first
    /// block of its extent; its object is mapped at `window(slot)`.
    pub open: Option<crate::jobs::Open>,
    /// A write of the data failed: the code the commit answers.
    pub failed: Option<u32>,
    /// The first write of the data of the receipt is still to come (the crash point).
    pub first_write: bool,
}

/// The state the worker starts with: the disk service connected, the store read, its
/// packages attached; the lines it prints are the service's account of what it found
/// (pk3-design R12).
fn boot() -> Result<Worker, Fail> {
    let process = view::<Process>(PROCESS);
    let disk = connect_disk(&process)?;
    let roots = roots();
    rt::print!("pkgd: roots");
    for key in &roots.0[..roots.1] {
        rt::print!(" {}", key.name.as_str());
    }
    rt::println!();
    let mut worker = Worker {
        disk,
        process,
        roots,
        revoked: None,
        open: None,
        failed: None,
        first_write: true,
    };
    worker.start()?;
    Ok(worker)
}

impl Worker {
    /// The start: the superblocks, the table, the settings, the list of revocations, each
    /// package of the table.
    fn start(&mut self) -> Result<(), Fail> {
        // The table is read into the scratch table of the next state, then it is the state's.
        // SAFETY: nothing reads either until `TABLE` has entries that are published.
        let scratch = unsafe { &mut (*NEXT.get()).next };
        let opened = match commit::open(&mut self.disk, scratch).map_err(|_| "the disk failed")? {
            Start::Store(opened) => opened,
            Start::Blank if self.disk.flush => {
                let opened =
                    commit::format(&mut self.disk, scratch).map_err(|_| "the format failed")?;
                rt::println!(
                    "pkgd: store formatted, {} blocks",
                    self.disk.blocks() - store::SUPERS
                );
                READ_ONLY.store(false, Release);
                self.set_state(scratch, opened);
                finish_counts(&opened, &self.disk);
                return Ok(());
            }
            Start::Blank => {
                rt::println!("pkgd: device has no flush, store read-only");
                READ_ONLY.store(true, Release);
                return Ok(());
            }
            Start::Damaged => {
                rt::println!("pkgd: store damaged, no package from the disk");
                DAMAGED.store(true, Release);
                return Ok(());
            }
        };
        if !self.disk.flush {
            rt::println!("pkgd: device has no flush, store read-only");
            READ_ONLY.store(true, Release);
        }
        self.set_state(scratch, opened);
        // SAFETY: as above, and the table is the thread's to read.
        let table = unsafe { &*TABLE.get() };
        let settings_len = self.read_settings(table);
        self.revoked = self.read_revoked(table);
        let mut disk_count = 0;
        for (slot, published) in PUBLISHED.iter().enumerate() {
            let record = table.record(slot);
            if record.kind != store::PACKAGE {
                continue;
            }
            match self.load(table, &record, slot, settings_len) {
                Ok(entry) => {
                    // SAFETY: the slot is published below, after the entry is whole.
                    unsafe { (*DISK_ENTRIES.get())[slot] = Some(entry) };
                    published.store(true, Release);
                    disk_count += 1;
                }
                Err(why) => rt::println!(
                    "pkgd: {}: {why}, skipped",
                    core::str::from_utf8(record.name_bytes()).unwrap_or("?")
                ),
            }
        }
        DISK_PACKAGES.store(disk_count, Release);
        finish_counts(&opened, &self.disk);
        Ok(())
    }

    /// `table` of the state `opened` is the table the main thread reads and the worker
    /// compares the next state with.
    fn set_state(&mut self, table: &Table, opened: commit::Opened) {
        // SAFETY: only at the start, before any entry is published, or inside `publish`.
        unsafe {
            (*TABLE.get()).0 = table.0;
            *OPENED.get() = Some(opened);
        }
        GENERATION.store(opened.superblock.generation, Release);
        let free = commit::free_of(table, &opened);
        FREE.store(free, Release);
        BLOCKS.store(self.disk.blocks(), Release);
    }

    /// The blob of settings from its extent, checked, made into the container of
    /// a layer and attached. The length of the blob, 0 for none. The blob is the
    /// state, whether its layer attached or not: the keys of the owner's repositories
    /// and `SETTINGS_GET` come from it, and a layer that did not attach says so.
    fn read_settings(&mut self, table: &Table) -> usize {
        let record = table.record(store::SETTINGS_SLOT);
        if record.kind != store::SETTINGS {
            return 0;
        }
        // SAFETY: the thread owns the blob until `STARTING` clears.
        let blob = unsafe { &mut *SETTINGS.get() };
        if record.length as usize > blob.len()
            || disk_read(&mut self.disk, &record, &mut blob[..]).is_err()
        {
            rt::println!("pkgd: settings damaged, no settings layer");
            return 0;
        }
        let bytes = &blob[..record.length as usize];
        let Ok(parsed) = Settings::parse(bytes)
            .map_err(|_| ())
            .and_then(|s| (sha256(bytes) == record.sha256).then_some(s).ok_or(()))
        else {
            rt::println!("pkgd: settings damaged, no settings layer");
            return 0;
        };
        SETTINGS_LEN.store(bytes.len(), Release);
        match self.settings_layer(&parsed, store::SETTINGS_SLOT) {
            Ok(()) => {}
            Err(why) => rt::println!("pkgd: settings layer: {why}, not attached"),
        }
        bytes.len()
    }

    /// The container of the settings `parsed` made into an object in place `slot` of
    /// `OBJECTS` and attached.
    pub fn settings_layer(&mut self, parsed: &Settings<'_>, slot: usize) -> Result<(), Fail> {
        let memory = self.settings_object(parsed)?;
        // SAFETY: the thread's.
        unsafe { (*OBJECTS.get())[slot] = Some(memory) };
        if let Err(code) = self.disk.attach(slot) {
            // SAFETY: as above.
            unsafe { (*OBJECTS.get())[slot] = None };
            rt::println!("pkgd: settings layer: code {code}");
            return Err("the file service refused it");
        }
        Ok(())
    }

    /// The object holding the container of the settings `parsed`.
    pub fn settings_object(&mut self, parsed: &Settings<'_>) -> Result<Handle<Memory>, Fail> {
        // SAFETY: the thread's.
        let out = unsafe { &mut *CONTAINER.get() };
        let len = settings::container(parsed, out).ok_or("the container is not made")?;
        let at = window(store::SETTINGS_NEW);
        let memory = sys::mem_create(len as u64).map_err(|_| "no memory")?;
        sys::mem_map(&self.process, &memory, 0, len as u64, at, Access::ReadWrite)
            .map_err(|_| "not mapped")?;
        // SAFETY: the window is the thread's and mapped for `len` bytes.
        unsafe { core::ptr::copy_nonoverlapping(out.as_ptr(), at as *mut u8, len) };
        // SAFETY: nothing reads the window any more.
        let _ = unsafe { sys::mem_unmap(&self.process, at, len as u64) };
        Ok(memory)
    }

    /// The list of revocations from its extent: the text, then the block of the
    /// signature of a root. The entries that count; none when the list is bad.
    fn read_revoked(&mut self, table: &Table) -> Option<Revoked<'static>> {
        let record = table.record(store::REVOKED_SLOT);
        if record.kind != store::REVOKED_LIST {
            return None;
        }
        // SAFETY: the thread owns the buffer until it is done.
        let buffer = unsafe { &mut *REVOKED_FILE.get() };
        let bad = |why: &str| {
            rt::println!("pkgd: revocation list damaged ({why}), using the empty list");
            None
        };
        if record.length as usize > buffer.len()
            || record.length as usize <= pkgfmt::sig::BLOCK_SIZE
            || disk_read(&mut self.disk, &record, buffer).is_err()
        {
            return bad("read");
        }
        if sha256(&buffer[..record.length as usize]) != record.sha256 {
            return bad("hash");
        }
        match self.parse_list(record.length as usize) {
            Ok(list) if list.serial == record.number => Some(list),
            Ok(_) => bad("serial"),
            Err(()) => bad("signature"),
        }
    }

    /// The list of revocations in the first `len` bytes of `REVOKED_FILE`, when a root
    /// signed it.
    pub fn parse_list(&self, len: usize) -> Result<Revoked<'static>, ()> {
        // SAFETY: the buffer is static and nothing writes it while the list is parsed.
        let bytes: &'static [u8] =
            unsafe { core::slice::from_raw_parts((*REVOKED_FILE.get()).as_ptr(), len) };
        list_of(bytes, &self.roots)
    }

    /// One package of the disk: its object created and filled while the hashes
    /// run, the checks of `pkgd::verify`, the attach. The words of what refused it.
    fn load(
        &mut self,
        table: &Table,
        record: &Record,
        slot: usize,
        settings_len: usize,
    ) -> Result<Entry, &'static str> {
        // A package of the image of the same name is the one that is used.
        // SAFETY: the main thread filled the image entries before this thread began.
        let images = unsafe { &*IMAGE_ENTRIES.get() };
        if pkgd::packages::in_image(images, record.name_bytes()) {
            return Err("in the image");
        }
        // A package the table marks revoked stays out when the list that says so is not read.
        if record.flags & store::REVOKED != 0 && self.revoked.is_none() {
            return Err("key revoked");
        }
        let len = record.length;
        let memory = sys::mem_create(len).map_err(|_| "no memory")?;
        let at = window(slot);
        sys::mem_map(&self.process, &memory, 0, len, at, Access::ReadWrite)
            .map_err(|_| "not mapped")?;
        let blocks = u64::from(record.blocks);
        let mut stream = Stream::new();
        let mut covered = [0u8; 32];
        let read = self.disk.read_run(record.first, blocks, |first, bytes| {
            // SAFETY: the window holds `len` bytes and this is the thread's alone.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    (at + first as usize * BLOCK) as *mut u8,
                    bytes.len(),
                )
            };
            let last = first + (bytes.len() / BLOCK) as u64 == blocks;
            let body = if last {
                bytes.len() - BLOCK
            } else {
                bytes.len()
            };
            // The hash is of the copy in the window.
            // SAFETY: the bytes were copied to the window just above.
            let copy = unsafe {
                core::slice::from_raw_parts((at + first as usize * BLOCK) as *const u8, bytes.len())
            };
            let hashing = Stopwatch::new();
            stream.update(&copy[..body]);
            if last {
                covered = stream.clone().finish();
                stream.update(&copy[body..]);
            }
            hashing.keep(&SHA_TICKS);
        });
        // SAFETY: the unmap below is the last use of the window.
        let unmap = || {
            let _ = unsafe { sys::mem_unmap(&self.process, at, len) };
        };
        if read.is_err() {
            unmap();
            return Err("read failed");
        }
        let whole = stream.finish();
        // SAFETY: the window holds the whole file, no one writes it now.
        let bytes = unsafe { core::slice::from_raw_parts(at as *const u8, len as usize) };
        let repo = table.repo(usize::from(record.repo)).map(|(name, _)| name);
        let own = match repo {
            Some(b"stafeto") | None => None,
            Some(name) => settings_key(settings_len, name),
        };
        let official = matches!(repo, Some(b"stafeto"));
        let own_keys = own.map_or([].as_slice(), |k| core::slice::from_ref(k));
        let trust = verify::select(official, &self.roots.0[..self.roots.1], own_keys);
        let checked = check_timed(
            bytes,
            &covered,
            &whole,
            record,
            &trust,
            self.revoked.as_ref(),
            false,
        );
        let entry = match checked {
            Ok(checked) => {
                let mut entry = Entry {
                    record: *record,
                    image: false,
                    layer: 0,
                    meta_len: 0,
                    meta: [0; pkgd::packages::META_MAX],
                    trailer: [0; pkgd::packages::TRAILER],
                };
                if entry.keep(checked.meta, checked.trailer) {
                    Ok(entry)
                } else {
                    Err(Fault::BadPackage)
                }
            }
            Err(fault) => Err(fault),
        };
        unmap();
        let mut entry = entry.map_err(Fault::words)?;
        // SAFETY: the thread's.
        unsafe { (*OBJECTS.get())[slot] = Some(memory) };
        if let Err(code) = self.disk.attach(slot) {
            // SAFETY: as above.
            unsafe { (*OBJECTS.get())[slot] = None };
            return Err(match code {
                proto_pkg::CONFLICT => "conflict",
                proto_pkg::NO_SPACE => "no space for a layer",
                _ => "not attached",
            });
        }
        // SAFETY: as above.
        entry.layer = unsafe { (*LAYER_OF.get())[slot] };
        Ok(entry)
    }
}

/// The list of revocations in `bytes` (the text, then the block of a root's signature).
pub fn list_of(bytes: &'static [u8], roots: &([Key; 4], usize)) -> Result<Revoked<'static>, ()> {
    if bytes.len() <= pkgfmt::sig::BLOCK_SIZE {
        return Err(());
    }
    let (text, block) = bytes.split_at(bytes.len() - pkgfmt::sig::BLOCK_SIZE);
    let trust = Trust {
        roots: &roots.0[..roots.1],
        direct: &[],
    };
    let parsed = core::str::from_utf8(text)
        .ok()
        .and_then(|t| Revoked::parse(t).ok());
    let signed = pkgfmt::Block::parse(block).ok().and_then(|b| {
        pkgfmt::trust::verify(
            &b,
            pkgfmt::Kind::Revoked,
            &sha256(text),
            text.len() as u64,
            &trust,
            &[],
        )
        .ok()
    });
    match (parsed, signed) {
        (Some(list), Some(_)) => Ok(list),
        _ => Err(()),
    }
}

/// `verify::check` with the time of its parts kept for the report, for a package that
/// came from the disk (`manifest` false) or from a client.
pub fn check_timed<'a>(
    bytes: &'a [u8],
    covered: &[u8; 32],
    whole: &[u8; 32],
    record: &Record,
    trust: &Trust<'_>,
    revoked: Option<&Revoked<'_>>,
    manifest: bool,
) -> Result<verify::Checked<'a>, Fault> {
    let mut mark = rt::time::now();
    verify::check(
        bytes,
        covered,
        whole,
        record,
        pkgd::SERIES,
        trust,
        revoked,
        manifest,
        &mut |phase| {
            let now = rt::time::now();
            let longest = match phase {
                Phase::Parsed => &PARSE_TICKS,
                Phase::Signed => &SIGN_TICKS,
                Phase::Portion => &MANIFEST_TICKS,
            };
            longest.fetch_max(
                now.wrapping_sub(mark),
                core::sync::atomic::Ordering::Relaxed,
            );
            mark = now;
        },
    )
}

fn finish_counts(opened: &commit::Opened, disk: &Disk) {
    // SAFETY: the table is the state's, read here by the thread that wrote it.
    let free = commit::free_of(unsafe { &*TABLE.get() }, opened);
    FREE.store(free, Release);
    BLOCKS.store(disk.blocks(), Release);
    GENERATION.store(opened.superblock.generation, Release);
    rt::println!(
        "pkgd: ready, {} packages from the disk, {} from the image, {free} blocks free",
        DISK_PACKAGES.load(Acquire),
        IMAGE_PACKAGES.load(Acquire),
    );
    // What the start took, from the process's first instruction to here: the connections, the
    // images' `meta`, the disk read, the hashes and signatures, the layers (pk3b, C8).
    let took = rt::time::now().saturating_sub(BEGAN.load(Acquire));
    rt::println!(
        "pkgd: start took {} ms",
        rt::time::ticks_to_ns(took) / 1_000_000
    );
}

/// The roots of the trust of the official repository.
fn roots() -> ([Key; 4], usize) {
    let mut keys = [Key {
        name: pkgfmt::Name::new("none").expect("a name"),
        public: [0; 32],
    }; 4];
    let mut n = 0;
    for line in pkgd::ROOTS {
        if let Ok(key) = keyfile::parse_public(line)
            && n < keys.len()
        {
            keys[n] = key;
            n += 1;
        }
    }
    (keys, n)
}

/// The extent of `record` into `out`.
fn disk_read(disk: &mut Disk, record: &Record, out: &mut [u8]) -> Result<(), Failed> {
    disk.read_run(record.first, u64::from(record.blocks), |at, bytes| {
        let from = at as usize * BLOCK;
        let n = bytes.len().min(out.len().saturating_sub(from));
        out[from..from + n].copy_from_slice(&bytes[..n]);
    })
}

/// The key of the owner's repository `name` out of the settings blob, which
/// the thread read (`read_settings`), parsed again.
pub fn settings_key(len: usize, name: &[u8]) -> Option<&'static Key> {
    if len == 0 {
        return None;
    }
    // SAFETY: the blob is the worker's to read: it changes under its hand alone.
    let blob = unsafe { core::slice::from_raw_parts((*SETTINGS.get()).as_ptr(), len) };
    let key = Settings::parse(blob)
        .ok()?
        .key_of(core::str::from_utf8(name).ok()?)?;
    // SAFETY: one key of the repository being loaded at a time.
    unsafe { *KEY.get() = Some(key) };
    unsafe { (*KEY.get()).as_ref() }
}
