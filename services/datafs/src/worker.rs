// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The worker thread: everything that waits for the disk. It connects to the disk service, picks the
//! data partition (`datafs::volume`), mounts the volume, and then takes the jobs of the main thread
//! one at a time in the order they came, runs each on the volume (`datafs::server`) and says it is
//! done. littlefs calls the disk in straight lines that wait in calls, so the main thread never waits
//! for the disk and keeps answering its clients and its heartbeat.

use crate::shared::*;
use abi::{Access, MESSAGE_MAX, Rights, Source};
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering::{Acquire, Release};
use datafs::server::Server;
use datafs::volume::{self, Did};
use datafs::{Device, DeviceError, SECTOR};
use proto_blk::{CELL_BYTES, CELLS, Info, Key as BlkKey, Method as Blk};
use proto_wire::{Status, Writer, long};
use rt::Handle;
use rt::handle::{Any, Channel, Process};
use rt::sys::{self, Received};

/// The thread's stack: the volume's calls and the 1 KiB buffers of a request. The stack is an object
/// of its own with no mapping on the page below it, so an overflow faults and ends the process.
const STACK_SIZE: usize = 96 * 1024;
const STACK_AT: usize = 0x58_2000_0000;
/// The thread's message buffer: the page after the main thread's.
const MSGBUF: usize = abi::INIT_MSGBUF as usize + 4096;
/// Where the thread maps the disk service's buffer.
const BUFFER_AT: usize = 0x58_1000_0000;

/// The raw handles of the main thread's, kept for this thread.
pub const HANDLES: usize = 3;
pub static RAW: [core::sync::atomic::AtomicU64; HANDLES] =
    [const { core::sync::atomic::AtomicU64::new(0) }; HANDLES];
pub const PROCESS: usize = 0;
pub const BLK_SESSION: usize = 1;
/// The notification that wakes the main thread.
pub const WAKE: usize = 2;
/// The channel the worker waits on for a kick; the main thread holds a notify handle to it.
pub static JOBS_CHANNEL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn view<K>(i: usize) -> core::mem::ManuallyDrop<Handle<K>> {
    Handle::borrowed(abi::Handle(RAW[i].load(Acquire)))
}

/// The level of the thread: below the disk service (39) it calls, below the clients' ceiling.
pub const LEVEL: u8 = 30;

pub fn start(process: &Handle<Process>) -> Result<Handle<rt::handle::Thread>, abi::Error> {
    let stack = sys::mem_create(STACK_SIZE as u64)?;
    sys::mem_map(
        process,
        &stack,
        0,
        STACK_SIZE as u64,
        STACK_AT,
        Access::ReadWrite,
    )?;
    // SAFETY: the stack is the thread's alone; the page below `STACK_AT` is never mapped.
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

/// How long the thread waits for the disk service to answer one request it took: a read or a write
/// of 16 KiB or a flush takes milliseconds; ten seconds is a service that is gone.
const DISK_WAIT_NS: u64 = 10_000_000_000;

/// The point the build for the crash tests stops at (`STAFETO_DATAFS_CRASH_AT`), 0 for none.
#[cfg(feature = "crash")]
const CRASH_AT: u64 = match option_env!("STAFETO_DATAFS_CRASH_AT") {
    Some(text) => {
        let (bytes, mut n, mut i) = (text.as_bytes(), 0u64, 0);
        while i < bytes.len() {
            n = n * 10 + (bytes[i] - b'0') as u64;
            i += 1;
        }
        n
    }
    None => 0,
};

/// The sectors written since the volume came up (the crash build counts them).
#[cfg(feature = "crash")]
static WRITTEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The crash build counts from the moment the volume is ready.
#[cfg(feature = "crash")]
static ARMED: AtomicBool = AtomicBool::new(false);

/// The disk service as a `Device`: one run of at most a cell at a time, with its own channel for the
/// notifications of the operations.
pub struct Disk {
    session: core::mem::ManuallyDrop<Handle<Channel>>,
    own: Handle<Channel>,
    timer: Handle<rt::handle::Timer>,
    /// The disk service did not answer in time: a request may still be with it and its cell will be
    /// written whenever it answers, so no request goes to it any more.
    dead: AtomicBool,
    notify: Handle<Channel>,
    sectors: u64,
    pub flush: bool,
}

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

    fn io(&self, method: Blk, count: u32, sector: u64) -> Result<u64, Status> {
        let mut w = Writer::new();
        method.header().write(&mut w)?;
        w.u32(0)?;
        w.u32(count)?;
        w.u64(sector)?;
        match self.call(w.as_bytes(), None)? {
            Got::Wait(key) => Ok(key),
            _ => Err(Status::BadSize),
        }
    }

    /// TAKE of `key` until it is READY, with a deadline for the wait.
    fn finish(&self, key: u64) -> Result<(), Status> {
        let mut w = Writer::new();
        BlkKey { key }.write(Blk::Take, &mut w)?;
        let mut notify =
            Some(sys::handle_duplicate(&self.notify, Rights::NOTIFY | Rights::TRANSFER)?.erase());
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
                    } if label == 1 && bits & 1 != 0 => break,
                    // An expiry before the deadline is a stale one of an earlier wait.
                    Received::Notification {
                        source: Source::Timer,
                        ..
                    } if rt::time::reached(until) => {
                        self.dead.store(true, Release);
                        rt::println!("datafs: the disk service did not answer in time");
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

    fn cell() -> *mut u8 {
        BUFFER_AT as *mut u8
    }
}

impl Device for Disk {
    fn sectors(&self) -> u64 {
        self.sectors
    }

    fn read(&mut self, sector: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        for (i, chunk) in out.chunks_mut(CELL_BYTES as usize).enumerate() {
            let at = sector + (i * CELL_BYTES as usize / SECTOR) as u64;
            let key = self
                .io(Blk::Read, (chunk.len() / SECTOR) as u32, at)
                .map_err(|_| DeviceError)?;
            self.finish(key).map_err(|_| DeviceError)?;
            // SAFETY: cell 0 of the mapped buffer; READY: the disk service wrote it, and no
            // request of it is in flight.
            unsafe {
                core::ptr::copy_nonoverlapping(Self::cell(), chunk.as_mut_ptr(), chunk.len())
            };
        }
        Ok(())
    }

    fn write(&mut self, sector: u64, data: &[u8]) -> Result<(), DeviceError> {
        for (i, chunk) in data.chunks(CELL_BYTES as usize).enumerate() {
            let at = sector + (i * CELL_BYTES as usize / SECTOR) as u64;
            #[cfg_attr(not(feature = "crash"), allow(unused_mut))]
            let mut count = (chunk.len() / SECTOR) as u32;
            #[cfg(feature = "crash")]
            let stop = crash_budget(&mut count);
            // SAFETY: cell 0 of the mapped buffer; no request of it is in flight.
            unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), Self::cell(), chunk.len()) };
            if count > 0 {
                let key = self.io(Blk::Write, count, at).map_err(|_| DeviceError)?;
                self.finish(key).map_err(|_| DeviceError)?;
            }
            #[cfg(feature = "crash")]
            if stop {
                crash_now();
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), DeviceError> {
        match self.call(&Blk::Flush.header().bytes(), None) {
            Ok(Got::Wait(key)) => self.finish(key).map_err(|_| DeviceError),
            _ => Err(DeviceError),
        }
    }
}

/// The sectors of this write that may still go to the disk before the crash point, lowered in
/// `count`; true when the point falls in this write (it is torn at the sector).
// The point is a constant of the build, 0 in a build that names none.
#[allow(clippy::absurd_extreme_comparisons)]
#[cfg(feature = "crash")]
fn crash_budget(count: &mut u32) -> bool {
    if CRASH_AT == 0 || !ARMED.load(Acquire) {
        return false;
    }
    let before = WRITTEN.load(Acquire);
    let after = before + u64::from(*count);
    WRITTEN.store(after, Release);
    if after < CRASH_AT {
        return false;
    }
    *count = CRASH_AT.saturating_sub(before) as u32;
    true
}

/// The build for the crash tests prints the line of its point and stops there for good: the host
/// kills the machine on the line and starts it again on the same disk.
#[cfg(feature = "crash")]
fn crash_now() -> ! {
    rt::println!("datafs: crash point {}", CRASH_AT);
    let held = sys::channel_create(LEVEL);
    loop {
        if let Ok(channel) = &held {
            let _ = sys::receive(channel);
        }
    }
}

/// The disk service: the buffer of four cells and its INFO.
fn connect_disk(process: &Handle<Process>) -> Result<Disk, &'static str> {
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
    if info.block as usize != SECTOR {
        return Err("the disk has blocks of other than 512 bytes");
    }
    let own = sys::channel_create(LEVEL).map_err(|_| "no channel")?;
    let notify = sys::handle_label(
        &own,
        Rights::NOTIFY | Rights::TRANSFER | Rights::DUPLICATE,
        1,
        LEVEL,
    )
    .map_err(|_| "no notification")?;
    let timer = sys::timer_create(&own, LEVEL).map_err(|_| "no timer")?;
    let _ = CELLS;
    Ok(Disk {
        session,
        notify,
        own,
        timer,
        dead: AtomicBool::new(false),
        sectors: info.sectors,
        flush: info.flush(),
    })
}

type Volume = datafs::Fs<'static, datafs::Window<Disk>>;

extern "C" fn work(_: u64) -> ! {
    let process = view::<Process>(PROCESS);
    let volume = match connect_disk(&process) {
        Ok(disk) => open_volume(disk),
        Err(why) => {
            rt::println!("datafs: no disk: {why}");
            None
        }
    };
    READY.store(volume.is_some(), Release);
    STARTING.store(false, Release);
    #[cfg(feature = "crash")]
    ARMED.store(true, Release);
    let wake = view::<Channel>(WAKE);
    let _ = sys::notify(&wake, 1);
    serve(volume, &wake)
}

fn open_volume(disk: Disk) -> Option<Volume> {
    if !disk.flush {
        rt::println!("datafs: the disk has no flush, no data volume");
        return None;
    }
    // The GUIDs of a new table come from the clock: unique enough for a table that is written once.
    let seed = rt::time::now() ^ disk.sectors;
    // SAFETY: the storage is the worker's alone, and lives for the life of the process.
    let storage = unsafe { &mut *STORAGE.get() };
    match volume::open(disk, storage, seed) {
        Ok((mut fs, did, part)) => {
            let used = fs.used_blocks().unwrap_or(0);
            let how = match did {
                Did::Partitioned => "partition table written, data volume formatted",
                Did::Formatted => "data volume formatted",
                Did::Mounted => "data volume mounted",
            };
            rt::println!(
                "datafs: {how}, {} blocks, {used} in use, partition at sector {}",
                fs.blocks(),
                part.first
            );
            Some(fs)
        }
        Err(refusal) => {
            rt::println!("datafs: {}", refusal.text());
            None
        }
    }
}

/// The loop of the thread: wait for a kick, run the queued jobs in order, say each is done.
fn serve(mut volume: Option<Volume>, wake: &Handle<Channel>) -> ! {
    let mut server = Server::new();
    let kicks = Handle::<Channel>::borrowed(abi::Handle(JOBS_CHANNEL.load(Acquire)));
    loop {
        while let Some(i) = oldest() {
            // SAFETY: the job is QUEUED: the main thread has finished with it and does not touch it
            // until it is DONE.
            let job = unsafe { &mut *job(i) };
            let request = &job.request[..job.request_len];
            match (&mut volume, job.kind) {
                (Some(fs), REQUEST) => {
                    let reply = server.handle(fs, job.owner, request);
                    let bytes = reply.as_bytes();
                    job.reply[..bytes.len()].copy_from_slice(bytes);
                    job.reply_len = bytes.len();
                    #[cfg(feature = "crash")]
                    report(request);
                }
                (Some(fs), _) => {
                    server.gone(fs, job.owner);
                    job.reply_len = 0;
                }
                (None, _) => {
                    let bytes = proto_wire::reply(Status::Unknown(NOT_READY));
                    job.reply[..bytes.len()].copy_from_slice(&bytes);
                    job.reply_len = bytes.len();
                }
            }
            state(i).store(DONE, Release);
            let _ = sys::notify(wake, 1);
        }
        let _ = sys::receive(&kicks);
    }
}

/// The crash build tells how many sectors a request wrote, on a STATFS: the host asks the probe's
/// last call for it to choose its crash points.
#[cfg(feature = "crash")]
fn report(request: &[u8]) {
    use proto_data::Method;
    if request.get(..2) == Some(&Method::Statfs.number().to_le_bytes()[..]) {
        rt::println!("datafs: written {}", WRITTEN.load(Acquire));
    }
}

/// The oldest QUEUED job.
fn oldest() -> Option<usize> {
    let mut best: Option<(u64, usize)> = None;
    for i in 0..JOBS {
        if state(i).load(Acquire) == QUEUED {
            // SAFETY: a QUEUED job's ticket is set before the state is released.
            let ticket = unsafe { (*job(i)).ticket.load(Acquire) };
            if best.is_none_or(|(t, _)| ticket < t) {
                best = Some((ticket, i));
            }
        }
    }
    best.map(|(_, i)| i)
}
