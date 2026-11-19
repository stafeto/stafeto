// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The worker thread: everything that waits for the disk. It connects to the disk service, picks the
//! data partition (`datafs::volume`), mounts the volume, and then takes the jobs of the main thread
//! one at a time in the order they came, runs each on the volume (`datafs::server`) and says it is
//! done. littlefs calls the disk in straight lines that wait in calls, so the main thread never waits
//! for the disk and keeps answering its clients and its heartbeat.

use crate::clock::Clock;
use crate::identity::{Identities, Notary};
use crate::shared::*;
use abi::{Access, MESSAGE_MAX, Rights, Source};
use core::sync::atomic::AtomicBool;
#[cfg(feature = "steps")]
use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::Ordering::{Acquire, Release};
use datafs::gpt::Found;
use datafs::server::Server;
use datafs::stop::Drain;
use datafs::volume::{self, Did, Refusal};
use datafs::{Device, DeviceError, SECTOR};
use proto_blk::{CELL_BYTES, CELLS, Info, Key as BlkKey, Method as Blk};
use proto_wire::{Status, Writer, long};
use rt::Handle;
use rt::handle::{Any, Channel, Process};
use rt::sys::{self, Received};

/// The thread's stack: the volume's calls and the 1 KiB buffers of a request. The stack is an object
/// of its own with no mapping on the page below it, so an overflow faults and ends the process.
const STACK_SIZE: usize = 128 * 1024;
const STACK_AT: usize = 0x58_2000_0000;
/// The thread's message buffer: the page after the main thread's.
const MSGBUF: usize = abi::INIT_MSGBUF as usize + 4096;
/// Where the thread maps the disk service's buffer.
const BUFFER_AT: usize = 0x58_1000_0000;

/// The raw handles of the main thread's, kept for this thread.
pub const HANDLES: usize = 4;
pub static RAW: [core::sync::atomic::AtomicU64; HANDLES] =
    [const { core::sync::atomic::AtomicU64::new(0) }; HANDLES];
pub const PROCESS: usize = 0;
pub const BLK_SESSION: usize = 1;
/// The notification that wakes the main thread.
pub const WAKE: usize = 2;
/// The service's channel to init, for the connections the worker makes itself (the notary session
/// and the clock).
pub const PARENT: usize = 3;
/// The channel the worker waits on for a kick; the main thread holds a notify handle to it.
pub static JOBS_CHANNEL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn view<K>(i: usize) -> core::mem::ManuallyDrop<Handle<K>> {
    Handle::borrowed(abi::Handle(RAW[i].load(Acquire)))
}

/// The level of the thread: below the disk service (39) it calls, below the clients' ceiling.
pub const LEVEL: u8 = 30;

/// The ticks the worker has spent in the reads of the disk (the request, the disk service's work
/// and the answer), the steps build: a walk's own work is its time less this.
#[cfg(feature = "steps")]
static WAITED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The handle of the worker's budget, 0 when it has none.
static WORK_BUDGET: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The ticks the worker's budget has charged so far and the overruns the kernel has counted (the
/// steps build, for the line of a walk).
#[cfg(feature = "steps")]
fn work_ran() -> (u64, u64) {
    match WORK_BUDGET.load(Acquire) {
        0 => (0, 0),
        raw => {
            let budget = Handle::<rt::handle::Budget>::borrowed(abi::Handle(raw));
            sys::budget_info(&budget).map_or((0, 0), |info| (info.ran, info.overruns))
        }
    }
}

/// The name of the worker's budget in the start data (init's table, `DATAFS_BUDGETS`).
pub const WORK: &str = "work";

pub fn start(
    process: &Handle<Process>,
    budget: Option<Handle<rt::handle::Budget>>,
) -> Result<Handle<rt::handle::Thread>, abi::Error> {
    let stack = sys::mem_create(STACK_SIZE as u64)?;
    sys::mem_map(
        process,
        &stack,
        0,
        STACK_SIZE as u64,
        STACK_AT,
        Access::ReadWrite,
    )?;
    // The thread that has the budget stands on CPU 1 (the budget's CPU, which init gives only to an
    // instance that may use it); a thread with none stands on the CPU of the loop.
    let on = if budget.is_some() { 2 } else { 0 };
    // SAFETY: the stack is the thread's alone; the page below `STACK_AT` is never mapped.
    let create = |cpu: u8| unsafe {
        sys::thread_create_on(
            process,
            work,
            STACK_AT + STACK_SIZE,
            0,
            LEVEL,
            abi::Policy::RoundRobin,
            MSGBUF,
            None,
            cpu,
        )
    };
    let (thread, budget) = match create(on) {
        Ok(thread) => (thread, budget),
        // CPU 1 is not up for this process: the thread stands on the loop's CPU and the budget,
        // which is for CPU 1, goes unused.
        Err(_) if on != 0 => (create(0)?, None),
        Err(e) => return Err(e),
    };
    // The budget is bound before the thread begins. A kernel that refuses it leaves the worker at 30
    // with no limit, as it ran before the budget: the line says so, and the service goes on (the
    // request thread's budget, which the service does not start without, holds its own 1 %).
    if let Ok(Some(kept)) = rt::budget::bind("datafs", "the worker", budget, &thread) {
        // The handle stays for the life of the service: the steps build reads the ticks the budget
        // has charged around a walk (`walk`).
        WORK_BUDGET.store(kept.raw().0, Release);
        core::mem::forget(kept);
    }
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
    /// The reads of the volume since the start, for the line of a walk.
    pub reads: u64,
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
    /// Waits for the disk call `key` and stamps the instant it completed, for the look of the request
    /// thread at the worker's progress.
    fn finish(&self, key: u64) -> Result<(), Status> {
        let done = self.finish_call(key);
        PROGRESS.store(rt::time::ticks_to_ns(rt::time::now()), Release);
        done
    }

    fn finish_call(&self, key: u64) -> Result<(), Status> {
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
        // A stop notice ends a walk at its next read, and so does a queued job when the walk may
        // give way to one: the walk only reads, nothing is lost, and the glue leaves the caches of
        // littlefs without the block of the failed read.
        if WALKING.load(Acquire) {
            if STOPPING.load(Acquire) {
                return Err(DeviceError);
            }
            if YIELD_OK.load(Acquire) && queued_job() {
                YIELDED.store(true, Release);
                return Err(DeviceError);
            }
        }
        self.reads += 1;
        for (i, chunk) in out.chunks_mut(CELL_BYTES as usize).enumerate() {
            let at = sector + (i * CELL_BYTES as usize / SECTOR) as u64;
            #[cfg(feature = "steps")]
            let asked = rt::time::now();
            let key = self
                .io(Blk::Read, (chunk.len() / SECTOR) as u32, at)
                .map_err(|_| DeviceError)?;
            self.finish(key).map_err(|_| DeviceError)?;
            #[cfg(feature = "steps")]
            WAITED.fetch_add(rt::time::now().saturating_sub(asked), Relaxed);
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
    if !ARMED.load(Acquire) {
        return false;
    }
    let before = WRITTEN.load(Acquire);
    let after = before + u64::from(*count);
    WRITTEN.store(after, Release);
    if CRASH_AT == 0 || after < CRASH_AT {
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
    if RAW[BLK_SESSION].load(Acquire) == 0 {
        return Err("no data volume on this machine");
    }
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
        reads: 0,
    })
}

type Volume = datafs::Fs<'static, datafs::Window<Disk>>;

extern "C" fn work(_: u64) -> ! {
    let process = view::<Process>(PROCESS);
    let began = rt::time::ticks_to_ns(rt::time::now());
    let volume = match connect_disk(&process) {
        Ok(disk) => open_volume(disk),
        Err(why) => {
            rt::println!("datafs: no disk: {why}");
            None
        }
    };
    let mut volume = volume;
    let mut clock = Clock::new();
    if !clock.attach(&view::<Channel>(PARENT), &process) {
        rt::println!("datafs: no clock service, the times of files are the count since boot");
    }
    mount_work(&mut volume, &mut clock);
    tell_pairs();
    if let Some(fs) = volume.as_mut() {
        // The time from the connection to the disk service to READY: the mount of littlefs and the
        // mount work (orphans, attributes, epoch). The count of the reads is the device's.
        let ms = rt::time::ticks_to_ns(rt::time::now()).saturating_sub(began) / 1_000_000;
        rt::println!(
            "datafs: ready after {ms} ms, {} reads",
            fs.device().device.reads
        );
    }
    // A volume of a later format is refused: every request answers NOT_READY.
    READY.store(volume.is_some(), Release);
    STARTING.store(false, Release);
    #[cfg(feature = "crash")]
    ARMED.store(true, Release);
    let wake = view::<Channel>(WAKE);
    let _ = sys::notify(&wake, 1);
    serve(volume, clock, &wake)
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
        Ok((fs, did, part)) => {
            // No count of the blocks in use here: that is a walk of the whole volume, which the
            // worker makes after READY, once its queue has been quiet (`idle_walk`).
            let how = match did {
                Did::Partitioned => "partition table written, data volume formatted",
                Did::Formatted => "data volume formatted",
                Did::Mounted => "data volume mounted",
                Did::Relocated => {
                    "backup partition table moved to the end of the disk, data volume mounted"
                }
            };
            rt::println!(
                "datafs: {how}, {} blocks, partition at sector {}",
                fs.blocks(),
                part.first
            );
            Some(fs)
        }
        Err(refusal) => {
            if let Refusal::Foreign(found) = refusal {
                say_foreign(&found);
            }
            rt::println!("datafs: {}", refusal.text());
            None
        }
    }
}

/// The two lines of a refusal of a disk that holds something else: where the first byte that is
/// not zero is, and whether the two sectors that a table would be in hold anything. No byte of the
/// disk is printed: on the disk of a user they are the user's data.
fn say_foreign(found: &Found) {
    let word = |zero: bool| if zero { "zero" } else { "non-zero" };
    rt::println!(
        "datafs: foreign at sector {} offset {}",
        found.sector,
        found.offset
    );
    rt::println!(
        "datafs: lba1 {} lba-last {}",
        word(found.lba1_zero),
        word(found.last_zero)
    );
}

/// The mount work, before READY and so before the first request: the clock, the hidden directory of
/// the orphans, what a stop or a cut left in it, the attributes of the volume (`Server::mount_work`:
/// a volume of version 2 gets its records, a later format is refused) and the epoch of this instance,
/// a count kept on the volume (the handles of an earlier instance answer STALE). The server starts
/// with nothing remembered of directories. Without a volume the epoch is the clock's. A conversion
/// of the volume of the first release is a few commits (three entries); READY waits for them, and
/// no request has been taken yet.
fn mount_work(volume: &mut Option<Volume>, clock: &mut Clock) {
    // SAFETY: the server is the worker's alone and lives for the life of the process.
    let server: &mut Server = unsafe { &mut *SERVER.get() };
    let mut epoch = (rt::time::now() >> 4) as u32;
    if let Some(fs) = volume.as_mut() {
        // The time of the first job, and of the records the mount work writes, is not 0.
        server.set_now(clock.now_ns());
        if datafs::server::ensure_orphans(fs).is_err() {
            rt::println!("datafs: the directory of the orphans could not be made");
        }
        match datafs::server::recover_orphans(fs) {
            Ok(done) if done.removed + done.restored + done.failed == 0 => {}
            Ok(done) => rt::println!(
                "datafs: orphans: {} removed, {} put back, {} left",
                done.removed,
                done.restored,
                done.failed
            ),
            Err(_) => rt::println!("datafs: the orphans could not be dealt with"),
        }
        match server.mount_work(fs) {
            Ok(done) if done.refused => {
                rt::println!(
                    "datafs: the volume's format is newer than this service's: left alone and refused"
                )
            }
            Ok(done) if done.converted > 0 || done.moved > 0 || !done.complete => rt::println!(
                "datafs: {} entries got attributes, {} inline files moved out{}",
                done.converted,
                done.moved,
                if done.complete {
                    ""
                } else {
                    ", more at the next mount"
                }
            ),
            Ok(_) => {}
            Err(_) => rt::println!("datafs: the attributes of the volume could not be made"),
        }
        match datafs::server::bump_epoch(fs) {
            Ok(count) => epoch = count,
            Err(_) => rt::println!("datafs: the epoch could not be kept, the clock's is used"),
        }
    }
    server.set_epoch(epoch);
}

/// The loop of the thread: wait for a kick, run the queued jobs in order, say each is done.
fn serve(mut volume: Option<Volume>, mut clock: Clock, wake: &Handle<Channel>) -> ! {
    // SAFETY: as in `mount_work`.
    let server: &mut Server = unsafe { &mut *SERVER.get() };
    // The notary session and the identity copies of the bound sessions.
    let parent = view::<Channel>(PARENT);
    let process = view::<Process>(PROCESS);
    let mut notary = Notary::new();
    let mut identities = Identities::new();
    let kicks = Handle::<Channel>::borrowed(abi::Handle(JOBS_CHANNEL.load(Acquire)));
    // The idle work: the first walk after READY, and the walk that finds the blocks removals gave
    // back. A timer on the kick channel wakes the thread when the queue has been empty for
    // `datafs::idle::QUIET_NS` (the first walk and the refresh walk alike); without one (the kernel
    // refused it) the first walk starts at once and the refresh does not happen.
    let timer = sys::timer_create(&kicks, LEVEL).ok();
    let mut idle = Idle {
        first_pending: volume.is_some(),
        last_job: rt::time::ticks_to_ns(rt::time::now()),
        refresh_failed: false,
        tries: 0,
        filled_at_mount: volume
            .as_ref()
            .is_some_and(|fs| u64::from(fs.window_state().2) == fs.blocks()),
    };
    loop {
        while let Some(i) = oldest() {
            if STOPPING.load(Acquire) && stop_decision() == Drain::GiveUp {
                break;
            }
            // SAFETY: the job is QUEUED: the main thread has finished with it and does not touch it
            // until it is DONE.
            let job = unsafe { &mut *job(i) };
            let request = &job.request[..job.request_len];
            // The time of this job, and the look at the binding of its session (rule 1): a moved
            // generation of the client's record asks Vouch again with the stored copy.
            if volume.is_some() {
                server.set_now(clock.now_ns());
                if job.kind == REQUEST && !proto_data::is_root(job.owner) {
                    let owner = job.owner;
                    datafs::vouching::before_job(
                        server,
                        owner,
                        |index| notary.generation(index),
                        || identities.get(owner).and_then(|copy| notary.vouch(copy)),
                    );
                }
            }
            #[cfg(feature = "steps")]
            let began = rt::time::now();
            match (&mut volume, job.kind) {
                // At the stop a job that would take blocks from an empty window would walk the
                // whole volume inside the 3 s of the stop (an aborted walk empties the window):
                // it gets the status the service gives every request after the notice.
                (Some(fs), REQUEST)
                    if STOPPING.load(Acquire)
                        && fs.window_state().2 == 0
                        && datafs::server::needs_blocks(request) =>
                {
                    let bytes = proto_wire::reply(Status::Kernel(abi::Error::BadState));
                    job.reply[..bytes.len()].copy_from_slice(&bytes);
                    job.reply_len = bytes.len();
                }
                // BIND, and the methods of the root channel: the worker vouches (it waits in calls).
                (Some(_), REQUEST)
                    if proto_data::is_root(job.owner) || identity_method(request) =>
                {
                    let ready = notary.ready(&parent, &process);
                    let bytes = identity_job(
                        server,
                        &mut identities,
                        ready,
                        &notary,
                        (request, job.owner, job.aux, job.carried),
                    );
                    job.reply[..bytes.len()].copy_from_slice(&bytes);
                    job.reply_len = bytes.len();
                }
                (Some(fs), REQUEST) => {
                    let reply = server.handle(fs, job.owner, job.aux, request);
                    let bytes = reply.as_bytes();
                    job.reply[..bytes.len()].copy_from_slice(bytes);
                    job.reply_len = bytes.len();
                    #[cfg(feature = "crash")]
                    report(request);
                }
                (Some(fs), _) => {
                    server.gone(fs, job.owner);
                    // The session's identity copy closes with it.
                    identities.remove(job.owner);
                    job.reply_len = 0;
                }
                (None, _) => {
                    let bytes = proto_wire::reply(Status::Unknown(NOT_READY));
                    job.reply[..bytes.len()].copy_from_slice(&bytes);
                    job.reply_len = bytes.len();
                }
            }
            #[cfg(feature = "steps")]
            if job.kind == REQUEST {
                longest_job(request, began);
            }
            // A creation that found the estimate at the cap counted the pairs: the line tells it.
            tell_pairs();
            state(i).store(DONE, Release);
            idle.last_job = rt::time::ticks_to_ns(rt::time::now());
            if STOPPING.load(Acquire) {
                STOP_JOBS.fetch_add(1, Release);
            }
            let _ = sys::notify(wake, 1);
        }
        if STOPPING.load(Acquire) {
            put_away(server, &mut volume);
            UNMOUNTED.store(true, Release);
            let _ = sys::notify(wake, 1);
            // The main thread ends the process once it has sent the replies.
            loop {
                let _ = sys::receive(&kicks);
            }
        }
        // The queue is empty. A walk (the first after the mount, or the refresh) starts after the
        // queue has been quiet for `QUIET_NS` from the end of the last job: the requests of a boot
        // come in bursts, and a walk beside them would only slow them. A job that comes during a
        // try stops it at the next read and is served; the next try waits for a quiet time again,
        // and after `datafs::idle::MAX_YIELDS` stopped tries a try runs to its end. A job that
        // needs the window itself walks inside its request.
        if let Some(fs) = volume.as_mut() {
            let first = idle.first_pending;
            if first || refresh_wanted(fs, &idle) {
                let now = rt::time::ticks_to_ns(rt::time::now());
                // No quiet time for the line of a window that is already full (a directory made
                // at mount filled it): there is no walk to wait for.
                let wait =
                    if first && (timer.is_none() || fs.window_state().2 as u64 == fs.blocks()) {
                        0
                    } else {
                        datafs::idle::quiet_wait(now, idle.last_job)
                    };
                if wait == 0 {
                    idle_walk(fs, &mut idle, first);
                    continue;
                }
                if let Some(timer) = &timer {
                    let _ = sys::timer_set(timer, now + wait);
                }
            }
        }
        let _ = sys::receive(&kicks);
    }
}

/// The longest job of each method so far, in microseconds, under the feature `steps` (the probe of
/// the steps of the loop reads the lines): a job that takes longer than the last of its method says
/// so, `datafs: job <method> longest <us> us`. The time is the worker's whole job, disk waits
/// included, from the pick-up to the reply.
#[cfg(feature = "steps")]
fn longest_job(request: &[u8], began: u64) {
    static LONGEST: [core::sync::atomic::AtomicU64; 64] =
        [const { core::sync::atomic::AtomicU64::new(0) }; 64];
    let Some(number) = request.get(..2).map(|b| u16::from_le_bytes([b[0], b[1]])) else {
        return;
    };
    let Some(method) = proto_data::Method::from_number(number) else {
        return;
    };
    let us = rt::time::ticks_to_ns(rt::time::now().saturating_sub(began)) / 1000;
    let slot = &LONGEST[usize::from(number) % LONGEST.len()];
    if us > slot.load(Relaxed) {
        slot.store(us, Relaxed);
        rt::println!("datafs: job {method:?} longest {us} us");
    }
}

/// The line of the count of pairs and directories, when the server made one since the last line:
/// `datafs: pairs N of 2048, directories M of 1024`.
fn tell_pairs() {
    // SAFETY: the server is the worker's alone.
    let server: &mut Server = unsafe { &mut *SERVER.get() };
    if let Some((tracked, counted)) = server.take_dirs_mismatch() {
        rt::println!(
            "datafs: the recount found {counted} directories where the service had followed {tracked}"
        );
    }
    if let Some((pairs, dirs)) = server.take_pairs_report() {
        rt::println!(
            "datafs: pairs {pairs} of {}, directories {dirs} of {}",
            datafs::server::PAIRS_MAX,
            datafs::server::DIRS_MAX
        );
    }
}

/// What the worker keeps for its idle walks.
struct Idle {
    /// The first walk after the mount has not been made yet.
    first_pending: bool,
    /// The instant the last job ended, in nanoseconds.
    last_job: u64,
    /// A refresh walk failed: no more of them in this instance (the disk is not answering well).
    refresh_failed: bool,
    /// The walks a queued job has stopped since the last walk that ended.
    tries: u32,
    /// The window was full when the mount work ended (a directory made at mount filled it).
    filled_at_mount: bool,
}

/// Whether a walk in the idle would help: the blocks that removals, truncations and replacing
/// renames gave back since the last walk are over a sixteenth of the volume (the free count of STATFS
/// is low by that much), or the window holds less than the volume (the allocator wrapped in the
/// middle of a request) and the free count is low.
fn refresh_wanted(fs: &Volume, idle: &Idle) -> bool {
    if idle.refresh_failed || STOPPING.load(Acquire) {
        return false;
    }
    datafs::idle::refresh_wanted(fs.blocks(), fs.freed_estimate(), fs.window_short())
}

/// How a walk ended.
enum Walked {
    Done {
        reads: u64,
        ms: u64,
    },
    /// A queued job (or the stop) ended it at a read: the window is empty and the walk is tried
    /// again later.
    Yielded {
        reads: u64,
    },
    Failed {
        reads: u64,
        ms: u64,
    },
}

/// The walk of a volume while no request waits: fills the allocator's window from the tree, so that
/// every request after it finds the free count and the free blocks with no walk of its own. It only
/// reads. The worker marks it (`WALKING`), the disk calls it makes stamp the progress the request
/// thread looks at, and a stop notice ends it at its next read, as a queued job does when `may_yield`.
fn walk(fs: &mut Volume, may_yield: bool) -> Walked {
    let reads_before = fs.device().device.reads;
    let started = rt::time::ticks_to_ns(rt::time::now());
    YIELDED.store(false, Release);
    YIELD_OK.store(may_yield, Release);
    WALKING.store(true, Release);
    #[cfg(feature = "steps")]
    let ran = work_ran();
    #[cfg(feature = "steps")]
    let waited = WAITED.load(Relaxed);
    let ok = fs.walk().is_ok();
    #[cfg(feature = "steps")]
    {
        // What the walk did besides wait for the disk: the share of its own work, on any number of
        // CPUs (the budget tells the CPU only where there is one). It is the time of the walk less the
        // time in the reads, so it counts what other threads took from the worker as its own.
        let wall = rt::time::ticks_to_ns(rt::time::now()).saturating_sub(started) / 1000;
        let wait = rt::time::ticks_to_ns(WAITED.load(Relaxed).saturating_sub(waited)) / 1000;
        rt::println!(
            "datafs: walk own work {} us of {wall} us, {wait} us in disk reads",
            wall.saturating_sub(wait)
        );
    }
    #[cfg(feature = "steps")]
    if WORK_BUDGET.load(Acquire) != 0 {
        // The CPU the worker took in the walk against the time it lasted: the share a walk takes
        // from the programs below 30 under the budget (at most 30 % at level 30). The budget counts
        // only the time at its own level: the time a thread spends lowered after an overrun is not in
        // `ran`, so the overruns of the walk are told beside it, and a share is true only when there
        // are few of them (the probe allows four for each period of the budget).
        let (after, overruns_after) = work_ran();
        let cpu = rt::time::ticks_to_ns(after.saturating_sub(ran.0)) / 1000;
        let wall = rt::time::ticks_to_ns(rt::time::now()).saturating_sub(started) / 1000;
        rt::println!(
            "datafs: walk cpu {cpu} us of {wall} us, {} overruns",
            overruns_after.saturating_sub(ran.1)
        );
    }
    WALKING.store(false, Release);
    YIELD_OK.store(false, Release);
    let ms = rt::time::ticks_to_ns(rt::time::now()).saturating_sub(started) / 1_000_000;
    let reads = fs.device().device.reads - reads_before;
    if ok {
        Walked::Done { reads, ms }
    } else if YIELDED.swap(false, Release) || STOPPING.load(Acquire) {
        Walked::Yielded { reads }
    } else {
        Walked::Failed { reads, ms }
    }
}

/// One idle walk, the first after the mount (`first`) or a refresh, with its line.
fn idle_walk(fs: &mut Volume, idle: &mut Idle, first: bool) {
    let blocks = fs.blocks();
    let used = |fs: &Volume| blocks.saturating_sub(fs.window_free());
    if first && u64::from(fs.window_state().2) == blocks {
        // The mount work or a request filled the window whole before this point.
        idle.first_pending = false;
        let who = if idle.filled_at_mount {
            "made at mount"
        } else {
            "made by a request"
        };
        rt::println!("datafs: first walk {who}, {} blocks used", used(fs));
        return;
    }
    let freed = fs.freed_estimate();
    match walk(fs, datafs::idle::walk_may_yield(first, idle.tries)) {
        Walked::Done { reads, ms } => {
            let tries = idle.tries;
            idle.tries = 0;
            let by = AbortedTries(tries);
            if first {
                idle.first_pending = false;
                rt::println!(
                    "datafs: first walk {} blocks used, {reads} reads, {ms} ms{by}",
                    used(fs)
                );
            } else {
                rt::println!(
                    "datafs: refresh walk {} blocks used, about {freed} given back, {reads} reads, {ms} ms{by}",
                    used(fs)
                );
                // The pairs and the directories are counted with the refresh: the estimate the
                // creations keep between counts starts again from the exact count.
                // SAFETY: the server is the worker's alone.
                let server: &mut Server = unsafe { &mut *SERVER.get() };
                let _ = server.recount(fs);
                tell_pairs();
            }
        }
        Walked::Yielded { reads } => {
            idle.tries += 1;
            rt::println!(
                "datafs: walk stopped for a request after {reads} reads, try {}",
                idle.tries
            );
        }
        Walked::Failed { reads, ms } => {
            if first {
                idle.first_pending = false;
                rt::println!("datafs: first walk failed after {reads} reads, {ms} ms");
            } else {
                idle.refresh_failed = true;
                rt::println!("datafs: refresh walk failed after {reads} reads, {ms} ms");
            }
        }
    }
}

/// The tail of a walk line that says how many tries a request stopped (nothing for none).
struct AbortedTries(u32);

impl core::fmt::Display for AbortedTries {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            0 => Ok(()),
            n => write!(f, ", after {n} tries a request stopped"),
        }
    }
}

/// The drain step for the jobs queued now, after the time since the stop notice.
fn stop_decision() -> Drain {
    let queued = (0..JOBS)
        .filter(|&i| state(i).load(Acquire) == QUEUED)
        .count();
    // 0 is a stop time not stored yet: no time has passed.
    let at = STOP_AT.load(Acquire);
    let since = if at == 0 {
        0
    } else {
        rt::time::now().saturating_sub(at)
    };
    datafs::stop::drain(queued, rt::time::ticks_to_ns(since))
}

/// The stop: closes what is still open, unmounts the volume and makes its writes durable.
fn put_away(server: &mut Server, volume: &mut Option<Volume>) {
    let Some(fs) = volume.as_mut() else { return };
    let failed = server.close_all(fs);
    if failed > 0 {
        rt::println!("datafs: {failed} files did not close");
    }
    if fs.unmount().is_err() {
        rt::println!("datafs: unmount failed");
    }
    if fs.device().flush().is_err() {
        rt::println!("datafs: flush failed");
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

/// Whether the request is BIND.
fn identity_method(request: &[u8]) -> bool {
    request.get(..2) == Some(&proto_data::Method::Bind.number().to_le_bytes()[..])
}

/// BIND, SESSION and VERIFY_SESSION: the vouching of the process service, which only the worker may
/// do. `call` is the request, its owner, the label the request thread made for the call and the
/// handle it brought. The reply bytes.
fn identity_job(
    server: &mut Server,
    identities: &mut Identities,
    ready: bool,
    notary: &Notary,
    call: (&[u8], u64, u64, u64),
) -> [u8; proto_wire::HEADER_LEN] {
    use proto_data::{self as p, Method};
    let (request, owner, aux, carried) = call;
    let status = |code: u32| proto_wire::reply(Status::Unknown(code));
    // The header is read whole, as the server reads it: a version other than this one is BAD_VERSION
    // and a body on a request that has none is BAD_SIZE.
    let mut reader = proto_wire::Reader::new(request);
    let header = match proto_wire::Header::read(&mut reader) {
        Ok(header) => header,
        Err(e) => return proto_wire::reply(e),
    };
    if header.version != p::VERSION {
        return proto_wire::reply(Status::BadVersion);
    }
    let method = Method::from_number(header.method);
    if matches!(method, Some(Method::Session | Method::Bind)) && reader.left() != 0 {
        return proto_wire::reply(Status::BadSize);
    }
    let root = p::is_root(owner);
    match method {
        // The root channel takes SESSION and VERIFY_SESSION and nothing else; a session takes
        // neither. VERIFY_SESSION is answered by the request thread.
        Some(Method::Session) if root => {
            vouch_and_bind(server, identities, ready, notary, true, aux, carried)
        }
        Some(Method::Bind) if !root => {
            vouch_and_bind(server, identities, ready, notary, false, owner, carried)
        }
        _ => status(p::IS_ROOT),
    }
}

/// Vouches for the identity session brought and binds `label` to the answer (`new`: a session made
/// by SESSION, bound at birth; otherwise BIND of an existing session). The worker keeps a copy of the
/// identity session of its own for as long as the session is bound.
fn vouch_and_bind(
    server: &mut Server,
    identities: &mut Identities,
    ready: bool,
    notary: &Notary,
    new: bool,
    label: u64,
    carried: u64,
) -> [u8; proto_wire::HEADER_LEN] {
    use proto_data as p;
    let status = |code: u32| proto_wire::reply(Status::Unknown(code));
    if carried == 0 {
        return proto_wire::reply(Status::BadSize);
    }
    if !ready {
        return status(p::ACCESS);
    }
    let brought = Handle::<Channel>::borrowed(abi::Handle(carried));
    let Ok(kept) = sys::handle_duplicate(&brought, Rights::NOTIFY | Rights::TRANSFER) else {
        return status(p::TABLE_FULL);
    };
    let Some(who) = notary.vouch(&kept) else {
        return status(p::ACCESS);
    };
    // An answer about a loader binds nothing (`bind_from`).
    match datafs::vouching::bind_from(server, new, label, &who) {
        Ok(()) if identities.put(label, kept) => proto_wire::reply(Status::Ok),
        Ok(()) => {
            server.set_binding(label, datafs::binding::Binding::Unbound);
            status(p::TABLE_FULL)
        }
        Err(Status::Unknown(code)) => status(code),
        Err(_) => status(p::INVALID),
    }
}
