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
const STACK_SIZE: usize = 96 * 1024;
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

/// The loop of the thread: wait for a kick, run the queued jobs in order, say each is done.
fn serve(mut volume: Option<Volume>, wake: &Handle<Channel>) -> ! {
    // The mount work, before the first request: the hidden directory of the orphans, what a stop or
    // a cut left in it, and the epoch of this instance, a count kept on the volume (the handles of
    // an earlier instance answer STALE). Without a volume the epoch is the clock's.
    let mut epoch = (rt::time::now() >> 4) as u32;
    if let Some(fs) = volume.as_mut() {
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
        match datafs::server::bump_epoch(fs) {
            Ok(count) => epoch = count,
            Err(_) => rt::println!("datafs: the epoch could not be kept, the clock's is used"),
        }
    }
    let mut server = Server::with_epoch(epoch);
    // The clock, the notary session and the identity copies of the bound sessions. The clock and
    // the volume's attributes (`Server::mount_work`) are set up before the first request: the
    // requests that came meanwhile wait in the table of jobs, which the main thread fills.
    let mut clock = Clock::new();
    let parent = view::<Channel>(PARENT);
    let process = view::<Process>(PROCESS);
    if !clock.attach(&parent, &process) {
        rt::println!("datafs: no clock service, the times of files are the count since boot");
    }
    let mut notary = Notary::new();
    let mut identities = Identities::new();
    if let Some(fs) = volume.as_mut() {
        server.set_now(clock.now_ns());
        match server.mount_work(fs) {
            Ok(done) if done.refused => rt::println!(
                "datafs: the volume's format is above this service's, left alone and refused"
            ),
            Ok(done) if done.converted > 0 || !done.complete => rt::println!(
                "datafs: {} entries got attributes{}",
                done.converted,
                if done.complete {
                    ""
                } else {
                    ", more at the next mount"
                }
            ),
            Ok(_) => {}
            Err(_) => rt::println!("datafs: the attributes of the volume could not be made"),
        }
    }
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
                        &mut server,
                        owner,
                        |index| notary.generation(index),
                        || identities.get(owner).and_then(|copy| notary.vouch(copy)),
                    );
                }
            }
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
                        &mut server,
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
            state(i).store(DONE, Release);
            idle.last_job = rt::time::ticks_to_ns(rt::time::now());
            if STOPPING.load(Acquire) {
                STOP_JOBS.fetch_add(1, Release);
            }
            let _ = sys::notify(wake, 1);
        }
        if STOPPING.load(Acquire) {
            put_away(&mut server, &mut volume);
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
/// renames gave back since the last walk are over a sixteenth of the volume and the window's free
/// bits are under a sixteenth too (a walk inside a request is then about to happen, and the free
/// count of STATFS is low by what was given back); or the window holds less than the volume (the
/// allocator wrapped in the middle of a request) and the free count is low.
fn refresh_wanted(fs: &Volume, idle: &Idle) -> bool {
    if idle.refresh_failed || STOPPING.load(Acquire) {
        return false;
    }
    let sixteenth = fs.blocks() / 16;
    fs.window_short() || (fs.freed_estimate() > sixteenth && fs.window_free() < sixteenth)
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
    let ok = fs.walk().is_ok();
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
    match walk(fs, datafs::idle::may_yield(idle.tries)) {
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
    let method = request
        .get(..2)
        .and_then(|b| Method::from_number(u16::from_le_bytes([b[0], b[1]])));
    let root = p::is_root(owner);
    match method {
        // The root channel takes SESSION and VERIFY_SESSION and nothing else; a session takes
        // neither (the server answers it, so only the root gets here with them).
        Some(Method::Session | Method::VerifySession) if !root => status(p::IS_ROOT),
        Some(Method::Session | Method::VerifySession) => {
            if method == Some(Method::VerifySession) {
                return if server.is_live(aux) {
                    proto_wire::reply(Status::Ok)
                } else {
                    status(p::BAD_HANDLE)
                };
            }
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
    use datafs::vouching::vouched_from;
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
    let vouched = vouched_from(&who);
    let bound = if new {
        server.bind_new(label, vouched)
    } else {
        server.bind(label, vouched)
    };
    match bound {
        Ok(()) if identities.put(label, kept) => proto_wire::reply(Status::Ok),
        Ok(()) => {
            server.set_binding(label, datafs::binding::Binding::Unbound);
            status(p::TABLE_FULL)
        }
        Err(Status::Unknown(code)) => status(code),
        Err(_) => status(p::INVALID),
    }
}
