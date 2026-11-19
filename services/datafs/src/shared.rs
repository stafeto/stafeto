// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the two threads share: the table of jobs. The main thread (the loop of the service) fills a
//! free job with a request and marks it QUEUED; the worker thread takes the oldest QUEUED job, runs it
//! on the volume, fills the reply and marks it DONE; the main thread sends the reply and frees the job.
//! Each state change is a release store and each look at it an acquire load, so the thread that sees a
//! state sees the bytes that went before it.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use proto_data as p;

/// A static the threads share by the rules above.
pub struct Shared<T>(UnsafeCell<T>);
// SAFETY: the rules above give each access one thread at a time.
unsafe impl<T> Sync for Shared<T> {}

impl<T> Shared<T> {
    pub const fn new(value: T) -> Shared<T> {
        Shared(UnsafeCell::new(value))
    }

    pub fn get(&self) -> *mut T {
        self.0.get()
    }
}

/// The requests in flight at once, and the notice of a session that went.
pub const JOBS: usize = 12;

/// The jobs one session may have in flight at once: no session fills the table alone.
pub const SESSION_JOBS: usize = 4;

/// The jobs only the sessions of native clients may take: the last of the table, so that the
/// sessions of the process trees (many, each with its share) never leave `datakey` with no job.
pub const NATIVE_JOBS: usize = 4;

pub const FREE: u8 = 0;
pub const QUEUED: u8 = 1;
pub const DONE: u8 = 2;

/// What a job is: a request of a session, or the close of what a session held.
pub const REQUEST: u8 = 0;
pub const GONE: u8 = 1;

pub struct Job {
    pub state: AtomicU8,
    /// The order of arrival: the worker takes the lowest.
    pub ticket: AtomicU64,
    /// The instant the job was queued, in nanoseconds (`datafs::watch`).
    pub queued_at: AtomicU64,
    pub kind: u8,
    pub owner: u64,
    /// The label the request thread made for the call (CLONE, EXPORT) or read from the pass the call
    /// brought (ADOPT); 0 for the rest.
    pub aux: u64,
    /// The raw handle of the identity session (BIND, SESSION) or the offered session
    /// (VERIFY_SESSION) the request brought, which the request thread keeps open until the job is
    /// done; 0 for the rest.
    pub carried: u64,
    pub request_len: usize,
    pub request: [u8; abi::MESSAGE_MAX],
    pub reply_len: usize,
    pub reply: [u8; abi::MESSAGE_MAX],
}

impl Job {
    const fn new() -> Job {
        Job {
            state: AtomicU8::new(FREE),
            ticket: AtomicU64::new(0),
            queued_at: AtomicU64::new(0),
            kind: REQUEST,
            owner: 0,
            aux: 0,
            carried: 0,
            request_len: 0,
            request: [0; abi::MESSAGE_MAX],
            reply_len: 0,
            reply: [0; abi::MESSAGE_MAX],
        }
    }
}

pub static TABLE: Shared<[Job; JOBS]> = Shared::new([const { Job::new() }; JOBS]);

/// The jobs, through a raw pointer so that the two threads never hold a reference to the whole
/// table at once: each looks only at the jobs its state names.
pub fn job(i: usize) -> *mut Job {
    // SAFETY: `i` is within the table; the pointer is not dereferenced here.
    unsafe { core::ptr::addr_of_mut!((*TABLE.get())[i]) }
}

pub fn state(i: usize) -> &'static AtomicU8 {
    // SAFETY: the atomic is read and written through shared references only.
    unsafe { &(*job(i)).state }
}

/// True until the worker has opened the volume or given up.
pub static STARTING: AtomicBool = AtomicBool::new(true);
/// The volume is mounted: requests may be served.
pub static READY: AtomicBool = AtomicBool::new(false);

/// The stop notice came: no new request is taken, the worker drains its queue. The stuck-job
/// watch does not fire while this is set (`datafs::watch::must_exit`): a drain that waits on the
/// disk is the stop at work. The disk calls of the stop still stamp `PROGRESS`.
pub static STOPPING: AtomicBool = AtomicBool::new(false);
/// The counter tick of the stop notice, stored before `STOPPING`; 0 means not yet.
pub static STOP_AT: AtomicU64 = AtomicU64::new(0);
/// The jobs the worker finished since the stop notice.
pub static STOP_JOBS: AtomicU64 = AtomicU64::new(0);
/// The worker put the volume away.
pub static UNMOUNTED: AtomicBool = AtomicBool::new(false);

/// The worker is in a walk of the volume (the first one after the mount, or a refresh in the idle):
/// it runs for as long as the volume needs, and every disk call of it stamps `PROGRESS`, so the
/// look at the worker (`datafs::watch`) sees steady progress while it lasts. A stop notice ends it
/// at its next disk call.
pub static WALKING: AtomicBool = AtomicBool::new(false);
/// The walk in progress may give way to a job that is queued: its next read fails, the job is
/// served, and the walk is tried again after the queue has been quiet for a while (`YIELDED` says it was
/// this).
pub static YIELD_OK: AtomicBool = AtomicBool::new(false);
pub static YIELDED: AtomicBool = AtomicBool::new(false);

/// A job is QUEUED: the main thread has queued it and the worker has not taken it.
pub fn queued_job() -> bool {
    (0..JOBS).any(|i| state(i).load(Ordering::Acquire) == QUEUED)
}

/// The server's tables (descriptions, open files, sessions, the memory of directories): about 50 KiB,
/// too much for the worker's stack, which overflowed when they lived there. The worker's alone.
pub static SERVER: Shared<datafs::server::Server> = Shared::new(datafs::server::Server::new());

/// The memory of the volume: littlefs's state, its caches and the buffers of the open files.
pub static STORAGE: Shared<datafs::Storage> = Shared::new(datafs::Storage::new());

/// The instant, in nanoseconds, of the last disk call the worker completed (`datafs::watch`).
pub static PROGRESS: AtomicU64 = AtomicU64::new(0);

/// The number of the next request.
pub static TICKET: AtomicU64 = AtomicU64::new(1);

pub fn next_ticket() -> u64 {
    TICKET.fetch_add(1, Ordering::Relaxed)
}

/// The label of the notification the worker gives the main thread (a job is done), and of the kick
/// the main thread gives the worker (a job is queued).
pub const LABEL_DONE: u64 = 0x4446_0001;
pub const LABEL_KICK: u64 = 1;

/// The status of a reply for a request the service cannot take now.
pub fn busy() -> proto_wire::Status {
    proto_wire::Status::Kernel(abi::Error::WouldBlock)
}

pub const NOT_READY: u32 = p::NOT_READY;
