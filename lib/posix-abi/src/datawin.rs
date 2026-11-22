// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's window for the large calls on `/data`: a memory object of `WINDOW_BYTES`
//! (128 KiB, 32 pages) of the process's own quota, mapped as the *data window piece* of the memory
//! map (posix_map::Kind::DataWindow) and sent to the data file service with WINDOW. It holds
//! `CELLS` cells of `CELL_BYTES`. A `read`, `pread`, `write` or `pwrite` of more than one message
//! takes a cell and moves its bytes in parts of the cell (READ_INTO, PREAD_INTO, WRITE_FROM,
//! PWRITE_FROM); the program's own thread copies into the cell before a part and out of it after
//! the reply, and the service maps the cell for the one job. (`data::readv` and `data::writev` use
//! the same parts but have no caller yet: the C library's `readv` and `writev` wait for a hook,
//! and nothing is promised for them.)
//!
//! * The first large call asks for the window; the other threads go by messages (`INLINE` parts)
//!   meanwhile. A refusal (no memory, no room in the map, a service that refuses WINDOW with
//!   INVALID four times in a row) is final until `exec`. A WINDOW that fails for another reason
//!   (a busy or restarting service) sends that call by messages and counts for nothing.
//! * The window is registered with the service for one session: `REGISTERED` is the session the
//!   service holds it for. A session of a new instance (the service restarted) differs, so the
//!   next call registers again, and a part that nevertheless finds the service without a window
//!   (NO_WINDOW) registers once and sends the part again before it goes by messages. The wait of
//!   a thread for another's WINDOW (`claim`) is bounded (2,000 turns, then messages).
//! * A cell is held from the first part of a call to the last, so a second thread that makes a
//!   large call takes the other cell, or goes by messages when both are taken. A call never waits
//!   for a cell, and a call from a signal handler never takes one.
//! * Every call under way has a record (`Live`) in a table, and the record holds its cell
//!   (`posix_fs::data::CellBook`): the cell goes back by one swap of the record, whoever does it
//!   first (the call's end, the hook of a jump, the exit of the thread), so it never goes back
//!   twice. A `siglongjmp` out of a handler that interrupted a call leaves the frame of the call:
//!   the hook of the jump (`abandon`, from `shared::jump_mark`) gives the cell back and the lease
//!   up (RELEASE, a blocking round trip). No request of the call is outstanding at a jump: a
//!   signal is delivered before the service takes a request, never while the layer waits for a
//!   reply, so the service no longer writes into the cell. The exit of a thread (`pthread_exit`
//!   from a handler that interrupted a call) does the same for all its records
//!   (`relibc::exit_thread`). A deferred cancellation acts only at the C boundary after the call
//!   has returned and dropped its cell, and the waits inside the calls are no points of
//!   cancellation (`sleep::pause`).
//! * A lease of a part belongs to the record only once its reply came (`Live::set_lease`). The
//!   entries of signal handlers are deferred from the send of a part to that record
//!   (`data::call_held`): a signal that came while the layer waited for the reply would otherwise
//!   run its handler on the return from the send, and a jump out of it would leave the lease to
//!   run out on its timer (`LEASE_GAP`, 1 s; `probe_leases_unrecorded` counts such jumps). A jump
//!   in the few instructions between taking a cell and recording it still loses the cell to the
//!   process until `exec`.
//! * A large call from a signal handler on a file whose lease the interrupted call holds waits for
//!   that lease (up to `LEASE_CLIENT_MAX`, 1 s, when it is waited for) and the interrupted call
//!   returns short with the lapse (`LAPSED`); the handler's call goes by messages (no cell).
//! * A forked child has neither the piece (`Map::inherited` leaves it out) nor the cells, and asks
//!   for its own; its session is a clone the service knows nothing of. A fork inside a handler
//!   whose child returns into the call finds the generation word changed (`generation`) and the
//!   call goes on by messages, touching no cell. An exec'd image starts without a window, and the
//!   service lets the old one go with the session's UNBIND.
//! * The state and the cells are atomic words; no lock of the layer is held over a request. The
//!   object is made and mapped under the lock of the heap alone.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use entries::{Frame, nested};
use posix_fs::data::CellBook;
use proto_data::{CELL_BYTES, CELLS, WINDOW_BYTES};
use rt::handle::{Handle, Memory};
use rt::sys;

const _: () = assert!(WINDOW_BYTES == CELLS * CELL_BYTES && CELLS <= 8);

// ---------------------------------------------------------------- the counters of the probes

/// The parts that went through a cell.
static CELL_PARTS: AtomicU64 = AtomicU64::new(0);
/// The parts that went in the message (`INLINE`).
static INLINE_PARTS: AtomicU64 = AtomicU64::new(0);
/// The calls cut short because their lease lapsed.
static LAPSED: AtomicU64 = AtomicU64::new(0);
/// The parts the service ran without a lease (a limit).
static UNLEASED: AtomicU64 = AtomicU64::new(0);
/// The parts sent again after NO_WINDOW and a new WINDOW.
static RETRIES: AtomicU64 = AtomicU64::new(0);

/// The RELEASEs of leases that were not sent or got no answer.
static RELEASES_DROPPED: AtomicU64 = AtomicU64::new(0);

/// The calls a jump or an exit ended after a part was sent and before the lease of its answer was
/// recorded (the lease then runs out on its timer; the entries deferred around the send of a part
/// keep this at 0).
static LEASES_UNRECORDED: AtomicU64 = AtomicU64::new(0);

/// How many calls were ended with a part sent and its lease not yet recorded.
pub fn probe_leases_unrecorded() -> u64 {
    LEASES_UNRECORDED.load(Ordering::Relaxed)
}

/// How many RELEASEs of leases failed (the lease then runs out on its timer).
pub fn probe_releases_dropped() -> u64 {
    RELEASES_DROPPED.load(Ordering::Relaxed)
}

pub(crate) fn count_release_dropped() {
    RELEASES_DROPPED.fetch_add(1, Ordering::Relaxed);
}

/// How many parts went through a cell so far.
pub fn probe_cell_parts() -> u64 {
    CELL_PARTS.load(Ordering::Relaxed)
}

/// How many parts went in the message (`INLINE`) so far.
pub fn probe_inline_parts() -> u64 {
    INLINE_PARTS.load(Ordering::Relaxed)
}

/// How many calls came back short because the service let their lease lapse.
pub fn probe_lapsed() -> u64 {
    LAPSED.load(Ordering::Relaxed)
}

/// How many parts the service ran with no lease.
pub fn probe_unleased() -> u64 {
    UNLEASED.load(Ordering::Relaxed)
}

/// How many parts were sent again after the service said NO_WINDOW and the window was sent anew.
pub fn probe_window_retries() -> u64 {
    RETRIES.load(Ordering::Relaxed)
}

pub(crate) fn count_cell_part() {
    CELL_PARTS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn count_inline_part() {
    INLINE_PARTS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn count_lapsed() {
    LAPSED.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn count_unleased(n: u32) {
    UNLEASED.fetch_add(u64::from(n), Ordering::Relaxed);
}

pub(crate) fn count_retry() {
    RETRIES.fetch_add(1, Ordering::Relaxed);
}

// ---------------------------------------------------------------- the window

/// The states of the window; any other value is `Ready`, the address of the piece (a page, never
/// below 4 KiB).
const ABSENT: usize = 0;
const ASKING: usize = 1;
const REFUSED: usize = 2;

static STATE: AtomicUsize = AtomicUsize::new(ABSENT);
/// The handle of the object, which the map of the layer owns; valid while `STATE` is `Ready`.
static OBJECT: AtomicU64 = AtomicU64::new(0);
/// The cells and the cell each record of `LIVE` holds.
static BOOK: CellBook<LIVE_SLOTS> = CellBook::new();
/// Counts the forks of the process: a value a call noted before a fork differs in the child.
static GENERATION: AtomicU32 = AtomicU32::new(0);
/// The session (its raw handle) the service holds the window for, 0 for none. A session parked
/// after its service went is never closed, so its number is never the next session's.
static REGISTERED: AtomicU64 = AtomicU64::new(0);
/// The thread that sends WINDOW now (its owner word), 0 for none.
static REGISTERING: AtomicU64 = AtomicU64::new(0);
/// The WINDOWs in a row the service refused or lost.
static FAILS: AtomicU32 = AtomicU32::new(0);

/// How many WINDOWs in a row may fail before the window is given up for good.
const FAILS_MAX: u32 = 4;
/// The turns a thread waits for another's WINDOW before it goes by messages.
const WAIT: u32 = 2000;

/// A cell a call holds; it goes back when the value drops, through the record of the call (the
/// record is cleared first, then the cell is free). A value that outlives a fork (a child that
/// returns into the call) gives nothing back.
pub(crate) struct Cell {
    index: u32,
    base: usize,
    slot: usize,
    generation: u32,
}

impl Cell {
    /// The number the part's `cell` field carries.
    pub(crate) fn index(&self) -> u32 {
        self.index
    }

    fn address(&self) -> *mut u8 {
        (self.base + self.index as usize * CELL_BYTES) as *mut u8
    }

    /// The first `n` bytes of the cell, for the caller to fill before the part that carries them.
    pub(crate) fn bytes_mut(&mut self, n: usize) -> &mut [u8] {
        debug_assert!(n <= CELL_BYTES);
        // SAFETY: the cell is this value's alone (its bit is taken), the piece stays mapped until
        // the process ends or execs, and no part is outstanding that the service could read it
        // for.
        unsafe { core::slice::from_raw_parts_mut(self.address(), n) }
    }

    /// The first `n` bytes of the cell, once the service has filled them.
    pub(crate) fn view(&self, n: usize) -> &[u8] {
        debug_assert!(n <= CELL_BYTES);
        // SAFETY: as for `bytes_mut`; the service wrote the bytes before it replied.
        unsafe { core::slice::from_raw_parts(self.address(), n) }
    }
}

impl Drop for Cell {
    fn drop(&mut self) {
        if self.generation == generation() {
            BOOK.release(self.slot);
        }
    }
}

/// The forks of this process so far, as the call that notes it before a fork can compare.
pub(crate) fn generation() -> u32 {
    GENERATION.load(Ordering::Acquire)
}

/// The window is asked for by one thread: the object and its piece. The address of the piece, or
/// None (refused, or another thread asks).
pub(crate) fn base() -> Option<usize> {
    match STATE.load(Ordering::Acquire) {
        ABSENT => ask(),
        ASKING | REFUSED => None,
        base => Some(base),
    }
}

fn ask() -> Option<usize> {
    if STATE
        .compare_exchange(ABSENT, ASKING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return None;
    }
    match make() {
        Ok(base) => {
            // From now on the layer notes the signal handlers (`handlers`).
            crate::handlers::track();
            BOOK.reset(CELLS);
            STATE.store(base, Ordering::Release);
            Some(base)
        }
        Err(()) => {
            STATE.store(REFUSED, Ordering::Release);
            None
        }
    }
}

/// The object, mapped as the data window piece.
fn make() -> Result<usize, ()> {
    let object = sys::mem_create(WINDOW_BYTES as u64).map_err(drop)?;
    let raw = object.raw().0;
    let base = crate::allocation::heap(|state| {
        state.map_special(
            object,
            WINDOW_BYTES / posix_map::PAGE,
            posix_map::Kind::DataWindow,
        )
    })
    .map_err(drop)?;
    OBJECT.store(raw, Ordering::Release);
    Ok(base)
}

/// The window is given up until `exec`: no cell is handed out any more.
pub(crate) fn refuse() {
    STATE.store(REFUSED, Ordering::Release);
}

/// The object of the window, to copy for WINDOW. Valid after `base` gave an address.
pub(crate) fn object() -> core::mem::ManuallyDrop<Handle<Memory>> {
    Handle::<Memory>::borrowed(rt::abi::Handle(OBJECT.load(Ordering::Acquire)))
}

/// The session the service holds the window for (its raw handle), 0 for none.
pub(crate) fn registered() -> u64 {
    REGISTERED.load(Ordering::Acquire)
}

/// The service lost the window (NO_WINDOW): the next call registers it again.
pub(crate) fn forget_registration(session: u64) {
    let _ = REGISTERED.compare_exchange(session, 0, Ordering::AcqRel, Ordering::Acquire);
}

/// What `registering` found.
pub(crate) enum Claim {
    /// This thread sends WINDOW; `done` ends it.
    Mine,
    /// The window is registered for the session already (another thread did it meanwhile).
    Registered,
    /// Another thread has been sending it too long, or the window is gone.
    Unavailable,
}

/// Claims the sending of WINDOW for `session`. A thread that finds another sending waits a little
/// for it (a send is one round trip) and then goes by messages.
pub(crate) fn claim(session: u64) -> Claim {
    let me = owner();
    for turn in 0..WAIT {
        // No window in this image (a forked child, a refusal, one not yet made): nothing to send.
        if STATE.load(Ordering::Acquire) <= REFUSED {
            return Claim::Unavailable;
        }
        if registered() == session {
            return Claim::Registered;
        }
        if REGISTERING
            .compare_exchange(0, me, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // A thread that finished while this one looked has registered the session.
            if registered() == session {
                REGISTERING.store(0, Ordering::Release);
                return Claim::Registered;
            }
            return Claim::Mine;
        }
        if turn % 16 == 15 {
            let _ = sys::yield_now();
        } else {
            core::hint::spin_loop();
        }
    }
    Claim::Unavailable
}

/// How a claimed sending of WINDOW ended.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sent {
    /// The service took the window for the session.
    Accepted,
    /// The service refused it (INVALID): four in a row give the window up until `exec`.
    Refused,
    /// A busy or restarting service, a handle that could not be copied: nothing is learned.
    Failed,
}

/// The end of a claimed sending.
pub(crate) fn done(session: u64, sent: Sent) {
    match sent {
        Sent::Accepted => {
            FAILS.store(0, Ordering::Release);
            REGISTERED.store(session, Ordering::Release);
        }
        Sent::Refused => {
            if FAILS.fetch_add(1, Ordering::AcqRel) + 1 >= FAILS_MAX {
                refuse();
            }
        }
        Sent::Failed => {}
    }
    REGISTERING.store(0, Ordering::Release);
}

/// A free cell of the window for the call whose record is `live`, None when every one is taken.
/// The window must be `Ready` and registered (the caller checked).
pub(crate) fn take(base: usize, live: &Live) -> Option<Cell> {
    let index = BOOK.take(live.index)?;
    Some(Cell {
        index,
        base,
        slot: live.index,
        generation: live.generation,
    })
}

/// A forked child: no window, no cell, no call under way; the calls of the parent's frames that
/// it returns into find the generation changed.
pub(crate) fn after_fork() {
    GENERATION.fetch_add(1, Ordering::AcqRel);
    STATE.store(ABSENT, Ordering::Release);
    BOOK.reset(0);
    REGISTERED.store(0, Ordering::Release);
    REGISTERING.store(0, Ordering::Release);
    FAILS.store(0, Ordering::Release);
    for slot in &LIVE {
        slot.owner.store(0, Ordering::Release);
    }
}

// ---------------------------------------------------------------- the calls under way

/// The word that names the calling thread in `LIVE` and `REGISTERING`: its block, never 0.
pub(crate) fn owner() -> u64 {
    let block = posix_thread::block() as usize as u64;
    if block == 0 { 1 } else { block }
}

/// The calls of parts that are under way: a thread that jumps out of a handler leaves frames of
/// such calls without running their destructors, and the hook of the jump finds what they held.
struct Slot {
    /// The thread of the call, 0 for a free slot.
    owner: AtomicU64,
    /// The frame of the call (its stack pointer and stack).
    sp: AtomicU64,
    alternate: AtomicU32,
    /// The lease the next part carries, 0 for none.
    lease: AtomicU32,
    /// The session the lease belongs to (its raw handle).
    session: AtomicU64,
    /// 1 from the send of a part to the record of its lease (`set_lease`): a jump that ends the
    /// call in between does not know the lease the answer brought.
    awaiting: AtomicU32,
}

impl Slot {
    const fn new() -> Slot {
        Slot {
            owner: AtomicU64::new(0),
            sp: AtomicU64::new(0),
            alternate: AtomicU32::new(0),
            lease: AtomicU32::new(0),
            session: AtomicU64::new(0),
            awaiting: AtomicU32::new(0),
        }
    }
}

/// The slots. A call that finds none free takes no cell and goes by messages without a record
/// (its lease then runs out on its timer if a jump leaves it).
const LIVE_SLOTS: usize = 16;
static LIVE: [Slot; LIVE_SLOTS] = [const { Slot::new() }; LIVE_SLOTS];

/// A call's record in `LIVE`; it is freed when the value drops (a call that ends or fails). A
/// jump or a thread's exit frees it from the hook. Declare it before the cell, so that the cell
/// drops first.
pub(crate) struct Live {
    index: usize,
    generation: u32,
}

impl Live {
    /// Records a call of the frame `frame` on the thread. None when no slot is free.
    pub(crate) fn enter(frame: Frame) -> Option<Live> {
        let me = owner();
        let generation = generation();
        for (index, slot) in LIVE.iter().enumerate() {
            if slot
                .owner
                .compare_exchange(0, me, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                slot.sp.store(frame.sp, Ordering::Relaxed);
                slot.alternate.store(u32::from(frame.z), Ordering::Relaxed);
                slot.lease.store(0, Ordering::Relaxed);
                slot.session.store(0, Ordering::Relaxed);
                slot.awaiting.store(0, Ordering::Relaxed);
                return Some(Live { index, generation });
            }
        }
        None
    }

    /// A part is about to be sent: its answer brings a lease that `set_lease` records.
    pub(crate) fn sending(&self) {
        LIVE[self.index].awaiting.store(1, Ordering::Release);
    }

    /// The part sent got no answer that carries a lease (the request was taken back, or failed).
    pub(crate) fn unsent(&self) {
        LIVE[self.index].awaiting.store(0, Ordering::Release);
    }

    /// The lease the next part carries, for the session `session` (0 and 0 for none).
    pub(crate) fn set_lease(&self, session: u64, lease: u32) {
        let slot = &LIVE[self.index];
        slot.session.store(session, Ordering::Relaxed);
        slot.lease.store(lease, Ordering::Release);
        slot.awaiting.store(0, Ordering::Release);
    }

    /// Whether a fork happened since the call began: its cell and record are the parent's.
    pub(crate) fn forked(&self) -> bool {
        self.generation != generation()
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if self.generation == generation() {
            LIVE[self.index].owner.store(0, Ordering::Release);
        }
    }
}

/// Ends the record `slot` of this thread: its cell goes back (through the book, once) and its
/// lease goes to `release` (the session's raw handle and the number).
fn end(slot: usize, release: &impl Fn(u64, u32)) {
    let record = &LIVE[slot];
    let lease = record.lease.swap(0, Ordering::AcqRel);
    if lease == 0 && record.awaiting.swap(0, Ordering::AcqRel) != 0 {
        LEASES_UNRECORDED.fetch_add(1, Ordering::Relaxed);
    }
    let session = record.session.load(Ordering::Relaxed);
    BOOK.release(slot);
    record.owner.store(0, Ordering::Release);
    if lease != 0 {
        release(session, lease);
    }
}

/// A jump of the calling thread to the frame `target`: every call of this thread whose frame lies
/// below it is over. Its cell goes back, and `release` is called for the lease it held. A WINDOW
/// the thread was sending goes with it.
pub(crate) fn abandon(target: Frame, release: impl Fn(u64, u32)) {
    let me = owner();
    let _ = REGISTERING.compare_exchange(me, 0, Ordering::AcqRel, Ordering::Acquire);
    for (index, slot) in LIVE.iter().enumerate() {
        if slot.owner.load(Ordering::Acquire) != me {
            continue;
        }
        let frame = Frame {
            z: slot.alternate.load(Ordering::Relaxed) as u8,
            sp: slot.sp.load(Ordering::Relaxed),
        };
        if nested(frame, target) {
            end(index, &release);
        }
    }
}

/// The calling thread ends: all its calls under way are over.
pub(crate) fn abandon_thread(release: impl Fn(u64, u32)) {
    let me = owner();
    let _ = REGISTERING.compare_exchange(me, 0, Ordering::AcqRel, Ordering::Acquire);
    for (index, slot) in LIVE.iter().enumerate() {
        if slot.owner.load(Ordering::Acquire) == me {
            end(index, &release);
        }
    }
}

/// Whether the calling thread runs inside a signal handler (a part there goes by messages).
pub(crate) fn in_handler() -> bool {
    // The layer's own count: the kernel's depth stays above zero for good after a long jump out of
    // a handler.
    crate::handlers::active()
}

/// Whether a window is mapped (for the probes and tests of the layer).
pub fn probe_window_ready() -> bool {
    STATE.load(Ordering::Acquire) > REFUSED
}

/// Whether the window was given up (refused).
pub fn probe_window_refused() -> bool {
    STATE.load(Ordering::Acquire) == REFUSED
}

/// The cells of the window that are free now (the book of the cells): 2 when no call holds one.
pub fn probe_free_cells() -> u32 {
    BOOK.free_mask().count_ones()
}

/// The calls of the calling thread that have a record now (a call that holds a cell or a lease).
pub fn probe_live_calls() -> u32 {
    let me = owner();
    LIVE.iter()
        .filter(|slot| slot.owner.load(Ordering::Acquire) == me)
        .count() as u32
}

/// Gives the window up until `exec`, as a refusal does: every large call goes by messages
/// (`INLINE`) from here on.
pub fn probe_ban_window() {
    refuse();
}

/// The mappings of the window's object now, in every process (the layer's own piece is one); 0
/// when there is no window.
pub fn probe_window_mappings() -> u64 {
    if !probe_window_ready() {
        return 0;
    }
    sys::memory_info(&object()).map_or(0, |info| info.mappings)
}

/// The bytes the window holds for the probes that count pages (the quota of the process).
pub const PROBE_WINDOW_BYTES: usize = WINDOW_BYTES;
