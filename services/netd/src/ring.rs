// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The bounds of one step of the service, the loopback's book and the
//! queues of its sessions. The books of the two rings of the device
//! (Virtio 1.2, 5.1.2: which buffer each token of a queue stands for, and
//! the pool of the buffers for sending) are the library's
//! (`virtio_net::books`), and this module names them for the service.

pub use virtio_net::books::{
    BUFFERS, NET_PAGES, QUEUE_SIZE, RX_BUFFERS, RxBook, TX_BUFFERS, TxBook, offset,
};

/// The frames a step of receiving takes and the frames a step of sending
/// sends at most (the bound of a step, so that a flood leaves the loop its
/// other work): by the measurement of stage P4a-1, which prices the frames
/// of the wire at full size (7 168 ticks received, 5 632 sent, p90) beside
/// those of the loopback (2 048 and 768): two frames received cost an
/// estimated 15 360 ticks, a group and a frame sent 12 800. The features `batch-N` (receiving) and `send-N` (sending) build the other
/// values, for the measurement that chose these.
#[cfg(feature = "batch-16")]
pub const STEP_RX: usize = 16;
#[cfg(all(feature = "batch-8", not(feature = "batch-16")))]
pub const STEP_RX: usize = 8;
#[cfg(all(
    feature = "batch-4",
    not(any(feature = "batch-16", feature = "batch-8"))
))]
pub const STEP_RX: usize = 4;
#[cfg(all(
    feature = "batch-1",
    not(any(feature = "batch-16", feature = "batch-8", feature = "batch-4"))
))]
pub const STEP_RX: usize = 1;
#[cfg(not(any(
    feature = "batch-16",
    feature = "batch-8",
    feature = "batch-4",
    feature = "batch-1"
)))]
pub const STEP_RX: usize = 2;
#[cfg(feature = "send-16")]
pub const STEP_TX: usize = 16;
#[cfg(all(feature = "send-8", not(feature = "send-16")))]
pub const STEP_TX: usize = 8;
#[cfg(all(feature = "send-4", not(any(feature = "send-16", feature = "send-8"))))]
pub const STEP_TX: usize = 4;
#[cfg(all(
    feature = "send-2",
    not(any(feature = "send-16", feature = "send-8", feature = "send-4"))
))]
pub const STEP_TX: usize = 2;
#[cfg(not(any(
    feature = "send-16",
    feature = "send-8",
    feature = "send-4",
    feature = "send-2"
)))]
pub const STEP_TX: usize = 1;
/// The frames the ring of sending holds before its doorbell rings while
/// steps of the service follow.
pub const BELL_TX: u32 = 8;
/// The steps a frame of sending waits at most for its doorbell while steps
/// of the service follow (a run of receiving that brings no answers must not
/// hold a short reply: a step is about 100 us, so 4 steps are under half a
/// millisecond).
pub const BELL_STEPS: u32 = 4;
/// Whether the ring of sending rings its doorbell at the end of a step:
/// `pending` frames went in since the last one, `waited` steps ended since
/// the first of them, and `more` says that another step of the service
/// follows at once. One ring serves the frames of the whole run of steps (a
/// ring is an exit from the guest, far dearer than a frame), and no frame
/// waits more than `BELL_STEPS` steps.
pub const fn tx_bell_due(pending: u32, waited: u32, more: bool) -> bool {
    bell_due(BELL_TX, pending, waited, more)
}

/// `tx_bell_due` for a ring of sending that rings after `limit` frames.
pub const fn bell_due(limit: u32, pending: u32, waited: u32, more: bool) -> bool {
    pending > 0 && (!more || pending >= limit || waited >= BELL_STEPS)
}

/// The longest the bell is held for the work queued behind the stack's step
/// (`Hold`): a call of a program or a step of the service told to itself. A
/// timer set when the hold starts rings it at `HOLD_NS`, wherever the queue
/// stands then (a call that the kernel withdrew or the library refused makes
/// no event of its own). The frame then waits `HOLD_NS`, plus the event in
/// progress when the timer fires (a step is at most 18 369 ticks, about 765 us
/// at 24 MHz), plus the time a level above the stack takes from it (the
/// switch's run, `SWITCH_RUN_NS`): about 2.9 ms in the worst case, 100 us and
/// a few events in the usual one.
pub const HOLD_NS: u64 = 100_000;

/// The doorbell held for the work queued behind the stack's step. A program's
/// call is a request in the service's queue, and the step it asks for is a
/// notification that goes ahead of the calls behind it, so a step ends with
/// calls still queued: the frames of the answers of those calls go out with one
/// bell, when the queue is empty or after `HOLD_NS`, whichever is first.
#[derive(Default)]
pub struct Hold {
    since: Option<u64>,
}

impl Hold {
    pub const fn new() -> Hold {
        Hold { since: None }
    }

    /// Frames wait for the bell and `queued` says whether work stands behind
    /// the event that ended just now, at `now`: true while the bell waits.
    /// False rings it (the queue is empty, or the wait reached `HOLD_NS`) and
    /// the next hold starts anew.
    pub fn waits(&mut self, queued: bool, now: u64) -> bool {
        if !queued {
            self.since = None;
            return false;
        }
        let since = *self.since.get_or_insert(now);
        if now.saturating_sub(since) >= HOLD_NS {
            self.since = None;
            return false;
        }
        true
    }

    /// The bell is being held.
    pub const fn on(&self) -> bool {
        self.since.is_some()
    }

    /// When the timer rings a held bell, if one is held.
    pub fn deadline(&self) -> Option<u64> {
        self.since.map(|since| since + HOLD_NS)
    }

    /// The end of an event with a bell that may be held: true when the bell
    /// is to ring now (it was held and the work behind is gone or its time is
    /// up), which is when `kick(false)` is due.
    pub fn release(&mut self, queued: bool, now: u64) -> bool {
        self.on() && !self.waits(queued, now)
    }
}

/// The frames the switch thread takes off the queue of receiving in one
/// step, and the frames of sending it puts in the queue (the bound of a
/// step, as `STEP_RX` and `STEP_TX` are for the stack): a frame costs the
/// switch a look at its header and a word in a ring, about 400 ticks under
/// -icount, and the step is bound by 0.9 of term B (18 369).
pub const SWITCH_RX: usize = 8;
pub const SWITCH_TX: usize = 16;
/// The buffers the stack gave back (of receiving, of sending) the switch
/// takes in a step, each.
pub const SWITCH_BACK: usize = 32;
/// The buffers of receiving the stack gives back before it wakes the switch
/// for them alone (with a frame to send or a held doorbell it wakes it anyway).
pub const RX_BACK_LAZY: usize = 64;
/// The frames of the wire the switch leaves for the stack at most: more
/// stay in the queue of the device until the stack gave buffers back.
pub const RX_AHEAD: usize = 32;
/// The buffers for sending the switch lends the stack: all 256 while the
/// stack is its only consumer (a pool of fewer ran dry under the flood of
/// `net-curl` where the device sends late, and a reply made in a step of
/// receiving found no buffer).
pub const TX_SHARE: usize = TX_BUFFERS;
/// The buffers of sending the stack may hold (lent, queued by it, in the device's queue on
/// its account) once consumers are attached; the rest of the 256 serves the consumers, who
/// share it by their count (`switch::Switch::consumer_cap`).
pub const STACK_SHARE: usize = 192;
/// The frames of the wire the switch routes in a step when consumers are attached, and the
/// frames of consumers it takes in a step: each costs a header parse, a hash and one or two
/// copies of up to 1 514 bytes, about 1 500 ticks under -icount.
pub const SWITCH_ROUTED: usize = 8;
pub const SWITCH_CTX: usize = 8;
/// The parked SYNs a step gives to members that joined.
pub const PARK_GIVE: usize = 2;
// A handoff is a small frame through `route` and a copy of at most 128 bytes (about 900 ticks):
// two of them stay within the frames a step takes whatever its time (`SWITCH_BASE`), and the worst
// step, the base frames of every kind and the tail, still fits the bound.
const _: () = assert!(
    PARK_GIVE <= SWITCH_BASE
        && 3_300 + PARK_GIVE * 900 + SWITCH_BASE * 1_500 + SWITCH_BASE * 1_800 + 3_000 <= 18_369
);
/// The frames of each kind a step always takes, and the time in clock ticks beyond which it
/// takes no more. Under -icount (the steps probes) a tick is an instruction-scale unit and the
/// soft share holds a step under the bound; on a real clock a step never reaches it.
pub const SWITCH_BASE: usize = 3;
pub const SWITCH_SOFT: u64 = 7_000;
/// The least time between two steps of the sweep of the flow table, in nanoseconds, and the
/// period of its timer when the line is quiet.
pub const SWEEP_EVERY_NS: u64 = 1_000_000;
pub const SWEEP_IDLE_NS: u64 = 100_000_000;
/// The CPU the switch thread leaves to the levels below it, two parts.
///
/// The budget (`Period`): the thread spends at most `CONSUMER_BUDGET_NS` of each
/// `CONSUMER_PERIOD_NS` on the entries of the consumers' TX rings (the time it measures around
/// each entry, all consumers together); the rest waits for the end of the period. The wire's frames are not under it and stay at the high
/// level. So the consumers hold 80 % of CPU 0 at most, and in a flood of entries the levels
/// below the switch keep 20 % (the probe `fast-switch-saturate`). A smaller budget costs
/// answers: 500 us took 10 % of the 10 KiB load with three workers on VZ, whose consumers need
/// about 600 us of each millisecond; with the wire's frames (about 30 %) that load fills CPU 0 and
/// only the backstop is left to the lower levels there. A count of entries would not do: a
/// refused entry costs about 0.1 us and a frame sent about 1.5 us.
///
/// The backstop (`RunClock`): a run of `SWITCH_RUN_NS` without a rest (a wait of
/// `SWITCH_REST_NS` or more) is followed by a pause of `SWITCH_PAUSE_NS`, so that the lower levels
/// get a twentieth of the CPU whatever supplies the thread (a pause of 500 us, a fifth, took
/// 20 % of the answers of the 10 KiB load with three workers, whose CPU 0 has no more to give).
/// Without both, the device and the consumers keep the thread running for seconds and init's
/// watchdog kills the service that was kept off the processor, the stack and the entropy service
/// among them (stafeto-design#653).
pub const SWITCH_RUN_NS: u64 = 2_000_000;
pub const SWITCH_PAUSE_NS: u64 = 100_000;
pub const SWITCH_REST_NS: u64 = 500_000;
/// One step of the switch at its bound of 18 369 ticks of 41.67 ns, rounded up.
pub const SWITCH_STEP_BOUND_NS: u64 = 770_000;
pub const CONSUMER_PERIOD_NS: u64 = 1_000_000;
pub const CONSUMER_BUDGET_NS: u64 = 800_000;

/// The time spent on the consumers' entries in the present period of `CONSUMER_PERIOD_NS`. The
/// consumers share it as the steps take their entries, one from each in turn, so a consumer with
/// many entries cannot shut out the others.
#[derive(Clone, Copy, Debug)]
pub struct Period {
    began: u64,
    spent: u64,
}

impl Period {
    pub const fn new() -> Period {
        Period { began: 0, spent: 0 }
    }

    /// A new period begins when the present one has lasted its time. The periods lie on a
    /// fixed grid (`began` moves by whole periods), so a late step does not stretch a window and
    /// the consumers cannot take 1.6 ms of time in 1 ms.
    pub fn refresh(&mut self, now: u64) {
        let late = now.wrapping_sub(self.began);
        if late >= CONSUMER_PERIOD_NS {
            self.began = self
                .began
                .wrapping_add(late / CONSUMER_PERIOD_NS * CONSUMER_PERIOD_NS);
            self.spent = 0;
        }
    }

    /// The time left of the present period at `now`.
    pub fn remaining(&self, now: u64) -> u64 {
        CONSUMER_PERIOD_NS.saturating_sub(now.wrapping_sub(self.began))
    }

    /// Whether the consumers have time left in this period.
    pub fn left(&self) -> bool {
        self.spent < CONSUMER_BUDGET_NS
    }

    /// `ns` went on an entry of a consumer.
    pub fn spend(&mut self, ns: u64) {
        self.spent = self.spent.saturating_add(ns);
    }
}

impl Default for Period {
    fn default() -> Period {
        Period::new()
    }
}

/// When the switch thread's current run began: a run goes on through the waits that return at
/// once (a notification was pending) and ends with a wait of `SWITCH_REST_NS` or more, or with
/// a pause.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunClock {
    since: Option<u64>,
}

impl RunClock {
    pub const fn new() -> RunClock {
        RunClock { since: None }
    }

    /// The thread came back at `now` from a wait that lasted `waited`.
    pub fn woke(&mut self, now: u64, waited: u64) {
        if waited >= SWITCH_REST_NS || self.since.is_none() {
            self.since = Some(now);
        }
    }

    /// The time since the run began.
    pub fn ran(&self, now: u64) -> u64 {
        self.since.map_or(0, |s| now.wrapping_sub(s))
    }

    /// Whether the run has lasted its time at `now` and the thread has to pause before the
    /// next step.
    pub fn pause_due(&self, now: u64) -> bool {
        self.ran(now) >= SWITCH_RUN_NS
    }

    /// The pause ended at `now`: a new run begins.
    pub fn rested(&mut self, now: u64) {
        self.since = Some(now);
    }
}

/// What the loop of steps of the switch thread needs of the switch (and of a model of it in the
/// tests): `drive` is the loop the thread runs.
pub trait Stepper {
    fn now(&mut self) -> u64;
    /// One step; true when another follows at once.
    fn step(&mut self, interrupt: bool) -> bool;
    /// The pause; true when the wait happened.
    fn pause(&mut self) -> bool;
    /// The longest run so far, when a step begins after a longer one.
    fn longest(&mut self, ran: u64);
}

/// Steps while they follow one another, with the backstop pause once the run has lasted
/// `SWITCH_RUN_NS`. `longest` holds the largest run seen, passed to `Stepper::longest` when it
/// grows. The run is the thread's, so `clock` outlives the call. The run is read when a step
/// begins, so the longest run it reports misses up to one step (the step that ends the run);
/// the probe's margin for the host's clock covers that.
pub fn drive<S: Stepper>(s: &mut S, clock: &mut RunClock, longest: &mut u64, mut interrupt: bool) {
    loop {
        let now = s.now();
        let ran = clock.ran(now);
        if ran > *longest {
            *longest = ran;
            s.longest(ran);
        }
        if clock.pause_due(now) {
            // A pause that did not happen (the timer refused) still starts a new run, so that
            // the failing call is not repeated at every step.
            s.pause();
            let after = s.now();
            clock.rested(after);
        }
        let more = s.step(interrupt);
        interrupt = false;
        if !more {
            break;
        }
    }
}

/// The frames the switch collects before its doorbell rings while the stack
/// follows with steps (the stack's own queue rang after `BELL_TX`).
pub const SWITCH_BELL: u32 = 32;
const _: () = assert!(TX_SHARE <= TX_BUFFERS && RX_AHEAD <= RX_BUFFERS && SWITCH_RX <= RX_AHEAD);
/// The longest step of the switch under -icount as its parts bound it: the
/// rest of the step (the interrupt status, up to `SWITCH_TX` frames put in the
/// queue, `RECLAIM_STEP` buffers taken back, up to `SWITCH_BACK` buffers of
/// each kind given back, the doorbells) about 9 400 ticks as a worst case,
/// and a frame of the wire taken off the queue about 210. Measured: 3 300
/// ticks the longest in `posix-net steps` and `net-curl steps` (the rest
/// before the cap of `SWITCH_BACK` reached 11 063). A step of the switch is
/// no longer than the longest step of the stack (12 521, `RECLAIM_STEP`
/// above) and so well under the bound of 18 369.
pub const SWITCH_STEP_REST: usize = 9_400;
pub const SWITCH_STEP_RX_FRAME: usize = 210;
const _: () = assert!(SWITCH_STEP_REST + SWITCH_RX * SWITCH_STEP_RX_FRAME <= 12_521);
/// With consumers the step takes `SWITCH_BASE` frames of each kind whatever the time (about
/// 1 500 and 1 800 ticks each), more only while it has used less than `SWITCH_SOFT` ticks,
/// and then the sweep of a few places and some commands (about 3 000) on the measured rest of
/// 3 300. The worst case is the soft share, one more frame, the base frames of the second
/// kind and the tail.
const _: () = assert!(
    SWITCH_SOFT as usize + 1_800 + SWITCH_BASE * 1_500 + 3_000 <= 18_369
        && 3_300 + SWITCH_BASE * 1_500 + SWITCH_BASE * 1_800 + 3_000 <= 18_369
);

/// The end of a run of steps for the interrupts of receiving: while steps
/// follow (`continued`) the device is asked for none; at the end it is asked
/// for them (`set(true)` includes the full barrier) and the queue is looked
/// at once more, since a frame that came in between brings no interrupt
/// (Virtio 1.2, 2.7.14); a frame found continues the run. Whether the run
/// continues.
pub fn settle_interrupts(
    continued: bool,
    mut tell: impl FnMut() -> bool,
    mut set: impl FnMut(bool),
    mut can_pop: impl FnMut() -> bool,
) -> bool {
    set(!continued);
    if !continued && can_pop() {
        let continued = tell();
        set(!continued);
        return continued;
    }
    continued
}

/// The sent buffers a step takes back from the ring of sending at most
/// (stafeto-design#635). Each costs 129 ticks under -icount; a device that
/// sends the whole queue at once (QEMU's bottom half run late on a busy
/// host) returned about 250 of them to one step of receiving, which took
/// 44 215 ticks against the bound of 18 369. Sixteen cost about 2 100 ticks
/// and are more than any step sends (`STEP_RX`, `STEP_TX`), so the pool does
/// not run dry: the rest come back in the next steps.
pub const RECLAIM_STEP: usize = 16;
// A step takes back more than it may send, and the taking back fits the
// bound beside the longest step of receiving of `net-curl steps` (12 521).
const _: () = assert!(RECLAIM_STEP >= STEP_RX && RECLAIM_STEP >= STEP_TX);
const _: () = assert!(12_521 + RECLAIM_STEP * 129 < 18_369);

/// The frames the loopback keeps for the next reception: two steps of
/// sending, or of the answers to receiving.
pub const LOOP_FRAMES: usize = 2 * if STEP_TX > STEP_RX { STEP_TX } else { STEP_RX };
/// The groups of sockets the pass of sending visits in one step, by the
/// measurement of stage P4a-1 (see STEP_RX). The features
/// `egress-1` and `egress-4` build the other values, for the measurement.
#[cfg(feature = "egress-1")]
pub const EGRESS_GROUPS: usize = 1;
#[cfg(all(feature = "egress-4", not(feature = "egress-1")))]
pub const EGRESS_GROUPS: usize = 4;
#[cfg(not(any(feature = "egress-1", feature = "egress-4")))]
pub const EGRESS_GROUPS: usize = 2;
/// The bytes one request with a cell of the shared buffer (SEND or RECV with
/// `BUF`) copies at most: by the measurement of stage P4b-1, the largest of
/// 16, 8 and 4 KiB whose steps stay within the budget of a step
/// (`netd::choose::portion`): at 16 KiB the longest SEND took 7 110 ticks
/// and the longest RECV 7 054, the copy of a cell 3 584 (p90). The features
/// `portion-16`, `portion-8` and `portion-4` build each, for the measurement.
#[cfg(feature = "portion-16")]
pub const BUFFER_PORTION: usize = 16 * 1024;
#[cfg(all(feature = "portion-8", not(feature = "portion-16")))]
pub const BUFFER_PORTION: usize = 8 * 1024;
#[cfg(all(
    feature = "portion-4",
    not(any(feature = "portion-16", feature = "portion-8"))
))]
pub const BUFFER_PORTION: usize = 4 * 1024;
#[cfg(not(any(feature = "portion-16", feature = "portion-8", feature = "portion-4")))]
pub const BUFFER_PORTION: usize = 16 * 1024;
/// The operations of one session that an ABANDON, or a step of departure,
/// lets go of at most: each costs the place it waits on and its handle's close,
/// so 16 at once came to 83 percent of the bound (reports/2026-11-04-net-p1b).
pub const ABANDON_PORTION: usize = 4;

/// Lets go of operations by `one`, which frees the next of the session's and
/// says whether it had one, up to `ABANDON_PORTION` of them; how many went,
/// and whether the session has more (the caller asks again).
pub fn abandon_portion(mut one: impl FnMut() -> bool) -> (usize, bool) {
    let mut gone = 0;
    while gone < ABANDON_PORTION {
        if !one() {
            return (gone, false);
        }
        gone += 1;
    }
    // A full portion: the next ask finds out whether there is more.
    (gone, true)
}

/// The operations of one session that wait at most (rt's LONG_SESSION_MAX).
pub const SESSION_OPS: usize = 16;
/// The notifications to clients and the checks of readiness the step of
/// waking does at most (the pipe service wakes eight at most).
pub const WAKE_TELLS: usize = 8;
pub const WAKE_CHECKS: usize = 32;

/// The frames the loopback keeps (spec 6, 3.3): the stack's frames to its
/// own address wait here for the next reception. The frames themselves lie in
/// a table of the service; this is the book of its places. A frame is
/// pushed at `head`, read at `read`, and its place is the reader's until
/// `done`: the stack builds replies to a frame while it holds it.
pub struct LoopBook {
    head: usize,
    read: usize,
    done: usize,
}

impl LoopBook {
    pub const fn new() -> LoopBook {
        LoopBook {
            head: 0,
            read: 0,
            done: 0,
        }
    }

    /// The place for a new frame, None when all LOOP_FRAMES are taken.
    pub fn push(&mut self) -> Option<usize> {
        if self.head - self.done >= LOOP_FRAMES {
            return None;
        }
        let place = self.head % LOOP_FRAMES;
        self.head += 1;
        Some(place)
    }

    /// The place of the oldest frame not read.
    pub fn pop(&mut self) -> Option<usize> {
        if self.read == self.head {
            return None;
        }
        let place = self.read % LOOP_FRAMES;
        self.read += 1;
        Some(place)
    }

    /// The oldest frame read is done with, its place is free: the place.
    pub fn done(&mut self) -> Option<usize> {
        if self.done < self.read {
            let place = self.done % LOOP_FRAMES;
            self.done += 1;
            Some(place)
        } else {
            None
        }
    }

    /// The frames waiting to be read.
    pub fn waiting(&self) -> usize {
        self.head - self.read
    }

    /// The places taken: the frames waiting and the one being read.
    pub fn used(&self) -> usize {
        self.head - self.done
    }

    /// Whether a frame of sending may be built: two places stay free, one
    /// for it and one for the stack's answer to the frame being read, so that
    /// no frame of the loop is lost for want of a place (a lost segment of TCP
    /// costs the retransmission timer, a second at least).
    pub fn room_to_send(&self) -> bool {
        self.used() + 2 <= LOOP_FRAMES
    }
}

impl Default for LoopBook {
    fn default() -> LoopBook {
        LoopBook::new()
    }
}

/// The streams no session holds, oldest first: the place and the time they
/// were let go of. A stream can leave the table from the middle (a close, an
/// eviction), so an entry may be stale; `live` says whether an entry still is
/// the stream let go of at that time. The queue never has more entries than
/// `N`, and a full one drops its stale entries before it drops anything.
pub struct OrphanQueue<const N: usize> {
    entries: [(u16, u64); N],
    head: usize,
    len: usize,
}

impl<const N: usize> OrphanQueue<N> {
    pub const fn new() -> Self {
        OrphanQueue {
            entries: [(0, 0); N],
            head: 0,
            len: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// The entry `k` places from the head, if any.
    pub fn get(&self, k: usize) -> Option<(usize, u64)> {
        (k < self.len).then(|| {
            let (place, at) = self.entries[(self.head + k) % N];
            (usize::from(place), at)
        })
    }

    /// Adds a stream. A full queue first drops its stale entries (there are
    /// some: the live streams are at most N, and one is being added, so at
    /// least one place of the queue is stale or the table has no room for the
    /// stream).
    pub fn push(&mut self, place: usize, at: u64, live: impl Fn(usize, u64) -> bool) {
        if self.len == N {
            self.compact(&live);
        }
        if self.len == N {
            // Every entry is live: the oldest stays and the new one is
            // refused only when N streams are live, which the table of N
            // places cannot hold together with a new one.
            return;
        }
        let tail = (self.head + self.len) % N;
        self.entries[tail] = (place as u16, at);
        self.len += 1;
    }

    /// Drops the stale entries, keeping the order of the live ones.
    pub fn compact(&mut self, live: &impl Fn(usize, u64) -> bool) {
        let mut kept = 0;
        for k in 0..self.len {
            let (place, at) = self.entries[(self.head + k) % N];
            if live(usize::from(place), at) {
                // The write trails the read, so no entry is written over
                // before it is read.
                self.entries[(self.head + kept) % N] = (place, at);
                kept += 1;
            }
        }
        self.len = kept;
    }

    /// The oldest live stream, dropping the stale entries before it.
    pub fn front(&mut self, live: impl Fn(usize, u64) -> bool) -> Option<(usize, u64)> {
        while self.len > 0 {
            let (place, at) = self.entries[self.head];
            if live(usize::from(place), at) {
                return Some((usize::from(place), at));
            }
            self.pop();
        }
        None
    }

    pub fn pop(&mut self) {
        if self.len > 0 {
            self.head = (self.head + 1) % N;
            self.len -= 1;
        }
    }
}

impl<const N: usize> Default for OrphanQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// The frames of the loopback (spec 6, 3.3): what the stack sends to its own
/// MAC waits here for the next reception. The frame stays in the buffer of
/// sending it was built in (no copy): the ring holds the number of the buffer
/// and the buffer is not in the pool until the stack is done with the frame.
/// Both tokens of a pair reach the ring, so its parts have interior
/// mutability; the book keeps the place of the frame being read apart from the
/// one a reply goes to.
pub struct LoopRing {
    book: core::cell::RefCell<LoopBook>,
    buffers: [core::cell::Cell<u16>; LOOP_FRAMES],
    lengths: [core::cell::Cell<usize>; LOOP_FRAMES],
    /// The buffers the stack is done with, which the pool of sending takes
    /// back at the start of the next reception and of the next use.
    returned: core::cell::RefCell<([u16; LOOP_FRAMES], usize)>,
    /// The frames that found no place.
    dropped: core::cell::Cell<u64>,
    /// The list of returned buffers was full when a frame was done with: a
    /// buffer would be lost, which the service must not go on from.
    overflowed: core::cell::Cell<bool>,
}

impl LoopRing {
    pub fn new() -> LoopRing {
        LoopRing {
            book: core::cell::RefCell::new(LoopBook::new()),
            buffers: core::array::from_fn(|_| core::cell::Cell::new(0)),
            lengths: core::array::from_fn(|_| core::cell::Cell::new(0)),
            returned: core::cell::RefCell::new(([0; LOOP_FRAMES], 0)),
            dropped: core::cell::Cell::new(0),
            overflowed: core::cell::Cell::new(false),
        }
    }

    pub fn waiting(&self) -> usize {
        self.book.borrow().waiting()
    }

    /// Whether the stack may build a frame of sending (`room_to_send`).
    pub fn room_to_send(&self) -> bool {
        self.book.borrow().room_to_send()
    }

    /// The frames that found no place since the start.
    pub fn dropped(&self) -> u64 {
        self.dropped.get()
    }

    /// Keeps the frame of `length` bytes in buffer `n`; false (counted, and
    /// the buffer stays the caller's) when the ring is full.
    pub fn push(&self, n: u16, length: usize) -> bool {
        let Some(place) = self.book.borrow_mut().push() else {
            self.dropped.set(self.dropped.get() + 1);
            return false;
        };
        self.buffers[place].set(n);
        self.lengths[place].set(length);
        true
    }

    /// The oldest frame: its place, its buffer and its length.
    pub fn pop(&self) -> Option<(usize, u16, usize)> {
        let place = self.book.borrow_mut().pop()?;
        Some((place, self.buffers[place].get(), self.lengths[place].get()))
    }

    /// The oldest frame read is done with: its buffer waits to go back to the
    /// pool.
    pub fn done(&self) {
        let Some(place) = self.book.borrow_mut().done() else {
            return;
        };
        let mut returned = self.returned.borrow_mut();
        let at = returned.1;
        // Every `take_returned` runs at the start of a reception, so the list
        // never holds more than the ring does.
        if at < LOOP_FRAMES {
            returned.0[at] = self.buffers[place].get();
            returned.1 += 1;
        } else {
            self.overflowed.set(true);
        }
    }

    /// Whether a buffer was lost for want of room in the list of returned
    /// ones.
    pub fn overflowed(&self) -> bool {
        self.overflowed.get()
    }

    /// A buffer the stack is done with.
    pub fn take_returned(&self) -> Option<u16> {
        let mut returned = self.returned.borrow_mut();
        returned.1 = returned.1.checked_sub(1)?;
        Some(returned.0[returned.1])
    }
}

impl Default for LoopRing {
    fn default() -> LoopRing {
        LoopRing::new()
    }
}

/// The index of the long operation `key` names in a table of `operations`
/// places, None for a key a client made up: the low word 0 (no operation),
/// or past the table.
pub fn op_index(key: u64, operations: usize) -> Option<usize> {
    let index = usize::try_from((key & 0xffff_ffff).checked_sub(1)?).ok()?;
    (index < operations).then_some(index)
}

/// The step the loop does next among those asked for in `bits`: the bit
/// after `last` in the order of `order`, going round, so that a step that asks
/// for itself again cannot keep the others from running (the order of the
/// bits would let receiving starve them). The place in `order` of the bit
/// chosen.
pub fn next_bit(order: &[u64], bits: u64, last: usize) -> Option<usize> {
    (1..=order.len())
        .map(|k| (last + k) % order.len())
        .find(|&i| bits & order[i] != 0)
}

/// What the step of waking may still do: WAKE_TELLS notifications and
/// WAKE_CHECKS checks of readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WakeBudget {
    tells: usize,
    checks: usize,
}

impl WakeBudget {
    pub const fn new() -> WakeBudget {
        WakeBudget {
            tells: WAKE_TELLS,
            checks: WAKE_CHECKS,
        }
    }

    /// Spends a check; false when the step has had its share.
    pub fn take_check(&mut self) -> bool {
        self.checks = match self.checks.checked_sub(1) {
            Some(left) => left,
            None => return false,
        };
        true
    }

    /// Spends `n` checks; false (and nothing spent) when the step has not
    /// that many left.
    pub fn take_checks(&mut self, n: usize) -> bool {
        match self.checks.checked_sub(n) {
            Some(left) => {
                self.checks = left;
                true
            }
            None => false,
        }
    }

    /// Spends a notification; false when the step has had its share.
    pub fn take_tell(&mut self) -> bool {
        self.tells = match self.tells.checked_sub(1) {
            Some(left) => left,
            None => return false,
        };
        true
    }
}

impl Default for WakeBudget {
    fn default() -> WakeBudget {
        WakeBudget::new()
    }
}

/// A walk over the marked places of a set, in order from `cursor` to the
/// end, at most `checks` places in a call; the next call resumes at `cursor`,
/// and a call that reaches the end starts the next walk at 0. `next(from)` is
/// the lowest marked place at or after `from`. `visit(place)` returns false
/// to leave the place (and the rest) for the next call. True when the end was
/// reached: the places marked behind the cursor meanwhile ask for a walk of
/// their own.
pub fn walk_round(
    cursor: &mut usize,
    checks: usize,
    next: impl Fn(usize) -> Option<usize>,
    mut visit: impl FnMut(usize) -> bool,
) -> bool {
    let mut left = checks;
    loop {
        let Some(m) = next(*cursor) else {
            *cursor = 0;
            return true;
        };
        if left == 0 || !visit(m) {
            *cursor = m;
            return false;
        }
        left -= 1;
        *cursor = m + 1;
    }
}

/// What one step of the service may still do: receive STEP_RX frames and
/// send STEP_TX (spec 6: a step is bounded so that a burst of frames
/// cannot hold the loop).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    rx: usize,
    tx: usize,
    rx_start: usize,
    tx_start: usize,
}

impl Budget {
    pub const fn new() -> Budget {
        Budget::with(STEP_RX, STEP_TX)
    }

    pub const fn with(rx: usize, tx: usize) -> Budget {
        Budget {
            rx,
            tx,
            rx_start: rx,
            tx_start: tx,
        }
    }

    /// A step of receiving: STEP_RX frames in, and as many of the stack's
    /// answers to them out.
    pub const fn receiving() -> Budget {
        Budget::with(STEP_RX, STEP_RX)
    }

    /// A step of sending: STEP_TX frames out, none in.
    pub const fn sending() -> Budget {
        Budget::with(0, STEP_TX)
    }

    /// Spends one reception; false when the step has had its share.
    pub fn take_rx(&mut self) -> bool {
        self.rx = match self.rx.checked_sub(1) {
            Some(left) => left,
            None => return false,
        };
        true
    }

    /// Spends one send; false when the step has had its share.
    pub fn take_tx(&mut self) -> bool {
        self.tx = match self.tx.checked_sub(1) {
            Some(left) => left,
            None => return false,
        };
        true
    }

    /// Ends the receiving of the step: the frames taken so far stay its
    /// share, and it takes no more.
    pub fn end_rx(&mut self) {
        self.rx_start -= self.rx;
        self.rx = 0;
    }

    pub fn rx_left(&self) -> usize {
        self.rx
    }

    pub fn tx_left(&self) -> usize {
        self.tx
    }

    /// The frames received and sent so far in the step.
    pub fn spent(&self) -> (usize, usize) {
        (self.rx_start - self.rx, self.tx_start - self.tx)
    }
}

impl Default for Budget {
    fn default() -> Budget {
        Budget::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_switch_collects_a_bigger_batch_than_the_stack() {
        assert!(!bell_due(SWITCH_BELL, SWITCH_BELL - 1, 0, true));
        assert!(bell_due(SWITCH_BELL, SWITCH_BELL, 0, true));
        assert!(
            bell_due(SWITCH_BELL, 1, 0, false),
            "the end of the run rings"
        );
        assert!(bell_due(SWITCH_BELL, 1, BELL_STEPS, true));
        assert!(!bell_due(SWITCH_BELL, 0, BELL_STEPS, false));
        assert_eq!(
            tx_bell_due(BELL_TX, 0, true),
            bell_due(BELL_TX, BELL_TX, 0, true)
        );
    }

    #[test]
    fn a_run_of_steps_of_sending_rings_once_at_its_end() {
        assert!(!tx_bell_due(0, 0, false), "nothing went in");
        assert!(!tx_bell_due(1, 0, true), "a step follows");
        assert!(!tx_bell_due(BELL_TX - 1, BELL_STEPS - 1, true));
        assert!(
            tx_bell_due(BELL_TX, 0, true),
            "a frame does not wait for ever"
        );
        assert!(tx_bell_due(1, 0, false), "the last step rings what is left");
        assert!(
            tx_bell_due(1, BELL_STEPS, true),
            "one reply under a one-way flow of inbound frames waits at most BELL_STEPS steps"
        );
        assert!(!tx_bell_due(0, BELL_STEPS, true), "nothing to ring");
    }

    /// The bells for `calls` events of the stack, ten microseconds apart, each
    /// of which leaves work queued behind it when `queued` says so.
    fn bells_for(calls: u64, queued: impl Fn(u64) -> bool) -> u64 {
        let mut hold = Hold::new();
        let mut bells = 0;
        for call in 0..calls {
            if !hold.waits(queued(call), call * 10_000) {
                bells += 1;
            }
        }
        bells
    }

    #[test]
    fn the_frames_of_queued_calls_share_a_bell() {
        // Eight calls stand in the queue: the first seven events leave work
        // behind, the eighth empties the queue.
        assert_eq!(bells_for(8, |call| call < 7), 1);
        // Two bursts of four, with the queue empty between them.
        assert_eq!(bells_for(8, |call| call % 4 != 3), 2);
        // Nothing queued: a bell for each frame, as an idle service rings.
        assert_eq!(bells_for(8, |_| false), 8);
    }

    /// A hold that ends with a request nobody handled (the library refused it
    /// or the kernel withdrew the call): no event follows, and only the timer
    /// at `deadline` can ring the bell. `timer` says whether the model has it.
    fn rung_after_a_lost_request(timer: bool) -> Option<u64> {
        let mut hold = Hold::new();
        // A step ends at t = 0 with a call queued behind it: the bell is held.
        assert!(hold.waits(true, 0));
        // The call is withdrawn at t = 10 us: no event, the queue is empty.
        let mut now = 10_000;
        while now <= 4 * HOLD_NS {
            let fired = timer && hold.deadline().is_some_and(|at| now >= at);
            if fired && hold.release(false, now) {
                return Some(now);
            }
            now += 1_000;
        }
        None
    }

    #[test]
    fn a_lost_request_does_not_strand_a_held_bell() {
        let rang = rung_after_a_lost_request(true).expect("the timer rings the bell");
        assert!(rang <= HOLD_NS + 1_000, "rang at {rang} ns");
        assert_eq!(
            rung_after_a_lost_request(false),
            None,
            "without the timer the bell waits for the next event"
        );
    }

    #[test]
    fn a_frame_waits_no_longer_than_hold_ns_for_the_bell() {
        let mut hold = Hold::new();
        assert!(hold.waits(true, 1_000));
        assert!(hold.on());
        assert!(hold.waits(true, 1_000 + HOLD_NS - 1));
        assert!(!hold.waits(true, 1_000 + HOLD_NS), "the bound rings");
        assert!(!hold.on());
        // A queue that never empties still rings every HOLD_NS or so.
        let bells = bells_for(100, |_| true);
        assert!((5..=10).contains(&bells), "{bells} bells for 1 ms of calls");
        assert!(!hold.waits(false, 5));
    }

    #[test]
    fn a_frame_that_came_while_the_interrupts_went_on_continues_the_run() {
        use core::cell::Cell;
        // The gap: the queue is empty at the last look of the step and a
        // frame is there after the interrupts are on.
        let on = Cell::new(false);
        let told = Cell::new(0);
        let settled = settle_interrupts(
            false,
            || {
                told.set(told.get() + 1);
                true
            },
            |v| on.set(v),
            || on.get(),
        );
        assert!(
            settled,
            "without the second look the run ends with the frame waiting"
        );
        assert_eq!(told.get(), 1);
        assert!(
            !on.get(),
            "the interrupts are off again while the run goes on"
        );
        // A run that goes on asks for no look and keeps the interrupts off.
        let settled = settle_interrupts(true, || false, |v| on.set(v), || true);
        assert!(settled);
        assert!(!on.get());
        // Nothing in the queue: the interrupts stay on.
        let settled = settle_interrupts(false, || false, |v| on.set(v), || false);
        assert!(!settled);
        assert!(on.get());
    }

    #[test]
    fn a_step_that_ends_its_receiving_keeps_the_frames_it_took() {
        let mut budget = Budget::with(4, 4);
        assert!(budget.take_rx() && budget.take_rx());
        budget.end_rx();
        assert_eq!((budget.rx_left(), budget.spent()), (0, (2, 0)));
        assert!(!budget.take_rx());
        assert!(budget.take_tx());
        assert_eq!(budget.spent(), (2, 1));
    }

    #[test]
    fn the_loop_keeps_frames_in_order_and_holds_the_place_until_done() {
        let mut book = LoopBook::new();
        assert_eq!(book.pop(), None);
        let a = book.push().unwrap();
        let b = book.push().unwrap();
        assert_ne!(a, b);
        assert_eq!(book.waiting(), 2);
        assert_eq!(book.pop(), Some(a));
        // The frame read is still held: its reply goes to the next place.
        let c = book.push().unwrap();
        assert!(c != a && c != b);
        book.done();
        assert_eq!(book.pop(), Some(b));
        assert_eq!(book.pop(), Some(c));
        assert_eq!(book.pop(), None);
    }

    #[test]
    fn the_loop_refuses_a_frame_when_it_is_full() {
        let mut book = LoopBook::new();
        for _ in 0..LOOP_FRAMES {
            assert!(book.push().is_some());
        }
        assert_eq!(book.push(), None);
        assert!(book.pop().is_some());
        assert_eq!(book.push(), None, "a place is free after done alone");
        assert_eq!(book.done(), Some(0));
        assert!(book.push().is_some());
        assert_eq!(book.waiting(), LOOP_FRAMES);
    }

    #[test]
    fn the_step_of_waking_tells_eight_and_checks_thirty_two() {
        let mut budget = WakeBudget::new();
        for _ in 0..WAKE_TELLS {
            assert!(budget.take_tell());
        }
        assert!(!budget.take_tell());
        for _ in 0..WAKE_CHECKS {
            assert!(budget.take_check());
        }
        assert!(!budget.take_check());
    }

    #[test]
    fn a_step_receives_and_sends_a_batch_of_frames() {
        let mut budget = Budget::new();
        for _ in 0..STEP_RX {
            assert!(budget.take_rx());
        }
        assert!(!budget.take_rx());
        assert_eq!(budget.tx_left(), STEP_TX);
        for _ in 0..STEP_TX {
            assert!(budget.take_tx());
        }
        assert!(!budget.take_tx());
        assert_eq!(budget.spent(), (STEP_RX, STEP_TX));
        assert_eq!(budget.rx_left(), 0);
    }

    #[test]
    fn a_step_of_receiving_answers_as_many_frames_and_a_step_of_sending_receives_none() {
        let mut receiving = Budget::receiving();
        assert_eq!(receiving.rx_left(), STEP_RX);
        assert_eq!(receiving.tx_left(), STEP_RX);
        assert!(receiving.take_rx());
        let mut sending = Budget::sending();
        assert!(!sending.take_rx());
        assert_eq!(sending.tx_left(), STEP_TX);
        assert_eq!(Budget::with(3, 5).spent(), (0, 0));
    }

    /// The last of the pool's buffers goes round the loop many times, as the
    /// seeding of neighbours and the receiving without answers do in idle: no
    /// buffer is lost and the list of returned ones never overflows.
    #[test]
    fn buffers_of_the_loop_go_back_to_the_pool_after_many_seeds_without_answers() {
        let ring = LoopRing::new();
        let mut pool = TxBook::new();
        for _ in 0..200 {
            // The seeding of two ARP replies.
            while let Some(n) = ring.take_returned() {
                assert!(pool.release(n));
            }
            for _ in 0..2 {
                let n = pool.alloc().expect("a buffer");
                assert!(ring.push(n, 42));
            }
            // The reception of them, with no answer.
            while let Some(_frame) = ring.pop() {
                ring.done();
            }
        }
        while let Some(n) = ring.take_returned() {
            assert!(pool.release(n));
        }
        assert_eq!(pool.free(), TX_BUFFERS);
        assert_eq!(ring.dropped(), 0);
    }

    #[test]
    fn a_frame_of_sending_leaves_a_place_for_the_answer_to_the_frame_being_read() {
        let mut book = LoopBook::new();
        let mut built = 0;
        while book.room_to_send() {
            book.push().unwrap();
            built += 1;
        }
        assert_eq!(built, LOOP_FRAMES - 1);
        // The answers to the frames read: each takes the place the stack needs
        // while its frame is still held, and none is lost.
        for _ in 0..built {
            book.pop().unwrap();
            assert!(book.push().is_some(), "an answer finds a place");
            book.done();
        }
    }

    #[test]
    fn a_full_queue_of_orphans_loses_no_live_one() {
        // A live stream is a place whose time is odd; the others went.
        let live = |_place: usize, at: u64| at % 2 == 1;
        let mut q = OrphanQueue::<8>::new();
        // A young live head, then entries that go stale (closed in the
        // middle), until the queue is full.
        q.push(0, 1, live);
        for k in 1..8 {
            q.push(k, 2 * k as u64, live);
        }
        assert_eq!(q.len(), 8);
        // A new live stream: the stale ones are dropped and the head stays.
        q.push(9, 21, live);
        assert_eq!(q.len(), 2);
        assert_eq!(q.get(0), Some((0, 1)));
        assert_eq!(q.get(1), Some((9, 21)));
        assert_eq!(q.front(live), Some((0, 1)));
        q.pop();
        assert_eq!(q.front(live), Some((9, 21)));
        q.pop();
        assert_eq!(q.front(live), None);
        assert!(q.is_empty());
    }

    #[test]
    fn compacting_a_wrapped_queue_keeps_every_live_entry() {
        // The head is in the middle of the array and the entries run over
        // its end; the live ones are the odd times.
        let live = |_place: usize, at: u64| at % 2 == 1;
        let mut q = OrphanQueue::<8>::new();
        for k in 0..6u64 {
            q.push(k as usize, 100 + k, |_, _| true);
        }
        for _ in 0..6 {
            q.pop();
        }
        // Head at 6: eight entries wrap to 0..6.
        let times = [3u64, 5, 7, 8, 10, 12, 14, 16];
        for (k, at) in times.into_iter().enumerate() {
            q.push(10 + k, at, |_, _| true);
        }
        assert_eq!(q.len(), 8);
        q.push(30, 31, live);
        assert_eq!(q.len(), 4);
        let got: Vec<_> = (0..q.len()).map(|k| q.get(k).unwrap()).collect();
        assert_eq!(got, vec![(10, 3), (11, 5), (12, 7), (30, 31)]);
    }

    #[test]
    fn a_walk_round_visits_each_place_once_and_resumes() {
        let marked = [true, false, true, true, false, true, true, false];
        let next = |from: usize| (from..marked.len()).find(|&i| marked[i]);
        // Two places a call: 0 2 | 3 5 | 6, and the third call reaches the end.
        let mut cursor = 0;
        let mut seen = Vec::new();
        let mut calls = 0;
        loop {
            calls += 1;
            assert!(calls < 10, "the walk must end");
            let done = walk_round(&mut cursor, 2, next, |m| {
                seen.push(m);
                true
            });
            if done {
                break;
            }
        }
        assert_eq!(seen, vec![0, 2, 3, 5, 6]);
        assert_eq!(calls, 3);
        assert_eq!(cursor, 0, "the next walk starts at the beginning");
        // A visit that leaves the place keeps the cursor on it.
        let mut cursor = 0;
        assert!(!walk_round(&mut cursor, 16, next, |m| m != 3));
        assert_eq!(cursor, 3);
        // Many marked places: a call looks at CHECKS of them at most.
        let all = |from: usize| (from < 100).then_some(from);
        let mut cursor = 0;
        let mut count = 0;
        assert!(!walk_round(&mut cursor, 32, all, |_| {
            count += 1;
            true
        }));
        assert_eq!((count, cursor), (32, 32));
    }

    #[test]
    fn the_queue_goes_round_its_array() {
        let live = |_: usize, _: u64| true;
        let mut q = OrphanQueue::<4>::new();
        for round in 0..10u64 {
            q.push(1, round, live);
            q.push(2, round, live);
            assert_eq!(q.front(live).map(|e| e.1), Some(round));
            q.pop();
            q.pop();
        }
        assert!(q.is_empty());
    }

    #[test]
    fn a_key_a_client_made_up_names_no_operation() {
        assert_eq!(op_index(0, 128), None);
        assert_eq!(op_index(1 << 32, 128), None, "generation only");
        assert_eq!(op_index(129, 128), None);
        assert_eq!(op_index(u64::MAX, 128), None);
        assert_eq!(op_index(1, 128), Some(0));
        assert_eq!(op_index((7 << 32) | 128, 128), Some(127));
    }

    #[test]
    fn the_next_step_goes_round_the_bits() {
        let order = [16, 1, 4, 2, 8];
        // Receiving asks for itself again: the others still run.
        let all = 16 | 1 | 4 | 2 | 8;
        let mut last = 0;
        let mut run = Vec::new();
        for _ in 0..5 {
            let at = next_bit(&order, all, last).unwrap();
            run.push(order[at]);
            last = at;
        }
        assert_eq!(run, [1, 4, 2, 8, 16]);
        assert_eq!(next_bit(&order, 16, 0), Some(0), "alone it runs again");
        assert_eq!(next_bit(&order, 0, 0), None);
        assert_eq!(next_bit(&order, 8 | 16, 2), Some(4));
    }

    #[test]
    fn the_loop_holds_the_frames_of_two_steps() {
        const { assert!(LOOP_FRAMES >= 2 * STEP_TX && LOOP_FRAMES >= 2 * STEP_RX) };
    }

    #[test]
    fn abandon_lets_go_of_four_at_most() {
        let left = core::cell::Cell::new(10);
        let mut one = || {
            if left.get() == 0 {
                return false;
            }
            left.set(left.get() - 1);
            true
        };
        assert_eq!(abandon_portion(&mut one), (4, true));
        assert_eq!(abandon_portion(&mut one), (4, true));
        assert_eq!(left.get(), 2);
        assert_eq!(abandon_portion(&mut one), (2, false));
        assert_eq!(abandon_portion(&mut one), (0, false));
    }

    /// A model of the switch for `drive`: every step costs `cost` ns of the thread's time and
    /// is followed by another (the supply never ends); `pause` lets the lower levels run for
    /// `SWITCH_PAUSE_NS`. `others` collects the longest stretch they were kept off.
    struct Model {
        now: u64,
        cost: u64,
        ends_at: u64,
        pauses_work: bool,
        since_others: u64,
        worst: u64,
        pauses: u32,
        seen: u64,
    }

    impl Stepper for Model {
        fn now(&mut self) -> u64 {
            self.now
        }
        fn step(&mut self, _: bool) -> bool {
            self.now += self.cost;
            self.since_others += self.cost;
            self.worst = self.worst.max(self.since_others);
            self.now < self.ends_at
        }
        fn pause(&mut self) -> bool {
            if !self.pauses_work {
                return false;
            }
            self.now += SWITCH_PAUSE_NS;
            self.since_others = 0;
            self.pauses += 1;
            true
        }
        fn longest(&mut self, ran: u64) {
            self.seen = ran;
        }
    }

    fn model(pauses_work: bool, total: u64) -> Model {
        let mut m = Model {
            now: 1_000_000,
            cost: 5_000,
            ends_at: 1_000_000 + total,
            pauses_work,
            since_others: 0,
            worst: 0,
            pauses: 0,
            seen: 0,
        };
        let mut clock = RunClock::new();
        clock.woke(m.now, 1_000);
        let mut longest = 0;
        drive(&mut m, &mut clock, &mut longest, true);
        m
    }

    #[test]
    fn a_switch_whose_pause_never_happens_starves_the_levels_below_it() {
        // The loop of the thread with a pause that fails (a timer that refuses): the lower
        // levels are kept off for the whole load, which is what init's watchdog kills for.
        let total = 3_000_000_000;
        let m = model(false, total);
        assert!(m.worst >= total, "kept off {} ns", m.worst);
    }

    #[test]
    fn the_loop_of_the_thread_leaves_the_lower_levels_a_slot_every_run() {
        let m = model(true, 3_000_000_000);
        // One run and one step at most between two slots, a fifth of the time for them.
        assert!(m.worst <= SWITCH_RUN_NS + 5_000, "kept off {} ns", m.worst);
        assert!(m.pauses as u64 >= 3_000_000_000 / (SWITCH_RUN_NS + SWITCH_PAUSE_NS) - 1);
        assert!(
            m.seen <= SWITCH_RUN_NS + 5_000,
            "the longest run {}",
            m.seen
        );
    }

    #[test]
    fn a_refused_pause_starts_a_new_run_and_is_not_repeated_at_every_step() {
        let m = model(false, 100_000_000);
        // 100 ms of 5 us steps: one attempt for each run of 2 ms.
        assert!(
            m.pauses == 0 && m.seen <= SWITCH_RUN_NS + 5_000,
            "{}",
            m.seen
        );
    }

    #[test]
    fn the_budget_of_a_period_stops_the_consumers_and_the_next_period_gives_it_back() {
        let mut p = Period::new();
        p.refresh(5_000_000);
        let mut entries = 0;
        while p.left() {
            p.spend(1_000);
            entries += 1;
        }
        assert_eq!(entries, CONSUMER_BUDGET_NS / 1_000);
        assert!(!p.left(), "the budget is spent");
        assert_eq!(
            p.remaining(5_000_000 + 400_000),
            CONSUMER_PERIOD_NS - 400_000
        );
        p.refresh(5_000_000 + CONSUMER_PERIOD_NS - 1);
        assert!(!p.left(), "the period has not ended");
        p.refresh(5_000_000 + CONSUMER_PERIOD_NS);
        assert!(p.left());
        // A late step does not move the grid: a step at 7.9 ms of the third period after the
        // first finds a period that began on the grid, 100 us from its end.
        p.spend(CONSUMER_BUDGET_NS);
        p.refresh(5_000_000 + 2 * CONSUMER_PERIOD_NS + 900_000);
        assert!(p.left(), "a new period");
        assert_eq!(
            p.remaining(5_000_000 + 2 * CONSUMER_PERIOD_NS + 900_000),
            100_000
        );
        // The consumers together hold 80 % of the CPU at most.
        const { assert!(CONSUMER_BUDGET_NS * 10 <= CONSUMER_PERIOD_NS * 8) };
    }

    #[test]
    fn a_run_goes_on_through_waits_that_return_at_once_and_ends_with_a_rest() {
        let mut clock = RunClock::new();
        clock.woke(100, 0);
        assert!(!clock.pause_due(100 + SWITCH_RUN_NS - 1));
        // A wait that returned at once (a notification was pending) is no rest.
        clock.woke(100 + SWITCH_RUN_NS - 1, SWITCH_REST_NS - 1);
        assert!(clock.pause_due(100 + SWITCH_RUN_NS));
        // A wait of `SWITCH_REST_NS` is one: the run begins anew.
        clock.woke(100 + SWITCH_RUN_NS, SWITCH_REST_NS);
        assert!(!clock.pause_due(100 + SWITCH_RUN_NS + 1));
        assert_eq!(clock.ran(100 + SWITCH_RUN_NS + 7), 7);
        clock.rested(1_000);
        assert_eq!(clock.ran(1_500), 500);
    }

    #[test]
    fn the_pause_leaves_the_lower_levels_a_fifth_of_the_time() {
        const { assert!(SWITCH_PAUSE_NS * 5 <= SWITCH_RUN_NS + SWITCH_PAUSE_NS) };
    }
}
