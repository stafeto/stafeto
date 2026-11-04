// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The books of the two rings of the device (Virtio 1.2, 5.1.2): which
//! buffer of the network object each token of a queue stands for, the pool
//! of the buffers for sending, and the bounds of one step of the service.
//!
//! The buffers are numbered 0 to 511 in the network object, BUFFER_LEN
//! bytes each: 0 to 255 for receiving, 256 to 511 for sending. The queue
//! of the device's crate hands out a token (the number of the first
//! descriptor of the chain) that has nothing to do with the buffer's
//! number, so each ring keeps the map from token to buffer.

use crate::frames::BUFFER_LEN;

/// The entries of each queue.
pub const QUEUE_SIZE: usize = 256;
/// The buffers for receiving and for sending, and all of them.
pub const RX_BUFFERS: usize = QUEUE_SIZE;
pub const TX_BUFFERS: usize = QUEUE_SIZE;
pub const BUFFERS: usize = RX_BUFFERS + TX_BUFFERS;
/// The pages of the network object: 512 buffers of BUFFER_LEN bytes.
pub const NET_PAGES: usize = BUFFERS * BUFFER_LEN / 4096;
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
/// (`netd::choose::portion`): at 16 KiB the longest SEND took 7 113 ticks
/// and the longest RECV 7 294, the copy of a cell 3 584 (p90). The features `portion-16`, `portion-8` and
/// `portion-4` build each, for the measurement.
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
const _: () = assert!(NET_PAGES == 256);

/// The offset in the network object of buffer `n`.
pub const fn offset(n: u16) -> usize {
    n as usize * BUFFER_LEN
}

/// The ring of receiving: every buffer of 0 to 255 is in the device's
/// queue from the start, and goes back as soon as the stack is done with
/// the frame it held.
pub struct RxBook {
    buffer_of: [u16; QUEUE_SIZE],
    /// Whether the token is out with the device.
    out: [bool; QUEUE_SIZE],
}

impl RxBook {
    pub const fn new() -> RxBook {
        RxBook {
            buffer_of: [0; QUEUE_SIZE],
            out: [false; QUEUE_SIZE],
        }
    }

    /// Buffer `buffer` is in the queue under `token`. False for a token
    /// out of range, one already out, or a buffer that is no receive
    /// buffer: nothing is recorded.
    pub fn put(&mut self, token: u16, buffer: u16) -> bool {
        let t = usize::from(token);
        if t >= QUEUE_SIZE || self.out[t] || usize::from(buffer) >= RX_BUFFERS {
            return false;
        }
        self.buffer_of[t] = buffer;
        self.out[t] = true;
        true
    }

    /// The device returned `token`: its buffer, None for a token the
    /// device does not hold (a fault of the device).
    pub fn take(&mut self, token: u16) -> Option<u16> {
        let t = usize::from(token);
        if t >= QUEUE_SIZE || !self.out[t] {
            return None;
        }
        self.out[t] = false;
        Some(self.buffer_of[t])
    }

    /// How many buffers the device holds.
    pub fn outstanding(&self) -> usize {
        self.out.iter().filter(|&&o| o).count()
    }
}

impl Default for RxBook {
    fn default() -> RxBook {
        RxBook::new()
    }
}

/// The ring of sending: a pool of the buffers 256 to 511, the ones in the
/// queue under their tokens.
pub struct TxBook {
    /// The free buffers (their numbers, as a stack) and how many.
    free: [u16; TX_BUFFERS],
    free_len: usize,
    buffer_of: [u16; QUEUE_SIZE],
    out: [bool; QUEUE_SIZE],
}

impl TxBook {
    pub const fn new() -> TxBook {
        let mut free = [0; TX_BUFFERS];
        let mut i = 0;
        while i < TX_BUFFERS {
            // The first to leave is the lowest.
            free[i] = (BUFFERS - 1 - i) as u16;
            i += 1;
        }
        TxBook {
            free,
            free_len: TX_BUFFERS,
            buffer_of: [0; QUEUE_SIZE],
            out: [false; QUEUE_SIZE],
        }
    }

    /// How many buffers are free.
    pub fn free(&self) -> usize {
        self.free_len
    }

    /// Takes a free buffer.
    pub fn alloc(&mut self) -> Option<u16> {
        self.free_len = self.free_len.checked_sub(1)?;
        Some(self.free[self.free_len])
    }

    /// Gives back a buffer that was never sent.
    pub fn release(&mut self, buffer: u16) -> bool {
        let b = usize::from(buffer);
        if !(RX_BUFFERS..BUFFERS).contains(&b) || self.free_len == TX_BUFFERS {
            return false;
        }
        self.free[self.free_len] = buffer;
        self.free_len += 1;
        true
    }

    /// The buffer `buffer` is in the queue under `token`.
    pub fn sent(&mut self, token: u16, buffer: u16) -> bool {
        let t = usize::from(token);
        if t >= QUEUE_SIZE || self.out[t] || !(RX_BUFFERS..BUFFERS).contains(&usize::from(buffer)) {
            return false;
        }
        self.buffer_of[t] = buffer;
        self.out[t] = true;
        true
    }

    /// The device returned `token`: its buffer goes back to the pool. The
    /// buffer, None for a token the device does not hold.
    pub fn reclaim(&mut self, token: u16) -> Option<u16> {
        let t = usize::from(token);
        if t >= QUEUE_SIZE || !self.out[t] {
            return None;
        }
        let buffer = self.buffer_of[t];
        if !self.release(buffer) {
            return None;
        }
        self.out[t] = false;
        Some(buffer)
    }

    /// How many buffers the device holds.
    pub fn outstanding(&self) -> usize {
        self.out.iter().filter(|&&o| o).count()
    }
}

impl Default for TxBook {
    fn default() -> TxBook {
        TxBook::new()
    }
}

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
    fn the_object_holds_the_buffers() {
        assert_eq!(NET_PAGES * 4096, BUFFERS * BUFFER_LEN);
        assert_eq!(offset(0), 0);
        assert_eq!(offset(256), 256 * 2048);
        assert_eq!(offset(511) + BUFFER_LEN, NET_PAGES * 4096);
    }

    #[test]
    fn a_receive_token_leads_to_its_buffer_once() {
        let mut book = RxBook::new();
        // The queue hands out numbers of its own.
        assert!(book.put(7, 0));
        assert!(book.put(0, 255));
        assert_eq!(book.outstanding(), 2);
        assert!(!book.put(7, 1), "a token already out");
        assert!(!book.put(256, 1), "a token past the queue");
        assert!(!book.put(8, 256), "a send buffer");
        assert_eq!(book.take(7), Some(0));
        assert_eq!(book.take(7), None, "the device returned it twice");
        assert_eq!(book.take(0), Some(255));
        assert_eq!(book.take(300), None);
        assert_eq!(book.outstanding(), 0);
    }

    #[test]
    fn a_buffer_that_is_not_returned_stays_out() {
        // The fault the probe's 300 pings catch: 256 buffers are all.
        let mut book = RxBook::new();
        for n in 0..RX_BUFFERS as u16 {
            assert!(book.put(n, n));
        }
        assert_eq!(book.outstanding(), RX_BUFFERS);
        assert_eq!(book.take(5), Some(5));
        assert!(book.put(5, 5), "back in the queue");
    }

    #[test]
    fn the_send_pool_hands_out_buffers_above_the_receive_ones() {
        let mut pool = TxBook::new();
        assert_eq!(pool.free(), TX_BUFFERS);
        let first = pool.alloc().expect("a buffer");
        assert_eq!(first, 256);
        let mut seen = vec![first];
        while let Some(b) = pool.alloc() {
            assert!((256..512).contains(&b));
            assert!(!seen.contains(&b), "{b} twice");
            seen.push(b);
        }
        assert_eq!(seen.len(), TX_BUFFERS);
        assert_eq!(pool.free(), 0);
        assert_eq!(pool.alloc(), None);
    }

    #[test]
    fn a_sent_buffer_returns_to_the_pool_by_its_token() {
        let mut pool = TxBook::new();
        let a = pool.alloc().unwrap();
        let b = pool.alloc().unwrap();
        assert!(pool.sent(40, a));
        assert!(pool.sent(3, b));
        assert!(!pool.sent(3, b), "a token already out");
        assert_eq!(pool.outstanding(), 2);
        assert_eq!(pool.free(), TX_BUFFERS - 2);
        assert_eq!(pool.reclaim(3), Some(b));
        assert_eq!(pool.reclaim(3), None);
        assert_eq!(pool.reclaim(999), None);
        assert_eq!(pool.reclaim(40), Some(a));
        assert_eq!(pool.free(), TX_BUFFERS);
        // A buffer given back that is not the pool's.
        assert!(!pool.release(5));
        assert!(!pool.release(300), "the pool is full");
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
}
