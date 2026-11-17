// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The consumers of the switch over the ENA kind of device: the tables, the commands of the
//! stack, the rings of the consumers and the budgets of `switch.rs`, over the wire of
//! `enawire.rs` where the Virtio switch has its two queues. The rules are the Virtio switch's
//! for a device with no offload and no merged segments (what the consumers are told at ATTACH:
//! `offload` and `tso` false): the consumers complete their own sums, a frame of the
//! segmentation offload is refused, a frame of the wire is routed by `switchlogic::route`
//! and copied into the ring of its consumer or passed to the stack's lane.
//!
//! The step here replaces `Wire::step` when the service has consumers; everything it decides
//! runs on the host over the model of the device (the tests below). One instance of the
//! stack: the lane is the one of `route::DEFAULT_INSTANCE`.
//!
//! Buffers. A buffer of sending is in one place at a time, as in `switch.rs`: the pool (the
//! wire's), lent to the stack (`tx_supply`), the stack's frame in `tx_sub`, the device's
//! (queued, on its owner's account), or the stack's again when the switch turns a frame of
//! a consumer into the tables (`rx_ready`, back through `rx_back`). The account is
//! `inflight`: a consumer's number below `MAX_CONSUMERS`, the stack's at it.

use crate::books::{self, Woken};
use crate::enawire::{Rings, Rx, Wire};
use crate::frames::HDR_LEN;
use crate::ring::{
    PARK_GIVE, Period, RX_AHEAD, STACK_SHARE, SWEEP_IDLE_NS, SWEEP_PIECE, SWITCH_BASE, SWITCH_CTX,
    SWITCH_ROUTED, SWITCH_SOFT, SWITCH_TX, TX_BUFFERS,
};
use crate::spsc::{pack_frame, unpack_frame};
use crate::stats::Stats;
use crate::switchlogic::commands::{self, Commands};
use crate::switchlogic::ring::Tx;
use crate::switchlogic::route::{self, Decision, Reason, Source, Verdict};
use crate::switchlogic::sums;
use crate::switchlogic::tables::{MAX_CONSUMERS, Tables};
use core::sync::atomic::Ordering::Relaxed;
use ena::Platform;
use proto_net::switch::CELL;

/// The account of the stack's own frames in the queue of sending.
const STACK: usize = MAX_CONSUMERS;

/// What the caller of `Routed::step` does after it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Out {
    /// Frames were put in the ring of the stack: wake it.
    pub passed: bool,
    /// Buffers of sending were lent to a stack that was out of them: wake it.
    pub lent: bool,
    /// Another step follows at once.
    pub more: bool,
    /// The queue is out of step: the admin side must reset the device.
    pub broken: bool,
    /// The switch put answers in `Commands::to_stack` that the stack has not looked at.
    pub back: bool,
    /// A timer is wanted after this many nanoseconds (the sweep of the flows, entries that
    /// wait for a buffer or for the next period).
    pub timer: Option<u64>,
}

pub struct Routed {
    pub tables: Tables<'static>,
    /// The frame of a consumer, copied out of its ring and checked here.
    scratch: [u8; CELL],
    /// The buffers of the queue of sending on each account.
    inflight: [u16; MAX_CONSUMERS + 1],
    period: Period,
    /// The consumer whose frames come first in the next step.
    next_c: u8,
    /// Frames of consumers wait for a buffer or a share (see `consumer_frames`), and a
    /// consumer spent its entries of the period.
    blocked: bool,
    budget_hit: bool,
    last_sweep: u64,
    settle_until: u32,
    consumers_before: usize,
    woken: Woken,
    /// The `switch_idle` flags are set in the rings.
    idle_set: bool,
    /// The thread's clock in ticks (the soft share of a step is in them) and in nanoseconds
    /// (the period of the consumers), and the ticks at the start of the step.
    ticks: fn() -> u64,
    nanos: fn() -> u64,
    step_began: u64,
    passed: bool,
}

/// The consumers of `t` that are attached now.
fn attached(t: &Tables<'_>) -> usize {
    t.consumers.iter().flatten().count()
}

impl Routed {
    pub fn new(tables: Tables<'static>, ticks: fn() -> u64, nanos: fn() -> u64) -> Routed {
        Routed {
            tables,
            scratch: [0; CELL],
            inflight: [0; MAX_CONSUMERS + 1],
            period: Period::new(),
            next_c: 0,
            blocked: false,
            budget_hit: false,
            last_sweep: 0,
            settle_until: 0,
            consumers_before: 0,
            woken: Woken::new(),
            idle_set: false,
            ticks,
            nanos,
            step_began: 0,
            passed: false,
        }
    }

    /// The buffers of the queue of sending one consumer may have at a time.
    fn consumer_cap(&self) -> usize {
        ((TX_BUFFERS - STACK_SHARE) / attached(&self.tables).max(1)).max(4)
    }

    fn over_soft(&self) -> bool {
        (self.ticks)().saturating_sub(self.step_began) > SWITCH_SOFT
    }

    /// The frames of the stack and of the consumers come in the lane's rings, the sent buffers
    /// come back, the frames of the wire go to the stack or to a consumer, and the doorbells
    /// ring. `now` is in nanoseconds; `wake` is told the raw handle of each consumer that
    /// sleeps and has news.
    pub fn step<P: Platform + Clone>(
        &mut self,
        wire: &mut Wire<P>,
        lane: &Rings<'_>,
        now: u64,
        queue: &Commands,
        stats: &Stats,
        wake: &mut dyn FnMut(u64),
    ) -> Out {
        let mut out = Out::default();
        if self.idle_set {
            self.clear_idle();
        }
        self.step_began = (self.ticks)();
        self.passed = false;
        let more_park;
        {
            let t = &mut self.tables;
            t.now = (now / 1_000_000_000) as u32;
            t.now_ms = (now / 1_000_000) as u32;
            commands::drain(t, queue);
            commands::poll(t, queue);
            // SYNs that waited for a member: members that joined get them (at most
            // `PARK_GIVE` a step), the others expire.
            let given = route::unpark(t, PARK_GIVE);
            stats.rx_consumer.fetch_add(given as u32, Relaxed);
            stats.park_given.fetch_add(given as u32, Relaxed);
            more_park = given == PARK_GIVE;
        }
        // Sustained load that keeps every step over its soft share would keep the sweep off:
        // once it is overdue a piece goes in first.
        if crate::ring::sweep_piece_due(now.wrapping_sub(self.last_sweep)) {
            self.last_sweep = now;
            self.tables.sweep_piece(SWEEP_PIECE);
        }
        // What the stack gave back, then its frames to send.
        wire.take_back(lane);
        let mut taken = 0;
        let mut sub_budget = SWITCH_TX;
        while sub_budget > 0 {
            let Some(word) = lane.tx_sub.pop() else {
                break;
            };
            sub_budget -= 1;
            let (n, len, partial) = unpack_frame(word);
            let turned = self.stack_frame(wire, lane, stats, n, usize::from(len), partial);
            // A frame turned into the tables costs a copy and a route as a frame of a consumer
            // does: past the first few the step goes on only while it is short.
            taken += usize::from(turned);
            if turned && !books::may_take(taken, SWITCH_BASE, self.over_soft()) {
                sub_budget = 0;
            }
        }
        let inflight = &mut self.inflight;
        out.broken |= wire.reclaim(|owner| {
            let slot = &mut inflight[usize::from(owner).min(STACK)];
            *slot = slot.saturating_sub(1);
        });
        out.lent = wire.lend(
            lane,
            STACK_SHARE,
            lane.tx_sub.len() + usize::from(self.inflight[STACK]),
        );
        let more_c = self.consumer_frames(wire, lane, stats);
        // The frames of the wire.
        let mut room = RX_AHEAD.saturating_sub(lane.rx_ready.len());
        let budget = room.min(SWITCH_ROUTED);
        out.broken |= self.receive(wire, lane, stats, budget, &mut room);
        // The sweep goes only into a step that is inside its soft share.
        let since = now.wrapping_sub(self.last_sweep);
        if crate::ring::sweep_at_end(
            since,
            (self.ticks)().saturating_sub(self.step_began) > crate::ring::SWEEP_SOFT,
        ) {
            self.last_sweep = now;
            self.tables.sweep();
        }
        out.timer = self.after_tables(now, stats, wake);
        out.back = !queue.to_stack.is_empty();
        out.passed = self.passed;
        let more_rx = room > 0 && wire.rx_ready();
        let mut more = more_rx
            || more_c
            || more_park
            || !lane.tx_sub.is_empty()
            || !lane.rx_back.is_empty()
            || !lane.tx_back.is_empty()
            || !queue.to_switch.is_empty();
        if !more {
            // The consumers' flags go up before the last look at their rings.
            more = self.go_idle(wire, queue);
        }
        out.more = wire.bells(lane) || more;
        out
    }

    /// The end of a run when the caller looked at the queue once more and found a frame: the
    /// consumers' flags come down.
    pub fn clear_idle(&mut self) {
        self.idle_set = false;
        for x in self.tables.consumers.iter().flatten() {
            x.ring.set_switch_idle(false);
        }
    }

    /// The last look before sleeping: every ring gets `switch_idle = 1`, a full barrier
    /// follows, and a frame a consumer wrote meanwhile (or a command) cancels the sleep.
    fn go_idle<P: Platform + Clone>(&mut self, wire: &Wire<P>, queue: &Commands) -> bool {
        let mut any = false;
        for x in self.tables.consumers.iter().flatten() {
            // A consumer that spent its budget does not poke the switch: its entries wait for
            // the timer of the next period.
            x.ring.set_switch_idle(self.period.left());
            any = true;
        }
        if !any {
            return false;
        }
        self.idle_set = true;
        // A consumer whose frame waits for a buffer or its share of the queue is no work (the
        // 1 ms timer and the returned buffers look at it again).
        let (cap, free) = (self.consumer_cap(), wire.tx_free());
        let work = books::has_work(
            self.tables
                .consumers
                .iter()
                .enumerate()
                .filter_map(|(c, x)| {
                    x.as_ref().map(|x| {
                        (
                            x.ring.tx_pending() && self.period.left(),
                            usize::from(self.inflight[c]),
                        )
                    })
                }),
            cap,
            free,
            !queue.to_switch.is_empty(),
        );
        if work {
            self.clear_idle();
        }
        work
    }

    /// A frame of the stack: a turn to the shared address goes through the tables, any other
    /// into the queue. Whether the frame was turned into the tables.
    fn stack_frame<P: Platform + Clone>(
        &mut self,
        wire: &mut Wire<P>,
        lane: &Rings<'_>,
        stats: &Stats,
        n: u16,
        len: usize,
        partial: bool,
    ) -> bool {
        let slice = wire.bytes(n);
        let frame = &slice[HDR_LEN..HDR_LEN + len];
        let t = &mut self.tables;
        if route::faces_own(t, frame) || route::faces_loop(frame) {
            let decision = if route::faces_loop(frame) {
                stats.looped.fetch_add(1, Relaxed);
                route::route_loop(t, frame)
            } else {
                stats.hairpin.fetch_add(1, Relaxed);
                route::route(t, frame, Source::Stack)
            };
            match decision {
                // A stale byte of the stack's: the frame goes back, and the stack answers it. A
                // full ring of frames for the stack drops it (TCP repeats it).
                Decision::Stack | Decision::Instance(_) => {
                    if books::offer(lane.rx_ready, pack_frame(n, len as u16, partial)) {
                        self.passed = true;
                    } else {
                        wire.tx_release(n);
                    }
                }
                Decision::Drop(why) => {
                    stats.drops[why as usize].fetch_add(1, Relaxed);
                    wire.tx_release(n);
                }
                d => {
                    if let Decision::Consumer { consumer, .. } = d {
                        stats.rx_consumer.fetch_add(1, Relaxed);
                        stats.rx_by[usize::from(consumer) % 8].fetch_add(1, Relaxed);
                    }
                    // The frame never reaches the device: a partial sum is good as it is.
                    route::deliver(t, sums::mark(d, partial), frame);
                    wire.tx_release(n);
                }
            }
            return true;
        }
        // The stack sums its own segments on a device with no offload (`partial` is never
        // set): the frame goes as it is.
        if wire.submit(n, len as u16, STACK as u8) {
            self.inflight[STACK] += 1;
        }
        false
    }

    /// Takes frames of the consumers' TX rings in turn, one from each in a round, up to
    /// `SWITCH_CTX`, and starts the next step with the next consumer. True when frames are
    /// left.
    fn consumer_frames<P: Platform + Clone>(
        &mut self,
        wire: &mut Wire<P>,
        lane: &Rings<'_>,
        stats: &Stats,
    ) -> bool {
        let cap = self.consumer_cap();
        self.period.refresh((self.nanos)());
        let mut budget = SWITCH_CTX;
        let mut taken = 0;
        let mut progressed = true;
        let mut blocked = false;
        let mut spent = false;
        while budget > 0 && progressed {
            progressed = false;
            for k in 0..MAX_CONSUMERS {
                if budget == 0 {
                    break;
                }
                // Frames past the first few go on only while the step is short.
                if !books::may_take(taken, SWITCH_BASE, self.over_soft()) {
                    budget = 0;
                    break;
                }
                let c = (usize::from(self.next_c) + k) % MAX_CONSUMERS;
                // A frame waits in its ring while this consumer holds its share of the queue,
                // or no buffer is free.
                if books::blocked(usize::from(self.inflight[c]), cap, wire.tx_free()) {
                    blocked = true;
                    continue;
                }
                // The consumer spent its entries of this period: the rest waits for the timer.
                if !self.period.left() {
                    blocked = true;
                    spent = true;
                    continue;
                }
                let Some(x) = self.tables.consumers[c].as_mut() else {
                    continue;
                };
                let began = (self.nanos)();
                match x.ring.take_tx(&mut self.scratch) {
                    Tx::Empty => {}
                    Tx::Refused => {
                        x.ring.refused = x.ring.refused.wrapping_add(1);
                        progressed = true;
                        budget -= 1;
                        taken += 1;
                    }
                    Tx::Frame(len) => {
                        progressed = true;
                        budget -= 1;
                        taken += 1;
                        self.consumer_frame(wire, lane, stats, c as u8, len);
                    }
                    Tx::Sum(len) => {
                        // ATTACH said the device has no offload: the entry is refused.
                        progressed = true;
                        budget -= 1;
                        taken += 1;
                        let _ = len;
                        route::refuse_tx(&mut self.tables, c as u8, Reason::Sum);
                    }
                    Tx::Loop(len) => {
                        progressed = true;
                        budget -= 1;
                        taken += 1;
                        self.consumer_loop(wire, lane, stats, c as u8, len);
                    }
                    Tx::Tso { .. } => {
                        // And that it does not cut.
                        progressed = true;
                        budget -= 1;
                        taken += 1;
                        route::refuse_tx(&mut self.tables, c as u8, Reason::Tso);
                        if let Some(x) = self.tables.consumers[c].as_mut() {
                            x.ring.tso_done();
                        }
                    }
                }
                self.period.spend((self.nanos)().wrapping_sub(began));
            }
        }
        self.budget_hit = spent;
        if spent {
            stats.budget_waits.fetch_add(1, Relaxed);
        }
        self.next_c = (self.next_c + 1) % MAX_CONSUMERS as u8;
        // Frames that wait for a buffer or a share of the queue do not make the switch run
        // again at once (it would spin above the stack): the timer looks again in a
        // millisecond, and the steps that return buffers go on as before.
        let waiting = self
            .tables
            .consumers
            .iter()
            .flatten()
            .any(|x| x.ring.tx_waiting());
        self.blocked = blocked && waiting;
        // More follows at once only for entries that may still be taken.
        budget == 0 && self.period.left() && waiting
    }

    /// The frame of consumer `c` (in `scratch`, `len` bytes): checked, then sent, or turned
    /// into the tables when it is for the shared address.
    fn consumer_frame<P: Platform + Clone>(
        &mut self,
        wire: &mut Wire<P>,
        lane: &Rings<'_>,
        stats: &Stats,
        c: u8,
        len: usize,
    ) {
        let t = &mut self.tables;
        let frame = &self.scratch[..len];
        match route::check_tx(t, c, frame) {
            // `check_tx` never answers the last two (the entries flagged `TX_LOOP` go through
            // `check_tx_loop`).
            Verdict::Refuse(_) | Verdict::Loop | Verdict::Broke => {}
            Verdict::Send => {
                let Some(n) = wire.tx_alloc() else {
                    return;
                };
                wire.bytes(n)[HDR_LEN..HDR_LEN + len].copy_from_slice(frame);
                if wire.submit(n, len as u16, c) {
                    stats.tx_consumer.fetch_add(1, Relaxed);
                    self.inflight[usize::from(c)] += 1;
                }
            }
            Verdict::Hairpin => {
                stats.hairpin.fetch_add(1, Relaxed);
                let d = route::route(t, frame, Source::Consumer(c));
                match d {
                    Decision::Drop(why) => {
                        stats.drops[why as usize].fetch_add(1, Relaxed);
                    }
                    Decision::Stack | Decision::Instance(_) | Decision::ArpAll => {
                        route::deliver(t, d, frame);
                        // The stack gets a buffer of sending to read the frame in; it comes
                        // back through `rx_back`. The frame never reaches the device.
                        if let Some(n) = wire.tx_alloc() {
                            wire.bytes(n)[HDR_LEN..HDR_LEN + len].copy_from_slice(frame);
                            if books::offer(lane.rx_ready, pack_frame(n, len as u16, false)) {
                                self.passed = true;
                            } else {
                                wire.tx_release(n);
                            }
                        }
                    }
                    d => {
                        route::deliver(t, sums::mark(d, false), frame);
                    }
                }
            }
        }
    }

    /// A packet of the loopback network of consumer `c` (entry flagged `TX_LOOP`, copied into
    /// `scratch`): checked, then routed by its port to the stack of the service or to a consumer.
    fn consumer_loop<P: Platform + Clone>(
        &mut self,
        wire: &mut Wire<P>,
        lane: &Rings<'_>,
        stats: &Stats,
        c: u8,
        len: usize,
    ) {
        let t = &mut self.tables;
        let frame = &self.scratch[..len];
        if route::check_tx_loop(t, c, frame) != Verdict::Loop {
            return;
        }
        stats.looped.fetch_add(1, Relaxed);
        match route::route_loop(t, frame) {
            Decision::Drop(why) => {
                stats.drops[why as usize].fetch_add(1, Relaxed);
            }
            Decision::Stack | Decision::Instance(_) | Decision::ArpAll => {
                if let Some(n) = wire.tx_alloc() {
                    wire.bytes(n)[HDR_LEN..HDR_LEN + len].copy_from_slice(frame);
                    // No sums are on the loopback, and none is checked.
                    if books::offer(lane.rx_ready, pack_frame(n, len as u16, true)) {
                        self.passed = true;
                    } else {
                        wire.tx_release(n);
                    }
                }
            }
            d => {
                route::deliver(t, d, frame);
            }
        }
    }

    /// Takes up to `budget` frames off the queue of receiving, each to the stack (its buffer
    /// and the length of its frame), to a consumer (copied into its ring, the buffer back in
    /// the queue), or back to the queue when the tables drop it. `room` is what the lane can
    /// still take: a frame for the stack with no room is dropped and counted. True when the
    /// queue is out of step.
    fn receive<P: Platform + Clone>(
        &mut self,
        wire: &mut Wire<P>,
        lane: &Rings<'_>,
        stats: &Stats,
        mut budget: usize,
        room: &mut usize,
    ) -> bool {
        let mut taken = 0;
        while budget > 0 {
            if taken >= SWITCH_BASE && self.over_soft() {
                break;
            }
            taken += 1;
            let (n, len) = match wire.rx_take() {
                Rx::Empty => break,
                Rx::Broken => return true,
                Rx::Skipped => {
                    budget -= 1;
                    continue;
                }
                Rx::Frame { n, len } => (n, len),
            };
            budget -= 1;
            let slice = wire.bytes(n);
            let frame = &slice[HDR_LEN..HDR_LEN + len];
            match route::route(&mut self.tables, frame, Source::Wire) {
                Decision::Drop(why) => {
                    stats.drops[why as usize].fetch_add(1, Relaxed);
                    wire.dropped(n);
                }
                d => {
                    if let Decision::Consumer { consumer, .. } = d {
                        stats.rx_consumer.fetch_add(1, Relaxed);
                        stats.rx_by[usize::from(consumer) % 8].fetch_add(1, Relaxed);
                    }
                    if !route::deliver(&mut self.tables, d, frame) {
                        wire.consumed(n);
                    } else if *room == 0 {
                        stats.lane_full.fetch_add(1, Relaxed);
                        wire.dropped(n);
                    } else {
                        *room -= 1;
                        // The ring cannot be full: `room` counted its free places.
                        if lane.rx_ready.push(pack_frame(n, len as u16, false)) {
                            wire.passed();
                            self.passed = true;
                        } else {
                            wire.dropped(n);
                        }
                    }
                }
            }
        }
        false
    }

    /// The end of a step: consumers with new frames are woken when they sleep, the counters and
    /// the indices are published, and the delay of the timer the sweep or the waiting entries
    /// want.
    fn after_tables(&mut self, now: u64, stats: &Stats, wake: &mut dyn FnMut(u64)) -> Option<u64> {
        let t = &mut self.tables;
        for (c, slot) in t.consumers.iter().enumerate() {
            let Some(x) = slot else { continue };
            x.ring.publish();
            let head = x.ring.done_head();
            // A new consumer on a number starts from nothing (`Woken` keys on the generation).
            if self.woken.news(c, x.generation, head) && x.wake != 0 && x.ring.consumer_idle() {
                wake(x.wake);
            }
        }
        let count = attached(t);
        if count < self.consumers_before {
            self.settle_until = t.flows.rounds().wrapping_add(3);
        }
        self.consumers_before = count;
        stats.consumers.store(count as u32, Relaxed);
        stats.flows.store(t.flows.len() as u32, Relaxed);
        stats
            .unconfirmed
            .store(t.flows.unconfirmed() as u32, Relaxed);
        stats.evicted.store(t.flows.evicted, Relaxed);
        stats.expired.store(t.flows.expired, Relaxed);
        stats.left.store(t.left, Relaxed);
        let (mut full, mut refused) = (0u32, 0u32);
        for x in t.consumers.iter().flatten() {
            full = full.wrapping_add(x.ring.rx_full);
            refused = refused.wrapping_add(x.ring.refused);
        }
        stats.rx_full.store(full, Relaxed);
        stats.tx_refused.store(refused, Relaxed);
        for (slot, v) in stats.refused_by.iter().zip(t.refused.iter()) {
            slot.store(*v, Relaxed);
        }
        // A consumer left lately: the rounds that return its number follow fast.
        let settling = t.flows.rounds().wrapping_sub(self.settle_until) >= u32::MAX / 2;
        let sweeping = count > 0 || !t.flows.is_empty() || settling || t.parked() > 0;
        if !(sweeping || self.blocked) {
            return None;
        }
        Some(if self.blocked && self.budget_hit {
            // The entries wait for the next period.
            self.period.remaining(now).max(20_000)
        } else if self.blocked {
            1_000_000
        } else if settling {
            2_000_000
        } else {
            SWEEP_IDLE_NS
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::Proto;
    use crate::spsc::Spsc;
    use crate::switchlogic::ring::tests::Rig as RingRig;
    use crate::switchlogic::tables::tests::{OWN, SECRET, tag};
    use crate::switchlogic::tables::{Flow, Flows};
    use core::sync::atomic::AtomicBool;
    use ena::device::Event;
    use ena::io::{BUFFER_LEN, Buffers, IO_END};
    use ena::model::{Model, Scenario, region};
    use proto_net::switch::{self as sw, Layout};

    const MS: u64 = 1_000_000;
    const MSI: [Option<(u64, u32)>; 2] = [Some((0x0801_0040, 5)), Some((0x0801_0040, 6))];
    const PEER: ([u8; 6], [u8; 4]) = ([2, 0, 0, 0, 0, 9], [203, 0, 113, 9]);
    const ME: ([u8; 6], [u8; 4]) = (OWN.mac, OWN.ip);
    const BLOCK0: u16 = 49152;

    struct Lane {
        rx_ready: Spsc<256>,
        rx_back: Spsc<256>,
        tx_sub: Spsc<256>,
        tx_supply: Spsc<256>,
        tx_back: Spsc<256>,
        starved: AtomicBool,
    }

    impl Lane {
        fn rings(&self) -> Rings<'_> {
            Rings {
                rx_ready: &self.rx_ready,
                rx_back: &self.rx_back,
                tx_sub: &self.tx_sub,
                tx_supply: &self.tx_supply,
                tx_back: &self.tx_back,
                starved: &self.starved,
            }
        }
    }

    fn ticks() -> u64 {
        0
    }

    fn nanos() -> u64 {
        std::thread_local!(static NOW: core::cell::Cell<u64> = const { core::cell::Cell::new(0) });
        NOW.with(|n| {
            n.set(n.get() + 50_000);
            n.get()
        })
    }

    struct Rig {
        model: Model,
        wire: Wire<Model>,
        lane: &'static Lane,
        routed: Routed,
        rings: Vec<&'static RingRig>,
        commands: &'static Commands,
        stats: &'static Stats,
        bufs: Buffers,
        woken: Vec<u64>,
        _ena: ena::Ena<Model>,
    }

    fn ip_frame(
        src: ([u8; 6], [u8; 4]),
        dst: ([u8; 6], [u8; 4]),
        proto: u8,
        part: &[u8],
    ) -> Vec<u8> {
        let mut f = [dst.0.as_slice(), &src.0, &[8, 0]].concat();
        let total = (20 + part.len()) as u16;
        f.extend([
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0x40,
            0,
            64,
            proto,
            0,
            0,
        ]);
        f.extend([src.1, dst.1].concat());
        f.extend(part);
        f
    }

    fn tcp_part(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut p = [sport.to_be_bytes(), dport.to_be_bytes()].concat();
        p.extend([0; 9]);
        p.extend([flags, 0, 0, 0, 0, 0, 0]);
        p
    }

    fn rig() -> Rig {
        let mem = region(IO_END, 0x4_3000_0000);
        let model = Model::new(mem, 0, Scenario::default());
        let buffers = region(512 * BUFFER_LEN, 0x4_3200_0000);
        model.add_region(buffers);
        model.set_vectors(MSI);
        let bufs = Buffers {
            va: buffers.va,
            pa: buffers.pa,
            count: 512,
        };
        // SAFETY: the region is the model's heap block, which lives on.
        let mut ena = unsafe { ena::Ena::open(model.platform(), mem, 0) }.unwrap();
        ena.set_data_path(bufs, Some(ena::model::MSIX_TABLE))
            .unwrap();
        let mut wire = Wire::new(model.platform(), mem, bufs);
        for _ in 0..2_000 {
            for _ in 0..200 {
                if matches!(ena.poll(), Event::Idle) {
                    break;
                }
            }
            model.advance(MS);
        }
        wire.sync(2, ena.io_info().expect("up"));
        let ports = Box::leak(vec![0u8; 131072].into_boxed_slice());
        let flows = Box::leak(vec![Flow::EMPTY; 4096].into_boxed_slice());
        let mut t = Tables::new(OWN, ports, Flows::new(flows, &SECRET), tag);
        let mut rings = Vec::new();
        for c in 0..3u8 {
            let rig: &'static RingRig =
                Box::leak(Box::new(RingRig::new(Layout::new(256, 64).unwrap())));
            rig.fill(&(0..64).collect::<Vec<_>>());
            assert!(t.attach(c, 1, rig.ring(), BLOCK0 + 512 * u16::from(c)));
            rings.push(rig);
        }
        assert!(t.hold(1, Proto::Tcp, 8080, 1));
        assert!(t.join(1, 0) && t.join(1, 1));
        t.poll_rings(|_, _| panic!("a ring broke"));
        let lane: &'static Lane = Box::leak(Box::new(Lane {
            rx_ready: Spsc::new(),
            rx_back: Spsc::new(),
            tx_sub: Spsc::new(),
            tx_supply: Spsc::new(),
            tx_back: Spsc::new(),
            starved: AtomicBool::new(false),
        }));
        let mut r = Rig {
            model,
            wire,
            lane,
            routed: Routed::new(t, ticks, nanos),
            rings,
            commands: Box::leak(Box::new(Commands::new())),
            stats: Box::leak(Box::new(Stats::new())),
            bufs,
            woken: Vec::new(),
            _ena: ena,
        };
        r.step();
        r
    }

    impl Rig {
        fn step(&mut self) -> Out {
            let woken = &mut self.woken;
            self.routed.step(
                &mut self.wire,
                &self.lane.rings(),
                nanos(),
                self.commands,
                self.stats,
                &mut |h| woken.push(h),
            )
        }

        fn buffer(&self, n: u16) -> &'static mut [u8] {
            // SAFETY: inside the buffers' block, nobody else touches it in the test.
            unsafe { virtio_net::rings::buffer_at(self.bufs.va, n) }
        }

        fn send(&self, c: usize, frame: &[u8], flags: u16) {
            self.rings[c].send(frame, flags);
        }
    }

    #[test]
    fn a_syn_for_a_held_port_goes_to_a_consumer_and_its_buffer_returns_to_the_queue() {
        let mut r = rig();
        let syn = ip_frame(PEER, ME, 6, &tcp_part(40000, 8080, 2));
        assert!(r.model.inject(&syn));
        let out = r.step();
        assert!(!out.passed && !out.broken);
        assert!(r.lane.rx_ready.is_empty(), "the stack does not see it");
        let (member, frames) = (0..2)
            .find_map(|c| {
                let (d, f) = r.rings[c].done(0);
                (d.len > 0).then_some((c, f))
            })
            .expect("a member got it");
        assert_eq!(frames, syn, "member {member}");
        assert_eq!(r.stats.rx_consumer.load(Relaxed), 1);
        // The buffer is the device's again: as many frames as buffers go through.
        for _ in 0..600 {
            assert!(
                r.model
                    .inject(&ip_frame(PEER, ME, 6, &tcp_part(40000, 8080, 0x10)))
            );
            r.step();
        }
        assert_eq!(r.wire.counts().doubles, 0);
        assert_eq!(r.model.violations(), Vec::<String>::new());
    }

    #[test]
    fn a_frame_nothing_claims_goes_to_the_stack_with_its_bytes() {
        let mut r = rig();
        let udp = ip_frame(PEER, ME, 17, &[0, 5, 0, 6, 0, 12, 0, 0, 1, 2, 3, 4]);
        assert!(r.model.inject(&udp));
        let out = r.step();
        assert!(out.passed);
        let (n, len, _) = unpack_frame(r.lane.rx_ready.pop().expect("a frame"));
        assert_eq!(&r.buffer(n)[HDR_LEN..HDR_LEN + usize::from(len)], &udp[..]);
        r.lane.rx_back.push(u32::from(n));
        r.step();
        assert_eq!(r.wire.counts().doubles, 0);
    }

    #[test]
    fn a_frame_of_a_consumer_goes_out_on_its_account_and_the_account_closes() {
        let mut r = rig();
        let f = ip_frame(ME, PEER, 6, &tcp_part(BLOCK0 + 512 * 2 + 9, 80, 2));
        r.send(2, &f, sw::TX_FLAGS);
        r.step();
        r.step();
        assert_eq!(r.model.sent_frames().last().unwrap(), &f);
        assert_eq!(r.stats.tx_consumer.load(Relaxed), 1);
        r.model.advance(MS);
        r.step();
        assert_eq!(r.routed.inflight[2], 0, "the completion closed the account");
        assert_eq!(r.model.violations(), Vec::<String>::new());
    }

    #[test]
    fn a_frame_of_a_consumer_for_the_shared_address_is_turned_into_the_tables() {
        let mut r = rig();
        // To a port the other member holds: the frame goes into its ring, not to the device.
        let f = ip_frame(ME, ME, 6, &tcp_part(BLOCK0 + 512 * 2 + 1, 8080, 2));
        let sent = r.model.sent_frames().len();
        r.send(2, &f, sw::TX_FLAGS);
        r.step();
        assert_eq!(r.model.sent_frames().len(), sent, "never on the wire");
        assert_eq!(r.stats.hairpin.load(Relaxed), 1);
        assert!(
            r.rings[..2].iter().any(|g| g.done(0).0.len > 0) || !r.lane.rx_ready.is_empty(),
            "a member or the stack got it"
        );
    }

    #[test]
    fn an_entry_that_asks_for_the_offload_is_refused_and_counted() {
        let mut r = rig();
        let f = ip_frame(ME, PEER, 6, &tcp_part(BLOCK0 + 512 * 2 + 9, 80, 2));
        let sent = r.model.sent_frames().len();
        r.send(2, &f, sw::TX_SUM);
        r.step();
        r.step();
        assert_eq!(r.model.sent_frames().len(), sent);
        assert_eq!(r.routed.tables.refused[Reason::Sum as usize], 1);
        assert_eq!(r.stats.tx_refused.load(Relaxed), 1);
    }

    #[test]
    fn a_frame_of_the_stack_goes_out_and_its_share_is_counted_with_the_account() {
        let mut r = rig();
        let f = ip_frame(ME, PEER, 17, &[0, 5, 0, 6, 0, 12, 0, 0, 1, 2, 3, 4]);
        let b = r.lane.tx_supply.pop().expect("a lent buffer");
        assert!(
            r.lane.tx_supply.len() <= STACK_SHARE,
            "the stack's share is below the pool"
        );
        r.buffer(b as u16)[HDR_LEN..HDR_LEN + f.len()].copy_from_slice(&f);
        r.lane
            .tx_sub
            .push(pack_frame(b as u16, f.len() as u16, false));
        r.step();
        assert_eq!(r.model.sent_frames().last().unwrap(), &f);
        assert_eq!(r.routed.inflight[STACK], 1);
        r.model.advance(MS);
        r.step();
        assert_eq!(r.routed.inflight[STACK], 0);
    }

    #[test]
    fn a_stack_that_holds_its_share_is_lent_no_more_so_the_consumers_keep_buffers() {
        let r = rig();
        assert_eq!(r.lane.tx_supply.len(), STACK_SHARE);
        assert!(r.wire.tx_free() >= TX_BUFFERS - STACK_SHARE);
    }

    #[test]
    fn a_sleeping_consumer_with_news_is_woken_once_and_the_switch_may_sleep_when_idle() {
        let mut r = rig();
        for c in 0..2 {
            r.routed.tables.consumers[c].as_mut().unwrap().wake = 77 + c as u64;
            r.rings[c].mem().store(sw::CONSUMER_IDLE, 1);
        }
        let syn = ip_frame(PEER, ME, 6, &tcp_part(40000, 8080, 2));
        assert!(r.model.inject(&syn));
        r.step();
        assert_eq!(r.woken.len(), 1, "told once: {:?}", r.woken);
        assert!(r.woken[0] == 77 || r.woken[0] == 78);
        let out = r.step();
        assert!(!out.more, "idle: nothing left to do");
        assert!(r.routed.idle_set);
        assert_eq!(r.woken.len(), 1, "no news, no second wake");
    }
}
