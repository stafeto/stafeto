// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The switch thread: the first device's queues, its line and its
//! doorbells, apart from the stack. The service runs this thread and one thread of
//! `rt::service`'s loop for each stack instance (`instance.rs`; the first thread only
//! waits). This one runs one level above the instances on the CPU of the line's interrupts
//! and owns the transport, the two queues and the binding of the line; an instance (smoltcp,
//! the sockets, DHCP, ARP) is an internal consumer of the switch, numbered in its tables
//! (`netd::switchlogic::tables::Internal`), and sees the device as a lane of five rings of
//! words (`Lane`, `netd::spsc`) that carry the numbers of the buffers of the device: no frame
//! is copied, and each ring has one writer and one reader. The tables name the instance a
//! frame is for (`route::Decision::Instance`); a frame they leave to the stack goes to the
//! default instance.
//!
//! * `rx_ready`: the switch took a frame off the queue of receiving, looked
//!   at its header (`frames::classify`) and passes it to the stack with its
//!   length. The stack gives the buffer back in `rx_back` once it is done
//!   with the frame, and the switch puts it in the queue.
//! * `tx_supply`: the free buffers of sending the switch lends the stack
//!   (`TX_SHARE`, all 256 while the stack is the only consumer). The stack builds a frame in
//!   one and passes it in `tx_sub`; the switch puts it in the queue, takes
//!   the sent buffers back (`reclaim`, at most `RECLAIM_STEP` a step) and
//!   lends them again. A buffer the stack did not send comes back in
//!   `tx_back`.
//!
//! Every buffer is in one place at a time, and each ring holds as many words
//! as there are buffers, so no push finds a ring full. The rules of the
//! doorbells and of the interrupts are the stack's of the stage before the
//! split (`ring::settle_interrupts`, `ring::bell_due`, `Stock`): the line
//! stays closed and the device asks for no interrupt while the switch's own
//! steps follow, the doorbell of sending rings once for a run of steps of
//! the stack (`netd::gates::Run`), and the queue is looked at once more after
//! the interrupts are asked for again.
//!
//! With consumers (`switch N` in `netd.conf`) the switch also routes the frames of the wire
//! by the tables of `netd::switchlogic` (a consumer's frame is copied into its ring, the
//! rest goes to the stack as before), takes the frames of the consumers' TX rings in turn,
//! copies each into a buffer of its own, checks the copy, and sends it, or turns it back
//! into the tables when it is for the shared address (the hairpin of R-2a). The stack
//! thread asks for changes of the tables through `COMMANDS` and hears what happened in
//! `Back` messages. The sleep flags `switch_idle` (the switch's, in every ring) and
//! `consumer_idle` (the consumer's) follow the rule of `ConsumerRing::consumer_idle`: write
//! the flag, full barrier, look at the inputs once more, then wait.
//!
//! The wakes between the two threads are one notification each, told once
//! until the other thread saw it (`stack_told`, `switch_told`): the switch
//! wakes the stack when it passed frames, the stack wakes the switch at the
//! end of a run of its steps when buffers or frames wait in the rings. The
//! stack never waits for the switch, and the switch never waits for the
//! stack.

use crate::device::{DEVICE, Queue, fail};
use crate::dma::{Host, net_at};
use crate::trace::{
    self, P_N_BELL, P_N_BELL_SKIP, P_N_RX, P_N_STEP, P_N_STK_TX, P_N_TO_STACK, P_N_TX_SEEN,
    P_N_TX_SUBMIT, P_N_WAKE, P_N_WAKE_STACK,
};
use core::cell::{RefCell, UnsafeCell};
use core::mem::MaybeUninit;
use core::sync::atomic::{
    AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering, fence,
};
use netd::frames::{self, HDR_LEN, RxFrame};
use netd::gates::{Run, Told};
use netd::profile::{self, Counter};
use netd::ring::{
    CUT_RESERVE, CUT_WEIGHT, PARK_GIVE, Period, RECLAIM_STEP, RX_AHEAD, RX_BACK_LAZY,
    RX_BACK_LAZY_MERGED, RX_BUFFERS, RunClock, STACK_SHARE, SUM_WEIGHT, SWEEP_EVERY_NS,
    SWEEP_IDLE_NS, SWITCH_BACK, SWITCH_BASE, SWITCH_BELL, SWITCH_CTX, SWITCH_PAUSE_NS,
    SWITCH_ROUTED, SWITCH_RX, SWITCH_SOFT, SWITCH_TX, Stepper, TX_BUFFERS, TX_SHARE, bell_due,
    drive,
};
use netd::spsc::{Spsc, pack_frame, unpack_frame};
use netd::switchlogic::commands::{self, Commands};
use netd::switchlogic::ring::Tx;
use netd::switchlogic::route::{self, DEFAULT_INSTANCE, Decision, Reason, Source, Verdict, Why};
use netd::switchlogic::sums;
use netd::switchlogic::tables::{MAX_CONSUMERS, MAX_INSTANCES, Tables};
use proto_net::switch::{CELL, WAKE_RING};
use rt::handle::{Channel, Interrupt, Process, Thread, Timer};
use rt::{Handle, Stack, sys};
use virtio_drivers::transport::SomeTransport;
use virtio_mmio::Isr;
use virtio_net::barrier::ring;
use virtio_net::books::TAIL_LEN;
use virtio_net::cut::{Frame2, Plan};
use virtio_net::frames::{BUFFER_LEN, MAX_FRAME};
use virtio_net::rings::{Sent, tail_at};

const RECEIVEQ: u16 = 0;
const TRANSMITQ: u16 = 1;

/// The rings of one stack instance with the switch, and what they tell each other: the
/// instance is an internal consumer of the switch (`switchlogic::tables::Internal`) and sees
/// the device as these five rings of words, which carry the numbers of the buffers of the
/// device. Each ring has one writer and one reader, the instance's thread and the switch's.
pub struct Lane {
    /// Switch to stack: a frame, `pack_frame(buffer, length, sum good)`.
    pub rx_ready: Spsc<256>,
    /// Stack to switch: a buffer of receiving that is free again.
    pub rx_back: Spsc<256>,
    /// Stack to switch: a frame to send, `pack_frame(buffer, length, sum partial)`.
    pub tx_sub: Spsc<256>,
    /// Switch to stack: a free buffer of sending.
    pub tx_supply: Spsc<256>,
    /// Stack to switch: a buffer of sending the stack did not use.
    pub tx_back: Spsc<256>,
    /// The switch told the stack of frames, and the stack has not looked.
    pub stack_told: Told,
    /// The stack's run of steps, and what the switch holds for its end.
    pub run: Run,
    /// The stack found no buffer of sending free.
    starved: AtomicBool,
    /// The channel of the instance, raw, for NOTIFY.
    stack_channel: AtomicU64,
    /// The switch put an answer in `COMMANDS.to_stack` and the stack has not looked.
    pub back_told: Told,
}

/// The rings between the threads: a lane for each stack instance, and the state the switch
/// keeps for all of them.
pub struct Inner {
    pub lanes: [Lane; MAX_INSTANCES],
    /// The stack told the switch, and the switch has not looked.
    pub switch_told: Told,
    /// The channel of the switch, raw, for NOTIFY.
    switch_channel: AtomicU64,
    /// Frames of the wire the switch dropped as no frame or as martian,
    /// and frames of sending the queue refused.
    dropped: AtomicU32,
    martian: AtomicU32,
    tx_dropped: AtomicU32,
    /// Doorbells rung for the queue of sending (the probe's line checks that
    /// a bell serves many frames).
    bells_tx: AtomicU32,
    /// Frames of sending the switch put in the queue.
    frames_tx: AtomicU32,
    /// The device completes the sums of TCP (set when the switch starts, before the stack runs).
    offload: AtomicBool,
    /// The device merges the segments it receives (the ring of receiving is chains of 64: the
    /// stack gives its buffers back sooner, `RX_BACK_LAZY_MERGED`).
    merged: AtomicBool,
    /// The switch holds a merged frame it cut part of and waits for the stack to take segments
    /// (the end of a run of the stack wakes it).
    cut_wait: AtomicBool,
    /// The start of the port table (the switch writes it, the stack reads single bytes), or 0
    /// without a switch table.
    ports_base: AtomicUsize,
    /// What the switch counts, for the stack's report.
    pub stats: Stats,
}

/// The counters of the switch the stack prints.
pub struct Stats {
    pub consumers: AtomicU32,
    pub flows: AtomicU32,
    pub unconfirmed: AtomicU32,
    pub evicted: AtomicU32,
    pub expired: AtomicU32,
    pub rx_full: AtomicU32,
    pub tx_refused: AtomicU32,
    /// Frames turned back into the tables (the hairpin), and frames to the device whose
    /// destination is the shared address (the turn takes them all: stays 0).
    pub hairpin: AtomicU32,
    #[cfg_attr(not(feature = "probe"), allow(dead_code))]
    pub own_to_device: AtomicU32,
    pub drops: [AtomicU32; 7],
    pub refused_by: [AtomicU32; Reason::COUNT],
    /// The frames of the wire for consumers, and the frames of consumers sent.
    pub rx_consumer: AtomicU32,
    pub tx_consumer: AtomicU32,
    /// The frames of the wire each consumer got (the probe reads the share of each worker).
    pub rx_by: [AtomicU32; 8],
    /// Parked SYNs handed to a member that joined.
    pub park_given: AtomicU32,
    /// Packets of the loopback network routed through the tables (R-2b).
    pub looped: AtomicU32,
    /// Memberships ended by LEAVE.
    pub left: AtomicU32,
    /// Pauses the thread took to leave the lower levels the processor (`SWITCH_RUN_NS`), and
    /// the pauses that did not happen (the timer or the wait refused).
    pub pauses: AtomicU32,
    pub pause_failed: AtomicU32,
    /// The longest run without a rest, in microseconds.
    pub run_max_us: AtomicU32,
    /// Steps that found a consumer's entries waiting for the next period (the budget spent).
    pub budget_waits: AtomicU32,
    /// Frames of TCP the device completes the sum of, frames of the wire whose sum the device
    /// checked (and the stack or consumer need not), and frames whose sum the switch completed
    /// in software for a device without the offload.
    pub sum_tx: AtomicU32,
    pub sum_rx: AtomicU32,
    pub sum_soft: AtomicU32,
    /// Merged frames the device handed over, the segments they were cut into, and the merged
    /// frames dropped whole (no plan, a sum the device did not check, a length past the chain).
    pub merged: AtomicU32,
    pub cut: AtomicU32,
    pub merged_dropped: AtomicU32,
    /// The longest merged frame seen, in bytes after the header.
    pub merged_max: AtomicU32,
}

impl Stats {
    const fn new() -> Stats {
        Stats {
            consumers: AtomicU32::new(0),
            flows: AtomicU32::new(0),
            unconfirmed: AtomicU32::new(0),
            evicted: AtomicU32::new(0),
            expired: AtomicU32::new(0),
            rx_full: AtomicU32::new(0),
            tx_refused: AtomicU32::new(0),
            hairpin: AtomicU32::new(0),
            own_to_device: AtomicU32::new(0),
            drops: [const { AtomicU32::new(0) }; 7],
            refused_by: [const { AtomicU32::new(0) }; Reason::COUNT],
            rx_consumer: AtomicU32::new(0),
            tx_consumer: AtomicU32::new(0),
            rx_by: [const { AtomicU32::new(0) }; 8],
            park_given: AtomicU32::new(0),
            looped: AtomicU32::new(0),
            left: AtomicU32::new(0),
            pauses: AtomicU32::new(0),
            pause_failed: AtomicU32::new(0),
            run_max_us: AtomicU32::new(0),
            budget_waits: AtomicU32::new(0),
            sum_tx: AtomicU32::new(0),
            sum_rx: AtomicU32::new(0),
            sum_soft: AtomicU32::new(0),
            merged: AtomicU32::new(0),
            cut: AtomicU32::new(0),
            merged_dropped: AtomicU32::new(0),
            merged_max: AtomicU32::new(0),
        }
    }
}

/// The commands the stack thread gives the switch and the answers it gets.
pub static COMMANDS: Commands = Commands::new();

/// Gives the switch a command and wakes it. False when the ring of commands is full.
pub fn command(cmd: commands::Command) -> bool {
    if !COMMANDS.to_switch.push(cmd) {
        return false;
    }
    INNER.wake_for_command();
    true
}

/// Whether a frame the stack built for its own address is for a port a group or a consumer
/// holds: it then goes to the switch, which turns it back in (R-2a). One byte of the port
/// table is read without a lock; a stale byte makes the switch hand the frame back to the
/// stack, which answers with a RST as for a SYN that came before `bind`.
pub fn turn_wanted(frame: &[u8]) -> bool {
    let base = INNER.ports_base.load(Ordering::Acquire);
    if base == 0 {
        return false;
    }
    let Some(p) = virtio_net::frames::packet(frame) else {
        return false;
    };
    let ip = &frame[virtio_net::frames::ETHERNET_HEADER..];
    let proto = match p.protocol {
        virtio_net::frames::IPV4_PROTO_TCP => 0,
        virtio_net::frames::IPV4_PROTO_UDP => 1,
        _ => return false,
    };
    if !p.first_fragment || p.end < p.header + 4 {
        return false;
    }
    let port = usize::from(u16::from_be_bytes([ip[p.header + 2], ip[p.header + 3]]));
    // SAFETY: `base` is the start of the port table of 2 x 65 536 bytes, which lives for the
    // service's life; a byte is read atomically, and the switch thread writes bytes.
    let byte = unsafe { AtomicU8::from_ptr((base + proto * 65536 + port) as *mut u8) };
    byte.load(Ordering::Relaxed) != 0
}

/// Puts `word` in `ring`. Each ring holds as many words as there are
/// buffers and every buffer is in one place, so a full ring says the books
/// of the buffers are wrong: the service ends and init starts it again
/// (a lost buffer would show only as a slower service hours later).
pub fn must(ring: &Spsc<256>, word: u32) {
    if !ring.push(word) {
        fail("a ring between the threads is full");
    }
}

/// The instance a decision of the tables puts a frame with: the one it names, or the default.
fn lane_of(d: Decision) -> usize {
    match d {
        Decision::Instance(k) => usize::from(k),
        _ => DEFAULT_INSTANCE,
    }
}

/// Puts a frame in the ring of instance `k` and marks the instance to be woken at the end of
/// the step. False when the ring is full.
fn offer(passed: &mut u8, k: usize, word: u32) -> bool {
    let put = netd::books::offer(&INNER.lanes[k].rx_ready, word);
    *passed |= u8::from(put) << k;
    put
}

/// `offer` for a ring that cannot be full (each holds as many words as there are buffers).
fn offer_must(passed: &mut u8, k: usize, word: u32) {
    must(&INNER.lanes[k].rx_ready, word);
    *passed |= 1 << k;
}

/// The buffers of receiving the stack gives back before it wakes the switch for them alone.
fn back_lazy() -> usize {
    if INNER.merged() {
        RX_BACK_LAZY_MERGED
    } else {
        RX_BACK_LAZY
    }
}

impl Lane {
    const fn new() -> Lane {
        Lane {
            rx_ready: Spsc::new(),
            rx_back: Spsc::new(),
            tx_sub: Spsc::new(),
            tx_supply: Spsc::new(),
            tx_back: Spsc::new(),
            stack_told: Told::new(),
            run: Run::new(),
            starved: AtomicBool::new(false),
            stack_channel: AtomicU64::new(0),
            back_told: Told::new(),
        }
    }

    /// The switch tells the stack thread (`BACK`) that answers wait in `COMMANDS.to_stack`.
    fn tell_back(&self) {
        if self.back_told.tell() {
            let channel = Handle::<Channel>::borrowed(rt::abi::Handle(
                self.stack_channel.load(Ordering::Acquire),
            ));
            if sys::notify(&channel, crate::BACK).is_err() {
                self.back_told.failed();
            }
        }
    }

    /// The free buffers of sending the switch lent the stack and it has
    /// not used. Nought says the stack is out of buffers, and the switch
    /// is to tell when it lent more.
    pub fn supply_len(&self) -> usize {
        let len = self.tx_supply.len();
        if len == 0 {
            self.starved.store(true, Ordering::SeqCst);
        }
        len
    }

    /// A free buffer of sending for the stack.
    pub fn take_supply(&self) -> Option<u16> {
        let taken = self.tx_supply.pop().map(|w| w as u16);
        if taken.is_none() {
            self.starved.store(true, Ordering::SeqCst);
        }
        taken
    }

    /// The stack's own channel is the one the switch wakes.
    pub fn set_stack_channel(&self, raw: u64) {
        self.stack_channel.store(raw, Ordering::Release);
    }

    /// The start of a step of the stack that the notification of the switch
    /// brought (receiving, sending): the frames the switch passed are looked
    /// at after this.
    pub fn stack_awake(&self) {
        self.stack_told.seen();
    }

    /// The end of a step of the stack: `more` says another follows at once.
    /// The switch is woken when the run is over and a frame to send, a held
    /// doorbell or a good deal of buffers waits for it, and inside a run when
    /// the rings hold a good deal.
    pub fn kick(&self, more: bool) {
        fence(Ordering::SeqCst);
        let starved = self.starved.load(Ordering::SeqCst);
        let due = if more {
            self.tx_sub.len() >= SWITCH_TX / 2 || self.rx_back.len() >= back_lazy() || starved
        } else {
            // One read-modify-write ends the run and reads what the switch
            // held, so that neither misses the other.
            let held = self.run.end();
            // Buffers of receiving given back wait for the switch's next step
            // (the queue has 256 of them), a frame to send does not.
            held || !self.tx_sub.is_empty()
                || self.rx_back.len() >= back_lazy()
                || starved
                || INNER.cut_wait.load(Ordering::SeqCst)
        };
        if due && INNER.switch_told.tell() {
            profile::count(Counter::WakeSwitch);
            let channel = Handle::<Channel>::borrowed(rt::abi::Handle(
                INNER.switch_channel.load(Ordering::Acquire),
            ));
            if sys::notify(&channel, 1).is_err() {
                INNER.switch_told.failed();
            }
        }
    }

    /// The switch wakes the stack with `bits` (RX or TX): a run of steps of
    /// the stack follows, and the switch holds its doorbell until it ends.
    fn wake_stack(&self, bits: u64) {
        self.run.begin();
        profile::count(Counter::WakeStack);
        trace::point(P_N_WAKE_STACK, bits as u32);
        let channel = Handle::<Channel>::borrowed(rt::abi::Handle(
            self.stack_channel.load(Ordering::Acquire),
        ));
        if sys::notify(&channel, bits).is_err() && bits == crate::RX {
            self.stack_told.failed();
        }
    }
}

impl Inner {
    const fn new() -> Inner {
        Inner {
            lanes: [const { Lane::new() }; MAX_INSTANCES],
            switch_told: Told::new(),
            switch_channel: AtomicU64::new(0),
            dropped: AtomicU32::new(0),
            martian: AtomicU32::new(0),
            tx_dropped: AtomicU32::new(0),
            bells_tx: AtomicU32::new(0),
            frames_tx: AtomicU32::new(0),
            offload: AtomicBool::new(false),
            merged: AtomicBool::new(false),
            cut_wait: AtomicBool::new(false),
            ports_base: AtomicUsize::new(0),
            stats: Stats::new(),
        }
    }

    /// A command is in the ring: the switch wakes unless it was told already.
    fn wake_for_command(&self) {
        if self.switch_told.tell() {
            let channel = Handle::<Channel>::borrowed(rt::abi::Handle(
                self.switch_channel.load(Ordering::Acquire),
            ));
            if sys::notify(&channel, 1).is_err() {
                self.switch_told.failed();
            }
        }
    }

    /// Whether the device completes the sums of TCP.
    /// Whether the device merges the segments it receives.
    pub fn merged(&self) -> bool {
        self.merged.load(Ordering::Relaxed)
    }

    pub fn offload(&self) -> bool {
        self.offload.load(Ordering::Relaxed)
    }

    /// Frames the switch dropped (no frame) and the martian ones.
    pub fn rx_counts(&self) -> (u64, u64) {
        (
            u64::from(self.dropped.load(Ordering::Relaxed)),
            u64::from(self.martian.load(Ordering::Relaxed)),
        )
    }

    #[cfg(feature = "probe")]
    pub fn frames_tx(&self) -> u64 {
        u64::from(self.frames_tx.load(Ordering::Relaxed))
    }

    #[cfg(feature = "probe")]
    pub fn bells_tx(&self) -> u64 {
        u64::from(self.bells_tx.load(Ordering::Relaxed))
    }

    pub fn tx_dropped(&self) -> u64 {
        u64::from(self.tx_dropped.load(Ordering::Relaxed))
    }
}

pub static INNER: Inner = Inner::new();

/// A merged frame the switch is cutting into segments: the buffer it came in (its head, with the
/// tail behind it), the bytes the device wrote, the plan, the next segment and where the
/// segments go (decided by the first).
#[derive(Clone, Copy)]
struct Big {
    n: u16,
    used: usize,
    plan: Plan,
    next: usize,
    to: Decision,
}

/// The owner of a buffer in the queue that is instance `k`'s: the numbers after the consumers'.
const fn own_stack(k: usize) -> u8 {
    MAX_CONSUMERS as u8 + k as u8
}

/// The stack instances the service runs (P1: one; the rings, the books of the buffers and the
/// routing take any number up to `MAX_INSTANCES`).
pub const INSTANCES: usize = 1;
const _: () = assert!(INSTANCES >= 1 && INSTANCES <= MAX_INSTANCES);
const _: () = assert!(Why::Parked as usize == 6);

/// The switch: the device's transport and queues, the binding of its
/// line, and (with consumers) the tables.
pub struct Switch {
    transport: SomeTransport<'static>,
    rx: virtio_net::RxRing<Host<DEVICE>>,
    tx: virtio_net::TxRing<Host<DEVICE>>,
    irq: Handle<Interrupt>,
    channel: Handle<Channel>,
    /// The line is closed (the kernel masked it at delivery and no step
    /// has opened it yet).
    line_closed: bool,
    /// The first interrupt of the device came (and was said once).
    interrupted: bool,
    /// Under MSI-X (`vectors`): the binding of the vector of sending, which
    /// lives as long as the switch, and the interrupts of each vector.
    msi: Option<Handle<Interrupt>>,
    per_vector: [u32; 2],
    link: bool,
    /// The tables of the consumers' side; none without `switch N`.
    tables: Option<Tables<'static>>,
    /// The timer of the sweep of the flow table, and the channel view it fires into.
    timer: Handle<Timer>,
    _view: Handle<Channel>,
    armed: bool,
    /// Frames of consumers wait for a buffer or a share (see `consumer_frames`).
    blocked: bool,
    last_sweep: u64,
    /// Rounds of the sweep until which the timer runs on a quiet line (a consumer left).
    settle_until: u32,
    consumers_before: usize,
    /// The consumer whose frames come first in the next step.
    next_c: u8,
    /// The instances (bit k for instance k) the step put a frame in the ring of, to be woken
    /// at its end.
    passed: u8,
    /// The frame of a consumer, copied out of its ring and checked here.
    scratch: [u8; CELL],
    /// The device completes the sums of TCP and checks them on frames it receives
    /// (`CSUM` and `GUEST_CSUM` negotiated); without it the switch completes them.
    offload: bool,
    /// The device merges the segments it receives (`GUEST_TSO4`): the ring of receiving is
    /// chains, and a frame may come longer than a frame of the wire.
    merged: bool,
    /// The merged frame being cut.
    big: Option<Big>,
    /// Whose each buffer of the queue of sending is, in the order they went in: the device
    /// returns them in order, so a count of reclaimed buffers pops the owners.
    fifo: [u8; TX_BUFFERS],
    fifo_head: usize,
    fifo_len: usize,
    inflight: [u16; MAX_CONSUMERS + MAX_INSTANCES],
    /// What each consumer's DONE index was when the switch last looked at waking it.
    woken: netd::books::Woken,
    /// The `switch_idle` flags are set in the rings.
    idle_set: bool,
    /// The channel and timer of the pauses.
    pause: Option<(Handle<Channel>, Handle<Timer>)>,
    /// The consumers' entries taken in this period (`Period`), and whether a consumer spent its
    /// share and waits for the next one.
    period: Period,
    budget_hit: bool,
    /// The longest step so far, in ticks of the thread's own time.
    #[cfg(feature = "steps")]
    longest: u64,
    #[cfg(feature = "steps")]
    own: Option<Handle<Thread>>,
    /// The thread's own time at the start of the step.
    step_began: u64,
    /// The longest parts of a step with consumers: frames of consumers, the sweep, commands.
    #[cfg(feature = "steps")]
    longest_part: [u64; 3],
    /// The multiples of 500 frames the probe's line said.
    #[cfg(feature = "probe")]
    said: u64,
}

/// Adds one to a counter only the switch thread writes (no read-modify-write instruction).
fn bump(counter: &AtomicU32) {
    counter.store(
        counter.load(Ordering::Relaxed).wrapping_add(1),
        Ordering::Relaxed,
    );
}

fn now_ns() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}

impl Switch {
    /// The switch over the device's two queues, which the device has not
    /// seen yet: the buffers of receiving go in, the device is told they
    /// did (`finish_init`), and the buffers of sending are lent to the
    /// stack.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mut transport: SomeTransport<'static>,
        rx_queue: Queue<DEVICE>,
        tx_queue: Queue<DEVICE>,
        irq: Handle<Interrupt>,
        channel: Handle<Channel>,
        link: bool,
        (offload, merged): (bool, bool),
        (tables, timer, view): (Option<Tables<'static>>, Handle<Timer>, Handle<Channel>),
    ) -> Switch {
        let mut rx = if merged {
            virtio_net::RxRing::with_tails(rx_queue, net_at(DEVICE), crate::dma::TAILS_AT)
        } else {
            virtio_net::RxRing::new(rx_queue, net_at(DEVICE))
        };
        if let Err(broken) = rx.fill(RX_BUFFERS) {
            fail(broken.text(false));
        }
        INNER.offload.store(offload, Ordering::Release);
        INNER.merged.store(merged, Ordering::Release);
        use virtio_drivers::transport::Transport;
        transport.finish_init();
        ring(&mut transport, RECEIVEQ);
        rx.rung();
        if let Some(t) = tables.as_ref() {
            INNER
                .ports_base
                .store(t.ports_ptr() as usize, Ordering::Release);
        }
        let mut switch = Switch {
            transport,
            rx,
            tx: virtio_net::TxRing::new(tx_queue, net_at(DEVICE)),
            irq,
            channel,
            line_closed: false,
            interrupted: false,
            msi: None,
            per_vector: [0; 2],
            link,
            tables,
            timer,
            _view: view,
            armed: false,
            blocked: false,
            last_sweep: 0,
            settle_until: 0,
            consumers_before: 0,
            next_c: 0,
            passed: 0,
            scratch: [0; CELL],
            offload,
            merged,
            big: None,
            fifo: [0; TX_BUFFERS],
            fifo_head: 0,
            fifo_len: 0,
            inflight: [0; MAX_CONSUMERS + MAX_INSTANCES],
            woken: netd::books::Woken::new(),
            idle_set: false,
            pause: None,
            period: Period::new(),
            budget_hit: false,
            #[cfg(feature = "steps")]
            longest: 0,
            #[cfg(feature = "steps")]
            own: None,
            step_began: 0,
            #[cfg(feature = "steps")]
            longest_part: [0; 3],
            #[cfg(feature = "probe")]
            said: 0,
        };
        switch.lend();
        switch
    }

    /// The device raises MSI-X, a vector a queue (msix.rs): `irq` is the
    /// vector of receiving and `irq_tx` that of sending. A notification of
    /// either asks for a whole step, which polls both queues; the ISR is not
    /// read (an MSI-X vector says it was the queue's).
    pub fn vectors(&mut self, irq_tx: Handle<Interrupt>) {
        self.msi = Some(irq_tx);
    }

    /// Counts an interrupt of the vector whose binding has `label` (init
    /// labels them with `proto_init::binding_label`), and says the count at
    /// 1, 4, 16, ... so that the log shows both vectors at work.
    fn count_vector(&mut self, label: u64) {
        let vector = usize::from(label == proto_init::binding_label(1));
        let count = &mut self.per_vector[vector];
        *count += 1;
        if count.is_power_of_two() && count.trailing_zeros().is_multiple_of(2) {
            rt::println!("virtio-net: vector {vector} interrupts {count}");
        }
    }

    /// The consumers attached now.
    fn consumers(&self) -> usize {
        self.tables
            .as_ref()
            .map_or(0, |t| t.consumers.iter().flatten().count())
    }

    /// The buffers of sending one stack instance may have: all while it is alone, `STACK_SHARE`
    /// of them once consumers are attached (the rest is theirs), divided among the instances.
    fn share(&self) -> usize {
        // The buffers the consumers will need are never lent: a stack that holds all of them
        // would keep them while its consumers wait.
        let all = if self.tables.is_some() {
            STACK_SHARE
        } else {
            TX_SHARE
        };
        all / INSTANCES
    }

    /// The buffers of the queue of sending one consumer may have at a time.
    fn consumer_cap(&self) -> usize {
        ((TX_BUFFERS - STACK_SHARE) / self.consumers().max(1)).max(4)
    }

    /// Lends each instance free buffers of sending up to its share. The set of the instances
    /// (bit k for instance k) that were out of them and have some now.
    fn lend(&mut self) -> u8 {
        let share = self.share();
        // A device that merges segments has the segments of a merged frame read in buffers of
        // sending (`cut_more`): the last `CUT_RESERVE` stay in the pool.
        let keep = if self.merged { CUT_RESERVE } else { 0 };
        let mut lent = 0;
        for (k, lane) in INNER.lanes[..INSTANCES].iter().enumerate() {
            if self.tables.is_none() {
                while lane.tx_supply.len() < share && self.tx.book.free() > keep {
                    let Some(n) = self.tx.book.alloc() else {
                        break;
                    };
                    must(&lane.tx_supply, u32::from(n));
                }
            } else {
                // With consumers the stack's buffers are counted wherever they are: lent,
                // waiting for the switch, and in the queue on its account.
                loop {
                    let held = lane.tx_supply.len()
                        + lane.tx_sub.len()
                        + usize::from(self.inflight[usize::from(own_stack(k))]);
                    if held >= share || self.tx.book.free() <= keep {
                        break;
                    }
                    let Some(n) = self.tx.book.alloc() else {
                        break;
                    };
                    must(&lane.tx_supply, u32::from(n));
                }
            }
            if !lane.tx_supply.is_empty() && lane.starved.swap(false, Ordering::AcqRel) {
                lent |= 1 << k;
            }
        }
        lent
    }

    /// A buffer went into the queue of sending on `owner`'s account.
    fn queued(&mut self, owner: u8) {
        if self.fifo_len < TX_BUFFERS {
            self.fifo[(self.fifo_head + self.fifo_len) % TX_BUFFERS] = owner;
            self.fifo_len += 1;
            self.inflight[usize::from(owner)] += 1;
        }
    }

    /// The device returned `count` buffers: their owners' accounts close.
    fn returned(&mut self, count: usize) {
        for _ in 0..count.min(self.fifo_len) {
            let owner = usize::from(self.fifo[self.fifo_head]);
            self.fifo_head = (self.fifo_head + 1) % TX_BUFFERS;
            self.fifo_len -= 1;
            self.inflight[owner] = self.inflight[owner].saturating_sub(1);
        }
    }

    /// The change of the link (the interrupt's configuration bit).
    fn link_changed(&mut self) {
        let Ok((_, up)) = virtio_net::open::read_config(&self.transport) else {
            return;
        };
        if up != self.link {
            self.link = up;
            rt::println!("virtio-net: link {}", if up { "up" } else { "down" });
        }
    }

    /// Gives the levels below the processor for `SWITCH_PAUSE_NS`: the thread waits on a timer of
    /// its own (a wait on its main channel returns at once while a notification is pending). True
    /// when the wait happened; a refusal of the timer or of the wait is counted apart.
    fn pause(&mut self) -> bool {
        let waited = match &self.pause {
            Some((channel, timer)) => {
                sys::timer_set(timer, now_ns() + SWITCH_PAUSE_NS).is_ok()
                    && sys::receive(channel).is_ok()
            }
            None => false,
        };
        if waited {
            INNER.stats.pauses.fetch_add(1, Ordering::Relaxed);
            profile::count(Counter::Pause);
        } else {
            INNER.stats.pause_failed.fetch_add(1, Ordering::Relaxed);
        }
        waited
    }

    /// One step: the buffers and frames the stack passed go to the queues,
    /// the sent buffers come back, the frames of the wire go to the stack or a
    /// consumer, the frames of the consumers go out, and the doorbells ring when
    /// a run is over. True when another step follows at once (frames left in
    /// the queue with room for them, or frames of the stack or a consumer left
    /// in their rings).
    fn step(&mut self, interrupt: bool) -> bool {
        profile::count(Counter::StepSwitch);
        trace::point(P_N_STEP, 0);
        if self.idle_set {
            self.clear_idle();
        }
        if interrupt && self.msi.is_some() {
            self.line_closed = true;
            if !core::mem::replace(&mut self.interrupted, true) {
                rt::println!("virtio-net: first interrupt");
            }
        } else if interrupt {
            self.line_closed = true;
            let began = profile::now();
            let isr = Isr::read(&mut self.transport);
            profile::timed(Counter::IsrN, Counter::IsrTicks, Counter::IsrMax, began);
            if !isr.is_empty() && !core::mem::replace(&mut self.interrupted, true) {
                rt::println!("virtio-net: first interrupt");
            }
            if isr.config() {
                self.link_changed();
            }
        }
        let now = now_ns();
        self.step_began = rt::time::now();
        #[cfg(feature = "steps")]
        let began = self.ran();
        let mut more_c = false;
        let mut more_park = false;
        if let Some(t) = self.tables.as_mut() {
            t.now = (now / 1_000_000_000) as u32;
            t.now_ms = (now / 1_000_000) as u32;
            commands::drain(t, &COMMANDS);
            commands::poll(t, &COMMANDS);
            // SYNs that waited for a member: members that joined get them (at most
            // `PARK_GIVE` a step), the others expire.
            let given = route::unpark(t, PARK_GIVE);
            INNER
                .stats
                .rx_consumer
                .fetch_add(given as u32, Ordering::Relaxed);
            INNER
                .stats
                .park_given
                .fetch_add(given as u32, Ordering::Relaxed);
            more_park = given == PARK_GIVE;
        }
        #[cfg(feature = "steps")]
        self.part(0, self.ran().saturating_sub(began));
        // What the stack passed: buffers of receiving, buffers of sending
        // it did not use, then its frames to send.
        // At most `SWITCH_BACK` of each a step (the step is bound, and the
        // rest makes the step follow at once).
        let lanes = &INNER.lanes[..INSTANCES];
        for lane in lanes {
            for _ in 0..SWITCH_BACK {
                let Some(word) = lane.rx_back.pop() else {
                    break;
                };
                // A frame the switch turned to the stack came in a buffer of sending.
                if word as usize >= RX_BUFFERS {
                    self.tx.book.release(word as u16);
                } else if let Err(broken) = self.rx.give(word as u16) {
                    fail(broken.text(false));
                }
            }
            for _ in 0..SWITCH_BACK {
                let Some(word) = lane.tx_back.pop() else {
                    break;
                };
                self.tx.book.release(word as u16);
            }
        }
        let mut passed = 0;
        let mut taken = 0;
        for (k, lane) in lanes.iter().enumerate() {
            for _ in 0..SWITCH_TX {
                let Some(word) = lane.tx_sub.pop() else {
                    break;
                };
                let (n, len, partial) = unpack_frame(word);
                let (to_stack, turned) = self.stack_frame(k, n, usize::from(len), partial);
                passed += to_stack;
                // A frame turned into the tables costs a copy and a route as a frame of a
                // consumer does: past the first few the step goes on only while it is short.
                taken += usize::from(turned);
                if turned && !netd::books::may_take(taken, SWITCH_BASE, self.over_soft()) {
                    break;
                }
            }
        }
        match self.tx.reclaim(RECLAIM_STEP) {
            Ok(count) => self.returned(count),
            Err(broken) => fail(broken.text(true)),
        }
        let lent = self.lend();
        #[cfg(feature = "steps")]
        let before_consumers = self.ran();
        if self.tables.is_some() {
            more_c = self.consumer_frames();
        }
        #[cfg(feature = "steps")]
        self.part(1, self.ran().saturating_sub(before_consumers));
        // The frames of the wire.
        let room = lanes
            .iter()
            .map(|lane| RX_AHEAD.saturating_sub(lane.rx_ready.len()))
            .min()
            .unwrap_or(0);
        let budget = if self.tables.is_some() {
            SWITCH_ROUTED
        } else {
            SWITCH_RX
        };
        passed += self.receive(room.min(budget));
        #[cfg(feature = "steps")]
        let before_sweep = self.ran();
        if let Some(t) = self.tables.as_mut()
            && now.wrapping_sub(self.last_sweep) >= SWEEP_EVERY_NS
        {
            self.last_sweep = now;
            t.sweep();
        }
        #[cfg(feature = "steps")]
        self.part(2, self.ran().saturating_sub(before_sweep));
        if self.tables.is_some() {
            self.after_tables(now);
        }
        // The instances that got frames (`pass`) and those that got buffers are woken.
        for (k, lane) in lanes.iter().enumerate() {
            if self.passed & (1 << k) != 0 && lane.stack_told.tell() {
                lane.wake_stack(crate::RX);
            }
            if lent & (1 << k) != 0 {
                lane.wake_stack(crate::TX);
            }
        }
        self.passed = 0;
        // Frames left in the queue with room for them, or in the stack's
        // ring of frames to send: another step follows at once.
        let room_left = room.saturating_sub(passed);
        // A merged frame with segments left goes on at once, unless it waits for the stack
        // (`cut_wait`: the end of the stack's run wakes the switch).
        let more_rx = room_left > 0
            && (self.rx.queue.can_pop()
                || self.big.is_some() && !INNER.cut_wait.load(Ordering::Relaxed));
        // While steps follow, the device is asked for no interrupt. The run
        // ends with the interrupts asked for again, a full barrier and one
        // more look at the queue, so that a frame that came between is not
        // left to wait (`ring::settle_interrupts`).
        let mut continued = more_rx
            || more_c
            || more_park
            || lanes.iter().any(|lane| {
                !lane.tx_sub.is_empty() || !lane.rx_back.is_empty() || !lane.tx_back.is_empty()
            })
            || !COMMANDS.to_switch.is_empty();
        if !continued {
            // The consumers' flags go up before the last look at their rings.
            continued = self.go_idle();
        }
        if !continued {
            continued = {
                let queue = RefCell::new(&mut self.rx.queue);
                netd::ring::settle_interrupts(
                    false,
                    || room_left > 0,
                    |on| virtio_net::rings::notify_on(&mut queue.borrow_mut(), on),
                    || queue.borrow().can_pop(),
                )
            };
            if continued {
                self.clear_idle();
            }
            if !continued && core::mem::take(&mut self.line_closed) {
                let began = profile::now();
                virtio_mmio::reopen(&self.irq);
                profile::timed(
                    Counter::ReopenN,
                    Counter::ReopenTicks,
                    Counter::ReopenMax,
                    began,
                );
            }
        }
        self.doorbells(continued);
        continued
    }

    /// The thread's own time in ticks (a thread of a higher level that runs in the middle
    /// of a step does not lengthen it).
    #[cfg(feature = "steps")]
    fn ran(&self) -> u64 {
        self.own
            .as_ref()
            .map_or(0, |t| sys::thread_ran(t).unwrap_or(0))
    }

    /// The step has used up its soft share of time: the frames past `SWITCH_BASE` wait for
    /// the next step.
    fn over_soft(&self) -> bool {
        rt::time::now().saturating_sub(self.step_began) > SWITCH_SOFT
    }

    #[cfg(feature = "steps")]
    fn part(&mut self, which: usize, ticks: u64) {
        if ticks > self.longest_part[which] {
            self.longest_part[which] = ticks;
            rt::println!(
                "service step: 14 kind {} {ticks} ticks detail 0",
                68 + which
            );
        }
    }

    /// The last look before sleeping: every ring gets `switch_idle = 1`, a full barrier
    /// follows, and a frame a consumer wrote meanwhile (or a command) cancels the sleep.
    fn go_idle(&mut self) -> bool {
        let Some(t) = self.tables.as_ref() else {
            return false;
        };
        let mut any = false;
        for x in t.consumers.iter().flatten() {
            // A consumer that spent its budget does not poke the switch: its entries wait for
            // the timer of the next period.
            x.ring.set_switch_idle(self.period.left());
            any = true;
        }
        if !any {
            return false;
        }
        self.idle_set = true;
        let t = self.tables.as_ref().expect("there");
        // A consumer whose frame waits for a buffer or its share of the queue is no work
        // (the 1 ms timer and the returned buffers look at it again); counting it would
        // make the switch run again at once, above the stack, and spin.
        let (cap, free) = (self.consumer_cap(), self.tx.book.free());
        let work = netd::books::has_work(
            t.consumers.iter().enumerate().filter_map(|(c, x)| {
                x.as_ref().map(|x| {
                    (
                        x.ring.tx_pending() && self.period.left(),
                        usize::from(self.inflight[c]),
                    )
                })
            }),
            cap,
            free,
            !COMMANDS.to_switch.is_empty(),
        );
        if work {
            self.clear_idle();
        }
        work
    }

    fn clear_idle(&mut self) {
        self.idle_set = false;
        if let Some(t) = self.tables.as_ref() {
            for x in t.consumers.iter().flatten() {
                x.ring.set_switch_idle(false);
            }
        }
    }

    /// A frame of the stack: a turn to the shared address goes through the tables, any other
    /// into the queue. The number of frames passed to the stack, and whether the frame was
    /// turned into the tables.
    /// `partial`: the stack left the sum of a segment of TCP partial (`TxRing::submit`).
    fn stack_frame(&mut self, from: usize, n: u16, len: usize, partial: bool) -> (usize, bool) {
        // SAFETY: the stack gave the buffer up (it is in `tx_sub`), and the device does not
        // hold it.
        let slice = unsafe { virtio_net::rings::buffer_at(self.tx.base(), n) };
        let frame = &slice[HDR_LEN..HDR_LEN + len];
        if let Some(t) = self.tables.as_mut()
            && (route::faces_own(t, frame) || route::faces_loop(frame))
        {
            let decision = if route::faces_loop(frame) {
                INNER.stats.looped.fetch_add(1, Ordering::Relaxed);
                route::route_loop(t, frame)
            } else {
                INNER.stats.hairpin.fetch_add(1, Ordering::Relaxed);
                route::route(t, frame, Source::Stack)
            };
            let passed = match decision {
                // A stale byte of the stack's: the frame goes back, and the stack answers it.
                // An instance a table names gets it as it is, the number of the buffer of
                // sending that carries it. A full ring of frames for the stack drops it (TCP
                // repeats it).
                Decision::Stack | Decision::Instance(_) => {
                    let to = if matches!(decision, Decision::Stack) {
                        from
                    } else {
                        lane_of(decision)
                    };
                    if offer(&mut self.passed, to, pack_frame(n, len as u16, partial)) {
                        1
                    } else {
                        self.tx.book.release(n);
                        0
                    }
                }
                Decision::Drop(why) => {
                    INNER.stats.drops[why as usize].fetch_add(1, Ordering::Relaxed);
                    self.tx.book.release(n);
                    0
                }
                d => {
                    if let Decision::Consumer { consumer, .. } = d {
                        INNER.stats.rx_consumer.fetch_add(1, Ordering::Relaxed);
                        INNER.stats.rx_by[usize::from(consumer) % 8]
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    // The frame never reaches the device: a partial sum is good as it is.
                    route::deliver(t, sums::mark(d, partial), frame);
                    self.tx.book.release(n);
                    0
                }
            };
            return (passed, true);
        }
        #[cfg(feature = "probe")]
        if let Some(t) = self.tables.as_ref()
            && t.own.ip != [0; 4]
            && frame.len() >= 34
            && frame[30..34] == t.own.ip
        {
            INNER.stats.own_to_device.fetch_add(1, Ordering::Relaxed);
        }
        let csum = if partial {
            // SAFETY: as above, the stack gave the buffer up.
            let slice = unsafe { virtio_net::rings::buffer_at(self.tx.base(), n) };
            frames::partial_place(&slice[HDR_LEN..HDR_LEN + len])
        } else {
            None
        };
        trace::frame(P_N_STK_TX, frame, false);
        match Self::send(&mut self.tx, self.offload, n, len, csum) {
            Ok(Sent::Queued) => {
                trace::frame(P_N_TX_SUBMIT, frame, false);
                INNER.frames_tx.fetch_add(1, Ordering::Relaxed);
                self.queued(own_stack(from));
            }
            Ok(Sent::Dropped) => {
                INNER.tx_dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(broken) => fail(broken.text(true)),
        }
        (0, false)
    }

    /// Takes frames of the consumers' TX rings in turn, one from each in a round, up to
    /// `SWITCH_CTX`, and starts the next step with the next consumer. True when frames are
    /// left.
    fn consumer_frames(&mut self) -> bool {
        let cap = self.consumer_cap();
        self.period.refresh(now_ns());
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
                if !netd::books::may_take(taken, SWITCH_BASE, self.over_soft()) {
                    budget = 0;
                    break;
                }
                let c = (usize::from(self.next_c) + k) % MAX_CONSUMERS;
                // A frame waits in its ring while this consumer holds its share of the
                // queue, or no buffer is free.
                if netd::books::blocked(usize::from(self.inflight[c]), cap, self.tx.book.free()) {
                    blocked = true;
                    continue;
                }
                // The consumer spent its entries of this period: the rest waits for the timer.
                if !self.period.left() {
                    blocked = true;
                    spent = true;
                    continue;
                }
                let Some(t) = self.tables.as_mut() else {
                    return false;
                };
                let Some(x) = t.consumers[c].as_mut() else {
                    continue;
                };
                let began = now_ns();
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
                        self.consumer_frame(c as u8, len, false);
                    }
                    Tx::Sum(len) => {
                        progressed = true;
                        budget -= 1;
                        taken += 1;
                        if self.consumer_frame(c as u8, len, true) {
                            // The sum made here counts as another frame (`SUM_WEIGHT`).
                            budget = budget.saturating_sub(SUM_WEIGHT - 1);
                            taken += SUM_WEIGHT - 1;
                        }
                    }
                    Tx::Loop(len) => {
                        progressed = true;
                        budget -= 1;
                        taken += 1;
                        self.consumer_loop(c as u8, len);
                    }
                }
                self.period.spend(now_ns().wrapping_sub(began));
            }
        }
        self.budget_hit = spent;
        if spent {
            INNER.stats.budget_waits.fetch_add(1, Ordering::Relaxed);
        }
        self.next_c = (self.next_c + 1) % MAX_CONSUMERS as u8;
        // Frames that wait for a buffer or a share of the queue do not make the switch run
        // again at once (it would spin above the stack): the timer looks again in a
        // millisecond, and the steps that return buffers go on as before.
        self.blocked = blocked
            && self
                .tables
                .as_ref()
                .is_some_and(|t| t.consumers.iter().flatten().any(|x| x.ring.tx_waiting()));
        // More follows at once only for entries that may still be taken.
        budget == 0
            && self.tables.as_ref().is_some_and(|t| {
                t.consumers
                    .iter()
                    .flatten()
                    .any(|x| x.ring.tx_waiting() && self.period.left())
            })
    }

    /// The copy in `scratch` is checked and goes out, or turns back into the tables. `sum`: the
    /// entry said `TX_SUM`, the segment's sum is not computed; the copy gets the sum of the
    /// pseudo-header, and a frame that is no whole segment of TCP is refused.
    fn consumer_frame(&mut self, c: u8, len: usize, sum: bool) -> bool {
        let Some(t) = self.tables.as_mut() else {
            return false;
        };
        // The consumer was told at ATTACH whether the device offloads: an entry with `TX_SUM`
        // on a device without it is refused and counted.
        if let Err(reason) = sums::admit(self.offload, sum) {
            route::refuse_tx(t, c, reason);
            return false;
        }
        let frame = &mut self.scratch[..len];
        trace::frame(P_N_TX_SEEN, frame, false);
        let verdict = route::check_tx(t, c, frame);
        let mut csum = None;
        if sum && matches!(verdict, Verdict::Send | Verdict::Hairpin) {
            csum = sums::prepare_tx(frame);
            if csum.is_none() {
                route::refuse_tx(t, c, Reason::Proto);
                return false;
            }
        }
        // The bytes after the IP packet do not go out: the device sums to the end of the frame.
        let len = if csum.is_some() {
            sums::wire_len(&self.scratch[..len])
        } else {
            len
        };
        let frame = &self.scratch[..len];
        // The switch completes the sum itself: a heavy frame (`SUM_WEIGHT`).
        let heavy = csum.is_some() && !self.offload && matches!(verdict, Verdict::Send);
        match verdict {
            // `check_tx` never answers these (the entries flagged `TX_LOOP` go through
            // `check_tx_loop`).
            Verdict::Refuse(_) | Verdict::Loop | Verdict::Broke => {}
            Verdict::Send => {
                let Some(n) = self.tx.book.alloc() else {
                    return false;
                };
                // SAFETY: the buffer is free (just taken from the pool).
                let slice = unsafe { virtio_net::rings::buffer_at(self.tx.base(), n) };
                slice[HDR_LEN..HDR_LEN + len].copy_from_slice(frame);
                match Self::send(&mut self.tx, self.offload, n, len, csum) {
                    Ok(Sent::Queued) => {
                        trace::frame(P_N_TX_SUBMIT, frame, false);
                        INNER.frames_tx.fetch_add(1, Ordering::Relaxed);
                        INNER.stats.tx_consumer.fetch_add(1, Ordering::Relaxed);
                        self.queued(c);
                    }
                    Ok(Sent::Dropped) => {
                        INNER.tx_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(broken) => fail(broken.text(true)),
                }
            }
            Verdict::Hairpin => {
                INNER.stats.hairpin.fetch_add(1, Ordering::Relaxed);
                let d = route::route(t, frame, Source::Consumer(c));
                match d {
                    Decision::Drop(why) => {
                        INNER.stats.drops[why as usize].fetch_add(1, Ordering::Relaxed);
                    }
                    Decision::Stack | Decision::Instance(_) | Decision::ArpAll => {
                        route::deliver(t, d, frame);
                        // The instance gets a buffer of sending to read the frame in; it comes
                        // back through `rx_back` (`step`). The frame never reaches the device:
                        // the sum left partial is good as it is.
                        if let Some(n) = self.tx.book.alloc() {
                            // SAFETY: the buffer is free (just taken from the pool).
                            let slice = unsafe { virtio_net::rings::buffer_at(self.tx.base(), n) };
                            slice[HDR_LEN..HDR_LEN + len].copy_from_slice(frame);
                            let word = pack_frame(n, len as u16, sum);
                            if !offer(&mut self.passed, lane_of(d), word) {
                                self.tx.book.release(n);
                            }
                        }
                    }
                    d => {
                        route::deliver(t, sums::mark(d, sum), frame);
                    }
                }
            }
        }
        heavy
    }

    /// The frame in buffer `n` goes in the queue of sending. A frame whose sum of TCP is
    /// partial (`csum`) goes with the header that has the device complete it, or, when the
    /// device has no offload, is completed here first (`sums::finish`).
    fn send(
        tx: &mut virtio_net::TxRing<Host<DEVICE>>,
        offload: bool,
        n: u16,
        len: usize,
        csum: Option<frames::Csum>,
    ) -> Result<Sent, virtio_net::rings::Broken> {
        let mut header = None;
        match sums::finish(offload, csum) {
            sums::Finish::Whole => {}
            sums::Finish::Device(c) => {
                bump(&INNER.stats.sum_tx);
                profile::count(Counter::SumTx);
                header = Some(c);
            }
            sums::Finish::Software(c) => {
                // SAFETY: the buffer is the switch's (it was just taken from the pool, or the
                // stack gave it up), and the device does not hold it.
                let slice = unsafe { virtio_net::rings::buffer_at(tx.base(), n) };
                frames::complete(&mut slice[HDR_LEN..HDR_LEN + len], c);
                bump(&INNER.stats.sum_soft);
                profile::count(Counter::SumSoft);
            }
        }
        profile::count(Counter::WireTx);
        tx.submit_with(n, len, header)
    }

    /// A packet of the loopback network of consumer `c` (entry flagged `TX_LOOP`, copied into
    /// `scratch`): checked, then routed by its port to the stack of the service or to a consumer
    /// (R-2b).
    fn consumer_loop(&mut self, c: u8, len: usize) {
        let Some(t) = self.tables.as_mut() else {
            return;
        };
        let frame = &self.scratch[..len];
        if route::check_tx_loop(t, c, frame) != Verdict::Loop {
            return;
        }
        INNER.stats.looped.fetch_add(1, Ordering::Relaxed);
        match route::route_loop(t, frame) {
            Decision::Drop(why) => {
                INNER.stats.drops[why as usize].fetch_add(1, Ordering::Relaxed);
            }
            // The stack gets a buffer of sending to read the packet in; it comes back through
            // `rx_back` (`step`).
            d @ (Decision::Stack | Decision::Instance(_) | Decision::ArpAll) => {
                if let Some(n) = self.tx.book.alloc() {
                    // SAFETY: the buffer is free (just taken from the pool).
                    let slice = unsafe { virtio_net::rings::buffer_at(self.tx.base(), n) };
                    slice[HDR_LEN..HDR_LEN + len].copy_from_slice(frame);
                    // No sums are on the loopback, and none is checked.
                    if !offer(
                        &mut self.passed,
                        lane_of(d),
                        pack_frame(n, len as u16, true),
                    ) {
                        self.tx.book.release(n);
                    }
                }
            }
            d => {
                route::deliver(t, d, frame);
            }
        }
    }

    /// The end of a step with tables: consumers with new frames are woken when they sleep,
    /// the counters and the indices are published, the stack hears what is owed it, and the
    /// timer of the sweep is set while there is something to sweep.
    fn after_tables(&mut self, now: u64) {
        let Some(t) = self.tables.as_mut() else {
            return;
        };
        for (c, slot) in t.consumers.iter().enumerate() {
            let Some(x) = slot else { continue };
            x.ring.publish();
            let head = x.ring.done_head();
            // A new consumer on a number starts from nothing (`Woken` keys on the generation).
            // The build with the trace also notes the consumer that was not woken.
            #[cfg(feature = "trace")]
            {
                let news = self.woken.news(c, x.generation, head) && x.wake != 0;
                if news && x.ring.consumer_idle() {
                    ::trace::point(::trace::P_N_CWAKE, c as u32);
                    let channel = Handle::<Channel>::borrowed(rt::abi::Handle(x.wake));
                    let _ = sys::notify(&channel, WAKE_RING);
                } else if news {
                    ::trace::point(::trace::P_N_CSKIP, c as u32);
                }
            }
            #[cfg(not(feature = "trace"))]
            if self.woken.news(c, x.generation, head) && x.wake != 0 && x.ring.consumer_idle() {
                let channel = Handle::<Channel>::borrowed(rt::abi::Handle(x.wake));
                let _ = sys::notify(&channel, WAKE_RING);
            }
        }
        let st = &INNER.stats;
        let count = t.consumers.iter().flatten().count();
        if count < self.consumers_before {
            self.settle_until = t.flows.rounds().wrapping_add(3);
        }
        self.consumers_before = count;
        st.consumers.store(count as u32, Ordering::Relaxed);
        st.flows.store(t.flows.len() as u32, Ordering::Relaxed);
        st.unconfirmed
            .store(t.flows.unconfirmed() as u32, Ordering::Relaxed);
        st.evicted.store(t.flows.evicted, Ordering::Relaxed);
        st.expired.store(t.flows.expired, Ordering::Relaxed);
        st.left.store(t.left, Ordering::Relaxed);
        let (mut full, mut refused) = (0u32, 0u32);
        for x in t.consumers.iter().flatten() {
            full = full.wrapping_add(x.ring.rx_full);
            refused = refused.wrapping_add(x.ring.refused);
        }
        st.rx_full.store(full, Ordering::Relaxed);
        st.tx_refused.store(refused, Ordering::Relaxed);
        for (slot, v) in st.refused_by.iter().zip(t.refused.iter()) {
            slot.store(*v, Ordering::Relaxed);
        }
        if !COMMANDS.to_stack.is_empty() {
            INNER.lanes[DEFAULT_INSTANCE].tell_back();
        }
        // A consumer left lately: the rounds that return its number follow fast.
        let settling = t.flows.rounds().wrapping_sub(self.settle_until) >= u32::MAX / 2;
        let sweeping = count > 0 || !t.flows.is_empty() || settling || t.parked() > 0;
        // A budget spent moves a timer armed for later (the sweep's) to the end of the period.
        let waits_for_period = self.blocked && self.budget_hit;
        // A merged frame waiting for the stack's ring or a buffer of sending is looked at again
        // by the same timer, so that it does not wait for the next event of another kind.
        let cutting = self.big.is_some() && INNER.cut_wait.load(Ordering::Relaxed);
        if (sweeping || self.blocked || cutting) && (!self.armed || waits_for_period) {
            let after = if self.blocked && self.budget_hit {
                // The entries wait for the next period.
                self.period.remaining(now_ns()).max(20_000)
            } else if self.blocked || cutting {
                1_000_000
            } else if settling {
                2_000_000
            } else {
                SWEEP_IDLE_NS
            };
            self.armed = sys::timer_set(&self.timer, now + after).is_ok();
        }
    }

    /// Takes up to `budget` used buffers off the queue of receiving, each
    /// to the stack (its number and the length of its frame), to a consumer
    /// (copied into its ring, the buffer back in the queue), or back to the
    /// queue when it holds no frame or one the tables drop. Every buffer
    /// taken costs one unit of the share. The number of frames passed to the
    /// stack.
    fn receive(&mut self, mut budget: usize) -> usize {
        let mut passed = 0;
        let mut taken = 0;
        // A merged frame cut in an earlier step goes on first: the frames behind it wait.
        if self.big.is_some() {
            passed += self.cut_more(&mut budget, &mut taken);
            if self.big.is_some() {
                return passed;
            }
        }
        while budget > 0 {
            if self.tables.is_some() && taken >= SWITCH_BASE && self.over_soft() {
                break;
            }
            taken += 1;
            let (n, used) = match self.rx.pop() {
                Ok(Some(popped)) => popped,
                Ok(None) => break,
                Err(broken) => fail(broken.text(false)),
            };
            budget -= 1;
            // SAFETY: the device returned the buffer (it is used), and the
            // switch holds no other reference to it.
            let slice = unsafe { virtio_net::rings::buffer_at(self.rx.base(), n) };
            // A frame longer than a frame of the wire: the device merged segments of one flow.
            if self.merged && used > HDR_LEN + MAX_FRAME {
                if self.begin_cut(n, used, slice) {
                    passed += self.cut_more(&mut budget, &mut taken);
                    if self.big.is_some() {
                        break;
                    }
                } else {
                    bump(&INNER.stats.merged_dropped);
                    self.give(n);
                }
                continue;
            }
            match frames::classify(slice, used) {
                RxFrame::Frame(len) => {
                    profile::count(Counter::WireRx);
                    if slice[0] != 0 {
                        profile::count(Counter::RxFlagged);
                    }
                    // A packet that is no TCP may come with its sum partial (`NEEDS_CSUM`): it is
                    // completed here, and counts as `SUM_WEIGHT` frames of the step.
                    if self.offload
                        && let Some(h) = frames::parse_header(slice)
                        && h.flags & virtio_net::frames::NEEDS_CSUM != 0
                        && !frames::is_tcp(&slice[HDR_LEN..HDR_LEN + len])
                        && frames::complete_received(&mut slice[HDR_LEN..HDR_LEN + len], &h)
                    {
                        budget = budget.saturating_sub(SUM_WEIGHT - 1);
                        taken += SUM_WEIGHT - 1;
                        bump(&INNER.stats.sum_soft);
                        profile::count(Counter::SumSoft);
                    }
                    let frame = &slice[HDR_LEN..HDR_LEN + len];
                    trace::frame(P_N_RX, frame, true);
                    // The device checked the segment's sum (or it is partial and good), and
                    // the header's sum holds: the stack that gets the frame does not check
                    // the segment.
                    let sum = self.offload && sums::wire_sum_ok(frames::sum_checked(slice), frame);
                    if sum {
                        bump(&INNER.stats.sum_rx);
                        profile::count(Counter::SumRx);
                    }
                    let Some(t) = self.tables.as_mut() else {
                        trace::frame(P_N_TO_STACK, frame, true);
                        offer_must(
                            &mut self.passed,
                            DEFAULT_INSTANCE,
                            pack_frame(n, len as u16, sum),
                        );
                        passed += 1;
                        continue;
                    };
                    match route::route(t, frame, Source::Wire) {
                        Decision::Drop(why) => {
                            INNER.stats.drops[why as usize].fetch_add(1, Ordering::Relaxed);
                            self.give(n);
                        }
                        d => {
                            if let Decision::Consumer { consumer, .. } = d {
                                INNER.stats.rx_consumer.fetch_add(1, Ordering::Relaxed);
                                INNER.stats.rx_by[usize::from(consumer) % 8]
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            #[cfg(feature = "trace")]
                            trace::frame(
                                if matches!(d, Decision::Consumer { .. }) {
                                    ::trace::P_N_TO_CONSUMER
                                } else {
                                    P_N_TO_STACK
                                },
                                frame,
                                true,
                            );
                            if route::deliver(t, sums::mark(d, sum), frame) {
                                let word = pack_frame(n, len as u16, sum);
                                offer_must(&mut self.passed, lane_of(d), word);
                                passed += 1;
                            } else {
                                self.give(n);
                            }
                        }
                    }
                }
                // A frame of the loopback network on the wire never reaches
                // the stack (RFC 1122, 3.2.1.3).
                RxFrame::Martian => {
                    INNER.martian.fetch_add(1, Ordering::Relaxed);
                    self.give(n);
                }
                RxFrame::Invalid => {
                    INNER.dropped.fetch_add(1, Ordering::Relaxed);
                    self.give(n);
                }
            }
        }
        passed
    }

    fn give(&mut self, n: u16) {
        if let Err(broken) = self.rx.give(n) {
            fail(broken.text(false));
        }
    }

    /// The bytes of the merged frame in chain `n`, `used` bytes written by the device (the
    /// header, then the frame): the part in the head and the part in the tail. None for a length
    /// past the chain.
    fn merged_frame(&self, n: u16, used: usize) -> Option<Frame2<'static>> {
        let total = used.checked_sub(HDR_LEN)?;
        if used > BUFFER_LEN + TAIL_LEN {
            return None;
        }
        let first = total.min(BUFFER_LEN - HDR_LEN);
        // SAFETY: the device returned the chain (it is used), and the switch holds no other
        // reference to it.
        let head = unsafe { virtio_net::rings::buffer_at(self.rx.base(), n) };
        let tail: &[u8] = if total > first {
            // SAFETY: the same chain's tail.
            unsafe { tail_at(self.rx.tails(), n) }
        } else {
            &[]
        };
        Some(Frame2 {
            head: &head[HDR_LEN..HDR_LEN + first],
            tail: &tail[..total - first],
        })
    }

    /// Starts the cut of the merged frame in chain `n` (`head` is its first buffer): false for
    /// a frame whose data the device did not check (the sums of the segments are made over it
    /// here, so a bad byte would pass for good) and for a frame that is no open flow of TCP in
    /// IPv4 or whose length is no chain's; the caller drops it.
    fn begin_cut(&mut self, n: u16, used: usize, head: &[u8]) -> bool {
        bump(&INNER.stats.merged);
        let longest = (used - HDR_LEN) as u32;
        if longest > INNER.stats.merged_max.load(Ordering::Relaxed) {
            INNER.stats.merged_max.store(longest, Ordering::Relaxed);
        }
        if !frames::sum_checked(head) {
            return false;
        }
        let Some(plan) = self
            .merged_frame(n, used)
            .and_then(|frame| Plan::new(&frame))
        else {
            return false;
        };
        self.big = Some(Big {
            n,
            used,
            plan,
            next: 0,
            to: Decision::Stack,
        });
        true
    }

    /// The merged frame ends: its buffer goes back to the device.
    fn end_cut(&mut self) {
        if let Some(big) = self.big.take() {
            self.give(big.n);
        }
    }

    /// Cuts the next segments of the merged frame and passes them on, as many as the step's
    /// budget allows (`CUT_WEIGHT` frames each) and the stack takes: the frame stays (`self.big`)
    /// while segments are left. The segments are frames of an MTU with whole sums (the device
    /// checked the data), so they go with the sum good; the first names where they all go, as
    /// the route of a flow does. The segments of the stack go in buffers of sending, read in
    /// place and given back through `rx_back` as any frame of the switch's own turn; when the
    /// stack's ring is full or no such buffer is free the cut waits (`cut_wait` has the end of
    /// the stack's run wake the switch). The number of segments passed to the stack.
    fn cut_more(&mut self, budget: &mut usize, taken: &mut usize) -> usize {
        if INNER.cut_wait.load(Ordering::Relaxed) {
            INNER.cut_wait.store(false, Ordering::SeqCst);
        }
        let mut passed = 0;
        while let Some(mut big) = self.big {
            if big.next >= big.plan.segments() {
                self.end_cut();
                break;
            }
            if *budget == 0 || (self.tables.is_some() && *taken >= SWITCH_BASE && self.over_soft())
            {
                break;
            }
            let Some(frame) = self.merged_frame(big.n, big.used) else {
                bump(&INNER.stats.merged_dropped);
                self.end_cut();
                break;
            };
            let Some(len) = big.plan.build(&frame, big.next, &mut self.scratch) else {
                bump(&INNER.stats.merged_dropped);
                self.end_cut();
                break;
            };
            let seg = &self.scratch[..len];
            if big.next == 0 {
                if frames::martian(seg) {
                    INNER.martian.fetch_add(1, Ordering::Relaxed);
                    self.end_cut();
                    break;
                }
                big.to = match self.tables.as_mut() {
                    Some(t) => route::route(t, seg, Source::Wire),
                    None => Decision::Stack,
                };
                if let Decision::Drop(why) = big.to {
                    INNER.stats.drops[why as usize].fetch_add(1, Ordering::Relaxed);
                    self.end_cut();
                    break;
                }
            }
            match (big.to, self.tables.as_mut()) {
                (Decision::Consumer { consumer, .. }, Some(t)) => {
                    INNER.stats.rx_consumer.fetch_add(1, Ordering::Relaxed);
                    INNER.stats.rx_by[usize::from(consumer) % 8].fetch_add(1, Ordering::Relaxed);
                    route::deliver(t, sums::mark(big.to, true), seg);
                }
                _ => {
                    let lane = lane_of(big.to);
                    let stack_full = INNER.lanes[lane].rx_ready.len() >= RX_AHEAD;
                    let Some(m) = (!stack_full).then(|| self.tx.book.alloc()).flatten() else {
                        INNER.cut_wait.store(true, Ordering::SeqCst);
                        self.big = Some(big);
                        break;
                    };
                    // SAFETY: the buffer is free (just taken from the pool).
                    let slice = unsafe { virtio_net::rings::buffer_at(self.tx.base(), m) };
                    slice[HDR_LEN..HDR_LEN + len].copy_from_slice(seg);
                    if offer(&mut self.passed, lane, pack_frame(m, len as u16, true)) {
                        passed += 1;
                    } else {
                        self.tx.book.release(m);
                        INNER.cut_wait.store(true, Ordering::SeqCst);
                        self.big = Some(big);
                        break;
                    }
                }
            }
            bump(&INNER.stats.cut);
            big.next += 1;
            self.big = Some(big);
            *budget = budget.saturating_sub(CUT_WEIGHT);
            *taken += CUT_WEIGHT;
        }
        passed
    }

    /// Rings the doorbell of each queue that got buffers, once for a run
    /// of steps: a ring is an exit from the guest and costs far more than
    /// the frame it announces (the rules are those of the stage before the
    /// split, with the batch of `SWITCH_BELL`).
    fn doorbells(&mut self, continued: bool) {
        let more = continued;
        let rx = &mut self.rx;
        let wanted = virtio_net::rings::wants_ring(&rx.queue);
        if rx.stock.due(wanted) {
            rx.rung();
            if wanted {
                let began = profile::now();
                ring(&mut self.transport, RECEIVEQ);
                profile::timed(Counter::RingN, Counter::RingTicks, Counter::RingMax, began);
                profile::count(Counter::BellRx);
            } else {
                profile::count(Counter::Skipped);
            }
        }
        let tx = &mut self.tx;
        if tx.pending > 0 {
            tx.waited += 1;
        }
        let lanes = &INNER.lanes[..INSTANCES];
        let more = more || lanes.iter().any(|lane| lane.run.busy());
        let due = bell_due(SWITCH_BELL, tx.pending, tx.waited, more);
        // Held for the end of the stack's run, which tells the switch; when
        // the run is over meanwhile, it rings now. Every instance in a run holds it.
        let ring_now = due
            || (tx.pending > 0
                && !continued
                && !lanes
                    .iter()
                    .fold(false, |held, lane| lane.run.hold() | held));
        if ring_now {
            lanes.iter().for_each(|lane| lane.run.unhold());
            INNER.bells_tx.fetch_add(1, Ordering::Relaxed);
            tx.rung();
            if virtio_net::rings::wants_ring(&tx.queue) {
                let began = profile::now();
                ring(&mut self.transport, TRANSMITQ);
                profile::timed(Counter::RingN, Counter::RingTicks, Counter::RingMax, began);
                profile::count(Counter::BellTx);
                trace::point(P_N_BELL, 0);
            } else {
                profile::count(Counter::Skipped);
                trace::point(P_N_BELL_SKIP, 0);
            }
        }
    }
}

/// The switch's place in `.bss`, and its stack and message buffer.
impl Stepper for Switch {
    fn now(&mut self) -> u64 {
        now_ns()
    }
    fn step(&mut self, interrupt: bool) -> bool {
        #[cfg(feature = "steps")]
        let began = self.ran();
        let ticked = profile::now();
        let more = Switch::step(self, interrupt);
        profile::add(Counter::SwitchTicks, profile::now().saturating_sub(ticked));
        #[cfg(feature = "steps")]
        {
            let ticks = self.ran().saturating_sub(began);
            if ticks > self.longest {
                self.longest = ticks;
                rt::println!("service step: 14 kind 67 {ticks} ticks detail 0");
            }
        }
        more
    }
    fn pause(&mut self) -> bool {
        Switch::pause(self)
    }
    fn longest(&mut self, ran: u64) {
        let us = (ran / 1_000).min(u64::from(u32::MAX)) as u32;
        INNER.stats.run_max_us.fetch_max(us, Ordering::Relaxed);
        profile::max(Counter::RunMax, u64::from(us));
    }
}

struct Slot(UnsafeCell<MaybeUninit<Switch>>);

// SAFETY: written once by the main thread before the switch thread starts,
// then used by that thread alone.
unsafe impl Sync for Slot {}

static SLOT: Slot = Slot(UnsafeCell::new(MaybeUninit::uninit()));
const STACK_BYTES: usize = 16 * 1024;
static STACK: Stack<STACK_BYTES> = Stack::new();
/// The message buffer of the thread: the page after the main thread's.
const BUFFER: usize = abi::INIT_MSGBUF as usize + 4096;

/// A tag for the thread that runs: 1 on the switch thread's stack, 0 elsewhere (the guard of
/// the tables checks that only the switch thread writes them).
pub fn tag() -> u32 {
    let here = 0u8;
    let sp = core::ptr::addr_of!(here) as usize;
    let top = STACK.top();
    u32::from(sp <= top && top - sp < STACK_BYTES)
}

/// Why the thread did not start.
pub struct NotStarted;

/// Starts the switch thread at `priority` (above the stack's) over
/// `switch`, which waits on its channel `channel` for the interrupts of the
/// line and the stack's notifications. `stack` is the stack's channel
/// copy with NOTIFY and `wake` the switch's, both for the life of the
/// service.
pub fn start(
    mut switch: Switch,
    process: &Handle<Process>,
    priority: u8,
    (stack, wake): (&Handle<Channel>, &Handle<Channel>),
) -> Result<Handle<Thread>, NotStarted> {
    // The channel and timer of the pauses: a wait channel, so that the pause lends no priority.
    let pause = sys::channel_create_wait(priority)
        .and_then(|channel| sys::timer_create(&channel, priority).map(|timer| (channel, timer)))
        .map_err(|_| NotStarted)?;
    switch.pause = Some(pause);
    INNER.lanes[DEFAULT_INSTANCE].set_stack_channel(stack.raw().0);
    INNER.switch_channel.store(wake.raw().0, Ordering::Release);
    // SAFETY: the slot is empty and the thread that reads it does not exist
    // yet.
    unsafe { (*SLOT.0.get()).write(switch) };
    // SAFETY: STACK is the thread's alone, and the page after the main
    // thread's message buffer is free.
    let thread = unsafe {
        sys::thread_create(
            process,
            run,
            STACK.top(),
            0,
            priority,
            abi::Policy::Fifo,
            BUFFER,
        )
    }
    .map_err(|_| NotStarted)?;
    sys::thread_start(&thread).map_err(|_| NotStarted)?;
    Ok(thread)
}

/// The thread: waits for a notification, and runs steps while they follow.
extern "C" fn run(_: u64) -> ! {
    // SAFETY: `start` wrote the slot before this thread was made, and this
    // is its only user.
    let switch = unsafe { (*SLOT.0.get()).assume_init_mut() };
    #[cfg(feature = "steps")]
    {
        switch.own = sys::self_thread().ok();
    }
    // The tables are the switch thread's from here on.
    if let Some(t) = switch.tables.as_mut() {
        t.claim();
    }
    // The line opens once the queues are up.
    virtio_mmio::reopen(&switch.irq);
    let (mut clock, mut longest) = (RunClock::new(), 0);
    loop {
        let waiting = now_ns();
        let interrupt = match sys::receive(&switch.channel) {
            Ok(sys::Received::Notification { source, label, .. }) => {
                // Seen before the rings are looked at: a word pushed after
                // that tells again.
                INNER.switch_told.seen();
                if source == abi::Source::Timer {
                    switch.armed = false;
                }
                if source == abi::Source::Interrupt && switch.msi.is_some() {
                    switch.count_vector(label);
                }
                source == abi::Source::Interrupt
            }
            Ok(_) => continue,
            Err(error) => {
                rt::println!("virtio-net: the switch cannot wait: {error:?}");
                sys::process_exit(crate::STOPPED)
            }
        };
        if interrupt {
            profile::count(Counter::Irq);
        }
        trace::point(P_N_WAKE, 1 + u32::from(!interrupt));
        let woke = now_ns();
        clock.woke(woke, woke.wrapping_sub(waiting));
        drive(switch, &mut clock, &mut longest, interrupt);
        // The probe's line, for the check that a doorbell serves many frames
        // of a burst (xtask `net_probe::bells_serve_frames`): every 500 frames.
        #[cfg(feature = "probe")]
        {
            let frames = INNER.frames_tx();
            if frames / 500 > switch.said {
                switch.said = frames / 500;
                rt::println!("net: bells tx {} frames {frames}", INNER.bells_tx());
            }
        }
    }
}
