// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The switch thread: the first device's queues, its line and its
//! doorbells, apart from the stack. The service has two threads. This one
//! runs one level above the stack on the CPU of the line's interrupts and
//! owns the transport, the two queues and the binding of the line; the
//! stack (the thread of `rt::service`'s loop: smoltcp, the sockets, DHCP,
//! ARP) is a consumer of the switch and sees the device as five rings of
//! words (`Inner`, `netd::spsc`) that carry the numbers of the buffers of
//! the device: no frame is copied, and each ring has one writer and one
//! reader.
//!
//! * `rx_ready`: the switch took a frame off the queue of receiving, looked
//!   at its header (`frames::classify`) and passes it to the stack with its
//!   length. The stack gives the buffer back in `rx_back` once it is done
//!   with the frame, and the switch puts it in the queue.
//! * `tx_supply`: the free buffers of sending the switch lends the stack
//!   (`TX_SHARE` of the 256; the rest stay with the switch for its own
//!   frames and for the stack that runs dry). The stack builds a frame in
//!   one and passes it in `tx_sub`; the switch puts it in the queue, takes
//!   the sent buffers back (`reclaim`, at most `RECLAIM_STEP` a step) and
//!   lends them again. A buffer the stack did not send comes back in
//!   `tx_back`.
//!
//! Every buffer is in one place at a time, and each ring holds as many words
//! as there are buffers, so no push finds a ring full. The rules of the
//! doorbells and of the interrupts are the stack's of the stage before the
//! split (`ring::settle_interrupts`, `ring::bell_due`, `Stock`): the line
//! stays closed and the device asks for no interrupt while steps follow, the
//! doorbell of sending rings once for a run of steps of the stack
//! (`Inner::stack_more`), and the queue is looked at once more after the
//! interrupts are asked for again.
//!
//! The wakes between the two threads are one notification each, told once
//! until the other thread saw it (`stack_told`, `switch_told`): the switch
//! wakes the stack when it passed frames, the stack wakes the switch at the
//! end of a run of its steps when buffers or frames wait in the rings. The
//! stack never waits for the switch, and the switch never waits for the
//! stack.

use crate::device::{DEVICE, Queue, fail};
use crate::dma::{Host, net_at};
use core::cell::{RefCell, UnsafeCell};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use netd::frames::{self, RxFrame};
use netd::profile::{self, Counter};
use netd::ring::{
    RECLAIM_STEP, RX_AHEAD, RX_BUFFERS, SWITCH_BELL, SWITCH_RX, SWITCH_TX, TX_SHARE, bell_due,
};
use netd::spsc::{Spsc, pack, unpack};
use rt::handle::{Channel, Interrupt, Process, Thread};
use rt::{Handle, Stack, sys};
use virtio_drivers::transport::SomeTransport;
use virtio_mmio::Isr;
use virtio_net::barrier::ring;
use virtio_net::rings::Sent;

const RECEIVEQ: u16 = 0;
const TRANSMITQ: u16 = 1;

/// The rings between the threads, and what they tell each other.
pub struct Inner {
    /// Switch to stack: a frame of the wire, `pack(buffer, length)`.
    pub rx_ready: Spsc<256>,
    /// Stack to switch: a buffer of receiving that is free again.
    pub rx_back: Spsc<256>,
    /// Stack to switch: a frame to send, `pack(buffer, length)`.
    pub tx_sub: Spsc<256>,
    /// Switch to stack: a free buffer of sending.
    pub tx_supply: Spsc<256>,
    /// Stack to switch: a buffer of sending the stack did not use.
    pub tx_back: Spsc<256>,
    /// The switch told the stack of frames, and the stack has not looked.
    pub stack_told: AtomicBool,
    /// The stack told the switch, and the switch has not looked.
    pub switch_told: AtomicBool,
    /// The stack found no buffer of sending free.
    starved: AtomicBool,
    /// A doorbell of sending waits for the end of the stack's run.
    held: AtomicBool,
    /// Another step of the stack follows at once.
    stack_more: AtomicBool,
    /// The channel of the stack and of the switch, raw, for NOTIFY.
    stack_channel: AtomicU64,
    switch_channel: AtomicU64,
    /// Frames of the wire the switch dropped as no frame or as martian,
    /// and frames of sending the queue refused.
    dropped: AtomicU32,
    martian: AtomicU32,
    tx_dropped: AtomicU32,
}

impl Inner {
    const fn new() -> Inner {
        Inner {
            rx_ready: Spsc::new(),
            rx_back: Spsc::new(),
            tx_sub: Spsc::new(),
            tx_supply: Spsc::new(),
            tx_back: Spsc::new(),
            stack_told: AtomicBool::new(false),
            switch_told: AtomicBool::new(false),
            starved: AtomicBool::new(false),
            held: AtomicBool::new(false),
            stack_more: AtomicBool::new(false),
            stack_channel: AtomicU64::new(0),
            switch_channel: AtomicU64::new(0),
            dropped: AtomicU32::new(0),
            martian: AtomicU32::new(0),
            tx_dropped: AtomicU32::new(0),
        }
    }

    /// Frames the switch dropped (no frame) and the martian ones.
    pub fn rx_counts(&self) -> (u64, u64) {
        (
            u64::from(self.dropped.load(Ordering::Relaxed)),
            u64::from(self.martian.load(Ordering::Relaxed)),
        )
    }

    pub fn tx_dropped(&self) -> u64 {
        u64::from(self.tx_dropped.load(Ordering::Relaxed))
    }

    /// The free buffers of sending the switch lent the stack and it has
    /// not used. Nought says the stack is out of buffers, and the switch
    /// is to tell when it lent more.
    pub fn supply_len(&self) -> usize {
        let len = self.tx_supply.len();
        if len == 0 {
            self.starved.store(true, Ordering::Release);
        }
        len
    }

    /// A free buffer of sending for the stack.
    pub fn take_supply(&self) -> Option<u16> {
        let taken = self.tx_supply.pop().map(|w| w as u16);
        if taken.is_none() {
            self.starved.store(true, Ordering::Release);
        }
        taken
    }

    /// The stack's own channel is the one the switch wakes.
    pub fn set_stack_channel(&self, raw: u64) {
        self.stack_channel.store(raw, Ordering::Release);
    }

    /// The end of a step of the stack: `more` says another follows at
    /// once. The switch is woken when the run is over (or the rings hold
    /// a good deal) and a buffer, a frame or a doorbell waits for it.
    pub fn kick(&self, more: bool) {
        self.stack_more.store(more, Ordering::Release);
        let starved = self.starved.load(Ordering::Acquire);
        let work = !self.tx_sub.is_empty() || !self.rx_back.is_empty();
        let due = if more {
            self.tx_sub.len() >= SWITCH_TX / 2 || self.rx_back.len() >= RX_AHEAD || starved
        } else {
            work || starved || self.held.load(Ordering::Acquire)
        };
        if due {
            self.wake_switch();
        }
    }

    fn wake_switch(&self) {
        if !self.switch_told.swap(true, Ordering::AcqRel) {
            profile::count(Counter::Told);
            let channel = Handle::<Channel>::borrowed(rt::abi::Handle(
                self.switch_channel.load(Ordering::Acquire),
            ));
            if sys::notify(&channel, 1).is_err() {
                self.switch_told.store(false, Ordering::Release);
            }
        }
    }

    fn wake_stack(&self, bits: u64) {
        let channel = Handle::<Channel>::borrowed(rt::abi::Handle(
            self.stack_channel.load(Ordering::Acquire),
        ));
        let _ = sys::notify(&channel, bits);
    }
}

pub static INNER: Inner = Inner::new();

/// The switch: the device's transport and queues, and the binding of its
/// line.
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
    link: bool,
    /// The longest step so far, in ticks of the thread's own time.
    #[cfg(feature = "steps")]
    longest: u64,
}

impl Switch {
    /// The switch over the device's two queues, which the device has not
    /// seen yet: the buffers of receiving go in, the device is told they
    /// did (`finish_init`), and the buffers of sending are lent to the
    /// stack.
    pub fn new(
        mut transport: SomeTransport<'static>,
        rx_queue: Queue<DEVICE>,
        tx_queue: Queue<DEVICE>,
        irq: Handle<Interrupt>,
        channel: Handle<Channel>,
        link: bool,
    ) -> Switch {
        let mut rx = virtio_net::RxRing::new(rx_queue, net_at(DEVICE));
        if let Err(broken) = rx.fill(RX_BUFFERS) {
            fail(broken.text(false));
        }
        use virtio_drivers::transport::Transport;
        transport.finish_init();
        ring(&mut transport, RECEIVEQ);
        rx.rung();
        let mut switch = Switch {
            transport,
            rx,
            tx: virtio_net::TxRing::new(tx_queue, net_at(DEVICE)),
            irq,
            channel,
            line_closed: false,
            interrupted: false,
            link,
            #[cfg(feature = "steps")]
            longest: 0,
        };
        switch.lend();
        switch
    }

    /// Lends the stack free buffers of sending up to its share. True when
    /// the stack was out of them and has some now.
    fn lend(&mut self) -> bool {
        while INNER.tx_supply.len() < TX_SHARE {
            let Some(n) = self.tx.book.alloc() else {
                break;
            };
            let _ = INNER.tx_supply.push(u32::from(n));
        }
        !INNER.tx_supply.is_empty() && INNER.starved.swap(false, Ordering::AcqRel)
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

    /// One step: the buffers and frames the stack passed go to the queues,
    /// the sent buffers come back, the frames of the wire go to the stack,
    /// and the doorbells ring when a run is over. True when another step
    /// follows at once (frames left in the queue with room for them, or
    /// frames of the stack left in its ring).
    fn step(&mut self, interrupt: bool) -> bool {
        profile::count(Counter::StepRx);
        if interrupt {
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
        // What the stack passed: buffers of receiving, buffers of sending
        // it did not use, then its frames to send.
        while let Some(word) = INNER.rx_back.pop() {
            if let Err(broken) = self.rx.give(word as u16) {
                fail(broken.text(false));
            }
        }
        while let Some(word) = INNER.tx_back.pop() {
            self.tx.book.release(word as u16);
        }
        for _ in 0..SWITCH_TX {
            let Some(word) = INNER.tx_sub.pop() else {
                break;
            };
            let (n, len) = unpack(word);
            match self.tx.submit(n, usize::from(len)) {
                Ok(Sent::Queued) => {}
                Ok(Sent::Dropped) => {
                    INNER.tx_dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(broken) => fail(broken.text(true)),
            }
        }
        if let Err(broken) = self.tx.reclaim(RECLAIM_STEP) {
            fail(broken.text(true));
        }
        let lent = self.lend();
        // The frames of the wire.
        let room = RX_AHEAD.saturating_sub(INNER.rx_ready.len());
        let passed = self.receive(room.min(SWITCH_RX));
        if passed > 0 && !INNER.stack_told.swap(true, Ordering::AcqRel) {
            profile::count(Counter::Told);
            INNER.wake_stack(crate::RX);
        }
        if lent {
            INNER.wake_stack(crate::TX);
        }
        // Frames left in the queue with room for them, or in the stack's
        // ring of frames to send: another step follows at once.
        let room_left = room.saturating_sub(passed);
        let more_rx = room_left > 0 && self.rx.queue.can_pop();
        // While steps follow, the device is asked for no interrupt. The run
        // ends with the interrupts asked for again, a full barrier and one
        // more look at the queue, so that a frame that came between is not
        // left to wait (`ring::settle_interrupts`).
        let continued = {
            let queue = RefCell::new(&mut self.rx.queue);
            netd::ring::settle_interrupts(
                more_rx,
                || room_left > 0,
                |on| virtio_net::rings::notify_on(&mut queue.borrow_mut(), on),
                || queue.borrow().can_pop(),
            )
        } || !INNER.tx_sub.is_empty();
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
        self.doorbells(continued || INNER.stack_more.load(Ordering::Acquire));
        continued
    }

    /// Takes up to `budget` used buffers off the queue of receiving, each
    /// to the stack (its number and the length of its frame) or back to the
    /// queue when it holds no frame or one the stack must not see. Every
    /// buffer taken costs one unit of the share. The number of frames
    /// passed.
    fn receive(&mut self, mut budget: usize) -> usize {
        let mut passed = 0;
        while budget > 0 {
            let (n, used) = match self.rx.pop() {
                Ok(Some(popped)) => popped,
                Ok(None) => break,
                Err(broken) => fail(broken.text(false)),
            };
            budget -= 1;
            // SAFETY: the device returned the buffer (it is used), and the
            // switch holds no other reference to it.
            let slice = unsafe { virtio_net::rings::buffer_at(self.rx.base(), n) };
            match frames::classify(slice, used) {
                RxFrame::Frame(len) => {
                    let _ = INNER.rx_ready.push(pack(n, len as u16));
                    passed += 1;
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

    /// Rings the doorbell of each queue that got buffers, once for a run
    /// of steps: a ring is an exit from the guest and costs far more than
    /// the frame it announces (the rules are those of the stage before the
    /// split, with the batch of `SWITCH_BELL`).
    fn doorbells(&mut self, more: bool) {
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
        if bell_due(SWITCH_BELL, tx.pending, tx.waited, more) {
            tx.rung();
            if virtio_net::rings::wants_ring(&tx.queue) {
                let began = profile::now();
                ring(&mut self.transport, TRANSMITQ);
                profile::timed(Counter::RingN, Counter::RingTicks, Counter::RingMax, began);
                profile::count(Counter::BellTx);
            } else {
                profile::count(Counter::Skipped);
            }
        }
        INNER.held.store(self.tx.pending > 0, Ordering::Release);
    }
}

/// The switch's place in `.bss`, and its stack and message buffer.
struct Slot(UnsafeCell<MaybeUninit<Switch>>);

// SAFETY: written once by the main thread before the switch thread starts,
// then used by that thread alone.
unsafe impl Sync for Slot {}

static SLOT: Slot = Slot(UnsafeCell::new(MaybeUninit::uninit()));
const STACK_BYTES: usize = 16 * 1024;
static STACK: Stack<STACK_BYTES> = Stack::new();
/// The message buffer of the thread: the page after the main thread's.
const BUFFER: usize = abi::INIT_MSGBUF as usize + 4096;

/// Why the thread did not start.
pub struct NotStarted;

/// Starts the switch thread at `priority` (above the stack's) over
/// `switch`, which waits on its channel `channel` for the interrupts of the
/// line and the stack's notifications. `stack` is the stack's channel
/// copy with NOTIFY and `wake` the switch's, both for the life of the
/// service.
pub fn start(
    switch: Switch,
    process: &Handle<Process>,
    priority: u8,
    (stack, wake): (&Handle<Channel>, &Handle<Channel>),
) -> Result<Handle<Thread>, NotStarted> {
    INNER.set_stack_channel(stack.raw().0);
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
    let own = sys::self_thread().ok();
    // The line opens once the queues are up.
    virtio_mmio::reopen(&switch.irq);
    loop {
        let interrupt = match sys::receive(&switch.channel) {
            Ok(sys::Received::Notification { source, .. }) => {
                // Seen before the rings are looked at: a word pushed after
                // that tells again.
                INNER.switch_told.store(false, Ordering::Release);
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
        let mut interrupt = interrupt;
        loop {
            #[cfg(feature = "steps")]
            let began = own.as_ref().map_or(0, |t| sys::thread_ran(t).unwrap_or(0));
            let more = switch.step(interrupt);
            interrupt = false;
            #[cfg(feature = "steps")]
            if let Some(t) = own.as_ref() {
                let ticks = sys::thread_ran(t).unwrap_or(0).saturating_sub(began);
                if ticks > switch.longest {
                    switch.longest = ticks;
                    rt::println!("service step: 14 kind 67 {ticks} ticks detail 0");
                }
            }
            if !more {
                break;
            }
        }
    }
}
