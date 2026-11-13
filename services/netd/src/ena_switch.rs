// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The switch thread of the ENA kind of device: the same place in the service
//! as `switch.rs` has for Virtio, over the same lane of five rings of words
//! (`switch::INNER.lanes`) and the same wakes between the threads, with the
//! pair of queues of the ENA (`netd::enawire::Wire`) where Virtio has its two
//! queues. `switch.rs` is not changed by it: the Virtio kinds take
//! no new work in their step.
//!
//! One lane, no consumers and no tables of the switch: the stack sees every
//! frame (the instances of the next step, RSS and `switch N` come with it).
//!
//! Where the interrupts go. Init binds the two events of the function's MSI
//! device through this thread's channel, each with the label of its binding
//! (`proto_init::binding_label`): vector 0 is the admin one (events, keep-alive
//! once a second), which the thread passes on to the admin thread, and vector 1
//! is the pair's. The pair's vector is masked by the device after each
//! interrupt: the end of a run of steps acknowledges the binding (`irq_ack`,
//! `WOULD_BLOCK` until the ITS commands of the event have run: retried on a
//! timer, never in a loop), unmasks the vector with one write, and looks at the
//! queue once more. A thread whose device has no vectors (or whose table the
//! driver refused) polls on a timer of 500 microseconds.
//!
//! The admin side (`ena_service.rs`) makes the pair and tells this thread by an
//! epoch and a notification; the thread never calls the admin machine.

use crate::ena_service::{self as svc, Hw};
use crate::switch::INNER;
use crate::trace::{self, P_N_STEP, P_N_WAKE};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::Ordering;
use netd::enawire::{Ack, Rings, Vector, Wire};
use netd::profile::{self, Counter};
use netd::ring::{RunClock, SWITCH_PAUSE_NS, Stepper, drive};
use rt::handle::{Channel, Interrupt, Process, Thread, Timer};
use rt::{Handle, Stack, sys};

/// The labels of the timer of the thread.
const TIMER_LABEL: u64 = 3;
/// The polling period of a device without vectors, the safety period of one with,
/// and the retry of an acknowledgement that said not yet.
const POLL_NS: u64 = 500_000;
const SAFETY_NS: u64 = 100_000_000;
const RETRY_NS: u64 = 200_000;
/// The bit the admin side notifies this thread with when the pair changes.
pub const EPOCH_BIT: u64 = 1 << 4;

/// What woke the thread, for the counters that tell whether the interrupts do the
/// work.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wake {
    Interrupt,
    Timer,
    Other,
}

pub struct EnaSwitch {
    wire: Wire<Hw>,
    channel: Handle<Channel>,
    irq: [Option<Handle<Interrupt>>; 2],
    vectors: [Vector; 2],
    timer: Handle<Timer>,
    _view: Handle<Channel>,
    armed: bool,
    /// The pair's vector is in use (the device has the table filled).
    msi: bool,
    wake: Wake,
    rx_seen: u64,
    pause: Option<(Handle<Channel>, Handle<Timer>)>,
    said: [bool; 2],
}

fn now_ns() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}

impl EnaSwitch {
    pub fn new(
        wire: Wire<Hw>,
        channel: Handle<Channel>,
        irq: [Option<Handle<Interrupt>>; 2],
        msi: bool,
        priority: u8,
    ) -> Option<EnaSwitch> {
        let view = sys::handle_label(&channel, abi::Rights::RECEIVE, TIMER_LABEL, priority).ok()?;
        let timer = sys::timer_create(&view, priority).ok()?;
        Some(EnaSwitch {
            wire,
            channel,
            irq,
            vectors: [Vector::new(); 2],
            timer,
            _view: view,
            armed: false,
            msi,
            wake: Wake::Other,
            rx_seen: 0,
            pause: None,
            said: [false; 2],
        })
    }

    fn arm(&mut self, after: u64) {
        if !self.armed {
            self.armed = sys::timer_set(&self.timer, now_ns() + after).is_ok();
        }
    }

    /// Acknowledges vector `v` when one is owed: true when the device's vector may be
    /// unmasked now. `NotYet` leaves it owed and arms the retry.
    fn acknowledge(&mut self, v: usize) -> bool {
        if !self.vectors[v].owed() {
            return true;
        }
        let Some(binding) = self.irq[v].as_ref() else {
            return true;
        };
        let answer = match sys::irq_ack(binding) {
            Ok(()) => Ack::Done,
            Err(abi::Error::WouldBlock) => Ack::NotYet,
            Err(_) => Ack::Gone,
        };
        let may = self.vectors[v].answered(answer);
        if answer == Ack::NotYet {
            self.arm(RETRY_NS);
        }
        may || answer == Ack::Gone
    }

    fn step(&mut self, interrupt: bool) -> bool {
        profile::count(Counter::StepSwitch);
        trace::point(P_N_STEP, 0);
        let _ = interrupt;
        // The switch thread does not acknowledge an epoch change to the admin thread: the
        // admin side may zero the rings of a pair this thread is about to leave only because
        // both threads stand on CPU 0 and this one runs at the higher priority, so it is not
        // inside a step while the admin side runs. A second CPU for either thread needs an
        // acknowledgement (the epoch of step g).
        let epoch = svc::IO_EPOCH.load(Ordering::Acquire);
        self.wire.sync(epoch, svc::io_info());
        // The admin vector: acknowledged here, handled by the admin thread.
        if self.vectors[0].owed() {
            self.acknowledge(0);
        }
        let lane = &INNER.lanes[0];
        let rings = Rings {
            rx_ready: &lane.rx_ready,
            rx_back: &lane.rx_back,
            tx_sub: &lane.tx_sub,
            tx_supply: &lane.tx_supply,
            tx_back: &lane.tx_back,
            starved: &lane.starved,
        };
        let s = self.wire.step(&rings);
        if s.broken {
            svc::ask_reset();
        }
        let rx = self.wire.counts().rx;
        let got = rx - self.rx_seen;
        self.rx_seen = rx;
        if got > 0 {
            let counter = match self.wake {
                Wake::Interrupt => &svc::STATS.rx_irq,
                Wake::Timer => &svc::STATS.rx_timer,
                Wake::Other => &svc::STATS.rx_other,
            };
            counter.fetch_add(got, Ordering::Relaxed);
        }
        self.wake = Wake::Other;
        if s.passed && lane.stack_told.tell() {
            lane.wake_stack(crate::RX);
        }
        if s.lent {
            lane.wake_stack(crate::TX);
        }
        if s.more {
            return true;
        }
        self.settle()
    }

    /// The end of a run: the interrupt of the pair is acknowledged and unmasked and the
    /// queue looked at once more; without vectors, or while the acknowledgement waits, a
    /// timer does the looking. True when a step must follow at once.
    fn settle(&mut self) -> bool {
        if !self.wire.is_up() {
            // The admin side's notification brings the next step.
            return false;
        }
        if !self.msi {
            self.arm(POLL_NS);
            return false;
        }
        if !self.acknowledge(1) {
            return false;
        }
        let again = self.wire.settle();
        if again {
            return true;
        }
        let after = if svc::POLL_FALLBACK.load(Ordering::Relaxed) {
            POLL_NS
        } else {
            SAFETY_NS
        };
        self.arm(after);
        false
    }

    fn pause(&mut self) -> bool {
        let waited = match &self.pause {
            Some((channel, timer)) => {
                sys::timer_set(timer, now_ns() + SWITCH_PAUSE_NS).is_ok()
                    && sys::receive(channel).is_ok()
            }
            None => false,
        };
        if waited {
            profile::count(Counter::Pause);
        }
        waited
    }

    /// An interrupt of the vector whose binding carries `label`.
    fn interrupted(&mut self, label: u64) {
        let v = usize::from(label == proto_init::binding_label(1));
        self.vectors[v].interrupted();
        svc::STATS.irq[v].fetch_add(1, Ordering::Relaxed);
        if !core::mem::replace(&mut self.said[v], true) {
            rt::println!("ena: first interrupt of vector {v}");
        }
        if v == 0 {
            svc::wake_admin();
        } else {
            self.wake = Wake::Interrupt;
        }
    }
}

impl Stepper for EnaSwitch {
    fn now(&mut self) -> u64 {
        now_ns()
    }
    fn step(&mut self, interrupt: bool) -> bool {
        EnaSwitch::step(self, interrupt)
    }
    fn pause(&mut self) -> bool {
        EnaSwitch::pause(self)
    }
    fn longest(&mut self, ran: u64) {
        let us = (ran / 1_000).min(u64::from(u32::MAX)) as u32;
        profile::max(Counter::RunMax, u64::from(us));
    }
}

struct Slot(UnsafeCell<MaybeUninit<EnaSwitch>>);

// SAFETY: written once by the main thread before the switch thread starts, then used by that
// thread alone.
unsafe impl Sync for Slot {}

static SLOT: Slot = Slot(UnsafeCell::new(MaybeUninit::uninit()));
const STACK_BYTES: usize = 16 * 1024;
static STACK: Stack<STACK_BYTES> = Stack::new();
/// The message buffer of the thread: the page after the main thread's.
const BUFFER: usize = abi::INIT_MSGBUF as usize + 4096;

/// Why the thread did not start.
pub struct NotStarted;

/// Starts the thread at `priority` over `switch`, which waits on its channel for the
/// interrupts, the notifications of the stack and the admin side's; `wake` is the copy
/// of the channel with NOTIFY the instances and the admin side wake it with.
pub fn start(
    mut switch: EnaSwitch,
    process: &Handle<Process>,
    priority: u8,
    wake: &Handle<Channel>,
) -> Result<Handle<Thread>, NotStarted> {
    let pause = sys::channel_create_wait(priority)
        .and_then(|channel| sys::timer_create(&channel, priority).map(|timer| (channel, timer)))
        .map_err(|_| NotStarted)?;
    switch.pause = Some(pause);
    INNER.set_switch_channel(wake.raw().0);
    svc::SWITCH_RAW.store(wake.raw().0, Ordering::Release);
    // SAFETY: the slot is empty and the thread that reads it does not exist yet.
    unsafe { (*SLOT.0.get()).write(switch) };
    // SAFETY: STACK is the thread's alone, and the page after the main thread's message buffer
    // is free.
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

extern "C" fn run(_: u64) -> ! {
    // SAFETY: `start` wrote the slot before this thread was made, and this is its only user.
    let switch = unsafe { (*SLOT.0.get()).assume_init_mut() };
    let (mut clock, mut longest) = (RunClock::new(), 0);
    // A first step: the pair may be up already.
    drive(switch, &mut clock, &mut longest, false);
    loop {
        let waiting = now_ns();
        let interrupt = match sys::receive(&switch.channel) {
            Ok(sys::Received::Notification { source, label, .. }) => {
                INNER.switch_told.seen();
                if source == abi::Source::Timer {
                    switch.armed = false;
                    switch.wake = Wake::Timer;
                }
                if source == abi::Source::Interrupt {
                    switch.interrupted(label);
                }
                source == abi::Source::Interrupt
            }
            Ok(_) => continue,
            Err(error) => {
                rt::println!("ena: the switch cannot wait: {error:?}");
                sys::process_exit(crate::STOPPED)
            }
        };
        trace::point(P_N_WAKE, 1 + u32::from(!interrupt));
        let woke = now_ns();
        clock.woke(woke, woke.wrapping_sub(waiting));
        drive(switch, &mut clock, &mut longest, interrupt);
    }
}
