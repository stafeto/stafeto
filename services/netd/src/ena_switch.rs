// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The switch thread of the ENA kind of device: the same place in the service
//! as `switch.rs` has for Virtio, over the same lane of five rings of words
//! (`switch::INNER.lanes`) and the same wakes between the threads, with the
//! pair of queues of the ENA (`netd::enawire::Wire`) where Virtio has its two
//! queues. `switch.rs` is not changed by it: the Virtio kinds take
//! no new work in their step.
//!
//! One lane. Without consumers (`switch N` absent from `netd.conf`) the stack sees every
//! frame. With them the tables and the rings of the consumers are `netd::routed`'s, over the
//! same wire and the same lane: the thread hands it the step, and takes from it the wakes of the
//! consumers, the answers owed the stack and the delay of its timer.
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
use crate::switch::{COMMANDS, INNER};
use crate::trace::{self, P_N_STEP, P_N_WAKE};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::Ordering;
use netd::enawire::{Ack, Rings, Step, Vector, Wire};
use netd::profile::{self, Counter};
use netd::ring::{Stepper, drive};
use netd::routed::Routed;
use rt::handle::{Budget, Channel, Interrupt, Process, Thread, Timer};
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
    /// When the timer fires, if it is set.
    due: Option<u64>,
    /// The consumers of the switch, none without `switch N`.
    routed: Option<Routed>,
    /// The pair's vector is in use (the device has the table filled).
    msi: bool,
    wake: Wake,
    rx_seen: u64,
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
        routed: Option<Routed>,
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
            due: None,
            routed,
            msi,
            wake: Wake::Other,
            rx_seen: 0,
            said: [false; 2],
        })
    }

    /// The timer fires `after` nanoseconds from now, unless it is set for an earlier time.
    fn arm(&mut self, after: u64) {
        let at = now_ns() + after;
        if self.due.is_none_or(|due| at < due) && sys::timer_set(&self.timer, at).is_ok() {
            self.due = Some(at);
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
        let s = match self.routed.as_mut() {
            None => self.wire.step(&rings),
            Some(routed) => {
                let out = routed.step(
                    &mut self.wire,
                    &rings,
                    now_ns(),
                    &COMMANDS,
                    &INNER.stats,
                    &mut |handle| {
                        let channel = Handle::<Channel>::borrowed(rt::abi::Handle(handle));
                        let _ = sys::notify(&channel, proto_net::switch::WAKE_RING);
                    },
                );
                if out.back {
                    lane.tell_back();
                }
                if let Some(after) = out.timer {
                    self.arm(after);
                }
                Step {
                    passed: out.passed,
                    lent: out.lent,
                    more: out.more,
                    broken: out.broken,
                }
            }
        };
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
        self.settle(&rings)
    }

    /// The end of a run: the interrupt of the pair is acknowledged and unmasked and the
    /// queue looked at once more; without vectors, or while the acknowledgement waits, a
    /// timer does the looking. True when a step must follow at once.
    fn settle(&mut self, rings: &Rings<'_>) -> bool {
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
        let again = self.wire.settle(rings);
        if again {
            if let Some(routed) = self.routed.as_mut() {
                routed.clear_idle();
            }
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
    fn step(&mut self, interrupt: bool) -> bool {
        EnaSwitch::step(self, interrupt)
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
/// of the channel with NOTIFY the instances and the admin side wake it with. The thread works
/// under `budget` from its first instruction (`budgets`).
pub fn start(
    switch: EnaSwitch,
    process: &Handle<Process>,
    priority: u8,
    wake: &Handle<Channel>,
    budget: Option<&Handle<Budget>>,
) -> Result<Handle<Thread>, NotStarted> {
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
    crate::budgets::bind("the switch", budget, &thread).map_err(|()| NotStarted)?;
    sys::thread_start(&thread).map_err(|_| NotStarted)?;
    Ok(thread)
}

extern "C" fn run(_: u64) -> ! {
    // SAFETY: `start` wrote the slot before this thread was made, and this is its only user.
    let switch = unsafe { (*SLOT.0.get()).assume_init_mut() };
    // A first step: the pair may be up already.
    drive(switch, false);
    loop {
        let interrupt = match sys::receive(&switch.channel) {
            Ok(sys::Received::Notification { source, label, .. }) => {
                INNER.switch_told.seen();
                if source == abi::Source::Timer {
                    switch.due = None;
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
        drive(switch, interrupt);
    }
}
