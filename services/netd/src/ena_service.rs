// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The network service with an ENA device (`kind` of its table record: the
//! start data holds the object `ena` and neither `dma` nor `net`): the
//! second kind of device after Virtio. At this step the service brings the
//! device up on polling (`ena::Ena`), prints its version, MAC, link and
//! keep-alive counts, watches it and resets it in place; there is no data
//! path yet, so it serves no client. The driver's logic is in the library
//! `ena`, tested on the host against a model of the device; this file holds
//! the calls: the windows, the object, the timer and the heartbeat.

use abi::{Access, Source};
use core::fmt;
use ena::mmio::Bar;
use ena::{Ena, Event, Platform, Region};
use proto_init::ServiceArgs;
use proto_wire::Status;
use rt::handle::{Memory, Timer};
use rt::service::{Answer, Config, Heartbeat, Notice, Request, Service, Session};
use rt::{Handle, sys, time};

/// Where the service maps what init gives it.
const ENA_AT: usize = 0x10_0000_0000;
const BAR_AT: usize = 0x10_1000_0000;
const ECAM_AT: usize = 0x10_2000_0000;
const PAGE: u64 = 4096;
const TIMER_LABEL: u64 = 1;
/// The step of the service: half the watchdog's 100 ms.
const TICK_NS: u64 = 50_000_000;
/// The steps one notification takes at most.
const STEPS: u32 = 64;
/// The command word of the function: the firmware leaves memory decoding off
/// until the owner of the function turns it on, and DMA needs bus mastering;
/// INTx stays off (the device is polled). Written as a whole word with the
/// status half 0, which clears nothing [G34].
const COMMAND: usize = 4;
const MEMORY: u32 = 1 << 1;
const BUS_MASTER: u32 = 1 << 2;
const INTX_DISABLE: u32 = 1 << 10;
const NOT_REGISTERED: u64 = 3;
const NOT_MAPPED: u64 = 4;
const NO_DEVICE: u64 = 6;
/// The code the service ends with when the device cannot be recovered; init
/// stops the device and starts the service again.
const FAILED: u64 = 8;

struct Hw {
    bar: Bar,
}

impl Platform for Hw {
    fn read32(&self, offset: u32) -> u32 {
        self.bar.read32(offset)
    }

    fn write32(&self, offset: u32, value: u32) {
        self.bar.write32(offset, value);
    }

    fn now_ns(&self) -> u64 {
        time::ticks_to_ns(time::now())
    }

    fn wmb(&self) {
        rt::dma::wmb();
    }

    fn rmb(&self) {
        rt::dma::rmb();
    }

    fn log(&self, line: fmt::Arguments<'_>) {
        rt::println!("{line}");
    }
}

struct EnaService {
    ena: Ena<Hw>,
    timer: Handle<Timer>,
    deadline: u64,
    /// The probe's deliberate break: after the first start the head of the
    /// event queue is not written back, until the reset it causes.
    #[cfg(feature = "ena-break-aenq")]
    broken: bool,
}

impl EnaService {
    fn arm(&mut self) {
        let now = time::ticks_to_ns(time::now());
        self.deadline = now + TICK_NS;
        let _ = sys::timer_set(&self.timer, self.deadline);
    }

    fn step(&mut self) {
        for _ in 0..STEPS {
            match self.ena.poll() {
                Event::Idle => break,
                Event::Failed(_) => sys::process_exit(FAILED),
                #[cfg(feature = "ena-break-aenq")]
                Event::Up if !self.broken => {
                    self.broken = true;
                    self.ena.hold_event_head(true);
                    rt::println!("ena: break: the event head is held");
                }
                #[cfg(feature = "ena-break-aenq")]
                Event::Resetting(_) => self.ena.hold_event_head(false),
                _ => {}
            }
        }
    }
}

impl Service<1> for EnaService {
    const VERSION: u16 = 1;
    const METHODS: &'static [u16] = &[];
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 1>, _: &mut Request<'_>) -> Answer {
        Answer::Status(Status::UnknownMethod)
    }

    fn notification(&mut self, n: Notice) {
        if let (Source::Timer, TIMER_LABEL) = (n.source, n.label)
            && time::reached(self.deadline)
        {
            self.step();
            self.arm();
        }
    }
}

/// Runs the service for the device whose objects the start data holds: the
/// object `ena` (its physical address is the first word of the record's own
/// arguments), the windows `bar` (BAR 0) and `ecam` (the page of the
/// function, whose revision byte picks the way registers are read).
pub fn run(s: rt::startup::Startup, object: Handle<Memory>) -> u64 {
    let args = ServiceArgs::read(s.args()).ok();
    let own = args.map_or(&[][..], |a| a.own);
    let pa = own
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes);
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(level) else {
        return NOT_REGISTERED;
    };
    let Ok(mut got) = rt::service::register(&s.parent, &channel) else {
        return NOT_REGISTERED;
    };
    let (Ok(bar), Ok(ecam)) = (got.take::<Memory>("bar"), got.take::<Memory>("ecam")) else {
        return NO_DEVICE;
    };
    let len = sys::memory_info(&object).map_or(0, |info| info.size);
    let rw = Access::ReadWrite;
    if pa == 0
        || sys::mem_map(&s.process, &object, 0, len, ENA_AT, rw).is_err()
        || sys::mem_map(&s.process, &bar, 0, 4 * PAGE, BAR_AT, rw).is_err()
        || sys::mem_map(&s.process, &ecam, 0, PAGE, ECAM_AT, rw).is_err()
    {
        return NOT_MAPPED;
    }
    // SAFETY: the page of the function is mapped at ECAM_AT, read and write,
    // as device memory; offset 8 is its revision and class word, offset 4 its
    // command word.
    let revision = unsafe {
        let command = rt::mmio::read32(ECAM_AT + COMMAND) & 0xFFFF;
        rt::mmio::write32(
            ECAM_AT + COMMAND,
            command | MEMORY | BUS_MASTER | INTX_DISABLE,
        );
        rt::mmio::read32(ECAM_AT + 8) as u8
    };
    let region = Region {
        va: ENA_AT,
        pa,
        len: len as usize,
    };
    // SAFETY: the object is mapped at ENA_AT for `len` bytes, uncached, and
    // this service alone uses it; the device addresses it at `pa`, as init's
    // reply to the creation of the object says.
    let opened = unsafe {
        Ena::open(
            Hw {
                bar: Bar::new(BAR_AT, 4 * PAGE as usize),
            },
            region,
            revision,
        )
    };
    let Ok(ena) = opened else {
        rt::println!("ena: the object does not fit the driver");
        return NO_DEVICE;
    };
    rt::println!("ena: pci revision {revision:#x}, object {pa:#x}+{len:#x}");
    let Ok(view) = sys::handle_label(&channel, abi::Rights::RECEIVE, TIMER_LABEL, level) else {
        return NOT_REGISTERED;
    };
    let Ok(timer) = sys::timer_create(&view, level) else {
        return NOT_REGISTERED;
    };
    let mut service = EnaService {
        ena,
        timer,
        deadline: 0,
        #[cfg(feature = "ena-break-aenq")]
        broken: false,
    };
    service.arm();
    let heartbeat = Heartbeat {
        to: &s.parent,
        period_ns: args.map_or(0, |a| a.period_ns),
        priority: level,
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(heartbeat),
    };
    let _ = rt::service::run::<EnaService, 2, 1>(&channel, &mut service, config);
    NO_DEVICE
}
