// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The service of the power button: it maps the page of the PL061 GPIO block (window `regs`),
//! makes pin 3 an input that detects the rising edge, enables that pin's interrupt alone (GPIOIE is written whole) and waits for the binding
//! `irq`. On the interrupt it clears the edge (GPIOIC), prints `power: button` and asks init to
//! stop the system with SHUTDOWN, kind off, once. The guest cannot tell a request to reboot from
//! a request to stop, so the answer to the button is always the power-off (`power` of
//! `proto_init`). The service is a native one of init's table: init answers SHUTDOWN only to the
//! record named `power`.

#![no_std]
#![no_main]

use abi::{Access, Source};
use power::{
    CLEAR_ALL, Config, ENABLE, GPIODIR, GPIOIBE, GPIOIC, GPIOIE, GPIOIEV, GPIOIS, GPIOMIS, MASK,
    PAGE, input, pressed, rising_edge,
};
use proto_init::{Method, SHUTDOWN_OFF, ServiceArgs, ShutdownAsk};
use proto_wire::{Header, Reader, Status, Writer};
use rt::handle::{Channel, Interrupt, Memory, Resource};
use rt::service::{Answer, Config as ServiceConfig, Heartbeat, Notice, Request, Service, Session};
use rt::{mmio, sys};

rt::entry!(main);

/// Where the service maps the block's page.
const REGS_AT: usize = 0x10_0000_0000;
/// The codes of a start that failed: no start data, REGISTER or the binding, the map.
const NO_START_DATA: u64 = 1;
const NOT_REGISTERED: u64 = 3;
const NOT_MAPPED: u64 = 4;
const STOPPED: u64 = 5;

fn reg_read(offset: usize) -> u32 {
    // SAFETY: the window maps the block's page at REGS_AT as device memory, read and write;
    // `offset` is one of the PL061's registers within it, 32-bit aligned.
    unsafe { mmio::read32(REGS_AT + offset) }
}

fn reg_write(offset: usize, value: u32) {
    // SAFETY: as for `reg_read`.
    unsafe { mmio::write32(REGS_AT + offset, value) }
}

/// The registers GPIODIR, GPIOIS, GPIOIEV and GPIOIE as the firmware left them.
struct Found {
    dir: u32,
    is: u32,
    iev: u32,
    ie: u32,
}

/// The block's interrupts masked, the button's pin an input that detects the rising edge, every
/// pending edge cleared, then the interrupt of the button's pin enabled alone: nothing else the
/// firmware left in GPIOIE stays enabled. The other pins keep their direction and detection.
fn set_up() -> Found {
    let found = Found {
        dir: reg_read(GPIODIR),
        is: reg_read(GPIOIS),
        iev: reg_read(GPIOIEV),
        ie: reg_read(GPIOIE),
    };
    reg_write(GPIOIE, 0);
    reg_write(GPIODIR, input(found.dir));
    let c = rising_edge(Config {
        is: found.is,
        ibe: reg_read(GPIOIBE),
        iev: found.iev,
    });
    reg_write(GPIOIS, c.is);
    reg_write(GPIOIBE, c.ibe);
    reg_write(GPIOIEV, c.iev);
    reg_write(GPIOIC, CLEAR_ALL);
    reg_write(GPIOIE, ENABLE);
    found
}

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let args = ServiceArgs::read(s.args()).ok();
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(1) else {
        return NOT_REGISTERED;
    };
    let Ok(mut got) = rt::service::register(&s.parent, &channel) else {
        return NOT_REGISTERED;
    };
    let (Ok(irq), Ok(regs)) = (got.take::<Interrupt>("irq"), got.take::<Memory>("regs")) else {
        return NOT_REGISTERED;
    };
    if sys::mem_map(
        &s.process,
        &regs,
        0,
        PAGE as u64,
        REGS_AT,
        Access::ReadWrite,
    )
    .is_err()
    {
        return NOT_MAPPED;
    }
    let found = set_up();
    // The line opens once the pin is set up.
    let _ = sys::irq_ack(&irq);
    rt::println!(
        "power: watching pin {} of the GPIO block (found dir {:#x} is {:#x} iev {:#x} ie {:#x})",
        power::PIN,
        found.dir,
        found.is,
        found.iev,
        found.ie
    );
    let mut button = Button {
        parent: &s.parent,
        irq,
        asked: false,
        _regs: regs,
    };
    let config = ServiceConfig {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &s.parent,
            period_ns: args.map_or(0, |a| a.period_ns),
            priority: level,
        }),
    };
    let _ = rt::service::run::<Button, 1, 0>(&channel, &mut button, config);
    STOPPED
}

/// The service: init's channel, the binding of the line and whether init was asked.
struct Button<'a> {
    parent: &'a rt::Handle<Channel>,
    irq: rt::Handle<Interrupt>,
    asked: bool,
    /// The window stays mapped for the service's life.
    _regs: rt::Handle<Memory>,
}

impl Button<'_> {
    /// SHUTDOWN with kind off to init; true when init took it.
    fn ask(&self) -> bool {
        let mut w = Writer::new();
        let ask = ShutdownAsk {
            kind: SHUTDOWN_OFF,
            flags: 0,
        };
        let written = Header::new(Method::Shutdown.number(), proto_init::VERSION)
            .write(&mut w)
            .and_then(|()| ask.write(&mut w));
        if written.is_err() {
            return false;
        }
        let reply = sys::send(self.parent, w.as_bytes()).map(|reply| {
            let mut buffer = [0; abi::MESSAGE_MAX];
            Reader::new(reply.bytes(&mut buffer)).u32()
        });
        reply == Ok(Ok(Status::Ok.code()))
    }

    /// An interrupt of the line (spec 9): the kernel masked it at delivery. The pin's status is
    /// cleared at the device first, then the line opens again [G26].
    fn interrupt(&mut self) {
        let button = pressed(reg_read(GPIOMIS));
        if button {
            reg_write(GPIOIC, MASK);
            // The store reaches the device before the line opens again.
            let _ = reg_read(GPIOMIS);
        }
        let _ = sys::irq_ack(&self.irq);
        if !button || self.asked {
            return;
        }
        rt::println!("power: button");
        if self.ask() {
            self.asked = true;
        } else {
            rt::println!("power: SHUTDOWN refused");
        }
    }
}

impl Service<0> for Button<'_> {
    const VERSION: u16 = 1;
    const METHODS: &'static [u16] = &[];
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 0>, _: &mut Request<'_>) -> Answer {
        Answer::Status(Status::UnknownMethod)
    }

    fn notification(&mut self, n: Notice) {
        if n.source == Source::Interrupt {
            self.interrupt();
        }
    }
}
