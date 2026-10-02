// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The test services of init's test table (spec 15.2): one program, the
//! file `svc` of the image of that table, whose role the first byte of the
//! own arguments of its record names (proto_init::ServiceArgs, and the
//! table `table-test` of services/init): `e` a service that answers ECHO,
//! LABEL, ARGS, GATE and OPEN (echo.rs), `d` a service with a window and
//! a binding (device.rs), `x` a service that faults right after its start
//! (`crash`), `s` a service that hangs on HANG (silent.rs), `k` a service
//! that keeps init's STATS from a kill (sink.rs), `l` a service of long
//! operations under the console's protocol (long.rs, rtbench 2), `m` a
//! service that never registers (`mute`), `c` the client that runs the
//! tests of init as a service manager (checker.rs). A service registers
//! its channel with init (rt::service::register) and serves it with its
//! heartbeat (rt::service::run). The program ends with the code of its
//! role, or FAILED when its start data did not come.

#![no_std]
#![no_main]

mod checker;
mod device;
mod echo;
mod long;
mod silent;
mod sink;

use abi::{Error, MESSAGE_MAX};
use proto_init::{Method, SERVICE_ARGS_FIXED, ServiceArgs};
use proto_wire::{Reader, Status};
use rt::handle::Channel;
use rt::service::{self, Config, Heartbeat, Service};
use rt::startup::Startup;
use rt::wait::Waiter;
use rt::{Handle, sys, time};

rt::entry!(main);

/// The roles, by the first byte of the own arguments.
const ECHO: u8 = b'e';
const DEVICE: u8 = b'd';
const CRASH: u8 = b'x';
const SILENT: u8 = b's';
const SINK: u8 = b'k';
const LONG: u8 = b'l';
const MUTE: u8 = b'm';
const CHECKER: u8 = b'c';

/// The code of a role that could not do its part.
const FAILED: u64 = 1;
/// The code of `mute` when init took a HEARTBEAT before its REGISTER.
const BEAT_TAKEN: u64 = 2;

/// The version of the protocol of the test services.
const VERSION: u16 = 1;

/// The methods of the test services. ECHO: the bytes of the request after
/// its header come back after the status. LABEL: the status, 4 zero bytes
/// and the label of the caller's session. ARGS: the status, 4 zero bytes
/// and the start arguments of the service. REPORT, of `device`: what its
/// REGISTER brought (device::Report). GATE, of an echo: the status once
/// OPEN came to that echo; OPEN: the status. HELLO, of `sink`: marks the
/// session; SEEN, of `sink`: the STATS it kept. HANG, of `silent`: raises
/// the service to its ceiling and spins, and never replies.
mod method {
    pub const ECHO: u16 = 1;
    pub const LABEL: u16 = 2;
    pub const ARGS: u16 = 3;
    pub const REPORT: u16 = 4;
    pub const GATE: u16 = 5;
    pub const OPEN: u16 = 6;
    pub const HELLO: u16 = 7;
    pub const SEEN: u16 = 8;
    pub const HANG: u16 = 9;
}

/// The sessions of a test service.
const SESSIONS: usize = 8;

fn main(_: u64) -> u64 {
    let Ok(s) = rt::startup() else {
        return FAILED;
    };
    match s.args().get(SERVICE_ARGS_FIXED) {
        Some(&ECHO) => echo::run(s),
        Some(&DEVICE) => device::run(s),
        Some(&CRASH) => crash(),
        Some(&SILENT) => silent::run(s),
        Some(&SINK) => sink::run(s),
        Some(&LONG) => long::run(s),
        Some(&MUTE) => mute(&s),
        Some(&CHECKER) => checker::run(s),
        _ => FAILED,
    }
}

/// The role `mute`: a service that never registers and never ends, so
/// init's watchdog from its start restarts it until it is broken (spec
/// 13.4). It sends HEARTBEAT every period of its arguments, which init
/// refuses with BAD_STATE before REGISTER; any other status ends it with
/// BEAT_TAKEN.
fn mute(s: &Startup) -> u64 {
    let period_ns = ServiceArgs::read(s.args()).map_or(0, |a| a.period_ns);
    let Ok(channel) = sys::channel_create(base(s)) else {
        return FAILED;
    };
    let Ok(waiter) = Waiter::new(&channel, 0, base(s)) else {
        return FAILED;
    };
    let beat = Method::Heartbeat.header().bytes();
    let refused = Status::Kernel(Error::BadState).code();
    let mut at = time::ticks_to_ns(time::now());
    loop {
        let got = sys::send(&s.parent, &beat).map(|reply| {
            let mut buffer = [0; MESSAGE_MAX];
            Reader::new(reply.bytes(&mut buffer)).u32()
        });
        if got != Ok(Ok(refused)) {
            return BEAT_TAKEN;
        }
        at += period_ns;
        let _ = waiter.receive_until(&channel, at);
    }
}

/// The role `crash`: a load from page 0, which nothing maps, ends the
/// program with a fault before it registers (spec 7.9).
fn crash() -> u64 {
    // SAFETY: the load is the fault the role exists for.
    unsafe {
        core::arch::asm!(
            "ldr {t}, [{a}]",
            t = out(reg) _,
            a = in(reg) 0_usize,
            options(nostack, readonly),
        )
    };
    FAILED
}

/// The base priority of the program's first thread.
fn base(s: &Startup) -> u8 {
    sys::thread_info(&s.thread).map_or(1, |info| info.base)
}

/// Serves `channel` with `service` in this thread, with the heartbeat to
/// init at the period of the service's arguments (spec 13.4); returns
/// only when the loop failed, with FAILED.
fn serve<S: Service<1>>(s: &Startup, channel: &Handle<Channel>, service: &mut S) -> u64 {
    let period_ns = ServiceArgs::read(s.args()).map_or(0, |a| a.period_ns);
    let heartbeat = Heartbeat {
        to: &s.parent,
        period_ns,
        priority: base(s),
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(heartbeat),
    };
    let _ = service::run::<S, SESSIONS, 1>(channel, service, config);
    FAILED
}
