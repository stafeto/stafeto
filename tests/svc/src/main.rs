// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The test services of init's test table (spec 15.2): one program, the
//! file `svc` of the image of that table, whose role the first byte of the
//! own arguments of its record names (proto_init::ServiceArgs, and the
//! table `table-test` of services/init): `e` a service that answers ECHO,
//! LABEL, ARGS, GATE and OPEN (echo.rs), `d` a service with a window and
//! a binding (device.rs), `c` the client that runs the tests of init as a
//! service manager (checker.rs). A service registers its channel with init
//! (rt::service::register) and serves it with its heartbeat
//! (rt::service::run). The program ends with the code of its role, or
//! FAILED when its start data did not come.

#![no_std]
#![no_main]

mod checker;
mod device;
mod echo;

use proto_init::{SERVICE_ARGS_FIXED, ServiceArgs};
use rt::handle::Channel;
use rt::service::{self, Config, Heartbeat, Service};
use rt::startup::Startup;
use rt::{Handle, sys};

rt::entry!(main);

/// The roles, by the first byte of the own arguments.
const ECHO: u8 = b'e';
const DEVICE: u8 = b'd';
const CHECKER: u8 = b'c';

/// The code of a role that could not do its part.
const FAILED: u64 = 1;

/// The version of the protocol of the test services.
const VERSION: u16 = 1;

/// The methods of the test services. ECHO: the bytes of the request after
/// its header come back after the status. LABEL: the status, 4 zero bytes
/// and the label of the caller's session. ARGS: the status, 4 zero bytes
/// and the start arguments of the service. REPORT, of `device`: what its
/// REGISTER brought (device::Report). GATE, of an echo: the status once
/// OPEN came to that echo; OPEN: the status.
mod method {
    pub const ECHO: u16 = 1;
    pub const LABEL: u16 = 2;
    pub const ARGS: u16 = 3;
    pub const REPORT: u16 = 4;
    pub const GATE: u16 = 5;
    pub const OPEN: u16 = 6;
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
        Some(&CHECKER) => checker::run(s),
        _ => FAILED,
    }
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
