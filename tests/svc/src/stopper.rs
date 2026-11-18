// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The roles of the probe of init's stop of the system (main.rs, the table
//! `table-shutdown` of services/init): `quiet` is a service that takes
//! init's stop notice and does nothing, so that init kills it at its
//! deadline, and `power` stands for the service of the power button: it
//! opens sessions with the services of the image, waits a little and sends init
//! SHUTDOWN (kind off), then serves its channel as a service that stops
//! with the default handler of rt::service.

use crate::{FAILED, VERSION, method, serve};
use proto_init::{Method, SHUTDOWN_OFF, ShutdownAsk};
use proto_wire::{Header, Reader, Status, Writer};
use rt::handle::Resource;
use rt::service::{Answer, Request, Service, Session};
use rt::startup::Startup;
use rt::wait::Waiter;
use rt::{sys, time};

/// The services `power` opens a session with before it asks: each answers
/// once it registered.
const NEIGHBOURS: [&str; 3] = ["echo", "quiet", "blk"];
/// How long `power` waits after the last session.
const SETTLE_NS: u64 = 300_000_000;

/// A service of one method that answers with status 0; with `ignore` it
/// takes init's stop notice and keeps running.
struct Quiet {
    ignore: bool,
}

impl Service<1> for Quiet {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = &[method::ECHO];
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 1>, _: &mut Request<'_>) -> Answer {
        Answer::Status(Status::Ok)
    }

    fn stop(&mut self) {
        if !self.ignore {
            sys::process_exit(0)
        }
    }
}

/// The role `quiet`: it registers and serves, and ignores the stop notice.
pub fn quiet(s: Startup) -> u64 {
    let Ok(channel) = sys::channel_create(crate::base(&s)) else {
        return FAILED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return FAILED;
    }
    serve(&s, &channel, &mut Quiet { ignore: true })
}

/// The role `power`.
pub fn power(mut s: Startup) -> u64 {
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let Ok(channel) = sys::channel_create(crate::base(&s)) else {
        return FAILED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return FAILED;
    }
    let (Ok(_echo), Ok(_quiet), Ok(_blk)) = (
        rt::service::connect(&s.parent, NEIGHBOURS[0]),
        rt::service::connect(&s.parent, NEIGHBOURS[1]),
        rt::service::connect(&s.parent, NEIGHBOURS[2]),
    ) else {
        return FAILED;
    };
    let Ok(waiter) = Waiter::new(&channel, 0, crate::base(&s)) else {
        return FAILED;
    };
    let _ = waiter.receive_until(&channel, time::ticks_to_ns(time::now()) + SETTLE_NS);
    ask(&s, &channel)
}

/// Asks init to stop the system and serves the channel until the stop notice.
fn ask(s: &Startup, channel: &rt::Handle<rt::handle::Channel>) -> u64 {
    let mut w = Writer::new();
    let ask = ShutdownAsk {
        kind: SHUTDOWN_OFF,
        flags: 0,
    };
    let written = Header::new(Method::Shutdown.number(), proto_init::VERSION)
        .write(&mut w)
        .and_then(|()| ask.write(&mut w));
    if written.is_err() {
        return FAILED;
    }
    let asked = sys::send(&s.parent, w.as_bytes()).map(|reply| {
        let mut buffer = [0; abi::MESSAGE_MAX];
        Reader::new(reply.bytes(&mut buffer)).u32()
    });
    if asked != Ok(Ok(Status::Ok.code())) {
        rt::println!("power: SHUTDOWN refused");
        return FAILED;
    }
    rt::println!("power: button");
    serve(s, channel, &mut Quiet { ignore: false })
}

/// How long `power_data` waits before it writes: the POSIX programs of the table say they are
/// ready by then.
const NEIGHBOURS_NS: u64 = 2_500_000_000;
/// The size of the file `/stop/f` and the salt of its bytes.
const FILE_BYTES: usize = 20_000;
const SALT: u32 = 7;
/// The bytes of the file written in one request.
const CHUNK: usize = 900;

/// The bytes of `/stop/f` from the offset.
fn fill(out: &mut [u8], offset: usize) {
    for (i, b) in out.iter_mut().enumerate() {
        let k = offset + i;
        *b = (k as u32)
            .wrapping_mul(31)
            .wrapping_add(SALT)
            .wrapping_add((k >> 8) as u32) as u8;
    }
}

/// A call to the data file service: the bytes of the reply after its status, and their number.
fn call(
    session: &rt::Handle<rt::handle::Channel>,
    build: impl FnOnce(&mut Writer) -> Result<(), Status>,
) -> Result<([u8; abi::MESSAGE_MAX], usize), Status> {
    let mut w = Writer::new();
    build(&mut w)?;
    let reply = sys::send(session, w.as_bytes())?;
    let mut bytes = [0; abi::MESSAGE_MAX];
    let len = reply.bytes(&mut bytes).len();
    proto_data::reply(&bytes[..len])?;
    Ok((bytes, len))
}

fn word(reply: &[u8; abi::MESSAGE_MAX], at: usize) -> u32 {
    u32::from_le_bytes(reply[4 + at..8 + at].try_into().unwrap_or([0; 4]))
}

/// The first boot: makes `/stop/f` and writes all of it, with no sync and no close, and keeps the
/// handle. The second: reads it back and says whether it is whole.
fn file(session: &rt::Handle<rt::handle::Channel>) -> Result<(), &'static str> {
    use proto_data as d;
    match call(session, |w| d::path_call(d::Method::Mkdir, b"/stop", w)) {
        Ok(_) | Err(Status::Unknown(d::EXISTS)) => {}
        Err(_) => return Err("mkdir"),
    }
    match call(session, |w| d::open(b"/stop/f", d::READ, w)) {
        Ok((reply, _)) => return verify(session, word(&reply, 0)),
        Err(Status::Unknown(d::NO_ENTRY)) => {}
        Err(_) => return Err("open for reading"),
    }
    let (reply, _) = call(session, |w| {
        d::open(b"/stop/f", d::WRITE | d::CREATE | d::TRUNCATE, w)
    })
    .map_err(|_| "open for writing")?;
    let handle = word(&reply, 0);
    let mut at = 0;
    let mut chunk = [0u8; CHUNK];
    while at < FILE_BYTES {
        let n = (FILE_BYTES - at).min(CHUNK);
        fill(&mut chunk[..n], at);
        let (reply, _) =
            call(session, |w| d::write(handle, &chunk[..n], w)).map_err(|_| "write")?;
        if word(&reply, 0) as usize != n {
            return Err("short write");
        }
        at += n;
    }
    rt::println!("power: wrote /stop/f, {FILE_BYTES} bytes, no sync and no close");
    Ok(())
}

fn verify(session: &rt::Handle<rt::handle::Channel>, handle: u32) -> Result<(), &'static str> {
    use proto_data as d;
    let mut at = 0;
    let mut expected = [0u8; d::MAX_READ];
    loop {
        let (reply, _) =
            call(session, |w| d::read(handle, d::MAX_READ as u32, w)).map_err(|_| "read")?;
        let n = word(&reply, 0) as usize;
        if n == 0 {
            break;
        }
        if at + n > FILE_BYTES {
            rt::println!("power: /stop/f is longer than it was written");
            return Err("too long");
        }
        fill(&mut expected[..n], at);
        if reply[8..8 + n] != expected[..n] {
            rt::println!("power: /stop/f differs at byte {at}");
            return Err("differs");
        }
        at += n;
    }
    if at != FILE_BYTES {
        rt::println!("power: /stop/f is {at} bytes of {FILE_BYTES}");
        return Err("short");
    }
    rt::println!("power: /stop/f whole, {at} bytes");
    Ok(())
}

/// The role `power-data`: `power` of the probe of the stop handlers. It waits for the POSIX programs
/// of the table, then writes `/stop/f` through its session with `datafs` (or, when the file is
/// there from an earlier boot, reads it back), and asks init to stop the system at once.
pub fn power_data(mut s: Startup) -> u64 {
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let Ok(channel) = sys::channel_create(crate::base(&s)) else {
        return FAILED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return FAILED;
    }
    let Ok(session) = rt::service::connect(&s.parent, "datafs") else {
        rt::println!("power: no session with datafs");
        return FAILED;
    };
    let Ok(waiter) = Waiter::new(&channel, 0, crate::base(&s)) else {
        return FAILED;
    };
    let _ = waiter.receive_until(&channel, time::ticks_to_ns(time::now()) + NEIGHBOURS_NS);
    if let Err(why) = file(&session) {
        rt::println!("power: file failed: {why}");
        return FAILED;
    }
    ask(&s, &channel)
}
