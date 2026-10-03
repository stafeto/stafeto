// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The guest probe of the terminal service (5f, xtask tty and tty-vz): a
//! client of `tty` that speaks proto_tty itself, in one of three roles its
//! record's own arguments name.
//!
//! With none, xtask types at the console and reads what it shows:
//!
//! 1. the settings a terminal opens with: canonical input with echo;
//! 2. a canonical read while "lost", INTR, then "ab", ERASE, "c" and Enter
//!    come: INTR drops "lost" and the read gives "ac\n";
//! 3. with ICANON off, VMIN 1 and VTIME 0, three reads each give the one
//!    byte xtask typed before it;
//! 4. LINES numbered lines in writes of MAX_WRITE bytes, which xtask finds
//!    whole and in their order.
//!
//! `S` is a quiet driver of the console (stub.rs) and `s` the client that
//! makes each kind of step of the service at its longest against it
//! (steps.rs), for the measure under -icount. Each role says on the
//! console where it stands; the probe ends with 0 once all went as they
//! should, with FAILED otherwise.

#![no_std]
#![no_main]

mod steps;
mod stub;

use abi::{MESSAGE_MAX, Rights, Source};
use proto_init::SERVICE_ARGS_FIXED;
use proto_tty::{
    CONSOLE, ECHO, ICANON, MAX_WRITE, NOW, Read, SetAttr, Termios, VMIN, VTIME, Write,
};
use proto_wire::{Status, Writer, long};
use rt::handle::Channel;
use rt::{Handle, sys};

rt::entry!(main);

const FAILED: u64 = 1;
/// The lines of the output of step 4.
const LINES: usize = 200;
/// The bytes of a line of step 4: its start, its number and TEXT.
const START: &[u8] = b"tty-probe line ";
const TEXT: &[u8] = b" abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\n";
const LINE: usize = START.len() + 3 + TEXT.len();

/// A session with the service and the probe's own channel, where the
/// service's bits of its long operations come.
pub struct Probe {
    pub tty: Handle<Channel>,
    own: Handle<Channel>,
    level: u8,
}

impl Probe {
    /// A request on `session` and its reply's bytes into `buffer`.
    pub fn call_on<'a>(
        session: &Handle<Channel>,
        request: &[u8],
        handle: Option<Handle<Channel>>,
        buffer: &'a mut [u8; MESSAGE_MAX],
    ) -> Result<&'a [u8], Status> {
        let reply = match handle {
            None => sys::send(session, request)?,
            Some(h) => sys::send_handles(session, request, [h.erase()])
                .map_err(|refused| Status::Kernel(refused.error))?,
        };
        Ok(reply.bytes(buffer))
    }

    pub fn call<'a>(
        &self,
        request: &[u8],
        handle: Option<Handle<Channel>>,
        buffer: &'a mut [u8; MESSAGE_MAX],
    ) -> Result<&'a [u8], Status> {
        Probe::call_on(&self.tty, request, handle, buffer)
    }

    /// A step of a long operation on `session`: the reply's kind, and its
    /// bytes into `out` for READY.
    pub fn step_on(
        &self,
        session: &Handle<Channel>,
        request: &[u8],
        handle: Option<Handle<Channel>>,
        out: &mut [u8],
    ) -> Result<Step, Status> {
        let mut buffer = [0; MESSAGE_MAX];
        Ok(
            match long::Reply::read(Probe::call_on(session, request, handle, &mut buffer)?)? {
                long::Reply::Ready(bytes) => Step::Ready(copy(bytes, out)),
                long::Reply::Wait(key) => Step::Wait(key),
                long::Reply::Armed => Step::Armed,
                long::Reply::Cancelled => Step::Cancelled,
            },
        )
    }

    /// A copy of the probe's channel labelled `key`, for the first take.
    pub fn labelled(&self, key: u64) -> Result<Handle<Channel>, Status> {
        Ok(sys::handle_label(
            &self.own,
            Rights::NOTIFY | Rights::TRANSFER,
            key,
            self.level,
        )?)
    }

    /// Waits for the service's bit of `key`.
    pub fn bit(&self, key: u64) -> Result<(), Status> {
        loop {
            if let sys::Received::Notification {
                source: Source::Session,
                label,
                bits,
                ..
            } = sys::receive(&self.own)?
                && label == key
                && bits & 1 != 0
            {
                return Ok(());
            }
        }
    }

    /// A long operation: `start`, then "take k" (`keyed`) once the
    /// service's bit came, until READY; its bytes into `out`, and whether
    /// it waited.
    fn long(
        &self,
        start: &[u8],
        keyed: impl Fn(u64, &mut Writer) -> Result<(), Status>,
        out: &mut [u8],
    ) -> Result<(usize, bool), Status> {
        let key = match self.step_on(&self.tty, start, None, out)? {
            Step::Ready(n) => return Ok((n, false)),
            Step::Wait(key) => key,
            _ => return Err(Status::BadSize),
        };
        let mut take = Writer::new();
        keyed(key, &mut take)?;
        let mut handle = Some(self.labelled(key)?);
        loop {
            match self.step_on(&self.tty, take.as_bytes(), handle.take(), out)? {
                Step::Ready(n) => return Ok((n, true)),
                Step::Armed => self.bit(key)?,
                _ => return Err(Status::BadSize),
            }
        }
    }

    /// A read of at most `count` bytes into `out`.
    fn read(&self, count: u32, out: &mut [u8]) -> Result<usize, Status> {
        let mut start = Writer::new();
        read_request(None, count, &mut start)?;
        let keyed = |key, w: &mut Writer| read_request(Some(key), count, w);
        self.long(start.as_bytes(), keyed, out).map(|(n, _)| n)
    }

    /// A write of `bytes`: the count taken, and whether it waited.
    fn write(&self, bytes: &[u8]) -> Result<(usize, bool), Status> {
        let mut start = Writer::new();
        write_request(None, bytes, &mut start)?;
        let keyed = |key, w: &mut Writer| write_request(Some(key), bytes, w);
        let mut count = [0; 4];
        let (n, waited) = self.long(start.as_bytes(), keyed, &mut count)?;
        if n != 4 {
            return Err(Status::BadSize);
        }
        Ok((u32::from_le_bytes(count) as usize, waited))
    }

    pub fn get_attr(&self) -> Result<Termios, Status> {
        let mut w = Writer::new();
        proto_tty::get_attr(CONSOLE, &mut w)?;
        let mut buffer = [0; MESSAGE_MAX];
        proto_tty::attr_reply(self.call(w.as_bytes(), None, &mut buffer)?)
    }

    pub fn set_attr(&self, termios: Termios, action: u32) -> Result<(), Status> {
        let mut w = Writer::new();
        SetAttr {
            terminal: CONSOLE,
            action,
            termios,
        }
        .write(&mut w)?;
        let mut buffer = [0; MESSAGE_MAX];
        status_of(self.call(w.as_bytes(), None, &mut buffer)?)
    }
}

/// What a step of a long operation gave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Ready(usize),
    Wait(u64),
    Armed,
    Cancelled,
}

/// The status of a reply that is its status alone.
pub fn status_of(reply: &[u8]) -> Result<(), Status> {
    let code = reply
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .map_or(u32::MAX, u32::from_le_bytes);
    match Status::from_code(code) {
        Status::Ok => Ok(()),
        status => Err(status),
    }
}

/// READ_START (no key) or READ_TAKE of `count` bytes of the console.
pub fn read_request(key: Option<u64>, count: u32, w: &mut Writer) -> Result<(), Status> {
    Read {
        key,
        terminal: CONSOLE,
        count,
    }
    .write(w)
}

/// WRITE_START (no key) or WRITE_TAKE of `bytes` to the console.
pub fn write_request(key: Option<u64>, bytes: &[u8], w: &mut Writer) -> Result<(), Status> {
    Write {
        key,
        terminal: CONSOLE,
        bytes,
    }
    .write(w)
}

fn copy(bytes: &[u8], out: &mut [u8]) -> usize {
    let n = bytes.len().min(out.len());
    out[..n].copy_from_slice(&bytes[..n]);
    n
}

/// The digits of `n` below 1000, three of them.
fn number(n: usize) -> [u8; 3] {
    [
        b'0' + (n / 100 % 10) as u8,
        b'0' + (n / 10 % 10) as u8,
        b'0' + (n % 10) as u8,
    ]
}

/// Byte `i` of the output of step 4.
fn byte_at(i: usize) -> u8 {
    let (n, at) = (i / LINE, i % LINE);
    if at < START.len() {
        START[at]
    } else if at < START.len() + 3 {
        number(n)[at - START.len()]
    } else {
        TEXT[at - START.len() - 3]
    }
}

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return FAILED;
    };
    if let Ok(console) = start.take::<rt::handle::Resource>("console") {
        rt::console::set(console);
    }
    let role = start.args().get(SERVICE_ARGS_FIXED).copied();
    if role == Some(b'S') {
        return stub::run(start);
    }
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let (Ok(tty), Ok(own)) = (
        rt::service::connect(&start.parent, "tty"),
        sys::channel_create(1),
    ) else {
        rt::println!("tty-probe: no session with the terminal service");
        return FAILED;
    };
    let probe = Probe { tty, own, level };
    let done = match role {
        Some(b's') => steps::run(&probe, &start.parent),
        _ => run(&probe),
    };
    match done {
        Ok(()) => {
            rt::println!("tty-probe: ok");
            0
        }
        Err(why) => {
            rt::println!("tty-probe: failed: {why}");
            FAILED
        }
    }
}

fn run(probe: &Probe) -> Result<(), &'static str> {
    // 1. The settings a terminal opens with.
    let opened = probe.get_attr().map_err(|_| "GET_ATTR")?;
    if opened != Termios::opened() || opened.lflag & (ICANON | ECHO) != ICANON | ECHO {
        return Err("the settings of a terminal that opens");
    }
    // 2. A canonical read: INTR drops "lost", ERASE takes the "b".
    rt::println!("tty-probe: canonical read waits");
    let mut line = [0; 64];
    let n = probe
        .read(64, &mut line)
        .map_err(|_| "the canonical read")?;
    if &line[..n] != b"ac\n" {
        return Err("the canonical read did not give \"ac\\n\"");
    }
    rt::println!("tty-probe: read ac and a newline");
    // 3. Raw reads, VMIN 1: each gives the byte typed before it.
    let mut raw = opened;
    raw.lflag &= !ICANON;
    raw.cc[VMIN] = 1;
    raw.cc[VTIME] = 0;
    probe.set_attr(raw, NOW).map_err(|_| "SET_ATTR")?;
    if probe.get_attr() != Ok(raw) {
        return Err("GET_ATTR after SET_ATTR");
    }
    for (i, &want) in b"xyz".iter().enumerate() {
        rt::println!("tty-probe: raw read {i} waits");
        let mut got = [0; 16];
        let n = probe.read(16, &mut got).map_err(|_| "a raw read")?;
        if got[..n] != [want] {
            return Err("a raw read did not give the one byte typed");
        }
        rt::println!("tty-probe: raw read {i} gave {}", want as char);
    }
    rt::println!("tty-probe: raw reads gave each byte");
    probe.set_attr(opened, NOW).map_err(|_| "SET_ATTR back")?;
    // 4. Output, on a line of its own after the echo of the raw reads.
    probe.write(b"\n").map_err(|_| "a write")?;
    let len = LINES * LINE;
    let (mut at, mut waited) = (0, 0);
    let mut chunk = [0; MAX_WRITE];
    while at < len {
        let end = (at + MAX_WRITE).min(len);
        for (i, b) in (at..end).zip(chunk.iter_mut()) {
            *b = byte_at(i);
        }
        let (n, w) = probe.write(&chunk[..end - at]).map_err(|_| "a write")?;
        if n == 0 || n > end - at {
            return Err("a write took no byte or too many");
        }
        at += n;
        waited += usize::from(w);
    }
    rt::println!("tty-probe: wrote {len} bytes, {waited} writes waited");
    Ok(())
}
