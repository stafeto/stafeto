// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The role `s`: each kind of step of the terminal service at its longest,
//! against the quiet driver (stub.rs), for the measure under -icount
//! (xtask tty):
//!
//! - WAITERS reads wait; INTR, which the service reports; a chunk of input
//!   of CHUNK bytes whose echo is longest (control characters, echoed as
//!   ^X, then KILL, which erases them byte by byte), then a line that tells
//!   every read;
//! - writes of MAX_WRITE newlines (each two bytes out) while the driver
//!   holds its output, until one waits; the driver's notification of room
//!   then wakes it, and one more waits and is cancelled;
//! - SET_ATTR, GET_ATTR, CLONE, ABANDON, the timer of VTIME;
//! - at the end the driver took every byte of echo and output: none was
//!   lost on the way through WRITE_SOME and ROOM.

use crate::stub::{FEED, HOLD, TAKEN};
use crate::{Probe, Step, read_request, status_of, write_request};
use abi::MESSAGE_MAX;
use proto_tty::{
    CONSOLE, Cancel, FLUSH, ICANON, MAX_READ, MAX_WRITE, Method, NOW, Termios, VMIN, VTIME, WAITERS,
};
use proto_wire::{Header, Reader, Status, Writer};
use rt::Handle;
use rt::handle::Channel;

/// The bytes of input of a step of the service (services/tty CHUNK).
const CHUNK: usize = 64;

/// A request of the stub's own: `method` and `body`.
fn stub_call(stub: &Handle<Channel>, method: u16, body: &[u8]) -> Result<u64, Status> {
    let mut w = Writer::new();
    Header::new(method, proto_uart::VERSION).write(&mut w)?;
    w.bytes(body)?;
    let mut buffer = [0; MESSAGE_MAX];
    let reply = Probe::call_on(stub, w.as_bytes(), None, &mut buffer)?;
    status_of(reply)?;
    let mut r = Reader::new(&reply[4..]);
    Ok(if r.left() == 8 { r.u64()? } else { 0 })
}

fn fail(_: Status) -> &'static str {
    "a request"
}

pub fn run(probe: &Probe, parent: &Handle<Channel>) -> Result<(), &'static str> {
    let stub = rt::service::connect(parent, "uart").map_err(|_| "no session with the driver")?;
    let opened = probe.get_attr().map_err(fail)?;
    // WAITERS reads wait, each armed.
    let mut keys = [0u64; WAITERS];
    let mut out = [0u8; MAX_READ];
    for key in &mut keys {
        let mut w = Writer::new();
        read_request(None, MAX_READ as u32, &mut w).map_err(fail)?;
        match probe
            .step_on(&probe.tty, w.as_bytes(), None, &mut out)
            .map_err(fail)?
        {
            Step::Wait(k) => *key = k,
            _ => return Err("a read with no input did not wait"),
        }
    }
    for &key in &keys {
        let mut w = Writer::new();
        read_request(Some(key), MAX_READ as u32, &mut w).map_err(fail)?;
        let handle = probe.labelled(key).map_err(fail)?;
        if probe.step_on(&probe.tty, w.as_bytes(), Some(handle), &mut out) != Ok(Step::Armed) {
            return Err("a take with no input did not arm");
        }
    }
    // INTR, which the service reports (job control sends it from T3 on)
    // and which drops nothing here; then the longest echo of a chunk, and
    // a line.
    stub_call(&stub, FEED, b"\x03").map_err(fail)?;
    let mut chunk = [0x01u8; CHUNK];
    chunk[CHUNK - 1] = 0x15;
    stub_call(&stub, FEED, &chunk).map_err(fail)?;
    let mut line = [b'a'; CHUNK];
    line[CHUNK - 1] = b'\r';
    stub_call(&stub, FEED, &line).map_err(fail)?;
    let echo = 2 + 2 * (CHUNK - 1) + 6 * (CHUNK - 1) + (CHUNK - 1) + 2;
    // Every read heard; one takes the line, the others wait on, and go.
    let mut lines = 0;
    for &key in &keys {
        probe.bit(key).map_err(fail)?;
        let mut w = Writer::new();
        read_request(Some(key), MAX_READ as u32, &mut w).map_err(fail)?;
        match probe
            .step_on(&probe.tty, w.as_bytes(), None, &mut out)
            .map_err(fail)?
        {
            Step::Ready(n) if n == CHUNK && out[CHUNK - 1] == b'\n' => lines += 1,
            Step::Armed => {
                let mut w = Writer::new();
                Cancel {
                    key,
                    terminal: CONSOLE,
                }
                .write(Method::ReadCancel, &mut w)
                .map_err(fail)?;
                if probe.step_on(&probe.tty, w.as_bytes(), None, &mut out) != Ok(Step::Cancelled) {
                    return Err("a cancel");
                }
            }
            _ => return Err("a take after the line"),
        }
    }
    if lines != 1 {
        return Err("the line went to no read, or to two");
    }
    rt::println!("tty-probe: {WAITERS} reads heard a line of {CHUNK} bytes");
    // Writes of newlines while the driver holds its output, until one
    // waits; room wakes it.
    stub_call(&stub, HOLD, &1u32.to_le_bytes()).map_err(fail)?;
    let newlines = [b'\n'; MAX_WRITE];
    let mut written = 0;
    let mut waiting = None;
    for _ in 0..8 {
        let mut w = Writer::new();
        write_request(None, &newlines, &mut w).map_err(fail)?;
        let mut count = [0; 4];
        match probe
            .step_on(&probe.tty, w.as_bytes(), None, &mut count)
            .map_err(fail)?
        {
            Step::Ready(4) => written += u32::from_le_bytes(count) as u64,
            Step::Wait(key) => {
                waiting = Some(key);
                break;
            }
            _ => return Err("a write"),
        }
    }
    let key = waiting.ok_or("no write waited for the driver")?;
    let mut w = Writer::new();
    write_request(Some(key), &newlines, &mut w).map_err(fail)?;
    let handle = probe.labelled(key).map_err(fail)?;
    if probe.step_on(&probe.tty, w.as_bytes(), Some(handle), &mut out) != Ok(Step::Armed) {
        return Err("a take of a write that waits did not arm");
    }
    stub_call(&stub, HOLD, &0u32.to_le_bytes()).map_err(fail)?;
    probe.bit(key).map_err(fail)?;
    let mut count = [0; 4];
    match probe
        .step_on(&probe.tty, w.as_bytes(), None, &mut count)
        .map_err(fail)?
    {
        Step::Ready(4) => written += u32::from_le_bytes(count) as u64,
        _ => return Err("the write that waited"),
    }
    // One more waits and is cancelled, with no effect.
    stub_call(&stub, HOLD, &1u32.to_le_bytes()).map_err(fail)?;
    let mut cancelled = false;
    for _ in 0..8 {
        let mut w = Writer::new();
        write_request(None, &newlines, &mut w).map_err(fail)?;
        let mut count = [0; 4];
        match probe
            .step_on(&probe.tty, w.as_bytes(), None, &mut count)
            .map_err(fail)?
        {
            Step::Ready(4) => written += u32::from_le_bytes(count) as u64,
            Step::Wait(key) => {
                let mut w = Writer::new();
                Cancel {
                    key,
                    terminal: CONSOLE,
                }
                .write(Method::WriteCancel, &mut w)
                .map_err(fail)?;
                if probe.step_on(&probe.tty, w.as_bytes(), None, &mut out) != Ok(Step::Cancelled) {
                    return Err("a cancel of a write");
                }
                cancelled = true;
                break;
            }
            _ => return Err("a write"),
        }
    }
    if !cancelled {
        return Err("no write waited to be cancelled");
    }
    stub_call(&stub, HOLD, &0u32.to_le_bytes()).map_err(fail)?;
    rt::println!("tty-probe: {written} newlines written past the driver's room");
    // The settings, a clone and its abandoned read, the timer of VTIME.
    probe.set_attr(opened, FLUSH).map_err(fail)?;
    let clone =
        rt::service::clone_session(&probe.tty, &Method::Clone.header().bytes()).map_err(fail)?;
    let mut w = Writer::new();
    read_request(None, 1, &mut w).map_err(fail)?;
    if !matches!(
        probe.step_on(&clone, w.as_bytes(), None, &mut out),
        Ok(Step::Wait(_))
    ) {
        return Err("a read of the clone did not wait");
    }
    let mut buffer = [0; MESSAGE_MAX];
    status_of(
        Probe::call_on(&clone, &Method::Abandon.header().bytes(), None, &mut buffer)
            .map_err(fail)?,
    )
    .map_err(fail)?;
    drop(clone);
    let mut timed: Termios = opened;
    timed.lflag &= !ICANON;
    timed.cc[VMIN] = 0;
    timed.cc[VTIME] = 1;
    probe.set_attr(timed, NOW).map_err(fail)?;
    let mut w = Writer::new();
    read_request(None, 16, &mut w).map_err(fail)?;
    let Ok(Step::Wait(key)) = probe.step_on(&probe.tty, w.as_bytes(), None, &mut out) else {
        return Err("a read of VTIME did not wait");
    };
    let mut w = Writer::new();
    read_request(Some(key), 16, &mut w).map_err(fail)?;
    let handle = probe.labelled(key).map_err(fail)?;
    if probe.step_on(&probe.tty, w.as_bytes(), Some(handle), &mut out) != Ok(Step::Armed) {
        return Err("a take of VTIME did not arm");
    }
    probe.bit(key).map_err(fail)?;
    if probe.step_on(&probe.tty, w.as_bytes(), None, &mut out) != Ok(Step::Ready(0)) {
        return Err("VTIME ran out with no 0");
    }
    probe.set_attr(opened, NOW).map_err(fail)?;
    // The driver took every byte: the echo and each newline as CR NL.
    let taken = stub_call(&stub, TAKEN, &[]).map_err(fail)?;
    let want = echo as u64 + 2 * written;
    rt::println!("tty-probe: the driver took {taken} bytes of {want}");
    if taken != want {
        return Err("bytes were lost on the way to the driver");
    }
    Ok(())
}
