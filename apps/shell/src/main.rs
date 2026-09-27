// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The shell (spec 13.6): a client of init's table at 30, with no
//! heartbeat, that reaches the console through the UART driver
//! (proto_uart). It connects to `uart`, says so, and then, a line at a
//! time, shows its prompt, reads input with READ, echoes each byte with
//! WRITE (shell::line), and runs the command the line names
//! (shell::command). `ps`, `mem` and `bench` ask init (LIST, STATS, PING
//! of proto_init); their lines come from shell::format. `trace` reads
//! the kernel event ring without moving the console cursor. `crash uart`
//! sends CRASH to the driver. A command's output goes in whole lines, one
//! WRITE while it fits. PEER_CLOSED from the driver, to any call, means it
//! died: the shell connects again, which waits in init for the new
//! instance, and says so. Once init says the driver is broken, the shell
//! says that through debug_write, the port being the kernel's again, and
//! waits for good without spinning. The program ends with a code of its
//! own when a call to the driver fails otherwise; init starts it again.

#![no_std]
#![no_main]

use abi::{
    Error, LOG_BATCH, LOG_INTERRUPT_KIND, LOG_LEN_AT, LOG_RECORD, LOG_SWITCH_KIND,
    LOG_SYSCALL_KIND, LOG_TEXT_AT, MESSAGE_MAX,
};
use core::fmt::{self, Write};
use proto_init::{ListReply, ListRequest, Method, Stats};
use proto_uart::{ReadReply, ReadRequest, WriteReply, WriteRequest};
use proto_wire::{Reader, Status, Writer};
use rt::handle::{Channel, Resource};
use rt::{Handle, println, sys, time};
use shell::command::{self, Command, HELP};
use shell::format::{self, Records, Rounds};
use shell::line::{ERASE, Line, Step};
use shell::text::{Text, WRITE_MAX};

rt::entry!(main);

/// The prompt, with no newline after it.
const PROMPT: &[u8] = b"stafeto> ";
/// The line the shell says once it connected, and once it connected again
/// after the driver died.
const CONNECTED: &[u8] = b"shell: connected to uart; type help for the commands\n";
const RECONNECTED: &[u8] = b"shell: uart restarted; connected again\n";
/// The line of `crash uart` before its CRASH.
const CRASHING: &[u8] = b"shell: crashing uart\n";
/// The line through debug_write once init says the driver is broken.
const BROKEN: &str = "shell: uart is broken; no console left";
/// The bytes one READ asks for at most.
const READ_BYTES: u32 = 64;
/// The round trips of PING that `bench` times.
const BENCH_ROUNDS: u32 = 1000;
/// The codes of its end: no start data; no session with the driver; a
/// call to the driver failed; no channel to wait on once the driver is
/// broken.
const NO_START_DATA: u64 = 1;
const NO_UART: u64 = 2;
const UART_FAILED: u64 = 3;
const NO_WAIT: u64 = 4;

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let trace = s.take::<Resource>("trace").ok();
    let uart = match connect(&s.parent) {
        Ok(uart) => uart,
        Err(code) => return code,
    };
    let mut shell = Shell {
        parent: s.parent,
        trace,
        trace_next: 1,
        uart,
        line: Line::new(),
        input: [0; READ_BYTES as usize],
        at: 0,
        len: 0,
    };
    let mut greeting = CONNECTED;
    loop {
        match shell.serve(greeting) {
            Ok(never) => match never {},
            Err(Status::Kernel(Error::PeerClosed)) => {}
            Err(_) => return UART_FAILED,
        }
        // The driver died: output that did not reach it is not written
        // again, and the line being typed goes.
        shell.uart = match connect(&shell.parent) {
            Ok(uart) => uart,
            Err(code) => return code,
        };
        shell.line.clear();
        shell.at = 0;
        shell.len = 0;
        greeting = RECONNECTED;
    }
}

/// A session with the driver (spec 13.4, 13.6): CONNECT waits in init
/// until an instance registers. PEER_CLOSED means the driver is broken:
/// the shell says BROKEN through debug_write, which reaches the port since
/// the driver's window went with it (spec 3.2), and waits for good
/// (`wait_for_good`); another refusal gives NO_UART.
fn connect(parent: &Handle<Channel>) -> Result<Handle<Channel>, u64> {
    match rt::service::connect(parent, "uart") {
        Ok(uart) => Ok(uart),
        Err(Status::Kernel(Error::PeerClosed)) => {
            println!("{BROKEN}");
            Err(wait_for_good())
        }
        Err(status) => {
            println!("shell: no session with uart: {status:?}");
            Err(NO_UART)
        }
    }
}

/// Waits for good without spinning or a timer (spec 13.6): a receive on
/// a channel of its own, whose one handle the shell keeps and which
/// nothing notifies or sends to. Gives NO_WAIT when it has no such
/// channel, or when a receive fails, which it never repeats.
fn wait_for_good() -> u64 {
    let Ok(channel) = sys::channel_create(1) else {
        return NO_WAIT;
    };
    loop {
        // Nothing comes; the handle with RECEIVE stays, so no PEER_CLOSED.
        if sys::receive(&channel).is_err() {
            return NO_WAIT;
        }
    }
}

/// The shell: its connection to init, its session with the driver, the
/// line it edits and the input it read and did not take yet.
struct Shell {
    parent: Handle<Channel>,
    trace: Option<Handle<Resource>>,
    trace_next: u64,
    uart: Handle<Channel>,
    line: Line,
    input: [u8; READ_BYTES as usize],
    at: usize,
    len: usize,
}

impl Shell {
    /// Says `greeting`, that it connected, then shows the prompt, reads a
    /// line and runs it, for as long as the driver answers.
    fn serve(&mut self, greeting: &[u8]) -> Result<core::convert::Infallible, Status> {
        self.write(greeting)?;
        loop {
            self.write(PROMPT)?;
            self.read_line()?;
            self.run()?;
            self.line.clear();
        }
    }

    /// Takes bytes of input into the line until it ends, and echoes them
    /// (spec 13.6): what the bytes of one READ echo goes in one WRITE. The
    /// bytes after the end stay for the next line.
    fn read_line(&mut self) -> Result<(), Status> {
        loop {
            if self.at == self.len {
                self.fill()?;
            }
            let mut echo = Text::<{ ERASE.len() * READ_BYTES as usize }>::new();
            let mut ended = false;
            while self.at < self.len && !ended {
                let b = self.input[self.at];
                self.at += 1;
                match self.line.push(b) {
                    Step::Echo(b) => echo.put(&[b]),
                    Step::Erase => echo.put(ERASE),
                    Step::End => {
                        echo.put(b"\n");
                        ended = true;
                    }
                    Step::Nothing => {}
                }
            }
            if !echo.is_empty() {
                self.write(echo.as_bytes())?;
            }
            if ended {
                return Ok(());
            }
        }
    }

    /// Runs the command of the line and writes its output (spec 13.6).
    fn run(&mut self) -> Result<(), Status> {
        let mut out = Out::new();
        match command::parse(self.line.text()) {
            Command::Empty => return Ok(()),
            Command::Help => {
                for line in HELP {
                    out.put(line.as_bytes());
                    out.put(b"\n");
                }
            }
            Command::Echo(words) => {
                for (i, word) in words.iter().enumerate() {
                    if i > 0 {
                        out.put(b" ");
                    }
                    out.put(word);
                }
                out.put(b"\n");
            }
            Command::Uptime => {
                // The line fits.
                let _ = format::uptime(&mut out, time::now(), time::scale());
            }
            Command::Ps => {
                let written = self.records().map(|r| format::ps(&mut out, &r));
                facts(&mut out, "ps", written);
            }
            Command::Mem => {
                let asked = self.records().and_then(|r| Ok((r, self.stats()?)));
                let written = asked.map(|(r, s)| format::mem(&mut out, &r, &s));
                facts(&mut out, "mem", written);
            }
            Command::Bench => {
                let asked = self.bench().and_then(|r| Ok((r, self.stats()?)));
                let written = asked.map(|(r, s)| format::bench(&mut out, &r, &s, time::scale()));
                facts(&mut out, "bench", written);
            }
            Command::Trace => return self.trace(),
            Command::CrashUart => {
                self.write(CRASHING)?;
                let status = match self.crash() {
                    Err(Status::Kernel(Error::PeerClosed)) => {
                        return Err(Status::Kernel(Error::PeerClosed));
                    }
                    Err(status) => status,
                    Ok(()) => Status::Ok,
                };
                // The driver lives, built without `crash`. The line fits.
                let _ = writeln!(out, "shell: crash uart: {status:?}");
            }
            Command::Unknown(line) => {
                for piece in command::unknown(line) {
                    out.put(piece);
                }
            }
        }
        self.write_lines(out.as_bytes())
    }

    /// Streams one snapshot of the ring, preserving the console cursor.
    fn trace(&mut self) -> Result<(), Status> {
        let Some(resource) = self.trace.as_ref() else {
            return self.write(b"shell: trace resource unavailable\n");
        };
        let mut snapshot_end = None;
        loop {
            let mut records = [[0u8; LOG_RECORD]; LOG_BATCH];
            let (batch, next) = match sys::log_peek(resource, self.trace_next, &mut records) {
                Ok(result) => result,
                Err(error) => {
                    let mut out = Out::new();
                    let _ = writeln!(out, "shell: trace: {error:?}");
                    return self.write(out.as_bytes());
                }
            };
            let end = *snapshot_end.get_or_insert(next.saturating_add(batch.left));
            if batch.lost > 0 {
                let mut out = Out::new();
                let _ = writeln!(out, "trace: lost {} records", batch.lost);
                self.write(out.as_bytes())?;
            }
            self.trace_next = next;
            let first = next.saturating_sub(batch.count);
            let count = batch.count.min(end.saturating_sub(first)) as usize;
            for record in records.iter().take(count) {
                let kind = match record[abi::LOG_KIND_AT] {
                    LOG_SYSCALL_KIND => "syscall",
                    LOG_SWITCH_KIND => "switch",
                    LOG_INTERRUPT_KIND => "interrupt",
                    _ => continue,
                };
                let time = u64::from_le_bytes(record[..8].try_into().unwrap());
                let len = usize::from(record[LOG_LEN_AT]).min(abi::LOG_TEXT);
                let text =
                    core::str::from_utf8(&record[LOG_TEXT_AT..LOG_TEXT_AT + len]).unwrap_or("?");
                let mut out = Out::new();
                let _ = writeln!(out, "trace: {time} {kind} {text}");
                self.write(out.as_bytes())?;
            }
            if next >= end || batch.count == 0 {
                return Ok(());
            }
        }
    }

    /// WRITE of `bytes` in pieces of whole lines, WRITE_MAX bytes at most
    /// each; a line longer than that goes in pieces of WRITE_MAX (spec
    /// 13.6).
    fn write_lines(&self, mut bytes: &[u8]) -> Result<(), Status> {
        while !bytes.is_empty() {
            let cut = match bytes.get(..WRITE_MAX) {
                Some(head) => head
                    .iter()
                    .rposition(|&b| b == b'\n')
                    .map_or(WRITE_MAX, |i| i + 1),
                None => bytes.len(),
            };
            self.write(&bytes[..cut])?;
            bytes = &bytes[cut..];
        }
        Ok(())
    }

    /// The records of LIST, every page of it (format::list).
    fn records(&self) -> Result<Records, Status> {
        let mut records = Records::new();
        let page = |first| {
            let mut w = Writer::new();
            ListRequest { first }.write(&mut w)?;
            let mut buffer = [0; MESSAGE_MAX];
            ListReply::read(call(&self.parent, w.as_bytes(), &mut buffer)?)
        };
        format::list(page, &mut records)?;
        Ok(records)
    }

    /// STATS of init.
    fn stats(&self) -> Result<Stats, Status> {
        let mut buffer = [0; MESSAGE_MAX];
        let request = Method::Stats.header().bytes();
        Stats::read(call(&self.parent, &request, &mut buffer)?)
    }

    /// BENCH_ROUNDS round trips of PING to init, each timed on the
    /// counter.
    fn bench(&self) -> Result<Rounds, Status> {
        let mut rounds = Rounds::new();
        let request = Method::Ping.header().bytes();
        let mut buffer = [0; MESSAGE_MAX];
        for _ in 0..BENCH_ROUNDS {
            let start = time::now();
            call(&self.parent, &request, &mut buffer)?;
            rounds.add(time::now().wrapping_sub(start));
        }
        Ok(rounds)
    }

    /// CRASH: the driver faults while it holds the request, and the kernel
    /// answers PEER_CLOSED; a driver built without the feature `crash`
    /// answers UNKNOWN_METHOD (spec 13.5).
    fn crash(&self) -> Result<(), Status> {
        let request = proto_uart::Method::Crash.header().bytes();
        let mut buffer = [0; MESSAGE_MAX];
        call(&self.uart, &request, &mut buffer).map(drop)
    }

    /// READ of up to READ_BYTES: the reply waits for input, and its bytes
    /// become the input to take.
    fn fill(&mut self) -> Result<(), Status> {
        let mut w = Writer::new();
        ReadRequest { max: READ_BYTES }.write(&mut w)?;
        let mut buffer = [0; MESSAGE_MAX];
        let reply = call(&self.uart, w.as_bytes(), &mut buffer)?;
        let bytes = ReadReply::read(reply, READ_BYTES)?.bytes;
        self.input[..bytes.len()].copy_from_slice(bytes);
        self.at = 0;
        self.len = bytes.len();
        Ok(())
    }

    /// WRITE of `bytes`: the reply comes once all are in the driver's
    /// ring.
    fn write(&self, bytes: &[u8]) -> Result<(), Status> {
        let mut w = Writer::new();
        WriteRequest { bytes }.write(&mut w)?;
        let mut buffer = [0; MESSAGE_MAX];
        let reply = call(&self.uart, w.as_bytes(), &mut buffer)?;
        WriteReply::read(reply).map(drop)
    }
}

/// The output of a command: two WRITEs' worth, which go in whole lines
/// (Shell::write_lines).
type Out = Text<{ 2 * WRITE_MAX }>;

/// The room the line of a cut output needs at most.
const CUT_LINE: usize = 64;

/// The output of a command of facts; when init refused it, the line
/// `shell: <command>: <status>` instead; when it did not fit, its whole
/// lines that leave room, then the line `shell: <command>: output cut`.
fn facts(out: &mut Out, command: &str, written: Result<fmt::Result, Status>) {
    match written {
        Ok(Ok(())) => {}
        Ok(Err(fmt::Error)) => {
            let head = &out.as_bytes()[..out.as_bytes().len().saturating_sub(CUT_LINE)];
            let keep = head.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
            out.truncate(keep);
            // The line fits.
            let _ = writeln!(out, "shell: {command}: output cut");
        }
        Err(status) => {
            out.clear();
            // The line fits.
            let _ = writeln!(out, "shell: {command}: {status:?}");
        }
    }
}

/// Sends `request` through `channel`: the reply in `buffer` when its
/// status is 0; the error of send, or the status of the reply, otherwise.
fn call<'b>(
    channel: &Handle<Channel>,
    request: &[u8],
    buffer: &'b mut [u8; MESSAGE_MAX],
) -> Result<&'b [u8], Status> {
    let reply = sys::send(channel, request).map_err(Status::Kernel)?;
    let bytes = reply.bytes(buffer);
    match Status::from_code(Reader::new(bytes).u32()?) {
        Status::Ok => Ok(bytes),
        status => Err(status),
    }
}
