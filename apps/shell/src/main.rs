// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The shell (spec 13.6): a client of init's table at 30, with no
//! heartbeat, that reaches the console through the UART driver
//! (proto_uart). It connects to `uart`, says so, and then, a line at a
//! time, shows its prompt, reads input with READ, echoes each byte with
//! WRITE (shell::line), and runs the command the line names
//! (shell::command). A command's output goes in one WRITE. The program
//! ends with a code of its own when a call to the driver fails; init
//! starts it again.

#![no_std]
#![no_main]

use abi::MESSAGE_MAX;
use core::fmt::Write;
use proto_uart::{ReadReply, ReadRequest, WriteReply, WriteRequest};
use proto_wire::{Reader, Status, Writer};
use rt::handle::{Channel, Resource};
use rt::{Handle, println, sys, time};
use shell::command::{self, Command, HELP};
use shell::line::{ERASE, Line, Step};
use shell::text::Text;

rt::entry!(main);

/// The prompt, with no newline after it.
const PROMPT: &[u8] = b"stafeto> ";
/// The line the shell says once it connected.
const CONNECTED: &[u8] = b"shell: connected to uart; type help for the commands\n";
/// The bytes one READ asks for at most.
const READ_BYTES: u32 = 64;
/// The codes of its end: no start data; no session with the driver; a
/// call to the driver failed.
const NO_START_DATA: u64 = 1;
const NO_UART: u64 = 2;
const UART_FAILED: u64 = 3;

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let uart = match rt::service::connect(&s.parent, "uart") {
        Ok(uart) => uart,
        Err(status) => {
            println!("shell: no session with uart: {status:?}");
            return NO_UART;
        }
    };
    let mut shell = Shell {
        uart,
        line: Line::new(),
        input: [0; READ_BYTES as usize],
        at: 0,
        len: 0,
    };
    match shell.serve() {
        Ok(never) => match never {},
        Err(_) => UART_FAILED,
    }
}

/// The shell: its session with the driver, the line it edits and the
/// input it read and did not take yet.
struct Shell {
    uart: Handle<Channel>,
    line: Line,
    input: [u8; READ_BYTES as usize],
    at: usize,
    len: usize,
}

impl Shell {
    /// Says that it connected, then shows the prompt, reads a line and
    /// runs it, for as long as the driver answers.
    fn serve(&mut self) -> Result<core::convert::Infallible, Status> {
        self.write(CONNECTED)?;
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
        let mut out: Text = Text::new();
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
                let ms = time::ticks_to_ns(time::now()) / 1_000_000;
                // The line fits.
                let _ = writeln!(out, "up {}.{:03} s", ms / 1000, ms % 1000);
            }
            Command::Ps | Command::Mem | Command::Bench | Command::CrashUart => {
                for piece in command::unknown(self.line.text()) {
                    out.put(piece);
                }
            }
            Command::Unknown(line) => {
                for piece in command::unknown(line) {
                    out.put(piece);
                }
            }
        }
        self.write(out.as_bytes())
    }

    /// READ of up to READ_BYTES: the reply waits for input, and its bytes
    /// become the input to take.
    fn fill(&mut self) -> Result<(), Status> {
        let mut w = Writer::new();
        ReadRequest { max: READ_BYTES }.write(&mut w)?;
        let mut buffer = [0; MESSAGE_MAX];
        let reply = self.call(w.as_bytes(), &mut buffer)?;
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
        let reply = self.call(w.as_bytes(), &mut buffer)?;
        WriteReply::read(reply).map(drop)
    }

    /// Sends `request` to the driver: the reply in `buffer` when its status
    /// is 0; the error of send, or the status of the reply, otherwise.
    fn call<'b>(
        &self,
        request: &[u8],
        buffer: &'b mut [u8; MESSAGE_MAX],
    ) -> Result<&'b [u8], Status> {
        let reply = sys::send(&self.uart, request).map_err(Status::Kernel)?;
        let bytes = reply.bytes(buffer);
        match Status::from_code(Reader::new(bytes).u32()?) {
            Status::Ok => Ok(bytes),
            status => Err(status),
        }
    }
}
