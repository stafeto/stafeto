// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The host's terminal for `cargo xtask ash-shell`: its keys go to the
//! machine through a pipe, and the size of its window goes there as a
//! report in the same bytes (services/tty/src/window.rs): at the
//! first prompt and with every SIGWINCH of the host.

use std::io::{Read, Write};
use std::process::{ChildStdin, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[repr(C)]
struct Winsize {
    rows: u16,
    columns: u16,
    xpixel: u16,
    ypixel: u16,
}

unsafe extern "C" {
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn isatty(fd: i32) -> i32;
    fn signal(signal: i32, handler: extern "C" fn(i32)) -> usize;
}

const TIOCGWINSZ: u64 = if cfg!(target_os = "macos") {
    0x4008_7468
} else {
    0x5413
};
const SIGWINCH: i32 = 28;

/// Set by the handler of SIGWINCH.
static CHANGED: AtomicBool = AtomicBool::new(false);

extern "C" fn window_changed(_: i32) {
    CHANGED.store(true, Ordering::SeqCst);
}

/// The rows and columns of the terminal on stdin, when it is one.
pub fn host_size() -> Option<(u16, u16)> {
    let mut size = Winsize {
        rows: 0,
        columns: 0,
        xpixel: 0,
        ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ writes a winsize at the address given.
    let done = unsafe { ioctl(0, TIOCGWINSZ, &mut size as *mut Winsize) };
    (done == 0 && size.rows > 0 && size.columns > 0).then_some((size.rows, size.columns))
}

/// The bytes of the report of a window of `rows` and `columns`.
pub fn report(rows: u16, columns: u16) -> Vec<u8> {
    format!("\x1dW{rows};{columns}\x1d").into_bytes()
}

/// The host's terminal in the mode the machine's keys need (no line
/// editing, echo, signals or translation of the carriage return), put back
/// when the guard goes. A stdin that is no terminal stays as it is.
pub struct RawTerminal {
    saved: Option<String>,
}

impl RawTerminal {
    pub fn enter() -> RawTerminal {
        // SAFETY: isatty only reads the descriptor's kind.
        if unsafe { isatty(0) } == 0 {
            return RawTerminal { saved: None };
        }
        let saved = Command::new("stty")
            .arg("-g")
            .stdin(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned());
        if saved.is_some() {
            let _ = Command::new("stty")
                .args([
                    "-icanon", "-echo", "-isig", "-ixon", "-ixoff", "-icrnl", "-inlcr", "-igncr",
                ])
                .status();
        }
        RawTerminal { saved }
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        if let Some(saved) = self.saved.take() {
            let _ = Command::new("stty").arg(saved).status();
        }
    }
}

fn send(pipe: &Mutex<ChildStdin>, bytes: &[u8]) {
    if let Ok(mut pipe) = pipe.lock() {
        let _ = pipe.write_all(bytes).and_then(|()| pipe.flush());
    }
}

/// The feeder of an interactive run: forwards the host's stdin to the
/// machine and keeps the machine's window the size of the host's.
pub fn feeder() -> crate::Feeder {
    Box::new(|pipe: ChildStdin, prompt: &AtomicBool| {
        let pipe = Arc::new(Mutex::new(pipe));
        // SAFETY: the handler only stores into an atomic.
        unsafe { signal(SIGWINCH, window_changed) };
        let send_size = {
            let pipe = pipe.clone();
            move || {
                if let Some((rows, columns)) = host_size() {
                    send(&pipe, &report(rows, columns));
                }
            }
        };
        // The first report goes at the first prompt: the serial line drops
        // what comes before the machine's driver is up, and half a report
        // would reach the shell as text.
        std::thread::scope(|scope| {
            let watcher = send_size.clone();
            scope.spawn(move || {
                let mut prompted = false;
                loop {
                    if !prompted && prompt.load(Ordering::SeqCst) {
                        prompted = true;
                        watcher();
                    }
                    if CHANGED.swap(false, Ordering::SeqCst) {
                        watcher();
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            });
            let mut keys = [0u8; 1024];
            let mut stdin = std::io::stdin();
            while let Ok(n) = stdin.read(&mut keys) {
                if n == 0 {
                    break;
                }
                send(&pipe, &keys[..n]);
            }
            // Keep the pipe open: the machine ends by the shell's end.
            loop {
                std::thread::sleep(Duration::from_secs(600));
            }
        });
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_is_the_one_the_terminal_service_reads() {
        assert_eq!(report(40, 132), b"\x1dW40;132\x1d");
    }
}
