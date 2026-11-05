// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `curl` as a child (pk4-design R3): a pipe whose write end is the child's
//! standard output, `/dev/null` for its standard input, the standard error
//! `pkg`'s own so that curl's one line about an error reaches the owner as it
//! is. The ends of the pipe are close-on-exec, and the child gets the
//! descriptors it needs from the file actions alone. `finish` waits for the
//! child on every path: no zombie is left.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{c_char, c_int, c_void};
use libc_ffi as c;

/// relibc's `posix_spawn_file_actions_t`: 24 bytes and a word of alignment.
#[repr(C, align(8))]
struct Actions([u8; 32]);

unsafe extern "C" {
    fn posix_spawn(
        pid: *mut c_int,
        path: *const c_char,
        actions: *const Actions,
        attributes: *const c_void,
        argv: *const *mut c_char,
        envp: *const *mut c_char,
    ) -> c_int;
    fn posix_spawn_file_actions_init(a: *mut Actions) -> c_int;
    fn posix_spawn_file_actions_destroy(a: *mut Actions) -> c_int;
    fn posix_spawn_file_actions_adddup2(a: *mut Actions, from: c_int, to: c_int) -> c_int;
    fn posix_spawn_file_actions_addclose(a: *mut Actions, fd: c_int) -> c_int;
    fn posix_spawn_file_actions_addopen(
        a: *mut Actions,
        fd: c_int,
        path: *const c_char,
        flags: c_int,
        mode: u32,
    ) -> c_int;
    fn pipe2(fds: *mut c_int, flags: c_int) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn kill(pid: c_int, signal: c_int) -> c_int;
}

/// relibc's `O_CLOEXEC`.
const O_CLOEXEC: c_int = 0x80000;
const SIGTERM: c_int = 15;
const ENOENT: c_int = 2;
const EACCES: c_int = 13;

/// A running curl: its pid and the read end of its output.
pub struct Child {
    pid: c_int,
    fd: c_int,
}

fn nul(text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(text.len() + 1);
    bytes.extend_from_slice(text.as_bytes());
    bytes.push(0);
    bytes
}

/// Starts `argv[0]` with `argv` and the environment `env` (`NAME=value`); the
/// line of the refusal when it cannot.
pub fn start(argv: &[String], env: &[String]) -> Result<Child, String> {
    let words: Vec<Vec<u8>> = argv.iter().map(|a| nul(a)).collect();
    let vars: Vec<Vec<u8>> = env.iter().map(|a| nul(a)).collect();
    let mut argp: Vec<*mut c_char> = words.iter().map(|w| w.as_ptr() as *mut c_char).collect();
    argp.push(core::ptr::null_mut());
    let mut envp: Vec<*mut c_char> = vars.iter().map(|w| w.as_ptr() as *mut c_char).collect();
    envp.push(core::ptr::null_mut());
    let program = &words[0];
    let shown = &argv[0];

    let mut fds = [0 as c_int; 2];
    // SAFETY: a two-int array.
    if unsafe { pipe2(fds.as_mut_ptr(), O_CLOEXEC) } != 0 {
        return Err("pkg: cannot make a pipe".into());
    }
    let (read_end, write_end) = (fds[0], fds[1]);
    let mut actions = Actions([0; 32]);
    let null = nul("/dev/null");
    let mut pid: c_int = 0;
    // SAFETY: `actions` is as big and as aligned as relibc's object; every string is
    // NUL-terminated and outlives the call; the arrays end with NULL.
    let code = unsafe {
        posix_spawn_file_actions_init(&mut actions);
        posix_spawn_file_actions_adddup2(&mut actions, write_end, 1);
        posix_spawn_file_actions_addopen(&mut actions, 0, null.as_ptr().cast(), 0, 0);
        posix_spawn_file_actions_addclose(&mut actions, read_end);
        posix_spawn_file_actions_addclose(&mut actions, write_end);
        let code = posix_spawn(
            &mut pid,
            program.as_ptr().cast(),
            &actions,
            core::ptr::null(),
            argp.as_ptr(),
            envp.as_ptr(),
        );
        posix_spawn_file_actions_destroy(&mut actions);
        code
    };
    // SAFETY: the end this process keeps no more.
    unsafe { c::close(write_end) };
    if code != 0 {
        // SAFETY: the descriptor made above.
        unsafe { c::close(read_end) };
        let why = match code {
            ENOENT => "ENOENT".into(),
            EACCES => "EACCES".into(),
            other => format!("error {other}"),
        };
        return Err(format!("pkg: {shown}: cannot run it ({why})"));
    }
    Ok(Child { pid, fd: read_end })
}

impl Child {
    /// Reads what curl wrote into `buf`: the number of bytes, 0 at the end of its output.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        loop {
            // SAFETY: the buffer is the room given.
            let n = unsafe { c::read(self.fd, buf.as_mut_ptr(), buf.len()) };
            if n < 0 && c::errno() == crate::sys::EINTR {
                continue;
            }
            return n.max(0) as usize;
        }
    }

    /// Reads into the memory at `at`, `room` bytes at most: the cell of the buffer.
    ///
    /// # Safety
    /// `at` is the start of `room` writable bytes.
    pub unsafe fn read_into(&mut self, at: *mut u8, room: usize) -> usize {
        // SAFETY: by the caller's promise.
        self.read(unsafe { core::slice::from_raw_parts_mut(at, room) })
    }

    /// Closes the pipe, stops the child when `stop` (SIGTERM), waits for it and
    /// gives its code: the exit code, 128 and the number of a signal for a child that was killed.
    pub fn finish(self, stop: bool) -> i32 {
        // SAFETY: the descriptor made in `start`.
        unsafe { c::close(self.fd) };
        if stop {
            // SAFETY: the pid of the child this process started.
            unsafe { kill(self.pid, SIGTERM) };
        }
        let mut status: c_int = 0;
        loop {
            // SAFETY: a valid out pointer.
            let got = unsafe { waitpid(self.pid, &mut status, 0) };
            if got < 0 && c::errno() == crate::sys::EINTR {
                continue;
            }
            if got < 0 {
                return -1;
            }
            break;
        }
        decode(status)
    }
}

/// The code of a wait status: the exit code, or 128 and the signal.
pub fn decode(status: c_int) -> i32 {
    if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        128 + (status & 0x7f)
    }
}
