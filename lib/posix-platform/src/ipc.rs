// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calls of message queues, semaphores and shared memory segments of
//! relibc's platform (posix_abi::ipc): relibc fills the words of the
//! protocol, the layer adds the credentials and the time. Each returns the
//! count of bytes it copied or a negated errno.

use super::{call, files, value};
use core::ffi::{c_char, c_int};
use layer::WORDS_MAX;
use posix_abi::constants::{EFAULT, EINVAL};
use posix_abi::ipc as layer;

// relibc's flags of open (Linux's, the platform's).
const O_ACCMODE: c_int = 3;
const O_CREAT: c_int = 0o100;
const O_EXCL: c_int = 0o200;
const O_NONBLOCK: c_int = 0o4000;
const O_CLOEXEC: c_int = 0o2000000;

/// # Safety
/// `pointer` is null or readable for `len` elements.
unsafe fn input<'a, T>(pointer: *const T, len: usize) -> Result<&'a [T], c_int> {
    if len == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(EFAULT);
    }
    // SAFETY: the caller's promise.
    Ok(unsafe { core::slice::from_raw_parts(pointer, len) })
}

/// # Safety
/// `pointer` is null or writable for `len` elements.
unsafe fn output<'a, T>(pointer: *mut T, len: usize) -> Result<&'a mut [T], c_int> {
    if len == 0 {
        return Ok(&mut []);
    }
    if pointer.is_null() {
        return Err(EFAULT);
    }
    // SAFETY: the caller's promise.
    Ok(unsafe { core::slice::from_raw_parts_mut(pointer, len) })
}

/// The cleaning of a call's reply into the caller's buffers.
///
/// # Safety
/// The buffers are as `stafeto_ipc` says.
#[allow(clippy::too_many_arguments)]
unsafe fn run(
    fd: Option<c_int>,
    operation: u32,
    words: *const u64,
    nwords: usize,
    cred_at: usize,
    bytes: *const u8,
    nbytes: usize,
    words_out: *mut u64,
    nwords_out: usize,
    bytes_out: *mut u8,
    cap_out: usize,
    deadline: u64,
) -> isize {
    // SAFETY: the caller's promise.
    let (words, bytes, words_out, bytes_out) = unsafe {
        match (
            input(words, nwords),
            input(bytes, nbytes),
            output(words_out, nwords_out),
            output(bytes_out, cap_out),
        ) {
            (Ok(w), Ok(b), Ok(wo), Ok(bo)) => (w, b, wo, bo),
            _ => return -(EFAULT as isize),
        }
    };
    let cred_at = (cred_at != usize::MAX).then_some(cred_at);
    let result = call(|| match fd {
        Some(fd) => layer::call_fd(fd, operation, words, cred_at, bytes, bytes_out, deadline),
        None => layer::call(operation, words, cred_at, bytes, bytes_out, deadline),
    });
    match result {
        Ok(reply) => {
            for (slot, word) in words_out.iter_mut().zip(&reply.words[..WORDS_MAX]) {
                *slot = *word;
            }
            reply.len as isize
        }
        Err(errno) => -(errno as isize),
    }
}

/// An operation of the IPC methods: `words` (`nwords` of them, with room
/// for the credentials at `cred_at`, or `usize::MAX` for none), `bytes`;
/// the answer's words into `words_out` and its bytes into `bytes_out`.
/// `deadline` is the monotonic ns at which a wait ends (`u64::MAX`: none).
///
/// # Safety
/// The pointers are readable or writable for their counts, or null with 0.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stafeto_ipc(
    operation: u32,
    words: *const u64,
    nwords: usize,
    cred_at: usize,
    bytes: *const u8,
    nbytes: usize,
    words_out: *mut u64,
    nwords_out: usize,
    bytes_out: *mut u8,
    cap_out: usize,
    deadline: u64,
) -> isize {
    // SAFETY: the caller's promise.
    unsafe {
        run(
            None, operation, words, nwords, cred_at, bytes, nbytes, words_out, nwords_out,
            bytes_out, cap_out, deadline,
        )
    }
}

/// `stafeto_ipc` on the message queue of the descriptor `fd`.
///
/// # Safety
/// As `stafeto_ipc`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stafeto_ipc_fd(
    fd: c_int,
    operation: u32,
    words: *const u64,
    nwords: usize,
    cred_at: usize,
    bytes: *const u8,
    nbytes: usize,
    words_out: *mut u64,
    nwords_out: usize,
    bytes_out: *mut u8,
    cap_out: usize,
    deadline: u64,
) -> isize {
    // SAFETY: the caller's promise.
    unsafe {
        run(
            Some(fd),
            operation,
            words,
            nwords,
            cred_at,
            bytes,
            nbytes,
            words_out,
            nwords_out,
            bytes_out,
            cap_out,
            deadline,
        )
    }
}

/// mq_open: the descriptor of the queue `name` (with its `/`), `oflag`
/// relibc's; `maxmsg` and `msgsize` when `has_attr`.
///
/// # Safety
/// `name` is a live C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_mq_open(
    name: *const c_char,
    oflag: c_int,
    mode: u32,
    has_attr: c_int,
    maxmsg: i64,
    msgsize: i64,
) -> c_int {
    // SAFETY: the caller's promise.
    let name = match unsafe { posix_abi::path(name) } {
        Ok(name) => name,
        Err(errno) => return -errno,
    };
    if oflag & !(O_ACCMODE | O_CREAT | O_EXCL | O_NONBLOCK | O_CLOEXEC) != 0 {
        return -EINVAL;
    }
    let mut ours = oflag & O_ACCMODE;
    for (theirs, layer) in [
        (O_CREAT, posix_abi::constants::O_CREAT),
        (O_EXCL, posix_abi::constants::O_EXCL),
        (O_NONBLOCK, posix_abi::constants::O_NONBLOCK),
    ] {
        if oflag & theirs != 0 {
            ours |= layer;
        }
    }
    let attr = if has_attr != 0 {
        if maxmsg <= 0 || msgsize <= 0 {
            return -EINVAL;
        }
        Some((maxmsg as u64, msgsize as u64))
    } else {
        None
    };
    let umask = files::umask();
    value(
        call(|| layer::mq_open(name, ours, mode, umask, attr, oflag & O_CLOEXEC != 0))
            .map(i64::from),
    ) as c_int
}
