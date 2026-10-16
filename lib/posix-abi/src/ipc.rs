// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Message queues, semaphores and shared memory segments (Ф11b;
//! proto_pipe::ipc): the calls of POSIX (`mq_*`, `sem_open`) and of XSI
//! (`msg*`, `sem*`, `shm*`) reach the pipe service through one request,
//! whose words relibc fills. This layer adds what only the process knows
//! (the credentials, the process number and the time, at the place the
//! caller leaves for them), finds the description a descriptor names (a
//! message queue of POSIX is a descriptor), and runs the operations that
//! wait as long operations in two steps from the calling thread
//! (`long::run_with`), with a deadline for the timed ones.

use crate::constants::*;
use crate::long;
use crate::shared;
use core::sync::atomic::{AtomicBool, Ordering};
use posix_fs::{DescriptorFlags, Target, Transport};
use proto_pipe::Method;
pub use proto_pipe::ipc::WORDS_MAX;
use proto_pipe::ipc::{Answer, Call, Cred, errno_of, op};
use proto_pipe::sock::SOCK_END;
use proto_wire::{Reader, Status, Writer};
use rt::abi::MESSAGE_MAX;

/// No deadline.
pub const NO_DEADLINE: u64 = u64::MAX;

/// What a call gave: the words of the answer and the bytes copied.
#[derive(Clone, Copy, Debug)]
pub struct Reply {
    pub words: [u64; WORDS_MAX],
    pub n: usize,
    pub len: usize,
}

fn refusal(status: Status) -> Option<i32> {
    errno_of(status).or_else(|| crate::sockets::refusal(status))
}

fn transport() -> Result<Transport, i32> {
    shared::with_files(|files| {
        files.pipes().ok_or(ENOSYS)?;
        Ok(files.transport())
    })
}

/// The time of the caller in seconds: the one word of a request that stands
/// for the caller (the service learns who it is from the process service).
fn now() -> u64 {
    crate::clock::gettime(crate::clock::CLOCK_REALTIME).map_or(0, |t| t.seconds as u64)
}

/// Whether the session with the pipe service has been given the identity
/// session of this image (a child of fork, whose session is new, is told
/// NEED_ID and sends it).
static IDENTITY_SENT: AtomicBool = AtomicBool::new(false);

/// What NEED_ID of the service is as an errno.
const NEED_ID: i32 = (proto_pipe::ipc::NEED_ID - proto_pipe::ipc::ERRNO) as i32;

fn parse(bytes: &[u8], out: &mut [u8]) -> Result<Reply, i32> {
    let answer = Answer::parse(Reader::new(bytes)).map_err(|_| EIO)?;
    let n = answer.bytes.len().min(out.len());
    out[..n].copy_from_slice(&answer.bytes[..n]);
    Ok(Reply {
        words: answer.words,
        n: answer.n,
        len: n,
    })
}

/// One request that answers at once.
#[inline(never)]
fn short(transport: Transport, call: &Call<'_>, out: &mut [u8]) -> Result<Reply, i32> {
    let pipes = transport.pipes().map_err(crate::error)?;
    let mut w = Writer::new();
    call.write(&mut w).map_err(|_| EIO)?;
    let reply = loop {
        let sent = if call.id {
            let copy = crate::process::identity()
                .and_then(|identity| {
                    rt::sys::handle_duplicate(
                        identity,
                        rt::abi::Rights::NOTIFY
                            | rt::abi::Rights::TRANSFER
                            | rt::abi::Rights::DUPLICATE,
                    )
                    .ok()
                })
                .ok_or(EIO)?;
            rt::sys::send_handles(&pipes, w.as_bytes(), [copy.erase()])
                .map_err(|refused| refused.error)
        } else {
            rt::sys::send(&pipes, w.as_bytes())
        };
        match sent {
            Err(rt::abi::Error::Interrupted) => continue,
            other => break other.map_err(|_| EIO)?,
        }
    };
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = reply.bytes(&mut buffer);
    let len = bytes.len();
    let mut r = Reader::new(&buffer[..len]);
    match Status::from_code(r.u32().map_err(|_| EIO)?) {
        Status::Ok => {
            let left = r.left();
            parse(&buffer[len - left..len], out)
        }
        status => Err(refusal(status).unwrap_or(EIO)),
    }
}

/// A long operation, the take of which repeats the call.
#[inline(never)]
fn long_call(
    transport: Transport,
    call: &Call<'_>,
    out: &mut [u8],
    deadline: u64,
) -> Result<Reply, i32> {
    let pipes = transport.pipes().map_err(crate::error)?;
    let mut start = Writer::new();
    call.write(&mut start).map_err(|_| EIO)?;
    let mut buffer = [0u8; MESSAGE_MAX];
    let keyed = |cancel: bool, key: u64, w: &mut Writer| -> Result<(), Status> {
        if cancel {
            Method::IpcCancel.header().write(w)?;
            w.u64(key)
        } else {
            let mut again = *call;
            again.key = Some(key);
            again.write(w)
        }
    };
    let n = if deadline == NO_DEADLINE && call.id {
        long::run_with_duplicable_identity(&pipes, start.as_bytes(), keyed, &mut buffer, &refusal)?
    } else if deadline == NO_DEADLINE {
        long::run_with(&pipes, start.as_bytes(), keyed, &mut buffer, &refusal)?
    } else {
        long::run_until(
            &pipes,
            start.as_bytes(),
            keyed,
            &mut buffer,
            &refusal,
            deadline,
            call.id,
        )?
    };
    parse(&buffer[..n], out)
}

fn run(
    transport: Transport,
    operation: u32,
    words: &[u64],
    cred_at: Option<usize>,
    bytes: &[u8],
    out: &mut [u8],
    deadline: u64,
) -> Result<Reply, i32> {
    if words.len() > WORDS_MAX || cred_at.is_some_and(|at| at + Cred::WORDS > words.len()) {
        return Err(EINVAL);
    }
    let mut all = [0u64; WORDS_MAX];
    all[..words.len()].copy_from_slice(words);
    if let Some(at) = cred_at {
        all[at] = now();
    }
    // The identity session goes with the first request, and again where the
    // service says it has none (the session of a child of fork).
    let mut send_identity = !IDENTITY_SENT.load(Ordering::Acquire);
    loop {
        let mut call = Call::new(operation, &all[..words.len()], bytes);
        call.id = send_identity;
        let result = if op::is_long(operation) {
            long_call(transport, &call, out, deadline)
        } else {
            short(transport, &call, out)
        };
        match result {
            Err(NEED_ID) if !send_identity => {
                IDENTITY_SENT.store(false, Ordering::Release);
                send_identity = true;
            }
            Ok(_) if send_identity => {
                IDENTITY_SENT.store(true, Ordering::Release);
                return result;
            }
            other => return other,
        }
    }
}

/// The operation `operation` with `words` (the credentials go at `cred_at`),
/// `bytes` and a `deadline` in ns of the monotonic clock for those that wait.
/// The answer's bytes go into `out`.
pub fn call(
    operation: u32,
    words: &[u64],
    cred_at: Option<usize>,
    bytes: &[u8],
    out: &mut [u8],
    deadline: u64,
) -> Result<Reply, i32> {
    let point = op::is_long(operation).then(crate::threads::cancel::Point::begin);
    let result = transport().and_then(|t| run(t, operation, words, cred_at, bytes, out, deadline));
    if let Some(point) = point {
        if result.is_ok() {
            point.end();
        } else {
            point.finish();
        }
    }
    result
}

/// `call` on the message queue the descriptor `fd` names: the first word
/// is its description's number.
pub fn call_fd(
    fd: i32,
    operation: u32,
    words: &[u64],
    cred_at: Option<usize>,
    bytes: &[u8],
    out: &mut [u8],
    deadline: u64,
) -> Result<Reply, i32> {
    let fd = u32::try_from(fd).map_err(|_| EBADF)?;
    let point = op::is_long(operation).then(crate::threads::cancel::Point::begin);
    let result = shared::held(fd, |transport, target| {
        let Target::Pipe(id) = target else {
            return Err(EBADF);
        };
        if id & SOCK_END == 0 || words.is_empty() {
            return Err(EBADF);
        }
        let mut all = [0u64; WORDS_MAX];
        all[..words.len()].copy_from_slice(words);
        all[0] = u64::from(id);
        run(
            transport,
            operation,
            &all[..words.len()],
            cred_at,
            bytes,
            out,
            deadline,
        )
    });
    if let Some(point) = point {
        if result.is_ok() {
            point.end();
        } else {
            point.finish();
        }
    }
    result
}

/// mq_open: a descriptor for the queue `name` (with its `/`). `oflag` is
/// the access mode, `O_CREAT`, `O_EXCL` and `O_NONBLOCK` of the layer's
/// numbers; `mode` is the permissions before the umask `umask`; `attr` the
/// `mq_maxmsg` and `mq_msgsize` given.
pub fn mq_open(
    name: &[u8],
    oflag: i32,
    mode: u32,
    umask: u32,
    attr: Option<(u64, u64)>,
    cloexec: bool,
) -> Result<i32, i32> {
    let transport = transport()?;
    let (maxmsg, msgsize) = attr.unwrap_or((0, 0));
    let words = [
        u64::from(oflag as u32 & (O_ACCMODE | O_CREAT | O_EXCL | O_NONBLOCK) as u32),
        u64::from(mode & !umask & 0o777),
        maxmsg,
        msgsize,
        u64::from(attr.is_some()),
        0,
    ];
    let mut out = [0u8; 0];
    let reply = run(
        transport,
        op::MQ_OPEN,
        &words,
        Some(5),
        name,
        &mut out,
        NO_DEADLINE,
    )?;
    let id = u32::try_from(reply.words[0]).map_err(|_| EIO)?;
    let flags = DescriptorFlags {
        close_on_exec: cloexec,
        close_on_fork: false,
    };
    let inserted = shared::with_files(|files| {
        files
            .insert(Target::Pipe(id), flags)
            .map(|fd| fd as i32)
            .map_err(crate::error)
    });
    if inserted.is_err() {
        let _ = transport.release(Some(Target::Pipe(id)));
    }
    inserted
}
