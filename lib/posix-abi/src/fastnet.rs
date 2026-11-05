// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The fast sockets (spec 6, 3.9; `<stafeto/fast.h>`): in a process whose
//! program registered a table of functions (`stafeto_fast_register`), every
//! `socket(AF_INET, SOCK_STREAM, ...)` is a socket of the TCP/IP stack that
//! lives in the process (F-Stack), seen under a number from `FAST_BASE` up
//! that no table of descriptors holds. The layer reaches the stack only
//! through the table, so `libc.so` names nothing of the program. Each call
//! of the table runs under `FAST_LOCK`: the stack has one thread context for
//! the process, and the holder of the lock of the layer has the entries of
//! signals deferred, so a handler never enters the stack in the middle of
//! another call.
//!
//! The functions of the table answer a count or a negated errno of Linux.
//! The stack starts at the first `socket`: the claim of the second device
//! and the table's `start`. The sockets are non-blocking from the birth
//! (the stack's `_sleep` answers EPERM to a blocking call).

use crate::constants::*;
use crate::fast::{self, FastClaim};
pub use crate::fast_events::{FAST_BASE, FAST_MAX, FAST_TICKETS, Number, classify, is_fast};
use core::cell::UnsafeCell;
use core::ffi::c_int;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use posix_sync::LayerLock;

const ENOTTY: i32 = 25;
const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const SOCK_NONBLOCK: i32 = 0o4000;
const SOCK_CLOEXEC: i32 = 0o2000000;
const SOCK_CLOFORK: i32 = crate::constants::O_CLOFORK;
const IPPROTO_TCP: i32 = 6;
const MSG_PEEK: i32 = 2;
const MSG_DONTWAIT: i32 = 0x40;
const MSG_WAITALL: i32 = 0x100;
const MSG_NOSIGNAL: i32 = 0x4000;
/// The ioctl requests of Linux that the stack translates.
const FIONBIO: u64 = 0x5421;
const FIONREAD: u64 = 0x541b;
/// The fcntl commands of relibc (Linux's) and the flags it has.
const F_DUPFD: c_int = 0;
const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const F_DUPFD_CLOEXEC: c_int = 1030;
const F_DUPFD_CLOFORK: c_int = 1100;
const FD_CLOEXEC: c_int = 0x8_0000;
const FD_CLOFORK: c_int = 0x100_0000;
const O_RDWR_: c_int = 2;

/// The flag of `struct stafeto_fast_table`: the program wants the process to
/// end when the network service lets the device go.
pub const EXIT_ON_LOSS: u32 = 1;
const KNOWN_FLAGS: u32 = EXIT_ON_LOSS;
/// The version of the table.
pub const VERSION: u32 = 1;

/// `struct iovec` and `struct msghdr` of Linux AArch64.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoVec {
    pub base: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct MsgHdr {
    pub name: *mut u8,
    pub namelen: u32,
    pub iov: *mut IoVec,
    pub iovlen: usize,
    pub control: *mut u8,
    pub controllen: usize,
    pub flags: c_int,
}

/// `struct stafeto_fast_table` (`<stafeto/fast.h>`). Every function answers
/// a count not below zero, or the negated errno of Linux.
#[repr(C)]
pub struct FastTable {
    pub version: u32,
    pub flags: u32,
    pub start: unsafe extern "C" fn(*const FastClaim) -> c_int,
    pub pass: unsafe extern "C" fn() -> c_int,
    pub next_tick_ns: unsafe extern "C" fn() -> u64,
    pub notify: unsafe extern "C" fn(c_int),
    pub absorb: unsafe extern "C" fn(u32),
    pub socket: unsafe extern "C" fn(c_int, c_int, c_int) -> c_int,
    pub bind: unsafe extern "C" fn(c_int, *const u8, u32) -> c_int,
    pub listen: unsafe extern "C" fn(c_int, c_int) -> c_int,
    pub accept4: unsafe extern "C" fn(c_int, *mut u8, *mut u32, c_int) -> c_int,
    pub connect: unsafe extern "C" fn(c_int, *const u8, u32) -> c_int,
    pub read: unsafe extern "C" fn(c_int, *mut u8, usize) -> isize,
    pub write: unsafe extern "C" fn(c_int, *const u8, usize) -> isize,
    pub readv: unsafe extern "C" fn(c_int, *const IoVec, c_int) -> isize,
    pub writev: unsafe extern "C" fn(c_int, *const IoVec, c_int) -> isize,
    pub recvfrom: unsafe extern "C" fn(c_int, *mut u8, usize, c_int, *mut u8, *mut u32) -> isize,
    pub sendto: unsafe extern "C" fn(c_int, *const u8, usize, c_int, *const u8, u32) -> isize,
    pub recvmsg: unsafe extern "C" fn(c_int, *mut MsgHdr, c_int) -> isize,
    pub sendmsg: unsafe extern "C" fn(c_int, *const MsgHdr, c_int) -> isize,
    pub close: unsafe extern "C" fn(c_int) -> c_int,
    pub shutdown: unsafe extern "C" fn(c_int, c_int) -> c_int,
    pub getsockopt: unsafe extern "C" fn(c_int, c_int, c_int, *mut u8, *mut u32) -> c_int,
    pub setsockopt: unsafe extern "C" fn(c_int, c_int, c_int, *const u8, u32) -> c_int,
    pub getsockname: unsafe extern "C" fn(c_int, *mut u8, *mut u32) -> c_int,
    pub getpeername: unsafe extern "C" fn(c_int, *mut u8, *mut u32) -> c_int,
    pub ioctl: unsafe extern "C" fn(c_int, u64, *mut u8) -> c_int,
    pub kqueue: unsafe extern "C" fn() -> c_int,
    pub kevent: unsafe extern "C" fn(c_int, *const u8, c_int, *mut u8, c_int) -> c_int,
}

/// The words of the table: the header of two `u32` and one pointer each.
pub const TABLE_WORDS: usize = core::mem::size_of::<FastTable>() / 8;
const _: () = assert!(core::mem::size_of::<FastTable>() == 8 + 8 * 27);
const _: () = assert!(core::mem::size_of::<IoVec>() == 16);
const _: () = assert!(core::mem::size_of::<MsgHdr>() == 56);

struct Slot(UnsafeCell<MaybeUninit<FastTable>>);
// SAFETY: written once under `REGISTRY` state 1, read after state 2.
unsafe impl Sync for Slot {}
static SLOT: Slot = Slot(UnsafeCell::new(MaybeUninit::uninit()));
/// 0 none, 1 being copied, 2 registered.
static REGISTRY: AtomicU32 = AtomicU32::new(0);

/// Registers the program's table (a copy is kept). EINVAL for a version or
/// a flag the layer does not know or for a null function, EBUSY for a
/// second registration.
///
/// # Safety
/// `table` points to a `struct stafeto_fast_table` readable in full.
pub unsafe fn register(table: *const FastTable) -> Result<(), i32> {
    if table.is_null() {
        return Err(EINVAL);
    }
    let words = table.cast::<u64>();
    // SAFETY: the caller's promise; the header word and the pointers.
    unsafe {
        let header = words.read();
        if header as u32 != VERSION || (header >> 32) as u32 & !KNOWN_FLAGS != 0 {
            return Err(EINVAL);
        }
        for i in 1..TABLE_WORDS {
            if words.add(i).read() == 0 {
                return Err(EINVAL);
            }
        }
    }
    if REGISTRY
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(EBUSY);
    }
    // SAFETY: state 1 is this call's alone; the table was checked above.
    unsafe { (*SLOT.0.get()).write(core::ptr::read(table)) };
    REGISTRY.store(2, Ordering::Release);
    Ok(())
}

/// Whether the program registered a table.
#[inline(always)]
pub fn registered() -> bool {
    REGISTRY.load(Ordering::Acquire) == 2
}

fn table() -> Option<&'static FastTable> {
    // SAFETY: state 2 follows the write of the whole table.
    registered().then(|| unsafe { (*SLOT.0.get()).assume_init_ref() })
}

/// The flags of the registered table.
pub fn table_flags() -> u32 {
    table().map_or(0, |t| t.flags)
}

/// The lock of every call of the table. The holder is in a critical
/// section of the layer, so the entries of signals wait. Nothing under it
/// sleeps: the stack's calls do not block, and the start of the stack runs
/// outside it.
static FAST_LOCK: LayerLock = LayerLock::new();

/// Runs `f` with the table under the lock, EBADF without a table or a stack.
fn locked<R>(f: impl FnOnce(&FastTable) -> R) -> Result<R, i32> {
    let t = table().ok_or(EBADF)?;
    if !up() {
        return Err(EBADF);
    }
    let _guard = FAST_LOCK.lock();
    Ok(f(t))
}

/// `locked` for a call whose answer is a count or a negated errno.
fn count(f: impl FnOnce(&FastTable) -> isize) -> Result<usize, i32> {
    let r = locked(f)?;
    if r < 0 {
        Err((-r) as i32)
    } else {
        Ok(r as usize)
    }
}

// -------------------------------------------------------------- the stack

/// The state of the stack in the process: 0 none, 1 starting, 2 up, 3 refused.
static STACK: AtomicU32 = AtomicU32::new(0);
static REFUSED: AtomicI32 = AtomicI32::new(0);

/// Whether the stack runs in the process.
#[inline(always)]
pub fn up() -> bool {
    STACK.load(Ordering::Acquire) == 2
}

/// Starts the stack once: the claim of the second device, then the
/// table's `start`. Outside `FAST_LOCK` (the claim waits for the device).
/// A refusal is final for the process, but a signal that ended the claim
/// leaves the start to the next call.
pub fn ensure_stack() -> Result<(), i32> {
    let t = table().ok_or(EBADF)?;
    loop {
        match STACK.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(2) => return Ok(()),
            Err(3) => return Err(REFUSED.load(Ordering::Acquire)),
            Err(_) => crate::threads::sleep::pause(1_000_000)?,
        }
    }
    // SAFETY: a `FastClaim` is plain numbers.
    let mut claim: FastClaim = unsafe { core::mem::zeroed() };
    let started = match fast::claim(&mut claim, 0) {
        // SAFETY: the table's start, with the claim it asked for.
        Ok(()) => match unsafe { (t.start)(&claim) } {
            r if r < 0 => Err(-r),
            _ => Ok(()),
        },
        Err(errno) => Err(errno),
    };
    match started {
        Ok(()) => {
            STACK.store(2, Ordering::Release);
            Ok(())
        }
        Err(errno) => {
            if errno == EINTR {
                STACK.store(0, Ordering::Release);
            } else {
                REFUSED.store(errno, Ordering::Release);
                STACK.store(3, Ordering::Release);
            }
            Err(errno)
        }
    }
}

/// Whether the network service let go of the device.
pub fn lost() -> bool {
    posix_sync::receiver::lost()
}

/// One step of the stack and a look at the kqueue `kq` for up to `room`
/// events, under the lock. Returns the work the step found and the events.
pub fn pass_and_poll(
    kq: c_int,
    out: &mut [crate::fast_events::Kevent],
) -> Result<(i32, usize), i32> {
    locked(|t| {
        // SAFETY: the table's functions; `out` holds `len` events.
        let work = unsafe { (t.pass)() };
        let got = if out.is_empty() {
            0
        } else {
            unsafe {
                (t.kevent)(
                    kq,
                    core::ptr::null(),
                    0,
                    out.as_mut_ptr().cast(),
                    out.len() as c_int,
                )
            }
        };
        (work, got)
    })
    .and_then(|(work, got)| {
        if got < 0 {
            Err(-got)
        } else {
            Ok((work, got as usize))
        }
    })
}

/// The look at the kqueue alone, under the lock.
pub fn poll(kq: c_int, out: &mut [crate::fast_events::Kevent]) -> Result<usize, i32> {
    count(|t| {
        // SAFETY: as above.
        unsafe {
            (t.kevent)(
                kq,
                core::ptr::null(),
                0,
                out.as_mut_ptr().cast(),
                out.len() as c_int,
            ) as isize
        }
    })
}

/// One step of the stack, under the lock: the work it found.
pub fn pass() -> Result<i32, i32> {
    // SAFETY: the table's function.
    locked(|t| unsafe { (t.pass)() })
}

/// The time to the next clock tick of the stack, nanoseconds.
pub fn next_tick_ns() -> u64 {
    // SAFETY: the table's function.
    locked(|t| unsafe { (t.next_tick_ns)() }).unwrap_or(10_000_000)
}

/// The device's interrupts on or off (`on` 1 puts a full barrier before the
/// caller's next look at the queues).
pub fn notify(on: bool) {
    // SAFETY: the table's function.
    let _ = locked(|t| unsafe { (t.notify)(c_int::from(on)) });
}

/// The bits of the service's notifications, to the program's stack.
pub fn absorb(bits: u32) {
    if bits != 0 {
        // SAFETY: the table's function.
        let _ = locked(|t| unsafe { (t.absorb)(bits) });
    }
}

/// A kqueue of the stack.
pub fn kqueue() -> Result<c_int, i32> {
    // SAFETY: the table's function.
    count(|t| unsafe { (t.kqueue)() as isize }).map(|kq| kq as c_int)
}

/// The changes `changes` on the kqueue `kq`, no events back.
pub fn change(kq: c_int, changes: &[crate::fast_events::Kevent]) -> Result<(), i32> {
    // SAFETY: the table's function; `changes` holds `len` events.
    count(|t| unsafe {
        (t.kevent)(
            kq,
            changes.as_ptr().cast(),
            changes.len() as c_int,
            core::ptr::null_mut(),
            0,
        ) as isize
    })
    .map(drop)
}

/// Closes a descriptor of the stack (a kqueue).
pub fn close_raw(n: c_int) {
    // SAFETY: the table's function.
    let _ = locked(|t| unsafe { (t.close)(n) });
}

// ------------------------------------------------------------ the numbers

/// The number of F-Stack behind a number of the program.
fn number(fd: i32) -> Result<c_int, i32> {
    match classify(fd) {
        Some(Number::Socket(n)) => Ok(n),
        // The tickets of the listeners come with the processes that open
        // them before the stack starts.
        Some(Number::Ticket(_)) | None => Err(EBADF),
    }
}

/// The socket `n` of the stack as the program's number; a number the range
/// cannot hold closes the socket.
fn publish(n: c_int) -> Result<i32, i32> {
    match crate::fast_events::number_of(n) {
        Some(fd) => Ok(fd),
        None => {
            close_raw(n);
            Err(EMFILE)
        }
    }
}

// --------------------------------------------------------------- the calls

/// Whether a `socket(domain, kind)` is a fast socket of the process.
#[inline(always)]
pub fn takes(domain: i32, kind: i32) -> bool {
    domain == AF_INET && kind & 0xf == SOCK_STREAM && registered()
}

pub fn socket(kind: i32, protocol: i32) -> Result<i32, i32> {
    if kind & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC | SOCK_CLOFORK) != 0 {
        return Err(EINVAL);
    }
    if protocol != 0 && protocol != IPPROTO_TCP {
        return Err(EINVAL);
    }
    ensure_stack()?;
    let n = count(|t| {
        // SAFETY: the table's functions.
        let n = unsafe { (t.socket)(AF_INET, SOCK_STREAM, 0) };
        if n < 0 {
            return n as isize;
        }
        let mut on: c_int = 1;
        let r = unsafe { (t.ioctl)(n, FIONBIO, (&raw mut on).cast()) };
        if r < 0 {
            unsafe { (t.close)(n) };
            return r as isize;
        }
        n as isize
    })? as c_int;
    publish(n)
}

pub fn bind(fd: i32, raw: &[u8]) -> Result<(), i32> {
    let n = number(fd)?;
    // SAFETY: the table's function; `raw` is readable.
    count(|t| unsafe { (t.bind)(n, raw.as_ptr(), raw.len() as u32) as isize }).map(drop)
}

pub fn listen(fd: i32, backlog: i32) -> Result<(), i32> {
    let n = number(fd)?;
    // SAFETY: the table's function.
    count(|t| unsafe { (t.listen)(n, backlog) as isize }).map(drop)
}

pub fn connect(fd: i32, raw: &[u8]) -> Result<(), i32> {
    let n = number(fd)?;
    // SAFETY: the table's function; `raw` is readable.
    count(|t| unsafe { (t.connect)(n, raw.as_ptr(), raw.len() as u32) as isize }).map(drop)
}

pub fn accept(fd: i32, out: Option<&mut [u8]>, flags: i32) -> Result<(i32, usize), i32> {
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC | SOCK_CLOFORK) != 0 {
        return Err(EINVAL);
    }
    let n = number(fd)?;
    let (pointer, mut len) = match out {
        Some(out) => (out.as_mut_ptr(), out.len() as u32),
        None => (core::ptr::null_mut(), 0),
    };
    let lenp: *mut u32 = if pointer.is_null() {
        core::ptr::null_mut()
    } else {
        &raw mut len
    };
    // The new socket is non-blocking from the birth.
    // SAFETY: the table's function; the buffer and its length are this call's.
    let new = count(|t| unsafe { (t.accept4)(n, pointer, lenp, SOCK_NONBLOCK) as isize })? as c_int;
    let fd = publish(new)?;
    Ok((fd, if pointer.is_null() { 0 } else { len as usize }))
}

fn name(fd: i32, peer: bool, out: &mut [u8]) -> Result<usize, i32> {
    let n = number(fd)?;
    let mut len = out.len() as u32;
    let pointer = out.as_mut_ptr();
    // SAFETY: the table's function; the buffer and its length are this call's.
    count(|t| unsafe {
        if peer {
            (t.getpeername)(n, pointer, &raw mut len) as isize
        } else {
            (t.getsockname)(n, pointer, &raw mut len) as isize
        }
    })?;
    Ok(len as usize)
}

pub fn getsockname(fd: i32, out: &mut [u8]) -> Result<usize, i32> {
    name(fd, false, out)
}

pub fn getpeername(fd: i32, out: &mut [u8]) -> Result<usize, i32> {
    name(fd, true, out)
}

pub fn getsockopt(fd: i32, level: i32, option: i32, out: &mut [u8]) -> Result<usize, i32> {
    let n = number(fd)?;
    let mut len = out.len() as u32;
    let pointer = out.as_mut_ptr();
    // SAFETY: the table's function; the buffer and its length are this call's.
    count(|t| unsafe { (t.getsockopt)(n, level, option, pointer, &raw mut len) as isize })?;
    Ok(len as usize)
}

pub fn setsockopt(fd: i32, level: i32, option: i32, value: &[u8]) -> Result<(), i32> {
    let n = number(fd)?;
    // SAFETY: the table's function; `value` is readable.
    count(|t| unsafe {
        (t.setsockopt)(n, level, option, value.as_ptr(), value.len() as u32) as isize
    })
    .map(drop)
}

pub fn shutdown(fd: i32, how: i32) -> Result<(), i32> {
    let n = number(fd)?;
    // SAFETY: the table's function.
    count(|t| unsafe { (t.shutdown)(n, how) as isize }).map(drop)
}

/// No fast socket has out-of-band data.
pub fn sockatmark(fd: i32) -> Result<i32, i32> {
    number(fd).map(|_| 0)
}

pub fn close(fd: i32) -> Result<(), i32> {
    let n = number(fd)?;
    // SAFETY: the table's function.
    count(|t| unsafe { (t.close)(n) as isize }).map(drop)
}

pub fn read(fd: i32, out: &mut [u8]) -> Result<usize, i32> {
    let n = number(fd)?;
    if out.is_empty() {
        return Ok(0);
    }
    // SAFETY: the table's function; the buffer is this call's.
    count(|t| unsafe { (t.read)(n, out.as_mut_ptr(), out.len()) })
}

/// A write has no SIGPIPE: EPIPE comes alone (the stack sends no signal).
pub fn write(fd: i32, bytes: &[u8]) -> Result<usize, i32> {
    let n = number(fd)?;
    if bytes.is_empty() {
        return Ok(0);
    }
    // SAFETY: the table's function; `bytes` is readable.
    count(|t| unsafe { (t.write)(n, bytes.as_ptr(), bytes.len()) })
}

/// writev with the program's own vector, no copy.
///
/// # Safety
/// `iov` points to `count` readable `struct iovec` whose parts are readable.
pub unsafe fn writev(fd: i32, iov: *const IoVec, count_: i32) -> Result<usize, i32> {
    let n = number(fd)?;
    if !(0..=1024).contains(&count_) {
        return Err(EINVAL);
    }
    // SAFETY: the table's function; the caller's vector.
    count(|t| unsafe { (t.writev)(n, iov, count_) })
}

/// The flags of a message that the glue translates; the rest are refused.
fn message_flags(flags: i32) -> Result<i32, i32> {
    if flags & !(MSG_PEEK | MSG_DONTWAIT | MSG_WAITALL | MSG_NOSIGNAL) != 0 {
        return Err(EOPNOTSUPP);
    }
    Ok(flags)
}

/// sendto and sendmsg without control data.
pub fn send(
    fd: i32,
    flags: i32,
    name: Option<&[u8]>,
    iov: &[&[u8]],
    control: &[u8],
) -> Result<usize, i32> {
    let n = number(fd)?;
    if !control.is_empty() {
        return Err(EOPNOTSUPP);
    }
    let flags = message_flags(flags)?;
    let (to, to_len) = match name {
        Some(name) => (name.as_ptr(), name.len() as u32),
        None => (core::ptr::null(), 0),
    };
    if let [part] = iov {
        // SAFETY: the table's function; the buffers are readable.
        return count(|t| unsafe { (t.sendto)(n, part.as_ptr(), part.len(), flags, to, to_len) });
    }
    let mut vector = [IoVec {
        base: core::ptr::null_mut(),
        len: 0,
    }; 16];
    if iov.len() > vector.len() {
        return Err(EINVAL);
    }
    for (slot, part) in vector.iter_mut().zip(iov) {
        *slot = IoVec {
            base: part.as_ptr().cast_mut(),
            len: part.len(),
        };
    }
    let message = MsgHdr {
        name: to.cast_mut(),
        namelen: to_len,
        iov: vector.as_mut_ptr(),
        iovlen: iov.len(),
        control: core::ptr::null_mut(),
        controllen: 0,
        flags: 0,
    };
    // SAFETY: the table's function; the message and its parts are this call's.
    count(|t| unsafe { (t.sendmsg)(n, &message, flags) })
}

/// recvfrom and recvmsg, no control data back.
pub fn recv(
    fd: i32,
    flags: i32,
    name: Option<&mut [u8]>,
    iov: &mut [&mut [u8]],
    control: &mut [u8],
) -> Result<crate::sockets::Message, i32> {
    let n = number(fd)?;
    let flags = message_flags(flags)?;
    let _ = control;
    let (from, mut from_len) = match name {
        Some(name) => (name.as_mut_ptr(), name.len() as u32),
        None => (core::ptr::null_mut(), 0),
    };
    let from_pointer: *mut u32 = if from.is_null() {
        core::ptr::null_mut()
    } else {
        &raw mut from_len
    };
    let got = if let [part] = iov {
        // SAFETY: the table's function; the buffers are this call's.
        count(|t| unsafe {
            (t.recvfrom)(n, part.as_mut_ptr(), part.len(), flags, from, from_pointer)
        })?
    } else {
        let mut vector = [IoVec {
            base: core::ptr::null_mut(),
            len: 0,
        }; 16];
        if iov.len() > vector.len() {
            return Err(EINVAL);
        }
        for (slot, part) in vector.iter_mut().zip(iov.iter_mut()) {
            *slot = IoVec {
                base: part.as_mut_ptr(),
                len: part.len(),
            };
        }
        let mut message = MsgHdr {
            name: from,
            namelen: from_len,
            iov: vector.as_mut_ptr(),
            iovlen: iov.len(),
            control: core::ptr::null_mut(),
            controllen: 0,
            flags: 0,
        };
        // SAFETY: the table's function; the message and its parts are this call's.
        let got = count(|t| unsafe { (t.recvmsg)(n, &mut message, flags) })?;
        from_len = message.namelen;
        got
    };
    Ok(crate::sockets::Message {
        count: got,
        name_len: if from.is_null() { 0 } else { from_len as usize },
        flags: 0,
        control_len: 0,
    })
}

/// fcntl of a fast number: O_NONBLOCK is always on and cannot go; the
/// descriptor flags are kept nowhere (a fast socket is closed by the
/// process that made it); duplication is refused.
pub fn fcntl(fd: i32, command: c_int, argument: u64) -> Result<c_int, i32> {
    number(fd)?;
    match command {
        F_GETFL => Ok(O_RDWR_ | O_NONBLOCK),
        F_SETFL => {
            if argument as c_int & O_NONBLOCK != 0 {
                Ok(0)
            } else {
                Err(EINVAL)
            }
        }
        F_GETFD => Ok(FD_CLOEXEC | FD_CLOFORK),
        F_SETFD => Ok(0),
        F_DUPFD | F_DUPFD_CLOEXEC | F_DUPFD_CLOFORK => Err(EOPNOTSUPP),
        _ => Err(EINVAL),
    }
}

/// ioctl of a fast number: FIONBIO on only, FIONREAD of the stack.
///
/// # Safety
/// `argument` is what `request` says: a readable int for FIONBIO, a
/// writable one for FIONREAD.
pub unsafe fn ioctl(fd: i32, request: u64, argument: *mut u8) -> Result<c_int, i32> {
    let n = number(fd)?;
    match request {
        FIONBIO => {
            if argument.is_null() {
                return Err(EFAULT);
            }
            // SAFETY: FIONBIO's argument is a readable int.
            if unsafe { argument.cast::<c_int>().read() } == 0 {
                return Err(EINVAL);
            }
            Ok(0)
        }
        FIONREAD => {
            if argument.is_null() {
                return Err(EFAULT);
            }
            // SAFETY: the table's function; the caller's int.
            count(|t| unsafe { (t.ioctl)(n, FIONREAD, argument) as isize }).map(|r| r as c_int)
        }
        _ => Err(ENOTTY),
    }
}

/// fstat: a socket.
pub fn stat(fd: i32) -> Result<proto_fs::NodeInfo, i32> {
    let n = number(fd)?;
    Ok(proto_fs::NodeInfo {
        kind: posix_fs::SOCKET,
        permissions: 0o600,
        device: 6,
        special_device: 0,
        inode: n as u64 + 1,
        links: 1,
        uid: 0,
        gid: 0,
        size: 0,
        block_size: 16_384,
        blocks: 0,
        access_time: proto_fs::Timestamp::ZERO,
        modify_time: proto_fs::Timestamp::ZERO,
        change_time: proto_fs::Timestamp::ZERO,
    })
}

/// Everything else over a fast number (`lseek`, `pread`, `mmap` and the
/// like): the socket is no file.
pub fn unsupported(fd: i32) -> i32 {
    if registered() && classify(fd).is_some() {
        ESPIPE
    } else {
        EBADF
    }
}

/// `dup` of a fast number: no other number can name the socket.
pub fn refuse_copy(fd: i32) -> i32 {
    if registered() && classify(fd).is_some() {
        EOPNOTSUPP
    } else {
        EBADF
    }
}

/// `dup2` and `dup3`: a fast number as the source is refused as `dup` is,
/// and as the target it names no entry of the table of descriptors.
pub fn refuse_dup(source: i32, target: i32) -> i32 {
    if is_fast(source) {
        refuse_copy(source)
    } else {
        let _ = target;
        EBADF
    }
}
