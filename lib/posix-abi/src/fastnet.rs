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
use crate::fast_events;
pub use crate::fast_events::{
    FAST_BASE, FAST_MAX, FAST_TICKETS, Number, above_table, classify, is_fast,
};
use crate::fast_tickets::{self, Tickets};
use crate::wait;
use core::cell::UnsafeCell;
use core::ffi::c_int;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use posix_sync::LayerLock;

const ENOTTY: i32 = 25;
const ENOTCONN: i32 = 107;
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

/// The channel of the thread that starts the stack: a handler that runs on
/// that thread while it waits and calls a fast socket meets the state
/// "starting" and must not wait for itself.
static STARTER: AtomicU64 = AtomicU64::new(0);

fn own_channel() -> u64 {
    crate::threads::own_block().channel.load(Ordering::Relaxed)
}

/// Starts the stack once: the claim of the second device, the table's
/// `start`, then the sockets of the stack for the tickets (all at once, so
/// that no SYN for the second listener finds its port closed while the
/// program adds the first). Outside `FAST_LOCK` (the claim waits for the
/// device); the pause of the claim is not ended by a signal, since the
/// calls that start the stack (`epoll_ctl`, `accept`, `connect`) have no
/// EINTR to give. A refusal is final for the process. A thread that finds
/// the start going waits for it; a handler on the starting thread gets
/// EAGAIN at once.
pub fn ensure_stack() -> Result<(), i32> {
    let t = table().ok_or(EBADF)?;
    loop {
        // The exchange and the mark of the starting thread are one step for
        // a handler of this thread: the entries of signals wait in a
        // critical section, so a handler never sees "starting" with no mark.
        posix_sync::enter();
        let swapped = STACK.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
        if swapped.is_ok() {
            STARTER.store(own_channel(), Ordering::Release);
        }
        posix_sync::leave();
        match swapped {
            Ok(_) => break,
            Err(2) => return Ok(()),
            Err(3) => return Err(REFUSED.load(Ordering::Acquire)),
            Err(_) => {
                if STARTER.load(Ordering::Acquire) == own_channel() {
                    return Err(EAGAIN);
                }
                let _ = crate::threads::sleep::pause(1_000_000);
            }
        }
    }
    // SAFETY: a `FastClaim` is plain numbers.
    let mut claim: FastClaim = unsafe { core::mem::zeroed() };
    let started = match fast::claim_steady(&mut claim, 0) {
        // SAFETY: the table's start, with the claim it asked for.
        Ok(()) => match unsafe { (t.start)(&claim) } {
            r if r < 0 => Err(-r),
            _ => Ok(()),
        },
        Err(errno) => Err(errno),
    };
    match started {
        Ok(()) => {
            // The state turns to "up" inside the tickets' lock, after their
            // sockets exist: a call on a ticket then finds a socket.
            tickets(|tickets| {
                make_sockets(t, tickets);
                STACK.store(2, Ordering::Release);
            });
            Ok(())
        }
        Err(errno) => {
            REFUSED.store(errno, Ordering::Release);
            STACK.store(3, Ordering::Release);
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

/// What a number of the program names now.
enum Route {
    /// The socket `n` of the stack.
    Stack(c_int),
    /// A ticket the stack has not made a socket for.
    Ticket(usize),
}

struct TicketTable(UnsafeCell<Tickets>);
// SAFETY: every access is under `TICKET_LOCK`.
unsafe impl Sync for TicketTable {}
static TICKETS: TicketTable = TicketTable(UnsafeCell::new(Tickets::new()));
/// The lock of the tickets. The holder is in a critical section and sleeps
/// nowhere; the start of the stack takes `FAST_LOCK` inside it (that order
/// only).
static TICKET_LOCK: LayerLock = LayerLock::new();

fn tickets<R>(f: impl FnOnce(&mut Tickets) -> R) -> R {
    let _guard = TICKET_LOCK.lock();
    // SAFETY: the lock gives this access alone.
    f(unsafe { &mut *TICKETS.0.get() })
}

/// Runs `f` on the tickets while the stack is not up, `None` once it is
/// (the tickets then have sockets, and the call goes the way of the stack).
fn on_ticket<R>(f: impl FnOnce(&mut Tickets) -> Result<R, i32>) -> Option<Result<R, i32>> {
    tickets(|t| if up() { None } else { Some(f(t)) })
}

fn route(fd: i32) -> Result<Route, i32> {
    match classify(fd) {
        Some(Number::Socket(n)) => Ok(Route::Stack(n)),
        Some(Number::Ticket(i)) if registered() => {
            let i = i as usize;
            let (used, socket, error) = tickets(|t| {
                let slot = &t.slots[i];
                (slot.used, slot.socket, slot.error)
            });
            if !used {
                Err(EBADF)
            } else if !up() {
                Ok(Route::Ticket(i))
            } else if socket >= 0 {
                Ok(Route::Stack(socket))
            } else if socket == fast_tickets::REFUSED {
                Err(error)
            } else {
                Err(EBADF)
            }
        }
        _ => Err(EBADF),
    }
}

/// The socket of the stack behind a number that has one.
fn number(fd: i32) -> Result<c_int, i32> {
    match route(fd)? {
        Route::Stack(n) => Ok(n),
        Route::Ticket(_) => Err(ENOTCONN),
    }
}

/// The socket of the stack behind a number, starting the stack when the
/// number is a ticket: `accept`, `connect` and `epoll_ctl` do that.
pub fn stack_of(fd: i32) -> Result<c_int, i32> {
    loop {
        match route(fd)? {
            Route::Stack(n) => return Ok(n),
            Route::Ticket(_) => ensure_stack()?,
        }
    }
}

/// A call that goes to the stack for a number of the stack and to the
/// record for a ticket that the stack has not made a socket for.
fn with_route<R>(
    fd: i32,
    mut stack: impl FnMut(c_int) -> Result<R, i32>,
    mut ticket: impl FnMut(&mut Tickets, usize) -> Result<R, i32>,
) -> Result<R, i32> {
    loop {
        match route(fd)? {
            Route::Stack(n) => return stack(n),
            Route::Ticket(i) => {
                if let Some(result) = on_ticket(|t| ticket(t, i)) {
                    return result;
                }
            }
        }
    }
}

/// The sockets of the stack for the tickets, when the stack starts (the
/// caller holds the lock of the tickets). A ticket whose socket cannot be made
/// keeps the errno: the calls on its number answer with it.
fn make_sockets(t: &FastTable, tickets: &mut Tickets) {
    for i in 0..tickets.slots.len() {
        if !tickets.slots[i].used {
            continue;
        }
        let ticket = tickets.slots[i];
        let _guard = FAST_LOCK.lock();
        match make_socket(t, &ticket) {
            Ok(n) => tickets.slots[i].socket = n,
            Err(errno) => tickets.refuse(i, errno),
        }
    }
}

/// One socket of the stack from a ticket: the options the program set,
/// non-blocking, the address, the backlog.
fn make_socket(t: &FastTable, ticket: &fast_tickets::Ticket) -> Result<c_int, i32> {
    // SAFETY: the table's functions; the buffers are this call's.
    unsafe {
        let n = (t.socket)(AF_INET, SOCK_STREAM, 0);
        if n < 0 {
            return Err(-n);
        }
        let failed = |why: c_int| {
            (t.close)(n);
            Err(-why)
        };
        if n >= FAST_MAX {
            return failed(-EMFILE);
        }
        let mut on: c_int = 1;
        let r = (t.ioctl)(n, FIONBIO, (&raw mut on).cast());
        if r < 0 {
            return failed(r);
        }
        for (&(level, name), value) in fast_tickets::OPTIONS.iter().zip(&ticket.options) {
            if let Some(value) = value {
                let r = (t.setsockopt)(n, level, name, (&raw const *value).cast(), 4);
                if r < 0 {
                    return failed(r);
                }
            }
        }
        if let Some(address) = &ticket.address {
            let r = (t.bind)(n, address.as_ptr(), address.len() as u32);
            if r < 0 {
                return failed(r);
            }
        }
        if let Some(backlog) = ticket.backlog {
            let r = (t.listen)(n, backlog);
            if r < 0 {
                return failed(r);
            }
        }
        Ok(n)
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
    let cloexec = kind & SOCK_CLOEXEC != 0;
    let clofork = kind & SOCK_CLOFORK != 0;
    // Before the stack runs the socket is a ticket (a process that opens its
    // listeners and then forks has no stack in the parent).
    let made = tickets(|tickets| match STACK.load(Ordering::Acquire) {
        2 => None,
        3 => Some(Err(REFUSED.load(Ordering::Acquire))),
        _ => Some(
            tickets
                .open(cloexec, clofork)
                .map(|i| FAST_BASE + FAST_MAX + i as i32),
        ),
    });
    if let Some(made) = made {
        return made;
    }
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
    let address = fast_events::check_inet(raw)?;
    with_route(
        fd,
        // SAFETY: the table's function; `address` is 16 readable bytes.
        |n| {
            count(|t| unsafe { (t.bind)(n, address.as_ptr(), address.len() as u32) as isize })
                .map(drop)
        },
        |tickets, i| tickets.bind(i, address),
    )
}

pub fn listen(fd: i32, backlog: i32) -> Result<(), i32> {
    with_route(
        fd,
        // SAFETY: the table's function.
        |n| count(|t| unsafe { (t.listen)(n, backlog) as isize }).map(drop),
        |tickets, i| {
            tickets.listen(i, backlog);
            Ok(())
        },
    )
}

pub fn connect(fd: i32, raw: &[u8]) -> Result<(), i32> {
    let address = fast_events::check_inet(raw)?;
    let n = stack_of(fd)?;
    // SAFETY: the table's function; `address` is 16 readable bytes.
    count(|t| unsafe { (t.connect)(n, address.as_ptr(), address.len() as u32) as isize }).map(drop)
}

pub fn accept(fd: i32, out: Option<&mut [u8]>, flags: i32) -> Result<(i32, usize), i32> {
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC | SOCK_CLOFORK) != 0 {
        return Err(EINVAL);
    }
    let n = stack_of(fd)?;
    // The stack writes the peer into the layer's own buffer; the program
    // gets as much of it as its length allows and learns the true length.
    let mut room = [0u8; fast_events::SOCKADDR_ROOM];
    let mut len = room.len() as u32;
    let (pointer, lenp): (*mut u8, *mut u32) = if out.is_some() {
        (room.as_mut_ptr(), &raw mut len)
    } else {
        (core::ptr::null_mut(), core::ptr::null_mut())
    };
    // The new socket is non-blocking from the birth.
    // SAFETY: the table's function; the buffer and its length are this call's.
    let new = count(|t| unsafe { (t.accept4)(n, pointer, lenp, SOCK_NONBLOCK) as isize })? as c_int;
    let fd = publish(new)?;
    let true_len = match out {
        Some(out) => fast_events::cut_address(&room, len as usize, out),
        None => 0,
    };
    Ok((fd, true_len))
}

fn name(fd: i32, peer: bool, out: &mut [u8]) -> Result<usize, i32> {
    let n = match route(fd)? {
        Route::Stack(n) => n,
        Route::Ticket(i) if !peer => {
            let address = tickets(|t| t.name(i));
            return Ok(fast_events::cut_address(&address, address.len(), out));
        }
        Route::Ticket(_) => return Err(ENOTCONN),
    };
    let mut room = [0u8; fast_events::SOCKADDR_ROOM];
    let mut len = room.len() as u32;
    let pointer = room.as_mut_ptr();
    // SAFETY: the table's function; the buffer and its length are this call's.
    count(|t| unsafe {
        if peer {
            (t.getpeername)(n, pointer, &raw mut len) as isize
        } else {
            (t.getsockname)(n, pointer, &raw mut len) as isize
        }
    })?;
    Ok(fast_events::cut_address(&room, len as usize, out))
}

pub fn getsockname(fd: i32, out: &mut [u8]) -> Result<usize, i32> {
    name(fd, false, out)
}

pub fn getpeername(fd: i32, out: &mut [u8]) -> Result<usize, i32> {
    name(fd, true, out)
}

pub fn getsockopt(fd: i32, level: i32, option: i32, out: &mut [u8]) -> Result<usize, i32> {
    loop {
        match route(fd)? {
            Route::Stack(n) => {
                let mut len = out.len() as u32;
                let pointer = out.as_mut_ptr();
                // SAFETY: the table's function; the buffer and its length are this call's.
                count(|t| unsafe {
                    (t.getsockopt)(n, level, option, pointer, &raw mut len) as isize
                })?;
                return Ok(len as usize);
            }
            Route::Ticket(i) => {
                let asked = on_ticket(|t| {
                    let value = t.option(i, level, option)?;
                    let room = out.first_chunk_mut::<4>().ok_or(EINVAL)?;
                    *room = value.to_ne_bytes();
                    Ok(4)
                });
                if let Some(result) = asked {
                    return result;
                }
            }
        }
    }
}

pub fn setsockopt(fd: i32, level: i32, option: i32, value: &[u8]) -> Result<(), i32> {
    with_route(
        fd,
        // SAFETY: the table's function; `value` is readable.
        |n| {
            count(|t| unsafe {
                (t.setsockopt)(n, level, option, value.as_ptr(), value.len() as u32) as isize
            })
            .map(drop)
        },
        |tickets, i| tickets.set_option(i, level, option, value),
    )
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
    // A ticket closes whatever became of it: the entry is freed, and the
    // socket of the stack, if the stack made one, closes (a ticket the stack
    // refused has none, and its number still closes with 0, as any open
    // number does).
    if let Some(Number::Ticket(i)) = classify(fd) {
        let i = i as usize;
        if !registered() {
            return Err(EBADF);
        }
        loop {
            let (used, socket) = tickets(|t| (t.slots[i].used, t.slots[i].socket));
            if !used {
                return Err(EBADF);
            }
            if !up() {
                if let Some(done) = on_ticket(|t| {
                    t.close(i);
                    Ok(())
                }) {
                    return done;
                }
                continue;
            }
            // SAFETY: the table's function.
            let closed = if socket >= 0 {
                count(|t| unsafe { (t.close)(socket) as isize }).map(drop)
            } else {
                Ok(())
            };
            tickets(|t| t.close(i));
            return closed;
        }
    }
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

/// The child of a `fork`: the tickets with `FD_CLOFORK` go.
pub fn after_fork() {
    if registered() {
        tickets(|t| t.after_fork());
        // The thread that was starting the stack is not in the child: a
        // start the parent had begun is the child's to make.
        let _ = STACK.compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire);
        STARTER.store(0, Ordering::Release);
    }
}

/// The service let go of the device and the program asked for the process
/// to end then (`EXIT_ON_LOSS`): the process ends with 2, which the main
/// process of nginx does not answer with a new worker.
pub fn exit_if_lost() {
    if lost() && table_flags() & EXIT_ON_LOSS != 0 {
        rt::println!("fast: the network service let the device go; the process ends");
        crate::exit(2);
    }
}

/// The longest the process stays on at its end for the stack's last
/// segments, and the quiet that ends the wait sooner: a stack that found no
/// work (no frame came, no work of its own was queued) for this long has
/// nothing to send that the peer's window lets it.
const DRAIN_MAX_NS: u64 = 200_000_000;
const DRAIN_QUIET_NS: u64 = 20_000_000;

/// The steps of the stack before the process ends, so that the FIN of the
/// sockets just closed and the tails of their send buffers leave: `close`
/// puts them in the ring, and the doorbell rings at the end of a step. A
/// socket that is closed while the peer has not yet taken all its data keeps
/// the rest in the stack, which dies with the process, so the steps go on
/// while the peer's acknowledgements keep the stack at work, for at most
/// `DRAIN_MAX_NS` and until `DRAIN_QUIET_NS` pass without work. Nothing
/// waits for the peer's answers to the FIN. They do not run after the
/// service let go.
pub fn last_pass() {
    if !(registered() && up() && !lost()) {
        return;
    }
    let started = wait::now();
    let mut quiet_from = started;
    loop {
        let now = wait::now();
        match pass() {
            Ok(0) => {}
            Ok(_) => quiet_from = now,
            Err(_) => return,
        }
        if lost()
            || now.saturating_sub(quiet_from) >= DRAIN_QUIET_NS
            || now.saturating_sub(started) >= DRAIN_MAX_NS
        {
            return;
        }
        core::hint::spin_loop();
    }
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
    let address = name.map(fast_events::check_inet).transpose()?;
    let (to, to_len) = match &address {
        Some(address) => (address.as_ptr(), address.len() as u32),
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
    // The sender's address goes to the layer's buffer first.
    let mut room = [0u8; fast_events::SOCKADDR_ROOM];
    let mut from_len = room.len() as u32;
    let wanted = name.is_some();
    let (from, from_pointer): (*mut u8, *mut u32) = if wanted {
        (room.as_mut_ptr(), &raw mut from_len)
    } else {
        (core::ptr::null_mut(), core::ptr::null_mut())
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
    let name_len = match name {
        Some(out) => fast_events::cut_address(&room, from_len as usize, out),
        None => 0,
    };
    Ok(crate::sockets::Message {
        count: got,
        name_len,
        flags: 0,
        control_len: 0,
    })
}

/// fcntl of a fast number: O_NONBLOCK is always on and cannot go; the
/// descriptor flags are kept nowhere (a fast socket is closed by the
/// process that made it); duplication is refused.
pub fn fcntl(fd: i32, command: c_int, argument: u64) -> Result<c_int, i32> {
    route(fd)?;
    // A ticket keeps its descriptor flags, for the fork that closes some.
    if let Some(Number::Ticket(i)) = classify(fd)
        && (command == F_GETFD || command == F_SETFD)
    {
        return tickets(|t| {
            let slot = &mut t.slots[i as usize];
            if command == F_SETFD {
                slot.cloexec = argument as c_int & FD_CLOEXEC != 0;
                slot.clofork = argument as c_int & FD_CLOFORK != 0;
                return Ok(0);
            }
            Ok(if slot.cloexec { FD_CLOEXEC } else { 0 }
                | if slot.clofork { FD_CLOFORK } else { 0 })
        });
    }
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
    let n = match route(fd)? {
        Route::Stack(n) => n,
        // A ticket has no data to read.
        Route::Ticket(_) if request == FIONREAD && !argument.is_null() => {
            // SAFETY: FIONREAD's argument is a writable int.
            unsafe { argument.cast::<c_int>().write(0) };
            return Ok(0);
        }
        Route::Ticket(_) => 0,
    };
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
    let n = match route(fd)? {
        Route::Stack(n) => n,
        Route::Ticket(i) => i as c_int,
    };
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

// The branches of the common entries (`close`, `read`, `write`, `lseek`,
// `dup*`) for a fast number stand in functions of their own: out of line and
// cold, so that the path of every other program stays a comparison and a
// tail call.

#[cold]
#[inline(never)]
pub fn close_cold(fd: i32) -> Result<(), i32> {
    close(fd)
}

#[cold]
#[inline(never)]
pub fn read_cold(fd: i32, out: &mut [u8]) -> Result<usize, i32> {
    read(fd, out)
}

#[cold]
#[inline(never)]
pub fn write_cold(fd: i32, bytes: &[u8]) -> Result<usize, i32> {
    write(fd, bytes)
}

#[cold]
#[inline(never)]
pub fn lseek_cold(fd: i32) -> Result<i64, i32> {
    Err(unsupported(fd))
}

#[cold]
#[inline(never)]
pub fn dup_cold(fd: i32) -> Result<c_int, i32> {
    Err(refuse_copy(fd))
}

#[cold]
#[inline(never)]
pub fn dup2_cold(source: i32, target: i32) -> Result<c_int, i32> {
    Err(refuse_dup(source, target))
}
