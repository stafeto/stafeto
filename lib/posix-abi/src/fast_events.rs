// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The numbers of the fast sockets and the translation between epoll and
//! the kqueue of the stack (spec 6, 3.9). Nothing here calls the kernel or
//! the stack, so the host tests run it (`xtask`, `fast_events_tests`).

/// The first number of a fast socket: above every number of the table of
/// descriptors (`posix_fs::OPEN_MAX`).
pub const FAST_BASE: i32 = 1 << 20;
/// The sockets of the stack: the number `n` of F-Stack is seen as
/// `FAST_BASE + n`, `n` below this.
pub const FAST_MAX: i32 = 262_144;
/// The tickets of the listeners the main process opens before the stack
/// starts: `FAST_BASE + FAST_MAX + i`.
pub const FAST_TICKETS: i32 = 16;

/// What a number above the table names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Number {
    /// The socket `n` of the stack.
    Socket(i32),
    /// The ticket `i` of a listener.
    Ticket(i32),
}

/// Whether `fd` is above the table of descriptors.
#[inline(always)]
pub fn is_fast(fd: i32) -> bool {
    fd >= FAST_BASE
}

/// The socket or ticket a number names, `None` outside both ranges.
pub fn classify(fd: i32) -> Option<Number> {
    let offset = fd.checked_sub(FAST_BASE)?;
    if offset < 0 {
        None
    } else if offset < FAST_MAX {
        Some(Number::Socket(offset))
    } else if offset - FAST_MAX < FAST_TICKETS {
        Some(Number::Ticket(offset - FAST_MAX))
    } else {
        None
    }
}

/// The number the program sees for the socket `n` of the stack, `None` when
/// the stack gave a number the range cannot hold.
pub fn number_of(n: i32) -> Option<i32> {
    (0..FAST_MAX).contains(&n).then_some(FAST_BASE + n)
}

// The filters and flags of the kqueue of FreeBSD.
pub const EVFILT_READ: i16 = -1;
pub const EVFILT_WRITE: i16 = -2;
pub const EV_ADD: u16 = 0x0001;
pub const EV_DELETE: u16 = 0x0002;
pub const EV_ONESHOT: u16 = 0x0010;
pub const EV_CLEAR: u16 = 0x0020;
pub const EV_DISPATCH: u16 = 0x0080;
pub const EV_ERROR: u16 = 0x4000;
pub const EV_EOF: u16 = 0x8000;

// The bits of the events of epoll (`proto_net::sockets::epoll`; `epoll.rs`
// asserts the equality).
pub const EPOLLIN: u32 = 0x1;
pub const EPOLLOUT: u32 = 0x4;
pub const EPOLLERR: u32 = 0x8;
pub const EPOLLHUP: u32 = 0x10;
pub const EPOLLRDHUP: u32 = 0x2000;
pub const EPOLLET: u32 = 1 << 31;
pub const EPOLLONESHOT: u32 = 1 << 30;

/// `struct kevent` of FreeBSD 15: 64 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Kevent {
    pub ident: u64,
    pub filter: i16,
    pub flags: u16,
    pub fflags: u32,
    pub data: i64,
    pub udata: u64,
    pub ext: [u64; 4],
}

const _: () = assert!(core::mem::size_of::<Kevent>() == 64);

/// The changes that make a record of `events` and `data` on socket `n`:
/// one for each filter, `EV_ADD`, with `EV_CLEAR` for an edge and
/// `EV_DISPATCH` for a oneshot (`EV_ONESHOT` would delete the record). A
/// record that asks for neither reading nor writing still watches reading,
/// where the end of the stream and the errors show.
pub fn changes(n: i32, events: u32, data: u64) -> ([Kevent; 2], usize) {
    let mut flags = EV_ADD;
    if events & EPOLLET != 0 {
        flags |= EV_CLEAR;
    }
    if events & EPOLLONESHOT != 0 {
        flags |= EV_DISPATCH;
    }
    let make = |filter| Kevent {
        ident: n as u64,
        filter,
        flags,
        udata: data,
        ..Kevent::default()
    };
    let read = events & (EPOLLIN | EPOLLRDHUP) != 0;
    let write = events & EPOLLOUT != 0;
    let mut list = [Kevent::default(); 2];
    let mut len = 0;
    if read || !write {
        list[len] = make(EVFILT_READ);
        len += 1;
    }
    if write {
        list[len] = make(EVFILT_WRITE);
        len += 1;
    }
    (list, len)
}

/// The change that deletes the filter of socket `n`.
pub fn delete(n: i32, filter: i16) -> Kevent {
    Kevent {
        ident: n as u64,
        filter,
        flags: EV_DELETE,
        ..Kevent::default()
    }
}

/// The events of one kevent as epoll has them (the design of the second device): reading
/// is `EPOLLIN`, and with the end of the stream also `EPOLLRDHUP`; writing
/// is `EPOLLOUT`, and with the end `EPOLLHUP`; an error of the record is
/// `EPOLLERR`.
pub fn events_of(k: &Kevent) -> u32 {
    if k.flags & EV_ERROR != 0 {
        return EPOLLERR;
    }
    let end = k.flags & EV_EOF != 0;
    match k.filter {
        EVFILT_READ if end => EPOLLIN | EPOLLRDHUP,
        EVFILT_READ => EPOLLIN,
        EVFILT_WRITE if end => EPOLLOUT | EPOLLHUP,
        EVFILT_WRITE => EPOLLOUT,
        _ => 0,
    }
}

/// Calls `push(events, data)` for the events of `batch`; two events in a
/// row for the same socket and the same data join into one. Returns how
/// many it pushed.
pub fn translate(batch: &[Kevent], mut push: impl FnMut(u32, u64)) -> usize {
    let mut pushed = 0;
    let mut held: Option<(u64, u64, u32)> = None;
    for k in batch {
        let events = events_of(k);
        if events == 0 {
            continue;
        }
        match held {
            Some((ident, data, ref mut joined)) if ident == k.ident && data == k.udata => {
                *joined |= events;
            }
            _ => {
                if let Some((_, data, joined)) = held {
                    push(joined, data);
                    pushed += 1;
                }
                held = Some((k.ident, k.udata, events));
            }
        }
    }
    if let Some((_, data, joined)) = held {
        push(joined, data);
        pushed += 1;
    }
    pushed
}
