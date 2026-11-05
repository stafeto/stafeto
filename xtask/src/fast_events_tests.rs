// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Host checks of the fast sockets (`lib/posix-abi/src/fast_events.rs`,
//! `fastnet.rs`): the numbers above the table of descriptors, the translation
//! between epoll and the kqueue of the stack, and the places where the layer
//! sends a call to the stack.

use crate::fast_events::*;
use std::fs;
use std::path::Path;

#[test]
fn the_numbers_are_classified_by_range() {
    assert_eq!(classify(0), None);
    assert_eq!(classify(1023), None);
    assert_eq!(classify(FAST_BASE - 1), None);
    assert_eq!(classify(FAST_BASE), Some(Number::Socket(0)));
    assert_eq!(
        classify(FAST_BASE + FAST_MAX - 1),
        Some(Number::Socket(FAST_MAX - 1))
    );
    assert_eq!(classify(FAST_BASE + FAST_MAX), Some(Number::Ticket(0)));
    assert_eq!(
        classify(FAST_BASE + FAST_MAX + FAST_TICKETS - 1),
        Some(Number::Ticket(FAST_TICKETS - 1))
    );
    assert_eq!(classify(FAST_BASE + FAST_MAX + FAST_TICKETS), None);
    assert_eq!(classify(i32::MAX), None);
    assert_eq!(classify(-1), None);
    assert!(is_fast(FAST_BASE) && !is_fast(FAST_BASE - 1));
    // The table of descriptors ends well below.
    assert!(FAST_BASE as usize > 1024);
}

#[test]
fn the_stack_numbers_that_do_not_fit_are_refused() {
    assert_eq!(number_of(0), Some(FAST_BASE));
    assert_eq!(number_of(FAST_MAX - 1), Some(FAST_BASE + FAST_MAX - 1));
    assert_eq!(number_of(FAST_MAX), None);
    assert_eq!(number_of(-1), None);
}

#[test]
fn an_add_makes_a_filter_for_each_kind_of_interest() {
    // nginx's connections: reading, writing, the edge.
    let (list, len) = changes(
        7,
        EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP,
        0xdead_beef_0000_0001,
    );
    assert_eq!(len, 2);
    assert_eq!(list[0].filter, EVFILT_READ);
    assert_eq!(list[1].filter, EVFILT_WRITE);
    for k in &list[..len] {
        assert_eq!(k.ident, 7);
        assert_eq!(k.udata, 0xdead_beef_0000_0001);
        assert_eq!(k.flags, EV_ADD | EV_CLEAR);
    }
    // A listener: reading by level.
    let (list, len) = changes(3, EPOLLIN, 9);
    assert_eq!(len, 1);
    assert_eq!((list[0].filter, list[0].flags), (EVFILT_READ, EV_ADD));
    // Writing alone.
    let (list, len) = changes(3, EPOLLOUT, 9);
    assert_eq!((len, list[0].filter), (1, EVFILT_WRITE));
    // The end of the stream alone asks for reading.
    let (list, len) = changes(3, EPOLLRDHUP, 9);
    assert_eq!((len, list[0].filter), (1, EVFILT_READ));
    // Nothing asked for: reading, where the end and the errors show.
    let (list, len) = changes(3, 0, 9);
    assert_eq!((len, list[0].filter), (1, EVFILT_READ));
}

#[test]
fn a_oneshot_record_is_dispatched_not_deleted() {
    let (list, len) = changes(5, EPOLLIN | EPOLLONESHOT, 1);
    assert_eq!(len, 1);
    assert_eq!(list[0].flags & EV_DISPATCH, EV_DISPATCH);
    assert_eq!(list[0].flags & EV_ONESHOT, 0);
    let (list, _) = changes(5, EPOLLIN | EPOLLET | EPOLLONESHOT, 1);
    assert_eq!(list[0].flags, EV_ADD | EV_CLEAR | EV_DISPATCH);
}

#[test]
fn a_delete_names_the_socket_and_the_filter() {
    let k = delete(11, EVFILT_WRITE);
    assert_eq!((k.ident, k.filter, k.flags), (11, EVFILT_WRITE, EV_DELETE));
}

fn event(ident: u64, filter: i16, flags: u16, udata: u64) -> Kevent {
    Kevent {
        ident,
        filter,
        flags,
        udata,
        ..Kevent::default()
    }
}

#[test]
fn each_filter_and_flag_has_its_epoll_events() {
    assert_eq!(events_of(&event(1, EVFILT_READ, 0, 0)), EPOLLIN);
    assert_eq!(
        events_of(&event(1, EVFILT_READ, EV_EOF, 0)),
        EPOLLIN | EPOLLRDHUP
    );
    assert_eq!(events_of(&event(1, EVFILT_WRITE, 0, 0)), EPOLLOUT);
    assert_eq!(
        events_of(&event(1, EVFILT_WRITE, EV_EOF, 0)),
        EPOLLOUT | EPOLLHUP
    );
    assert_eq!(events_of(&event(1, EVFILT_READ, EV_ERROR, 0)), EPOLLERR);
    assert_eq!(
        events_of(&event(1, EVFILT_WRITE, EV_ERROR | EV_EOF, 0)),
        EPOLLERR
    );
    // A filter the layer never adds gives nothing.
    assert_eq!(events_of(&event(1, -4, 0, 0)), 0);
}

fn collect(batch: &[Kevent]) -> Vec<(u32, u64)> {
    let mut got = Vec::new();
    let n = translate(batch, |e, d| got.push((e, d)));
    assert_eq!(n, got.len());
    got
}

#[test]
fn neighbours_of_one_socket_join_into_one_event() {
    let got = collect(&[
        event(4, EVFILT_READ, 0, 77),
        event(4, EVFILT_WRITE, 0, 77),
        event(9, EVFILT_READ, EV_EOF, 88),
    ]);
    assert_eq!(got, [(EPOLLIN | EPOLLOUT, 77), (EPOLLIN | EPOLLRDHUP, 88)]);
}

#[test]
fn events_that_are_not_neighbours_or_differ_in_data_stay_apart() {
    let got = collect(&[
        event(4, EVFILT_READ, 0, 77),
        event(9, EVFILT_READ, 0, 88),
        event(4, EVFILT_WRITE, 0, 77),
    ]);
    assert_eq!(got.len(), 3);
    // The same socket with other data (a record added again): two events.
    let got = collect(&[event(4, EVFILT_READ, 0, 1), event(4, EVFILT_WRITE, 0, 2)]);
    assert_eq!(got, [(EPOLLIN, 1), (EPOLLOUT, 2)]);
    assert!(collect(&[]).is_empty());
    assert!(collect(&[event(1, -4, 0, 0)]).is_empty());
}

#[test]
fn a_kevent_is_64_bytes_with_the_fields_in_place() {
    assert_eq!(std::mem::size_of::<Kevent>(), 64);
    assert_eq!(std::mem::offset_of!(Kevent, filter), 8);
    assert_eq!(std::mem::offset_of!(Kevent, flags), 10);
    assert_eq!(std::mem::offset_of!(Kevent, fflags), 12);
    assert_eq!(std::mem::offset_of!(Kevent, data), 16);
    assert_eq!(std::mem::offset_of!(Kevent, udata), 24);
}

fn text(path: &str) -> String {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    fs::read_to_string(repo.join(path)).unwrap()
}

/// The text of the function that starts at the line with `signature`: up to
/// the next line that starts with `}` at the margin.
fn body<'a>(source: &'a str, signature: &str) -> &'a str {
    let at = source
        .find(signature)
        .unwrap_or_else(|| panic!("no {signature}"));
    let rest = &source[at..];
    let end = rest.find("\n}\n").unwrap_or(rest.len());
    &rest[..end]
}

/// Every call of the table runs under the lock: the table is reached only
/// through `locked` (and the start of the stack), and `locked` takes
/// `FAST_LOCK` before it calls.
#[test]
fn every_call_of_the_table_is_under_the_lock() {
    let source = text("lib/posix-abi/src/fastnet.rs");
    let locked = body(&source, "fn locked<R>(");
    assert!(
        locked.contains("let _guard = FAST_LOCK.lock();"),
        "locked does not take FAST_LOCK"
    );
    assert!(locked.find("FAST_LOCK.lock()") < locked.find("Ok(f(t))"));
    assert_eq!(source.matches("FAST_LOCK.lock()").count(), 1);
    // `table()` is read by `locked`, `ensure_stack` (outside the lock, since
    // the claim sleeps) and `table_flags`, and nowhere else.
    let readers = source
        .lines()
        .filter(|l| l.contains("table()") && !l.trim_start().starts_with("//"))
        .count();
    assert_eq!(readers, 4, "the table is read in an unexpected place");
    // The function pointers are called only inside closures given to
    // `locked` or `count`, or in `ensure_stack`.
    for (n, line) in source.lines().enumerate() {
        let code = line.split("//").next().unwrap();
        if code.contains("(t.start)") {
            assert!(
                body(&source, "pub fn ensure_stack()").contains(code.trim()),
                "line {}",
                n + 1
            );
        }
    }
}

/// The calls that reach the stack: each function of the layer starts
/// with a test for the fast numbers (or `takes`, for `socket`).
#[test]
fn every_routed_call_has_its_branch() {
    let routes: &[(&str, &[&str])] = &[
        (
            "lib/posix-abi/src/sockets.rs",
            &[
                "pub fn socket(",
                "pub fn bind(",
                "pub fn listen(",
                "pub fn connect(",
                "pub fn accept(",
                "pub fn getsockname(",
                "pub fn getpeername(",
                "pub fn getsockopt(",
                "pub fn setsockopt(",
                "pub fn shutdown(",
                "pub fn sockatmark(",
                "pub fn send(",
                "pub fn recv(",
            ],
        ),
        (
            "lib/posix-abi/src/lib.rs",
            &[
                "pub fn close(",
                "pub fn read(",
                "pub fn write(",
                "pub fn lseek(",
                "pub fn dup(",
                "pub fn dup2(",
                "pub fn dup3(",
            ],
        ),
        ("lib/posix-abi/src/epoll.rs", &["pub fn ctl("]),
        ("lib/posix-abi/src/wait.rs", &["pub fn poll("]),
        ("lib/posix-abi/src/names.rs", &["pub fn fstatat("]),
        (
            "lib/posix-platform/src/files.rs",
            &[
                "pub extern \"C\" fn stafeto_fcntl(",
                "pub unsafe extern \"C\" fn stafeto_ioctl(",
                "pub unsafe extern \"C\" fn stafeto_pread(",
                "pub unsafe extern \"C\" fn stafeto_pwrite(",
            ],
        ),
        (
            "lib/posix-platform/src/sockets.rs",
            &["pub unsafe extern \"C\" fn stafeto_writev_socket("],
        ),
    ];
    for (file, signatures) in routes {
        let source = text(file);
        for signature in *signatures {
            let function = body(&source, signature);
            assert!(
                function.contains("fastnet::"),
                "{file}: {signature} has no branch for the fast numbers"
            );
        }
    }
    // The wait of epoll drives the stack for an instance with fast records.
    let epoll = text("lib/posix-abi/src/epoll.rs");
    assert!(body(&epoll, "pub fn pwait(").contains("pwait_fast"));
}

/// The loop of the stack notifies before it looks once more, and the wait
/// that sleeps asks the bank before each receive.
#[test]
fn the_idle_loop_turns_the_interrupts_on_and_asks_the_bank() {
    let source = text("lib/posix-abi/src/epoll.rs");
    let round = body(&source, "fn fast_round(");
    let on = round.find("fastnet::notify(true)").expect("notify on");
    let look = round[on..].find("look(").expect("a look after notify");
    let sleep = round.find("Some(fast_wake)").expect("the wake test");
    assert!(on < on + look && on + look < sleep);
    assert!(round.contains("fastnet::notify(false)"));
    let wait = text("lib/posix-abi/src/wait.rs");
    let run = body(&wait, "fn run_waking(");
    assert!(run.matches("wake.is_some_and(|w| w())").count() >= 2);
    let before_receive = run.find("crate::fast::receive(&channel)").expect("receive");
    assert!(
        run[..before_receive]
            .rfind("wake.is_some_and(|w| w())")
            .is_some()
    );
}

fn sockaddr_in(len: usize, family: u16) -> Vec<u8> {
    let mut a = vec![0u8; len];
    if len >= 2 {
        a[..2].copy_from_slice(&family.to_ne_bytes());
    }
    a
}

#[test]
fn an_address_for_the_stack_is_16_bytes_of_the_inet_family() {
    // Lengths below 16, and none at all, are EINVAL.
    for len in [0, 1, 2, 4, 15, 129, 200] {
        assert_eq!(
            check_inet(&sockaddr_in(len, AF_INET)),
            Err(22),
            "length {len}"
        );
    }
    // Another family is EAFNOSUPPORT.
    assert_eq!(check_inet(&sockaddr_in(16, 1)), Err(97));
    assert_eq!(check_inet(&sockaddr_in(16, 10)), Err(97));
    // 16 bytes pass whole; a longer address is cut to 16 (Linux ignores the
    // rest), so the stack never copies more than a sockaddr_in.
    let mut long = sockaddr_in(100, AF_INET);
    long[2..16].copy_from_slice(&[0x50, 0, 127, 0, 0, 1, 9, 9, 9, 9, 9, 9, 9, 9]);
    long[16] = 0xee;
    assert_eq!(check_inet(&sockaddr_in(128, AF_INET)).unwrap().len(), 16);
    let got = check_inet(&long).unwrap();
    assert_eq!(got.len(), SOCKADDR_IN);
    assert_eq!(&got[..], &long[..16]);
    assert_eq!(check_inet(&sockaddr_in(16, AF_INET)).unwrap().len(), 16);
}

#[test]
fn an_address_written_by_the_stack_is_cut_to_the_programs_length() {
    let mut have = [0xaau8; SOCKADDR_ROOM];
    have[..16].copy_from_slice(&[2, 0, 0x1f, 0x90, 10, 0, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0]);
    // Room enough: 16 bytes, the true length 16.
    let mut big = [0xffu8; 32];
    assert_eq!(cut_address(&have[..16], 16, &mut big), 16);
    assert_eq!(&big[..16], &have[..16]);
    assert_eq!(&big[16..], &[0xff; 16]);
    // Four bytes of room: four are written, the guard behind stays, and the
    // true length 16 comes back.
    let mut small = [0xffu8; 8];
    assert_eq!(cut_address(&have, 16, &mut small[..4]), 16);
    assert_eq!(&small[..4], &have[..4]);
    assert_eq!(&small[4..], &[0xff; 4]);
    // No room at all: nothing is written.
    let mut none: [u8; 0] = [];
    assert_eq!(cut_address(&have, 16, &mut none), 16);
}

#[test]
fn one_unsigned_compare_splits_the_table_from_the_rest() {
    // Below the table: false. A fast number and a negative one (which the
    // cold branch answers with EBADF): true.
    assert!(!above_table(0));
    assert!(!above_table(1023));
    assert!(!above_table(FAST_BASE - 1));
    assert!(above_table(FAST_BASE));
    assert!(above_table(FAST_BASE + FAST_MAX + FAST_TICKETS));
    assert!(above_table(-1));
    assert!(above_table(i32::MIN));
}
