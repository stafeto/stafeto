// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Host checks of the fast sockets (`lib/posix-abi/src/fast_events.rs`,
//! `fastnet.rs`): the numbers above the table of descriptors, the translation
//! between epoll and the kqueue of the stack, and the places where the layer
//! sends a call to the stack.

use crate::fast_events::*;
use crate::fast_tickets::*;
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
    // The other place is the making of the tickets' sockets at the start of the
    // stack, which holds the lock for each socket it makes.
    assert_eq!(source.matches("FAST_LOCK.lock()").count(), 2);
    let making = body(&source, "fn make_sockets(");
    assert!(making.find("FAST_LOCK.lock()") < making.find("make_socket(t,"));
    assert_eq!(source.matches("make_socket(t,").count(), 1);
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
    // Both waits return the events they hold when the boundary says EINTR.
    assert!(body(&epoll, "pub fn pwait(").contains("Err(EINTR) if held > 0"));
    assert!(body(&epoll, "fn pwait_fast(").contains("Err(EINTR) if held > 0"));
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
    let run = body(&wait, "pub(crate) fn turn(");
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

// ------------------------------------------------------------- the tickets

fn address(port: u16, host: [u8; 4]) -> [u8; SOCKADDR_IN] {
    let mut a = [0u8; SOCKADDR_IN];
    a[0] = AF_INET as u8;
    a[2..4].copy_from_slice(&port.to_be_bytes());
    a[4..8].copy_from_slice(&host);
    a
}

#[test]
fn sixteen_tickets_and_no_more() {
    let mut t = Tickets::new();
    for i in 0..FAST_TICKETS as usize {
        assert_eq!(t.open(false, false), Ok(i));
    }
    assert_eq!(t.open(false, false), Err(24));
    t.close(5);
    assert_eq!(t.open(false, false), Ok(5));
}

#[test]
fn an_address_in_use_by_another_ticket_is_refused() {
    let mut t = Tickets::new();
    let a = t.open(false, false).unwrap();
    let b = t.open(false, false).unwrap();
    assert_eq!(t.bind(a, address(80, [0; 4])), Ok(()));
    // The same port, the same or another address under a wildcard: in use.
    assert_eq!(t.bind(b, address(80, [0; 4])), Err(98));
    assert_eq!(t.bind(b, address(80, [10, 0, 3, 15])), Err(98));
    assert_eq!(t.bind(b, address(81, [0; 4])), Ok(()));
    // A second bind of one ticket is EINVAL.
    assert_eq!(t.bind(b, address(82, [0; 4])), Err(22));
    // Port 0 never conflicts.
    let c = t.open(false, false).unwrap();
    let d = t.open(false, false).unwrap();
    assert_eq!(t.bind(c, address(0, [0; 4])), Ok(()));
    assert_eq!(t.bind(d, address(0, [0; 4])), Ok(()));
    // Both with SO_REUSEPORT share a port, one without does not.
    let e = t.open(false, false).unwrap();
    let f = t.open(false, false).unwrap();
    let g = t.open(false, false).unwrap();
    let on = 1i32.to_ne_bytes();
    t.set_option(e, 1, SO_REUSEPORT, &on).unwrap();
    t.set_option(f, 1, SO_REUSEPORT, &on).unwrap();
    assert_eq!(t.bind(e, address(8080, [0; 4])), Ok(()));
    assert_eq!(t.bind(f, address(8080, [0; 4])), Ok(()));
    assert_eq!(t.bind(g, address(8080, [0; 4])), Err(98));
    // A closed ticket frees its address.
    t.close(a);
    let h = t.open(false, false).unwrap();
    assert_eq!(h, a);
    assert_eq!(t.bind(h, address(80, [0; 4])), Ok(()));
}

#[test]
fn the_last_listen_wins_and_the_options_are_kept() {
    let mut t = Tickets::new();
    let a = t.open(false, false).unwrap();
    t.listen(a, 511);
    t.listen(a, 128);
    assert_eq!(t.slots[a].backlog, Some(128));
    t.set_option(a, 1, SO_REUSEADDR, &1i32.to_ne_bytes())
        .unwrap();
    t.set_option(a, 6, TCP_KEEPIDLE, &30i32.to_ne_bytes())
        .unwrap();
    assert_eq!(t.option(a, 1, SO_REUSEADDR), Ok(1));
    assert_eq!(t.option(a, 6, TCP_KEEPIDLE), Ok(30));
    // Not set: zero, and a default for the buffers.
    assert_eq!(t.option(a, 6, TCP_NODELAY), Ok(0));
    assert_eq!(t.option(a, 1, SO_RCVBUF), Ok(65_536));
    // The type and the error come from the record.
    assert_eq!(t.option(a, 1, SO_TYPE), Ok(1));
    assert_eq!(t.option(a, 1, SO_ERROR), Ok(0));
    // What the table does not name, and a value too short.
    assert_eq!(t.set_option(a, 6, 3, &1i32.to_ne_bytes()), Err(92));
    assert_eq!(t.option(a, 1, 1234), Err(92));
    assert_eq!(t.set_option(a, 1, SO_REUSEADDR, &[1, 0]), Err(22));
}

#[test]
fn the_name_of_a_ticket_is_its_address_or_the_wildcard() {
    let mut t = Tickets::new();
    let a = t.open(false, false).unwrap();
    assert_eq!(t.name(a), address(0, [0; 4]));
    t.bind(a, address(443, [0; 4])).unwrap();
    assert_eq!(t.name(a), address(443, [0; 4]));
}

#[test]
fn a_fork_closes_the_tickets_with_fd_clofork_only() {
    let mut t = Tickets::new();
    let keep = t.open(true, false).unwrap();
    let go = t.open(false, true).unwrap();
    t.after_fork();
    assert!(t.slots[keep].used && t.slots[keep].cloexec);
    assert!(!t.slots[go].used);
}

#[test]
fn a_ticket_the_stack_refused_keeps_the_errno() {
    let mut t = Tickets::new();
    let a = t.open(false, false).unwrap();
    assert_eq!(t.slots[a].socket, NOT_MADE);
    t.refuse(a, 98);
    assert_eq!((t.slots[a].socket, t.slots[a].error), (REFUSED, 98));
}

/// The stack starts without the signals ending it, and the sockets of the
/// tickets are made before the state turns to "up".
#[test]
fn the_start_of_the_stack_is_steady_and_makes_the_tickets_first() {
    let source = text("lib/posix-abi/src/fastnet.rs");
    let start = body(&source, "pub fn ensure_stack()");
    assert!(start.contains("fast::claim_steady("));
    assert!(!start.contains("fast::claim("));
    let made = start.find("make_sockets(t, tickets)").expect("sockets");
    let up = start.find("STACK.store(2").expect("up");
    assert!(made < up);
    // A handler on the thread that is starting the stack does not wait for it.
    assert!(start.contains("return Err(EAGAIN)"));
    let fast = text("lib/posix-abi/src/fast.rs");
    assert!(body(&fast, "fn pause(").contains("if !steady"));
    assert!(body(&fast, "pub fn claim(").contains("claim_with(out, flags, false)"));
    assert!(body(&fast, "pub fn claim_steady(").contains("claim_with(out, flags, true)"));
}

/// `socket` before the stack makes a ticket and starts nothing; `accept`,
/// `connect` and `epoll_ctl` start the stack.
#[test]
fn only_accept_connect_and_epoll_ctl_start_the_stack() {
    let source = text("lib/posix-abi/src/fastnet.rs");
    assert!(!body(&source, "pub fn socket(").contains("ensure_stack"));
    assert!(body(&source, "pub fn accept(").contains("stack_of(fd)"));
    assert!(body(&source, "pub fn connect(").contains("stack_of(fd)"));
    assert_eq!(
        source
            .lines()
            .filter(|l| {
                l.contains("ensure_stack()")
                    && !l.trim_start().starts_with("//")
                    && !l.contains("pub fn")
            })
            .count(),
        1,
        "only stack_of starts the stack"
    );
    let epoll = text("lib/posix-abi/src/epoll.rs");
    assert!(body(&epoll, "fn ctl_fast(").contains("fastnet::stack_of(fd)"));
}

/// The end of the process gives the stack one last step, and a service that
/// let go ends the process with 2 when the program asked.
#[test]
fn the_process_ends_with_a_last_step_and_on_loss() {
    let abi = text("lib/posix-abi/src/lib.rs");
    let exit = body(&abi, "pub fn exit(");
    assert!(exit.find("fastnet::last_pass()") < exit.find("process_exit"));
    let net = text("lib/posix-abi/src/fastnet.rs");
    let last = body(&net, "pub fn last_pass()");
    assert!(last.contains("up()") && last.contains("!lost()") && last.contains("pass()"));
    let exit_if = body(&net, "pub fn exit_if_lost()");
    assert!(exit_if.contains("EXIT_ON_LOSS") && exit_if.contains("crate::exit(2)"));
    let epoll = text("lib/posix-abi/src/epoll.rs");
    assert!(body(&epoll, "fn fast_round(").contains("fastnet::exit_if_lost()"));
    let glue = text("ports/f-stack/ff_stafeto_glue.c");
    assert!(glue.contains(".flags = STAFETO_FAST_EXIT_ON_LOSS"));
    // The child of a fork closes the tickets with FD_CLOFORK.
    let fork = text("lib/posix-abi/src/fork.rs");
    assert!(fork.contains("crate::fastnet::after_fork()"));
}

/// The loop keeps its subscriptions for the call and makes them again only
/// when the records change.
#[test]
fn the_loop_keeps_its_subscriptions_for_the_call() {
    let epoll = text("lib/posix-abi/src/epoll.rs");
    let pwait = body(&epoll, "fn pwait_fast(");
    assert!(pwait.contains("Sharing::new()") && pwait.contains("sharing.end()"));
    let round = body(&epoll, "fn fast_round(");
    assert!(!round.contains("round_once("));
    assert_eq!(round.matches("sharing.turn(").count(), 2);
    let turn = body(&epoll, "fn turn(");
    assert!(turn.contains("same_records(old, &fresh)"));
    assert!(turn.contains(".build(&fresh.items"));
}

/// The wait on the service's set asks for what the turn has room for.
#[test]
fn each_turn_fits_the_pairs_of_the_service_to_its_room() {
    let epoll = text("lib/posix-abi/src/epoll.rs");
    let turn = body(&epoll, "fn turn(");
    let fit = turn.find("net.fit(most as u32)").expect("fit");
    let run = turn.find("watching.turn(").expect("turn");
    assert!(fit < run);
    let wait = text("lib/posix-abi/src/wait.rs");
    let fits = body(&wait, "pub fn fit(");
    // A started operation that asks for more than the room is cancelled.
    assert!(fits.contains("most < self.most") && fits.contains("self.cancel()"));
}

/// The close of a ticket frees the entry whatever the stack made of it.
#[test]
fn a_ticket_the_stack_refused_still_closes() {
    let source = text("lib/posix-abi/src/fastnet.rs");
    let close = body(&source, "pub fn close(fd: i32)");
    let ticket = close.find("Number::Ticket(i)").expect("ticket branch");
    let route = close.find("route(").unwrap_or(usize::MAX);
    assert!(ticket < route, "the ticket branch asks the route first");
    assert!(close.contains("tickets(|t| t.close(i))"));
    assert!(!close.contains("number(fd)?;\n    // SAFETY: the table's function.\n    let closed"));
}

/// Both hangs of the lazy start are closed.
#[test]
fn the_start_marks_its_thread_in_one_step_and_a_fork_clears_it() {
    let source = text("lib/posix-abi/src/fastnet.rs");
    let start = body(&source, "pub fn ensure_stack()");
    let enter = start.find("posix_sync::enter()").expect("enter");
    let swap = start.find("compare_exchange(0, 1").expect("exchange");
    let mark = start.find("STARTER.store(own_channel()").expect("mark");
    let leave = start.find("posix_sync::leave()").expect("leave");
    assert!(enter < swap && swap < mark && mark < leave);
    let fork = body(&source, "pub fn after_fork()");
    assert!(fork.contains("compare_exchange(1, 0"));
    assert!(fork.contains("STARTER.store(0"));
}

/// The probe counts the builds of the loop's waits, and the layer exports it.
#[test]
fn the_builds_of_the_waits_are_counted_for_the_probe() {
    let wait = text("lib/posix-abi/src/wait.rs");
    assert!(body(&wait, "pub(crate) fn build(").contains("BUILDS.fetch_add"));
    let platform = text("lib/posix-platform/src/lib.rs");
    assert!(platform.contains("pub extern \"C\" fn stafeto_probe_watch_builds()"));
    let probe = text("tests/fstack-probe/layer.c");
    assert!(probe.contains("stafeto_probe_watch_builds() - before == 1"));
    assert!(probe.contains("stafeto_probe_watch_builds() - before == 2"));
}
