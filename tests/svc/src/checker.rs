// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The role `checker` (main.rs): the client of init's test table that
//! tests init as a service manager (spec 13.4, 15.2) through its
//! connection to init and the sessions CONNECT gives it: its start data,
//! START past LAST, PING and HEARTBEAT, REGISTER from a client, CONNECT
//! to services that registered, to one that registers later and past four
//! waiting requests, and to names the table does not give it, what the
//! REGISTER of `device` brought, the restarts of `crash` until it is
//! broken, the wait of `hog` for quota, LIST and STATS. LIST and STATS
//! come once `crash` is broken, when no record starts again. It prints
//! `TEST <name> ok` or `TEST <name> FAIL <why>` for each test in turn,
//! then `TESTS DONE total=<n> failed=<m>`, and ends with code 0; xtask
//! reads the lines, and init's line of its end.

use crate::device::{BINDING, BINDING_COPIES, EDGE, Report, WINDOW, WINDOW_COPIES};
use crate::{CHECKER, ECHO, VERSION, base, method};
use abi::{
    Error, MESSAGE_MAX, ObjectKind, Policy, ProcessHandles, ProcessMemory, Rights, Source,
    ThreadState,
};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use proto_init::{
    Connect, LIST_PAGE, ListReply, ListRequest, Method, Record as Listed, ServiceArgs, State, Stats,
};
use proto_wire::{Header, Name, Reader, Status, Writer};
use rt::handle::{Channel, Resource, Thread};
use rt::startup::Startup;
use rt::sys::{self, Received};
use rt::wait::{Waited, Waiter};
use rt::{Handle, Stack, println, time};

type Outcome = Result<(), &'static str>;

/// A test's name and body.
type Test = (&'static str, fn(&Checker) -> Outcome);

/// The tests in the order they run. The helpers of
/// `a_fifth_waiting_connect_gets_limit_reached` wait for `slow`, which
/// registers once the checker opens the gate of `echo`, and
/// `connect_waits_for_registration` opens it and collects them.
const TESTS: [Test; 18] = [
    (
        "start_data_brings_the_service_args",
        start_data_brings_the_service_args,
    ),
    ("start_after_last_is_refused", start_after_last_is_refused),
    (
        "ping_is_answered_and_a_client_has_no_heartbeat",
        ping_is_answered_and_a_client_has_no_heartbeat,
    ),
    (
        "register_from_a_client_is_refused",
        register_from_a_client_is_refused,
    ),
    (
        "a_fifth_waiting_connect_gets_limit_reached",
        a_fifth_waiting_connect_gets_limit_reached,
    ),
    (
        "connect_gives_a_working_session",
        connect_gives_a_working_session,
    ),
    (
        "each_connect_makes_a_new_session",
        each_connect_makes_a_new_session,
    ),
    (
        "connect_to_a_name_the_table_denies_is_refused",
        connect_to_a_name_the_table_denies_is_refused,
    ),
    (
        "register_brings_windows_and_bindings",
        register_brings_windows_and_bindings,
    ),
    (
        "register_refuses_receive_and_a_second_time",
        register_refuses_receive_and_a_second_time,
    ),
    (
        "connect_waits_for_registration",
        connect_waits_for_registration,
    ),
    (
        "crash_is_broken_after_five_failures",
        crash_is_broken_after_five_failures,
    ),
    (
        "connect_to_a_broken_service_is_peer_closed",
        connect_to_a_broken_service_is_peer_closed,
    ),
    (
        "a_record_without_quota_waits_and_is_not_broken",
        a_record_without_quota_waits_and_is_not_broken,
    ),
    (
        "list_names_every_record_in_its_state",
        list_names_every_record_in_its_state,
    ),
    (
        "list_pages_from_its_first_entry",
        list_pages_from_its_first_entry,
    ),
    (
        "list_counts_the_handles_and_memory_of_an_instance",
        list_counts_the_handles_and_memory_of_an_instance,
    ),
    (
        "stats_bring_the_kernel_the_worker_and_the_quota",
        stats_bring_the_kernel_the_worker_and_the_quota,
    ),
];

const MS: u64 = 1_000_000;
/// The heartbeat and the watchdog of `echo` in init's test table.
const ECHO_PERIOD_NS: u64 = 20 * MS;
const ECHO_DEADLINE_NS: u64 = 100 * MS;
/// The bound of a wait for the helpers.
const BOUND_NS: u64 = 2000 * MS;
/// The line of the PL031 and its PeriphID0 and PeriphID1.
const RTC_LINE: u32 = 34;
const RTC_IDS: [u32; 2] = [0x31, 0x10];
/// The bytes ECHO sends.
const HELLO: &[u8] = b"hello";
/// The records LIST gives: init, then the records of init's test table in
/// its order, each with its priority, its ceiling and whether it is a
/// client.
const RECORDS: [(&str, u8, u8, bool); 8] = [
    ("init", 63, 63, false),
    ("echo", 40, 40, false),
    ("slow", 40, 40, false),
    ("device", 40, 40, false),
    ("crash", 35, 35, false),
    ("checker", 30, 30, true),
    ("private", 20, 20, false),
    ("hog", 20, 20, false),
];
/// The records that do not run with no failure once `crash` is broken:
/// their state, their failures within 60 s and their restarts.
const NOT_RUNNING: [(&str, State, u8, u32); 2] =
    [("crash", State::Broken, 5, 4), ("hog", State::Quota, 0, 0)];
/// The level of init's worker thread with no job.
const WORKER_IDLE: u8 = 1;
const PAGE: u64 = 4096;

/// The helper threads of the checker, each with its stack and its message
/// buffer above that of the first thread.
const HELPERS: usize = 4;
static STACKS: [Stack<8192>; HELPERS] = [const { Stack::new() }; HELPERS];
/// What each helper saw: whether its CONNECT came back, and whether ECHO
/// worked through the session it got.
static CAME: [AtomicBool; HELPERS] = [const { AtomicBool::new(false) }; HELPERS];
static ECHOED: [AtomicBool; HELPERS] = [const { AtomicBool::new(false) }; HELPERS];
/// The values of the helpers' threads and of the channel they notify when
/// they are done, bit i for helper i.
static THREADS: [AtomicU64; HELPERS] = [const { AtomicU64::new(0) }; HELPERS];
static DONE: AtomicU64 = AtomicU64::new(0);

/// What the tests share: the checker's start data, when it started and
/// the failures of `crash` then (LIST).
pub struct Checker {
    s: Startup,
    started_ns: u64,
    crash_failures: u8,
}

pub fn run(mut s: Startup) -> u64 {
    let started_ns = now_ns();
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let c = Checker {
        s,
        started_ns,
        crash_failures: 0,
    };
    let crash_failures = record(&c, "crash").map_or(0, |r| r.failures);
    let c = Checker {
        crash_failures,
        ..c
    };
    let mut failed = 0;
    for (name, test) in TESTS {
        match test(&c) {
            Ok(()) => println!("TEST {name} ok"),
            Err(why) => {
                failed += 1;
                println!("TEST {name} FAIL {why}");
            }
        }
    }
    println!("TESTS DONE total={} failed={failed}", TESTS.len());
    0
}

fn check(ok: bool, why: &'static str) -> Outcome {
    if ok { Ok(()) } else { Err(why) }
}

fn now_ns() -> u64 {
    time::ticks_to_ns(time::now())
}

/// The reply to `request` through `to`, its bytes in `buffer`, with its
/// status first; the send's error as the status.
fn call<'b>(
    to: &Handle<Channel>,
    request: &[u8],
    buffer: &'b mut [u8; MESSAGE_MAX],
) -> Result<&'b [u8], Status> {
    let reply = sys::send(to, request)?;
    let bytes = reply.bytes(buffer);
    match Status::from_code(Reader::new(bytes).u32()?) {
        Status::Ok => Ok(bytes),
        status => Err(status),
    }
}

/// The status of the reply to `request` through `to`.
fn status(to: &Handle<Channel>, request: &[u8]) -> Status {
    call(to, request, &mut [0; MESSAGE_MAX]).map_or_else(|s| s, |_| Status::Ok)
}

/// A request of the test services: the header of `method` and `body`.
fn request(method: u16, body: &[u8]) -> Writer {
    let mut w = Writer::new();
    let _ = Header::new(method, VERSION).write(&mut w);
    let _ = w.bytes(body);
    w
}

/// Whether ECHO through `session` gives its bytes back.
fn echoes(session: &Handle<Channel>) -> bool {
    let mut buffer = [0; MESSAGE_MAX];
    let reply = call(
        session,
        request(method::ECHO, HELLO).as_bytes(),
        &mut buffer,
    );
    reply.is_ok_and(|bytes| bytes.get(4..) == Some(HELLO))
}

/// The label of the session `session` as the test service sees it (LABEL).
fn label_of(session: &Handle<Channel>) -> Result<u64, &'static str> {
    let mut buffer = [0; MESSAGE_MAX];
    let reply = call(session, request(method::LABEL, &[]).as_bytes(), &mut buffer);
    let bytes = reply.map_err(|_| "LABEL was refused")?;
    let mut r = Reader::new(bytes.get(8..).ok_or("LABEL gave no label")?);
    r.u64().map_err(|_| "LABEL gave no label")
}

impl Checker {
    /// A session with the service `name` (rt::service::connect).
    fn connect(&self, name: &str) -> Result<Handle<Channel>, Status> {
        rt::service::connect(&self.s.parent, name)
    }
}

/// The start data bring ServiceArgs: 0 as the heartbeat and the watchdog
/// of a client with its own arguments, and those of `echo`'s record to
/// `echo` (ARGS).
fn start_data_brings_the_service_args(c: &Checker) -> Outcome {
    let own =
        ServiceArgs::read(c.s.args()).map_err(|_| "the checker's arguments are no ServiceArgs")?;
    check(
        own.period_ns == 0 && own.deadline_ns == 0 && own.own == [CHECKER],
        "the checker's arguments are not those of a client with its role",
    )?;
    let echo = c.connect("echo").map_err(|_| "no session with echo")?;
    let mut buffer = [0; MESSAGE_MAX];
    let reply = call(&echo, request(method::ARGS, &[]).as_bytes(), &mut buffer);
    let bytes = reply.map_err(|_| "ARGS was refused")?;
    let args = bytes.get(8..).map(ServiceArgs::read);
    let args = args
        .and_then(Result::ok)
        .ok_or("echo's arguments are no ServiceArgs")?;
    check(
        args.period_ns == ECHO_PERIOD_NS
            && args.deadline_ns == ECHO_DEADLINE_NS
            && args.own == [ECHO],
        "echo's arguments are not those of its record",
    )
}

/// The start data went with LAST: one more START gets BAD_STATE.
fn start_after_last_is_refused(c: &Checker) -> Outcome {
    let got = status(&c.s.parent, &Method::Start.header().bytes());
    check(
        got == Status::Kernel(Error::BadState),
        "a START after LAST did not get BAD_STATE",
    )
}

/// PING gets 0; HEARTBEAT of a client BAD_STATE.
fn ping_is_answered_and_a_client_has_no_heartbeat(c: &Checker) -> Outcome {
    let ping = status(&c.s.parent, &Method::Ping.header().bytes());
    check(ping == Status::Ok, "PING was not answered with 0")?;
    let beat = status(&c.s.parent, &Method::Heartbeat.header().bytes());
    check(
        beat == Status::Kernel(Error::BadState),
        "the HEARTBEAT of a client did not get BAD_STATE",
    )
}

/// REGISTER from a client gets BAD_STATE.
fn register_from_a_client_is_refused(c: &Checker) -> Outcome {
    let channel = sys::channel_create(base(&c.s)).map_err(|_| "channel_create failed")?;
    let got = rt::service::register(&c.s.parent, &channel).err();
    check(
        got == Some(Status::Kernel(Error::BadState)),
        "the REGISTER of a client did not get BAD_STATE",
    )
}

/// Four helper threads ask for `slow`, which has not registered, and wait
/// in their CONNECT; a fifth request gets LIMIT_REACHED at once. The
/// helpers go on waiting (`connect_waits_for_registration`).
fn a_fifth_waiting_connect_gets_limit_reached(c: &Checker) -> Outcome {
    let done = sys::channel_create(base(&c.s)).map_err(|_| "channel_create failed")?;
    DONE.store(done.into_raw().0, Relaxed);
    for (i, stack) in STACKS.iter().enumerate() {
        let buffer = abi::INIT_MSGBUF as usize + (i + 1) * 4096;
        // SAFETY: the stack is the helper's alone.
        let t = unsafe {
            sys::thread_create(
                &c.s.process,
                helper,
                stack.top(),
                i as u64,
                base(&c.s),
                Policy::Fifo,
                buffer,
            )
        };
        let t = t.map_err(|_| "thread_create failed")?;
        sys::thread_start(&t).map_err(|_| "thread_start failed")?;
        THREADS[i].store(t.into_raw().0, Relaxed);
    }
    // The helpers run at the checker's level, each until its CONNECT
    // waits.
    sys::yield_now().map_err(|_| "yield failed")?;
    let waits = THREADS.iter().all(|t| {
        let t = Handle::<Thread>::borrowed(abi::Handle(t.load(Relaxed)));
        sys::thread_info(&t).is_ok_and(|info| info.state == ThreadState::AwaitingReply)
    });
    check(waits, "the helpers did not wait in their CONNECT to slow")?;
    let fifth = c.connect("slow").err();
    check(
        fifth == Some(Status::Kernel(Error::LimitReached)),
        "a fifth CONNECT to slow did not get LIMIT_REACHED",
    )
}

/// A helper of the checker: CONNECT to `slow`, then ECHO through the
/// session, what it saw into CAME[i] and ECHOED[i], and bit i to the
/// channel DONE.
extern "C" fn helper(i: u64) -> ! {
    let i = i as usize;
    let parent = Handle::<Channel>::borrowed(abi::START_CHANNEL);
    let session = rt::service::connect(&parent, "slow");
    CAME[i].store(true, Relaxed);
    ECHOED[i].store(session.is_ok_and(|s| echoes(&s)), Relaxed);
    let done = Handle::<Channel>::borrowed(abi::Handle(DONE.load(Relaxed)));
    let _ = sys::notify(&done, 1 << i);
    sys::thread_exit()
}

/// The kind and the rights of the handle that the reply to a CONNECT to
/// `name` brings.
fn connect_info(c: &Checker, name: &str) -> Result<(ObjectKind, Rights), &'static str> {
    let name = Name::new(name.as_bytes()).map_err(|_| "no name")?;
    let mut w = Writer::new();
    Connect { name }
        .write(&mut w)
        .map_err(|_| "CONNECT does not fit")?;
    let reply = sys::send(&c.s.parent, w.as_bytes()).map_err(|_| "CONNECT failed")?;
    reply.handles.info(0).ok_or("CONNECT brought no handle")
}

/// CONNECT to `echo` gives a channel with SEND and TRANSFER alone, a
/// session that ECHO goes through.
fn connect_gives_a_working_session(c: &Checker) -> Outcome {
    check(
        connect_info(c, "echo")? == (ObjectKind::Channel, Rights::SEND | Rights::TRANSFER),
        "a session is no channel with SEND and TRANSFER alone",
    )?;
    let echo = c.connect("echo").map_err(|_| "no session with echo")?;
    check(echoes(&echo), "ECHO did not come back through the session")
}

/// Each CONNECT makes a session of its own: two with `echo` have two
/// labels, neither 0.
fn each_connect_makes_a_new_session(c: &Checker) -> Outcome {
    let first = c.connect("echo").map_err(|_| "no session with echo")?;
    let second = c
        .connect("echo")
        .map_err(|_| "no second session with echo")?;
    let (a, b, again) = (label_of(&first)?, label_of(&second)?, label_of(&first)?);
    check(
        a != 0 && b != 0 && a != b && again == a,
        "two sessions with echo do not have two labels of their own",
    )
}

/// CONNECT to `private`, a service of the table the checker may not
/// connect to, and to `nobody`, no record, get ACCESS_DENIED.
fn connect_to_a_name_the_table_denies_is_refused(c: &Checker) -> Outcome {
    let denied = Some(Status::Kernel(Error::AccessDenied));
    check(
        c.connect("private").err() == denied,
        "CONNECT to private did not get ACCESS_DENIED",
    )?;
    check(
        c.connect("nobody").err() == denied,
        "CONNECT to nobody did not get ACCESS_DENIED",
    )
}

/// What the REGISTER of `device` brought (REPORT).
fn report(c: &Checker) -> Result<Report, &'static str> {
    let device = c.connect("device").map_err(|_| "no session with device")?;
    let mut buffer = [0; MESSAGE_MAX];
    let reply = call(
        &device,
        request(method::REPORT, &[]).as_bytes(),
        &mut buffer,
    );
    let bytes = reply.map_err(|_| "REPORT was refused")?;
    Report::read(bytes).map_err(|_| "REPORT gave no report")
}

/// The reply to REGISTER brings the window `rtc`, which shows the PL031's
/// PeriphID, and the binding `rtc-irq` of its line, level-triggered, each
/// a handle that makes no copies.
fn register_brings_windows_and_bindings(c: &Checker) -> Outcome {
    let r = report(c)?;
    check(r.flags & WINDOW != 0, "no window rtc came")?;
    check(
        r.flags & (WINDOW_COPIES | BINDING_COPIES) == 0,
        "the window or the binding came with DUPLICATE",
    )?;
    check(r.ids == RTC_IDS, "the window rtc does not show the PL031")?;
    check(r.flags & BINDING != 0, "no binding rtc-irq came")?;
    check(
        r.line == RTC_LINE && r.flags & EDGE == 0,
        "the binding is not of line 34, level-triggered",
    )
}

/// REGISTER with a channel that carries RECEIVE, and with one that lacks
/// DUPLICATE, gets ACCESS_DENIED, one as a service sends it 0, and a
/// second one BAD_STATE.
fn register_refuses_receive_and_a_second_time(c: &Checker) -> Outcome {
    let r = report(c)?;
    let denied = Status::Kernel(Error::AccessDenied).code();
    let expected = [
        denied,
        denied,
        Status::Ok.code(),
        Status::Kernel(Error::BadState).code(),
    ];
    check(
        r.statuses == expected,
        "the four REGISTER of device did not get ACCESS_DENIED twice, 0 and BAD_STATE",
    )
}

/// The helpers' requests for `slow` come back only once it registered,
/// after the checker opened the gate of `echo`, and their sessions work.
/// The wait for them has a bound.
fn connect_waits_for_registration(c: &Checker) -> Outcome {
    let done = DONE.load(Relaxed);
    check(done != 0, "the helpers never started")?;
    check(
        CAME.iter().all(|came| !came.load(Relaxed)),
        "a request for slow came back before slow registered",
    )?;
    let echo = c.connect("echo").map_err(|_| "no session with echo")?;
    check(
        status(&echo, request(method::OPEN, &[]).as_bytes()) == Status::Ok,
        "echo did not open its gate",
    )?;
    let done = Handle::<Channel>::borrowed(abi::Handle(done));
    let waiter = Waiter::new(&done, 0, base(&c.s)).map_err(|_| "timer_create failed")?;
    let deadline = now_ns() + BOUND_NS;
    let mut seen = 0;
    while seen != (1 << HELPERS) - 1 {
        match waiter.receive_until(&done, deadline) {
            Ok(Waited::Got(Received::Notification {
                source: Source::Unlabeled,
                bits,
                ..
            })) => seen |= bits,
            Ok(Waited::Got(_)) => {}
            Ok(Waited::Expired) => return Err("the requests for slow did not come back"),
            Err(_) => return Err("the wait for the helpers failed"),
        }
    }
    for t in &THREADS {
        drop(Handle::<Thread>::from_raw(abi::Handle(t.swap(0, Relaxed))));
    }
    check(
        ECHOED.iter().all(|e| e.load(Relaxed)),
        "ECHO did not go through a session with slow",
    )
}

/// The page of LIST from the record `first`.
fn list(c: &Checker, first: u16) -> Result<ListReply, &'static str> {
    let mut w = Writer::new();
    let _ = ListRequest { first }.write(&mut w);
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = call(&c.s.parent, w.as_bytes(), &mut buffer).map_err(|_| "LIST was refused")?;
    ListReply::read(bytes).map_err(|_| "LIST gave no page")
}

/// Lowers the checker to level 1 and back to its base priority: it runs
/// again once every thread above waits, so the worker of init has loaded
/// every record and each service it started has registered. A receive
/// with no wait drops the lift of the last notification first (spec 6.5).
fn settle(c: &Checker) -> Outcome {
    let (base, lowest) = (base(&c.s), 1);
    let channel = sys::channel_create(lowest).map_err(|_| "channel_create failed")?;
    let _ = sys::try_receive(&channel);
    let lower = sys::thread_set_priority(&c.s.thread, lowest, Policy::Fifo);
    lower.map_err(|_| "the checker could not lower itself")?;
    let back = sys::thread_set_priority(&c.s.thread, base, Policy::Fifo);
    back.map_err(|_| "the checker could not come back to its level")
}

/// Whether `got` names the record `name`.
fn named(got: &Listed, name: &str) -> bool {
    got.name.as_bytes() == name.as_bytes()
}

/// LIST gives init first, then every record of the table in its order,
/// each with its priority, ceiling and kind; all run with no failure but
/// those of NOT_RUNNING, each in its state with its failures and restarts.
fn list_names_every_record_in_its_state(c: &Checker) -> Outcome {
    settle(c)?;
    let page = list(c, 0)?;
    check(
        usize::from(page.total) == RECORDS.len() && page.len() == RECORDS.len(),
        "LIST does not count init and the records of the table",
    )?;
    for (got, &(name, priority, ceiling, client)) in page.records().zip(&RECORDS) {
        check(named(got, name), "LIST names another record")?;
        check(
            (got.priority, got.ceiling, got.client) == (priority, ceiling, client),
            "LIST gives a record other levels or another kind",
        )?;
        let expected = NOT_RUNNING
            .iter()
            .find(|r| r.0 == name)
            .map_or((State::Running, 0, 0), |&(_, s, f, r)| (s, f, r));
        check(
            (got.state, got.failures, got.restarts) == expected,
            "a record has another state, other failures or other restarts",
        )?;
    }
    Ok(())
}

/// A page of LIST holds the records from its first on, at most
/// LIST_PAGE, and the count of all; past the last record it is empty.
fn list_pages_from_its_first_entry(c: &Checker) -> Outcome {
    for first in [2, 5, 6, 9] {
        let page = list(c, first)?;
        let from = usize::from(first).min(RECORDS.len());
        check(
            page.len() == (RECORDS.len() - from).min(LIST_PAGE)
                && usize::from(page.total) == RECORDS.len(),
            "a page of LIST has another count",
        )?;
        let expected = RECORDS[from..].iter().map(|&(name, ..)| name);
        check(
            page.records()
                .zip(expected)
                .all(|(got, name)| named(got, name)),
            "a page of LIST does not start at its first record",
        )?;
    }
    Ok(())
}

/// The handles and the memory of the checker's process, as it sees them.
fn own_counts(c: &Checker) -> Option<(ProcessHandles, ProcessMemory)> {
    let handles = sys::process_handles(&c.s.process).ok()?;
    Some((handles, sys::process_memory(&c.s.process).ok()?))
}

/// The record of an instance in LIST gives the live and retired handles,
/// the room for handles and the quota and used pages of its process: the
/// checker's own record shows what the checker sees of itself.
fn list_counts_the_handles_and_memory_of_an_instance(c: &Checker) -> Outcome {
    let before = own_counts(c);
    let page = list(c, 0)?;
    check(
        before == own_counts(c),
        "the checker's counts changed during LIST",
    )?;
    let (h, m) = before.ok_or("PROCESS_HANDLES or PROCESS_MEMORY failed")?;
    let got = page.records().find(|r| named(r, "checker"));
    let got = got.ok_or("LIST has no record checker")?;
    let handles = [h.live, h.retired, h.limit].map(|n| n as u32);
    check(
        [got.live, got.retired, got.limit] == handles,
        "LIST gives the checker other handles",
    )?;
    check(
        [got.quota_pages, got.used_pages] == [m.quota / PAGE, m.used / PAGE].map(|n| n as u32),
        "LIST gives the checker other memory",
    )
}

/// The reply to STATS.
fn stats(c: &Checker) -> Result<Stats, &'static str> {
    let mut buffer = [0; MESSAGE_MAX];
    let request = Method::Stats.header().bytes();
    let bytes = call(&c.s.parent, &request, &mut buffer).map_err(|_| "STATS was refused")?;
    Stats::read(bytes).map_err(|_| "STATS gave no counts")
}

/// STATS brings the counts of the kernel, the worker, init's free quota
/// and the labels init gave: with every record started or broken the
/// worker has no job and waits at its idle level, in receive or on its way
/// there (READY: init lowered it as soon as its last job was done, and
/// the checker keeps the processor above it), and one more CONNECT gives
/// one more label.
fn stats_bring_the_kernel_the_worker_and_the_quota(c: &Checker) -> Outcome {
    let first = stats(c)?;
    check(
        first.kernel.free_frames > 0 && first.kernel.pool_pages > 0,
        "STATS gives no counts of the kernel",
    )?;
    check(
        first.job.is_none() && first.pending == 0,
        "the worker has a job",
    )?;
    let idle = [ThreadState::Receiving, ThreadState::Ready].map(|s| s.code());
    check(
        (first.worker_priority, first.worker_effective) == (WORKER_IDLE, WORKER_IDLE)
            && idle.contains(&u64::from(first.worker_state)),
        "the worker does not wait at its idle level",
    )?;
    check(first.free_pages > 0, "STATS gives init no free quota")?;
    let own = list(c, 0)?
        .records()
        .next()
        .map(|r| (r.quota_pages, r.used_pages));
    let (quota, used) = own.ok_or("LIST has no record init")?;
    check(
        first.free_pages == u64::from(quota.saturating_sub(used)),
        "STATS gives init another free quota than LIST",
    )?;
    // The worker's label and one for each instance: as many as LIST has
    // records, and those of the sessions so far.
    check(
        first.labels >= RECORDS.len() as u64,
        "STATS counts fewer labels than init gave",
    )?;
    let _echo = c.connect("echo").map_err(|_| "no session with echo")?;
    let second = stats(c)?;
    check(second.labels > first.labels, "a CONNECT gave no label")
}

/// The record `name` in the first page of LIST.
fn record(c: &Checker, name: &str) -> Result<Listed, &'static str> {
    let page = list(c, 0)?;
    let found = page.records().find(|r| named(r, name)).copied();
    found.ok_or("LIST has no such record")
}

/// CONNECT to `crash`, which faults right after each start, waits while
/// init restarts it after pauses of 100, 200, 400 and 800 ms, and gets
/// PEER_CLOSED once its fifth failure marks it broken, no earlier than
/// the pauses after the failures it had not had when the checker started.
/// LIST shows it BROKEN with five failures and four restarts.
fn crash_is_broken_after_five_failures(c: &Checker) -> Outcome {
    let got = c.connect("crash").err();
    check(
        got == Some(Status::Kernel(Error::PeerClosed)),
        "CONNECT to crash did not get PEER_CLOSED",
    )?;
    check(
        c.crash_failures < 5,
        "crash was broken before the checker started",
    )?;
    // The pauses after the failures still to come: 100 ms * 2^(k-1) after
    // failure k, from the failures of crash when the checker started.
    let pauses: u64 = (u32::from(c.crash_failures)..4)
        .map(|k| (100 * MS) << k)
        .sum();
    check(
        now_ns() >= c.started_ns + pauses,
        "crash was broken before its pauses were over",
    )?;
    let crash = record(c, "crash")?;
    check(
        (crash.state, crash.failures, crash.restarts) == (State::Broken, 5, 4),
        "LIST does not show crash broken after five failures",
    )
}

/// A CONNECT to a broken service gets PEER_CLOSED at once.
fn connect_to_a_broken_service_is_peer_closed(c: &Checker) -> Outcome {
    let got = c.connect("crash").err();
    check(
        got == Some(Status::Kernel(Error::PeerClosed)),
        "CONNECT to the broken crash did not get PEER_CLOSED",
    )
}

/// `hog` needs more than init's quota: its start waits (QUOTA) with no
/// failure, no restart and no instance.
fn a_record_without_quota_waits_and_is_not_broken(c: &Checker) -> Outcome {
    let hog = record(c, "hog")?;
    check(hog.state == State::Quota, "hog does not wait for quota")?;
    check(
        hog.failures == 0 && hog.restarts == 0,
        "the wait of hog counted as a failure",
    )?;
    check(hog.live == 0 && hog.quota_pages == 0, "hog has an instance")
}
