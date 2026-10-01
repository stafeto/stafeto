// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Credentials in the process service: the shared state of a record,
//! retained transitions, Child snapshots, the records' bound, a record that
//! goes with its session and its PID one generation on, Create refused
//! through a session, and sessions the service did not give.
use super::*;
use process_client::Client;
use proto_process::{Change, Credentials, Label, Method, RECORDS};
use proto_wire::{Header, Reader, Status};
const BASE: u64 = 1 << 61;
static HANDLED: AtomicUsize = AtomicUsize::new(0);
extern "C" fn handler(_: i32) {
    if abi::process::getuid() == 0 && abi::process::geteuid() == 1000 {
        HANDLED.fetch_add(1, Ordering::Release);
    }
}
unsafe extern "C" fn reader(_: *mut c_void) -> *mut c_void {
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 733 };
    let passed = abi::process::getuid() == 0
        && abi::process::geteuid() == 1000
        && abi::process::getgid() == 0
        && abi::process::getegid() == 0
        && unsafe { *errno } == 733;
    usize::from(passed) as *mut c_void
}
unsafe extern "C" fn interrupted(_: *mut c_void) -> *mut c_void {
    let native = unsafe { threads::probe_native(threads::pthread_self()) }.unwrap();
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 744 };
    for method in [Method::Change, Method::Ack] {
        abi::process::probe_interrupt(&native, method).unwrap();
        if abi::process::seteuid(1000) != 0
            || abi::process::getuid() != 0
            || abi::process::geteuid() != 1000
            || unsafe { *errno } != 744
        {
            return ptr::null_mut();
        }
        if abi::process::seteuid(0) != 0 {
            return ptr::null_mut();
        }
    }
    ptr::dangling_mut::<c_void>()
}
fn joined(entry: unsafe extern "C" fn(*mut c_void) -> *mut c_void) -> bool {
    let mut thread = 0;
    let mut value = ptr::null_mut();
    (unsafe { threads::pthread_create(&mut thread, ptr::null(), Some(entry), ptr::null_mut()) })
        == 0
        && (unsafe { threads::pthread_join(thread, &mut value) }) == 0
        && value as usize == 1
}
/// The clock peer, a process init created without root, has a record of
/// its own: another PID, parent 1, no privilege; Create through its
/// session, with a copy of this process, is refused.
fn peer(parent: &Handle<Channel>, own: &Handle<rt::handle::Process>) -> bool {
    let connection = rt::service::connect(parent, "clock-peer").unwrap();
    let packet = Header {
        version: proto_clock::VERSION,
        method: 8,
    }
    .bytes();
    let reply = sys::send(&connection, &packet).unwrap();
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut r = Reader::new(reply.bytes(&mut buffer));
    if r.u32() != Ok(0)
        || !r
            .u32()
            .is_ok_and(|pid| pid != abi::process::getpid() as u32)
        || r.u32() != Ok(proto_process::INIT_PID)
    {
        return false;
    }
    for id in Credentials::NOBODY.words() {
        if r.u32() != Ok(id) {
            return false;
        }
    }
    if r.finish().is_err() {
        return false;
    }
    let rights = rt::abi::Rights::DUPLICATE | rt::abi::Rights::TRANSFER | rt::abi::Rights::MANAGE;
    let copy = sys::handle_duplicate(own, rights).unwrap();
    let packet = Header {
        version: proto_clock::VERSION,
        method: 9,
    }
    .bytes();
    let reply = sys::send_handles(&connection, &packet, [copy.erase()]).unwrap();
    let bytes = reply.bytes(&mut buffer);
    bytes == proto_wire::reply(Status::from_code(proto_process::PERMISSION))
}
/// Whether the service holds `count` records: the CLIENT_GONE of a closed
/// session comes to it as a notification, so a few yields at most.
fn settled(c: &Client, count: u64) -> bool {
    (0..1000).any(|_| {
        let now = c.stats().unwrap()[4] == count;
        if !now {
            let _ = sys::yield_now();
        }
        now
    })
}
/// A native child with no thread, as the parent of a POSIX child makes it
/// before it starts.
fn native() -> Handle<rt::handle::Process> {
    sys::process_create(65536, 16, 30).unwrap()
}
/// The records' bound: the service fills its free records with copies of
/// one native child, keeping their sessions (transport-probe), up to
/// RECORDS in all; Child is FULL then, and once the service let the
/// sessions go the records are free again. The failed stage, if any.
#[inline(never)]
fn bound(c: &Client, baseline: u64) -> Option<usize> {
    let child = native();
    let Ok(count) = c.fill(Some(&child)) else {
        return Some(500);
    };
    if u64::from(count) + baseline != RECORDS as u64
        || c.stats().unwrap()[4] != RECORDS as u64
        || c.child(&child).err() != Some(Status::from_code(proto_process::FULL))
    {
        return Some(501);
    }
    if c.fill(None) != Ok(0) {
        return Some(502);
    }
    sys::process_kill(&child).unwrap();
    drop(child);
    if !settled(c, baseline) {
        return Some(502);
    }
    None
}
#[inline(never)]
pub(super) fn run(parent: &Handle<Channel>) -> bool {
    let own =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let c = abi::process::client();
    let original = c.query().unwrap();
    if original.pid != abi::process::getpid() as u32
        || original.parent != proto_process::INIT_PID
        || original.credentials != Credentials::ROOT
    {
        return failed(490);
    }
    if abi::process::seteuid(1000) != 0 || !joined(reader) || !peer(parent, &own) {
        return failed(491);
    }
    let action = abi::signals::SigAction {
        handler: handler as *const () as u64,
        mask: 0,
        flags: 0,
    };
    let mut old = action;
    if unsafe { abi::signals::sigaction(SIGUSR1, &action, &mut old) } != 0
        || abi::signals::raise(SIGUSR1) != 0
        || HANDLED.load(Ordering::Acquire) != 1
        || unsafe { abi::signals::sigaction(SIGUSR1, &old, ptr::null_mut()) } != 0
    {
        return failed(492);
    }
    // Create only through the channel with no label; a session the
    // service did not give, with a label of init's space or of a gone
    // generation of this record, names no record.
    let stale = Label {
        index: (original.pid % RECORDS as u32) as u16,
        generation: original.pid / RECORDS as u32 + 1,
    };
    let foreign = [0x1234, stale.raw()].map(|label| c.forge(label).map(Client::new));
    if c.create(&own, true).err() != Some(Status::from_code(proto_process::PERMISSION))
        || foreign.iter().any(|f| {
            f.as_ref().map_or(true, |f| {
                f.query().err() != Some(Status::from_code(proto_process::UNREGISTERED))
            })
        })
    {
        return failed(493);
    }
    drop(foreign);
    if abi::process::seteuid(0) != 0 || !joined(interrupted) || c.query().unwrap() != original {
        return failed(494);
    }
    // A saved successful result must not apply again over a later credential state.
    c.change_retained(BASE, Change::EffectiveUid, 1000).unwrap();
    c.change(Change::EffectiveUid, 0).unwrap();
    if c.change_retained(BASE, Change::EffectiveUid, 1000).is_err()
        || c.query().unwrap() != original
        || c.change_retained(BASE, Change::EffectiveUid, 1001)
            != Err(Status::from_code(proto_process::INVALID))
    {
        return failed(495);
    }
    c.ack(BASE).unwrap();
    c.ack(BASE).unwrap();
    // An old permission error stays an error even after root privileges return.
    c.change(Change::EffectiveUid, 1000).unwrap();
    if c.change_retained(BASE + 1, Change::EffectiveGid, 42)
        != Err(Status::from_code(proto_process::PERMISSION))
    {
        return failed(496);
    }
    c.change(Change::EffectiveUid, 0).unwrap();
    if c.change_retained(BASE + 1, Change::EffectiveGid, 42)
        != Err(Status::from_code(proto_process::PERMISSION))
        || c.query().unwrap() != original
    {
        return failed(497);
    }
    c.ack(BASE + 1).unwrap();
    // A stopped native child gets a snapshot of the caller's credentials,
    // which later changes of the caller leave alone.
    let baseline = c.stats().unwrap()[4];
    let child = native();
    let (first, first_session) = c.child(&child).unwrap();
    if first.parent != original.pid
        || first.pid == original.pid
        || first.credentials != Credentials::ROOT
    {
        return failed(498);
    }
    c.change(Change::EffectiveUid, 1000).unwrap();
    let unprivileged = native();
    let (inherited, inherited_session) = c.child(&unprivileged).unwrap();
    let first_client = Client::new(first_session);
    if inherited.credentials.words() != [0, 1000, 0, 0, 0, 0]
        || inherited.parent != original.pid
        || first_client.query() != Ok(first)
    {
        return failed(510);
    }
    c.change(Change::EffectiveUid, 0).unwrap();
    // A record goes with its session; its index comes back with the next
    // generation, so its PID is new.
    drop(inherited_session);
    sys::process_kill(&unprivileged).unwrap();
    drop(unprivileged);
    drop(first_client);
    sys::process_kill(&child).unwrap();
    drop(child);
    if !settled(c, baseline) {
        return failed(511);
    }
    let child = native();
    let (fresh, fresh_session) = c.child(&child).unwrap();
    if fresh.pid != first.pid + RECORDS as u32 || fresh.credentials != Credentials::ROOT {
        return failed(499);
    }
    drop(fresh_session);
    sys::process_kill(&child).unwrap();
    drop(child);
    // The records' bound is checked before insertion, and records whose
    // sessions closed are free again.
    if !settled(c, baseline) {
        return failed(512);
    }
    if let Some(stage) = bound(c, baseline) {
        return failed(stage);
    }
    // Grow retained storage, then reject new reservation with all handle slots full.
    let empty = c.stats().unwrap();
    for n in 0..2000 {
        c.change_retained(BASE + 100 + n, Change::EffectiveUid, 0)
            .unwrap();
    }
    let full = c.stats().unwrap();
    if full[0] <= empty[0] || full[1] < 131072 {
        return failed(503);
    }
    c.control(8, true).unwrap();
    c.control(9, true).unwrap();
    if c.change_retained(BASE + 3000, Change::EffectiveUid, 1000)
        != Err(Status::from_code(proto_process::FULL))
        || c.query().unwrap() != original
    {
        return failed(504);
    }
    for n in 0..2000 {
        if c.change_retained(BASE + 100 + n, Change::EffectiveUid, 0)
            .is_err()
        {
            return failed(505);
        }
        c.ack(BASE + 100 + n).unwrap();
    }
    if c.stats().unwrap()[0] != empty[0] {
        return failed(506);
    }
    c.control(9, false).unwrap();
    c.control(8, false).unwrap();
    // The end of a record takes its retained replies with it.
    let child = native();
    let (_, session) = c.child(&child).unwrap();
    let other = Client::new(session);
    for n in 0..100 {
        other
            .change_retained(BASE + 4000 + n, Change::EffectiveUid, 0)
            .unwrap();
    }
    if c.stats().unwrap()[0] <= empty[0] {
        return failed(507);
    }
    drop(other);
    sys::process_kill(&child).unwrap();
    drop(child);
    if !settled(c, baseline) || c.stats().unwrap()[0] != empty[0] {
        return failed(508);
    }
    rt::println!(
        "credential-probe: shared UID/GID, saved IDs, sessions by label, child snapshots, retry/ACK, limits and resource pressure ok"
    );
    true
}
