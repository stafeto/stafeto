// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Authenticated shared credentials, retained transitions and registry lifetime.
use super::*;
use process_client::Client;
use proto_process::{Change, Credentials, Method};
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
        || r.u32() != Ok(1)
    {
        return false;
    }
    for _ in 0..6 {
        if r.u32() != Ok(0) {
            return false;
        }
    }
    if r.finish().is_err() {
        return false;
    }
    let copy =
        sys::handle_duplicate(own, rt::abi::Rights::DUPLICATE | rt::abi::Rights::TRANSFER).unwrap();
    let packet = Header {
        version: proto_clock::VERSION,
        method: 9,
    }
    .bytes();
    let reply = sys::send_handles(&connection, &packet, [copy.erase()]).unwrap();
    let bytes = reply.bytes(&mut buffer);
    bytes == proto_wire::reply(Status::from_code(proto_process::PERMISSION))
}
#[inline(never)]
pub(super) fn run(parent: &Handle<Channel>) -> bool {
    let own =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let c = Client::connect(parent).unwrap();
    let other = Client::connect(parent).unwrap();
    let original = c.query().unwrap();
    if original.identity.id != abi::process::getpid() as u32
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
    let enrolled = c.enroll(&own).unwrap();
    if enrolled.credentials.euid != 1000
        || enrolled.credentials.uid != 0
        || other.query().unwrap() != enrolled
    {
        return failed(493);
    }
    if abi::process::seteuid(0) != 0 || !joined(interrupted) || c.query().unwrap() != original {
        return failed(494);
    }
    // A saved successful result must not apply again over a later credential state.
    c.change_retained(BASE, Change::EffectiveUid, 1000).unwrap();
    other.change(Change::EffectiveUid, 0).unwrap();
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
    other.change(Change::EffectiveUid, 0).unwrap();
    if c.change_retained(BASE + 1, Change::EffectiveGid, 42)
        != Err(Status::from_code(proto_process::PERMISSION))
        || c.query().unwrap() != original
    {
        return failed(497);
    }
    c.ack(BASE + 1).unwrap();
    // An ACK on another session cannot discard this session's old result.
    c.change_retained(BASE + 2, Change::EffectiveUid, 1000)
        .unwrap();
    other.ack(BASE + 2).unwrap();
    other.change(Change::EffectiveUid, 0).unwrap();
    if c.change_retained(BASE + 2, Change::EffectiveUid, 1000)
        .is_err()
        || c.query().unwrap() != original
        || c.child(&own) != Err(Status::from_code(proto_process::PERMISSION))
    {
        return failed(509);
    }
    c.ack(BASE + 2).unwrap();
    // A stopped native child receives a snapshot; retry never replaces it.
    let child = sys::process_create(65536, 16, 30).unwrap();
    let first = c.child(&child).unwrap();
    other.change(Change::EffectiveUid, 1000).unwrap();
    if c.child(&child).unwrap() != first
        || c.enroll(&child) != Err(Status::from_code(proto_process::PERMISSION))
    {
        return failed(498);
    }
    let unprivileged_child = sys::process_create(65536, 16, 30).unwrap();
    let inherited = c.child(&unprivileged_child).unwrap();
    if inherited.credentials != other.query().unwrap().credentials
        || inherited.credentials.words() != [0, 1000, 0, 0, 0, 0]
        || inherited.identity.parent != original.identity.id
    {
        return failed(510);
    }
    sys::process_kill(&unprivileged_child).unwrap();
    drop(unprivileged_child);
    other.change(Change::EffectiveUid, 0).unwrap();
    sys::process_kill(&child).unwrap();
    drop(child);
    let child = sys::process_create(65536, 16, 30).unwrap();
    let fresh = c.child(&child).unwrap();
    if fresh.identity.id == first.identity.id
        || fresh.credentials != Credentials::ROOT
        || fresh.identity.parent != original.identity.id
    {
        return failed(499);
    }
    sys::process_kill(&child).unwrap();
    drop(child);
    // Registry limits are checked before insertion and dead shells are reusable.
    let mut children: [Option<Handle<rt::handle::Process>>; 64] = core::array::from_fn(|_| None);
    let baseline = c.stats().unwrap()[4];
    let mut count = 0;
    for slot in &mut children {
        let child = sys::process_create(65536, 16, 30).unwrap();
        match c.child(&child) {
            Ok(_) => {
                *slot = Some(child);
                count += 1;
            }
            Err(status) if status.code() == proto_process::FULL => {
                sys::process_kill(&child).unwrap();
                drop(child);
                break;
            }
            _ => return failed(500),
        }
    }
    if count + baseline != 64 || c.stats().unwrap()[4] != 64 {
        return failed(501);
    }
    for child in children.iter_mut().filter_map(Option::take) {
        sys::process_kill(&child).unwrap();
    }
    if c.stats().unwrap()[4] != baseline {
        return failed(502);
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
    // Disconnect removes replies but does not restore root credentials.
    for n in 0..100 {
        c.change_retained(BASE + 4000 + n, Change::EffectiveUid, 0)
            .unwrap();
    }
    if other.stats().unwrap()[0] <= empty[0] {
        return failed(511);
    }
    c.change(Change::EffectiveUid, 1000).unwrap();
    drop(c);
    let reconnected = Client::connect(parent).unwrap();
    if reconnected.enroll(&own).unwrap().credentials.euid != 1000 {
        return failed(507);
    }
    reconnected.change(Change::EffectiveUid, 0).unwrap();
    if reconnected.query().unwrap() != original {
        return failed(508);
    }
    if reconnected.stats().unwrap()[0] != empty[0] {
        return failed(512);
    }
    rt::println!(
        "credential-probe: shared UID/GID, saved IDs, authenticated processes, child snapshots, retry/ACK, limits and resource pressure ok"
    );
    true
}
