// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Credentials in the process service: the shared state of a record,
//! Child snapshots and the right Child takes, Create refused through a
//! session. The records' bound, the children of a record, a record that
//! goes with its session and its PID one generation on, and labels the
//! service did not give are the service's host tests (records.rs).
use super::*;
use process_client::Client;
use proto_process::{Change, Credentials};
use proto_wire::{Header, Reader, Status};
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
fn joined(entry: unsafe extern "C" fn(*mut c_void) -> *mut c_void) -> bool {
    let mut thread = 0;
    let mut value = ptr::null_mut();
    (unsafe { ffi::pthread_create(&mut thread, ptr::null(), Some(entry), ptr::null_mut()) }) == 0
        && (unsafe { ffi::pthread_join(thread, &mut value) }) == 0
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
/// A native child with no thread, as the parent of a POSIX child makes it
/// before it starts.
fn native() -> Handle<rt::handle::Process> {
    sys::process_create(65536, 16, 30).unwrap()
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
    // Create only through the channel with no label.
    if c.create(&own, true).err() != Some(Status::from_code(proto_process::PERMISSION))
        || abi::process::seteuid(0) != 0
        || c.query().unwrap() != original
    {
        return failed(493);
    }
    // A stopped native child gets a snapshot of the caller's credentials,
    // which later changes of the caller leave alone.
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
    drop(inherited_session);
    sys::process_kill(&unprivileged).unwrap();
    drop(unprivileged);
    drop(first_client);
    sys::process_kill(&child).unwrap();
    drop(child);
    // Child takes a process handle with MANAGE alone.
    let child = native();
    let weak = c.child_with(&child, rt::abi::Rights::DUPLICATE);
    if weak.err() != Some(Status::from_code(proto_process::PERMISSION)) {
        return failed(513);
    }
    sys::process_kill(&child).unwrap();
    drop(child);
    rt::println!(
        "credential-probe: shared UID/GID, saved IDs, sessions by label, child snapshots and rights ok"
    );
    true
}
