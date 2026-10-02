// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Credentials in the process service: the shared state of a record,
//! Create refused through a session, and a record that goes with its
//! process whoever holds its session. The records' bound, a record that
//! goes with the notification of its end and its PID one generation on,
//! and labels the service did not give are the service's host tests
//! (records.rs).
use super::*;
use proto_process::Credentials;
use proto_wire::{Header, Reader, Status};
static HANDLED: AtomicUsize = AtomicUsize::new(0);
extern "C" fn handler(_: i32) {
    if abi::process::getuid() == 0 && abi::process::geteuid() == 1000 {
        HANDLED.fetch_add(1, Ordering::Release);
    }
}
unsafe extern "C" fn reader(_: *mut c_void) -> *mut c_void {
    let errno = unsafe { ffi::__errno_location() };
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
/// A channel of the probe's own, offered to the clock in place of its
/// identity session, proves nothing, even to a root process: the clock
/// asks the process service, which finds no identity place reached
/// (PERMISSION at once, the clock never sends to the channel); the real
/// identity session on another connection sets the clock. Says so.
fn forged(parent: &Handle<Channel>) -> bool {
    let time = posix_time::Time {
        seconds: 1_800_000_000,
        nanos: 0,
    };
    let Ok(own) = sys::channel_create(30) else {
        return false;
    };
    let rights = rt::abi::Rights::NOTIFY | rt::abi::Rights::TRANSFER | rt::abi::Rights::DUPLICATE;
    let Ok(fake) = sys::handle_label(&own, rights, 77, 30) else {
        return false;
    };
    let (Ok(forger), Ok(honest)) = (
        posix_clock::Client::connect(parent),
        posix_clock::Client::connect(parent),
    ) else {
        return false;
    };
    let refused = forger.set(time, Some(&fake)) == Err(Status::from_code(proto_clock::PERMISSION));
    let allowed = honest.set(time, abi::process::identity()).is_ok();
    if refused && allowed {
        rt::println!("credential-probe: a forged identity does not set the clock");
    }
    refused && allowed
}

/// A record goes with its process (case (a) of mk.P1 in the audit 4):
/// `posix-sender` (tests/svc, role `t`) gives the clock peer its own
/// session and ends; a query through that session, which the peer still
/// holds, then finds no record. Before the sender's session reached the
/// peer the peer says BAD_STATE; while the record lives the query passes.
/// Two seconds at most.
fn transferred(parent: &Handle<Channel>) -> bool {
    let connection = rt::service::connect(parent, "clock-peer").unwrap();
    let ask = Header {
        version: proto_clock::VERSION,
        method: 11,
    }
    .bytes();
    let gone = proto_wire::reply(Status::from_code(proto_process::UNREGISTERED));
    let pause = abi::metadata::Timespec {
        tv_sec: 0,
        tv_nsec: 10_000_000,
    };
    for _ in 0..200 {
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        let reply = sys::send(&connection, &ask).unwrap();
        if reply.bytes(&mut buffer) == gone {
            return true;
        }
        let _ = unsafe { crate::layer::sleep::nanosleep(&pause, ptr::null_mut()) };
    }
    false
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
    if abi::process::seteuid(1000).is_err() || !joined(reader) || !peer(parent, &own) {
        return failed(491);
    }
    let action = crate::layer::signals::SigAction {
        handler: handler as *const () as u64,
        mask: 0,
        flags: 0,
    };
    let mut old = action;
    if unsafe { crate::layer::signals::sigaction(SIGUSR1, &action, &mut old) } != 0
        || crate::layer::signals::raise(SIGUSR1) != 0
        || HANDLED.load(Ordering::Acquire) != 1
        || unsafe { crate::layer::signals::sigaction(SIGUSR1, &old, ptr::null_mut()) } != 0
    {
        return failed(492);
    }
    if abi::process::seteuid(0).is_err() || c.query().unwrap() != original {
        return failed(493);
    }
    if !transferred(parent) {
        return failed(498);
    }
    if !forged(parent) {
        return failed(499);
    }
    rt::println!(
        "credential-probe: shared UID/GID, saved IDs, sessions by label, a record that goes with its process ok"
    );
    true
}
