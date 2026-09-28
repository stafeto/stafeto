// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Interrupted committed operations retain independent replies across nesting.
use super::*;
use abi::shared;
rt::upcall_entry!(entry, dispatch);
static NATIVE: AtomicU64 = AtomicU64::new(0);
static FD: AtomicUsize = AtomicUsize::new(0);
static MODE: AtomicUsize = AtomicUsize::new(0);
static DEPTH: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
fn native() -> core::mem::ManuallyDrop<Handle<Thread>> {
    Handle::borrowed(rt::abi::Handle(NATIVE.load(Ordering::Acquire)))
}
unsafe extern "C" fn dispatch() {
    let depth = DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
    CALLS.fetch_add(1, Ordering::SeqCst);
    let errno = unsafe { abi::__errno_location() };
    let saved = unsafe { *errno };
    let fd = FD.load(Ordering::Acquire) as i32;
    if depth == 1 {
        shared::probe_reply_upcall(&native());
        // The next handler interrupts this handler's own committed operation.
        unsafe { rt::upcall::enable() }.unwrap();
    }
    // An Ack with a lost reply must be harmless to both retained ancestor results.
    if depth == 2 {
        shared::probe_ack_interrupt(&native());
    }
    let passed = match MODE.load(Ordering::Acquire) {
        1 => {
            let byte = if depth == 1 { b'B' } else { b'C' };
            (unsafe { abi::write(fd, &byte, 1) }) == 1
        }
        2 => {
            let mut byte = 0;
            (unsafe { abi::read(fd, &mut byte, 1) }) == 1
                && byte == if depth == 1 { b'B' } else { b'C' }
        }
        3 => {
            let opened = unsafe { abi::open(c"/etc/motd".as_ptr(), O_RDONLY) };
            opened >= 0 && unsafe { abi::close(opened) } == 0
        }
        _ => false,
    };
    rt::upcall::mask().unwrap();
    if !passed || unsafe { *errno } != saved {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    unsafe { *errno = saved };
    DEPTH.fetch_sub(1, Ordering::SeqCst);
}
fn arm(mode: usize) {
    MODE.store(mode, Ordering::Release);
    CALLS.store(0, Ordering::Release);
    shared::probe_reply_upcall(&native());
}
fn handlers_ok() -> bool {
    CALLS.load(Ordering::Acquire) == 2
        && DEPTH.load(Ordering::Acquire) == 0
        && ERRORS.load(Ordering::Acquire) == 0
}
fn exercise() -> bool {
    let native = unsafe { threads::probe_native(threads::pthread_self()) }.unwrap();
    NATIVE.store(native.raw().0, Ordering::Release);
    let fd = unsafe { abi::open(c"/tmp/probe".as_ptr(), O_RDWR) };
    if fd < 0 || unsafe { abi::lseek(fd, 0, SEEK_SET) } != 0 {
        return failed(250);
    }
    FD.store(fd as usize, Ordering::Release);
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let handles = sys::process_handles(&process).unwrap().live;
    let used = sys::process_memory(&process).unwrap().used;
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 777 };
    unsafe { rt::upcall::bind(entry) }.unwrap();
    unsafe { rt::upcall::enable() }.unwrap();
    arm(1);
    if unsafe { abi::write(fd, b"A".as_ptr(), 1) } != 1 || !handlers_ok() {
        return failed(251);
    }
    if unsafe { abi::lseek(fd, 0, SEEK_SET) } != 0 {
        return failed(252);
    }
    arm(2);
    let mut first = 0;
    if unsafe { abi::read(fd, &mut first, 1) } != 1
        || first != b'A'
        || !handlers_ok()
        || unsafe { abi::lseek(fd, 0, SEEK_CUR) } != 3
    {
        return failed(253);
    }
    arm(3);
    let opened = unsafe { abi::open(c"/etc/motd".as_ptr(), O_RDONLY) };
    if opened < 0 || !handlers_ok() {
        return failed(254);
    }
    let mut byte = 0;
    if unsafe { abi::read(opened, &mut byte, 1) } != 1
        || byte != b's'
        || unsafe { abi::close(opened) } != 0
        || unsafe { *errno } != 777
    {
        return failed(255);
    }
    rt::upcall::mask().unwrap();
    rt::upcall::unbind().unwrap();
    // Repetition catches missing Ack allocations after warming the journal.
    for _ in 0..200 {
        let mut cwd = [0; 2];
        if unsafe { abi::getcwd(cwd.as_mut_ptr().cast(), cwd.len()) }.is_null() {
            return failed(256);
        }
    }
    if sys::process_handles(&process).unwrap().live != handles
        || sys::process_memory(&process).unwrap().used != used
    {
        return failed(257);
    }
    if !storage(fd) || !before_accept(fd) || unsafe { abi::close(fd) } != 0 {
        return false;
    }
    rt::println!(
        "file-reply-probe: nested committed write/read/open and interrupted Ack retain results, offsets and quota"
    );
    true
}

unsafe extern "C" fn queued_write(_: *mut c_void) -> *mut c_void {
    let fd = FD.load(Ordering::Acquire) as i32;
    let status = unsafe { abi::write(fd, b"Y".as_ptr(), 1) };
    let errno = unsafe { *abi::__errno_location() };
    usize::from(status == -1 && errno == EINTR) as *mut c_void
}

fn before_accept(fd: i32) -> bool {
    use rt::wait::{Waited, Waiter};
    fn now() -> u64 {
        rt::time::ticks_to_ns(rt::time::now())
    }
    let ready = sys::channel_create(30).unwrap();
    let gate = sys::channel_create(30).unwrap();
    let wake = sys::channel_create(30).unwrap();
    let timer = sys::timer_create(&wake, 30).unwrap();
    let waiter = Waiter::new(&ready, 0, 30).unwrap();
    let mut cwd = [0; 2];
    shared::probe_pause_after_ack(&gate, &ready);
    if unsafe { abi::getcwd(cwd.as_mut_ptr().cast(), cwd.len()) }.is_null()
        || !matches!(
            waiter.receive_until(&ready, now() + 500_000_000),
            Ok(Waited::Got(_))
        )
    {
        return failed(271);
    }
    let mut id = 0;
    if unsafe { threads::pthread_create(&mut id, ptr::null(), Some(queued_write), ptr::null_mut()) }
        != 0
    {
        return failed(272);
    }
    let target = unsafe { threads::probe_native(id) }.unwrap();
    let deadline = now() + 500_000_000;
    while sys::thread_info(&target).unwrap().state != ThreadState::Sending {
        if now() >= deadline {
            return failed(273);
        }
        sys::timer_set(&timer, now() + 1_000_000).unwrap();
        sys::receive(&wake).unwrap();
    }
    // Sending proves the request is queued while the owner receives from gate.
    sys::thread_interrupt(&target).unwrap();
    sys::notify(&gate, 1).unwrap();
    let mut result = ptr::null_mut();
    if unsafe { threads::pthread_join(id, &mut result) } != 0
        || result as usize != 1
        || unsafe { abi::lseek(fd, 0, SEEK_CUR) } != 4
    {
        return failed(274);
    }
    rt::println!("file-reply-probe: interrupted unaccepted write returns EINTR without effects");
    true
}

unsafe extern "C" fn worker(_: *mut c_void) -> *mut c_void {
    usize::from(exercise()) as *mut c_void
}

fn storage(fd: i32) -> bool {
    use posix_request::{MESSAGE_MAX, Reply, Request, exchange::Exchange};
    use proto_wire::Writer;
    fn transact(exchange: Exchange<'_>, buffer: &mut [u8; MESSAGE_MAX]) -> usize {
        let mut wire = Writer::new();
        exchange.write(&mut wire).unwrap();
        shared::probe_exchange(wire.as_bytes(), buffer).unwrap()
    }
    let mut request = Writer::new();
    Request::Cwd.write(&mut request).unwrap();
    let mut buffer = [0; MESSAGE_MAX];
    const FIRST: u64 = 0xf000_0000_0000_0000;
    let mut write = Writer::new();
    Request::Write {
        fd: fd as u32,
        bytes: b"Z",
    }
    .write(&mut write)
    .unwrap();
    for _ in 0..2 {
        let size = transact(
            Exchange::Execute {
                nonce: FIRST + 500,
                request: write.as_bytes(),
            },
            &mut buffer,
        );
        if Reply::read(&buffer[..size]) != Ok(Reply::Number(1)) {
            return failed(268);
        }
    }
    transact(Exchange::Ack(FIRST + 500), &mut buffer);
    if unsafe { abi::lseek(fd, 0, SEEK_CUR) } != 4 || unsafe { abi::lseek(fd, 3, SEEK_SET) } != 3 {
        return failed(269);
    }
    // Hold enough independent results to grow beyond one 64 KiB mapping.
    for nonce in FIRST..FIRST + 80 {
        let size = transact(
            Exchange::Execute {
                nonce,
                request: request.as_bytes(),
            },
            &mut buffer,
        );
        if Reply::read(&buffer[..size]) != Ok(Reply::Bytes(b"/")) {
            return failed(259);
        }
    }
    for nonce in FIRST..FIRST + 80 {
        let size = transact(Exchange::Fetch(nonce), &mut buffer);
        if Reply::read(&buffer[..size]) != Ok(Reply::Bytes(b"/")) {
            return failed(260);
        }
    }
    // Remove alternating entries twice; the others must remain fetchable.
    for nonce in (FIRST..FIRST + 80).step_by(2) {
        for _ in 0..2 {
            let size = transact(Exchange::Ack(nonce), &mut buffer);
            if Reply::read(&buffer[..size]) != Ok(Reply::Unit) {
                return failed(261);
            }
        }
    }
    for nonce in FIRST..FIRST + 80 {
        let size = transact(Exchange::Fetch(nonce), &mut buffer);
        let expected = if nonce.is_multiple_of(2) {
            Reply::Error(EINTR)
        } else {
            Reply::Bytes(b"/")
        };
        if Reply::read(&buffer[..size]) != Ok(expected) {
            return failed(262);
        }
        transact(Exchange::Ack(nonce), &mut buffer);
    }
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let used = sys::process_memory(&process).unwrap().used;
    let handles = sys::process_handles(&process).unwrap().live;
    // Exhaust handles so the journal cannot acquire a new memory chunk. Existing
    // capacity remains usable; the first refused reservation must precede effects.
    let mut held: [Option<Handle<Channel>>; 128] = core::array::from_fn(|_| None);
    let mut held_count = 0;
    while held_count < held.len() {
        let Ok(channel) = sys::channel_create(1) else {
            break;
        };
        held[held_count] = Some(channel);
        held_count += 1;
    }
    if held_count == 0 || held_count == held.len() {
        return failed(263);
    }
    let first = FIRST + 1000;
    let mut count = 0;
    while count < 200 {
        let size = transact(
            Exchange::Execute {
                nonce: first + count,
                request: request.as_bytes(),
            },
            &mut buffer,
        );
        match Reply::read(&buffer[..size]) {
            Ok(Reply::Bytes(b"/")) => count += 1,
            Ok(Reply::Error(ENOMEM)) => break,
            _ => return failed(264),
        }
    }
    if count <= 80 || count == 200 {
        return failed(265);
    }
    request = Writer::new();
    Request::Write {
        fd: fd as u32,
        bytes: b"X",
    }
    .write(&mut request)
    .unwrap();
    let refused = first + count;
    let size = transact(
        Exchange::Execute {
            nonce: refused,
            request: request.as_bytes(),
        },
        &mut buffer,
    );
    if Reply::read(&buffer[..size]) != Ok(Reply::Error(ENOMEM)) {
        return failed(266);
    }
    for nonce in first..=refused {
        transact(Exchange::Ack(nonce), &mut buffer);
    }
    drop(held);
    if unsafe { abi::lseek(fd, 0, SEEK_CUR) } != 3
        || sys::process_memory(&process).unwrap().used != used
        || sys::process_handles(&process).unwrap().live != handles
    {
        return failed(267);
    }
    let mut byte = 0;
    if unsafe { abi::read(fd, &mut byte, 1) } != 1 || byte != b'Z' {
        return failed(270);
    }
    rt::println!(
        "file-reply-probe: journal growth, independent identities, repeated Ack and pre-effect allocation failure ok"
    );
    true
}

pub(super) fn run() -> bool {
    // Three transport frames plus two native trampolines need a managed 64 KiB
    // stack; the boot main thread has only 16 KiB and no alternate signal stack.
    let mut id = 0;
    let mut result = ptr::null_mut();
    if unsafe { threads::pthread_create(&mut id, ptr::null(), Some(worker), ptr::null_mut()) } != 0
        || unsafe { threads::pthread_join(id, &mut result) } != 0
        || result as usize != 1
    {
        return failed(258);
    }
    true
}
