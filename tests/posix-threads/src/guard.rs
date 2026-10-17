// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The guard of a thread's stack is a hole below the stack (no object, no
//! memory, no entry of the kernel's table): it costs no quota whatever its
//! size, no mapping takes it, and 200 threads in a row leave the room as it
//! was. A write into a guard is SIGSEGV (tests/posix-procs/faults.c).

use super::*;
use ffi::Attr;

static READY: AtomicU64 = AtomicU64::new(0);
static RELEASE: AtomicU64 = AtomicU64::new(0);
/// The stack and the guard of the thread that ran last: base, size, guard.
static BASE: AtomicUsize = AtomicUsize::new(0);
static SIZE: AtomicUsize = AtomicUsize::new(0);
static GUARD: AtomicUsize = AtomicUsize::new(0);

/// Notes the stack the thread runs on.
fn note() {
    let mut attr = Attr::new();
    let mut base: *mut c_void = ptr::null_mut();
    let (mut size, mut guard) = (0usize, 0usize);
    // SAFETY: the calling thread is live; the out parameters are locals.
    unsafe {
        if ffi::pthread_getattr_np(ffi::pthread_self(), &mut attr) != 0
            || ffi::pthread_attr_getstack(&attr, &mut base, &mut size) != 0
            || ffi::pthread_attr_getguardsize(&attr, &mut guard) != 0
        {
            return;
        }
    }
    BASE.store(base as usize, Ordering::Release);
    SIZE.store(size, Ordering::Release);
    GUARD.store(guard, Ordering::Release);
}

/// Notes its stack, tells it is ready and waits to be released.
unsafe extern "C" fn live(argument: *mut c_void) -> *mut c_void {
    note();
    let ready = Handle::<Channel>::borrowed(rt::abi::Handle(READY.load(Ordering::Acquire)));
    let release = Handle::<Channel>::borrowed(rt::abi::Handle(RELEASE.load(Ordering::Acquire)));
    sys::notify(&ready, 1).expect("guard probe ready");
    sys::receive(&release).expect("guard probe release");
    argument
}

fn attr_with(guard: Option<usize>) -> Attr {
    let mut attr = Attr::new();
    // SAFETY: `attr` is a local.
    unsafe {
        ffi::pthread_attr_init(&mut attr);
        ffi::pthread_attr_setstacksize(&mut attr, 65536);
        if let Some(guard) = guard {
            ffi::pthread_attr_setguardsize(&mut attr, guard);
        }
    }
    attr
}

/// A live thread with `guard` bytes of guard: its pthread and the quota
/// the process has used while it lives.
fn start(process: &Handle<rt::handle::Process>, guard: usize) -> Option<(u64, u64)> {
    let attr = attr_with(Some(guard));
    let mut thread = 0;
    // SAFETY: valid attributes and a start routine.
    if unsafe { ffi::pthread_create(&mut thread, &attr, Some(live), ptr::null_mut()) } != 0 {
        return None;
    }
    let ready = Handle::<Channel>::borrowed(rt::abi::Handle(READY.load(Ordering::Acquire)));
    sys::receive(&ready).ok()?;
    let used = sys::process_memory(process).ok()?.used;
    Some((thread, used))
}

/// Releases and joins the live threads.
fn stop(threads: &[u64]) -> bool {
    let release = Handle::<Channel>::borrowed(rt::abi::Handle(RELEASE.load(Ordering::Acquire)));
    threads.iter().all(|_| sys::notify(&release, 1).is_ok())
        && threads
            .iter()
            .all(|&thread| unsafe { ffi::pthread_join(thread, &mut ptr::null_mut()) } == 0)
        && settle()
}

/// The quota a live thread takes with `guard` bytes of guard, over the
/// quota before it.
fn cost(process: &Handle<rt::handle::Process>, guard: usize) -> Option<u64> {
    let before = sys::process_memory(process).ok()?.used;
    let (thread, used) = start(process, guard)?;
    stop(&[thread]).then_some(())?;
    Some(used - before)
}

pub(super) fn run() -> bool {
    let ready = sys::channel_create(30).expect("guard ready channel");
    let release = sys::channel_create(30).expect("guard release channel");
    READY.store(ready.raw().0, Ordering::Release);
    RELEASE.store(release.raw().0, Ordering::Release);
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));

    // The quota: a warm-up round pays for the pools, then the thread costs
    // the same with no guard, one page and sixteen.
    if cost(&process, 0).is_none() {
        return failed(1700);
    }
    let costs = [0, 4096, 16 * 4096].map(|guard| cost(&process, guard));
    if costs.iter().any(Option::is_none) || costs[0] != costs[1] || costs[0] != costs[2] {
        rt::println!("guard-probe: quota costs {:?}", costs);
        return failed(1701);
    }

    // Two live threads: each has its guard, and the second stack does not
    // lie in the first one's guard.
    let Some((one, _)) = start(&process, 4096) else {
        return failed(1702);
    };
    let (base1, size1, guard1) = (
        BASE.load(Ordering::Acquire),
        SIZE.load(Ordering::Acquire),
        GUARD.load(Ordering::Acquire),
    );
    let Some((two, _)) = start(&process, 4096) else {
        return failed(1703);
    };
    let (base2, size2) = (BASE.load(Ordering::Acquire), SIZE.load(Ordering::Acquire));
    let hole1 = base1 - guard1;
    if guard1 != 4096
        || size1 != 65536
        || (base2 < base1 && base2 + size2 > hole1)
        || (base2 >= hole1 && base2 < base1 + size1)
    {
        return failed(1704);
    }
    if !stop(&[one, two]) {
        return failed(1706);
    }

    // 200 threads in a row leave the room as it was.
    let own = posix_abi::allocation::probe_own_pages();
    for _ in 0..200 {
        if cost(&process, 4096).is_none() {
            return failed(1708);
        }
    }
    if posix_abi::allocation::probe_own_pages() != own {
        rt::println!(
            "guard-probe: room {} pages before, {} after",
            own,
            posix_abi::allocation::probe_own_pages()
        );
        return failed(1709);
    }
    rt::println!(
        "guard-probe: guard is a hole: same quota at 0, 1 and 16 pages, no mapping in a hole, 200 cycles"
    );
    true
}
