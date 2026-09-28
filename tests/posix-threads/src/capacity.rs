// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The advertised 64 pthreads are live simultaneously with internal workers.

use super::*;
use threads::specific::*;

static KEY: AtomicU64 = AtomicU64::new(0);
static READY: AtomicU64 = AtomicU64::new(0);
static RELEASE: AtomicU64 = AtomicU64::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
const CHILDREN: usize = PTHREAD_THREADS_MAX as usize - 1;

unsafe extern "C" fn live(argument: *mut c_void) -> *mut c_void {
    let key = KEY.load(Ordering::Acquire);
    let errno = unsafe { abi::__errno_location() };
    if !pthread_getspecific(key).is_null() || pthread_setspecific(key, argument) != 0 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    unsafe { *errno = 700 + argument as i32 };
    let ready = Handle::<Channel>::borrowed(rt::abi::Handle(READY.load(Ordering::Acquire)));
    let release = Handle::<Channel>::borrowed(rt::abi::Handle(RELEASE.load(Ordering::Acquire)));
    sys::notify(&ready, 1).expect("live pthread ready");
    sys::receive(&release).expect("live pthread release");
    if pthread_getspecific(key) != argument || unsafe { *errno } != 700 + argument as i32 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    argument
}

fn receiving(native: &Handle<Thread>) -> bool {
    let wake = sys::channel_create(30).expect("capacity poll channel");
    let timer = sys::timer_create(&wake, 30).expect("capacity poll timer");
    for _ in 0..100 {
        if sys::thread_info(native).is_ok_and(|info| info.state == ThreadState::Receiving) {
            return true;
        }
        sys::timer_set(
            &timer,
            sys::clock_now().expect("capacity clock") + 1_000_000,
        )
        .expect("capacity deadline");
        sys::receive(&wake).expect("capacity poll wake");
    }
    false
}

pub(super) fn run() -> bool {
    let ready = sys::channel_create(30).expect("capacity ready channel");
    let release = sys::channel_create(30).expect("capacity release channel");
    READY.store(ready.raw().0, Ordering::Release);
    RELEASE.store(release.raw().0, Ordering::Release);
    let mut key = 0;
    if unsafe { pthread_key_create(&mut key, None) } != 0
        || pthread_setspecific(key, VALUE as *const c_void) != 0
    {
        return failed(80);
    }
    KEY.store(key, Ordering::Release);
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 123 };
    for round in 0..2 {
        let handles = sys::process_handles(&process)
            .expect("capacity handle baseline")
            .live;
        let used = sys::process_memory(&process)
            .expect("capacity quota baseline")
            .used;
        let mut children = [0; CHILDREN];
        for (index, child) in children.iter_mut().enumerate() {
            if unsafe {
                threads::pthread_create(child, ptr::null(), Some(live), (index + 1) as *mut c_void)
            } != 0
            {
                rt::println!("posix-capacity-probe: created only {} live children", index);
                return failed(81);
            }
            sys::receive(&ready).expect("confirmed live child");
            let native =
                unsafe { threads::probe_native(*child) }.expect("live child native handle");
            if !receiving(&native) {
                return failed(82);
            }
        }
        rt::println!(
            "posix-capacity-probe: {} application threads live",
            children.len() + 1
        );
        let mut past = 987;
        if unsafe {
            threads::pthread_create(&mut past, ptr::null(), Some(returning), ptr::null_mut())
        } != EAGAIN
            || past != 987
            || unsafe { *errno } != 123
            || pthread_getspecific(key) as usize != VALUE
        {
            return failed(83);
        }
        // Heap and file workers must still run while all application slots are occupied.
        let memory = unsafe { abi::allocation::malloc(64) };
        if memory.is_null() {
            return failed(84);
        }
        unsafe { abi::allocation::free(memory) };
        let fd = unsafe { abi::open(c"/etc/motd".as_ptr(), O_RDONLY) };
        let mut text = [0u8; 3];
        if fd < 0
            || unsafe { abi::read(fd, text.as_mut_ptr().cast(), text.len()) } != 3
            || text != *b"sta"
            || unsafe { abi::close(fd) } != 0
            || unsafe { *errno } != 123
        {
            return failed(85);
        }
        for _ in &children {
            sys::notify(&release, 1).expect("release one live pthread");
        }
        for (index, child) in children.into_iter().enumerate() {
            let mut value = ptr::null_mut();
            if unsafe { threads::pthread_join(child, &mut value) } != 0
                || value as usize != index + 1
            {
                return failed(86);
            }
        }
        let after = sys::process_memory(&process)
            .expect("capacity quota after join")
            .used;
        if sys::process_handles(&process)
            .expect("capacity handles after join")
            .live
            != handles
            || (round == 1 && after != used)
            || ERRORS.load(Ordering::Relaxed) != 0
            || unsafe { *errno } != 123
        {
            return failed(87);
        }
        // Round one grows paid pools and page tables; round two must reuse them.
    }
    if pthread_key_delete(key) != 0 {
        return failed(88);
    }
    rt::println!("posix-capacity-probe: exact limit, live workers and warmed quota recovery ok");
    true
}
