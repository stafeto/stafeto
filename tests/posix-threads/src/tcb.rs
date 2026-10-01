// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The TCB of every pthread in relibc's layout (spec 2, 3.5): TPIDR_EL0
//! names the ABI word, the word the TCB, whose generic part relibc reads
//! (an empty TLS ending at the TCB, the TCB naming itself) and whose block
//! of the layer is 32 bytes on, errno in it. The main thread's page is in
//! `.bss`, a pthread's above its stack; two threads have two blocks; a
//! scope of the layer keeps the thread's block. A handler that enters
//! while the thread waits in a call of the layer, and a second one that
//! enters inside the first, leave each errno as it was.
use super::*;
use abi::signals::{self as api, SigAction};
use posix_thread::{BLOCK_OFFSET, Block, TCB_OFFSET};

static ERRORS: AtomicUsize = AtomicUsize::new(0);
static BLOCKS: [AtomicUsize; 2] = [const { AtomicUsize::new(0) }; 2];
static HANDLED: AtomicUsize = AtomicUsize::new(0);
static GATED: AtomicU64 = AtomicU64::new(0);

fn error() {
    ERRORS.fetch_add(1, Ordering::SeqCst);
}

/// The calling thread's block found through the register by hand, after
/// the checks of relibc's fields; 0 when one fails.
fn chain() -> usize {
    let word: usize;
    // SAFETY: reading the thread's own register changes no memory.
    unsafe { core::arch::asm!("mrs {}, tpidr_el0", out(reg) word) };
    if word == 0 {
        return 0;
    }
    // SAFETY: the register names this thread's ABI word.
    let tcb = unsafe { *(word as *const usize) };
    // SAFETY: the word names the TCB, whose first four words relibc owns.
    let generic = unsafe { *(tcb as *const [usize; 4]) };
    let block = tcb + BLOCK_OFFSET;
    let errno = unsafe { abi::__errno_location() } as usize;
    let fine = tcb == word + TCB_OFFSET
        && generic == [tcb, 0, tcb, generic[3]]
        && generic[3] >= core::mem::size_of::<posix_thread::Tcb>()
        && errno == block + core::mem::offset_of!(Block, errno)
        && block == posix_thread::block() as usize;
    if fine { block } else { 0 }
}

unsafe extern "C" fn on_signal(_: i32) {
    // SAFETY: the handler runs on a thread with a block.
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 99 };
    HANDLED.fetch_add(1, Ordering::SeqCst);
    // A second entry inside this one: its errno goes back to 99.
    if api::raise(SIGUSR2) != 0 || unsafe { *errno } != 99 {
        error();
    }
}

unsafe extern "C" fn on_nested(_: i32) {
    // SAFETY: as above.
    unsafe { *abi::__errno_location() = 98 };
    HANDLED.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn worker(argument: *mut c_void) -> *mut c_void {
    let index = argument as usize;
    let block = chain();
    let local = 0u8;
    let stack = &raw const local as usize;
    let word = posix_thread::thread_pointer();
    // The page of the TCB lies right above this thread's stack.
    if block == 0 || word < stack || word - stack > 0x10_0000 || !word.is_multiple_of(4096) {
        error();
    }
    // A scope of the layer keeps the thread's block and gives errno back.
    unsafe { *abi::__errno_location() = 55 };
    let inner = tls::with_process(|| {
        unsafe { *abi::__errno_location() = 66 };
        chain()
    });
    if inner != block || unsafe { *abi::__errno_location() } != 55 {
        error();
    }
    BLOCKS[index].store(block, Ordering::SeqCst);
    ptr::null_mut()
}

/// Joins the thread GATED holds back, with errno 777, while a handler
/// writes 99 to errno.
unsafe extern "C" fn waiter(_: *mut c_void) -> *mut c_void {
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 777 };
    let mut value = ptr::null_mut();
    let status = unsafe { threads::pthread_join(GATED.load(Ordering::Acquire), &mut value) };
    if status != 0 || HANDLED.load(Ordering::SeqCst) != 2 || unsafe { *errno } != 777 {
        error();
    }
    ptr::null_mut()
}

fn create(callback: unsafe extern "C" fn(*mut c_void) -> *mut c_void, value: usize) -> u64 {
    let mut id = 0;
    if unsafe {
        threads::pthread_create(&mut id, ptr::null(), Some(callback), value as *mut c_void)
    } != 0
    {
        error();
    }
    id
}

fn join(id: u64) {
    if unsafe { threads::pthread_join(id, ptr::null_mut()) } != 0 {
        error();
    }
}

pub(super) fn run() -> bool {
    let main = chain();
    if main == 0 || posix_thread::thread_pointer() != tls::main_page() as usize {
        return failed(600);
    }
    let workers = [create(worker, 0), create(worker, 1)];
    workers.into_iter().for_each(join);
    let blocks = BLOCKS.each_ref().map(|b| b.load(Ordering::SeqCst));
    if ERRORS.load(Ordering::SeqCst) != 0
        || blocks.contains(&0)
        || blocks[0] == blocks[1]
        || blocks.contains(&main)
    {
        return failed(601);
    }
    rt::println!("tcb-probe: each thread's register, ABI word, TCB and block at +32");
    let action = SigAction {
        handler: on_signal as *const () as u64,
        mask: 0,
        flags: 0,
    };
    let nested = SigAction {
        handler: on_nested as *const () as u64,
        mask: 0,
        flags: 0,
    };
    if unsafe { api::sigaction(SIGUSR1, &action, ptr::null_mut()) } != 0
        || unsafe { api::sigaction(SIGUSR2, &nested, ptr::null_mut()) } != 0
    {
        return failed(602);
    }
    let gate = sys::channel_create(30).expect("tcb gate");
    GATED.store(create(gated, gate.raw().0 as usize), Ordering::Release);
    let joining = create(waiter, 0);
    let native = unsafe { threads::probe_native(joining) }.expect("tcb waiter handle");
    if !waiting(&native) || api::pthread_kill(joining, SIGUSR1) != 0 {
        return failed(603);
    }
    for _ in 0..1000 {
        if HANDLED.load(Ordering::SeqCst) == 2 {
            break;
        }
        sys::yield_now().expect("tcb handler wait");
    }
    sys::notify(&gate, 1).expect("tcb gate release");
    join(joining);
    let restored = SigAction {
        handler: api::DEFAULT,
        mask: 0,
        flags: 0,
    };
    if unsafe { api::sigaction(SIGUSR1, &restored, ptr::null_mut()) } != 0
        || unsafe { api::sigaction(SIGUSR2, &restored, ptr::null_mut()) } != 0
        || HANDLED.load(Ordering::SeqCst) != 2
        || ERRORS.load(Ordering::SeqCst) != 0
    {
        return failed(604);
    }
    rt::println!(
        "tcb-probe: a handler inside a call of the layer and one nested in it leave errno as it was"
    );
    true
}
