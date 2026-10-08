// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::*;
use crate::layer::signals::{self as api, SigAction};
use rt::handle::Thread;

const POSTS: usize = 64;
const MAX_SPAN: usize = 8192;
static REMAINING: AtomicUsize = AtomicUsize::new(0);
static CLAIMS: AtomicUsize = AtomicUsize::new(0);
static HANDLED: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static CLAIM_LOW: AtomicUsize = AtomicUsize::new(usize::MAX);
static CLAIM_HIGH: AtomicUsize = AtomicUsize::new(0);
static HANDLER_LOW: AtomicUsize = AtomicUsize::new(usize::MAX);
static HANDLER_HIGH: AtomicUsize = AtomicUsize::new(0);

fn record(low: &AtomicUsize, high: &AtomicUsize) -> bool {
    let sp: usize;
    // SAFETY: read only the current stack address.
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags))
    };
    low.fetch_min(sp, Ordering::SeqCst);
    high.fetch_max(sp, Ordering::SeqCst);
    high.load(Ordering::SeqCst) - low.load(Ordering::SeqCst) <= MAX_SPAN
}

extern "C" fn after_claim(signal: i32) {
    CLAIMS.fetch_add(1, Ordering::SeqCst);
    if signal != SIGUSR1 || !record(&CLAIM_LOW, &CLAIM_HIGH) {
        // Stop the failing sequence while the original stack is still usable.
        ERRORS.fetch_add(1, Ordering::SeqCst);
        return;
    }
    let remaining = REMAINING.load(Ordering::SeqCst);
    if remaining != 0 {
        REMAINING.store(remaining - 1, Ordering::SeqCst);
        abi::signals::probe_settled_claim_window(Some(after_claim));
        if api::raise(SIGUSR1) != 0 {
            ERRORS.fetch_add(1, Ordering::SeqCst);
        }
    }
}

unsafe extern "C" fn handler(signal: i32) {
    HANDLED.fetch_add(1, Ordering::SeqCst);
    if signal != SIGUSR1 || !record(&HANDLER_LOW, &HANDLER_HIGH) {
        ERRORS.fetch_add(1, Ordering::SeqCst);
    }
    // SAFETY: the current thread retains its attached block throughout the callback.
    let block = unsafe { &*posix_thread::block() };
    if block.scope.load(Ordering::SeqCst) & posix_thread::scope::DELIVERY_PREPARING != 0
        || posix_sync::critical()
    {
        ERRORS.fetch_add(1, Ordering::SeqCst);
    }
}

pub fn run() -> bool {
    let bit = 1u64 << (SIGUSR1 - 1);
    let action = SigAction {
        handler: handler as *const () as u64,
        mask: 0,
        flags: 0,
    };
    let mut saved_action = posix_signals::INITIAL;
    let mut saved_mask = 0;
    if unsafe { api::sigaction(SIGUSR1, &action, &mut saved_action) } != 0
        || unsafe { api::pthread_sigmask(SIG_UNBLOCK, &bit, &mut saved_mask) } != 0
    {
        return false;
    }
    let mut ok = true;
    for native in [false, true] {
        REMAINING.store(POSTS, Ordering::SeqCst);
        CLAIMS.store(0, Ordering::SeqCst);
        HANDLED.store(0, Ordering::SeqCst);
        ERRORS.store(0, Ordering::SeqCst);
        CLAIM_LOW.store(usize::MAX, Ordering::SeqCst);
        CLAIM_HIGH.store(0, Ordering::SeqCst);
        HANDLER_LOW.store(usize::MAX, Ordering::SeqCst);
        HANDLER_HIGH.store(0, Ordering::SeqCst);
        abi::signals::probe_settled_claim_window(Some(after_claim));
        if native {
            // SAFETY: this is the block of the live caller, with an owned Thread capability.
            let block = unsafe { &*posix_thread::block() };
            block.pending.fetch_or(bit, Ordering::SeqCst);
            let thread =
                Handle::<Thread>::borrowed(rt::abi::Handle(block.thread.load(Ordering::Relaxed)));
            ok &= sys::thread_upcall_request(&thread).is_ok();
        } else {
            ok &= api::raise(SIGUSR1) == 0;
        }
        abi::signals::probe_settled_claim_window(None);
        ok &= CLAIMS.load(Ordering::SeqCst) == POSTS + 1
            && HANDLED.load(Ordering::SeqCst) == POSTS + 1
            && REMAINING.load(Ordering::SeqCst) == 0
            && ERRORS.load(Ordering::SeqCst) == 0;
        if !ok {
            break;
        }
    }
    ok &= unsafe { api::sigaction(SIGUSR1, &saved_action, ptr::null_mut()) } == 0;
    ok &= unsafe { api::pthread_sigmask(SIG_SETMASK, &saved_mask, ptr::null_mut()) } == 0;
    if ok {
        rt::println!(
            "signal-preparation-probe: 65 direct and native claims keep bounded stack and pending delivery"
        );
    }
    ok
}
