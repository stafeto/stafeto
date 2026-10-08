// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Atomic observation of one exact native lifetime for guest regressions.
use super::*;
static OWNER: AtomicU64 = AtomicU64::new(0);
static NATIVE: AtomicU64 = AtomicU64::new(0);
static CHANNEL: AtomicU64 = AtomicU64::new(0);
static TIMER: AtomicU64 = AtomicU64::new(0);
static PAGE: AtomicUsize = AtomicUsize::new(0);
static BLOCK: AtomicUsize = AtomicUsize::new(0);
static OUTER: AtomicU32 = AtomicU32::new(0);
static WAITED: AtomicU32 = AtomicU32::new(0);
static UNSAFE: AtomicU32 = AtomicU32::new(0);
static EARLY_ENTRY: AtomicU32 = AtomicU32::new(0);
static ENTRIES: AtomicU32 = AtomicU32::new(0);
static PARKED: AtomicU64 = AtomicU64::new(0);
static QUEUE: AtomicU32 = AtomicU32::new(0);
static QUEUED: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
pub struct NativeStopSnapshot {
    pub owner: u64,
    pub native: u64,
    pub channel: u64,
    pub timer: u64,
    pub page: usize,
    pub block: usize,
    pub waited: bool,
    pub unsafe_accept: bool,
    pub early_entry: bool,
    pub entries: u32,
    pub parked: u64,
    pub queued: u32,
}

/// Reset the journal in the selected caller's installed scope.
pub fn probe_native_stop_arm() -> Result<NativeStopSnapshot, i32> {
    let block = own();
    let owner = crate::relibc::open_owner()?;
    if !crate::relibc::native::is_resident(block) {
        return Err(EINVAL);
    }
    OWNER.store(0, Ordering::SeqCst);
    NATIVE.store(block.thread.load(Ordering::SeqCst), Ordering::SeqCst);
    CHANNEL.store(block.channel.load(Ordering::SeqCst), Ordering::SeqCst);
    TIMER.store(block.timer.load(Ordering::SeqCst), Ordering::SeqCst);
    PAGE.store(posix_thread::thread_pointer() & !4095, Ordering::SeqCst);
    BLOCK.store(core::ptr::from_ref(block) as usize, Ordering::SeqCst);
    OUTER.store(0, Ordering::SeqCst);
    WAITED.store(0, Ordering::SeqCst);
    UNSAFE.store(0, Ordering::SeqCst);
    EARLY_ENTRY.store(0, Ordering::SeqCst);
    ENTRIES.store(0, Ordering::SeqCst);
    PARKED.store(0, Ordering::SeqCst);
    QUEUE.store(0, Ordering::SeqCst);
    QUEUED.store(0, Ordering::SeqCst);
    OWNER.store(owner, Ordering::SeqCst);
    Ok(probe_native_stop_snapshot())
}

pub fn probe_native_stop_snapshot() -> NativeStopSnapshot {
    NativeStopSnapshot {
        owner: OWNER.load(Ordering::SeqCst),
        native: NATIVE.load(Ordering::SeqCst),
        channel: CHANNEL.load(Ordering::SeqCst),
        timer: TIMER.load(Ordering::SeqCst),
        page: PAGE.load(Ordering::SeqCst),
        block: BLOCK.load(Ordering::SeqCst),
        waited: WAITED.load(Ordering::SeqCst) != 0,
        unsafe_accept: UNSAFE.load(Ordering::SeqCst) != 0,
        early_entry: EARLY_ENTRY.load(Ordering::SeqCst) != 0,
        entries: ENTRIES.load(Ordering::SeqCst),
        parked: PARKED.load(Ordering::SeqCst),
        queued: QUEUED.load(Ordering::SeqCst),
    }
}
fn selected(block: &Block) -> bool {
    let owner = OWNER.load(Ordering::SeqCst);
    owner != 0
        && crate::relibc::owner_token(block.thread_id) == Some(owner)
        && block.thread.load(Ordering::SeqCst) == NATIVE.load(Ordering::SeqCst)
}
pub fn probe_native_stop_outer(held: bool) {
    assert!(selected(own()));
    OUTER.store(u32::from(held), Ordering::SeqCst);
}
pub(super) fn scan(block: &Block, native: u64, state: stop_barrier::State, quiet: bool) {
    if selected(block)
        && native == NATIVE.load(Ordering::SeqCst)
        && matches!(state, stop_barrier::State::KernelWait)
    {
        if quiet && OUTER.load(Ordering::SeqCst) != 0 {
            UNSAFE.store(1, Ordering::SeqCst);
        }
        if !quiet {
            WAITED.store(1, Ordering::SeqCst);
        }
    }
}
pub(super) fn entry(block: &Block) {
    if selected(block) {
        ENTRIES.fetch_add(1, Ordering::SeqCst);
        if OUTER.load(Ordering::SeqCst) != 0 {
            EARLY_ENTRY.store(1, Ordering::SeqCst);
        }
    }
}
pub(super) fn park(block: &Block, raw: u64) {
    if selected(block) {
        PARKED.store(raw, Ordering::SeqCst);
    }
}
pub fn probe_native_exit_queue() {
    assert!(selected(own()));
    QUEUE.store(1, Ordering::SeqCst);
}
pub(super) fn queue_after_intent(block: &Block) {
    if selected(block) && QUEUE.swap(0, Ordering::SeqCst) != 0 {
        let native =
            Handle::<rt::handle::Thread>::borrowed(rt::abi::Handle(NATIVE.load(Ordering::SeqCst)));
        QUEUED.store(3, Ordering::SeqCst);
        let result = sys::thread_upcall_request(&native);
        QUEUED.store(if result.is_ok() { 1 } else { 2 }, Ordering::SeqCst);
    }
}
