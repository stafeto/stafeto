// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Native scope state in the resident Block's existing metadata word.

use super::*;

const NATIVE: u64 = posix_thread::scope::NATIVE;
const FALLBACK: u64 = posix_thread::scope::FALLBACK;
const DEPTH: u64 = posix_thread::scope::DEPTH_MASK;
const ERROR: u64 = (u32::MAX as u64) << 32;

unsafe extern "C" {
    fn relibc_stafeto_native_layout_v1(out: *mut usize) -> i32;
    fn relibc_stafeto_native_tcb_v1(
        page: *mut u8,
        length: usize,
        id: usize,
        out: *mut usize,
    ) -> i32;
}

pub(crate) fn is_resident(block: &Block) -> bool {
    block.scope.load(Ordering::Acquire) & NATIVE != 0
}

pub(crate) fn fallback(block: &Block, error: i32) {
    block
        .scope
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
            Some((old & !(ERROR | DEPTH | NATIVE)) | FALLBACK | (u64::from(error as u32) << 32))
        })
        .unwrap();
}

pub(super) fn admission_error(block: &Block) -> Option<i32> {
    let scope = block.scope.load(Ordering::Acquire);
    let error = (scope >> 32) as u32 as i32;
    (scope & FALLBACK != 0 || (scope & NATIVE != 0 && (error != 0 || scope & DEPTH == DEPTH)))
        .then_some(if error == 0 { EAGAIN } else { error })
}

fn set_scope(block: &Block, depth: u64, error: i32) {
    block
        .scope
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
            Some(
                (old & !(ERROR | DEPTH | FALLBACK))
                    | NATIVE
                    | depth
                    | (u64::from(error as u32) << 32),
            )
        })
        .unwrap();
}

/// The current Thread keeps this row and mapping through the full scope.
pub(crate) fn begin_scope(block: &Block) -> Result<(), i32> {
    let old_depth = posix_thread::scope::enter(&block.scope).ok_or(EAGAIN)?;
    if old_depth != 0 {
        return admission_error(block).map_or(Ok(()), Err);
    }
    let index = usize::try_from(block.thread_id)
        .ok()
        .and_then(|id| id.checked_sub(1))
        .ok_or(EIO)?;
    let place = TABLE.get(index).ok_or(EIO)?;
    let Some(owner) = place.state.token(index) else {
        set_scope(block, 1, EAGAIN);
        return Err(EAGAIN);
    };
    let admitted = detach_open_owner(owner) && place.state.renew_native_scope();
    let error = if admitted { 0 } else { EAGAIN };
    set_scope(block, 1, error);
    if admitted { Ok(()) } else { Err(error) }
}

pub(crate) fn end_scope(block: &Block) {
    let scope = block.scope.load(Ordering::Acquire);
    let depth = scope & DEPTH;
    assert!(scope & NATIVE != 0 && depth != 0);
    if depth == 1
        && let Some(owner) = owner_token(block.thread_id)
    {
        detach_open_owner(owner);
    }
    posix_thread::scope::leave(&block.scope);
}

/// TABLE_LOCK and common entry deferral cover every resource insertion.
/// Each successful SVC moves its exact owner into this prepaid MAKING row.
fn populate(place: &Place, index: usize) -> Result<*mut u8, i32> {
    let native = sys::self_thread_managed().map_err(|_| EAGAIN)?;
    let raw = native.into_raw().0;
    place.native.store(raw, Ordering::Release);
    let info = sys::thread_info(&borrowed::<Thread>(raw)).map_err(|_| EIO)?;
    let channel = sys::channel_create(info.base).map_err(|_| EAGAIN)?;
    let channel_raw = channel.into_raw().0;
    place.floating.store(channel_raw, Ordering::Release);
    let timer =
        sys::timer_create(&borrowed::<Channel>(channel_raw), info.base).map_err(|_| EAGAIN)?;
    let timer_raw = timer.into_raw().0;
    place.stack_len.store(timer_raw as usize, Ordering::Release);
    let page = allocation::try_map_pages(PAGE)?.as_ptr();
    place.tcb.store(page as usize, Ordering::Release);
    place.tcb_len.store(PAGE, Ordering::Release);
    // SAFETY: the row exclusively owns a zeroed heap page; it has not
    // published this Block or installed its TLS yet.
    let mut out = [0usize; 2];
    unsafe {
        let error = relibc_stafeto_native_tcb_v1(page, PAGE, index + 1, out.as_mut_ptr());
        if error != 0 {
            return Err(error);
        }
        let block = &mut *(out[1] as *mut Block);
        block.thread_id = index as u64 + 1;
        block.scope.store(NATIVE, Ordering::Relaxed);
        block.thread.store(raw, Ordering::Relaxed);
        block.channel.store(channel_raw, Ordering::Relaxed);
        block.timer.store(timer_raw, Ordering::Relaxed);
        block
            .base_level
            .store(u32::from(info.base), Ordering::Relaxed);
        block.policy.store(
            info.policy.map_or(u64::MAX, |policy| policy as u64),
            Ordering::Relaxed,
        );
        block.flags.store(flag::CANCEL_DISABLED, Ordering::Relaxed);
        place
            .block
            .store(block as *mut Block as usize, Ordering::Release);
    }
    Ok(out[0] as *mut u8)
}

/// Failure leaves the exact raw owner available for a later retry.
fn close_owned(raw: u64) -> bool {
    if raw == 0 {
        return true;
    }
    let mut args = [0; 10];
    args[0] = raw;
    // SAFETY: the prepaid journal exclusively owns this capability. The
    // raw interface keeps it owned through every returned failure.
    let reply = unsafe { sys::raw::<{ rt::abi::Call::HandleClose.number() }>(args) };
    if let Some(error) = rt::abi::Error::from_code(reply[0]) {
        debug_assert_ne!(error, rt::abi::Error::BadHandle, "native owner invariant");
        return false;
    }
    true
}

fn close_retained(field: &AtomicU64) -> bool {
    native_owner::close_u64(field, close_owned)
}

/// Dispose a quiescent native journal, preserving its genuine identity last.
///
/// # Safety
/// TABLE_LOCK protects this row. Its Thread has genuinely Ended, or the
/// exact current creator rolled back before LIVE, removed its resident handler
/// and restored its previous TLS. No execution can borrow its Block.
unsafe fn clean_journal(place: &Place, ended: bool) -> bool {
    let block = place.block.load(Ordering::Acquire) as *const Block;
    if ended && !block.is_null() {
        // SAFETY: genuine End and TABLE keep the published resource owner resident.
        let block = unsafe { &*block };
        unsafe { posix_sync::abandon_ended(block) };
        if place.stack_len.load(Ordering::Acquire) == 0 {
            place.stack_len.store(
                block.timer.swap(0, Ordering::AcqRel) as usize,
                Ordering::Release,
            );
        }
        if place.floating.load(Ordering::Acquire) == 0 {
            place
                .floating
                .store(block.channel.swap(0, Ordering::AcqRel), Ordering::Release);
        }
    }
    if !native_owner::close_usize(&place.stack_len, close_owned) {
        return false;
    }
    if !close_retained(&place.floating) {
        return false;
    }
    let page = place.tcb.load(Ordering::Acquire);
    if page != 0 {
        let length = place.tcb_len.load(Ordering::Acquire);
        // SAFETY: the caller proves that this row exclusively owns the
        // page and no live caller or sync node can refer to its Block.
        if !unsafe {
            allocation::try_unmap_pages(core::ptr::NonNull::new_unchecked(page as *mut u8), length)
        } {
            return false;
        }
        place.block.store(0, Ordering::Release);
        place.tcb.store(0, Ordering::Release);
        place.tcb_len.store(0, Ordering::Release);
    }
    close_retained(&place.native)
}

/// Search before admission: only the kernel's current-object test proves reuse.
/// The caller holds TABLE_LOCK so each borrowed cap and page stays alive.
fn find_current() -> Result<Option<usize>, i32> {
    for (index, place) in TABLE.iter().enumerate().skip(1) {
        if place.stack.load(Ordering::Acquire) != 1 {
            continue;
        }
        let raw = place.native.load(Ordering::Acquire);
        if raw != 0 && sys::is_current_thread(&borrowed::<Thread>(raw)).map_err(|_| EIO)? {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

/// Common deferral covers the kernel resource-to-MAKING publication interval.
/// A returned page remains resident until genuine Thread End.
pub(crate) fn enter() -> Result<*mut u8, i32> {
    if !allocation::ready() || !crate::threads::ready() {
        return Err(EAGAIN);
    }
    let mut layout = [0usize; 4];
    // SAFETY: the startup provider writes only the supplied geometry words.
    let error = unsafe { relibc_stafeto_native_layout_v1(layout.as_mut_ptr()) };
    if error != 0 {
        return Err(error);
    }
    let _deferred = rt::upcall::defer_entries().map_err(|_| EAGAIN)?;
    reclaim();
    let Some(_table) = TABLE_LOCK.try_lock() else {
        return Err(EAGAIN);
    };
    if let Some(index) = find_current()? {
        let place = &TABLE[index];
        if place.state.flags() & LIVE == 0 {
            return Err(EAGAIN);
        }
        return Ok((place.tcb.load(Ordering::Acquire) + layout[3]) as *mut u8);
    }
    let Some(index) = TABLE
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(index, p)| p.state.reserve().then_some(index))
    else {
        return Err(EAGAIN);
    };
    let place = &TABLE[index];
    place.stack.store(1, Ordering::Release); // Native journal tag; no stack pointer.
    let result = populate(place, index);
    match result {
        Ok(page) => {
            let attached = crate::signals::attach_native(page);
            if let Err(error) = attached {
                // No TLS was installed and no resident handler remains.
                place.state.set_flags(lifetime::MAKING | DETACHED);
                if unsafe { clean_journal(place, false) } {
                    place.stack.store(0, Ordering::Release);
                    publish_free(place);
                }
                return Err(error);
            }
            // The resident Block becomes the sole owner of channel/timer;
            // later priority changes replace those exact fields. Journal aliases disarm.
            place.stack_len.store(0, Ordering::Release);
            place.floating.store(0, Ordering::Release);
            place.state.set_flags(LIVE | DETACHED);
            Ok(page)
        }
        Err(error) => {
            place.state.set_flags(lifetime::MAKING | DETACHED);
            if unsafe { clean_journal(place, false) } {
                place.stack.store(0, Ordering::Release);
                publish_free(place);
            }
            Err(error)
        }
    }
}

/// Called under TABLE_LOCK; failed resource cleanup keeps every journal owner.
pub(super) fn collect_row(index: usize, place: &Place) -> bool {
    if place.stack.load(Ordering::Acquire) != 1 {
        return false;
    }
    let native = place.native.load(Ordering::Acquire);
    let ended = native != 0
        && sys::thread_info(&borrowed::<Thread>(native))
            .is_ok_and(|i| i.state == ThreadState::Ended);
    if ended {
        place.state.native_ended();
    }
    let flags = place.state.flags();
    let collectible = ended && flags == LIVE | EXITED | RELEASED | DETACHED;
    if collectible && !place.state.claim_collect() {
        return true;
    }
    if collectible || flags == lifetime::MAKING | DETACHED {
        // SAFETY: genuine End or exact bootstrap rollback prevents live readers.
        if unsafe { clean_journal(place, ended) } {
            place.stack.store(0, Ordering::Release);
            publish_free(place);
        }
    }
    let _ = index;
    true
}

/// Opportunistic End collection never waits with an uninstalled or borrowed Block.
fn reclaim() {
    for (index, place) in TABLE.iter().enumerate().skip(1) {
        let owner = {
            let Some(_guard) = TABLE_LOCK.try_lock() else {
                return;
            };
            if place.stack.load(Ordering::Acquire) != 1 {
                continue;
            }
            let raw = place.native.load(Ordering::Acquire);
            let ended = raw != 0
                && sys::thread_info(&borrowed::<Thread>(raw))
                    .is_ok_and(|i| i.state == ThreadState::Ended);
            if ended {
                place.state.native_ended();
                place.state.token(index)
            } else {
                None
            }
        };
        if let Some(owner) = owner {
            detach_open_owner(owner);
        }
        let Some(_guard) = TABLE_LOCK.try_lock() else {
            return;
        };
        collect_row(index, place);
    }
}
