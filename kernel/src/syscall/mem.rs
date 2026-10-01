// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calls of memory objects (spec 7, 11): mem_create, mem_map, mem_unmap and mem_protect, long calls in portions.

use super::{Args, Values, caller, cause, dispatch, lookup, restart, run_portions, set_result};
use crate::arch::timer as clock;
use crate::memory::{self, Memory};
use crate::object::Object;
use crate::process::{self, Change, Op};
use crate::thread::{self, Long, Thread};
use crate::{arch, cleanup, sched};
use abi::{DMA_MEMORY_RIGHTS, Error, Handle, MEMORY_RIGHTS, Rights};
use core::ptr::NonNull;
use kcore::PAGE_SIZE;
use kcore::args::{MemoryKind, access_arg, memory_kind_arg, memory_size_arg, range_arg};
use kcore::maps::Mapping;

/// The next entry of the long call `long` of `thread` (spec 7.7), which
/// started over after an interrupt. An entry with the call's number goes
/// on where the call stopped, wherever its `svc` stands, with no check made
/// again, and its portions count from this entry. An entry with another
/// number gives the long call up as the caller's leaving does, what the
/// call held going at the thread's priority (thread::drop_long): a stretch
/// of its own, which counts toward the longest portion (KERNEL_STATS x5).
/// With an interrupt pending the entry then starts over at its `svc`
/// (`restart`), and call `number` runs the usual way on the next entry;
/// otherwise it runs at once. Kept out of `dispatch`: inlined, its loop
/// back into `dispatch` lengthens the entry of every call.
#[inline(never)]
pub(super) fn go_on(thread: NonNull<Thread>, long: Long, number: u16) {
    let entry = clock::now();
    if number != long.call().number() {
        // SAFETY: the running thread is alive, and nothing uses what its
        // call held afterwards.
        unsafe { thread::drop_long(thread, cause(thread)) };
        cleanup::count_portion(entry);
        sched::entry_polled();
        if arch::irq_pending() {
            return restart(thread);
        }
        // The poll above ended the entry's interval; the call starts one.
        sched::entry_started();
        return dispatch(thread, number);
    }
    match long {
        Long::Create(m) => make(thread, m, entry),
        Long::Change(on) => portions(thread, on, entry),
    }
}

/// mem_create(x0 size, x1 flags, x2 resource): a memory object of `size`
/// bytes, whole pages from one page to abi::MAX_MEMORY, whose frames the
/// kernel takes and zeroes at once, in portions (spec 7.3, 7.7); x1
/// returns a handle to it with abi::MEMORY_RIGHTS once it is whole. With
/// abi::MEM_CONTIGUOUS the object is one block of the frame allocator,
/// whose frames are also cleaned out of the data cache, x2 names a system
/// resource with DEVICE, the handle carries abi::DMA_MEMORY_RIGHTS and x2
/// returns the block's physical address; with abi::MEM_UNCACHED as well
/// its mappings are Normal Non-cacheable. The checks in the order of spec
/// 11: the size, then the flags, an unknown bit, MEM_UNCACHED alone, or a
/// contiguous size other than a power of two of pages up to
/// abi::MAX_CONTIGUOUS_PAGES (INVALID_ARGS); x2 with MEM_CONTIGUOUS alone
/// (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED without DEVICE); then the
/// resources in the order the call takes them: room in the caller's table
/// (LIMIT_REACHED) and a chunk for it (NO_MEMORY;
/// process::reserve_handles), a place in the caller's pool of memory
/// objects, whose page the caller's quota pays for when the pool grows,
/// and the object's budget, its pages and the nodes of their list, from
/// the caller's quota at once (NO_MEMORY; memory::create), and for a
/// contiguous object its block (NO_MEMORY; memory::create_contiguous). A
/// call that fails there changes nothing but a chunk of the table or a page
/// of the pool, which stay the caller's. Then the portions (`make`); the
/// call writes its own result.
pub(super) fn mem_create(thread: NonNull<Thread>, a: &Args) {
    let entry = clock::now();
    let made = memory_size_arg(a[0]).and_then(|pages| {
        let kind = memory_kind_arg(a[1], pages)?;
        if matches!(kind, MemoryKind::Contiguous { .. }) {
            lookup(thread, a[2], Rights::DEVICE, Object::resource)?;
        }
        process::reserve_handles(caller(thread), 1)?;
        match kind {
            MemoryKind::Pages => memory::create(caller(thread), pages),
            MemoryKind::Contiguous { order, uncached } => {
                memory::create_contiguous(caller(thread), order, uncached)
            }
        }
    });
    match made {
        Ok(m) => {
            thread::begin_long(thread, Long::Create(m));
            make(thread, m, entry)
        }
        Err(e) => set_result(thread, Err(e)),
    }
}

/// The portions of the mem_create of `thread` for `m`, which the thread's
/// long call holds (spec 7.7), from `entry`, the counter when the kernel
/// took the call: each takes up to memory::CREATE_PORTION pages. Each
/// stretch between two polls for interrupts counts toward the longest
/// portion (KERNEL_STATS x5): the first with the checks of its entry, the
/// last with the handle and the end of the call. After a portion that
/// leaves pages, with an interrupt pending the call starts over at its
/// `svc` (`restart`), and its next entry comes back here; otherwise the
/// next portion follows. Once the object is whole its handle goes into the
/// caller's table, where the first entry made room; when other threads of
/// the process took the room meanwhile, the call fails with LIMIT_REACHED
/// or NO_MEMORY, the only error that comes late, and the object goes at
/// the caller's priority.
fn make(thread: NonNull<Thread>, m: NonNull<Memory>, entry: u64) {
    let Some((_, start)) = run_portions(thread, entry, || Ok(memory::fill(m))) else {
        return;
    };
    thread::end_long(thread);
    let base = memory::contiguous_base(m);
    let rights = if base.is_some() {
        DMA_MEMORY_RIGHTS
    } else {
        MEMORY_RIGHTS
    };
    let h = process::insert_handle(caller(thread), Object::Memory(m), rights);
    // SAFETY: the reference `create` handed out, which the long call held,
    // goes; the handle, if it went in, holds the object, and without it
    // the object goes.
    unsafe { memory::release(m, cause(thread)) };
    set_result(
        thread,
        h.map(|h| match base {
            Some(pa) => Values::new(&[h.0, pa]),
            None => Values::new(&[h.0]),
        }),
    );
    cleanup::count_portion(start);
}

/// mem_map(x0 process with MANAGE, x1 memory object, x2 offset, x3 length,
/// x4 address, x5 access): shows `length` bytes of the object from byte
/// `offset` at `address` of the process, with access R, RW or RX
/// (abi::Access, spec 7.4); only x0 returns. The checks in the order of
/// spec 11: the values, the offset, the length and the address whole
/// pages, the length not 0, the range in the lower half, and the access
/// (INVALID_ARGS); x0 (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED without
/// MANAGE), x1 (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED without MAP_READ, or
/// MAP_WRITE for W, or MAP_EXEC for X); the process lives (BAD_STATE); the
/// range lies in the object and touches no mapping of the process and no
/// message buffer of its threads (INVALID_ARGS, process::check_free); then
/// the resources, which the process pays for whoever calls: a place in its
/// table of mappings (LIMIT_REACHED), the block of the table and the most
/// tables the range may take (NO_MEMORY, process::add_mapping). A call
/// that fails changes nothing but the block. Then the portions
/// (`portions`), which never fail but for a process that ends meanwhile;
/// the entry records the rights of x1 to map, which bound its mem_protect.
pub(super) fn mem_map(thread: NonNull<Thread>, a: &Args) -> Result<Change, Error> {
    let pages = range_arg(a[4], a[3])?;
    if !a[2].is_multiple_of(PAGE_SIZE) {
        return Err(Error::InvalidArgs);
    }
    let access = access_arg(a[5])?;
    let target = lookup(thread, a[0], Rights::MANAGE, Object::process)?;
    // SAFETY: the calling thread holds its process.
    let (m, rights) = unsafe { caller(thread).as_ref() }.lookup_with_rights(
        Handle(a[1]),
        access.rights(),
        Object::memory,
    )?;
    process::check_alive(target)?;
    let size = memory::pages(m) as u64 * PAGE_SIZE;
    if a[2].checked_add(a[3]).is_none_or(|end| end > size) {
        return Err(Error::InvalidArgs);
    }
    process::check_free(target, a[4], pages)?;
    let map = Rights::MAP_READ | Rights::MAP_WRITE | Rights::MAP_EXEC;
    let offset = (a[2] / PAGE_SIZE) as u32;
    let mapping = Mapping::new(a[4], pages as u32, offset, m, Rights(rights.0 & map.0));
    let on = process::add_mapping(target, mapping, access)?;
    process::retain(target);
    Ok(on)
}

/// mem_unmap(x0 process with MANAGE, x1 address, x2 length): the mapping
/// of the process that is exactly that range goes, its pages and their TLB
/// entries (spec 7.4); only x0 returns. The checks in the order of spec
/// 11: the values, the address and the length whole pages, the length not
/// 0, the range in the lower half (INVALID_ARGS); x0 (BAD_HANDLE,
/// WRONG_TYPE, ACCESS_DENIED without MANAGE); the process lives
/// (BAD_STATE); one mapping is exactly that range, and the page of a
/// message buffer is no mapping (INVALID_ARGS); no long call works on it
/// (BAD_STATE). Then the portions; the mapping's reference to its object
/// goes at the end.
pub(super) fn mem_unmap(thread: NonNull<Thread>, a: &Args) -> Result<Change, Error> {
    let pages = range_arg(a[1], a[2])?;
    let target = lookup(thread, a[0], Rights::MANAGE, Object::process)?;
    process::check_alive(target)?;
    let (index, _) = process::find_mapping(target, a[1], pages)?;
    process::retain(target);
    Ok(process::begin_change(target, index, Op::Unmap))
}

/// mem_protect(x0 process with MANAGE, x1 address, x2 length, x3 access):
/// the pages of the mapping of the process that is exactly that range get
/// access R, RW or RX (spec 7.4); only x0 returns. The checks in the order
/// of spec 11: the range as mem_unmap takes it and the access
/// (INVALID_ARGS); x0 (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED without
/// MANAGE); the process lives (BAD_STATE); a mapping is that range
/// (INVALID_ARGS), no long call works on it (BAD_STATE), and the access
/// needs no right the mapping was not made with (ACCESS_DENIED). Then the
/// portions.
pub(super) fn mem_protect(thread: NonNull<Thread>, a: &Args) -> Result<Change, Error> {
    let pages = range_arg(a[1], a[2])?;
    let access = access_arg(a[3])?;
    let target = lookup(thread, a[0], Rights::MANAGE, Object::process)?;
    process::check_alive(target)?;
    let (index, rights) = process::find_mapping(target, a[1], pages)?;
    if !rights.contains(access.rights()) {
        return Err(Error::AccessDenied);
    }
    process::retain(target);
    Ok(process::begin_change(target, index, Op::Protect { access }))
}

/// The first entry of mem_map, mem_unmap or mem_protect, whose checks and
/// resources are `first`'s: a call that passed them begins its long call
/// and its portions; one that failed writes the error.
pub(super) fn change(
    thread: NonNull<Thread>,
    a: &Args,
    first: fn(NonNull<Thread>, &Args) -> Result<Change, Error>,
) {
    let entry = clock::now();
    match first(thread, a) {
        Ok(on) => {
            thread::begin_long(thread, Long::Change(on));
            portions(thread, on, entry)
        }
        Err(e) => set_result(thread, Err(e)),
    }
}

/// The portions of the change of a mapping `long` of `thread` (spec 7.7),
/// each up to process::PORTION pages or process::EXEC_PORTION with
/// execution, from `entry`, the counter when the kernel took the call.
/// Each stretch between two polls for interrupts counts toward the longest
/// portion (KERNEL_STATS x5): the first with the checks of its entry, the
/// last with the end of the call. After a portion that leaves pages, with
/// an interrupt pending the call starts over at its `svc` (`restart`), and
/// its next entry comes back here; otherwise the next portion follows. The
/// last one ends the call with 0 (process::finish_change); a process that
/// ended meanwhile ends it with BAD_STATE (process::abandon_change). Either
/// way the call's reference to the process goes, at the caller's priority.
fn portions(thread: NonNull<Thread>, mut on: Change, entry: u64) {
    let Some((result, start)) = run_portions(thread, entry, || {
        let done = process::step_change(&mut on)?;
        if !done {
            thread::update_long(thread, Long::Change(on));
        }
        Ok(done)
    }) else {
        return;
    };
    thread::end_long(thread);
    // SAFETY: the call is over, and its reference to the process goes
    // last.
    unsafe {
        match result {
            Ok(()) => process::finish_change(on, cause(thread)),
            Err(_) => process::abandon_change(on, cause(thread)),
        }
        process::release(on.target, cause(thread));
    }
    set_result(thread, result.map(|()| Values::none()));
    cleanup::count_portion(start);
}
