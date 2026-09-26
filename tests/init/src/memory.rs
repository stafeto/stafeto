// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tests of memory objects, their mappings and the long calls that change
//! them (spec 7.3, 7.4, 7.7).

use crate::calls::LOWER_END;
use crate::harness::*;
use crate::timers::timer_at;

/// The tests of this module, in the order they run.
pub(crate) const TESTS: [Test; 20] = [
    (
        "mem_create_checks_its_arguments",
        mem_create_checks_its_arguments,
    ),
    (
        "mem_create_takes_the_whole_object_at_once",
        mem_create_takes_the_whole_object_at_once,
    ),
    (
        "closed_object_gives_its_frames_back",
        closed_object_gives_its_frames_back,
    ),
    (
        "memory_info_reports_size_pages_and_mappings",
        memory_info_reports_size_pages_and_mappings,
    ),
    ("mem_map_checks_its_arguments", mem_map_checks_its_arguments),
    ("map_access_is_r_rw_or_rx", map_access_is_r_rw_or_rx),
    (
        "map_needs_the_rights_of_its_access",
        map_needs_the_rights_of_its_access,
    ),
    (
        "two_mappings_show_the_same_pages",
        two_mappings_show_the_same_pages,
    ),
    (
        "mem_unmap_takes_whole_mappings",
        mem_unmap_takes_whole_mappings,
    ),
    (
        "mem_protect_takes_whole_mappings_within_their_rights",
        mem_protect_takes_whole_mappings_within_their_rights,
    ),
    ("mapping_limit_is_64", mapping_limit_is_64),
    (
        "buffer_page_cannot_be_mapped_over",
        buffer_page_cannot_be_mapped_over,
    ),
    (
        "buffer_page_cannot_be_unmapped",
        buffer_page_cannot_be_unmapped,
    ),
    (
        "buffer_page_cannot_be_protected",
        buffer_page_cannot_be_protected,
    ),
    ("busy_mapping_is_bad_state", busy_mapping_is_bad_state),
    (
        "thread_buffer_cannot_land_in_a_mapping",
        thread_buffer_cannot_land_in_a_mapping,
    ),
    ("long_calls_let_a_timer_in", long_calls_let_a_timer_in),
    (
        "mapped_object_outlives_its_last_handle",
        mapped_object_outlives_its_last_handle,
    ),
    (
        "protect_to_exec_runs_new_code",
        protect_to_exec_runs_new_code,
    ),
    ("init_segments_are_taken", init_segments_are_taken),
];

/// A memory object of `pages` pages.
pub(crate) fn memory_object(pages: u64) -> Result<Handle<Memory>, &'static str> {
    sys::mem_create(pages * PAGE as u64).map_err(|_| "mem_create failed")
}

/// mem_create(x0 size, x1 flags) checks its values, the size and then the
/// flags, of which none is known (spec 7.3, 11), and changes x0 alone on an
/// error: a size of 0, off whole pages, past abi::MAX_MEMORY or with bits
/// past it, and any flag fail with INVALID_ARGS. A good call changes x0 and
/// x1 alone: a handle with abi::MEMORY_RIGHTS, which a copy with all of
/// them shows and one with MANAGE does not get. The caller's resources are
/// kernel tests (mem_create_over_the_quota_is_no_memory).
fn mem_create_checks_its_arguments() -> Outcome {
    const N: u16 = Call::MemCreate.number();
    let page = PAGE as u64;
    let values = [
        (0, 0),
        (1, 0),
        (page - 1, 0),
        (page + 8, 0),
        (abi::MAX_MEMORY + page, 0),
        (1 << 40, 0),
        (u64::MAX, 0),
        (page, 1),
        (page, 1 << 63),
        (0, 1),
    ]
    .into_iter()
    .all(|(size, flags)| x0_alone::<N>(&[size, flags], Error::InvalidArgs.code()));
    check(
        values,
        "a bad size or a flag did not fail with INVALID_ARGS alone",
    )?;
    let mut x = marked();
    x[..2].copy_from_slice(&[2 * page, 0]);
    // SAFETY: mem_create only reads its registers.
    let after = unsafe { sys::raw::<N>(x) };
    check(
        after[0] == 0 && after[1] != 0 && after[2..] == x[2..],
        "a good mem_create failed or changed registers past x1",
    )?;
    let m: Handle<Memory> = Handle::from_raw(abi::Handle(after[1]));
    let all = sys::handle_duplicate(&m, abi::MEMORY_RIGHTS).map(close);
    let more = sys::handle_duplicate(&m, abi::MEMORY_RIGHTS | Rights::MANAGE).map(close);
    close(m)?;
    check(
        all == Ok(Ok(())) && more == Err(Error::AccessDenied),
        "the handle of mem_create does not carry MEMORY_RIGHTS and no more",
    )
}

/// mem_create takes the whole object before it returns (spec 7.3): right
/// afterwards MEMORY counts every page of an object of 600 pages as owned,
/// init's used memory grew by the pages and the three nodes of their list
/// and by nothing else, and the free frames fell by the pages at least.
/// An object made and closed first leaves a free place in init's pool of
/// memory objects, so that the call charges no page of the pool.
fn mem_create_takes_the_whole_object_at_once() -> Outcome {
    const PAGES: u64 = 600;
    close(memory_object(1)?)?;
    let before = counts()?;
    let m = memory_object(PAGES)?;
    let info = sys::memory_info(&m);
    let after = counts()?;
    check(
        info == Ok(MemoryInfo {
            size: PAGES * PAGE as u64,
            pages: PAGES,
            mappings: 0,
        }),
        "MEMORY does not count every page of a new object as owned",
    )?;
    check(
        after.0 == before.0 + (PAGES + 3) * PAGE as u64,
        "init's used memory did not grow by the pages and the nodes of the new object",
    )?;
    check(
        before.1.saturating_sub(after.1) >= PAGES,
        "the free frames did not fall by the pages of the new object",
    )?;
    close(m)
}

/// The cleanup of a memory object runs at init's level before its
/// handle_close returns (spec 7.7): right after the close of an object of
/// 256 pages, whose frames go back in portions, init's used memory, the
/// free frames and the pages of kernel pools are what they were before
/// mem_create. An object made and closed first leaves a free place in
/// init's pool of memory objects.
fn closed_object_gives_its_frames_back() -> Outcome {
    close(memory_object(1)?)?;
    let before = counts()?;
    close(memory_object(256)?)?;
    check(
        counts()? == before,
        "the frames of a closed object were not back when handle_close returned",
    )
}

/// object_info(MEMORY) takes a memory object's handle with no right needed
/// and returns its size in bytes, the pages whose frames it owns, all of a
/// new object, and its mappings, none yet, in x1-x3, and nothing past them
/// (spec 11). A process and the system resource are WRONG_TYPE for it, a
/// memory object is WRONG_TYPE for the kinds of a process and for
/// KERNEL_STATS, and a closed handle is BAD_HANDLE; x0 alone changes.
fn memory_info_reports_size_pages_and_mappings() -> Outcome {
    let m = memory_object(3)?;
    let bare = copy(&m, Rights::NONE)?;
    let gone = closed_handle()?;
    let result = memory_info_cases(bare.raw().0, gone);
    close(bare)?;
    close(m)?;
    result
}

fn memory_info_cases(bare: u64, gone: u64) -> Outcome {
    const N: u16 = Call::ObjectInfo.number();
    let memory = abi::INFO_MEMORY;
    let mut x = marked();
    x[..3].copy_from_slice(&[bare, memory, 0]);
    // SAFETY: object_info only reads its registers.
    let after = unsafe { sys::raw::<N>(x) };
    let three = MemoryInfo {
        size: 3 * PAGE as u64,
        pages: 3,
        mappings: 0,
    };
    let wrong = [
        (own().raw().0, memory, Error::WrongType),
        (resource().raw().0, memory, Error::WrongType),
        (bare, abi::INFO_PROCESS_STATE, Error::WrongType),
        (bare, abi::INFO_PROCESS_MEMORY, Error::WrongType),
        (bare, abi::INFO_KERNEL_STATS, Error::WrongType),
        (gone, memory, Error::BadHandle),
    ]
    .into_iter()
    .all(|(h, kind, error)| x0_alone::<N>(&[h, kind, 0], error.code()));
    check(
        after[0] == 0 && after[1..4] == three.to_words() && after[4..] == x[4..],
        "MEMORY through a copy with no rights did not give the size, the pages and no mapping in x1-x3 alone",
    )?;
    check(
        wrong,
        "a handle of another kind or a closed one did not fail alone",
    )
}

// Mappings (spec 6.2, 7.4, 7.7).

/// The tables and the table of mappings a page at `addr` needs are made:
/// a page of an object is mapped there and unmapped, and the object goes.
/// Tables stay until the space goes (spec 7.5), so a test that counts
/// memory afterwards sees none of them come.
fn warm(addr: usize) -> Outcome {
    let m = memory_object(1)?;
    map(&m, 0, PAGE as u64, addr, Access::Read)?;
    unmap(addr, PAGE as u64)?;
    close(m)
}

/// A child that ended, killed.
fn ended_child() -> Result<Handle<Process>, &'static str> {
    let c = child(LEVEL)?;
    sys::process_kill(&c).map_err(|_| "process_kill failed")?;
    Ok(c)
}

/// mem_map(x0 process with MANAGE, x1 memory object, x2 offset, x3 length,
/// x4 address, x5 access) checks in the order of spec 11 and changes x0
/// alone on an error: an offset, a length or an address off whole pages, a
/// length of 0, a range past the lower half and an access other than R, RW
/// or RX fail with INVALID_ARGS, through closed handles too; then x0 (a
/// closed handle BAD_HANDLE, a memory object WRONG_TYPE, a copy without
/// MANAGE ACCESS_DENIED), then x1 (BAD_HANDLE, a process WRONG_TYPE, a
/// copy without MAP_READ ACCESS_DENIED); a process that ended fails with
/// BAD_STATE before its range is looked at; a range past the object and
/// one over a mapping fail with INVALID_ARGS. A good call changes x0
/// alone. The limit of mappings is mapping_limit_is_64; the quota of the
/// process, which pays for the tables, is a kernel test
/// (map_that_does_not_fit_maps_nothing).
fn mem_map_checks_its_arguments() -> Outcome {
    let m = memory_object(4)?;
    let no_read = copy(&m, Rights::MAP_WRITE | Rights::MAP_EXEC)?;
    let no_manage = copy(&own(), Rights::NONE)?;
    let ended = ended_child()?;
    let gone = closed_handle()?;
    let result = map_cases(&m, no_read.raw().0, no_manage.raw().0, ended.raw().0, gone);
    close(no_read)?;
    close(no_manage)?;
    close(ended)?;
    let unmapped = unmap(WINDOW, PAGE as u64);
    close(m)?;
    result.and(unmapped)
}

fn map_cases(m: &Handle<Memory>, no_read: u64, no_manage: u64, ended: u64, gone: u64) -> Outcome {
    const N: u16 = Call::MemMap.number();
    let (own, mem) = (own().raw().0, m.raw().0);
    let (page, at, r) = (PAGE as u64, WINDOW as u64, Access::Read.raw());
    let cases = [
        ([own, mem, 8, page, at, r], Error::InvalidArgs),
        ([own, mem, 0, 0, at, r], Error::InvalidArgs),
        ([own, mem, 0, page + 8, at, r], Error::InvalidArgs),
        ([own, mem, 0, page, at + 8, r], Error::InvalidArgs),
        (
            [own, mem, 0, 2 * page, LOWER_END - page, r],
            Error::InvalidArgs,
        ),
        ([own, mem, 0, page, at, 6], Error::InvalidArgs),
        ([gone, gone, 8, page, at, r], Error::InvalidArgs),
        ([gone, mem, 0, page, at, r], Error::BadHandle),
        ([mem, mem, 0, page, at, r], Error::WrongType),
        ([no_manage, gone, 0, page, at, r], Error::AccessDenied),
        ([own, gone, 0, page, at, r], Error::BadHandle),
        ([own, own, 0, page, at, r], Error::WrongType),
        ([own, no_read, 0, page, at, r], Error::AccessDenied),
        ([ended, mem, 3 * page, 2 * page, at, r], Error::BadState),
        ([own, mem, 3 * page, 2 * page, at, r], Error::InvalidArgs),
        (
            [own, mem, u64::MAX - page + 1, page, at, r],
            Error::InvalidArgs,
        ),
    ]
    .into_iter()
    .all(|(args, error)| x0_alone::<N>(&args, error.code()));
    check(
        cases,
        "a bad mem_map did not fail alone as spec 11 orders it",
    )?;
    check(
        x0_alone::<N>(&[own, mem, 3 * page, page, at, r], 0),
        "a good mem_map failed or changed registers past x0",
    )?;
    check(
        x0_alone::<N>(&[own, mem, 0, page, at, r], Error::InvalidArgs.code()),
        "a mapping over another did not fail with INVALID_ARGS alone",
    )
}

/// W^X in one mapping (spec 7.4): of the access values only R (1), RW (3)
/// and RX (5) map; 0, W alone, X alone, W with X, the three together and
/// the bits past them fail with INVALID_ARGS alone.
fn map_access_is_r_rw_or_rx() -> Outcome {
    const N: u16 = Call::MemMap.number();
    let m = memory_object(1)?;
    let (own, mem, page, at) = (own().raw().0, m.raw().0, PAGE as u64, WINDOW as u64);
    let refused = [0, 2, 4, 6, 7, 8, 9, 1 << 32 | 1]
        .into_iter()
        .all(|access| x0_alone::<N>(&[own, mem, 0, page, at, access], Error::InvalidArgs.code()));
    let mut mapped = true;
    for access in [Access::Read, Access::ReadWrite, Access::ReadExec] {
        mapped &= map(&m, 0, page, WINDOW, access).is_ok() && unmap(WINDOW, page).is_ok();
    }
    close(m)?;
    check(
        refused,
        "an access other than R, RW or RX was not refused alone",
    )?;
    check(mapped, "R, RW or RX did not map")
}

/// Each access needs its rights of the object's handle (spec 5.2, 7.4): a
/// copy with MAP_READ alone maps R and fails RW and RX with ACCESS_DENIED
/// alone; one without MAP_EXEC maps RW, one without MAP_WRITE maps RX.
fn map_needs_the_rights_of_its_access() -> Outcome {
    const N: u16 = Call::MemMap.number();
    let m = memory_object(1)?;
    let (read, read_write, read_exec) = (
        copy(&m, Rights::MAP_READ)?,
        copy(&m, Rights::MAP_READ | Rights::MAP_WRITE)?,
        copy(&m, Rights::MAP_READ | Rights::MAP_EXEC)?,
    );
    let (own, page, at) = (own().raw().0, PAGE as u64, WINDOW as u64);
    let denied = [
        (&read, Access::ReadWrite),
        (&read, Access::ReadExec),
        (&read_write, Access::ReadExec),
        (&read_exec, Access::ReadWrite),
    ]
    .into_iter()
    .all(|(h, access)| {
        let args = [own, h.raw().0, 0, page, at, access.raw()];
        x0_alone::<N>(&args, Error::AccessDenied.code())
    });
    let mut mapped = true;
    for (h, access) in [
        (&read, Access::Read),
        (&read_write, Access::ReadWrite),
        (&read_exec, Access::ReadExec),
    ] {
        mapped &= map(h, 0, page, WINDOW, access).is_ok() && unmap(WINDOW, page).is_ok();
    }
    for h in [read, read_write, read_exec, m] {
        close(h)?;
    }
    check(
        denied,
        "an access past the rights of the handle was not refused alone",
    )?;
    check(
        mapped,
        "a handle with the rights of an access did not map it",
    )
}

/// Two mappings of one object show the same frames (spec 7.4): a word
/// written through one reads back through the other, and object_info
/// MEMORY counts both, then none once they went.
fn two_mappings_show_the_same_pages() -> Outcome {
    let m = memory_object(2)?;
    let (first, second) = (WINDOW, WINDOW + 16 * PAGE);
    map(&m, 0, 2 * PAGE as u64, first, Access::ReadWrite)?;
    map(&m, PAGE as u64, PAGE as u64, second, Access::ReadWrite)?;
    // SAFETY: both pages are init's mappings of the object, read and write.
    let seen = unsafe {
        ((first + PAGE + 8) as *mut u64).write_volatile(0x5EE5_BAC4);
        ((second + 8) as *const u64).read_volatile()
    };
    let info = sys::memory_info(&m);
    unmap(first, 2 * PAGE as u64)?;
    unmap(second, PAGE as u64)?;
    let after = sys::memory_info(&m);
    close(m)?;
    check(seen == 0x5EE5_BAC4, "the second mapping shows other frames")?;
    check(
        info.is_ok_and(|i| i.mappings == 2) && after.is_ok_and(|i| i.mappings == 0),
        "MEMORY did not count the mappings",
    )
}

/// mem_unmap(x0 process with MANAGE, x1 address, x2 length) takes exactly
/// one whole mapping (spec 7.4) and changes x0 alone on an error: an
/// address or a length off whole pages, a length of 0 and a range past the
/// lower half fail with INVALID_ARGS, through a closed handle too; then x0
/// (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED without MANAGE); a process that
/// ended fails with BAD_STATE; a part of a mapping, more than it, and a
/// range that starts inside it fail with INVALID_ARGS and unmap nothing.
/// The whole mapping goes with 0 in x0 alone, and a second time fails.
fn mem_unmap_takes_whole_mappings() -> Outcome {
    let m = memory_object(4)?;
    let no_manage = copy(&own(), Rights::NONE)?;
    let ended = ended_child()?;
    let gone = closed_handle()?;
    map(&m, 0, 4 * PAGE as u64, WINDOW, Access::ReadWrite)?;
    let result = unmap_cases(m.raw().0, no_manage.raw().0, ended.raw().0, gone);
    close(no_manage)?;
    close(ended)?;
    close(m)?;
    result
}

fn unmap_cases(mem: u64, no_manage: u64, ended: u64, gone: u64) -> Outcome {
    const N: u16 = Call::MemUnmap.number();
    let (own, page, at) = (own().raw().0, PAGE as u64, WINDOW as u64);
    let cases = [
        ([own, at + 8, 4 * page], Error::InvalidArgs),
        ([own, at, 4 * page + 8], Error::InvalidArgs),
        ([own, at, 0], Error::InvalidArgs),
        ([own, LOWER_END - page, 2 * page], Error::InvalidArgs),
        ([gone, at, 0], Error::InvalidArgs),
        ([gone, at, 4 * page], Error::BadHandle),
        ([mem, at, 4 * page], Error::WrongType),
        ([no_manage, at, 4 * page], Error::AccessDenied),
        ([ended, at, 4 * page], Error::BadState),
        ([own, at, page], Error::InvalidArgs),
        ([own, at, 8 * page], Error::InvalidArgs),
        ([own, at + page, 3 * page], Error::InvalidArgs),
    ]
    .into_iter()
    .all(|(args, error)| x0_alone::<N>(&args, error.code()));
    // SAFETY: the page is init's mapping, which the refused calls kept.
    let kept = unsafe { ((WINDOW + 3 * PAGE) as *const u64).read_volatile() } == 0;
    check(
        cases,
        "a bad mem_unmap did not fail alone as spec 11 orders it",
    )?;
    check(kept, "a refused mem_unmap took the mapping")?;
    check(
        x0_alone::<N>(&[own, at, 4 * page], 0),
        "the whole mapping did not go with 0 alone",
    )?;
    check(
        x0_alone::<N>(&[own, at, 4 * page], Error::InvalidArgs.code()),
        "a mapping went twice",
    )
}

/// mem_protect(x0 process with MANAGE, x1 address, x2 length, x3 access)
/// takes exactly one whole mapping within the rights it was mapped with
/// (spec 5.2, 7.4), and changes x0 alone on an error: the range as
/// mem_unmap checks it and an access other than R, RW or RX fail with
/// INVALID_ARGS, through a closed handle too; then x0 (BAD_HANDLE,
/// WRONG_TYPE, ACCESS_DENIED without MANAGE); a process that ended fails
/// with BAD_STATE; a part of a mapping fails with INVALID_ARGS; RX of a
/// mapping made through a copy without MAP_EXEC fails with ACCESS_DENIED.
/// R and then RW again change the access with 0 alone, and the pages keep
/// their contents.
fn mem_protect_takes_whole_mappings_within_their_rights() -> Outcome {
    let m = memory_object(2)?;
    let read_write = copy(&m, Rights::MAP_READ | Rights::MAP_WRITE)?;
    let no_manage = copy(&own(), Rights::NONE)?;
    let ended = ended_child()?;
    let gone = closed_handle()?;
    map(&read_write, 0, 2 * PAGE as u64, WINDOW, Access::ReadWrite)?;
    // SAFETY: the page is init's mapping, read and write.
    unsafe { ((WINDOW + 8) as *mut u64).write_volatile(0x7E57) };
    let result = protect_cases(m.raw().0, no_manage.raw().0, ended.raw().0, gone);
    let unmapped = unmap(WINDOW, 2 * PAGE as u64);
    close(read_write)?;
    close(no_manage)?;
    close(ended)?;
    close(m)?;
    result.and(unmapped)
}

fn protect_cases(mem: u64, no_manage: u64, ended: u64, gone: u64) -> Outcome {
    const N: u16 = Call::MemProtect.number();
    let (own, page, at) = (own().raw().0, PAGE as u64, WINDOW as u64);
    let (r, rw, rx) = (
        Access::Read.raw(),
        Access::ReadWrite.raw(),
        Access::ReadExec.raw(),
    );
    let cases = [
        ([own, at + 8, 2 * page, r], Error::InvalidArgs),
        ([own, at, 0, r], Error::InvalidArgs),
        ([own, at, 2 * page, 6], Error::InvalidArgs),
        ([gone, at, 2 * page, 7], Error::InvalidArgs),
        ([gone, at, 2 * page, r], Error::BadHandle),
        ([mem, at, 2 * page, r], Error::WrongType),
        ([no_manage, at, 2 * page, r], Error::AccessDenied),
        ([ended, at, 2 * page, r], Error::BadState),
        ([own, at, page, r], Error::InvalidArgs),
        ([own, at + page, page, r], Error::InvalidArgs),
        ([own, at, 2 * page, rx], Error::AccessDenied),
    ]
    .into_iter()
    .all(|(args, error)| x0_alone::<N>(&args, error.code()));
    check(
        cases,
        "a bad mem_protect did not fail alone as spec 11 orders it",
    )?;
    check(
        x0_alone::<N>(&[own, at, 2 * page, r], 0),
        "R within the rights failed or changed registers past x0",
    )?;
    // SAFETY: the page is init's mapping, readable in any access.
    let read = unsafe { ((WINDOW + 8) as *const u64).read_volatile() };
    check(
        x0_alone::<N>(&[own, at, 2 * page, rw], 0),
        "RW within the rights failed or changed registers past x0",
    )?;
    // SAFETY: as above, writable again.
    let written = unsafe {
        ((WINDOW + 16) as *mut u64).write_volatile(0x7E58);
        ((WINDOW + 16) as *const u64).read_volatile()
    };
    check(
        read == 0x7E57 && written == 0x7E58,
        "the pages lost their contents or their access",
    )
}

/// A process has 64 mappings at most (spec 7.4): the 65th fails with
/// LIMIT_REACHED alone, and once one went the next one maps. Init has
/// INIT_MAPPINGS of its own.
fn mapping_limit_is_64() -> Outcome {
    const N: u16 = Call::MemMap.number();
    let m = memory_object(1)?;
    let (own, mem, page) = (own().raw().0, m.raw().0, PAGE as u64);
    let mut made = 0;
    while made <= abi::MAX_MAPPINGS as usize
        && map(&m, 0, page, WINDOW + made * PAGE, Access::Read).is_ok()
    {
        made += 1;
    }
    let next = (WINDOW + made * PAGE) as u64;
    let refused = x0_alone::<N>(
        &[own, mem, 0, page, next, Access::Read.raw()],
        Error::LimitReached.code(),
    );
    let freed = unmap(WINDOW, page).is_ok();
    let again = map(&m, 0, page, WINDOW, Access::Read).is_ok();
    let mut unmapped = true;
    for i in 0..made {
        unmapped &= unmap(WINDOW + i * PAGE, page).is_ok();
    }
    close(m)?;
    check(
        made + INIT_MAPPINGS == abi::MAX_MAPPINGS as usize && refused,
        "the 65th mapping did not fail with LIMIT_REACHED alone",
    )?;
    check(freed && again && unmapped, "no mapping fit once one went")
}

/// A page of a message buffer is no page to map (spec 6.2): mem_map of a
/// range that takes init's buffer or the buffer of a new thread of init
/// fails with INVALID_ARGS alone, and the page next to them maps.
fn buffer_page_cannot_be_mapped_over() -> Outcome {
    const N: u16 = Call::MemMap.number();
    let m = memory_object(2)?;
    let t = thread(0, add_mark, 0, LOW, Policy::Fifo)?;
    let (own, mem, page, r) = (own().raw().0, m.raw().0, PAGE as u64, Access::Read.raw());
    let refused = [
        abi::INIT_MSGBUF - page,
        abi::INIT_MSGBUF,
        buffer(0) as u64 - page,
    ]
    .into_iter()
    .all(|at| x0_alone::<N>(&[own, mem, 0, 2 * page, at, r], Error::InvalidArgs.code()));
    let next = buffer(0) + PAGE;
    let mapped = map(&m, 0, page, next, Access::Read).and_then(|()| unmap(next, page));
    close(t)?;
    close(m)?;
    check(
        refused,
        "a range over a message buffer was not refused alone",
    )?;
    mapped
}

/// A page of a message buffer is no mapping (spec 6.2): mem_unmap of
/// init's fails with INVALID_ARGS alone, and the buffer keeps its words.
fn buffer_page_cannot_be_unmapped() -> Outcome {
    const N: u16 = Call::MemUnmap.number();
    let word = (abi::INIT_MSGBUF + 8) as *mut u64;
    // SAFETY: the page is init's message buffer, which nothing else uses
    // now.
    unsafe { word.write_volatile(0xB0FF) };
    let refused = x0_alone::<N>(
        &[own().raw().0, abi::INIT_MSGBUF, PAGE as u64],
        Error::InvalidArgs.code(),
    );
    // SAFETY: as above.
    let kept = unsafe { word.read_volatile() } == 0xB0FF;
    check(
        refused,
        "mem_unmap of the message buffer was not refused alone",
    )?;
    check(kept, "the message buffer lost its words")
}

/// A page of a message buffer is no mapping (spec 6.2): mem_protect of
/// init's to R fails with INVALID_ARGS alone, and the buffer stays
/// writable.
fn buffer_page_cannot_be_protected() -> Outcome {
    const N: u16 = Call::MemProtect.number();
    let args = [
        own().raw().0,
        abi::INIT_MSGBUF,
        PAGE as u64,
        Access::Read.raw(),
    ];
    let refused = x0_alone::<N>(&args, Error::InvalidArgs.code());
    let word = (abi::INIT_MSGBUF + 16) as *mut u64;
    // SAFETY: the page is init's message buffer, which nothing else uses
    // now.
    let written = unsafe {
        word.write_volatile(0xB0FE);
        word.read_volatile()
    };
    check(
        refused,
        "mem_protect of the message buffer was not refused alone",
    )?;
    check(written == 0xB0FE, "the message buffer is not writable")
}

/// Maps BIG bytes of the object whose handle is `m` at WINDOW of init, RW,
/// and unmaps them, again and again, until a probe caught the mapping busy
/// (mark 3) or ROUNDS rounds went; mark 2 names the call it makes, and
/// mark 0 notes 1 once every call passed.
extern "C" fn map_big(m: u64) -> ! {
    const ROUNDS: u32 = 1000;
    let m = Handle::<Memory>::borrowed(abi::Handle(m));
    let mut passed = true;
    for _ in 0..ROUNDS {
        if mark(3) != 0 || !passed {
            break;
        }
        MARKS[2].store(Call::MemMap.number().into(), Relaxed);
        passed &= sys::mem_map(&own(), &m, 0, BIG, WINDOW, Access::ReadWrite).is_ok();
        MARKS[2].store(Call::MemUnmap.number().into(), Relaxed);
        // SAFETY: the window is the test's, and nothing else uses it.
        passed &= unsafe { sys::mem_unmap(&own(), WINDOW, BIG) }.is_ok();
    }
    MARKS[0].store(passed.into(), Relaxed);
    sys::thread_exit()
}

/// Maps and unmaps BIG bytes of a new object at WINDOW of init in a thread
/// at LEVEL (`map_big`), in portions, while a thread at HIGH,
/// `probe(channel)`, waits on a channel whose timer wakes it every
/// PROBE_PERIOD_NS until it finds the mapping in the middle of the portions
/// of a mem_map (`caught_busy`). Once both ended, nothing is mapped there.
fn during_a_long_map(probe: extern "C" fn(u64) -> !) -> Outcome {
    reset_marks();
    let m = memory_object(BIG / PAGE as u64)?;
    let c = channel(QUIET)?;
    let t = timer_at(&c, HIGH)?;
    PROBE_TIMER.store(t.raw().0, Relaxed);
    let prober = spawn(1, probe, c.raw().0, HIGH, Policy::Fifo)?;
    let mapper = spawn(0, map_big, m.raw().0, LEVEL, Policy::Fifo)?;
    let armed = clock_now().and_then(|now| arm(&t, now + PROBE_PERIOD_NS));
    let ran = armed.and_then(|()| let_run());
    for h in [prober, mapper] {
        close(h)?;
    }
    close(t)?;
    close(c)?;
    close(m)?;
    ran?;
    check(
        mark(0) == 1,
        "a mem_map or a mem_unmap of the window failed",
    )?;
    check(
        mark(3) == 1,
        "no probe came in the middle of a long mem_map",
    )
}

/// Waits on channel `c` for the timer of `during_a_long_map`, again and
/// again, until mem_protect RW of the mapping of `map_big`, which changes
/// nothing, says that a long call works on it (BAD_STATE) while `map_big`
/// makes its mem_map, and marks 3; the timer comes again PROBE_PERIOD_NS
/// later otherwise. False once the channel closed.
fn caught_busy(c: u64) -> bool {
    let c = Handle::<Channel>::borrowed(abi::Handle(c));
    let t = Handle::<Timer>::borrowed(abi::Handle(PROBE_TIMER.load(Relaxed)));
    let map = u64::from(Call::MemMap.number());
    while sys::receive(&c).is_ok() {
        // SAFETY: RW is the access of the mapping; nothing changes.
        let probed = unsafe { sys::mem_protect(&own(), WINDOW, BIG, Access::ReadWrite) };
        if probed == Err(Error::BadState) && mark(2) == map {
            MARKS[3].store(1, Relaxed);
            return true;
        }
        let now = sys::clock_now().unwrap_or(0);
        let _ = sys::timer_set(&t, now + PROBE_PERIOD_NS);
    }
    false
}

/// Once a mem_map of `map_big` is busy (`caught_busy` on channel `c`),
/// calls mem_unmap and mem_protect on its mapping: mark 1 notes 1 when both
/// fail with BAD_STATE.
extern "C" fn probe_busy(c: u64) -> ! {
    if caught_busy(c) {
        // SAFETY: the calls must fail and change nothing.
        let (unmapped, protected) = unsafe {
            (
                sys::mem_unmap(&own(), WINDOW, BIG),
                sys::mem_protect(&own(), WINDOW, BIG, Access::Read),
            )
        };
        let busy = unmapped == Err(Error::BadState) && protected == Err(Error::BadState);
        MARKS[1].store(busy.into(), Relaxed);
    }
    sys::thread_exit()
}

/// A mapping that a long call works on is busy (spec 7.7): mem_unmap and
/// mem_protect of it from a thread that runs in the middle of the portions
/// of its mem_map fail with BAD_STATE; once no call works on a mapping
/// both pass.
fn busy_mapping_is_bad_state() -> Outcome {
    during_a_long_map(probe_busy)?;
    let m = memory_object(1)?;
    let mapped = map(&m, 0, PAGE as u64, WINDOW, Access::ReadWrite);
    // SAFETY: the mapping is the test's window, which nothing else uses.
    let protected = unsafe { sys::mem_protect(&own(), WINDOW, PAGE as u64, Access::Read) };
    let unmapped = unmap(WINDOW, PAGE as u64);
    close(m)?;
    check(
        mark(1) == 1,
        "a busy mapping did not refuse mem_unmap and mem_protect with BAD_STATE",
    )?;
    check(
        mapped.is_ok() && protected.is_ok() && unmapped.is_ok(),
        "mem_protect or mem_unmap failed once no call worked on the mapping",
    )
}

/// Once a mem_map of `map_big` is busy (`caught_busy` on channel `c`), asks
/// for a thread of init whose buffer is the last page of its mapping,
/// which is not mapped yet: mark 1 notes 1 for INVALID_ARGS. A thread made
/// all the same goes at once, with its buffer.
extern "C" fn probe_buffer(c: u64) -> ! {
    if caught_busy(c) {
        let last = WINDOW + BIG as usize - PAGE;
        // SAFETY: the thread never runs.
        let made = unsafe {
            sys::thread_create(
                &own(),
                add_mark,
                STACKS[2].top(),
                3,
                LOW,
                Policy::Fifo,
                last,
            )
        };
        MARKS[1].store((made == Err(Error::InvalidArgs)).into(), Relaxed);
        if let Ok(t) = made {
            let _ = t.close();
        }
    }
    sys::thread_exit()
}

/// Rounds of the calls of `long_calls` at most.
const LONG_ROUNDS: u32 = 16;
/// The long calls of memory objects (spec 7.7) that `long_calls` makes.
const LONG_CALLS: [Call; 4] = [
    Call::MemCreate,
    Call::MemMap,
    Call::MemProtect,
    Call::MemUnmap,
];
/// The free frames before the mem_create of `long_calls`.
static FREE_BEFORE: AtomicU64 = AtomicU64::new(0);

/// The bit of `call` among the calls a probe found in the middle of their
/// portions (mark 3).
fn call_bit(call: Call) -> u64 {
    1 << call.number()
}

/// Free frames now (KERNEL_STATS).
fn free_frames() -> u64 {
    sys::kernel_stats(&resource()).map_or(0, |s| s.free_frames)
}

/// Makes mem_create of BIG bytes, mem_map of them RX at WINDOW of init,
/// mem_protect to R and mem_unmap, and closes the object, round after
/// round, until a probe found each of them in the middle of its portions
/// (mark 3) or LONG_ROUNDS rounds went; mark 2 names the call it makes,
/// mark 0 notes 1 once every call passed, and mark 1 notes 1 at the end.
extern "C" fn long_calls(_: u64) -> ! {
    let all = LONG_CALLS.iter().fold(0, |bits, &c| bits | call_bit(c));
    let mut passed = true;
    let now = |call: Call| MARKS[2].store(call.number().into(), Relaxed);
    for _ in 0..LONG_ROUNDS {
        if mark(3) == all || !passed {
            break;
        }
        FREE_BEFORE.store(free_frames(), Relaxed);
        now(Call::MemCreate);
        let Ok(m) = sys::mem_create(BIG) else {
            passed = false;
            break;
        };
        now(Call::MemMap);
        passed &= sys::mem_map(&own(), &m, 0, BIG, WINDOW, Access::ReadExec).is_ok();
        // SAFETY: the window is the test's, and nothing else uses it.
        unsafe {
            now(Call::MemProtect);
            passed &= sys::mem_protect(&own(), WINDOW, BIG, Access::Read).is_ok();
            now(Call::MemUnmap);
            passed &= sys::mem_unmap(&own(), WINDOW, BIG).is_ok();
        }
        MARKS[2].store(0, Relaxed);
        passed &= m.close().is_ok();
    }
    MARKS[0].store(passed.into(), Relaxed);
    MARKS[1].store(1, Relaxed);
    sys::thread_exit()
}

/// Waits on channel `c` for its timer, PROBE_TIMER, again and again until
/// `long_calls` ended (mark 1), and looks whether the call mark 2 names is
/// in the middle of its portions, once for each call until it found it so:
/// for mem_create, the free frames fell since the call began, and by less
/// than the object's pages; for the others, mem_protect of their mapping
/// with the access the mapping has when no call works on it fails with
/// BAD_STATE. It marks the call in mark 3, and the timer comes again
/// PROBE_PERIOD_NS later.
extern "C" fn probe_long_calls(c: u64) -> ! {
    let c = Handle::<Channel>::borrowed(abi::Handle(c));
    let t = Handle::<Timer>::borrowed(abi::Handle(PROBE_TIMER.load(Relaxed)));
    while mark(1) == 0 && sys::receive(&c).is_ok() {
        let call = LONG_CALLS
            .into_iter()
            .find(|&n| u64::from(n.number()) == mark(2) && mark(3) & call_bit(n) == 0);
        let caught = match call {
            Some(Call::MemCreate) => {
                let fell = FREE_BEFORE.load(Relaxed).saturating_sub(free_frames());
                fell > 0 && fell < BIG / PAGE as u64
            }
            Some(n) => {
                let access = if n == Call::MemMap {
                    Access::ReadExec
                } else {
                    Access::Read
                };
                // SAFETY: an idle mapping at the window has this access
                // already, so the call changes nothing.
                let probed = unsafe { sys::mem_protect(&own(), WINDOW, BIG, access) };
                probed == Err(Error::BadState)
            }
            None => false,
        };
        if let Some(n) = call.filter(|_| caught) {
            MARKS[3].fetch_or(call_bit(n), Relaxed);
        }
        let now = sys::clock_now().unwrap_or(0);
        let _ = sys::timer_set(&t, now + PROBE_PERIOD_NS);
    }
    sys::thread_exit()
}

/// Spec 15.2 (memory), 7.7: long calls let a timer in. A thread at LEVEL
/// makes mem_create of BIG bytes, mem_map of them RX, whose portions take
/// 8 pages and make the instruction cache coherent for them, mem_protect
/// to R and mem_unmap (`long_calls`), while a thread at HIGH wakes every
/// PROBE_PERIOD_NS at its timer (`probe_long_calls`): it runs in the middle
/// of the portions of each of the four calls, each of which passes.
fn long_calls_let_a_timer_in() -> Outcome {
    reset_marks();
    let c = channel(QUIET)?;
    let t = timer_at(&c, HIGH)?;
    PROBE_TIMER.store(t.raw().0, Relaxed);
    let prober = spawn(1, probe_long_calls, c.raw().0, HIGH, Policy::Fifo)?;
    let caller = spawn(0, long_calls, 0, LEVEL, Policy::Fifo)?;
    let armed = clock_now().and_then(|now| arm(&t, now + PROBE_PERIOD_NS));
    let ran = armed.and_then(|()| let_run());
    for h in [prober, caller] {
        close(h)?;
    }
    close(t)?;
    close(c)?;
    ran?;
    check(mark(0) == 1, "a long call failed")?;
    check(
        mark(3) == LONG_CALLS.iter().fold(0, |bits, &c| bits | call_bit(c)),
        "no timer came in the middle of mem_create, mem_map, mem_protect and mem_unmap",
    )
}

/// A message buffer lands in no mapping (spec 6.2): thread_create with its
/// buffer on a page of a mapping that a long mem_map has not mapped yet
/// fails with INVALID_ARGS, and so does one on a page of a whole mapping.
fn thread_buffer_cannot_land_in_a_mapping() -> Outcome {
    during_a_long_map(probe_buffer)?;
    let m = memory_object(1)?;
    map(&m, 0, PAGE as u64, WINDOW, Access::ReadWrite)?;
    // SAFETY: the thread is refused, and would never run.
    let made = unsafe {
        sys::thread_create(
            &own(),
            add_mark,
            STACKS[2].top(),
            3,
            LOW,
            Policy::Fifo,
            WINDOW,
        )
    };
    let refused = made == Err(Error::InvalidArgs);
    if let Ok(t) = made {
        close(t)?;
    }
    unmap(WINDOW, PAGE as u64)?;
    close(m)?;
    check(
        mark(1) == 1,
        "a buffer went on a page of a mapping not mapped yet",
    )?;
    check(refused, "a buffer went on a page of a mapping")
}

/// A mapping keeps its object (spec 4, 7.4): once the only handle to an
/// object of 4 pages closes, its mapping still shows what init wrote, and
/// a new object of 4 pages takes none of its frames; once the mapping
/// goes, init's used memory, the free frames and the pages of kernel pools
/// are what they were before the object.
fn mapped_object_outlives_its_last_handle() -> Outcome {
    const PAGES: usize = 4;
    warm(WINDOW)?;
    close(memory_object(PAGES as u64)?)?;
    let before = counts()?;
    let m = memory_object(PAGES as u64)?;
    map(&m, 0, (PAGES * PAGE) as u64, WINDOW, Access::ReadWrite)?;
    let word = |i: usize| (WINDOW + i * PAGE + 8) as *mut u64;
    for i in 0..PAGES {
        // SAFETY: the page is init's mapping, read and write.
        unsafe { word(i).write_volatile(0xA11E_0000 + i as u64) };
    }
    close(m)?;
    let other = memory_object(PAGES as u64)?;
    // SAFETY: as above; the mapping holds the object.
    let kept = (0..PAGES).all(|i| unsafe { word(i).read_volatile() } == 0xA11E_0000 + i as u64);
    close(other)?;
    // A mapping that lost its object stays: taking it would free the
    // object twice.
    check(kept, "the mapping lost its object with the last handle")?;
    unmap(WINDOW, (PAGES * PAGE) as u64)?;
    check(
        counts()? == before,
        "the object did not go with its mapping",
    )
}

/// mem_protect to RX makes code init wrote runnable (spec 7.4): a page of
/// an object, RW, gets a function that returns 42; once the page is RX,
/// the function runs and returns 42.
fn protect_to_exec_runs_new_code() -> Outcome {
    let m = memory_object(1)?;
    map(&m, 0, PAGE as u64, WINDOW, Access::ReadWrite)?;
    let code = WINDOW as *mut u32;
    for (i, &insn) in RETURN_42.iter().enumerate() {
        // SAFETY: the page is init's mapping, read and write.
        unsafe { code.add(i).write_volatile(insn) };
    }
    // SAFETY: the page holds code init wrote, and nothing else uses it.
    let protected = unsafe { sys::mem_protect(&own(), WINDOW, PAGE as u64, Access::ReadExec) };
    let got = protected.map(|()| {
        // SAFETY: the page is RX and holds a function that takes nothing
        // and returns a word.
        let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(WINDOW) };
        f()
    });
    unmap(WINDOW, PAGE as u64)?;
    close(m)?;
    check(got == Ok(42), "the code written into the page did not run")
}

/// Init's own pages are mappings (spec 13.3): mem_map over the page of its
/// code, of its data and of its stack fails with INVALID_ARGS alone.
fn init_segments_are_taken() -> Outcome {
    const N: u16 = Call::MemMap.number();
    let m = memory_object(1)?;
    let page = |at: usize| (at & !(PAGE - 1)) as u64;
    let local = 0u64;
    let taken = [
        page(init_segments_are_taken as *const () as usize),
        page(&raw const MARKS as usize),
        page(&raw const local as usize),
    ]
    .into_iter()
    .all(|at| {
        let args = [
            own().raw().0,
            m.raw().0,
            0,
            PAGE as u64,
            at,
            Access::Read.raw(),
        ];
        x0_alone::<N>(&args, Error::InvalidArgs.code())
    });
    close(m)?;
    check(
        taken,
        "a page of init's code, data or stack was not refused alone",
    )
}

// Children with code (spec 7.9, 13.2, 13.3, 15.2): init loads the child
// program (tests/child), the boot image's file `child`, with rt::loader.
// Each child asks for its start data through its start channel, a copy of
// the channel of its `Kid` with the label START (rt::loader::spawn), and
// the arguments name its role (child::Role). Init waits for a child's
// requests and for its end on that channel, and a timer bounds each wait
// (spec 10).
