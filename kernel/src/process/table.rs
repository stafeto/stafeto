// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The handle table of a process (spec 5.1, 11, 13.3): lookups, inserts
//! and closes, init's first handles and the start entry of a child.

use super::*;

impl Process {
    /// What `kind` makes of the object behind `h`, checked in the order of
    /// the system calls: BAD_HANDLE, WRONG_TYPE, then ACCESS_DENIED when
    /// the handle lacks `rights`.
    pub fn lookup<U>(
        &self,
        h: Handle,
        rights: Rights,
        kind: impl FnOnce(&Object) -> Option<U>,
    ) -> Result<U, Error> {
        self.handles.get_as(h, rights, kind)
    }

    /// As `lookup`, with every right of the handle as well: what a handle
    /// that moves takes along (process_create x5).
    pub fn lookup_with_rights<U>(
        &self,
        h: Handle,
        rights: Rights,
        kind: impl FnOnce(&Object) -> Option<U>,
    ) -> Result<(U, Rights), Error> {
        let found = self.lookup(h, rights, kind)?;
        let (_, all) = self.handles.get(h)?;
        Ok((found, all))
    }
}

/// The handle table of `process` and the memory for its blocks: the
/// process's pool of blocks, which its quota pays for by the page
/// (spec 7.5, 7.8).
///
/// # Safety
/// `process` is alive, and nothing else borrows its table, its pools, its
/// quota or its page log meanwhile.
pub(super) unsafe fn table<'a>(process: NonNull<Process>) -> (&'a mut Handles, Chunks<'a>) {
    let p = process.as_ptr();
    // SAFETY: the caller's promise; only these fields are borrowed.
    unsafe {
        let chunks = Chunks {
            blocks: &mut (*p).pools.blocks,
            pages: PaidPages::new(KernelPages, &mut (*p).quota, &mut (*p).pages),
        };
        (&mut (*p).handles, chunks)
    }
}

/// LIMIT_REACHED when the handle table of `process` has no room for one
/// more entry (spec 11): a call that would insert a handle checks this
/// before it allocates anything for the call, so a full table costs
/// nothing beyond the checks that come before it in the fixed order.
pub fn handle_room(process: NonNull<Process>) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the process; only the field
    // is read.
    if unsafe { (*process.as_ptr()).handles.room() } > 0 {
        Ok(())
    } else {
        Err(Error::LimitReached)
    }
}

/// Puts `object` in the handle table of `process` with `rights`; the new
/// handle holds a reference to it. A new chunk or directory of the table
/// comes from the pool of blocks of `process`, whose quota pays for a page
/// when the pool grows, whoever the handle comes from. LIMIT_REACHED at
/// the table's limit, NO_MEMORY when the quota falls short for a page.
/// The process lives: the table of one that ended stays empty.
pub fn insert_handle(
    process: NonNull<Process>,
    object: Object,
    rights: Rights,
) -> Result<Handle, Error> {
    assert!(
        check_alive(process).is_ok(),
        "a handle went into the table of a process that ended"
    );
    // SAFETY: the caller holds a reference to the process.
    let (handles, mut chunks) = unsafe { table(process) };
    let h = handles.insert(&mut chunks, object, rights)?;
    object::retain(object, rights);
    Ok(h)
}

/// Closes handle `h` of `process`: its reference goes, and the last one
/// queues the object for cleanup at `cause`. BAD_HANDLE for a handle that
/// is not live.
pub fn close_handle(mut process: NonNull<Process>, h: Handle, cause: u8) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the process other than the
    // handle, so the process outlives the release below.
    let (object, rights) = unsafe { process.as_mut() }.handles.remove(h)?;
    // SAFETY: the handle is gone, and its reference with it.
    unsafe { object::release(object, rights, cause) };
    Ok(())
}

/// Puts init's first handles in the fresh table of `init` (spec 13.3): the
/// system resource with every right, init's process and its `first`
/// thread, and an entry for the boot image that goes at once, so that
/// INIT_BOOT_IMAGE stays bad (until milestone 1.3 brings the boot image as
/// a memory object). The values follow from the order in a fresh table and
/// are those abi fixes.
pub fn install_init_handles(init: NonNull<Process>, first: NonNull<Thread>) -> Result<(), Error> {
    let handles = [
        insert_handle(init, Object::Resource, abi::INIT_RESOURCE_RIGHTS)?,
        insert_handle(init, Object::Process(init), abi::OWNER_RIGHTS)?,
        insert_handle(init, Object::Thread(first), abi::OWNER_RIGHTS)?,
        insert_handle(init, Object::Resource, Rights::NONE)?,
    ];
    // The system resource is never queued: any level will do.
    close_handle(init, handles[3], 1)?;
    assert_eq!(
        handles,
        [
            abi::INIT_RESOURCE,
            abi::INIT_PROCESS,
            abi::INIT_THREAD,
            abi::INIT_BOOT_IMAGE
        ],
        "init's handles went into a table that was not fresh"
    );
    Ok(())
}

/// Entry 0 of the fresh table of a child that process_create made
/// (spec 13.3): with no start channel, a stub goes in and out at once, so
/// abi::START_CHANNEL stays bad there for good, even for a channel the
/// child makes itself. The directory and the first chunk of the table
/// share the first page of the child's pool of blocks, which the child
/// pays for: NO_MEMORY when its quota falls short.
pub fn reserve_start(child: NonNull<Process>) -> Result<(), Error> {
    let stub = insert_handle(child, Object::Resource, Rights::NONE)?;
    assert_eq!(
        stub,
        abi::START_CHANNEL,
        "the start entry went into a table that was not fresh"
    );
    // The system resource is never queued: any level will do.
    close_handle(child, stub, 1)
}

/// Entry 0 of the fresh table of a child that process_create made
/// (spec 13.3): the start channel, `object` with `rights`, which the
/// caller's handle names. The handle takes a new reference first; the
/// caller's handle goes only once the child is made, so the count of
/// handles with RECEIVE and the copies of a session never fall to zero
/// on the way, and a child that fails leaves the handle where it was. The
/// directory and the first chunk share the first page of the child's pool
/// of blocks, which the child pays for: NO_MEMORY when its quota falls
/// short.
pub fn move_start(child: NonNull<Process>, object: Object, rights: Rights) -> Result<(), Error> {
    let h = insert_handle(child, object, rights)?;
    assert_eq!(
        h,
        abi::START_CHANNEL,
        "the start entry went into a table that was not fresh"
    );
    Ok(())
}

/// The handles of `process`, which the caller holds, for object_info's
/// PROCESS_HANDLES: live, retired at their last generation, and the limit.
/// A process whose stage Handles is over has an empty table.
pub fn handle_counts(process: NonNull<Process>) -> (u32, u32, u32) {
    // SAFETY: the caller holds a reference to the process; only the field
    // is read.
    let handles = unsafe { &(*process.as_ptr()).handles };
    (handles.len(), handles.retired(), handles.limit())
}
