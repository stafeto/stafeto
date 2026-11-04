// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The owner of a socket's signals (`fcntl` F_SETOWN and F_GETOWN) and its
//! asynchronous flag (`ioctl` FIOASYNC), on the sockets of the network
//! service and of the pipe service. They are accepted and remembered; no
//! SIGIO or SIGURG is ever sent. The table keeps a record for a descriptor
//! of this process (its number and the generation of its entry), so the
//! owner belongs to the descriptor here; Linux keeps it with the open file
//! description, which another process that shares the description sees too.
//! A record whose descriptor closed is free again. The table is read and
//! changed under the lock of the descriptors.

use crate::constants::*;
use crate::shared;
use core::cell::UnsafeCell;
use posix_fs::Target;

pub use posix_fd::owners::{OWNERS, Owners};

struct Table(UnsafeCell<Owners>);
// SAFETY: every access is under the lock of the descriptors (`with_fd`).
unsafe impl Sync for Table {}
static TABLE: Table = Table(UnsafeCell::new(Owners::new()));

/// Whether `target` is a socket: of the network service, or of the pipe
/// service.
fn socket(target: Target) -> bool {
    match target {
        Target::Net(_) => true,
        Target::Pipe(end) => end & proto_pipe::sock::SOCK_END != 0,
        _ => false,
    }
}

/// What to do with the record of a socket.
pub enum Change {
    GetOwner,
    SetOwner(i32),
    Asynchronous(bool),
}

/// The change on the record of socket `fd`: the owner for GetOwner, 0 for
/// the others. `not_socket` is the errno of a descriptor that is no socket
/// (EINVAL for fcntl, ENOTTY for ioctl).
pub fn change(fd: i32, what: Change, not_socket: i32) -> Result<i32, i32> {
    let number = u32::try_from(fd).map_err(|_| EBADF)?;
    shared::with_fd(number, |files| {
        let target = files.target(number).map_err(crate::error)?;
        if !socket(target) {
            return Err(not_socket);
        }
        let generation = files.entry_generation(number).map_err(crate::error)?;
        let live =
            |fd: u32, generation: u64| files.entry_generation(fd).is_ok_and(|g| g == generation);
        // SAFETY: the lock of the descriptors is held for the closure.
        let table = unsafe { &mut *TABLE.0.get() };
        match what {
            Change::GetOwner => Ok(table.owner(number, generation)),
            Change::SetOwner(owner) => table.set_owner(number, generation, owner, live).map(|()| 0),
            Change::Asynchronous(on) => table
                .set_asynchronous(number, generation, on, live)
                .map(|()| 0),
        }
    })
}
