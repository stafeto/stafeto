// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Copied AArch64 LP64 flock fields for the four nonblocking commands.

use super::constants::{EAGAIN, EBADF, EFAULT, EINVAL, EIO, ENOLCK, EOVERFLOW};
use proto_fs::{LockCommand, LockKind, LockPhase, LockReply};

/// The pinned relibc AArch64 flock layout. Padding stays in the caller's memory.
#[repr(C)]
pub struct Flock {
    pub kind: i16,
    pub whence: i16,
    pub start: i64,
    pub length: i64,
    pub pid: i32,
}

const _: () = {
    assert!(core::mem::size_of::<Flock>() == 32);
    assert!(core::mem::align_of::<Flock>() == 8);
    assert!(core::mem::offset_of!(Flock, kind) == 0);
    assert!(core::mem::offset_of!(Flock, whence) == 2);
    assert!(core::mem::offset_of!(Flock, start) == 8);
    assert!(core::mem::offset_of!(Flock, length) == 16);
    assert!(core::mem::offset_of!(Flock, pid) == 24);
};

/// Semantic input copied before any IPC; it owns no caller address or authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Input {
    pub command: LockCommand,
    pub kind: LockKind,
    pub whence: u32,
    pub start: i64,
    pub length: i64,
    pub pid: i32,
}

impl Input {
    /// Copy the fields used by fcntl. The RAM service normalizes signed ranges.
    ///
    /// # Safety
    /// A nonnull pointer names readable flock fields for this copy.
    pub unsafe fn read(command: i32, pointer: *const u8) -> Result<Self, i32> {
        let command = match command {
            5 => LockCommand::GetPid,
            6 => LockCommand::SetPid,
            36 => LockCommand::GetOfd,
            37 => LockCommand::SetOfd,
            _ => return Err(EINVAL),
        };
        if pointer.is_null() {
            return Err(EFAULT);
        }
        // SAFETY: the caller supplies these readable fields; padding is untouched.
        let (kind, whence, start, length, pid) = unsafe {
            (
                pointer.cast::<i16>().read_unaligned(),
                pointer.add(2).cast::<i16>().read_unaligned(),
                pointer.add(8).cast::<i64>().read_unaligned(),
                pointer.add(16).cast::<i64>().read_unaligned(),
                pointer.add(24).cast::<i32>().read_unaligned(),
            )
        };
        let kind = match kind {
            0 => LockKind::Read,
            1 => LockKind::Write,
            2 => LockKind::Unlock,
            _ => return Err(EINVAL),
        };
        if !(0..=2).contains(&whence)
            || command.ofd() && pid != 0
            || command == LockCommand::GetPid && kind == LockKind::Unlock
        {
            return Err(EINVAL);
        }
        Ok(Self {
            command,
            kind,
            whence: whence as u32,
            start,
            length,
            pid: if command.ofd() { pid } else { 0 },
        })
    }

    /// Apply one saved terminal outcome after the driver settled its exact key.
    /// The driver resolves internal cancellation using its retained source reason.
    ///
    /// # Safety
    /// For successful GET, pointer names writable flock fields in this invocation.
    /// Replies passed as Ok have been strictly decoded from the RAM service.
    pub unsafe fn finish(
        self,
        pointer: *mut u8,
        outcome: Result<LockReply, i32>,
    ) -> Result<i32, i32> {
        let reply = outcome?;
        if reply.phase != LockPhase::Complete {
            return Err(EIO);
        }
        terminal_result(reply.result)?;
        if !self.command.get() {
            return if reply.blocker.is_none() {
                Ok(0)
            } else {
                Err(EIO)
            };
        }
        if pointer.is_null() {
            return Err(EFAULT);
        }
        // SAFETY: the caller supplies writable fields; each write preserves padding.
        unsafe {
            if let Some(blocker) = reply.blocker {
                pointer.cast::<i16>().write_unaligned(blocker.kind as i16);
                pointer.add(2).cast::<i16>().write_unaligned(0);
                pointer.add(8).cast::<i64>().write_unaligned(blocker.start);
                pointer
                    .add(16)
                    .cast::<i64>()
                    .write_unaligned(blocker.length);
                pointer.add(24).cast::<i32>().write_unaligned(blocker.pid);
            } else {
                pointer.cast::<i16>().write_unaligned(2);
            }
        }
        Ok(0)
    }
}

/// Map canonical service errors; transport retries and cancellation belong to the driver.
pub fn terminal_result(result: u32) -> Result<(), i32> {
    match result {
        0 => Ok(()),
        proto_fs::BAD_FD => Err(EBADF),
        proto_fs::INVALID_ARGUMENT => Err(EINVAL),
        proto_fs::OFFSET_OVERFLOW => Err(EOVERFLOW),
        proto_fs::NO_LOCKS => Err(ENOLCK),
        proto_fs::LOCK_CONFLICT => Err(EAGAIN),
        _ => Err(EIO),
    }
}
