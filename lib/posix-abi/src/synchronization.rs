// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! RAM has no asynchronous writes or deferred writeback. Synchronization
//! validates the current descriptor and its immutable type without an I/O loan.

use crate::constants::{EBADF, EINVAL};
use posix_fs::{FileKind, Target};

/// Both fsync and fdatasync are deferred cancellation points. Descriptor
/// custody and the table guard end before cancellation invokes user cleanup.
pub fn synchronize(number: i32) -> Result<(), i32> {
    let point = crate::threads::cancel::Point::begin();
    let result = (|| {
        let fd = u32::try_from(number).map_err(|_| EBADF)?;
        crate::shared::with_fd(fd, |files| {
            let target = files.target(fd).map_err(crate::error)?;
            let Target::Ram(exact) = target else {
                return Err(EINVAL);
            };
            match exact.kind().map_err(crate::error)? {
                FileKind::Regular | FileKind::Directory => Ok(()),
                _ => Err(EINVAL),
            }
        })
    })();
    if result.is_ok() {
        point.end();
    } else {
        point.finish();
    }
    result
}

/// All supported file systems complete their writes before returning them.
pub fn sync() -> Result<(), i32> {
    Ok(())
}
