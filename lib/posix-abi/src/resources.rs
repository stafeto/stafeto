// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Public resource limits and supplementary groups of the authenticated process.
use crate::constants::{EAGAIN, EINVAL, EIO, ENOSYS, EPERM};
use core::sync::atomic::{AtomicU32, Ordering};
pub use proto_process::Limit;
use proto_process::{CORE, FSIZE, NOFILE};
static SETTER: AtomicU32 = AtomicU32::new(0);
struct Guard;
impl Guard {
    fn lock() -> Self {
        posix_sync::enter();
        while SETTER
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            if posix_sync::futex_wait(&SETTER, 1, posix_sync::CLOCK_MONOTONIC, None) == Err(EINVAL)
            {
                let _ = rt::sys::yield_now();
            }
        }
        Self
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        SETTER.store(0, Ordering::Release);
        posix_sync::futex_wake(&SETTER, u32::MAX);
        posix_sync::leave();
    }
}
/// # Safety
/// The fork child's sole thread, before any public resource operation.
pub unsafe fn after_fork() {
    SETTER.store(0, Ordering::Relaxed);
}
fn errno(status: proto_wire::Status) -> i32 {
    match status.code() {
        proto_process::INVALID => EINVAL,
        proto_process::PERMISSION => EPERM,
        proto_process::AGAIN => EAGAIN,
        _ => EIO,
    }
}
fn resource(value: i32) -> Result<usize, i32> {
    match value {
        0..=15 => match value {
            1 => Ok(FSIZE),
            4 => Ok(CORE),
            7 => Ok(NOFILE),
            _ => Err(ENOSYS),
        },
        _ => Err(EINVAL),
    }
}
pub fn get(value: i32) -> Result<Limit, i32> {
    let _guard = Guard::lock();
    match resource(value) {
        Ok(index) => crate::process::client().limit(index).map_err(errno),
        Err(ENOSYS) => Ok(Limit {
            soft: u64::MAX,
            hard: u64::MAX,
        }),
        Err(error) => Err(error),
    }
}
pub fn set(value: i32, limit: Limit) -> Result<(), i32> {
    let index = resource(value)?;
    let _guard = Guard::lock();
    crate::process::client()
        .set_limit(index, limit)
        .map_err(errno)?;
    if index == NOFILE {
        crate::shared::set_nofile_limit(limit.soft)?;
    }
    Ok(())
}
pub fn initialize_nofile() -> Result<(), i32> {
    let limit = crate::process::client().limit(NOFILE).map_err(errno)?;
    crate::shared::set_nofile_limit(limit.soft)
}
pub fn groups() -> Result<proto_process::Groups, i32> {
    crate::process::client().groups().map_err(errno)
}

/// Close the implementation-owned descriptor before delivering a size signal.
pub fn truncate_path(path: &[u8], length: i64, umask: u32) -> Result<(), i32> {
    use crate::constants::{O_CLOEXEC, O_CLOFORK, O_NOCTTY, O_WRONLY};
    struct Entry;
    impl Drop for Entry {
        fn drop(&mut self) {
            posix_sync::leave();
        }
    }
    let result = (|| {
        posix_sync::enter();
        let _entry = Entry;
        let length = u64::try_from(length).map_err(|_| EINVAL)?;
        let fd = crate::open_policy(path, O_WRONLY | O_NOCTTY | O_CLOEXEC | O_CLOFORK, 0, umask)?;
        let result = crate::shared::held(fd as u32, |_, target| {
            let posix_fs::Target::Ram(target) = target else {
                return Err(EINVAL);
            };
            crate::change::truncate(target, length)
        });
        // Retry only pre-admission Full while the internal fd and signal
        // deferral remain owned. Later errors retain exact paid close custody.
        let _ = crate::close_driver::close_owned(fd as u32);
        result
    })();
    crate::finish_file_size(result)
}
