// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Public resource limits and supplementary groups of the authenticated process.
use crate::constants::{EAGAIN, EINVAL, EIO, ENOSYS, EPERM};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
pub use proto_process::Limit;
use proto_process::{AS, CORE, DATA, FSIZE, NOFILE, STACK};
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
            2 => Ok(DATA),
            3 => Ok(STACK),
            4 => Ok(CORE),
            7 => Ok(NOFILE),
            9 => Ok(AS),
            _ => Err(ENOSYS),
        },
        _ => Err(EINVAL),
    }
}
/// RLIMIT_MEMLOCK (Linux's 8), kept by the layer apart from the service's
/// limits: the memory of a process is resident, so the limit only decides
/// who may lock (`lock_check`). A child of `fork` has the same.
const MEMLOCK: i32 = 8;
static MEMLOCK_SOFT: AtomicU64 = AtomicU64::new(u64::MAX);
static MEMLOCK_HARD: AtomicU64 = AtomicU64::new(u64::MAX);
/// `mlockall(MCL_FUTURE)` is on: what is mapped from now on is to be locked.
static LOCK_FUTURE: AtomicBool = AtomicBool::new(false);
static LOCKED_ALL: AtomicBool = AtomicBool::new(false);

/// Whether the caller may lock `bytes` of memory: a process of the
/// superuser always; another within RLIMIT_MEMLOCK, which is EPERM at 0 and
/// ENOMEM past it.
pub fn lock_check(bytes: u64) -> Result<(), i32> {
    if crate::process::geteuid() == 0 {
        return Ok(());
    }
    match MEMLOCK_SOFT.load(Ordering::Relaxed) {
        0 => Err(EPERM),
        soft if bytes > soft => Err(crate::constants::ENOMEM),
        _ => Ok(()),
    }
}

/// `mlockall` of the flags `current` (MCL_CURRENT) and `future`
/// (MCL_FUTURE): the check of what is mapped now, and the mark for what is
/// mapped later.
pub fn lock_all(current: bool, future: bool) -> Result<(), i32> {
    if current {
        let used = rt::sys::process_memory(crate::allocation::process()).map_or(0, |m| m.used);
        lock_check(used)?;
    } else {
        lock_check(0)?;
    }
    LOCK_FUTURE.store(future, Ordering::Relaxed);
    LOCKED_ALL.store(true, Ordering::Relaxed);
    Ok(())
}

/// Whether `mlockall` locked the process's memory (and `munlockall` has not
/// undone it): MS_INVALIDATE of a locked page is EBUSY.
pub fn locked_all() -> bool {
    LOCKED_ALL.load(Ordering::Relaxed)
}

/// `munlockall`: later mappings are no longer to be locked.
pub fn unlock_all() {
    LOCK_FUTURE.store(false, Ordering::Relaxed);
    LOCKED_ALL.store(false, Ordering::Relaxed);
}

/// A mapping of `bytes` under `mlockall(MCL_FUTURE)`: EAGAIN where the
/// caller may not lock it (past RLIMIT_MEMLOCK).
pub fn future_check(bytes: u64) -> Result<(), i32> {
    if LOCK_FUTURE.load(Ordering::Relaxed) {
        lock_check(bytes).map_err(|_| EAGAIN)
    } else {
        Ok(())
    }
}

pub fn get(value: i32) -> Result<Limit, i32> {
    if value == MEMLOCK {
        return Ok(Limit {
            soft: MEMLOCK_SOFT.load(Ordering::Relaxed),
            hard: MEMLOCK_HARD.load(Ordering::Relaxed),
        });
    }
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
    if value == MEMLOCK {
        if limit.soft > limit.hard {
            return Err(EINVAL);
        }
        // The hard limit goes up only for the superuser.
        if limit.hard > MEMLOCK_HARD.load(Ordering::Relaxed) && crate::process::geteuid() != 0 {
            return Err(EPERM);
        }
        MEMLOCK_SOFT.store(limit.soft, Ordering::Relaxed);
        MEMLOCK_HARD.store(limit.hard, Ordering::Relaxed);
        return Ok(());
    }
    let index = resource(value)?;
    let _guard = Guard::lock();
    crate::process::client()
        .set_limit(index, limit)
        .map_err(errno)?;
    if index == NOFILE {
        crate::shared::set_nofile_limit(limit.soft)?;
    }
    if index == DATA || index == AS {
        crate::mmap::set_limit(value, limit.soft);
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
