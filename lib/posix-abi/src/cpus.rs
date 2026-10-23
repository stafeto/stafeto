// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The CPUs of the machine as a program sees them (XSH sysconf
//! `_SC_NPROCESSORS_CONF` and `_SC_NPROCESSORS_ONLN`, `sched_getaffinity`,
//! `sched_setaffinity`, `/proc/stat`, `/proc/cpuinfo`; spec 8, SMP).
//!
//! The kernel tells how many CPUs are up and what each has slept and spent
//! in entries (object_info CPU, no handle needed), and which of them the
//! process may use at all: its CPU mask, set by its creator and never
//! changed (kernel spec 8, process_create x8; the process service gives
//! each process the mask of its record in init's table, and fork, spawn and
//! exec keep it). A process's threads run on its CPU: the process service
//! puts the main thread of each new image on the least busy of the CPUs the
//! process's page allows (`Page::cpus`, 0 for all) within that mask and a
//! thread the process makes starts on the CPU of its creator.
//! `sched_setaffinity` writes the process's mask to the page, within the
//! mask of the kernel: the threads made after it and the image of the next
//! exec go where the mask allows, and a thread that runs stays on its CPU
//! (the kernel moves no thread). `sched_getaffinity` and `nproc` show the
//! mask of the page cut to the mask of the kernel.

use crate::constants::*;
use core::sync::atomic::{AtomicU8, Ordering};
use rt::sys;

/// The CPUs one mask word names.
const WORD: usize = 64;
/// 0 until the first call; then the CPUs up.
static COUNT: AtomicU8 = AtomicU8::new(0);
/// 0 until the first call; then the CPU mask of the kernel for this
/// process, which never changes (fork keeps it, exec starts anew).
static KERNEL: AtomicU8 = AtomicU8::new(0);

/// The CPUs that are up, at least 1 and at most `WORD`.
pub fn count() -> usize {
    match COUNT.load(Ordering::Relaxed) {
        0 => {
            let cpus = sys::cpu_info(0).map_or(1, |info| info.cpus as usize);
            let cpus = cpus.clamp(1, WORD);
            COUNT.store(cpus as u8, Ordering::Relaxed);
            cpus
        }
        cpus => usize::from(cpus),
    }
}

/// The CPU the calling thread runs on, 0 where the kernel does not tell.
pub fn current() -> usize {
    sys::cpu_info(0).map_or(0, |info| info.current as usize)
}

/// The mask of the CPUs that are up.
fn online() -> u64 {
    match count() {
        WORD => u64::MAX,
        cpus => (1u64 << cpus) - 1,
    }
}

/// The CPUs the kernel lets the process's threads run on (object_info CPU,
/// x6) among those that are up; every CPU that is up where the kernel does
/// not tell.
pub fn permitted() -> u64 {
    match KERNEL.load(Ordering::Relaxed) {
        0 => {
            let mask = sys::cpu_info(0).map_or(0, |info| info.allowed) & online();
            let mask = if mask == 0 { online() } else { mask };
            KERNEL.store(mask as u8, Ordering::Relaxed);
            mask
        }
        mask => u64::from(mask),
    }
}

/// The CPUs the process may use: the mask of its page within the mask of
/// the kernel, or all of the kernel's.
pub fn allowed() -> u64 {
    match crate::process::page().cpus.load(Ordering::Acquire) & permitted() {
        0 => permitted(),
        mask => mask,
    }
}

/// The time of CPU `index` in hundredths of a second since it started:
/// busy in user mode, busy in the kernel and idle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Times {
    pub user: u64,
    pub system: u64,
    pub idle: u64,
}

/// What CPU `index` has counted (object_info CPU), None for a CPU that is
/// not up. User time is what remains of the time since the start less the
/// time asleep and in the kernel: it holds the time of the programs and the
/// kernel's work between entries (interrupts, cleanup).
pub fn times(index: usize) -> Option<Times> {
    let info = sys::cpu_info(index as u64).ok()?;
    let hundredths = |ticks: u64| rt::time::ticks_to_ns(ticks) / 10_000_000;
    let (system, idle) = (info.system.min(info.since), info.idle.min(info.since));
    let user = info.since.saturating_sub(system).saturating_sub(idle);
    Some(Times {
        user: hundredths(user),
        system: hundredths(system),
        idle: hundredths(idle),
    })
}

/// The mask of the CPUs the process `pid` may use, all that are up for a
/// mask of 0 (the process's own page for 0 and the caller's PID, the
/// process service's listing for another process: ESRCH when it does not
/// exist).
fn mask_of(pid: i32) -> Result<u64, i32> {
    let stored = if pid < 0 {
        return Err(ESRCH);
    } else if pid == 0 || pid == crate::process::getpid() {
        crate::process::page().cpus.load(Ordering::Acquire)
    } else {
        // The record of a process is its PID modulo the records, and the
        // first live record from that index is the process when it lives.
        let wanted = pid as u32;
        let (_, found, _) = crate::process::list(wanted % proto_process::RECORDS as u32)?;
        found.filter(|l| l.pid == wanted).ok_or(ESRCH)?.cpus
    };
    // The listing of the process service gives the mask of another process
    // within its CPUs already; here it is shown within those that are up.
    let within = if pid == 0 || pid == crate::process::getpid() {
        permitted()
    } else {
        online()
    };
    Ok(match stored & within {
        0 => within,
        mask => mask,
    })
}

/// The caller's process, as `pid` names it: 0 and its own PID. Another
/// process that exists is not the caller's to set (EPERM), one that does not
/// is ESRCH.
fn own(pid: i32) -> Result<(), i32> {
    if pid < 0 {
        return Err(ESRCH);
    }
    if pid == 0 || pid == crate::process::getpid() {
        return Ok(());
    }
    mask_of(pid).and(Err(EPERM))
}

/// sched_getaffinity: the process's mask into `out`, little-endian bytes
/// with the rest zeros. EINVAL for room too small for the CPUs that are up.
pub fn getaffinity(pid: i32, out: &mut [u8]) -> Result<(), i32> {
    let mask = mask_of(pid)?;
    if out.len() * 8 < count() {
        return Err(EINVAL);
    }
    out.fill(0);
    let mask = mask.to_le_bytes();
    let n = out.len().min(mask.len());
    out[..n].copy_from_slice(&mask[..n]);
    Ok(())
}

/// sched_setaffinity: the process's mask from `mask`, little-endian bytes.
/// EINVAL when none of the CPUs it names is up and allowed by the kernel;
/// the bits past those are ignored, and the page keeps the rest. The threads
/// made after the call and the image of the next exec go where the mask
/// allows.
pub fn setaffinity(pid: i32, mask: &[u8]) -> Result<(), i32> {
    own(pid)?;
    let mut word = [0u8; 8];
    let n = mask.len().min(word.len());
    word[..n].copy_from_slice(&mask[..n]);
    let named = u64::from_le_bytes(word) & permitted();
    if named == 0 {
        return Err(EINVAL);
    }
    // All the kernel's CPUs named is the default, which a child leaves to
    // the service.
    let stored = if named == permitted() { 0 } else { named };
    crate::process::page().cpus.store(stored, Ordering::Release);
    Ok(())
}

/// The CPU for a thread the caller makes (thread_create x5, the CPU plus
/// one; 0 for the caller's CPU): the caller's own when the mask allows it.
pub fn new_thread_cpu() -> u8 {
    let mask = allowed();
    if mask == permitted() {
        return 0;
    }
    if mask >> current() & 1 != 0 {
        return 0;
    }
    (mask.trailing_zeros() + 1) as u8
}

/// The directory the kernel's CPUs are listed in, as Linux names it: the
/// image holds it and a directory for each of the CPUs the machine can have
/// (`cpu0` to `cpu7`), and the listing of the directory names the CPUs that
/// are up (`entries`). htop and `nproc --all` count them.
pub const DIRECTORY: &[u8] = b"/sys/devices/system/cpu";

/// Whether `info` is the node of the directory `DIRECTORY` of the image.
/// An image without it has no such directory: that is asked once.
pub fn is_directory(info: &proto_fs::NodeInfo) -> bool {
    use core::sync::atomic::AtomicU64;
    static ASKED: AtomicU8 = AtomicU8::new(0);
    static DEVICE_OF: AtomicU64 = AtomicU64::new(0);
    static INODE_OF: AtomicU64 = AtomicU64::new(0);
    if info.kind != 1 || ASKED.load(Ordering::Acquire) == 2 {
        return false;
    }
    if ASKED.load(Ordering::Acquire) == 0 {
        let Ok(node) = crate::names::fstatat(crate::names::AT_FDCWD, Some(DIRECTORY), 0) else {
            ASKED.store(2, Ordering::Release);
            return false;
        };
        DEVICE_OF.store(node.device, Ordering::Relaxed);
        INODE_OF.store(node.inode, Ordering::Relaxed);
        ASKED.store(1, Ordering::Release);
    }
    info.device == DEVICE_OF.load(Ordering::Relaxed)
        && info.inode == INODE_OF.load(Ordering::Relaxed)
}

/// The entries of the listing of `DIRECTORY` in Linux's dirent64 records
/// from `position`: ".", ".." and `cpu0` to the last CPU that is up, each
/// directory. The offset after an entry is its place plus one.
pub fn entries(out: &mut [u8], position: u64) -> Result<usize, i32> {
    let cpus = count() as u64;
    let at = core::cell::Cell::new(position);
    posix_change::dirent::fill(
        out,
        |name| {
            let here = at.get();
            if here >= cpus + 2 {
                return Ok(None);
            }
            let len = match here {
                0 => {
                    name[0] = b'.';
                    1
                }
                1 => {
                    name[..2].copy_from_slice(b"..");
                    2
                }
                n => {
                    let cpu = n - 2;
                    name[..3].copy_from_slice(b"cpu");
                    // At most 8 CPUs here: one digit.
                    name[3] = b'0' + (cpu % 10) as u8;
                    4
                }
            };
            at.set(here + 1);
            Ok(Some(posix_change::dirent::Item {
                inode: 0x5359_5300 + here,
                kind: 4,
                name_len: len,
                before: here as i64,
                after: here as i64 + 1,
            }))
        },
        |offset| {
            at.set(u64::try_from(offset).map_err(|_| EINVAL)?);
            Ok(())
        },
    )
}
