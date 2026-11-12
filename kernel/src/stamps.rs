// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Time stamps of the kernel (the build feature `stamps`, which no normal
//! or ci image has; `cargo xtask net-trace` turns it on). Each CPU keeps a
//! ring of RECORDS records of 16 bytes (kcore::stamps), in frames taken at
//! boot: the counter, the point, the CPU and a key. A record is written with
//! interrupts masked on the CPU that owns the ring, with no lock and no
//! atomic read-modify-write. The six points: an interrupt came in (`irq`), a
//! thread became ready with its cause (`ready`), a thread got the CPU
//! (`run`), an SGI was sent (`sgi_sent`) and received (`sgi_got`), the CPU
//! went into `wfi` and came out (`wfi`). object_info STAMPS reads a ring in
//! portions (`read`). Without the feature every function is empty and the
//! kernel is the one that has no stamps at all; object_info STAMPS is then an
//! unknown kind (INVALID_ARGS).

use crate::thread::Thread;
use core::ptr::NonNull;

/// The records of a ring: 8 192 of 16 bytes, 32 frames, 128 KiB.
#[cfg(feature = "stamps")]
pub const RECORDS: usize = 8192;
#[cfg(feature = "stamps")]
const ORDER: u8 = 5;
#[cfg(feature = "stamps")]
const _: () = ::core::assert!(RECORDS * abi::STAMPS_RECORD == (kcore::PAGE_SIZE as usize) << ORDER);

/// What one CPU keeps (`Local::stamps`).
#[cfg(feature = "stamps")]
pub struct Stamps {
    ring: kcore::stamps::Ring,
    /// 1 plus the number of the thread whose last record is a `run`, with no
    /// other record since: a thread that goes on after a call makes no second one.
    last_run: core::sync::atomic::AtomicU32,
    /// The cause that the code posting a notification names for the wake-up
    /// it makes (a timer, a device); 0 for none.
    origin: core::sync::atomic::AtomicU8,
}

#[cfg(feature = "stamps")]
impl Stamps {
    pub const fn new() -> Stamps {
        Stamps {
            ring: kcore::stamps::Ring::new(),
            last_run: core::sync::atomic::AtomicU32::new(0),
            origin: core::sync::atomic::AtomicU8::new(0),
        }
    }
}

/// Gives CPU `index`, which has not started or is the boot CPU, the memory
/// of its ring: 128 KiB of frames. A kernel with no such block has no
/// stamps on that CPU and says so.
#[cfg(feature = "stamps")]
pub fn init(index: usize) {
    // A CPU that was refused leaves its block prepared, and the next CPU
    // takes the same index: the memory stays.
    if crate::arch::cpu::block(index)
        .local
        .stamps
        .ring
        .is_installed()
    {
        return;
    }
    let mut quota = kcore::quota::Account::new((RECORDS * abi::STAMPS_RECORD) as u64);
    match crate::mm::phys::alloc_zeroed(ORDER, &mut quota) {
        Ok(frame) => {
            let words = (kcore::layout::LINEAR_BASE + frame.into_raw() as usize) as *mut u64;
            // SAFETY: the block is 2^ORDER frames of RAM that nothing else
            // uses and that live for good, the linear map covers them, and
            // RECORDS is a power of two.
            unsafe {
                crate::arch::cpu::block(index)
                    .local
                    .stamps
                    .ring
                    .install(words, RECORDS)
            };
        }
        Err(_) => log_line!("stamps     CPU {index}: no memory for the ring"),
    }
}

#[cfg(feature = "stamps")]
#[inline(always)]
fn put(point: u8, key: u32) {
    let s = &crate::local::local().stamps;
    s.last_run.store(0, core::sync::atomic::Ordering::Relaxed);
    record(s, point, key);
}

#[cfg(feature = "stamps")]
#[inline(always)]
fn record(s: &Stamps, point: u8, key: u32) {
    let cpu = crate::arch::cpu::this().index() as u8;
    s.ring.push(crate::arch::timer::now(), point, cpu, key);
}

/// An interrupt of line `intid` came in (not an SGI).
#[inline(always)]
pub fn irq(intid: u32) {
    #[cfg(feature = "stamps")]
    put(abi::STAMP_IRQ, intid);
    #[cfg(not(feature = "stamps"))]
    let _ = intid;
}

/// The thread `t`, taken out of a wait, becomes ready (or is told to by a
/// command to its CPU) for `cause` (abi::WAKE_*): the key holds its number,
/// the cause and its CPU.
#[inline(always)]
pub fn ready(t: NonNull<Thread>, cause: u8) {
    #[cfg(feature = "stamps")]
    {
        use core::sync::atomic::Ordering::Relaxed;
        let origin = crate::local::local().stamps.origin.load(Relaxed);
        let cause = if origin != 0 { origin } else { cause };
        let number = crate::thread::try_index(t).unwrap_or(u16::MAX);
        let cpu = crate::thread::cpu_of(t) as u32;
        put(
            abi::STAMP_READY,
            u32::from(number) | u32::from(cause) << 16 | cpu << 24,
        );
    }
    #[cfg(not(feature = "stamps"))]
    let _ = (t, cause);
}

/// The code that posts a notification for a timer or a device names it
/// (abi::WAKE_TIMER, WAKE_IRQ) around the post, and 0 after.
#[inline(always)]
pub fn origin(cause: u8) {
    #[cfg(feature = "stamps")]
    crate::local::local()
        .stamps
        .origin
        .store(cause, core::sync::atomic::Ordering::Relaxed);
    #[cfg(not(feature = "stamps"))]
    let _ = cause;
}

/// The thread `t` is about to get the CPU. A thread that goes on after a
/// call, with no other record since its last, makes no second record.
#[inline(always)]
pub fn run(t: NonNull<Thread>) {
    #[cfg(feature = "stamps")]
    {
        use core::sync::atomic::Ordering::Relaxed;
        let number = crate::thread::try_index(t).unwrap_or(u16::MAX);
        let s = &crate::local::local().stamps;
        if s.last_run.load(Relaxed) != u32::from(number) + 1 {
            record(s, abi::STAMP_RUN, u32::from(number));
            s.last_run.store(u32::from(number) + 1, Relaxed);
        }
    }
    #[cfg(not(feature = "stamps"))]
    let _ = t;
}

/// An SGI of the commands goes to CPU `to`; `sgi` says whether it is sent
/// (it is not when the target polls and the bell is enough).
#[inline(always)]
pub fn sgi_sent(to: usize, sgi: bool) {
    #[cfg(feature = "stamps")]
    put(abi::STAMP_SGI_SENT, to as u32 | u32::from(sgi) << 8);
    #[cfg(not(feature = "stamps"))]
    let _ = (to, sgi);
}

/// The SGI `intid` was received.
#[inline(always)]
pub fn sgi_got(intid: u32) {
    #[cfg(feature = "stamps")]
    put(abi::STAMP_SGI_GOT, intid);
    #[cfg(not(feature = "stamps"))]
    let _ = intid;
}

/// The CPU goes into `wfi` (`out` false) or came out of it (`out` true).
#[inline(always)]
pub fn wfi(out: bool) {
    #[cfg(feature = "stamps")]
    put(abi::STAMP_WFI, u32::from(out));
    #[cfg(not(feature = "stamps"))]
    let _ = out;
}

/// Every ring of the CPUs that are up stops taking records, for good
/// (abi::STAMPS_FREEZE).
#[cfg(feature = "stamps")]
pub fn freeze() {
    for cpu in 0..crate::smp::cpus() {
        crate::arch::cpu::block(cpu).local.stamps.ring.freeze();
    }
}

/// object_info STAMPS: up to abi::STAMPS_BATCH records of the ring of CPU
/// `cpu` from number `first` on, each to `put` (abi::INFO_STAMPS). None for
/// a CPU that is not up or has no ring.
#[cfg(feature = "stamps")]
pub fn read(
    cpu: usize,
    first: u64,
    put: impl FnMut(usize, [u64; 2]),
) -> Option<kcore::stamps::Batch> {
    if cpu >= crate::smp::cpus() {
        return None;
    }
    let ring = &crate::arch::cpu::block(cpu).local.stamps.ring;
    ring.is_installed().then(|| ring.read(first, put))
}
