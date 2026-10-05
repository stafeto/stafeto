// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Real pthread owners and helpers end only while the native IPC is Waiting.
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
};
use posix_abi::data_probe::{Event, Stage};
use posix_fs::data::{OwnerToken, Phase};
use rt::{
    abi::{Error, ProcessState, ThreadState},
    sys,
};

struct Observation {
    event: Event,
    live: [u64; 5],
}
struct Cell(UnsafeCell<Option<Observation>>);
// SAFETY: one worker publishes one immutable event before READY's Release.
// The supervisor resets it only after the original worker ended or joined.
unsafe impl Sync for Cell {}
static OBSERVATION: Cell = Cell(UnsafeCell::new(None));
static READY: AtomicBool = AtomicBool::new(false);
static RELEASE: AtomicBool = AtomicBool::new(false);
static CASE: AtomicU32 = AtomicU32::new(0);
static ORIGINAL: AtomicU64 = AtomicU64::new(0);
static HELPER: AtomicU64 = AtomicU64::new(0);
static HELPER_LIVE: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

fn event() -> Result<Event, i32> {
    if !READY.load(Ordering::Acquire) {
        return Err(5);
    }
    // SAFETY: READY publishes the immutable event until supervisor reset.
    unsafe { (&*OBSERVATION.0.get()).as_ref().map(|o| o.event) }.ok_or(5)
}
fn live() -> [u64; 5] {
    // SAFETY: the dedicated IPC-loss kernel returns value-only counters.
    let r = unsafe { sys::raw::<0xffe3>([0; 10]) };
    r[1..6].try_into().expect("five physical counts")
}
fn arm(event: Event, method: proto_fs::Method, by_job: bool) -> Result<(), i32> {
    posix_abi::shared::with_files(|files| {
        let actual = files.data_state(event.token).map_err(posix_abi::error)?;
        if actual != event.state
            || actual.owner != Some(event.owner)
            || files.sessions().0.raw().0 != event.state.session_handle
        {
            return Err(5);
        }
        if let Some(claim) = event.claim
            && files.data_claim_state(claim).map_err(posix_abi::error)? != actual
        {
            return Err(5);
        }
        Ok(())
    })?;
    let mut args = [0; 10];
    args[0] = event.state.session_handle;
    args[1] = u64::from_le_bytes(method.header().bytes());
    args[2] = event.token.slot() as u64;
    args[3] = event.token.generation();
    args[4] = event.state.job;
    args[5] = u64::from(by_job);
    // SAFETY: the test kernel retains this current worker and exact session.
    (unsafe { sys::raw::<0xffe0>(args) }[0] == 0)
        .then_some(())
        .ok_or(5)
}
fn observed(event: Event) -> Result<(), i32> {
    let case = CASE.load(Ordering::Acquire);
    if event.owner.value() != ORIGINAL.load(Ordering::Acquire)
        || event.state.owner != Some(event.owner)
        || (case == 1 && event.state.progress != Phase::Starting)
        || (case == 2 && event.state.progress != Phase::Ready)
        || (case == 3 && (event.state.progress != Phase::Committing || event.claim.is_some()))
    {
        return Err(5);
    }
    // SAFETY: register is one-shot, and this worker is the sole writer.
    unsafe {
        *OBSERVATION.0.get() = Some(Observation {
            event,
            live: live(),
        })
    };
    READY.store(true, Ordering::Release);
    match case {
        1 => arm(event, proto_fs::Method::DataStart, false),
        2 => arm(event, proto_fs::Method::DataCommit, true),
        3 => {
            while !RELEASE.load(Ordering::Acquire) {
                sys::yield_now().map_err(|_| 5)?;
            }
            Ok(())
        }
        _ => Err(5),
    }
}

#[unsafe(no_mangle)]
extern "C" fn files_data_loss_register(case: u32) -> i32 {
    let result = (|| {
        let stage = match case {
            1 => Stage::CapturedBeforeStart,
            2 => Stage::ReadyBeforeCommit,
            3 => Stage::ClaimReleasedAfterCommit,
            _ => return Err(22),
        };
        let owner = posix_abi::relibc::open_owner()?;
        ORIGINAL.store(owner, Ordering::Release);
        HELPER.store(0, Ordering::Release);
        CASE.store(case, Ordering::Release);
        READY.store(false, Ordering::Release);
        RELEASE.store(false, Ordering::Release);
        posix_abi::data_probe::register(owner, stage, observed)
    })();
    result.err().unwrap_or(0)
}

fn ended(owner: u64) -> Result<bool, i32> {
    OwnerToken::new(owner).map_err(|_| 5)?;
    let (_, native) = posix_abi::relibc::target((owner & 63) + 1)?;
    Ok(sys::thread_info(&native).map_err(|_| 5)?.state == ThreadState::Ended)
}
/// This is read-only: the production helper must perform the first detach.
#[unsafe(no_mangle)]
extern "C" fn files_data_loss_status(helper: i32) -> i32 {
    let result = (|| {
        let event = event()?;
        let owner = if helper != 0 {
            HELPER.load(Ordering::Acquire)
        } else {
            event.owner.value()
        };
        if !ended(owner)? {
            return Ok(0);
        }
        let actual = posix_abi::shared::with_files(|files| {
            files.data_state(event.token).map_err(posix_abi::error)
        })?;
        if actual.owner != Some(event.owner)
            || (helper != 0 && actual.claimant.map(OwnerToken::value) != Some(owner))
        {
            return Err(5);
        }
        // SAFETY: the dedicated kernel returns its actual accepted Reply observation.
        let snapshot = unsafe { sys::raw::<0xffe1>([0; 10]) };
        if snapshot[..6]
            != [
                0,
                1,
                1,
                Error::PeerClosed.code(),
                event.token.slot() as u64,
                event.token.generation(),
            ]
            || sys::process_state(posix_abi::allocation::process()) != Ok(ProcessState::Alive)
        {
            return Err(5);
        }
        if helper != 0 && live() != core::array::from_fn(|i| HELPER_LIVE[i].load(Ordering::Acquire))
        {
            return Err(5);
        }
        Ok(2)
    })();
    result.unwrap_or(-1)
}

#[unsafe(no_mangle)]
extern "C" fn files_data_loss_ready() -> i32 {
    i32::from(READY.load(Ordering::Acquire))
}

#[unsafe(no_mangle)]
extern "C" fn files_data_loss_help() -> i32 {
    let result = (|| {
        let event = event()?;
        for _ in 0..128 {
            posix_abi::shared::help_open_recovery();
            if posix_abi::shared::with_files(|files| Ok(files.data_state(event.token).is_err()))? {
                return Ok(());
            }
            sys::yield_now().map_err(|_| 5)?;
        }
        Err(5)
    })();
    result.err().unwrap_or(0)
}

#[unsafe(no_mangle)]
extern "C" fn files_data_loss_helper() -> i32 {
    let result: Result<(), i32> = (|| {
        let event = event()?;
        if event.state.result.is_some()
            || event.state.claimant.is_some()
            || event.state.progress != Phase::Committing
            || event.claim.is_some()
        {
            return Err(5);
        }
        let owner = posix_abi::relibc::open_owner()?;
        HELPER.store(owner, Ordering::Release);
        for (slot, value) in HELPER_LIVE.iter().zip(live()) {
            slot.store(value, Ordering::Release);
        }
        arm(event, proto_fs::Method::DataQuery, false)?;
        for _ in 0..128 {
            posix_abi::shared::help_open_recovery();
        }
        // The actual matching Query must kill this helper before returning.
        Err(5)
    })();
    result.err().unwrap_or(0)
}
#[unsafe(no_mangle)]
extern "C" fn files_data_loss_release() {
    RELEASE.store(true, Ordering::Release);
}

#[unsafe(no_mangle)]
extern "C" fn files_data_loss_finish() -> i32 {
    let result = (|| {
        let event = event()?;
        posix_abi::data_probe::disable(event.owner.value())?;
        if posix_abi::shared::with_files(|files| Ok(files.data_state(event.token).is_ok()))? {
            return Err(5);
        }
        // The pthread's own allocation is retained on both sides of this
        // comparison; it is reclaimed separately at process exit.
        let baseline = unsafe { (&*OBSERVATION.0.get()).as_ref().ok_or(5)?.live };
        if CASE.load(Ordering::Acquire) < 3 && live() != baseline {
            return Err(5);
        }
        Ok(())
    })();
    result.err().unwrap_or(0)
}
