// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Observe real paid WAIT custody; these probes never cancel or release it.
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use posix_abi::WaitProbe;
use posix_fs::wait::WaitToken;
use proto_wire::{Reader, Writer};
static ARMED: AtomicBool = AtomicBool::new(false);
static MODE: AtomicU32 = AtomicU32::new(0);
static SLOT: AtomicU32 = AtomicU32::new(u32::MAX);
static GENERATION: AtomicU64 = AtomicU64::new(0);
static RAW: AtomicU64 = AtomicU64::new(0);
unsafe extern "C" {
    fn wait_lifecycle_stage();
    fn wait_lifecycle_exit();
}
fn hook(phase: WaitProbe, token: WaitToken) -> bool {
    if phase != WaitProbe::Receive || !ARMED.swap(false, Ordering::AcqRel) {
        return false;
    }
    let saved = posix_abi::shared::with_files(|files| {
        let snapshot = files.wait_snapshot(token).map_err(|_| -1)?;
        snapshot.channel.ok_or(-2)
    });
    if let Ok(raw) = saved {
        SLOT.store(token.slot() as u32, Ordering::Release);
        GENERATION.store(token.generation(), Ordering::Release);
        RAW.store(raw, Ordering::Release);
    }
    // SAFETY: only the dedicated C worker invokes this post-Arm observation.
    unsafe { wait_lifecycle_stage() };
    if MODE.load(Ordering::Acquire) == 2 {
        // SAFETY: no FILES_LOCK or temporary Arm transfer ownership is held.
        unsafe { wait_lifecycle_exit() };
    }
    false
}
#[unsafe(no_mangle)]
pub extern "C" fn wait_lifecycle_arm(mode: u32) -> i32 {
    if posix_abi::shared::with_files(|files| Ok(files.wait_tokens().count())).unwrap_or(1) != 0 {
        return -1;
    }
    SLOT.store(u32::MAX, Ordering::Release);
    GENERATION.store(0, Ordering::Release);
    RAW.store(0, Ordering::Release);
    MODE.store(mode, Ordering::Release);
    ARMED.store(true, Ordering::Release);
    posix_abi::probe_wait_hook(Some(hook));
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn wait_lifecycle_disarm() {
    posix_abi::probe_wait_hook(None);
    ARMED.store(false, Ordering::Release);
}
#[unsafe(no_mangle)]
pub extern "C" fn wait_lifecycle_generation() -> u64 {
    GENERATION.load(Ordering::Acquire)
}
#[unsafe(no_mangle)]
pub extern "C" fn wait_lifecycle_count() -> i32 {
    posix_abi::shared::with_files(|files| Ok(files.wait_tokens().count() as i32)).unwrap_or(-1)
}
fn raw_info(raw: u64) -> Result<rt::abi::ChannelInfo, rt::abi::Error> {
    let mut args = [0; 10];
    args[0] = raw;
    args[1] = rt::abi::INFO_CHANNEL;
    // SAFETY: read-only identity query, no memory or borrowed Handle ownership.
    let words = unsafe { rt::sys::raw::<{ rt::abi::Call::ObjectInfo.number() }>(args) };
    if words[0] == 0 {
        Ok(rt::abi::ChannelInfo::from_words([
            words[1], words[2], words[3], words[4],
        ]))
    } else {
        Err(rt::abi::Error::from_code(words[0]).unwrap_or(rt::abi::Error::BadState))
    }
}
fn query_old() -> Result<Result<proto_fs::WaitReply, u32>, i32> {
    let transport = posix_abi::shared::with_files(|files| Ok(files.transport())).map_err(|_| -3)?;
    let key = proto_fs::WaitKey {
        slot: SLOT.load(Ordering::Acquire),
        generation: GENERATION.load(Ordering::Acquire),
    };
    let mut packet = Writer::new();
    proto_fs::write_wait_key(proto_fs::Method::WaitQuery, key, &mut packet).map_err(|_| -4)?;
    let _scope = rt::upcall::defer_entries().map_err(|_| -5)?;
    let response =
        rt::sys::send(transport.files().sessions().0, packet.as_bytes()).map_err(|_| -6)?;
    if !response.handles.is_empty() || response.len > rt::abi::INLINE_MAX {
        return Err(-7);
    }
    let bytes = rt::abi::inline_bytes(&response.words);
    let mut r = Reader::new(&bytes[..response.len]);
    let status = r.u32().map_err(|_| -8)?;
    if status != 0 {
        if r.u32().map_err(|_| -9)? != 0 || r.finish().is_err() {
            return Err(-10);
        }
        Ok(Err(status))
    } else {
        proto_fs::WaitReply::read(Reader::new(&bytes[..response.len]))
            .map(Ok)
            .map_err(|_| -11)
    }
}
/// Pure observation after ordinary public entries have helped the collector.
#[unsafe(no_mangle)]
pub extern "C" fn wait_lifecycle_recovered() -> i32 {
    let count = wait_lifecycle_count();
    if count != 0 {
        return if count > 0 { 0 } else { -12 };
    }
    let raw = RAW.load(Ordering::Acquire);
    if raw == 0 || GENERATION.load(Ordering::Acquire) == 0 {
        return -13;
    }
    let Ok(_scope) = rt::upcall::defer_entries() else {
        return -14;
    };
    if raw_info(raw) != Err(rt::abi::Error::BadHandle) {
        return -15;
    }
    match query_old() {
        Ok(Err(proto_fs::OPEN_RETIRED)) => 1,
        _ => -16,
    }
}
/// Fork-child local emptiness is checked separately before using this parent oracle.
#[unsafe(no_mangle)]
pub extern "C" fn wait_lifecycle_still_sleeping() -> i32 {
    let exact = posix_abi::shared::with_files(|files| {
        let mut tokens = files.wait_tokens();
        let Some(token) = tokens.next() else {
            return Ok(false);
        };
        if tokens.next().is_some()
            || token.slot() as u32 != SLOT.load(Ordering::Acquire)
            || token.generation() != GENERATION.load(Ordering::Acquire)
        {
            return Ok(false);
        }
        let snapshot = files.wait_snapshot(token).map_err(|_| -17)?;
        Ok(snapshot.channel == Some(RAW.load(Ordering::Acquire)))
    });
    if exact != Ok(true) {
        return -17;
    }
    let Ok(_scope) = rt::upcall::defer_entries() else {
        return -18;
    };
    if raw_info(RAW.load(Ordering::Acquire)).is_err() {
        return -19;
    }
    match query_old() {
        Ok(Ok(reply)) if reply.phase == proto_fs::WaitPhase::Sleeping => 1,
        _ => -20,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wait_lifecycle_receiver_waiting() -> i32 {
    let Ok(_scope) = rt::upcall::defer_entries() else {
        return -21;
    };
    match raw_info(RAW.load(Ordering::Acquire)) {
        Ok(info) => i32::from(info.receivers != 0 && !info.closed),
        Err(_) => -22,
    }
}

static PEER_OWNER: AtomicU64 = AtomicU64::new(0);
static PEER_SLOT: AtomicU32 = AtomicU32::new(u32::MAX);
static PEER_GENERATION: AtomicU64 = AtomicU64::new(0);
static PEER_REGISTRATION: AtomicU32 = AtomicU32::new(u32::MAX);
fn peer_observe(fd: i32, pid: u32, nonce: u64, first: u32, exact: bool) -> Result<bool, i32> {
    if nonce == 0 || pid == 0 || !matches!(first, 0 | 8) {
        return Err(-30);
    }
    let (transport, backend) = posix_abi::shared::with_files(|files| {
        let posix_fs::Target::Ram(backend) = files.target(fd as u32).map_err(|_| -31)? else {
            return Err(-32);
        };
        Ok((files.transport(), backend))
    })?;
    let mut request = Writer::new();
    proto_wire::Header::new(0xfff7, proto_fs::VERSION)
        .write(&mut request)
        .map_err(|_| -33)?;
    request.u32(if exact { 2 } else { 1 }).map_err(|_| -34)?;
    request.u64(nonce).map_err(|_| -34)?;
    request
        .u32(backend.fd() | backend.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT)
        .map_err(|_| -34)?;
    request.u64(backend.generation()).map_err(|_| -34)?;
    request.u32(pid).map_err(|_| -34)?;
    request.u32(first).map_err(|_| -34)?;
    if exact {
        request
            .u64(PEER_OWNER.load(Ordering::Acquire))
            .map_err(|_| -34)?;
        request
            .u32(PEER_SLOT.load(Ordering::Acquire))
            .map_err(|_| -34)?;
        request
            .u64(PEER_GENERATION.load(Ordering::Acquire))
            .map_err(|_| -34)?;
    }
    let _scope = rt::upcall::defer_entries().map_err(|_| -35)?;
    let reply =
        rt::sys::send(transport.files().sessions().0, request.as_bytes()).map_err(|_| -36)?;
    if !reply.handles.is_empty() || reply.len != 48 {
        return Err(-37);
    }
    let bytes = rt::abi::inline_bytes(&reply.words);
    let mut r = Reader::new(&bytes[..reply.len]);
    if r.u32().map_err(|_| -38)? != 0
        || r.u64().map_err(|_| -39)? != nonce
        || r.u32().map_err(|_| -40)? != pid
    {
        return Err(-41);
    }
    let visited = r.u32().map_err(|_| -42)?;
    let present = r.u32().map_err(|_| -43)?;
    let owner = r.u64().map_err(|_| -44)?;
    let slot = r.u32().map_err(|_| -45)?;
    let generation = r.u64().map_err(|_| -46)?;
    let registration = r.u32().map_err(|_| -47)?;
    r.finish().map_err(|_| -48)?;
    if !(1..=8).contains(&visited) || present > 1 {
        return Err(-49);
    }
    if present == 0 {
        if owner != 0 || slot != 0 || generation != 0 || registration != 0 {
            return Err(-50);
        }
        return Ok(false);
    }
    if owner == 0 || (proto_fs::WaitKey { slot, generation }).validate().is_err() {
        return Err(-51);
    }
    if exact {
        if owner != PEER_OWNER.load(Ordering::Acquire)
            || slot != PEER_SLOT.load(Ordering::Acquire)
            || generation != PEER_GENERATION.load(Ordering::Acquire)
            || !(registration == u32::MAX || (first..first + 8).contains(&registration))
        {
            return Err(-52);
        }
    } else {
        if !(first..first + 8).contains(&registration) {
            return Err(-53);
        }
        PEER_OWNER.store(owner, Ordering::Release);
        PEER_SLOT.store(slot, Ordering::Release);
        PEER_GENERATION.store(generation, Ordering::Release);
        PEER_REGISTRATION.store(registration, Ordering::Release);
    }
    Ok(true)
}
#[unsafe(no_mangle)]
pub extern "C" fn wait_process_discover(fd: i32, pid: u32, nonce: u64) -> i32 {
    PEER_OWNER.store(0, Ordering::Release);
    PEER_GENERATION.store(0, Ordering::Release);
    for first in [0, 8] {
        match peer_observe(fd, pid, nonce, first, false) {
            Ok(true) => {
                rt::println!(
                    "posix-procs: WAIT exit full PID {} owner {} key {}/{} registration {}",
                    pid,
                    PEER_OWNER.load(Ordering::Acquire),
                    PEER_SLOT.load(Ordering::Acquire),
                    PEER_GENERATION.load(Ordering::Acquire),
                    PEER_REGISTRATION.load(Ordering::Acquire)
                );
                return 1;
            }
            Ok(false) => (),
            Err(error) => return error,
        }
    }
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn wait_process_receipt_gone(fd: i32, pid: u32, nonce: u64) -> i32 {
    if PEER_OWNER.load(Ordering::Acquire) == 0 || PEER_GENERATION.load(Ordering::Acquire) == 0 {
        return -54;
    }
    let mut present = false;
    for first in [0, 8] {
        match peer_observe(fd, pid, nonce, first, true) {
            Ok(value) => present |= value,
            Err(error) => return error,
        }
    }
    i32::from(!present)
}
#[unsafe(no_mangle)]
pub extern "C" fn wait_process_owner() -> u64 {
    PEER_OWNER.load(Ordering::Acquire)
}
