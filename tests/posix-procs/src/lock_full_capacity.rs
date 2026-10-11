// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Exact readonly paid-WAIT observations; no cleanup RPC is sent here.
use proto_fs::{Method, WaitKey};
use proto_wire::{Reader, Writer};
#[unsafe(no_mangle)]
pub extern "C" fn full_no_locks() -> u32 {
    proto_fs::NO_LOCKS
}
#[unsafe(no_mangle)]
pub extern "C" fn full_cancelled() -> u32 {
    proto_fs::LOCK_CANCELLED
}
fn observe(fd: u32, expected: super::lock_full_wire::WaitObservation) -> Result<bool, i32> {
    let super::lock_full_wire::WaitObservation {
        pid,
        nonce,
        owner,
        slot,
        generation,
        discover,
        first,
    } = expected;
    posix_abi::shared::held(fd, |transport, target| {
        let posix_fs::Target::Ram(source) = target else {
            return Err(-1);
        };
        let mut w = Writer::new();
        proto_wire::Header::new(0xfff7, proto_fs::VERSION)
            .write(&mut w)
            .map_err(|_| -2)?;
        w.u32(if discover { 1 } else { 2 })
            .and_then(|()| w.u64(nonce))
            .and_then(|()| {
                w.u32(source.fd() | source.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT)
            })
            .and_then(|()| w.u64(source.generation()))
            .and_then(|()| w.u32(pid))
            .and_then(|()| w.u32(first))
            .map_err(|_| -3)?;
        if !discover {
            w.u64(owner)
                .and_then(|()| w.u32(slot))
                .and_then(|()| w.u64(generation))
                .map_err(|_| -3)?;
        }
        let reply =
            rt::fs::Files::send_on(transport.files().sessions().0, w.as_bytes()).map_err(|_| -4)?;
        if !reply.handles.is_empty() || reply.len != 48 {
            return Err(-5);
        }
        let bytes = rt::abi::inline_bytes(&reply.words);
        super::lock_full_wire::wait_observation(&bytes[..reply.len], expected).map_err(|_| -6)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn full_wait_observe(
    fd: u32,
    pid: u32,
    nonce: u64,
    owner: u64,
    slot: u32,
    generation: u64,
    sleeping: u32,
) -> i32 {
    let key = WaitKey { slot, generation };
    if nonce == 0 || pid == 0 || owner == 0 || key.validate().is_err() || sleeping > 1 {
        return -7;
    }
    let mut present = false;
    for first in [0, 8] {
        match observe(
            fd,
            super::lock_full_wire::WaitObservation {
                nonce,
                pid,
                owner,
                slot,
                generation,
                first,
                discover: sleeping == 1,
            },
        ) {
            Ok(value) => present |= value,
            Err(error) => return error,
        }
    }
    i32::from(present)
}
#[unsafe(no_mangle)]
pub extern "C" fn full_wait_retired(slot: u32, generation: u64) -> i32 {
    let key = WaitKey { slot, generation };
    if key.validate().is_err() {
        return -1;
    }
    let result = posix_abi::shared::with_files(|files| {
        if files.wait_tokens().next().is_some() {
            return Err(-2);
        }
        Ok(files.transport())
    });
    let Ok(transport) = result else {
        return -3;
    };
    let mut w = Writer::new();
    if proto_fs::write_wait_key(Method::WaitQuery, key, &mut w).is_err() {
        return -4;
    }
    let Ok(reply) = rt::fs::Files::send_on(transport.files().sessions().0, w.as_bytes()) else {
        return -5;
    };
    if !reply.handles.is_empty() || reply.len != 8 {
        return -6;
    }
    let bytes = rt::abi::inline_bytes(&reply.words);
    let mut r = Reader::new(&bytes[..reply.len]);
    i32::from(r.u32() == Ok(proto_fs::OPEN_RETIRED) && r.u32() == Ok(0) && r.finish().is_ok())
}
