// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Exec observations expose only authenticated resident identities and scalar entries.
const _: () = assert!(
    super::lock_full_exec_wire::BACKEND_MASK
        == (proto_fs::OPEN_FD_MASK | proto_fs::OPEN_DESCRIPTION_MASK) as u64
);
#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_exec_binding(output: *mut u64) -> i32 {
    if output.is_null() {
        return -1;
    }
    let result = (|| {
        let nonce = super::lock_full::nonce()?;
        let mut w = proto_wire::Writer::new();
        proto_wire::Header::new(0xfff8, proto_fs::VERSION)
            .write(&mut w)
            .map_err(|_| -2)?;
        w.u64(nonce).map_err(|_| -2)?;
        let raw =
            posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())).map_err(|_| -3)?;
        let channel = rt::Handle::<rt::handle::Channel>::borrowed(raw);
        let reply = rt::fs::Files::send_on(&channel, w.as_bytes()).map_err(|_| -4)?;
        if !reply.handles.is_empty() || reply.len > rt::abi::INLINE_MAX {
            return Err(-5);
        }
        let bytes = rt::abi::inline_bytes(&reply.words);
        super::lock_full_exec_wire::binding(&bytes[..reply.len], nonce).map_err(|_| -6)
    })();
    match result {
        Ok(words) => {
            // SAFETY: the C fixture supplies nine cells for this synchronous call.
            unsafe { core::ptr::copy_nonoverlapping(words.as_ptr(), output, 9) };
            0
        }
        Err(error) => error,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_exec_sample(fd: u32, output: *mut u64) -> i32 {
    if output.is_null() {
        return -1;
    }
    let result = posix_abi::shared::with_files(|files| {
        let entry = files.lock_source(fd).map_err(|_| -1)?;
        let posix_fs::Target::Ram(target) = files.target(fd).map_err(|_| -1)? else {
            return Err(-1);
        };
        Ok([
            u64::from(fd),
            entry.generation(),
            u64::from(
                target.fd() | (target.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT),
            ),
            target.generation(),
        ])
    });
    match result {
        Ok(words) => {
            // SAFETY: the C fixture supplies four scalar cells, without retained pointers.
            unsafe { core::ptr::copy_nonoverlapping(words.as_ptr(), output, 4) };
            0
        }
        Err(error) => error,
    }
}

/// A negative request supplies the exact old observer source on the fresh session.
#[unsafe(no_mangle)]
pub extern "C" fn full_exec_old_scope(
    fd: u32,
    packed: u64,
    generation: u64,
    cookie: u64,
    epoch: u64,
) -> i32 {
    if packed > u64::from(u32::MAX) || generation == 0 || cookie == 0 || epoch == 0 {
        return -1;
    }
    let result = posix_abi::shared::held(fd, |transport, target| {
        if !matches!(target, posix_fs::Target::Ram(_)) {
            return Err(-2);
        }
        let mut w = proto_wire::Writer::new();
        proto_wire::Header::new(0xfff1, proto_fs::VERSION)
            .write(&mut w)
            .map_err(|_| -3)?;
        w.u32(3)
            .and_then(|()| w.u64(cookie))
            .and_then(|()| w.u64(epoch))
            .and_then(|()| w.u32(packed as u32))
            .and_then(|()| w.u64(generation))
            .map_err(|_| -3)?;
        let reply =
            rt::fs::Files::send_on(transport.files().sessions().0, w.as_bytes()).map_err(|_| -4)?;
        if !reply.handles.is_empty() || reply.len != 8 {
            return Err(-5);
        }
        let bytes = rt::abi::inline_bytes(&reply.words);
        let mut r = proto_wire::Reader::new(&bytes[..8]);
        let code = r.u32().map_err(|_| -6)?;
        if r.u32().map_err(|_| -6)? != 0
            || r.finish().is_err()
            || code == 0
            || code > i32::MAX as u32
        {
            return Err(-6);
        }
        Ok(-(code as i32))
    });
    result.unwrap_or_else(|error| error)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_exec_valid(
    state: *const u64,
    bytes: usize,
    stage: u32,
    case: u64,
    nonce: u64,
) -> i32 {
    if state.is_null() || bytes != super::lock_full_exec_wire::WORDS * 8 {
        return -1;
    }
    // SAFETY: C supplies the complete static 2816-byte state for this synchronous check.
    let state = unsafe { core::slice::from_raw_parts(state, bytes / 8) };
    let valid = match stage {
        1 => super::lock_full_exec_wire::initial(state, case, nonce),
        2 => super::lock_full_exec_wire::permitted(state, case, nonce),
        3 => super::lock_full_exec_wire::ready(state, case, nonce),
        4 => super::lock_full_exec_wire::stopped(state, case, nonce),
        _ => false,
    };
    if valid { 0 } else { -1 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_exec_absence(status: *const i32) -> i32 {
    if status.is_null() {
        return -1;
    }
    // SAFETY: C supplies twenty synchronous page statuses.
    let status = unsafe { core::slice::from_raw_parts(status, 20) };
    if super::lock_full_exec_wire::absence(status) {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_exec_frozen(state: *const u64, expected: *const u64) -> i32 {
    if state.is_null() || expected.is_null() {
        return -1;
    }
    // SAFETY: C supplies the full static state and its independent pre-exec 32-word header.
    let (state, expected) = unsafe {
        (
            core::slice::from_raw_parts(state, super::lock_full_exec_wire::WORDS),
            core::slice::from_raw_parts(expected, 32),
        )
    };
    if super::lock_full_exec_wire::frozen(state, expected) {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn full_exec_advance(current: u32, next: u32) -> i32 {
    if super::lock_full_exec_wire::advance(u64::from(current), u64::from(next)) {
        0
    } else {
        -1
    }
}
