// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Observations use the actual resident RAM source, held over an unlocked RPC.
use core::sync::atomic::{AtomicU64, Ordering};
use posix_fs::Target;
static NONCE: AtomicU64 = AtomicU64::new(1);
fn nonce() -> Result<u64, i32> {
    NONCE
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
        .map_err(|_| -1)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_telemetry(
    fd: u32,
    action: u32,
    cookie: u64,
    epoch: u64,
    argument: u32,
    output: *mut u64,
) -> i32 {
    if output.is_null() {
        return -1;
    }
    let result = posix_abi::shared::held(fd, |transport, target| {
        let Target::Ram(source) = target else {
            return Err(-2);
        };
        let mut w = proto_wire::Writer::new();
        proto_wire::Header::new(0xfff1, proto_fs::VERSION)
            .write(&mut w)
            .map_err(|_| -3)?;
        w.u32(action)
            .and_then(|()| w.u64(cookie))
            .and_then(|()| w.u64(epoch))
            .and_then(|()| {
                w.u32(source.fd() | (source.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT))
            })
            .and_then(|()| w.u64(source.generation()))
            .map_err(|_| -4)?;
        match action {
            0 | 4 => w.u32(argument).map_err(|_| -5)?,
            2 | 3 | 5 => (),
            _ => return Err(-6),
        }
        let files = transport.files();
        let reply = rt::fs::Files::send_on(files.sessions().0, w.as_bytes()).map_err(|_| -7)?;
        if !reply.handles.is_empty() || reply.len > rt::abi::INLINE_MAX {
            return Err(-8);
        }
        let inline = rt::abi::inline_bytes(&reply.words);
        let expected = if action == 0 { None } else { Some(epoch) };
        let words =
            super::lock_full_wire::reply(&inline[..reply.len], cookie, expected).map_err(|_| -9)?;
        if action == 4 {
            super::lock_full_wire::census(
                argument,
                [words[1], words[2], words[3], words[4], words[5]],
            )
            .map_err(|_| -10)?;
        }
        Ok(words)
    });
    match result {
        Ok(words) => {
            // SAFETY: this isolated C fixture supplies six cells for this call only.
            unsafe { core::ptr::copy_nonoverlapping(words.as_ptr(), output, words.len()) };
            0
        }
        Err(error) => error,
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_source(fd: u32, output: *mut u64) -> i32 {
    if output.is_null() {
        return -1;
    }
    let result = posix_abi::shared::held(fd, |_, target| {
        let Target::Ram(b) = target else {
            return Err(-2);
        };
        Ok([
            u64::from(b.fd() | (b.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT)),
            b.generation(),
        ])
    });
    match result {
        Ok(words) => {
            // SAFETY: C supplies two cells; the exact source is copied, never retained.
            unsafe { core::ptr::copy_nonoverlapping(words.as_ptr(), output, 2) };
            0
        }
        Err(e) => e,
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_identity(target: u32, output: *mut u64) -> i32 {
    if output.is_null() {
        return -1;
    }
    let result = (|| {
        let nonce = nonce()?;
        let mut w = proto_wire::Writer::new();
        proto_wire::Header::new(0xfff6, proto_fs::VERSION)
            .write(&mut w)
            .map_err(|_| -2)?;
        w.u64(nonce).and_then(|()| w.u32(target)).map_err(|_| -3)?;
        let raw =
            posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())).map_err(|_| -4)?;
        let channel = rt::Handle::<rt::handle::Channel>::borrowed(raw);
        let reply = rt::fs::Files::send_on(&channel, w.as_bytes()).map_err(|_| -5)?;
        if !reply.handles.is_empty() || reply.len > rt::abi::INLINE_MAX {
            return Err(-6);
        }
        let bytes = rt::abi::inline_bytes(&reply.words);
        let mut r = proto_wire::Reader::new(&bytes[..reply.len]);
        if r.u32().map_err(|_| -7)? != 0
            || r.u64().map_err(|_| -7)? != nonce
            || r.u32().map_err(|_| -7)? != target
        {
            return Err(-7);
        }
        let mut words = [0_u64; 4];
        for word in &mut words {
            *word = u64::from(r.u32().map_err(|_| -8)?);
        }
        for _ in 4..11 {
            r.u32().map_err(|_| -8)?;
        }
        r.finish().map_err(|_| -9)?;
        if words[0] == 0 || words[1] > 1 || words[2] == 0 || words[3] == 0 {
            return Err(-10);
        }
        Ok(words)
    })();
    match result {
        Ok(words) => {
            // SAFETY: C provides four cells; caller identity and target liveness stay distinct.
            unsafe { core::ptr::copy_nonoverlapping(words.as_ptr(), output, 4) };
            0
        }
        Err(e) => e,
    }
}
