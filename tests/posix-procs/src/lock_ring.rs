// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Strict read-only observations of the genuine authenticated payer and proof.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use posix_abi::WaitProbe;
use posix_fs::wait::WaitToken;
static ARMED: AtomicBool = AtomicBool::new(false);
static NONCE: AtomicU64 = AtomicU64::new(1);
unsafe extern "C" {
    fn ring_wait_sleeping();
}
fn hook(phase: WaitProbe, _: WaitToken) -> bool {
    if phase == WaitProbe::Receive && ARMED.swap(false, Ordering::AcqRel) {
        // SAFETY: the isolated ring C fixture supplies the callback.
        unsafe { ring_wait_sleeping() };
    }
    false
}
#[unsafe(no_mangle)]
pub extern "C" fn ring_probe_arm() {
    ARMED.store(true, Ordering::Release);
    posix_abi::probe_wait_hook(Some(hook));
}
#[unsafe(no_mangle)]
pub extern "C" fn ring_probe_disarm() {
    posix_abi::probe_wait_hook(None);
    ARMED.store(false, Ordering::Release);
}
/// C passes eleven u32 cells; no pointer survives this read-only RPC.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ring_identity(target: u32, output: *mut u32) -> i32 {
    let result = (|| {
        let nonce = NONCE
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| -1)?;
        let mut request = proto_wire::Writer::new();
        proto_wire::Header::new(0xfff6, proto_fs::VERSION)
            .write(&mut request)
            .map_err(|_| -2)?;
        request
            .u64(nonce)
            .and_then(|()| request.u32(target))
            .map_err(|_| -3)?;
        let raw =
            posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())).map_err(|_| -4)?;
        let channel = rt::Handle::<rt::handle::Channel>::borrowed(raw);
        let reply = rt::fs::Files::send_on(&channel, request.as_bytes()).map_err(|_| -5)?;
        if !reply.handles.is_empty() {
            return Err(-6);
        }
        let mut bytes = [0; rt::abi::MESSAGE_MAX];
        let mut body = proto_wire::Reader::new(reply.bytes(&mut bytes));
        if body.u32().map_err(|_| -7)? != 0
            || body.u64().map_err(|_| -8)? != nonce
            || body.u32().map_err(|_| -9)? != target
        {
            return Err(-10);
        }
        let mut words = [0; 11];
        for word in &mut words {
            *word = body.u32().map_err(|_| -11)?;
        }
        body.finish().map_err(|_| -12)?;
        if words[0] == 0 || words[1] > 1 || words[2] == 0 || words[3] == 0 || words[4] < 128 {
            return Err(-13);
        }
        if output.is_null() {
            return Err(-14);
        }
        // SAFETY: C provides eleven writable u32 cells for this current call.
        unsafe { core::ptr::copy_nonoverlapping(words.as_ptr(), output, words.len()) };
        Ok(())
    })();
    result.map_or_else(|error| error, |()| 0)
}
