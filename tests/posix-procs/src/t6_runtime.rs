// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Value snapshots observe actual runtime executable accounting and timestamps.
use proto_wire::{Header, Reader, Status};
use rt::handle::{Channel, Handle};

fn channel() -> Result<core::mem::ManuallyDrop<Handle<Channel>>, Status> {
    let raw = posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw()))
        .map_err(|_| Status::BadSize)?;
    Ok(Handle::borrowed(raw))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn t6_runtime_counts(output: *mut u32) -> i32 {
    fn snapshot() -> Result<[u32; 4], Status> {
        let channel = channel()?;
        let reply = rt::sys::send(&channel, &Header::new(0xfff8, proto_fs::VERSION).bytes())
            .map_err(Status::Kernel)?;
        if reply.len != 20 || !reply.handles.is_empty() {
            return Err(Status::BadSize);
        }
        let bytes = rt::abi::inline_bytes(&reply.words);
        let mut r = Reader::new(&bytes[..20]);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let result = [r.u32()?, r.u32()?, r.u32()?, r.u32()?];
        r.finish()?;
        Ok(result)
    }
    match snapshot() {
        Ok(values) => {
            // SAFETY: the C caller owns four writable u32s until this call returns.
            unsafe { core::ptr::copy_nonoverlapping(values.as_ptr(), output, values.len()) };
            0
        }
        Err(error) => {
            rt::println!("t6-runtime: counter snapshot {:?}", error);
            -1
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn t6_runtime_stage(fd: i32) -> i32 {
    match super::image_gates::ambiguous_setid(fd) {
        Ok(()) => {
            rt::println!(
                "t6-runtime: actual Stage Installed, malformed reply, AbortRequired and Abort ok"
            );
            0
        }
        Err(error) => {
            rt::println!("t6-runtime: Stage observation {:?}", error);
            -1
        }
    }
}
