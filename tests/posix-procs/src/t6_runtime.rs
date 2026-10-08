// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Value snapshots observe actual runtime executable accounting and timestamps.
use proto_wire::{Header, Reader, Status, Writer};
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

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PinSnapshot {
    counts: [u32; 4],
    pins: u32,
    writers: u32,
    own_descriptions: u32,
    global_descriptions: u32,
    root: [u64; 2],
}
const _: () = assert!(core::mem::size_of::<PinSnapshot>() == 48);

fn decode_pins(bytes: &[u8], handles_empty: bool) -> Result<PinSnapshot, Status> {
    if bytes.len() != 56 || !handles_empty {
        return Err(Status::BadSize);
    }
    let mut r = Reader::new(bytes);
    if r.u32()? != 0 {
        return Err(Status::BadSize);
    }
    let counts = [r.u32()?, r.u32()?, r.u32()?, r.u32()?];
    let pins = r.u32()?;
    let writers = r.u32()?;
    let own_descriptions = r.u32()?;
    let global_descriptions = r.u32()?;
    if r.u32()? != 0 {
        return Err(Status::BadSize);
    }
    let root = [r.u64()?, r.u64()?];
    r.finish()?;
    if root.contains(&0) {
        return Err(Status::BadSize);
    }
    Ok(PinSnapshot {
        counts,
        pins,
        writers,
        own_descriptions,
        global_descriptions,
        root,
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn t6_runtime_pins(fd: i32, output: *mut PinSnapshot) -> i32 {
    let result = posix_abi::shared::held(fd as u32, |transport, target| {
        let posix_fs::Target::Ram(exact) = target else {
            return Err(posix_abi::constants::EIO);
        };
        let request = || -> Result<PinSnapshot, Status> {
            let mut w = Writer::new();
            Header::new(0xfff8, proto_fs::VERSION).write(&mut w)?;
            w.u32(exact.fd())?;
            w.u32(exact.description_slot())?;
            w.u64(exact.generation())?;
            let files = transport.files();
            let reply = rt::fs::Files::send_on(files.sessions().0, w.as_bytes())?;
            let bytes = rt::abi::inline_bytes(&reply.words);
            decode_pins(
                &bytes[..reply.len.min(bytes.len())],
                reply.handles.is_empty(),
            )
        };
        request().map_err(|_| posix_abi::constants::EIO)
    });
    match result {
        Ok(snapshot) => {
            // SAFETY: the C caller owns one aligned writable snapshot until return.
            unsafe { output.write(snapshot) };
            0
        }
        Err(error) => {
            rt::println!("t6-runtime: pin snapshot errno {}", error);
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
