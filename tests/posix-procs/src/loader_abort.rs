// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The old exec image retains a genuine Pending session across ExecAbort.

use proto_wire::{Header, Reader, Status, Writer};
use rt::abi::{ObjectKind, Rights};
use rt::fs::Files;
use rt::handle::{Channel, Handle};
use rt::sys;

unsafe extern "C" {
    fn files_loader_abort_sleep() -> i32;
}

pub(super) fn counts(channel: &Handle<Channel>) -> Result<[u32; 8], Status> {
    let request = Header::new(0xfffe, proto_fs::VERSION).bytes();
    let reply = sys::send(channel, &request).map_err(Status::Kernel)?;
    if reply.len != 36 || !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let bytes = rt::abi::inline_bytes(&reply.words);
    let mut reader = Reader::new(&bytes[..reply.len]);
    if reader.u32()? != 0 {
        return Err(Status::BadSize);
    }
    let mut counters = [0; 8];
    for counter in &mut counters {
        *counter = reader.u32()?;
    }
    reader.finish()?;
    Ok(counters)
}

pub(super) unsafe fn sleep_for_cleanup() -> i32 {
    // SAFETY: this fixture helper takes no pointers and returns its observed result.
    unsafe { files_loader_abort_sleep() }
}
fn abort() -> Result<(), Status> {
    let reply = sys::send(
        posix_abi::process::client().session(),
        &proto_process::Method::ExecAbort.header().bytes(),
    )
    .map_err(Status::Kernel)?;
    if reply.len != 8 || reply.words[0] != 0 || !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    Ok(())
}

/// Standard Start/Go/HandlesDone loads a real ELF before an uncommitted abort.
pub(super) fn load_image(loader: &Handle<Channel>) -> Result<(), Status> {
    const WINDOW: usize = 0x58_0000_0000;
    const PAGE: u64 = 4096;
    let object = sys::mem_create(PAGE).map_err(Status::Kernel)?;
    let process = posix_abi::allocation::process();
    sys::mem_map(
        process,
        &object,
        0,
        PAGE,
        WINDOW,
        rt::abi::Access::ReadWrite,
    )
    .map_err(Status::Kernel)?;
    // SAFETY: this single-threaded probe exclusively owns the fresh mapped page.
    let buffer = unsafe { core::slice::from_raw_parts_mut(WINDOW as *mut u8, PAGE as usize) };
    let length = proto_loader::Block::write(
        buffer,
        b"/bin/posix-files",
        b"/",
        0o022,
        [b"posix-files".as_slice()].into_iter(),
        [].into_iter(),
    );
    // SAFETY: the probe's sole temporary mapping is unused after Block::write.
    let unmapped = unsafe { sys::mem_unmap(process, WINDOW, PAGE) };
    unmapped.map_err(Status::Kernel)?;
    let length = length.map_err(|_| Status::BadSize)?;
    let copy = sys::handle_duplicate(&object, Rights::MAP_READ | Rights::TRANSFER)
        .map_err(Status::Kernel)?;
    let mut request = [0; proto_wire::HEADER_LEN + 4];
    request[..proto_wire::HEADER_LEN]
        .copy_from_slice(&proto_loader::Method::Start.header().bytes());
    request[proto_wire::HEADER_LEN..].copy_from_slice(&(length as u32).to_le_bytes());
    let reply = sys::send_handles(loader, &request, [copy.erase()])
        .map_err(|refused| Status::Kernel(refused.error))?;
    if reply.len != 8 || reply.words[0] != 0 || !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    for method in [proto_loader::Method::Go, proto_loader::Method::HandlesDone] {
        let reply = sys::send(loader, &method.header().bytes()).map_err(Status::Kernel)?;
        if reply.len != 8 || reply.words[0] >> 32 != 0 || !reply.handles.is_empty() {
            return Err(Status::BadSize);
        }
        if reply.words[0] != 0 {
            return Err(Status::from_code(reply.words[0] as u32));
        }
    }
    Ok(())
}

#[unsafe(no_mangle)]
extern "C" fn files_loader_abort_capture(fd: i32, loaded: i32) -> i32 {
    fn run(fd: i32, loaded: i32) -> Result<(), Status> {
        let fd = u32::try_from(fd).map_err(|_| Status::BadSize)?;
        let descriptor = posix_abi::shared::with_files(|files| match files.target(fd) {
            Ok(posix_fs::Target::Ram(fd)) => Ok(fd.fd()),
            _ => Err(posix_abi::constants::EIO),
        })
        .map_err(|_| Status::BadSize)?;
        let raw = posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw()))
            .map_err(|_| Status::BadSize)?;
        let mut clone = Writer::new();
        proto_fs::Method::Clone.header().write(&mut clone)?;
        clone.u32(1)?;
        clone.u32(descriptor)?;
        let offered = Files::clone_on(&Handle::<Channel>::borrowed(raw), clone.as_bytes())?;
        let before = posix_abi::process::client().query()?;
        let mut request = Writer::new();
        proto_process::Method::ExecStart
            .header()
            .write(&mut request)?;
        proto_process::SpawnStart {
            flags: 0,
            pgroup: 0,
            level: 1,
            mask: 0,
            default: 0,
        }
        .write(&mut request)?;
        let mut started = sys::send(posix_abi::process::client().session(), request.as_bytes())
            .map_err(Status::Kernel)?;
        if started.len < 4 || started.words[0] as u32 != 0 || started.handles.len() != 1 {
            return Err(Status::BadSize);
        }
        let loader = started.handles.take::<Channel>(0).map_err(Status::Kernel)?;
        let result = (|| {
            let request = Header::new(0xfffc, proto_loader::VERSION).bytes();
            let mut captured = sys::send_handles(&loader, &request, [offered.erase()])
                .map_err(|refused| Status::Kernel(refused.error))?;
            if captured.len != 8
                || captured.words[0] != 0
                || captured.handles.len() != 1
                || !captured.handles.info(0).is_some_and(|(kind, rights)| {
                    kind == ObjectKind::Channel && rights == Rights::SEND | Rights::TRANSFER
                })
            {
                return Err(Status::BadSize);
            }
            let pending = captured
                .handles
                .take::<Channel>(0)
                .map_err(Status::Kernel)?;
            let images = super::image_hold::capture(&pending)?;
            let initial = counts(&pending)?;
            if initial[0] != 1 || initial[2] != 0 || initial[3] != 1 || initial[4] != 0 {
                return Err(Status::BadSize);
            }
            rt::println!("posix-files: loader abort retained before {:?}", initial);
            if loaded != 0 {
                #[cfg(feature = "image-info-probe")]
                {
                    let observer = sys::channel_create(1).map_err(Status::Kernel)?;
                    let copy = sys::handle_duplicate(&observer, Rights::NOTIFY | Rights::TRANSFER)
                        .map_err(Status::Kernel)?;
                    let reply = sys::send_handles(
                        &loader,
                        &Header::new(0xfffb, proto_loader::VERSION).bytes(),
                        [copy.erase()],
                    )
                    .map_err(|refused| Status::Kernel(refused.error))?;
                    if reply.len != 8 || reply.words[0] != 0 || !reply.handles.is_empty() {
                        return Err(Status::BadSize);
                    }
                    let mut arm = Writer::new();
                    Header::new(0xfff7, proto_fs::VERSION).write(&mut arm)?;
                    arm.u32(loaded as u32)?;
                    let reply = sys::send(&pending, arm.as_bytes()).map_err(Status::Kernel)?;
                    if reply.len != 8 || reply.words[0] != 0 || !reply.handles.is_empty() {
                        return Err(Status::BadSize);
                    }
                    if load_image(&loader) != Err(Status::from_code(proto_loader::IO)) {
                        return Err(Status::BadSize);
                    }
                    let sys::Received::Notification {
                        source: rt::abi::Source::Unlabeled,
                        label: 0,
                        bits,
                        ..
                    } = sys::receive(&observer).map_err(Status::Kernel)?
                    else {
                        return Err(Status::BadSize);
                    };
                    let before = (bits >> 8) & 0xffff;
                    let received = (bits >> 24) & 0xffff;
                    let after = (bits >> 40) & 0xffff;
                    let caps = bits >> 56;
                    if bits & 0xff != 0x87
                        || before != after
                        || received != before + caps
                        || caps != u64::from(loaded == 3)
                    {
                        return Err(Status::BadSize);
                    }
                    rt::println!(
                        "posix-files: image metadata {loaded} handles={caps} live={before}->{received}->{after} refused before Ready"
                    );
                }
                #[cfg(not(feature = "image-info-probe"))]
                load_image(&loader)?;
                #[cfg(not(feature = "image-info-probe"))]
                {
                    let ready = counts(&pending)?;
                    if ready[0] != 1 || ready[3] != 1 || ready[4] != 0 {
                        return Err(Status::BadSize);
                    }
                    rt::println!("posix-files: loader abort loaded capture {:?}", ready);
                }
            }
            abort()?;
            let after = posix_abi::process::client().query()?;
            if after.pid != before.pid || after.credentials != before.credentials {
                return Err(Status::BadSize);
            }
            for _ in 0..200 {
                let final_counts = counts(&pending)?;
                if final_counts[..5] == [0; 5] {
                    rt::println!(
                        "posix-files: loader abort retained after {:?}",
                        final_counts
                    );
                    // The terminal refusal remains stable while this exact cap lives.
                    for _ in 0..2 {
                        let reply =
                            sys::send(&pending, &proto_fs::Method::FinishBinding.header().bytes())
                                .map_err(Status::Kernel)?;
                        if reply.len != 8
                            || reply.words[0] != u64::from(proto_fs::PERMISSION)
                            || !reply.handles.is_empty()
                        {
                            return Err(Status::BadSize);
                        }
                    }
                    super::image_hold::released(&images)?;
                    return Ok(());
                }
                // SAFETY: the C helper takes no pointers and returns its observed result.
                if unsafe { files_loader_abort_sleep() } != 0 {
                    return Err(Status::BadSize);
                }
            }
            Err(Status::BadSize)
        })();
        // Also abort an incomplete probe when any preceding observation failed.
        if result.is_err() {
            let _ = abort();
        }
        result
    }
    match run(fd, loaded) {
        Ok(()) => 0,
        Err(error) => {
            rt::println!("posix-files: loader abort failed {:?}", error);
            -1
        }
    }
}
