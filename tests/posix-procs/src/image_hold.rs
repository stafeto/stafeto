// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Genuine pending exec authority retains exact image capabilities across Abort.
use proto_wire::{Header, Reader, Status, Writer};
use rt::abi::{ObjectKind, Rights};
use rt::fs::Files;
use rt::handle::{Channel, Handle};
use rt::sys;

pub(super) fn image_counts(image: &Handle<Channel>) -> Result<[u32; 4], Status> {
    let reply = sys::send(image, &Header::new(0xfffa, proto_fs::VERSION).bytes())
        .map_err(Status::Kernel)?;
    if reply.len != 20 || !reply.handles.is_empty() {
        rt::println!(
            "posix-files: image counts reply len {} caps {} word0 {}",
            reply.len,
            reply.handles.len(),
            reply.words[0]
        );
        return Err(Status::BadSize);
    }
    let bytes = rt::abi::inline_bytes(&reply.words);
    let mut body = Reader::new(&bytes[..reply.len]);
    let code = body.u32()?;
    if code != 0 {
        rt::println!("posix-files: image counts status {}", code);
        return Err(Status::BadSize);
    }
    let mut counts = [0; 4];
    for count in &mut counts {
        *count = body.u32()?;
    }
    Ok(counts)
}
fn opened(reply: &mut sys::Reply) -> Result<Handle<Channel>, Status> {
    if reply.len != 4
        || reply.words[0] as u32 != 0
        || reply.handles.len() != 1
        || !reply.handles.info(0).is_some_and(|(kind, rights)| {
            kind == ObjectKind::Channel && rights == Rights::SEND | Rights::TRANSFER
        })
    {
        return Err(Status::BadSize);
    }
    reply.handles.take::<Channel>(0).map_err(Status::Kernel)
}
pub(super) fn elf(image: &Handle<Channel>) -> Result<(), Status> {
    let mut request = Writer::new();
    proto_fs::Method::ReadAt.header().write(&mut request)?;
    request.u32(0)?;
    request.u64(0)?;
    request.u32(4)?;
    let reply = Files::send_on(image, request.as_bytes())?;
    if reply.len != 12
        || !reply.handles.is_empty()
        || reply.words[0] != 4 << 32
        || reply.words[1] as u32 != u32::from_le_bytes(*b"\x7fELF")
    {
        return Err(Status::BadSize);
    }
    Ok(())
}
pub(super) struct CapturedImages {
    pub(super) handles: [Handle<Channel>; 2],
    descriptions_after_release: u32,
}
pub(super) fn capture(pending: &Handle<Channel>) -> Result<CapturedImages, Status> {
    let mut request = Writer::new();
    proto_fs::Method::ResolveStart
        .header()
        .write(&mut request)?;
    request.u32(0)?;
    request.u64(1)?;
    request.u32(0)?;
    request.u32(1)?;
    request.bytes(b"/bin/posix-files")?;
    let reply = Files::send_on(pending, request.as_bytes())?;
    if reply.len != 12 || !reply.handles.is_empty() || reply.words[0] as u32 != 0 {
        return Err(Status::BadSize);
    }
    let bytes = rt::abi::inline_bytes(&reply.words);
    let mut body = Reader::new(&bytes[..reply.len]);
    body.u32()?;
    let job = body.u64()?;
    let mut step = Writer::new();
    proto_fs::Method::ResolveStep.header().write(&mut step)?;
    step.u64(job)?;
    loop {
        let reply = Files::send_on(pending, step.as_bytes())?;
        if reply.len != 8 || reply.words[0] >> 32 != 0 || !reply.handles.is_empty() {
            return Err(Status::BadSize);
        }
        match reply.words[0] as u32 {
            0 => break,
            proto_fs::RESOLVING => {}
            code => return Err(Status::from_code(code)),
        }
    }
    let mut open = Writer::new();
    proto_fs::Method::OpenExec.header().write(&mut open)?;
    open.u64(job)?;
    let prepared = Files::send_on(pending, open.as_bytes())?;
    if prepared.len != 8
        || prepared.words[0] != u64::from(proto_fs::RESOLVING)
        || !prepared.handles.is_empty()
    {
        return Err(Status::BadSize);
    }
    let mut first = Files::send_on(pending, open.as_bytes())?;
    let image = opened(&mut first)?;
    // This accepted result goes undecoded; the same original proof recovers it.
    drop(Files::send_on(pending, open.as_bytes())?);
    let mut duplicate = Files::send_on(pending, open.as_bytes())?;
    let duplicate = opened(&mut duplicate)?;
    elf(&image)?;
    elf(&duplicate)?;
    let a = image_counts(&image)?;
    let b = image_counts(&duplicate)?;
    if a != b || a[0] != 1 || a[1] != 1 || a[3] != 1 {
        return Err(Status::BadSize);
    }
    let mut cancel = Writer::new();
    proto_fs::Method::ResolveCancel
        .header()
        .write(&mut cancel)?;
    cancel.u64(job)?;
    let canceled = Files::send_on(pending, cancel.as_bytes())?;
    if canceled.len != 8 || canceled.words[0] != 0 || !canceled.handles.is_empty() {
        return Err(Status::BadSize);
    }
    for _ in 0..2 {
        let retired = Files::send_on(pending, open.as_bytes())?;
        if retired.len != 8
            || retired.words[0] != u64::from(proto_fs::OPEN_RETIRED)
            || !retired.handles.is_empty()
        {
            return Err(Status::BadSize);
        }
        let canceled = Files::send_on(pending, cancel.as_bytes())?;
        if canceled.len != 8 || canceled.words[0] != 0 || !canceled.handles.is_empty() {
            return Err(Status::BadSize);
        }
    }
    elf(&image)?;
    if image_counts(&image)? != a {
        return Err(Status::BadSize);
    }
    rt::println!(
        "posix-files: exact image pin and cached capability ok {:?}",
        a
    );
    Ok(CapturedImages {
        handles: [image, duplicate],
        descriptions_after_release: a[2].checked_sub(1).ok_or(Status::BadSize)?,
    })
}
pub(super) fn released(captured: &CapturedImages) -> Result<(), Status> {
    let images = &captured.handles;
    let mut after = [0; 4];
    for visit in 0..200 {
        after = image_counts(&images[0])?;
        if visit == 0 {
            rt::println!(
                "posix-files: image release first counts {:?}, expected descriptions {}",
                after,
                captured.descriptions_after_release
            );
        }
        if after == [0, 0, captured.descriptions_after_release, 0] {
            break;
        }
        // SAFETY: the existing C helper takes no pointers and performs a timed wait.
        let slept = unsafe { super::loader_abort::sleep_for_cleanup() };
        if slept != 0 {
            rt::println!("posix-files: image release sleep result {}", slept);
            return Err(Status::BadSize);
        }
    }
    if after != [0, 0, captured.descriptions_after_release, 0] {
        rt::println!("posix-files: image release unsettled counts {:?}", after);
        return Err(Status::BadSize);
    }
    let duplicate = image_counts(&images[1])?;
    if duplicate != after {
        rt::println!(
            "posix-files: image release duplicate counts {:?}, original {:?}",
            duplicate,
            after
        );
        return Err(Status::BadSize);
    }
    if elf(&images[0]).is_ok() {
        rt::println!("posix-files: image release still readable after counts settled");
        return Err(Status::BadSize);
    }
    rt::println!("posix-files: aborted held image released {:?}", after);
    Ok(())
}
