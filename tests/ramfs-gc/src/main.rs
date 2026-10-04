// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Read-only observations require both maintenance branches to make progress.
#![no_std]
#![no_main]
#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

use proto_wire::{Header, Reader, Status, Writer};
use rt::{
    fs::Files,
    handle::{Channel, Handle},
    sys,
};
unsafe extern "C" {
    fn files_gc_sleep() -> i32;
}

fn send(channel: &Handle<Channel>, request: &Writer) -> Result<(), Status> {
    let reply = sys::send(channel, request.as_bytes()).map_err(Status::Kernel)?;
    if reply.len == 8 && reply.words[0] == 0 && reply.handles.is_empty() {
        Ok(())
    } else {
        Err(Status::BadSize)
    }
}
fn pages(channel: &Handle<Channel>) -> Result<u32, Status> {
    let mut request = Writer::new();
    Header::new(0xfffc, proto_fs::VERSION).write(&mut request)?;
    request.u32(3)?;
    let reply = sys::send(channel, request.as_bytes()).map_err(Status::Kernel)?;
    if reply.len != 8 || reply.words[0] as u32 != 0 || !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    Ok((reply.words[0] >> 32) as u32)
}
fn counts(channel: &Handle<Channel>) -> Result<[u32; 8], Status> {
    let reply = sys::send(channel, &Header::new(0xfffe, proto_fs::VERSION).bytes())
        .map_err(Status::Kernel)?;
    if reply.len != 36 || !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let bytes = rt::abi::inline_bytes(&reply.words);
    let mut reader = Reader::new(&bytes[..reply.len]);
    if reader.u32()? != 0 {
        return Err(Status::BadSize);
    }
    let mut result = [0; 8];
    for value in &mut result {
        *value = reader.u32()?;
    }
    reader.finish()?;
    Ok(result)
}
fn control(channel: &Handle<Channel>, phase: u32) -> Result<(), Status> {
    let mut request = Writer::new();
    Header::new(0xfffc, proto_fs::VERSION).write(&mut request)?;
    request.u32(phase)?;
    send(channel, &request)
}
fn run() -> Result<(), Status> {
    let files = Files::connect(&posix_crt::parent())?;
    let identity = posix_abi::process::identity().ok_or(Status::BadSize)?;
    files.bind(identity)?;
    let fd = files.open("/etc/motd", proto_fs::READ_ONLY)?;
    let channel = files.sessions().0;
    let baseline = pages(channel)?;
    rt::println!("ramfs-gc: before inode preparation");
    control(channel, 0)?;
    rt::println!("ramfs-gc: inode created, before page allocation");
    for page in 0..32 {
        let mut request = Writer::new();
        Header::new(0xfffc, proto_fs::VERSION).write(&mut request)?;
        request.u32(1)?;
        request.u32(page * 4096)?;
        request.bytes(b"x")?;
        send(channel, &request)?;
        if pages(channel)? != baseline + page + 1 {
            return Err(Status::BadSize);
        }
    }
    rt::println!("ramfs-gc: pages allocated, before binding barrier");
    let armed = sys::send(channel, &Header::new(0xfffd, proto_fs::VERSION).bytes())
        .map_err(Status::Kernel)?;
    if armed.len != 8 || armed.words[0] != 0 || !armed.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let copy = sys::handle_duplicate(
        identity,
        rt::abi::Rights::NOTIFY | rt::abi::Rights::DUPLICATE | rt::abi::Rights::TRANSFER,
    )
    .map_err(Status::Kernel)?;
    let reply = sys::send_handles(
        channel,
        &proto_fs::Method::Bind.header().bytes(),
        [copy.erase()],
    )
    .map_err(|r| Status::Kernel(r.error))?;
    if reply.len != 8
        || reply.words[0] != u64::from(proto_fs::RESOLVING)
        || !reply.handles.is_empty()
    {
        return Err(Status::BadSize);
    }
    let initial = counts(channel)?;
    if initial[..5] != [1, 0, 1, 1, 0] || initial[7] != 1 || pages(channel)? != baseline + 32 {
        return Err(Status::BadSize);
    }
    rt::println!("ramfs-gc: prepared binding retained with 32 allocated pages");
    control(channel, 2)?;
    for _ in 0..200 {
        let current = counts(channel)?;
        let remaining = pages(channel)?;
        if current[0] != 1 || current[3] != 1 || current[4] != 0 || remaining > baseline + 32 {
            return Err(Status::BadSize);
        }
        if current[2] == 0 && remaining == baseline {
            Files::finish_on(channel)?;
            let mut byte = [0];
            if files.read_at(fd, 0, &mut byte)? != 1 || byte != *b"s" {
                return Err(Status::BadSize);
            }
            files.close(fd)?;
            rt::println!(
                "ramfs-gc: preparation 1 -> 0, pages {} -> {}",
                baseline + 32,
                baseline
            );
            return Ok(());
        }
        // SAFETY: the C helper takes no pointers and its return value is checked.
        if unsafe { files_gc_sleep() } != 0 {
            return Err(Status::BadSize);
        }
    }
    Err(Status::BadSize)
}
#[unsafe(no_mangle)]
extern "C" fn files_gc_binding() -> i32 {
    match run() {
        Ok(()) => 0,
        Err(error) => {
            rt::println!("ramfs-gc: observation failed {:?}", error);
            1
        }
    }
}
