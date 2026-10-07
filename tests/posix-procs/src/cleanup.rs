// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Creates a paid unfinished binding and moves its sole session capability.
use core::mem::ManuallyDrop;
use proto_wire::{Reader, Writer};
use rt::abi::Rights;
use rt::handle::{Channel, Handle};

#[unsafe(no_mangle)]
extern "C" fn files_cleanup_owner(phase: u32) -> i32 {
    let parent = posix_crt::parent();
    let Some(identity) = posix_abi::process::identity() else {
        return 1;
    };
    let Ok(files) = rt::fs::Files::connect(&parent) else {
        return 2;
    };
    let files = ManuallyDrop::new(files);
    if files.bind(identity).is_err() {
        return 3;
    }
    if files.open("/etc/motd", proto_fs::READ_ONLY).is_err() {
        return 4;
    }
    let Ok(offered) = rt::sys::handle_duplicate(
        identity,
        Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER,
    ) else {
        return 5;
    };
    let channel = files.sessions().0;
    let Ok(armed) = rt::sys::send(
        channel,
        &proto_wire::Header::new(0xfffd, proto_fs::VERSION).bytes(),
    ) else {
        return 14;
    };
    let mut arm_buffer = [0; rt::abi::MESSAGE_MAX];
    if Reader::new(armed.bytes(&mut arm_buffer)).u32() != Ok(0) {
        return 15;
    }
    let Ok(reply) = rt::sys::send_handles(
        channel,
        &proto_fs::Method::Bind.header().bytes(),
        [offered.erase()],
    ) else {
        return 6;
    };
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    if Reader::new(reply.bytes(&mut buffer)).u32() != Ok(proto_fs::RESOLVING) {
        return 7;
    }
    for _ in 0..phase {
        let Ok(reply) = rt::sys::send(channel, &proto_fs::Method::FinishBinding.header().bytes())
        else {
            return 8;
        };
        if Reader::new(reply.bytes(&mut buffer)).u32() != Ok(proto_fs::RESOLVING) {
            return 9;
        }
    }
    let Ok(holder) = rt::service::connect(&parent, "ramfs-holder") else {
        return 10;
    };
    let mut request = Writer::new();
    if proto_wire::Header::new(1, 1)
        .write(&mut request)
        .and_then(|()| request.u32(phase + 1))
        .is_err()
    {
        return 11;
    }
    // ManuallyDrop owns this sole S|T session; moving it never creates a duplicate.
    let session = Handle::<Channel>::from_raw(channel.raw());
    let Ok(reply) = rt::sys::send_handles(&holder, request.as_bytes(), [session.erase()]) else {
        return 12;
    };
    if Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
        return 13;
    }
    0
}

#[unsafe(no_mangle)]
extern "C" fn files_cleanup_check(phase: u32) -> i32 {
    let parent = posix_crt::parent();
    let Ok(holder) = rt::service::connect(&parent, "ramfs-holder") else {
        return -1;
    };
    let mut request = Writer::new();
    if proto_wire::Header::new(2, 1)
        .write(&mut request)
        .and_then(|()| request.u32(phase + 1))
        .is_err()
    {
        return -6;
    }
    let Ok(reply) = rt::sys::send(&holder, request.as_bytes()) else {
        return -2;
    };
    if !reply.handles.is_empty() {
        return -3;
    }
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    if reply.len == 8
        && reply.words[0] >> 32 == 0
        && Reader::new(reply.bytes(&mut buffer)).u32()
            == Ok(proto_wire::Status::Kernel(rt::abi::Error::BadState).code())
    {
        return 1;
    }
    let mut reader = Reader::new(reply.bytes(&mut buffer));
    let mut values = [0; 12];
    for value in &mut values {
        let Ok(n) = reader.u32() else {
            return -4;
        };
        *value = n;
    }
    if reader.finish().is_err() || values[0] != 0 || values[11] != phase + 1 {
        return -5;
    }
    if values[1..6] != [0; 5] || values[8] != 0 {
        return 1;
    }
    if values[6] != 0 || values[7] != 0 {
        return 1;
    }
    0
}
