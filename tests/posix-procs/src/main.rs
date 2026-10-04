// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of POSIX processes: a C main on relibc (procs.c); posix-crt
//! starts the layer, relibc starts C.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

/// A counterfeit identity capability must leave the already bound session intact.
#[cfg(feature = "files")]
#[unsafe(no_mangle)]
extern "C" fn files_fake_identity() -> i32 {
    use rt::abi::Rights;
    let Ok(fake) = rt::sys::channel_create(1) else {
        return -1;
    };
    let Ok(copy) =
        rt::sys::handle_duplicate(&fake, Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER)
    else {
        return -2;
    };
    let Ok(raw) = posix_abi::shared::with_files(|f| Ok(f.sessions().0.raw())) else {
        return -3;
    };
    let channel = rt::Handle::<rt::handle::Channel>::borrowed(raw);
    let request = proto_fs::Method::Bind.header().bytes();
    let Ok(reply) = rt::sys::send_handles(&channel, &request, [copy.erase()]) else {
        return -4;
    };
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut status = proto_wire::Reader::new(reply.bytes(&mut buffer)).u32();
    let request = proto_fs::Method::FinishBinding.header().bytes();
    while status == Ok(proto_fs::RESOLVING) {
        let Ok(reply) = rt::sys::send(&channel, &request) else {
            return -5;
        };
        status = proto_wire::Reader::new(reply.bytes(&mut buffer)).u32();
    }
    if status == Ok(proto_fs::PERMISSION) {
        0
    } else {
        -6
    }
}

#[cfg(feature = "auth-probe")]
mod cleanup;
