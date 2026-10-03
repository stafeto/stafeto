// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Ordinary queries through the probe's own held terminal session.

use posix_fs::Target;
use proto_wire::{Header, Reader, Writer};
use rt::sys;

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_pty_description(fd: u32) -> u32 {
    posix_abi::shared::held(fd, |_, target| match target {
        Target::Tty(id) => Ok(id),
        _ => Err(25),
    })
    .unwrap_or(u32::MAX)
}

/// GET_FLAGS tests both the current description and the probe's own
/// previously closed description after its place has been reused.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_pty_query(fd: u32, description: u32) -> u32 {
    posix_abi::shared::held(fd, |transport, target| {
        if !matches!(target, Target::Tty(_)) {
            return Err(25);
        }
        let channel = transport.terminal().ok_or(25)?;
        let mut bytes = Writer::new();
        Header::new(42, proto_tty::VERSION)
            .write(&mut bytes)
            .map_err(|_| 5)?;
        bytes.u32(description).map_err(|_| 5)?;
        let reply = sys::send(&channel, bytes.as_bytes()).map_err(|_| 5)?;
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        Reader::new(reply.bytes(&mut buffer)).u32().map_err(|_| 5)
    })
    .unwrap_or(u32::MAX)
}
