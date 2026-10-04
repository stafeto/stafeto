// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A measurement image transfers its genuine Pending capture to its parent.

use super::Own;
use proto_wire::{Reader, Status};
use rt::abi::Rights;
use rt::handle::{Channel, Handle, Incoming};
use rt::sys::{self, Token};

pub const METHOD: u16 = 0xfffc;

pub fn capture(own: &Own, body: Reader<'_>, mut handles: Incoming, token: Token) {
    let result = (|| {
        if body.finish().is_err() || handles.len() != 1 {
            return Err(Status::BadSize);
        }
        let offered = handles.take::<Channel>(0).map_err(Status::Kernel)?;
        let identity = sys::handle_duplicate(
            &own.identity,
            Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER,
        )
        .map_err(Status::Kernel)?;
        let mut request = [0; proto_wire::HEADER_LEN + 4];
        request[..proto_wire::HEADER_LEN]
            .copy_from_slice(&proto_fs::Method::BindPending.header().bytes());
        request[proto_wire::HEADER_LEN..].copy_from_slice(&1u32.to_le_bytes());
        let mut reply =
            sys::send_handles(&own.files, &request, [offered.erase(), identity.erase()])
                .map_err(|refused| Status::Kernel(refused.error))?;
        if reply.len != 4 || reply.words[0] as u32 != 0 || reply.handles.len() != 1 {
            return Err(Status::BadSize);
        }
        let pending = reply.handles.take::<Channel>(0).map_err(Status::Kernel)?;
        rt::fs::Files::finish_on(&pending)?;
        Ok::<Handle<Channel>, Status>(pending)
    })();
    match result {
        Ok(pending) => {
            let _ = token.reply_handles(&proto_wire::reply(Status::Ok), [pending.erase()]);
        }
        Err(status) => {
            let _ = token.reply(&proto_wire::reply(status));
        }
    }
}
