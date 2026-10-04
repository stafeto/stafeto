// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A measurement image transfers its genuine Pending capture to its parent.

use super::Own;
use proto_wire::{Reader, Status};
use rt::abi::{ObjectKind, Rights};
use rt::handle::{Channel, Handle, Incoming};
use rt::sys::{self, Token};

pub const METHOD: u16 = 0xfffc;

fn identity(own: &Own, rights: Rights) -> Result<Handle<Channel>, Status> {
    sys::handle_duplicate(&own.identity, rights).map_err(Status::Kernel)
}

fn refused(own: &Own, require: u32, rights: Rights) -> Result<(), Status> {
    let mut request = proto_wire::Writer::new();
    proto_fs::Method::BindPending.header().write(&mut request)?;
    request.u32(require)?;
    let copy = identity(own, rights)?;
    let reply = sys::send_handles(&own.files, request.as_bytes(), [copy.erase()])
        .map_err(|refused| Status::Kernel(refused.error))?;
    if reply.len != 8
        || reply.words[0] != u64::from(proto_fs::PERMISSION)
        || !reply.handles.is_empty()
    {
        return Err(Status::BadSize);
    }
    Ok(())
}

/// Verify cold returned custody and the subsequent warm admission.
fn admission(own: &Own, offered: Handle<Channel>) -> Result<Handle<Channel>, Status> {
    let complete = Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER;
    // The valid first reply precedes the warm refusals on this genuine root.
    let mut request = proto_wire::Writer::new();
    proto_fs::Method::BindPending.header().write(&mut request)?;
    request.u32(1)?;
    let mut reply = sys::send_handles(
        &own.files,
        request.as_bytes(),
        [offered.erase(), identity(own, complete)?.erase()],
    )
    .map_err(|refused| Status::Kernel(refused.error))?;
    let pending = if reply.words[0] as u32 == proto_fs::AUTHENTICATING {
        if reply.len != 8
            || reply.words[0] != u64::from(proto_fs::AUTHENTICATING)
            || reply.handles.len() != 2
            || reply.handles.info(0) != Some((ObjectKind::Channel, Rights::SEND | Rights::TRANSFER))
            || reply.handles.info(1) != Some((ObjectKind::Channel, complete))
        {
            return Err(Status::BadSize);
        }
        let offered = reply.handles.take::<Channel>(0).map_err(Status::Kernel)?;
        let identity = reply.handles.take::<Channel>(1).map_err(Status::Kernel)?;
        rt::fs::Files::bind_pending_on(&own.files, true, Some(offered), identity)?
    } else {
        if reply.len != 4
            || reply.words[0] as u32 != 0
            || reply.handles.len() != 1
            || reply.handles.info(0) != Some((ObjectKind::Channel, Rights::SEND | Rights::TRANSFER))
        {
            return Err(Status::BadSize);
        }
        reply.handles.take::<Channel>(0).map_err(Status::Kernel)?
    };
    refused(own, 2, complete)?;
    refused(own, 1, complete)?;
    refused(own, 0, Rights::NOTIFY | Rights::TRANSFER)?;
    let memory = sys::mem_create(4096).map_err(Status::Kernel)?;
    let memory = sys::handle_duplicate(&memory, Rights::MAP_READ | Rights::TRANSFER)
        .map_err(Status::Kernel)?;
    let wrong_kind = sys::send_handles(
        &own.files,
        request.as_bytes(),
        [memory.erase(), self::identity(own, complete)?.erase()],
    )
    .map_err(|refused| Status::Kernel(refused.error))?;
    if wrong_kind.len != 8
        || wrong_kind.words[0] != u64::from(proto_fs::PERMISSION)
        || !wrong_kind.handles.is_empty()
    {
        return Err(Status::BadSize);
    }
    rt::println!("loader: pending admission ordered handles and refusals ok");
    Ok(pending)
}

pub fn capture(own: &Own, body: Reader<'_>, mut handles: Incoming, token: Token) {
    let result = (|| {
        if body.finish().is_err() || handles.len() != 1 {
            return Err(Status::BadSize);
        }
        let offered = handles.take::<Channel>(0).map_err(Status::Kernel)?;
        let pending = admission(own, offered)?;
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
