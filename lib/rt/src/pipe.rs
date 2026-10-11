// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact named-open receipts. Callers retain the ticket before moving a capability.

use crate::handle::{Channel, Handle};
use proto_pipe::{Method, NamedReply, NamedTicket};
use proto_wire::{Reader, Status, Writer};

pub struct NamedResponse {
    pub state: NamedReply,
    pub capability: Option<Handle<Channel>>,
}

pub fn request(
    session: &Handle<Channel>,
    method: Method,
    ticket: NamedTicket,
    capability: Option<Handle<Channel>>,
) -> Result<NamedResponse, Status> {
    let mut writer = Writer::new();
    ticket.request(method, &mut writer)?;
    send(session, writer.as_bytes(), capability)
}

pub fn send(
    session: &Handle<Channel>,
    bytes: &[u8],
    capability: Option<Handle<Channel>>,
) -> Result<NamedResponse, Status> {
    let mut reply = match capability {
        Some(capability) => crate::sys::send_handles(session, bytes, [capability.erase()])
            .map_err(|refused| Status::Kernel(refused.error))?,
        None => crate::sys::send(session, bytes).map_err(Status::Kernel)?,
    };
    let mut buffer = [0; crate::abi::MESSAGE_MAX];
    let state = NamedReply::parse(Reader::new(reply.bytes(&mut buffer)))?;
    if reply.handles.len() > 1 {
        return Err(Status::BadSize);
    }
    let capability = if reply.handles.len() == 1 {
        Some(reply.handles.take::<Channel>(0).map_err(Status::Kernel)?)
    } else {
        None
    };
    Ok(NamedResponse { state, capability })
}

/// A rejected broker handoff returns its exact offered witness for replay.
pub struct NamedRefused {
    pub status: Status,
    pub capability: Option<Handle<Channel>>,
}

pub fn send_preserving(
    session: &Handle<Channel>,
    bytes: &[u8],
    capability: Option<Handle<Channel>>,
) -> Result<NamedResponse, NamedRefused> {
    let mut reply = match capability {
        Some(capability) => match crate::sys::send_handles(session, bytes, [capability.erase()]) {
            Ok(reply) => reply,
            Err(mut refused) => {
                let capability = refused
                    .back
                    .as_mut()
                    .and_then(|back| back.pop())
                    .map(|handle| Handle::<Channel>::from_raw(handle.into_raw()));
                return Err(NamedRefused {
                    status: Status::Kernel(refused.error),
                    capability,
                });
            }
        },
        None => crate::sys::send(session, bytes).map_err(|error| NamedRefused {
            status: Status::Kernel(error),
            capability: None,
        })?,
    };
    if reply.handles.len() > 1 {
        return Err(NamedRefused {
            status: Status::BadSize,
            capability: None,
        });
    }
    let capability = if reply.handles.len() == 1 {
        Some(
            reply
                .handles
                .take::<Channel>(0)
                .map_err(|error| NamedRefused {
                    status: Status::Kernel(error),
                    capability: None,
                })?,
        )
    } else {
        None
    };
    let mut buffer = [0; crate::abi::MESSAGE_MAX];
    match NamedReply::parse(Reader::new(reply.bytes(&mut buffer))) {
        Ok(state) => Ok(NamedResponse { state, capability }),
        Err(status) => Err(NamedRefused { status, capability }),
    }
}
