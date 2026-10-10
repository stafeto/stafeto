// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The genuine Process notary supplies permanent read-only full PID lifetimes.

use rt::abi::{Access, ObjectKind, Rights};
use rt::handle::{Channel, Handle, Memory, Process};
use rt::sys;
const WINDOW: usize = 0x59_0000_0000;
pub struct Lifetimes {
    _memory: Handle<Memory>,
}
impl Lifetimes {
    pub fn receive(notary: &Handle<Channel>) -> Option<Handle<Memory>> {
        let mut reply = sys::send(
            notary,
            &proto_process::Method::RegisterLifetimes.header().bytes(),
        )
        .ok()?;
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        let mut body = proto_wire::Reader::new(reply.bytes(&mut buffer));
        if body.u32().ok()? != 0
            || body.finish().is_err()
            || reply.handles.len() != 1
            || reply.handles.info(0)
                != Some((ObjectKind::Memory, Rights::MAP_READ | Rights::TRANSFER))
        {
            return None;
        }
        reply.handles.take::<Memory>(0).ok()
    }
    pub fn map(memory: Handle<Memory>, process: &Handle<Process>) -> Option<Self> {
        sys::mem_map(process, &memory, 0, 4096, WINDOW, Access::Read).ok()?;
        Some(Self { _memory: memory })
    }
    pub fn live(&self, pid: u32) -> bool {
        // SAFETY: the genuine producer initialized Page; this mapping and handle
        // remain read-only and live for the entire single-threaded service loop.
        unsafe { &*(WINDOW as *const proto_process::lifetimes::Page) }.live(pid)
    }
}
