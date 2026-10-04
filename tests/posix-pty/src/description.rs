// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Ordinary queries through the probe's own held terminal session.

use posix_fs::Target;
use proto_wire::{Header, Reader, Writer};
use rt::sys;

use core::cell::UnsafeCell;
use rt::handle::{Channel, Handle};

struct CloneChain(UnsafeCell<[Option<Handle<Channel>>; 255]>);
// SAFETY: the single-threaded clone role alone calls the helpers. Its
// forked child never touches the inherited array and ends with _exit.
unsafe impl Sync for CloneChain {}
static CLONES: CloneChain = CloneChain(UnsafeCell::new([const { None }; 255]));

/// Fill the probe's own root with a chain inheriting exactly 32 real
/// descriptions, verify the final session, then leave one place for fork.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_pty_clone_full(fd: u32) -> i32 {
    let result = posix_abi::shared::held(fd, |transport, target| {
        if !matches!(target, Target::Tty(_)) {
            return Err(25);
        }
        let parent = transport.terminal().ok_or(25)?;
        let mut ids = [0; posix_fs::OPEN_MAX];
        let count = posix_abi::shared::terminals_kept_by_fork(&mut ids)?;
        if count != 32 {
            return Err(5);
        }
        let mut first = Writer::new();
        proto_tty::Method::Clone
            .header()
            .write(&mut first)
            .map_err(|_| 5)?;
        first.u32(count as u32).map_err(|_| 5)?;
        for id in &ids[..count] {
            first.u32(*id).map_err(|_| 5)?;
        }
        let next = proto_tty::Method::Clone.header().bytes();
        // SAFETY: only this single-threaded role accesses CLONES. The
        // child created afterwards does not access these parent handles.
        let chain = unsafe { &mut *CLONES.0.get() };
        if chain.iter().any(Option::is_some) {
            return Err(5);
        }
        let mut used = 0;
        loop {
            let from = if used == 0 {
                &*parent
            } else {
                chain[used - 1].as_ref().ok_or(5)?
            };
            let bytes = if used == 0 { first.as_bytes() } else { &next };
            match rt::service::clone_session(from, bytes) {
                Ok(channel) => {
                    if used == chain.len() {
                        return Err(5);
                    }
                    chain[used] = Some(channel);
                    used += 1;
                }
                Err(proto_wire::Status::Kernel(rt::abi::Error::LimitReached)) => break,
                Err(_) => return Err(5),
            }
        }
        if used < 250 {
            return Err(5);
        }
        let last = chain[used - 1].as_ref().ok_or(5)?;
        for id in &ids[..count] {
            let mut query = Writer::new();
            proto_tty::Method::Stat
                .header()
                .write(&mut query)
                .map_err(|_| 5)?;
            query.u32(*id).map_err(|_| 5)?;
            let reply = sys::send(last, query.as_bytes()).map_err(|_| 5)?;
            let mut buffer = [0; rt::abi::MESSAGE_MAX];
            if Reader::new(reply.bytes(&mut buffer)).u32().map_err(|_| 5)? != 0 {
                return Err(5);
            }
        }
        chain[used - 1] = None;
        Ok(used as i32)
    });
    result.unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_pty_clone_clear() {
    // SAFETY: only the original single-threaded clone role calls cleanup;
    // the forked child uses _exit without touching this array.
    let chain = unsafe { &mut *CLONES.0.get() };
    for channel in chain {
        *channel = None;
    }
}

#[cfg(feature = "clone-steps")]
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_pty_clone_stats(fd: u32) -> i32 {
    let mut maxima = [(0, 0); 66];
    let result = posix_abi::shared::held(fd, |transport, _| {
        let channel = transport.terminal().ok_or(25)?;
        for (kind, maximum) in maxima.iter_mut().enumerate() {
            let mut request = Writer::new();
            Header::new(30, proto_tty::VERSION)
                .write(&mut request)
                .map_err(|_| 5)?;
            request.u32(kind as u32).map_err(|_| 5)?;
            let reply = sys::send(&channel, request.as_bytes()).map_err(|_| 5)?;
            let mut buffer = [0; rt::abi::MESSAGE_MAX];
            let mut body = Reader::new(reply.bytes(&mut buffer));
            if body.u32().map_err(|_| 5)? != 0 {
                return Err(5);
            }
            *maximum = (body.u64().map_err(|_| 5)?, body.u64().map_err(|_| 5)?);
            body.finish().map_err(|_| 5)?;
        }
        Ok(())
    });
    if result.is_err() {
        return -1;
    }
    for (kind, (ticks, detail)) in maxima.into_iter().enumerate() {
        if ticks != 0 {
            rt::println!("service step: 5 kind {kind} {ticks} ticks detail {detail}");
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_pty_action_packet(mode: u32) {
    posix_abi::process::probe_terminal_packet(mode);
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_pty_action_result() -> u64 {
    posix_abi::process::probe_terminal_packet_result()
}

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
