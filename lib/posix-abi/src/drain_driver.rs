// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact terminal drain custody precedes START and survives frame/thread loss.

use crate::{constants::*, long::ShortScope, terminal::ENOTTY};
use entries::Frame;
use posix_fs::change::{ControlClaimToken, ControlPhase, ControlResult, ControlToken, OwnerToken};
use posix_fs::{Target, drain::Server};
use proto_wire::{Status, Writer, long};
use rt::abi::{Error, Rights};
use rt::handle::{Channel, Handle};
use rt::sys;

struct Record(ControlClaimToken);
impl crate::long::Custody for Record {
    fn record(&self, kind: u32, key: u64) -> Result<(), i32> {
        crate::shared::with_files(|files| {
            match kind {
                long::WAIT => files.publish_drain_wait(self.0, key),
                long::READY => files.publish_drain_terminal(self.0, true),
                long::CANCELLED => files.publish_drain_terminal(self.0, false),
                _ => return Err(EIO),
            }
            .map_err(crate::error)
        })
    }
}

/// The C boundary keeps its Point outside this resident resource owner.
pub(crate) fn operation(fd: u32) -> Result<(), i32> {
    let block = crate::threads::own_block();
    let _outer = crate::long::OuterRestart::enter(&block.flags);
    let owner = OwnerToken::new(crate::relibc::open_owner()?).map_err(|_| EIO)?;
    let current = crate::change::frame();
    // with_fd may settle an existing Close. It runs before short admission
    // deferral; no newly created resource can be lost at this boundary.
    let (source, session, terminal) = crate::shared::with_fd(fd, |files| {
        let target = files.target(fd).map_err(crate::error)?;
        let transport = files.transport();
        let terminal = transport.terminal_number(target).ok_or(ENOTTY)?;
        let session = transport.terminal().ok_or(EBADF)?.raw().0;
        Ok((
            files.lock_source(fd).map_err(crate::error)?,
            session,
            terminal,
        ))
    })?;
    let (token, claim) = loop {
        if crate::long::ending(&block.flags, true) {
            return Err(EINTR);
        }
        collect(Some(owner), current, None, true);
        let scope = ShortScope::enter(true)?;
        let paid = crate::shared::with_files(|files| {
            files
                .begin_drain_record(owner, source, current, session, terminal)
                .map_err(crate::error)
        });
        drop(scope);
        match paid? {
            Some(paid) => break paid,
            None => crate::long::admission_pause()?,
        }
    };
    let result = crate::terminal::drain_owned(session, terminal, &Record(claim));
    let outcome = match result {
        Ok(()) => ControlResult::Value(0),
        Err(errno) => ControlResult::Failed(errno),
    };
    {
        let _scope = ShortScope::enter(true)?;
        crate::shared::with_files(|files| {
            files
                .complete_drain_record(claim, outcome)
                .map_err(crate::error)
        })?;
    }
    // One turn pays normal cleanup. Any refused short request leaves its debt
    // in the same paid record, available to a later admission or lifetime pass.
    let _ = cleanup_step(token);
    let saved = {
        let _scope = ShortScope::enter(true)?;
        crate::shared::with_files(|files| {
            files
                .handoff_drain_record(token, owner)
                .map_err(crate::error)
        })?
    };
    match saved {
        ControlResult::Value(0) => Ok(()),
        ControlResult::Failed(errno) => Err(errno),
        _ => Err(EIO),
    }
}

/// One short authenticated request, with no notification or retained RPC.
fn send_once(session: u64, request: &Writer, authenticated: bool) -> Result<sys::Reply, Error> {
    let service = Handle::<Channel>::borrowed(rt::abi::Handle(session));
    if !authenticated {
        return sys::send(&service, request.as_bytes());
    }
    let identity = crate::process::identity().ok_or(Error::BadState)?;
    let identity = sys::handle_duplicate(identity, Rights::NOTIFY | Rights::TRANSFER)?;
    sys::send_handles(&service, request.as_bytes(), [identity.erase()])
        .map_err(|refused| refused.error)
}

/// true retains unpaid debt; false means this exact record completed cleanup.
#[inline(never)]
fn cleanup_step(token: ControlToken) -> Result<bool, i32> {
    let _scope = ShortScope::enter(true)?;
    let snapshot =
        crate::shared::with_files(|files| files.drain_snapshot(token).map_err(crate::error))?;
    if snapshot.phase == ControlPhase::Cleaned {
        return Ok(false);
    }
    let mut debt =
        crate::shared::with_files(|files| files.begin_drain_cleanup(token).map_err(crate::error))?;
    if debt.server() == Server::Waiting {
        let mut request = Writer::new();
        proto_tty::Cancel {
            key: debt.key(),
            terminal: debt.terminal(),
        }
        .write(proto_tty::Method::DrainCancel, &mut request)
        .map_err(|_| EIO)?;
        let reply = match send_once(debt.session(), &request, true) {
            Ok(reply) => reply,
            Err(_) => return Ok(true),
        };
        if reply.len > rt::abi::INLINE_MAX || !reply.handles.is_empty() {
            return Ok(true);
        }
        let inline = rt::abi::inline_bytes(&reply.words);
        let gone = match long::Reply::read(&inline[..reply.len]) {
            Ok(long::Reply::Cancelled) => true,
            Ok(long::Reply::Ready(bytes)) => bytes.is_empty(),
            Err(Status::Kernel(Error::BadState)) => true,
            _ => false,
        };
        if !gone {
            return Ok(true);
        }
        crate::shared::with_files(|files| {
            files
                .confirm_drain_gone(token, debt.session(), debt.key())
                .map_err(crate::error)
        })?;
    }
    debt =
        crate::shared::with_files(|files| files.release_drain_hold(token).map_err(crate::error))?;
    if let Some(target) = debt.release() {
        // Real drain uses early-release TTY or implicit console. Retain a
        // returned full Target anyway; never silently drop an unpaid close.
        match target {
            Target::Tty(id) => {
                // A turn already spent its one RPC on Cancel above.
                if snapshot
                    .recovery
                    .drain()
                    .is_some_and(|d| d.server() == Server::Waiting)
                {
                    return Ok(true);
                }
                let mut request = Writer::new();
                proto_tty::description(proto_tty::Method::Close, id, None, &mut request)
                    .map_err(|_| EIO)?;
                let reply = match send_once(debt.session(), &request, false) {
                    Ok(reply) => reply,
                    Err(_) => return Ok(true),
                };
                if !matches!(reply.len, 4 | 8) || !reply.handles.is_empty() {
                    return Ok(true);
                }
                let bytes = rt::abi::inline_bytes(&reply.words);
                let status = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| EIO)?);
                if !((reply.len == 4 && status == 0)
                    || (reply.len == 8
                        && status == proto_tty::BAD_DESCRIPTION
                        && bytes[4..8] == [0; 4]))
                {
                    return Ok(true);
                }
            }
            Target::Input | Target::Output | Target::Error => {}
            _ => return Ok(true),
        }
        crate::shared::with_files(|files| {
            files
                .confirm_drain_release(token, target)
                .map_err(crate::error)
        })?;
    }
    crate::shared::with_files(|files| files.finish_drain_cleanup(token).map_err(crate::error))?;
    Ok(false)
}

pub(crate) fn collect(
    me: Option<OwnerToken>,
    current: Frame,
    skip: Option<ControlToken>,
    blocking: bool,
) {
    // Selection owns no stack-only resource. Its exact paid token survives
    // any helper jump before the separately guarded cleanup turn.
    let Ok(_scope) = ShortScope::enter(true) else {
        return;
    };
    let find = |files: &mut posix_fs::PosixFs| {
        files
            .pick_drain_cleanup(me, current, skip)
            .map_err(crate::error)
    };
    let selected = if blocking {
        crate::shared::with_files(find)
    } else {
        crate::shared::try_with_files(find)
    };
    // cleanup_step owns its own preparation. Release this one only after the
    // selected token has no resource held solely by the helper's stack.
    drop(_scope);
    if let Ok(Some(token)) = selected {
        let _ = cleanup_step(token);
    }
}
pub(crate) fn detach(owner: u64) -> bool {
    let Ok(owner) = OwnerToken::new(owner) else {
        return false;
    };
    crate::shared::try_with_files(|files| {
        while files.abandon_drain_owner(owner).is_some() {}
        Ok(())
    })
    .is_ok()
}
pub(crate) fn help() {
    collect(None, Frame::main(0), None, false);
}
