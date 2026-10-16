// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! F_GETLK and F_SETLK, with their OFD forms, in one request to the file
//! service. The service answers in the same step and keeps nothing, so the
//! client keeps nothing either. A reply lost to a signal costs a repeat: a
//! query changes nothing and a set is idempotent for one owner.

use crate::constants::EIO;
use proto_fs::{LockReply, LockStart};
use proto_wire::{Reader, Status, Writer};
use rt::abi::Error;

#[cfg(feature = "lock-probe")]
static HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// For the guest probes: `hook` runs after each reply, inside the deferral
/// of entries, and may raise a signal; true makes the reply count as lost.
#[cfg(feature = "lock-probe")]
pub fn probe_hook(hook: Option<fn() -> bool>) {
    HOOK.store(
        hook.map_or(0, |hook| hook as usize),
        core::sync::atomic::Ordering::Release,
    );
}
#[cfg(feature = "lock-probe")]
fn lost() -> bool {
    let raw = HOOK.load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: probe_hook stores only functions of this exact type.
    raw != 0 && unsafe { core::mem::transmute::<usize, fn() -> bool>(raw) }()
}

enum Turn {
    /// A signal ended the call, or the service is binding: send again.
    Again,
    Done(Result<LockReply, i32>),
}

fn send(transport: &posix_fs::Transport, wire: LockStart) -> Turn {
    let mut request = Writer::new();
    if wire.write(&mut request).is_err() {
        return Turn::Done(Err(crate::constants::EINVAL));
    }
    let files = transport.files();
    let response = match rt::fs::Files::send_on(files.sessions().0, request.as_bytes()) {
        Ok(response) => response,
        Err(Status::Kernel(Error::Interrupted)) => return Turn::Again,
        Err(_) => return Turn::Done(Err(EIO)),
    };
    if !response.handles.is_empty() || response.len > rt::abi::INLINE_MAX {
        return Turn::Done(Err(EIO));
    }
    let bytes = rt::abi::inline_bytes(&response.words);
    let bytes = &bytes[..response.len];
    let Some(&[a, b, c, d]) = bytes.first_chunk::<4>() else {
        return Turn::Done(Err(EIO));
    };
    match u32::from_le_bytes([a, b, c, d]) {
        0 => {}
        proto_fs::RESOLVING => return Turn::Again,
        code => return Turn::Done(Err(crate::lock_fields::refusal(code))),
    }
    Turn::Done(LockReply::read(Reader::new(bytes)).map_err(|_| EIO))
}

/// The copied input names no caller address. The entries of signals stay
/// deferred from the begin of the command to its end, so that a handler
/// that leaves by a jump cannot leave the command count raised.
pub(crate) fn operation(fd: u32, input: crate::lock_fields::Input) -> Result<LockReply, i32> {
    // The description of the first try stays for the repeats: a number that
    // another thread closed meanwhile must not hide a lock the first try took.
    let mut named = None;
    loop {
        let turn = (|| {
            let _entries = rt::upcall::defer_entries().map_err(|_| EIO)?;
            let (description, transport) = match named {
                None => crate::shared::with_fd(fd, |files| {
                    let description = files.lock_begins(fd).map_err(crate::error)?;
                    Ok((description, files.transport()))
                })?,
                Some(description) => crate::shared::with_files(|files| {
                    files.lock_begins_again();
                    Ok((description, files.transport()))
                })?,
            };
            named = Some(description);
            let turn = send(
                &transport,
                LockStart {
                    description,
                    command: input.command,
                    kind: input.kind,
                    whence: input.whence,
                    start: input.start,
                    length: input.length,
                    pid: input.pid,
                },
            );
            crate::shared::with_files(|files| {
                files.lock_ends();
                Ok(())
            })?;
            #[cfg(feature = "lock-probe")]
            if lost() {
                return Ok(Turn::Again);
            }
            Ok::<_, i32>(turn)
        })()?;
        match turn {
            Turn::Done(result) => return result,
            Turn::Again => {
                let _ = rt::sys::yield_now();
            }
        }
    }
}
