// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact resident Control drives lock requests outside the descriptor-table lock.

use crate::constants;
use constants::{EBADF, EIO, ENOLCK};
use posix_fs::Transport;
use posix_fs::change::{ControlClaimToken, ControlPhase, ControlResult, ControlToken, OwnerToken};
use posix_fs::control::{CancelReason, Input, TerminalReply};
use proto_fs::{LockReply, Method};
use proto_wire::{Reader, Status, Writer};

mod core;
mod status;
use core::{Failure, Phase, Session, State};

fn failure(status: Status) -> Failure {
    match status {
        Status::Kernel(rt::abi::Error::Interrupted) => Failure::Interrupted,
        Status::Unknown(proto_fs::JOBS_FULL) => Failure::Room,
        Status::Unknown(proto_fs::AUTHENTICATING) => Failure::Authenticating,
        Status::Unknown(proto_fs::RESOLVING) => Failure::Resolving,
        Status::Unknown(proto_fs::OPEN_RETIRED) => Failure::Retired,
        Status::Unknown(code) => Failure::Rejected(code),
        error => Failure::Fatal(crate::error(error.into())),
    }
}

struct Live {
    token: ControlToken,
    claim: Option<ControlClaimToken>,
    owner: Option<OwnerToken>,
    transport: Transport,
    room_repeats: u32,
}
impl Live {
    /// One native request; a helper never runs an implicit Bind inside its turn.
    fn send(&self, request: &Writer) -> Result<rt::sys::Reply, Failure> {
        let files = self.transport.files();
        rt::sys::send(files.sessions().0, request.as_bytes())
            .map_err(|error| failure(Status::Kernel(error)))
    }
    fn decode(&self, response: rt::sys::Reply) -> Result<LockReply, Failure> {
        if !response.handles.is_empty() {
            return Err(Failure::Fatal(EIO));
        }
        let mut bytes = [0; rt::abi::MESSAGE_MAX];
        let bytes = response.bytes(&mut bytes);
        let mut status = Reader::new(bytes);
        let code = status.u32().map_err(failure)?;
        if code != 0 {
            status::read(bytes).map_err(failure)?;
            return Err(failure(Status::from_code(code)));
        }
        LockReply::read(Reader::new(bytes)).map_err(failure)
    }
    fn keyed(&self, method: Method) -> Result<LockReply, Failure> {
        let mut request = Writer::new();
        proto_fs::write_lock_key(method, self.key(), &mut request).map_err(failure)?;
        self.decode(self.send(&request)?)
    }
    fn key(&self) -> proto_fs::OpenKey {
        proto_fs::OpenKey {
            slot: self.token.slot() as u32,
            generation: self.token.generation(),
        }
    }
}
impl Session for Live {
    type Completion = LockReply;
    fn state(&mut self) -> Result<State, i32> {
        crate::shared::with_files(|files| {
            let Ok(snapshot) = files.lock_snapshot(self.token) else {
                return Ok(State {
                    phase: Phase::Gone,
                    claim_live: false,
                    saved: false,
                });
            };
            let lock = snapshot.recovery.lock().ok_or(EIO)?;
            if snapshot.result.is_some() != lock.outcome().is_some() {
                return Err(EIO);
            }
            Ok(State {
                phase: match snapshot.phase {
                    ControlPhase::Working => Phase::Live,
                    ControlPhase::Complete | ControlPhase::CleanupRequired => Phase::Complete,
                    ControlPhase::Cleaning => Phase::Cleaning,
                    ControlPhase::Cleaned => Phase::Cleaned,
                },
                claim_live: self.claim.is_some_and(|claim| files.lock_is_live(claim)),
                saved: snapshot.result.is_some(),
            })
        })
    }
    fn start(&mut self) -> Result<LockReply, Failure> {
        let wire = crate::shared::with_files(|files| {
            let claim = self.claim.ok_or(EIO)?;
            if !files.lock_is_live(claim) {
                return Ok(None);
            }
            let snapshot = files.lock_snapshot(self.token).map_err(crate::error)?;
            Ok(Some(
                snapshot.recovery.lock().ok_or(EIO)?.request(self.token),
            ))
        })
        .map_err(Failure::Fatal)?;
        let Some(wire) = wire else {
            return Err(Failure::Retired);
        };
        let mut request = Writer::new();
        wire.write(&mut request).map_err(failure)?;
        self.decode(self.send(&request)?)
    }
    fn query(&mut self) -> Result<LockReply, Failure> {
        self.keyed(Method::LockQuery)
    }
    fn cancel(&mut self) -> Result<LockReply, Failure> {
        self.keyed(Method::LockCancel)
    }
    fn release(&mut self) -> Result<(), Failure> {
        let mut request = Writer::new();
        proto_fs::write_lock_key(Method::LockRelease, self.key(), &mut request).map_err(failure)?;
        let response = self.send(&request)?;
        if !response.handles.is_empty() {
            return Err(Failure::Fatal(EIO));
        }
        let mut bytes = [0; rt::abi::MESSAGE_MAX];
        let code = status::read(response.bytes(&mut bytes)).map_err(failure)?;
        if code == 0 {
            Ok(())
        } else {
            Err(failure(Status::from_code(code)))
        }
    }
    fn authenticate(&mut self) -> Result<(), Failure> {
        self.transport.files().finish_binding().map_err(failure)
    }
    fn pause(&mut self, room: bool) {
        if room {
            let pause = posix_change::room_pause_ns(self.room_repeats);
            self.room_repeats = self.room_repeats.saturating_add(1);
            let _ = crate::threads::sleep::pause(pause);
        } else {
            let _ = rt::sys::yield_now();
        }
    }
    fn publish(&mut self, reply: LockReply) -> Result<(), i32> {
        let terminal = TerminalReply::from_reply(reply).map_err(crate::error)?;
        crate::shared::with_files(|files| {
            let snapshot = files.lock_snapshot(self.token).map_err(crate::error)?;
            if snapshot.result.is_some() {
                return Ok(());
            }
            let lock = snapshot.recovery.lock().ok_or(EIO)?;
            let result = if reply.result == 0 {
                ControlResult::Value(0)
            } else {
                let errno = if reply.result == proto_fs::LOCK_CANCELLED {
                    match lock.cancel_reason() {
                        CancelReason::Close => EBADF,
                        CancelReason::Abandoned => EIO,
                    }
                } else {
                    match crate::lock_fields::terminal_result(reply.result) {
                        Err(errno) if errno != EIO => errno,
                        _ => crate::error(Status::Unknown(reply.result).into()),
                    }
                };
                ControlResult::Failed(errno)
            };
            if let Some(claim) = self.claim.filter(|&claim| files.lock_is_live(claim)) {
                files
                    .complete_lock_record(claim, result, terminal)
                    .map_err(crate::error)?;
            } else {
                if snapshot.phase != ControlPhase::Cleaning {
                    files
                        .begin_lock_cleanup(self.token, lock.cancel_reason())
                        .map_err(crate::error)?;
                }
                files
                    .publish_lock_cleanup(self.token, result, terminal)
                    .map_err(crate::error)?;
            }
            Ok(())
        })
    }
    fn begin_cleanup(&mut self) -> Result<(), i32> {
        crate::shared::with_files(|files| {
            let snapshot = files.lock_snapshot(self.token).map_err(crate::error)?;
            if snapshot.phase != ControlPhase::Cleaning {
                let reason = snapshot.recovery.lock().ok_or(EIO)?.cancel_reason();
                files
                    .begin_lock_cleanup(self.token, reason)
                    .map_err(crate::error)?;
            }
            Ok(())
        })
    }
    fn finish_cleanup(&mut self) -> Result<(), i32> {
        crate::shared::with_files(|files| {
            files.finish_lock_cleanup(self.token).map_err(crate::error)
        })
    }
    fn acknowledge(&mut self) -> Result<LockReply, i32> {
        let owner = self.owner.ok_or(EIO)?;
        crate::shared::with_files(|files| {
            let (result, reply) = files
                .ack_lock_record(self.token, owner)
                .map_err(crate::error)?;
            result.into_result()?;
            reply.ok_or(EIO)
        })
    }
}

/// The copied input contains no caller pointer. Public activation follows close fencing.
pub(crate) fn operation(fd: u32, input: crate::lock_fields::Input) -> Result<LockReply, i32> {
    let owner = OwnerToken::new(crate::relibc::open_owner()?).map_err(|_| EIO)?;
    let frame = crate::change::frame();
    let input = Input {
        command: input.command,
        kind: input.kind,
        whence: input.whence,
        start: input.start,
        length: input.length,
        pid: input.pid,
    };
    let (token, claim, transport) = crate::change::take_place(owner, frame, |files| {
        let source = files.lock_source(fd)?;
        let (token, claim) = files.begin_lock_record(owner, source, frame, input)?;
        Ok((token, claim, files.transport()))
    })
    .map_err(|errno| {
        if errno == constants::EAGAIN {
            ENOLCK
        } else {
            errno
        }
    })?;
    let result = core::drive(&mut Live {
        token,
        claim: Some(claim),
        owner: Some(owner),
        transport,
        room_repeats: 0,
    });
    crate::change::wake_places();
    result
}

/// A close or lifetime helper keeps the same key and pays one bounded cleanup turn.
pub(crate) fn cleanup_step(token: ControlToken) -> Result<bool, i32> {
    let transport = crate::shared::with_files(|files| {
        Ok(files.lock_snapshot(token).ok().map(|_| files.transport()))
    })?;
    let Some(transport) = transport else {
        return Ok(true);
    };
    let completed = core::cleanup_step(&mut Live {
        token,
        claim: None,
        owner: None,
        transport,
        room_repeats: 0,
    })?;
    if completed {
        crate::change::wake_places();
    }
    Ok(completed)
}
