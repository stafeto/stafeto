// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Resident snapshots select exact requests and preserve outcomes before Release.

use super::constants::EIO;
use proto_fs::{LockPhase, LockReply};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Live,
    Complete,
    Cleaning,
    Cleaned,
    Gone,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct State {
    pub phase: Phase,
    pub claim_live: bool,
    pub saved: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    Interrupted,
    Room,
    Authenticating,
    Resolving,
    Retired,
    Rejected(u32),
    Fatal(i32),
}
pub trait Session {
    type Completion;
    fn state(&mut self) -> Result<State, i32>;
    fn start(&mut self) -> Result<LockReply, Failure>;
    fn query(&mut self) -> Result<LockReply, Failure>;
    fn cancel(&mut self) -> Result<LockReply, Failure>;
    fn release(&mut self) -> Result<(), Failure>;
    fn authenticate(&mut self) -> Result<(), Failure>;
    fn pause(&mut self, room: bool);
    fn publish(&mut self, reply: LockReply) -> Result<(), i32>;
    fn begin_cleanup(&mut self) -> Result<(), i32>;
    fn finish_cleanup(&mut self) -> Result<(), i32>;
    fn acknowledge(&mut self) -> Result<Self::Completion, i32>;
}

/// A helper sends at most one request and saves the canonical result before Release.
pub fn cleanup_step(session: &mut impl Session) -> Result<bool, i32> {
    let state = session.state()?;
    match state.phase {
        Phase::Gone | Phase::Cleaned => return Ok(true),
        Phase::Live | Phase::Complete => {
            session.begin_cleanup()?;
            return Ok(false);
        }
        Phase::Cleaning => {}
    }
    if state.saved {
        match session.release() {
            Ok(()) => session.finish_cleanup()?,
            Err(Failure::Interrupted | Failure::Resolving | Failure::Room) => {}
            Err(Failure::Authenticating) => return Err(EIO),
            Err(Failure::Retired) => session.finish_cleanup()?,
            Err(Failure::Rejected(_) | Failure::Fatal(_)) => return Err(EIO),
        }
    } else {
        match session.cancel() {
            Ok(reply) if reply.phase == LockPhase::Complete => session.publish(reply)?,
            Ok(_) | Err(Failure::Interrupted | Failure::Resolving | Failure::Room) => {}
            Err(Failure::Authenticating) => return Err(EIO),
            Err(Failure::Retired | Failure::Rejected(_) | Failure::Fatal(_)) => {
                return Err(EIO);
            }
        }
    }
    Ok(false)
}

/// Each retry checks resident authority before sending the original registered key.
pub fn drive<S: Session>(session: &mut S) -> Result<S::Completion, i32> {
    let mut admitted = false;
    loop {
        let state = session.state()?;
        match state.phase {
            Phase::Gone => return Err(EIO),
            Phase::Cleaned => return session.acknowledge(),
            Phase::Complete | Phase::Cleaning => {
                cleanup_step(session)?;
                session.pause(false);
                continue;
            }
            Phase::Live if !state.claim_live => {
                session.begin_cleanup()?;
                continue;
            }
            Phase::Live => {}
        }
        let reply = if admitted {
            session.query()
        } else {
            session.start()
        };
        match reply {
            Ok(reply) => {
                admitted = true;
                if reply.phase == LockPhase::Complete {
                    session.publish(reply)?;
                } else {
                    session.pause(false);
                }
            }
            Err(Failure::Interrupted | Failure::Resolving) => session.pause(false),
            Err(Failure::Room) => session.pause(true),
            Err(Failure::Authenticating) => match session.authenticate() {
                Ok(()) | Err(Failure::Interrupted | Failure::Resolving) => {}
                Err(_) => session.begin_cleanup()?,
            },
            Err(Failure::Rejected(result)) if !admitted => {
                session.publish(LockReply {
                    phase: LockPhase::Complete,
                    result,
                    blocker: None,
                })?;
            }
            Err(Failure::Retired | Failure::Rejected(_) | Failure::Fatal(_)) => {
                session.begin_cleanup()?;
            }
        }
    }
}
