// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! One paid key survives retries, signal cancellation and helper cleanup.

use proto_fs::{WaitPhase, WaitReply};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Working,
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
    pub channel: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    Signal,
    Abandoned,
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
    fn ending(&mut self) -> bool;
    fn start(&mut self) -> Result<WaitReply, Failure>;
    fn query(&mut self) -> Result<WaitReply, Failure>;
    fn arm(&mut self) -> Result<WaitReply, Failure>;
    fn receive(&mut self) -> Result<(), Failure>;
    fn cancel(&mut self) -> Result<WaitReply, Failure>;
    fn release(&mut self) -> Result<(), Failure>;
    fn close_channel(&mut self) -> Result<(), i32>;
    fn authenticate(&mut self) -> Result<(), Failure>;
    fn pause(&mut self, room: bool);
    fn publish(&mut self, reply: WaitReply) -> Result<(), i32>;
    fn begin_cleanup(&mut self, reason: Reason) -> Result<(), i32>;
    fn finish_cleanup(&mut self) -> Result<(), i32>;
    fn acknowledge(&mut self) -> Result<Self::Completion, i32>;
}

const EIO: i32 = 5;

/// Channel admission runs before Start; a proven resource refusal has no effect.
pub fn prepared(session: &mut impl Session, created: Result<(), Failure>) -> Result<(), i32> {
    match created {
        Ok(()) | Err(Failure::Retired) => Ok(()),
        Err(Failure::Room) => session.publish(WaitReply {
            phase: WaitPhase::Complete,
            result: proto_fs::NO_LOCKS,
        }),
        Err(Failure::Fatal(error)) => {
            session.begin_cleanup(Reason::Abandoned)?;
            Err(error)
        }
        Err(_) => {
            session.begin_cleanup(Reason::Abandoned)?;
            Err(EIO)
        }
    }
}

/// An error can race a helper that already saved the canonical receipt.
fn failed_turn(session: &mut impl Session, saved: bool) -> Result<bool, i32> {
    let now = session.state()?;
    if matches!(now.phase, Phase::Gone | Phase::Cleaned) || !saved && now.saved {
        Ok(false)
    } else {
        Err(EIO)
    }
}

/// At most one RPC, or one exact raw channel close, outside the table lock.
pub fn cleanup_step(session: &mut impl Session) -> Result<bool, i32> {
    let state = session.state()?;
    match state.phase {
        Phase::Gone => return Ok(true),
        Phase::Cleaned => {
            if state.channel {
                session.close_channel()?;
            }
            return Ok(!session.state()?.channel);
        }
        Phase::Working | Phase::Complete => {
            session.begin_cleanup(Reason::Abandoned)?;
            return Ok(false);
        }
        Phase::Cleaning => {}
    }
    if state.saved {
        match session.release() {
            Ok(()) | Err(Failure::Retired) => session.finish_cleanup()?,
            Err(Failure::Interrupted | Failure::Resolving | Failure::Room) => {}
            Err(_) => return failed_turn(session, true),
        }
    } else {
        match session.cancel() {
            Ok(reply) if reply.phase == WaitPhase::Complete => session.publish(reply)?,
            Ok(_) | Err(Failure::Interrupted | Failure::Resolving | Failure::Room) => {}
            Err(_) => return failed_turn(session, false),
        }
    }
    Ok(false)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Next {
    Start,
    Query,
    Arm,
    Receive,
}

/// Arm is followed by Query; a wake merely prompts Query of the same key.
pub fn drive<S: Session>(session: &mut S) -> Result<S::Completion, i32> {
    let mut next = Next::Start;
    let mut admitted = false;
    loop {
        let state = session.state()?;
        match state.phase {
            Phase::Gone => return Err(EIO),
            Phase::Cleaned if !state.channel => return session.acknowledge(),
            Phase::Complete | Phase::Cleaning | Phase::Cleaned => {
                cleanup_step(session)?;
                session.pause(false);
                continue;
            }
            Phase::Working if !state.claim_live => {
                session.begin_cleanup(Reason::Abandoned)?;
                continue;
            }
            Phase::Working => {}
        }
        if session.ending() {
            session.begin_cleanup(Reason::Signal)?;
            continue;
        }
        let sent = next;
        if sent == Next::Receive {
            // The production receive rechecks signal state under entry deferral.
            match session.receive() {
                Ok(()) | Err(Failure::Interrupted | Failure::Retired) => {}
                Err(Failure::Fatal(error)) => {
                    session.begin_cleanup(Reason::Abandoned)?;
                    return Err(error);
                }
                Err(_) => {
                    session.begin_cleanup(Reason::Abandoned)?;
                    return Err(EIO);
                }
            }
            next = Next::Query;
            continue;
        }
        let reply = match sent {
            Next::Start => session.start(),
            Next::Query => session.query(),
            Next::Arm => session.arm(),
            Next::Receive => unreachable!(),
        };
        // An unknown Arm transfer fate is reconciled by authoritative Query.
        if sent == Next::Arm {
            next = Next::Query;
        }
        match reply {
            Ok(reply) => {
                admitted = true;
                match reply.phase {
                    WaitPhase::Complete => session.publish(reply)?,
                    WaitPhase::NeedsArm => next = Next::Arm,
                    WaitPhase::Sleeping if sent == Next::Query => next = Next::Receive,
                    WaitPhase::Sleeping => next = Next::Query,
                    WaitPhase::Queued => {
                        next = Next::Query;
                        session.pause(false);
                    }
                }
            }
            Err(Failure::Interrupted | Failure::Resolving) => session.pause(false),
            Err(Failure::Room) => session.pause(true),
            Err(Failure::Authenticating) => match session.authenticate() {
                Ok(()) | Err(Failure::Interrupted | Failure::Resolving) => {}
                Err(Failure::Fatal(error)) => {
                    session.begin_cleanup(Reason::Abandoned)?;
                    return Err(error);
                }
                Err(_) => {
                    session.begin_cleanup(Reason::Abandoned)?;
                    return Err(EIO);
                }
            },
            Err(Failure::Rejected(result)) if !admitted && sent == Next::Start => {
                session.publish(WaitReply {
                    phase: WaitPhase::Complete,
                    result,
                })?;
            }
            Err(Failure::Retired) => {
                // A close helper can revoke the owner between snapshot and syscall.
                let now = session.state()?;
                if now.phase == Phase::Working && now.claim_live {
                    session.begin_cleanup(Reason::Abandoned)?;
                    return Err(EIO);
                }
            }
            Err(Failure::Fatal(error)) => {
                session.begin_cleanup(Reason::Abandoned)?;
                return Err(error);
            }
            Err(Failure::Rejected(_)) => {
                session.begin_cleanup(Reason::Abandoned)?;
                return Err(EIO);
            }
        }
    }
}
