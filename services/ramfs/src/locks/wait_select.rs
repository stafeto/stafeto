// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! One bounded FIFO eligibility attempt belongs to one exact paid Control key.
use super::{
    Lock,
    actor::{Actor, Command, ReadState, Reader},
    jobs::{Id as ControlId, Queue as ControlQueue},
    request::Captured,
    wait_receipts::{Phase as ReceiptPhase, Queue},
    waiters::{CAPACITY, Cursor, Phase, Pool, RegistrationToken},
};
use crate::storage::Token;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Candidate {
    pub registration: RegistrationToken,
    pub captured: Captured,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Control,
    Wait(Candidate),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Progress {
    pub visited: usize,
    pub decision: Option<Decision>,
}

pub struct Selector {
    control: Option<ControlId>,
    captured: Option<Captured>,
    spent: bool,
    cursor: Option<Cursor>,
    remaining: usize,
    candidates: [Option<Candidate>; CAPACITY],
    count: usize,
    next: usize,
    reader: Option<Reader>,
    blocked: bool,
}
const _: () = assert!(core::mem::size_of::<Selector>() == 2696);

impl Selector {
    /// # Safety
    /// Exclusive aligned writable uninitialized storage for Self.
    pub unsafe fn initialize_at(destination: *mut Self) {
        // SAFETY: every field is initialized in the caller's exclusive storage.
        unsafe {
            core::ptr::addr_of_mut!((*destination).control).write(None);
            core::ptr::addr_of_mut!((*destination).captured).write(None);
            core::ptr::addr_of_mut!((*destination).spent).write(false);
            core::ptr::addr_of_mut!((*destination).cursor).write(None);
            core::ptr::addr_of_mut!((*destination).remaining).write(0);
            let candidates =
                core::ptr::addr_of_mut!((*destination).candidates).cast::<Option<Candidate>>();
            for index in 0..CAPACITY {
                candidates.add(index).write(None);
            }
            core::ptr::addr_of_mut!((*destination).count).write(0);
            core::ptr::addr_of_mut!((*destination).next).write(0);
            core::ptr::addr_of_mut!((*destination).reader).write(None);
            core::ptr::addr_of_mut!((*destination).blocked).write(false);
        }
    }

    /// Same exact Control custody cannot earn another attempt after cancellation.
    /// The caller verifies this id/capture against its paid Control queue.
    pub fn begin(
        &mut self,
        id: ControlId,
        captured: Captured,
        pool: &Pool,
        jobs: &ControlQueue,
    ) -> Result<(), u32> {
        let (paid, _, _) = jobs.snapshot(id)?;
        if paid != captured {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let paid_spent = jobs.wait_attempt_spent(id)?;
        if self.control == Some(id) {
            self.spent |= paid_spent;
            return if self.captured == Some(captured) {
                Ok(())
            } else {
                Err(proto_fs::INVALID_ARGUMENT)
            };
        }
        self.control = Some(id);
        self.captured = Some(captured);
        self.spent = paid_spent || !matches!(captured.request.command, Command::Set(Some(_)));
        self.cursor = Some(pool.cursor());
        self.remaining = pool.count();
        self.candidates.fill(None);
        self.count = 0;
        self.next = 0;
        self.reader = None;
        self.blocked = false;
        Ok(())
    }
    fn control(&mut self, jobs: &mut ControlQueue, visited: usize) -> Progress {
        if let Some(id) = self.control {
            let _ = jobs.spend_wait_attempt(id);
        }
        self.spent = true;
        self.reader = None;
        Progress {
            visited,
            decision: Some(Decision::Control),
        }
    }
    fn valid(candidate: Candidate, pool: &Pool, queue: &Queue) -> bool {
        let Ok((input, phase)) = pool.snapshot(candidate.registration) else {
            return false;
        };
        let Ok((captured, receipt_phase, _)) = queue.snapshot(candidate.registration.receipt())
        else {
            return false;
        };
        input.receipt == candidate.registration.receipt()
            && input.root == captured.root
            && input.inode == captured.request.inode
            && input.range == captured.request.range
            && matches!(captured.request.command, Command::Set(Some(kind)) if kind == input.kind)
            && captured == candidate.captured
            && matches!(phase, Phase::Sleeping | Phase::Ready)
            && matches!(receipt_phase, ReceiptPhase::Sleeping | ReceiptPhase::Ready)
    }

    /// Copy FIFO entries or visit published lock records, never both in one turn.
    /// The caller revalidates exact source authority before starting the Actor.
    pub fn part<
        const G: usize,
        const I: usize,
        const P: usize,
        const D: usize,
        const R: usize,
        const S: usize,
    >(
        &mut self,
        pool: &Pool,
        queue: &Queue,
        jobs: &mut ControlQueue,
        actor: &Actor<G, I, P, D, R, S>,
        pid_live: impl FnMut(u32) -> bool,
        ofd_live: impl FnMut(Token) -> bool,
    ) -> Progress {
        if self.spent
            || self
                .control
                .is_none_or(|id| jobs.wait_attempt_spent(id) != Ok(false))
        {
            return self.control(jobs, 0);
        }
        let Some(control) = self.captured else {
            return self.control(jobs, 0);
        };
        let Command::Set(Some(kind)) = control.request.command else {
            return self.control(jobs, 0);
        };
        if let Some(cursor) = &mut self.cursor {
            let mut invalid = false;
            let result = pool.scan(cursor, |registration, input, phase| {
                if self.remaining == 0 {
                    return;
                }
                self.remaining -= 1;
                if phase == Phase::Running || input.inode != control.request.inode {
                    return;
                }
                let Ok((captured, receipt_phase, _)) = queue.snapshot(registration.receipt())
                else {
                    invalid = true;
                    return;
                };
                if !matches!(receipt_phase, ReceiptPhase::Sleeping | ReceiptPhase::Ready) {
                    return;
                }
                let candidate = Candidate {
                    registration,
                    captured,
                };
                if !Self::valid(candidate, pool, queue) {
                    invalid = true;
                    return;
                }
                let prospective = Lock {
                    owner: captured.request.owner,
                    kind: input.kind,
                    range: input.range,
                };
                let later = Lock {
                    owner: control.request.owner,
                    kind,
                    range: control.request.range,
                };
                if prospective.conflicts(later) {
                    self.candidates[self.count] = Some(candidate);
                    self.count += 1;
                }
            });
            let visited = match result {
                Ok(n) => n,
                Err(_) => return self.control(jobs, 8),
            };
            if invalid {
                return self.control(jobs, visited);
            }
            if cursor.done() || self.remaining == 0 {
                self.cursor = None;
            }
            return Progress {
                visited,
                decision: None,
            };
        }
        let Some(candidate) = self.candidates.get(self.next).copied().flatten() else {
            return self.control(jobs, 0);
        };
        if !Self::valid(candidate, pool, queue) {
            return self.control(jobs, 0);
        }
        if self.reader.is_none() {
            self.reader = match actor.reader(candidate.captured.request) {
                Ok(Some(reader)) => Some(reader),
                _ => return self.control(jobs, 0),
            };
            self.blocked = false;
        }
        let reader = self.reader.as_mut().expect("initialized candidate reader");
        let progress = actor.reader_part(reader, pid_live, ofd_live);
        self.blocked |= progress.blockers.iter().any(Option::is_some);
        match progress.state {
            ReadState::Invalidated => self.control(jobs, progress.visited),
            ReadState::More => Progress {
                visited: progress.visited,
                decision: None,
            },
            ReadState::Done => {
                if !actor.reader_snapshot_valid(reader.snapshot())
                    || !Self::valid(candidate, pool, queue)
                {
                    return self.control(jobs, progress.visited);
                }
                self.reader = None;
                if self.blocked {
                    self.next += 1;
                    Progress {
                        visited: progress.visited,
                        decision: None,
                    }
                } else {
                    if self
                        .control
                        .is_none_or(|id| jobs.spend_wait_attempt(id) != Ok(true))
                    {
                        return self.control(jobs, progress.visited);
                    }
                    self.spent = true;
                    Progress {
                        visited: progress.visited,
                        decision: Some(Decision::Wait(candidate)),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "wait_select_tests.rs"]
mod tests;
