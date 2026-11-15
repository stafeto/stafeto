// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The loop's side of the time budgets of POSIX threads (`Method::Budget`,
//! proto_process::sporadic): the requests of a record's session (ASK, DONE,
//! UNBIND, DROP) and the WORK of the budget thread (budgeter.rs). The state
//! is `posix_process_service::budgets::Budgets`; this file makes the replies
//! and the copies of the handles.

use crate::Processes;
use posix_process_service::budgets::Refusal;
use proto_process::sporadic::{self, Ask, Done, Job};
use proto_wire::{Status, Writer};
use rt::abi::{self, Rights};
use rt::handle::{Budget, Handle, Outgoing};
use rt::service::{Answer, Request};
use rt::sys;

/// The status of a refusal of init, as the layer reads it: the share is
/// gone (FULL) or the numbers are no budget (INVALID).
fn status_of(init: u32) -> u32 {
    if init == Status::Kernel(abi::Error::InvalidArgs).code() || init == proto_process::INVALID {
        proto_process::INVALID
    } else {
        proto_process::FULL
    }
}

fn refuse(code: u32) -> Answer {
    Answer::Status(Status::from_code(code))
}

/// The copy of `budget` a program gets: the right BUDGET alone.
fn copy(budget: &Handle<Budget>) -> Result<Handle<Budget>, abi::Error> {
    sys::handle_duplicate(budget, Rights::BUDGET)
}

impl Processes {
    /// The PID of the record `index`: the guard of its entries against a
    /// record that took the index later.
    fn budget_owner(&self, index: usize) -> u64 {
        self.records
            .get(index)
            .map_or(0, |r| u64::from(r.label.pid()))
    }

    /// Method::Budget.
    pub(crate) fn budget(&mut self, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let Ok(op) = body.u32() else {
            return Answer::Status(Status::BadSize);
        };
        if op == sporadic::WORK {
            if r.label() != 0 {
                return refuse(proto_process::PERMISSION);
            }
            return self.budget_work(r);
        }
        let Some(index) = self.records.find(r.label()) else {
            return refuse(proto_process::UNREGISTERED);
        };
        let owner = self.budget_owner(index);
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        match op {
            sporadic::ASK => {
                let (Ok(ask), Ok(())) = (Ask::read(&mut body), body.finish()) else {
                    return Answer::Status(Status::BadSize);
                };
                if ask.thread == 0
                    || !(1..=4).contains(&ask.max_repl)
                    || !(1..=63).contains(&ask.low)
                    || ask.cpu >= 8
                {
                    return refuse(proto_process::INVALID);
                }
                let Some(pending) = r.defer() else {
                    return Answer::Status(Status::BadSize);
                };
                if let Err((why, pending)) = self.budgets.ask(index, owner, ask, pending) {
                    let code = match why {
                        Refusal::Again => proto_process::AGAIN,
                        Refusal::Room => proto_process::FULL,
                    };
                    let _ = pending
                        .answer(&proto_wire::reply(Status::from_code(code)), Outgoing::new());
                    return Answer::Deferred;
                }
                self.dispatch_budget();
                Answer::Deferred
            }
            sporadic::DONE => {
                let (Ok(thread), Ok(bound), Ok(())) = (body.u32(), body.u32(), body.finish())
                else {
                    return Answer::Status(Status::BadSize);
                };
                let known = self.budgets.commit(index, owner, thread, bound != 0);
                self.dispatch_budget();
                if known {
                    Answer::Status(Status::Ok)
                } else {
                    refuse(proto_process::NO_PROCESS)
                }
            }
            sporadic::UNBIND => {
                let (Ok(thread), Ok(())) = (body.u32(), body.finish()) else {
                    return Answer::Status(Status::BadSize);
                };
                let Some(current) = self.budgets.current(index, owner, thread) else {
                    return refuse(proto_process::NO_PROCESS);
                };
                let Ok(give) = copy(current) else {
                    return Answer::Status(Status::Kernel(abi::Error::NoMemory));
                };
                let mut out = Outgoing::new();
                let _ = out.push(give.erase());
                let _ = r.reply().u32(0).and_then(|()| r.reply().u32(0));
                Answer::Reply(out)
            }
            sporadic::DROP => {
                let (Ok(thread), Ok(())) = (body.u32(), body.finish()) else {
                    return Answer::Status(Status::BadSize);
                };
                self.budgets.drop_thread(index, owner, thread);
                self.dispatch_budget();
                Answer::Status(Status::Ok)
            }
            _ => Answer::Status(Status::UnknownMethod),
        }
    }

    /// WORK from the budget thread: the result of its last job, and the wait
    /// for the next.
    fn budget_work(&mut self, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let (Ok(_), Ok(done)) = (body.u32(), Done::read(&mut body)) else {
            return Answer::Status(Status::BadSize);
        };
        if body.finish().is_err() || r.handles.len() > 1 {
            return Answer::Status(Status::BadSize);
        }
        let handle = r.handles.take::<Budget>(0).ok();
        if self.budgeter.is_some() {
            return refuse(proto_process::AGAIN);
        }
        if done.seq != 0
            && let Some(completed) = self.budgets.done(done.seq, done.status, done.id, handle)
        {
            self.complete_ask(completed.slot, completed.status, completed.pending);
        }
        self.budgeter = r.defer();
        self.dispatch_budget();
        Answer::Deferred
    }

    /// The reply of a finished ASK: the budget, and the current one when the
    /// thread has one, or the refusal.
    fn complete_ask(&mut self, slot: usize, status: u32, pending: rt::service::Pending) {
        if status != 0 {
            let reply = proto_wire::reply(Status::from_code(status_of(status)));
            let _ = pending.answer(&reply, Outgoing::new());
            return;
        }
        let copies = self.budgets.handles(slot).map(|(new, old)| {
            let new = copy(new);
            let old = old.map(copy);
            (new, old)
        });
        let mut out = Outgoing::new();
        let made = match copies {
            Some((Ok(new), None)) => out.push(new.erase()).is_ok(),
            Some((Ok(new), Some(Ok(old)))) => {
                out.push(new.erase()).is_ok() && out.push(old.erase()).is_ok()
            }
            _ => false,
        };
        if !made {
            self.budgets.fail(slot);
            let reply = proto_wire::reply(Status::Kernel(abi::Error::NoMemory));
            let _ = pending.answer(&reply, Outgoing::new());
            return;
        }
        let mut w = Writer::new();
        if w.u32(0).and_then(|()| w.u32(0)).is_err() || pending.answer(w.as_bytes(), out).is_err() {
            self.budgets.fail(slot);
        }
    }

    /// Gives the waiting WORK the next job, if both wait.
    pub(crate) fn dispatch_budget(&mut self) {
        if self.budgeter.is_none() {
            return;
        }
        let Some(next) = self.budgets.take_job() else {
            return;
        };
        let job = Job {
            kind: next.kind,
            seq: next.seq,
            id: next.id,
            ask: next.ask,
        };
        let mut w = Writer::new();
        let pending = self.budgeter.take().expect("a waiting WORK");
        if w.u32(0).and_then(|()| job.write(&mut w)).is_err()
            || pending.answer(w.as_bytes(), Outgoing::new()).is_err()
        {
            // The thread is gone: the job is lost with it; the service ends
            // with its thread (budgeter.rs).
            rt::println!("posix-process: the budget thread did not take a job");
        }
    }

    /// The record `index` ended: its threads' budgets go back.
    pub(crate) fn budgets_of_record_ended(&mut self, index: usize) {
        let owner = self.budget_owner(index);
        self.budgets.drop_record(index, owner);
        self.dispatch_budget();
    }
}
