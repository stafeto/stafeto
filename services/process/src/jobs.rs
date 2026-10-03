// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Suspension, wait reports and signals of newly orphaned groups.
use super::*;
use core::sync::atomic::Ordering;
use proto_process::{PAGE_NOCLDSTOP, SIGCONT, SIGHUP, SIGTSTP, SIGTTIN, SIGTTOU};

impl Processes {
    pub(super) fn can_generate_job(&self, target: usize, signal: u8) -> bool {
        let Some(r) = self.records.get(target) else {
            return false;
        };
        if signal == SIGCONT {
            r.stop_epoch.checked_add(8).is_some()
        } else if matches!(signal, SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU) {
            r.cont_epoch.checked_add(2).is_some()
        } else {
            true
        }
    }

    pub(super) fn generate_job(&mut self, target: usize, signal: u8) -> Option<u64> {
        let page = self.pages.page(target)?;
        let r = self.records.get_mut(target)?;
        let ticket = signals::generation(&mut r.stop_epoch, &mut r.cont_epoch, page, signal)?;
        if signal == SIGSTOP {
            self.stop_process(target, signal)
        } else if signal == SIGCONT {
            self.continue_process(target)
        }
        Some(ticket)
    }

    fn stop_process(&mut self, target: usize, signal: u8) {
        let r = self.records.get(target).expect("a stop target");
        if matches!(r.state, State::Zombie(_)) || r.stopped.is_some() {
            return;
        }
        let loading = r.state == State::Loading;
        if !loading && sys::process_control(&r.process, true, r.ceiling).is_err() {
            return;
        }
        self.records.set_stopped(target, Some(signal));
        if !loading {
            self.child_report(target, Some(signal))
        }
    }

    fn continue_process(&mut self, target: usize) {
        let r = self.records.get(target).expect("a continue target");
        if matches!(r.state, State::Zombie(_)) || r.stopped.is_none() {
            return;
        }
        let loading = r.state == State::Loading;
        if !loading && sys::process_control(&r.process, false, r.ceiling).is_err() {
            return;
        }
        self.records.set_stopped(target, None);
        if !loading {
            self.child_report(target, None)
        }
    }

    pub(super) fn child_report(&mut self, child: usize, signal: Option<u8>) {
        let r = self.records.get(child).expect("a reported child");
        let (parent, pid, uid) = (r.parent_index, r.label.pid(), r.credentials.uid);
        self.records.report(child, signal);
        let Some(parent) = parent.map(usize::from) else {
            return;
        };
        self.tell(parent, child);
        if self
            .pages
            .page(parent)
            .is_some_and(|p| p.flags.load(Ordering::Acquire) & PAGE_NOCLDSTOP != 0)
        {
            return;
        }
        self.signal(
            parent,
            SIGCHLD,
            Info {
                code: if signal.is_some() {
                    proto_process::CLD_STOPPED
                } else {
                    proto_process::CLD_CONTINUED
                },
                pid,
                uid,
                status: i32::from(signal.unwrap_or(SIGCONT)),
            },
        );
    }

    pub(super) fn signal_generation(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let (Ok(signal), Ok(())) = (body.u32(), body.finish()) else {
            return Answer::Status(Status::BadSize);
        };
        let Ok(signal) = u8::try_from(signal) else {
            return refuse(proto_process::INVALID);
        };
        if signal != SIGSTOP && proto_process::job::class(signal).is_none() {
            return refuse(proto_process::INVALID);
        }
        let Some(ticket) = self.generate_job(index, signal) else {
            return refuse(proto_process::AGAIN);
        };
        if r.reply()
            .u32(0)
            .and_then(|()| r.reply().u64(ticket))
            .is_err()
        {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    /// Only the current image can return its assignment. The service remains
    /// the sole publisher of job information, including this slow path.
    pub(super) fn return_job_signal(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let (Ok(signal), Ok(ticket), Ok(code), Ok(pid), Ok(uid), Ok(status), Ok(())) = (
            body.u32(),
            body.u64(),
            body.u32(),
            body.u32(),
            body.u32(),
            body.u32(),
            body.finish(),
        ) else {
            return Answer::Status(Status::BadSize);
        };
        let Ok(signal) = u8::try_from(signal) else {
            return refuse(proto_process::INVALID);
        };
        if proto_process::job::class(signal).is_none() {
            return refuse(proto_process::INVALID);
        }
        let Some(page) = self.pages.page(index) else {
            return refuse(proto_process::NO_PROCESS);
        };
        if signals::return_job(
            page,
            signal,
            ticket,
            Info {
                code: code as i32,
                pid,
                uid,
                status: status as i32,
            },
        ) == Some(Posted::Pending)
            && let Some(router) = self.routers[index].as_ref()
        {
            let _ = sys::thread_upcall_request(router);
        }
        Answer::Status(Status::Ok)
    }

    pub(super) fn stop_self(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let (Ok(signal), Ok(ticket), Ok(())) = (body.u32(), body.u64(), body.finish()) else {
            return Answer::Status(Status::BadSize);
        };
        let Ok(signal) = u8::try_from(signal) else {
            return refuse(proto_process::INVALID);
        };
        if !matches!(signal, SIGTSTP | SIGTTIN | SIGTTOU) {
            return refuse(proto_process::INVALID);
        }
        let record = self.records.get(index).expect("the calling image");
        if record.stop_epoch == ticket && self.records.orphaned(record.pgid) == Some(false) {
            self.stop_process(index, signal);
        }
        Answer::Status(Status::Ok)
    }

    /// One bounded step. HUP completes its group walk before CONT starts.
    pub(super) fn orphan_step(&mut self) {
        if self.orphan_walk.is_none() {
            let Some(group) = self.records.take_orphan() else {
                return;
            };
            self.orphan_walk = Some((group, Walk::new(Target::Group(group), RECORDS), false));
        }
        let (group, mut walk, continuing) = self.orphan_walk.take().expect("an orphan walk");
        match walk.step(&self.records) {
            Step::Found(target) => {
                self.deliver_terminal(target, if continuing { SIGCONT } else { SIGHUP });
            }
            Step::Looked => {}
            Step::Done if continuing => return,
            Step::Done => {
                self.orphan_walk = Some((group, Walk::new(Target::Group(group), RECORDS), true));
                return;
            }
        }
        self.orphan_walk = Some((group, walk, continuing));
    }
}
