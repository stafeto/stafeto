// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! One existing Work row retains end owners and paid wait notifications.
use super::*;
use records::Retirement;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Reason,
    Loader,
    Executable,
    Children,
    ChildExecutable,
    ChildProcess,
    ChildRelease,
    Router,
    Witness,
    Terminal,
    Metadata,
    Signal,
    Tell,
    Process,
    Release,
    Reply,
}

pub(super) struct Ending {
    key: preparing::Key,
    parent: Option<preparing::Key>,
    child: Option<preparing::Key>,
    executable: Option<Handle<Channel>>,
    process: Option<Handle<Process>>,
    retirement: Option<Retirement>,
    pending: Option<Pending>,
    tell_keys: [u64; WAITS_OF_RECORD],
    info: Info,
    phase: Phase,
    tell_cursor: u8,
    terminal: bool,
}
impl Ending {
    fn new(key: preparing::Key, pending: Option<Pending>) -> Self {
        Self {
            key,
            parent: None,
            child: None,
            executable: None,
            process: None,
            retirement: None,
            pending,
            tell_keys: [0; WAITS_OF_RECORD],
            info: Info {
                code: 0,
                pid: 0,
                uid: 0,
                status: 0,
            },
            phase: Phase::Reason,
            tell_cursor: 0,
            terminal: false,
        }
    }
    fn accept_wait(
        &mut self,
        key: preparing::Key,
        process: Handle<Process>,
        token: Retirement,
    ) -> Result<(), (Handle<Process>, Retirement)> {
        if key != self.key || token.key() != key || self.retirement.is_some() {
            return Err((process, token));
        }
        self.process = Some(process);
        self.retirement = Some(token);
        if matches!(self.phase, Phase::Process | Phase::Release | Phase::Reply) {
            self.phase = Phase::Process;
        }
        Ok(())
    }
}

impl Processes {
    /// A free existing row starts ownership cleanup; preceding debt retains its row.
    pub(super) fn start_ending(&mut self, index: usize, pending: Option<Pending>) {
        assert!(self.replacing[index].is_none());
        let record = self.records.get(index).expect("the retained ended record");
        assert!(record.state.end_pending());
        let key = preparing::Key {
            label: record.label,
            image: record.image,
        };
        self.replacing[index] = Some(Work::Ending(Ending::new(key, pending)));
        self.replace_cleanup += 1;
    }

    /// Before Record detach, capture matching exact LongOps keys without any SVC.
    fn end_tells(&self, journal: &mut Ending, parent: usize, child: usize) {
        let parent_record = self.records.get(parent).expect("the recorded parent");
        journal.parent = Some(preparing::Key {
            label: parent_record.label,
            image: parent_record.image,
        });
        for (slot, wait) in journal.tell_keys.iter_mut().zip(self.waits.told(
            parent,
            |selector| self.records.takes(child, selector),
            |w| self.ops.waits(w.label, w.key),
        )) {
            *slot = wait.key;
        }
    }

    fn end_parent_live(&self, journal: &Ending) -> Option<usize> {
        let key = journal.parent?;
        let index = usize::from(key.label.index);
        self.records
            .get(index)
            .filter(|r| r.label == key.label && r.image == key.image && r.state.live())
            .map(|_| index)
    }

    /// Wait transfers its one remaining owner into this row before any future dispatch.
    pub(super) fn reap_wait_retained(&mut self, parent: usize, child: usize) {
        let record = self.records.get(child).expect("the reportable zombie");
        let key = preparing::Key {
            label: record.label,
            image: record.image,
        };
        if self.replacing[child].is_none() {
            let mut journal = Ending::new(key, None);
            journal.phase = Phase::Tell;
            self.end_tells(&mut journal, parent, child);
            self.replacing[child] = Some(Work::Ending(journal));
            self.replace_cleanup += 1;
        }
        assert!(
            matches!(self.replacing[child], Some(Work::Ending(_))),
            "a final Zombie keeps only its ending journal"
        );
        let (record, token) = self
            .records
            .reap_retained(key)
            .expect("the exact unreaped zombie");
        let Record {
            process,
            active_exec,
            ..
        } = record;
        assert!(
            active_exec.is_none(),
            "executable custody settles before Zombie publication"
        );
        let Some(Work::Ending(journal)) = self.replacing[child].as_mut() else {
            unreachable!()
        };
        assert!(journal.accept_wait(key, process, token).is_ok());
    }

    pub(super) fn try_end_step(&mut self, index: usize) {
        let Some(Work::Ending(mut journal)) = self.replacing[index].take() else {
            unreachable!()
        };
        if self.end_effect(index, &mut journal) {
            assert!(
                journal.process.is_none()
                    && journal.executable.is_none()
                    && journal.retirement.is_none()
                    && journal.pending.is_none()
            );
            self.replace_cleanup -= 1;
        } else {
            self.replacing[index] = Some(Work::Ending(journal));
        }
    }

    fn end_effect(&mut self, index: usize, journal: &mut Ending) -> bool {
        match journal.phase {
            Phase::Reason => {
                if self.records.end_reason(journal.key).is_none() {
                    let record = self.records.get(index).expect("the exact ended record");
                    if let Ok(state) = sys::process_state(&record.process)
                        && !matches!(
                            state,
                            abi::ProcessState::Alive | abi::ProcessState::Unknown(_)
                        )
                        && let Some(reason) = End::of(state)
                    {
                        self.records.mark_end_pending(journal.key, Some(reason));
                    }
                    return false;
                }
                journal.phase = Phase::Loader;
            }
            Phase::Loader => {
                if self.loaders.of(index).is_some() {
                    self.abort_load(index, Status::from_code(proto_process::AGAIN));
                    return false;
                }
                journal.executable = self
                    .records
                    .begin_end_retained(journal.key)
                    .expect("an exact pending end with known reason");
                journal.phase = Phase::Executable;
            }
            Phase::Executable => {
                if close_owned(&mut journal.executable) {
                    journal.phase = Phase::Children;
                }
            }
            Phase::Children => {
                let Some(child) = self.records.ending_child(journal.key) else {
                    journal.phase = Phase::Router;
                    return false;
                };
                let at = usize::from(child.label.index);
                if self.replacing[at].is_some() || self.loaders.of(at).is_some() {
                    if self
                        .records
                        .get(at)
                        .is_some_and(|r| r.state == State::Loading)
                    {
                        self.abort_load(at, Status::Kernel(abi::Error::PeerClosed));
                    }
                    return false;
                }
                if self
                    .records
                    .get(at)
                    .is_some_and(|r| matches!(r.state, State::Zombie(_)))
                {
                    let (record, token) = self
                        .records
                        .reap_retained(child)
                        .expect("the exact head zombie");
                    let Record {
                        process,
                        active_exec,
                        ..
                    } = record;
                    journal.child = Some(child);
                    journal.process = Some(process);
                    journal.executable = active_exec;
                    journal.retirement = Some(token);
                    journal.phase = Phase::ChildExecutable;
                } else if self.records.orphan_ending_child(journal.key, child)
                    && let Some(page) = self.pages.page(at)
                {
                    page.ppid
                        .store(INIT_PID, core::sync::atomic::Ordering::Release);
                }
            }
            Phase::ChildExecutable => {
                if close_owned(&mut journal.executable) {
                    journal.phase = Phase::ChildProcess;
                }
            }
            Phase::ChildProcess => {
                if close_owned(&mut journal.process) {
                    journal.phase = Phase::ChildRelease;
                }
            }
            Phase::ChildRelease => {
                let token = journal
                    .retirement
                    .take()
                    .expect("the child's withheld slot");
                if let Err(token) = self.records.release_retained(token) {
                    journal.retirement = Some(token);
                    return false;
                }
                self.generations.set_groups(
                    usize::from(
                        journal
                            .child
                            .take()
                            .expect("the retained child key")
                            .label
                            .index,
                    ),
                    None,
                );
                journal.phase = Phase::Children;
            }
            Phase::Router => {
                if close_owned(&mut self.routers[index]) {
                    journal.phase = Phase::Witness;
                }
            }
            Phase::Witness => {
                if close_owned(&mut self.witnesses[index]) {
                    self.tickets[index] = 0;
                    journal.phase = Phase::Terminal;
                }
            }
            Phase::Terminal => {
                let record = self.records.get(index).expect("the ending record");
                if record.label.pid() == record.sid {
                    self.terminals.leader_ended(record.sid);
                    journal.terminal = true;
                }
                journal.phase = Phase::Metadata;
                if journal.terminal
                    && let Some(notice) = self.terminal_notice.as_ref()
                {
                    let _ = sys::notify(notice, 1);
                }
            }
            Phase::Metadata => {
                let record = self.records.get(index).expect("the ending record");
                let reason = self
                    .records
                    .end_reason(journal.key)
                    .expect("the first known reason");
                journal.info = Info {
                    code: if matches!(reason, End::Exited(_)) {
                        CLD_EXITED
                    } else {
                        CLD_KILLED
                    },
                    pid: record.label.pid(),
                    uid: record.credentials.uid,
                    status: match reason {
                        End::Exited(n) => i32::from(n),
                        End::Signaled(n) => i32::from(n),
                    },
                };
                let parent = record
                    .parent_index
                    .filter(|_| matches!(record.state, State::EndingAlive(_)))
                    .map(usize::from);
                if let Some(parent) = parent {
                    self.end_tells(journal, parent, index);
                }
                let metadata = self
                    .records
                    .finish_end_metadata(journal.key)
                    .expect("settled children and executable custody");
                if let Some((record, token)) = metadata.retired {
                    let Record {
                        process,
                        active_exec,
                        ..
                    } = record;
                    assert!(active_exec.is_none());
                    journal.process = Some(process);
                    journal.retirement = Some(token);
                } else if let Exit::Zombie { parent } = metadata.exit {
                    let dead_parent = self.end_parent_live(journal).is_none();
                    let flags = self
                        .pages
                        .page(parent)
                        .map_or(0, |p| p.flags.load(core::sync::atomic::Ordering::Acquire));
                    if dead_parent || flags & (PAGE_NOCLDWAIT | PAGE_CHLD_IGNORED) != 0 {
                        let (record, token) = self
                            .records
                            .reap_retained(journal.key)
                            .expect("the unpublished wait-free zombie");
                        let Record {
                            process,
                            active_exec,
                            ..
                        } = record;
                        assert!(active_exec.is_none());
                        journal.process = Some(process);
                        journal.retirement = Some(token);
                    }
                }
                journal.phase = Phase::Signal;
            }
            Phase::Signal => {
                if let Some(parent) = self.end_parent_live(journal) {
                    self.signal(parent, SIGCHLD, journal.info);
                }
                journal.phase = Phase::Tell;
            }
            Phase::Tell => {
                if usize::from(journal.tell_cursor) == WAITS_OF_RECORD {
                    journal.phase = Phase::Process;
                    return false;
                }
                let key = journal.tell_keys[usize::from(journal.tell_cursor)];
                journal.tell_cursor += 1;
                if self.end_parent_live(journal).is_some()
                    && key != 0
                    && let Some(wait) = self.wait(key)
                    && journal
                        .parent
                        .is_some_and(|p| usize::from(p.label.index) == wait.parent)
                {
                    self.ops.tell(wait.label, wait.key);
                }
            }
            Phase::Process => {
                if close_owned(&mut journal.process) {
                    journal.phase = Phase::Release;
                }
            }
            Phase::Release => {
                if let Some(token) = journal.retirement.take() {
                    if let Err(token) = self.records.release_retained(token) {
                        journal.retirement = Some(token);
                        return false;
                    }
                    self.generations.set_groups(index, None);
                }
                journal.phase = Phase::Reply;
            }
            Phase::Reply => {
                if let Some(pending) = journal.pending.take() {
                    let _ = pending.answer(&proto_wire::reply(Status::Ok), Outgoing::new());
                }
                return true;
            }
        }
        false
    }
}
