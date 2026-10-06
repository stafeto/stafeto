// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Owned state for one bounded cold process preparation in its existing record slot.

use crate::records::{Join, Reservation, StartParent};
use crate::signals::PageStart;
use proto_process::{Create, Credentials, Label};

pub enum RecordWork<R, S> {
    Replacing(R),
    Preparing(S),
}

pub struct Birth {
    pub flags: u32,
    pub pgroup: u32,
    pub level: u8,
    pub credentials: Credentials,
    pub page: PageStart,
}

pub enum Kind {
    Initial {
        create: Create,
    },
    Child {
        birth: Birth,
        join: Join,
        ctty: Option<(u16, u64)>,
    },
    Exec {
        mask: u64,
        replace_serial: u64,
    },
}

pub struct Origin {
    pub parent: Option<StartParent>,
    pub credentials_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub label: Label,
    pub image: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Admission,
    Process,
    PageMemory,
    PageOwnMap,
    PageInit,
    PageTargetMap,
    Code,
    Rodata,
    DataMemory,
    DataOwnMap,
    DataCopy,
    DataUnmap,
    DataTargetMap,
    Thread,
    Start,
    Reply,
    Kill,
    Close,
    Terminal,
}

/// Each capability stays owned until its native effect or one cleanup step consumes it.
pub struct Resources<P, C, M, T> {
    pub process: Option<P>,
    pub start: Option<C>,
    pub exit: Option<C>,
    pub witness: Option<C>,
    pub copy: Option<P>,
    pub session: Option<C>,
    pub who: Option<C>,
    pub data: Option<M>,
    pub narrow: Option<M>,
    pub thread: Option<T>,
}
impl<P, C, M, T> Resources<P, C, M, T> {
    pub const fn new() -> Self {
        Self {
            process: None,
            start: None,
            exit: None,
            witness: None,
            copy: None,
            session: None,
            who: None,
            data: None,
            narrow: None,
            thread: None,
        }
    }
}
impl<P, C, M, T> Default for Resources<P, C, M, T> {
    fn default() -> Self {
        Self::new()
    }
}

pub enum Released<P, C, M, T> {
    Process(P),
    Channel(C),
    Memory(M),
    Thread(T),
}

pub struct StartPreparation<P, C, M, T, D> {
    key: Key,
    phase: Phase,
    error: Option<u32>,
    pub reservation: Option<Reservation>,
    pub pending: Option<D>,
    pub kind: Kind,
    pub origin: Origin,
    pub priority: u8,
    pub copy_cursor: u16,
    pub identity: [u32; 4],
    pub resources: Resources<P, C, M, T>,
}
impl<P, C, M, T, D> StartPreparation<P, C, M, T, D> {
    /// Admission has already prepaid the record and any required loader place.
    pub fn new(key: Key, kind: Kind, origin: Origin, priority: u8, pending: D) -> Self {
        Self {
            key,
            phase: Phase::Admission,
            error: None,
            reservation: None,
            pending: Some(pending),
            kind,
            origin,
            priority,
            copy_cursor: 0,
            identity: [0; 4],
            resources: Resources::new(),
        }
    }
    pub const fn key(&self) -> Key {
        self.key
    }
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    pub const fn error(&self) -> Option<u32> {
        self.error
    }

    /// A stale step or cleanup state has no authority to start a fresh effect.
    pub fn advance(&mut self, key: Key, expected: Phase) -> bool {
        if self.key != key || self.phase != expected {
            return false;
        }
        self.phase = match expected {
            Phase::Admission => Phase::Process,
            Phase::Process => Phase::PageMemory,
            Phase::PageMemory => Phase::PageOwnMap,
            Phase::PageOwnMap => Phase::PageInit,
            Phase::PageInit => Phase::PageTargetMap,
            Phase::PageTargetMap if matches!(self.kind, Kind::Initial { .. }) => Phase::Reply,
            Phase::PageTargetMap => Phase::Code,
            Phase::Code => Phase::Rodata,
            Phase::Rodata => Phase::DataMemory,
            Phase::DataMemory => Phase::DataOwnMap,
            Phase::DataOwnMap => Phase::DataCopy,
            Phase::DataCopy => Phase::DataUnmap,
            Phase::DataUnmap => Phase::DataTargetMap,
            Phase::DataTargetMap => Phase::Thread,
            Phase::Thread => Phase::Start,
            Phase::Start => Phase::Reply,
            Phase::Reply | Phase::Kill | Phase::Close | Phase::Terminal => return false,
        };
        true
    }

    /// The first failure remains resident across Kill errors and helper retries.
    pub fn cancel(&mut self, key: Key, error: u32, requires_stop: bool) -> bool {
        if self.key != key || self.phase == Phase::Terminal {
            return false;
        }
        if self.error.is_none() {
            self.error = Some(error);
            self.phase = if requires_stop {
                Phase::Kill
            } else {
                Phase::Close
            };
        }
        true
    }

    /// The caller supplies successful native Kill or exact terminal ProcessInfo evidence.
    pub fn stopped(&mut self, key: Key) -> bool {
        if self.key != key || self.phase != Phase::Kill {
            return false;
        }
        self.phase = Phase::Close;
        true
    }

    /// Reply and reservation ownership must have crossed their final cleanup boundary.
    pub fn finish_cleanup(&mut self, key: Key) -> bool {
        if self.key != key
            || self.phase != Phase::Close
            || self.pending.is_some()
            || self.reservation.is_some()
            || self.resources.process.is_some()
            || self.resources.start.is_some()
            || self.resources.exit.is_some()
            || self.resources.witness.is_some()
            || self.resources.copy.is_some()
            || self.resources.session.is_some()
            || self.resources.who.is_some()
            || self.resources.data.is_some()
            || self.resources.narrow.is_some()
            || self.resources.thread.is_some()
        {
            return false;
        }
        self.phase = Phase::Terminal;
        true
    }

    /// The caller closes at most this single returned capability outside the resident borrow.
    /// Its reply and reservation remain resident until the final native cleanup acknowledgement.
    pub fn cleanup_one(&mut self, key: Key) -> Option<Released<P, C, M, T>> {
        if self.key != key || self.phase != Phase::Close {
            return None;
        }
        if let Some(value) = self.resources.thread.take() {
            return Some(Released::Thread(value));
        }
        if let Some(value) = self.resources.narrow.take() {
            return Some(Released::Memory(value));
        }
        if let Some(value) = self.resources.data.take() {
            return Some(Released::Memory(value));
        }
        for slot in [
            &mut self.resources.who,
            &mut self.resources.session,
            &mut self.resources.witness,
            &mut self.resources.exit,
            &mut self.resources.start,
        ] {
            if let Some(value) = slot.take() {
                return Some(Released::Channel(value));
            }
        }
        if let Some(value) = self.resources.copy.take() {
            return Some(Released::Process(value));
        }
        if let Some(value) = self.resources.process.take() {
            return Some(Released::Process(value));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};
    struct Cap(Rc<Cell<u32>>);
    impl Drop for Cap {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    fn key() -> Key {
        Key {
            label: Label {
                index: 3,
                generation: 5,
            },
            image: 2,
        }
    }
    fn preparation() -> StartPreparation<Cap, Cap, Cap, Cap, u32> {
        StartPreparation::new(
            key(),
            Kind::Exec {
                mask: 3,
                replace_serial: u64::MAX,
            },
            Origin {
                parent: None,
                credentials_generation: 7,
            },
            31,
            42,
        )
    }
    #[test]
    fn stopped_target_and_every_capability_survive_kill_error_and_repeated_cancel() {
        let count = Rc::new(Cell::new(0));
        let cap = || Some(Cap(count.clone()));
        let mut work = preparation();
        work.resources = Resources {
            process: cap(),
            start: cap(),
            exit: cap(),
            witness: cap(),
            copy: cap(),
            session: cap(),
            who: cap(),
            data: cap(),
            narrow: cap(),
            thread: cap(),
        };
        assert!(work.cancel(key(), 5, true));
        assert!(work.cancel(key(), 12, false));
        assert_eq!(work.error(), Some(5));
        assert!(work.cleanup_one(key()).is_none());
        assert!(!work.advance(key(), Phase::Kill));
        assert_eq!(count.get(), 0);
        assert_eq!(work.pending, Some(42));
        assert!(work.stopped(key()));
        for expected in 1..=10 {
            drop(work.cleanup_one(key()).expect("one owned capability"));
            assert_eq!(count.get(), expected);
        }
        assert!(work.cleanup_one(key()).is_none());
        assert_eq!(work.pending, Some(42));
        assert!(!work.finish_cleanup(key()));
        work.pending = None;
        assert!(work.finish_cleanup(key()));
        assert!(!work.cancel(key(), 12, true));
        assert!(!work.stopped(key()));
    }
    #[test]
    fn each_effect_is_attempted_once_and_stale_keys_never_advance_cleanup_or_new_work() {
        let mut work = preparation();
        let mut stale = key();
        stale.image -= 1;
        assert!(!work.advance(stale, Phase::Admission));
        assert!(!work.cancel(stale, 5, true));
        assert!(work.advance(key(), Phase::Admission));
        assert!(!work.advance(key(), Phase::Admission));
        for phase in [
            Phase::Process,
            Phase::PageMemory,
            Phase::PageOwnMap,
            Phase::PageInit,
            Phase::PageTargetMap,
            Phase::Code,
            Phase::Rodata,
            Phase::DataMemory,
            Phase::DataOwnMap,
            Phase::DataCopy,
            Phase::DataUnmap,
            Phase::DataTargetMap,
            Phase::Thread,
            Phase::Start,
        ] {
            assert!(work.advance(key(), phase));
            assert!(!work.advance(key(), phase));
        }
        assert_eq!(work.phase(), Phase::Reply);
        assert!(!work.advance(key(), Phase::Reply));
        assert!(work.cancel(key(), 5, true));
        assert!(!work.stopped(stale));
        assert_eq!(work.phase(), Phase::Kill);
    }
}
