// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Capability ownership accompanies one exact loader attempt and its committed image.
use crate::loaders::{LOADERS, Loaders, Stage};
use proto_process::{ExecKind, NO_ID, StageExec, StageReceipt};

pub struct ExecCustody<C> {
    pub pending_exec: Option<C>,
    pub fork_source: Option<C>,
    pub receipt: Option<StageReceipt>,
}
impl<C> Default for ExecCustody<C> {
    fn default() -> Self {
        Self::new()
    }
}
impl<C> ExecCustody<C> {
    pub const fn new() -> Self {
        Self {
            pending_exec: None,
            fork_source: None,
            receipt: None,
        }
    }
}
/// Resident custody of an old image until the kernel confirms that it cannot run.
pub struct RetiredExec<P, C> {
    pub process: P,
    pub executable: Option<C>,
    ceiling: u8,
    stopped: bool,
    cleanup_requested: bool,
}
impl<P, C> RetiredExec<P, C> {
    pub fn new(process: P, executable: Option<C>, ceiling: u8) -> Self {
        Self {
            process,
            executable,
            ceiling,
            stopped: false,
            cleanup_requested: false,
        }
    }
    /// Init handoff acknowledgement or direct replacement authorizes cleanup once.
    pub fn request_cleanup(&mut self) -> bool {
        let first = !self.cleanup_requested;
        self.cleanup_requested = true;
        first
    }
    pub fn cleanup_requested(&self) -> bool {
        self.cleanup_requested
    }
    /// An offered replacement keeps its resident offer until handoff acknowledgement.
    /// A failed Kill preserves both capabilities for the next bounded retry.
    pub fn try_stop<E>(
        &mut self,
        base: u8,
        kill: impl FnOnce(&P, u8) -> Result<(), E>,
    ) -> Result<bool, E> {
        if !self.cleanup_requested {
            return Ok(false);
        }
        if !self.stopped {
            kill(&self.process, self.ceiling.min(base))?;
            self.stopped = true;
        }
        Ok(true)
    }
    /// An exact native Exit independently confirms the old image's end.
    pub fn ended(&mut self) {
        self.stopped = true;
    }
}

pub trait ExecHolder {
    type Cap;
    fn exec_custody(&mut self) -> &mut ExecCustody<Self::Cap>;
    fn fork(&self) -> bool;
}
/// The caller closes a replay transfer outside the borrowed loader place.
pub enum Staged<C> {
    Installed,
    Replay(C),
}
/// Refusal preserves the incoming capability for explicit caller cleanup.
pub struct Refused<C>(pub C);

impl<T: ExecHolder> Loaders<T> {
    /// The native handler validates genuine notary, PID and transferred object first.
    /// All tuple and replay checks precede the atomic capability/credentials mutation.
    pub fn stage_exec(
        &mut self,
        record: usize,
        args: StageExec,
        cap: T::Cap,
    ) -> Result<Staged<T::Cap>, Refused<T::Cap>> {
        let index = (args.ticket & 0xff) as usize;
        if index >= LOADERS || self.ticket(index) != args.ticket {
            return Err(Refused(cap));
        }
        let Some(place) = self.get_mut(index) else {
            return Err(Refused(cap));
        };
        if place.record != record
            || place.image != args.image
            || matches!(
                place.stage,
                Stage::Preparing | Stage::Booting | Stage::Aborting
            )
            || place.held.fork() != (args.kind == ExecKind::Fork)
        {
            return Err(Refused(cap));
        }
        let exec = place.held.exec_custody();
        if let Some(receipt) = exec.receipt {
            return if receipt == args.receipt() {
                Ok(Staged::Replay(cap))
            } else {
                Err(Refused(cap))
            };
        }
        if place.stage != Stage::Loading
            || place.set_id.is_some()
            || exec.pending_exec.is_some()
            || args.label == 0
            || args.kind == ExecKind::Fork
                && (args.uid != NO_ID || args.gid != NO_ID || exec.fork_source.is_none())
        {
            return Err(Refused(cap));
        }
        exec.pending_exec = Some(cap);
        exec.receipt = Some(args.receipt());
        if args.kind == ExecKind::Execute {
            place.set_id = Some((args.uid, args.gid));
        }
        Ok(Staged::Installed)
    }

    /// A successful Commit transfers the prepaid cap while retaining replay arguments.
    pub fn take_pending_exec(&mut self, record: usize) -> Option<T::Cap> {
        let index = self.of(record)?;
        let place = self.get_mut(index)?;
        if place.stage != Stage::Ready {
            return None;
        }
        place.held.exec_custody().pending_exec.take()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::records::{Join, Records, State};
    use proto_process::{Credentials, End};
    use std::{cell::RefCell, rc::Rc, vec::Vec};
    struct Cap {
        id: u32,
        root: (u32, u32),
        dropped: Rc<RefCell<Vec<u32>>>,
    }
    impl Drop for Cap {
        fn drop(&mut self) {
            self.dropped.borrow_mut().push(self.id);
        }
    }
    struct Held {
        exec: ExecCustody<Cap>,
        fork: bool,
    }
    impl ExecHolder for Held {
        type Cap = Cap;
        fn exec_custody(&mut self) -> &mut ExecCustody<Cap> {
            &mut self.exec
        }
        fn fork(&self) -> bool {
            self.fork
        }
    }
    fn cap(id: u32, log: &Rc<RefCell<Vec<u32>>>) -> Cap {
        Cap {
            id,
            root: (257, 7),
            dropped: log.clone(),
        }
    }
    fn loading(t: &mut Loaders<Held>, record: usize, fork: bool, source: Option<Cap>) -> StageExec {
        let mut exec = ExecCustody::new();
        exec.fork_source = source;
        let slot = t.take(record, record, 2, Held { exec, fork }).unwrap();
        t.get_mut(slot).unwrap().stage = Stage::Loading;
        StageExec {
            pid: record as u32 + 256,
            image: 2,
            ticket: t.ticket(slot),
            uid: NO_ID,
            gid: NO_ID,
            kind: if fork {
                ExecKind::Fork
            } else {
                ExecKind::Execute
            },
            label: record as u64 + 1,
        }
    }
    fn stage(t: &mut Loaders<Held>, record: usize, args: StageExec, cap: Cap) {
        assert!(matches!(
            t.stage_exec(record, args, cap),
            Ok(Staged::Installed)
        ));
    }
    fn record(t: &mut Records<u32, Cap>, parent: Option<usize>) -> usize {
        t.insert(
            t.next_label().unwrap(),
            1,
            parent,
            Credentials::ROOT,
            31,
            Join::Inherit,
        )
    }
    #[test]
    fn immutable_replay_survives_ready_commit_cap_transfer_and_take() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut t = Loaders::new();
        let mut args = loading(&mut t, 5, false, None);
        args.uid = 37;
        stage(&mut t, 5, args, cap(1, &log));
        for ready in 0..3 {
            if ready == 1 {
                t.loaded(5).unwrap();
            }
            if ready == 2 {
                assert_eq!(t.commit(5), Ok(Some((37, NO_ID))));
            }
            match t.stage_exec(5, args, cap(ready + 2, &log)) {
                Ok(Staged::Replay(extra)) => drop(extra),
                _ => panic!("exact replay"),
            }
            assert!(
                t.get(t.of(5).unwrap())
                    .unwrap()
                    .held
                    .exec
                    .pending_exec
                    .is_some()
            );
        }
        let active = t.take_pending_exec(5).unwrap();
        assert_eq!(active.id, 1);
        assert!(t.take_pending_exec(5).is_none());
        match t.stage_exec(5, args, cap(5, &log)) {
            Ok(Staged::Replay(extra)) => drop(extra),
            _ => panic!("committed replay"),
        }
        t.free(5).unwrap();
        assert!(!log.borrow().contains(&1));
        let Err(Refused(extra)) = t.stage_exec(5, args, cap(6, &log)) else {
            panic!("retired ticket")
        };
        drop(extra);
        drop(active);
        assert!(log.borrow().contains(&1));
    }
    #[test]
    fn stale_tuple_and_changed_assertions_preserve_both_pending_credentials_and_cap() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut t = Loaders::new();
        let mut args = loading(&mut t, 5, false, None);
        args.uid = 37;
        args.gid = 43;
        stage(&mut t, 5, args, cap(1, &log));
        let mut changes = [args; 5];
        changes[0].ticket += 256;
        changes[1].image += 1;
        changes[2].uid += 1;
        changes[3].gid += 1;
        changes[4].label += 1;
        for changed in changes {
            let Err(Refused(extra)) = t.stage_exec(5, changed, cap(2, &log)) else {
                panic!("changed args")
            };
            drop(extra);
        }
        let Err(Refused(extra)) = t.stage_exec(6, args, cap(3, &log)) else {
            panic!("changed record")
        };
        drop(extra);
        let p = t.get(t.of(5).unwrap()).unwrap();
        assert_eq!(p.set_id, Some((37, 43)));
        assert_eq!(p.held.exec.pending_exec.as_ref().unwrap().id, 1);
        t.free(5).unwrap();
        assert_eq!(log.borrow().iter().filter(|&&id| id == 1).count(), 1);
    }
    #[test]
    fn failed_exec_drops_pending_and_success_replaces_active_until_native_end_before_wait() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut records = Records::<u32, Cap>::with_exec_custody();
        let parent = record(&mut records, None);
        records.get_mut(parent).unwrap().state = State::Alive;
        let child = record(&mut records, Some(parent));
        records.get_mut(child).unwrap().state = State::Alive;
        records.replace_active_exec(child, Some(cap(1, &log)));
        let mut t = Loaders::new();
        let args = loading(&mut t, child, false, None);
        stage(&mut t, child, args, cap(2, &log));
        t.free(child).unwrap();
        assert!(!log.borrow().contains(&1));
        assert!(log.borrow().contains(&2));
        let args = loading(&mut t, child, false, None);
        stage(&mut t, child, args, cap(3, &log));
        t.loaded(child).unwrap();
        t.commit(child).unwrap();
        let old = records.replace_active_exec(child, t.take_pending_exec(child));
        assert!(!log.borrow().contains(&1));
        drop(old);
        assert!(log.borrow().contains(&1));
        t.free(child).unwrap();
        assert!(!log.borrow().contains(&3));
        records.exited(child, End::Exited(7));
        assert!(matches!(
            records.get(child).unwrap().state,
            State::Zombie(_)
        ));
        assert!(records.get(child).unwrap().active_exec.is_none());
        assert_eq!(log.borrow().iter().filter(|&&id| id == 3).count(), 1);
        records.reap(child).unwrap();
        assert_eq!(log.borrow().iter().filter(|&&id| id == 3).count(), 1);
    }
    #[test]
    fn fork_retains_origin_after_parent_end_and_requires_distinct_child_custody() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut records = Records::<u32, Cap>::with_exec_custody();
        let parent = record(&mut records, None);
        records.get_mut(parent).unwrap().state = State::Alive;
        records.replace_active_exec(parent, Some(cap(1, &log)));
        let mut t = Loaders::new();
        let args = loading(&mut t, 5, true, Some(cap(2, &log)));
        records.exited(parent, End::Exited(0));
        assert!(log.borrow().contains(&1));
        assert!(!log.borrow().contains(&2));
        stage(&mut t, 5, args, cap(3, &log));
        t.loaded(5).unwrap();
        assert_eq!(t.commit(5), Ok(None));
        let active = t.take_pending_exec(5).unwrap();
        assert_eq!(active.root, (257, 7));
        t.free(5).unwrap();
        assert!(log.borrow().contains(&2));
        assert!(!log.borrow().contains(&3));
        drop(active);
        let args = loading(&mut t, 6, true, None);
        let Err(Refused(extra)) = t.stage_exec(6, args, cap(4, &log)) else {
            panic!("missing source")
        };
        drop(extra);
        assert!(
            t.get(t.of(6).unwrap())
                .unwrap()
                .held
                .exec
                .pending_exec
                .is_none()
        );
    }
    #[test]
    fn old_image_kill_error_keeps_cap_until_retry_and_exit_confirmation() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut old = RetiredExec::new(cap(1, &log), Some(cap(2, &log)), 31);
        assert!(old.request_cleanup());
        assert_eq!(
            old.try_stop(5, |process, level| {
                assert_eq!((process.id, level), (1, 5));
                Err(9)
            }),
            Err(9)
        );
        assert!(log.borrow().is_empty());
        assert_eq!(old.executable.as_ref().unwrap().id, 2);
        assert_eq!(
            old.try_stop(3, |process, level| {
                assert_eq!((process.id, level), (1, 3));
                Ok::<(), u32>(())
            }),
            Ok(true)
        );
        old.try_stop(31, |_, _| -> Result<(), u32> { panic!("stopped image") })
            .unwrap();
        assert!(log.borrow().is_empty());
        drop(old);
        assert_eq!(&*log.borrow(), &[1, 2]);
        let mut ended = RetiredExec::new(cap(3, &log), Some(cap(4, &log)), 2);
        ended.ended();
        assert!(ended.request_cleanup());
        ended
            .try_stop(31, |_, _| -> Result<(), u32> {
                panic!("exact ended image")
            })
            .unwrap();
        drop(ended);
        assert_eq!(&*log.borrow(), &[1, 2, 3, 4]);
    }

    #[test]
    fn abort_error_keeps_exact_place_and_refuses_late_effect_until_once_free() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut t = Loaders::new();
        let args = loading(&mut t, 5, false, None);
        stage(&mut t, 5, args, cap(1, &log));
        assert_eq!(t.begin_abort(5), Ok(true));
        // A failed Kill leaves the production Aborting place resident.
        assert_eq!(t.begin_abort(5), Ok(false));
        assert_eq!(t.ticket(t.of(5).unwrap()), args.ticket);
        assert!(t.vouches(5).is_none());
        assert!(t.retained(5, args.image, args.ticket, 1, 0, true).is_none());
        assert!(t.set_id(args.ticket, 5, 2, (37, 43)).is_err());
        assert!(t.loaded(5).is_err());
        assert!(t.commit(5).is_err());
        let Err(Refused(extra)) = t.stage_exec(5, args, cap(2, &log)) else {
            panic!("aborting replay")
        };
        drop(extra);
        assert!(!log.borrow().contains(&1));
        assert!(t.take_pending_exec(5).is_none());
        // Confirmed stop permits the existing free path exactly once.
        drop(t.free(5).unwrap());
        assert!(t.free(5).is_none());
        assert_eq!(log.borrow().iter().filter(|&&id| id == 1).count(), 1);
        let newer = loading(&mut t, 5, false, None);
        assert_ne!(args.ticket, newer.ticket);
        let Err(Refused(extra)) = t.stage_exec(5, args, cap(3, &log)) else {
            panic!("stale attempt")
        };
        drop(extra);
        assert!(t.get(t.of(5).unwrap()).unwrap().held.exec.receipt.is_none());
    }

    #[test]
    fn all_sixteen_paid_places_keep_custody_and_capacity_after_repeated_abort() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut t = Loaders::new();
        for record in 0..LOADERS {
            let args = loading(&mut t, record, false, None);
            stage(&mut t, record, args, cap(record as u32, &log));
        }
        assert!(!t.room());
        let held = Held {
            exec: ExecCustody::new(),
            fork: false,
        };
        assert!(t.take(20, 20, 2, held).is_none());
        for record in 0..LOADERS {
            assert_eq!(t.begin_abort(record), Ok(true));
            assert_eq!(t.begin_abort(record), Ok(false));
        }
        assert!(!t.room());
        assert!(log.borrow().is_empty());
        for record in 0..LOADERS {
            drop(t.free(record).unwrap());
            assert!(t.free(record).is_none());
        }
        assert!(t.room());
        for id in 0..LOADERS as u32 {
            assert_eq!(log.borrow().iter().filter(|&&v| v == id).count(), 1);
        }
    }

    #[test]
    fn legacy_set_id_and_unready_pending_transfer_preserve_first_authority() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut t = Loaders::new();
        let args = loading(&mut t, 5, false, None);
        t.set_id(args.ticket, 5, 2, (37, 43)).unwrap();
        let Err(Refused(extra)) = t.stage_exec(5, args, cap(1, &log)) else {
            panic!("legacy authority")
        };
        drop(extra);
        assert_eq!(t.get(t.of(5).unwrap()).unwrap().set_id, Some((37, 43)));
        drop(t.free(5));
        let args = loading(&mut t, 5, false, None);
        stage(&mut t, 5, args, cap(2, &log));
        assert!(t.take_pending_exec(5).is_none());
        t.loaded(5).unwrap();
        assert!(t.take_pending_exec(5).is_none());
        t.commit(5).unwrap();
        assert_eq!(t.begin_abort(5), Err(crate::loaders::Refused));
        let active = t.take_pending_exec(5).unwrap();
        drop(t.free(5));
        assert!(!log.borrow().contains(&2));
        drop(active);
    }
    #[test]
    fn old_end_before_init_handoff_preserves_offer_and_completion() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut old = RetiredExec::new(cap(1, &log), Some(cap(2, &log)), 31);
        let offer = cap(3, &log);
        let ready = cap(4, &log);
        let pending = cap(5, &log);
        let mut cleanup_count = 0_u32;
        old.ended();
        assert!(!old.cleanup_requested());
        assert_eq!(cleanup_count, 0);
        assert_eq!(
            old.try_stop(1, |_, _| -> Result<(), u32> { panic!("no handoff") }),
            Ok(false)
        );
        assert!(log.borrow().is_empty());
        // Genuine Init handoff transfers the offered new process before cleanup.
        drop(offer);
        if old.request_cleanup() {
            cleanup_count += 1;
        }
        assert!(!old.request_cleanup());
        assert_eq!(cleanup_count, 1);
        assert_eq!(
            old.try_stop(1, |_, _| -> Result<(), u32> { panic!("old ended") }),
            Ok(true)
        );
        cleanup_count -= 1;
        drop((old, ready, pending));
        assert_eq!(cleanup_count, 0);
        assert_eq!(&*log.borrow(), &[3, 1, 2, 4, 5]);
    }

    #[test]
    fn old_end_after_init_handoff_allows_existing_cleanup_debt_to_finish() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut old = RetiredExec::new(cap(1, &log), Some(cap(2, &log)), 31);
        assert!(old.request_cleanup());
        assert_eq!(old.try_stop(1, |_, _| Err(7)), Err(7));
        assert!(log.borrow().is_empty());
        old.ended();
        assert_eq!(
            old.try_stop(1, |_, _| -> Result<(), u32> { panic!("exact native End") }),
            Ok(true)
        );
        drop(old);
        assert_eq!(&*log.borrow(), &[1, 2]);
    }
}
