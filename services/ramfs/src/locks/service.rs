// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Permanent group custody joins actor record accounting to exact storage roots.

use super::actor::{Actor, Command, Error, GroupEvent, Progress, Request};
use super::{Owner, budget, groups::Id};
use crate::storage::{LockAnchor, Root, Storage, Token};
pub const GROUPS: usize = 512;
type Table = Actor<GROUPS, { crate::storage::NODES }, 256, 128, { crate::storage::ROOTS }, 256>;
struct PaidGroup {
    id: Id,
    root: LockAnchor,
}
pub struct LockService {
    actor: Table,
    groups: [Option<PaidGroup>; GROUPS],
    request_root: Option<LockAnchor>,
}
impl LockService {
    /// Initialize every field directly in permanent aligned storage.
    ///
    /// # Safety
    /// The destination exclusively owns aligned writable uninitialized Self storage.
    pub unsafe fn initialize_at(destination: *mut Self) {
        // SAFETY: all field destinations lie within the caller's exclusive allocation.
        unsafe {
            Table::initialize_at(core::ptr::addr_of_mut!((*destination).actor));
            let groups = core::ptr::addr_of_mut!((*destination).groups).cast::<Option<PaidGroup>>();
            for index in 0..GROUPS {
                groups.add(index).write(None);
            }
            core::ptr::addr_of_mut!((*destination).request_root).write(None);
        }
    }
    pub fn busy(&self) -> bool {
        self.actor.busy()
    }
    pub fn counts(&self) -> budget::Counts {
        self.actor.counts()
    }
    pub fn record_charge(&self, root: u16) -> Option<usize> {
        self.actor.record_charge(root)
    }
    pub fn group_charge(&self, root: u16) -> Option<usize> {
        self.actor.group_charge(root)
    }
    /// The authenticated caller supplies its complete payer after fd validation.
    pub fn start(
        &mut self,
        storage: &mut Storage<'_>,
        mut request: Request,
        root: Root,
    ) -> Result<(), Error> {
        if self.busy() {
            return Err(Error::Busy);
        }
        assert!(self.request_root.is_none());
        request.root = 0;
        self.actor.validate_request(request)?;
        let anchor = if matches!(request.command, Command::Set(Some(_))) {
            if root.generation == 0 {
                return Err(Error::Invalid);
            }
            Some(storage.lock_anchor(root).map_err(|_| Error::NoLocks)?)
        } else {
            None
        };
        if let Some(anchor) = &anchor {
            request.root = anchor.index();
        }
        if let Err(error) = self.actor.start(request) {
            if let Some(anchor) = anchor {
                storage
                    .release_lock_anchor(anchor)
                    .expect("unadmitted exact root");
            }
            return Err(error);
        }
        self.request_root = anchor;
        Ok(())
    }
    pub fn cancel(&mut self) -> bool {
        self.actor.cancel()
    }
    pub fn close(&mut self, inode: Token, owner: Owner) -> Result<(), Error> {
        self.actor.close(inode, owner)
    }
    pub fn depart_pid(&mut self, pid: u32) -> Result<(), Error> {
        self.actor.depart_pid(pid)
    }
    pub fn audit_pid(
        &mut self,
        index: usize,
        live: impl FnMut(u32) -> bool,
    ) -> Result<bool, Error> {
        self.actor.audit_pid(index, live)
    }
    pub fn step(&mut self, storage: &mut Storage<'_>, live: impl FnMut(u32) -> bool) -> Progress {
        let progress = self.actor.step_with_life(live);
        // Group custody is established before a terminal result drops request custody.
        match progress.group_event {
            Some(GroupEvent::Created { id, root }) => {
                let request = self
                    .request_root
                    .as_ref()
                    .expect("new group has a paid request");
                assert_eq!(request.index(), root);
                let slot = &mut self.groups[id.slot()];
                assert!(slot.is_none(), "previous full group lifetime released");
                *slot = Some(PaidGroup {
                    id,
                    root: storage
                        .retain_lock_anchor(request)
                        .expect("bounded group retention"),
                });
            }
            Some(GroupEvent::Released { id, root }) => {
                let group = self.groups[id.slot()].take().expect("paid group release");
                assert_eq!(group.id, id);
                assert_eq!(group.root.index(), root);
                storage
                    .release_lock_anchor(group.root)
                    .expect("exact group payer");
            }
            None => {}
        }
        if progress.completed.is_some()
            && let Some(anchor) = self.request_root.take()
        {
            storage
                .release_lock_anchor(anchor)
                .expect("completed request payer");
        }
        progress
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::locks::{Kind, Range, actor::Response};
    use std::boxed::Box;
    fn fresh() -> Box<LockService> {
        let mut allocation = Box::<LockService>::new_uninit();
        // SAFETY: the Box supplies exclusive aligned storage for the complete service.
        unsafe {
            LockService::initialize_at(allocation.as_mut_ptr());
            allocation.assume_init()
        }
    }
    fn root(id: u64, generation: u64) -> Root {
        Root { id, generation }
    }
    fn request(node: u16, pid: u32, command: Command, start: i64, len: i64) -> Request {
        Request {
            inode: Token {
                slot: node,
                generation: 1,
            },
            owner: Owner::Process(pid),
            root: u16::MAX,
            range: Range::relative(0, start, len).unwrap(),
            command,
        }
    }
    fn page() -> proto_process::lifetimes::Page {
        let page = proto_process::lifetimes::Page::new();
        for pid in 256..265 {
            page.publish(pid).unwrap();
        }
        page
    }
    fn check(service: &LockService) {
        let mut paid = 0;
        for root in 0..crate::storage::ROOTS as u16 {
            paid += service.record_charge(root).unwrap();
        }
        assert_eq!(paid, service.counts().paid());
        for group in service.groups.iter().flatten() {
            assert!(service.group_charge(group.root.index()).unwrap() > 0);
        }
    }
    fn drain(
        service: &mut LockService,
        storage: &mut Storage<'_>,
        page: &proto_process::lifetimes::Page,
    ) {
        for _ in 0..4000 {
            if !service.busy() {
                check(service);
                return;
            }
            let progress = service.step(storage, |pid| page.live(pid));
            assert!(progress.visited <= 8);
            assert!(progress.completed.is_none());
            check(service);
        }
        panic!("service debt did not finish");
    }
    fn run(
        service: &mut LockService,
        storage: &mut Storage<'_>,
        page: &proto_process::lifetimes::Page,
        request: Request,
        root: Root,
    ) -> Result<Response, Error> {
        service.start(storage, request, root)?;
        let mut result = None;
        for _ in 0..4000 {
            let progress = service.step(storage, |pid| page.live(pid));
            assert!(progress.visited <= 8);
            check(service);
            if let Some(done) = progress.completed {
                assert!(result.replace(done).is_none());
            }
            if !service.busy() {
                return result.expect("service terminal");
            }
        }
        panic!("service request did not finish");
    }
    #[test]
    fn own_dispatches_finish_a_stalled_client_and_reclaim_death_without_take() {
        use super::super::dispatch::{Dispatch, Work};
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let mut service = fresh();
        let page = page();
        let mut dispatch = Dispatch::default();
        service
            .start(
                &mut ram.storage,
                request(0, 256, Command::Set(Some(Kind::Write)), 0, 1),
                root(10, 1),
            )
            .unwrap();
        let mut completion = None;
        let mut legacy = 0;
        for _ in 0..512 {
            match dispatch.next(0, service.busy(), true) {
                Work::Actor => {
                    let progress = service.step(&mut ram.storage, |pid| page.live(pid));
                    assert!(progress.visited <= 8);
                    if let Some(done) = progress.completed {
                        assert!(completion.replace(done).is_none());
                    }
                    check(&service);
                }
                Work::Audit { first, end } => {
                    for index in first..end {
                        service.audit_pid(index, |pid| page.live(pid)).unwrap();
                    }
                }
                Work::Legacy => legacy += 1,
            }
            if !dispatch.pending(service.busy()) {
                break;
            }
        }
        assert_eq!(completion, Some(Ok(Response::Changed)));
        assert!(dispatch.audited());
        assert!(legacy > 0);
        assert_eq!(service.counts().published, 1);
        assert!(page.retire(256));
        for _ in 0..512 {
            match dispatch.next(250_000_000, service.busy(), true) {
                Work::Actor => {
                    let progress = service.step(&mut ram.storage, |pid| page.live(pid));
                    assert!(progress.visited <= 8);
                    assert!(progress.completed.is_none());
                    check(&service);
                }
                Work::Audit { first, end } => {
                    for index in first..end {
                        service.audit_pid(index, |pid| page.live(pid)).unwrap();
                    }
                }
                Work::Legacy => {}
            }
            if !dispatch.pending(service.busy()) {
                break;
            }
        }
        assert!(!service.busy());
        assert_eq!(service.counts().paid(), 0);
        assert!(service.groups.iter().all(Option::is_none));
        let replacement = ram.storage.lock_anchor(root(99, 1)).unwrap();
        assert_eq!(replacement.index(), 0);
        ram.storage.release_lock_anchor(replacement).unwrap();
    }
    #[test]
    fn service_layout_initializes_directly_and_preserves_accounted_size() {
        let service = fresh();
        let bytes = core::mem::size_of::<LockService>();
        std::println!(
            "LockService: {bytes} bytes, {} pages; PaidGroup {} bytes",
            bytes.div_ceil(4096),
            core::mem::size_of::<Option<PaidGroup>>()
        );
        assert_eq!(bytes, 868904);
        assert_eq!(core::mem::size_of::<Option<PaidGroup>>(), 40);
        assert!(!service.busy());
        assert!(service.request_root.is_none());
        assert!(service.groups.iter().all(Option::is_none));
        check(&service);
    }
    #[test]
    fn busy_and_invalid_requests_do_not_allocate_an_expenditure_root() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let mut service = fresh();
        let page = page();
        assert_eq!(
            service.start(
                &mut ram.storage,
                request(0, 0, Command::Set(Some(Kind::Write)), 0, 1),
                root(10, 1)
            ),
            Err(Error::Invalid)
        );
        assert_eq!(
            service.start(
                &mut ram.storage,
                request(0, 256, Command::Set(Some(Kind::Write)), 0, 1),
                root(10, 0)
            ),
            Err(Error::Invalid)
        );
        assert!(!service.busy());
        service
            .start(
                &mut ram.storage,
                request(0, 256, Command::Set(Some(Kind::Write)), 0, 1),
                root(10, 1),
            )
            .unwrap();
        assert_eq!(service.request_root.as_ref().unwrap().index(), 0);
        assert_eq!(
            service.start(
                &mut ram.storage,
                request(1, 257, Command::Set(Some(Kind::Read)), 0, 1),
                root(11, 1)
            ),
            Err(Error::Busy)
        );
        let peer = ram.storage.lock_anchor(root(12, 1)).unwrap();
        assert_eq!(peer.index(), 1);
        ram.storage.release_lock_anchor(peer).unwrap();
        service.cancel();
        let terminal = service.step(&mut ram.storage, |pid| page.live(pid));
        assert_eq!(terminal.completed, Some(Err(Error::Cancelled)));
        assert!(service.request_root.is_none());
        assert!(!service.busy());
        let peer = ram.storage.lock_anchor(root(12, 1)).unwrap();
        assert_eq!(peer.index(), 0);
        ram.storage.release_lock_anchor(peer).unwrap();
    }
    #[test]
    fn terminal_cancel_keeps_group_root_until_physical_debt_finishes() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let mut service = fresh();
        let page = page();
        service
            .start(
                &mut ram.storage,
                request(0, 256, Command::Set(Some(Kind::Write)), 0, 1),
                root(10, 1),
            )
            .unwrap();
        for _ in 0..100 {
            let progress = service.step(&mut ram.storage, |pid| page.live(pid));
            assert!(progress.completed.is_none());
            if service.counts().private > 0 {
                break;
            }
        }
        assert_eq!(service.counts().private, 1);
        service.cancel();
        let terminal = service.step(&mut ram.storage, |pid| page.live(pid));
        assert_eq!(terminal.completed, Some(Err(Error::Cancelled)));
        assert!(service.request_root.is_none());
        assert_eq!(service.groups.iter().flatten().count(), 1);
        let peer = ram.storage.lock_anchor(root(11, 1)).unwrap();
        assert_eq!(peer.index(), 1);
        ram.storage.release_lock_anchor(peer).unwrap();
        drain(&mut service, &mut ram.storage, &page);
        assert!(service.groups.iter().all(Option::is_none));
        let peer = ram.storage.lock_anchor(root(11, 1)).unwrap();
        assert_eq!(peer.index(), 0);
        ram.storage.release_lock_anchor(peer).unwrap();
    }
    #[test]
    fn changed_caller_root_keeps_group_original_payer_and_returns_request_root() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let mut service = fresh();
        let page = page();
        let first = root(11, 3);
        let later = root(11, 4);
        run(
            &mut service,
            &mut ram.storage,
            &page,
            request(0, 256, Command::Set(Some(Kind::Write)), 0, 1),
            first,
        )
        .unwrap();
        run(
            &mut service,
            &mut ram.storage,
            &page,
            request(0, 256, Command::Set(Some(Kind::Write)), 1, 1),
            later,
        )
        .unwrap();
        let group = service.groups.iter().flatten().next().unwrap();
        assert_eq!(group.root.root(), first);
        assert_eq!(group.root.index(), 0);
        assert_eq!(service.record_charge(0), Some(1));
        assert_eq!(service.record_charge(1), Some(0));
        let other = ram.storage.lock_anchor(later).unwrap();
        assert_eq!(other.index(), 1);
        ram.storage.release_lock_anchor(other).unwrap();
        service
            .close(
                Token {
                    slot: 0,
                    generation: 1,
                },
                Owner::Process(256),
            )
            .unwrap();
        drain(&mut service, &mut ram.storage, &page);
        let other = ram.storage.lock_anchor(later).unwrap();
        assert_eq!(other.index(), 0);
        ram.storage.release_lock_anchor(other).unwrap();
    }
    #[test]
    fn get_and_unlock_need_no_new_account_when_all_320_places_are_retained() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let mut service = fresh();
        let page = page();
        run(
            &mut service,
            &mut ram.storage,
            &page,
            request(0, 256, Command::Set(Some(Kind::Write)), 0, 1),
            root(11, 1),
        )
        .unwrap();
        let mut peers = std::vec::Vec::new();
        for id in 100..419 {
            peers.push(ram.storage.lock_anchor(root(id, 1)).unwrap());
        }
        assert_eq!(
            ram.storage.lock_anchor(root(999, 1)),
            Err(proto_fs::NO_SPACE)
        );
        let blocker = run(
            &mut service,
            &mut ram.storage,
            &page,
            request(0, 257, Command::Get(Kind::Read), 0, 1),
            root(999, 1),
        )
        .unwrap();
        assert!(matches!(blocker, Response::Blocker(Some(_))));
        assert_eq!(
            run(
                &mut service,
                &mut ram.storage,
                &page,
                request(0, 256, Command::Set(None), 0, 0),
                root(999, 1)
            ),
            Ok(Response::Changed)
        );
        assert_eq!(service.counts().paid(), 0);
        let replacement = ram.storage.lock_anchor(root(999, 1)).unwrap();
        assert_eq!(replacement.index(), 0);
        ram.storage.release_lock_anchor(replacement).unwrap();
        for peer in peers {
            ram.storage.release_lock_anchor(peer).unwrap();
        }
    }
    #[test]
    fn ninth_root_failure_establishes_group_custody_before_terminal() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let mut service = fresh();
        let page = page();
        for index in 0..8 {
            run(
                &mut service,
                &mut ram.storage,
                &page,
                request(
                    index,
                    256 + u32::from(index),
                    Command::Set(Some(Kind::Write)),
                    0,
                    1,
                ),
                root(10 + u64::from(index), 1),
            )
            .unwrap();
        }
        service
            .start(
                &mut ram.storage,
                request(8, 264, Command::Set(Some(Kind::Write)), 0, 1),
                root(99, 1),
            )
            .unwrap();
        let mut found = false;
        for _ in 0..100 {
            let progress = service.step(&mut ram.storage, |pid| page.live(pid));
            if let Some(result) = progress.completed {
                assert_eq!(result, Err(Error::NoLocks));
                let Some(GroupEvent::Created { id, root: 8 }) = progress.group_event else {
                    panic!("failed new group custody")
                };
                assert_eq!(
                    service.groups[id.slot()].as_ref().unwrap().root.root(),
                    root(99, 1)
                );
                found = true;
                break;
            }
        }
        assert!(found);
        assert!(service.request_root.is_none());
        let peer = ram.storage.lock_anchor(root(100, 1)).unwrap();
        assert_eq!(peer.index(), 9);
        ram.storage.release_lock_anchor(peer).unwrap();
        drain(&mut service, &mut ram.storage, &page);
        let peer = ram.storage.lock_anchor(root(100, 1)).unwrap();
        assert_eq!(peer.index(), 8);
        ram.storage.release_lock_anchor(peer).unwrap();
        assert_eq!(service.groups.iter().flatten().count(), 8);
        assert_eq!(service.counts().published, 8);
    }
    #[test]
    fn idle_death_observation_releases_exact_root_without_a_client() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let mut service = fresh();
        let page = page();
        run(
            &mut service,
            &mut ram.storage,
            &page,
            request(0, 256, Command::Set(Some(Kind::Write)), 0, 1),
            root(11, 1),
        )
        .unwrap();
        page.retire(256);
        assert_eq!(service.audit_pid(0, |pid| page.live(pid)), Ok(true));
        assert_eq!(service.group_charge(0), Some(1));
        drain(&mut service, &mut ram.storage, &page);
        assert!(service.groups.iter().all(Option::is_none));
        let other = ram.storage.lock_anchor(root(11, 2)).unwrap();
        assert_eq!(other.index(), 0);
        ram.storage.release_lock_anchor(other).unwrap();
    }
}
