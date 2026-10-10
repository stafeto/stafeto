// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Permanent group custody joins actor record accounting to exact storage roots.

use super::actor::{Actor, Command, Error, GroupEvent, Progress, Request};
use super::{Owner, budget, groups::Id};
use crate::storage::{LockAnchor, Pin, Root, Storage, Token};
pub const GROUPS: usize = 512;
type Table = Actor<GROUPS, { crate::storage::NODES }, 256, 128, { crate::storage::ROOTS }, 256>;
struct PaidGroup {
    id: Id,
    root: LockAnchor,
    inode: Token,
}
pub struct LockService {
    actor: Table,
    groups: [Option<PaidGroup>; GROUPS],
    request_root: Option<LockAnchor>,
    request_inode: Option<Token>,
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
            core::ptr::addr_of_mut!((*destination).request_inode).write(None);
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
        assert!(self.request_inode.is_none());
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
        if storage.pin(request.inode, Pin::Lock).is_err() {
            if let Some(anchor) = anchor {
                storage
                    .release_lock_anchor(anchor)
                    .expect("unstarted exact root");
            }
            return Err(Error::Invalid);
        }
        if let Err(error) = self.actor.start(request) {
            storage
                .unpin(request.inode, Pin::Lock)
                .expect("unadmitted exact inode");
            if let Some(anchor) = anchor {
                storage
                    .release_lock_anchor(anchor)
                    .expect("unadmitted exact root");
            }
            return Err(error);
        }
        self.request_root = anchor;
        self.request_inode = Some(request.inode);
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
    pub fn audit_description(
        &mut self,
        index: usize,
        live: impl FnMut(Token) -> bool,
    ) -> Result<bool, Error> {
        self.actor.audit_description(index, live)
    }
    #[cfg(test)]
    pub fn step(&mut self, storage: &mut Storage<'_>, live: impl FnMut(u32) -> bool) -> Progress {
        self.step_with_owners(storage, live, |_| true)
    }
    pub fn step_with_owners(
        &mut self,
        storage: &mut Storage<'_>,
        live: impl FnMut(u32) -> bool,
        ofd_live: impl FnMut(Token) -> bool,
    ) -> Progress {
        let progress = self.actor.step_with_owners(live, ofd_live);
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
                let inode = self.request_inode.expect("new group has an exact inode");
                storage
                    .pin(inode, Pin::Lock)
                    .expect("bounded exact group inode");
                *slot = Some(PaidGroup {
                    id,
                    root: storage
                        .retain_lock_anchor(request)
                        .expect("bounded group retention"),
                    inode,
                });
            }
            Some(GroupEvent::Released { id, root }) => {
                let group = self.groups[id.slot()].take().expect("paid group release");
                assert_eq!(group.id, id);
                assert_eq!(group.root.index(), root);
                storage
                    .unpin(group.inode, Pin::Lock)
                    .expect("exact group inode");
                storage
                    .release_lock_anchor(group.root)
                    .expect("exact group payer");
            }
            None => {}
        }
        if progress.completed.is_some() {
            let inode = self.request_inode.take().expect("completed request inode");
            storage
                .unpin(inode, Pin::Lock)
                .expect("completed exact inode");
            if let Some(anchor) = self.request_root.take() {
                storage
                    .release_lock_anchor(anchor)
                    .expect("completed request payer");
            }
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
    fn request(inode: Token, pid: u32, command: Command, start: i64, len: i64) -> Request {
        Request {
            inode,
            owner: Owner::Process(pid),
            root: u16::MAX,
            range: Range::relative(0, start, len).unwrap(),
            command,
        }
    }
    fn fixture() -> (crate::Ram<'static>, [Token; 9]) {
        let paths: std::vec::Vec<_> = (0..9).map(|i| std::format!("/lock{i}")).collect();
        let entries: std::vec::Vec<_> = paths
            .iter()
            .enumerate()
            .map(|(i, path)| bootimg::rootfs::Entry {
                path,
                mode: bootimg::rootfs::REGULAR | 0o600,
                uid: 0,
                gid: 0,
                file: (i + 1) as u32,
            })
            .collect();
        let table = bootimg::rootfs::write::rootfs(&entries, 11).unwrap();
        let mut files = std::vec![("init", &b"init"[..])];
        for path in &paths {
            files.push((path.as_str(), &b"x"[..]));
        }
        files.push(("rootfs", &table));
        let bytes = Box::leak(bootimg::write::image(&files).unwrap().into_boxed_slice());
        let index = Box::leak(Box::new(crate::tree::Index::new()));
        let tree = crate::tree::load(bytes, index).unwrap();
        let ram = crate::Ram::with_tree(proto_fs::Timestamp::ZERO, tree);
        let inodes = core::array::from_fn(|i| ram.storage.resolve(paths[i].as_bytes()).unwrap());
        (ram, inodes)
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
    fn check_pins(service: &LockService, storage: &Storage<'_>) {
        let mut expected = [0u16; crate::storage::NODES];
        for group in service.groups.iter().flatten() {
            storage
                .node(group.inode)
                .expect("retained exact group inode");
            expected[group.inode.slot as usize] += 1;
        }
        if let Some(inode) = service.request_inode {
            storage.node(inode).expect("retained exact worker inode");
            expected[inode.slot as usize] += 1;
        }
        for (node, expected) in storage.state.nodes.iter().zip(expected) {
            assert_eq!(node.pins[Pin::Lock as usize], expected);
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
                check_pins(service, storage);
                return;
            }
            let progress = service.step(storage, |pid| page.live(pid));
            assert!(progress.visited <= 8);
            assert!(progress.completed.is_none());
            check(service);
            check_pins(service, storage);
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
        check_pins(service, storage);
        let mut result = None;
        for _ in 0..4000 {
            let progress = service.step(storage, |pid| page.live(pid));
            assert!(progress.visited <= 8);
            check(service);
            check_pins(service, storage);
            if let Some(done) = progress.completed {
                assert!(result.replace(done).is_none());
            }
            if !service.busy() {
                return result.expect("service terminal");
            }
        }
        panic!("service request did not finish");
    }
    fn real_step(
        service: &mut LockService,
        ram: &mut crate::Ram<'_>,
        page: Option<&proto_process::lifetimes::Page>,
    ) -> Progress {
        let (storage, descriptions) = ram.lock_parts();
        service.step_with_owners(
            storage,
            |pid| page.is_some_and(|page| page.live(pid)),
            |token| descriptions.live(token),
        )
    }
    fn real_run(
        service: &mut LockService,
        ram: &mut crate::Ram<'_>,
        page: Option<&proto_process::lifetimes::Page>,
        request: Request,
        payer: Root,
    ) -> Result<Response, Error> {
        for _ in 0..4000 {
            if !service.busy() {
                break;
            }
            let progress = real_step(service, ram, page);
            assert!(progress.visited <= 8);
            assert!(progress.completed.is_none());
            check_pins(service, &ram.storage);
        }
        assert!(
            !service.busy(),
            "previous close debt drains before admission"
        );
        service.start(&mut ram.storage, request, payer)?;
        let mut response = None;
        for _ in 0..4000 {
            let progress = real_step(service, ram, page);
            assert!(progress.visited <= 8);
            check_pins(service, &ram.storage);
            if let Some(done) = progress.completed {
                assert!(response.replace(done).is_none());
            }
            if !service.busy() {
                return response.expect("completed real owner request");
            }
        }
        panic!("real owner work did not finish");
    }
    fn owned(mut request: Request, description: Token) -> Request {
        request.owner = Owner::Description {
            slot: description.slot,
            generation: description.generation,
        };
        request
    }
    fn close_blocker(
        service: &mut LockService,
        ram: &mut crate::Ram<'_>,
        page: &proto_process::lifetimes::Page,
        inode: Token,
        start: i64,
    ) -> Option<Owner> {
        match real_run(
            service,
            ram,
            Some(page),
            request(inode, 259, Command::Get(Kind::Write), start, 1),
            root(999, 1),
        )
        .unwrap()
        {
            Response::Blocker(blocker) => blocker.map(|lock| lock.owner),
            Response::Changed => panic!("GET result"),
        }
    }
    fn close_who(pid: u32) -> proto_process::WhoReply {
        proto_process::WhoReply {
            pid,
            credentials: proto_process::Credentials::NOBODY,
            generation: 1,
            loader: None,
            index: pid & 255,
            ctty: None,
            image: 1,
            groups: proto_process::Groups::EMPTY,
            limits: proto_process::ResourceLimits::initial(2 * 1024 * 1024),
            root: proto_process::ExpenditureRoot {
                pid: 10,
                generation: 1,
            },
        }
    }
    fn close_event(
        ram: &crate::Ram<'_>,
        fds: &crate::Fds,
        fd: u32,
        slot: u32,
        generation: u64,
        last_alias: bool,
    ) -> proto_fs::CloseEvent {
        let description = ram.capture_description(fds, fd).unwrap().0.description;
        proto_fs::CloseEvent {
            key: proto_fs::CloseKey { slot, generation },
            packed: fd | u32::from(description.slot) << proto_fs::OPEN_DESCRIPTION_SHIFT,
            description_generation: description.generation,
            last_alias,
        }
    }
    #[test]
    fn numeric_alias_close_revokes_only_that_inode_pid_and_replay_preserves_new_locks() {
        let (mut ram, inodes) = fixture();
        let mut service = fresh();
        let page = page();
        let payer = root(10, 1);
        let mut fds = crate::Fds {
            root: payer,
            binding: crate::authority::Binding::Active(close_who(257)),
            ..crate::Fds::default()
        };
        let fd = ram.open(&mut fds, "/lock0", proto_fs::READ_ONLY).unwrap();
        let description = ram.capture_description(&fds, fd).unwrap().0.description;
        for start in [0, 6] {
            real_run(
                &mut service,
                &mut ram,
                Some(&page),
                request(inodes[0], 257, Command::Set(Some(Kind::Read)), start, 1),
                payer,
            )
            .unwrap();
        }
        for r in [
            owned(
                request(inodes[0], 257, Command::Set(Some(Kind::Read)), 2, 1),
                description,
            ),
            request(inodes[0], 258, Command::Set(Some(Kind::Read)), 4, 1),
            request(inodes[1], 257, Command::Set(Some(Kind::Read)), 0, 1),
        ] {
            real_run(&mut service, &mut ram, Some(&page), r, payer).unwrap();
        }
        let event = close_event(&ram, &fds, fd, 48, 1, false);
        ram.close_event(&mut fds, &mut service, event).unwrap();
        assert_eq!(
            close_blocker(&mut service, &mut ram, &page, inodes[0], 0),
            None
        );
        assert_eq!(
            close_blocker(&mut service, &mut ram, &page, inodes[1], 0),
            Some(Owner::Process(257))
        );
        assert_eq!(
            close_blocker(&mut service, &mut ram, &page, inodes[0], 4),
            Some(Owner::Process(258))
        );
        assert_eq!(
            close_blocker(&mut service, &mut ram, &page, inodes[0], 2),
            Some(Owner::Description {
                slot: description.slot,
                generation: description.generation
            })
        );
        assert!(
            ram.live_description(&fds, ram.capture_description(&fds, fd).unwrap().0)
                .is_ok()
        );
        assert_eq!(ram.read(&mut fds, fd, &mut [0; 1]), Ok(1));
        real_run(
            &mut service,
            &mut ram,
            Some(&page),
            request(inodes[0], 257, Command::Set(Some(Kind::Read)), 0, 1),
            payer,
        )
        .unwrap();
        ram.close_event(&mut fds, &mut service, event).unwrap();
        assert_eq!(
            close_blocker(&mut service, &mut ram, &page, inodes[0], 0),
            Some(Owner::Process(257))
        );
    }
    #[test]
    fn inherited_last_fd_close_preserves_parent_pid_and_excludes_ofd_before_physical_io() {
        let (mut ram, inodes) = fixture();
        let mut service = fresh();
        let page = page();
        let payer = root(10, 1);
        let who = close_who(257);
        let mut parent = crate::Fds {
            root: payer,
            binding: crate::authority::Binding::Active(who),
            ..crate::Fds::default()
        };
        let fd = ram
            .open(&mut parent, "/lock0", proto_fs::READ_ONLY)
            .unwrap();
        let held = ram.capture_description(&parent, fd).unwrap().0;
        let mut child = ram.clone_fds(&parent, &[fd]).unwrap();
        child.binding = crate::authority::Binding::Inherited(who);
        real_run(
            &mut service,
            &mut ram,
            Some(&page),
            owned(
                request(inodes[0], 257, Command::Set(Some(Kind::Read)), 2, 1),
                held.description,
            ),
            payer,
        )
        .unwrap();
        let event = close_event(&ram, &parent, fd, 48, 1, true);
        ram.close_event(&mut parent, &mut service, event).unwrap();
        assert!(ram.lock_parts().1.live(held.description));
        let next = ram
            .open(&mut parent, "/lock0", proto_fs::READ_ONLY)
            .unwrap();
        real_run(
            &mut service,
            &mut ram,
            Some(&page),
            request(inodes[0], 257, Command::Set(Some(Kind::Read)), 0, 1),
            payer,
        )
        .unwrap();
        let event = close_event(&ram, &child, fd, 48, 1, true);
        ram.close_event(&mut child, &mut service, event).unwrap();
        assert_eq!(
            service.counts().published,
            1,
            "OFD revocation precedes the reply and audit"
        );
        assert!(!ram.lock_parts().1.live(held.description));
        assert_eq!(
            close_blocker(&mut service, &mut ram, &page, inodes[0], 0),
            Some(Owner::Process(257))
        );
        assert_eq!(
            close_blocker(&mut service, &mut ram, &page, inodes[0], 2),
            None
        );
        assert_eq!(ram.read(&mut parent, fd, &mut [0; 1]), Ok(1));
        assert_eq!(
            ram.pread(&child, fd, 0, &mut [0; 1], proto_fs::Timestamp::ZERO),
            Ok(1)
        );
        assert!(
            ram.live_description(&parent, ram.capture_description(&parent, next).unwrap().0)
                .is_ok()
        );
    }
    #[test]
    fn cached_close_precedes_reused_descriptor_and_rejected_new_body_preserves_the_old_receipt() {
        let (mut ram, inodes) = fixture();
        let mut service = fresh();
        let page = page();
        let payer = root(10, 1);
        let mut fds = crate::Fds {
            root: payer,
            binding: crate::authority::Binding::Active(close_who(257)),
            ..crate::Fds::default()
        };
        let fd = ram.open(&mut fds, "/lock0", proto_fs::READ_ONLY).unwrap();
        let original = close_event(&ram, &fds, fd, 48, 9, true);
        ram.close_event(&mut fds, &mut service, original).unwrap();
        ram.close(&mut fds, fd).unwrap();
        let next = ram.open(&mut fds, "/lock1", proto_fs::READ_ONLY).unwrap();
        assert_eq!(fd, next);
        let replacement = close_event(&ram, &fds, next, 48, 10, true);
        assert_ne!(
            original.description_generation,
            replacement.description_generation
        );
        real_run(
            &mut service,
            &mut ram,
            Some(&page),
            request(inodes[1], 257, Command::Set(Some(Kind::Read)), 0, 1),
            payer,
        )
        .unwrap();
        assert_eq!(ram.close_event(&mut fds, &mut service, original), Ok(()));
        assert_eq!(
            ram.close_event(
                &mut fds,
                &mut service,
                proto_fs::CloseEvent {
                    key: original.key,
                    ..replacement
                }
            ),
            Err(proto_fs::INVALID_ARGUMENT)
        );
        assert_eq!(
            ram.close_event(
                &mut fds,
                &mut service,
                proto_fs::CloseEvent {
                    key: proto_fs::CloseKey {
                        generation: 8,
                        ..original.key
                    },
                    ..original
                }
            ),
            Err(proto_fs::OPEN_RETIRED)
        );
        assert_eq!(
            ram.close_event(
                &mut fds,
                &mut service,
                proto_fs::CloseEvent {
                    key: replacement.key,
                    ..original
                }
            ),
            Err(proto_fs::BAD_FD)
        );
        assert_eq!(ram.close_event(&mut fds, &mut service, original), Ok(()));
        assert_eq!(
            close_blocker(&mut service, &mut ram, &page, inodes[1], 0),
            Some(Owner::Process(257))
        );
        assert!(
            ram.live_description(&fds, ram.capture_description(&fds, next).unwrap().0)
                .is_ok()
        );
        ram.close_event(&mut fds, &mut service, replacement)
            .unwrap();
        assert_eq!(
            close_blocker(&mut service, &mut ram, &page, inodes[1], 0),
            None
        );
        assert_eq!(
            ram.close_event(&mut fds, &mut service, original),
            Err(proto_fs::OPEN_RETIRED)
        );
    }
    #[test]
    fn pending_and_handoff_close_use_the_exact_target_pid_while_unvouched_states_do_not() {
        let who = close_who(257);
        for binding in [
            crate::authority::Binding::Active(who),
            crate::authority::Binding::Pending(who),
            crate::authority::Binding::Handoff(who),
        ] {
            let (mut ram, inodes) = fixture();
            let mut service = fresh();
            let page = page();
            let payer = root(10, 1);
            let mut fds = crate::Fds {
                root: payer,
                binding,
                ..crate::Fds::default()
            };
            let fd = ram.open(&mut fds, "/lock0", proto_fs::READ_ONLY).unwrap();
            real_run(
                &mut service,
                &mut ram,
                Some(&page),
                request(inodes[0], 257, Command::Set(Some(Kind::Read)), 0, 1),
                payer,
            )
            .unwrap();
            let event = close_event(&ram, &fds, fd, 48, 1, false);
            ram.close_event(&mut fds, &mut service, event).unwrap();
            assert_eq!(
                close_blocker(&mut service, &mut ram, &page, inodes[0], 0),
                None
            );
        }
        for binding in [
            crate::authority::Binding::Boot,
            crate::authority::Binding::Unbound,
            crate::authority::Binding::Cleanup,
            crate::authority::Binding::Inherited(who),
        ] {
            assert_eq!(binding.close_pid(), None);
        }
    }
    #[test]
    fn all_close_domains_leave_open_watermarks_independent_and_fork_starts_with_fresh_receipts() {
        let mut ram = crate::Ram::default();
        let mut service = fresh();
        let mut parent = crate::Fds {
            binding: crate::authority::Binding::Boot,
            ..crate::Fds::default()
        };
        parent.open_watermarks.fill(97);
        let fd = ram
            .open(&mut parent, "/etc/motd", proto_fs::READ_ONLY)
            .unwrap();
        for slot in 48..64 {
            let event = close_event(&ram, &parent, fd, slot, 7, false);
            ram.close_event(&mut parent, &mut service, event).unwrap();
        }
        assert!(parent.open_watermarks.iter().all(|&g| g == 97));
        let mut child = ram.clone_fds(&parent, &[fd]).unwrap();
        assert!(child.close_receipts.iter().all(Option::is_none));
        let held = ram.capture_description(&child, fd).unwrap().0;
        let event = close_event(&ram, &child, fd, 48, 1, true);
        ram.close_event(&mut child, &mut service, event).unwrap();
        assert!(ram.lock_parts().1.live(held.description));
        assert!(parent.close_receipts.iter().all(Option::is_some));
    }
    #[test]
    fn disappearance_of_32_true_descriptors_excludes_ofds_and_preserves_the_live_pid_group() {
        let (mut ram, inodes) = fixture();
        let mut service = fresh();
        let page = page();
        let payer = root(10, 1);
        let mut fds = crate::Fds {
            root: payer,
            binding: crate::authority::Binding::Active(close_who(257)),
            ..crate::Fds::default()
        };
        let mut held = std::vec::Vec::new();
        for _ in 0..32 {
            let fd = ram.open(&mut fds, "/lock0", proto_fs::READ_ONLY).unwrap();
            let description = ram.capture_description(&fds, fd).unwrap().0;
            real_run(
                &mut service,
                &mut ram,
                Some(&page),
                owned(
                    request(inodes[0], 257, Command::Set(Some(Kind::Read)), 2, 1),
                    description.description,
                ),
                payer,
            )
            .unwrap();
            held.push(description);
        }
        real_run(
            &mut service,
            &mut ram,
            Some(&page),
            request(inodes[0], 257, Command::Set(Some(Kind::Read)), 0, 1),
            payer,
        )
        .unwrap();
        assert_eq!(ram.detach_session_descriptions(&mut fds, &mut service), 32);
        assert_eq!(ram.detach_session_descriptions(&mut fds, &mut service), 0);
        assert_eq!(
            service.counts().published,
            1,
            "all 32 OFDs retire before audit"
        );
        for item in held {
            assert!(!ram.lock_parts().1.live(item.description));
            assert_eq!(ram.read(&mut fds, item.fd, &mut [0; 1]), Ok(1));
        }
        assert_eq!(
            close_blocker(&mut service, &mut ram, &page, inodes[0], 0),
            Some(Owner::Process(257))
        );
        assert_eq!(
            close_blocker(&mut service, &mut ram, &page, inodes[0], 2),
            None
        );
        assert_eq!(service.counts().published, 1);
        ram.release(&mut fds);
        assert_eq!(ram.open_descriptions(), 0);
        assert_eq!(ram.storage.usage(payer).descriptions, 0);
        assert_eq!(
            close_blocker(&mut service, &mut ram, &page, inodes[0], 0),
            Some(Owner::Process(257))
        );
        check_pins(&service, &ram.storage);
    }
    #[test]
    fn last_real_ofd_close_excludes_foreign_blocker_while_physical_read_and_payer_remain() {
        let mut ram = crate::Ram::default();
        let mut service = fresh();
        let page = page();
        let payer = root(10, 1);
        let mut fds = crate::Fds {
            root: payer,
            ..crate::Fds::default()
        };
        let fd = ram
            .open(&mut fds, "/etc/motd", proto_fs::READ_ONLY)
            .unwrap();
        let held = ram.capture_description(&fds, fd).unwrap().0;
        let inode = ram.live_description(&fds, held).unwrap().0;
        real_run(
            &mut service,
            &mut ram,
            Some(&page),
            owned(
                request(inode, 256, Command::Set(Some(Kind::Read)), 0, 1),
                held.description,
            ),
            payer,
        )
        .unwrap();
        assert_eq!(service.counts().published, 1);
        assert!(
            ram.detach_descriptor(&mut fds, held)
                .unwrap()
                .unwrap()
                .last_fd
        );
        assert_eq!(
            real_run(
                &mut service,
                &mut ram,
                Some(&page),
                request(inode, 257, Command::Get(Kind::Write), 0, 1),
                root(999, 1)
            ),
            Ok(Response::Blocker(None))
        );
        assert_eq!(service.counts(), budget::Counts::default());
        assert_eq!(ram.read(&mut fds, fd, &mut [0; 1]), Ok(1));
        assert_eq!(ram.storage.usage(payer).descriptions, 1);
        let other = ram.storage.lock_anchor(root(999, 1)).unwrap();
        assert_eq!(other.index(), 1);
        ram.storage.release_lock_anchor(other).unwrap();
        ram.close(&mut fds, fd).unwrap();
        let other = ram.storage.lock_anchor(root(999, 1)).unwrap();
        assert_eq!(other.index(), 0);
        ram.storage.release_lock_anchor(other).unwrap();
    }
    #[test]
    fn boot_ofd_survives_one_fork_reference_then_idle_audit_reclaims_it_without_pid_page() {
        let mut ram = crate::Ram::default();
        let mut service = fresh();
        let payer = root(10, 1);
        let mut parent = crate::Fds {
            root: payer,
            ..crate::Fds::default()
        };
        let fd = ram
            .open(&mut parent, "/etc/motd", proto_fs::READ_ONLY)
            .unwrap();
        let held = ram.capture_description(&parent, fd).unwrap().0;
        let inode = ram.live_description(&parent, held).unwrap().0;
        let mut child = ram.clone_fds(&parent, &[fd]).unwrap();
        real_run(
            &mut service,
            &mut ram,
            None,
            owned(
                request(inode, 256, Command::Set(Some(Kind::Read)), 0, 1),
                held.description,
            ),
            payer,
        )
        .unwrap();
        assert!(
            !ram.detach_descriptor(&mut parent, held)
                .unwrap()
                .unwrap()
                .last_fd
        );
        let (_, descriptions) = ram.lock_parts();
        assert!(
            !service
                .audit_description(held.description.slot as usize, |token| descriptions
                    .live(token))
                .unwrap()
        );
        assert_eq!(service.counts().published, 1);
        assert!(
            ram.detach_descriptor(&mut child, held)
                .unwrap()
                .unwrap()
                .last_fd
        );
        let mut dispatch = super::super::dispatch::Dispatch::default();
        for _ in 0..512 {
            match dispatch.next(0, service.busy(), false) {
                super::super::dispatch::Work::Actor => {
                    assert!(real_step(&mut service, &mut ram, None).completed.is_none());
                }
                super::super::dispatch::Work::Audit { first, end } => {
                    let (_, descriptions) = ram.lock_parts();
                    for position in first..end {
                        assert!(position >= proto_process::RECORDS);
                        service
                            .audit_description(position - proto_process::RECORDS, |token| {
                                descriptions.live(token)
                            })
                            .unwrap();
                    }
                }
                _ => {}
            }
            check_pins(&service, &ram.storage);
            if !dispatch.pending(service.busy()) {
                break;
            }
        }
        assert!(!service.busy());
        assert_eq!(service.counts(), budget::Counts::default());
        assert!(!dispatch.audited());
        assert_eq!(ram.read(&mut parent, fd, &mut [0; 1]), Ok(1));
        ram.release(&mut parent);
        ram.release(&mut child);
    }
    #[test]
    fn physical_legacy_close_and_description_reuse_retire_the_exact_old_ofd() {
        let mut ram = crate::Ram::default();
        let mut service = fresh();
        let payer = root(10, 1);
        let mut fds = crate::Fds {
            root: payer,
            ..crate::Fds::default()
        };
        let fd = ram
            .open(&mut fds, "/etc/motd", proto_fs::READ_ONLY)
            .unwrap();
        let old = ram.capture_description(&fds, fd).unwrap().0;
        let inode = ram.live_description(&fds, old).unwrap().0;
        real_run(
            &mut service,
            &mut ram,
            None,
            owned(
                request(inode, 256, Command::Set(Some(Kind::Read)), 0, 1),
                old.description,
            ),
            payer,
        )
        .unwrap();
        ram.close(&mut fds, fd).unwrap();
        let fd = ram
            .open(&mut fds, "/tmp/probe", proto_fs::READ_WRITE)
            .unwrap();
        let next = ram.capture_description(&fds, fd).unwrap().0;
        assert_eq!(next.description.slot, old.description.slot);
        assert!(next.description.generation > old.description.generation);
        let next_inode = ram.live_description(&fds, next).unwrap().0;
        real_run(
            &mut service,
            &mut ram,
            None,
            owned(
                request(next_inode, 256, Command::Set(Some(Kind::Write)), 0, 1),
                next.description,
            ),
            payer,
        )
        .unwrap();
        assert_eq!(service.counts().published, 1);
        let page = page();
        assert_eq!(
            real_run(
                &mut service,
                &mut ram,
                Some(&page),
                request(inode, 257, Command::Get(Kind::Write), 0, 1),
                payer
            ),
            Ok(Response::Blocker(None))
        );
        let Response::Blocker(Some(blocker)) = real_run(
            &mut service,
            &mut ram,
            Some(&page),
            request(next_inode, 257, Command::Get(Kind::Read), 0, 1),
            payer,
        )
        .unwrap() else {
            panic!("new OFD missing");
        };
        assert_eq!(
            blocker.owner,
            Owner::Description {
                slot: next.description.slot,
                generation: next.description.generation
            }
        );
    }
    #[test]
    fn closing_ofd_during_private_preparation_cancels_and_returns_all_group_debt() {
        let mut ram = crate::Ram::default();
        let mut service = fresh();
        let payer = root(10, 1);
        let mut fds = crate::Fds {
            root: payer,
            ..crate::Fds::default()
        };
        let fd = ram
            .open(&mut fds, "/tmp/probe", proto_fs::READ_WRITE)
            .unwrap();
        let held = ram.capture_description(&fds, fd).unwrap().0;
        let inode = ram.live_description(&fds, held).unwrap().0;
        for position in (0..12).step_by(2) {
            real_run(
                &mut service,
                &mut ram,
                None,
                owned(
                    request(inode, 256, Command::Set(Some(Kind::Read)), position, 1),
                    held.description,
                ),
                payer,
            )
            .unwrap();
        }
        assert_eq!(service.counts().published, 6);
        service
            .start(
                &mut ram.storage,
                owned(
                    request(inode, 256, Command::Set(Some(Kind::Write)), 0, 12),
                    held.description,
                ),
                payer,
            )
            .unwrap();
        for _ in 0..32 {
            let progress = real_step(&mut service, &mut ram, None);
            assert!(progress.completed.is_none());
            if service.counts().private != 0 {
                break;
            }
        }
        assert!(service.counts().private > 0);
        ram.close(&mut fds, fd).unwrap();
        assert_eq!(
            real_step(&mut service, &mut ram, None).completed,
            Some(Err(Error::Cancelled))
        );
        for _ in 0..4000 {
            if !service.busy() {
                break;
            }
            assert!(real_step(&mut service, &mut ram, None).completed.is_none());
        }
        assert!(!service.busy());
        assert_eq!(service.counts(), budget::Counts::default());
        check_pins(&service, &ram.storage);
        let other = ram.storage.lock_anchor(root(999, 1)).unwrap();
        assert_eq!(other.index(), 0);
    }
    #[test]
    fn all_128_dead_ofds_return_256_records_and_eight_payers_without_new_requests() {
        let mut ram = crate::Ram::default();
        let mut service = fresh();
        let mut fds: [crate::Fds; 8] = core::array::from_fn(|i| crate::Fds {
            root: root(10 + i as u64, 1),
            ..crate::Fds::default()
        });
        for session in &mut fds {
            for _ in 0..16 {
                let fd = ram.open(session, "/etc/motd", proto_fs::READ_ONLY).unwrap();
                let held = ram.capture_description(session, fd).unwrap().0;
                let inode = ram.live_description(session, held).unwrap().0;
                for position in [0, 2] {
                    real_run(
                        &mut service,
                        &mut ram,
                        None,
                        owned(
                            request(inode, 256, Command::Set(Some(Kind::Read)), position, 1),
                            held.description,
                        ),
                        session.root,
                    )
                    .unwrap();
                }
            }
        }
        assert_eq!(service.counts().published, 256);
        for session in &mut fds {
            ram.release(session);
        }
        assert_eq!(ram.open_descriptions(), 0);
        let mut dispatch = super::super::dispatch::Dispatch::default();
        let mut audits = [0; crate::DESCRIPTIONS];
        for _ in 0..4000 {
            match dispatch.next(0, service.busy(), false) {
                super::super::dispatch::Work::Actor => {
                    let progress = real_step(&mut service, &mut ram, None);
                    assert!(progress.completed.is_none());
                    assert!(progress.visited <= 8);
                }
                super::super::dispatch::Work::Audit { first, end } => {
                    let (_, descriptions) = ram.lock_parts();
                    for position in first..end {
                        let index = position - proto_process::RECORDS;
                        audits[index] += 1;
                        service
                            .audit_description(index, |token| descriptions.live(token))
                            .unwrap();
                    }
                }
                _ => {}
            }
            check_pins(&service, &ram.storage);
            assert!(service.counts().paid() <= 512);
            if !dispatch.pending(service.busy()) {
                break;
            }
        }
        assert!(audits.into_iter().all(|n| n == 1));
        assert!(!service.busy());
        assert_eq!(service.counts(), budget::Counts::default());
        assert_eq!(service.group_charge(0), Some(0));
        let other = ram.storage.lock_anchor(root(999, 1)).unwrap();
        assert_eq!(other.index(), 0);
        ram.storage.release_lock_anchor(other).unwrap();
    }
    #[test]
    fn deleted_inode_stays_paid_until_dead_group_release_then_reuses_its_place() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let mut service = fresh();
        let page = page();
        let payer = root(10, 1);
        let parent = ram.storage.resolve(b"/tmp").unwrap();
        let reservation = ram
            .storage
            .reserve(payer, parent, b"held", (crate::REG, 0o600, 0, 0))
            .unwrap();
        let inode = ram.storage.commit(reservation).unwrap();
        let identity = crate::authority::Identity {
            uid: 0,
            gid: 0,
            groups: proto_process::Groups::EMPTY,
        };
        let mut fds = crate::Fds {
            root: payer,
            ..crate::Fds::default()
        };
        let fd = ram
            .open_token(&mut fds, inode, proto_fs::READ_WRITE, identity)
            .unwrap();
        assert_eq!(ram.write(&mut fds, fd, b"x"), Ok(1));
        run(
            &mut service,
            &mut ram.storage,
            &page,
            request(inode, 256, Command::Set(Some(Kind::Write)), 0, 1),
            payer,
        )
        .unwrap();
        assert_eq!(ram.storage.unlink(parent, b"held", payer), Ok(inode));
        assert!(page.retire(256));
        ram.close(&mut fds, fd).unwrap();
        for _ in 0..32 {
            ram.storage.reclaim_step();
        }
        assert_eq!(ram.storage.node(inode).unwrap().pins[Pin::Lock as usize], 1);
        assert_eq!(ram.storage.usage(payer).pages, 1);
        check_pins(&service, &ram.storage);
        let next_payer = root(20, 1);
        let reservation = ram
            .storage
            .reserve(next_payer, parent, b"next", (crate::REG, 0o600, 0, 0))
            .unwrap();
        let next = ram.storage.commit(reservation).unwrap();
        assert_ne!(next.slot, inode.slot);
        assert_eq!(
            run(
                &mut service,
                &mut ram.storage,
                &page,
                request(next, 257, Command::Set(Some(Kind::Write)), 0, 1),
                next_payer
            ),
            Ok(Response::Changed)
        );
        assert!(service.audit_pid(0, |pid| page.live(pid)).unwrap());
        drain(&mut service, &mut ram.storage, &page);
        for _ in 0..32 {
            ram.storage.reclaim_step();
        }
        assert!(ram.storage.node(inode).is_err());
        assert_eq!(ram.storage.usage(payer).pages, 0);
        let reservation = ram
            .storage
            .reserve(payer, parent, b"replacement", (crate::REG, 0o600, 0, 0))
            .unwrap();
        let replacement = ram.storage.commit(reservation).unwrap();
        assert_eq!(replacement.slot, inode.slot);
        assert!(replacement.generation > inode.generation);
        assert_eq!(
            run(
                &mut service,
                &mut ram.storage,
                &page,
                request(replacement, 258, Command::Set(Some(Kind::Read)), 0, 1),
                payer
            ),
            Ok(Response::Changed)
        );
    }
    #[test]
    fn query_worker_keeps_deleted_inode_until_its_cancelled_terminal() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let mut service = fresh();
        let page = page();
        let payer = root(10, 1);
        let parent = ram.storage.resolve(b"/tmp").unwrap();
        let reservation = ram
            .storage
            .reserve(payer, parent, b"held", (crate::REG, 0o600, 0, 0))
            .unwrap();
        let inode = ram.storage.commit(reservation).unwrap();
        service
            .start(
                &mut ram.storage,
                request(inode, 256, Command::Get(Kind::Read), 0, 1),
                root(999, 1),
            )
            .unwrap();
        assert!(service.request_root.is_none());
        ram.storage.unlink(parent, b"held", payer).unwrap();
        for _ in 0..32 {
            ram.storage.reclaim_step();
        }
        assert_eq!(ram.storage.node(inode).unwrap().pins[Pin::Lock as usize], 1);
        assert!(service.cancel());
        assert_eq!(ram.storage.node(inode).unwrap().pins[Pin::Lock as usize], 1);
        let terminal = service.step(&mut ram.storage, |pid| page.live(pid));
        assert_eq!(terminal.completed, Some(Err(Error::Cancelled)));
        assert!(service.request_inode.is_none());
        check_pins(&service, &ram.storage);
        for _ in 0..32 {
            ram.storage.reclaim_step();
        }
        assert!(ram.storage.node(inode).is_err());
        let peer = ram.storage.lock_anchor(root(999, 1)).unwrap();
        assert_eq!(peer.index(), 0);
        ram.storage.release_lock_anchor(peer).unwrap();
    }
    #[test]
    fn stale_inode_start_returns_its_root_and_leaves_all_pins_unchanged() {
        let (mut ram, inodes) = fixture();
        let mut service = fresh();
        let mut stale = inodes[0];
        stale.generation += 1;
        assert_eq!(
            service.start(
                &mut ram.storage,
                request(stale, 256, Command::Set(Some(Kind::Write)), 0, 1),
                root(10, 1)
            ),
            Err(Error::Invalid)
        );
        check_pins(&service, &ram.storage);
        assert!(!service.busy());
        assert!(service.request_inode.is_none());
        assert!(service.request_root.is_none());
        let peer = ram.storage.lock_anchor(root(20, 1)).unwrap();
        assert_eq!(peer.index(), 0);
        ram.storage.release_lock_anchor(peer).unwrap();
        assert_eq!(
            service.start(
                &mut ram.storage,
                request(stale, 256, Command::Get(Kind::Read), 0, 1),
                root(30, 1)
            ),
            Err(Error::Invalid)
        );
        check_pins(&service, &ram.storage);
    }
    #[test]
    fn own_dispatches_finish_a_stalled_client_and_reclaim_death_without_take() {
        use super::super::dispatch::{Dispatch, Work};
        let (mut ram, inodes) = fixture();
        let mut service = fresh();
        let page = page();
        let mut dispatch = Dispatch::default();
        service
            .start(
                &mut ram.storage,
                request(inodes[0], 256, Command::Set(Some(Kind::Write)), 0, 1),
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
                        if index < proto_process::RECORDS {
                            service.audit_pid(index, |pid| page.live(pid)).unwrap();
                        } else {
                            service
                                .audit_description(index - proto_process::RECORDS, |_| true)
                                .unwrap();
                        }
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
                        if index < proto_process::RECORDS {
                            service.audit_pid(index, |pid| page.live(pid)).unwrap();
                        } else {
                            service
                                .audit_description(index - proto_process::RECORDS, |_| true)
                                .unwrap();
                        }
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
        assert_eq!(bytes, 877120);
        assert_eq!(core::mem::size_of::<Option<PaidGroup>>(), 56);
        assert!(!service.busy());
        assert!(service.request_root.is_none());
        assert!(service.groups.iter().all(Option::is_none));
        check(&service);
    }
    #[test]
    fn busy_and_invalid_requests_do_not_allocate_an_expenditure_root() {
        let (mut ram, inodes) = fixture();
        let mut service = fresh();
        let page = page();
        assert_eq!(
            service.start(
                &mut ram.storage,
                request(inodes[0], 0, Command::Set(Some(Kind::Write)), 0, 1),
                root(10, 1)
            ),
            Err(Error::Invalid)
        );
        assert_eq!(
            service.start(
                &mut ram.storage,
                request(inodes[0], 256, Command::Set(Some(Kind::Write)), 0, 1),
                root(10, 0)
            ),
            Err(Error::Invalid)
        );
        assert!(!service.busy());
        service
            .start(
                &mut ram.storage,
                request(inodes[0], 256, Command::Set(Some(Kind::Write)), 0, 1),
                root(10, 1),
            )
            .unwrap();
        assert_eq!(service.request_root.as_ref().unwrap().index(), 0);
        assert_eq!(
            service.start(
                &mut ram.storage,
                request(inodes[1], 257, Command::Set(Some(Kind::Read)), 0, 1),
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
        let (mut ram, inodes) = fixture();
        let mut service = fresh();
        let page = page();
        service
            .start(
                &mut ram.storage,
                request(inodes[0], 256, Command::Set(Some(Kind::Write)), 0, 1),
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
        let (mut ram, inodes) = fixture();
        let mut service = fresh();
        let page = page();
        let first = root(11, 3);
        let later = root(11, 4);
        run(
            &mut service,
            &mut ram.storage,
            &page,
            request(inodes[0], 256, Command::Set(Some(Kind::Write)), 0, 1),
            first,
        )
        .unwrap();
        run(
            &mut service,
            &mut ram.storage,
            &page,
            request(inodes[0], 256, Command::Set(Some(Kind::Write)), 1, 1),
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
        service.close(inodes[0], Owner::Process(256)).unwrap();
        drain(&mut service, &mut ram.storage, &page);
        let other = ram.storage.lock_anchor(later).unwrap();
        assert_eq!(other.index(), 0);
        ram.storage.release_lock_anchor(other).unwrap();
    }
    #[test]
    fn get_and_unlock_need_no_new_account_when_all_320_places_are_retained() {
        let (mut ram, inodes) = fixture();
        let mut service = fresh();
        let page = page();
        run(
            &mut service,
            &mut ram.storage,
            &page,
            request(inodes[0], 256, Command::Set(Some(Kind::Write)), 0, 1),
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
            request(inodes[0], 257, Command::Get(Kind::Read), 0, 1),
            root(999, 1),
        )
        .unwrap();
        assert!(matches!(blocker, Response::Blocker(Some(_))));
        assert_eq!(
            run(
                &mut service,
                &mut ram.storage,
                &page,
                request(inodes[0], 256, Command::Set(None), 0, 0),
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
        let (mut ram, inodes) = fixture();
        let mut service = fresh();
        let page = page();
        for index in 0u16..8 {
            run(
                &mut service,
                &mut ram.storage,
                &page,
                request(
                    inodes[index as usize],
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
                request(inodes[8], 264, Command::Set(Some(Kind::Write)), 0, 1),
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
        let (mut ram, inodes) = fixture();
        let mut service = fresh();
        let page = page();
        run(
            &mut service,
            &mut ram.storage,
            &page,
            request(inodes[0], 256, Command::Set(Some(Kind::Write)), 0, 1),
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
