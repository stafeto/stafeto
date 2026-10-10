// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Genuine actor completion and close events validate internal retry custody.

extern crate std;
use super::{Id, Phase, Queue};
use crate::locks::{
    Kind, Owner,
    actor::{Command, Error, Request, Response},
    request::Captured,
    server,
    service::LockService,
};
use crate::{
    Fds, Ram,
    authority::Binding,
    storage::{Pin, Root},
};
use proto_fs::{
    CloseEvent, CloseKey, DataDescription, LockCommand, LockKind, LockPhase, LockReply, LockStart,
    OpenKey,
};
use proto_process::lifetimes::Page;
use std::boxed::Box;

struct Fixture {
    ram: Ram<'static>,
    fds: Fds,
    queue: Box<Queue>,
    service: Box<LockService>,
    page: Page,
    wire: LockStart,
    id: Id,
    captured: Captured,
}
impl Fixture {
    fn new(whence: u32, ofd: bool) -> Self {
        let mut ram = Ram::default();
        let mut fds = Fds {
            root: Root {
                id: 10,
                generation: 1,
            },
            binding: Binding::Active(proto_process::WhoReply {
                pid: 257,
                credentials: proto_process::Credentials::ROOT,
                generation: 1,
                loader: None,
                index: 1,
                ctty: None,
                image: 1,
                groups: proto_process::Groups::EMPTY,
                limits: proto_process::ResourceLimits::initial(2 * 1024 * 1024),
                root: proto_process::ExpenditureRoot {
                    pid: 10,
                    generation: 1,
                },
            }),
            ..Fds::default()
        };
        let fd = ram
            .open(&mut fds, "/tmp/probe", proto_fs::READ_WRITE)
            .unwrap();
        ram.write(&mut fds, fd, b"01234567890123456789").unwrap();
        ram.seek(&mut fds, fd, 7).unwrap();
        let held = ram.capture_description(&fds, fd).unwrap().0;
        let wire = LockStart {
            key: OpenKey {
                slot: 32,
                generation: 1,
            },
            description: DataDescription {
                packed: ram.marked_open(&fds, held).unwrap(),
                generation: held.description.generation,
            },
            command: if ofd {
                LockCommand::SetOfd
            } else {
                LockCommand::SetPid
            },
            kind: LockKind::Read,
            whence,
            start: 2,
            length: 3,
            pid: 0,
        };
        let captured = ram.capture_lock(&fds, wire).unwrap();
        let mut queue = Box::<Queue>::new_uninit();
        let mut service = Box::<LockService>::new_uninit();
        // SAFETY: exclusive aligned allocations are initialized directly.
        let (mut queue, mut service) = unsafe {
            Queue::initialize_at(queue.as_mut_ptr());
            LockService::initialize_at(service.as_mut_ptr());
            (queue.assume_init(), service.assume_init())
        };
        let page = Page::new();
        page.publish(257).unwrap();
        page.publish(258).unwrap();
        server::start(&mut queue, &mut ram, &mut fds, 1, 41, wire).unwrap();
        let id = queue.occupied(1, 41, 32).unwrap().unwrap();
        server::begin(&mut queue, &mut service, &mut ram, id, Some(&fds));
        let mut result = Self {
            ram,
            fds,
            queue,
            service,
            page,
            wire,
            id,
            captured,
        };
        result.prepare();
        result
    }
    fn step(&mut self) -> Option<Result<Response, Error>> {
        let (storage, descriptions) = self.ram.lock_parts();
        let progress = self.service.step_with_owners(
            storage,
            |pid| self.page.live(pid),
            |token| descriptions.live(token),
        );
        assert!(progress.visited <= 8);
        progress.completed
    }
    fn prepare(&mut self) {
        for _ in 0..3 {
            assert_eq!(self.step(), None);
        }
        assert_eq!(self.queue.snapshot(self.id).unwrap().1, Phase::Active);
        assert!(self.service.counts().private > 0);
    }
    fn terminal(&mut self) -> Result<Response, Error> {
        for _ in 0..512 {
            if let Some(result) = self.step() {
                return result;
            }
        }
        panic!("actor failed to produce a bounded completion");
    }
    fn drain(&mut self) {
        for _ in 0..512 {
            if !self.service.busy() {
                return;
            }
            assert_eq!(self.step(), None);
        }
        panic!("paid actor debt did not drain");
    }
    fn close_event(&mut self, fd: u32, generation: u64) {
        let held = self.ram.capture_description(&self.fds, fd).unwrap().0;
        let packed = self.ram.marked_open(&self.fds, held).unwrap();
        self.ram
            .close_event(
                &mut self.fds,
                &mut self.service,
                CloseEvent {
                    key: CloseKey {
                        slot: 48,
                        generation,
                    },
                    packed,
                    description_generation: held.description.generation,
                    last_alias: true,
                },
            )
            .unwrap();
    }
    fn finish(&mut self, result: Result<Response, Error>) -> bool {
        server::finish_with_source(
            &mut self.queue,
            &mut self.ram,
            result,
            Some(&self.fds),
            |pid| self.page.live(pid),
        )
    }
    fn query(&self) -> LockReply {
        server::query(&self.queue, &self.fds, 1, 41, self.wire.key).unwrap()
    }
    fn release(&mut self) {
        assert!(
            !server::release(
                &mut self.queue,
                &mut self.ram,
                &mut self.fds,
                1,
                41,
                self.wire.key
            )
            .unwrap()
        );
        assert_eq!((self.queue.work, self.queue.held), (0, 0));
    }
    fn clean_groups(&mut self) {
        self.service
            .close(self.captured.request.inode, self.captured.request.owner)
            .unwrap();
        self.drain();
        assert_eq!(self.service.counts().paid(), 0);
        assert_eq!(
            self.ram
                .storage
                .node(self.captured.request.inode)
                .unwrap()
                .pins[Pin::Lock as usize],
            0
        );
    }
}

#[test]
fn genuine_other_fd_close_retries_original_cur_and_end_with_exact_payment() {
    for whence in [1, 2] {
        let mut f = Fixture::new(whence, false);
        let payment = f
            .queue
            .job(f.id)
            .unwrap()
            .anchor
            .as_ref()
            .map(|anchor| (anchor.index(), anchor.root()));
        assert!(payment.is_some());
        for generation in 1..=3 {
            let other = f
                .ram
                .open(&mut f.fds, "/tmp/probe", proto_fs::READ_WRITE)
                .unwrap();
            f.ram
                .seek(&mut f.fds, f.captured.source.fd, 70 + generation as u32)
                .unwrap();
            f.ram
                .seek_from(&mut f.fds, other, 0, proto_fs::SeekFrom::End)
                .unwrap();
            f.ram.write(&mut f.fds, other, b"changed EOF").unwrap();
            assert_ne!(
                f.ram.capture_lock(&f.fds, f.wire).unwrap().request.range,
                f.captured.request.range
            );
            f.close_event(other, generation);
            let result = f.terminal();
            assert_eq!(result, Err(Error::Cancelled));
            assert!(!f.finish(result));
            assert_eq!(
                f.queue.snapshot(f.id).unwrap(),
                (f.captured, Phase::Queued, false)
            );
            assert_eq!((f.queue.work, f.queue.held), (1, 1));
            assert_eq!(
                f.queue
                    .job(f.id)
                    .unwrap()
                    .anchor
                    .as_ref()
                    .map(|anchor| (anchor.index(), anchor.root())),
                payment
            );
            assert_eq!(f.query().phase, LockPhase::Pending);
            assert_eq!(server::replay(&f.queue, 1, 41, f.wire), Ok(Some(f.query())));
            f.drain();
            assert_eq!(
                f.ram.storage.node(f.captured.request.inode).unwrap().pins[Pin::Lock as usize],
                1
            );
            server::begin(&mut f.queue, &mut f.service, &mut f.ram, f.id, Some(&f.fds));
            f.prepare();
        }
        let result = f.terminal();
        assert_eq!(result, Ok(Response::Changed));
        assert!(!f.finish(result));
        assert_eq!((f.queue.work, f.queue.held), (0, 1));
        assert_eq!(f.query().result, 0);
        f.drain();
        let request = Request {
            owner: Owner::Process(258),
            command: Command::Get(Kind::Write),
            ..f.captured.request
        };
        f.service
            .start(&mut f.ram.storage, request, f.captured.root)
            .unwrap();
        let result = f.terminal();
        let Ok(Response::Blocker(Some(blocker))) = result else {
            panic!("original captured range has no blocker: {result:?}")
        };
        assert_eq!(
            (blocker.owner, blocker.range),
            (Owner::Process(257), f.captured.request.range)
        );
        f.drain();
        f.release();
        f.clean_groups();
    }
}

#[test]
fn explicit_cancel_with_live_source_retains_cancelled_until_release() {
    let mut f = Fixture::new(1, false);
    let (_, active) = server::cancel(&mut f.queue, &mut f.fds, 1, 41, f.wire.key).unwrap();
    assert!(active);
    assert!(f.service.cancel());
    let result = f.terminal();
    assert_eq!(result, Err(Error::Cancelled));
    assert!(!f.finish(result));
    assert_eq!((f.queue.work, f.queue.held), (0, 1));
    assert_eq!(f.query().result, proto_fs::LOCK_CANCELLED);
    let saved = f.query();
    assert_eq!(
        server::cancel(&mut f.queue, &mut f.fds, 1, 41, f.wire.key),
        Ok((saved, false))
    );
    f.drain();
    f.release();
    f.clean_groups();
}

#[test]
fn release_during_private_preparation_denies_retry_and_returns_every_job_charge() {
    let mut f = Fixture::new(1, false);
    assert!(server::release(&mut f.queue, &mut f.ram, &mut f.fds, 1, 41, f.wire.key).unwrap());
    assert!(f.service.cancel());
    let result = f.terminal();
    assert!(f.finish(result));
    assert_eq!((f.queue.work, f.queue.held), (0, 0));
    assert!(f.queue.snapshot(f.id).is_err());
    f.drain();
    f.clean_groups();
}

#[test]
fn full_pid_death_or_closed_and_reused_source_denies_retry() {
    for reused in [false, true] {
        let mut f = Fixture::new(1, false);
        if reused {
            f.close_event(f.captured.source.fd, 1);
            f.ram.close(&mut f.fds, f.captured.source.fd).unwrap();
            let next = f
                .ram
                .open(&mut f.fds, "/tmp/probe", proto_fs::READ_WRITE)
                .unwrap();
            assert_eq!(next, f.captured.source.fd);
            assert_ne!(
                f.ram
                    .capture_description(&f.fds, next)
                    .unwrap()
                    .0
                    .description,
                f.captured.source.description
            );
        } else {
            assert!(f.page.retire(257));
            f.page.publish(513).unwrap();
            assert!(f.page.live(513));
            assert!(!f.page.live(257));
        }
        let result = f.terminal();
        assert_eq!(result, Err(Error::Cancelled));
        assert!(!f.finish(result));
        assert_eq!(f.query().result, proto_fs::LOCK_CANCELLED);
        assert_eq!((f.queue.work, f.queue.held), (0, 1));
        f.drain();
        f.release();
        f.clean_groups();
    }
}

#[test]
fn last_true_ofd_close_denies_retry_despite_a_retained_physical_description() {
    let mut f = Fixture::new(1, true);
    f.close_event(f.captured.source.fd, 1);
    assert_eq!(
        f.ram.read(&mut f.fds, f.captured.source.fd, &mut [0; 1]),
        Ok(1)
    );
    assert!(!f.ram.lock_parts().1.live(f.captured.source.description));
    let result = f.terminal();
    assert_eq!(result, Err(Error::Cancelled));
    assert!(!f.finish(result));
    assert_eq!(f.query().result, proto_fs::LOCK_CANCELLED);
    assert_eq!((f.queue.work, f.queue.held), (0, 1));
    f.drain();
    f.release();
    f.clean_groups();
}

#[test]
fn postpublication_close_preserves_success_instead_of_retrying_or_cancelling() {
    let mut f = Fixture::new(1, false);
    let result = f.terminal();
    assert_eq!(result, Ok(Response::Changed));
    let other = f
        .ram
        .open(&mut f.fds, "/tmp/probe", proto_fs::READ_ONLY)
        .unwrap();
    f.close_event(other, 1);
    assert!(!f.finish(result));
    assert_eq!(f.query().phase, LockPhase::Complete);
    assert_eq!(f.query().result, 0);
    assert_eq!((f.queue.work, f.queue.held), (0, 1));
    f.drain();
    f.release();
    f.clean_groups();
}

#[test]
fn other_pid_close_cannot_cancel_the_active_preparation() {
    let mut f = Fixture::new(1, false);
    f.service
        .close(f.captured.request.inode, Owner::Process(258))
        .unwrap();
    let result = f.terminal();
    assert_eq!(result, Ok(Response::Changed));
    assert!(!f.finish(result));
    assert_eq!(f.query().result, 0);
    f.drain();
    f.release();
    f.clean_groups();
}
