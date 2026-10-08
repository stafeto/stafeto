// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Initial record custody and one-effect native steps in the existing Work.
use crate::{Processes, Work, controller, pages};
use posix_process_service::initial_resident::{CleanupOwner, Phase};
use proto_wire::Status;
use rt::abi;
use rt::handle::Channel;
use rt::service::{Answer, Request};

impl Processes {
    pub(super) fn initial_ack(&mut self, request: &mut Request<'_>) -> Answer {
        let Ok(ack) = proto_process::initial_ack::Ack::read(
            &request.bytes()[proto_wire::HEADER_LEN..],
            request.handles.len(),
        ) else {
            return Answer::Status(Status::BadSize);
        };
        let Some(index) = self.records.find_pid(ack.receipt.pid) else {
            return crate::refuse(proto_process::UNREGISTERED);
        };
        let ticket = self.tickets[index];
        let record = self.records.get(index).expect("the current initial record");
        if !record.matches_initial_ack(ticket, ack) {
            return crate::refuse(proto_process::PERMISSION);
        }
        let key = posix_process_service::initial_resident::SeedKey {
            epoch: ack.epoch,
            ticket: ack.ticket,
            label: ack.label,
        };
        if record.initial_ack_replay_matches(ticket, ack) {
            return receipt_reply(request, ack.receipt);
        }
        let Some(resident) = self.replacing[index].as_mut().and_then(Work::initial_mut) else {
            return crate::refuse(proto_process::PERMISSION);
        };
        if !resident.init_ack(key, ack.receipt) {
            return crate::refuse(proto_process::PERMISSION);
        }
        let record = self
            .records
            .get_mut(index)
            .expect("the acknowledged initial record");
        let mut origin = record
            .initial_origin(ticket)
            .expect("the checked initial source");
        origin.flags |= posix_process_service::initial_origin::INIT_ACKED;
        assert!(record.set_initial_origin(ticket, origin));
        self.kick();
        receipt_reply(request, ack.receipt)
    }

    pub(super) fn initial_stage(&mut self, request: &mut Request<'_>) -> Answer {
        let reconciliation = request.handles.is_empty();
        let decode = if reconciliation {
            proto_process::initial_stage::Stage::read_reconciliation
        } else {
            proto_process::initial_stage::Stage::read
        };
        let Ok(stage) = decode(
            &request.bytes()[proto_wire::HEADER_LEN..],
            request.handles.len(),
        ) else {
            return Answer::Status(Status::BadSize);
        };
        let Some(index) = self.records.find(stage.label) else {
            return crate::refuse(proto_process::UNREGISTERED);
        };
        let Some(resident) = self.replacing[index].as_mut().and_then(Work::initial_mut) else {
            return crate::refuse(proto_process::PERMISSION);
        };
        if reconciliation {
            let exact = self.records.get(index).is_some_and(|record| {
                resident.matches_image(record.label.raw_at(record.image), record.image)
                    && record.active_guard_label != 0
                    && record.active_exec.is_some()
            });
            return if exact && resident.stage_replay_matches(&stage) {
                receipt_reply(request, resident.publication.map.receipt)
            } else {
                Answer::Status(Status::Kernel(abi::Error::BadState))
            };
        }
        if resident.key.ticket != stage.ticket
            || resident.key.label != stage.label
            || resident.publication.source != stage.source
            || resident.publication.map.receipt != stage.query.receipt
            || resident.phase() != Phase::GuardWait
            || resident.operation_pending.is_some()
            || resident.cleanup[0].is_some()
            || request.handles.info(0).is_none_or(|(kind, rights)| {
                kind != abi::ObjectKind::Channel
                    || !rights.contains(
                        abi::Rights::SEND | abi::Rights::DUPLICATE | abi::Rights::TRANSFER,
                    )
            })
        {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        }
        let Some(pending) = request.defer() else {
            return Answer::Status(Status::BadSize);
        };
        let candidate = request
            .handles
            .take::<Channel>(0)
            .expect("the checked source Channel");
        assert!(resident.queue_stage(stage.epoch, stage.uid, stage.gid, stage.mode));
        resident.cleanup[0] = Some(CleanupOwner::Channel(candidate));
        resident.operation_pending = Some(pending);
        self.replace_queue.push(index);
        self.kick();
        Answer::Deferred
    }

    pub(super) fn initial_of(&mut self, request: &mut Request<'_>) -> Answer {
        let Ok(query) = proto_process::initial_identity::Query::read(
            &request.bytes()[proto_wire::HEADER_LEN..],
            request.handles.len(),
        ) else {
            return Answer::Status(Status::BadSize);
        };
        let Some(index) = self.records.find(query.receipt.label) else {
            return crate::refuse(proto_process::UNREGISTERED);
        };
        let Some(resident) = self.replacing[index].as_mut().and_then(Work::initial_mut) else {
            return crate::refuse(proto_process::PERMISSION);
        };
        if !resident.maps_ready()
            || resident.publication.map.receipt != query.receipt
            || resident.crt_pending.is_some()
            || resident.retained_identity.is_some()
            || request
                .handles
                .info(0)
                .is_none_or(|(kind, _)| kind != abi::ObjectKind::Channel)
        {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        }
        let Some(pending) = request.defer() else {
            return Answer::Status(Status::BadSize);
        };
        resident.retained_identity = Some(
            request
                .handles
                .take::<Channel>(0)
                .expect("the checked identity owner"),
        );
        resident.crt_pending = Some(pending);
        self.kick();
        Answer::Deferred
    }

    pub(super) fn initial_maps(&mut self, request: &mut Request<'_>) -> Answer {
        let reconciliation = request.handles.is_empty();
        let decode = if reconciliation {
            proto_process::initial_publication::Publication::read_reconciliation
        } else {
            proto_process::initial_publication::Publication::read
        };
        let Ok(publication) = decode(
            &request.bytes()[proto_wire::HEADER_LEN..],
            request.handles.len(),
        ) else {
            return Answer::Status(Status::BadSize);
        };
        let Some(index) = self.records.find(publication.map.receipt.label) else {
            return crate::refuse(proto_process::UNREGISTERED);
        };
        let Some(resident) = self.replacing[index].as_mut().and_then(Work::initial_mut) else {
            return crate::refuse(proto_process::PERMISSION);
        };
        if reconciliation {
            let exact = self.records.get(index).is_some_and(|record| {
                resident.matches_image(record.label.raw_at(record.image), record.image)
                    && record.active_guard_label != 0
                    && record.active_exec.is_some()
            });
            return if exact && resident.maps_replay_matches(&publication) {
                receipt_reply(request, resident.publication.map.receipt)
            } else {
                Answer::Status(Status::Kernel(abi::Error::BadState))
            };
        }
        if !resident.page_ready()
            || resident.phase() != Phase::Loading
            || resident.publication.source != publication.source
            || resident.publication.map.receipt != publication.map.receipt
            || resident.operation_pending.is_some()
            || resident.memory_validation().is_some()
        {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        }
        let Some(program) = crate::make::initial_program(publication.source) else {
            return Answer::Status(Status::BadSize);
        };
        let mut slot = 0;
        for (part, segment) in program.segments.iter().enumerate() {
            if segment.mem_size == 0 {
                continue;
            }
            let entry = publication.map.entries[slot];
            let pages = segment.pages();
            let access = [
                abi::Access::ReadExec,
                abi::Access::Read,
                abi::Access::ReadWrite,
            ][part];
            if entry.address != pages.start
                || u64::from(entry.pages) != (pages.end - pages.start) / 4096
                || entry.access != access
            {
                return Answer::Status(Status::BadSize);
            }
            slot += 1;
        }
        let stack = publication.map.entries[slot];
        if stack.address != abi::INIT_STACK_TOP - u64::from(program.stack_size)
            || u64::from(stack.pages) != u64::from(program.stack_size) / 4096
            || stack.access != abi::Access::ReadWrite
            || usize::from(publication.map.count) != slot + 1
        {
            return Answer::Status(Status::BadSize);
        }
        for (slot, entry) in publication.map.entries[..usize::from(publication.map.count)]
            .iter()
            .enumerate()
        {
            if request.handles.info(slot).is_none_or(|(kind, rights)| {
                kind != abi::ObjectKind::Memory
                    || rights
                        != entry.access.rights() | abi::Rights::DUPLICATE | abi::Rights::TRANSFER
            }) {
                return Answer::Status(Status::BadSize);
            }
        }
        let Some(pending) = request.defer() else {
            return Answer::Status(Status::BadSize);
        };
        let mut owners = core::array::from_fn(|_| None);
        for (slot, owner) in owners
            .iter_mut()
            .enumerate()
            .take(usize::from(publication.map.count))
        {
            *owner = Some(
                request
                    .handles
                    .take::<rt::handle::Memory>(slot)
                    .expect("the checked Memory owner"),
            );
        }
        assert!(resident.begin_publish(publication, owners).is_ok());
        resident.operation_pending = Some(pending);
        self.kick();
        Answer::Deferred
    }

    pub(super) fn initial_step(&mut self, index: usize) {
        let Some(resident) = self.replacing[index].as_mut().and_then(Work::initial_mut) else {
            return;
        };
        let ticket = self.tickets[index];
        let releasable = self
            .records
            .get(index)
            .is_some_and(|record| resident.releasable_for(record, ticket));
        if releasable {
            self.replacing[index] = None;
            self.preparing_count -= 1;
            if self
                .records
                .get(index)
                .is_some_and(|record| record.state.end_pending())
            {
                self.start_ending(index, None);
            }
            return;
        }
        if let Some(reason) = resident.end_reason() {
            // Exact native Exit has released the target's mappings. The shared
            // service PageGroup remains resident for all four record slots.
            if !resident.native_end_confirmed() {
                if resident.needs_stop() {
                    let record = self.records.get(index).expect("the exact initial record");
                    if record.label.raw_at(record.image) == resident.key.label
                        && rt::sys::process_kill(&record.process).is_ok()
                    {
                        resident.stop_sent();
                    }
                }
                return;
            }
            for slot in 0..resident.cleanup.len() {
                if let Some(owner) = resident.cleanup[slot].as_ref() {
                    let raw = match owner {
                        CleanupOwner::Memory(owner) => owner.raw().0,
                        CleanupOwner::Channel(owner) => owner.raw().0,
                        CleanupOwner::Thread(owner) => owner.raw().0,
                    };
                    if controller::raw_close(raw).is_ok() {
                        match resident.cleanup[slot]
                            .take()
                            .expect("the exact closed owner")
                        {
                            CleanupOwner::Memory(owner) => {
                                owner.into_raw();
                            }
                            CleanupOwner::Channel(owner) => {
                                owner.into_raw();
                            }
                            CleanupOwner::Thread(owner) => {
                                owner.into_raw();
                            }
                        }
                    }
                    return;
                }
            }
            if let Some(identity) = resident.retained_identity.as_ref() {
                if controller::raw_close(identity.raw().0).is_ok() {
                    resident
                        .retained_identity
                        .take()
                        .expect("the exact closed identity")
                        .into_raw();
                }
                return;
            }
            if let Some((slot, owner)) = resident.cleanup_original() {
                if controller::raw_close(owner.raw().0).is_ok() {
                    owner.into_raw();
                } else {
                    assert!(resident.restore_original(slot, owner).is_ok());
                }
                return;
            }
            if let Some((slot, owner)) = resident.cleanup_reply_copy() {
                if controller::raw_close(owner.raw().0).is_ok() {
                    owner.into_raw();
                } else {
                    assert!(resident.restore_reply_copy(slot, owner).is_ok());
                }
                return;
            }
            if let Some(owner) = resident.cleanup_thread() {
                if controller::raw_close(owner.raw().0).is_ok() {
                    owner.into_raw();
                } else {
                    assert!(resident.retained_thread.replace(owner).is_none());
                }
                return;
            }
            if let Some(record) = self.records.get_mut(index)
                && resident.matches_image(record.label.raw_at(record.image), record.image)
                && let Some(owner) = record.active_exec.as_ref()
            {
                if controller::raw_close(owner.raw().0).is_ok() {
                    record
                        .active_exec
                        .take()
                        .expect("the exact closed source")
                        .into_raw();
                    record.active_guard_label = 0;
                }
                return;
            }
            let notary = resident.operation_pending.is_none();
            let pending = if notary {
                resident.crt_pending.as_mut()
            } else {
                resident.operation_pending.as_mut()
            };
            if let Some(pending) = pending {
                if let Some(token) = pending.take_token() {
                    let reply = proto_wire::reply(Status::from_code(reason));
                    match token.reply_handles(&reply, rt::handle::Outgoing::new()) {
                        Ok(()) => {
                            if notary {
                                resident.settle_identity(false);
                            } else {
                                resident.settle_operation(false);
                            }
                        }
                        Err(mut refused) => {
                            assert!(
                                refused
                                    .back
                                    .as_ref()
                                    .is_none_or(rt::handle::Outgoing::is_empty)
                            );
                            if let Some(token) = refused.token.take() {
                                assert!(pending.restore_token(token).is_ok());
                            } else if notary {
                                resident.settle_identity(false);
                            } else {
                                resident.settle_operation(false);
                            }
                        }
                    }
                } else {
                    if notary {
                        resident.settle_identity(false);
                    } else {
                        resident.settle_operation(false);
                    }
                }
            }
            return;
        }
        if resident.crt_pending.is_some() {
            if let Some(identity) = resident.retained_identity.as_ref() {
                if !resident.identity_checked() {
                    let expected = self.records.get(index).expect("the exact initial record");
                    let genuine = resident
                        .matches_image(expected.label.raw_at(expected.image), expected.image)
                        && rt::sys::copy_label(&self.identities, identity)
                            == Ok(expected.label.identity_at(expected.image));
                    resident.identity_result(genuine);
                } else if controller::raw_close(identity.raw().0).is_ok() {
                    resident
                        .retained_identity
                        .take()
                        .expect("the exact closed identity")
                        .into_raw();
                }
                return;
            }
            let mut reply = proto_wire::Writer::new();
            if resident.identity_genuine() {
                proto_process::initial_identity::Reply {
                    query: proto_process::initial_identity::Query {
                        receipt: resident.publication.map.receipt,
                    },
                    source: resident.publication.source,
                }
                .write(&mut reply)
                .expect("the checked initial identity receipt");
            } else {
                reply
                    .bytes(&proto_wire::reply(Status::Kernel(abi::Error::BadState)))
                    .expect("the identity refusal");
            }
            let pending = resident
                .crt_pending
                .as_mut()
                .expect("the retained notary token");
            if let Some(token) = pending.take_token() {
                match token.reply_handles(reply.as_bytes(), rt::handle::Outgoing::new()) {
                    Ok(()) => {
                        resident.settle_identity(false);
                    }
                    Err(mut refused) => {
                        assert!(
                            refused
                                .back
                                .as_ref()
                                .is_none_or(rt::handle::Outgoing::is_empty)
                        );
                        if let Some(token) = refused.token.take() {
                            assert!(pending.restore_token(token).is_ok());
                        } else {
                            resident.settle_identity(false);
                        }
                    }
                }
            } else {
                resident.settle_identity(false);
            }
            return;
        }
        if resident.page_needs_copy() {
            if let Ok(copy) = self.pages.narrow(index) {
                assert!(resident.retain_page_copy(copy).is_ok());
            }
            return;
        }
        if resident.phase() == Phase::Loading && !resident.page_ready() {
            if let Some(copy) = resident.page_copy() {
                if !resident.page_mapped() {
                    let record = self
                        .records
                        .get(index)
                        .expect("the reserved initial record");
                    if record.label.raw_at(1) == resident.key.label
                        && record.image == 1
                        && pages::Pages::map_prepared(index, &record.process, copy).is_ok()
                    {
                        assert!(resident.confirm_page_map());
                    }
                } else if controller::raw_close(copy.raw().0).is_ok() {
                    resident
                        .remove_page_copy()
                        .expect("the removed narrow owner")
                        .into_raw();
                    assert!(resident.confirm_page_settled());
                }
                return;
            }
        }
        if let Some((slot, memory, entry)) = resident.memory_validation() {
            match rt::sys::memory_info(memory) {
                Ok(info)
                    if info.size == u64::from(entry.pages) * 4096
                        && info.pages == u64::from(entry.pages) =>
                {
                    assert!(resident.memory_validated(slot));
                }
                Ok(_) => {
                    assert!(resident.ended(resident.key, Status::BadSize.code()));
                }
                Err(error) => {
                    assert!(resident.ended(resident.key, Status::Kernel(error).code()));
                }
            }
            return;
        }
        if resident.page_ready()
            && resident.memory_validation().is_none()
            && let Some(pending) = resident.operation_pending.as_mut()
        {
            let mut reply = proto_wire::Writer::new();
            reply
                .bytes(&[0; 8])
                .and_then(|()| {
                    proto_process::initial_identity::Query {
                        receipt: resident.publication.map.receipt,
                    }
                    .write(&mut reply)
                })
                .expect("the initial Stage receipt");
            if let Some(token) = pending.take_token() {
                match token.reply_handles(reply.as_bytes(), rt::handle::Outgoing::new()) {
                    Ok(()) => {
                        resident.settle_operation(false);
                    }
                    Err(mut refused) => {
                        assert!(
                            refused
                                .back
                                .as_ref()
                                .is_none_or(rt::handle::Outgoing::is_empty)
                        );
                        if let Some(token) = refused.token.take() {
                            assert!(pending.restore_token(token).is_ok());
                        } else {
                            resident.settle_operation(false);
                        }
                    }
                }
            } else {
                resident.settle_operation(false);
            }
            return;
        }
    }
}

fn receipt_reply(
    request: &mut Request<'_>,
    receipt: proto_process::initial_map::Receipt,
) -> Answer {
    proto_process::initial_ack::Reply { receipt }
        .write(request.reply())
        .expect("the fixed initial receipt reply");
    Answer::Reply(rt::handle::Outgoing::new())
}
