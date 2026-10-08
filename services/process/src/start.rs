// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Resident cold-start phases. Each invocation visits one existing work slot.

use super::*;

impl Processes {
    pub(super) fn prepare_step(&mut self) {
        let index = usize::from(self.preparing_cursor);
        self.preparing_cursor = ((index + 1) % RECORDS) as u16;
        let Some(work) = self.replacing[index].as_ref().and_then(Work::preparing) else {
            return;
        };
        let key = work.key();
        let phase = work.phase();
        if phase == PreparePhase::Kill {
            self.prepare_kill(index, key);
            return;
        }
        if phase == PreparePhase::Close {
            self.prepare_close(index, key);
            return;
        }
        if let Err(error) = self.prepare_effect(index, key, phase) {
            let work = self.replacing[index]
                .as_mut()
                .and_then(Work::preparing_mut)
                .expect("an exact preparation");
            let requires_stop =
                work.resources.process.is_some() || self.records.get(index).is_some();
            work.cancel(key, Status::Kernel(error).code(), requires_stop);
        }
    }

    fn prepare_effect(
        &mut self,
        index: usize,
        key: preparing::Key,
        phase: PreparePhase,
    ) -> Result<(), abi::Error> {
        let work = self.replacing[index]
            .as_mut()
            .and_then(Work::preparing_mut)
            .ok_or(abi::Error::BadState)?;
        if work.key() != key {
            return Err(abi::Error::BadState);
        }
        let PrepareKind::Initial { create } = work.kind else {
            return Err(abi::Error::BadState);
        };
        match phase {
            PreparePhase::Admission => {
                match work.copy_cursor {
                    0 => {
                        let exit = records::exit_place(key.label, &create, self.level);
                        work.resources.exit = Some(sys::handle_label(
                            &self.channel,
                            Rights::NOTIFY,
                            exit.label,
                            exit.slot,
                        )?);
                    }
                    1 => {
                        work.resources.session = Some(sys::handle_label(
                            &self.channel,
                            Rights::SEND | Rights::TRANSFER,
                            key.label.raw(),
                            self.level,
                        )?)
                    }
                    2 => {
                        work.resources.who = Some(sys::handle_label(
                            &self.identities,
                            Rights::NOTIFY | Rights::TRANSFER | Rights::DUPLICATE,
                            key.label.identity(),
                            self.level,
                        )?)
                    }
                    _ => {
                        work.copy_cursor = 0;
                        assert!(work.advance(key, phase));
                        return Ok(());
                    }
                }
                work.copy_cursor += 1;
            }
            PreparePhase::Process => {
                if work.copy_cursor == 0 {
                    let exit = work.resources.exit.as_ref().ok_or(abi::Error::BadState)?;
                    let start = work.resources.start.take();
                    match sys::process_create_with(
                        create.quota,
                        create.handle_limit,
                        create.ceiling,
                        Some((exit, create.ceiling)),
                        start,
                    ) {
                        Ok(process) => work.resources.process = Some(process),
                        Err((error, start)) => {
                            work.resources.start = start;
                            return Err(error);
                        }
                    }
                    work.copy_cursor = 1;
                } else {
                    let process = work
                        .resources
                        .process
                        .as_ref()
                        .ok_or(abi::Error::BadState)?;
                    work.resources.copy = Some(sys::handle_duplicate(
                        process,
                        Rights::MANAGE | Rights::DUPLICATE | Rights::TRANSFER,
                    )?);
                    work.copy_cursor = 0;
                    assert!(work.advance(key, phase));
                }
            }
            PreparePhase::PageMemory => match self.pages.claim(index, key) {
                GroupClaim::Waiting => {}
                GroupClaim::Mapped => {
                    assert!(work.advance(key, phase));
                    assert!(work.advance(key, PreparePhase::PageOwnMap));
                }
                GroupClaim::Owned => {
                    work.resources.data = Some(pages::Pages::create_group()?);
                    assert!(work.advance(key, phase));
                }
            },
            PreparePhase::PageOwnMap => {
                self.pages
                    .map_group(&make::own(), index, key, &mut work.resources.data)?;
                assert!(work.advance(key, phase));
            }
            PreparePhase::PageInit => {
                self.pages.initialize(index, work.identity)?;
                assert!(work.advance(key, phase));
            }
            PreparePhase::PageTargetMap => {
                match work.copy_cursor {
                    0 => work.resources.narrow = Some(self.pages.narrow(index)?),
                    1 => {
                        let process = work
                            .resources
                            .process
                            .as_ref()
                            .ok_or(abi::Error::BadState)?;
                        let narrow = work.resources.narrow.as_ref().ok_or(abi::Error::BadState)?;
                        pages::Pages::map_prepared(index, process, narrow)?;
                    }
                    2 => {
                        let narrow = work.resources.narrow.take().ok_or(abi::Error::BadState)?;
                        narrow.close()?;
                        work.copy_cursor = 0;
                        assert!(work.advance(key, phase));
                        return Ok(());
                    }
                    _ => return Err(abi::Error::BadState),
                }
                work.copy_cursor += 1;
            }
            PreparePhase::Reply => {
                if let Some(exit) = work.resources.exit.take() {
                    // The process retains its exit source. Close the temporary
                    // owner before the reply makes Loaded and Exec admissible.
                    exit.close()?;
                    return Ok(());
                }
                return self.publish_initial(index, key);
            }
            _ => return Err(abi::Error::BadState),
        }
        Ok(())
    }

    fn publish_initial(&mut self, index: usize, key: preparing::Key) -> Result<(), abi::Error> {
        let work = self.replacing[index]
            .as_mut()
            .and_then(Work::preparing_mut)
            .ok_or(abi::Error::BadState)?;
        let PrepareKind::Initial { create } = work.kind else {
            return Err(abi::Error::BadState);
        };
        let credentials = if create.root {
            Credentials::ROOT
        } else {
            Credentials::NOBODY
        };
        let reservation = work.reservation.take().ok_or(abi::Error::BadState)?;
        let process = work.resources.process.take().ok_or(abi::Error::BadState)?;
        let result = self.records.consume_reserved(
            reservation,
            process,
            None,
            credentials,
            create.ceiling,
            Join::Inherit,
        );
        if let Err(refused) = result {
            work.reservation = Some(refused.reservation);
            work.resources.process = Some(refused.process);
            return Err(abi::Error::BadState);
        }
        let record = self
            .records
            .get_mut(index)
            .expect("the consumed initial record");
        record.quota = create.quota;
        record.limits = proto_process::ResourceLimits::initial(create.quota);
        record.handle_limit = create.handle_limit;
        self.witnesses[index] = work.resources.witness.take();
        self.tickets[index] = create.ticket;
        self.generations.raise(index);
        let mut bytes = Writer::new();
        bytes
            .u32(0)
            .and_then(|()| bytes.u32(key.label.pid()))
            .and_then(|()| bytes.u64(key.label.raw()))
            .expect("the fixed initial reply");
        let copy = work
            .resources
            .copy
            .take()
            .expect("the prepaid process transfer");
        let session = work
            .resources
            .session
            .take()
            .expect("the prepaid record session");
        let who = work
            .resources
            .who
            .take()
            .expect("the prepaid identity session");
        let pending = work.pending.take().expect("the original Create request");
        let accepted = pending
            .answer(
                bytes.as_bytes(),
                [copy.erase(), session.erase(), who.erase()],
            )
            .is_ok();
        if accepted {
            assert!(work.cancel(key, 0, false));
            assert!(work.finish_cleanup(key));
            // Every owner has crossed its transfer or close boundary. The
            // empty slot becomes available before the next request dispatch.
            self.replacing[index] = None;
            self.preparing_count -= 1;
        } else {
            work.cancel(key, Status::Kernel(abi::Error::PeerClosed).code(), true);
        }
        self.publish_groups(index);
        Ok(())
    }

    fn prepare_kill(&mut self, index: usize, key: preparing::Key) {
        let Some(work) = self.replacing[index].as_mut().and_then(Work::preparing_mut) else {
            return;
        };
        let target = work
            .resources
            .process
            .as_ref()
            .or_else(|| self.records.get(index).map(|record| &record.process));
        let Some(target) = target else {
            return;
        };
        let level = match work.kind {
            PrepareKind::Initial { create } => create.ceiling.min(self.level),
            _ => self.level,
        };
        if sys::process_kill_at(target, level).is_ok() {
            work.stopped(key);
        }
    }

    fn prepare_close(&mut self, index: usize, key: preparing::Key) {
        let Some(work) = self.replacing[index].as_mut().and_then(Work::preparing_mut) else {
            return;
        };
        if let Some(cap) = work.cleanup_one(key) {
            // The returned owner is dropped after its resident borrow ends.
            drop(cap);
            return;
        }
        self.pages.cancel_group(index, key);
        if let Some(reservation) = work.reservation.take() {
            if let Err(reservation) = self.records.cancel_reserved(reservation) {
                work.reservation = Some(reservation);
            }
            return;
        }
        if let Some(pending) = work.pending.take() {
            let status = Status::from_code(
                work.error()
                    .unwrap_or(Status::Kernel(abi::Error::BadState).code()),
            );
            let _ = pending.answer(&proto_wire::reply(status), Outgoing::new());
            return;
        }
        if work.finish_cleanup(key) {
            self.replacing[index] = None;
            self.preparing_count -= 1;
        }
    }
}
