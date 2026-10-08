// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Resident cold-start phases. Each invocation visits one existing work slot.

use super::*;

impl Processes {
    fn empty_loader(fork: bool, ceiling: u8) -> Held {
        Held {
            thread: None,
            ready: None,
            start: None,
            incoming: None,
            fork,
            exec: ExecCustody::new(),
            outcome: crate::LoaderOutcome::None,
            abort_ceiling: ceiling,
            abort_cursor: 0,
        }
    }

    pub(super) fn prepare_child(
        &mut self,
        parent_index: usize,
        mut birth: Birth,
        r: &mut Request<'_>,
    ) -> Answer {
        if self.replacing[parent_index]
            .as_ref()
            .and_then(Work::initial)
            .is_some_and(|resident| !resident.user_ready())
        {
            return kernel(abi::Error::BadState);
        }
        if self.loader.is_none() || self.files.is_none() {
            return refuse(proto_process::NOT_FOUND);
        }
        let Some(parent) = self.records.start_parent(parent_index) else {
            return refuse(proto_process::NO_PROCESS);
        };
        if !self.records.may_spawn(parent_index) || !self.loaders.room_for(parent_index) {
            return refuse(proto_process::AGAIN);
        }
        let Some(label) = self.records.next_label() else {
            return refuse(proto_process::AGAIN);
        };
        let index = usize::from(label.index);
        if self.replacing[index].is_some() || self.loaders.of(index).is_some() {
            return refuse(proto_process::AGAIN);
        }
        if !self.generations.room(index, 4) {
            self.records.retire_next(label);
            return refuse(proto_process::AGAIN);
        }
        let Some(join) = self
            .records
            .joining(parent_index, birth.flags, birth.pgroup, label.pid())
        else {
            return refuse(proto_process::PERMISSION);
        };
        let record = self.records.get(parent_index).expect("a captured parent");
        if !loaders::pool_allows(free_quota(), record.quota) {
            return kernel(abi::Error::NoMemory);
        }
        let ceiling = record.ceiling;
        let ctty = if matches!(join, Join::NewSession) {
            None
        } else {
            record.ctty.filter(|&(terminal, generation)| {
                self.terminals
                    .link(terminal as usize)
                    .is_some_and(|link| link.sid == record.sid && link.generation == generation)
            })
        };
        let identity = [
            label.pid(),
            parent.label().pid(),
            match join {
                Join::Inherit => record.pgid,
                Join::Group(group) => group,
                _ => label.pid(),
            },
            if matches!(join, Join::NewSession) {
                label.pid()
            } else {
                record.sid
            },
        ];
        if let PageStart::Spawn { mask, default } = birth.page {
            let ignored = self.pages.page(parent_index).map_or(0, |page| {
                page.ignored.load(core::sync::atomic::Ordering::Acquire)
            }) & !default;
            birth.page = PageStart::PreparedSpawn { mask, ignored };
        }
        let fork = matches!(birth.page, PageStart::Fork { .. });
        let priority = birth.level.clamp(1, ceiling);
        let Some(pending) = r.defer() else {
            return refuse(proto_process::AGAIN);
        };
        let reservation = self.records.reserve_next().expect("a preflighted record");
        self.loaders
            .take_preparing(index, parent_index, 1, Self::empty_loader(fork, ceiling))
            .unwrap_or_else(|_| unreachable!("the preflighted loader credits remain free"));
        let key = preparing::Key { label, image: 1 };
        let mut work = NativePreparation::new(
            key,
            PrepareKind::Child {
                birth: preparing::Birth {
                    flags: birth.flags,
                    pgroup: birth.pgroup,
                    level: birth.level,
                    credentials: birth.credentials,
                    page: birth.page,
                },
                join,
                ctty: ctty.map(|(terminal, generation)| (terminal as u16, generation)),
            },
            preparing::Origin {
                parent: Some(parent),
                credentials_generation: self.generations.get(parent_index),
            },
            priority,
            pending,
        );
        work.reservation = Some(reservation);
        work.identity = identity;
        self.replacing[index] = Some(Work::Preparing(work));
        self.preparing_count += 1;
        self.kick();
        Answer::Deferred
    }

    pub(super) fn prepare_exec(
        &mut self,
        index: usize,
        start: SpawnStart,
        r: &mut Request<'_>,
    ) -> Answer {
        let Some(parent) = self.records.start_parent(index) else {
            return refuse(proto_process::NO_PROCESS);
        };
        let record = self.records.get(index).expect("a captured image");
        if self.loaders.of(index).is_some()
            || self.replacing[index].is_some()
            || !self.loaders.room_for(index)
            || record.tried >= proto_process::IMAGE_MAX
            || !self.generations.live_room(index, 3)
        {
            return refuse(proto_process::AGAIN);
        }
        if !loaders::pool_allows(free_quota(), record.quota) {
            return kernel(abi::Error::NoMemory);
        };
        let key = preparing::Key {
            label: record.label,
            image: record.tried + 1,
        };
        let priority = start.level.clamp(1, record.ceiling);
        let ceiling = record.ceiling;
        let replace_serial = if self.tickets[index] != 0 {
            let Some(serial) = self.replacer.prepay() else {
                return refuse(proto_process::AGAIN);
            };
            serial
        } else {
            0
        };
        let Some(pending) = r.defer() else {
            return refuse(proto_process::AGAIN);
        };
        self.loaders
            .take_preparing(index, index, key.image, Self::empty_loader(false, ceiling))
            .unwrap_or_else(|_| unreachable!("the preflighted loader credits remain free"));
        self.records
            .get_mut(index)
            .expect("the captured image")
            .tried = key.image;
        let work = NativePreparation::new(
            key,
            PrepareKind::Exec {
                mask: start.mask,
                replace_serial,
            },
            preparing::Origin {
                parent: Some(parent),
                credentials_generation: self.generations.get(index),
            },
            priority,
            pending,
        );
        self.replacing[index] = Some(Work::Preparing(work));
        self.preparing_count += 1;
        self.kick();
        Answer::Deferred
    }

    fn prepare_create(&self, index: usize, key: preparing::Key) -> Result<Create, abi::Error> {
        let work = self.replacing[index]
            .as_ref()
            .and_then(Work::preparing)
            .ok_or(abi::Error::BadState)?;
        if work.key() != key {
            return Err(abi::Error::BadState);
        };
        if let PrepareKind::Initial { create, .. } = work.kind {
            return Ok(create);
        };
        let parent = work.origin.parent.ok_or(abi::Error::BadState)?;
        let parent_index = usize::from(parent.label().index);
        if self.records.start_parent(parent_index) != Some(parent)
            || self.generations.get(parent_index) != work.origin.credentials_generation
        {
            return Err(abi::Error::PeerClosed);
        }
        let record = self.records.get(parent_index).ok_or(abi::Error::BadState)?;
        if let PrepareKind::Child {
            ref birth, join, ..
        } = work.kind
            && (work.reservation.is_some() && !self.records.may_spawn(parent_index)
                || self
                    .records
                    .joining(parent_index, birth.flags, birth.pgroup, key.label.pid())
                    != Some(join))
        {
            return Err(abi::Error::BadState);
        }
        Ok(Create {
            quota: record.quota,
            handle_limit: record.handle_limit,
            ceiling: record.ceiling,
            priority: work.priority,
            root: false,
            ticket: 0,
        })
    }

    pub(super) fn prepare_step(&mut self) {
        let index = usize::from(self.preparing_cursor);
        self.preparing_cursor = ((index + 1) % RECORDS) as u16;
        if self.replacing[index]
            .as_ref()
            .and_then(Work::initial)
            .is_some()
        {
            self.initial_step(index);
            return;
        }
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
            let requires_stop = work.resources.process.is_some()
                || self
                    .records
                    .get(index)
                    .is_some_and(|record| record.image == key.image);
            work.cancel(key, Status::Kernel(error).code(), requires_stop);
        }
    }

    fn prepare_effect(
        &mut self,
        index: usize,
        key: preparing::Key,
        phase: PreparePhase,
    ) -> Result<(), abi::Error> {
        let create = self.prepare_create(index, key)?;
        let work = self.replacing[index]
            .as_mut()
            .and_then(Work::preparing_mut)
            .ok_or(abi::Error::BadState)?;
        if work.key() != key {
            return Err(abi::Error::BadState);
        }
        match phase {
            PreparePhase::Admission => {
                match work.copy_cursor {
                    0 => {
                        let exit = records::ExitPlace {
                            label: key.label.exit_at(key.image),
                            slot: create.ceiling,
                            notice: create.ceiling,
                        };
                        work.resources.exit = Some(sys::handle_label(
                            &self.channel,
                            Rights::NOTIFY,
                            exit.label,
                            exit.slot,
                        )?);
                    }
                    1 => {
                        let label = if matches!(work.kind, PrepareKind::Initial { .. }) {
                            key.label.raw()
                        } else {
                            key.label.loader_at(key.image)
                        };
                        work.resources.start = if matches!(work.kind, PrepareKind::Initial { .. }) {
                            work.resources.start.take()
                        } else {
                            Some(sys::handle_label(
                                &self.channel,
                                Rights::SEND | Rights::TRANSFER,
                                label,
                                self.level,
                            )?)
                        };
                        if matches!(work.kind, PrepareKind::Initial { .. }) {
                            work.resources.session = Some(sys::handle_label(
                                &self.channel,
                                Rights::SEND | Rights::TRANSFER,
                                label,
                                self.level,
                            )?);
                        }
                    }
                    2 if matches!(work.kind, PrepareKind::Initial { .. }) => {
                        work.resources.who = Some(sys::handle_label(
                            &self.identities,
                            Rights::NOTIFY | Rights::TRANSFER | Rights::DUPLICATE,
                            key.label.identity(),
                            self.level,
                        )?)
                    }
                    2 => {
                        let parent = work.origin.parent.ok_or(abi::Error::BadState)?;
                        let parent_index = usize::from(parent.label().index);
                        let slot = self.loaders.of(index).ok_or(abi::Error::BadState)?;
                        let held =
                            &mut self.loaders.get_mut(slot).ok_or(abi::Error::BadState)?.held;
                        if held.fork {
                            held.exec.fork_source = match self
                                .records
                                .get(parent_index)
                                .and_then(|record| record.active_exec.as_ref())
                            {
                                Some(source) => Some(sys::handle_duplicate(
                                    source,
                                    Rights::SEND | Rights::DUPLICATE | Rights::TRANSFER,
                                )?),
                                None => None,
                            };
                        }
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
                } else if matches!(work.kind, PrepareKind::Initial { .. }) {
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
                } else {
                    work.copy_cursor = 0;
                    assert!(work.advance(key, phase));
                    if matches!(work.kind, PrepareKind::Exec { .. }) {
                        assert!(work.advance(key, PreparePhase::PageMemory));
                        assert!(work.advance(key, PreparePhase::PageOwnMap));
                        assert!(work.advance(key, PreparePhase::PageInit));
                    }
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
                if let PrepareKind::Child { ref birth, .. } = work.kind {
                    let parent = work.origin.parent.ok_or(abi::Error::BadState)?;
                    let from = self
                        .pages
                        .page(usize::from(parent.label().index))
                        .ok_or(abi::Error::BadState)?;
                    birth
                        .page
                        .write(self.pages.page(index).ok_or(abi::Error::BadState)?, from);
                }
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
            PreparePhase::Code | PreparePhase::Rodata => {
                let image = self.loader.as_ref().ok_or(abi::Error::BadState)?;
                let part = if phase == PreparePhase::Code {
                    bootimg::Part::Code
                } else {
                    bootimg::Part::Rodata
                };
                let (offset, len, at, access) = image.shared_mapping(part);
                if len == 0 {
                    assert!(work.advance(key, phase));
                    return Ok(());
                };
                match work.copy_cursor {
                    0 => work.resources.narrow = Some(image.narrow_shared(part)?),
                    1 => {
                        let process = work
                            .resources
                            .process
                            .as_ref()
                            .ok_or(abi::Error::BadState)?;
                        let narrow = work.resources.narrow.as_ref().ok_or(abi::Error::BadState)?;
                        sys::mem_map(process, narrow, offset, len, at, access)?;
                    }
                    2 => {
                        work.resources
                            .narrow
                            .take()
                            .ok_or(abi::Error::BadState)?
                            .close()?;
                        work.copy_cursor = 0;
                        assert!(work.advance(key, phase));
                        return Ok(());
                    }
                    _ => return Err(abi::Error::BadState),
                }
                work.copy_cursor += 1;
            }
            PreparePhase::DataMemory => {
                work.resources.data = Some(sys::mem_create(
                    self.loader.as_ref().ok_or(abi::Error::BadState)?.data_len(),
                )?);
                assert!(work.advance(key, phase));
            }
            PreparePhase::DataOwnMap => {
                if self.window_owner.is_some_and(|(owner, _)| owner != key) {
                    return Ok(());
                };
                let memory = work.resources.data.as_ref().ok_or(abi::Error::BadState)?;
                let len = self.loader.as_ref().ok_or(abi::Error::BadState)?.data_len();
                self.window_owner = Some((key, 0));
                let mapped = sys::mem_map(
                    &make::own(),
                    memory,
                    0,
                    len,
                    loader::WINDOW,
                    Access::ReadWrite,
                );
                if let Err(error) = mapped {
                    // These refusals precede mapping insertion in add_mapping.
                    // Other outcomes retain the exact owner for cleanup.
                    if matches!(error, abi::Error::NoMemory | abi::Error::LimitReached) {
                        self.window_owner = None;
                    }
                    return Err(error);
                }
                assert!(work.advance(key, phase));
            }
            PreparePhase::DataCopy => {
                if self.window_owner != Some((key, work.copy_cursor)) {
                    return Err(abi::Error::BadState);
                };
                let bytes = self
                    .loader
                    .as_ref()
                    .ok_or(abi::Error::BadState)?
                    .data_bytes();
                let cursor = usize::from(work.copy_cursor);
                let remaining = bytes.get(cursor..).ok_or(abi::Error::BadState)?;
                let count = remaining.len().min(4096);
                // SAFETY: the exact resident owner maps this private object at WINDOW.
                // The source is immutable boot memory; no slice of WINDOW escapes this step.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        remaining.as_ptr(),
                        (loader::WINDOW + cursor) as *mut u8,
                        count,
                    )
                };
                work.copy_cursor =
                    u16::try_from(cursor + count).map_err(|_| abi::Error::BadState)?;
                self.window_owner = Some((key, work.copy_cursor));
                if cursor + count == bytes.len() {
                    assert!(work.advance(key, phase))
                };
            }
            PreparePhase::DataUnmap => {
                if self.window_owner != Some((key, work.copy_cursor)) {
                    return Err(abi::Error::BadState);
                };
                unsafe {
                    sys::mem_unmap(
                        &make::own(),
                        loader::WINDOW,
                        self.loader.as_ref().ok_or(abi::Error::BadState)?.data_len(),
                    )
                }?;
                self.window_owner = None;
                work.copy_cursor = 0;
                assert!(work.advance(key, phase));
            }
            PreparePhase::DataTargetMap => {
                let image = self.loader.as_ref().ok_or(abi::Error::BadState)?;
                match work.copy_cursor {
                    0 => {
                        work.resources.narrow = Some(sys::handle_duplicate(
                            work.resources.data.as_ref().ok_or(abi::Error::BadState)?,
                            Access::ReadWrite.rights(),
                        )?)
                    }
                    1 => sys::mem_map(
                        work.resources
                            .process
                            .as_ref()
                            .ok_or(abi::Error::BadState)?,
                        work.resources.narrow.as_ref().ok_or(abi::Error::BadState)?,
                        0,
                        image.data_len(),
                        image.data_at(),
                        Access::ReadWrite,
                    )?,
                    2 => work
                        .resources
                        .narrow
                        .take()
                        .ok_or(abi::Error::BadState)?
                        .close()?,
                    3 => {
                        work.resources
                            .data
                            .take()
                            .ok_or(abi::Error::BadState)?
                            .close()?;
                        work.copy_cursor = 0;
                        assert!(work.advance(key, phase));
                        return Ok(());
                    }
                    _ => return Err(abi::Error::BadState),
                }
                work.copy_cursor += 1;
            }
            PreparePhase::Thread => return self.prepare_thread(index, key, create),
            PreparePhase::Start => return self.prepare_start(index, key),
            PreparePhase::Reply => {
                if matches!(
                    work.kind,
                    PrepareKind::Initial {
                        admission: Some(_),
                        ..
                    }
                ) && work.resources.exit.is_some()
                {
                    if !crate::close_owned(&mut work.resources.exit) {
                        return Err(abi::Error::BadState);
                    }
                    return Ok(());
                }
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

    fn prepare_thread(
        &mut self,
        index: usize,
        key: preparing::Key,
        create: Create,
    ) -> Result<(), abi::Error> {
        let work = self.replacing[index]
            .as_mut()
            .and_then(Work::preparing_mut)
            .ok_or(abi::Error::BadState)?;
        match work.copy_cursor {
            0 => {
                if let PrepareKind::Child {
                    ref birth,
                    join,
                    ctty,
                } = work.kind
                {
                    if self.births.key().is_some() {
                        return Ok(());
                    }
                    let reservation = work.reservation.take().ok_or(abi::Error::BadState)?;
                    let process = work.resources.process.take().ok_or(abi::Error::BadState)?;
                    if let Err(refused) = self.records.consume_reserved(
                        reservation,
                        process,
                        work.origin.parent,
                        birth.credentials,
                        create.ceiling,
                        join,
                    ) {
                        work.reservation = Some(refused.reservation);
                        work.resources.process = Some(refused.process);
                        return Err(abi::Error::BadState);
                    }
                    let record = self.records.get_mut(index).ok_or(abi::Error::BadState)?;
                    record.quota = create.quota;
                    record.handle_limit = create.handle_limit;
                    record.ctty =
                        ctty.map(|(terminal, generation)| (u32::from(terminal), generation));
                    self.generations.raise(index);
                    self.publish_groups(index);
                    self.capture_newborn(key);
                }
            }
            1 => {
                if self.births.key() == Some(key) {
                    self.newborn_step(key)?;
                    return Ok(());
                }
                let work = self.replacing[index]
                    .as_mut()
                    .and_then(Work::preparing_mut)
                    .ok_or(abi::Error::BadState)?;
                let image = self.loader.as_ref().ok_or(abi::Error::BadState)?;
                let process = work
                    .resources
                    .process
                    .as_ref()
                    .or_else(|| {
                        self.records
                            .get(index)
                            .filter(|record| record.image == key.image)
                            .map(|record| &record.process)
                    })
                    .ok_or(abi::Error::BadState)?;
                work.resources.thread = Some(rt::loader::thread_at(
                    process,
                    image.entry(),
                    image.data_at() as u64 + image.data_len(),
                    u64::from(work.priority),
                    work.priority,
                    abi::Policy::RoundRobin,
                )?);
            }
            2 => work
                .resources
                .exit
                .take()
                .ok_or(abi::Error::BadState)?
                .close()?,
            3 => {
                work.copy_cursor = 0;
                assert!(work.advance(key, PreparePhase::Thread));
                return Ok(());
            }
            _ => return Err(abi::Error::BadState),
        }
        self.replacing[index]
            .as_mut()
            .and_then(Work::preparing_mut)
            .ok_or(abi::Error::BadState)?
            .copy_cursor += 1;
        Ok(())
    }

    fn prepare_start(&mut self, index: usize, key: preparing::Key) -> Result<(), abi::Error> {
        let work = self.replacing[index]
            .as_mut()
            .and_then(Work::preparing_mut)
            .ok_or(abi::Error::BadState)?;
        if let PrepareKind::Exec { mask, .. } = work.kind {
            self.pages
                .page(index)
                .ok_or(abi::Error::BadState)?
                .start_mask
                .store(mask, core::sync::atomic::Ordering::Release);
        }
        let slot = self.loaders.of(index).ok_or(abi::Error::BadState)?;
        let place = self.loaders.get_mut(slot).ok_or(abi::Error::BadState)?;
        if place.stage != Stage::Preparing || place.image != key.image {
            return Err(abi::Error::BadState);
        };
        place.held.thread = work.resources.thread.take();
        place.held.start = work.pending.take();
        if matches!(work.kind, PrepareKind::Exec { .. }) {
            place.held.incoming = work.resources.process.take()
        };
        if let PrepareKind::Exec { replace_serial, .. } = work.kind {
            place.held.outcome = crate::LoaderOutcome::Serial(replace_serial);
        }
        self.loaders
            .begin_boot(index)
            .map_err(|_| abi::Error::BadState)?;
        let thread = self
            .loaders
            .get(slot)
            .and_then(|place| place.held.thread.as_ref())
            .ok_or(abi::Error::BadState)?;
        let result = sys::thread_start(thread);
        if let Err(error) = result {
            if self.loaders.begin_abort(index) == Ok(true) {
                self.abort_cleanup += 1
            };
            self.loaders
                .get_mut(slot)
                .ok_or(abi::Error::BadState)?
                .held
                .abort(Status::Kernel(error));
        }
        assert!(work.cancel(key, 0, false));
        assert!(work.finish_cleanup(key));
        self.replacing[index] = None;
        self.preparing_count -= 1;
        Ok(())
    }

    fn publish_initial(&mut self, index: usize, key: preparing::Key) -> Result<(), abi::Error> {
        let work = self.replacing[index]
            .as_mut()
            .and_then(Work::preparing_mut)
            .ok_or(abi::Error::BadState)?;
        let PrepareKind::Initial { create, admission } = work.kind else {
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
        let initial_receipt = proto_process::initial_map::Receipt {
            key: proto_process::initial_map::Key {
                key: create.ticket,
                image: 1,
            },
            label: key.label.raw_at(1),
            pid: key.label.pid(),
            init_ticket: create.ticket,
        };
        if let Some(admission) = admission {
            use posix_process_service::initial_origin::{InitialOrigin, SourceOrigin};
            record.source_origin = SourceOrigin::boot(
                admission.source.artifact,
                admission.source.canonical.is_none(),
            )
            .expect("validated initial artifact");
            assert!(record.set_initial_origin(
                create.ticket,
                InitialOrigin::new(admission.source.artifact, 0).expect("initial flags"),
            ));
        }
        let mut bytes = Writer::new();
        if admission.is_some() {
            bytes
                .u32(0)
                .and_then(|()| bytes.u32(key.label.pid()))
                .and_then(|()| bytes.u64(key.label.raw()))
                .and_then(|()| {
                    proto_process::initial_identity::Query {
                        receipt: initial_receipt,
                    }
                    .write(&mut bytes)
                })
                .expect("the reserved initial receipt");
        } else {
            bytes
                .u32(0)
                .and_then(|()| bytes.u32(key.label.pid()))
                .and_then(|()| bytes.u64(key.label.raw()))
                .expect("the fixed initial reply");
        }
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
        let returned = [copy.raw(), session.raw(), who.raw()];
        let answer = if admission.is_some() {
            let pending = work
                .pending
                .as_mut()
                .expect("the retained CreateInitial request");
            let token = pending.take_token().expect("the original initial token");
            token.reply_handles(
                bytes.as_bytes(),
                [copy.erase(), session.erase(), who.erase()],
            )
        } else {
            work.pending
                .take()
                .expect("the original Create request")
                .answer(
                    bytes.as_bytes(),
                    [copy.erase(), session.erase(), who.erase()],
                )
        };
        let failure = match answer {
            Ok(()) => None,
            Err(mut refused) => {
                if admission.is_some()
                    && let Some(token) = refused.token.take()
                {
                    assert!(
                        work.pending
                            .as_mut()
                            .expect("initial pending")
                            .restore_token(token)
                            .is_ok()
                    );
                }
                if let Some(back) = refused.back.take() {
                    // The reply returns the complete original transfer on a
                    // refusal that keeps handles. Keep Drop disarmed while
                    // checking this exact tuple, including a fail-stop path.
                    let mut back = ManuallyDrop::new(back);
                    assert_eq!(back.len(), returned.len(), "the full initial transfer");
                    let who = ManuallyDrop::new(back.pop().expect("the returned identity"));
                    assert_eq!(who.raw(), returned[2], "the exact initial identity");
                    work.resources.who =
                        Some(Handle::from_raw(ManuallyDrop::into_inner(who).into_raw()));
                    let session = ManuallyDrop::new(back.pop().expect("the returned session"));
                    assert_eq!(session.raw(), returned[1], "the exact initial session");
                    work.resources.session = Some(Handle::from_raw(
                        ManuallyDrop::into_inner(session).into_raw(),
                    ));
                    let copy = ManuallyDrop::new(back.pop().expect("the returned process"));
                    assert_eq!(copy.raw(), returned[0], "the exact initial process");
                    work.resources.copy =
                        Some(Handle::from_raw(ManuallyDrop::into_inner(copy).into_raw()));
                }
                Some(refused.error)
            }
        };
        if let Some(error) = failure {
            work.cancel(key, Status::Kernel(error).code(), true);
        } else {
            work.pending.take(); // Its bounded token has crossed the Reply boundary.
            assert!(work.cancel(key, 0, false));
            assert!(work.finish_cleanup(key));
            // Every owner has crossed its transfer or close boundary. The
            // empty slot becomes available before the next request dispatch.
            if let Some(admission) = admission {
                let mut resident = crate::NativeInitial::reserved(
                    posix_process_service::initial_resident::SeedKey {
                        epoch: 0,
                        ticket: create.ticket,
                        label: key.label.raw_at(1),
                    },
                    initial_receipt,
                    admission.source,
                )
                .expect("the immutable reserved receipt");
                assert!(resident.awaiting_guard());
                self.replacing[index] = Some(Work::Initial(resident));
            } else {
                self.replacing[index] = None;
                self.preparing_count -= 1;
            }
        }
        self.publish_groups(index);
        Ok(())
    }

    fn prepare_kill(&mut self, index: usize, key: preparing::Key) {
        let Some(work) = self.replacing[index].as_mut().and_then(Work::preparing_mut) else {
            return;
        };
        let target = work.resources.process.as_ref().or_else(|| {
            self.records
                .get(index)
                .filter(|record| record.image == key.image)
                .map(|record| &record.process)
        });
        let Some(target) = target else {
            return;
        };
        let level = match work.kind {
            PrepareKind::Initial { create, .. } => create.ceiling.min(self.level),
            _ => self
                .loaders
                .of(index)
                .and_then(|slot| self.loaders.get(slot))
                .map_or(self.level, |place| place.held.abort_ceiling.min(self.level)),
        };
        if sys::process_kill_at(target, level).is_ok() {
            work.stopped(key);
        }
    }

    fn prepare_close(&mut self, index: usize, key: preparing::Key) {
        if self.births.key() == Some(key) {
            let _ = self.newborn_step(key);
            return;
        }
        if self.window_owner.is_some_and(|(owner, _)| owner == key) {
            let Some(image) = self.loader.as_ref() else {
                return;
            };
            if unsafe { sys::mem_unmap(&make::own(), loader::WINDOW, image.data_len()) }.is_ok() {
                self.window_owner = None;
            }
            return;
        }
        let Some(work) = self.replacing[index].as_mut().and_then(Work::preparing_mut) else {
            return;
        };
        if let Some(cap) = work.cleanup_one(key) {
            // The returned owner is dropped after its resident borrow ends.
            drop(cap);
            return;
        }
        self.pages.cancel_group(index, key);
        if self
            .loaders
            .of(index)
            .and_then(|slot| self.loaders.get(slot))
            .is_some_and(|place| place.image == key.image && place.stage == Stage::Preparing)
        {
            drop(self.loaders.free(index));
            return;
        }
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
            if self
                .records
                .get(index)
                .is_some_and(|record| record.state.end_pending())
            {
                self.start_ending(index, None);
            }
        }
    }
}
