// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Private diagnostics on authenticated current process and owned child records.

use super::*;

impl Processes {
    pub(super) fn image_probe_request(&mut self, index: usize, r: &mut Request<'_>) -> Answer {
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        match r.method() {
            image_probe::ARM => {
                if r.body().finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let Some(slot) = self.loaders.of(index) else {
                    return refuse(proto_process::PERMISSION);
                };
                let Some(place) = self.loaders.get(slot) else {
                    return refuse(proto_process::PERMISSION);
                };
                let record = self.records.get(index).expect("the current caller");
                let ticket = self.loaders.ticket(slot);
                if record.state != State::Alive
                    || place.parent != index
                    || place.stage != Stage::Loading
                    || place.held.incoming.is_none()
                    || place.image == record.image
                    || !sys::process_state(&record.process)
                        .is_ok_and(|state| state == abi::ProcessState::Alive)
                    || (record.image_probe.ticket != ticket && place.set_id.is_some())
                {
                    return refuse(proto_process::PERMISSION);
                }
                let (image, pid) = (place.image, record.label.pid());
                if self
                    .records
                    .get_mut(index)
                    .expect("the caller")
                    .image_probe
                    .arm(ticket, image)
                    .is_err()
                {
                    return refuse(proto_process::PERMISSION);
                }
                let w = r.reply();
                if w.u32(0)
                    .and_then(|()| w.u32(0))
                    .and_then(|()| w.u64(ticket))
                    .and_then(|()| w.u32(image))
                    .and_then(|()| w.u32(pid))
                    .is_err()
                {
                    return Answer::Status(Status::BadSize);
                }
            }
            image_probe::TRACE => {
                let mut body = r.body();
                let (Ok(ticket), Ok(())) = (body.u64(), body.finish()) else {
                    return Answer::Status(Status::BadSize);
                };
                let record = self.records.get(index).expect("the current caller");
                let observation = record.image_probe;
                if ticket == 0 || ticket != observation.ticket {
                    return refuse(proto_process::PERMISSION);
                }
                let place = self
                    .loaders
                    .of(index)
                    .filter(|&slot| self.loaders.ticket(slot) == ticket)
                    .and_then(|slot| self.loaders.get(slot))
                    .filter(|place| place.image == observation.image);
                let pending = place.and_then(|place| place.set_id);
                let counts = place.map_or(observation.counts, |place| place.image_probe_counts);
                let (uid, gid) = pending.unwrap_or((proto_process::NO_ID, proto_process::NO_ID));
                let native_alive = sys::process_state(&record.process)
                    .is_ok_and(|state| state == abi::ProcessState::Alive);
                let fields = [
                    record.label.pid(),
                    observation.image,
                    record.image,
                    counts.attempts,
                    counts.successes,
                    observation.terminal as u32,
                    u32::from(place.is_some()),
                    u32::from(pending.is_some()),
                    uid,
                    gid,
                    u32::from(place.is_some_and(|place| place.held.incoming.is_some())),
                    u32::from(native_alive),
                ];
                let credentials = record.credentials.words();
                let w = r.reply();
                if w.u32(0)
                    .and_then(|()| w.u32(0))
                    .and_then(|()| w.u64(ticket))
                    .is_err()
                    || fields
                        .iter()
                        .chain(&credentials)
                        .any(|&field| w.u32(field).is_err())
                {
                    return Answer::Status(Status::BadSize);
                }
            }
            image_probe::CHILD_HANDOFF => {
                let mut body = r.body();
                let (Ok(pid), Ok(())) = (body.u32(), body.finish()) else {
                    return Answer::Status(Status::BadSize);
                };
                let Some(child) = self.records.find_pid(pid).filter(|&child| {
                    self.records
                        .get(child)
                        .is_some_and(|record| record.parent_index == Some(index as u16))
                }) else {
                    return refuse(proto_process::PERMISSION);
                };
                let record = self.records.get(child).expect("the owned child");
                let native_alive = sys::process_state(&record.process)
                    .is_ok_and(|state| state == abi::ProcessState::Alive);
                let (image, ticket) = (
                    record.image,
                    record.loader_ticket(self.tickets[child]).unwrap_or(0),
                );
                let fields = [
                    u32::from(native_alive),
                    u32::from(record.state == State::Alive),
                    u32::from(self.loaders.of(child).is_some()),
                    0,
                ];
                let credentials = record.credentials.words();
                let w = r.reply();
                if w.u32(0)
                    .and_then(|()| w.u32(0))
                    .and_then(|()| w.u32(pid))
                    .and_then(|()| w.u32(image))
                    .and_then(|()| w.u64(ticket))
                    .is_err()
                    || fields
                        .iter()
                        .chain(&credentials)
                        .any(|&field| w.u32(field).is_err())
                {
                    return Answer::Status(Status::BadSize);
                }
            }
            _ => return Answer::Status(Status::UnknownMethod),
        }
        Answer::Reply(Outgoing::new())
    }

    pub(super) fn abort_ended_load(&mut self, child: usize, status: Status) {
        let ticket = self.loaders.of(child).map(|slot| self.loaders.ticket(slot));
        self.abort_load(child, status);
        if let Some(ticket) = ticket
            && self.loaders.of(child).is_none()
            && let Some(record) = self.records.get_mut(child)
            && record.image_probe.ticket == ticket
            && record.image_probe.terminal == Terminal::Aborted
        {
            record.image_probe.terminal = Terminal::Ended;
        }
    }
}
