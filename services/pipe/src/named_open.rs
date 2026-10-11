// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::*;
use pipe::{NamedInode, admissions::Admissions};
use proto_pipe::{
    BrokerCancel, BrokerPrepare, Endpoint, NamedPhase, NamedReply, NamedTicket, RAM_BROKER,
};

fn reply(r: &mut Request<'_>, value: NamedReply, outgoing: Option<Handle<Channel>>) -> Answer {
    if let Err(error) = value.write(r.reply()) {
        return Answer::Status(error);
    }
    Answer::Reply(outgoing.map_or_else(Outgoing::new, |h| [h.erase()].into()))
}
fn absent(ticket: NamedTicket) -> NamedReply {
    NamedReply {
        ticket,
        phase: NamedPhase::Cancelled,
        result: 0,
        endpoint: Endpoint::default(),
    }
}

impl PipeService {
    pub(super) fn named_room(&self) -> bool {
        self.ops.counts().0 + self.named.count() < OPERATIONS
    }
    fn named_answer(&self, ticket: NamedTicket, r: &mut Request<'_>, cap: bool) -> Answer {
        let Some(record) = self.named.get(ticket) else {
            return status(proto_pipe::BAD_FD);
        };
        let outgoing = if cap && matches!(record.phase, NamedPhase::Witness | NamedPhase::Grant) {
            match record
                .handle
                .as_ref()
                .ok_or(Error::BadState)
                .and_then(|h| sys::handle_duplicate(h, Rights::TRANSFER))
            {
                Ok(handle) => Some(handle),
                Err(error) => return Answer::Status(Status::Kernel(error)),
            }
        } else {
            None
        };
        reply(r, record.reply(ticket), outgoing)
    }
    fn named_free(&mut self, ticket: NamedTicket, release: bool) {
        if let Some(record) = self.named.free(ticket) {
            if release && record.endpoint.is_named() {
                let mut wakes = Wakes::default();
                let _ = self.pipes.cancel_named(record.endpoint, &mut wakes);
                self.tell(&wakes);
            }
            self.roots.give(record.root, 1);
        }
    }
    pub(super) fn named_cleanup(&mut self) -> bool {
        if let Some(ticket) = self.named.cleanup_ticket() {
            self.named_free(ticket, true);
        }
        self.named.cleanup_due()
    }
    pub(super) fn named_tell(&mut self, label: u64, key: u64) -> bool {
        let Some(ticket) = Admissions::<Handle<Channel>>::from_waiter(label, key) else {
            return false;
        };
        let Some(record) = self.named.get(ticket) else {
            return true;
        };
        let endpoint = record.endpoint;
        if record.phase == NamedPhase::Waiting && self.pipes.named_ready(endpoint).unwrap_or(false)
        {
            if let Ok(end) = self.pipes.queue_end(endpoint) {
                self.pipes.unwait(end, (label, key));
            }
            self.named.get_mut(ticket).unwrap().phase = NamedPhase::Ready;
        }
        if let Some(record) = self.named.get(ticket)
            && record.phase == NamedPhase::Ready
            && let Some(handle) = record.handle.as_ref()
        {
            let _ = sys::notify(handle, 1);
        }
        true
    }
    fn cancel_candidate(&mut self, ticket: NamedTicket) {
        let Some(record) = self.named.get(ticket) else {
            return;
        };
        if matches!(record.phase, NamedPhase::Failed | NamedPhase::Cancelled) {
            return;
        }
        let endpoint = record.endpoint;
        if endpoint.is_named() {
            if let Ok(end) = self.pipes.queue_end(endpoint) {
                self.pipes
                    .unwait(end, Admissions::<Handle<Channel>>::waiter(ticket));
            }
            let mut wakes = Wakes::default();
            let _ = self.pipes.cancel_named(endpoint, &mut wakes);
            self.tell(&wakes);
        }
        let record = self.named.get_mut(ticket).unwrap();
        record.phase = NamedPhase::Cancelled;
        record.endpoint = Endpoint::default();
        record.handle = None;
    }
    fn witness(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let open = match NamedTicket::parse(r.body()) {
            Ok(key) if key.is_open_key() && r.handles.is_empty() => key,
            _ => return Answer::Status(Status::BadSize),
        };
        if let Some(ticket) = self.named.find(s.label(), open) {
            return self.named_answer(ticket, r, true);
        }
        if !self.named_room() {
            return status(proto_pipe::AGAIN);
        }
        if s.data.held.count() + self.named.reservations(s.label()) >= HELD_MAX {
            return status(proto_pipe::MFILE);
        }
        if let Err(code) = self.roots.take(s.data.root) {
            return status(code);
        }
        let Some(ticket) = self.named.give(s.label(), s.data.root, open) else {
            self.roots.give(s.data.root, 1);
            return status(proto_pipe::AGAIN);
        };
        let cap = self
            .named
            .fresh_label()
            .ok_or(Error::LimitReached)
            .and_then(|label| {
                sys::handle_label(
                    &self.channel,
                    Rights::DUPLICATE | Rights::TRANSFER,
                    label,
                    self.level,
                )
                .map(|handle| (label, handle))
            });
        match cap {
            Ok((label, handle)) => {
                let record = self.named.get_mut(ticket).unwrap();
                record.cap_label = label;
                record.handle = Some(handle);
                self.named_answer(ticket, r, true)
            }
            Err(error) => {
                self.named_free(ticket, true);
                Answer::Status(Status::Kernel(error))
            }
        }
    }
    fn prepare(&mut self, r: &mut Request<'_>) -> Answer {
        if r.label() & (RAM_BROKER | OWN) != RAM_BROKER {
            return status(proto_pipe::BAD_FD);
        }
        let body = match BrokerPrepare::parse(r.body()) {
            Ok(body) => body,
            Err(error) => return Answer::Status(error),
        };
        let Some(record) = self.named.get(body.ticket) else {
            return status(proto_pipe::BAD_FD);
        };
        if let Some(capture) = record.capture {
            if record.broker != r.label() || capture != body || !r.handles.is_empty() {
                return status(proto_pipe::INVALID);
            }
            return self.named_answer(body.ticket, r, true);
        }
        if record.phase != NamedPhase::Witness || record.open != body.open || r.handles.len() != 1 {
            return status(proto_pipe::INVALID);
        }
        if !matches!(r.handles.info(0),Some((rt::abi::ObjectKind::Channel,rights)) if rights == Rights::TRANSFER)
        {
            return Answer::Status(Status::BadSize);
        }
        let offered = match r.handles.take::<Channel>(0) {
            Ok(h) => h,
            Err(e) => return Answer::Status(Status::Kernel(e)),
        };
        if sys::copy_label(&self.channel, &offered).ok() != Some(record.cap_label) {
            return status(proto_pipe::BAD_FD);
        }
        let (creator, root) = (record.creator, record.root);
        let record = self.named.get_mut(body.ticket).unwrap();
        record.capture = Some(body);
        record.broker = r.label();
        record.handle = None;
        let endpoint = self.pipes.reserve_named(
            NamedInode {
                broker: r.label(),
                inode: body.inode,
            },
            creator,
            root,
            body.flags,
        );
        match endpoint {
            Err(code) => {
                let record = self.named.get_mut(body.ticket).unwrap();
                record.phase = NamedPhase::Failed;
                record.result = code;
            }
            Ok(endpoint) => {
                let record = self.named.get_mut(body.ticket).unwrap();
                record.endpoint = endpoint;
                let cap = self
                    .named
                    .fresh_label()
                    .ok_or(Error::LimitReached)
                    .and_then(|label| {
                        sys::handle_label(
                            &self.channel,
                            Rights::DUPLICATE | Rights::TRANSFER,
                            label,
                            self.level,
                        )
                        .map(|h| (label, h))
                    });
                match cap {
                    Ok((label, handle)) => {
                        let record = self.named.get_mut(body.ticket).unwrap();
                        record.cap_label = label;
                        record.handle = Some(handle);
                        record.phase = NamedPhase::Grant;
                    }
                    Err(error) => {
                        let mut wakes = Wakes::default();
                        let _ = self.pipes.cancel_named(endpoint, &mut wakes);
                        self.tell(&wakes);
                        let record = self.named.get_mut(body.ticket).unwrap();
                        record.phase = NamedPhase::Failed;
                        record.result = Status::Kernel(error).code();
                        record.endpoint = Endpoint::default();
                    }
                }
            }
        }
        self.named_answer(body.ticket, r, true)
    }
    fn broker_cancel(&mut self, r: &mut Request<'_>) -> Answer {
        if r.label() & (RAM_BROKER | OWN) != RAM_BROKER || !r.handles.is_empty() {
            return status(proto_pipe::BAD_FD);
        }
        let body = match BrokerCancel::parse(r.body()) {
            Ok(v) => v,
            Err(e) => return Answer::Status(e),
        };
        if let Some(ticket) = self.named.broker_ticket(r.label(), body.client, body.open) {
            self.cancel_candidate(ticket);
        }
        words(r, &[])
    }
    pub(super) fn named_request(
        &mut self,
        s: &mut Session<Client, 0>,
        r: &mut Request<'_>,
        method: Method,
    ) -> Answer {
        match method {
            Method::PayerWitness => return self.witness(s, r),
            Method::BrokerPrepare => return self.prepare(r),
            Method::BrokerCancel => return self.broker_cancel(r),
            _ => {}
        }
        let ticket = match NamedTicket::parse(r.body()) {
            Ok(v) => v,
            Err(e) => return Answer::Status(e),
        };
        let Some(record) = self.named.get(ticket) else {
            if !r.handles.is_empty() {
                return Answer::Status(Status::BadSize);
            }
            if let Some(endpoint) = self.pipes.ack_endpoint(&s.data.held, s.label(), ticket) {
                if method == Method::NamedCancel {
                    let mut wakes = Wakes::default();
                    let _ = self
                        .pipes
                        .close_endpoint(&mut s.data.held, endpoint, &mut wakes);
                    self.tell(&wakes);
                    return reply(r, absent(ticket), None);
                }
                if matches!(
                    method,
                    Method::NamedAck | Method::NamedQuery | Method::NamedTake
                ) {
                    return reply(
                        r,
                        NamedReply {
                            ticket,
                            phase: NamedPhase::Taken,
                            result: 0,
                            endpoint,
                        },
                        None,
                    );
                }
            }
            return if matches!(method, Method::NamedCancel | Method::NamedAck) {
                reply(r, absent(ticket), None)
            } else {
                status(proto_pipe::BAD_FD)
            };
        };
        if record.owner != s.label() {
            return status(proto_pipe::BAD_FD);
        }
        let endpoint = record.endpoint;
        match method {
            Method::NamedAttach => {
                if r.handles.len() != 1
                    || !matches!(r.handles.info(0),Some((rt::abi::ObjectKind::Channel,rights)) if rights==Rights::TRANSFER)
                {
                    return Answer::Status(Status::BadSize);
                }
                let offered = match r.handles.take::<Channel>(0) {
                    Ok(h) => h,
                    Err(e) => return Answer::Status(Status::Kernel(e)),
                };
                if sys::copy_label(&self.channel, &offered).ok() != Some(record.cap_label) {
                    return status(proto_pipe::BAD_FD);
                }
                if record.phase == NamedPhase::Grant {
                    self.named.get_mut(ticket).unwrap().handle = None;
                    let mut wakes = Wakes::default();
                    let result = self.pipes.attach_named(endpoint, &mut wakes);
                    match result {
                        Ok(true) => self.named.get_mut(ticket).unwrap().phase = NamedPhase::Ready,
                        Ok(false) => {
                            let end = self.pipes.queue_end(endpoint).unwrap();
                            let ops = &self.ops;
                            let named = &self.named;
                            match self.pipes.wait(
                                end,
                                Admissions::<Handle<Channel>>::waiter(ticket),
                                |(l, k)| ops.waits(l, k) || named.alive(l, k),
                            ) {
                                Ok(()) => {
                                    self.named.get_mut(ticket).unwrap().phase = NamedPhase::Waiting
                                }
                                Err(code) => {
                                    self.cancel_candidate(ticket);
                                    let record = self.named.get_mut(ticket).unwrap();
                                    record.phase = NamedPhase::Failed;
                                    record.result = code;
                                }
                            }
                        }
                        Err(code) => {
                            self.cancel_candidate(ticket);
                            let record = self.named.get_mut(ticket).unwrap();
                            record.phase = NamedPhase::Failed;
                            record.result = code;
                        }
                    }
                    self.tell(&wakes);
                }
            }
            Method::NamedQuery => {
                if r.handles.len() > 1 {
                    return Answer::Status(Status::BadSize);
                }
                if !r.handles.is_empty() {
                    if !matches!(r.handles.info(0),Some((rt::abi::ObjectKind::Channel,rights)) if rights.contains(Rights::NOTIFY))
                    {
                        return Answer::Status(Status::BadSize);
                    }
                    let notify = match r.handles.take::<Channel>(0) {
                        Ok(h) => h,
                        Err(e) => return Answer::Status(Status::Kernel(e)),
                    };
                    if self
                        .named
                        .get(ticket)
                        .is_some_and(|r| matches!(r.phase, NamedPhase::Waiting | NamedPhase::Ready))
                    {
                        self.named.get_mut(ticket).unwrap().handle = Some(notify);
                    }
                }
                let (label, key) = Admissions::<Handle<Channel>>::waiter(ticket);
                self.named_tell(label, key);
            }
            Method::NamedTake => {
                if !r.handles.is_empty() {
                    return Answer::Status(Status::BadSize);
                }
                if record.phase == NamedPhase::Ready {
                    self.named.get_mut(ticket).unwrap().phase = NamedPhase::Taken;
                }
            }
            Method::NamedCancel => {
                if !r.handles.is_empty() {
                    return Answer::Status(Status::BadSize);
                }
                self.cancel_candidate(ticket);
            }
            Method::NamedAck => {
                if !r.handles.is_empty() {
                    return Answer::Status(Status::BadSize);
                }
                let phase = record.phase;
                if !matches!(
                    phase,
                    NamedPhase::Taken | NamedPhase::Failed | NamedPhase::Cancelled
                ) {
                    return status(proto_pipe::INVALID);
                }
                let value = record.reply(ticket);
                let owner = s.label();
                if phase == NamedPhase::Taken
                    && let Err(code) =
                        self.pipes
                            .ack_named(&mut s.data.held, owner, ticket, endpoint)
                {
                    return status(code);
                }
                self.named_free(ticket, false);
                return reply(r, value, None);
            }
            _ => return Answer::Status(Status::UnknownMethod),
        }
        self.named_answer(ticket, r, false)
    }
}
