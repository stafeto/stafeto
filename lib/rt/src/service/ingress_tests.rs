// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Actual Received, Incoming, Token and dispatch with an injected syscall boundary.
use super::*;
use crate::sys::test_calls;
use abi::Call;
use std::vec::Vec;

#[derive(Default)]
struct Data {
    closing: bool,
}
#[derive(Default)]
struct Fixture {
    requests: usize,
    gone: usize,
    deferred: Option<Token>,
    mode: u8,
    tail_visits: u8,
    maintenance_visits: usize,
    overwrite_msgbuf: bool,
}
impl Service<0> for Fixture {
    const VERSION: u16 = 1;
    const METHODS: &'static [u16] = &[15, 34];
    const PLACED: usize = 320;
    const RETAIN_CLOSED: bool = true;
    const BOUNDED_INGRESS: bool = true;
    type Data = Data;
    fn place(&self, label: u64) -> Option<usize> {
        Some((label & 511) as usize)
    }
    fn closing(&self, s: &Session<Data, 0>) -> bool {
        s.data.closing
    }
    fn gone(&mut self, s: &mut Session<Data, 0>) {
        self.gone += 1;
        s.data.closing = true;
    }
    fn request_tail(&mut self, request: &mut Request<'_>) -> TailProgress {
        if self.overwrite_msgbuf {
            assert!(
                request.bytes()[HEADER_LEN..]
                    .iter()
                    .all(|byte| *byte == 0x39)
            );
            assert_eq!(
                request.handles.info(0),
                Some((
                    abi::ObjectKind::Memory,
                    abi::Rights::MAP_READ | abi::Rights::MAP_WRITE
                ))
            );
            assert_eq!(request.token.as_ref().unwrap().raw(), 123);
            assert_eq!(request.loan().unwrap()[8], u64::MAX);
        }
        if self.tail_visits == 0 {
            if let Some(words) = request.loan() {
                words[0] = 0;
            }
            return TailProgress::Idle;
        }
        self.tail_visits -= 1;
        let _ = sys::yield_now();
        if self.tail_visits == 0 {
            TailProgress::Detach
        } else {
            TailProgress::Continue
        }
    }
    fn request_maintenance(&mut self, _: &mut [Option<Session<Data, 0>>], protected: u64) {
        assert_eq!(protected, 0);
        self.maintenance_visits += 1;
        if self.overwrite_msgbuf {
            // An unrelated Process send reuses the kernel message buffer.
            crate::msgbuf::put_handles(&[abi::Handle::new(999, 1)]);
            crate::msgbuf::write(
                abi::msgbuf::INFO,
                &abi::msgbuf::info(abi::ObjectKind::Channel, abi::Rights::SEND).to_ne_bytes(),
            );
            assert!(sys::send(&Handle::borrowed(abi::Handle::new(99, 1)), &[0xa7; 96]).is_err());
        } else {
            let _ = sys::notify(&Handle::borrowed(abi::Handle::new(99, 1)), 1);
        }
    }
    fn request(&mut self, _: &mut Session<Data, 0>, r: &mut Request<'_>) -> Answer {
        self.requests += 1;
        match self.mode {
            1 => {
                self.deferred = r.token.take();
                Answer::Deferred
            }
            3 => {
                let _ = r.reply().u32(0);
                Answer::Reply(Outgoing::new())
            }
            2 => {
                let _ = r.reply().u32(0);
                let _ = r.reply().u32(7);
                Answer::Reply(Outgoing::new())
            }
            _ => Answer::Status(Status::BadSize),
        }
    }
}
fn caps(count: usize) -> Vec<abi::Handle> {
    (0..count)
        .map(|i| abi::Handle::new(i as u32 + 1, abi::Handle::MAX_GENERATION))
        .collect()
}
fn received(label: u64, bytes: &[u8], caps: &[abi::Handle]) -> Received {
    Received::Message {
        label,
        len: bytes.len(),
        handles: Incoming::fixture(caps),
        token: Token::fixture(123),
        words: abi::inline_words(bytes),
    }
}
fn dispatch<'a>(
    s: &mut Fixture,
    table: &mut [Option<Session<Data, 0>>],
    received: Received,
    bytes: &'a mut [u8; INLINE_MAX],
) -> CurrentRequest<'a> {
    let Received::Message {
        label,
        len,
        handles,
        token,
        words,
    } = received
    else {
        panic!()
    };
    bytes[..len].copy_from_slice(&abi::inline_bytes(&words)[..len]);
    let mut current = CurrentRequest::new(label, &bytes[..len], handles, token);
    request(s, table, 0, &mut current);
    current
}
fn step(s: &mut Fixture, current: &mut CurrentRequest<'_>) -> bool {
    let before = test_calls::log().len();
    let retry = current.step(s, &mut []);
    assert!(
        test_calls::log().len() - before <= 1,
        "combined kernel effects"
    );
    retry
}
fn settle(s: &mut Fixture, current: &mut CurrentRequest<'_>) {
    for _ in 0..20 {
        if !step(s, current) {
            test_calls::complete();
            return;
        }
    }
    panic!("nonterminal current loan");
}
fn assert_reply(status: Status) {
    let (_, regs) = test_calls::log().last().copied().unwrap();
    assert_eq!(regs[0], 123);
    assert_eq!(regs[1], proto_wire::HEADER_LEN as u64); // Exact existing application wire, zero handles.
    assert_eq!(regs[2], u64::from(status.code()));
}

#[test]
fn invalid_header_version_method_and_body_drain_all_four_before_reply() {
    for (bytes, status, called) in [
        (Vec::new(), Status::BadSize, false),
        (
            Header::new(15, 2).bytes().to_vec(),
            Status::BadVersion,
            false,
        ),
        (
            Header::new(999, 1).bytes().to_vec(),
            Status::UnknownMethod,
            false,
        ),
        (Header::new(15, 1).bytes().to_vec(), Status::BadSize, true),
        (Header::new(34, 1).bytes().to_vec(), Status::BadSize, true),
    ] {
        for count in 0..=4 {
            let caps = caps(count);
            test_calls::expect(
                (0..count)
                    .map(|_| (Call::HandleClose.number(), None))
                    .chain([(Call::Reply.number(), None)]),
            );
            let mut s = Fixture::default();
            let mut table = core::array::from_fn::<_, 320, _>(|_| None);
            let mut buffer = [0; INLINE_MAX];
            let mut current = dispatch(&mut s, &mut table, received(1, &bytes, &caps), &mut buffer);
            assert!(test_calls::log().is_empty(), "effect in admission");
            assert_eq!(s.requests, usize::from(called));
            for (index, cap) in caps.iter().enumerate() {
                assert!(step(&mut s, &mut current));
                assert_eq!(test_calls::log()[index].1[0], cap.0);
            }
            assert!(!step(&mut s, &mut current));
            assert_reply(status);
            test_calls::complete();
            drop(current); // Every Incoming entry is disarmed; unexpected Drop traps fail.
        }
    }
}

#[test]
fn full_320_session_collision_and_closing_refusal_keep_exact_owner() {
    for closing in [false, true] {
        let mut s = Fixture::default();
        let mut table = core::array::from_fn::<_, 320, _>(|i| {
            Some(Session::new(i as u64, Data { closing }, 0))
        });
        let label = if closing { 319 } else { 319 + 512 };
        let mut buffer = [0; INLINE_MAX];
        test_calls::expect(
            [(Call::HandleClose.number(), None); 4]
                .into_iter()
                .chain([(Call::Reply.number(), None)]),
        );
        let mut current = dispatch(
            &mut s,
            &mut table,
            received(label, &Header::new(15, 1).bytes(), &caps(4)),
            &mut buffer,
        );
        assert_eq!(s.requests, 0);
        assert_eq!(s.gone, usize::from(!closing));
        assert_eq!(table[319].as_ref().unwrap().label, 319);
        assert!(table.iter().all(Option::is_some));
        settle(&mut s, &mut current);
        assert_reply(Status::Kernel(if closing {
            Error::AccessDenied
        } else {
            Error::LimitReached
        }));
    }
}

#[test]
fn out_of_table_missing_session_uses_same_tail_without_allocating() {
    let mut s = Fixture::default();
    let mut table = core::array::from_fn::<_, 319, _>(|_| None);
    let mut buffer = [0; INLINE_MAX];
    test_calls::expect(
        [(Call::HandleClose.number(), None); 4]
            .into_iter()
            .chain([(Call::Reply.number(), None)]),
    );
    let mut current = dispatch(
        &mut s,
        &mut table,
        received(319, &Header::new(34, 1).bytes(), &caps(4)),
        &mut buffer,
    );
    settle(&mut s, &mut current);
    assert_reply(Status::Kernel(Error::LimitReached));
    assert!(table.iter().all(Option::is_none));
}

#[test]
fn failed_close_retains_exact_max_generation_owner_until_success() {
    let cap = caps(1)[0];
    test_calls::expect([
        (Call::HandleClose.number(), Some(Error::Unknown(998))),
        (Call::HandleClose.number(), None),
        (Call::Reply.number(), None),
    ]);
    let mut s = Fixture::default();
    let mut table = [None];
    let mut buffer = [0; INLINE_MAX];
    let mut current = dispatch(&mut s, &mut table, received(0, &[], &[cap]), &mut buffer);
    assert!(step(&mut s, &mut current));
    assert_eq!(current.held.as_ref().unwrap().raw(), cap);
    assert_eq!(current.request.token.as_ref().unwrap().raw(), 123);
    assert!(step(&mut s, &mut current));
    assert!(current.held.is_none());
    assert!(!step(&mut s, &mut current));
    assert_eq!(test_calls::log()[1].1[0], cap.0);
    test_calls::complete();
}

#[test]
fn canonical_reply_refusals_consume_or_retain_the_actual_token() {
    for error in [
        Error::BadState,
        Error::PeerClosed,
        Error::Unknown(997),
        Error::WouldBlock,
        Error::Interrupted,
        Error::NoMemory,
        Error::LimitReached,
    ] {
        let returned = error.keeps_handles() && error != Error::BadState;
        let mut expected = Vec::from([(Call::Reply.number(), Some(error))]);
        if returned {
            expected.push((Call::Reply.number(), None));
        }
        test_calls::expect(expected);
        let mut s = Fixture::default();
        let mut table = [None];
        let mut buffer = [0; INLINE_MAX];
        let mut current = dispatch(&mut s, &mut table, received(0, &[], &[]), &mut buffer);
        assert_eq!(step(&mut s, &mut current), returned);
        assert_eq!(
            current.request.token.as_ref().map(Token::raw),
            returned.then_some(123)
        );
        if returned {
            assert!(!step(&mut s, &mut current));
            assert_reply(Status::Kernel(error));
        } else {
            assert!(!step(&mut s, &mut current));
            assert_eq!(test_calls::log().len(), 1);
        }
        test_calls::complete();
    }
}

#[test]
fn returned_outgoing_drains_each_cap_before_separate_canonical_fallback() {
    test_calls::expect(
        [(Call::Reply.number(), Some(Error::WouldBlock))]
            .into_iter()
            .chain([(Call::HandleClose.number(), None); 4])
            .chain([(Call::Reply.number(), None)]),
    );
    let mut s = Fixture {
        mode: 2,
        ..Default::default()
    };
    let mut table = [None];
    let mut buffer = [0; INLINE_MAX];
    let mut current = dispatch(
        &mut s,
        &mut table,
        received(0, &Header::new(15, 1).bytes(), &[]),
        &mut buffer,
    );
    let caps = caps(4);
    for cap in &caps {
        current.outgoing.push(Handle::from_raw(*cap)).unwrap();
    }
    assert!(step(&mut s, &mut current));
    assert_eq!(test_calls::log()[0].1[1], 8 | 4 << abi::HANDLES_SHIFT);
    for cap in caps.iter().rev() {
        assert!(step(&mut s, &mut current));
        assert_eq!(test_calls::log().last().unwrap().1[0], cap.0);
    }
    assert!(!step(&mut s, &mut current));
    assert_reply(Status::Kernel(Error::WouldBlock));
    test_calls::complete();
}

#[test]
fn deferred_clone_token_and_successful_codec_stay_with_their_original_owner() {
    let mut s = Fixture {
        mode: 1,
        ..Default::default()
    };
    let mut table = [None];
    let mut buffer = [0; INLINE_MAX];
    test_calls::expect([(Call::HandleClose.number(), None); 4]);
    let mut current = dispatch(
        &mut s,
        &mut table,
        received(0, &Header::new(34, 1).bytes(), &caps(4)),
        &mut buffer,
    );
    settle(&mut s, &mut current);
    assert_eq!(s.deferred.as_ref().unwrap().raw(), 123);
    assert!(current.request.token.is_none());
    assert_eq!(test_calls::log().len(), 4);
    drop(current);
    // The retained Clone journal owns its original token and classifies its own reply.
    test_calls::expect([(Call::Reply.number(), Some(Error::Unknown(996)))]);
    let refused = s
        .deferred
        .take()
        .unwrap()
        .reply_handles(&proto_wire::reply(Status::Ok), Outgoing::new())
        .unwrap_err();
    assert!(refused.token.is_none());
    assert!(refused.back.is_none());
    assert_eq!(test_calls::log()[0].1[1], 8); // Existing CloneEffects status envelope.
    test_calls::complete();
    s.mode = 2;
    test_calls::expect([(Call::Reply.number(), None)]);
    let mut current = dispatch(
        &mut s,
        &mut table,
        received(0, &Header::new(15, 1).bytes(), &[]),
        &mut buffer,
    );
    settle(&mut s, &mut current);
    let (_, regs) = test_calls::log()[0];
    assert_eq!(regs[1], 8);
    assert_eq!(regs[2], 7 << 32);
}

#[test]
fn strict_bad_handle_fails_stop_with_the_exact_owner_still_held() {
    test_calls::expect([(Call::HandleClose.number(), Some(Error::BadHandle))]);
    let mut s = Fixture::default();
    let mut table = [None];
    let mut buffer = [0; INLINE_MAX];
    let cap = caps(1)[0];
    let mut current = dispatch(&mut s, &mut table, received(0, &[], &[cap]), &mut buffer);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || current.step(&mut s, &mut table)
        ))
        .is_err()
    );
    assert_eq!(current.held.as_ref().unwrap().raw(), cap);
    // The fixture resumes only to disarm before test teardown; production panic ends the process.
    test_calls::expect([
        (Call::HandleClose.number(), None),
        (Call::Reply.number(), None),
    ]);
    settle(&mut s, &mut current);
}

#[test]
fn service_loan_operation_and_detach_are_separate_from_ingress_drain() {
    test_calls::expect(
        [(Call::Yield.number(), None); 2]
            .into_iter()
            .chain([(Call::HandleClose.number(), None); 4])
            .chain([(Call::Reply.number(), None)]),
    );
    let mut s = Fixture {
        tail_visits: 2,
        ..Default::default()
    };
    let mut table = [None];
    let mut buffer = [0; INLINE_MAX];
    let mut current = dispatch(&mut s, &mut table, received(0, &[], &caps(4)), &mut buffer);
    settle(&mut s, &mut current);
    assert_reply(Status::BadSize);
}

#[test]
fn consumed_reply_back_drains_without_resurrecting_the_token_or_offer() {
    for error in [Error::BadState, Error::Unknown(991), Error::PeerClosed] {
        let kept = error.keeps_handles();
        test_calls::expect(
            [(Call::Reply.number(), Some(error))]
                .into_iter()
                .chain((0..if kept { 4 } else { 0 }).map(|_| (Call::HandleClose.number(), None))),
        );
        let mut s = Fixture {
            mode: 2,
            ..Default::default()
        };
        let mut table = [None];
        let mut buffer = [0; INLINE_MAX];
        let mut current = dispatch(
            &mut s,
            &mut table,
            received(0, &Header::new(15, 1).bytes(), &[]),
            &mut buffer,
        );
        for cap in caps(4) {
            current.outgoing.push(Handle::from_raw(cap)).unwrap();
        }
        assert_eq!(step(&mut s, &mut current), kept);
        assert!(current.request.token.is_none());
        settle(&mut s, &mut current);
        assert_eq!(
            test_calls::log()
                .iter()
                .filter(|(n, _)| *n == Call::Reply.number())
                .count(),
            1
        );
        assert!(current.outgoing.is_empty());
        test_calls::complete();
    }
}

#[test]
fn explicit_four_byte_writer_reply_preserves_its_existing_length() {
    test_calls::expect([(Call::Reply.number(), None)]);
    let mut s = Fixture {
        mode: 3,
        ..Default::default()
    };
    let mut table = [None];
    let mut buffer = [0; INLINE_MAX];
    let mut current = dispatch(
        &mut s,
        &mut table,
        received(0, &Header::new(15, 1).bytes(), &[]),
        &mut buffer,
    );
    settle(&mut s, &mut current);
    assert_eq!(test_calls::log()[0].1[1], 4);
}

#[test]
fn ongoing_loan_runs_distinct_fair_maintenance_before_each_fifo_yield_and_final_reply() {
    let mut service = Fixture {
        mode: 2,
        tail_visits: 3,
        ..Default::default()
    };
    let mut table = [None];
    let mut buffer = [0; INLINE_MAX];
    let mut loan = [0; 11];
    loan[0] = 1;
    let mut calls = Vec::new();
    for _ in 0..3 {
        calls.push((Call::Yield.number(), None)); // Actual loan operation.
        calls.push((Call::Notify.number(), None)); // Actual maintenance operation.
        calls.push((Call::Yield.number(), None)); // FIFO handoff.
    }
    calls.push((Call::Reply.number(), None));
    test_calls::expect(calls);
    let mut current = dispatch(
        &mut service,
        &mut table,
        received(0, &Header::new(15, 1).bytes(), &[]),
        &mut buffer,
    );
    current.request.loan = Some(&mut loan);
    current.finish(&mut service, &mut table, 15);
    assert_eq!(service.maintenance_visits, 3);
    assert!(current.request.token.is_none());
    assert_eq!(test_calls::log().last().unwrap().0, Call::Reply.number());
    test_calls::complete();
}

#[test]
fn process_maintenance_send_overwrites_kernel_buffer_while_current_bytes_caps_token_and_loan_stay_owned()
 {
    let mut service = Fixture {
        mode: 2,
        tail_visits: 2,
        overwrite_msgbuf: true,
        ..Default::default()
    };
    let mut table = [None];
    let mut bytes = [0x39; 96];
    bytes[..HEADER_LEN].copy_from_slice(&Header::new(15, 1).bytes());
    let original = abi::Handle::new(71, abi::Handle::MAX_GENERATION);
    crate::msgbuf::write(0, &bytes);
    crate::msgbuf::put_handles(&[original]);
    crate::msgbuf::write(
        abi::msgbuf::INFO,
        &abi::msgbuf::info(
            abi::ObjectKind::Memory,
            abi::Rights::MAP_READ | abi::Rights::MAP_WRITE,
        )
        .to_ne_bytes(),
    );
    // This is the production buffered receive capture: local bytes and owned Incoming arrays.
    let handles = Incoming::from_buffer(1);
    let mut buffer = [0; MESSAGE_MAX];
    crate::msgbuf::read(0, &mut buffer[..bytes.len()]);
    let mut loan = [0; 11];
    loan[0] = 1;
    loan[8] = u64::MAX;
    let mut current = CurrentRequest::new(0, &buffer[..bytes.len()], handles, Token::fixture(123));
    current.request.loan = Some(&mut loan);
    request(&mut service, &mut table, 0, &mut current);
    let mut calls = Vec::new();
    for _ in 0..2 {
        calls.push((Call::Yield.number(), None));
        calls.push((Call::Send.number(), Some(Error::PeerClosed)));
        calls.push((Call::Yield.number(), None));
    }
    calls.extend([
        (Call::HandleClose.number(), None),
        (Call::Yield.number(), None),
        (Call::Reply.number(), None),
    ]);
    test_calls::expect(calls);
    current.finish(&mut service, &mut table, 15);
    assert_eq!(current.request.bytes(), bytes);
    assert!(current.request.token.is_none());
    assert_eq!(
        test_calls::log()
            .iter()
            .find(|(call, _)| *call == Call::HandleClose.number())
            .unwrap()
            .1[0],
        original.0
    );
    assert_eq!(crate::msgbuf::handle(0).0, abi::Handle::new(999, 1));
    assert_eq!(current.request.loan().unwrap()[8], u64::MAX);
    test_calls::complete();
}

#[derive(Default)]
struct ReentryData {
    closing: bool,
    effects: usize,
}
#[derive(Default)]
struct ReentryFixture {
    requests: usize,
    visits: usize,
    maintenance: usize,
    place: usize,
}
impl Service<0> for ReentryFixture {
    const PLACED: usize = 2;
    const VERSION: u16 = 1;
    const METHODS: &'static [u16] = &[15];
    const RETAIN_CLOSED: bool = true;
    const BOUNDED_INGRESS: bool = true;
    type Data = ReentryData;
    fn place(&self, _: u64) -> Option<usize> {
        Some(self.place)
    }
    fn closing(&self, s: &Session<ReentryData, 0>) -> bool {
        s.data.closing
    }
    fn request_tail(&mut self, request: &mut Request<'_>) -> TailProgress {
        if request.loan().is_some_and(|words| words[0] != 0) {
            TailProgress::Reenter
        } else {
            TailProgress::Idle
        }
    }
    fn request_maintenance(
        &mut self,
        table: &mut [Option<Session<ReentryData, 0>>],
        protected: u64,
    ) {
        assert_eq!(protected, 0x8000_0001_0000_0000);
        self.maintenance += 1;
        // An unrelated owner progresses and its Process Send overwrites the kernel buffer.
        table[1].as_mut().unwrap().data.effects += 1;
        crate::msgbuf::write(0, &[0xa7; 96]);
        let _ = sys::send(&Handle::borrowed(abi::Handle::new(99, 1)), &[0xb7; 96]);
    }
    fn request(&mut self, s: &mut Session<ReentryData, 0>, request: &mut Request<'_>) -> Answer {
        assert_eq!(request.label(), 0x8000_0001_0000_0000);
        assert_eq!(request.body().u64(), Ok(0x3939_3939_3939_3939));
        assert_eq!(request.token.as_ref().unwrap().raw(), 123);
        self.requests += 1;
        if self.requests == 1 {
            let label = request.label();
            let words = request.loan().unwrap();
            words[0] = REENTER_TAG | 1;
            words[1] = label;
            words[REENTER_SLOT] = u64::MAX;
        } else {
            self.visits += 1;
            assert_eq!(request.loan().unwrap()[REENTER_SLOT], 0);
            if self.visits == 3 {
                s.data.effects += 1;
                request.loan().unwrap().fill(0);
                request.reply().u32(0).unwrap();
                request.reply().u32(7).unwrap();
            }
        }
        Answer::Reply(Outgoing::new())
    }
}

fn reentry_bytes() -> [u8; HEADER_LEN + 8] {
    let mut bytes = [0x39; HEADER_LEN + 8];
    bytes[..HEADER_LEN].copy_from_slice(&Header::new(15, 1).bytes());
    bytes
}

#[test]
fn reentry_resets_provisional_status_then_commits_once_with_exact_token() {
    test_calls::expect([(Call::Reply.number(), None)]);
    let bytes = reentry_bytes();
    let mut words = [0; 11];
    let mut current = CurrentRequest::new(
        0x8000_0001_0000_0000,
        &bytes,
        Incoming::fixture(&[]),
        Token::fixture(123),
    );
    current.request.loan = Some(&mut words);
    let mut service = ReentryFixture::default();
    let mut table = [None];
    request(&mut service, &mut table, 0, &mut current);
    current.status = Some(Status::Unknown(proto_fs::AUTHENTICATING));
    for _ in 0..3 {
        assert!(current.step(&mut service, &mut table));
        assert!(test_calls::log().is_empty());
        assert!(current.status.is_none());
    }
    assert_eq!(service.requests, 4);
    assert_eq!(table[0].as_ref().unwrap().data.effects, 1);
    assert!(!current.step(&mut service, &mut table));
    assert_eq!(service.requests, 4);
    let (_, regs) = test_calls::log()[0];
    assert_eq!((regs[0], regs[1], regs[2]), (123, 8, 7 << 32));
    test_calls::complete();
}

#[test]
fn reentry_never_creates_replaces_or_reopens_a_missing_foreign_or_closed_session() {
    for mode in 0..4 {
        test_calls::expect([(Call::Reply.number(), None)]);
        let bytes = reentry_bytes();
        let mut words = [0; 11];
        let mut current = CurrentRequest::new(
            0x8000_0001_0000_0000,
            &bytes,
            Incoming::fixture(&[]),
            Token::fixture(123),
        );
        current.request.loan = Some(&mut words);
        let mut service = ReentryFixture::default();
        let mut table = [None, None];
        request(&mut service, &mut table, 0, &mut current);
        assert!(current.step(&mut service, &mut table));
        match mode {
            0 => table[0] = None,
            1 => {
                table[0] = Some(Session::new(
                    0x8000_0002_0000_0000,
                    ReentryData::default(),
                    0,
                ))
            }
            2 => table[0].as_mut().unwrap().data.closing = true,
            _ => {
                service.place = 1;
                table[1] = Some(Session::new(
                    0x8000_0001_0000_0000,
                    ReentryData::default(),
                    0,
                ));
            }
        }
        assert!(current.step(&mut service, &mut table));
        assert_eq!(service.requests, 2);
        assert!(
            current
                .request
                .loan()
                .unwrap()
                .iter()
                .all(|word| *word == 0)
        );
        assert!(!current.step(&mut service, &mut table));
        assert_reply(Status::Kernel(Error::AccessDenied));
        if mode == 0 {
            assert!(table[0].is_none());
        }
        if mode == 1 {
            assert_eq!(table[0].as_ref().unwrap().label(), 0x8000_0002_0000_0000);
        }
        assert!(table.iter().flatten().all(|s| s.data.effects == 0));
        test_calls::complete();
    }
}

#[test]
fn reentry_fair_visits_preserve_local_request_while_other_owner_send_overwrites_msgbuf() {
    test_calls::expect(
        [
            (Call::Send.number(), Some(Error::Unknown(77))),
            (Call::Yield.number(), None),
        ]
        .into_iter()
        .cycle()
        .take(4)
        .chain([(Call::Yield.number(), None), (Call::Reply.number(), None)]),
    );
    let bytes = reentry_bytes();
    let mut words = [0; 11];
    let mut current = CurrentRequest::new(
        0x8000_0001_0000_0000,
        &bytes,
        Incoming::fixture(&[]),
        Token::fixture(123),
    );
    current.request.loan = Some(&mut words);
    let mut service = ReentryFixture::default();
    let mut table = [None, Some(Session::new(9, ReentryData::default(), 0))];
    request(&mut service, &mut table, 0, &mut current);
    current.finish(&mut service, &mut table, 15);
    assert_eq!(service.maintenance, 2);
    assert_eq!(table[1].as_ref().unwrap().data.effects, 2);
    assert_eq!(table[0].as_ref().unwrap().data.effects, 1);
    test_calls::complete();
}

#[test]
fn reentry_rejects_consumed_token_and_each_nonpristine_owner_without_discarding_them() {
    for mode in 0..7 {
        test_calls::expect([]);
        let bytes = reentry_bytes();
        let mut words = [0; 11];
        let mut current = CurrentRequest::new(
            0x8000_0001_0000_0000,
            &bytes,
            Incoming::fixture(&[]),
            Token::fixture(123),
        );
        current.request.loan = Some(&mut words);
        let mut service = ReentryFixture::default();
        let mut table = [None];
        request(&mut service, &mut table, 0, &mut current);
        let cap = abi::Handle::new(91, 1);
        match mode {
            0 => current.request.token = None,
            1 => current.held = Some(Handle::from_raw(cap)),
            2 => current.outgoing.push(Handle::from_raw(cap)).unwrap(),
            3 => current.drain_back = true,
            4 => current.cursor = 1,
            5 => current.request.handles = Incoming::fixture(&[cap]),
            _ => {
                current.request.reply().u32(991).unwrap();
            }
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || current.step(&mut service, &mut table)
            ))
            .is_err()
        );
        assert_eq!(service.requests, 1);
        assert!(test_calls::log().is_empty());
        match mode {
            0 => assert!(current.request.token.is_none()),
            1 => {
                assert_eq!(current.held.as_ref().unwrap().raw(), cap);
                current.held.take().unwrap().into_raw();
            }
            2 => {
                assert_eq!(current.outgoing.pop().unwrap().into_raw(), cap);
            }
            3 => assert!(current.drain_back),
            4 => assert_eq!(current.cursor, 1),
            5 => {
                assert_eq!(current.request.handles.take_any(0).unwrap().into_raw(), cap);
            }
            _ => {
                assert_eq!(
                    current.request.reply.as_ref().unwrap().as_bytes(),
                    &991u32.to_le_bytes()
                );
            }
        }
        test_calls::complete();
    }
}
