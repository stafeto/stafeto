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
    fn request_tail(&mut self, _: &mut Request<'_>) -> TailProgress {
        if self.tail_visits == 0 {
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
    request(s, table, 0, label, &bytes[..len], handles, token).unwrap()
}
fn step(s: &mut Fixture, current: &mut CurrentRequest<'_>) -> bool {
    let before = test_calls::log().len();
    let retry = current.step(s);
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
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| current.step(&mut s))).is_err()
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
