// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exercise the production picker against retained IPC and independent local debt.
use super::*;

#[test]
fn physical_rotation_pays_later_local_debts_without_finishing_earlier_rpc() {
    let (mut files, entry, _, control_input) = fixture();
    let foreign = OwnerToken::new(2).unwrap();
    let mut tokens = [None; crate::WAIT_RECORDS];
    let mut claims = [None; crate::WAIT_RECORDS];
    for slot in 0..crate::WAIT_RECORDS {
        let who = if slot == 9 { foreign } else { owner() };
        let frame = Frame::main(if slot == 10 { 300 } else { 100 });
        let (token, claim) = files.begin_wait_record(who, entry, frame, input()).unwrap();
        assert_eq!(token.slot(), slot);
        tokens[slot] = Some(token);
        claims[slot] = Some(claim);
    }
    let early = tokens[0].unwrap();
    let skipped = tokens[11].unwrap();
    let ready = tokens[14].unwrap();
    let channel = tokens[15].unwrap();
    // Holes are physical places, not a compact array of the remaining records.
    for slot in [1, 2, 3, 4, 5, 6, 7, 8, 12, 13] {
        let token = tokens[slot].unwrap();
        saved_cleanup(&mut files, token);
        files.ack_wait_record(token, owner()).unwrap();
    }
    saved_cleanup(&mut files, ready);
    files
        .attach_wait_channel(claims[15].unwrap(), 0xabcdef1234560007)
        .unwrap();
    saved_cleanup(&mut files, channel);
    let (_, control) = files
        .begin_lock_record(owner(), entry, Frame::main(100), control_input)
        .unwrap();
    let me = Some(owner());
    let current = Frame::main(200);
    let skip = Some(skipped);
    assert_eq!(
        files.pick_wait_cleanup_from(me, current, skip, 0),
        Ok(Some(early))
    );
    let unpaid = files.wait_snapshot(early).unwrap();
    assert_eq!(unpaid.phase, WaitRecordPhase::Cleaning);
    assert_eq!(unpaid.result, None);
    // Model a refused Send by leaving exactly this real production journal unpaid.
    assert_eq!(
        files.pick_wait_cleanup_from(me, current, skip, early.slot() + 1),
        Ok(Some(channel))
    );
    assert!(
        files.wait_snapshot(ready).is_err(),
        "later local-only ack is not starved"
    );
    let debt = files.wait_channel_debt(channel).unwrap().unwrap();
    assert_eq!(debt.raw(), 0xabcdef1234560007);
    files.confirm_wait_channel_closed(debt).unwrap();
    assert_eq!(
        files.pick_wait_cleanup_from(me, current, skip, channel.slot() + 1),
        Ok(Some(early))
    );
    assert_eq!(
        files.pick_wait_cleanup_from(me, current, skip, early.slot() + 1),
        Ok(Some(early))
    );
    assert!(
        files.wait_snapshot(channel).is_err(),
        "paid channel permits later local ack"
    );
    assert_eq!(
        files.wait_snapshot(early).unwrap(),
        unpaid,
        "earlier RPC remains unpaid and immutable"
    );
    assert!(
        files.wait_is_live(claims[9].unwrap()),
        "foreign live owner protected"
    );
    assert!(
        files.wait_is_live(claims[10].unwrap()),
        "nested live owner protected"
    );
    assert!(
        files.wait_is_live(claims[11].unwrap()),
        "exact skipped generation protected"
    );
    assert!(
        files.lock_is_live(control),
        "ordinary Control family is untouched"
    );
}

#[test]
fn physical_cursor_wraps_over_holes_and_stale_skip_does_not_hide_reused_slot() {
    let (mut files, entry, _, _) = fixture();
    let mut tokens = [None; crate::WAIT_RECORDS];
    for (slot, target) in tokens.iter_mut().enumerate() {
        *target = Some(
            files
                .begin_wait_record(owner(), entry, Frame::main(100), input())
                .unwrap()
                .0,
        );
        assert_eq!(target.unwrap().slot(), slot);
    }
    let early = tokens[0].unwrap();
    let last = tokens[15].unwrap();
    for token in tokens[1..15].iter().flatten().copied() {
        saved_cleanup(&mut files, token);
        files.ack_wait_record(token, owner()).unwrap();
    }
    assert_eq!(
        files.pick_wait_cleanup_from(Some(owner()), Frame::main(200), None, usize::MAX),
        Ok(Some(last))
    );
    assert_eq!(
        files.pick_wait_cleanup_from(Some(owner()), Frame::main(200), None, last.slot() + 1),
        Ok(Some(early))
    );
    saved_cleanup(&mut files, last);
    files.ack_wait_record(last, owner()).unwrap();
    let (reused, claim) = files
        .begin_wait_record(owner(), entry, Frame::main(100), input())
        .unwrap();
    assert_eq!(reused.slot(), 1);
    // Reuse the real first-free slot again to compare an exact old generation.
    saved_cleanup(&mut files, reused);
    files.ack_wait_record(reused, owner()).unwrap();
    let (next, next_claim) = files
        .begin_wait_record(owner(), entry, Frame::main(100), input())
        .unwrap();
    assert_eq!(next.slot(), reused.slot());
    assert!(next.generation() > reused.generation());
    assert_eq!(
        files.pick_wait_cleanup_from(Some(owner()), Frame::main(200), Some(reused), next.slot()),
        Ok(Some(next))
    );
    assert!(!files.wait_is_live(claim));
    assert!(!files.wait_is_live(next_claim));
    assert!(files.wait_snapshot(reused).is_err());
}

#[test]
fn full_resident_capacity_rotates_each_unpaid_physical_slot_once() {
    let (mut files, entry, _, _) = fixture();
    let mut tokens = [None; crate::WAIT_RECORDS];
    for token in &mut tokens {
        *token = Some(
            files
                .begin_wait_record(owner(), entry, Frame::main(100), input())
                .unwrap()
                .0,
        );
    }
    let mut cursor = 0;
    for expected in tokens.into_iter().flatten() {
        let selected = files
            .pick_wait_cleanup_from(Some(owner()), Frame::main(200), None, cursor)
            .unwrap()
            .unwrap();
        assert_eq!(selected, expected);
        cursor = (selected.slot() + 1) % crate::WAIT_RECORDS;
        assert_eq!(files.wait_snapshot(selected).unwrap().result, None);
    }
    assert_eq!(files.wait_tokens().count(), crate::WAIT_RECORDS);
    assert_eq!(cursor, 0);
}
