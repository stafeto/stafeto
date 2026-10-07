// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::storage::{Pin, ROOT, Root, Token};
use crate::{DescriptionSlot, Fds, OpenReceipt, Ram, TentativeOpen, clone::Snapshot};
use proto_fs::{OpenKey, Timestamp};

#[test]
fn internal_slot_keeps_both_endpoints_and_rejects_every_out_of_range_input() {
    assert_eq!(core::mem::size_of::<Option<DescriptionSlot>>(), 1);
    for index in 0..128 {
        let slot = DescriptionSlot::new(index).unwrap();
        assert_eq!(slot.index(), index);
        assert_eq!(usize::from(slot.0.get()), index + 1);
    }
    assert_eq!(DescriptionSlot::new(0).unwrap().0.get(), 1);
    assert_eq!(DescriptionSlot::new(127).unwrap().0.get(), 128);
    for index in [128, 255, 256, 65535, usize::MAX] {
        assert_eq!(DescriptionSlot::new(index), None);
    }
}

#[test]
fn invalid_receipt_is_refused_before_empty_slot_equivalence_or_table_indexing() {
    for occupied in [false, true] {
        let mut ram = Ram::new(Timestamp::ZERO);
        let mut fds = Fds::default();
        let original = if occupied {
            let fd = ram
                .open(&mut fds, "/etc/motd", proto_fs::READ_ONLY)
                .unwrap();
            Some(ram.capture_description(&fds, fd).unwrap().0)
        } else {
            None
        };
        let key = OpenKey {
            slot: 7,
            generation: 19,
        };
        let before = fds.slots;
        let descriptions = ram.open_descriptions();
        let refs = ram.descriptions[0].map(|shared| shared.refs);
        let pins = ram.storage.node(ROOT).unwrap().pins;
        for index in [128, 255, 256, 65535] {
            let description = Token {
                slot: index,
                generation: 1,
            };
            fds.open_receipts[0] = OpenReceipt { key, description };
            assert_eq!(ram.finished_open(&fds, key), Err(proto_fs::OPEN_RETIRED));
            assert_eq!(
                ram.marked_open(&fds, TentativeOpen { fd: 3, description }),
                Err(proto_fs::BAD_FD)
            );
            assert_eq!(fds.slots, before);
            assert_eq!(ram.open_descriptions(), descriptions);
            assert_eq!(ram.descriptions[0].map(|shared| shared.refs), refs);
            assert_eq!(ram.storage.node(ROOT).unwrap().pins, pins);
            if let Some(held) = original {
                assert_eq!(ram.description_token(&fds, held.fd), Ok(held.description));
            }
        }
        ram.release(&mut fds);
        assert_eq!(ram.open_descriptions(), 0);
    }
}

#[test]
fn full_description_table_preserves_raw_127_wire_replay_aliases_and_generation_reuse() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let mut owners = [Fds::default(); 4];
    for (owner, fds) in owners.iter_mut().enumerate() {
        fds.root = Root {
            id: 900 + owner as u64,
            generation: 1,
        };
        for _ in 0..32 {
            ram.open(fds, "/etc/motd", proto_fs::READ_ONLY).unwrap();
        }
    }
    assert_eq!(owners[0].slots[0].unwrap().index(), 0);
    assert_eq!(owners[3].slots[31].unwrap().index(), 127);
    assert_eq!(owners[3].slots[31].unwrap().0.get(), 128);
    let held = ram.capture_description(&owners[3], 34).unwrap().0;
    assert_eq!(held.description.slot, 127);
    let key = OpenKey {
        slot: 31,
        generation: 1,
    };
    owners[3].open_receipts[31] = OpenReceipt {
        key,
        description: held.description,
    };
    assert_eq!(ram.finished_open(&owners[3], key), Ok(held));
    let marked = ram.marked_open(&owners[3], held).unwrap();
    assert_eq!(
        (marked & proto_fs::OPEN_DESCRIPTION_MASK) >> proto_fs::OPEN_DESCRIPTION_SHIFT,
        127
    );
    assert_eq!(marked & proto_fs::OPEN_FD_MASK, 34);

    let mut repeated = Snapshot::capture(&mut ram, &owners[3], &[34; 32]).unwrap();
    assert_eq!(ram.descriptions[127].unwrap().refs, 2);
    assert!(repeated.release_step(&mut ram).unwrap());
    assert!(!repeated.release_step(&mut ram).unwrap());
    assert_eq!(ram.descriptions[127].unwrap().refs, 1);
    let all = core::array::from_fn::<_, 32, _>(|i| i as u32 + 3);
    let mut captured = Snapshot::capture(&mut ram, &owners[3], &all).unwrap();
    for index in 96..128 {
        assert_eq!(ram.descriptions[index].unwrap().refs, 2);
    }
    for _ in 0..32 {
        assert!(captured.release_step(&mut ram).unwrap());
    }
    assert!(!captured.release_step(&mut ram).unwrap());

    let mut aliases = Fds {
        slots: [owners[3].slots[31]; 32],
        cwd: Some(ROOT),
        ..Fds::default()
    };
    ram.descriptions[127].as_mut().unwrap().refs += 32;
    ram.storage.pin(ROOT, Pin::Cwd).unwrap();
    let pins = ram.storage.node(ROOT).unwrap().pins;
    ram.descriptions[127].as_mut().unwrap().refs = u16::MAX - 31;
    assert!(Snapshot::preflight(&ram, &aliases, &all).is_err());
    assert_eq!(ram.descriptions[127].unwrap().refs, u16::MAX - 31);
    assert_eq!(ram.storage.node(ROOT).unwrap().pins, pins);
    ram.descriptions[127].as_mut().unwrap().refs = 33;
    let mut snapshot = Snapshot::capture(&mut ram, &aliases, &all).unwrap();
    assert_eq!(ram.descriptions[127].unwrap().refs, 65);
    assert!(snapshot.release_step(&mut ram).unwrap()); // Exactly one retained CWD pin.
    assert_eq!(ram.descriptions[127].unwrap().refs, 65);
    for remaining in (33..65).rev() {
        assert!(snapshot.release_step(&mut ram).unwrap());
        assert_eq!(ram.descriptions[127].unwrap().refs, remaining);
    }
    assert!(!snapshot.release_step(&mut ram).unwrap());
    ram.release(&mut aliases);
    assert_eq!(ram.descriptions[127].unwrap().refs, 1);

    ram.close(&mut owners[3], held.fd).unwrap();
    let reused = ram
        .open(&mut owners[3], "/etc/motd", proto_fs::READ_ONLY)
        .unwrap();
    assert_eq!(reused, held.fd);
    let fresh = ram.description_token(&owners[3], reused).unwrap();
    assert_eq!(fresh.slot, 127);
    assert_ne!(fresh.generation, held.description.generation);
    assert_eq!(
        ram.finished_open(&owners[3], key),
        Err(proto_fs::OPEN_RETIRED)
    );
    assert_eq!(ram.marked_open(&owners[3], held), Err(proto_fs::BAD_FD));
    assert_eq!(ram.close_exact_description(&mut owners[3], held), Ok(false));
    assert!(ram.read(&mut owners[3], reused, &mut [0; 1]).unwrap() > 0);
    for fds in &mut owners {
        ram.release(fds);
    }
    assert_eq!(ram.open_descriptions(), 0);
    assert_eq!(ram.storage.node(ROOT).unwrap().pins, [0; 5]);
}
