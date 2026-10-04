// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::{Fds, File, Open, REG, Ram, io::*, storage::*};
use proto_fs::{APPEND, BAD_FD, NO_SPACE, READ_ONLY, READ_WRITE, STALE_PROOF};

const FIRST: Root = Root {
    id: 11,
    generation: 7,
};
const SECOND: Root = Root {
    id: 22,
    generation: 9,
};

fn create(ram: &mut Ram<'_>, root: Root, name: &[u8]) -> (Fds, u32, Token) {
    let r = ram
        .storage
        .reserve(root, ROOT, name, (REG, 0o6644, 1, 2))
        .unwrap();
    let token = ram.storage.commit(r).unwrap();
    let mut fds = Fds {
        root,
        ..Fds::default()
    };
    let fd = ram
        .insert(
            &mut fds,
            Open {
                file: File::Node(token),
                offset: 0,
                flags: READ_WRITE,
            },
        )
        .unwrap();
    (fds, fd, token)
}
fn write(ram: &mut Ram<'_>, fds: &Fds, fd: u32, at: Option<u64>, bytes: &[u8], now: u64) -> usize {
    let mut prep = ram.prepare_write(fds, fd, bytes, at).unwrap();
    while !prep.step(ram).unwrap() {}
    let count = prep.commit(ram, now).unwrap();
    while !prep.cancel(ram).unwrap() {}
    count
}
fn truncate(ram: &mut Ram<'_>, fds: &Fds, fd: u32, length: u64, now: u64) {
    let mut prep = ram.prepare_truncate(fds, fd, length).unwrap();
    while !prep.step(ram).unwrap() {}
    assert_eq!(prep.commit(ram, now), Ok(length));
    while !prep.cancel(ram).unwrap() {}
}
fn append(ram: &mut Ram<'_>, fds: &Fds, fd: u32) {
    let mut open = ram.get(fds, fd).unwrap();
    open.flags |= APPEND;
    ram.put(fds, fd, open).unwrap();
}
fn bytes(ram: &Ram<'_>, token: Token, at: u64, out: &mut [u8]) -> usize {
    ram.storage.read(token, at, out).unwrap()
}

#[test]
fn write_stages_two_pages_and_cancel_restores_exact_resources() {
    let mut ram = Ram::new(0);
    let (fds, fd, token) = create(&mut ram, FIRST, b"staged");
    let before = ram.storage.usage(FIRST);
    let mut prep = ram
        .prepare_write(&fds, fd, &[7; 4], Some(PAGE as u64 - 2))
        .unwrap();
    assert_eq!(ram.storage.usage(FIRST).pages, before.pages + 2);
    assert!(!prep.step(&mut ram).unwrap());
    assert_eq!(ram.storage.node(token).unwrap().length, 0);
    assert_eq!(ram.get(&fds, fd).unwrap().offset, 0);
    assert!(prep.step(&mut ram).unwrap());
    assert!(!prep.cancel(&mut ram).unwrap());
    assert_eq!(ram.storage.usage(FIRST).pages, before.pages + 1);
    while !prep.cancel(&mut ram).unwrap() {}
    assert_eq!(ram.storage.usage(FIRST), before);
    assert_eq!(prep.commit(&mut ram, 1), Err(BAD_FD));
}

#[test]
fn append_revalidates_eof_and_cached_commit_preserves_later_write() {
    let mut ram = Ram::new(0);
    let (fds, fd, token) = create(&mut ram, FIRST, b"append");
    append(&mut ram, &fds, fd);
    let mut first = ram.prepare_write(&fds, fd, b"A", None).unwrap();
    let mut second = ram.prepare_write(&fds, fd, b"B", None).unwrap();
    assert!(first.step(&mut ram).unwrap());
    assert!(second.step(&mut ram).unwrap());
    assert_eq!(first.commit(&mut ram, 1), Ok(1));
    assert_eq!(second.commit(&mut ram, 2), Err(STALE_PROOF));
    while !second.cancel(&mut ram).unwrap() {}
    assert_eq!(write(&mut ram, &fds, fd, None, b"B", 3), 1);
    assert_eq!(first.commit(&mut ram, 9), Ok(1));
    let mut out = [0; 2];
    assert_eq!(bytes(&ram, token, 0, &mut out), 2);
    assert_eq!(out, *b"AB");
    assert_eq!(ram.storage.node(token).unwrap().times[1], 3);
    while !first.cancel(&mut ram).unwrap() {}
}

#[test]
fn pwrite_preserves_shared_append_flags_and_seek_position() {
    let mut ram = Ram::new(0);
    let (mut fds, fd, token) = create(&mut ram, FIRST, b"position");
    write(&mut ram, &fds, fd, None, b"abcd", 1);
    ram.seek(&mut fds, fd, 3).unwrap();
    append(&mut ram, &fds, fd);
    assert_eq!(write(&mut ram, &fds, fd, Some(1), b"X", 2), 1);
    assert_eq!(ram.get(&fds, fd).unwrap().offset, 3);
    assert_eq!(ram.get(&fds, fd).unwrap().flags, READ_WRITE | APPEND);
    let mut out = [0; 4];
    bytes(&ram, token, 0, &mut out);
    assert_eq!(out, *b"aXcd");
}

#[test]
fn retained_writer_survives_chmod_unlink_and_original_fd_close() {
    let mut ram = Ram::new(0);
    let (mut fds, fd, token) = create(&mut ram, FIRST, b"retained");
    let mut prep = ram.prepare_write(&fds, fd, b"live", None).unwrap();
    ram.storage.node_mut(token).unwrap().mode = 0;
    ram.storage.unlink(ROOT, b"retained", FIRST).unwrap();
    ram.close(&mut fds, fd).unwrap();
    assert!(ram.storage.node(token).unwrap().live());
    while !prep.step(&mut ram).unwrap() {}
    assert_eq!(prep.commit(&mut ram, 4), Ok(4));
    let mut out = [0; 4];
    bytes(&ram, token, 0, &mut out);
    assert_eq!(out, *b"live");
    while !prep.cancel(&mut ram).unwrap() {}
    while ram.storage.reclaim_step() {}
    assert_eq!(ram.storage.usage(FIRST), Usage::default());
}

#[test]
fn truncate_partial_tail_is_private_and_extension_reveals_zeroes() {
    let mut ram = Ram::new(0);
    let (mut fds, fd, token) = create(&mut ram, FIRST, b"tail");
    write(&mut ram, &fds, fd, Some(PAGE as u64 - 3), b"abcdef", 1);
    ram.seek(&mut fds, fd, 99).unwrap();
    let mut prep = ram.prepare_truncate(&fds, fd, PAGE as u64 - 1).unwrap();
    while !prep.step(&mut ram).unwrap() {}
    let mut old = [0; 6];
    assert_eq!(bytes(&ram, token, PAGE as u64 - 3, &mut old), 6);
    assert_eq!(old, *b"abcdef");
    assert_eq!(prep.commit(&mut ram, 2), Ok(PAGE as u64 - 1));
    assert_eq!(ram.get(&fds, fd).unwrap().offset, 99);
    while !prep.cancel(&mut ram).unwrap() {}
    truncate(&mut ram, &fds, fd, PAGE as u64 + 3, 3);
    let mut out = [9; 6];
    assert_eq!(bytes(&ram, token, PAGE as u64 - 3, &mut out), 6);
    assert_eq!(out, [b'a', b'b', 0, 0, 0, 0]);
    while ram.storage.reclaim_step() {}
    assert_eq!(ram.storage.usage(FIRST).pages, 1);
}

#[test]
fn same_length_truncate_updates_metadata_once_and_keeps_offset() {
    let mut ram = Ram::new(0);
    let (mut fds, fd, token) = create(&mut ram, FIRST, b"same");
    write(&mut ram, &fds, fd, None, b"abc", 1);
    ram.storage.node_mut(token).unwrap().mode |= 0o6000;
    ram.seek(&mut fds, fd, 1).unwrap();
    let mut prep = ram.prepare_truncate(&fds, fd, 3).unwrap();
    assert!(prep.step(&mut ram).unwrap());
    assert_eq!(prep.commit(&mut ram, 10), Ok(3));
    assert_eq!(ram.storage.node(token).unwrap().times[1..], [10, 10]);
    assert_eq!(ram.storage.node(token).unwrap().mode & 0o6000, 0);
    ram.storage.node_mut(token).unwrap().times[1] = 20;
    assert_eq!(prep.commit(&mut ram, 30), Ok(3));
    assert_eq!(ram.storage.node(token).unwrap().times[1], 20);
    assert_eq!(ram.get(&fds, fd).unwrap().offset, 1);
    while !prep.cancel(&mut ram).unwrap() {}
}

#[test]
fn stale_scan_and_counter_exhaustion_preserve_original_bytes() {
    let mut ram = Ram::new(0);
    let (fds, fd, token) = create(&mut ram, FIRST, b"stale");
    write(&mut ram, &fds, fd, Some(0), b"old", 1);
    let mut prep = ram.prepare_truncate(&fds, fd, 1).unwrap();
    assert!(!prep.step(&mut ram).unwrap());
    write(&mut ram, &fds, fd, Some(1), b"X", 2);
    assert_eq!(prep.step(&mut ram), Err(STALE_PROOF));
    assert_eq!(prep.commit(&mut ram, 3), Err(proto_fs::INVALID_ARGUMENT));
    while !prep.cancel(&mut ram).unwrap() {}
    ram.storage.state.epoch = u64::MAX;
    assert!(matches!(
        ram.prepare_write(&fds, fd, b"bad", None),
        Err(NO_SPACE)
    ));
    assert!(matches!(ram.prepare_truncate(&fds, fd, 0), Err(NO_SPACE)));
    let mut out = [0; 3];
    bytes(&ram, token, 0, &mut out);
    assert_eq!(out, *b"oXd");
}

#[test]
fn empty_write_validates_descriptor_access_and_signed_position() {
    let mut ram = Ram::new(0);
    let (fds, fd, token) = create(&mut ram, FIRST, b"empty");
    let before = ram.storage.usage(FIRST);
    let mut prep = ram.prepare_write(&fds, fd, &[], None).unwrap();
    assert_eq!(prep.commit(&mut ram, 7), Ok(0));
    assert!(prep.cancel(&mut ram).unwrap());
    assert_eq!(ram.storage.usage(FIRST), before);
    assert_eq!(ram.storage.node(token).unwrap().times, [0; 3]);
    assert!(matches!(
        ram.prepare_write(&fds, 100, &[], None),
        Err(BAD_FD)
    ));
    assert!(matches!(
        ram.prepare_write(&fds, fd, &[], Some(u64::MAX)),
        Err(proto_fs::OFFSET_OVERFLOW)
    ));
    let mut readonly = Fds::default();
    let ro = ram
        .insert(
            &mut readonly,
            Open {
                file: File::Node(token),
                offset: 0,
                flags: READ_ONLY,
            },
        )
        .unwrap();
    assert!(matches!(
        ram.prepare_write(&readonly, ro, &[], None),
        Err(BAD_FD)
    ));
}

#[test]
fn full_page_pool_allows_aligned_shrink_and_zero_without_tail_allocation() {
    let mut ram = Ram::new(0);
    let (fds, fd, first) = create(&mut ram, FIRST, b"full-first");
    let (_, _, second) = create(&mut ram, SECOND, b"full-second");
    for logical in 0..FILE_PAGES {
        ram.storage
            .write(first, FIRST, logical * PAGE, &[7])
            .unwrap();
        ram.storage
            .write(second, SECOND, logical * PAGE, &[8])
            .unwrap();
    }
    assert_eq!(ram.storage.available().pages, 0);
    assert!(matches!(ram.prepare_truncate(&fds, fd, 1), Err(NO_SPACE)));
    truncate(&mut ram, &fds, fd, PAGE as u64, 5);
    assert_eq!(ram.storage.available().pages, 0);
    let mut kept = [0];
    assert_eq!(bytes(&ram, first, 0, &mut kept), 1);
    assert_eq!(kept, [7]);
    truncate(&mut ram, &fds, fd, 0, 6);
    while ram.storage.reclaim_step() {}
    assert_eq!(ram.storage.available().pages as usize, FILE_PAGES);
    assert_eq!(ram.storage.usage(FIRST).pages, 0);
    assert_eq!(ram.storage.usage(SECOND).pages as usize, FILE_PAGES);
}

#[test]
fn file_capacity_returns_short_cached_prefix_and_distinct_errors() {
    let mut ram = Ram::new(0);
    let (fds, fd, token) = create(&mut ram, FIRST, b"capacity");
    let end = (FILE_PAGES * PAGE) as u64;
    assert_eq!(write(&mut ram, &fds, fd, Some(end - 2), b"abcd", 1), 2);
    assert_eq!(ram.storage.node(token).unwrap().length, end);
    assert!(matches!(
        ram.prepare_write(&fds, fd, b"x", Some(end)),
        Err(FILE_TOO_LARGE)
    ));
    assert!(matches!(
        ram.prepare_truncate(&fds, fd, end + 1),
        Err(FILE_TOO_LARGE)
    ));
}

#[test]
fn root_page_quota_returns_a_paid_short_prefix_and_cancel_keeps_charge_owner() {
    let mut ram = Ram::new(0);
    let (_, _, full) = create(&mut ram, FIRST, b"quota-full");
    let (_, _, rest) = create(&mut ram, FIRST, b"quota-rest");
    let (fds, fd, target) = create(&mut ram, FIRST, b"quota-target");
    for logical in 0..FILE_PAGES {
        ram.storage
            .write(full, FIRST, logical * PAGE, &[1])
            .unwrap();
    }
    for logical in 0..PAGE_SHARE as usize - FILE_PAGES - 1 {
        ram.storage
            .write(rest, FIRST, logical * PAGE, &[2])
            .unwrap();
    }
    let mut prep = ram
        .prepare_write(&fds, fd, b"abc", Some(PAGE as u64 - 1))
        .unwrap();
    assert_eq!(ram.storage.usage(FIRST).pages, PAGE_SHARE);
    while !prep.step(&mut ram).unwrap() {}
    assert_eq!(prep.commit(&mut ram, 1), Ok(1));
    assert_eq!(prep.commit(&mut ram, 2), Ok(1));
    let mut out = [0];
    bytes(&ram, target, PAGE as u64 - 1, &mut out);
    assert_eq!(out, [b'a']);
    while !prep.cancel(&mut ram).unwrap() {}
    assert!(matches!(
        ram.prepare_write(&fds, fd, b"x", Some(PAGE as u64)),
        Err(NO_SPACE)
    ));
    assert_eq!(ram.storage.usage(SECOND), Usage::default());
}

#[test]
fn new_overlay_retains_originating_root_and_cancel_releases_private_overlay() {
    let mut ram = Ram::new(0);
    let mut fds = Fds {
        root: FIRST,
        ..Fds::default()
    };
    let fd = ram.open(&mut fds, "/tmp/probe", READ_WRITE).unwrap();
    // A child's data admission belongs to its current root account.
    fds.root = SECOND;
    let before = ram.storage.usage(SECOND);
    let mut prep = ram.prepare_write(&fds, fd, b"x", None).unwrap();
    assert_eq!(ram.storage.usage(FIRST).descriptions, 1);
    assert_eq!(ram.storage.usage(SECOND).inodes, 1);
    assert_eq!(ram.storage.usage(SECOND).pages, 1);
    assert_eq!(
        ram.storage.node(ram.token(File::Scratch)).unwrap().length,
        0
    );
    while !prep.cancel(&mut ram).unwrap() {}
    assert_eq!(ram.storage.usage(SECOND), before);
    assert_eq!(write(&mut ram, &fds, fd, None, b"y", 1), 1);
    fds.root = FIRST;
    assert_eq!(write(&mut ram, &fds, fd, Some(PAGE as u64), b"z", 2), 1);
    assert_eq!(ram.storage.usage(SECOND).pages, 2);
    assert_eq!(ram.storage.usage(FIRST).pages, 0);
}

#[test]
fn seek_flags_and_data_generation_exhaustion_refuse_unpublished_effects() {
    let mut ram = Ram::new(0);
    let (mut fds, fd, token) = create(&mut ram, FIRST, b"metadata-stale");
    let mut prep = ram.prepare_write(&fds, fd, b"old", None).unwrap();
    while !prep.step(&mut ram).unwrap() {}
    ram.seek(&mut fds, fd, 1).unwrap();
    assert_eq!(prep.commit(&mut ram, 2), Err(STALE_PROOF));
    while !prep.cancel(&mut ram).unwrap() {}
    let mut prep = ram.prepare_write(&fds, fd, b"next", Some(0)).unwrap();
    while !prep.step(&mut ram).unwrap() {}
    append(&mut ram, &fds, fd);
    assert_eq!(prep.commit(&mut ram, 3), Err(STALE_PROOF));
    while !prep.cancel(&mut ram).unwrap() {}
    ram.storage.node_mut(token).unwrap().data_generation = u64::MAX;
    assert!(matches!(
        ram.prepare_write(&fds, fd, b"bad", None),
        Err(NO_SPACE)
    ));
    assert!(matches!(ram.prepare_truncate(&fds, fd, 0), Err(NO_SPACE)));
    assert_eq!(ram.storage.node(token).unwrap().length, 0);
    assert_eq!(ram.storage.usage(FIRST).pages, 0);
}

#[test]
fn preparation_layout_keeps_page_bytes_in_the_paid_data_pool() {
    extern crate std;
    let write = core::mem::size_of::<WritePreparation>();
    let truncate = core::mem::size_of::<TruncatePreparation>();
    std::println!(
        "WritePreparation {write}, TruncatePreparation {truncate}, MAX_WRITE {}",
        proto_fs::MAX_WRITE
    );
    assert!(write <= proto_fs::MAX_WRITE + 256);
    assert!(truncate <= 256);
}

#[test]
fn retained_description_writes_original_inode_after_numeric_fd_reuse() {
    let mut ram = Ram::new(0);
    let (mut fds, fd, original) = create(&mut ram, FIRST, b"original-fd");
    let mut prep = ram.prepare_write(&fds, fd, b"old", None).unwrap();
    ram.close(&mut fds, fd).unwrap();
    let (_, _, replacement) = create(&mut ram, FIRST, b"replacement-fd");
    let reused = ram
        .insert(
            &mut fds,
            Open {
                file: File::Node(replacement),
                offset: 0,
                flags: READ_WRITE,
            },
        )
        .unwrap();
    assert_eq!(reused, fd);
    while !prep.step(&mut ram).unwrap() {}
    assert_eq!(prep.commit(&mut ram, 4), Ok(3));
    assert_eq!(ram.storage.node(replacement).unwrap().length, 0);
    assert_eq!(ram.get(&fds, reused).unwrap().offset, 0);
    let mut out = [0; 3];
    bytes(&ram, original, 0, &mut out);
    assert_eq!(out, *b"old");
    while !prep.cancel(&mut ram).unwrap() {}
    assert_eq!(ram.storage.node(replacement).unwrap().length, 0);
}

#[test]
fn general_truncate_boot_mask_keeps_prefix_and_zeroes_later_extension() {
    let mut ram = Ram::new(0);
    let token = Token {
        slot: 3,
        generation: 1,
    };
    let old_length = ram.storage.node(token).unwrap().length;
    let mut shrink = ram.storage.prepare_data_truncate(token, 3).unwrap();
    assert!(ram.storage.step_data_truncate(&mut shrink).unwrap());
    ram.storage.commit_data_truncate(&mut shrink, 1).unwrap();
    let mut extend = ram
        .storage
        .prepare_data_truncate(token, old_length)
        .unwrap();
    assert!(ram.storage.step_data_truncate(&mut extend).unwrap());
    ram.storage.commit_data_truncate(&mut extend, 2).unwrap();
    let mut out = [0xff; 16];
    assert_eq!(bytes(&ram, token, 0, &mut out), old_length as usize);
    assert_eq!(&out[..3], b"sta");
    assert!(out[3..old_length as usize].iter().all(|byte| *byte == 0));
    let mut write = ram.storage.prepare_data_write(token, FIRST, 5, 1).unwrap();
    assert!(ram.storage.step_data_write(&mut write).unwrap());
    ram.storage.commit_data_write(&mut write, b"X", 3).unwrap();
    assert_eq!(bytes(&ram, token, 0, &mut out), old_length as usize);
    assert_eq!(&out[..6], &[b's', b't', b'a', 0, 0, b'X']);
}

#[test]
fn cancel_private_tail_preserves_live_bytes_metadata_and_page_credit() {
    let mut ram = Ram::new(0);
    let (fds, fd, token) = create(&mut ram, FIRST, b"cancel-tail");
    write(&mut ram, &fds, fd, None, b"abcd", 1);
    let usage = ram.storage.usage(FIRST);
    let generation = ram.storage.node(token).unwrap().data_generation;
    let mut prep = ram.prepare_truncate(&fds, fd, 1).unwrap();
    while !prep.step(&mut ram).unwrap() {}
    assert_eq!(ram.storage.usage(FIRST).pages, usage.pages + 1);
    assert!(!prep.cancel(&mut ram).unwrap());
    assert_eq!(ram.storage.usage(FIRST), usage);
    assert!(prep.cancel(&mut ram).unwrap());
    assert_eq!(ram.storage.node(token).unwrap().data_generation, generation);
    assert_eq!(ram.storage.node(token).unwrap().times[1], 1);
    let mut out = [0; 4];
    bytes(&ram, token, 0, &mut out);
    assert_eq!(out, *b"abcd");
}

#[test]
fn truncate_cached_replay_keeps_later_payload_and_shared_offset() {
    let mut ram = Ram::new(0);
    let (fds, fd, token) = create(&mut ram, FIRST, b"truncate-replay");
    write(&mut ram, &fds, fd, None, b"old", 1);
    let mut prep = ram.prepare_truncate(&fds, fd, 0).unwrap();
    assert!(prep.step(&mut ram).unwrap());
    assert_eq!(prep.commit(&mut ram, 2), Ok(0));
    write(&mut ram, &fds, fd, None, b"new", 3);
    assert_eq!(prep.commit(&mut ram, 4), Ok(0));
    assert_eq!(ram.storage.node(token).unwrap().length, 6);
    assert_eq!(ram.get(&fds, fd).unwrap().offset, 6);
    assert_eq!(ram.storage.node(token).unwrap().times[1], 3);
    let mut out = [0; 6];
    bytes(&ram, token, 0, &mut out);
    assert_eq!(out, [0, 0, 0, b'n', b'e', b'w']);
    while !prep.cancel(&mut ram).unwrap() {}
    assert_eq!(prep.commit(&mut ram, 9), Ok(0));
}
