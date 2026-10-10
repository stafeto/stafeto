// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::storage::*;
use crate::{Fds, REG, Ram};
use proto_fs::{NO_ENTRY, NO_SPACE, READ_WRITE};
extern crate std;
use std::format;

const FIRST: Root = Root {
    id: 11,
    generation: 7,
};
const SECOND: Root = Root {
    id: 22,
    generation: 9,
};
fn create(ram: &mut Ram<'_>, root: Root, name: &[u8]) -> Token {
    let r = ram
        .storage
        .reserve(root, ROOT, name, (REG, 0o644, 1, 2))
        .unwrap();
    ram.storage.commit(r).unwrap()
}
fn drain(ram: &mut Ram<'_>) -> usize {
    let mut steps = 0;
    while ram.storage.reclaim_step() {
        steps += 1;
        assert!(steps <= PAGES + INODES);
    }
    steps
}

#[cfg(feature = "auth-probe")]
#[test]
fn diagnostic_gc_creation_is_paid_unpublished_and_commits_once() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let mut fds = Fds {
        root: FIRST,
        ..Fds::default()
    };
    assert_eq!(ram.auth_probe_gc_reserve(&mut fds), Ok(()));
    assert_eq!(ram.storage.lookup(ROOT, b"auth-probe-gc"), Err(NO_ENTRY));
    assert_eq!(ram.storage.preparations_used(), 1);
    assert_eq!(ram.storage.usage(FIRST).inodes, 1);
    assert_eq!(
        ram.auth_probe_gc_reserve(&mut fds),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    assert_eq!(ram.storage.preparations_used(), 1);
    assert_eq!(ram.auth_probe_gc_commit(&mut fds), Ok(()));
    assert!(fds.auth_probe_gc_reservation.is_none());
    assert_eq!(
        ram.storage.lookup(ROOT, b"auth-probe-gc"),
        Ok(fds.auth_probe_gc.unwrap())
    );
    assert_eq!(ram.storage.preparations_used(), 0);
    assert_eq!(
        ram.auth_probe_gc_commit(&mut fds),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    assert_eq!(
        ram.auth_probe_gc_reserve(&mut fds),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    ram.storage.unlink(ROOT, b"auth-probe-gc", FIRST).unwrap();
    assert_eq!(drain(&mut ram), 1);
    assert_eq!(ram.storage.usage(FIRST), Usage::default());
}

#[cfg(feature = "auth-probe")]
#[test]
fn diagnostic_gc_commit_refusal_cancels_exact_reservation_once() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let mut fds = Fds {
        root: FIRST,
        ..Fds::default()
    };
    ram.auth_probe_gc_reserve(&mut fds).unwrap();
    let other = create(&mut ram, SECOND, b"other");
    assert_eq!(
        ram.auth_probe_gc_commit(&mut fds),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    assert!(fds.auth_probe_gc_reservation.is_none());
    assert!(fds.auth_probe_gc.is_none());
    assert_eq!(ram.storage.preparations_used(), 0);
    assert!(!ram.release_step(&mut fds));
    assert_eq!(
        ram.auth_probe_gc_commit(&mut fds),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    assert_eq!(drain(&mut ram), 1);
    assert_eq!(ram.storage.usage(FIRST), Usage::default());
    assert_eq!(ram.storage.lookup(ROOT, b"other"), Ok(other));
    ram.storage.unlink(ROOT, b"other", SECOND).unwrap();
    assert_eq!(drain(&mut ram), 1);
    assert_eq!(ram.storage.usage(SECOND), Usage::default());
}

#[cfg(feature = "auth-probe")]
#[test]
fn diagnostic_gc_reservation_follows_portioned_and_gone_release() {
    for gone in [false, true] {
        let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
        let mut fds = Fds {
            root: FIRST,
            ..Fds::default()
        };
        ram.auth_probe_gc_reserve(&mut fds).unwrap();
        if gone {
            ram.release(&mut fds);
        } else {
            assert!(ram.release_step(&mut fds));
        }
        assert!(fds.auth_probe_gc_reservation.is_none());
        assert_eq!(ram.storage.preparations_used(), 0);
        assert!(!ram.release_step(&mut fds));
        assert_eq!(
            ram.auth_probe_gc_commit(&mut fds),
            Err(proto_fs::INVALID_ARGUMENT)
        );
        assert_eq!(drain(&mut ram), 1);
        assert_eq!(ram.storage.usage(FIRST), Usage::default());
    }
}

#[test]
fn inode_and_name_shares_leave_a_second_roots_reserve() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let mut tokens = std::vec::Vec::new();
    for i in 0..INODE_SHARE {
        tokens.push(create(&mut ram, FIRST, format!("a{i}").as_bytes()));
    }
    assert_eq!(
        ram.storage
            .reserve(FIRST, ROOT, b"over", (REG, 0o644, 1, 2))
            .err(),
        Some(NO_SPACE)
    );
    for i in 0..INODE_SHARE {
        ram.storage
            .link(
                FIRST,
                ROOT,
                format!("link{i}").as_bytes(),
                tokens[i as usize],
            )
            .unwrap();
    }
    assert_eq!(ram.storage.usage(FIRST).dentries, DENTRY_SHARE);
    assert_eq!(
        ram.storage.link(FIRST, ROOT, b"too-many-names", tokens[0]),
        Err(NO_SPACE)
    );
    for i in 0..INODES - INODE_SHARE as usize {
        tokens.push(create(&mut ram, SECOND, format!("b{i}").as_bytes()));
    }
    assert_eq!(ram.storage.available().inodes, 0);
    assert_eq!(
        ram.storage
            .reserve(SECOND, ROOT, b"global-full", (REG, 0o644, 1, 2))
            .err(),
        Some(NO_SPACE)
    );
    for i in 0..DENTRIES - DENTRY_SHARE as usize - (INODES - INODE_SHARE as usize) {
        ram.storage
            .link(
                SECOND,
                ROOT,
                format!("second-link{i}").as_bytes(),
                tokens[0],
            )
            .unwrap();
    }
    assert_eq!(ram.storage.available().dentries, 0);
    assert_eq!(
        ram.storage
            .link(SECOND, ROOT, b"global-name-full", tokens[0]),
        Err(NO_SPACE)
    );
    assert_eq!(ram.storage.usage(FIRST).inodes, INODE_SHARE);
    assert_eq!(
        ram.storage.usage(SECOND).inodes as usize,
        INODES - INODE_SHARE as usize
    );
}

#[test]
fn all_pages_are_prepaid_and_reclaimed_one_per_step_after_the_last_pin() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let a = create(&mut ram, FIRST, b"a");
    let b = create(&mut ram, FIRST, b"b");
    let c = create(&mut ram, SECOND, b"c");
    let page = [0x5a; PAGE];
    for i in 0..PAGE_SHARE as usize {
        ram.storage
            .write(
                if i < FILE_PAGES { a } else { b },
                FIRST,
                i % FILE_PAGES * PAGE,
                &page,
            )
            .unwrap();
    }
    assert_eq!(ram.storage.usage(FIRST).pages, PAGE_SHARE);
    assert_eq!(
        ram.storage.write(b, FIRST, 1024 * PAGE, b"!"),
        Err(NO_SPACE)
    );
    for i in 0..PAGES - PAGE_SHARE as usize {
        ram.storage.write(c, SECOND, i * PAGE, &page).unwrap();
    }
    assert_eq!(ram.storage.available().pages, 0);
    assert_eq!(
        ram.storage.write(c, SECOND, 1024 * PAGE, b"!"),
        Err(NO_SPACE)
    );
    ram.storage.pin(c, Pin::Fd).unwrap();
    ram.storage.unlink(ROOT, b"c", SECOND).unwrap();
    assert_eq!(drain(&mut ram), 0);
    assert_eq!(ram.storage.usage(SECOND).pages, 1024);
    let mut bytes = [0; 4];
    assert_eq!(ram.storage.read(c, PAGE as u64, &mut bytes), Ok(4));
    assert_eq!(bytes, [0x5a; 4]);
    ram.storage.unpin(c, Pin::Fd).unwrap();
    assert!(ram.storage.reclaim_step());
    assert_eq!(ram.storage.available().pages, 1);
    assert_eq!(drain(&mut ram), 1024);
    assert_eq!(ram.storage.usage(SECOND), Usage::default());
    assert_eq!(ram.storage.node(c).err(), Some(NO_ENTRY));
}

#[test]
fn reservation_cancellation_lost_reply_and_each_pin_keep_accounting() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let r = ram
        .storage
        .reserve(FIRST, ROOT, b"unaccepted", (REG, 0o644, 1, 2))
        .unwrap();
    ram.storage.write(r.token, FIRST, 0, b"paid bytes").unwrap();
    assert_eq!(ram.storage.lookup(ROOT, b"unaccepted"), Err(NO_ENTRY));
    ram.storage.cancel(r).unwrap();
    assert_eq!(drain(&mut ram), 2);
    assert_eq!(ram.storage.usage(FIRST), Usage::default());
    let token = create(&mut ram, FIRST, b"accepted");
    for pin in [Pin::Fd, Pin::Cwd, Pin::Image, Pin::Pending, Pin::Parent] {
        ram.storage.pin(token, pin).unwrap();
    }
    ram.storage.unlink(ROOT, b"accepted", FIRST).unwrap();
    for pin in [Pin::Fd, Pin::Cwd, Pin::Image, Pin::Pending] {
        ram.storage.unpin(token, pin).unwrap();
        assert_eq!(drain(&mut ram), 0);
        assert_eq!(ram.storage.usage(FIRST).inodes, 1);
    }
    ram.storage.unpin(token, Pin::Parent).unwrap();
    assert_eq!(drain(&mut ram), 1);
    let new = create(&mut ram, FIRST, b"new");
    assert_eq!(new.slot, token.slot);
    assert!(new.generation > token.generation);
    assert_eq!(ram.storage.read(token, 0, &mut [0; 1]), Err(NO_ENTRY));
}

#[test]
fn description_share_is_charged_to_the_retained_root_across_clone() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let mut fds = [Fds::default(); 4];
    for session in &mut fds {
        session.root = FIRST;
    }
    for session in &mut fds[..3] {
        for _ in 0..32 {
            ram.open(session, "/tmp/probe", READ_WRITE).unwrap();
        }
    }
    assert_eq!(ram.storage.usage(FIRST).descriptions, DESCRIPTION_SHARE);
    assert_eq!(
        ram.open(&mut fds[3], "/tmp/probe", READ_WRITE),
        Err(proto_fs::TOO_MANY_OPEN_FILES)
    );
    fds[3].root = SECOND;
    for _ in 0..32 {
        ram.open(&mut fds[3], "/tmp/probe", READ_WRITE).unwrap();
    }
    assert_eq!(ram.open_descriptions(), 128);
    let mut child = ram.clone_fds(&fds[0], &[3]).unwrap();
    ram.release(&mut fds[0]);
    assert_eq!(ram.storage.usage(FIRST).descriptions, 65);
    ram.release(&mut child);
    assert_eq!(ram.storage.usage(FIRST).descriptions, 64);
    for session in &mut fds {
        ram.release(session);
    }
    assert_eq!(ram.storage.usage(FIRST), Usage::default());
    assert_eq!(ram.storage.usage(SECOND), Usage::default());
}

#[test]
fn sparse_original_overlay_and_boot_hardlinks_share_actual_bytes() {
    use bootimg::rootfs::{Entry, REGULAR};
    let entry = |path| Entry {
        path,
        mode: REGULAR | 0o644,
        uid: 1,
        gid: 2,
        file: 1,
    };
    let image = crate::tree::test_image(&[entry("/a"), entry("/b")]);
    let mut index = crate::tree::Index::new();
    let tree = crate::tree::load(&image, &mut index).unwrap();
    let mut ram = Ram::with_tree(proto_fs::Timestamp::legacy_ns(0), tree);
    let a = ram.storage.resolve(b"/a").unwrap();
    let b = ram.storage.resolve(b"/b").unwrap();
    assert_eq!(a, b);
    ram.storage
        .write(a, FIRST, 2 * PAGE + 7, b"suffix")
        .unwrap();
    let mut out = [1; 20];
    assert_eq!(ram.storage.read(b, 0, &mut out), Ok(20));
    assert_eq!(&out[..11], b"alpha bytes");
    assert_eq!(&out[11..], &[0; 9]);
    assert_eq!(ram.storage.read(b, (2 * PAGE) as u64, &mut out), Ok(13));
    assert_eq!(&out[..13], b"\0\0\0\0\0\0\0suffix");
    assert_eq!(ram.storage.usage(FIRST).pages, 1);
    assert_eq!(tree.data(0), b"alpha bytes");
    ram.storage.unlink(ROOT, b"a", FIRST).unwrap();
    assert_eq!(ram.storage.node(b).unwrap().links, 1);
    assert_eq!(ram.storage.read(b, 0, &mut out[..11]), Ok(11));
}

#[test]
fn gone_sessions_cancel_paid_preparations_and_leave_the_other_roots_reserve() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let mut sessions = [Fds::default(); 8];
    for (i, s) in sessions.iter_mut().enumerate() {
        s.root = if i < 6 { FIRST } else { SECOND };
        for j in 0..16 {
            ram.reserve_create(s, ROOT, format!("p{i}-{j}").as_bytes(), REG)
                .unwrap();
        }
        assert_eq!(
            ram.reserve_create(s, ROOT, b"session-overflow", REG).err(),
            Some(proto_fs::TOO_MANY_OPEN_FILES)
        );
    }
    let mut extra = Fds {
        root: FIRST,
        ..Fds::default()
    };
    assert_eq!(
        ram.reserve_create(&mut extra, ROOT, b"root-overflow", REG)
            .err(),
        Some(proto_fs::TOO_MANY_OPEN_FILES)
    );
    extra.root = Root {
        id: 33,
        generation: 1,
    };
    assert_eq!(
        ram.reserve_create(&mut extra, ROOT, b"global-overflow", REG)
            .err(),
        Some(proto_fs::TOO_MANY_OPEN_FILES)
    );
    for s in &mut sessions {
        ram.release(s);
    }
    assert_eq!(drain(&mut ram), 128);
    assert_eq!(ram.storage.usage(FIRST), Usage::default());
    assert_eq!(ram.storage.usage(SECOND), Usage::default());
    assert_eq!(ram.storage.available().inodes, 256);
    assert_eq!(ram.storage.available().dentries, 512);
    assert_eq!(
        ram.storage.node(ROOT).unwrap().pins[Pin::Pending as usize],
        0
    );
    let mut s = Fds {
        root: FIRST,
        ..Fds::default()
    };
    let r = ram
        .reserve_create(&mut s, ROOT, b"lost-reply", REG)
        .unwrap();
    let token = ram.commit_create(&mut s, r).unwrap();
    ram.release(&mut s);
    assert_eq!(ram.storage.lookup(ROOT, b"lost-reply"), Ok(token));
    assert_eq!(ram.storage.usage(FIRST).inodes, 1);
    let reused = Root {
        id: FIRST.id,
        generation: FIRST.generation + 1,
    };
    create(&mut ram, reused, b"new-root-generation");
    assert_eq!(ram.storage.usage(FIRST).inodes, 1);
    assert_eq!(ram.storage.usage(reused).inodes, 1);
}

#[test]
fn live_descriptions_cwd_and_generation_use_the_services_actual_backend() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let old = create(&mut ram, FIRST, b"live");
    let mut fds = Fds {
        root: FIRST,
        ..Fds::default()
    };
    ram.set_cwd_token(&mut fds, ROOT).unwrap();
    let fd = ram.open(&mut fds, "/live", READ_WRITE).unwrap();
    let description = ram.description_token(&fds, fd).unwrap();
    ram.write(&mut fds, fd, b"retained").unwrap();
    ram.storage.unlink(ROOT, b"live", FIRST).unwrap();
    let replacement = create(&mut ram, FIRST, b"live");
    assert_ne!(old, replacement);
    assert_eq!(drain(&mut ram), 0);
    assert_eq!(ram.descriptor_information(&fds, fd).unwrap().links, 0);
    ram.seek(&mut fds, fd, 0).unwrap();
    let mut bytes = [0; 8];
    assert_eq!(ram.read(&mut fds, fd, &mut bytes), Ok(8));
    assert_eq!(&bytes, b"retained");
    let mut child = ram.clone_fds(&fds, &[]).unwrap();
    assert_eq!(ram.storage.node(ROOT).unwrap().pins[Pin::Cwd as usize], 2);
    ram.close(&mut fds, fd).unwrap();
    assert_eq!(drain(&mut ram), 2);
    let new_fd = ram.open(&mut fds, "/live", READ_WRITE).unwrap();
    let next = ram.description_token(&fds, new_fd).unwrap();
    assert_eq!(next.slot, description.slot);
    assert!(next.generation > description.generation);
    ram.release(&mut fds);
    ram.release(&mut child);
    assert_eq!(ram.storage.node(ROOT).unwrap().pins[Pin::Cwd as usize], 0);
}

#[test]
fn boot_copy_preserves_unaligned_offsets_destinations_and_short_tails() {
    use bootimg::rootfs::{Entry, REGULAR};
    let expected: std::vec::Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
    let table = bootimg::rootfs::write::rootfs(
        &[Entry {
            path: "/copy",
            mode: REGULAR | 0o644,
            uid: 1,
            gid: 2,
            file: 1,
        }],
        3,
    )
    .unwrap();
    let image =
        bootimg::write::image(&[("init", b"init"), ("copy", &expected), ("rootfs", &table)])
            .unwrap();
    let mut index = crate::tree::Index::new();
    let tree = crate::tree::load(&image, &mut index).unwrap();
    let ram = Ram::with_tree(proto_fs::Timestamp::legacy_ns(0), tree);
    let token = ram.storage.resolve(b"/copy").unwrap();
    for offset in 0..8 {
        for destination in 0..8 {
            let mut out = [0x55; 256];
            let count = ram
                .storage
                .read(token, offset as u64, &mut out[destination..])
                .unwrap();
            assert_eq!(
                &out[destination..destination + count],
                &expected[offset..offset + count]
            );
            assert!(out[..destination].iter().all(|b| *b == 0x55));
            assert!(out[destination + count..].iter().all(|b| *b == 0x55));
        }
    }
}

#[test]
fn independent_review_first_write_refusal_keeps_unmodified_boot_account() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let a = create(&mut ram, FIRST, b"fill-a");
    let b = create(&mut ram, FIRST, b"fill-b");
    for i in 0..PAGE_SHARE as usize {
        ram.storage
            .write(
                if i < FILE_PAGES { a } else { b },
                FIRST,
                i % FILE_PAGES * PAGE,
                &[9],
            )
            .unwrap();
    }
    let original = ram.storage.resolve(b"/tmp/probe").unwrap();
    let before = ram.storage.usage(FIRST);
    let epoch = ram.storage.state.epoch;
    assert_eq!(ram.storage.write(original, FIRST, 0, b"x"), Err(NO_SPACE));
    std::println!(
        "refused write: before={before:?}, after={:?}, epoch={epoch}->{}",
        ram.storage.usage(FIRST),
        ram.storage.state.epoch
    );
    assert_eq!(
        ram.storage.usage(FIRST),
        before,
        "refused first write retained unpaid-effect overlay"
    );
    assert_eq!(ram.storage.state.epoch, epoch);
}

#[test]
fn independent_review_original_unlink_refusal_preserves_account() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let token = create(&mut ram, FIRST, b"existing");
    for i in 1..DENTRY_SHARE {
        ram.storage
            .link(FIRST, ROOT, format!("full-{i}").as_bytes(), token)
            .unwrap();
    }
    let before = ram.storage.usage(FIRST);
    let epoch = ram.storage.state.epoch;
    let parent = ram.storage.resolve(b"/etc").unwrap();
    assert_eq!(ram.storage.unlink(parent, b"motd", FIRST), Err(NO_SPACE));
    std::println!(
        "refused unlink: before={before:?}, after={:?}, epoch={epoch}->{}",
        ram.storage.usage(FIRST),
        ram.storage.state.epoch
    );
    assert_eq!(
        ram.storage.usage(FIRST),
        before,
        "refused unlink retained overlay"
    );
    assert_eq!(ram.storage.state.epoch, epoch);
}

#[test]
fn independent_review_open_directory_is_an_authorized_relative_base() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let pending = ram
        .storage
        .reserve(FIRST, ROOT, b"base", (crate::DIR, 0o755, 0, 0))
        .unwrap();
    let directory = ram.storage.commit(pending).unwrap();
    let mut fds = Fds {
        root: FIRST,
        ..Fds::default()
    };
    let fd = ram.open(&mut fds, "/base", proto_fs::READ_ONLY).unwrap();
    std::println!(
        "directory inode={directory:?}, fd={fd}, description={:?}",
        ram.description_token(&fds, fd).unwrap()
    );
    assert!(
        ram.owns_directory_base(&fds, directory),
        "genuine open directory denied as relative base"
    );
    ram.release(&mut fds);
}

#[test]
fn directory_base_rejects_a_colliding_regular_description() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let mut fds = Fds::default();
    let first = ram
        .open(&mut fds, "/etc/motd", proto_fs::READ_ONLY)
        .unwrap();
    let second = ram
        .open(&mut fds, "/etc/motd", proto_fs::READ_ONLY)
        .unwrap();
    let directory = ram.storage.resolve(b"/etc").unwrap();
    assert_eq!(ram.description_token(&fds, second).unwrap(), directory);
    assert!(!ram.owns_directory_base(&fds, directory));
    ram.close(&mut fds, first).unwrap();
    ram.close(&mut fds, second).unwrap();
    ram.release(&mut fds);
}

#[test]
fn full_retired_page_fifo_preserves_every_inode_cleanup_credit() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let mut files = std::vec::Vec::new();
    for i in 0..INODES {
        let root = if i < INODE_SHARE as usize {
            FIRST
        } else {
            SECOND
        };
        let name = format!("retirement-{i}");
        files.push((root, create(&mut ram, root, name.as_bytes()), name));
    }
    let first = files[0].1;
    let second = files[INODE_SHARE as usize].1;
    for i in 0..PAGES {
        let (root, token) = if i < PAGE_SHARE as usize {
            (FIRST, first)
        } else {
            (SECOND, second)
        };
        assert_eq!(ram.storage.write(token, root, 0, &[i as u8]), Ok(1));
        ram.storage
            .truncate_zero(token, proto_fs::Timestamp::legacy_ns(i as u64))
            .unwrap();
    }
    assert_eq!(ram.storage.usage(FIRST).pages, PAGE_SHARE);
    assert_eq!(
        ram.storage.usage(SECOND).pages as usize,
        PAGES - PAGE_SHARE as usize
    );
    // Empty truncation is valid with all 4096 detached credits already occupied.
    ram.storage
        .truncate_zero(first, proto_fs::Timestamp::legacy_ns(5000))
        .unwrap();
    assert_eq!(
        ram.storage.write(first, FIRST, 0, b"refused"),
        Err(NO_SPACE)
    );
    assert_eq!(ram.storage.node(first).unwrap().length, 0);
    for (root, _, name) in &files {
        ram.storage.unlink(ROOT, name.as_bytes(), *root).unwrap();
    }
    let before = ram.storage.usage(FIRST);
    assert!(ram.storage.reclaim_step());
    assert_eq!(ram.storage.usage(FIRST).inodes, before.inodes - 1);
    assert_eq!(ram.storage.usage(FIRST).pages, before.pages);
    assert!(ram.storage.reclaim_step());
    assert_eq!(ram.storage.usage(FIRST).inodes, before.inodes - 1);
    assert_eq!(ram.storage.usage(FIRST).pages, before.pages - 1);
    let mut steps = 2;
    while ram.storage.reclaim_step() {
        steps += 1;
        assert!(steps <= PAGES + INODES);
    }
    assert_eq!(steps, PAGES + INODES);
    assert_eq!(ram.storage.usage(FIRST), Usage::default());
    assert_eq!(ram.storage.usage(SECOND), Usage::default());
    for (_, token, _) in files {
        assert_eq!(ram.storage.node(token).err(), Some(NO_ENTRY));
    }
}

#[test]
fn retired_pages_never_clear_new_mappings_or_reused_overlay_slots() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let old = create(&mut ram, FIRST, b"old");
    ram.storage.write(old, FIRST, 0, b"old bytes").unwrap();
    ram.storage
        .truncate_zero(old, proto_fs::Timestamp::legacy_ns(10))
        .unwrap();
    ram.storage.write(old, FIRST, 0, b"new bytes").unwrap();
    assert!(ram.storage.reclaim_step());
    // Reuse the freed physical page while the first logical page stays live.
    ram.storage.write(old, FIRST, PAGE, b"second page").unwrap();
    let mut bytes = [0; 12];
    assert_eq!(ram.storage.read(old, 0, &mut bytes), Ok(12));
    assert_eq!(&bytes[..9], b"new bytes");
    assert_eq!(&bytes[9..], &[0; 3]);
    ram.storage
        .truncate_zero(old, proto_fs::Timestamp::legacy_ns(20))
        .unwrap();
    ram.storage.unlink(ROOT, b"old", FIRST).unwrap();
    // Inode cleanup wins this turn, while its detached pages retain their root.
    assert!(ram.storage.reclaim_step());
    let new = create(&mut ram, SECOND, b"new");
    assert_eq!(new.slot, old.slot);
    assert_ne!(new.generation, old.generation);
    ram.storage.write(new, SECOND, 0, b"replacement").unwrap();
    while ram.storage.reclaim_step() {}
    assert_eq!(ram.storage.usage(FIRST), Usage::default());
    assert_eq!(ram.storage.usage(SECOND).pages, 1);
    assert_eq!(ram.storage.read(new, 0, &mut bytes), Ok(11));
    assert_eq!(&bytes[..11], b"replacement");
    ram.storage.unlink(ROOT, b"new", SECOND).unwrap();
    assert_eq!(drain(&mut ram), 2);
    assert_eq!(ram.storage.usage(SECOND), Usage::default());
}

#[test]
fn truncation_masks_boot_bytes_and_exhaustion_preserves_live_payload() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let motd = Token {
        slot: 3,
        generation: 1,
    };
    let original_length = ram.storage.node(motd).unwrap().length;
    ram.storage
        .truncate_zero(motd, proto_fs::Timestamp::legacy_ns(10))
        .unwrap();
    // The future extension publishes only its length; the retained backend mask
    // independently prevents boot bytes returning to sparse holes and new pages.
    ram.storage.node_mut(motd).unwrap().length = original_length;
    let mut bytes = [0xff; 16];
    assert_eq!(
        ram.storage.read(motd, 0, &mut bytes),
        Ok(original_length as usize)
    );
    assert!(
        bytes[..original_length as usize]
            .iter()
            .all(|&byte| byte == 0)
    );
    ram.storage.write(motd, FIRST, 4, b"x").unwrap();
    ram.storage.read(motd, 0, &mut bytes).unwrap();
    assert_eq!(&bytes[..5], &[0, 0, 0, 0, b'x']);
    let token = create(&mut ram, FIRST, b"exhausted");
    ram.storage.write(token, FIRST, 0, b"kept").unwrap();
    let before = ram.storage.usage(FIRST);
    ram.storage.node_mut(token).unwrap().data_generation = u64::MAX;
    assert_eq!(
        ram.storage
            .truncate_zero(token, proto_fs::Timestamp::legacy_ns(100)),
        Err(NO_SPACE)
    );
    assert_eq!(ram.storage.node(token).unwrap().length, 4);
    assert_eq!(ram.storage.usage(FIRST), before);
    assert!(!ram.storage.reclaim_step());
    ram.storage.node_mut(token).unwrap().data_generation = 1;
    assert_eq!(ram.storage.read(token, 0, &mut bytes), Ok(4));
    assert_eq!(&bytes[..4], b"kept");
    assert_eq!(ram.storage.node(token).unwrap().data_generation, 1);
    assert_eq!(ram.storage.usage(FIRST), before);
    assert!(!ram.storage.reclaim_step());
}

#[test]
fn a_reservation_of_a_name_cannot_commit_after_another_one_of_the_same_name_did() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let first = ram
        .storage
        .reserve(FIRST, ROOT, b"same", (crate::REG, 0o644, 0, 0))
        .unwrap();
    let second = ram
        .storage
        .reserve(FIRST, ROOT, b"same", (crate::REG, 0o600, 0, 0))
        .unwrap();
    let before = ram.storage.name_gen(ROOT).unwrap();
    ram.storage.commit(first).unwrap();
    assert!(ram.storage.name_gen(ROOT).unwrap() > before);
    // The proof that the name was not there went with the first name.
    assert_eq!(
        ram.storage.reserved_token(second, FIRST),
        Err(proto_fs::STALE_PROOF)
    );
    assert_eq!(ram.storage.commit(second), Err(proto_fs::INVALID_ARGUMENT));
    ram.storage.cancel(second).unwrap();
    ram.storage.check_name_index();
}

#[test]
fn what_changes_names_raises_the_generation_of_their_directory_and_what_changes_a_file_does_not() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let dir = create(&mut ram, FIRST, b"dir");
    let r = ram
        .storage
        .reserve(FIRST, ROOT, b"d2", (crate::DIR, 0o755, 0, 0))
        .unwrap();
    let d2 = ram.storage.commit(r).unwrap();
    let generation_of = |ram: &Ram<'_>, t| ram.storage.name_gen(t).unwrap();
    let (root_gen, d2_gen) = (generation_of(&ram, ROOT), generation_of(&ram, d2));
    // A reservation publishes nothing.
    let r = ram
        .storage
        .reserve(FIRST, d2, b"x", (crate::REG, 0o644, 0, 0))
        .unwrap();
    assert_eq!(generation_of(&ram, d2), d2_gen);
    let bucket = name_bucket(d2, b"x");
    let stamp = ram.storage.stamp(bucket);
    let x = ram.storage.commit(r).unwrap();
    assert!(generation_of(&ram, d2) > d2_gen, "a name made");
    assert_eq!(ram.storage.stamp(bucket), stamp + 1, "the bucket counts it");
    let g = generation_of(&ram, d2);
    // The bytes, mode, owner and times of a file are no part of any directory.
    ram.storage.write(x, FIRST, 0, b"bytes").unwrap();
    ram.storage.set_attributes(x, 0o600, 5, 5).unwrap();
    ram.storage
        .truncate_zero(x, proto_fs::Timestamp::legacy_ns(5))
        .unwrap();
    assert_eq!(
        (generation_of(&ram, d2), generation_of(&ram, ROOT)),
        (g, root_gen)
    );
    // The mode of a directory is not a name, and has a generation of its own.
    let access = ram.storage.node(d2).unwrap().access_gen;
    ram.storage.set_attributes(d2, 0o700, 0, 0).unwrap();
    assert_eq!(generation_of(&ram, d2), g);
    assert_eq!(ram.storage.node(d2).unwrap().access_gen, access + 1);
    ram.storage.unlink(d2, b"x", FIRST).unwrap();
    assert!(generation_of(&ram, d2) > g, "a name gone");
    let _ = dir;
}
