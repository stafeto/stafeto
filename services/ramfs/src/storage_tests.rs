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

#[test]
fn inode_and_name_shares_leave_a_second_roots_reserve() {
    let mut ram = Ram::new(0);
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
    let mut ram = Ram::new(0);
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
    let mut ram = Ram::new(0);
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
    let mut ram = Ram::new(0);
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
    let mut ram = Ram::with_tree(0, tree);
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
    let mut ram = Ram::new(0);
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
    let mut ram = Ram::new(0);
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
