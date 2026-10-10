// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The live image tree and storage account exercise loading pin cleanup.
extern crate std;
use crate::{
    Fds, REG, Ram,
    authority::Identity,
    storage::{Pin, ROOT, Root},
};
const EXPENSE: Root = Root {
    id: 300,
    generation: 1,
};
const ADMIN: Identity = Identity {
    uid: 0,
    gid: 0,
    groups: proto_process::Groups::EMPTY,
};
fn image() -> std::vec::Vec<u8> {
    let table = bootimg::rootfs::write::rootfs(
        &[bootimg::rootfs::Entry {
            path: "/program",
            mode: bootimg::rootfs::REGULAR | 0o755,
            uid: 0,
            gid: 0,
            file: 1,
        }],
        3,
    )
    .unwrap();
    bootimg::write::image(&[
        ("init", b"init"),
        ("program", b"old image bytes"),
        ("rootfs", &table),
    ])
    .unwrap()
}
#[test]
fn image_pin_keeps_unlinked_bytes_and_cleanup_uses_its_original_root() {
    let bytes = image();
    let mut index = crate::tree::Index::new();
    let tree = crate::tree::load(&bytes, &mut index).unwrap();
    let mut ram = Ram::with_tree(proto_fs::Timestamp::legacy_ns(0), tree);
    let token = ram.storage.resolve(b"/program").unwrap();
    let entry = ram.storage.node(token).unwrap().boot;
    let mut fds = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    ram.hold_image(&mut fds, token, entry).unwrap();
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 1);
    assert_eq!(
        ram.storage.node(token).unwrap().pins[Pin::Image as usize],
        1
    );
    assert_eq!(
        ram.hold_image(&mut fds, token, entry),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    ram.storage.unlink(ROOT, b"program", EXPENSE).unwrap();
    let reserved = ram
        .storage
        .reserve(EXPENSE, ROOT, b"program", (REG, 0o600, 0, 0))
        .unwrap();
    let fresh = ram.storage.commit(reserved).unwrap();
    ram.storage.write(fresh, EXPENSE, 0, b"new bytes").unwrap();
    assert_ne!(token, fresh);
    let mut out = [0; 15];
    assert_eq!(ram.held_image_read(&fds, 0, &mut out), Ok(15));
    assert_eq!(&out, b"old image bytes");
    assert_eq!(ram.held_image_information(&fds).unwrap().links, 0);
    let mut child = ram.clone_fds(&fds, &[]).unwrap();
    assert_eq!(
        ram.held_image_read(&child, 0, &mut out),
        Err(proto_fs::BAD_FD)
    );
    ram.release(&mut child);
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 1);
    // Cleanup owns the originating account even after the session enters another binding.
    fds.root = Root {
        id: 301,
        generation: 1,
    };
    assert!(ram.release_step(&mut fds));
    assert!(!ram.release_step(&mut fds));
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 0);
    assert_eq!(ram.storage.usage(fds.root).descriptions, 0);
    assert_eq!(
        ram.held_image_read(&fds, 0, &mut out),
        Err(proto_fs::BAD_FD)
    );
    assert_eq!(
        ram.storage.node(fresh).unwrap().pins[Pin::Image as usize],
        0
    );
}
#[test]
fn full_root_description_account_refuses_image_before_pin_and_recovers_one_credit() {
    let bytes = image();
    let mut index = crate::tree::Index::new();
    let tree = crate::tree::load(&bytes, &mut index).unwrap();
    let mut ram = Ram::with_tree(proto_fs::Timestamp::legacy_ns(0), tree);
    let token = ram.storage.resolve(b"/program").unwrap();
    let entry = ram.storage.node(token).unwrap().boot;
    let mut filled = [Fds {
        root: EXPENSE,
        ..Fds::default()
    }; 3];
    for fds in &mut filled {
        for _ in 0..32 {
            ram.open_token(fds, token, proto_fs::READ_ONLY, ADMIN)
                .unwrap();
        }
    }
    let mut image = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    assert_eq!(
        ram.hold_image(&mut image, token, entry),
        Err(proto_fs::TOO_MANY_OPEN_FILES)
    );
    assert!(image.image_hold.is_none());
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 96);
    assert_eq!(
        ram.storage.node(token).unwrap().pins[Pin::Image as usize],
        0
    );
    ram.close(&mut filled[0], 3).unwrap();
    ram.hold_image(&mut image, token, entry).unwrap();
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 96);
    ram.release(&mut image);
    ram.release(&mut image);
    for fds in &mut filled {
        ram.release(fds);
    }
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 0);
    assert_eq!(
        ram.storage.node(token).unwrap().pins,
        [0; crate::storage::PIN_KINDS]
    );
}
