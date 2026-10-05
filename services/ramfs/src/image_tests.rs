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
        &[
            bootimg::rootfs::Entry {
                path: "/program",
                mode: bootimg::rootfs::REGULAR | 0o755,
                uid: 0,
                gid: 0,
                file: 1,
            },
            bootimg::rootfs::Entry {
                path: "/dev",
                mode: bootimg::rootfs::DIRECTORY | 0o755,
                uid: 0,
                gid: 0,
                file: 0,
            },
            bootimg::rootfs::Entry {
                path: "/dev/null",
                mode: bootimg::rootfs::REGULAR | 0o666,
                uid: 0,
                gid: 0,
                file: 0,
            },
        ],
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
    assert_eq!(ram.storage.node(token).unwrap().pins, [0; 5]);
}

fn writable_inode(ram: &mut Ram<'_>, name: &[u8]) -> crate::storage::Token {
    let reservation = ram
        .storage
        .reserve(EXPENSE, ROOT, name, (REG, 0o755, 0, 0))
        .unwrap();
    ram.storage.commit(reservation).unwrap()
}
fn session() -> Fds {
    Fds {
        root: EXPENSE,
        ..Fds::default()
    }
}
#[test]
fn writer_lifetime_survives_clone_numeric_close_unlink_and_data_lease() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let token = writable_inode(&mut ram, b"program");
    let mut fds = session();
    let fd = ram
        .open_token(&mut fds, token, proto_fs::READ_WRITE, ADMIN)
        .unwrap();
    let description = ram.description_token(&fds, fd).unwrap();
    let lease = ram.capture_data_lease(&fds, fd, description).unwrap();
    let mut child = ram.clone_fds(&fds, &[fd]).unwrap();
    assert_eq!(ram.storage.node(token).unwrap().writers, 1);
    assert!(matches!(
        ram.exec_inode(token, ADMIN),
        Err(proto_fs::TEXT_BUSY)
    ));
    let mut loader = session();
    let before = ram.storage.usage(EXPENSE);
    assert_eq!(
        ram.hold_image(&mut loader, token, crate::storage::NONE),
        Err(proto_fs::TEXT_BUSY)
    );
    assert_eq!(ram.storage.usage(EXPENSE), before);
    let reader = ram
        .open_token(&mut loader, token, proto_fs::READ_ONLY, ADMIN)
        .unwrap();
    ram.storage.unlink(ROOT, b"program", EXPENSE).unwrap();
    ram.close(&mut fds, fd).unwrap();
    ram.close(&mut child, fd).unwrap();
    assert_eq!(ram.storage.node(token).unwrap().writers, 1);
    lease.cancel(&mut ram);
    assert_eq!(ram.storage.node(token).unwrap().writers, 0);
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 1);
    ram.exec_inode(token, ADMIN).unwrap();
    ram.hold_image(&mut loader, token, crate::storage::NONE)
        .unwrap();
    assert!(ram.release_image(&mut loader));
    assert!(!ram.release_image(&mut loader));
    ram.close(&mut loader, reader).unwrap();
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 0);
}
#[test]
fn tentative_writer_cancel_and_publication_preserve_one_counter() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let token = writable_inode(&mut ram, b"tentative");
    let mut fds = session();
    let before = ram.storage.usage(EXPENSE);
    let held = ram
        .prepare_open_token(&mut fds, token, proto_fs::READ_WRITE, ADMIN, None)
        .unwrap();
    assert_eq!(ram.storage.node(token).unwrap().writers, 1);
    ram.cancel_open(&mut fds, held).unwrap();
    assert_eq!(ram.cancel_open(&mut fds, held), Err(proto_fs::BAD_FD));
    assert_eq!(ram.storage.node(token).unwrap().writers, 0);
    assert_eq!(ram.storage.usage(EXPENSE), before);
    let held = ram
        .prepare_open_token(&mut fds, token, proto_fs::WRITE_ONLY, ADMIN, None)
        .unwrap();
    let fd = ram.publish_open(&mut fds, held).unwrap();
    assert_eq!(ram.storage.node(token).unwrap().writers, 1);
    ram.close(&mut fds, fd).unwrap();
    assert_eq!(ram.storage.node(token).unwrap().writers, 0);
}
#[test]
fn image_pin_refuses_new_writers_and_all_content_effects_without_resources() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let token = writable_inode(&mut ram, b"pinned");
    ram.storage.write(token, EXPENSE, 0, b"old").unwrap();
    let mut image = session();
    ram.hold_image(&mut image, token, crate::storage::NONE)
        .unwrap();
    let mut fds = session();
    let before = ram.storage.usage(EXPENSE);
    let generation = ram.storage.node(token).unwrap().data_generation;
    let times = ram.storage.node(token).unwrap().times;
    assert_eq!(
        ram.open_token(&mut fds, token, proto_fs::READ_WRITE, ADMIN),
        Err(proto_fs::TEXT_BUSY)
    );
    assert!(matches!(
        ram.prepare_open_token(
            &mut fds,
            token,
            proto_fs::READ_ONLY | proto_fs::TRUNCATE,
            ADMIN,
            None
        ),
        Err(proto_fs::TEXT_BUSY)
    ));
    assert!(matches!(
        ram.storage.prepare_data_write(token, EXPENSE, 0, 1),
        Err(proto_fs::TEXT_BUSY)
    ));
    assert!(matches!(
        ram.storage.prepare_data_truncate(token, 0),
        Err(proto_fs::TEXT_BUSY)
    ));
    assert_eq!(
        ram.storage.write(token, EXPENSE, 0, b"new"),
        Err(proto_fs::TEXT_BUSY)
    );
    assert_eq!(
        ram.storage
            .truncate_zero(token, proto_fs::Timestamp::legacy_ns(7)),
        Err(proto_fs::TEXT_BUSY)
    );
    assert_eq!(ram.storage.usage(EXPENSE), before);
    assert_eq!(ram.storage.node(token).unwrap().data_generation, generation);
    assert_eq!(ram.storage.node(token).unwrap().times, times);
    let mut bytes = [0; 3];
    assert_eq!(ram.held_image_read(&image, 0, &mut bytes), Ok(3));
    assert_eq!(&bytes, b"old");
    ram.release_image(&mut image);
    ram.storage.write(token, EXPENSE, 0, b"new").unwrap();
}
#[test]
fn image_pin_between_paid_prepare_and_commit_blocks_first_effect_and_keeps_cached_effect() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let token = writable_inode(&mut ram, b"staged");
    let mut data = ram
        .storage
        .prepare_data_write(token, EXPENSE, 0, 1)
        .unwrap();
    while !ram.storage.step_data_write(&mut data).unwrap() {}
    let mut image = session();
    ram.hold_image(&mut image, token, crate::storage::NONE)
        .unwrap();
    assert_eq!(
        ram.storage
            .commit_data_write(&mut data, b"x", proto_fs::Timestamp::ZERO),
        Err(proto_fs::TEXT_BUSY)
    );
    assert_eq!(ram.storage.node(token).unwrap().length, 0);
    ram.release_image(&mut image);
    ram.storage
        .commit_data_write(&mut data, b"x", proto_fs::Timestamp::ZERO)
        .unwrap();
    ram.hold_image(&mut image, token, crate::storage::NONE)
        .unwrap();
    ram.storage
        .commit_data_write(&mut data, b"x", proto_fs::Timestamp::legacy_ns(99))
        .unwrap();
    assert_eq!(ram.storage.node(token).unwrap().length, 1);
    while !ram.storage.cancel_data_write(&mut data).unwrap() {}
    ram.release_image(&mut image);
}
#[test]
fn put_preserves_file_access_and_allows_append_without_counter_change() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let token = writable_inode(&mut ram, b"original");
    let other = writable_inode(&mut ram, b"other");
    let mut fds = session();
    let fd = ram
        .open_token(&mut fds, token, proto_fs::READ_WRITE, ADMIN)
        .unwrap();
    let original = ram.get(&fds, fd).unwrap();
    let mut changed = original;
    changed.flags = proto_fs::READ_ONLY;
    assert_eq!(ram.put(&fds, fd, changed), Err(proto_fs::INVALID_ARGUMENT));
    changed = original;
    changed.file = crate::File::Node(other);
    assert_eq!(ram.put(&fds, fd, changed), Err(proto_fs::INVALID_ARGUMENT));
    assert_eq!(ram.get(&fds, fd).unwrap().file, original.file);
    changed = original;
    changed.flags |= proto_fs::APPEND;
    changed.offset = 7;
    ram.put(&fds, fd, changed).unwrap();
    assert_eq!(ram.storage.node(token).unwrap().writers, 1);
    assert_eq!(ram.storage.node(other).unwrap().writers, 0);
    ram.close(&mut fds, fd).unwrap();
}
#[test]
fn canonical_fixed_regular_bytes_devices_and_legacy_boot_barrier() {
    let bytes = image();
    let mut index = crate::tree::Index::new();
    let tree = crate::tree::load(&bytes, &mut index).unwrap();
    let mut ram = Ram::with_tree(proto_fs::Timestamp::ZERO, tree);
    for (slot, file) in [(3, crate::File::Motd), (4, crate::File::Scratch)] {
        let token = crate::storage::Token {
            slot,
            generation: 1,
        };
        ram.storage.node_mut(token).unwrap().mode = 0o755;
        ram.storage.write(token, EXPENSE, 0, b"captured").unwrap();
        ram.exec_inode(token, ADMIN).unwrap();
        assert!(matches!(
            ram.exec_token(token, ADMIN),
            Err(proto_fs::ACCESS_DENIED)
        ));
        let mut image = session();
        ram.hold_image(&mut image, token, crate::storage::NONE)
            .unwrap();
        let mut out = [0; 8];
        assert_eq!(ram.held_image_read(&image, 0, &mut out), Ok(8));
        assert_eq!(&out, b"captured");
        assert_eq!(ram.token(file), token);
        ram.release_image(&mut image);
    }
    let mut fds = session();
    assert_eq!(
        ram.open_file(&mut fds, crate::File::Motd, proto_fs::WRITE_ONLY),
        Err(proto_fs::ACCESS_DENIED)
    );
    let device = ram.storage.resolve(b"/dev/null").unwrap();
    let device_fd = ram
        .open_token(&mut fds, device, proto_fs::READ_WRITE, ADMIN)
        .unwrap();
    assert_eq!(ram.storage.node(device).unwrap().writers, 0);
    ram.close(&mut fds, device_fd).unwrap();
    for token in [ROOT, device] {
        assert!(matches!(
            ram.exec_inode(token, ADMIN),
            Err(proto_fs::ACCESS_DENIED)
        ));
        assert_eq!(
            ram.hold_image(&mut fds, token, crate::storage::NONE),
            Err(proto_fs::ACCESS_DENIED)
        );
    }
}
#[test]
fn writer_and_image_pin_exhaustion_roll_back_exact_description_charge() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let token = writable_inode(&mut ram, b"exhausted");
    let mut fds = session();
    let before = ram.storage.usage(EXPENSE);
    ram.storage.node_mut(token).unwrap().writers = u16::MAX;
    assert_eq!(
        ram.open_token(&mut fds, token, proto_fs::READ_WRITE, ADMIN),
        Err(proto_fs::NO_SPACE)
    );
    assert_eq!(ram.storage.node(token).unwrap().pins, [0; 5]);
    assert_eq!(ram.storage.usage(EXPENSE), before);
    ram.storage.node_mut(token).unwrap().writers = 0;
    ram.storage.node_mut(token).unwrap().pins[Pin::Image as usize] = u16::MAX;
    assert_eq!(
        ram.hold_image(&mut fds, token, crate::storage::NONE),
        Err(proto_fs::NO_SPACE)
    );
    assert_eq!(ram.storage.usage(EXPENSE), before);
    assert!(fds.image_hold.is_none());
    ram.storage.node_mut(token).unwrap().pins[Pin::Image as usize] = 0;
    let fd = ram
        .open_token(&mut fds, token, proto_fs::READ_WRITE, ADMIN)
        .unwrap();
    assert_eq!(ram.storage.node(token).unwrap().writers, 1);
    ram.close(&mut fds, fd).unwrap();
}
#[test]
fn writers_use_node_padding_and_leave_all_fixed_pool_sizes_unchanged() {
    assert_eq!(core::mem::size_of::<crate::storage::Node>(), 136);
    assert_eq!(core::mem::align_of::<crate::storage::Node>(), 8);
    std::println!(
        "Node={} State={} Ram={} Fds={} ImageHold={}",
        core::mem::size_of::<crate::storage::Node>(),
        core::mem::size_of::<crate::storage::State>(),
        core::mem::size_of::<Ram<'_>>(),
        core::mem::size_of::<Fds>(),
        core::mem::size_of::<crate::image::ImageHold>()
    );
}

#[test]
fn hardlink_canonical_writer_blocks_image_alias_and_origin_root_survives_rebind() {
    let bytes = image();
    let mut index = crate::tree::Index::new();
    let tree = crate::tree::load(&bytes, &mut index).unwrap();
    let mut ram = Ram::with_tree(proto_fs::Timestamp::ZERO, tree);
    let token = ram.storage.resolve(b"/program").unwrap();
    ram.storage.link(EXPENSE, ROOT, b"alias", token).unwrap();
    let alias = ram.storage.resolve(b"/alias").unwrap();
    assert_eq!(token, alias);
    let mut fds = session();
    // The trusted model installs a writable description to exercise canonical aliases.
    let fd = ram
        .insert(
            &mut fds,
            crate::Open {
                file: crate::File::Node(token),
                offset: 0,
                flags: proto_fs::WRITE_ONLY,
            },
        )
        .unwrap();
    assert!(matches!(
        ram.exec_token(alias, ADMIN),
        Err(proto_fs::TEXT_BUSY)
    ));
    assert!(matches!(
        ram.exec("/alias", crate::Who { euid: 0, egid: 0 }),
        Err(proto_fs::TEXT_BUSY)
    ));
    let mut loader = session();
    let entry = ram.storage.node(alias).unwrap().boot;
    assert_eq!(
        ram.hold_image(&mut loader, alias, entry),
        Err(proto_fs::TEXT_BUSY)
    );
    fds.root = Root {
        id: 301,
        generation: 2,
    };
    ram.close(&mut fds, fd).unwrap();
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 0);
    assert_eq!(ram.storage.usage(fds.root).descriptions, 0);
    ram.exec_token(alias, ADMIN).unwrap();
    ram.hold_image(&mut loader, alias, entry).unwrap();
    assert_eq!(
        ram.open_token(&mut fds, token, proto_fs::WRITE_ONLY, ADMIN),
        Err(proto_fs::TEXT_BUSY)
    );
    ram.release_image(&mut loader);
    assert_eq!(
        ram.open_token(&mut fds, token, proto_fs::WRITE_ONLY, ADMIN),
        Err(proto_fs::ACCESS_DENIED)
    );
}
#[test]
fn paid_truncate_pin_commit_race_and_cached_result_preserve_exact_bytes() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let token = writable_inode(&mut ram, b"truncate");
    ram.storage.write(token, EXPENSE, 0, b"data").unwrap();
    let mut data = ram.storage.prepare_data_truncate(token, 2).unwrap();
    while !ram.storage.step_data_truncate(&mut data).unwrap() {}
    let mut image = session();
    ram.hold_image(&mut image, token, crate::storage::NONE)
        .unwrap();
    assert_eq!(
        ram.storage
            .commit_data_truncate(&mut data, proto_fs::Timestamp::ZERO),
        Err(proto_fs::TEXT_BUSY)
    );
    assert_eq!(ram.storage.node(token).unwrap().length, 4);
    ram.release_image(&mut image);
    ram.storage
        .commit_data_truncate(&mut data, proto_fs::Timestamp::ZERO)
        .unwrap();
    ram.hold_image(&mut image, token, crate::storage::NONE)
        .unwrap();
    ram.storage
        .commit_data_truncate(&mut data, proto_fs::Timestamp::legacy_ns(77))
        .unwrap();
    assert_eq!(ram.storage.node(token).unwrap().length, 2);
    assert_eq!(
        ram.storage.node(token).unwrap().times[1],
        proto_fs::Timestamp::ZERO
    );
    while !ram.storage.cancel_data_truncate(&mut data).unwrap() {}
    ram.release_image(&mut image);
}

#[test]
fn closed_numeric_slot_reuse_preserves_original_retained_writer_and_exact_cleanup() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let old = writable_inode(&mut ram, b"old");
    let new = writable_inode(&mut ram, b"new");
    let mut fds = session();
    let fd = ram
        .open_token(&mut fds, old, proto_fs::READ_WRITE, ADMIN)
        .unwrap();
    let description = ram.description_token(&fds, fd).unwrap();
    let lease = ram.capture_data_lease(&fds, fd, description).unwrap();
    ram.close(&mut fds, fd).unwrap();
    assert_eq!(
        ram.open_token(&mut fds, new, proto_fs::READ_WRITE, ADMIN),
        Ok(fd)
    );
    assert_ne!(ram.description_token(&fds, fd).unwrap(), description);
    assert_eq!(ram.storage.node(old).unwrap().writers, 1);
    assert_eq!(ram.storage.node(new).unwrap().writers, 1);
    lease.cancel(&mut ram);
    assert_eq!(ram.storage.node(old).unwrap().writers, 0);
    assert_eq!(ram.storage.node(new).unwrap().writers, 1);
    ram.exec_inode(old, ADMIN).unwrap();
    assert!(matches!(
        ram.exec_inode(new, ADMIN),
        Err(proto_fs::TEXT_BUSY)
    ));
    ram.close(&mut fds, fd).unwrap();
    assert_eq!(ram.storage.node(new).unwrap().writers, 0);
}

#[test]
fn attempted_stage_revokes_reads_and_preserves_inode_until_last_session_gone() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let token = writable_inode(&mut ram, b"runtime");
    ram.storage.write(token, EXPENSE, 0, b"ELF bytes").unwrap();
    let mut held = session();
    ram.hold_image(&mut held, token, crate::storage::NONE)
        .unwrap();
    let now = proto_fs::Timestamp::new(-7, 23).unwrap();
    assert_eq!(ram.arm_image_execution(&mut held, token, now), Ok(true));
    assert_eq!(ram.storage.node(token).unwrap().times[0], now);
    let mut source = crate::image::ImageOutcome {
        job: 9,
        label: 11,
        token,
        phase: crate::image::ImagePhase::Prepared,
    };
    source.begin_stage().unwrap();
    assert_eq!(source.phase, crate::image::ImagePhase::AbortRequired);
    assert_eq!(source.begin_stage(), Err(proto_fs::IMAGE_ABORT_REQUIRED));
    // A retained-audit failure or explicit Close revokes the old read tuple.
    held.binding = crate::authority::Binding::Cleanup;
    held.root = Root {
        id: 301,
        generation: 2,
    };
    let before = ram.storage.usage(EXPENSE);
    let mut out = [0; 9];
    assert_eq!(
        ram.held_image_read(&held, 0, &mut out),
        Err(proto_fs::PERMISSION)
    );
    assert_eq!(ram.held_image_information(&held), Err(proto_fs::PERMISSION));
    assert!(!ram.release_loading_image(&mut held));
    assert!(!ram.release_step(&mut held));
    assert_eq!(ram.storage.usage(EXPENSE), before);
    assert_eq!(
        ram.storage.node(token).unwrap().pins[Pin::Image as usize],
        1
    );
    assert_eq!(
        ram.storage.write(token, EXPENSE, 0, b"new"),
        Err(proto_fs::TEXT_BUSY)
    );
    assert_eq!(
        ram.open_token(&mut session(), token, proto_fs::WRITE_ONLY, ADMIN),
        Err(proto_fs::TEXT_BUSY)
    );
    assert_eq!(
        ram.arm_image_execution(&mut held, token, proto_fs::Timestamp::ZERO),
        Ok(false)
    );
    assert_eq!(ram.storage.node(token).unwrap().times[0], now);
    // Canonical GONE occurs after the Process custodian releases its last copy.
    ram.release(&mut held);
    ram.release(&mut held);
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 0);
    assert_eq!(
        ram.storage.node(token).unwrap().pins[Pin::Image as usize],
        0
    );
    assert_eq!(ram.storage.write(token, EXPENSE, 0, b"new"), Ok(3));
}

#[test]
fn fork_image_keeps_exact_origin_after_parent_authority_and_account_reuse() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let token = writable_inode(&mut ram, b"fork-runtime");
    ram.storage
        .write(token, EXPENSE, 0, b"old executable")
        .unwrap();
    let mut parent = session();
    ram.hold_image(&mut parent, token, crate::storage::NONE)
        .unwrap();
    let now = proto_fs::Timestamp::new(33, 99).unwrap();
    ram.arm_image_execution(&mut parent, token, now).unwrap();
    parent.binding = crate::authority::Binding::Cleanup;
    parent.root = Root {
        id: 999,
        generation: 2,
    };
    let mut child = Fds {
        root: Root {
            id: 777,
            generation: 1,
        },
        ..Fds::default()
    };
    ram.hold_fork_image(&mut child, &parent).unwrap();
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 2);
    assert_eq!(ram.storage.usage(parent.root).descriptions, 0);
    assert_eq!(ram.storage.usage(child.root).descriptions, 0);
    assert_eq!(
        ram.storage.node(token).unwrap().pins[Pin::Image as usize],
        2
    );
    ram.storage.unlink(ROOT, b"fork-runtime", EXPENSE).unwrap();
    let fresh = writable_inode(&mut ram, b"fork-runtime");
    assert_ne!(token, fresh);
    ram.release(&mut parent);
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 1);
    assert_eq!(
        ram.storage.node(token).unwrap().pins[Pin::Image as usize],
        1
    );
    assert_eq!(ram.storage.node(token).unwrap().times[0], now);
    let mut out = [0; 14];
    assert_eq!(ram.held_image_read(&child, 0, &mut out), Ok(14));
    assert_eq!(&out, b"old executable");
    assert_eq!(
        ram.storage.write(token, EXPENSE, 0, b"new"),
        Err(proto_fs::TEXT_BUSY)
    );
    assert_eq!(ram.storage.write(fresh, EXPENSE, 0, b"new"), Ok(3));
    child.binding = crate::authority::Binding::Cleanup;
    assert!(!ram.release_step(&mut child));
    ram.release(&mut child);
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 0);
    assert!(ram.storage.node(token).is_err());
}

#[test]
fn stage_preflight_and_strict_accepted_reply_preserve_exact_once_effect() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let token = writable_inode(&mut ram, b"first");
    let other = writable_inode(&mut ram, b"other");
    let mut held = session();
    ram.hold_image(&mut held, token, crate::storage::NONE)
        .unwrap();
    let times = ram.storage.node(token).unwrap().times;
    let usage = ram.storage.usage(EXPENSE);
    assert_eq!(
        ram.arm_image_execution(&mut held, other, proto_fs::Timestamp::ZERO),
        Err(proto_fs::STALE_PROOF)
    );
    assert_eq!(ram.storage.node(token).unwrap().times, times);
    assert_eq!(ram.storage.usage(EXPENSE), usage);
    assert!(ram.release_loading_image(&mut held));
    use crate::image::stage_accepted_reply;
    assert!(stage_accepted_reply(&[0; 8], 0));
    for size in 0..8 {
        assert!(!stage_accepted_reply(&[0; 8][..size], 0));
    }
    assert!(!stage_accepted_reply(&[0; 9], 0));
    assert!(!stage_accepted_reply(&[0; 8], 1));
    for i in 0..8 {
        let mut bad = [0; 8];
        bad[i] = 1;
        assert!(!stage_accepted_reply(&bad, 0));
    }
}

#[test]
fn fork_preflight_preserves_full_origin_budget_and_loading_source() {
    let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
    let token = writable_inode(&mut ram, b"fork-budget");
    let mut parent = session();
    ram.hold_image(&mut parent, token, crate::storage::NONE)
        .unwrap();
    let mut child = Fds {
        root: Root {
            id: 777,
            generation: 1,
        },
        ..Fds::default()
    };
    let usage = ram.storage.usage(EXPENSE);
    assert_eq!(
        ram.hold_fork_image(&mut child, &parent),
        Err(proto_fs::PERMISSION)
    );
    assert_eq!(ram.storage.usage(EXPENSE), usage);
    assert!(child.image_hold.is_none());
    ram.arm_image_execution(&mut parent, token, proto_fs::Timestamp::ZERO)
        .unwrap();
    for _ in 1..crate::storage::DESCRIPTION_SHARE {
        ram.storage.charge_description(EXPENSE).unwrap();
    }
    let usage = ram.storage.usage(EXPENSE);
    assert_eq!(
        ram.hold_fork_image(&mut child, &parent),
        Err(proto_fs::TOO_MANY_OPEN_FILES)
    );
    assert_eq!(ram.storage.usage(EXPENSE), usage);
    assert_eq!(
        ram.storage.node(token).unwrap().pins[Pin::Image as usize],
        1
    );
    assert!(child.image_hold.is_none());
    ram.storage.release_description(EXPENSE);
    ram.hold_fork_image(&mut child, &parent).unwrap();
    ram.release(&mut parent);
    ram.release(&mut child);
    for _ in 2..crate::storage::DESCRIPTION_SHARE {
        ram.storage.release_description(EXPENSE);
    }
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 0);
}

#[test]
fn fork_snapshot_admission_and_final_child_cleanup_preserve_exact_origin_and_atime() {
    let bytes = image();
    let mut index = crate::tree::Index::new();
    let tree = crate::tree::load(&bytes, &mut index).unwrap();
    let mut ram = Ram::with_tree(proto_fs::Timestamp::legacy_ns(0), tree);
    let token = ram.storage.resolve(b"/program").unwrap();
    let entry = ram.storage.node(token).unwrap().boot;
    let target_root = Root {
        id: 301,
        generation: 2,
    };
    let mut parent = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    ram.hold_image(&mut parent, token, entry).unwrap();
    let mut child = Fds {
        root: target_root,
        ..Fds::default()
    };
    let unarmed = parent.image_hold.unwrap();
    assert_eq!(
        ram.hold_fork_snapshot(&mut child, unarmed),
        Err(proto_fs::PERMISSION)
    );
    assert!(child.image_hold.is_none());
    let time = proto_fs::Timestamp::new(-5, 42).unwrap();
    ram.arm_image_execution(&mut parent, token, time).unwrap();
    let held = parent.image_hold.unwrap();
    parent.binding = crate::authority::Binding::Cleanup;
    parent.root = target_root;
    let charge = ram.storage.charge_preparation(target_root).unwrap();
    ram.hold_fork_snapshot(&mut child, held).unwrap();
    assert_eq!(ram.storage.node(token).unwrap().times[0], time);
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 2);
    assert_eq!(ram.storage.usage(target_root).descriptions, 0);
    ram.storage.release_preparation(charge);
    ram.release(&mut parent);
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 1);
    assert_eq!(
        ram.storage.node(token).unwrap().pins[Pin::Image as usize],
        1
    );
    assert!(!ram.release_loading_image(&mut child));
    assert_eq!(
        ram.storage.write(token, target_root, 0, b"x"),
        Err(proto_fs::TEXT_BUSY)
    );
    ram.release(&mut child);
    ram.release(&mut child);
    assert_eq!(
        ram.storage.node(token).unwrap().pins[Pin::Image as usize],
        0
    );
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 0);
    assert_eq!(ram.storage.preparations_used(), 0);
}

#[test]
fn clone_preparation_shares_existing_global_and_root_budget_before_any_image_reference() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let other = Root {
        id: 301,
        generation: 1,
    };
    let mut paid = [0; crate::storage::PREPARATIONS];
    for (i, p) in paid.iter_mut().enumerate() {
        *p = ram
            .storage
            .charge_preparation(if i < 96 { EXPENSE } else { other })
            .unwrap();
    }
    let mut child = Fds {
        root: other,
        ..Fds::default()
    };
    assert_eq!(
        ram.storage.charge_preparation(other),
        Err(proto_fs::TOO_MANY_OPEN_FILES)
    );
    assert!(child.image_hold.is_none());
    assert_eq!(ram.storage.usage(other).descriptions, 0);
    for p in paid {
        ram.storage.release_preparation(p);
    }
    child.resolvers.fill(1);
    assert!(!child.preparation_available());
    child.resolvers[15] = 0;
    assert!(child.preparation_available());
    assert_eq!(ram.storage.preparations_used(), 0);
}
