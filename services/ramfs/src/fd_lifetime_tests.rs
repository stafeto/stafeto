// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::*;
use proto_fs::READ_WRITE;

fn identity() -> authority::Identity {
    authority::Identity {
        uid: 0,
        gid: 0,
        groups: proto_process::Groups::EMPTY,
    }
}
fn held(ram: &Ram<'_>, fds: &Fds, fd: u32) -> TentativeOpen {
    TentativeOpen {
        fd,
        description: ram.description_token(fds, fd).unwrap(),
    }
}
fn counts(ram: &Ram<'_>, token: Token) -> (u16, u16) {
    let shared = ram.descriptions[token.slot as usize].as_ref().unwrap();
    assert_eq!(shared.generation, token.generation);
    (shared.refs, shared.fd_refs)
}

#[test]
fn last_real_fd_detaches_before_retained_io_and_shared_fork_description() {
    let mut ram = Ram::default();
    let mut parent = Fds::default();
    let fd = ram.open(&mut parent, "/etc/motd", READ_ONLY).unwrap();
    let original = held(&ram, &parent, fd);
    let inode = ram.live_description(&parent, original).unwrap().0;
    let mut child = ram.clone_fds(&parent, &[fd, fd]).unwrap();
    assert_eq!(held(&ram, &child, fd), original);
    assert_eq!(counts(&ram, original.description), (2, 2));
    assert_eq!(
        ram.detach_descriptor(&mut parent, original),
        Ok(Some(DescriptorClose {
            inode,
            description: original.description,
            last_fd: false,
        }))
    );
    assert_eq!(counts(&ram, original.description), (2, 1));
    assert_eq!(ram.live_description(&parent, original), Err(BAD_FD));
    assert_eq!(ram.detach_descriptor(&mut parent, original), Ok(None));
    assert_eq!(ram.read(&mut parent, fd, &mut [0; 3]), Ok(3));
    let mut output = [0; 3];
    assert_eq!(ram.read(&mut child, fd, &mut output), Ok(3));
    assert_eq!(&output, b"fet");
    assert_eq!(
        ram.detach_descriptor(&mut child, original),
        Ok(Some(DescriptorClose {
            inode,
            description: original.description,
            last_fd: true,
        }))
    );
    assert_eq!(counts(&ram, original.description), (2, 0));
    assert_eq!(ram.storage.usage(parent.root).descriptions, 1);
    ram.close(&mut child, fd).unwrap();
    assert_eq!(counts(&ram, original.description), (1, 0));
    assert_eq!(ram.read(&mut parent, fd, &mut [0; 1]), Ok(1));
    ram.close(&mut parent, fd).unwrap();
    assert_eq!(ram.open_descriptions(), 0);
    assert_eq!(ram.storage.usage(parent.root).descriptions, 0);
}

#[test]
fn unreturned_open_has_only_physical_custody_until_first_publication() {
    let mut ram = Ram::default();
    let mut fds = Fds::default();
    let inode = ram.storage.resolve(b"/etc/motd").unwrap();
    let first = ram
        .prepare_open_token(&mut fds, inode, READ_ONLY, identity(), None)
        .unwrap();
    assert_eq!(counts(&ram, first.description), (1, 0));
    assert_eq!(ram.live_description(&fds, first), Err(BAD_FD));
    assert_eq!(ram.detach_descriptor(&mut fds, first), Ok(None));
    ram.cancel_open(&mut fds, first).unwrap();
    assert_eq!(ram.open_descriptions(), 0);
    let second = ram
        .prepare_open_token(&mut fds, inode, READ_ONLY, identity(), None)
        .unwrap();
    assert_eq!(second.fd, first.fd);
    assert_ne!(second.description, first.description);
    assert_eq!(ram.publish_open(&mut fds, second), Ok(second.fd));
    assert_eq!(counts(&ram, second.description), (1, 1));
    assert_eq!(ram.live_description(&fds, second), Ok((inode, READ_ONLY)));
    assert_eq!(ram.detach_descriptor(&mut fds, first), Ok(None));
    assert_eq!(counts(&ram, second.description), (1, 1));
    assert_eq!(ram.close_exact_description(&mut fds, first), Ok(false));
    assert!(
        ram.detach_descriptor(&mut fds, second)
            .unwrap()
            .unwrap()
            .last_fd
    );
    ram.close(&mut fds, second.fd).unwrap();
}

#[test]
fn repeated_finish_preserves_one_real_reference_and_retired_physical_custody() {
    let mut ram = Ram::default();
    let mut fds = Fds::default();
    let inode = ram.storage.resolve(b"/etc/motd").unwrap();
    let open = ram
        .prepare_open_token(&mut fds, inode, READ_ONLY, identity(), None)
        .unwrap();
    let key = proto_fs::OpenKey {
        slot: 0,
        generation: 1,
    };
    for _ in 0..3 {
        assert_eq!(ram.finish_open(&mut fds, key, open), Ok(open));
        assert_eq!(counts(&ram, open.description), (1, 1));
    }
    assert!(
        ram.detach_descriptor(&mut fds, open)
            .unwrap()
            .unwrap()
            .last_fd
    );
    assert_eq!(counts(&ram, open.description), (1, 0));
    assert_eq!(ram.finish_open(&mut fds, key, open), Ok(open));
    assert_eq!(counts(&ram, open.description), (1, 0));
    assert_eq!(ram.live_description(&fds, open), Err(BAD_FD));
    ram.cancel_finished_open(&mut fds, key).unwrap();
    assert_eq!(ram.open_descriptions(), 0);
}

#[test]
fn clone_rejects_closed_real_fd_before_all_reference_and_destination_changes() {
    let mut ram = Ram::default();
    let mut source = Fds::default();
    let good_fd = ram.open(&mut source, "/etc/motd", READ_ONLY).unwrap();
    let bad_fd = ram.open(&mut source, "/tmp/probe", READ_WRITE).unwrap();
    let good = held(&ram, &source, good_fd);
    let bad = held(&ram, &source, bad_fd);
    ram.detach_descriptor(&mut source, bad).unwrap();
    let mut destination = Fds::default();
    assert_eq!(
        ram.clone_fds_into(&source, &[good_fd, bad_fd], &mut destination),
        Err(BAD_FD)
    );
    assert!(destination.fresh_clone_destination());
    assert_eq!(counts(&ram, good.description), (1, 1));
    assert_eq!(counts(&ram, bad.description), (1, 0));
    ram.release(&mut source);
    assert_eq!(ram.open_descriptions(), 0);
}

#[test]
fn real_reference_bookkeeping_has_measured_fixed_layout() {
    std::println!(
        "Shared={} Fds={}",
        core::mem::size_of::<Shared>(),
        core::mem::size_of::<Fds>()
    );
    assert_eq!(core::mem::size_of::<Shared>(), 72);
    assert_eq!(core::mem::size_of::<Fds>(), 2816);
}
