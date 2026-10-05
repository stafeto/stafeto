// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::{
    DIR, Fds, REG, Ram,
    authority::Identity,
    directory::*,
    storage::{ROOT, Root, Token},
};
use proto_fs::{READ_ONLY, STALE_PROOF, Timestamp};
use proto_process::Groups;
const EXPENSE: Root = Root {
    id: 11,
    generation: 7,
};
const ADMIN: Identity = Identity {
    uid: 0,
    gid: 0,
    groups: Groups::EMPTY,
};
fn create(ram: &mut Ram<'_>, parent: Token, name: &[u8], kind: u32) -> Token {
    let r = ram
        .storage
        .reserve(EXPENSE, parent, name, (kind, 0o755, 0, 0))
        .unwrap();
    ram.storage.commit(r).unwrap()
}
fn read(
    ram: &mut Ram<'_>,
    fds: &Fds,
    fd: u32,
    limit: usize,
    format: DirectoryFormat,
    now: Timestamp,
) -> (Vec<u8>, i64) {
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let mut j = ram
        .prepare_directory(fds, fd, charge, ADMIN, limit, format)
        .unwrap();
    for _ in 0..1000 {
        if j.step(ram, ADMIN).unwrap() {
            break;
        }
    }
    let DirectoryOutcome::Bytes { next, .. } = j.commit(ram, ADMIN, now).unwrap() else {
        panic!("expected byte result");
    };
    let bytes = j.bytes().unwrap().to_vec();
    assert_eq!(
        j.commit(ram, ADMIN, Timestamp::ZERO).unwrap(),
        j.outcome().unwrap()
    );
    assert!(j.cancel_step(ram));
    ram.storage.release_preparation(charge);
    (bytes, next)
}
fn entries(bytes: &[u8]) -> Vec<(i64, u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let len = u16::from_le_bytes(bytes[at + 16..at + 18].try_into().unwrap()) as usize;
        assert_eq!(len % 8, 0);
        let name = &bytes[at + 19..at + len];
        let nul = name.iter().position(|&b| b == 0).unwrap();
        out.push((
            i64::from_le_bytes(bytes[at + 8..at + 16].try_into().unwrap()),
            bytes[at + 18],
            name[..nul].to_vec(),
        ));
        at += len;
    }
    out
}
#[test]
fn directory_prefix_cursor_shared_clone_and_eof_atime_are_cached_once() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let dir = create(&mut ram, ROOT, b"dir", DIR);
    for name in [b"a", b"b", b"c", b"d"] {
        create(&mut ram, dir, name, REG);
    }
    let mut fds = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    let fd = ram.open(&mut fds, "/dir", READ_ONLY).unwrap();
    let mut clone = ram.clone_fds(&fds, &[fd]).unwrap();
    let first = read(
        &mut ram,
        &fds,
        fd,
        proto_fs::MAX_READ,
        DirectoryFormat::Linux64,
        Timestamp::legacy_ns(7),
    );
    let e = entries(&first.0);
    assert_eq!(e.len(), 3);
    assert_eq!(e[0].2, b".");
    assert_eq!(e[1].2, b"..");
    assert_eq!(e[2].2, b"a");
    let second = read(
        &mut ram,
        &clone,
        fd,
        proto_fs::MAX_READ,
        DirectoryFormat::PosixDent,
        Timestamp::legacy_ns(8),
    );
    assert_eq!(
        entries(&second.0)
            .iter()
            .map(|e| e.2.clone())
            .collect::<Vec<_>>(),
        vec![b"b".to_vec(), b"c".to_vec(), b"d".to_vec()]
    );
    let eof = read(
        &mut ram,
        &fds,
        fd,
        0,
        DirectoryFormat::PosixDent,
        Timestamp::legacy_ns(9),
    );
    assert!(eof.0.is_empty());
    assert_eq!(eof.1, second.1);
    assert_eq!(
        ram.storage.node(dir).unwrap().times[0],
        Timestamp::legacy_ns(9)
    );
    ram.directory_seek(&fds, fd, first.1).unwrap();
    let again = read(
        &mut ram,
        &clone,
        fd,
        1016,
        DirectoryFormat::Linux64,
        Timestamp::legacy_ns(10),
    );
    assert_eq!(again.0, second.0);
    ram.release(&mut clone);
    ram.release(&mut fds);
}
#[test]
fn pending_cursor_or_namespace_change_refuses_before_effect_and_tiny_buffer_keeps_state() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let dir = create(&mut ram, ROOT, b"dir", DIR);
    let mut fds = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    let fd = ram.open(&mut fds, "/dir", READ_ONLY).unwrap();
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let mut j = ram
        .prepare_directory(&fds, fd, charge, ADMIN, 0, DirectoryFormat::Linux64)
        .unwrap();
    let mut failed = false;
    for _ in 0..1000 {
        match j.step(&ram, ADMIN) {
            Err(proto_fs::INVALID_ARGUMENT) => {
                failed = true;
                break;
            }
            Ok(false) => (),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(failed);
    assert_eq!(ram.storage.node(dir).unwrap().times[0], Timestamp::ZERO);
    assert_eq!(
        ram.seek_from(&mut fds, fd, 0, proto_fs::SeekFrom::Current),
        Ok(0)
    );
    j.cancel_step(&mut ram);
    ram.storage.release_preparation(charge);
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let mut j = ram
        .prepare_directory(&fds, fd, charge, ADMIN, 1016, DirectoryFormat::Linux64)
        .unwrap();
    while !j.step(&ram, ADMIN).unwrap() {}
    ram.directory_seek(&fds, fd, 1).unwrap();
    assert_eq!(
        j.commit(&mut ram, ADMIN, Timestamp::legacy_ns(7)),
        Err(STALE_PROOF)
    );
    j.cancel_step(&mut ram);
    ram.storage.release_preparation(charge);
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let mut j = ram
        .prepare_directory(&fds, fd, charge, ADMIN, 1016, DirectoryFormat::Linux64)
        .unwrap();
    create(&mut ram, dir, b"a", REG);
    assert_eq!(j.step(&ram, ADMIN), Err(STALE_PROOF));
    j.cancel_step(&mut ram);
    ram.storage.release_preparation(charge);
    ram.release(&mut fds);
}

pub(crate) fn rename(ram: &mut Ram<'_>, source: &[u8], dest: &[u8]) {
    use crate::{
        namespace::{NamespaceIntent, NamespaceOutcome, NamespacePath},
        resolve::{Intent, Progress, Resolve},
    };
    let mut a = Resolve::with_intent(
        &mut ram.storage,
        source,
        ROOT,
        ADMIN,
        Intent::Namespace {
            path: NamespacePath::Victim,
        },
    )
    .unwrap();
    while a.step(&mut ram.storage, ADMIN).unwrap() == Progress::More {}
    let mut b = Resolve::with_intent(
        &mut ram.storage,
        dest,
        ROOT,
        ADMIN,
        Intent::Namespace {
            path: NamespacePath::Destination,
        },
    )
    .unwrap();
    while b.step(&mut ram.storage, ADMIN).unwrap() == Progress::More {}
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let ap = a
        .namespace_proof(&ram.storage, ADMIN, NamespacePath::Victim)
        .unwrap();
    let bp = b
        .namespace_proof(&ram.storage, ADMIN, NamespacePath::Destination)
        .unwrap();
    let mut p = ram
        .storage
        .prepare_namespace_paid(
            EXPENSE,
            charge,
            NamespaceIntent::Rename,
            ap,
            Some(bp),
            ADMIN,
        )
        .unwrap();
    a.release(&mut ram.storage);
    b.release(&mut ram.storage);
    while !p.step(&mut ram.storage, ADMIN).unwrap() {}
    assert!(matches!(
        p.commit(&mut ram.storage, ADMIN, Timestamp::legacy_ns(1)),
        Ok(NamespaceOutcome::Applied | NamespaceOutcome::Unchanged)
    ));
    while !p.cancel_step(&mut ram.storage).unwrap() {}
    ram.storage.release_preparation(charge);
}
#[test]
fn cookie_delete_reuse_rename_symlink_and_boot_move_preserve_ordered_boundaries() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let dir = create(&mut ram, ROOT, b"dir", DIR);
    create(&mut ram, dir, b"a", REG);
    create(&mut ram, dir, b"b", REG);
    create(&mut ram, dir, b"c", REG);
    let mut fds = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    let fd = ram.open(&mut fds, "/dir", READ_ONLY).unwrap();
    let first = read(
        &mut ram,
        &fds,
        fd,
        1016,
        DirectoryFormat::Linux64,
        Timestamp::ZERO,
    );
    let first_entries = entries(&first.0);
    let a_cookie = first_entries.last().unwrap().0;
    let old = read(
        &mut ram,
        &fds,
        fd,
        1016,
        DirectoryFormat::Linux64,
        Timestamp::ZERO,
    );
    let old_entries = entries(&old.0);
    let b_cookie = old_entries[0].0;
    rename(&mut ram, b"/dir/b", b"/dir/z");
    ram.directory_seek(&fds, fd, a_cookie).unwrap();
    let renamed = entries(
        &read(
            &mut ram,
            &fds,
            fd,
            1016,
            DirectoryFormat::Linux64,
            Timestamp::ZERO,
        )
        .0,
    );
    assert_eq!(renamed[0].2, b"z");
    assert_eq!(renamed[0].0, b_cookie);
    ram.storage.unlink(dir, b"z", EXPENSE).unwrap();
    while ram.storage.reclaim_step() {}
    create(&mut ram, dir, b"new", crate::storage::SYMLINK);
    ram.directory_seek(&fds, fd, a_cookie).unwrap();
    let reused = entries(
        &read(
            &mut ram,
            &fds,
            fd,
            1016,
            DirectoryFormat::PosixDent,
            Timestamp::ZERO,
        )
        .0,
    );
    assert_eq!(reused[0].2, b"c");
    assert_eq!(reused[1].2, b"new");
    assert!(reused[1].0 > old_entries[1].0);
    assert_eq!(reused[1].1, 10);
    rename(&mut ram, b"/etc/motd", b"/dir/moved");
    let later = entries(
        &read(
            &mut ram,
            &fds,
            fd,
            1016,
            DirectoryFormat::Linux64,
            Timestamp::ZERO,
        )
        .0,
    );
    assert_eq!(later.len(), 1);
    assert_eq!(later[0].2, b"moved");
    assert!(later[0].0 > reused[1].0);
    ram.release(&mut fds);
}
#[test]
fn ready_directory_survives_close_reuse_and_invalid_time_has_no_effect() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let dir = create(&mut ram, ROOT, b"dir", DIR);
    let mut fds = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    let fd = ram.open(&mut fds, "/dir", READ_ONLY).unwrap();
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let mut j = ram
        .prepare_directory(&fds, fd, charge, ADMIN, 1016, DirectoryFormat::Linux64)
        .unwrap();
    while !j.step(&ram, ADMIN).unwrap() {}
    let mut invalid = Timestamp::ZERO;
    invalid.nanos = 1_000_000_000;
    assert_eq!(
        j.commit(&mut ram, ADMIN, invalid),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    assert_eq!(ram.storage.node(dir).unwrap().times[0], Timestamp::ZERO);
    ram.close(&mut fds, fd).unwrap();
    assert_eq!(ram.open(&mut fds, "/tmp/probe", READ_ONLY).unwrap(), fd);
    assert!(matches!(
        j.commit(&mut ram, ADMIN, Timestamp::legacy_ns(77)),
        Ok(DirectoryOutcome::Bytes { .. })
    ));
    assert_eq!(
        entries(j.bytes().unwrap())
            .iter()
            .map(|e| e.2.clone())
            .collect::<Vec<_>>(),
        vec![b".".to_vec(), b"..".to_vec()]
    );
    assert_eq!(
        ram.seek_from(&mut fds, fd, 0, proto_fs::SeekFrom::Current),
        Ok(0)
    );
    assert_eq!(
        ram.storage.node(dir).unwrap().times[0],
        Timestamp::legacy_ns(77)
    );
    j.cancel_step(&mut ram);
    ram.storage.release_preparation(charge);
    ram.release(&mut fds);
}

#[test]
fn committed_directory_prefix_survives_rmdir_until_exact_cleanup() {
    use crate::{
        namespace::{NamespaceIntent, NamespaceOutcome, NamespacePath},
        resolve::{Intent, Progress, Resolve},
    };
    let mut ram = Ram::new(Timestamp::ZERO);
    let dir = create(&mut ram, ROOT, b"dir", DIR);
    let mut fds = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    let fd = ram.open(&mut fds, "/dir", READ_ONLY).unwrap();
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let mut j = ram
        .prepare_directory(&fds, fd, charge, ADMIN, 1016, DirectoryFormat::Linux64)
        .unwrap();
    while !j.step(&ram, ADMIN).unwrap() {}
    let result = j.commit(&mut ram, ADMIN, Timestamp::legacy_ns(7)).unwrap();
    let original = j.bytes().unwrap().to_vec();
    let mut r = Resolve::with_intent(
        &mut ram.storage,
        b"/dir",
        ROOT,
        ADMIN,
        Intent::Namespace {
            path: NamespacePath::Victim,
        },
    )
    .unwrap();
    while r.step(&mut ram.storage, ADMIN).unwrap() == Progress::More {}
    let remove_charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let proof = r
        .namespace_proof(&ram.storage, ADMIN, NamespacePath::Victim)
        .unwrap();
    let mut prep = ram
        .storage
        .prepare_namespace_paid(
            EXPENSE,
            remove_charge,
            NamespaceIntent::Rmdir,
            proof,
            None,
            ADMIN,
        )
        .unwrap();
    r.release(&mut ram.storage);
    while !prep.step(&mut ram.storage, ADMIN).unwrap() {}
    assert_eq!(
        prep.commit(&mut ram.storage, ADMIN, Timestamp::legacy_ns(9)),
        Ok(NamespaceOutcome::Applied)
    );
    while !prep.cancel_step(&mut ram.storage).unwrap() {}
    ram.storage.release_preparation(remove_charge);
    ram.close(&mut fds, fd).unwrap();
    while ram.storage.reclaim_step() {}
    assert!(ram.storage.node(dir).is_ok());
    assert_eq!(j.bytes().unwrap(), original);
    let mut invalid = Timestamp::ZERO;
    invalid.nanos = 1_000_000_000;
    assert_eq!(j.commit(&mut ram, ADMIN, invalid), Ok(result));
    assert_eq!(
        ram.storage.node(dir).unwrap().times[0],
        Timestamp::legacy_ns(7)
    );
    assert!(j.cancel_step(&mut ram));
    assert!(j.cancel_step(&mut ram));
    ram.storage.release_preparation(charge);
    while ram.storage.reclaim_step() {}
    assert!(ram.storage.node(dir).is_err());
    assert_eq!(ram.storage.usage(EXPENSE), crate::storage::Usage::default());
}
