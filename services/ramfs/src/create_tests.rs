// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::authority::Identity;
use crate::namespace::{CreateJournal, NamespaceOutcome, NamespacePath, ReadLinkJournal};
use crate::resolve::{Intent, Progress, Resolve};
use crate::storage::*;
use crate::{DIR, REG, Ram};
use proto_fs::{ALREADY_EXISTS, MAX_PATH, NO_ENTRY, NO_SPACE, STALE_PROOF};
use proto_process::Groups;
extern crate std;
use std::vec;

const ROOT_ACCOUNT: Root = Root {
    id: 37,
    generation: 9,
};
const OTHER: Root = Root {
    id: 38,
    generation: 10,
};
const OWNER: Identity = Identity {
    uid: 37,
    gid: 43,
    groups: Groups::EMPTY,
};
fn writable_root(now: u64) -> Ram<'static> {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(now));
    ram.storage.node_mut(ROOT).unwrap().mode = 0o777;
    ram
}
fn create(ram: &mut Ram<'_>, parent: Token, name: &[u8], kind: u32) -> Token {
    let r = ram
        .storage
        .reserve(ROOT_ACCOUNT, parent, name, (kind, 0o777, 37, 43))
        .unwrap();
    ram.storage.commit(r).unwrap()
}
fn resolve(
    ram: &mut Ram<'_>,
    path: &[u8],
    role: NamespacePath,
    identity: Identity,
) -> Result<Resolve, u32> {
    let intent = match role {
        NamespacePath::CreateDirectory => Intent::DirectoryCreate,
        NamespacePath::CreateSymbolicLink => Intent::SymbolicLinkCreate,
        NamespacePath::ReadLink => Intent::Lookup { follow: false },
        _ => unreachable!(),
    };
    let mut result = Resolve::with_intent(&mut ram.storage, path, ROOT, identity, intent)?;
    for _ in 0..20_000 {
        match result.step(&mut ram.storage, identity) {
            Ok(Progress::More) => {}
            Ok(_) => return Ok(result),
            Err(code) => {
                result.release(&mut ram.storage);
                return Err(code);
            }
        }
    }
    panic!("resolver failed to progress")
}
fn prepare(
    ram: &mut Ram<'_>,
    journal: &mut CreateJournal,
    r: &Resolve,
    charge: &mut u16,
    identity: Identity,
) -> Result<(), u32> {
    for _ in 0..4 {
        let proof = r.namespace_proof(&ram.storage, identity, journal.role())?;
        if journal.step_paid(&mut ram.storage, ROOT_ACCOUNT, charge, proof, identity)? {
            return Ok(());
        }
    }
    panic!("creation failed to progress")
}
fn commit(
    ram: &mut Ram<'_>,
    journal: &mut CreateJournal,
    r: &Resolve,
    charge: &mut u16,
    identity: Identity,
    now: u64,
) -> Result<NamespaceOutcome, u32> {
    let proof = r.namespace_proof(&ram.storage, identity, journal.role())?;
    journal.commit(
        &mut ram.storage,
        ROOT_ACCOUNT,
        charge,
        Some(proof),
        identity,
        proto_fs::Timestamp::legacy_ns(now),
    )
}
fn finish(ram: &mut Ram<'_>, journal: &mut CreateJournal, r: Resolve, charge: &mut u16) {
    assert!(journal.cancel_step(&mut ram.storage, charge).unwrap());
    r.release(&mut ram.storage);
    ram.storage.release_preparation(*charge);
    let mut steps = 0;
    while ram.storage.reclaim_step() {
        steps += 1;
        assert!(steps <= PAGES + INODES);
    }
}
fn pins(ram: &Ram<'_>) -> std::vec::Vec<[u16; 5]> {
    ram.storage.state.nodes.iter().map(|n| n.pins).collect()
}
fn read(ram: &mut Ram<'_>, path: &[u8], requested: usize, now: u64) -> (ReadLinkJournal, Resolve) {
    let r = resolve(ram, path, NamespacePath::ReadLink, OWNER).unwrap();
    let mut j = ReadLinkJournal::new(requested);
    let p = r
        .namespace_proof(&ram.storage, OWNER, NamespacePath::ReadLink)
        .unwrap();
    j.capture(
        &mut ram.storage,
        Some(p),
        OWNER,
        proto_fs::Timestamp::legacy_ns(now),
    )
    .unwrap();
    (j, r)
}

#[test]
fn mkdir_reuses_paid_reservation_umask_gid_and_checked_parent_nlink() {
    let mut ram = writable_root(7);
    let parent = create(&mut ram, ROOT, b"parent", DIR);
    ram.storage.node_mut(parent).unwrap().gid = 99;
    ram.storage.node_mut(parent).unwrap().mode = 0o2777;
    let mut j = CreateJournal::directory(0o777, 0o027);
    let r = resolve(&mut ram, b"/parent/child/", j.role(), OWNER).unwrap();
    let mut charge = ram.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
    prepare(&mut ram, &mut j, &r, &mut charge, OWNER).unwrap();
    assert_eq!(charge, NONE);
    assert_eq!(ram.storage.preparations_used(), 1);
    assert_eq!(ram.storage.lookup(parent, b"child"), Err(NO_ENTRY));
    assert_eq!(
        commit(&mut ram, &mut j, &r, &mut charge, OWNER, 22),
        Ok(NamespaceOutcome::Applied)
    );
    let token = ram.storage.lookup(parent, b"child").unwrap();
    let node = ram.storage.node(token).unwrap();
    assert_eq!(
        (node.mode, node.uid, node.gid, node.links, node.times),
        (0o2750, 37, 99, 2, [proto_fs::Timestamp::legacy_ns(22); 3])
    );
    assert_eq!(ram.storage.node(parent).unwrap().links, 3);
    assert_eq!(
        ram.storage.node(parent).unwrap().times[1..],
        [proto_fs::Timestamp::legacy_ns(22); 2]
    );
    let epoch = ram.storage.state.epoch;
    assert_eq!(
        j.commit(
            &mut ram.storage,
            OTHER,
            &mut charge,
            None,
            Identity { uid: 55, ..OWNER },
            proto_fs::Timestamp::legacy_ns(99)
        ),
        Ok(NamespaceOutcome::Applied)
    );
    assert_eq!(ram.storage.state.epoch, epoch);
    assert_eq!(
        ram.storage.node(token).unwrap().times,
        [proto_fs::Timestamp::legacy_ns(22); 3]
    );
    finish(&mut ram, &mut j, r, &mut charge);
    assert_eq!(ram.storage.preparations_used(), 0);
}

#[test]
fn creation_keeps_known_final_names_with_slash_for_exists_refusal() {
    let mut ram = writable_root(0);
    let link = create(&mut ram, ROOT, b"dangling", SYMLINK);
    ram.storage.write(link, ROOT_ACCOUNT, 0, b"absent").unwrap();
    let regular = create(&mut ram, ROOT, b"regular", REG);
    for directory in [false, true] {
        for path in [b"/dangling/".as_slice(), b"/regular/", b"/dangling", b"/"] {
            let mut j = if directory {
                CreateJournal::directory(0o700, 0)
            } else {
                CreateJournal::symlink(b"raw").unwrap()
            };
            let before_pins = pins(&ram);
            let usage = ram.storage.usage(ROOT_ACCOUNT);
            let epoch = ram.storage.state.epoch;
            let r = resolve(&mut ram, path, j.role(), OWNER).unwrap();
            let mut charge = ram.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
            assert_eq!(
                prepare(&mut ram, &mut j, &r, &mut charge, OWNER),
                Err(ALREADY_EXISTS)
            );
            assert_ne!(charge, NONE);
            finish(&mut ram, &mut j, r, &mut charge);
            assert_eq!(ram.storage.usage(ROOT_ACCOUNT), usage);
            assert_eq!(pins(&ram), before_pins);
            assert_eq!(ram.storage.state.epoch, epoch);
            assert_eq!(ram.storage.preparations_used(), 0);
        }
    }
    assert!(matches!(
        resolve(
            &mut ram,
            b"/absent/",
            NamespacePath::CreateSymbolicLink,
            OWNER
        ),
        Err(NO_ENTRY)
    ));
    assert_eq!(ram.storage.lookup(ROOT, b"dangling"), Ok(link));
    assert_eq!(ram.storage.lookup(ROOT, b"regular"), Ok(regular));
}

#[test]
fn symlink_empty_and_raw_target_are_published_without_pathname_validation() {
    let mut ram = writable_root(0);
    for (name, target) in [
        (b"/empty".as_slice(), b"".as_slice()),
        (b"/raw", b"../missing//\xff/./"),
    ] {
        let mut j = CreateJournal::symlink(target).unwrap();
        let r = resolve(&mut ram, name, j.role(), OWNER).unwrap();
        let mut charge = ram.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
        prepare(&mut ram, &mut j, &r, &mut charge, OWNER).unwrap();
        commit(&mut ram, &mut j, &r, &mut charge, OWNER, 31).unwrap();
        finish(&mut ram, &mut j, r, &mut charge);
        let (mut read, r) = read(&mut ram, name, MAX_PATH, 42);
        assert_eq!(read.result(), Some(target));
        read.cancel_step(&mut ram.storage).unwrap();
        r.release(&mut ram.storage);
    }
    let mut r = Resolve::with_intent(
        &mut ram.storage,
        b"/empty",
        ROOT,
        OWNER,
        Intent::Lookup { follow: true },
    )
    .unwrap();
    let mut result = None;
    for _ in 0..20_000 {
        match r.step(&mut ram.storage, OWNER) {
            Ok(Progress::More) => {}
            other => {
                result = Some(other);
                break;
            }
        }
    }
    assert_eq!(result, Some(Err(NO_ENTRY)));
    r.release(&mut ram.storage);
}

#[test]
fn readlink_short_zero_and_cached_bytes_preserve_one_atime_and_no_offset() {
    let mut ram = writable_root(1);
    let link = create(&mut ram, ROOT, b"symbol", SYMLINK);
    ram.storage.write(link, ROOT_ACCOUNT, 0, b"abcdef").unwrap();
    let (mut short, r) = read(&mut ram, b"/symbol", 3, 10);
    assert_eq!(short.result(), Some(b"abc".as_slice()));
    assert_eq!(
        ram.storage.node(link).unwrap().times[0],
        proto_fs::Timestamp::legacy_ns(10)
    );
    ram.storage.write(link, ROOT_ACCOUNT, 0, b"XXXXXX").unwrap();
    assert_eq!(
        short.capture(
            &mut ram.storage,
            None,
            Identity { uid: 8, ..OWNER },
            proto_fs::Timestamp::legacy_ns(99)
        ),
        Ok(3)
    );
    assert_eq!(short.result(), Some(b"abc".as_slice()));
    assert_eq!(
        ram.storage.node(link).unwrap().times[0],
        proto_fs::Timestamp::legacy_ns(10)
    );
    short.cancel_step(&mut ram.storage).unwrap();
    r.release(&mut ram.storage);
    assert_eq!(
        short.capture(
            &mut ram.storage,
            None,
            OWNER,
            proto_fs::Timestamp::legacy_ns(77)
        ),
        Ok(3)
    );
    assert_eq!(short.result(), Some(b"abc".as_slice()));
    let (mut zero, r) = read(&mut ram, b"/symbol", 0, 55);
    assert_eq!(zero.result(), Some(b"".as_slice()));
    assert_eq!(
        ram.storage.node(link).unwrap().times[0],
        proto_fs::Timestamp::legacy_ns(55)
    );
    zero.cancel_step(&mut ram.storage).unwrap();
    r.release(&mut ram.storage);
    let (mut full, r) = read(&mut ram, b"/symbol", usize::MAX, 66);
    assert_eq!(full.result(), Some(b"XXXXXX".as_slice()));
    full.cancel_step(&mut ram.storage).unwrap();
    r.release(&mut ram.storage);
}

#[test]
fn readlink_pin_and_role_refusals_preserve_atime_bytes_and_pins() {
    let mut ram = writable_root(8);
    let link = create(&mut ram, ROOT, b"symbol", SYMLINK);
    ram.storage.write(link, ROOT_ACCOUNT, 0, b"target").unwrap();
    let r = resolve(&mut ram, b"/symbol", NamespacePath::ReadLink, OWNER).unwrap();
    let before = ram.storage.node(link).unwrap().times;
    let old = ram.storage.node(link).unwrap().pins[Pin::Pending as usize];
    ram.storage.node_mut(link).unwrap().pins[Pin::Pending as usize] = u16::MAX;
    let mut j = ReadLinkJournal::new(20);
    let p = r
        .namespace_proof(&ram.storage, OWNER, NamespacePath::ReadLink)
        .unwrap();
    assert_eq!(
        j.capture(
            &mut ram.storage,
            Some(p),
            OWNER,
            proto_fs::Timestamp::legacy_ns(88)
        ),
        Err(NO_SPACE)
    );
    assert_eq!(ram.storage.node(link).unwrap().times, before);
    assert!(j.result().is_none());
    ram.storage.node_mut(link).unwrap().pins[Pin::Pending as usize] = old;
    let p = r
        .namespace_proof(&ram.storage, OWNER, NamespacePath::ReadLink)
        .unwrap();
    assert_eq!(
        j.capture(
            &mut ram.storage,
            Some(p),
            Identity { uid: 88, ..OWNER },
            proto_fs::Timestamp::legacy_ns(88)
        ),
        Err(STALE_PROOF)
    );
    assert_eq!(ram.storage.node(link).unwrap().times, before);
    r.release(&mut ram.storage);
    create(&mut ram, ROOT, b"regular", REG);
    let r = resolve(&mut ram, b"/regular", NamespacePath::ReadLink, OWNER).unwrap();
    let p = r
        .namespace_proof(&ram.storage, OWNER, NamespacePath::ReadLink)
        .unwrap();
    assert_eq!(
        j.capture(
            &mut ram.storage,
            Some(p),
            OWNER,
            proto_fs::Timestamp::legacy_ns(88)
        ),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    r.release(&mut ram.storage);
}

#[test]
fn changed_creation_identity_and_epoch_keep_staged_resources_until_cancel() {
    let mut ram = writable_root(0);
    let mut j = CreateJournal::symlink(b"prepared target").unwrap();
    let r = resolve(&mut ram, b"/new", j.role(), OWNER).unwrap();
    let mut charge = ram.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
    prepare(&mut ram, &mut j, &r, &mut charge, OWNER).unwrap();
    let usage = ram.storage.usage(ROOT_ACCOUNT);
    assert_eq!(usage.pages, 1);
    let other = Identity { uid: 0, ..OWNER };
    let r2 = resolve(&mut ram, b"/new", j.role(), other).unwrap();
    assert_eq!(
        commit(&mut ram, &mut j, &r2, &mut charge, other, 88),
        Err(STALE_PROOF)
    );
    r2.release(&mut ram.storage);
    // A name of another bucket changes nothing of the proof of "new"
    // (the old resolver is stale for its identity alone), a name of the same
    // bucket does.
    let elsewhere = crate::storage::tests_support::other_bucket(ROOT, b"new");
    create(&mut ram, ROOT, &elsewhere, REG);
    let rival = crate::storage::tests_support::same_bucket(ROOT, b"new");
    create(&mut ram, ROOT, &rival, REG);
    assert_eq!(
        commit(&mut ram, &mut j, &r, &mut charge, OWNER, 88),
        Err(STALE_PROOF)
    );
    let fresh = resolve(&mut ram, b"/new", j.role(), OWNER).unwrap();
    assert_eq!(
        commit(&mut ram, &mut j, &fresh, &mut charge, OWNER, 88),
        Err(STALE_PROOF)
    );
    fresh.release(&mut ram.storage);
    assert_eq!(ram.storage.lookup(ROOT, b"new"), Err(NO_ENTRY));
    assert_eq!(ram.storage.usage(ROOT_ACCOUNT).pages, 1);
    finish(&mut ram, &mut j, r, &mut charge);
    assert_eq!(ram.storage.usage(ROOT_ACCOUNT).pages, 0);
    assert_eq!(ram.storage.preparations_used(), 0);
}

#[test]
fn full_page_pool_refuses_symlink_content_and_cancels_the_exact_reservation() {
    let mut ram = writable_root(0);
    let first = create(&mut ram, ROOT, b"first", REG);
    let second = ram
        .storage
        .reserve(OTHER, ROOT, b"second", (REG, 0o600, 38, 44))
        .unwrap();
    let second = ram.storage.commit(second).unwrap();
    let content = vec![5u8; FILE_PAGES * PAGE];
    ram.storage.write(first, ROOT_ACCOUNT, 0, &content).unwrap();
    ram.storage.write(second, OTHER, 0, &content).unwrap();
    assert_eq!(ram.storage.available().pages, 0);
    let before = ram.storage.usage(ROOT_ACCOUNT);
    let epoch = ram.storage.state.epoch;
    let mut j = CreateJournal::symlink(b"target").unwrap();
    let r = resolve(&mut ram, b"/no-space", j.role(), OWNER).unwrap();
    let mut charge = ram.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
    assert_eq!(
        prepare(&mut ram, &mut j, &r, &mut charge, OWNER),
        Err(NO_SPACE)
    );
    assert_eq!(ram.storage.lookup(ROOT, b"no-space"), Err(NO_ENTRY));
    assert_eq!(ram.storage.state.epoch, epoch);
    assert_eq!(ram.storage.preparations_used(), 1);
    finish(&mut ram, &mut j, r, &mut charge);
    assert_eq!(ram.storage.usage(ROOT_ACCOUNT), before);
    assert_eq!(ram.storage.available().pages, 0);
    // An empty target needs no content page in the same full pool.
    let mut j = CreateJournal::symlink(b"").unwrap();
    let r = resolve(&mut ram, b"/empty-full", j.role(), OWNER).unwrap();
    let mut charge = ram.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
    prepare(&mut ram, &mut j, &r, &mut charge, OWNER).unwrap();
    commit(&mut ram, &mut j, &r, &mut charge, OWNER, 17).unwrap();
    finish(&mut ram, &mut j, r, &mut charge);
    assert_eq!(ram.storage.available().pages, 0);
}

#[test]
fn mkdir_nlink_exhaustion_keeps_the_unpublished_child_until_cancel() {
    let mut ram = writable_root(0);
    ram.storage.node_mut(ROOT).unwrap().links = u32::MAX;
    let before = ram.storage.usage(ROOT_ACCOUNT);
    let epoch = ram.storage.state.epoch;
    let mut j = CreateJournal::directory(0o700, 0);
    let r = resolve(&mut ram, b"/child", j.role(), OWNER).unwrap();
    let mut charge = ram.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
    prepare(&mut ram, &mut j, &r, &mut charge, OWNER).unwrap();
    assert_eq!(
        commit(&mut ram, &mut j, &r, &mut charge, OWNER, 77),
        Err(crate::namespace::TOO_MANY_LINKS)
    );
    assert_eq!(ram.storage.lookup(ROOT, b"child"), Err(NO_ENTRY));
    assert_eq!(ram.storage.node(ROOT).unwrap().links, u32::MAX);
    assert_eq!(ram.storage.state.epoch, epoch);
    finish(&mut ram, &mut j, r, &mut charge);
    assert_eq!(ram.storage.usage(ROOT_ACCOUNT), before);
}

#[test]
fn creation_and_readlink_actual_layout_stays_resident_without_a_new_pool() {
    std::println!(
        "CreateJournal={} ReadLinkJournal={} Node={} State={}",
        core::mem::size_of::<CreateJournal>(),
        core::mem::size_of::<ReadLinkJournal>(),
        core::mem::size_of::<Node>(),
        core::mem::size_of::<State>()
    );
    assert!(core::mem::size_of::<CreateJournal>() < 768);
    assert!(core::mem::size_of::<ReadLinkJournal>() < 576);
}

#[test]
fn target_bounds_and_final_role_preserve_unpublished_creation_and_readlink() {
    let mut ram = writable_root(4);
    let usage = ram.storage.usage(ROOT_ACCOUNT);
    assert!(matches!(
        CreateJournal::symlink(&[b'x'; MAX_PATH + 1]),
        Err(proto_fs::NAME_TOO_LONG)
    ));
    assert!(matches!(
        CreateJournal::symlink(b"a\0b"),
        Err(proto_fs::INVALID_ARGUMENT)
    ));
    assert_eq!(ram.storage.usage(ROOT_ACCOUNT), usage);
    let target = [b'x'; MAX_PATH];
    let mut j = CreateJournal::symlink(&target).unwrap();
    let r = resolve(&mut ram, b"/max", j.role(), OWNER).unwrap();
    let mut charge = ram.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
    let wrong = resolve(&mut ram, b"/max", NamespacePath::CreateDirectory, OWNER).unwrap();
    let p = wrong
        .namespace_proof(&ram.storage, OWNER, NamespacePath::CreateDirectory)
        .unwrap();
    assert_eq!(
        j.step_paid(&mut ram.storage, ROOT_ACCOUNT, &mut charge, p, OWNER),
        Err(STALE_PROOF)
    );
    wrong.release(&mut ram.storage);
    prepare(&mut ram, &mut j, &r, &mut charge, OWNER).unwrap();
    commit(&mut ram, &mut j, &r, &mut charge, OWNER, 33).unwrap();
    finish(&mut ram, &mut j, r, &mut charge);
    assert_eq!(ram.storage.usage(ROOT_ACCOUNT).pages, 1);
    let (mut read, r) = read(&mut ram, b"/max", usize::MAX, 44);
    assert_eq!(read.result(), Some(target.as_slice()));
    read.cancel_step(&mut ram.storage).unwrap();
    r.release(&mut ram.storage);
}
