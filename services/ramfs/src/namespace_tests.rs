// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::authority::Identity;
use crate::namespace::*;
use crate::resolve::{Intent, Progress, Resolve};
use crate::storage::*;
use crate::{DIR, Fds, REG, Ram};
use proto_fs::{NO_ENTRY, NO_SPACE, READ_ONLY, STALE_PROOF};
use proto_process::Groups;
extern crate std;
use std::{format, vec::Vec};

const FIRST: Root = Root {
    id: 11,
    generation: 7,
};
const SECOND: Root = Root {
    id: 22,
    generation: 9,
};
const ROOT_USER: Identity = Identity {
    uid: 0,
    gid: 0,
    groups: Groups::EMPTY,
};
const OWNER: Identity = Identity {
    uid: 37,
    gid: 43,
    groups: Groups::EMPTY,
};
fn create(
    ram: &mut Ram<'_>,
    root: Root,
    parent: Token,
    name: &[u8],
    kind: u32,
    mode: u32,
) -> Token {
    let r = ram
        .storage
        .reserve(root, parent, name, (kind, mode, 37, 43))
        .unwrap();
    ram.storage.commit(r).unwrap()
}
fn resolved(
    ram: &mut Ram<'_>,
    path: &[u8],
    role: NamespacePath,
    identity: Identity,
) -> Result<Resolve, u32> {
    let mut r = Resolve::with_intent(
        &mut ram.storage,
        path,
        ROOT,
        identity,
        Intent::Namespace { path: role },
    )?;
    for _ in 0..200_000 {
        match r.step(&mut ram.storage, identity) {
            Ok(Progress::More) => {}
            Ok(_) => return Ok(r),
            Err(code) => {
                r.release(&mut ram.storage);
                return Err(code);
            }
        }
    }
    panic!("namespace resolution failed to progress")
}
fn begin(
    ram: &mut Ram<'_>,
    charge: u16,
    root: Root,
    intent: NamespaceIntent,
    source: &[u8],
    destination: Option<&[u8]>,
    identity: Identity,
) -> Result<Preparation, u32> {
    let role = match intent {
        NamespaceIntent::Link { follow_source } => NamespacePath::LinkSource {
            follow: follow_source,
        },
        _ => NamespacePath::Victim,
    };
    let source = resolved(ram, source, role, identity)?;
    let dest = match destination
        .map(|p| resolved(ram, p, NamespacePath::Destination, identity))
        .transpose()
    {
        Ok(dest) => dest,
        Err(code) => {
            source.release(&mut ram.storage);
            return Err(code);
        }
    };
    let result = ram.storage.prepare_namespace_paid(
        root,
        charge,
        intent,
        source
            .namespace_proof(&ram.storage, identity, role)
            .unwrap(),
        dest.as_ref().map(|r| {
            r.namespace_proof(&ram.storage, identity, NamespacePath::Destination)
                .unwrap()
        }),
        identity,
    );
    source.release(&mut ram.storage);
    if let Some(dest) = dest {
        dest.release(&mut ram.storage);
    }
    result
}
fn ready(ram: &mut Ram<'_>, prep: &mut Preparation, identity: Identity) -> Result<usize, u32> {
    for steps in 1..10_000 {
        if prep.step(&mut ram.storage, identity)? {
            return Ok(steps);
        }
    }
    panic!("namespace preparation failed to progress")
}
fn cleanup(ram: &mut Ram<'_>, prep: &mut Preparation) -> usize {
    for steps in 1..32 {
        if prep.cancel_step(&mut ram.storage).unwrap() {
            return steps;
        }
    }
    panic!("namespace cleanup failed to progress")
}
fn run(
    ram: &mut Ram<'_>,
    intent: NamespaceIntent,
    source: &[u8],
    destination: Option<&[u8]>,
    now: u64,
) -> Result<NamespaceOutcome, u32> {
    let charge = ram.storage.charge_preparation(FIRST)?;
    let mut prep = match begin(ram, charge, FIRST, intent, source, destination, ROOT_USER) {
        Ok(prep) => prep,
        Err(code) => {
            ram.storage.release_preparation(charge);
            return Err(code);
        }
    };
    let result = ready(ram, &mut prep, ROOT_USER).and_then(|_| {
        prep.commit(
            &mut ram.storage,
            ROOT_USER,
            proto_fs::Timestamp::legacy_ns(now),
        )
    });
    cleanup(ram, &mut prep);
    ram.storage.release_preparation(charge);
    result
}
fn pins(ram: &Ram<'_>) -> Vec<[u16; 5]> {
    ram.storage.state.nodes.iter().map(|n| n.pins).collect()
}
fn drain(ram: &mut Ram<'_>) -> usize {
    let mut count = 0;
    while ram.storage.reclaim_step() {
        count += 1;
        assert!(count <= PAGES + INODES);
    }
    count
}

#[test]
fn rename_replacement_preserves_the_open_victim_and_source_expense_root() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(10));
    let left = create(&mut ram, FIRST, ROOT, b"left", DIR, 0o777);
    let right = create(&mut ram, SECOND, ROOT, b"right", DIR, 0o777);
    let source = create(&mut ram, FIRST, left, b"source", REG, 0o644);
    let victim = create(&mut ram, SECOND, right, b"victim", REG, 0o644);
    ram.storage.write(source, FIRST, 0, b"source").unwrap();
    ram.storage.write(victim, SECOND, 0, b"old").unwrap();
    let mut fds = Fds {
        root: SECOND,
        ..Fds::default()
    };
    let fd = ram.open(&mut fds, "/right/victim", READ_ONLY).unwrap();
    let first = ram.storage.usage(FIRST);
    let second = ram.storage.usage(SECOND);
    assert_eq!(
        run(
            &mut ram,
            NamespaceIntent::Rename,
            b"/left/source",
            Some(b"/right/victim"),
            99
        ),
        Ok(NamespaceOutcome::Applied)
    );
    assert_eq!(ram.storage.lookup(left, b"source"), Err(NO_ENTRY));
    assert_eq!(ram.storage.lookup(right, b"victim"), Ok(source));
    assert_eq!(ram.storage.usage(FIRST), first);
    assert_eq!(ram.storage.usage(SECOND).dentries, second.dentries - 1);
    assert_eq!(ram.storage.node(victim).unwrap().links, 0);
    let mut bytes = [0; 3];
    assert_eq!(
        ram.read_at(
            &mut fds,
            fd,
            &mut bytes,
            proto_fs::Timestamp::legacy_ns(100)
        )
        .unwrap(),
        3
    );
    assert_eq!(&bytes, b"old");
    assert_eq!(
        ram.storage.node(left).unwrap().times[1..],
        [
            proto_fs::Timestamp::legacy_ns(99),
            proto_fs::Timestamp::legacy_ns(99)
        ]
    );
    assert_eq!(
        ram.storage.node(right).unwrap().times[1..],
        [
            proto_fs::Timestamp::legacy_ns(99),
            proto_fs::Timestamp::legacy_ns(99)
        ]
    );
    assert_eq!(
        ram.storage.node(victim).unwrap().times[2],
        proto_fs::Timestamp::legacy_ns(99)
    );
    ram.close(&mut fds, fd).unwrap();
    drain(&mut ram);
    assert!(ram.storage.node(victim).is_err());
}

#[test]
fn cached_commit_survives_epoch_credentials_and_cleanup_without_repeating_time() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(10));
    let source = create(&mut ram, FIRST, ROOT, b"source", REG, 0o644);
    let charge = ram.storage.charge_preparation(FIRST).unwrap();
    let mut prep = begin(
        &mut ram,
        charge,
        FIRST,
        NamespaceIntent::Link {
            follow_source: false,
        },
        b"/source",
        Some(b"/alias"),
        ROOT_USER,
    )
    .unwrap();
    ready(&mut ram, &mut prep, ROOT_USER).unwrap();
    assert_eq!(
        prep.commit(
            &mut ram.storage,
            ROOT_USER,
            proto_fs::Timestamp::legacy_ns(71)
        ),
        Ok(NamespaceOutcome::Applied)
    );
    ram.storage.set_attributes(source, 0, 37, 43).unwrap();
    assert_eq!(
        prep.commit(&mut ram.storage, OWNER, proto_fs::Timestamp::legacy_ns(999)),
        Ok(NamespaceOutcome::Applied)
    );
    assert_eq!(ram.storage.node(source).unwrap().links, 2);
    assert_eq!(
        ram.storage.node(source).unwrap().times[2],
        proto_fs::Timestamp::legacy_ns(71)
    );
    cleanup(&mut ram, &mut prep);
    assert_eq!(
        prep.commit(
            &mut ram.storage,
            OWNER,
            proto_fs::Timestamp::legacy_ns(1000)
        ),
        Ok(NamespaceOutcome::Applied)
    );
    ram.storage.release_preparation(charge);
}

#[test]
fn same_inode_rename_succeeds_at_full_name_share_without_changing_epoch_or_times() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(10));
    let source = create(&mut ram, FIRST, ROOT, b"source", REG, 0o644);
    ram.storage.link(FIRST, ROOT, b"alias", source).unwrap();
    for n in 0..DENTRY_SHARE - 2 {
        ram.storage
            .link(FIRST, ROOT, format!("f{n}").as_bytes(), source)
            .unwrap();
    }
    let usage = ram.storage.usage(FIRST);
    let epoch = ram.storage.state.epoch;
    let times = ram.storage.node(source).unwrap().times;
    let links = ram.storage.node(source).unwrap().links;
    assert_eq!(
        run(
            &mut ram,
            NamespaceIntent::Rename,
            b"/source",
            Some(b"/alias"),
            90
        ),
        Ok(NamespaceOutcome::Unchanged)
    );
    assert_eq!(ram.storage.usage(FIRST), usage);
    assert_eq!(ram.storage.state.epoch, epoch);
    assert_eq!(ram.storage.node(source).unwrap().times, times);
    assert_eq!(ram.storage.node(source).unwrap().links, links);
    assert_eq!(ram.storage.lookup(ROOT, b"source"), Ok(source));
    assert_eq!(ram.storage.lookup(ROOT, b"alias"), Ok(source));
}

#[test]
fn captured_search_identity_prevents_reusing_a_prefix_proof_after_euid_change() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    create(&mut ram, FIRST, ROOT, b"secret", DIR, 0o100);
    let public = create(&mut ram, FIRST, ROOT, b"public", DIR, 0o777);
    let file = create(&mut ram, FIRST, public, b"file", REG, 0o644);
    let charge = ram.storage.charge_preparation(FIRST).unwrap();
    let mut prep = begin(
        &mut ram,
        charge,
        FIRST,
        NamespaceIntent::Unlink,
        b"/secret/../public/file",
        None,
        OWNER,
    )
    .unwrap();
    ready(&mut ram, &mut prep, OWNER).unwrap();
    let changed = Identity { uid: 38, ..OWNER };
    assert_eq!(
        prep.commit(
            &mut ram.storage,
            changed,
            proto_fs::Timestamp::legacy_ns(22)
        ),
        Err(STALE_PROOF)
    );
    assert_eq!(ram.storage.lookup(public, b"file"), Ok(file));
    cleanup(&mut ram, &mut prep);
    ram.storage.release_preparation(charge);
}

#[test]
fn constructor_refusals_preserve_charge_usage_pins_epoch_and_exact_root() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    create(&mut ram, FIRST, ROOT, b"file", REG, 0o644);
    let charge = ram.storage.charge_preparation(FIRST).unwrap();
    let usage = ram.storage.usage(FIRST);
    let before_pins = pins(&ram);
    let epoch = ram.storage.state.epoch;
    assert!(matches!(
        begin(
            &mut ram,
            charge,
            SECOND,
            NamespaceIntent::Unlink,
            b"/file",
            None,
            ROOT_USER
        ),
        Err(proto_fs::INVALID_ARGUMENT)
    ));
    assert!(matches!(
        begin(
            &mut ram,
            charge,
            FIRST,
            NamespaceIntent::Rmdir,
            b"/file",
            None,
            ROOT_USER
        ),
        Err(proto_fs::NOT_DIRECTORY)
    ));
    assert!(matches!(
        begin(
            &mut ram,
            charge,
            FIRST,
            NamespaceIntent::Rename,
            b"/file",
            Some(b"/missing/"),
            ROOT_USER
        ),
        Err(proto_fs::NOT_DIRECTORY)
    ));
    assert_eq!(ram.storage.usage(FIRST), usage);
    assert_eq!(pins(&ram), before_pins);
    assert_eq!(ram.storage.state.epoch, epoch);
    assert_eq!(ram.storage.preparations_used(), 1);
    ram.storage.release_preparation(charge);
}

#[test]
fn raw_dot_dotdot_and_slash_survive_link_expansion_and_missing_destination() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let dir = create(&mut ram, FIRST, ROOT, b"dir", DIR, 0o777);
    let link = create(&mut ram, FIRST, ROOT, b"link", SYMLINK, 0o777);
    ram.storage.write(link, FIRST, 0, b"dir").unwrap();
    for path in [b"/link/.".as_slice(), b"/link/../dir/.."] {
        assert_eq!(
            run(&mut ram, NamespaceIntent::Rmdir, path, None, 42),
            Err(proto_fs::INVALID_ARGUMENT)
        );
    }
    assert_eq!(
        run(&mut ram, NamespaceIntent::Rmdir, b"/", None, 42),
        Err(BUSY)
    );
    assert_eq!(ram.storage.lookup(ROOT, b"dir"), Ok(dir));
    assert_eq!(
        run(&mut ram, NamespaceIntent::Unlink, b"/link", None, 42),
        Ok(NamespaceOutcome::Applied)
    );
    assert_eq!(ram.storage.lookup(ROOT, b"dir"), Ok(dir));
}

#[test]
fn rename_rejects_ancestor_and_nonempty_destination_with_bounded_cancel() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let top = create(&mut ram, FIRST, ROOT, b"top", DIR, 0o777);
    create(&mut ram, FIRST, top, b"child", DIR, 0o777);
    let other = create(&mut ram, FIRST, ROOT, b"other", DIR, 0o777);
    create(&mut ram, FIRST, other, b"member", REG, 0o644);
    let usage = ram.storage.usage(FIRST);
    let epoch = ram.storage.state.epoch;
    assert_eq!(
        run(
            &mut ram,
            NamespaceIntent::Rename,
            b"/top",
            Some(b"/top/child/new"),
            11
        ),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    assert_eq!(
        run(
            &mut ram,
            NamespaceIntent::Rename,
            b"/top",
            Some(b"/other"),
            11
        ),
        Err(NOT_EMPTY)
    );
    assert_eq!(ram.storage.usage(FIRST), usage);
    assert_eq!(ram.storage.state.epoch, epoch);
    assert_eq!(ram.storage.lookup(ROOT, b"top"), Ok(top));
}

#[test]
fn nlink_exhaustion_and_directory_create_refuse_before_publication() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let file = create(&mut ram, FIRST, ROOT, b"file", REG, 0o644);
    ram.storage.node_mut(file).unwrap().links = u32::MAX;
    let usage = ram.storage.usage(FIRST);
    let epoch = ram.storage.state.epoch;
    assert_eq!(
        run(
            &mut ram,
            NamespaceIntent::Link {
                follow_source: false
            },
            b"/file",
            Some(b"/new"),
            11
        ),
        Err(TOO_MANY_LINKS)
    );
    assert_eq!(ram.storage.lookup(ROOT, b"new"), Err(NO_ENTRY));
    assert_eq!(ram.storage.usage(FIRST), usage);
    assert_eq!(ram.storage.state.epoch, epoch);
    ram.storage.node_mut(ROOT).unwrap().links = u32::MAX;
    let r = ram
        .storage
        .reserve(FIRST, ROOT, b"newdir", (DIR, 0o777, 37, 43))
        .unwrap();
    assert_eq!(ram.storage.commit_keep_charge(r), Err(TOO_MANY_LINKS));
    assert_eq!(ram.storage.lookup(ROOT, b"newdir"), Err(NO_ENTRY));
    ram.storage.cancel(r).unwrap();
    assert_eq!(ram.storage.state.epoch, epoch);
}

#[test]
fn rename_directory_replacement_combines_parent_delta_at_nlink_max() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let left = create(&mut ram, FIRST, ROOT, b"left", DIR, 0o777);
    let right = create(&mut ram, FIRST, ROOT, b"right", DIR, 0o777);
    let source = create(&mut ram, FIRST, left, b"source", DIR, 0o777);
    let victim = create(&mut ram, FIRST, right, b"victim", DIR, 0o777);
    ram.storage.node_mut(right).unwrap().links = u32::MAX;
    assert_eq!(
        run(
            &mut ram,
            NamespaceIntent::Rename,
            b"/left/source",
            Some(b"/right/victim"),
            22
        ),
        Ok(NamespaceOutcome::Applied)
    );
    assert_eq!(ram.storage.node(left).unwrap().links, 2);
    assert_eq!(ram.storage.node(right).unwrap().links, u32::MAX);
    assert_eq!(ram.storage.node(source).unwrap().parent, right);
    assert_eq!(ram.storage.lookup(right, b"victim"), Ok(source));
    drain(&mut ram);
    assert!(ram.storage.node(victim).is_err());
}

#[test]
fn rmdir_orphan_parent_survives_fd_walk_and_cascades_before_slot_reuse() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let parent = create(&mut ram, FIRST, ROOT, b"parent", DIR, 0o777);
    let child = create(&mut ram, FIRST, parent, b"child", DIR, 0o777);
    let mut fds = Fds {
        root: FIRST,
        ..Fds::default()
    };
    let fd = ram.open(&mut fds, "/parent/child", READ_ONLY).unwrap();
    assert_eq!(
        run(&mut ram, NamespaceIntent::Rmdir, b"/parent/child", None, 12),
        Ok(NamespaceOutcome::Applied)
    );
    assert_eq!(
        run(&mut ram, NamespaceIntent::Rmdir, b"/parent", None, 13),
        Ok(NamespaceOutcome::Applied)
    );
    assert_eq!(ram.storage.node(child).unwrap().links, 0);
    assert_eq!(ram.storage.node(parent).unwrap().links, 0);
    assert_eq!(
        ram.storage.node(parent).unwrap().pins[Pin::Parent as usize],
        1
    );
    let mut up = Resolve::new(&mut ram.storage, b"..", child, ROOT_USER, false).unwrap();
    loop {
        if up.step(&mut ram.storage, ROOT_USER).unwrap() == Progress::Found(parent) {
            break;
        }
    }
    up.release(&mut ram.storage);
    assert_eq!(
        ram.storage
            .reserve(FIRST, child, b"new", (REG, 0o644, 37, 43))
            .err(),
        Some(NO_ENTRY)
    );
    let temporary = create(&mut ram, FIRST, ROOT, b"temporary", DIR, 0o777);
    assert_ne!(temporary.slot, parent.slot);
    ram.close(&mut fds, fd).unwrap();
    assert_eq!(drain(&mut ram), 2);
    assert!(ram.storage.node(parent).is_err());
    assert!(ram.storage.node(child).is_err());
    assert_eq!(
        ram.storage.node(ROOT).unwrap().pins[Pin::Parent as usize],
        0
    );
    let reused = create(&mut ram, FIRST, ROOT, b"reused", DIR, 0o777);
    assert_eq!(reused.slot, parent.slot);
    assert!(reused.generation > parent.generation);
}

#[test]
fn unpublished_child_reservation_cannot_commit_into_a_removed_parent() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let parent = create(&mut ram, FIRST, ROOT, b"parent", DIR, 0o777);
    let child = ram
        .storage
        .reserve(FIRST, parent, b"unpublished", (REG, 0o644, 37, 43))
        .unwrap();
    assert_eq!(
        run(&mut ram, NamespaceIntent::Rmdir, b"/parent", None, 30),
        Ok(NamespaceOutcome::Applied)
    );
    assert_eq!(ram.storage.node(parent).unwrap().links, 0);
    assert!(ram.storage.commit_keep_charge(child).is_err());
    ram.storage.cancel(child).unwrap();
    drain(&mut ram);
    assert_eq!(ram.storage.usage(FIRST), Usage::default());
    assert_eq!(
        ram.storage.node(ROOT).unwrap().pins[Pin::Parent as usize],
        0
    );
}

#[test]
fn full_preparation_pool_uses_the_existing_admission_and_cancel_is_exact() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    create(&mut ram, FIRST, ROOT, b"file", REG, 0o644);
    let charge = ram.storage.charge_preparation(FIRST).unwrap();
    let mut charges = Vec::new();
    for _ in 1..PREPARATION_SHARE {
        charges.push(ram.storage.charge_preparation(FIRST).unwrap());
    }
    for _ in PREPARATION_SHARE as usize..PREPARATIONS {
        charges.push(ram.storage.charge_preparation(SECOND).unwrap());
    }
    let usage = ram.storage.usage(FIRST);
    let mut prep = begin(
        &mut ram,
        charge,
        FIRST,
        NamespaceIntent::Rename,
        b"/file",
        Some(b"/new"),
        ROOT_USER,
    )
    .unwrap();
    ready(&mut ram, &mut prep, ROOT_USER).unwrap();
    assert_eq!(ram.storage.preparations_used(), PREPARATIONS as u16);
    cleanup(&mut ram, &mut prep);
    assert!(prep.cancel_step(&mut ram.storage).unwrap());
    assert_eq!(ram.storage.usage(FIRST), usage);
    assert!(ram.storage.lookup(ROOT, b"file").is_ok());
    assert_eq!(ram.storage.lookup(ROOT, b"new"), Err(NO_ENTRY));
    assert_eq!(
        prep.commit(
            &mut ram.storage,
            ROOT_USER,
            proto_fs::Timestamp::legacy_ns(21)
        ),
        Err(STALE_PROOF)
    );
    for charge in charges {
        ram.storage.release_preparation(charge);
    }
    ram.storage.release_preparation(charge);
    assert_eq!(ram.storage.preparations_used(), 0);
}

#[test]
fn step_failure_keeps_reserved_names_until_explicit_cancel_and_blocks_stale_effect() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let source = create(&mut ram, FIRST, ROOT, b"source", REG, 0o644);
    let charge = ram.storage.charge_preparation(FIRST).unwrap();
    let mut prep = begin(
        &mut ram,
        charge,
        FIRST,
        NamespaceIntent::Link {
            follow_source: false,
        },
        b"/source",
        Some(b"/new"),
        ROOT_USER,
    )
    .unwrap();
    let usage = ram.storage.usage(FIRST);
    while ram.storage.usage(FIRST).dentries == usage.dentries {
        assert!(!prep.step(&mut ram.storage, ROOT_USER).unwrap());
    }
    ram.storage.set_attributes(source, 0o600, 37, 43).unwrap();
    assert_eq!(prep.step(&mut ram.storage, ROOT_USER), Err(STALE_PROOF));
    assert_eq!(ram.storage.usage(FIRST).dentries, usage.dentries + 1);
    assert_eq!(
        prep.commit(
            &mut ram.storage,
            ROOT_USER,
            proto_fs::Timestamp::legacy_ns(77)
        ),
        Err(STALE_PROOF)
    );
    cleanup(&mut ram, &mut prep);
    assert_eq!(ram.storage.usage(FIRST), usage);
    ram.storage.release_preparation(charge);
}

#[test]
fn boot_rename_prepays_both_tombstones_and_preserves_open_destination() {
    use bootimg::rootfs::{Entry, REGULAR};
    let image = crate::tree::test_image(&[
        Entry {
            path: "/source",
            mode: REGULAR | 0o644,
            uid: 37,
            gid: 43,
            file: 1,
        },
        Entry {
            path: "/victim",
            mode: REGULAR | 0o644,
            uid: 37,
            gid: 43,
            file: 2,
        },
    ]);
    let mut index = crate::tree::Index::new();
    let tree = crate::tree::load(&image, &mut index).unwrap();
    let mut ram = Ram::with_tree(proto_fs::Timestamp::legacy_ns(10), tree);
    let source = ram.storage.lookup(ROOT, b"source").unwrap();
    let victim = ram.storage.lookup(ROOT, b"victim").unwrap();
    let mut fds = Fds {
        root: SECOND,
        ..Fds::default()
    };
    let fd = ram.open(&mut fds, "/victim", READ_ONLY).unwrap();
    let mut before = [0; 64];
    let n = ram
        .pread(&fds, fd, 0, &mut before, proto_fs::Timestamp::legacy_ns(12))
        .unwrap();
    assert_eq!(
        run(
            &mut ram,
            NamespaceIntent::Rename,
            b"/source",
            Some(b"/victim"),
            41
        ),
        Ok(NamespaceOutcome::Applied)
    );
    assert_eq!(ram.storage.usage(FIRST).dentries, 3);
    assert_eq!(ram.storage.usage(FIRST).inodes, 2);
    assert_eq!(ram.storage.lookup(ROOT, b"source"), Err(NO_ENTRY));
    assert_eq!(ram.storage.lookup(ROOT, b"victim"), Ok(source));
    let mut after = [0; 64];
    assert_eq!(
        ram.pread(&fds, fd, 0, &mut after, proto_fs::Timestamp::legacy_ns(44))
            .unwrap(),
        n
    );
    assert_eq!(&before[..n], &after[..n]);
    assert_eq!(ram.storage.node(victim).unwrap().links, 0);
    ram.close(&mut fds, fd).unwrap();
    drain(&mut ram);
    assert_eq!(ram.storage.usage(FIRST).inodes, 1);
    assert_eq!(ram.storage.usage(FIRST).dentries, 3);
}

#[test]
fn boot_preparation_cancel_reverses_partial_reserves_and_preserves_original_metadata() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(10));
    let source = ram
        .storage
        .lookup(
            Token {
                slot: 1,
                generation: 1,
            },
            b"motd",
        )
        .unwrap();
    let charge = ram.storage.charge_preparation(FIRST).unwrap();
    let mut prep = begin(
        &mut ram,
        charge,
        FIRST,
        NamespaceIntent::Rename,
        b"/etc/motd",
        Some(b"/new"),
        ROOT_USER,
    )
    .unwrap();
    ready(&mut ram, &mut prep, ROOT_USER).unwrap();
    assert_eq!(ram.storage.usage(FIRST).dentries, 2);
    assert_eq!(ram.storage.usage(FIRST).inodes, 1);
    assert_eq!(
        ram.storage.node(source).unwrap().times,
        [proto_fs::Timestamp::legacy_ns(10); 3]
    );
    assert_eq!(
        ram.storage.lookup(
            Token {
                slot: 1,
                generation: 1
            },
            b"motd"
        ),
        Ok(source)
    );
    cleanup(&mut ram, &mut prep);
    assert_eq!(ram.storage.usage(FIRST), Usage::default());
    assert_eq!(
        ram.storage.node(source).unwrap().times,
        [proto_fs::Timestamp::legacy_ns(10); 3]
    );
    ram.storage.release_preparation(charge);
}

#[test]
fn remove_dispatches_the_actual_type_and_link_follow_intent_is_exact() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let file = create(&mut ram, FIRST, ROOT, b"file", REG, 0o644);
    let link = create(&mut ram, FIRST, ROOT, b"symbol", SYMLINK, 0o777);
    ram.storage.write(link, FIRST, 0, b"file").unwrap();
    assert_eq!(
        run(
            &mut ram,
            NamespaceIntent::Link {
                follow_source: true
            },
            b"/symbol",
            Some(b"/alias"),
            31
        ),
        Ok(NamespaceOutcome::Applied)
    );
    assert_eq!(ram.storage.lookup(ROOT, b"alias"), Ok(file));
    assert_eq!(
        run(
            &mut ram,
            NamespaceIntent::Link {
                follow_source: false
            },
            b"/symbol",
            Some(b"/symbol-alias"),
            32
        ),
        Ok(NamespaceOutcome::Applied)
    );
    assert_eq!(ram.storage.lookup(ROOT, b"symbol-alias"), Ok(link));
    let dir = create(&mut ram, FIRST, ROOT, b"dir", DIR, 0o777);
    assert_eq!(
        run(&mut ram, NamespaceIntent::Remove, b"/dir", None, 33),
        Ok(NamespaceOutcome::Applied)
    );
    assert_eq!(
        run(&mut ram, NamespaceIntent::Remove, b"/symbol", None, 34),
        Ok(NamespaceOutcome::Applied)
    );
    assert_eq!(ram.storage.node(file).unwrap().links, 2);
    drain(&mut ram);
    assert!(ram.storage.node(dir).is_err());
    assert_eq!(ram.storage.node(link).unwrap().links, 1);
}

#[test]
fn native_role_mismatch_and_group_change_preserve_the_prepared_namespace() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    create(&mut ram, FIRST, ROOT, b"file", REG, 0o644);
    let r = resolved(&mut ram, b"/file", NamespacePath::Victim, ROOT_USER).unwrap();
    assert!(matches!(
        r.namespace_proof(
            &ram.storage,
            ROOT_USER,
            NamespacePath::LinkSource { follow: false }
        ),
        Err(STALE_PROOF)
    ));
    r.release(&mut ram.storage);
    let charge = ram.storage.charge_preparation(FIRST).unwrap();
    let mut prep = begin(
        &mut ram,
        charge,
        FIRST,
        NamespaceIntent::Unlink,
        b"/file",
        None,
        ROOT_USER,
    )
    .unwrap();
    let mut changed = ROOT_USER;
    changed.groups.count = 1;
    changed.groups.ids[0] = 123;
    assert_eq!(prep.step(&mut ram.storage, changed), Err(STALE_PROOF));
    cleanup(&mut ram, &mut prep);
    ram.storage.release_preparation(charge);
}

#[test]
fn namespace_actual_layout_uses_the_existing_paid_job_and_node_padding() {
    assert_eq!(core::mem::size_of::<Preparation>(), 648);
    assert_eq!(core::mem::size_of::<Node>(), 136);
    std::println!(
        "T4 actual layout: Preparation={} Node={} State={}",
        core::mem::size_of::<Preparation>(),
        core::mem::size_of::<Node>(),
        core::mem::size_of::<State>()
    );
}

#[test]
fn boot_full_share_failure_restores_partial_tombstone_reserve_without_publishing() {
    use bootimg::rootfs::{Entry, REGULAR};
    let image = crate::tree::test_image(&[
        Entry {
            path: "/source",
            mode: REGULAR | 0o644,
            uid: 37,
            gid: 43,
            file: 1,
        },
        Entry {
            path: "/victim",
            mode: REGULAR | 0o644,
            uid: 37,
            gid: 43,
            file: 2,
        },
    ]);
    let mut index = crate::tree::Index::new();
    let tree = crate::tree::load(&image, &mut index).unwrap();
    let mut ram = Ram::with_tree(proto_fs::Timestamp::legacy_ns(10), tree);
    let filler = create(&mut ram, FIRST, ROOT, b"filler", REG, 0o644);
    for i in 0..DENTRY_SHARE - 2 {
        ram.storage
            .link(FIRST, ROOT, format!("f{i}").as_bytes(), filler)
            .unwrap();
    }
    let usage = ram.storage.usage(FIRST);
    let epoch = ram.storage.state.epoch;
    let original_source = ram.storage.lookup(ROOT, b"source").unwrap();
    let original_victim = ram.storage.lookup(ROOT, b"victim").unwrap();
    let before_pins = pins(&ram);
    assert_eq!(
        run(
            &mut ram,
            NamespaceIntent::Rename,
            b"/source",
            Some(b"/victim"),
            89
        ),
        Err(NO_SPACE)
    );
    assert_eq!(ram.storage.usage(FIRST), usage);
    assert_eq!(ram.storage.state.epoch, epoch);
    assert_eq!(ram.storage.lookup(ROOT, b"source"), Ok(original_source));
    assert_eq!(ram.storage.lookup(ROOT, b"victim"), Ok(original_victim));
    assert_eq!(pins(&ram), before_pins);
    assert_eq!(
        ram.storage.node(original_source).unwrap().times,
        [proto_fs::Timestamp::legacy_ns(10); 3]
    );
}

#[test]
fn constructor_pin_exhaustion_is_atomic_after_genuine_resolver_capture() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let source = create(&mut ram, FIRST, ROOT, b"source", REG, 0o644);
    let charge = ram.storage.charge_preparation(FIRST).unwrap();
    let resolver = resolved(&mut ram, b"/source", NamespacePath::Victim, ROOT_USER).unwrap();
    let old = ram.storage.node(source).unwrap().pins[Pin::Pending as usize];
    ram.storage.node_mut(source).unwrap().pins[Pin::Pending as usize] = u16::MAX;
    let before_pins = pins(&ram);
    let usage = ram.storage.usage(FIRST);
    let epoch = ram.storage.state.epoch;
    let proof = resolver
        .namespace_proof(&ram.storage, ROOT_USER, NamespacePath::Victim)
        .unwrap();
    assert!(matches!(
        ram.storage.prepare_namespace_paid(
            FIRST,
            charge,
            NamespaceIntent::Unlink,
            proof,
            None,
            ROOT_USER
        ),
        Err(NO_SPACE)
    ));
    assert_eq!(ram.storage.usage(FIRST), usage);
    assert_eq!(pins(&ram), before_pins);
    assert_eq!(ram.storage.state.epoch, epoch);
    assert_eq!(ram.storage.preparations_used(), 1);
    ram.storage.node_mut(source).unwrap().pins[Pin::Pending as usize] = old;
    resolver.release(&mut ram.storage);
    ram.storage.release_preparation(charge);
}

#[test]
fn source_and_destination_role_capture_cannot_be_exchanged() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    create(&mut ram, FIRST, ROOT, b"source", REG, 0o644);
    let source = resolved(&mut ram, b"/source", NamespacePath::Victim, ROOT_USER).unwrap();
    let destination =
        resolved(&mut ram, b"/missing", NamespacePath::Destination, ROOT_USER).unwrap();
    let charge = ram.storage.charge_preparation(FIRST).unwrap();
    let epoch = ram.storage.state.epoch;
    let usage = ram.storage.usage(FIRST);
    let result = ram.storage.prepare_namespace_paid(
        FIRST,
        charge,
        NamespaceIntent::Rename,
        destination
            .namespace_proof(&ram.storage, ROOT_USER, NamespacePath::Destination)
            .unwrap(),
        Some(
            source
                .namespace_proof(&ram.storage, ROOT_USER, NamespacePath::Victim)
                .unwrap(),
        ),
        ROOT_USER,
    );
    assert!(matches!(result, Err(STALE_PROOF)));
    assert_eq!(ram.storage.usage(FIRST), usage);
    assert_eq!(ram.storage.state.epoch, epoch);
    source.release(&mut ram.storage);
    destination.release(&mut ram.storage);
    ram.storage.release_preparation(charge);
}

#[test]
fn followed_link_source_directory_and_root_return_permission_without_new_names() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
    let link = create(&mut ram, FIRST, ROOT, b"rootlink", SYMLINK, 0o777);
    ram.storage.write(link, FIRST, 0, b"/").unwrap();
    let usage = ram.storage.usage(FIRST);
    let epoch = ram.storage.state.epoch;
    assert_eq!(
        run(
            &mut ram,
            NamespaceIntent::Link {
                follow_source: true
            },
            b"/rootlink",
            Some(b"/new"),
            42
        ),
        Err(proto_fs::PERMISSION)
    );
    assert_eq!(ram.storage.usage(FIRST), usage);
    assert_eq!(ram.storage.state.epoch, epoch);
    assert_eq!(ram.storage.lookup(ROOT, b"new"), Err(NO_ENTRY));
}

#[test]
fn typed_unlink_directory_returns_permission_and_preserves_all_paid_state() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(17));
    let dir = create(&mut ram, FIRST, ROOT, b"directory", DIR, 0o777);
    let link = create(&mut ram, FIRST, ROOT, b"directory-link", SYMLINK, 0o777);
    ram.storage.write(link, FIRST, 0, b"directory").unwrap();
    let charge = ram.storage.charge_preparation(FIRST).unwrap();
    let usage = ram.storage.usage(FIRST);
    let before_pins = pins(&ram);
    let epoch = ram.storage.state.epoch;
    let before_dir = *ram.storage.node(dir).unwrap();
    let before_link = *ram.storage.node(link).unwrap();
    let before_root = *ram.storage.node(ROOT).unwrap();
    for path in [b"/directory".as_slice(), b"/directory-link/"] {
        assert!(matches!(
            begin(
                &mut ram,
                charge,
                FIRST,
                NamespaceIntent::Unlink,
                path,
                None,
                ROOT_USER
            ),
            Err(proto_fs::PERMISSION)
        ));
        assert_eq!(ram.storage.usage(FIRST), usage);
        assert_eq!(pins(&ram), before_pins);
        assert_eq!(ram.storage.state.epoch, epoch);
        assert_eq!(ram.storage.preparations_used(), 1);
        for (token, before) in [(dir, before_dir), (link, before_link), (ROOT, before_root)] {
            let after = ram.storage.node(token).unwrap();
            assert_eq!(
                (after.times, after.links, after.parent, after.length),
                (before.times, before.links, before.parent, before.length)
            );
        }
        assert_eq!(ram.storage.lookup(ROOT, b"directory"), Ok(dir));
        assert_eq!(ram.storage.lookup(ROOT, b"directory-link"), Ok(link));
    }
    ram.storage.release_preparation(charge);
    assert_eq!(ram.storage.preparations_used(), 0);
    assert_eq!(
        ram.storage.unlink(ROOT, b"directory", FIRST),
        Err(proto_fs::IS_DIRECTORY)
    );
    assert_eq!(ram.storage.preparations_used(), 0);
    assert_eq!(ram.storage.usage(FIRST), usage);
    assert_eq!(pins(&ram), before_pins);
    assert_eq!(ram.storage.state.epoch, epoch);
    assert_eq!(
        run(
            &mut ram,
            NamespaceIntent::Unlink,
            b"/directory-link",
            None,
            99
        ),
        Ok(NamespaceOutcome::Applied)
    );
    assert_eq!(ram.storage.lookup(ROOT, b"directory"), Ok(dir));
    assert_eq!(ram.storage.lookup(ROOT, b"directory-link"), Err(NO_ENTRY));
}

fn rename_into_exact_parent(ram: &mut Ram<'_>, charge: u16, parent: Token) -> Preparation {
    let source = resolved(ram, b"/source", NamespacePath::Victim, ROOT_USER).unwrap();
    let mut destination = Resolve::with_intent(
        &mut ram.storage,
        b"moved",
        parent,
        ROOT_USER,
        Intent::Namespace {
            path: NamespacePath::Destination,
        },
    )
    .unwrap();
    while destination.step(&mut ram.storage, ROOT_USER).unwrap() == Progress::More {}
    let prep = ram
        .storage
        .prepare_namespace_paid(
            FIRST,
            charge,
            NamespaceIntent::Rename,
            source
                .namespace_proof(&ram.storage, ROOT_USER, NamespacePath::Victim)
                .unwrap(),
            Some(
                destination
                    .namespace_proof(&ram.storage, ROOT_USER, NamespacePath::Destination)
                    .unwrap(),
            ),
            ROOT_USER,
        )
        .unwrap();
    source.release(&mut ram.storage);
    destination.release(&mut ram.storage);
    prep
}

#[test]
fn rename_ancestors_include_deep_boot_and_relative_dynamic_directories() {
    let paths = (1..=255)
        .map(|depth| "/a".repeat(depth))
        .collect::<Vec<_>>();
    let entries = paths
        .iter()
        .map(|path| bootimg::rootfs::Entry {
            path,
            mode: bootimg::rootfs::DIRECTORY | 0o755,
            uid: 0,
            gid: 0,
            file: 0,
        })
        .collect::<Vec<_>>();
    let image = crate::tree::test_image(&entries);
    let mut index = crate::tree::Index::new();
    let tree = crate::tree::load(&image, &mut index).unwrap();
    let mut ram = Ram::with_tree(proto_fs::Timestamp::ZERO, tree);
    let mut parent = ram
        .storage
        .resolve(paths.last().unwrap().as_bytes())
        .unwrap();
    for _ in 0..4 {
        parent = create(&mut ram, FIRST, parent, b"child", DIR, 0o755);
    }
    let source = create(&mut ram, FIRST, ROOT, b"source", DIR, 0o755);
    let charge = ram.storage.charge_preparation(FIRST).unwrap();
    let before_pins = pins(&ram);
    let usage = ram.storage.usage(FIRST);
    let epoch = ram.storage.state.epoch;
    let mut prep = rename_into_exact_parent(&mut ram, charge, parent);
    assert!(ready(&mut ram, &mut prep, ROOT_USER).unwrap() > INODES);
    assert_eq!(ram.storage.usage(FIRST), usage);
    assert_eq!(ram.storage.state.epoch, epoch);
    let now = proto_fs::Timestamp::legacy_ns(73);
    assert_eq!(
        prep.commit(&mut ram.storage, ROOT_USER, now),
        Ok(NamespaceOutcome::Applied)
    );
    assert_eq!(ram.storage.lookup(parent, b"moved"), Ok(source));
    assert_eq!(ram.storage.lookup(ROOT, b"source"), Err(NO_ENTRY));
    assert_eq!(ram.storage.node(source).unwrap().parent, parent);
    assert_eq!(ram.storage.node(parent).unwrap().times[1], now);
    cleanup(&mut ram, &mut prep);
    cleanup(&mut ram, &mut prep);
    assert_eq!(pins(&ram), before_pins);
    assert_eq!(ram.storage.preparations_used(), 1);
    ram.storage.release_preparation(charge);
}

#[test]
fn rename_ancestors_cycle_refuses_with_exact_paid_cleanup() {
    let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(19));
    let parent = create(&mut ram, FIRST, ROOT, b"parent", DIR, 0o755);
    let source = create(&mut ram, FIRST, ROOT, b"source", DIR, 0o755);
    let charge = ram.storage.charge_preparation(FIRST).unwrap();
    let before_pins = pins(&ram);
    let mut prep = rename_into_exact_parent(&mut ram, charge, parent);
    // This model keeps the captured namespace epoch and supplies a cyclic parent graph.
    ram.storage.state.nodes[parent.slot as usize].parent = parent;
    let usage = ram.storage.usage(FIRST);
    let epoch = ram.storage.state.epoch;
    let times = ram
        .storage
        .state
        .nodes
        .iter()
        .map(|node| node.times)
        .collect::<Vec<_>>();
    assert_eq!(
        ready(&mut ram, &mut prep, ROOT_USER),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    assert_eq!(ram.storage.usage(FIRST), usage);
    assert_eq!(ram.storage.state.epoch, epoch);
    assert_eq!(
        ram.storage
            .state
            .nodes
            .iter()
            .map(|node| node.times)
            .collect::<Vec<_>>(),
        times
    );
    assert_eq!(ram.storage.lookup(ROOT, b"source"), Ok(source));
    assert_eq!(ram.storage.lookup(parent, b"moved"), Err(NO_ENTRY));
    cleanup(&mut ram, &mut prep);
    cleanup(&mut ram, &mut prep);
    assert_eq!(pins(&ram), before_pins);
    assert_eq!(ram.storage.preparations_used(), 1);
    ram.storage.release_preparation(charge);
}
