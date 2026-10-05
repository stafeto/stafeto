// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::{
    Fds, REG, Ram,
    authority::Identity,
    metadata::*,
    resolve::{Intent, Progress, Resolve},
    storage::{Pin, ROOT, Root, Token},
};
use proto_fs::{
    ACCESS_DENIED, INVALID_ARGUMENT, NO_SPACE, PERMISSION, READ_WRITE, RESOLVING, STALE_PROOF,
    Timestamp,
};
use proto_process::{Credentials, Groups};

const EXPENSE: Root = Root {
    id: 11,
    generation: 7,
};
const ADMIN: Identity = Identity {
    uid: 0,
    gid: 0,
    groups: Groups::EMPTY,
};
const OWNER: Identity = Identity {
    uid: 37,
    gid: 43,
    groups: Groups::EMPTY,
};
const OTHER: Identity = Identity {
    uid: 38,
    gid: 44,
    groups: Groups::EMPTY,
};
const NOW: Timestamp = match Timestamp::new(-1, 999_999_999) {
    Ok(value) => value,
    Err(_) => panic!("valid timestamp"),
};
fn file(ram: &mut Ram<'_>, parent: Token, name: &[u8], kind: u32, mode: u32) -> Token {
    let reserve = ram
        .storage
        .reserve(EXPENSE, parent, name, (kind, mode, OWNER.uid, OWNER.gid))
        .unwrap();
    ram.storage.commit(reserve).unwrap()
}
fn resolve(
    ram: &mut Ram<'_>,
    bytes: &[u8],
    identity: Identity,
    path: MetadataPath,
) -> Result<Resolve, u32> {
    let mut resolver = Resolve::with_intent(
        &mut ram.storage,
        bytes,
        ROOT,
        identity,
        Intent::Metadata { path },
    )?;
    for _ in 0..10000 {
        match resolver.step(&mut ram.storage, identity) {
            Ok(Progress::More) => (),
            Ok(_) => return Ok(resolver),
            Err(code) => {
                resolver.release(&mut ram.storage);
                return Err(code);
            }
        }
    }
    panic!("metadata resolver did not complete")
}
fn begin(
    ram: &mut Ram<'_>,
    bytes: &[u8],
    identity: Identity,
    intent: MetadataIntent,
) -> (MetadataJournal, Resolve, u16) {
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let path = intent.path(true);
    let resolver = resolve(ram, bytes, identity, path).unwrap();
    let proof = resolver
        .metadata_proof(&ram.storage, identity, path)
        .unwrap();
    let journal =
        MetadataJournal::path(&mut ram.storage, EXPENSE, charge, proof, identity, intent).unwrap();
    (journal, resolver, charge)
}
fn cleanup(
    ram: &mut Ram<'_>,
    mut journal: MetadataJournal,
    resolver: Option<Resolve>,
    charge: u16,
) {
    assert!(journal.cancel_step(ram).unwrap());
    assert!(journal.cancel_step(ram).unwrap());
    if let Some(resolver) = resolver {
        resolver.release(&mut ram.storage);
    }
    ram.storage.release_preparation(charge);
}
fn apply(
    ram: &mut Ram<'_>,
    bytes: &[u8],
    identity: Identity,
    intent: MetadataIntent,
    now: Option<Timestamp>,
) -> MetadataOutcome {
    let (mut journal, resolver, charge) = begin(ram, bytes, identity, intent);
    let proof = resolver
        .metadata_proof(&ram.storage, identity, intent.path(true))
        .unwrap();
    let outcome = journal
        .commit(ram, EXPENSE, identity, Some(proof), now)
        .unwrap();
    cleanup(ram, journal, Some(resolver), charge);
    outcome
}

#[test]
fn chmod_ignores_type_bits_and_uses_owner_group_class_once() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let token = file(&mut ram, ROOT, b"mode", REG, 0o4755);
    let before = ram.storage.usage(EXPENSE);
    let (mut journal, resolver, charge) = begin(
        &mut ram,
        b"/mode",
        OWNER,
        MetadataIntent::Chmod(0o100_000 | 0o2754),
    );
    let proof = resolver
        .metadata_proof(&ram.storage, OWNER, MetadataIntent::Chmod(0).path(true))
        .unwrap();
    assert_eq!(
        journal.commit(&mut ram, EXPENSE, OWNER, Some(proof), Some(NOW)),
        Ok(MetadataOutcome::Applied)
    );
    let node = ram.storage.node(token).unwrap();
    assert_eq!(node.mode, 0o2754);
    assert_eq!(node.times[2], NOW);
    let epoch = ram.storage.state.epoch;
    assert_eq!(
        journal.commit(&mut ram, EXPENSE, OTHER, None, None),
        Ok(MetadataOutcome::Applied)
    );
    assert_eq!(ram.storage.state.epoch, epoch);
    assert_eq!(ram.storage.node(token).unwrap().times[2], NOW);
    cleanup(&mut ram, journal, Some(resolver), charge);
    assert_eq!(ram.storage.usage(EXPENSE), before);
    ram.storage
        .set_attributes(token, 0o644, OWNER.uid, 99)
        .unwrap();
    assert_eq!(
        apply(
            &mut ram,
            b"/mode",
            OWNER,
            MetadataIntent::Chmod(0o2755),
            Some(NOW)
        ),
        MetadataOutcome::Applied
    );
    assert_eq!(ram.storage.node(token).unwrap().mode, 0o755);
    let mut member = OWNER;
    member.groups.count = 1;
    member.groups.ids[0] = 99;
    assert_eq!(
        apply(
            &mut ram,
            b"/mode",
            member,
            MetadataIntent::Chmod(0o2755),
            Some(NOW)
        ),
        MetadataOutcome::Applied
    );
    assert_eq!(ram.storage.node(token).unwrap().mode, 0o2755);
    assert_eq!(
        apply(&mut ram, b"/mode", OTHER, MetadataIntent::Chmod(0), None),
        MetadataOutcome::Failed(PERMISSION)
    );
    assert_eq!(ram.storage.node(token).unwrap().mode, 0o2755);
}

#[test]
fn chown_same_uid_supplementary_gid_both_none_and_denials_are_cached() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let token = file(&mut ram, ROOT, b"owner", REG, 0o6755);
    let mut member = OWNER;
    member.groups.count = 1;
    member.groups.ids[0] = 99;
    assert_eq!(
        apply(
            &mut ram,
            b"/owner",
            member,
            MetadataIntent::Chown {
                uid: Some(37),
                gid: Some(99)
            },
            Some(NOW)
        ),
        MetadataOutcome::Applied
    );
    assert_eq!(
        (
            ram.storage.node(token).unwrap().uid,
            ram.storage.node(token).unwrap().gid,
            ram.storage.node(token).unwrap().mode
        ),
        (37, 99, 0o755)
    );
    ram.storage.set_attributes(token, 0o6755, 37, 99).unwrap();
    let later = Timestamp::new(i64::MIN, 0).unwrap();
    let (mut journal, resolver, charge) = begin(
        &mut ram,
        b"/owner",
        member,
        MetadataIntent::Chown {
            uid: None,
            gid: None,
        },
    );
    let proof = resolver
        .metadata_proof(
            &ram.storage,
            member,
            MetadataIntent::Chown {
                uid: None,
                gid: None,
            }
            .path(true),
        )
        .unwrap();
    assert_eq!(
        journal.commit(&mut ram, EXPENSE, member, Some(proof), Some(later)),
        Ok(MetadataOutcome::Applied)
    );
    assert_eq!(ram.storage.node(token).unwrap().mode, 0o755);
    assert_eq!(
        journal.commit(&mut ram, EXPENSE, member, None, Some(NOW)),
        Ok(MetadataOutcome::Applied)
    );
    assert_eq!(ram.storage.node(token).unwrap().times[2], later);
    cleanup(&mut ram, journal, Some(resolver), charge);
    assert_eq!(
        apply(
            &mut ram,
            b"/owner",
            OWNER,
            MetadataIntent::Chown {
                uid: Some(38),
                gid: None
            },
            None
        ),
        MetadataOutcome::Failed(PERMISSION)
    );
    assert_eq!(
        apply(
            &mut ram,
            b"/owner",
            OWNER,
            MetadataIntent::Chown {
                uid: None,
                gid: Some(100)
            },
            None
        ),
        MetadataOutcome::Failed(PERMISSION)
    );
    assert_eq!(
        apply(
            &mut ram,
            b"/owner",
            OTHER,
            MetadataIntent::Chown {
                uid: None,
                gid: None
            },
            None
        ),
        MetadataOutcome::Failed(PERMISSION)
    );
    assert_eq!(
        apply(
            &mut ram,
            b"/owner",
            ADMIN,
            MetadataIntent::Chown {
                uid: Some(38),
                gid: Some(100)
            },
            Some(NOW)
        ),
        MetadataOutcome::Applied
    );
    assert_eq!(
        (
            ram.storage.node(token).unwrap().uid,
            ram.storage.node(token).unwrap().gid
        ),
        (38, 100)
    );
}

#[test]
fn times_exact_now_omit_and_zero_effect_permissions_preserve_signed_values() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let token = file(&mut ram, ROOT, b"times", REG, 0o6222);
    let earliest = Timestamp::new(i64::MIN, 1).unwrap();
    let latest = Timestamp::new(i64::MAX, 999_999_999).unwrap();
    assert_eq!(
        apply(
            &mut ram,
            b"/times",
            OWNER,
            MetadataIntent::Times([TimeSetting::Exact(earliest), TimeSetting::Exact(latest)]),
            Some(NOW)
        ),
        MetadataOutcome::Applied
    );
    assert_eq!(
        ram.storage.node(token).unwrap().times,
        [earliest, latest, NOW]
    );
    assert_eq!(ram.storage.node(token).unwrap().mode, 0o6222);
    assert_eq!(
        apply(
            &mut ram,
            b"/times",
            OTHER,
            MetadataIntent::Times([TimeSetting::Now; 2]),
            Some(latest)
        ),
        MetadataOutcome::Applied
    );
    assert_eq!(ram.storage.node(token).unwrap().times, [latest; 3]);
    assert_eq!(
        apply(
            &mut ram,
            b"/times",
            OTHER,
            MetadataIntent::Times([TimeSetting::Now, TimeSetting::Omit]),
            None
        ),
        MetadataOutcome::Failed(PERMISSION)
    );
    ram.storage
        .set_attributes(token, 0, OWNER.uid, OWNER.gid)
        .unwrap();
    let epoch = ram.storage.state.epoch;
    let before = ram.storage.node(token).unwrap().times;
    assert_eq!(
        apply(
            &mut ram,
            b"/times",
            OTHER,
            MetadataIntent::Times([TimeSetting::Omit; 2]),
            None
        ),
        MetadataOutcome::Unchanged
    );
    assert_eq!(ram.storage.state.epoch, epoch);
    assert_eq!(ram.storage.node(token).unwrap().times, before);
    assert_eq!(
        apply(
            &mut ram,
            b"/times",
            OWNER,
            MetadataIntent::Times([TimeSetting::Omit, TimeSetting::Now]),
            Some(earliest)
        ),
        MetadataOutcome::Applied
    );
    assert_eq!(
        ram.storage.node(token).unwrap().times,
        [latest, earliest, earliest]
    );
}

#[test]
fn constructor_failures_clock_deferral_epoch_and_identity_refuse_before_effect() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let token = file(&mut ram, ROOT, b"checked", REG, 0o644);
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let intent = MetadataIntent::Chmod(0o600);
    let resolver = resolve(&mut ram, b"/checked", OWNER, intent.path(true)).unwrap();
    let before = ram.storage.usage(EXPENSE);
    let pins = ram.storage.node(token).unwrap().pins;
    let mut bad = Timestamp::ZERO;
    bad.nanos = 1_000_000_000;
    let proof = resolver
        .metadata_proof(&ram.storage, OWNER, intent.path(true))
        .unwrap();
    assert!(matches!(
        MetadataJournal::path(
            &mut ram.storage,
            EXPENSE,
            charge,
            proof,
            OWNER,
            MetadataIntent::Times([TimeSetting::Exact(bad); 2])
        ),
        Err(INVALID_ARGUMENT)
    ));
    assert_eq!(ram.storage.node(token).unwrap().pins, pins);
    assert_eq!(ram.storage.usage(EXPENSE), before);
    assert_eq!(ram.storage.preparations_used(), 1);
    let proof = resolver
        .metadata_proof(&ram.storage, OWNER, intent.path(true))
        .unwrap();
    let mut journal =
        MetadataJournal::path(&mut ram.storage, EXPENSE, charge, proof, OWNER, intent).unwrap();
    let proof = resolver
        .metadata_proof(&ram.storage, OWNER, intent.path(true))
        .unwrap();
    assert_eq!(
        journal.commit(&mut ram, EXPENSE, OWNER, Some(proof), None),
        Err(RESOLVING)
    );
    assert_eq!(journal.outcome(), None);
    let proof = resolver
        .metadata_proof(&ram.storage, OWNER, intent.path(true))
        .unwrap();
    assert_eq!(
        journal.commit(&mut ram, EXPENSE, OWNER, Some(proof), Some(bad)),
        Err(INVALID_ARGUMENT)
    );
    let proof = resolver
        .metadata_proof(&ram.storage, OWNER, intent.path(true))
        .unwrap();
    assert_eq!(
        journal.commit(&mut ram, EXPENSE, OTHER, Some(proof), Some(NOW)),
        Err(STALE_PROOF)
    );
    ram.storage.state.epoch += 1;
    assert!(matches!(
        resolver.metadata_proof(&ram.storage, OWNER, intent.path(true)),
        Err(STALE_PROOF)
    ));
    assert_eq!(
        journal.commit(&mut ram, EXPENSE, OWNER, None, Some(NOW)),
        Err(STALE_PROOF)
    );
    assert_eq!(ram.storage.node(token).unwrap().mode, 0o644);
    assert_eq!(ram.storage.node(token).unwrap().times, [Timestamp::ZERO; 3]);
    cleanup(&mut ram, journal, Some(resolver), charge);
    ram.storage.state.epoch = u64::MAX;
    let (mut journal, resolver, charge) = begin(&mut ram, b"/checked", OWNER, intent);
    let proof = resolver
        .metadata_proof(&ram.storage, OWNER, intent.path(true))
        .unwrap();
    assert_eq!(
        journal.commit(&mut ram, EXPENSE, OWNER, Some(proof), Some(NOW)),
        Err(NO_SPACE)
    );
    assert_eq!(ram.storage.node(token).unwrap().mode, 0o644);
    cleanup(&mut ram, journal, Some(resolver), charge);
}

#[test]
fn exact_description_metadata_survives_chmod_unlink_close_and_numeric_reuse() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let token = file(&mut ram, ROOT, b"old", REG, 0o644);
    let mut fds = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    let fd = ram.open_token(&mut fds, token, READ_WRITE, OWNER).unwrap();
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let mut journal = ram
        .prepare_metadata(
            &fds,
            fd,
            charge,
            OWNER,
            MetadataIntent::Chmod(0o100_000 | 0o600),
        )
        .unwrap();
    ram.storage
        .set_attributes(token, 0, OWNER.uid, OWNER.gid)
        .unwrap();
    ram.storage.unlink(ROOT, b"old", EXPENSE).unwrap();
    ram.close(&mut fds, fd).unwrap();
    let fresh = file(&mut ram, ROOT, b"new", REG, 0o644);
    let replacement = ram.open_token(&mut fds, fresh, READ_WRITE, OWNER).unwrap();
    assert_eq!(replacement, fd);
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 2);
    assert_eq!(
        journal.commit(&mut ram, EXPENSE, OWNER, None, Some(NOW)),
        Ok(MetadataOutcome::Applied)
    );
    assert_eq!(ram.storage.node(token).unwrap().mode, 0o600);
    assert_eq!(ram.storage.node(fresh).unwrap().mode, 0o644);
    assert_eq!(ram.storage.node(fresh).unwrap().times, [Timestamp::ZERO; 3]);
    cleanup(&mut ram, journal, None, charge);
    assert_eq!(ram.storage.usage(EXPENSE).descriptions, 1);
    while ram.storage.reclaim_step() {}
    assert!(ram.storage.node(token).is_err());
    assert_eq!(
        ram.descriptor_information(&fds, fd).unwrap().permissions,
        0o644
    );
}

#[test]
fn access_real_and_effective_search_use_the_same_class_and_have_no_atime_effect() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let directory = file(&mut ram, ROOT, b"private", crate::DIR, 0o700);
    let token = file(&mut ram, directory, b"file", REG, 0o044);
    let credentials = Credentials {
        uid: OTHER.uid,
        euid: OWNER.uid,
        suid: OWNER.uid,
        gid: OTHER.gid,
        egid: OWNER.gid,
        sgid: OWNER.gid,
    };
    let real = Identity::of(credentials, Groups::EMPTY, true);
    let effective = Identity::of(credentials, Groups::EMPTY, false);
    let real_intent = MetadataIntent::Access {
        bits: 4,
        real: true,
    };
    assert!(matches!(
        resolve(&mut ram, b"/private/file", real, real_intent.path(true)),
        Err(ACCESS_DENIED)
    ));
    let before = ram.storage.state.epoch;
    assert_eq!(
        apply(
            &mut ram,
            b"/private/file",
            effective,
            MetadataIntent::Access {
                bits: 4,
                real: false
            },
            None
        ),
        MetadataOutcome::Failed(ACCESS_DENIED)
    );
    assert_eq!(ram.storage.state.epoch, before);
    assert_eq!(ram.storage.node(token).unwrap().times, [Timestamp::ZERO; 3]);
    assert_eq!(
        apply(
            &mut ram,
            b"/private/file",
            effective,
            MetadataIntent::Access {
                bits: 0,
                real: false
            },
            None
        ),
        MetadataOutcome::Unchanged
    );
    assert_eq!(
        apply(
            &mut ram,
            b"/private/file",
            ADMIN,
            MetadataIntent::Access {
                bits: 1,
                real: false
            },
            None
        ),
        MetadataOutcome::Failed(ACCESS_DENIED)
    );
    ram.storage
        .set_attributes(token, 0o001, OWNER.uid, OWNER.gid)
        .unwrap();
    assert_eq!(
        apply(
            &mut ram,
            b"/private/file",
            ADMIN,
            MetadataIntent::Access {
                bits: 1,
                real: false
            },
            None
        ),
        MetadataOutcome::Unchanged
    );
    let lookup = Resolve::new(&mut ram.storage, b"/private/file", ROOT, effective, true).unwrap();
    assert!(matches!(
        lookup.metadata_proof(&ram.storage, effective, MetadataIntent::Chmod(0).path(true)),
        Err(STALE_PROOF)
    ));
    lookup.release(&mut ram.storage);
}

#[test]
fn boot_chmod_changes_canonical_node_without_overlay_or_extra_charge() {
    use bootimg::rootfs::{Entry, REGULAR};
    let image = crate::tree::test_image(&[
        Entry {
            path: "/program",
            mode: REGULAR | 0o755,
            uid: 37,
            gid: 43,
            file: 1,
        },
        Entry {
            path: "/alias",
            mode: REGULAR | 0o755,
            uid: 37,
            gid: 43,
            file: 1,
        },
    ]);
    let mut index = crate::tree::Index::new();
    let tree = crate::tree::load(&image, &mut index).unwrap();
    let mut ram = Ram::with_tree(Timestamp::ZERO, tree);
    let before = ram.storage.filesystem_information(EXPENSE);
    let usage = ram.storage.usage(EXPENSE);
    assert_eq!(
        apply(
            &mut ram,
            b"/program",
            OWNER,
            MetadataIntent::Chmod(0o100_000 | 0o640),
            Some(NOW)
        ),
        MetadataOutcome::Applied
    );
    assert_eq!(ram.information("/alias").unwrap().permissions, 0o640);
    assert_eq!(ram.information("/alias").unwrap().change_time, NOW);
    assert_eq!(ram.storage.filesystem_information(EXPENSE), before);
    assert_eq!(ram.storage.usage(EXPENSE), usage);
}

#[test]
fn metadata_pin_exhaustion_and_paid_admission_preserve_all_resources() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let token = file(&mut ram, ROOT, b"pins", REG, 0o644);
    let intent = MetadataIntent::Chmod(0o600);
    let resolver = resolve(&mut ram, b"/pins", OWNER, intent.path(true)).unwrap();
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    ram.storage.node_mut(token).unwrap().pins[Pin::Pending as usize] = u16::MAX;
    let before = ram.storage.usage(EXPENSE);
    let proof = resolver
        .metadata_proof(&ram.storage, OWNER, intent.path(true))
        .unwrap();
    assert!(matches!(
        MetadataJournal::path(&mut ram.storage, EXPENSE, charge, proof, OWNER, intent),
        Err(NO_SPACE)
    ));
    assert_eq!(ram.storage.usage(EXPENSE), before);
    assert_eq!(ram.storage.preparations_used(), 1);
    assert_eq!(ram.storage.node(token).unwrap().mode, 0o644);
    // Restore the resolver's exact target reference before its normal release.
    ram.storage.node_mut(token).unwrap().pins[Pin::Pending as usize] = 1;
    resolver.release(&mut ram.storage);
    ram.storage.release_preparation(charge);
    assert_eq!(ram.storage.node(token).unwrap().pins, [0; 5]);
}

#[test]
fn nonzero_legacy_write_clears_set_id_before_proof_reuse_and_zero_preserves_it() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let token = file(&mut ram, ROOT, b"writer", REG, 0o6755);
    let mut fds = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    let fd = ram.open_token(&mut fds, token, READ_WRITE, OWNER).unwrap();
    let intent = MetadataIntent::Chmod(0o600);
    let resolver = resolve(&mut ram, b"/writer", OWNER, intent.path(true)).unwrap();
    let epoch = ram.storage.state.epoch;
    assert_eq!(ram.write_at(&mut fds, fd, &[], NOW), Ok(0));
    assert_eq!(ram.storage.node(token).unwrap().mode, 0o6755);
    assert_eq!(ram.storage.state.epoch, epoch);
    assert_eq!(ram.write_at(&mut fds, fd, b"x", NOW), Ok(1));
    assert_eq!(ram.storage.node(token).unwrap().mode, 0o755);
    assert!(ram.storage.state.epoch > epoch);
    assert!(matches!(
        resolver.metadata_proof(&ram.storage, OWNER, intent.path(true)),
        Err(STALE_PROOF)
    ));
    resolver.release(&mut ram.storage);
    ram.storage
        .set_attributes(token, 0o6755, OWNER.uid, OWNER.gid)
        .unwrap();
    ram.storage.state.epoch = u64::MAX;
    let usage = ram.storage.usage(EXPENSE);
    let data_generation = ram.storage.node(token).unwrap().data_generation;
    assert_eq!(ram.pwrite(&mut fds, fd, 0, b"bad", NOW), Err(NO_SPACE));
    assert_eq!(ram.storage.usage(EXPENSE), usage);
    assert_eq!(
        ram.storage.node(token).unwrap().data_generation,
        data_generation
    );
    assert_eq!(ram.storage.node(token).unwrap().mode, 0o6755);
    let mut bytes = [0; 1];
    assert_eq!(ram.storage.read(token, 0, &mut bytes), Ok(1));
    assert_eq!(bytes, *b"x");
}

#[test]
fn nofollow_metadata_proof_targets_the_symbolic_link_and_preserves_target_times() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let target = file(&mut ram, ROOT, b"target", REG, 0o600);
    let symbol = file(&mut ram, ROOT, b"symbol", crate::storage::SYMLINK, 0o777);
    ram.storage.write(symbol, EXPENSE, 0, b"/target").unwrap();
    let intent = MetadataIntent::Times([TimeSetting::Now; 2]);
    let path = intent.path(false);
    let resolver = resolve(&mut ram, b"/symbol", OWNER, path).unwrap();
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let proof = resolver.metadata_proof(&ram.storage, OWNER, path).unwrap();
    let mut journal =
        MetadataJournal::path(&mut ram.storage, EXPENSE, charge, proof, OWNER, intent).unwrap();
    let proof = resolver.metadata_proof(&ram.storage, OWNER, path).unwrap();
    assert_eq!(
        journal.commit(&mut ram, EXPENSE, OWNER, Some(proof), Some(NOW)),
        Ok(MetadataOutcome::Applied)
    );
    assert_eq!(ram.storage.node(symbol).unwrap().times, [NOW; 3]);
    assert_eq!(
        ram.storage.node(target).unwrap().times,
        [Timestamp::ZERO; 3]
    );
    cleanup(&mut ram, journal, Some(resolver), charge);
}

#[test]
fn actual_metadata_layout_is_reported() {
    extern crate std;
    std::println!(
        "T4 metadata layout: Journal={} Proof={} Intent={}",
        core::mem::size_of::<MetadataJournal>(),
        core::mem::size_of::<MetadataProof>(),
        core::mem::size_of::<MetadataIntent>()
    );
}
