// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Fixtures use the live RAM backend before public mutation methods exist.
extern crate std;
use crate::authority::{Binding, Identity};
use crate::resolve::{Progress, Resolve};
use crate::storage::{Pin, ROOT, Root, SYMLINK, Token};
use crate::{DIR, Fds, REG, Ram};
use proto_process::{Credentials, ExpenditureRoot, Groups, LoaderOf, ResourceLimits, WhoReply};
use std::format;
const ROOT_ACCOUNT: Root = Root {
    id: 300,
    generation: 1,
};
const OWNER: Identity = Identity {
    uid: 11,
    gid: 22,
    groups: Groups::EMPTY,
};
const ADMIN: Identity = Identity {
    uid: 0,
    gid: 0,
    groups: Groups::EMPTY,
};
fn create(r: &mut Ram<'_>, parent: Token, name: &[u8], kind: u32, mode: u32) -> Token {
    let pending = r
        .storage
        .reserve(ROOT_ACCOUNT, parent, name, (kind, mode, 11, 22))
        .unwrap();
    r.storage.commit(pending).unwrap()
}
fn finish(r: &mut Ram<'_>, job: &mut Resolve, identity: Identity) -> Result<Token, u32> {
    for _ in 0..20000 {
        if let Progress::Found(token) = job.step(&mut r.storage, identity)? {
            return Ok(token);
        }
    }
    panic!("bounded fixture failed to terminate");
}
fn walk(r: &mut Ram<'_>, path: &[u8], identity: Identity) -> Result<Token, u32> {
    let mut job = Resolve::new(&mut r.storage, path, ROOT, identity, true)?;
    let result = finish(r, &mut job, identity);
    job.release(&mut r.storage);
    result
}
fn who() -> WhoReply {
    WhoReply {
        pid: 300,
        credentials: Credentials::NOBODY,
        generation: 1,
        loader: None,
        index: 44,
        ctty: None,
        image: 1,
        groups: Groups::EMPTY,
        limits: ResourceLimits::initial(2 * 1024 * 1024),
        root: ExpenditureRoot {
            pid: 300,
            generation: 1,
        },
    }
}
#[test]
fn refreshed_capture_preserves_authority_class_and_retained_descriptions() {
    let parent = who();
    let pending = WhoReply { loader: Some(LoaderOf { ticket: 7, image: parent.image }), ..parent };
    let mut ram = Ram::new(0);
    let mut fds = Fds::default();
    let fd = ram.open(&mut fds, "/tmp/probe", proto_fs::READ_WRITE).unwrap();
    ram.set_cwd_token(&mut fds, ROOT).unwrap();
    let description = ram.description_token(&fds, fd).unwrap();
    let usage = ram.storage.usage(ROOT_ACCOUNT);
    for original in [Binding::Inherited(parent), Binding::Active(parent), Binding::Pending(pending)] {
        fds.binding = original;
        let old = original.snapshot().unwrap();
        let fresh = WhoReply { generation: 2, ..old };
        fds.binding = original.refreshed(&fresh).unwrap();
        assert_eq!(fds.binding.snapshot(), Some(fresh));
        assert_eq!(core::mem::discriminant(&fds.binding), core::mem::discriminant(&original));
        if matches!(original, Binding::Inherited(_)) {
            assert_eq!(fds.binding.identity(false), Err(proto_fs::PERMISSION));
        }
        assert_eq!(ram.description_token(&fds, fd), Ok(description));
        assert_eq!(fds.cwd, Some(ROOT));
        assert_eq!(ram.storage.usage(ROOT_ACCOUNT), usage);
        for changed in [WhoReply { pid: fresh.pid + 1, ..fresh }, WhoReply { image: fresh.image + 1, ..fresh }, WhoReply { index: fresh.index + 1, ..fresh }, WhoReply { loader: None, ..pending }, WhoReply { generation: proto_process::GENERATION_DEAD, ..fresh }] {
            if changed == fresh { continue; }
            assert_eq!(Binding::Pending(pending).refreshed(&changed), Err(proto_fs::PERMISSION));
        }
    }
    ram.release(&mut fds);
}
#[test]
fn refresh_checks_every_capture_class_without_changing_the_old_snapshot() {
    let active = who();
    let pending = WhoReply {
        loader: Some(LoaderOf {
            ticket: 7,
            image: active.image,
        }),
        ..active
    };
    for original in [
        Binding::Active(active),
        Binding::Inherited(active),
        Binding::Pending(pending),
    ] {
        let old = original.snapshot().unwrap();
        let mut fresh = WhoReply {
            generation: old.generation + 1,
            ..old
        };
        fresh.credentials.euid = 123;
        let refreshed = original.refreshed(&fresh).unwrap();
        assert_eq!(refreshed.snapshot(), Some(fresh));
        assert_eq!(
            core::mem::discriminant(&refreshed),
            core::mem::discriminant(&original)
        );
        for invalid in [
            WhoReply {
                pid: old.pid + 1,
                ..fresh
            },
            WhoReply {
                index: old.index + 1,
                ..fresh
            },
            WhoReply {
                image: old.image + 1,
                ..fresh
            },
            WhoReply {
                root: ExpenditureRoot {
                    pid: old.root.pid + 1,
                    ..old.root
                },
                ..fresh
            },
            WhoReply {
                root: ExpenditureRoot {
                    generation: old.root.generation + 1,
                    ..old.root
                },
                ..fresh
            },
            WhoReply {
                generation: 0,
                ..fresh
            },
            WhoReply {
                generation: proto_process::GENERATION_DEAD | fresh.generation,
                ..fresh
            },
            WhoReply {
                loader: if old.loader.is_some() {
                    None
                } else {
                    pending.loader
                },
                ..fresh
            },
        ] {
            assert_eq!(original.refreshed(&invalid), Err(proto_fs::PERMISSION));
            assert_eq!(original.snapshot(), Some(old));
        }
        if let Some(loader) = old.loader {
            for changed in [
                LoaderOf {
                    ticket: loader.ticket + 1,
                    ..loader
                },
                LoaderOf {
                    image: loader.image + 1,
                    ..loader
                },
            ] {
                assert_eq!(
                    original.refreshed(&WhoReply {
                        loader: Some(changed),
                        ..fresh
                    }),
                    Err(proto_fs::PERMISSION)
                );
            }
        }
    }
    for original in [Binding::Unbound, Binding::Boot, Binding::Cleanup] {
        assert_eq!(original.refreshed(&active), Err(proto_fs::PERMISSION));
    }
}

#[test]
fn binding_retains_vouched_identity_image_and_root() {
    let mut binding = Binding::Unbound;
    assert_eq!(binding.bind(None, false), Err(proto_fs::PERMISSION));
    let mut w = who();
    binding.bind(Some(w), false).unwrap();
    assert!(binding.valid(1));
    assert!(!binding.valid(2));
    w.credentials.euid = 11;
    w.generation = 2;
    binding.bind(Some(w), false).unwrap();
    assert_eq!(binding.identity(false).unwrap().uid, 11);
    for changed in [
        WhoReply { pid: 301, ..w },
        WhoReply { image: 2, ..w },
        WhoReply { index: 45, ..w },
        WhoReply {
            root: ExpenditureRoot {
                pid: 301,
                generation: 1,
            },
            ..w
        },
    ] {
        assert_eq!(
            binding.bind(Some(changed), false),
            Err(proto_fs::PERMISSION)
        );
    }
    assert_eq!(binding.snapshot(), Some(w));
    binding = Binding::Cleanup;
    assert_eq!(binding.bind(Some(w), false), Err(proto_fs::PERMISSION));
    assert!(binding.identity(false).is_err());
    let pending = WhoReply {
        loader: Some(LoaderOf {
            ticket: 9,
            image: 2,
        }),
        image: 2,
        ..w
    };
    binding = Binding::Unbound;
    assert!(binding.bind(Some(pending), false).is_err());
    binding.bind(Some(pending), true).unwrap();
    assert!(
        binding
            .bind(
                Some(WhoReply {
                    loader: Some(LoaderOf {
                        ticket: 10,
                        image: 2
                    }),
                    ..pending
                }),
                true
            )
            .is_err()
    );
    binding
        .bind(
            Some(WhoReply {
                loader: None,
                ..pending
            }),
            false,
        )
        .unwrap();
    assert!(matches!(binding, Binding::Active(_)));
}
#[test]
fn inherited_clone_denies_effects_and_rebinds_only_with_same_expenditure_root() {
    let parent = who();
    let mut inherited = Binding::Inherited(parent);
    assert!(!inherited.valid(parent.generation));
    assert!(inherited.identity(false).is_err());
    let child = WhoReply {
        pid: 301,
        index: 45,
        image: 2,
        ..parent
    };
    assert!(
        inherited
            .bind(
                Some(WhoReply {
                    root: ExpenditureRoot {
                        pid: 301,
                        generation: 1
                    },
                    ..child
                }),
                false
            )
            .is_err()
    );
    inherited.bind(Some(child), false).unwrap();
    assert!(inherited.valid(child.generation));
    assert_eq!(inherited.snapshot(), Some(child));
}

#[test]
fn owner_group_other_use_one_class_and_real_effective_supplementary_ids() {
    let mut r = Ram::new(0);
    let token = create(&mut r, ROOT, b"file", REG, 0o640);
    let n = r.storage.node(token).unwrap();
    assert!(OWNER.permits(n, 6));
    assert!(
        Identity {
            uid: 33,
            gid: 22,
            ..OWNER
        }
        .permits(n, 4)
    );
    assert!(
        !Identity {
            uid: 33,
            gid: 44,
            ..OWNER
        }
        .permits(n, 4)
    );
    let mut groups = Groups::EMPTY;
    groups.count = 16;
    groups.ids = [22; 16];
    assert!(
        Identity {
            uid: 33,
            gid: 44,
            groups
        }
        .permits(n, 4)
    );
    let ids = Credentials {
        uid: 33,
        gid: 44,
        euid: 11,
        egid: 22,
        suid: 55,
        sgid: 66,
    };
    assert!(!Identity::of(ids, Groups::EMPTY, true).permits(n, 4));
    assert!(Identity::of(ids, Groups::EMPTY, false).permits(n, 6));
    r.storage.node_mut(token).unwrap().mode = 0o047;
    assert!(
        !OWNER.permits(r.storage.node(token).unwrap(), 4),
        "owner cannot borrow other bits"
    );
    assert!(ADMIN.permits(r.storage.node(token).unwrap(), 6));
    r.storage.node_mut(token).unwrap().mode = 0o600;
    assert!(!ADMIN.permits(r.storage.node(token).unwrap(), 1));
    r.storage.node_mut(token).unwrap().mode |= 1;
    assert!(ADMIN.permits(r.storage.node(token).unwrap(), 1));
    let directory = create(&mut r, ROOT, b"dir", DIR, 0);
    assert!(ADMIN.permits(r.storage.node(directory).unwrap(), 1));
}
#[test]
fn traversal_checks_denied_directory_before_parent_component() {
    let mut r = Ram::new(0);
    let denied = create(&mut r, ROOT, b"denied", DIR, 0o700);
    let allowed = create(&mut r, ROOT, b"allowed", REG, 0o644);
    let other = Identity {
        uid: 33,
        gid: 44,
        ..OWNER
    };
    assert_eq!(
        walk(&mut r, b"/denied/../allowed", other),
        Err(proto_fs::ACCESS_DENIED)
    );
    assert_eq!(walk(&mut r, b"/denied/../allowed", OWNER), Ok(allowed));
    assert_eq!(
        walk(&mut r, b"/allowed/..", OWNER),
        Err(proto_fs::NOT_DIRECTORY)
    );
    assert_eq!(walk(&mut r, b"/../../allowed", OWNER), Ok(allowed));
    assert_eq!(walk(&mut r, b"/denied/.", OWNER), Ok(denied));
}
#[test]
fn link_parent_walks_target_directory_and_preserves_invalid_utf8() {
    let mut r = Ram::new(0);
    let a = create(&mut r, ROOT, b"a", DIR, 0o755);
    let child = create(&mut r, a, b"child", DIR, 0o755);
    let target = create(&mut r, a, b"\xff", REG, 0o644);
    let link = create(&mut r, ROOT, b"link", SYMLINK, 0o777);
    r.storage.write(link, ROOT_ACCOUNT, 0, b"a/child").unwrap();
    assert_eq!(walk(&mut r, b"/link/../\xff", OWNER), Ok(target));
    let mut nofollow = Resolve::new(&mut r.storage, b"/link", ROOT, OWNER, false).unwrap();
    assert_eq!(finish(&mut r, &mut nofollow, OWNER), Ok(link));
    nofollow.release(&mut r.storage);
    assert_eq!(walk(&mut r, b"/link/", OWNER), Ok(child));
    let absolute = create(&mut r, a, b"absolute", SYMLINK, 0o777);
    r.storage
        .write(absolute, ROOT_ACCOUNT, 0, b"/a/\xff")
        .unwrap();
    assert_eq!(walk(&mut r, b"/a/absolute", OWNER), Ok(target));
}
#[test]
fn link_limit_is_32_and_path_and_component_bounds_are_bytes() {
    let mut r = Ram::new(0);
    let target = create(&mut r, ROOT, &[b'x'; 255], REG, 0o644);
    let mut path = std::vec![b'/'];
    path.extend_from_slice(&[b'x'; 255]);
    assert_eq!(walk(&mut r, &path, OWNER), Ok(target));
    path.push(b'x');
    assert_eq!(walk(&mut r, &path, OWNER), Err(proto_fs::NAME_TOO_LONG));
    let long = [b'/'; 511];
    assert_eq!(walk(&mut r, &long, OWNER), Ok(ROOT));
    assert_eq!(
        Resolve::new(&mut r.storage, &[b'/'; 512], ROOT, OWNER, true).err(),
        Some(proto_fs::NAME_TOO_LONG)
    );
    for i in (0..33).rev() {
        let link = create(&mut r, ROOT, format!("s{i}").as_bytes(), SYMLINK, 0o777);
        let next = if i == 32 {
            b"/".to_vec()
        } else {
            format!("s{}", i + 1).into_bytes()
        };
        r.storage.write(link, ROOT_ACCOUNT, 0, &next).unwrap();
    }
    assert_eq!(walk(&mut r, b"/s1", OWNER), Ok(ROOT));
    assert_eq!(walk(&mut r, b"/s0", OWNER), Err(proto_fs::LOOP));
}
#[test]
fn proof_restarts_after_namespace_and_authority_changes_and_retains_base() {
    let mut r = Ram::new(0);
    let directory = create(&mut r, ROOT, b"base", DIR, 0o700);
    let file = create(&mut r, directory, b"file", REG, 0o644);
    let mut job = Resolve::new(&mut r.storage, b"file", directory, OWNER, true).unwrap();
    assert_eq!(finish(&mut r, &mut job, OWNER), Ok(file));
    assert_eq!(job.proof(&r.storage, OWNER), Ok(file));
    let other = Identity {
        uid: 33,
        gid: 44,
        ..OWNER
    };
    assert_eq!(job.proof(&r.storage, other), Err(proto_fs::STALE_PROOF));
    assert_eq!(job.step(&mut r.storage, other), Ok(Progress::More));
    assert_eq!(
        finish(&mut r, &mut job, other),
        Err(proto_fs::ACCESS_DENIED)
    );
    assert_eq!(finish(&mut r, &mut job, OWNER), Ok(file));
    r.storage.set_attributes(directory, 0o600, 11, 22).unwrap();
    assert_eq!(job.proof(&r.storage, OWNER), Err(proto_fs::STALE_PROOF));
    assert_eq!(
        finish(&mut r, &mut job, OWNER),
        Err(proto_fs::ACCESS_DENIED)
    );
    r.storage.set_attributes(directory, 0o700, 11, 22).unwrap();
    assert_eq!(finish(&mut r, &mut job, OWNER), Ok(file));
    create(&mut r, ROOT, b"change", REG, 0o644);
    assert_eq!(job.proof(&r.storage, OWNER), Err(proto_fs::STALE_PROOF));
    assert_eq!(finish(&mut r, &mut job, OWNER), Ok(file));
    let mut fds = Fds::default();
    r.set_cwd_token(&mut fds, ROOT).unwrap();
    assert_eq!(
        job.base, directory,
        "another cwd cannot change captured base"
    );
    job.release(&mut r.storage);
    r.release(&mut fds);
    let bad = Token {
        slot: directory.slot,
        generation: directory.generation + 1,
    };
    assert!(Resolve::new(&mut r.storage, b"file", bad, OWNER, true).is_err());
    let mut absolute = Resolve::new(&mut r.storage, b"/base/file", bad, OWNER, true).unwrap();
    assert_eq!(finish(&mut r, &mut absolute, OWNER), Ok(file));
    absolute.release(&mut r.storage);
    r.storage.pin(directory, Pin::Cwd).unwrap();
    r.storage.unpin(directory, Pin::Cwd).unwrap();
}
#[test]
fn two_path_preparation_uses_one_charge_and_two_independent_pinned_bases() {
    let mut r = Ram::new(0);
    let a = create(&mut r, ROOT, b"a", DIR, 0o755);
    let b = create(&mut r, ROOT, b"b", DIR, 0o755);
    let x = create(&mut r, a, b"x", REG, 0o644);
    let y = create(&mut r, b, b"y", REG, 0o644);
    let before = r.storage.usage(ROOT_ACCOUNT);
    let charge = r.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
    let mut first = Resolve::new(&mut r.storage, b"x", a, OWNER, true).unwrap();
    let mut second = Resolve::new(&mut r.storage, b"y", b, OWNER, true).unwrap();
    assert_eq!(r.storage.preparations_used(), 1);
    assert_eq!(finish(&mut r, &mut first, OWNER), Ok(x));
    assert_eq!(finish(&mut r, &mut second, OWNER), Ok(y));
    assert_eq!(first.proof(&r.storage, OWNER), Ok(x));
    assert_eq!(second.proof(&r.storage, OWNER), Ok(y));
    first.release(&mut r.storage);
    second.release(&mut r.storage);
    r.storage.release_preparation(charge);
    assert_eq!(r.storage.preparations_used(), 0);
    assert_eq!(r.storage.usage(ROOT_ACCOUNT), before);
}

#[test]
fn lost_binding_preparation_returns_its_charge_without_dropping_creator_files() {
    let mut r = Ram::new(0);
    let file = create(&mut r, ROOT, b"captured", REG, 0o600);
    let mut creator = crate::Fds {
        root: ROOT_ACCOUNT,
        ..crate::Fds::default()
    };
    let fd = r
        .open_token(&mut creator, file, proto_fs::READ_ONLY, OWNER)
        .unwrap();
    let mut prepared = crate::Fds {
        root: ROOT_ACCOUNT,
        ..crate::Fds::default()
    };
    prepared.binding_preparation = Some(r.storage.charge_preparation(ROOT_ACCOUNT).unwrap());
    prepared.binding_source = Some((7, 19));
    assert_eq!(r.storage.preparations_used(), 1);
    assert!(r.release_step(&mut prepared));
    assert_eq!(r.storage.preparations_used(), 0);
    assert_eq!(prepared.binding_source, None);
    assert!(r.description_token(&creator, fd).is_ok());
    assert_eq!(r.open_descriptions(), 1);
    prepared.binding_preparation = Some(r.storage.charge_preparation(ROOT_ACCOUNT).unwrap());
    r.release(&mut prepared);
    assert_eq!(r.storage.preparations_used(), 0);
    assert_eq!(r.open_descriptions(), 1);
    r.release(&mut creator);
    assert_eq!(r.open_descriptions(), 0);
}

#[test]
fn preparation_root_transfer_preserves_global_charge_at_the_full_limit() {
    let mut r = Ram::new(0);
    let boot = crate::storage::BOOT_ROOT;
    let other = Root {
        id: 17,
        generation: 3,
    };
    let mut first = [0; 96];
    let mut second = [0; 32];
    for ticket in &mut first {
        *ticket = r.storage.charge_preparation(boot).unwrap();
    }
    for ticket in &mut second {
        *ticket = r.storage.charge_preparation(other).unwrap();
    }
    assert_eq!(r.storage.preparations_used(), 128);
    first[0] = r.storage.reassign_preparation(first[0], other).unwrap();
    assert_eq!(r.storage.preparations_used(), 128);
    assert_eq!(
        r.storage.charge_preparation(ROOT_ACCOUNT),
        Err(proto_fs::TOO_MANY_OPEN_FILES)
    );
    for ticket in first.into_iter().chain(second) {
        r.storage.release_preparation(ticket);
    }
    assert_eq!(r.storage.preparations_used(), 0);
    // Both zero-usage accounts become reusable, including retained generation.
    let renewed = Root {
        id: other.id,
        generation: other.generation + 1,
    };
    let ticket = r.storage.charge_preparation(renewed).unwrap();
    r.storage.release_preparation(ticket);
    assert_eq!(r.storage.preparations_used(), 0);
}

#[test]
fn preparation_root_transfer_refuses_a_full_share_without_losing_the_old_charge() {
    let mut r = Ram::new(0);
    let mut full = [0; 96];
    for ticket in &mut full {
        *ticket = r.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
    }
    let old = r
        .storage
        .charge_preparation(crate::storage::BOOT_ROOT)
        .unwrap();
    assert_eq!(
        r.storage.reassign_preparation(old, ROOT_ACCOUNT),
        Err(proto_fs::TOO_MANY_OPEN_FILES)
    );
    assert_eq!(r.storage.preparations_used(), 97);
    r.storage.release_preparation(old);
    for ticket in full {
        r.storage.release_preparation(ticket);
    }
    assert_eq!(r.storage.preparations_used(), 0);
}

#[test]
fn new_authentic_generation_invalidates_a_proof_with_unchanged_ids() {
    let mut binding = Binding::Unbound;
    let mut w = who();
    binding.bind(Some(w), false).unwrap();
    let stamp = binding.stamp();
    let identity = binding.identity(false).unwrap();
    let mut r = Ram::new(0);
    let file = create(&mut r, ROOT, b"same-ids", REG, 0o600);
    let mut proof = Resolve::new(&mut r.storage, b"/same-ids", ROOT, OWNER, true).unwrap();
    assert_eq!(finish(&mut r, &mut proof, OWNER), Ok(file));
    w.generation += 1;
    binding.bind(Some(w), false).unwrap();
    assert_eq!(binding.identity(false).unwrap(), identity);
    assert_ne!(binding.stamp(), stamp);
    proof.invalidate();
    assert_eq!(proof.proof(&r.storage, OWNER), Err(proto_fs::STALE_PROOF));
    assert_eq!(finish(&mut r, &mut proof, OWNER), Ok(file));
    proof.release(&mut r.storage);
}
