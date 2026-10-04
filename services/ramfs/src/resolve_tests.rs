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

fn intent_ready(
    r: &mut Ram<'_>,
    resolver: &mut Resolve,
    identity: Identity,
) -> Result<(Progress, usize), u32> {
    for step in 1..2000 {
        let progress = resolver.step(&mut r.storage, identity)?;
        if progress != Progress::More {
            return Ok((progress, step));
        }
    }
    panic!("bounded intent fixture failed to terminate");
}

#[test]
fn create_intent_retains_missing_edge_and_restarts_before_publication() {
    use crate::resolve::Intent;
    let mut r = Ram::new(0);
    let parent = create(&mut r, ROOT, b"parent", DIR, 0o755);
    let intent = Intent::Open {
        flags: proto_fs::CREATE | proto_fs::READ_WRITE,
    };
    let before = r.storage.node(parent).unwrap().pins;
    let mut resolver =
        Resolve::with_intent(&mut r.storage, b"/parent/\xff", ROOT, OWNER, intent).unwrap();
    let (progress, steps) = intent_ready(&mut r, &mut resolver, OWNER).unwrap();
    assert_eq!(progress, Progress::Missing(parent));
    assert!(steps >= crate::storage::DENTRIES / 8);
    let proof = resolver.result_proof(&r.storage, OWNER, intent).unwrap();
    assert_eq!(proof.parent, parent);
    assert_eq!(proof.leaf, b"\xff");
    assert_eq!(proof.target, None);
    assert_eq!(resolver.proof(&r.storage, OWNER), Err(proto_fs::PERMISSION));
    assert!(!proof.trailing_slash);
    assert!(
        resolver
            .result_proof(&r.storage, OWNER, Intent::DirectoryCreate)
            .is_err()
    );
    assert_eq!(
        r.storage.node(parent).unwrap().pins[Pin::Pending as usize],
        before[Pin::Pending as usize] + 1
    );
    let new = create(&mut r, parent, b"\xff", REG, 0o600);
    assert!(resolver.result_proof(&r.storage, OWNER, intent).is_err());
    assert_eq!(resolver.step(&mut r.storage, OWNER), Ok(Progress::More));
    assert_eq!(
        intent_ready(&mut r, &mut resolver, OWNER).unwrap().0,
        Progress::Found(new)
    );
    let proof = resolver.result_proof(&r.storage, OWNER, intent).unwrap();
    assert_eq!(
        (proof.parent, proof.leaf, proof.target),
        (parent, b"\xff".as_slice(), Some(new))
    );
    resolver.release(&mut r.storage);
    assert_eq!(r.storage.node(parent).unwrap().pins, before);
    assert_eq!(r.storage.node(new).unwrap().pins, [0; 5]);
}

#[test]
fn create_intent_requires_search_and_absence_only_at_final_component() {
    use crate::resolve::Intent;
    let mut r = Ram::new(0);
    create(&mut r, ROOT, b"denied", DIR, 0);
    let intent = Intent::Open {
        flags: proto_fs::CREATE,
    };
    for (path, error) in [
        (b"/absent/child".as_slice(), proto_fs::NO_ENTRY),
        (b"/absent/", proto_fs::NO_ENTRY),
        (b"/denied/.", proto_fs::ACCESS_DENIED),
        (b"/denied/../new", proto_fs::ACCESS_DENIED),
    ] {
        let mut resolver = Resolve::with_intent(&mut r.storage, path, ROOT, OWNER, intent).unwrap();
        assert_eq!(intent_ready(&mut r, &mut resolver, OWNER), Err(error));
        resolver.release(&mut r.storage);
    }
    let mut directory = Resolve::with_intent(
        &mut r.storage,
        b"/new/",
        ROOT,
        OWNER,
        Intent::DirectoryCreate,
    )
    .unwrap();
    assert_eq!(
        intent_ready(&mut r, &mut directory, OWNER).unwrap().0,
        Progress::Missing(ROOT)
    );
    assert!(
        directory
            .result_proof(&r.storage, OWNER, Intent::DirectoryCreate)
            .unwrap()
            .trailing_slash
    );
    directory.release(&mut r.storage);
    assert_eq!(r.storage.node(ROOT).unwrap().pins, [0; 5]);
}

#[test]
fn exclusive_intent_captures_dangling_symlink_and_existing_naming_edge() {
    use crate::resolve::Intent;
    let mut r = Ram::new(0);
    let link = create(&mut r, ROOT, b"dangling", SYMLINK, 0o777);
    r.storage.write(link, ROOT_ACCOUNT, 0, b"/missing").unwrap();
    let exclusive = Intent::Open {
        flags: proto_fs::CREATE | proto_fs::EXCLUSIVE,
    };
    for path in [b"/dangling".as_slice(), b"/dangling/"] {
        let mut resolver =
            Resolve::with_intent(&mut r.storage, path, ROOT, OWNER, exclusive).unwrap();
        assert_eq!(
            intent_ready(&mut r, &mut resolver, OWNER).unwrap().0,
            Progress::Found(link)
        );
        let proof = resolver.result_proof(&r.storage, OWNER, exclusive).unwrap();
        assert_eq!(
            (proof.parent, proof.leaf, proof.target),
            (ROOT, b"dangling".as_slice(), Some(link))
        );
        resolver.release(&mut r.storage);
    }
    let normal = Intent::Open {
        flags: proto_fs::CREATE,
    };
    let mut resolver =
        Resolve::with_intent(&mut r.storage, b"/dangling", ROOT, OWNER, normal).unwrap();
    assert_eq!(
        intent_ready(&mut r, &mut resolver, OWNER).unwrap().0,
        Progress::Missing(ROOT)
    );
    assert_eq!(
        resolver
            .result_proof(&r.storage, OWNER, normal)
            .unwrap()
            .leaf,
        b"missing"
    );
    resolver.release(&mut r.storage);
    assert_eq!(r.storage.node(link).unwrap().pins, [0; 5]);
    assert_eq!(r.storage.node(ROOT).unwrap().pins, [0; 5]);
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
fn retained_handoff_preserves_real_capture_until_genuine_startup_bind() {
    use crate::authority::{Admission, BindingPurpose};
    use proto_process::{RetainedLoaderReply, RetainedLoaderState};
    let old = WhoReply {
        loader: Some(LoaderOf {
            image: 1,
            ticket: 7,
        }),
        ..who()
    };
    let handoff = RetainedLoaderReply {
        state: RetainedLoaderState::Handoff,
        who: WhoReply {
            generation: 2,
            ..old
        },
    };
    let mut wire = proto_wire::Writer::new();
    handoff.write(&mut wire).unwrap();
    assert_eq!(wire.as_bytes().len(), 260);
    assert!(WhoReply::read(wire.as_bytes()).is_err());
    let mut admission = Admission::RetainedWire(wire.as_bytes().try_into().unwrap());
    let mut ram = Ram::new(0);
    let mut fds = Fds {
        binding: Binding::Pending(old),
        root: ROOT_ACCOUNT,
        ..Fds::default()
    };
    let file = create(&mut ram, ROOT, b"handoff", REG, 0o600);
    let fd = ram
        .open_token(&mut fds, file, proto_fs::READ_ONLY, OWNER)
        .unwrap();
    ram.set_cwd_token(&mut fds, ROOT).unwrap();
    let capture = ram.description_token(&fds, fd).unwrap();
    ram.begin_binding(&mut fds).unwrap();
    admission.decode().unwrap();
    admission.validate_retained(fds.binding, 2).unwrap();
    assert!(matches!(admission, Admission::RetainedValidated(_)));
    assert_eq!(fds.binding, Binding::Pending(old));
    fds.binding = fds.binding.retained_refresh(&handoff).unwrap();
    ram.complete_binding(&mut fds, 0);
    assert!(!fds.binding.valid(2));
    assert_eq!(fds.binding.identity(false), Err(proto_fs::PERMISSION));
    assert_eq!(fds.binding.identity(true), Err(proto_fs::PERMISSION));
    assert_eq!(ram.description_token(&fds, fd), Ok(capture));
    assert_eq!(fds.cwd, Some(ROOT));
    assert_eq!(
        fds.binding.bind(Some(handoff.who), true),
        Err(proto_fs::PERMISSION)
    );
    let real = WhoReply {
        loader: None,
        generation: 3,
        ..old
    };
    let mut candidate = Admission::Vouched(real);
    ram.begin_binding(&mut fds).unwrap();
    candidate
        .validate(fds.binding, BindingPurpose::Candidate, false, 3)
        .unwrap();
    assert!(matches!(fds.binding, Binding::Handoff(_)));
    fds.binding.bind(Some(real), false).unwrap();
    ram.complete_binding(&mut fds, 0);
    assert!(fds.binding.valid(3));
    assert_eq!(fds.binding.snapshot(), Some(real));
    assert_eq!(ram.description_token(&fds, fd), Ok(capture));
    assert_eq!(fds.cwd, Some(ROOT));
    assert_eq!(ram.storage.preparations_used(), 0);
}
#[test]
fn refreshed_capture_preserves_authority_class_and_retained_descriptions() {
    let parent = who();
    let pending = WhoReply {
        loader: Some(LoaderOf {
            ticket: 7,
            image: parent.image,
        }),
        ..parent
    };
    let mut ram = Ram::new(0);
    let mut fds = Fds::default();
    let fd = ram
        .open(&mut fds, "/tmp/probe", proto_fs::READ_WRITE)
        .unwrap();
    ram.set_cwd_token(&mut fds, ROOT).unwrap();
    let description = ram.description_token(&fds, fd).unwrap();
    let usage = ram.storage.usage(ROOT_ACCOUNT);
    for original in [
        Binding::Inherited(parent),
        Binding::Active(parent),
        Binding::Pending(pending),
    ] {
        fds.binding = original;
        let old = original.snapshot().unwrap();
        let fresh = WhoReply {
            generation: 2,
            ..old
        };
        fds.binding = original.refreshed(&fresh).unwrap();
        assert_eq!(fds.binding.snapshot(), Some(fresh));
        assert_eq!(
            core::mem::discriminant(&fds.binding),
            core::mem::discriminant(&original)
        );
        if matches!(original, Binding::Inherited(_)) {
            assert_eq!(fds.binding.identity(false), Err(proto_fs::PERMISSION));
        }
        assert_eq!(ram.description_token(&fds, fd), Ok(description));
        assert_eq!(fds.cwd, Some(ROOT));
        assert_eq!(ram.storage.usage(ROOT_ACCOUNT), usage);
        for changed in [
            WhoReply {
                pid: fresh.pid + 1,
                ..fresh
            },
            WhoReply {
                image: fresh.image + 1,
                ..fresh
            },
            WhoReply {
                index: fresh.index + 1,
                ..fresh
            },
            WhoReply {
                loader: None,
                ..pending
            },
            WhoReply {
                generation: proto_process::GENERATION_DEAD,
                ..fresh
            },
        ] {
            if changed == fresh {
                continue;
            }
            assert_eq!(
                Binding::Pending(pending).refreshed(&changed),
                Err(proto_fs::PERMISSION)
            );
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

#[test]
fn paid_admission_phases_preserve_capture_and_cleanup_the_real_session() {
    use crate::authority::{Admission, BindingPurpose};
    let old = who();
    let fresh = WhoReply {
        generation: old.generation + 1,
        ..old
    };
    let mut wire = proto_wire::Writer::new();
    fresh.write(&mut wire).unwrap();
    let mut admission = Admission::Wire(wire.as_bytes().try_into().unwrap());
    let mut ram = Ram::new(0);
    let mut fds = Fds {
        binding: Binding::Inherited(old),
        root: ROOT_ACCOUNT,
        ..Fds::default()
    };
    let file = create(&mut ram, ROOT, b"phase", REG, 0o600);
    let fd = ram
        .open_token(&mut fds, file, proto_fs::READ_ONLY, OWNER)
        .unwrap();
    ram.set_cwd_token(&mut fds, ROOT).unwrap();
    let retained = ram.description_token(&fds, fd).unwrap();
    ram.begin_binding(&mut fds).unwrap();
    assert_eq!(ram.storage.preparations_used(), 1);
    admission.decode().unwrap();
    assert!(matches!(admission, Admission::Vouched(_)));
    assert_eq!(fds.binding, Binding::Inherited(old));
    admission
        .validate(
            fds.binding,
            BindingPurpose::Refresh,
            false,
            fresh.generation,
        )
        .unwrap();
    let Admission::Validated(checked) = admission else {
        panic!("separate validation phase")
    };
    assert_eq!(fds.binding, Binding::Inherited(old));
    fds.binding = fds.binding.refreshed(&checked).unwrap();
    ram.complete_binding(&mut fds, 0);
    assert_eq!(fds.binding, Binding::Inherited(fresh));
    assert_eq!(fds.binding_outcome, Some(0));
    assert_eq!(ram.storage.preparations_used(), 0);
    assert_eq!(ram.description_token(&fds, fd), Ok(retained));
    assert_eq!(fds.cwd, Some(ROOT));
    // A lost Finish reply sees the same finite journal, without another effect.
    assert_eq!(fds.binding_outcome, Some(0));
    ram.begin_binding(&mut fds).unwrap();
    assert_eq!(fds.binding_outcome, None);
    admission = Admission::Vouched(fresh);
    assert_eq!(
        admission.validate(
            fds.binding,
            BindingPurpose::Refresh,
            false,
            proto_process::GENERATION_DEAD | fresh.generation
        ),
        Err(proto_fs::PERMISSION)
    );
    ram.complete_binding(&mut fds, proto_fs::PERMISSION);
    assert_eq!(fds.binding_outcome, Some(proto_fs::PERMISSION));
    assert_eq!(ram.storage.preparations_used(), 0);
    fds.binding = Binding::Cleanup;
    assert!(ram.release_step(&mut fds));
    assert_eq!(fds.cwd, None);
    assert_eq!(ram.description_token(&fds, fd), Ok(retained));
    assert!(ram.release_step(&mut fds));
    assert_eq!(ram.description_token(&fds, fd), Err(proto_fs::BAD_FD));
    assert!(!ram.release_step(&mut fds));
    assert_eq!(ram.open_descriptions(), 0);
}

#[test]
fn binding_and_resolver_preparations_share_the_sixteen_session_slots() {
    let mut ram = Ram::new(0);
    let mut fds = Fds {
        root: ROOT_ACCOUNT,
        ..Fds::default()
    };
    let mut charges = [0; 16];
    for (i, charge) in charges.iter_mut().enumerate() {
        *charge = ram.storage.charge_preparation(fds.root).unwrap();
        fds.resolvers[i] = (i + 1) as u64;
    }
    assert_eq!(
        ram.begin_binding(&mut fds),
        Err(proto_fs::TOO_MANY_OPEN_FILES)
    );
    assert_eq!(ram.storage.preparations_used(), 16);
    ram.storage.release_preparation(charges[15]);
    fds.resolvers[15] = 0;
    ram.begin_binding(&mut fds).unwrap();
    assert_eq!(ram.storage.preparations_used(), 16);
    assert_eq!(
        ram.begin_binding(&mut fds),
        Err(proto_fs::TOO_MANY_OPEN_FILES)
    );
    ram.complete_binding(&mut fds, proto_fs::PERMISSION);
    assert_eq!(ram.storage.preparations_used(), 15);
    assert_eq!(fds.binding_outcome, Some(proto_fs::PERMISSION));
    for charge in &charges[..15] {
        ram.storage.release_preparation(*charge);
    }
    assert_eq!(ram.storage.preparations_used(), 0);
}

#[test]
fn cleanup_audit_preserves_real_capture_and_proofs_at_every_preparation_limit() {
    use crate::authority::{Admission, AuditStep, BindingPurpose, CleanupAudit};
    for limit in [16, 96, 128] {
        let mut ram = Ram::new(0);
        let old = who();
        let fresh = WhoReply {
            generation: old.generation + 1,
            credentials: Credentials {
                euid: 65533,
                ..old.credentials
            },
            ..old
        };
        let mut fds = Fds {
            binding: Binding::Active(old),
            root: ROOT_ACCOUNT,
            ..Fds::default()
        };
        let file = create(&mut ram, ROOT, b"audit-live", REG, 0o600);
        let fd = ram
            .open_token(&mut fds, file, proto_fs::READ_ONLY, OWNER)
            .unwrap();
        ram.set_cwd_token(&mut fds, ROOT).unwrap();
        let retained = ram.description_token(&fds, fd).unwrap();
        let stamp = fds.binding.stamp();
        let mut jobs = std::vec::Vec::new();
        let mut charges = std::vec::Vec::new();
        for i in 0..limit {
            let root = if i < 96 {
                ROOT_ACCOUNT
            } else {
                Root {
                    id: 301,
                    generation: 1,
                }
            };
            charges.push(ram.storage.charge_preparation(root).unwrap());
            if limit == 16 {
                let mut job =
                    Resolve::new(&mut ram.storage, b"/audit-live", ROOT, OWNER, true).unwrap();
                assert_eq!(finish(&mut ram, &mut job, OWNER), Ok(file));
                jobs.push(job);
                fds.resolvers[i] = 256 + i as u64;
            }
        }
        assert_eq!(
            ram.begin_binding(&mut fds),
            Err(proto_fs::TOO_MANY_OPEN_FILES)
        );
        let mut audit = CleanupAudit::default();
        let mut admission = Admission::Unvouched;
        audit.start(&mut admission, fresh.generation);
        let mut wire = proto_wire::Writer::new();
        fresh.write(&mut wire).unwrap();
        admission = Admission::Wire(wire.as_bytes().try_into().unwrap());
        assert_eq!(
            audit.step(fds.binding, &mut admission, fresh.generation),
            AuditStep::Advance
        );
        assert_eq!(
            audit.step(fds.binding, &mut admission, fresh.generation),
            AuditStep::Advance
        );
        assert_eq!(
            audit.step(fds.binding, &mut admission, fresh.generation),
            AuditStep::Alive
        );
        assert!(audit.cached(fresh.generation));
        assert!(!audit.cached(fresh.generation + 1));
        assert_eq!(fds.binding, Binding::Active(old));
        assert_eq!(fds.binding.stamp(), stamp);
        assert_eq!(ram.description_token(&fds, fd), Ok(retained));
        assert_eq!(fds.cwd, Some(ROOT));
        assert_eq!(ram.storage.preparations_used() as usize, limit);
        assert_eq!(
            ram.begin_binding(&mut fds),
            Err(proto_fs::TOO_MANY_OPEN_FILES)
        );
        for job in &jobs {
            assert_eq!(job.proof(&ram.storage, OWNER), Ok(file));
        }
        // ResolveCancel frees one real job and its sole charge before normal Refresh.
        if let Some(job) = jobs.pop() {
            job.release(&mut ram.storage);
            fds.resolvers[15] = 0;
        }
        let removed = if limit == 16 {
            charges.pop().unwrap()
        } else {
            charges.remove(0)
        };
        ram.storage.release_preparation(removed);
        audit.reset();
        ram.begin_binding(&mut fds).unwrap();
        assert_eq!(ram.storage.preparations_used() as usize, limit);
        admission = Admission::Vouched(fresh);
        admission
            .validate(
                fds.binding,
                BindingPurpose::Refresh,
                false,
                fresh.generation,
            )
            .unwrap();
        fds.binding = fds.binding.refreshed(&fresh).unwrap();
        ram.complete_binding(&mut fds, 0);
        assert_ne!(fds.binding.stamp(), stamp);
        assert!(!audit.cached(fresh.generation));
        for mut job in jobs {
            job.invalidate();
            assert_eq!(job.proof(&ram.storage, OWNER), Err(proto_fs::STALE_PROOF));
            job.release(&mut ram.storage);
        }
        for charge in charges {
            ram.storage.release_preparation(charge);
        }
        fds.resolvers.fill(0);
        assert_eq!(ram.storage.preparations_used(), 0);
        fds.binding = Binding::Cleanup;
        assert!(ram.release_step(&mut fds));
        assert_eq!(fds.cwd, None);
        assert!(ram.release_step(&mut fds));
        assert_eq!(ram.open_descriptions(), 0);
        assert!(!ram.release_step(&mut fds));
    }
}

#[test]
fn cleanup_audit_retries_unconfirmed_responses_and_rechecks_every_epoch() {
    use crate::authority::{Admission, AuditStep, CleanupAudit, NotaryReply};
    let old = who();
    let fresh = WhoReply {
        generation: 2,
        ..old
    };
    let denied = proto_wire::reply(proto_wire::Status::Unknown(proto_process::PERMISSION));
    assert!(matches!(
        NotaryReply::<252>::read(&denied, true),
        NotaryReply::Denied
    ));
    assert!(matches!(
        NotaryReply::<252>::read(&denied, false),
        NotaryReply::Retry
    ));
    let mut malformed = denied;
    malformed[4] = 1;
    assert!(matches!(
        NotaryReply::<252>::read(&malformed, true),
        NotaryReply::Retry
    ));
    assert!(matches!(
        NotaryReply::<252>::read(&denied[..4], true),
        NotaryReply::Retry
    ));
    assert!(matches!(
        NotaryReply::<252>::read(&proto_wire::reply(proto_wire::Status::BadSize), true),
        NotaryReply::Retry
    ));
    assert!(matches!(
        NotaryReply::<252>::read(
            &proto_wire::reply(proto_wire::Status::Unknown(proto_fs::PERMISSION)),
            true
        ),
        NotaryReply::Retry
    ));
    let mut audit = CleanupAudit::default();
    let mut admission = Admission::Unvouched;
    audit.start(&mut admission, 2);
    admission = Admission::Wire([0; 252]);
    assert_eq!(
        audit.step(Binding::Active(old), &mut admission, 2),
        AuditStep::Retry
    );
    assert!(matches!(admission, Admission::Unvouched));
    assert!(!audit.cached(2));
    let mut wire = proto_wire::Writer::new();
    fresh.write(&mut wire).unwrap();
    let wire: [u8; 252] = wire.as_bytes().try_into().unwrap();
    for phase in 0..4 {
        audit.start(&mut admission, 2);
        admission = match phase {
            0 => Admission::Unvouched,
            1 => Admission::Wire(wire),
            2 => Admission::Vouched(fresh),
            _ => Admission::Validated(fresh),
        };
        assert_eq!(
            audit.step(
                Binding::Active(old),
                &mut admission,
                proto_process::GENERATION_DEAD | 2
            ),
            AuditStep::Denied
        );
        assert!(!audit.cached(2));
    }
    audit.start(&mut admission, 2);
    admission = Admission::Vouched(WhoReply {
        image: old.image + 1,
        ..fresh
    });
    assert_eq!(
        audit.step(Binding::Active(old), &mut admission, 2),
        AuditStep::Denied
    );
    audit.start(&mut admission, 2);
    admission = Admission::Vouched(fresh);
    assert_eq!(
        audit.step(Binding::Active(old), &mut admission, 2),
        AuditStep::Advance
    );
    assert_eq!(
        audit.step(Binding::Active(old), &mut admission, 3),
        AuditStep::Retry
    );
    assert!(matches!(admission, Admission::Unvouched));
    assert!(!audit.cached(2));
    admission = Admission::Vouched(WhoReply {
        generation: 3,
        ..fresh
    });
    assert_eq!(
        audit.step(Binding::Active(old), &mut admission, 3),
        AuditStep::Advance
    );
    assert_eq!(
        audit.step(Binding::Active(old), &mut admission, 3),
        AuditStep::Alive
    );
    assert!(audit.cached(3));
    assert_eq!(audit.synchronize(&mut admission, 4), AuditStep::Retry);
    assert!(!audit.cached(3));
    audit.reset();
    assert!(!audit.cached(4));
}

#[test]
fn retrying_binding_cursor_releases_dead_and_superseded_real_captures() {
    use crate::authority::{Admission, AuditStep, CleanupAudit, NotaryReply};
    let mut ram = Ram::new(0);
    let old = who();
    let file = create(&mut ram, ROOT, b"cursor", REG, 0o600);
    let mut sessions: [Fds; 4] = core::array::from_fn(|_| Fds {
        binding: Binding::Active(old),
        root: ROOT_ACCOUNT,
        ..Fds::default()
    });
    for session in &mut sessions[1..] {
        ram.open_token(session, file, proto_fs::READ_ONLY, OWNER)
            .unwrap();
        ram.set_cwd_token(session, ROOT).unwrap();
        ram.begin_binding(session).unwrap();
    }
    let mut cursor = crate::maintenance::Cursor {
        position: 1,
        remaining: 3,
    };
    let mut first = Admission::Unvouched;
    for _ in 0..32 {
        let index = cursor.position;
        let session = &mut sessions[index];
        let work = if index == 1 {
            // The exact production transport adapter preserves this real preparation.
            NotaryReply::<252>::Retry
                .admit(&mut first, Admission::Wire)
                .unwrap()
        } else if session.binding != Binding::Cleanup {
            let mut audit = CleanupAudit::default();
            let mut admission = Admission::Vouched(WhoReply {
                generation: 2,
                image: old.image + 1,
                ..old
            });
            audit.start(&mut admission, 2);
            admission = Admission::Vouched(WhoReply {
                generation: 2,
                image: old.image + 1,
                ..old
            });
            let generation = if index == 2 {
                proto_process::GENERATION_DEAD | 2
            } else {
                2
            };
            assert_eq!(
                audit.step(session.binding, &mut admission, generation),
                AuditStep::Denied
            );
            session.binding = Binding::Cleanup;
            true
        } else {
            ram.release_step(session)
        };
        cursor.complete(work, sessions.len());
    }
    assert!(sessions[1].binding_preparation.is_some());
    assert!(sessions[1].cwd.is_some());
    assert!(matches!(first, Admission::Unvouched));
    assert_eq!(ram.open_descriptions(), 1);
    assert_eq!(ram.storage.preparations_used(), 1);
    for session in &sessions[2..] {
        assert_eq!(session.binding, Binding::Cleanup);
        assert_eq!(session.binding_preparation, None);
        assert_eq!(session.cwd, None);
        assert_eq!(ram.description_token(session, 0), Err(proto_fs::BAD_FD));
    }
    ram.release(&mut sessions[1]);
    assert_eq!(ram.open_descriptions(), 0);
    assert_eq!(ram.storage.preparations_used(), 0);
}

#[test]
fn creation_binding_and_path_jobs_share_the_session_budget() {
    let mut ram = Ram::new(0);
    let mut fds = Fds {
        root: ROOT_ACCOUNT,
        ..Fds::default()
    };
    let mut charges = [0; 8];
    for (i, charge) in charges.iter_mut().enumerate() {
        *charge = ram.storage.charge_preparation(fds.root).unwrap();
        fds.resolvers[i] = i as u64 + 1;
    }
    let mut reservations = std::vec::Vec::new();
    for i in 0..7 {
        reservations.push(
            ram.reserve_create(&mut fds, ROOT, format!("held{i}").as_bytes(), REG)
                .unwrap(),
        );
    }
    ram.begin_binding(&mut fds).unwrap();
    assert_eq!(fds.preparation_count(), 16);
    assert!(!fds.preparation_available());
    assert!(matches!(
        ram.reserve_create(&mut fds, ROOT, b"overflow", REG),
        Err(proto_fs::TOO_MANY_OPEN_FILES)
    ));
    assert_eq!(ram.storage.preparations_used(), 16);
    ram.complete_binding(&mut fds, 0);
    ram.reserve_create(&mut fds, ROOT, b"replacement", REG)
        .unwrap();
    assert_eq!(
        ram.begin_binding(&mut fds),
        Err(proto_fs::TOO_MANY_OPEN_FILES)
    );
    for (i, charge) in charges.into_iter().enumerate() {
        ram.storage.release_preparation(charge);
        fds.resolvers[i] = 0;
    }
    while ram.release_step(&mut fds) {}
    assert_eq!(ram.storage.preparations_used(), 0);
    assert_eq!(fds.preparation_count(), 0);
    assert_eq!(ram.storage.node(ROOT).unwrap().pins.iter().sum::<u16>(), 0);
}

#[test]
fn paid_creation_transfers_at_full_global_and_root_budgets_once() {
    let mut ram = Ram::new(0);
    let other = Root {
        id: 301,
        generation: 1,
    };
    let mut charges = std::vec::Vec::new();
    for _ in 0..96 {
        charges.push(ram.storage.charge_preparation(ROOT_ACCOUNT).unwrap());
    }
    for _ in 0..32 {
        charges.push(ram.storage.charge_preparation(other).unwrap());
    }
    let mut paid = charges[0];
    let renewed = Root {
        generation: 2,
        ..ROOT_ACCOUNT
    };
    let usage = ram.storage.usage(ROOT_ACCOUNT);
    assert!(
        ram.storage
            .reserve_paid(
                ROOT_ACCOUNT,
                ROOT,
                b"bad/name",
                (REG, 0o600, 11, 22),
                &mut paid
            )
            .is_err()
    );
    assert_eq!(paid, charges[0]);
    assert_eq!(ram.storage.usage(ROOT_ACCOUNT), usage);
    assert_eq!(ram.storage.preparations_used(), 128);
    assert!(matches!(
        ram.storage
            .reserve_paid(renewed, ROOT, b"wrong", (REG, 0o600, 11, 22), &mut paid),
        Err(proto_fs::INVALID_ARGUMENT)
    ));
    assert_eq!(paid, charges[0]);
    let r = ram
        .storage
        .reserve_paid(
            ROOT_ACCOUNT,
            ROOT,
            b"transferred",
            (REG, 0o600, 11, 22),
            &mut paid,
        )
        .unwrap();
    assert_eq!(paid, crate::storage::NONE);
    assert_eq!(ram.storage.preparations_used(), 128);
    assert!(matches!(
        ram.storage.reserve_paid(
            ROOT_ACCOUNT,
            ROOT,
            b"duplicate",
            (REG, 0o600, 11, 22),
            &mut paid
        ),
        Err(proto_fs::INVALID_ARGUMENT)
    ));
    let token = ram.storage.commit_keep_charge(r).unwrap();
    assert_eq!(ram.storage.lookup(ROOT, b"transferred"), Ok(token));
    assert_eq!(ram.storage.preparations_used(), 128);
    assert!(ram.storage.commit_keep_charge(r).is_err());
    assert!(ram.storage.cancel(r).is_err());
    assert_eq!(ram.storage.preparations_used(), 128);
    ram.storage.release_preparation(r.charge());
    for charge in charges.into_iter().skip(1) {
        ram.storage.release_preparation(charge);
    }
    assert_eq!(ram.storage.preparations_used(), 0);
    // A retired reservation cannot cancel another generation at the reused place.
    let mut next = ram.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
    let replacement = ram
        .storage
        .reserve_paid(
            ROOT_ACCOUNT,
            ROOT,
            b"replacement",
            (REG, 0o600, 11, 22),
            &mut next,
        )
        .unwrap();
    assert!(ram.storage.cancel(r).is_err());
    assert_eq!(ram.storage.preparations_used(), 1);
    ram.storage.cancel(replacement).unwrap();
    assert!(ram.storage.cancel(replacement).is_err());
    assert_eq!(ram.storage.preparations_used(), 0);
    assert_eq!(ram.storage.node(ROOT).unwrap().pins.iter().sum::<u16>(), 0);
}

#[test]
fn no_follow_open_still_resolves_a_link_with_a_trailing_slash() {
    use crate::resolve::Intent;
    let mut ram = Ram::new(0);
    let target = create(&mut ram, ROOT, b"target-dir", DIR, 0o755);
    let link = create(&mut ram, ROOT, b"dir-link", SYMLINK, 0o777);
    ram.storage
        .write(link, ROOT_ACCOUNT, 0, b"/target-dir")
        .unwrap();
    for (path, expected) in [
        (b"/dir-link/".as_slice(), target),
        (b"/dir-link".as_slice(), link),
    ] {
        let intent = Intent::Open {
            flags: proto_fs::NO_FOLLOW,
        };
        let mut resolver =
            Resolve::with_intent(&mut ram.storage, path, ROOT, OWNER, intent).unwrap();
        assert_eq!(
            intent_ready(&mut ram, &mut resolver, OWNER).unwrap().0,
            Progress::Found(expected)
        );
        assert_eq!(
            resolver
                .result_proof(&ram.storage, OWNER, intent)
                .unwrap()
                .target,
            Some(expected)
        );
        resolver.release(&mut ram.storage);
    }
    assert_eq!(ram.storage.node(ROOT).unwrap().pins.iter().sum::<u16>(), 0);
    assert_eq!(
        ram.storage.node(target).unwrap().pins.iter().sum::<u16>(),
        0
    );
    assert_eq!(ram.storage.node(link).unwrap().pins.iter().sum::<u16>(), 0);
}

#[test]
fn tentative_open_prepays_resources_without_exposing_a_descriptor() {
    let mut ram = Ram::new(0);
    let mut fds = Fds {
        root: ROOT_ACCOUNT,
        ..Fds::default()
    };
    let token = create(&mut ram, ROOT, b"prepaid", REG, 0o600);
    let before = ram.storage.usage(ROOT_ACCOUNT);
    let held = ram
        .prepare_open_token(&mut fds, token, proto_fs::READ_WRITE, OWNER, false)
        .unwrap();
    assert_eq!(ram.open_descriptions(), 1);
    assert_eq!(
        ram.storage.usage(ROOT_ACCOUNT).descriptions,
        before.descriptions + 1
    );
    assert_eq!(fds.numbers().count(), 0);
    assert_eq!(ram.description_token(&fds, held.fd), Err(proto_fs::BAD_FD));
    assert!(matches!(
        ram.clone_fds(&fds, &[held.fd]),
        Err(proto_fs::BAD_FD)
    ));
    assert_eq!(
        ram.read(&mut fds, held.fd, &mut [0; 1]),
        Err(proto_fs::BAD_FD)
    );
    assert_eq!(ram.write(&mut fds, held.fd, b"x"), Err(proto_fs::BAD_FD));
    assert_eq!(ram.close(&mut fds, held.fd), Err(proto_fs::BAD_FD));
    ram.cancel_open(&mut fds, held).unwrap();
    assert_eq!(ram.cancel_open(&mut fds, held), Err(proto_fs::BAD_FD));
    assert_eq!(ram.storage.usage(ROOT_ACCOUNT), before);
    let replacement = ram
        .prepare_open_token(&mut fds, token, proto_fs::READ_WRITE, OWNER, false)
        .unwrap();
    assert_eq!(replacement.fd, held.fd);
    assert_ne!(
        replacement.description.generation,
        held.description.generation
    );
    assert_eq!(ram.cancel_open(&mut fds, held), Err(proto_fs::BAD_FD));
    assert_eq!(ram.publish_open(&mut fds, replacement), Ok(replacement.fd));
    assert_eq!(
        ram.publish_open(&mut fds, replacement),
        Err(proto_fs::BAD_FD)
    );
    assert_eq!(
        ram.description_token(&fds, replacement.fd),
        Ok(replacement.description)
    );
    assert_eq!(ram.write(&mut fds, replacement.fd, b"live"), Ok(4));
    ram.close(&mut fds, replacement.fd).unwrap();
    assert_eq!(ram.open_descriptions(), 0);
    assert_eq!(ram.storage.node(token).unwrap().pins.iter().sum::<u16>(), 0);
}

#[test]
fn created_mode_zero_can_be_prepaid_and_session_cleanup_closes_it_once() {
    let mut ram = Ram::new(0);
    let mut fds = Fds {
        root: ROOT_ACCOUNT,
        ..Fds::default()
    };
    let reservation = ram
        .storage
        .reserve(
            ROOT_ACCOUNT,
            ROOT,
            b"mode-zero",
            (REG, 0, OWNER.uid, OWNER.gid),
        )
        .unwrap();
    assert!(matches!(
        ram.prepare_open_token(
            &mut fds,
            reservation.token,
            proto_fs::READ_WRITE,
            OWNER,
            false
        ),
        Err(proto_fs::ACCESS_DENIED)
    ));
    let held = ram
        .prepare_open_token(
            &mut fds,
            reservation.token,
            proto_fs::READ_WRITE | proto_fs::CREATE,
            OWNER,
            true,
        )
        .unwrap();
    ram.storage.commit(reservation).unwrap();
    assert_eq!(ram.publish_open(&mut fds, held), Ok(held.fd));
    assert_eq!(ram.write(&mut fds, held.fd, b"created"), Ok(7));
    ram.close(&mut fds, held.fd).unwrap();
    let token = ram.storage.lookup(ROOT, b"mode-zero").unwrap();
    ram.storage
        .set_attributes(token, 0o600, OWNER.uid, OWNER.gid)
        .unwrap();
    ram.prepare_open_token(&mut fds, token, proto_fs::READ_WRITE, OWNER, false)
        .unwrap();
    assert!(ram.release_step(&mut fds));
    assert!(!ram.release_step(&mut fds));
    assert_eq!(ram.open_descriptions(), 0);
    assert_eq!(ram.storage.node(token).unwrap().pins.iter().sum::<u16>(), 0);
    assert_eq!(ram.storage.preparations_used(), 0);
}

#[test]
fn tentative_open_failure_and_full_cleanup_preserve_descriptor_accounting() {
    let mut ram = Ram::new(0);
    let mut fds = Fds {
        root: ROOT_ACCOUNT,
        ..Fds::default()
    };
    let token = create(&mut ram, ROOT, b"full-open", REG, 0o600);
    for _ in 0..32 {
        ram.prepare_open_token(&mut fds, token, proto_fs::READ_WRITE, OWNER, false)
            .unwrap();
    }
    let before = ram.storage.usage(ROOT_ACCOUNT);
    assert_eq!(fds.numbers().count(), 0);
    assert_eq!(ram.open_descriptions(), 32);
    assert!(matches!(
        ram.prepare_open_token(&mut fds, token, proto_fs::READ_WRITE, OWNER, false),
        Err(proto_fs::TOO_MANY_OPEN_FILES)
    ));
    assert_eq!(ram.storage.usage(ROOT_ACCOUNT), before);
    assert_eq!(ram.open_descriptions(), 32);
    for _ in 0..32 {
        assert!(ram.release_step(&mut fds));
    }
    assert!(!ram.release_step(&mut fds));
    assert_eq!(ram.open_descriptions(), 0);
    assert_eq!(ram.storage.usage(ROOT_ACCOUNT).descriptions, 0);
    assert_eq!(ram.storage.node(token).unwrap().pins.iter().sum::<u16>(), 0);
    assert!(matches!(
        ram.prepare_open_token(
            &mut fds,
            token,
            proto_fs::CREATE | proto_fs::EXCLUSIVE,
            OWNER,
            false
        ),
        Err(proto_fs::ALREADY_EXISTS)
    ));
    let motd = Token {
        slot: 3,
        generation: 1,
    };
    assert!(matches!(
        ram.prepare_open_token(&mut fds, motd, proto_fs::WRITE_ONLY, ADMIN, false),
        Err(proto_fs::READ_ONLY_FILESYSTEM)
    ));
    assert_eq!(ram.open_descriptions(), 0);
}
