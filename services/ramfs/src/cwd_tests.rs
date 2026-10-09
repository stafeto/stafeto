// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::{
    DIR, Fds, Ram,
    authority::Identity,
    cwd::*,
    resolve::{Progress, Resolve},
    storage::{ROOT, Root, Token},
};
use proto_fs::{ACCESS_DENIED, NOT_DIRECTORY, READ_ONLY, STALE_PROOF, Timestamp};
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
const OWNER: Identity = Identity {
    uid: 37,
    gid: 43,
    groups: Groups::EMPTY,
};
fn directory(ram: &mut Ram<'_>, name: &[u8], mode: u32) -> Token {
    let r = ram
        .storage
        .reserve(EXPENSE, ROOT, name, (DIR, mode, 37, 43))
        .unwrap();
    ram.storage.commit(r).unwrap()
}
fn resolver(ram: &mut Ram<'_>, path: &[u8], identity: Identity) -> Resolve {
    let mut r = Resolve::new(&mut ram.storage, path, ROOT, identity, true).unwrap();
    for _ in 0..10000 {
        if r.step(&mut ram.storage, identity).unwrap() != Progress::More {
            return r;
        }
    }
    panic!("resolver did not finish")
}
#[test]
fn authentic_path_change_is_cached_and_old_cwd_pin_is_replaced() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let a = directory(&mut ram, b"a", 0o755);
    let b = directory(&mut ram, b"b", 0o755);
    let mut fds = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    ram.set_cwd_token(&mut fds, a).unwrap();
    let r = resolver(&mut ram, b"/b", OWNER);
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let proof = r.cwd_proof(&ram.storage, OWNER).unwrap();
    let mut j = CwdJournal::path(&mut ram.storage, EXPENSE, charge, proof, OWNER).unwrap();
    let proof = r.cwd_proof(&ram.storage, OWNER).unwrap();
    assert_eq!(
        j.commit(&mut ram, &mut fds, OWNER, Some(proof)),
        Ok(CwdOutcome::Applied)
    );
    assert_eq!(fds.cwd, Some(b));
    let pins = ram.storage.node(b).unwrap().pins;
    assert_eq!(
        j.commit(&mut ram, &mut fds, ADMIN, None),
        Ok(CwdOutcome::Applied)
    );
    assert_eq!(ram.storage.node(b).unwrap().pins, pins);
    assert!(j.cancel_step(&mut ram).unwrap());
    r.release(&mut ram.storage);
    ram.storage.release_preparation(charge);
    ram.release(&mut fds);
    assert!(ram.storage.node(a).unwrap().pins.iter().all(|&v| v == 0));
    assert!(ram.storage.node(b).unwrap().pins.iter().all(|&v| v == 0));
}
#[test]
fn retained_fchdir_survives_close_reuse_and_checks_current_search() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let target = directory(&mut ram, b"directory", 0o755);
    let mut fds = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    let fd = ram.open(&mut fds, "/directory", READ_ONLY).unwrap();
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let mut j = ram.prepare_fchdir(&fds, fd, charge, OWNER).unwrap();
    ram.close(&mut fds, fd).unwrap();
    assert_eq!(ram.open(&mut fds, "/tmp/probe", READ_ONLY).unwrap(), fd);
    ram.storage.set_attributes(target, 0o600, 37, 43).unwrap();
    assert_eq!(
        j.commit(&mut ram, &mut fds, OWNER, None),
        Ok(CwdOutcome::Failed(ACCESS_DENIED))
    );
    assert_eq!(fds.cwd, None);
    assert!(j.cancel_step(&mut ram).unwrap());
    ram.storage.release_preparation(charge);
    ram.close(&mut fds, fd).unwrap();
    ram.storage.set_attributes(target, 0o755, 37, 43).unwrap();
    let fd = ram.open(&mut fds, "/directory", READ_ONLY).unwrap();
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let mut j = ram.prepare_fchdir(&fds, fd, charge, OWNER).unwrap();
    ram.close(&mut fds, fd).unwrap();
    assert_eq!(
        j.commit(&mut ram, &mut fds, OWNER, None),
        Ok(CwdOutcome::Applied)
    );
    assert_eq!(fds.cwd, Some(target));
    j.cancel_step(&mut ram).unwrap();
    ram.storage.release_preparation(charge);
    ram.release(&mut fds);
}
#[test]
fn stale_identity_epoch_and_nondirectory_refuse_without_cwd_effect() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let target = directory(&mut ram, b"directory", 0o755);
    let mut fds = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    let r = resolver(&mut ram, b"/directory", OWNER);
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let proof = r.cwd_proof(&ram.storage, OWNER).unwrap();
    let mut j = CwdJournal::path(&mut ram.storage, EXPENSE, charge, proof, OWNER).unwrap();
    assert_eq!(j.commit(&mut ram, &mut fds, ADMIN, None), Err(STALE_PROOF));
    ram.storage.set_attributes(target, 0o700, 37, 43).unwrap();
    assert_eq!(j.commit(&mut ram, &mut fds, OWNER, None), Err(STALE_PROOF));
    assert_eq!(fds.cwd, None);
    j.cancel_step(&mut ram).unwrap();
    r.release(&mut ram.storage);
    ram.storage.release_preparation(charge);
    let fd = ram.open(&mut fds, "/tmp/probe", READ_ONLY).unwrap();
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let before = ram.storage.usage(EXPENSE);
    assert!(matches!(
        ram.prepare_fchdir(&fds, fd, charge, OWNER),
        Err(NOT_DIRECTORY)
    ));
    assert_eq!(ram.storage.usage(EXPENSE), before);
    ram.storage.release_preparation(charge);
    ram.release(&mut fds);
}

#[test]
fn cwd_pin_exhaustion_has_no_effect_and_cancel_preserves_existing_pins() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let target = directory(&mut ram, b"directory", 0o755);
    let mut fds = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    let r = resolver(&mut ram, b"/directory", OWNER);
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let proof = r.cwd_proof(&ram.storage, OWNER).unwrap();
    let mut j = CwdJournal::path(&mut ram.storage, EXPENSE, charge, proof, OWNER).unwrap();
    ram.storage.node_mut(target).unwrap().pins[1] = u16::MAX;
    let proof = r.cwd_proof(&ram.storage, OWNER).unwrap();
    assert_eq!(
        j.commit(&mut ram, &mut fds, OWNER, Some(proof)),
        Err(proto_fs::NO_SPACE)
    );
    assert_eq!(fds.cwd, None);
    j.cancel_step(&mut ram).unwrap();
    r.release(&mut ram.storage);
    assert_eq!(ram.storage.node(target).unwrap().pins[1], u16::MAX);
    ram.storage.node_mut(target).unwrap().pins[1] = 0;
    ram.storage.release_preparation(charge);
}

fn deep_cwd(ram: &mut Ram<'_>, depth: usize, name: &[u8]) -> (Fds, Vec<u8>) {
    let mut node = ROOT;
    let mut path = Vec::new();
    for _ in 0..depth {
        let r = ram
            .storage
            .reserve(EXPENSE, node, name, (DIR, 0o755, 37, 43))
            .unwrap();
        node = ram.storage.commit(r).unwrap();
        path.push(b'/');
        path.extend_from_slice(name);
    }
    path.push(0);
    let mut fds = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    ram.set_cwd_token(&mut fds, node).unwrap();
    (fds, path)
}
fn getcwd_ready(ram: &mut Ram<'_>, journal: &mut GetcwdJournal) -> GetcwdOutcome {
    for _ in 0..50000 {
        if journal.step(&mut ram.storage, OWNER).unwrap() {
            return journal.outcome().unwrap();
        }
    }
    panic!("getcwd did not complete")
}
fn getcwd_bytes(ram: &Ram<'_>, journal: &mut GetcwdJournal, length: usize) -> Vec<u8> {
    let mut result = Vec::new();
    while result.len() < length {
        let mut out = [0; proto_fs::MAX_READ];
        for _ in 0..100 {
            if let Some(n) = journal
                .read_step(&ram.storage, result.len() as u32, &mut out)
                .unwrap()
            {
                assert!(n > 0);
                let mut retry = [0; proto_fs::MAX_READ];
                for _ in 0..100 {
                    if let Some(again) = journal
                        .read_step(&ram.storage, result.len() as u32, &mut retry)
                        .unwrap()
                    {
                        assert_eq!(again, n);
                        assert_eq!(retry[..n], out[..n]);
                        break;
                    }
                }
                result.extend_from_slice(&out[..n]);
                break;
            }
        }
    }
    result
}
fn getcwd_cancel(ram: &mut Ram<'_>, journal: &mut GetcwdJournal) {
    for _ in 0..100 {
        let before = ram.storage.available().pages;
        let done = journal.cancel_step(&mut ram.storage).unwrap();
        let after = ram.storage.available().pages;
        assert!(after == before || after == before + 1);
        if done {
            return;
        }
    }
    panic!("getcwd cleanup did not finish")
}
#[test]
fn paged_getcwd_raw_deep_path_is_immutable_and_cleanup_returns_every_page() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let mut name = [b'x'; 255];
    name[0] = 0xfe;
    let (mut fds, path) = deep_cwd(&mut ram, 150, &name);
    let before = ram.storage.available();
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let mut j = ram
        .prepare_getcwd(&fds, charge, OWNER, path.len() as u64)
        .unwrap();
    assert_eq!(
        getcwd_ready(&mut ram, &mut j),
        GetcwdOutcome::Ready {
            length: path.len() as u32
        }
    );
    let pages = (path.len()).div_ceil(crate::storage::PAGE) as u16;
    assert_eq!(before.pages - ram.storage.available().pages, pages);
    let info = ram.storage.filesystem_information(EXPENSE);
    assert_eq!(info.free_blocks, u64::from(ram.storage.available().pages));
    assert_eq!(getcwd_bytes(&ram, &mut j, path.len()), path);
    ram.storage.set_attributes(ROOT, 0o755, 0, 0).unwrap();
    assert!(j.step(&mut ram.storage, ADMIN).unwrap());
    assert_eq!(getcwd_bytes(&ram, &mut j, path.len()), path);
    ram.release(&mut fds);
    getcwd_cancel(&mut ram, &mut j);
    assert_eq!(ram.storage.available().pages, before.pages);
    ram.storage.release_preparation(charge);
}
#[test]
fn getcwd_root_small_buffer_zero_and_actual_length_errors() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let mut fds = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    assert!(matches!(
        ram.prepare_getcwd(&fds, charge, OWNER, 0),
        Err(proto_fs::INVALID_ARGUMENT)
    ));
    let mut j = ram.prepare_getcwd(&fds, charge, OWNER, 1).unwrap();
    assert_eq!(
        getcwd_ready(&mut ram, &mut j),
        GetcwdOutcome::BufferTooSmall { required: 2 }
    );
    getcwd_cancel(&mut ram, &mut j);
    let mut j = ram.prepare_getcwd(&fds, charge, OWNER, 2).unwrap();
    assert_eq!(
        getcwd_ready(&mut ram, &mut j),
        GetcwdOutcome::Ready { length: 2 }
    );
    assert_eq!(getcwd_bytes(&ram, &mut j, 2), b"/\0");
    getcwd_cancel(&mut ram, &mut j);
    ram.storage.release_preparation(charge);
    ram.release(&mut fds);
    let (mut fds, path) = deep_cwd(&mut ram, 3, &[b'x'; 255]);
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let pages = ram.storage.available().pages;
    let mut j = ram
        .prepare_getcwd(&fds, charge, OWNER, (path.len() - 1) as u64)
        .unwrap();
    assert_eq!(
        getcwd_ready(&mut ram, &mut j),
        GetcwdOutcome::BufferTooSmall {
            required: path.len() as u32
        }
    );
    assert_eq!(ram.storage.available().pages, pages);
    getcwd_cancel(&mut ram, &mut j);
    ram.storage.release_preparation(charge);
    ram.release(&mut fds);
}
#[test]
fn epoch_restart_cleans_old_result_before_rebuild_and_identity_failure_keeps_custody() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let (mut fds, path) = deep_cwd(&mut ram, 40, &[b'x'; 255]);
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let pages = ram.storage.available().pages;
    let mut j = ram
        .prepare_getcwd(&fds, charge, OWNER, path.len() as u64)
        .unwrap();
    for _ in 0..50000 {
        assert!(!j.step(&mut ram.storage, OWNER).unwrap());
        if pages - ram.storage.available().pages == 2 {
            break;
        }
    }
    assert_eq!(pages - ram.storage.available().pages, 2);
    ram.storage.set_attributes(ROOT, 0o755, 0, 0).unwrap();
    assert_eq!(j.step(&mut ram.storage, ADMIN), Err(STALE_PROOF));
    assert_eq!(pages - ram.storage.available().pages, 2);
    assert!(!j.step(&mut ram.storage, OWNER).unwrap());
    assert_eq!(pages - ram.storage.available().pages, 1);
    assert!(!j.step(&mut ram.storage, OWNER).unwrap());
    assert_eq!(ram.storage.available().pages, pages);
    assert_eq!(
        getcwd_ready(&mut ram, &mut j),
        GetcwdOutcome::Ready {
            length: path.len() as u32
        }
    );
    assert_eq!(getcwd_bytes(&ram, &mut j, path.len()), path);
    getcwd_cancel(&mut ram, &mut j);
    ram.storage.release_preparation(charge);
    ram.release(&mut fds);
}

#[test]
fn result_pages_root_quota_and_global_pool_refuse_before_ready_and_recover_all_charges() {
    use crate::cwd::getcwd::{NO_MEMORY, ResultPages};
    use crate::storage::{NONE, PAGE_SHARE};
    let mut ram = Ram::new(Timestamp::ZERO);
    let (mut fds, path) = deep_cwd(&mut ram, 3, &[b'x'; 255]);
    let other = Root {
        id: 12,
        generation: 7,
    };
    let third = Root {
        id: 13,
        generation: 7,
    };
    let mut chains = Vec::new();
    for (root, total) in [
        (EXPENSE, usize::from(PAGE_SHARE)),
        (other, crate::storage::PAGES - usize::from(PAGE_SHARE)),
    ] {
        let mut left = total;
        while left > 0 {
            let charge = ram.storage.charge_preparation(root).unwrap();
            let mut pages = ResultPages {
                head: NONE,
                first: 0,
                root: charge,
                count: 0,
                length: 0,
            };
            let count = left.min(81);
            for _ in 0..count {
                ram.storage.cwd_result_allocate(&mut pages).unwrap();
            }
            assert_eq!(pages.count as usize, count);
            chains.push((pages, charge));
            left -= count;
        }
    }
    assert_eq!(ram.storage.available().pages, 0);
    assert_eq!(ram.storage.usage(EXPENSE).pages, PAGE_SHARE);
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let mut j = ram
        .prepare_getcwd(&fds, charge, OWNER, path.len() as u64)
        .unwrap();
    let mut denied = false;
    for _ in 0..1000 {
        match j.step(&mut ram.storage, OWNER) {
            Err(NO_MEMORY) => {
                denied = true;
                break;
            }
            Ok(false) => (),
            other => panic!("unexpected result {other:?}"),
        }
    }
    assert!(denied);
    assert_eq!(j.outcome(), None);
    assert_eq!(ram.storage.available().pages, 0);
    getcwd_cancel(&mut ram, &mut j);
    ram.storage.release_preparation(charge);
    let mut third_fds = Fds {
        root: third,
        ..Fds::default()
    };
    ram.set_cwd_token(&mut third_fds, fds.cwd.unwrap()).unwrap();
    let charge = ram.storage.charge_preparation(third).unwrap();
    let mut j = ram
        .prepare_getcwd(&third_fds, charge, OWNER, path.len() as u64)
        .unwrap();
    let mut denied = false;
    for _ in 0..1000 {
        match j.step(&mut ram.storage, OWNER) {
            Err(NO_MEMORY) => {
                denied = true;
                break;
            }
            Ok(false) => (),
            other => panic!("unexpected result {other:?}"),
        }
    }
    assert!(denied);
    assert_eq!(ram.storage.usage(third).pages, 0);
    getcwd_cancel(&mut ram, &mut j);
    ram.storage.release_preparation(charge);
    for (mut pages, charge) in chains {
        while pages.head != NONE {
            let before = ram.storage.available().pages;
            ram.storage.cwd_result_free(&mut pages);
            assert_eq!(ram.storage.available().pages, before + 1);
        }
        ram.storage.release_preparation(charge);
    }
    assert_eq!(ram.storage.available().pages, crate::storage::PAGES as u16);
    assert_eq!(ram.storage.usage(EXPENSE).pages, 0);
    assert_eq!(ram.storage.usage(other).pages, 0);
    ram.release(&mut third_fds);
    ram.release(&mut fds);
}
#[test]
fn result_chain_81_pages_boundary_and_two_page_chunk_have_exact_live_ownership() {
    use crate::cwd::getcwd::ResultPages;
    use crate::storage::{NONE, PAGE};
    let mut ram = Ram::new(Timestamp::ZERO);
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let mut pages = ResultPages {
        head: NONE,
        first: 0,
        root: charge,
        count: 0,
        length: 0,
    };
    let mut name = [0u8; 256];
    for (i, byte) in name.iter_mut().enumerate() {
        *byte = i as u8;
    }
    ram.storage.cwd_result_allocate(&mut pages).unwrap();
    ram.storage.cwd_result_prepend(&mut pages, &[0]);
    for _ in 0..(crate::storage::NODES - 1) {
        let mut left = name.len();
        while left > 0 {
            if pages.first == 0 {
                ram.storage.cwd_result_allocate(&mut pages).unwrap();
            }
            let n = left.min(pages.first as usize);
            ram.storage
                .cwd_result_prepend(&mut pages, &name[left - n..left]);
            left -= n;
        }
    }
    assert_eq!(pages.count, 81);
    assert_eq!(pages.length, 328705);
    let before = ram.storage.available();
    assert_eq!(
        ram.storage.cwd_result_allocate(&mut pages),
        Err(crate::cwd::getcwd::NO_MEMORY)
    );
    assert_eq!(ram.storage.available(), before);
    let mut out = [0u8; proto_fs::MAX_READ];
    ram.storage.cwd_result_read(pages.head, PAGE - 1, &mut out);
    assert_eq!(out[0], 0);
    assert_eq!(out[1], 1);
    assert_eq!(out[2], 2);
    while pages.head != NONE {
        ram.storage.cwd_result_free(&mut pages);
    }
    assert_eq!(ram.storage.usage(EXPENSE).pages, 0);
    ram.storage.release_preparation(charge);
}
#[test]
fn deleted_cwd_is_preserved_for_clone_but_has_no_absolute_name() {
    let mut ram = Ram::new(Timestamp::ZERO);
    let target = directory(&mut ram, b"directory", 0o755);
    let mut fds = Fds {
        root: EXPENSE,
        ..Fds::default()
    };
    ram.set_cwd_token(&mut fds, target).unwrap();
    let mut r = Resolve::with_intent(
        &mut ram.storage,
        b"/directory",
        ROOT,
        ADMIN,
        crate::resolve::Intent::Namespace {
            path: crate::namespace::NamespacePath::Victim,
        },
    )
    .unwrap();
    while r.step(&mut ram.storage, ADMIN).unwrap() == Progress::More {}
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let proof = r
        .namespace_proof(&ram.storage, ADMIN, crate::namespace::NamespacePath::Victim)
        .unwrap();
    let mut prep = ram
        .storage
        .prepare_namespace_paid(
            EXPENSE,
            charge,
            crate::namespace::NamespaceIntent::Rmdir,
            proof,
            None,
            ADMIN,
        )
        .unwrap();
    r.release(&mut ram.storage);
    while !prep.step(&mut ram.storage, ADMIN).unwrap() {}
    assert_eq!(
        prep.commit(&mut ram.storage, ADMIN, Timestamp::ZERO),
        Ok(crate::namespace::NamespaceOutcome::Applied)
    );
    while !prep.cancel_step(&mut ram.storage).unwrap() {}
    ram.storage.release_preparation(charge);
    let mut cloned = ram.clone_fds(&fds, &[]).unwrap();
    assert_eq!(cloned.cwd, Some(target));
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let mut j = ram.prepare_getcwd(&cloned, charge, OWNER, 512).unwrap();
    assert_eq!(
        getcwd_ready(&mut ram, &mut j),
        GetcwdOutcome::Failed(proto_fs::NO_ENTRY)
    );
    ram.release(&mut fds);
    assert!(ram.storage.node(target).is_ok());
    getcwd_cancel(&mut ram, &mut j);
    ram.storage.release_preparation(charge);
    ram.release(&mut cloned);
    while ram.storage.reclaim_step() {}
    assert!(ram.storage.node(target).is_err());
}

#[test]
fn getcwd_takes_a_step_a_level_through_the_back_reference() {
    let mut ram = Ram::new(Timestamp::ZERO);
    // 64 levels of short names: the path fits the inline buffer, so no page is built.
    let (fds, path) = deep_cwd(&mut ram, 64, b"d");
    let charge = ram.storage.charge_preparation(EXPENSE).unwrap();
    let mut j = ram
        .prepare_getcwd(&fds, charge, OWNER, path.len() as u64)
        .unwrap();
    let mut steps = 0;
    while !j.step(&mut ram.storage, OWNER).unwrap() {
        steps += 1;
        assert!(steps < 1000);
    }
    steps += 1;
    std::println!("getcwd of depth 64: {steps} steps");
    assert!(steps <= 66, "{steps} steps for 64 levels");
    assert_eq!(
        j.outcome(),
        Some(GetcwdOutcome::Ready {
            length: path.len() as u32
        })
    );
    getcwd_cancel(&mut ram, &mut j);
    ram.storage.release_preparation(charge);
}
