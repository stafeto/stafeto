// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::*;

const NOBODY: &[u32] = &[];

fn file(mode: u32, uid: u32, gid: u32) -> Attr {
    Attr {
        kind: Kind::File,
        mode,
        uid,
        gid,
    }
}
fn dir(mode: u32, uid: u32, gid: u32) -> Attr {
    Attr {
        kind: Kind::Directory,
        mode,
        uid,
        gid,
    }
}
fn user<'a>(uid: u32, gid: u32, groups: &'a [u32]) -> Identity<'a> {
    Identity::new(uid, gid, groups)
}

// XBD 4.7: the class is chosen by who the caller is, and a class never falls back.
#[test]
fn xbd_4_7_class_table() {
    let f = file(0o640, 100, 200);
    // owner
    assert!(permits(user(100, 1, NOBODY), &f, READ | WRITE));
    assert!(!permits(user(100, 1, NOBODY), &f, EXEC));
    // group by the group ID
    assert!(permits(user(1, 200, NOBODY), &f, READ));
    assert!(!permits(user(1, 200, NOBODY), &f, WRITE));
    // group from the supplementary groups
    assert!(permits(user(1, 2, &[7, 200]), &f, READ));
    assert!(!permits(user(1, 2, &[7, 200]), &f, WRITE));
    // others
    assert!(!permits(user(1, 2, &[7]), &f, READ));
    assert!(permits(user(1, 2, NOBODY), &file(0o604, 100, 200), READ));
}

#[test]
fn xbd_4_7_owner_without_the_bit_does_not_fall_back_to_the_group() {
    // The owner has no read bit although the group has one: the owner is refused.
    let f = file(0o040, 100, 200);
    assert!(!permits(user(100, 200, NOBODY), &f, READ));
    assert!(permits(user(5, 200, NOBODY), &f, READ));
}

#[test]
fn xbd_4_7_group_without_the_bit_does_not_fall_back_to_others() {
    let f = file(0o404, 100, 200);
    assert!(!permits(user(5, 200, NOBODY), &f, READ));
    assert!(permits(user(5, 9, NOBODY), &f, READ));
}

#[test]
fn xbd_4_7_a_request_for_several_bits_needs_all_of_them() {
    let f = file(0o640, 100, 200);
    assert!(permits(user(100, 0, NOBODY), &f, READ | WRITE));
    assert!(!permits(user(5, 200, NOBODY), &f, READ | WRITE));
}

#[test]
fn xbd_4_7_root_passes_read_write_and_search() {
    let root = user(0, 0, NOBODY);
    assert!(permits(root, &file(0o000, 5, 5), READ | WRITE));
    assert!(permits(root, &dir(0o000, 5, 5), READ | WRITE | EXEC));
}

#[test]
fn xbd_4_7_root_executes_a_file_only_with_an_execute_bit() {
    let root = user(0, 0, NOBODY);
    assert!(!permits(root, &file(0o666, 5, 5), EXEC));
    assert!(permits(root, &file(0o001, 5, 5), EXEC));
    assert!(permits(root, &file(0o010, 5, 5), EXEC));
    assert!(permits(root, &file(0o100, 5, 5), EXEC));
}

#[test]
fn a_zero_bit_request_is_the_existence_check() {
    assert!(permits(user(5, 5, NOBODY), &file(0o000, 1, 1), 0));
}

// XSH open() and mkdir(): the owner of a new object is the caller.
#[test]
fn xsh_open_creation_owner_and_group_of_the_caller() {
    let parent = dir(0o755, 0, 0);
    let c = creation(user(100, 200, NOBODY), &parent, Kind::File, 0o666, 0o022);
    assert_eq!(
        c,
        Created {
            mode: 0o644,
            uid: 100,
            gid: 200
        }
    );
}

#[test]
fn xsh_open_creation_with_umask_0_022_and_077() {
    let parent = dir(0o755, 0, 0);
    let id = user(100, 200, NOBODY);
    assert_eq!(creation(id, &parent, Kind::File, 0o666, 0).mode, 0o666);
    assert_eq!(creation(id, &parent, Kind::File, 0o666, 0o022).mode, 0o644);
    assert_eq!(creation(id, &parent, Kind::File, 0o666, 0o077).mode, 0o600);
    assert_eq!(
        creation(id, &parent, Kind::Directory, 0o777, 0o022).mode,
        0o755
    );
}

#[test]
fn xsh_open_creation_ignores_bits_outside_the_mode_mask() {
    let parent = dir(0o755, 0, 0);
    let c = creation(user(1, 1, NOBODY), &parent, Kind::File, 0o170666, 0);
    assert_eq!(c.mode, 0o666);
}

#[test]
fn xsh_mkdir_setgid_directory_gives_its_group_and_the_bit_to_a_subdirectory() {
    let parent = dir(0o2775, 0, 300);
    let c = creation(user(100, 200, &[300]), &parent, Kind::Directory, 0o755, 0);
    assert_eq!(c.gid, 300);
    assert_eq!(c.mode, 0o2755);
    assert_eq!(c.uid, 100);
}

#[test]
fn xsh_open_setgid_directory_gives_its_group_to_a_file_without_the_bit() {
    let parent = dir(0o2775, 0, 300);
    let c = creation(user(100, 200, NOBODY), &parent, Kind::File, 0o2644, 0);
    assert_eq!(c.gid, 300);
    // The creator is not in group 300: the file's own set-group-ID bit goes.
    assert_eq!(c.mode, 0o644);
}

#[test]
fn xsh_open_setgid_bit_of_a_file_stays_for_a_member_of_the_group() {
    let parent = dir(0o2775, 0, 300);
    let c = creation(user(100, 200, &[300]), &parent, Kind::File, 0o2644, 0);
    assert_eq!(c.mode, 0o2644);
    let own = creation(
        user(100, 200, NOBODY),
        &dir(0o755, 0, 0),
        Kind::File,
        0o2644,
        0,
    );
    assert_eq!(own.mode, 0o2644);
}

#[test]
fn xsh_open_user_id_0_keeps_the_setgid_bit_of_a_new_file() {
    let parent = dir(0o2775, 0, 300);
    let c = creation(user(0, 0, NOBODY), &parent, Kind::File, 0o2644, 0);
    assert_eq!(c.mode, 0o2644);
}

#[test]
fn a_plain_directory_does_not_hand_down_the_bit_it_lacks() {
    let c = creation(
        user(1, 2, NOBODY),
        &dir(0o755, 0, 9),
        Kind::Directory,
        0o2755,
        0,
    );
    // The requested bit stays (the mode is the caller's); the group is the caller's.
    assert_eq!(c.gid, 2);
    assert_eq!(c.mode, 0o2755);
}

// XSH unlink() and rename(): the sticky directory, four cases.
#[test]
fn xsh_unlink_sticky_directory_four_cases() {
    let parent = dir(0o1777, 10, 10);
    let victim = file(0o644, 20, 20);
    // the owner of the entry
    assert!(sticky_allows(user(20, 1, NOBODY), &parent, &victim));
    // the owner of the directory
    assert!(sticky_allows(user(10, 1, NOBODY), &parent, &victim));
    // user ID 0
    assert!(sticky_allows(user(0, 0, NOBODY), &parent, &victim));
    // somebody else
    assert!(!sticky_allows(user(30, 1, NOBODY), &parent, &victim));
}

#[test]
fn xsh_unlink_without_the_sticky_bit_anybody_passes_this_rule() {
    let parent = dir(0o777, 10, 10);
    assert!(sticky_allows(
        user(30, 1, NOBODY),
        &parent,
        &file(0o600, 20, 20)
    ));
}

#[test]
fn xsh_chmod_owner_and_root_only() {
    let f = file(0o644, 100, 200);
    assert_eq!(chmod_result(user(100, 200, NOBODY), &f, 0o600), Ok(0o600));
    assert_eq!(chmod_result(user(0, 0, NOBODY), &f, 0o600), Ok(0o600));
    assert_eq!(
        chmod_result(user(5, 200, NOBODY), &f, 0o600),
        Err(Denial::Permission)
    );
}

#[test]
fn xsh_chmod_setgid_is_cleared_for_an_owner_outside_the_group() {
    let f = file(0o644, 100, 200);
    assert_eq!(chmod_result(user(100, 1, NOBODY), &f, 0o2755), Ok(0o755));
    assert_eq!(chmod_result(user(100, 1, &[200]), &f, 0o2755), Ok(0o2755));
    assert_eq!(chmod_result(user(100, 200, NOBODY), &f, 0o2755), Ok(0o2755));
    assert_eq!(chmod_result(user(0, 0, NOBODY), &f, 0o2755), Ok(0o2755));
}

#[test]
fn xsh_chmod_keeps_setuid_and_sticky_and_drops_the_file_type_bits() {
    let f = file(0o644, 100, 200);
    assert_eq!(
        chmod_result(user(100, 200, NOBODY), &f, 0o104755),
        Ok(0o4755)
    );
    assert_eq!(chmod_result(user(100, 200, NOBODY), &f, 0o1755), Ok(0o1755));
}

#[test]
fn xsh_chown_only_root_changes_the_owner() {
    let f = file(0o644, 100, 200);
    assert_eq!(
        chown_result(user(100, 200, NOBODY), &f, Some(101), None),
        Err(Denial::Permission)
    );
    let r = chown_result(user(0, 0, NOBODY), &f, Some(101), None).unwrap();
    assert_eq!((r.uid, r.gid), (101, 200));
}

#[test]
fn xsh_chown_owner_changes_the_group_to_one_of_its_own() {
    let f = file(0o644, 100, 200);
    let me = user(100, 300, &[400]);
    assert_eq!(chown_result(me, &f, None, Some(300)).unwrap().gid, 300);
    assert_eq!(chown_result(me, &f, None, Some(400)).unwrap().gid, 400);
    assert_eq!(
        chown_result(me, &f, None, Some(500)),
        Err(Denial::Permission)
    );
    // naming its own owner and the present group changes nothing and is allowed
    assert!(chown_result(me, &f, Some(100), Some(200)).is_ok());
}

#[test]
fn xsh_chown_somebody_else_may_not_change_the_group() {
    let f = file(0o644, 100, 200);
    assert_eq!(
        chown_result(user(5, 300, NOBODY), &f, None, Some(300)),
        Err(Denial::Permission)
    );
}

#[test]
fn xsh_chown_clears_the_set_id_bits_of_a_file() {
    let f = file(0o6755, 100, 200);
    let me = user(100, 300, NOBODY);
    assert_eq!(chown_result(me, &f, None, Some(300)).unwrap().mode, 0o755);
    let root = user(0, 0, NOBODY);
    assert_eq!(chown_result(root, &f, Some(7), None).unwrap().mode, 0o755);
}

#[test]
fn xsh_chown_keeps_the_set_id_bits_of_a_directory() {
    let d = dir(0o2755, 100, 200);
    let me = user(100, 300, NOBODY);
    assert_eq!(chown_result(me, &d, None, Some(300)).unwrap().mode, 0o2755);
}

#[test]
fn xsh_write_clears_the_set_id_bits() {
    assert_eq!(mode_after_write(0o6755), 0o755);
    assert_eq!(mode_after_write(0o1777), 0o1777);
}

#[test]
fn xsh_futimens_the_three_requests() {
    let f = file(0o644, 100, 200);
    let owner = user(100, 1, NOBODY);
    let other_writer = user(5, 200, NOBODY);
    let reader = user(6, 9, NOBODY);
    let g = file(0o664, 100, 200);
    assert_eq!(utimens_allowed(owner, &f, TimesRequest::Explicit), Ok(()));
    assert_eq!(
        utimens_allowed(user(0, 0, NOBODY), &f, TimesRequest::Explicit),
        Ok(())
    );
    assert_eq!(
        utimens_allowed(other_writer, &g, TimesRequest::Explicit),
        Err(Denial::Permission)
    );
    assert_eq!(utimens_allowed(other_writer, &g, TimesRequest::Now), Ok(()));
    assert_eq!(
        utimens_allowed(reader, &f, TimesRequest::Now),
        Err(Denial::Access)
    );
    assert_eq!(utimens_allowed(reader, &f, TimesRequest::Omit), Ok(()));
}

#[test]
fn xsh_access_real_and_effective_ids() {
    // A set-user-ID process: real user 1000, effective user 0 (the file is root's, mode 0600).
    let ids = Ids {
        uid: 1000,
        euid: 0,
        gid: 1000,
        egid: 0,
    };
    let secret = file(0o600, 0, 0);
    assert_eq!(
        access(ids, NOBODY, &secret, READ, true),
        Err(Denial::Access)
    );
    assert_eq!(access(ids, NOBODY, &secret, READ, false), Ok(()));
    // The other way: real user is the owner, effective user is not.
    let ids = Ids {
        uid: 100,
        euid: 200,
        gid: 1,
        egid: 1,
    };
    let mine = file(0o600, 100, 5);
    assert_eq!(access(ids, NOBODY, &mine, WRITE, true), Ok(()));
    assert_eq!(
        access(ids, NOBODY, &mine, WRITE, false),
        Err(Denial::Access)
    );
}

#[test]
fn xsh_access_uses_the_effective_group_for_the_effective_check() {
    let ids = Ids {
        uid: 1,
        euid: 1,
        gid: 10,
        egid: 20,
    };
    let f = file(0o060, 5, 20);
    assert_eq!(access(ids, NOBODY, &f, READ, true), Err(Denial::Access));
    assert_eq!(access(ids, NOBODY, &f, READ, false), Ok(()));
}

#[test]
fn xsh_access_existence_check_passes_with_no_bits() {
    let ids = Ids {
        uid: 1,
        euid: 1,
        gid: 1,
        egid: 1,
    };
    assert_eq!(access(ids, NOBODY, &file(0o000, 0, 0), 0, true), Ok(()));
}

#[test]
fn xsh_access_root_execute_needs_a_bit() {
    let ids = Ids {
        uid: 0,
        euid: 0,
        gid: 0,
        egid: 0,
    };
    assert_eq!(
        access(ids, NOBODY, &file(0o666, 5, 5), EXEC, true),
        Err(Denial::Access)
    );
    assert_eq!(access(ids, NOBODY, &dir(0o000, 5, 5), EXEC, true), Ok(()));
}

// XBD 4.5 Directory Protection and XSH unlink(), rename(): the compound rules.
#[test]
fn xbd_4_5_remove_needs_write_and_search_on_the_parent() {
    let victim = file(0o600, 20, 20);
    let me = user(30, 30, NOBODY);
    assert_eq!(remove_allowed(me, &dir(0o777, 10, 10), &victim), Ok(()));
    assert_eq!(
        remove_allowed(me, &dir(0o755, 10, 10), &victim),
        Err(Denial::Access)
    );
    assert_eq!(
        remove_allowed(me, &dir(0o766, 10, 10), &victim),
        Err(Denial::Access)
    );
    assert_eq!(remove_allowed(me, &dir(0o733, 10, 10), &victim), Ok(()));
}

#[test]
fn xbd_4_5_remove_in_a_sticky_directory_is_a_permission_refusal() {
    let parent = dir(0o1777, 10, 10);
    let victim = file(0o666, 20, 20);
    assert_eq!(
        remove_allowed(user(30, 30, NOBODY), &parent, &victim),
        Err(Denial::Permission)
    );
    assert_eq!(
        remove_allowed(user(20, 30, NOBODY), &parent, &victim),
        Ok(())
    );
    assert_eq!(
        remove_allowed(user(10, 30, NOBODY), &parent, &victim),
        Ok(())
    );
    assert_eq!(remove_allowed(user(0, 0, NOBODY), &parent, &victim), Ok(()));
}

#[test]
fn xbd_4_5_access_is_refused_before_the_sticky_rule() {
    // No write on a sticky parent: the permission bits come first.
    let parent = dir(0o1555, 10, 10);
    assert_eq!(
        remove_allowed(user(30, 30, NOBODY), &parent, &file(0o600, 20, 20)),
        Err(Denial::Access)
    );
}

#[test]
fn xsh_rename_needs_write_and_search_on_both_parents() {
    let source = file(0o644, 5, 5);
    let open_dir = dir(0o777, 1, 1);
    let closed = dir(0o555, 1, 1);
    let me = user(5, 5, NOBODY);
    assert_eq!(
        rename_allowed(me, &open_dir, &source, &open_dir, None, true),
        Ok(())
    );
    assert_eq!(
        rename_allowed(me, &closed, &source, &open_dir, None, false),
        Err(Denial::Access)
    );
    assert_eq!(
        rename_allowed(me, &open_dir, &source, &closed, None, false),
        Err(Denial::Access)
    );
}

#[test]
fn xsh_rename_sticky_rule_applies_to_the_source_and_to_the_target() {
    let sticky = dir(0o1777, 1, 1);
    let open_dir = dir(0o777, 1, 1);
    let mine = file(0o644, 5, 5);
    let theirs = file(0o644, 6, 6);
    let me = user(5, 5, NOBODY);
    // The source is in a sticky directory and belongs to somebody else.
    assert_eq!(
        rename_allowed(me, &sticky, &theirs, &open_dir, None, false),
        Err(Denial::Permission)
    );
    // The target is in a sticky directory and belongs to somebody else.
    assert_eq!(
        rename_allowed(me, &open_dir, &mine, &sticky, Some(&theirs), false),
        Err(Denial::Permission)
    );
    // A new name in a sticky directory needs no ownership.
    assert_eq!(
        rename_allowed(me, &open_dir, &mine, &sticky, None, false),
        Ok(())
    );
    // Own target in a sticky directory passes; the directory's owner passes.
    assert_eq!(
        rename_allowed(me, &open_dir, &mine, &sticky, Some(&mine), false),
        Ok(())
    );
    assert_eq!(
        rename_allowed(
            user(1, 1, NOBODY),
            &open_dir,
            &mine,
            &sticky,
            Some(&theirs),
            false
        ),
        Ok(())
    );
}

#[test]
fn xsh_rename_a_directory_to_another_parent_needs_write_on_itself() {
    let open_dir = dir(0o777, 1, 1);
    let me = user(5, 5, NOBODY);
    let read_only_child = dir(0o555, 5, 5);
    let writable_child = dir(0o755, 5, 5);
    assert_eq!(
        rename_allowed(me, &open_dir, &read_only_child, &open_dir, None, false),
        Err(Denial::Access)
    );
    assert_eq!(
        rename_allowed(me, &open_dir, &writable_child, &open_dir, None, false),
        Ok(())
    );
    // Inside one parent the `..` entry stays, and a file never needs it.
    assert_eq!(
        rename_allowed(me, &open_dir, &read_only_child, &open_dir, None, true),
        Ok(())
    );
    assert_eq!(
        rename_allowed(me, &open_dir, &file(0o444, 5, 5), &open_dir, None, false),
        Ok(())
    );
    // User ID 0 passes write on the directory.
    assert_eq!(
        rename_allowed(
            user(0, 0, NOBODY),
            &open_dir,
            &read_only_child,
            &open_dir,
            None,
            false
        ),
        Ok(())
    );
}

#[test]
fn place_allowed_is_the_destination_half() {
    let open_dir = dir(0o777, 1, 1);
    assert_eq!(place_allowed(user(5, 5, NOBODY), &open_dir, None), Ok(()));
    assert_eq!(
        place_allowed(user(5, 5, NOBODY), &dir(0o555, 1, 1), None),
        Err(Denial::Access)
    );
}
