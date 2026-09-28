// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! POSIX real/effective/saved ID transitions. Effective UID zero is privileged.
#![cfg_attr(not(test), no_std)]
pub use proto_process::{Change, Credentials};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Permission,
}
/// Compute the entire next state before changing the process record.
pub fn change(mut current: Credentials, operation: Change, id: u32) -> Result<Credentials, Error> {
    if id == u32::MAX {
        return Err(Error::Invalid);
    }
    let privileged = current.euid == 0;
    match operation {
        Change::Uid if privileged => {
            current.uid = id;
            current.euid = id;
            current.suid = id;
        }
        Change::Uid | Change::EffectiveUid => {
            if !privileged && id != current.uid && id != current.suid {
                return Err(Error::Permission);
            }
            current.euid = id;
        }
        Change::Gid if privileged => {
            current.gid = id;
            current.egid = id;
            current.sgid = id;
        }
        Change::Gid | Change::EffectiveGid => {
            if !privileged && id != current.gid && id != current.sgid {
                return Err(Error::Permission);
            }
            current.egid = id;
        }
    }
    Ok(current)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn privileged_uid_change_drops_all_three_and_cannot_regain_root() {
        let next = change(Credentials::ROOT, Change::Uid, 1000).unwrap();
        assert_eq!(next.words(), [1000, 1000, 1000, 0, 0, 0]);
        assert_eq!(change(next, Change::Uid, 0), Err(Error::Permission));
        assert_eq!(
            change(next, Change::EffectiveUid, 0),
            Err(Error::Permission)
        );
    }
    #[test]
    fn effective_uid_drop_preserves_real_and_saved_and_can_regain() {
        let next = change(Credentials::ROOT, Change::EffectiveUid, 1000).unwrap();
        assert_eq!(next.words(), [0, 1000, 0, 0, 0, 0]);
        assert_eq!(change(next, Change::EffectiveUid, 0), Ok(Credentials::ROOT));
        assert_eq!(change(next, Change::Uid, 0), Ok(Credentials::ROOT));
        assert_eq!(
            change(next, Change::EffectiveUid, 1001),
            Err(Error::Permission)
        );
    }
    #[test]
    fn nonprivileged_user_uses_real_or_saved_and_preserves_other_ids() {
        let current = Credentials::from_words([1000, 1001, 1002, 10, 11, 12]);
        for op in [Change::Uid, Change::EffectiveUid] {
            for id in [1000, 1002] {
                let next = change(current, op, id).unwrap();
                assert_eq!(
                    next,
                    Credentials {
                        euid: id,
                        ..current
                    }
                );
            }
            assert_eq!(change(current, op, 1001), Err(Error::Permission));
            assert_eq!(change(current, op, 1003), Err(Error::Permission));
        }
    }
    #[test]
    fn group_privilege_depends_on_effective_uid_and_changes_saved_only_for_setgid() {
        let root = Credentials::ROOT;
        assert_eq!(
            change(root, Change::Gid, 42).unwrap().words(),
            [0, 0, 0, 42, 42, 42]
        );
        assert_eq!(
            change(root, Change::EffectiveGid, 42).unwrap().words(),
            [0, 0, 0, 0, 42, 0]
        );
        let user = Credentials::from_words([1000, 1000, 1000, 10, 11, 12]);
        for op in [Change::Gid, Change::EffectiveGid] {
            for id in [10, 12] {
                assert_eq!(change(user, op, id), Ok(Credentials { egid: id, ..user }));
            }
            assert_eq!(change(user, op, 11), Err(Error::Permission));
            assert_eq!(change(user, op, 42), Err(Error::Permission));
        }
    }
    #[test]
    fn maximum_is_invalid_and_largest_valid_id_is_preserved() {
        for op in [
            Change::Uid,
            Change::EffectiveUid,
            Change::Gid,
            Change::EffectiveGid,
        ] {
            assert_eq!(change(Credentials::ROOT, op, u32::MAX), Err(Error::Invalid));
            assert!(change(Credentials::ROOT, op, u32::MAX - 1).is_ok());
        }
    }
}
