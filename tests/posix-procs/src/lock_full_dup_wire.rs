// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Full numeric-entry and backend identities of one ordinary replacement.

pub fn replacement(before: &[u64; 12], after: &[u64; 12], event: &[u64; 10], last: bool) -> bool {
    let target = &before[..4];
    let source = &before[4..8];
    let alias = &before[8..];
    target[0] != source[0]
        && target[1] != 0
        && target[3] != 0
        && source[1] != 0
        && source[3] != 0
        && target[2..] != source[2..]
        && after[0] == target[0]
        && after[1] > target[1]
        && after[2..4] == source[2..4]
        && after[4..8] == *source
        && after[8..] == *alias
        && event[..4] == *target
        && event[4..6] == source[2..4]
        && event[7] == u64::from(last)
        && (48..64).contains(&event[8])
        && event[9] != 0
        && if last {
            alias == [0; 4]
        } else {
            alias[0] != target[0]
                && alias[0] != source[0]
                && alias[1] != 0
                && alias[2..] == target[2..]
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(last: bool) -> ([u64; 12], [u64; 12], [u64; 10]) {
        let mut before = [
            3,
            9,
            0x30001,
            0x100000001,
            4,
            7,
            0x40002,
            0x200000002,
            0,
            0,
            0,
            0,
        ];
        if !last {
            let alias = [5, 8, before[2], before[3]];
            before[8..].copy_from_slice(&alias);
        }
        let mut after = before;
        after[1] = 10;
        after[2] = before[6];
        after[3] = before[7];
        let event = [
            before[0],
            before[1],
            before[2],
            before[3],
            before[6],
            before[7],
            0,
            u64::from(last),
            48,
            0x300000003,
        ];
        (before, after, event)
    }
    #[test]
    fn replacement_checks_each_frozen_identity_and_surviving_alias() {
        for last in [false, true] {
            let (before, after, event) = fixture(last);
            assert!(replacement(&before, &after, &event, last));
            for index in 0..after.len() {
                let mut wrong = after;
                wrong[index] ^= 1_u64 << 32;
                if index == 1 {
                    wrong[index] = before[1];
                }
                assert!(!replacement(&before, &wrong, &event, last), "after {index}");
            }
            for index in [0, 1, 2, 3, 4, 5, 7, 8, 9] {
                let mut wrong = event;
                wrong[index] ^= 1_u64 << 32;
                if index == 9 {
                    wrong[index] = 0;
                }
                assert!(!replacement(&before, &after, &wrong, last), "event {index}");
            }
        }
    }
    #[test]
    fn last_alias_and_source_are_distinct_physical_lifetimes() {
        let (before, after, event) = fixture(false);
        assert!(!replacement(&before, &after, &event, true));
        let (mut before, mut after, mut event) = fixture(true);
        before[6] = before[2];
        before[7] = before[3];
        after[2] = before[2];
        after[3] = before[3];
        event[4] = before[2];
        event[5] = before[3];
        assert!(!replacement(&before, &after, &event, true));
    }
    #[test]
    fn real_frozen_close_record_replaces_target_and_preserves_alias_and_source() {
        use posix_fd::{CloseAdmission, Flags, OwnerToken, Table};
        for last in [false, true] {
            let mut table = Table::<(u32, u64), 32, (), (), u64>::default();
            let owner = OwnerToken::new(0x100000001).unwrap();
            let flags = Flags {
                close_on_exec: true,
                close_on_fork: true,
            };
            let target = table
                .insert((0x30001, 0x100000001), Flags::default())
                .unwrap();
            let source = table
                .insert((0x40002, 0x200000002), Flags::default())
                .unwrap();
            let alias = if last {
                None
            } else {
                Some(table.duplicate(target, 0, Flags::default()).unwrap())
            };
            fn sample(table: &Table<(u32, u64), 32, (), (), u64>, fd: u32) -> [u64; 4] {
                let entry = table.entry_token(fd).unwrap();
                let backend = table.get(fd).unwrap();
                [
                    u64::from(fd),
                    entry.generation(),
                    u64::from(backend.0),
                    backend.1,
                ]
            }
            let mut before = [0; 12];
            before[..4].copy_from_slice(&sample(&table, target));
            before[4..8].copy_from_slice(&sample(&table, source));
            if let Some(alias) = alias {
                before[8..].copy_from_slice(&sample(&table, alias));
            }
            let old = table.entry_token(target).unwrap();
            assert_eq!(
                table.begin_replace(owner, target, target, Some(flags), 7),
                Err(posix_fd::Error::InvalidArgument)
            );
            assert_eq!(table.entry_token(target).unwrap(), old);
            assert_eq!(
                table.begin_replace(owner, target, target, None, 7),
                Ok(CloseAdmission::Replaced(target))
            );
            let CloseAdmission::Started { token, snapshot } = table
                .begin_replace(owner, source, target, Some(flags), 7)
                .unwrap()
            else {
                panic!()
            };
            assert_eq!(snapshot.owner, Some(owner));
            assert_eq!(snapshot.entry, old);
            assert_eq!(table.get(source), Ok((0x40002, 0x200000002)));
            assert_eq!(table.close_snapshot(token).unwrap(), snapshot);
            let event = [
                u64::from(snapshot.entry.fd),
                snapshot.entry.generation(),
                u64::from(snapshot.backend.0),
                snapshot.backend.1,
                u64::from(snapshot.replacement.unwrap().0.0),
                snapshot.replacement.unwrap().0.1,
                3,
                u64::from(snapshot.last_alias),
                token.slot() as u64,
                token.generation(),
            ];
            assert_eq!(
                table.finish_close(token).unwrap(),
                last.then_some((0x30001, 0x100000001))
            );
            assert_eq!(table.flags(target), Ok(flags));
            assert_eq!(table.flags(source), Ok(Flags::default()));
            let mut after = [0; 12];
            after[..4].copy_from_slice(&sample(&table, target));
            after[4..8].copy_from_slice(&sample(&table, source));
            if let Some(alias) = alias {
                after[8..].copy_from_slice(&sample(&table, alias));
            }
            assert!(replacement(&before, &after, &event, last));
            assert_eq!(table.close_exact(old), None);
            assert_eq!(table.get(target), Ok((0x40002, 0x200000002)));
            if last {
                table.finish_close_release(token, snapshot.backend).unwrap();
            }
            table.ack_close(token, Some(owner)).unwrap();
            assert_eq!(
                table.close_snapshot(token),
                Err(posix_fd::Error::BadFileDescriptor)
            );
        }
    }
}
