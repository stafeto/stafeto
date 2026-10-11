// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Eight genuine Create payers. Every quota and connection keeps the existing value.
use super::{Record, ramfs::POSIX_PROCS_TABLE as BASE};
pub const TABLE4: &[Record] = &[
    BASE[0],
    BASE[1],
    BASE[2],
    BASE[3],
    Record {
        name: "lock-full-0",
        args: b"posix-procs\0full-launch\x004\x000\0",
        root: true,
        ..BASE[4]
    },
    Record {
        name: "lock-full-1",
        args: b"posix-procs\0full-launch\x004\x001\0",
        root: false,
        ..BASE[4]
    },
    Record {
        name: "lock-full-2",
        args: b"posix-procs\0full-launch\x004\x002\0",
        root: false,
        ..BASE[4]
    },
    Record {
        name: "lock-full-3",
        args: b"posix-procs\0full-launch\x004\x003\0",
        root: false,
        ..BASE[4]
    },
    Record {
        name: "lock-full-4",
        args: b"posix-procs\0full-launch\x004\x004\0",
        root: false,
        ..BASE[4]
    },
    Record {
        name: "lock-full-5",
        args: b"posix-procs\0full-launch\x004\x005\0",
        root: false,
        ..BASE[4]
    },
    Record {
        name: "lock-full-6",
        args: b"posix-procs\0full-launch\x004\x006\0",
        root: false,
        ..BASE[4]
    },
    Record {
        name: "lock-full-7",
        args: b"posix-procs\0full-launch\x004\x007\0",
        root: false,
        ..BASE[4]
    },
    BASE[5],
    BASE[6],
];
pub const TABLE7: &[Record] = &[
    BASE[0],
    BASE[1],
    BASE[2],
    BASE[3],
    Record {
        name: "lock-full-0",
        args: b"posix-procs\0full-launch\x007\x000\0",
        root: true,
        ..BASE[4]
    },
    Record {
        name: "lock-full-1",
        args: b"posix-procs\0full-launch\x007\x001\0",
        root: false,
        ..BASE[4]
    },
    Record {
        name: "lock-full-2",
        args: b"posix-procs\0full-launch\x007\x002\0",
        root: false,
        ..BASE[4]
    },
    Record {
        name: "lock-full-3",
        args: b"posix-procs\0full-launch\x007\x003\0",
        root: false,
        ..BASE[4]
    },
    Record {
        name: "lock-full-4",
        args: b"posix-procs\0full-launch\x007\x004\0",
        root: false,
        ..BASE[4]
    },
    Record {
        name: "lock-full-5",
        args: b"posix-procs\0full-launch\x007\x005\0",
        root: false,
        ..BASE[4]
    },
    Record {
        name: "lock-full-6",
        args: b"posix-procs\0full-launch\x007\x006\0",
        root: false,
        ..BASE[4]
    },
    Record {
        name: "lock-full-7",
        args: b"posix-procs\0full-launch\x007\x007\0",
        root: false,
        ..BASE[4]
    },
    BASE[5],
    BASE[6],
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eight_payers_keep_real_create_payment_and_start_order() {
        for table in [TABLE4, TABLE7] {
            assert_eq!(table.len(), 14);
            assert!(super::super::check(table).is_ok());
            let clients: Vec<_> = table.iter().filter(|r| r.is_posix()).collect();
            assert_eq!(clients.len(), 8);
            assert_eq!(clients.iter().filter(|r| r.root).count(), 1);
            for (i, r) in clients.into_iter().enumerate() {
                assert_eq!(r.name, format!("lock-full-{i}"));
                assert_eq!(r.program, BASE[4].program);
                assert_eq!(r.quota, BASE[4].quota);
                assert_eq!(r.handle_limit, BASE[4].handle_limit);
                assert_eq!(r.connects, BASE[4].connects);
                assert_eq!(r.priority, BASE[4].priority);
            }
            for i in 0..4 {
                assert_eq!(table[i], BASE[i]);
            }
            assert_eq!(table[12], BASE[5]);
            assert_eq!(table[13], BASE[6]);
        }
    }
}
