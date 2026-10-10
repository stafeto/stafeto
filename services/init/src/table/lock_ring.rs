// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Four genuine Create roots, each paying four sleeping PID registrations.
use super::{Record, ramfs::POSIX_PROCS_TABLE as BASE};
pub const TABLE: &[Record] = &[
    BASE[0],
    BASE[1],
    BASE[2],
    BASE[3],
    Record {
        name: "lock-ring-0",
        args: b"posix-procs\0ring-launch\0\x30\0",
        ..BASE[4]
    },
    Record {
        name: "lock-ring-1",
        args: b"posix-procs\0ring-launch\0\x31\0",
        root: false,
        ..BASE[4]
    },
    Record {
        name: "lock-ring-2",
        args: b"posix-procs\0ring-launch\0\x32\0",
        root: false,
        ..BASE[4]
    },
    Record {
        name: "lock-ring-3",
        args: b"posix-procs\0ring-launch\0\x33\0",
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
    fn four_real_create_records_keep_existing_payment_and_one_credential_root() {
        let clients: Vec<_> = TABLE.iter().filter(|record| record.is_posix()).collect();
        assert_eq!(clients.len(), 4);
        assert_eq!(clients.iter().filter(|record| record.root).count(), 1);
        for (index, client) in clients.into_iter().enumerate() {
            assert_eq!(client.name, format!("lock-ring-{index}"));
            assert_eq!(client.program, BASE[4].program);
            assert_eq!(client.quota, BASE[4].quota);
            assert_eq!(client.handle_limit, BASE[4].handle_limit);
            assert_eq!(client.connects, BASE[4].connects);
        }
        for index in 0..4 {
            assert_eq!(TABLE[index], BASE[index]);
        }
    }
}
