// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The quota an instance needs (spec 7.5, 13.4). Before each start, the
//! first and each restart, init compares the free part of its own quota
//! with what the instance takes from it: the quota of the record, the
//! pages of the program's segments and stack, whose objects init pays for
//! (rt::loader::load), POOL_PAGES of init's pools and TABLES_AHEAD for the
//! tables of its loader window. A start that falls
//! short waits and is no failure: the rest of the quota of an instance
//! that ended comes back only when its clients let go of it.

use crate::PAGE;
use crate::restart::{PAUSE_FIRST_NS, PAUSE_MAX_NS};
use bootimg::Program;

/// The pages of init's pools an instance takes: its shell, the memory
/// objects of its program and the session of its start channel.
pub const POOL_PAGES: u64 = 4;

/// The pages of init's quota a mapping in init's loader window pays for
/// its tables ahead (spec 7.5).
pub const TABLES_AHEAD: u64 = 3;

/// The pages of init's quota an instance of a record with `quota` bytes
/// takes when it loads `program`: the quota, the whole pages of each
/// segment and of the stack, POOL_PAGES and TABLES_AHEAD.
pub fn need_pages(quota: u64, program: &Program<'_>) -> u64 {
    let segments: u64 = program
        .segments
        .iter()
        .map(|s| (s.pages().end - s.pages().start) / PAGE)
        .sum();
    let stack = u64::from(program.stack_size).div_ceil(PAGE);
    quota.div_ceil(PAGE) + segments + stack + POOL_PAGES + TABLES_AHEAD
}

/// Whether `free` pages of init's quota cover `need`.
pub fn fits(free: u64, need: u64) -> bool {
    free >= need
}

/// When an instance starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    Now,
    /// Init looks at its quota again after this pause.
    Wait {
        pause_ns: u64,
    },
}

/// Whether an instance that needs `need` pages starts with `free` pages of
/// init's quota free: now, when they fit; otherwise after twice the pause
/// its record waited before this look, `pause_ns` (0 before a first
/// start), from PAUSE_FIRST_NS up to PAUSE_MAX_NS.
pub fn start(free: u64, need: u64, pause_ns: u64) -> Start {
    if fits(free, need) {
        Start::Now
    } else {
        Start::Wait {
            pause_ns: pause_ns
                .saturating_mul(2)
                .clamp(PAUSE_FIRST_NS, PAUSE_MAX_NS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bootimg::Segment;

    const MS: u64 = 1_000_000;

    /// Code of 3 pages and a byte, read-only data of 2, data of 7 pages,
    /// of which the file holds 1, and a stack of 4.
    fn program() -> Program<'static> {
        let segment = |vaddr: u64, mem_size: u64, bytes: &'static [u8]| Segment {
            vaddr,
            mem_size,
            bytes,
        };
        Program {
            entry: 0x20_0000,
            stack_size: 4 * PAGE as u32,
            segments: [
                segment(0x20_0000, 3 * PAGE + 1, &[0; 16]),
                segment(0x21_0000, 2 * PAGE, &[0; 16]),
                segment(0x22_0000, 7 * PAGE, &[0; 4096]),
            ],
        }
    }

    #[test]
    fn an_instance_needs_its_quota_program_and_pools() {
        let p = program();
        assert_eq!(
            need_pages(20 * PAGE, &p),
            20 + 4 + 2 + 7 + 4 + POOL_PAGES + TABLES_AHEAD
        );
        let small = Program {
            segments: [p.segments[0], Segment::EMPTY, Segment::EMPTY],
            stack_size: PAGE as u32,
            ..p
        };
        assert_eq!(
            need_pages(15 * PAGE, &small),
            15 + 4 + 1 + POOL_PAGES + TABLES_AHEAD
        );
        assert_eq!((POOL_PAGES, TABLES_AHEAD), (4, 3));
    }

    #[test]
    fn a_start_waits_while_the_quota_falls_short() {
        let need = need_pages(20 * PAGE, &program());
        assert!(fits(need, need));
        assert!(!fits(need - 1, need));
        assert_eq!(start(need, need, 0), Start::Now);
        assert_eq!(start(u64::MAX, need, 800 * MS), Start::Now);
        // Short: the pause doubles from 100 ms up to 5 s, from a first
        // start and from the pause of a restart.
        let mut pause = 0;
        let mut waits = Vec::new();
        for _ in 0..8 {
            let Start::Wait { pause_ns } = start(need - 1, need, pause) else {
                panic!("a start that falls short went on");
            };
            waits.push(pause_ns / MS);
            pause = pause_ns;
        }
        assert_eq!(waits, [100, 200, 400, 800, 1600, 3200, 5000, 5000]);
        assert_eq!(
            start(0, need, 800 * MS),
            Start::Wait {
                pause_ns: 1600 * MS
            }
        );
    }
}
