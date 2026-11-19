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
use crate::table::{Dma, Shares};
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

/// The pages of the DMA objects of a record, which init makes in its worker
/// (`mem_create_contiguous`) and pays for from its own quota: apart from
/// `need_pages`, since the objects are made after the program loaded. The
/// kernel takes a block of 2^order frames for a contiguous object, so each
/// object counts as its pages rounded up to a power of two.
pub fn dma_pages(dma: &[Dma]) -> u64 {
    dma.iter()
        .map(|d| d.size.div_ceil(PAGE).next_power_of_two())
        .sum()
}

/// The pages of init's quota one instance takes in all: `need_pages` and the
/// pages of its DMA objects. A start that checks `need_pages` alone can pass
/// and then fail in the contiguous allocation (`did not load`), which counts
/// toward the record's failures.
pub fn need_with_dma(quota: u64, program: &Program<'_>, dma: &[Dma]) -> u64 {
    need_pages(quota, program) + dma_pages(dma)
}

/// The pool of the process service as init sizes it at boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pool {
    /// The pages the pool has: the remainder, and at least `min`.
    pub pages: u64,
    /// How far the remainder falls under `min` (0 when it does not).
    pub short: u64,
}

/// The pool of the process service: what is left of the `free` pages of
/// init's quota once the instances init loads besides the process service
/// (`others`, with the POSIX records the service loads for) and the process
/// service's own program (`own`) are paid for, and `reserve` and `slack`
/// stay free. A remainder under `min` gives `min` and the shortfall.
pub fn pool_pages(free: u64, others: u64, own: u64, reserve: u64, slack: u64, min: u64) -> Pool {
    let rest = free
        .saturating_sub(others)
        .saturating_sub(own)
        .saturating_sub(reserve)
        .saturating_sub(slack);
    Pool {
        pages: rest.max(min),
        short: min.saturating_sub(rest),
    }
}

/// Whether `free` pages of init's quota cover `need`.
pub fn fits(free: u64, need: u64) -> bool {
    free >= need
}

/// Whether the free part of init's own shares, `free` thread numbers and
/// timer places (object_info PROCESS_SHARES of init's process), covers the
/// `shares` an instance takes of them (spec 7.5): the rest of the shares
/// of an instance that ended comes back only when its clients let go of it,
/// as its quota does.
pub fn shares_fit(free: (u64, u64), shares: Shares) -> bool {
    free.0 >= u64::from(shares.threads) && free.1 >= u64::from(shares.timers)
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
/// init's quota free and, when `shares_ok`, with its shares of thread
/// numbers and timer places free (`shares_fit`): now, when they fit;
/// otherwise after twice the pause its record waited before this look,
/// `pause_ns` (0 before a first start), from PAUSE_FIRST_NS up to
/// PAUSE_MAX_NS.
pub fn start(free: u64, need: u64, shares_ok: bool, pause_ns: u64) -> Start {
    if shares_ok && fits(free, need) {
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
        assert_eq!(start(need, need, true, 0), Start::Now);
        assert_eq!(start(u64::MAX, need, true, 800 * MS), Start::Now);
        // Short: the pause doubles from 100 ms up to 5 s, from a first
        // start and from the pause of a restart.
        let mut pause = 0;
        let mut waits = Vec::new();
        for _ in 0..8 {
            let Start::Wait { pause_ns } = start(need - 1, need, true, pause) else {
                panic!("a start that falls short went on");
            };
            waits.push(pause_ns / MS);
            pause = pause_ns;
        }
        assert_eq!(waits, [100, 200, 400, 800, 1600, 3200, 5000, 5000]);
        assert_eq!(
            start(0, need, true, 800 * MS),
            Start::Wait {
                pause_ns: 1600 * MS
            }
        );
        // Shares that fall short make a start wait however much quota is
        // free, and shares of none always fit.
        assert_eq!(
            start(u64::MAX, need, false, 0),
            Start::Wait { pause_ns: 100 * MS }
        );
    }

    #[test]
    fn dma_objects_count_in_the_need() {
        let dma = |size: u64| Dma {
            name: "d",
            size,
            uncached: false,
            duplicate: false,
        };
        let p = program();
        let objects = [dma(16 * PAGE), dma(256 * PAGE)];
        assert_eq!(dma_pages(&objects), 272);
        assert_eq!(dma_pages(&[dma(PAGE + 1)]), 2);
        // The kernel charges 2^order frames: 24 pages take 32.
        assert_eq!(dma_pages(&[dma(24 * PAGE)]), 32);
        assert_eq!(
            need_with_dma(20 * PAGE, &p, &objects),
            need_pages(20 * PAGE, &p) + 272
        );
        assert_eq!(need_with_dma(20 * PAGE, &p, &[]), need_pages(20 * PAGE, &p));
        // A restart that has `need_pages` free and lacks the pages of its DMA objects waits.
        let need = need_with_dma(20 * PAGE, &p, &objects);
        let free = need_pages(20 * PAGE, &p);
        assert!(!fits(free, need));
    }

    #[test]
    fn the_pool_is_the_remainder_above_the_reserve() {
        let pool = pool_pages(130_000, 30_000, 100, 16_384, 64, 52_120);
        assert_eq!(
            pool,
            Pool {
                pages: 130_000 - 30_000 - 100 - 16_384 - 64,
                short: 0
            }
        );
    }

    #[test]
    fn a_remainder_of_exactly_the_minimum_is_no_shortfall() {
        let pool = pool_pages(52_120 + 100 + 16_384 + 64 + 7, 7, 100, 16_384, 64, 52_120);
        assert_eq!((pool.pages, pool.short), (52_120, 0));
    }

    #[test]
    fn a_remainder_under_the_minimum_gives_the_minimum_and_names_the_shortfall() {
        let pool = pool_pages(52_120 + 100 + 16_384 + 64 - 25, 0, 100, 16_384, 64, 52_120);
        assert_eq!(
            (pool.pages, pool.short),
            (52_120, 25),
            "pool {} pages, under POOL_MIN 52120 by {}",
            pool.pages,
            pool.short
        );
    }

    #[test]
    fn the_pool_subtraction_does_not_wrap() {
        let pool = pool_pages(10, 1_000, 1_000, 1_000, 1_000, 500);
        assert_eq!((pool.pages, pool.short), (500, 500));
        assert_eq!(pool_pages(0, 0, 0, 0, 0, 0), Pool { pages: 0, short: 0 });
    }

    #[test]
    fn shares_fit_while_init_has_them_free() {
        let own = Shares {
            threads: 768,
            timers: 6144,
        };
        assert!(shares_fit((768, 6144), own));
        assert!(!shares_fit((767, 6144), own));
        assert!(!shares_fit((768, 6143), own));
        assert!(shares_fit((0, 0), Shares::CREATOR));
        assert!(shares_fit((896, 7168), own));
    }
}
