// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The reserve of init's free pages against the restart of its heaviest
//! record: `cargo xtask init-reserve`, and the step "init reserve" of the
//! host checks of ci.
//!
//! After the services of the base image and the full image started, init
//! keeps `INIT_RESERVE_PAGES` of its own quota free and gives the pool of the
//! process service everything above them (services/init/src/table/base.rs).
//! The use init has for free pages after the boot is the restart of a
//! record with `Restart::Always` while its clients still hold the old
//! instance: the instance takes its quota, the pages of its segments and
//! stack, init's pools and the pages of its DMA objects once more
//! (init::quota::need_with_dma). The check builds the programs of those
//! records, adds the needs of all of them, and adds the DMA pages one failed
//! stop leaks for good (`Instance::keep_dma`, the largest of the records);
//! it fails when the total is over the reserve.

use init::quota::{dma_pages, need_with_dma};
use init::table::Restart;
use init::table::base::{BASE_TABLE, INIT_RESERVE_PAGES};
use std::sync::PoisonError;

const PAGE: u64 = 4096;

/// What one restart of a record takes of init's quota, by part.
#[derive(Debug, PartialEq, Eq)]
struct Need {
    quota: u64,
    segments: u64,
    stack: u64,
    dma: u64,
    total: u64,
}

fn need_of(record: &init::table::Record, program: &bootimg::Program<'_>, stack_size: u32) -> Need {
    let segments = program
        .segments
        .iter()
        .map(|s| (s.pages().end - s.pages().start) / PAGE)
        .sum();
    Need {
        quota: record.quota.div_ceil(PAGE),
        segments,
        stack: u64::from(stack_size).div_ceil(PAGE),
        dma: dma_pages(record.dma),
        total: need_with_dma(record.quota, program, record.dma),
    }
}

/// What the check found: the sum of the restart needs, the largest DMA leak
/// of one record and the record with the largest need.
#[derive(Debug, PartialEq, Eq)]
struct Found {
    sum: u64,
    leak: u64,
    leaker: String,
    largest: String,
    largest_pages: u64,
}

/// The sum of the needs of all the records, plus the DMA pages one failed
/// stop leaks (`Instance::keep_dma`: the largest of the records), against
/// `reserve`; the error names the parts when they are over it.
fn verdict(needs: &[(&str, Need)], reserve: u64) -> Result<Found, String> {
    let (Some((largest, worst)), Some((leaker, leaky))) = (
        needs.iter().max_by_key(|(_, n)| n.total),
        needs.iter().max_by_key(|(_, n)| n.dma),
    ) else {
        return Err("init-reserve: the base table has no record that restarts".to_owned());
    };
    let sum: u64 = needs.iter().map(|(_, n)| n.total).sum();
    let found = Found {
        sum,
        leak: leaky.dma,
        leaker: leaker.to_string(),
        largest: largest.to_string(),
        largest_pages: worst.total,
    };
    if sum + found.leak > reserve {
        return Err(format!(
            "init-reserve: the restarts of all records need {sum} pages (largest {largest} with {}: \
             quota {}, segments {}, stack {}, DMA {}) and a failed stop of {leaker} leaks {} \
             pages of DMA, over INIT_RESERVE_PAGES {reserve} in services/init/src/table/base.rs",
            worst.total, worst.quota, worst.segments, worst.stack, worst.dma, found.leak
        ));
    }
    Ok(found)
}

/// Builds the programs of the records of the base table that restart as the
/// base image ships them and checks the largest need against the reserve.
pub fn check() -> Result<(), String> {
    let image = super::base_image::programs(super::base_image::BASE_IMAGE);
    let records: Vec<_> = BASE_TABLE
        .iter()
        .filter(|r| r.restart == Restart::Always)
        .collect();
    let mut wanted = Vec::new();
    for record in &records {
        let found = image
            .iter()
            .find(|p| p.0 == record.program)
            .ok_or_else(|| {
                format!(
                    "init-reserve: no program {} for {}",
                    record.program, record.name
                )
            })?;
        wanted.push(*found);
    }
    let mut cmd = super::cargo();
    cmd.arg("build")
        .args(super::Profile::Release.args())
        .args(["--target", super::PROGRAM_TARGET]);
    for (_, package, _, features) in &wanted {
        cmd.args(["--package", package]);
        for feature in *features {
            cmd.args(["--features", &format!("{package}/{feature}")]);
        }
    }
    let target = super::target_dir();
    let elfs = {
        let _building = super::BUILD_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        super::run_cmd(&mut cmd)?;
        let mut elfs = Vec::new();
        for (_, package, _, _) in &wanted {
            let built = super::cargo_output(
                &target,
                super::PROGRAM_TARGET,
                super::Profile::Release,
                package,
            );
            elfs.push(std::fs::read(&built).map_err(|e| format!("{}: {e}", built.display()))?);
        }
        elfs
    };
    let mut needs = Vec::new();
    for ((record, elf), (_, _, stack, _)) in records.iter().zip(&elfs).zip(&wanted) {
        let program = bootimg::elf::program(elf, *stack)
            .map_err(|e| format!("init-reserve: {}: {e}", record.program))?;
        let need = need_of(record, &program, *stack);
        println!(
            "init-reserve: {} needs {} pages at a restart (quota {}, segments {}, stack {}, DMA {})",
            record.name, need.total, need.quota, need.segments, need.stack, need.dma
        );
        needs.push((record.name, need));
    }
    let found = verdict(&needs, INIT_RESERVE_PAGES)?;
    println!(
        "init-reserve: the restarts of all records need {} pages (largest {}, {}), a failed stop of {} leaks {} pages of DMA, {} in all within INIT_RESERVE_PAGES {INIT_RESERVE_PAGES}",
        found.sum,
        found.largest,
        found.largest_pages,
        found.leaker,
        found.leak,
        found.sum + found.leak
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn need(total: u64) -> Need {
        Need {
            quota: total - 100,
            segments: 60,
            stack: 30,
            dma: 10,
            total,
        }
    }

    fn need_dma(total: u64, dma: u64) -> Need {
        Need { dma, ..need(total) }
    }

    #[test]
    fn the_sum_and_the_leak_within_the_reserve_pass() {
        let needs = [
            ("blk", need_dma(150, 32)),
            ("display", need_dma(659, 532)),
            ("netd", need_dma(10_400, 264)),
        ];
        let found = verdict(&needs, 16_384).unwrap();
        assert_eq!(
            found,
            Found {
                sum: 11_209,
                leak: 532,
                leaker: "display".to_owned(),
                largest: "netd".to_owned(),
                largest_pages: 10_400
            }
        );
        // Exactly the reserve passes; one page less does not.
        assert!(verdict(&needs, 11_209 + 532).is_ok());
        assert!(verdict(&needs, 11_209 + 531).is_err());
    }

    #[test]
    fn a_sum_over_the_reserve_names_the_parts() {
        // Each record alone is within the reserve; together with the leak they are not.
        let needs = [("blk", need_dma(9_000, 32)), ("netd", need_dma(9_000, 264))];
        let error = verdict(&needs, 16_384).unwrap_err();
        assert!(error.contains("need 18000 pages"), "{error}");
        assert!(error.contains("leaks 264 pages of DMA"), "{error}");
        assert!(error.contains("INIT_RESERVE_PAGES 16384"), "{error}");
        assert!(
            error.contains("quota 8900, segments 60, stack 30, DMA"),
            "{error}"
        );
    }

    #[test]
    fn a_table_with_no_restarting_record_is_refused() {
        assert!(verdict(&[], 16_384).is_err());
    }
}
