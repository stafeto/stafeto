// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The reserve of init's free pages against the restart of its heaviest
//! record: `cargo xtask init-reserve`, and the step "init reserve" of the
//! host checks of ci.
//!
//! After the services of the base image and the full image started, init
//! keeps `INIT_RESERVE_PAGES` of its own quota free and gives the pool of the
//! process service everything above them (services/init/src/table/base.rs).
//! The one use init has for free pages after the boot is the restart of a
//! record with `Restart::Always` while its clients still hold the old
//! instance: the instance takes its quota, the pages of its segments and
//! stack, init's pools and the pages of its DMA objects once more
//! (init::quota::need_with_dma). The check builds the programs of those
//! records and fails when the largest of those needs is over the reserve.

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

/// The record with the largest need, and the error that names it when
/// that need is over `reserve`.
fn verdict(needs: &[(&str, Need)], reserve: u64) -> Result<(String, u64), String> {
    let Some((name, worst)) = needs.iter().max_by_key(|(_, n)| n.total) else {
        return Err("init-reserve: the base table has no record that restarts".to_owned());
    };
    if worst.total > reserve {
        return Err(format!(
            "init-reserve: {name} needs {} pages at a restart (quota {}, segments {}, stack {}, \
             DMA {}), over INIT_RESERVE_PAGES {reserve} in services/init/src/table/base.rs",
            worst.total, worst.quota, worst.segments, worst.stack, worst.dma
        ));
    }
    Ok((name.to_string(), worst.total))
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
    let (name, total) = verdict(&needs, INIT_RESERVE_PAGES)?;
    println!(
        "init-reserve: the largest need is {name}, {total} pages, within INIT_RESERVE_PAGES {INIT_RESERVE_PAGES}"
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

    #[test]
    fn the_largest_need_within_the_reserve_passes() {
        let needs = [("blk", need(150)), ("netd", need(10_400))];
        assert_eq!(verdict(&needs, 16_384), Ok(("netd".to_owned(), 10_400)));
        assert_eq!(verdict(&needs, 10_400), Ok(("netd".to_owned(), 10_400)));
    }

    #[test]
    fn a_need_over_the_reserve_names_the_record_and_its_parts() {
        let needs = [("blk", need(150)), ("netd", need(17_000))];
        let error = verdict(&needs, 16_384).unwrap_err();
        assert!(error.contains("netd needs 17000 pages"), "{error}");
        assert!(
            error.contains("quota 16900, segments 60, stack 30, DMA 10"),
            "{error}"
        );
        assert!(error.contains("INIT_RESERVE_PAGES 16384"), "{error}");
    }

    #[test]
    fn a_table_with_no_restarting_record_is_refused() {
        assert!(verdict(&[], 16_384).is_err());
    }
}
