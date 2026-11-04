// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The quota of the network service's records against what the service
//! charges to it (stafeto-design#548, item 17): `cargo xtask netd-quota`,
//! and the step "netd quota" of the host checks of ci.
//!
//! The stage's formula (p1-design, R9) set the quota to the pages of
//! `.data` and `.bss`, the whole stack and 16 more. That counts those pages
//! twice from init's side. Init makes the object of each segment and of the
//! stack and pays for them from its own quota (rt::loader, the payer of
//! `mem_create` is the process that makes the object), and it reserves
//! them apart from the record's quota (init::quota::need_pages: quota +
//! segments + stack + pools). It makes the DMA objects in its worker as
//! well (worker.rs, `mem_create_contiguous`), so they are init's too. What
//! the record's quota pays for is what the kernel charges to the service's
//! own process: the translation tables of every mapping in its space, which
//! mem_map charges up front by kcore::paging::tables_bound whoever maps
//! (kernel/src/process/maps.rs), and the kernel objects the service makes
//! (its mapping table, threads, channels, timer, the blocks of its handle
//! table). So the need here is the bound of the tables of the segments, the
//! stack, the DMA objects and the windows, plus OBJECTS_MARGIN for the rest.
//! The run of role `B` measured the whole charge at 30 pages with one client
//! buffer mapped and 39 with 64 (reports/2026-11-04-net-p4b1).

use crate::net::NETD_STACK_SIZE;
use init::table::Record;
use init::table::net::{NETD, NETD_TWO, NETD_VZ, NETD_VZ2};
use std::path::Path;
use std::sync::PoisonError;

const PAGE: u64 = 4096;

/// The pages the check allows for what the service charges to its quota
/// besides the tables of the mappings of its records: the mapping table,
/// the message buffer's mapping, its threads, channels and timer, the
/// blocks of its handle table, and the mappings it makes as it runs (the
/// clients' buffers). The buffers are BUFFERS_MAX (64) of 256 KiB, one after
/// another from BUFFERS_AT (services/netd/src/config.rs, dma.rs): 16 MiB,
/// which take at most 8 tables of the third level and one of the second, so
/// the 39 pages role B measured with all 64 mapped is the most they reach.
pub const OBJECTS_MARGIN: u64 = 64;

/// Every record of the service: they share NETD's quota.
const RECORDS: [(&str, &Record); 4] = [
    ("NETD", &NETD),
    ("NETD_VZ", &NETD_VZ),
    ("NETD_VZ2", &NETD_VZ2),
    ("NETD_TWO", &NETD_TWO),
];

/// The most tables a mapping of `pages` pages adds anywhere in the lower
/// half: tables_bound at the worst placement, one more at each level than
/// the regions the pages fill. The service picks the addresses of its DMA
/// objects and windows itself (services/netd/src/dma.rs).
fn tables_anywhere(pages: u64) -> u64 {
    [9, 18, 27]
        .into_iter()
        .map(|shift| pages.div_ceil(1 << shift) + 1)
        .sum()
}

/// The pages of a record's need besides OBJECTS_MARGIN, given the bound of
/// the tables of the program's segments and stack.
fn record_tables(record: &Record, program_tables: u64) -> u64 {
    let dma: u64 = record
        .dma
        .iter()
        .map(|d| tables_anywhere(d.size.div_ceil(PAGE)))
        .sum();
    let windows: u64 = record
        .windows
        .iter()
        .map(|w| tables_anywhere(w.len.div_ceil(PAGE)))
        .sum();
    program_tables + dma + windows
}

/// Builds the service as the shell's image ships it and checks every
/// record's quota against its need.
pub fn check() -> Result<(), String> {
    let elf = {
        let _building = super::BUILD_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        super::run_cmd(
            super::cargo()
                .arg("build")
                .args(super::Profile::Release.args())
                .args(["--target", super::PROGRAM_TARGET, "--package", "netd"]),
        )?;
        let built = super::cargo_output(
            &super::target_dir(),
            super::PROGRAM_TARGET,
            super::Profile::Release,
            "netd",
        );
        std::fs::read(&built).map_err(|e| format!("{}: {e}", built.display()))?
    };
    check_elf(&elf, Path::new("netd"))
}

fn check_elf(elf: &[u8], name: &Path) -> Result<(), String> {
    let program = bootimg::elf::program(elf, NETD_STACK_SIZE)
        .map_err(|e| format!("{}: {e}", name.display()))?;
    let mut segment_pages = 0;
    let mut program_tables = 0;
    for segment in program.segments.iter().filter(|s| s.mem_size != 0) {
        let range = segment.pages();
        let pages = (range.end - range.start) / PAGE;
        segment_pages += pages;
        program_tables += kcore::paging::tables_bound(range.start, pages);
    }
    let stack_pages = u64::from(NETD_STACK_SIZE).div_ceil(PAGE);
    program_tables +=
        kcore::paging::tables_bound(abi::INIT_STACK_TOP - stack_pages * PAGE, stack_pages);
    let data = &program.segments[bootimg::Part::Data as usize];
    let data_pages = (data.pages().end - data.pages().start) / PAGE;
    let mut failed = Vec::new();
    for (label, record) in RECORDS {
        let quota = record.quota.div_ceil(PAGE);
        let need = record_tables(record, program_tables) + OBJECTS_MARGIN;
        let dma: u64 = record.dma.iter().map(|d| d.size.div_ceil(PAGE)).sum();
        println!(
            "netd quota: {label} has {quota} pages, needs {need} (tables of the mappings {}, \
             objects {OBJECTS_MARGIN}); init pays apart for {segment_pages} pages of segments \
             ({data_pages} of .data and .bss), {stack_pages} of stack and {dma} of DMA",
            need - OBJECTS_MARGIN
        );
        if quota < need {
            failed.push(format!("{label}: quota {quota} pages, need {need}"));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the quota of netd's records is below their need: {}",
            failed.join("; ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_anywhere_bounds_every_placement() {
        for pages in [1, 2, 8, 256, 511, 512, 513, 4817] {
            let worst = (0..1024)
                .map(|page| kcore::paging::tables_bound((1 << 30) + page * PAGE, pages))
                .max()
                .unwrap_or(0);
            assert!(tables_anywhere(pages) >= worst, "{pages} pages");
        }
    }
}
