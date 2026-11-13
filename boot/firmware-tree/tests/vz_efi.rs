// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The same on Apple Virtualization.framework: the tables and the memory map
//! of its EFI firmware (`vz-run --efi-writable` with the loader's `dump`, then
//! `cargo xtask efi-fixtures vz DISK`) against the tree its Linux boot gives
//! (`kcore/tests/fixtures/apple-vz.dtb`). VZ's firmware has no SPCR, IORT or
//! ITS, so the console, the ITS and the MSI map are not compared.

use firmware_tree::acpi::{Table, Tables};
use firmware_tree::check::{Placement, check};
use firmware_tree::efimap::{Desc, classify};
use firmware_tree::platform::Platform;
use firmware_tree::tree::{Input, build};
use kcore::bootinfo::{BootInfo, Region, parse, pci_hosts};
use kcore::fdt::{Event, Fdt};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vz-efi");
const DTB: &[u8] = include_bytes!("../../../kcore/tests/fixtures/apple-vz.dtb");
const MAP: &[u8] = include_bytes!("fixtures/vz-efi/memmap.bin");

fn tables() -> Tables<'static> {
    let mut names: Vec<_> = std::fs::read_dir(DIR)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".bin") && n.as_bytes()[2] == b'-')
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let data: &'static [u8] = Box::leak(
            std::fs::read(format!("{DIR}/{name}"))
                .unwrap()
                .into_boxed_slice(),
        );
        out.push(Table {
            signature: data[..4].try_into().unwrap(),
            revision: data[8],
            data,
        });
    }
    Tables {
        tables: out,
        rejected: Vec::new(),
    }
}

fn map() -> Vec<Desc> {
    let u64_at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    MAP.as_chunks::<32>()
        .0
        .iter()
        .map(|r| Desc {
            ty: u64_at(r, 0) as u32,
            phys: u64_at(r, 8),
            pages: u64_at(r, 16),
            attr: u64_at(r, 24),
        })
        .collect()
}

const KERNEL: Region = Region {
    base: 0x7000_0000,
    size: 0x1d_0000,
};
const TREE: Region = Region {
    base: 0x701d_0000,
    size: 0x1_0000,
};
const IMAGE: Region = Region {
    base: 0x7800_0000,
    size: 0x3_2000,
};

fn ours() -> Vec<u8> {
    let platform = Platform::from_tables(&tables()).unwrap();
    let memory = classify(&map(), &[KERNEL, TREE, IMAGE]).unwrap();
    build(&Input {
        platform: &platform,
        memory: &memory,
        initrd: IMAGE,
        boot_mpidr: 0,
        pci_windows: &[],
    })
    .unwrap()
}

fn info(blob: &[u8]) -> BootInfo {
    parse(&Fdt::new(blob).unwrap()).unwrap()
}

/// The PPI numbers (second cell of each triple) of the `timer` node.
fn timer_ppis(blob: &[u8]) -> Vec<u32> {
    let fdt = Fdt::new(blob).unwrap();
    let mut ppis = Vec::new();
    let mut in_timer = false;
    fdt.walk(|e| match e {
        Event::BeginNode { name, depth: 2 } => in_timer = name == "timer",
        Event::Prop {
            name: "interrupts",
            value,
        } if in_timer => {
            ppis = value
                .chunks(12)
                .map(|c| u32::from_be_bytes(c[4..8].try_into().unwrap()))
                .collect();
        }
        _ => {}
    })
    .unwrap();
    ppis
}

#[test]
fn the_tree_from_the_acpi_tables_reads_as_the_one_vz_gives_linux() {
    let (mine, theirs) = (info(&ours()), info(DTB));
    let g = |i: &BootInfo| i.gic.unwrap();
    assert_eq!(g(&mine).version, g(&theirs).version);
    assert_eq!(
        g(&mine).mapped(),
        g(&theirs).mapped(),
        "the GIC's distributor and redistributor"
    );
    assert_eq!(mine.psci, theirs.psci);
    assert_eq!(mine.cpus.as_slice(), theirs.cpus.as_slice());
    let hull = |i: &BootInfo| {
        let m = i.memory.as_slice();
        (
            m.iter().map(|r| r.base).min().unwrap(),
            m.iter().map(|r| r.end()).max().unwrap(),
        )
    };
    assert_eq!(
        hull(&mine),
        hull(&theirs),
        "the RAM, as the union of the memory nodes"
    );
    let a = ours();
    let (hm, ht) = (
        pci_hosts(&Fdt::new(&a).unwrap()).unwrap(),
        pci_hosts(&Fdt::new(DTB).unwrap()).unwrap(),
    );
    assert_eq!(hm.as_slice(), ht.as_slice());
    assert_eq!(timer_ppis(&a), timer_ppis(DTB));
    // What VZ's firmware leaves out: no SPCR, no IORT, no ITS.
    assert!(mine.uart_pl011.is_none() && mine.its.is_none() && mine.max_device_id().is_none());
}

#[test]
fn the_tree_passes_the_kernels_checks_as_the_loader_placed_it() {
    let blob = ours();
    let (summary, _) = check(
        &blob,
        &Placement {
            kernel: KERNEL,
            tree: Region {
                base: TREE.base,
                size: blob.len() as u64,
            },
            boot_image: IMAGE,
        },
    )
    .unwrap();
    assert_eq!(summary.cpus, 1);
    assert_eq!(summary.msi_entries, 0);
}
